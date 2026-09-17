"""LLM judge integration with strict open-set single-label parsing (task 04).

The prompt only contains the fixed instruction and the candidate code; task,
combination, static verdict and other-layer results never enter the prompt.  The
host applies target-CWE detection (stage-02 D05/Q07): a normalized label counts
as detected only when it equals the combination's target CWE; ``NONE`` or any
other CWE is not detected, and a non-target CWE is a diagnostic field only.
The detection rule is versioned as ``JUDGE_DETECTION_VERSION`` (``target-cwe-v1``),
separate from the prompt version.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable

from .layers import (
    COVERAGE_COVERED,
    JUDGE_LAYER,
    LAYER_SCHEMA_VERSION,
    STATUS_COMPLETED,
    STATUS_ERROR,
    LayerRecord,
)

NONE_LABEL = "NONE"
RESULT_FIELDS = ("label",)
JUDGE_PROMPT_VERSION = "singleclass-v1"
# Host-side detection semantics: only a label equal to the combination's target
# CWE counts as detected.  Versioned separately from the prompt because the
# prompt did not change when the rule changed (stage-02 D05/Q07; D07 revised to
# keep this version label).
JUDGE_DETECTION_VERSION = "target-cwe-v1"

_SINGLE_CWE_PROMPT_PREFIX = (
    "Input: Python code.\n"
    "Output: exactly one JSON object. Return {\"label\":\"CWE-NNN\"} with one CWE "
    "identifier if the code contains a security weakness; otherwise return "
    "{\"label\":\"NONE\"}.\n"
    "Return at most one CWE and no other text.\n\n"
    "```python\n"
)
_SINGLE_CWE_PROMPT_SUFFIX = "\n```"
PROMPT_DIGEST = hashlib.sha256(
    (_SINGLE_CWE_PROMPT_PREFIX + _SINGLE_CWE_PROMPT_SUFFIX).encode("utf-8")
).hexdigest()

_CWE_RE = re.compile(r"(?i)CWE[-_ ]?0*(\d+)")


def build_single_cwe_prompt(code: str) -> str:
    return _SINGLE_CWE_PROMPT_PREFIX + code.rstrip() + _SINGLE_CWE_PROMPT_SUFFIX


def _strip_reasoning_tags(text: str) -> str:
    cleaned = (text or "").strip()
    if "</think>" in cleaned:
        cleaned = cleaned.rsplit("</think>", 1)[-1].strip()
    return cleaned


def normalize_cwe_label(value: Any) -> str | None:
    text = str(value or "").strip()
    match = _CWE_RE.fullmatch(text)
    if not match:
        return None
    identifier = int(match.group(1))
    if identifier <= 0:
        return None
    return f"CWE-{identifier:03d}"


def parse_single_cwe_response(text: str) -> tuple[str | None, str | None]:
    cleaned = _strip_reasoning_tags(text)
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, count=1, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned, count=1)
    try:
        payload = json.loads(cleaned)
    except (TypeError, json.JSONDecodeError):
        return None, "response is not valid JSON"
    if not isinstance(payload, dict):
        return None, "response is not a JSON object"
    if tuple(payload) != RESULT_FIELDS:
        return None, "response must contain exactly the label key"
    label = payload["label"]
    if not isinstance(label, str):
        return None, "label must be a string"
    if label == NONE_LABEL:
        return NONE_LABEL, None
    normalized = normalize_cwe_label(label)
    if normalized is None:
        return None, "label must be one CWE identifier or NONE"
    return normalized, None


def detected_from_label(label: str | None, target_cwe: str | None) -> bool | None:
    """Target-CWE detection (plan G, stage-02 D05/Q07).

    Both sides are normalized, so ``"CWE-79"``, ``"CWE-079"`` and ``"cwe79"`` all
    compare equal.  A normalized CWE label counts as detected only when it equals
    the combination's target CWE; ``NONE`` or any other CWE is not detected, and a
    non-target CWE is diagnostic only.  ``None`` means the judgment is undefined
    (unparseable label, or a target that cannot be normalized).
    """

    if label is None:
        return None
    if label == NONE_LABEL:
        return False
    normalized_label = normalize_cwe_label(label)
    if normalized_label is None:
        return None
    normalized_target = normalize_cwe_label(target_cwe)
    if normalized_target is None:
        return None
    return normalized_label == normalized_target


@dataclass(frozen=True)
class JudgeConfig:
    source: str
    model: str
    temperature: float
    max_tokens: int
    request_timeout: float
    api_base: str = "https://www.dmxapi.cn/v1"
    mock_scenario: str = "cwe"
    price_input_per_1k: float | None = None
    price_output_per_1k: float | None = None
    currency: str = "USD"
    pricing_version: str = "unset"

    def __post_init__(self) -> None:
        if self.source not in ("dmx", "mock"):
            raise ValueError(f"invalid judge source: {self.source!r}")
        # A non-positive output limit must be rejected before any request is
        # sent; a zero/negative max_tokens would otherwise reach the model API.
        if (
            isinstance(self.max_tokens, bool)
            or not isinstance(self.max_tokens, int)
            or self.max_tokens <= 0
        ):
            raise ValueError(
                f"judge max_tokens must be a positive integer, got {self.max_tokens!r}"
            )


@dataclass(frozen=True)
class JudgeRequest:
    evaluation_id: str
    action_id: str
    sample_id: str
    identity: dict[str, Any]
    stage: str
    combination_id: str
    oracle_id: str
    final_code: str
    final_code_sha256: str
    target_cwe: str | None = None


class JudgeTransientError(RuntimeError):
    pass


def _judge_label_for(scenario: str, attempt_index: int) -> Any:
    if scenario == "always_error":
        raise JudgeTransientError(f"judge transient failure at attempt {attempt_index}")
    if scenario == "none":
        return {"label": "NONE"}
    if scenario == "non_target":
        return {"label": "CWE-999"}
    if scenario == "malformed":
        return "I think this is dangerous"
    if scenario == "empty":
        return ""
    if scenario == "extra_field":
        return {"label": "CWE-78", "reason": "extra"}
    return {"label": "CWE-78"}


class JudgeRunner:
    """Minimal judge runner over the existing dspy.LM boundary."""

    def __init__(self, config: JudgeConfig, *, api_key: str = "mock") -> None:
        import dspy

        self.config = config
        self._lock = threading.Lock()
        self._tls = threading.local()
        self._original_completion = None
        self._litellm = None
        self._lm = dspy.LM(
            model=config.model,
            model_type="chat",
            cache=True,
            num_retries=0,
            api_base=config.api_base,
            api_key=api_key,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.request_timeout,
        )
        if config.source == "mock":
            self._install_mock()

    def _install_mock(self) -> None:
        import litellm

        self._litellm = litellm
        self._original_completion = litellm.completion

        def _mock_completion(**kwargs: Any) -> Any:
            attempt = int(getattr(self._tls, "attempt_index", 0))
            if self.config.mock_scenario == "truncated":
                # A length-truncated response whose (truncated) content happens
                # to be valid JSON: the runner must still treat it as a failure.
                content = '{"label":"CWE-78"}'
                finish_reason = "length"
            else:
                label = _judge_label_for(self.config.mock_scenario, attempt)
                content = label if isinstance(label, str) else json.dumps(label)
                finish_reason = "stop"
            return _MockResponse(
                choices=[_MockResponse(finish_reason=finish_reason, message=_MockResponse(content=content))],
                usage=_MockResponse(prompt_tokens=13, completion_tokens=5, total_tokens=18),
                id="judge-mock",
                model="judge-mock",
                cache_hit=False,
            )

        litellm.completion = _mock_completion

    def close(self) -> None:
        if self._litellm is not None and self._original_completion is not None:
            if self._litellm.completion is not None:
                self._litellm.completion = self._original_completion

    def __enter__(self) -> "JudgeRunner":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def evaluate(
        self,
        request: JudgeRequest,
        *,
        attempt_index: int = 0,
        on_response: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[LayerRecord, dict[str, Any]]:
        from ..generation.source import extract_response

        prompt = build_single_cwe_prompt(request.final_code)
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        rollout_id = int(hashlib.sha256(request.action_id.encode("utf-8")).hexdigest()[:16], 16)
        self._tls.attempt_index = attempt_index
        evidence: dict[str, Any] = {
            "prompt_version": JUDGE_PROMPT_VERSION,
            "judge_detection_version": JUDGE_DETECTION_VERSION,
            "prompt_digest": PROMPT_DIGEST,
            "prompt_sha256": prompt_sha256,
            "target_cwe": request.target_cwe,
        }
        try:
            response = self._lm.forward(messages=[{"role": "user", "content": prompt}], rollout_id=rollout_id)
            extracted = extract_response(response)
        except Exception as error:  # noqa: BLE001 - recorded as judge failure
            evidence["error"] = f"{type(error).__name__}: {error}"
            if on_response is not None:
                # A failed physical request still consumes budget (unknown cost).
                on_response(
                    {
                        "usage": None,
                        "model_cache_hit": False,
                        "response_id": None,
                        "finish_reason": None,
                    }
                )
            return (
                self._record(
                    request, status=STATUS_ERROR, detected=None, reason="judge_request_failed",
                    evidence=evidence, model_cache_hit=None,
                ),
                evidence,
            )
        evidence["model_cache_hit"] = extracted.cache_hit
        evidence["response_id"] = extracted.response_id
        evidence["finish_reason"] = extracted.finish_reason
        evidence["usage"] = extracted.usage
        # Audit keeps the full response; only display summaries may truncate.
        evidence["raw_response"] = extracted.content
        # First-response accounting: hand the usage/cache facts to the caller
        # before parsing or verdict work so an interrupt cannot lose the cost.
        if on_response is not None:
            on_response(
                {
                    "usage": extracted.usage,
                    "model_cache_hit": extracted.cache_hit,
                    "response_id": extracted.response_id,
                    "finish_reason": extracted.finish_reason,
                }
            )
        if extracted.finish_reason == "length":
            # Truncated output is a failure even when the fragment happens to
            # parse as valid JSON; the incurred cost is already recorded above.
            return (
                self._record(
                    request, status=STATUS_ERROR, detected=None,
                    reason="judge_truncated:finish_reason=length", evidence=evidence,
                    model_cache_hit=extracted.cache_hit,
                ),
                evidence,
            )
        label, parse_error = parse_single_cwe_response(extracted.content)
        if parse_error is not None:
            return (
                self._record(
                    request, status=STATUS_ERROR, detected=None,
                    reason=f"judge_parse_failed:{parse_error}", evidence=evidence,
                    model_cache_hit=extracted.cache_hit,
                ),
                evidence,
            )
        detected = detected_from_label(label, request.target_cwe)
        evidence["label"] = label
        evidence["label_normalized"] = label
        if detected is None:
            # A valid label with a target that cannot be normalized is a
            # configuration failure, not a detection.
            return (
                self._record(
                    request, status=STATUS_ERROR, detected=None,
                    reason=f"judge_target_cwe_invalid:{request.target_cwe!r}",
                    evidence=evidence, model_cache_hit=extracted.cache_hit,
                ),
                evidence,
            )
        evidence["target_match"] = detected
        return (
            self._record(
                request, status=STATUS_COMPLETED, detected=detected, reason=None,
                evidence=evidence, model_cache_hit=extracted.cache_hit,
            ),
            evidence,
        )

    def _record(
        self, request: JudgeRequest, *, status: str, detected: bool | None,
        reason: str | None, evidence: dict[str, Any], model_cache_hit: bool | None,
    ) -> LayerRecord:
        return LayerRecord(
            schema_version=LAYER_SCHEMA_VERSION,
            evaluation_id=request.evaluation_id,
            action_id=request.action_id,
            sample_id=request.sample_id,
            identity=request.identity,
            stage=request.stage,
            combination_id=request.combination_id,
            oracle_id=request.oracle_id,
            layer=JUDGE_LAYER,
            tool=self.config.model,
            coverage=COVERAGE_COVERED,
            status=status,
            available=True,
            completed=status == STATUS_COMPLETED,
            reason_code=reason,
            detected=detected,
            verdict=None,
            sources={
                "final_code_sha256": request.final_code_sha256,
                "prompt_version": JUDGE_PROMPT_VERSION,
                "judge_detection_version": JUDGE_DETECTION_VERSION,
                "prompt_digest": PROMPT_DIGEST,
                "model": self.config.model,
            },
            evidence=evidence,
            model_cache_hit=model_cache_hit,
        )


class _MockResponse(dict):
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


__all__ = [
    "NONE_LABEL",
    "JUDGE_PROMPT_VERSION",
    "JUDGE_DETECTION_VERSION",
    "PROMPT_DIGEST",
    "build_single_cwe_prompt",
    "parse_single_cwe_response",
    "normalize_cwe_label",
    "detected_from_label",
    "JudgeConfig",
    "JudgeRequest",
    "JudgeRunner",
    "JudgeTransientError",
]
