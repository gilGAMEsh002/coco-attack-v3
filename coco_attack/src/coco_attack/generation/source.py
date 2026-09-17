"""Model sources for generation (plan section 6).

Both sources use the exact same synchronous ``dspy.LM.forward`` path so that the
DSPy response cache and the ledger see identical request boundaries.  The mock
source replaces only the synchronous LiteLLM completion boundary, leaving
``dspy.LM.forward -> request_cache -> completion`` intact.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from .contracts import GenerationConfig

DMX_BASE = "https://www.dmxapi.cn/v1"

# Exception-name markers that indicate a transient, retryable provider failure.
_RETRYABLE_MARKERS = (
    "RateLimit",
    "Timeout",
    "Connection",
    "Transient",
    "ServiceUnavailable",
    "InternalServer",
    "APIError",
)
_RETRYABLE_STATUS = (408, 409, 425, 429, 500, 502, 503, 504)


class ResponseContractError(ValueError):
    """The provider response did not have the single-choice chat shape."""


class MockTransientError(RuntimeError):
    """Deterministic mock failure used to exercise the retry path."""


class _AttrDict(dict):
    """Minimal dict whose keys are also readable as attributes.

    LiteLLM's real ``ModelResponse`` supports both access styles; the mock needs
    the same shape because DSPy's truncation check reads ``choice.finish_reason``
    while the cache probe reads ``response.usage``.
    """

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


@dataclass(frozen=True)
class ExtractedResponse:
    content: str
    finish_reason: str | None
    usage: dict[str, int]
    cache_hit: bool
    response_id: str | None
    model: str | None


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _usage_to_dict(usage: Any) -> dict[str, int]:
    if usage is None:
        return {}
    mapping: Any = usage
    if not isinstance(mapping, dict):
        for attr in ("model_dump", "to_dict", "dict"):
            method = getattr(mapping, attr, None)
            if callable(method):
                try:
                    candidate = method()
                except Exception:  # noqa: BLE001 - best-effort normalization
                    continue
                if isinstance(candidate, dict):
                    mapping = candidate
                    break
    if not isinstance(mapping, dict):
        return {}
    return {
        str(key): int(value)
        for key, value in mapping.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def extract_response(response: Any) -> ExtractedResponse:
    """Extract text/metadata from a single-choice chat response.

    ``n=1`` is fixed this round; multiple choices or an uninterpretable shape are
    treated as an interface error instead of silently selecting one.
    """

    choices = _get(response, "choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ResponseContractError(
            f"expected exactly one choice, got {len(choices) if isinstance(choices, list) else type(choices).__name__}"
        )
    choice = choices[0]
    message = _get(choice, "message")
    content = _get(message, "content") if message is not None else None
    if content is not None and not isinstance(content, str):
        raise ResponseContractError(f"message content is not text: {type(content).__name__}")
    return ExtractedResponse(
        content=content or "",
        finish_reason=_get(choice, "finish_reason"),
        usage=_usage_to_dict(_get(response, "usage")),
        cache_hit=bool(getattr(response, "cache_hit", False)),
        response_id=_get(response, "id"),
        model=_get(response, "model"),
    )


def is_retryable(exc: BaseException) -> bool:
    """Classify transient failures across the wrapped exception chain."""

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        name = type(current).__name__
        if any(marker in name for marker in _RETRYABLE_MARKERS):
            return True
        status = getattr(current, "status", None) or getattr(current, "status_code", None)
        if status in _RETRYABLE_STATUS:
            return True
        current = current.__cause__
    return False


def build_lm(config: GenerationConfig, api_key: str):
    import dspy

    return dspy.LM(
        model=config.model,
        model_type="chat",
        cache=True,
        num_retries=0,
        api_base=config.api_base or DMX_BASE,
        api_key=api_key,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout=config.request_timeout,
    )


class DspyLMSource:
    """Real (DMX) source over the fixed synchronous ``LM.forward`` path."""

    kind = "dmx"

    def __init__(self, config: GenerationConfig, api_key: str) -> None:
        self.config = config
        self._lm = build_lm(config, api_key)

    def generate(self, messages: list[dict[str, Any]], rollout_id: int, attempt_index: int) -> ExtractedResponse:
        response = self._lm.forward(messages=messages, rollout_id=rollout_id)
        return extract_response(response)


class MockSource:
    """Deterministic offline source that patches the LiteLLM completion boundary."""

    kind = "mock"

    def __init__(self, config: GenerationConfig, scenario: str | None = None) -> None:
        import litellm

        self.config = config
        self.scenario = scenario or config.mock_scenario
        self._litellm = litellm
        self._original_completion = litellm.completion
        self._tls = threading.local()
        self._install_lock = threading.Lock()
        self._lm = build_lm(config, api_key="mock")
        with self._install_lock:
            litellm.completion = self._mock_completion

    def close(self) -> None:
        with self._install_lock:
            if self._litellm.completion is self._mock_completion:
                self._litellm.completion = self._original_completion

    def __enter__(self) -> "MockSource":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def generate(self, messages: list[dict[str, Any]], rollout_id: int, attempt_index: int) -> ExtractedResponse:
        self._tls.attempt_index = attempt_index
        response = self._lm.forward(messages=messages, rollout_id=rollout_id)
        return extract_response(response)

    # -- mock provider ----------------------------------------------------- #

    def _mock_completion(self, **kwargs: Any) -> Any:
        attempt = int(getattr(self._tls, "attempt_index", 0))
        scenario = self.scenario
        if scenario == "always_error" or (scenario == "error_once" and attempt == 0):
            raise MockTransientError(f"mock transient failure at attempt {attempt}")
        if scenario == "permanent_error":
            raise ValueError(f"mock permanent failure at attempt {attempt}")
        if scenario == "slow":
            time.sleep(0.01)
        if scenario == "empty":
            return _mock_response("", "stop")
        if scenario == "truncated":
            return _mock_response("def task_func():\n    return 1\n", "length")
        if scenario == "invalid":
            return _AttrDict(choices=[], usage=_mock_usage(), id="mock-invalid", model="mock")
        if scenario == "dirty":
            return _mock_response(
                "Here is the solution:\n```python\n"
                "def task_func():\n    return 1\n"
                "```\n",
                "stop",
            )
        return _mock_response("def task_func():\n    return 1\n", "stop")


def _mock_usage(prompt: int = 11, completion: int = 7) -> _AttrDict:
    return _AttrDict(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
    )


def _mock_response(content: str, finish_reason: str) -> _AttrDict:
    return _AttrDict(
        choices=[_AttrDict(finish_reason=finish_reason, message=_AttrDict(content=content))],
        usage=_mock_usage(),
        id="mock-response",
        model="mock",
        cache_hit=False,
    )
