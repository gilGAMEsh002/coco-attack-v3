"""Public records for the model-generation service (plan section 3)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from ..assets.artifacts import canonical_json_bytes, sha256_bytes
from ..protocol.stages import Stage

SOURCE_CHOICES = ("dmx", "mock")
STAGE_CHOICES = tuple(stage.value for stage in Stage)  # ("search", "holdout")
CLEAN_FORMS = ("clean_0shot", "clean_fewshot_cot", "clean_fewshot_no_cot")

STATUS_SUCCESS = "success"
STATUS_EMPTY = "empty"
STATUS_TRUNCATED = "truncated"
STATUS_ERROR = "error"
STATUS_INVALID_RESPONSE = "invalid_response"
GENERATION_STATUSES = (
    STATUS_SUCCESS,
    STATUS_EMPTY,
    STATUS_TRUNCATED,
    STATUS_ERROR,
    STATUS_INVALID_RESPONSE,
)

ADAPTER_VERSION = "generation-adapter-v1"

_ROLLOUT_IDENTITY_FIELDS = (
    "stage",
    "batch_id",
    "combination_id",
    "task_id",
    "repeat_id",
    "prompt_version",
    "candidate_hash",
)


class GenerationContractError(ValueError):
    """Raised when a generation configuration or record is invalid."""


def _non_empty(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise GenerationContractError(f"{where} must be a non-empty string")
    return value


def _non_negative_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GenerationContractError(f"{where} must be a non-negative integer")
    return value


def _positive_int(value: Any, where: str) -> int:
    result = _non_negative_int(value, where)
    if result == 0:
        raise GenerationContractError(f"{where} must be a positive integer")
    return result


def _number(value: Any, where: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GenerationContractError(f"{where} must be a number")
    return float(value)


@dataclass(frozen=True)
class SampleIdentity:
    """The seven-field rollout identity from plan section 4.3."""

    stage: str
    batch_id: str
    combination_id: str
    task_id: str
    repeat_id: int
    prompt_version: str
    candidate_hash: str

    def __post_init__(self) -> None:
        if self.stage not in STAGE_CHOICES:
            raise GenerationContractError(f"invalid stage: {self.stage!r}")
        for name in ("batch_id", "combination_id", "task_id", "prompt_version", "candidate_hash"):
            _non_empty(getattr(self, name), f"sample_identity.{name}")
        _non_negative_int(self.repeat_id, "sample_identity.repeat_id")

    def to_json(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _ROLLOUT_IDENTITY_FIELDS}

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "SampleIdentity":
        missing = [name for name in _ROLLOUT_IDENTITY_FIELDS if name not in payload]
        if missing:
            raise GenerationContractError(f"sample identity missing fields: {missing}")
        extra = sorted(set(payload) - set(_ROLLOUT_IDENTITY_FIELDS))
        if extra:
            raise GenerationContractError(f"sample identity has unknown fields: {extra}")
        return cls(**{name: payload[name] for name in _ROLLOUT_IDENTITY_FIELDS})

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json())

    def sample_id(self) -> str:
        """Full SHA-256 hex digest of the canonical identity."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def rollout_id(self) -> int:
        """Non-negative integer derived from the same digest (not truncated)."""

        return int.from_bytes(hashlib.sha256(self.canonical_bytes()).digest(), "big")


@dataclass(frozen=True)
class GenerationConfig:
    source: str
    model: str
    batch_id: str
    combination_id: str
    oracle_id: str
    stage: str
    form: str
    prompt_version: str
    candidate_hash: str
    temperature: float
    repeats: int
    max_tokens: int
    request_timeout: float
    max_concurrency: int
    max_request_attempts: int
    max_sample_retries: int
    api_base: str = "https://www.dmxapi.cn/v1"
    model_type: str = "chat"
    price_input_per_1k: float | None = None
    price_output_per_1k: float | None = None
    currency: str = "USD"
    pricing_version: str = "unset"
    mock_scenario: str = "normal"
    schema_version: str = "1"
    task_ids: tuple[str, ...] = ()
    requests_per_minute: float | None = None
    tokens_per_minute: int | None = None

    def __post_init__(self) -> None:
        if self.source not in SOURCE_CHOICES:
            raise GenerationContractError(f"source must be one of {SOURCE_CHOICES}")
        if self.stage not in STAGE_CHOICES:
            raise GenerationContractError(f"stage must be one of {STAGE_CHOICES}")
        for name in ("model", "batch_id", "combination_id", "oracle_id", "prompt_version"):
            _non_empty(getattr(self, name), f"config.{name}")
        if not isinstance(self.candidate_hash, str):
            raise GenerationContractError("config.candidate_hash must be a string")
        if self.candidate_hash and not re.fullmatch(r"[0-9a-f]{64}", self.candidate_hash):
            raise GenerationContractError(
                "config.candidate_hash must be empty or a 64-character lowercase hex digest"
            )
        if self.form not in CLEAN_FORMS:
            raise GenerationContractError(f"form must be one of {CLEAN_FORMS}")
        _number(self.temperature, "config.temperature")
        _positive_int(self.repeats, "config.repeats")
        _positive_int(self.max_tokens, "config.max_tokens")
        _number(self.request_timeout, "config.request_timeout")
        _positive_int(self.max_concurrency, "config.max_concurrency")
        _positive_int(self.max_request_attempts, "config.max_request_attempts")
        _non_negative_int(self.max_sample_retries, "config.max_sample_retries")
        _number(self.price_input_per_1k, "config.price_input_per_1k", allow_none=True)
        _number(self.price_output_per_1k, "config.price_output_per_1k", allow_none=True)
        if self.requests_per_minute is not None:
            _number(self.requests_per_minute, "config.requests_per_minute")
            if self.requests_per_minute < 1:
                raise GenerationContractError("config.requests_per_minute must be at least 1 or None")
        if self.tokens_per_minute is not None:
            _positive_int(self.tokens_per_minute, "config.tokens_per_minute")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "model": self.model,
            "model_type": self.model_type,
            "api_base": self.api_base,
            "batch_id": self.batch_id,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "stage": self.stage,
            "form": self.form,
            "prompt_version": self.prompt_version,
            "candidate_hash": self.candidate_hash,
            "temperature": self.temperature,
            "repeats": self.repeats,
            "max_tokens": self.max_tokens,
            "request_timeout": self.request_timeout,
            "max_concurrency": self.max_concurrency,
            "max_request_attempts": self.max_request_attempts,
            "max_sample_retries": self.max_sample_retries,
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "currency": self.currency,
            "pricing_version": self.pricing_version,
            "mock_scenario": self.mock_scenario,
            "task_ids": list(self.task_ids),
            "requests_per_minute": self.requests_per_minute,
            "tokens_per_minute": self.tokens_per_minute,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "GenerationConfig":
        required = (
            "source", "model", "batch_id", "combination_id", "oracle_id", "stage",
            "form", "prompt_version", "candidate_hash", "temperature", "repeats",
            "max_tokens", "request_timeout", "max_concurrency", "max_request_attempts",
            "max_sample_retries",
        )
        missing = [name for name in required if name not in payload]
        if missing:
            raise GenerationContractError(f"generation config missing fields: {missing}")
        allowed = set(GenerationConfig.__dataclass_fields__)
        extra = sorted(set(payload) - allowed)
        if extra:
            raise GenerationContractError(f"generation config has unknown fields: {extra}")
        if "task_ids" in payload and payload["task_ids"] is not None:
            payload = {**payload, "task_ids": tuple(payload["task_ids"])}
        return cls(**payload)

    def run_config_hash(self) -> str:
        """Credential-free hash of everything that can change the experiment."""

        return sha256_bytes(canonical_json_bytes(self.to_json()))


@dataclass(frozen=True)
class GenerationRecord:
    identity: SampleIdentity
    sample_id: str
    rollout_id: int
    combination_id: str
    oracle_id: str
    source: str
    model: str
    form: str
    run_config_hash: str
    task_snapshot_sha256: str
    prompt_sha256: str
    status: str
    generation: str
    error_reason: str | None
    response_id: str | None
    finish_reason: str | None
    request_attempt_id: str | None
    retry_count: int
    usage: dict[str, Any]
    cost: dict[str, Any]
    cache_hit: bool
    adapter_version: str = ADAPTER_VERSION
    dspy_fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.status not in GENERATION_STATUSES:
            raise GenerationContractError(f"invalid generation status: {self.status!r}")
        if self.status != STATUS_SUCCESS and self.status != STATUS_TRUNCATED and self.status != STATUS_EMPTY:
            if self.generation:
                raise GenerationContractError("failed generation must carry an empty generation text")
        if self.status in (STATUS_SUCCESS, STATUS_TRUNCATED, STATUS_EMPTY, STATUS_INVALID_RESPONSE):
            if not isinstance(self.generation, str):
                raise GenerationContractError("generation must be a string")

    def to_cleaner_row(self) -> dict[str, Any]:
        """A minimal ``clean_generations`` row; extra identity fields are allowed."""

        return {
            "task_id": self.identity.task_id,
            "repeat_id": self.identity.repeat_id,
            "status": self.status,
            "generation": self.generation,
            "cwe": self.combination_id,
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            # Cleaner-compatible top-level fields (clean_generations reads these).
            "task_id": self.identity.task_id,
            "repeat_id": self.identity.repeat_id,
            "status": self.status,
            "generation": self.generation,
            "cwe": self.combination_id,
            # Full identity and provenance.
            "identity": self.identity.to_json(),
            "sample_id": self.sample_id,
            "rollout_id": self.rollout_id,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "source": self.source,
            "model": self.model,
            "form": self.form,
            "run_config_hash": self.run_config_hash,
            "task_snapshot_sha256": self.task_snapshot_sha256,
            "prompt_sha256": self.prompt_sha256,
            "generation_sha256": sha256_bytes(self.generation.encode("utf-8")),
            "error_reason": self.error_reason,
            "response_id": self.response_id,
            "finish_reason": self.finish_reason,
            "request_attempt_id": self.request_attempt_id,
            "retry_count": self.retry_count,
            "usage": self.usage,
            "cost": self.cost,
            "cache_hit": self.cache_hit,
            "adapter_version": self.adapter_version,
            "dspy_fingerprint": self.dspy_fingerprint,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "GenerationRecord":
        return cls(
            identity=SampleIdentity.from_json(payload["identity"]),
            sample_id=payload["sample_id"],
            rollout_id=int(payload["rollout_id"]),
            combination_id=payload["combination_id"],
            oracle_id=payload["oracle_id"],
            source=payload["source"],
            model=payload["model"],
            form=payload["form"],
            run_config_hash=payload["run_config_hash"],
            task_snapshot_sha256=payload["task_snapshot_sha256"],
            prompt_sha256=payload["prompt_sha256"],
            status=payload["status"],
            generation=payload["generation"],
            error_reason=payload.get("error_reason"),
            response_id=payload.get("response_id"),
            finish_reason=payload.get("finish_reason"),
            request_attempt_id=payload.get("request_attempt_id"),
            retry_count=int(payload.get("retry_count", 0)),
            usage=dict(payload.get("usage") or {}),
            cost=dict(payload.get("cost") or {}),
            cache_hit=bool(payload.get("cache_hit", False)),
            adapter_version=payload.get("adapter_version", ADAPTER_VERSION),
            dspy_fingerprint=payload.get("dspy_fingerprint", ""),
        )
