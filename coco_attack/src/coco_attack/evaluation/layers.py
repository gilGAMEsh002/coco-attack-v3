"""Independent evaluation-layer records and validation (stage 02, task 04).

Each non-static layer produces one strict record.  Coverage (does the layer
support this combination), availability (are tools/dependencies present),
completion (was a validated result formed) and the verdict are kept separate and
never folded into a single boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LAYER_SCHEMA_VERSION = "layer-result-v1"

COVERAGE_COVERED = "covered"
COVERAGE_NOT_COVERED = "not_covered"
COVERAGES = (COVERAGE_COVERED, COVERAGE_NOT_COVERED)

STATUS_COMPLETED = "completed"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"
STATUS_INCOMPLETE = "incomplete"
STATUS_SKIPPED = "skipped"
LAYER_STATUSES = (
    STATUS_COMPLETED,
    STATUS_UNAVAILABLE,
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    STATUS_SKIPPED,
)

SAST_LAYER = "sast"
JUDGE_LAYER = "judge"
DYNAMIC_LAYER = "dynamic"
REALISM_LAYER = "realism"
LAYERS = (SAST_LAYER, JUDGE_LAYER, DYNAMIC_LAYER, REALISM_LAYER)

DYNAMIC_VERDICTS = ("observed", "not_observed", "inconclusive")
REALISM_VERDICTS = (
    "confirmed_vulnerable",
    "not_vulnerable",
    "inconclusive",
    "execution_error",
)

# Old four combinations have dynamic/realism coverage; the new five do not.
OLD_FOUR = ("cwe078-0", "cwe094-0", "cwe295-0", "cwe502-0")
NEW_FIVE = ("cwe022-0", "cwe089-0", "cwe295-1", "cwe367-0", "cwe400-0")


class LayerContractError(ValueError):
    pass


@dataclass(frozen=True)
class LayerRecord:
    schema_version: str
    evaluation_id: str
    action_id: str
    sample_id: str
    identity: dict[str, Any]
    stage: str
    combination_id: str
    oracle_id: str
    layer: str
    tool: str
    coverage: str
    status: str
    available: bool
    completed: bool
    reason_code: str | None
    detected: bool | None
    verdict: str | None
    sources: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    evaluation_cache_hit: bool = False
    cache_reason: str = "cache_disabled"
    model_cache_hit: bool | None = None
    semantics_pending: bool = False

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            raise LayerContractError(f"unknown layer: {self.layer!r}")
        if self.coverage not in COVERAGES:
            raise LayerContractError(f"invalid coverage: {self.coverage!r}")
        if self.status not in LAYER_STATUSES:
            raise LayerContractError(f"invalid layer status: {self.status!r}")
        if self.detected not in (True, False, None):
            raise LayerContractError("detected must be a strict bool or null")
        if self.layer in (SAST_LAYER, JUDGE_LAYER):
            if self.verdict is not None:
                raise LayerContractError(f"{self.layer} uses detected, not verdict")
        elif self.layer == DYNAMIC_LAYER:
            if self.verdict is not None and self.verdict not in DYNAMIC_VERDICTS:
                raise LayerContractError(f"invalid dynamic verdict: {self.verdict!r}")
            if self.detected is not None:
                raise LayerContractError("dynamic layer must not set detected")
        else:
            if self.verdict is not None and self.verdict not in REALISM_VERDICTS:
                raise LayerContractError(f"invalid realism verdict: {self.verdict!r}")
            if self.detected is not None:
                raise LayerContractError("realism layer must not set detected")
        if self.completed and self.status != STATUS_COMPLETED:
            raise LayerContractError("completed=true requires status=completed")
        if self.coverage == COVERAGE_NOT_COVERED and (
            self.verdict is not None or self.detected is not None
        ):
            raise LayerContractError("not_covered layers must not carry a verdict")
        if self.evaluation_cache_hit:
            raise LayerContractError("other-evaluator layers never reuse an evaluation cache")
        if self.status == STATUS_COMPLETED and self.coverage == COVERAGE_COVERED:
            if self.layer in (SAST_LAYER, JUDGE_LAYER) and self.detected is None:
                raise LayerContractError("completed sast/judge layers require a bool detected")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evaluation_id": self.evaluation_id,
            "action_id": self.action_id,
            "sample_id": self.sample_id,
            "identity": self.identity,
            "stage": self.stage,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "layer": self.layer,
            "tool": self.tool,
            "coverage": self.coverage,
            "status": self.status,
            "available": self.available,
            "completed": self.completed,
            "reason_code": self.reason_code,
            "detected": self.detected,
            "verdict": self.verdict,
            "sources": self.sources,
            "evidence": self.evidence,
            "evaluation_cache_hit": self.evaluation_cache_hit,
            "cache_reason": self.cache_reason,
            "model_cache_hit": self.model_cache_hit,
            "semantics_pending": self.semantics_pending,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "LayerRecord":
        return cls(
            schema_version=payload.get("schema_version", LAYER_SCHEMA_VERSION),
            evaluation_id=payload["evaluation_id"],
            action_id=payload["action_id"],
            sample_id=payload["sample_id"],
            identity=dict(payload.get("identity") or {}),
            stage=payload["stage"],
            combination_id=payload["combination_id"],
            oracle_id=payload["oracle_id"],
            layer=payload["layer"],
            tool=payload["tool"],
            coverage=payload["coverage"],
            status=payload["status"],
            available=bool(payload["available"]),
            completed=bool(payload["completed"]),
            reason_code=payload.get("reason_code"),
            detected=payload.get("detected"),
            verdict=payload.get("verdict"),
            sources=dict(payload.get("sources") or {}),
            evidence=dict(payload.get("evidence") or {}),
            evaluation_cache_hit=bool(payload.get("evaluation_cache_hit", False)),
            cache_reason=payload.get("cache_reason", "cache_disabled"),
            model_cache_hit=payload.get("model_cache_hit"),
            semantics_pending=bool(payload.get("semantics_pending", False)),
        )


def coverage_for(combination_id: str, layer: str) -> str:
    if layer in (DYNAMIC_LAYER, REALISM_LAYER):
        return COVERAGE_COVERED if combination_id in OLD_FOUR else COVERAGE_NOT_COVERED
    if combination_id in OLD_FOUR + NEW_FIVE:
        return COVERAGE_COVERED
    raise LayerContractError(f"unknown combination: {combination_id!r}")


def not_covered_record(
    *,
    evaluation_id: str,
    action_id: str,
    sample_id: str,
    identity: dict[str, Any],
    stage: str,
    combination_id: str,
    oracle_id: str,
    layer: str,
    tool: str,
) -> LayerRecord:
    return LayerRecord(
        schema_version=LAYER_SCHEMA_VERSION,
        evaluation_id=evaluation_id,
        action_id=action_id,
        sample_id=sample_id,
        identity=identity,
        stage=stage,
        combination_id=combination_id,
        oracle_id=oracle_id,
        layer=layer,
        tool=tool,
        coverage=COVERAGE_NOT_COVERED,
        status=STATUS_SKIPPED,
        available=True,
        completed=False,
        reason_code="layer_not_covered",
        detected=None,
        verdict=None,
    )


__all__ = [
    "LAYER_SCHEMA_VERSION",
    "COVERAGE_COVERED",
    "COVERAGE_NOT_COVERED",
    "COVERAGES",
    "STATUS_COMPLETED",
    "STATUS_UNAVAILABLE",
    "STATUS_ERROR",
    "STATUS_INCOMPLETE",
    "STATUS_SKIPPED",
    "LAYER_STATUSES",
    "SAST_LAYER",
    "JUDGE_LAYER",
    "DYNAMIC_LAYER",
    "REALISM_LAYER",
    "LAYERS",
    "DYNAMIC_VERDICTS",
    "REALISM_VERDICTS",
    "OLD_FOUR",
    "NEW_FIVE",
    "LayerContractError",
    "LayerRecord",
    "coverage_for",
    "not_covered_record",
]
