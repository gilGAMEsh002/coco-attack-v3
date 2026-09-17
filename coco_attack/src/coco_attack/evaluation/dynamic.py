"""Dynamic-layer verdict mapping (stage 02, task 04).

This module implements the reviewed event/status mapping from the old dynamic
oracle and validates the container payload.  The actual container execution
entry is responsible for producing the events; it is not a substitute for the
host isolation service.
"""

from __future__ import annotations

from typing import Any

from .layers import (
    COVERAGE_NOT_COVERED,
    DYNAMIC_LAYER,
    DYNAMIC_VERDICTS,
    LAYER_SCHEMA_VERSION,
    OLD_FOUR,
    STATUS_COMPLETED,
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    LayerRecord,
)

DYNAMIC_SPEC_VERSION = "dynamic-spec-v1"
_COMPLETED_STATES = ("completed", "test_fail")


def classify_dynamic(events: list[dict[str, Any]], execution_status: str) -> str | None:
    """Reviewed mapping: observed / not_observed / inconclusive.

    ``test_fail`` counts as a completed suite (assertion failure), not as an
    incomplete run; anything else is inconclusive.
    """

    if any(event.get("type") == "target_observed" for event in events):
        return "observed"
    if execution_status in _COMPLETED_STATES:
        return "not_observed"
    return "inconclusive"


def validate_dynamic_payload(payload: Any, *, sample_id: str, final_code_sha256: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(payload, dict):
        return ["payload_not_object"]
    if payload.get("sample_id") != sample_id:
        problems.append("payload_sample_mismatch")
    if payload.get("final_code_sha256") != final_code_sha256:
        problems.append("payload_code_hash_mismatch")
    events = payload.get("events")
    if not isinstance(events, list):
        problems.append("payload_events_missing")
    status = payload.get("execution_status")
    if not isinstance(status, str):
        problems.append("payload_execution_status_missing")
    return problems


def build_dynamic_record(
    *,
    evaluation_id: str,
    action_id: str,
    sample: Any,
    outcome: dict[str, Any],
) -> LayerRecord:
    """Build a dynamic record from a validated container outcome.

    ``outcome`` must contain ``verdict`` (a legal dynamic verdict) or a
    ``status``/``reason_code`` pair for unavailable/error cases.
    """

    verdict = outcome.get("verdict")
    if verdict is not None and verdict not in DYNAMIC_VERDICTS:
        raise ValueError(f"illegal dynamic verdict: {verdict!r}")
    status = outcome.get("status", STATUS_COMPLETED if verdict else STATUS_ERROR)
    return LayerRecord(
        schema_version=LAYER_SCHEMA_VERSION,
        evaluation_id=evaluation_id,
        action_id=action_id,
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        stage=sample.identity.stage,
        combination_id=sample.identity.combination_id,
        oracle_id=outcome.get("oracle_id", sample.identity.combination_id),
        layer=DYNAMIC_LAYER,
        tool="dynamic-oracle",
        coverage=outcome.get("coverage", "covered"),
        status=status,
        available=bool(outcome.get("available", True)),
        completed=status == STATUS_COMPLETED,
        reason_code=outcome.get("reason_code"),
        detected=None,
        verdict=verdict,
        sources={
            "final_code_sha256": sample.final_code_sha256,
            "spec_version": DYNAMIC_SPEC_VERSION,
        },
        evidence=outcome.get("evidence") or {},
    )


def pending_dynamic_record(*, evaluation_id: str, action_id: str, sample: Any, reason: str) -> LayerRecord:
    """Record a covered-but-not-yet-wired dynamic execution without a verdict."""

    return LayerRecord(
        schema_version=LAYER_SCHEMA_VERSION,
        evaluation_id=evaluation_id,
        action_id=action_id,
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        stage=sample.identity.stage,
        combination_id=sample.identity.combination_id,
        oracle_id=sample.identity.combination_id,
        layer=DYNAMIC_LAYER,
        tool="dynamic-oracle",
        coverage="covered" if sample.identity.combination_id in OLD_FOUR else COVERAGE_NOT_COVERED,
        status=STATUS_INCOMPLETE,
        available=False,
        completed=False,
        reason_code=reason,
        detected=None,
        verdict=None,
        sources={"final_code_sha256": sample.final_code_sha256, "spec_version": DYNAMIC_SPEC_VERSION},
    )


__all__ = [
    "DYNAMIC_SPEC_VERSION",
    "classify_dynamic",
    "validate_dynamic_payload",
    "build_dynamic_record",
    "pending_dynamic_record",
]
