"""Functional test result contracts and classification (stage 02, task 03).

The functional layer consumes a container-side payload produced by
``docker/evaluator/functional_runner.py`` and turns it into a strict
``FunctionalResult``.  It never infers a functional verdict from the outer
execution envelope, exit code, entry presence or syntax alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..assets.artifacts import canonical_json_bytes, sha256_bytes

FUNCTIONAL_SCHEMA_VERSION = "functional-result-v1"
FUNCTIONAL_PAYLOAD_SCHEMA = "functional-payload-v1"
HARNESS_VERSION = "functional-harness-v3"

OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_ERROR = "error"
OUTCOME_INCOMPLETE = "incomplete"
FUNCTIONAL_OUTCOMES = (
    OUTCOME_PASSED,
    OUTCOME_FAILED,
    OUTCOME_UNAVAILABLE,
    OUTCOME_ERROR,
    OUTCOME_INCOMPLETE,
)


class FunctionalContractError(ValueError):
    pass


@dataclass(frozen=True)
class FunctionalResult:
    sample_id: str
    identity: dict[str, Any]
    combination_id: str
    oracle_id: str
    attempt_id: str | None
    outcome: str
    passed: bool | None
    reason: str | None
    tests_discovered: int
    tests_run: int
    failures: int
    errors: int
    skipped: int
    expected_failures: int
    unexpected_successes: int
    suite_completed: bool
    failure_stage: str | None
    test_details: tuple[dict[str, Any], ...]
    execution: dict[str, Any]
    fingerprint: dict[str, Any]
    fingerprint_sha256: str
    payload_sha256: str | None
    cache_eligible: bool
    accounting_id: str | None = None
    duration_seconds: float | None = None
    cost: dict[str, Any] = field(default_factory=dict)
    reuse_source: str | None = None
    harness_version: str = HARNESS_VERSION
    schema_version: str = FUNCTIONAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.outcome not in FUNCTIONAL_OUTCOMES:
            raise FunctionalContractError(f"invalid outcome: {self.outcome!r}")
        if self.passed not in (True, False, None):
            raise FunctionalContractError("passed must be a strict bool or null")
        for name in (
            "tests_discovered",
            "tests_run",
            "failures",
            "errors",
            "skipped",
            "expected_failures",
            "unexpected_successes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FunctionalContractError(f"{name} must be a non-negative integer")
        if self.passed is True and self.outcome != OUTCOME_PASSED:
            raise FunctionalContractError("passed=true requires outcome=passed")
        if self.outcome == OUTCOME_PASSED and self.passed is not True:
            raise FunctionalContractError("outcome=passed requires passed=true")

    @property
    def cache_key(self) -> tuple[str, str]:
        return self.sample_id, self.fingerprint_sha256

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sample_id": self.sample_id,
            "identity": self.identity,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "attempt_id": self.attempt_id,
            "outcome": self.outcome,
            "passed": self.passed,
            "reason": self.reason,
            "tests_discovered": self.tests_discovered,
            "tests_run": self.tests_run,
            "failures": self.failures,
            "errors": self.errors,
            "skipped": self.skipped,
            "expected_failures": self.expected_failures,
            "unexpected_successes": self.unexpected_successes,
            "suite_completed": self.suite_completed,
            "failure_stage": self.failure_stage,
            "test_details": list(self.test_details),
            "execution": self.execution,
            "fingerprint": self.fingerprint,
            "fingerprint_sha256": self.fingerprint_sha256,
            "payload_sha256": self.payload_sha256,
            "cache_eligible": self.cache_eligible,
            "accounting_id": self.accounting_id,
            "duration_seconds": self.duration_seconds,
            "cost": self.cost,
            "reuse_source": self.reuse_source,
            "harness_version": self.harness_version,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "FunctionalResult":
        return cls(
            sample_id=payload["sample_id"],
            identity=dict(payload["identity"]),
            combination_id=payload["combination_id"],
            oracle_id=payload["oracle_id"],
            attempt_id=payload.get("attempt_id"),
            outcome=payload["outcome"],
            passed=payload["passed"],
            reason=payload.get("reason"),
            tests_discovered=int(payload["tests_discovered"]),
            tests_run=int(payload["tests_run"]),
            failures=int(payload["failures"]),
            errors=int(payload["errors"]),
            skipped=int(payload["skipped"]),
            expected_failures=int(payload["expected_failures"]),
            unexpected_successes=int(payload["unexpected_successes"]),
            suite_completed=bool(payload["suite_completed"]),
            failure_stage=payload.get("failure_stage"),
            test_details=tuple(payload.get("test_details") or ()),
            execution=dict(payload.get("execution") or {}),
            fingerprint=dict(payload.get("fingerprint") or {}),
            fingerprint_sha256=payload["fingerprint_sha256"],
            payload_sha256=payload.get("payload_sha256"),
            cache_eligible=bool(payload.get("cache_eligible", False)),
            accounting_id=payload.get("accounting_id"),
            duration_seconds=payload.get("duration_seconds"),
            cost=dict(payload.get("cost") or {}),
            reuse_source=payload.get("reuse_source"),
            harness_version=payload.get("harness_version", HARNESS_VERSION),
        )


def validate_payload(
    payload: Any,
    *,
    sample_id: str,
    attempt_id: str,
    code_sha256: str,
    tests_sha256: str,
    entry_point: str,
) -> list[str]:
    """Return a list of structural/identity problems; empty means valid."""

    problems: list[str] = []
    if not isinstance(payload, dict):
        return ["payload_not_object"]
    if payload.get("functional_schema") != FUNCTIONAL_PAYLOAD_SCHEMA:
        problems.append("payload_schema_mismatch")
    if payload.get("harness_version") != HARNESS_VERSION:
        problems.append("payload_harness_version_mismatch")
    if payload.get("sample_id") != sample_id:
        problems.append("payload_sample_mismatch")
    if payload.get("attempt_id") != attempt_id:
        problems.append("payload_attempt_mismatch")
    if payload.get("code_sha256") != code_sha256:
        problems.append("payload_code_hash_mismatch")
    if payload.get("tests_sha256") != tests_sha256:
        problems.append("payload_tests_hash_mismatch")
    if payload.get("entry_point") != entry_point:
        problems.append("payload_entry_mismatch")
    load = payload.get("load")
    run = payload.get("run")
    if not isinstance(load, dict):
        problems.append("payload_load_missing")
    if not isinstance(run, dict):
        problems.append("payload_run_missing")
    if isinstance(load, dict):
        for name in ("solution_compiled", "entry_present", "tests_compiled"):
            if not isinstance(load.get(name), bool):
                problems.append(f"payload_{name}_invalid")
    if isinstance(load, dict) and isinstance(run, dict):
        for name in (
            "tests_run", "failures", "errors",
            "skipped", "expected_failures", "unexpected_successes",
        ):
            value = run.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                problems.append(f"payload_{name}_invalid")
        discovered = load.get("tests_discovered")
        if isinstance(discovered, bool) or not isinstance(discovered, int) or discovered < 0:
            problems.append("payload_tests_discovered_invalid")
        if not isinstance(run.get("suite_completed"), bool):
            problems.append("payload_suite_completed_invalid")
        if not isinstance(run.get("candidate_timeout", False), bool):
            problems.append("payload_candidate_timeout_invalid")
        failure_stage = run.get("failure_stage")
        if failure_stage is not None and not isinstance(failure_stage, str):
            problems.append("payload_failure_stage_invalid")
    return problems


def classify_payload(
    payload: dict[str, Any] | None,
    *,
    validation_problems: list[str],
    execution_available: bool,
    execution_timed_out: bool,
    execution_incomplete: bool,
    declared_modules: tuple[str, ...] = (),
) -> tuple[str, bool | None, str | None, bool]:
    """Return ``(outcome, passed, reason, cache_eligible)``.

    ``execution_incomplete`` means the outer layer could not obtain a trustworthy
    functional payload (outer timeout/OOM/kill without a complete inner result).
    """

    if not execution_available:
        return OUTCOME_UNAVAILABLE, None, "execution_unavailable", False
    if execution_incomplete or payload is None:
        return OUTCOME_INCOMPLETE, None, "no_trustworthy_functional_payload", False
    if validation_problems:
        return OUTCOME_ERROR, None, f"payload_invalid:{validation_problems[0]}", False

    load = payload.get("load") or {}
    run = payload.get("run") or {}
    discovered = int(load.get("tests_discovered", 0))
    stage = run.get("failure_stage")
    if not load.get("solution_compiled", False):
        return OUTCOME_FAILED, False, "candidate_syntax_error", False
    if stage == "exec":
        # The candidate failed to load/execute.  A missing module the task
        # declares is an environment gap (unavailable); a missing module that is
        # not declared is a candidate failure.  With no declared dependency
        # information we cannot attribute it, so keep it indeterminate rather
        # than choosing a favorable side.
        missing = load.get("missing_module")
        declared_roots = {str(name).split(".")[0] for name in declared_modules}
        if isinstance(missing, str) and missing.split(".")[0] in declared_roots:
            return OUTCOME_UNAVAILABLE, None, f"declared_dependency_missing:{missing}", False
        if missing is not None and declared_roots:
            return OUTCOME_FAILED, False, f"candidate_load_error:{load.get('loader_error')}", False
        return (
            OUTCOME_ERROR,
            None,
            f"import_error_unattributable:{load.get('loader_error')}",
            False,
        )
    if (
        not load.get("tests_compiled", True)
        or load.get("loader_error")
        or stage in ("load", "tests_compile")
    ):
        return OUTCOME_ERROR, None, f"tests_load_error:{load.get('loader_error') or load.get('tests_error')}", False
    if not load.get("entry_present", False):
        return OUTCOME_FAILED, False, "entry_missing", False
    if run.get("candidate_timeout"):
        return OUTCOME_FAILED, False, "candidate_timeout", False
    tests_run = int(run.get("tests_run", 0))
    failures = int(run.get("failures", 0))
    errors = int(run.get("errors", 0))
    skipped = int(run.get("skipped", 0))
    expected_failures = int(run.get("expected_failures", 0))
    unexpected_successes = int(run.get("unexpected_successes", 0))
    suite_completed = bool(run.get("suite_completed"))

    if discovered == 0:
        return OUTCOME_ERROR, None, "zero_tests_discovered", False
    if not suite_completed:
        return OUTCOME_INCOMPLETE, None, f"suite_not_completed:{stage or 'run'}", False
    if skipped or expected_failures or unexpected_successes:
        return (
            OUTCOME_ERROR,
            None,
            f"unverified_test_outcomes:skipped={skipped},expectedFailure={expected_failures},unexpectedSuccess={unexpected_successes}",
            False,
        )
    if errors or failures:
        return OUTCOME_FAILED, False, f"tests_failed:failures={failures},errors={errors}", True
    if tests_run == 0:
        return OUTCOME_ERROR, None, "zero_tests_run", False
    return OUTCOME_PASSED, True, None, True


def fingerprint_sha256(fingerprint: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(fingerprint))


def deterministic_input_outcome(
    generation_status: str | None,
    final_code: str,
) -> tuple[str, bool, str, bool] | None:
    """Handle generation failure / empty code without starting a container."""

    if generation_status is not None and generation_status != "success":
        return OUTCOME_FAILED, False, f"generation_{generation_status}", False
    if not final_code.strip():
        return OUTCOME_FAILED, False, "empty_final_code", False
    return None


__all__ = [
    "FUNCTIONAL_SCHEMA_VERSION",
    "FUNCTIONAL_PAYLOAD_SCHEMA",
    "HARNESS_VERSION",
    "FUNCTIONAL_OUTCOMES",
    "OUTCOME_PASSED",
    "OUTCOME_FAILED",
    "OUTCOME_UNAVAILABLE",
    "OUTCOME_ERROR",
    "OUTCOME_INCOMPLETE",
    "FunctionalContractError",
    "FunctionalResult",
    "validate_payload",
    "classify_payload",
    "fingerprint_sha256",
    "deterministic_input_outcome",
]
