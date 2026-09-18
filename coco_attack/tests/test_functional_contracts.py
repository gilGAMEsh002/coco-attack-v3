"""Functional result classification tests (stage 02, task 03)."""

from __future__ import annotations

import pytest

from coco_attack.evaluation.functional import (
    OUTCOME_ERROR,
    OUTCOME_FAILED,
    OUTCOME_INCOMPLETE,
    OUTCOME_PASSED,
    OUTCOME_UNAVAILABLE,
    FunctionalContractError,
    FunctionalResult,
    classify_payload,
    deterministic_input_outcome,
    validate_payload,
)


def _payload(**overrides) -> dict:
    payload = {
        "functional_schema": "functional-payload-v1",
        "harness_version": "functional-harness-v5",
        "sample_id": "s1",
        "attempt_id": "a1",
        "entry_point": "task_func",
        "code_sha256": "c" * 64,
        "tests_sha256": "t" * 64,
        "load": {
            "solution_compiled": True,
            "solution_error": None,
            "entry_present": True,
            "tests_compiled": True,
            "tests_error": None,
            "loader_error": None,
            "missing_module": None,
            "tests_discovered": 1,
        },
        "run": {
            "tests_run": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
            "suite_completed": True,
            "failure_stage": None,
            "candidate_timeout": False,
        },
        "test_details": [],
    }
    for key, value in overrides.items():
        payload[key] = value
    return payload


def _classify(payload, problems=None, **kwargs):
    return classify_payload(
        payload,
        validation_problems=problems or [],
        execution_available=kwargs.get("execution_available", True),
        execution_timed_out=kwargs.get("execution_timed_out", False),
        execution_incomplete=kwargs.get("execution_incomplete", False),
        declared_modules=kwargs.get("declared_modules", ()),
    )


def test_classify_candidate_load_error_and_declared_dependency() -> None:
    payload = _payload()
    payload["run"]["failure_stage"] = "exec"
    payload["load"]["loader_error"] = "ModuleNotFoundError: No module named 'numpy'"
    payload["load"]["missing_module"] = "numpy"
    payload["load"]["entry_present"] = False

    outcome, passed, reason, eligible = _classify(payload, declared_modules=("os", "json"))
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason.startswith("candidate_load_error")

    outcome, passed, reason, eligible = _classify(payload, declared_modules=("numpy",))
    assert (outcome, passed, eligible) == (OUTCOME_UNAVAILABLE, None, False)
    assert reason.startswith("declared_dependency_missing")

    # Without declared dependencies the exec failure is still candidate-side and
    # is counted as a failed functional result (D04, 2026-09-18).
    outcome, passed, reason, eligible = _classify(payload)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason.startswith("candidate_load_error")


def test_classify_candidate_exec_name_error_is_failed() -> None:
    # A candidate-side NameError is a failed result, not an indeterminate error,
    # so it stays in the denominator instead of making pass@k undefined.
    payload = _payload()
    payload["run"]["failure_stage"] = "exec"
    payload["load"]["loader_error"] = "NameError: name 'x' is not defined"
    payload["load"]["entry_present"] = False
    outcome, passed, reason, eligible = _classify(payload)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason.startswith("candidate_load_error")


def test_classify_candidate_timeout_is_failed() -> None:
    payload = _payload()
    payload["run"]["candidate_timeout"] = True
    payload["run"]["suite_completed"] = False
    payload["run"]["failure_stage"] = "run"
    outcome, passed, reason, eligible = _classify(payload)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason == "candidate_timeout"


def test_validate_payload_rejects_harness_version_mismatch() -> None:
    payload = _payload()
    payload["harness_version"] = "functional-harness-v1"
    problems = validate_payload(
        payload, sample_id="s1", attempt_id="a1", code_sha256="c" * 64,
        tests_sha256="t" * 64, entry_point="task_func",
    )
    assert "payload_harness_version_mismatch" in problems


def test_validate_payload_detects_identity_and_field_errors() -> None:
    good = _payload()
    assert validate_payload(
        good, sample_id="s1", attempt_id="a1", code_sha256="c" * 64,
        tests_sha256="t" * 64, entry_point="task_func",
    ) == []
    bad = _payload(sample_id="other")
    assert "payload_sample_mismatch" in validate_payload(
        bad, sample_id="s1", attempt_id="a1", code_sha256="c" * 64,
        tests_sha256="t" * 64, entry_point="task_func",
    )
    assert validate_payload(None, sample_id="s1", attempt_id="a1", code_sha256="c" * 64,
                            tests_sha256="t" * 64, entry_point="task_func") == ["payload_not_object"]


def test_classify_pass_and_fail() -> None:
    outcome, passed, reason, eligible = _classify(_payload())
    assert (outcome, passed, eligible) == (OUTCOME_PASSED, True, True)
    failed = _payload()
    failed["run"]["failures"] = 1
    failed["run"]["tests_run"] = 1
    outcome, passed, reason, eligible = _classify(failed)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, True)


def test_classify_candidate_errors_are_failed_not_unavailable() -> None:
    syntax = _payload()
    syntax["load"]["solution_compiled"] = False
    syntax["load"]["solution_error"] = "bad syntax"
    outcome, passed, reason, eligible = _classify(syntax)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason == "candidate_syntax_error"

    missing_entry = _payload()
    missing_entry["load"]["entry_present"] = False
    outcome, passed, reason, eligible = _classify(missing_entry)
    assert (outcome, passed, eligible) == (OUTCOME_FAILED, False, False)
    assert reason == "entry_missing"


def test_classify_harness_and_unverified_are_not_cacheable() -> None:
    harness_error = _payload()
    harness_error["load"]["loader_error"] = "TestCases_missing"
    outcome, passed, _reason, eligible = _classify(harness_error)
    assert (outcome, passed, eligible) == (OUTCOME_ERROR, None, False)

    zero = _payload()
    zero["load"]["tests_discovered"] = 0
    zero["run"]["tests_run"] = 0
    outcome, passed, _reason, eligible = _classify(zero)
    assert (outcome, passed, eligible) == (OUTCOME_ERROR, None, False)

    skipped = _payload()
    skipped["run"]["skipped"] = 1
    outcome, passed, _reason, eligible = _classify(skipped)
    assert (outcome, passed, eligible) == (OUTCOME_ERROR, None, False)


def test_classify_incomplete_and_unavailable() -> None:
    outcome, passed, _reason, eligible = _classify(None, execution_incomplete=True)
    assert (outcome, passed, eligible) == (OUTCOME_INCOMPLETE, None, False)
    outcome, passed, _reason, eligible = _classify(_payload(), execution_available=False)
    assert (outcome, passed, eligible) == (OUTCOME_UNAVAILABLE, None, False)
    not_completed = _payload()
    not_completed["run"]["suite_completed"] = False
    outcome, passed, _reason, eligible = _classify(not_completed)
    assert (outcome, passed, eligible) == (OUTCOME_INCOMPLETE, None, False)


def test_classify_rejects_invalid_payload() -> None:
    outcome, passed, reason, eligible = _classify(_payload(), problems=["payload_run_missing"])
    assert (outcome, passed, eligible) == (OUTCOME_ERROR, None, False)
    assert reason.startswith("payload_invalid")


def test_deterministic_input_outcome() -> None:
    assert deterministic_input_outcome("success", "def f():\n    return 1\n") is None
    assert deterministic_input_outcome("error", "")[1] is False
    assert deterministic_input_outcome("success", "   ")[2] == "empty_final_code"


def test_functional_result_strict_booleans() -> None:
    with pytest.raises(FunctionalContractError):
        FunctionalResult(
            sample_id="s", identity={}, combination_id="c", oracle_id="c", attempt_id=None,
            outcome=OUTCOME_PASSED, passed=None, reason=None,
            tests_discovered=1, tests_run=1, failures=0, errors=0, skipped=0,
            expected_failures=0, unexpected_successes=0, suite_completed=True,
            failure_stage=None, test_details=(), execution={}, fingerprint={},
            fingerprint_sha256="f" * 64, payload_sha256=None, cache_eligible=True,
        )
    result = FunctionalResult(
        sample_id="s", identity={}, combination_id="c", oracle_id="c", attempt_id=None,
        outcome=OUTCOME_FAILED, passed=False, reason="tests_failed",
        tests_discovered=1, tests_run=1, failures=1, errors=0, skipped=0,
        expected_failures=0, unexpected_successes=0, suite_completed=True,
        failure_stage=None, test_details=(), execution={}, fingerprint={},
        fingerprint_sha256="f" * 64, payload_sha256=None, cache_eligible=True,
    )
    assert FunctionalResult.from_json(result.to_json()).passed is False
