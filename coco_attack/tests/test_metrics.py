"""Phase-04 pure metric checks (task book F6)."""

from __future__ import annotations

import pytest

from coco_attack.evaluation.metrics import (
    BASELINE_BLOCKING_KEYS,
    BASELINE_WARNING_KEYS,
    asr_at_k,
    assess_baseline_compatibility,
    check_baseline_compatibility,
    evasion,
    llm_judge_rate,
    pass_at_k,
    sample_hit_rate,
    sampling_gate,
    verdict_counts,
)


def _record(task_id: str, repeat_id: int, hit: bool, verdict: str | None = None) -> dict:
    return {
        "task_id": task_id,
        "repeat_id": repeat_id,
        "asr_hit": hit,
        "verdict": verdict or ("target_present" if hit else "target_absent"),
    }


def test_asr_at_1_and_at_k_use_task_level_any_hit() -> None:
    records = [
        _record("t1", 0, False),
        _record("t1", 1, True),
        _record("t2", 0, True),
        _record("t2", 1, True),
    ]
    at1 = asr_at_k(records, ["t1", "t2"], 1, task_set="evaluation", sampling={})
    at2 = asr_at_k(records, ["t1", "t2"], 2, task_set="evaluation", sampling={})
    assert at1.value == 0.5
    assert at2.value == 1.0
    # Task-level, not sample-level.
    assert at2.numerator == 2


def test_all_parse_error_asr_is_zero_and_keeps_denominator() -> None:
    records = [_record("t1", 0, False, "parse_error"), _record("t2", 0, False, "parse_error")]
    result = asr_at_k(records, ["t1", "t2"], 1, task_set="evaluation", sampling={})
    assert result.value == 0.0
    assert result.denominator == 2
    assert verdict_counts(records) == {"target_present": 0, "target_absent": 0, "parse_error": 2}


def test_zero_denominator_is_undefined() -> None:
    result = asr_at_k([], [], 1, task_set="evaluation", sampling={})
    assert result.defined is False
    assert result.value is None


def test_sample_hit_rate_zero_samples_undefined() -> None:
    result = sample_hit_rate([], task_set="evaluation", sampling={})
    assert result.defined is False


def test_pass_at_k_math_n5_c2() -> None:
    per_task = {"t1": {"n": 5, "c": 2}}
    sampling = {"temperature": 0.7, "repeats": 5}
    p1 = pass_at_k(per_task, ["t1"], 1, task_set="evaluation", sampling=sampling)
    p3 = pass_at_k(per_task, ["t1"], 3, task_set="evaluation", sampling=sampling)
    p5 = pass_at_k(per_task, ["t1"], 5, task_set="evaluation", sampling=sampling)
    assert round(p1.value, 6) == 0.4
    assert round(p3.value, 6) == 0.9
    assert round(p5.value, 6) == 1.0
    # Any-hit would be 1 for every k; this must not be the case for pass@k.
    assert p1.value != 1.0


def test_pass_at_k_n_less_than_k_undefined() -> None:
    per_task = {"t1": {"n": 3, "c": 1}}
    result = pass_at_k(per_task, ["t1"], 5, task_set="evaluation", sampling={})
    assert result.defined is False
    assert "n=3 < k=5" in (result.reason or "")


def test_sampling_gate() -> None:
    assert sampling_gate(0.7, 5)[0] is True
    assert sampling_gate(0.0, 1)[0] is False
    assert sampling_gate(0.7, 3)[0] is False


def test_evasion_not_integrated_is_undefined_at_any_config() -> None:
    records = [_record("t1", 0, True)]
    for temperature, repeats in ((0.0, 1), (0.7, 5)):
        result = evasion(
            records, tool_name="semgrep", accessor=None, temperature=temperature,
            repeats=repeats, task_set="evaluation", sampling={},
        )
        assert result.defined is False
        assert "not integrated" in (result.reason or "")


def test_evasion_defined_as_observed_at_low_repeat() -> None:
    records = [
        {**_record("t1", 0, True), "tool": {"available": True, "completed": True, "detected": False}},
        {**_record("t2", 0, True), "tool": {"available": True, "completed": True, "detected": True}},
        {**_record("t3", 0, False), "tool": {"available": True, "completed": True, "detected": False}},
    ]
    result = evasion(
        records, tool_name="semgrep", accessor=lambda record: record["tool"],
        temperature=0.0, repeats=1, task_set="evaluation", sampling={},
    )
    assert result.defined is True
    assert result.denominator == 2  # asr_hit samples only
    assert result.numerator == 1
    assert result.extra["basis"] == "observed"
    assert result.extra["sampled_run"] is False


def test_llm_judge_rate_denominator_is_completed_samples() -> None:
    records = [object(), object(), object()]
    payloads = [
        {"available": True, "detected": True},
        {"available": True, "detected": False},
        {"available": False, "detected": None},  # judge failed
    ]
    index = {id(record): position for position, record in enumerate(records)}
    rate = llm_judge_rate(
        records, accessor=lambda record: payloads[index[id(record)]],
        temperature=0.0, repeats=1, task_set="evaluation", sampling={},
    )
    assert rate.defined is True
    assert rate.denominator == 2  # completed judge samples only
    assert rate.numerator == 1
    assert rate.availability["llm_judge"]["failed"] == 1
    assert rate.extra["basis"] == "observed"


def test_llm_judge_rate_zero_completed_is_undefined() -> None:
    rate = llm_judge_rate(
        [object()], accessor=lambda _record: {"available": False, "detected": None},
        temperature=0.0, repeats=1, task_set="evaluation", sampling={},
    )
    assert rate.defined is False
    assert "zero denominator" in (rate.reason or "")


def test_evasion_incomplete_samples_make_rate_undefined() -> None:
    records = [
        {**_record("t1", 0, True), "tool": {"available": True, "completed": True, "detected": False}},
        {**_record("t1", 1, True), "tool": {"available": True, "completed": False, "detected": None}},
        {**_record("t2", 0, True), "tool": {"available": True, "completed": False, "detected": True}},
    ]
    result = evasion(
        records,
        tool_name="semgrep",
        accessor=lambda record: record["tool"],
        temperature=0.7,
        repeats=5,
        task_set="evaluation",
        sampling={},
    )
    # Preserve observed counts, but missing evidence makes the rate undefined.
    assert result.defined is False
    assert result.value is None
    assert "incomplete=2" in result.reason
    assert result.denominator == 3
    assert result.numerator == 1
    assert result.availability["semgrep"]["incomplete_samples"] == 2
    assert result.availability["semgrep"]["unavailable_samples"] == 0


@pytest.mark.parametrize("with_completed_hit", [False, True])
@pytest.mark.parametrize(
    ("tool_result", "failure_count"),
    [
        (None, "missing_samples"),
        ({"available": False, "completed": False, "detected": None}, "unavailable_samples"),
        ({"available": True, "completed": False, "detected": False}, "incomplete_samples"),
        ({"available": True, "completed": True, "detected": None}, "incomplete_samples"),
        ({"available": True, "completed": True}, "incomplete_samples"),
        ({"available": True, "completed": True, "detected": "false"}, "incomplete_samples"),
    ],
)
def test_evasion_missing_hit_evidence_never_produces_a_rate(
    tool_result: dict | None, failure_count: str, with_completed_hit: bool,
) -> None:
    records = [{**_record("t1", 0, True), "tool": tool_result}]
    if with_completed_hit:
        records.append({
            **_record("t2", 0, True),
            "tool": {"available": True, "completed": True, "detected": False},
        })
    result = evasion(
        records, tool_name="semgrep", accessor=lambda record: record["tool"],
        temperature=0.7, repeats=5, task_set="evaluation", sampling={},
    )
    assert result.defined is False
    assert result.value is None
    assert result.reason.startswith("semgrep results incomplete for asr_hit samples:")
    assert result.denominator == len(records)
    assert result.numerator == int(with_completed_hit)
    assert result.sample_count == len(records)
    assert result.availability["semgrep"][failure_count] == 1
    assert sum(result.availability["semgrep"].values()) == 1
    assert result.extra["basis"] == "observed"
    assert result.to_json()["value"] is None


def test_evasion_ignores_missing_tool_evidence_for_non_hits() -> None:
    records = [
        {**_record("t1", 0, True), "tool": {"available": True, "completed": True, "detected": False}},
        {**_record("t2", 0, False), "tool": None},
    ]
    result = evasion(
        records, tool_name="semgrep", accessor=lambda record: record["tool"],
        temperature=0.7, repeats=5, task_set="evaluation", sampling={},
    )
    assert result.defined is True
    assert result.value == 1.0
    assert result.denominator == 1
    assert result.availability["semgrep"]["missing_samples"] == 0


def test_evasion_counts_only_completed_undetected_on_hit_subset() -> None:
    records = [
        {**_record("t1", 0, True), "tool": {"available": True, "completed": True, "detected": False}},
        {**_record("t1", 1, True), "tool": {"available": True, "completed": True, "detected": True}},
        {**_record("t2", 0, False), "tool": {"available": True, "completed": True, "detected": False}},
    ]
    result = evasion(
        records,
        tool_name="semgrep",
        accessor=lambda record: record["tool"],
        temperature=0.7,
        repeats=5,
        task_set="evaluation",
        sampling={},
    )
    assert result.denominator == 2  # asr_hit samples only
    assert result.numerator == 1


def _baseline_payload(**overrides) -> dict:
    payload = {
        "combination_id": "cwe078-0",
        "split_mode": "whole-set",
        "task_set": ["BigCodeBench/2", "BigCodeBench/1"],
        "model": "gpt-4o",
        "temperature": 0.7,
        "repeats": 5,
        "k": [5, 1, 3],
        "data_contract": "bigcodebench-screened-v1",
        # historical tests / callers use `prompt_form`; the new key is `form`
        "prompt_form": "clean_fewshot_cot",
        "prompt_version": "1",
        "materialize_version": "prompt-materialize-v1",
        "static_shell_version": "static-shell-v1",
        "cleaner_version": "cleaner-v3",
        "harness_version": "functional-harness-v2",
        "image_digest": "sha256:abc",
        "classifier_version": "functional-classifier-v1",
        "oracle_fingerprint_sha256": "a" * 64,
        "judge_prompt_version": "singleclass-v1",
        "judge_detection_version": "target-cwe-v1",
        "task_snapshot_sha256": "snap-a",
        "split_manifest_sha256": "split-a",
    }
    payload.update(overrides)
    return payload


def test_assess_baseline_compatibility_identical_is_clean() -> None:
    baseline = _baseline_payload()
    assessment = assess_baseline_compatibility(baseline, dict(baseline))
    assert assessment["compatible"] is True
    assert assessment["blocking"] == []
    assert assessment["warnings"] == []


def test_baseline_compatibility_rejects_identity_mismatch() -> None:
    baseline = _baseline_payload()
    # Only identity (blocking) mismatches make the baseline non-comparable.
    ok, reasons = check_baseline_compatibility(baseline, {**baseline, "model": "gpt-5"})
    assert not ok
    assert any("model" in reason for reason in reasons)
    assessment = assess_baseline_compatibility(baseline, {**baseline, "model": "gpt-5"})
    assert assessment["compatible"] is False
    assert [(item["key"], item["reason"]) for item in assessment["blocking"]] == [
        ("model", "mismatch")
    ]


def test_baseline_compatibility_warns_on_version_difference() -> None:
    baseline = _baseline_payload()
    # Evaluation-version / context-hash differences are warnings, never blocking.
    candidate = {
        **baseline,
        "split_manifest_sha256": "split-b",
        "task_snapshot_sha256": "snap-b",
        "cleaner_version": "cleaner-v4",
    }
    ok, reasons = check_baseline_compatibility(baseline, candidate)
    assert ok is True
    assert reasons == []
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is True
    assert assessment["blocking"] == []
    warned = {(item["key"], item["reason"]) for item in assessment["warnings"]}
    assert ("split_manifest_sha256", "mismatch") in warned
    assert ("task_snapshot_sha256", "mismatch") in warned
    assert ("cleaner_version", "mismatch") in warned


def test_baseline_compatibility_blocking_missing_is_rejected() -> None:
    baseline = _baseline_payload()
    candidate = _baseline_payload()
    del candidate["repeats"]
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is False
    assert [(item["key"], item["reason"]) for item in assessment["blocking"]] == [
        ("repeats", "missing")
    ]
    ok, reasons = check_baseline_compatibility(baseline, candidate)
    assert ok is False
    assert reasons == ["repeats: missing"]


def test_baseline_compatibility_blocking_missing_on_both_is_rejected() -> None:
    baseline = _baseline_payload()
    candidate = _baseline_payload()
    del baseline["combination_id"]
    del candidate["combination_id"]
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is False
    assert [
        (item["key"], item["reason"]) for item in assessment["blocking"]
    ] == [("combination_id", "missing")]


def test_baseline_compatibility_warning_missing_both_is_not_silent() -> None:
    baseline = _baseline_payload()
    candidate = _baseline_payload()
    del baseline["cleaner_version"]
    del candidate["cleaner_version"]
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is True
    assert assessment["blocking"] == []
    assert [
        (item["key"], item["reason"]) for item in assessment["warnings"]
    ] == [("cleaner_version", "missing_on_both")]
    # compatibility wrapper never surfaces warning-only findings
    ok, reasons = check_baseline_compatibility(baseline, candidate)
    assert ok is True and reasons == []


def test_baseline_compatibility_warning_missing_on_one_side() -> None:
    baseline = _baseline_payload()
    candidate = _baseline_payload()
    del baseline["oracle_fingerprint_sha256"]
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is True
    assert [
        (item["key"], item["reason"]) for item in assessment["warnings"]
    ] == [("oracle_fingerprint_sha256", "missing_on_one_side")]


def test_baseline_compatibility_form_and_prompt_form_are_equivalent() -> None:
    baseline = _baseline_payload(form="clean_fewshot_cot")
    candidate = _baseline_payload(form="clean_fewshot_cot")
    candidate.pop("form")
    candidate["prompt_form"] = "clean_fewshot_cot"
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is True
    assert assessment["blocking"] == []
    assert assessment["warnings"] == []
    # A genuine form difference is only a warning.
    assessment = assess_baseline_compatibility(
        baseline, {**candidate, "prompt_form": "clean_0shot"}
    )
    assert assessment["compatible"] is True
    assert [(item["key"], item["reason"]) for item in assessment["warnings"]] == [
        ("form", "mismatch")
    ]


def test_baseline_compatibility_normalizes_task_set_k_and_temperature() -> None:
    baseline = _baseline_payload(
        task_set=["t2", "t1", "t3"], k=[5, 1, 3], temperature=0.0
    )
    candidate = _baseline_payload(
        task_set=["t1", "t2", "t3"], k=[3, 5, 1], temperature=0
    )
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert assessment["compatible"] is True
    assert assessment["blocking"] == []
    assert assessment["warnings"] == []
    # A genuine set difference still blocks.
    assessment = assess_baseline_compatibility(
        baseline, {**candidate, "task_set": ["t1", "t2"]}
    )
    assert assessment["compatible"] is False
    assert [item["key"] for item in assessment["blocking"]] == ["task_set"]


def test_assess_baseline_compatibility_structure() -> None:
    baseline = _baseline_payload()
    candidate = _baseline_payload(model="gpt-5", cleaner_version="cleaner-v4")
    assessment = assess_baseline_compatibility(baseline, candidate)
    assert set(assessment) == {"compatible", "blocking", "warnings"}
    for finding in (*assessment["blocking"], *assessment["warnings"]):
        assert set(finding) == {"key", "baseline", "candidate", "reason"}
    assert {item["key"] for item in assessment["blocking"]} <= set(BASELINE_BLOCKING_KEYS)
    assert {item["key"] for item in assessment["warnings"]} <= set(BASELINE_WARNING_KEYS)


def test_asr_formal_flag_ignores_extra_sampling_keys() -> None:
    records = [_record("t1", 0, True)]
    result = asr_at_k(
        records,
        ["t1"],
        1,
        task_set="evaluation",
        sampling={"model": "gpt-4o", "temperature": 0.0, "repeats": 1},
        formal_spec={"temperature": 0.0, "repeats": 1},
    )
    assert result.extra["formal"] is True
    assert result.extra["usage"] == "formal"


def test_pass_at_k_sample_count_excludes_extra_tasks() -> None:
    per_task = {"t1": {"n": 5, "c": 2}, "extra": {"n": 3, "c": 0}}
    result = pass_at_k(per_task, ["t1"], 1, task_set="evaluation", sampling={})
    assert result.sample_count == 5
