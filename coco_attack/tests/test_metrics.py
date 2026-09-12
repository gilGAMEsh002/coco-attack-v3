"""Phase-04 pure metric checks (task book F6)."""

from __future__ import annotations

from coco_attack.evaluation.metrics import (
    asr_at_k,
    check_baseline_compatibility,
    evasion,
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


def test_evasion_gate_and_missing_tool() -> None:
    records = [_record("t1", 0, True)]
    gated = evasion(
        records, tool_name="semgrep", accessor=None, temperature=0.0, repeats=1,
        task_set="evaluation", sampling={},
    )
    assert gated.defined is False
    integrated = evasion(
        records, tool_name="semgrep", accessor=None, temperature=0.7, repeats=5,
        task_set="evaluation", sampling={},
    )
    assert integrated.defined is False
    assert "not integrated" in (integrated.reason or "")


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


def test_baseline_compatibility_rejects_mismatch() -> None:
    baseline = {
        "combination_id": "cwe078-0",
        "task_set": "evaluation",
        "split_manifest_sha256": "split-a",
        "task_snapshot_sha256": "snap-a",
        "prompt_form": "clean_fewshot_cot",
        "k": 5,
        "temperature": 0.7,
        "model": "gpt-4o",
        "repeats": 5,
        "data_contract": "bigcodebench-screened-v1",
        "cleaner_version": "cleaner-v3",
        "oracle_fingerprint_sha256": "abc",
    }
    ok, reasons = check_baseline_compatibility(baseline, dict(baseline))
    assert ok and not reasons
    candidate = {**baseline, "model": "gpt-5"}
    ok, reasons = check_baseline_compatibility(baseline, candidate)
    assert not ok
    assert any("model" in reason for reason in reasons)
    # Split revision and prompt form are part of compatibility.
    ok, reasons = check_baseline_compatibility(
        baseline, {**baseline, "split_manifest_sha256": "split-b"}
    )
    assert not ok and any("split_manifest_sha256" in reason for reason in reasons)


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
