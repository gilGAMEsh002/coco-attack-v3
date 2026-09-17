"""Batch-3 blocker fixes: corruption handling, judge accounting, fixed-set judge rate."""

from __future__ import annotations

import json

import pytest

from coco_attack.evaluation.functional import FunctionalResult
from coco_attack.evaluation.layers import LayerRecord
from coco_attack.evaluation.run_functional import (
    FunctionalInputError,
    _append_jsonl as _append_functional_jsonl,
    _read_results as _read_functional_results,
)
from coco_attack.evaluation.run_other import (
    EvaluatorsConfig,
    _append_jsonl,
    _evaluator_metrics,
    _judge_accounting,
    _read_jsonl,
)
from coco_attack.evaluation.judge import JudgeConfig
from coco_attack.evaluation.reporting import collect_costs
from coco_attack.runtime.ledger import EVENT_EXECUTION_RECORDED, EVENT_RESPONSE_RECEIVED, Ledger


def _functional_row(sample_id: str) -> dict:
    return FunctionalResult(
        sample_id=sample_id,
        identity={},
        combination_id="c",
        oracle_id="o",
        attempt_id="a",
        outcome="failed",
        passed=False,
        reason="x",
        tests_discovered=1,
        tests_run=1,
        failures=1,
        errors=0,
        skipped=0,
        expected_failures=0,
        unexpected_successes=0,
        suite_completed=True,
        failure_stage=None,
        test_details=(),
        execution={},
        fingerprint={},
        fingerprint_sha256="f" * 64,
        payload_sha256=None,
        cache_eligible=True,
        accounting_id=f"local:{sample_id}",
    ).to_json()


def _functional_row_bytes(sample_id: str) -> bytes:
    return json.dumps(_functional_row(sample_id)).encode("utf-8") + b"\n"


def test_read_functional_results_rejects_midfile_corruption(tmp_path) -> None:
    path = tmp_path / "functional_results.jsonl"
    path.write_bytes(_functional_row_bytes("old") + b"not json\n" + _functional_row_bytes("new"))
    with pytest.raises(FunctionalInputError):
        _read_functional_results(path)


def test_read_functional_results_tolerates_a_torn_tail(tmp_path) -> None:
    path = tmp_path / "functional_results.jsonl"
    path.write_bytes(_functional_row_bytes("old") + b'{"sample_id":"torn"')
    results = _read_functional_results(path)
    assert [result.sample_id for result in results] == ["old"]
    assert (tmp_path / "functional_results.jsonl.tail").read_bytes() == b'{"sample_id":"torn"'


def test_read_functional_results_repairs_torn_tail_before_append(tmp_path) -> None:
    path = tmp_path / "functional_results.jsonl"
    _append_functional_jsonl(path, _functional_row("a"))
    with open(path, "ab") as handle:
        handle.write(b'{"sample_id":"torn"')
    assert [result.sample_id for result in _read_functional_results(path)] == ["a"]
    assert (tmp_path / "functional_results.jsonl.tail").read_bytes() == b'{"sample_id":"torn"'
    _append_functional_jsonl(path, _functional_row("c"))
    assert [result.sample_id for result in _read_functional_results(path)] == ["a", "c"]


def test_read_jsonl_rejects_midfile_corruption(tmp_path) -> None:
    path = tmp_path / "layers.jsonl"
    path.write_bytes(b'{"a": 1}\nnot json\n{"b": 2}\n')
    with pytest.raises(FunctionalInputError):
        _read_jsonl(path)


def test_read_jsonl_tolerates_a_torn_tail(tmp_path) -> None:
    path = tmp_path / "layers.jsonl"
    path.write_bytes(b'{"a": 1}\n{"b": 2')
    assert _read_jsonl(path) == [{"a": 1}]
    assert (tmp_path / "layers.jsonl.tail").read_bytes() == b'{"b": 2'


def test_read_jsonl_repairs_torn_tail_before_append(tmp_path) -> None:
    path = tmp_path / "layers.jsonl"
    _append_jsonl(path, {"a": 1})
    with open(path, "ab") as handle:
        handle.write(b'{"b": 2, "event_typ')
    assert _read_jsonl(path) == [{"a": 1}]
    assert (tmp_path / "layers.jsonl.tail").read_bytes().startswith(b'{"b": 2')
    _append_jsonl(path, {"c": 3})
    assert _read_jsonl(path) == [{"a": 1}, {"c": 3}]


def _judge_cfg(*, priced: bool = True) -> EvaluatorsConfig:
    return EvaluatorsConfig(
        combination_id="cwe078-0", oracle_id="cwe078-0", stage="search",
        judge=JudgeConfig(
            source="mock", model="m", temperature=0.0, max_tokens=8, request_timeout=1.0,
            price_input_per_1k=1.0 if priced else None,
            price_output_per_1k=2.0 if priced else None,
        ),
    )


def test_judge_cache_recovery_does_not_change_report_totals(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = _judge_cfg()
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 100, "completion_tokens": 50}, "model_cache_hit": False},
        physical_attempt_id="p1",
    )
    judge = collect_costs(tmp_path)["roles"]["judge"]
    assert abs(judge["cost"]["known"] - 0.2) < 1e-9
    assert judge["usage"]["prompt_tokens"] == 100

    cache = {"usage": {}, "model_cache_hit": True}
    for _ in range(2):
        _judge_accounting(
            ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
            info=cache, physical_attempt_id="cache",
        )
    judge = collect_costs(tmp_path)["roles"]["judge"]
    assert abs(judge["cost"]["known"] - 0.2) < 1e-9  # no double counting
    assert judge["usage"]["prompt_tokens"] == 100
    assert judge["usage"]["completion_tokens"] == 50


def test_victim_cache_reuse_is_not_double_counted(tmp_path) -> None:
    gen_dir = tmp_path / "generation"
    gen_dir.mkdir()
    ledger = Ledger(gen_dir / "ledger.jsonl")
    ledger.append(
        EVENT_RESPONSE_RECEIVED,
        sample_id="s1",
        request_attempt_id="real",
        payload={
            "content": "x",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            "cost": {"basis": "estimated", "amount": 0.2, "currency": "USD"},
        },
    )
    # A cache-hit reuse copies the first response's usage/cost but must not be
    # counted again by the report aggregator.
    ledger.append(
        EVENT_RESPONSE_RECEIVED,
        sample_id="s1",
        request_attempt_id="cache",
        payload={
            "content": "x",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            "cost": {
                "basis": "estimated",
                "amount": 0.2,
                "currency": "USD",
                "reused_from_first_response": True,
            },
        },
    )
    victim = collect_costs(tmp_path)["roles"]["victim"]
    assert victim["events"] == 1
    assert abs(victim["cost"]["known"] - 0.2) < 1e-9
    assert victim["usage"]["prompt_tokens"] == 100
    assert victim["usage"]["completion_tokens"] == 50


def test_judge_cache_lost_then_real_request_adds_cost(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = _judge_cfg()
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 100, "completion_tokens": 50}, "model_cache_hit": False},
        physical_attempt_id="p1",
    )
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 10, "completion_tokens": 5}, "model_cache_hit": False},
        physical_attempt_id="p2",
    )
    judge = collect_costs(tmp_path)["roles"]["judge"]
    assert abs(judge["cost"]["known"] - (0.2 + 0.02)) < 1e-9
    assert judge["usage"]["prompt_tokens"] == 110


def test_judge_cache_reference_points_to_latest_real_response(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = _judge_cfg()
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 1, "completion_tokens": 1}, "model_cache_hit": False},
        physical_attempt_id="p1",
    )
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 2, "completion_tokens": 2}, "model_cache_hit": False},
        physical_attempt_id="p2",
    )
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {}, "model_cache_hit": True}, physical_attempt_id="cache",
    )
    events = [e["payload"] for e in ledger.replay().events if e["event_type"] == EVENT_EXECUTION_RECORDED]
    cache_event = events[-1]
    second_real = events[-2]
    assert cache_event["reused_from"] == second_real["accounting_id"]


def test_judge_cache_reference_follows_interleaved_real_responses(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = _judge_cfg()

    def _real(prompt: int, completion: int, physical: str) -> None:
        _judge_accounting(
            ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
            info={"usage": {"prompt_tokens": prompt, "completion_tokens": completion},
                  "model_cache_hit": False},
            physical_attempt_id=physical,
        )

    def _cache() -> None:
        _judge_accounting(
            ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
            info={"usage": {}, "model_cache_hit": True}, physical_attempt_id="cache",
        )

    _real(100, 50, "p1")
    _cache()
    _cache()  # same source -> deduplicated
    _real(10, 5, "p2")
    _cache()  # must now reference p2

    payloads = [
        e["payload"] for e in ledger.replay().events if e["event_type"] == EVENT_EXECUTION_RECORDED
    ]
    reals = [p for p in payloads if not p["model_cache_hit"]]
    caches = [p for p in payloads if p["model_cache_hit"]]
    assert len(reals) == 2
    assert len(caches) == 2  # one per source; repeated source de-duplicated
    assert caches[0]["reused_from"] == reals[0]["accounting_id"]
    assert caches[1]["reused_from"] == reals[1]["accounting_id"]
    judge = collect_costs(tmp_path)["roles"]["judge"]
    assert abs(judge["cost"]["known"] - (0.2 + 0.02)) < 1e-9
    assert judge["usage"]["prompt_tokens"] == 110


def test_judge_unknown_first_cost_is_not_duplicated_on_recovery(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = _judge_cfg(priced=False)
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {"prompt_tokens": 1, "completion_tokens": 1}, "model_cache_hit": False},
        physical_attempt_id="p1",
    )
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info={"usage": {}, "model_cache_hit": True}, physical_attempt_id="cache",
    )
    judge = collect_costs(tmp_path)["roles"]["judge"]
    assert judge["cost"]["unknown"] == 1


def test_judge_accounting_counts_each_physical_attempt(tmp_path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    config = EvaluatorsConfig(combination_id="cwe078-0", oracle_id="cwe078-0", stage="search")
    info = {"usage": {"total_tokens": 10}, "model_cache_hit": False}
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info=info, physical_attempt_id="p1",
    )
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info=info, physical_attempt_id="p2",
    )
    events = [e for e in ledger.replay().events if e["event_type"] == EVENT_EXECUTION_RECORDED]
    assert len(events) == 2
    # Replaying the same physical response must not double-book.
    _judge_accounting(
        ledger, evaluation_id="e", action_id="a", sample_id="s1", config=config,
        info=info, physical_attempt_id="p2",
    )
    events = [e for e in ledger.replay().events if e["event_type"] == EVENT_EXECUTION_RECORDED]
    assert len(events) == 2


def test_evaluator_metrics_llm_evasion_when_complete() -> None:
    record = LayerRecord(
        schema_version="layer-result-v1", evaluation_id="e", action_id="a", sample_id="s1",
        identity={}, stage="search", combination_id="cwe078-0", oracle_id="cwe078-0",
        layer="judge", tool="openai/gpt-4o", coverage="covered", status="completed",
        available=True, completed=True, reason_code=None, detected=False, verdict=None,
    )
    records = {"sast": [], "judge": [record], "dynamic": [], "realism": []}
    metrics = _evaluator_metrics(
        records, {"s1": True}, expected_sample_ids=["s1"],
        victim_temperature=0.7, victim_repeats=5,
    )
    assert metrics["llm_evasion"]["defined"] is True
    assert metrics["llm_evasion"]["denominator"] == 1
    assert metrics["llm_evasion"]["numerator"] == 1


def test_evaluator_metrics_judge_incomplete_is_undefined() -> None:
    record = LayerRecord(
        schema_version="layer-result-v1", evaluation_id="e", action_id="a", sample_id="s1",
        identity={}, stage="search", combination_id="cwe078-0", oracle_id="cwe078-0",
        layer="judge", tool="openai/gpt-4o", coverage="covered", status="completed",
        available=True, completed=True, reason_code=None, detected=True, verdict=None,
    )
    records = {"sast": [], "judge": [record], "dynamic": [], "realism": []}
    metrics = _evaluator_metrics(
        records, {"s1": True, "s2": True}, expected_sample_ids=["s1", "s2"],
        victim_temperature=0.7, victim_repeats=5,
    )
    assert metrics["llm_judge_rate"]["defined"] is False
    assert metrics["llm_judge_rate"]["reason"].startswith("judge_rows_incomplete")
