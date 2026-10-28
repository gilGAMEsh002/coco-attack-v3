"""Stage budget and public-ledger consumption aggregation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from coco_attack.generation.source import ExtractedResponse
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.runtime.ledger import (
    EVENT_ATTEMPT_FAILED,
    EVENT_ATTEMPT_STARTED,
    EVENT_RESPONSE_RECEIVED,
    Ledger,
)
from coco_methods.evidence_guided_search.budget import (
    Budget,
    BudgetConflictError,
    summarize_consumption,
)


def test_budget_reserves_settles_and_never_borrows_retest(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    budget = Budget(path, {"reference": 2, "search": 5, "retest": 3})

    assert budget.reserve("ref-1", "reference", 2)
    assert budget.reserve("ref-1", "reference", 2)  # same key is not reserved twice
    with pytest.raises(BudgetConflictError):
        budget.reserve("ref-1", "search", 2)

    assert budget.reserve("search-1", "search", 4)
    assert not budget.reserve("search-2", "search", 2)  # 4 in flight + 2 > 5
    assert budget.summary()["phases"]["retest"]["available"] == 3

    budget.settle("search-1", 3)  # known actual releases the unused reservation
    assert budget.reserve("search-2", "search", 2)
    budget.settle("search-2", None)  # unknown keeps the whole reservation

    summary = budget.summary()
    assert summary["phases"]["search"] == {
        "allocated": 5,
        "used": 3,
        "known_used": 3,
        "unknown_occupied": 2,
        "reserved": 0,
        "available": 0,
        "unknown": 1,
        "overage": 0,
        "entries": 2,
    }
    assert summary["phases"]["retest"]["available"] == 3
    assert summary["phases"]["reference"]["reserved"] == 2

    reloaded = Budget(path, {"reference": 2, "search": 5, "retest": 3})
    assert reloaded.summary()["phases"] == summary["phases"]
    budget.settle("ref-1", 1)
    assert budget.summary()["phases"]["reference"]["available"] == 1
    with pytest.raises(BudgetConflictError):
        Budget(path, {"reference": 3, "search": 5, "retest": 3})


def test_settle_is_idempotent_and_unknown_can_be_clarified(tmp_path: Path) -> None:
    budget = Budget(tmp_path / "budget.json", {"reference": 0, "search": 4, "retest": 0})

    assert budget.reserve("known", "search", 2)
    budget.settle("known", 1)
    budget.settle("known", 1)  # repeated known actual is a no-op
    with pytest.raises(BudgetConflictError):
        budget.settle("known", 2)  # a known actual cannot change
    with pytest.raises(BudgetConflictError):
        budget.settle("known", None)  # and cannot be erased

    assert budget.reserve("unknown", "search", 2)
    budget.settle("unknown", None)
    budget.settle("unknown", None)  # repeated unknown is a no-op
    before = budget.summary()["phases"]["search"]
    assert before["known_used"] == 1
    assert before["used"] == 1
    assert before["unknown_occupied"] == 2
    assert before["available"] == 1

    budget.settle("unknown", 2)  # unknown may be clarified once
    budget.settle("unknown", 2)
    after = budget.summary()["phases"]["search"]
    assert after["known_used"] == 3
    assert after["unknown_occupied"] == 0
    assert after["available"] == 1
    with pytest.raises(BudgetConflictError):
        budget.settle("unknown", 3)


def test_actual_over_reservation_reports_overage_and_blocks_dispatch(
    tmp_path: Path,
) -> None:
    budget = Budget(tmp_path / "budget.json", {"reference": 0, "search": 3, "retest": 0})

    assert budget.reserve("over", "search", 2)
    budget.settle("over", 4)  # the provider really attempted more than reserved
    summary = budget.summary()
    assert summary["phases"]["search"]["known_used"] == 4
    assert summary["phases"]["search"]["used"] == 4
    assert summary["phases"]["search"]["available"] == -1
    assert summary["phases"]["search"]["overage"] == 1
    assert summary["total"]["known_used"] == 4
    assert summary["total"]["unknown_occupied"] == 0
    assert summary["total"]["overage"] == 1

    # Over-consumption is not hidden and blocks any further search dispatch.
    assert not budget.reserve("next", "search", 1)


def test_budget_reservations_are_atomic_across_instances_and_threads(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    first = Budget(path, {"reference": 0, "search": 7, "retest": 0})
    second = Budget(path, {"reference": 0, "search": 7, "retest": 0})

    def reserve(index: int) -> bool:
        budget = first if index % 2 else second
        return budget.reserve(f"key-{index}", "search", 1)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(40)))

    assert sum(results) == 7
    summary = first.summary()
    assert summary["phases"]["search"]["reserved"] == 7
    assert summary["phases"]["search"]["used"] == 0
    assert summary["phases"]["search"]["available"] == 0


def test_summarize_consumption_keeps_unknown_and_cache_facts_separate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)

    ledger.append(
        EVENT_ATTEMPT_STARTED, sample_id="s1", request_attempt_id="a1",
        payload={"attempt_index": 0},
    )
    ledger.append(
        EVENT_RESPONSE_RECEIVED, sample_id="s1", request_attempt_id="a1",
        payload={
            "attempt_index": 0,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            "cost": {"basis": "estimated", "amount": 0.01, "currency": "USD"},
            "cache_hit": False,
        },
    )
    ledger.append(
        EVENT_ATTEMPT_STARTED, sample_id="s1", request_attempt_id="a2",
        payload={"attempt_index": 1},
    )
    ledger.append(
        EVENT_RESPONSE_RECEIVED, sample_id="s1", request_attempt_id="a2",
        payload={
            "attempt_index": 1,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            "cost": {"basis": "estimated", "amount": 0.01, "currency": "USD",
                     "reused_from_first_response": True},
            "cache_hit": True,
        },
    )
    ledger.append(
        EVENT_ATTEMPT_STARTED, sample_id="s2", request_attempt_id="a3",
        payload={"attempt_index": 0},
    )
    ledger.append(
        EVENT_ATTEMPT_FAILED, sample_id="s2", request_attempt_id="a3",
        payload={"attempt_index": 0, "retryable": True},
    )
    ledger.append(
        EVENT_ATTEMPT_STARTED, sample_id="s2", request_attempt_id="a4",
        payload={"attempt_index": 1},
    )
    ledger.append(
        EVENT_ATTEMPT_STARTED, sample_id="s3", request_attempt_id="a5",
        payload={"attempt_index": 0},
    )
    ledger.append(
        EVENT_ATTEMPT_FAILED, sample_id="s3", request_attempt_id="a5",
        payload={
            "attempt_index": 0,
            "retryable": False,
            "usage": {"total_tokens": 7},
            "cost": {"basis": "estimated", "amount": 0.02, "currency": "USD"},
        },
    )

    result = summarize_consumption([str(path), str(path)])

    assert len(result["sources"]) == 1
    assert result["sources"][0]["status"] == "ok"
    assert result["attempts"] == {
        "total": 5,
        "api": 4,
        "new_responses": 1,
        "cache_references": 1,
        "failed": 2,
        "retries": 2,
        "api_retries": 1,
        "cache_retries": 1,
        "sample_retries": None,
        "sample_retry_basis": "not separately recorded by the public ledgers",
        "unknown_outcomes": 1,
    }
    # The cache hit reuses 15 tokens; only the two new/known attempts count.
    assert result["tokens"] == {
        "known": 22,
        "known_attempts": 2,
        "unknown_attempts": 2,
    }
    assert result["cost"]["known"] == pytest.approx({"USD": 0.03})
    assert result["cost"]["known_entries"] == 2
    assert result["cost"]["unknown_attempts"] == 2
    assert any(
        entry.get("request_attempt_id") == "a4"
        and entry["reason"] == "attempt_without_terminal"
        for entry in result["unresolved"]
    )


def test_summarize_consumption_action_events_dedup_and_unresolved_refs(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "actions"
    store = ActionStore(run_dir)

    first = store.record_attempt_started("cand-1", 0)
    store.save_response(
        "cand-1",
        first,
        0,
        ExtractedResponse(
            content="{}", finish_reason="stop",
            usage={"prompt_tokens": 10, "completion_tokens": 2},
            cache_hit=False, response_id="r1", model="m",
        ),
        cost={"basis": "estimated", "amount": 0.005, "currency": "USD"},
    )
    failed = store.record_attempt_started("cand-2", 0)
    store.record_attempt_failed("cand-2", failed, 0, RuntimeError("boom"), True)
    reused = store.record_attempt_started("cand-2", 1)
    store.save_response(
        "cand-2",
        reused,
        1,
        ExtractedResponse(
            content="{}", finish_reason="stop",
            usage={"prompt_tokens": 5, "completion_tokens": 1},
            cache_hit=True, response_id="r2", model="m",
        ),
        cost={"basis": "estimated", "amount": 0.003, "currency": "USD"},
    )

    missing = tmp_path / "missing" / "ledger.jsonl"
    unrecognized = tmp_path / "notes"
    unrecognized.mkdir()

    result = summarize_consumption([
        str(store.actions_path),
        str(run_dir),
        str(missing),
        str(unrecognized),
    ])

    # The file and its directory are the same resolved event path.
    assert len(result["sources"]) == 3
    assert result["attempts"] == {
        "total": 3,
        "api": 2,
        "new_responses": 1,
        "cache_references": 1,
        "failed": 1,
        "retries": 1,
        "api_retries": 0,
        "cache_retries": 1,
        "sample_retries": None,
        "sample_retry_basis": "not separately recorded by the public ledgers",
        "unknown_outcomes": 0,
    }
    assert result["tokens"] == {
        "known": 12,
        "known_attempts": 1,
        "unknown_attempts": 1,
    }
    assert result["cost"]["known"] == pytest.approx({"USD": 0.005})
    assert result["cost"]["known_entries"] == 1
    assert result["cost"]["unknown_attempts"] == 1

    reasons = {(entry["ref"], entry["reason"]) for entry in result["unresolved"]}
    assert (str(missing), "missing") in reasons
    assert (str(unrecognized), "unrecognized") in reasons
