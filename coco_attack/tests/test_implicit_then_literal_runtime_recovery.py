"""Durable-state recovery windows for the ``implicit_then_literal`` runtime.

Each test injects a crash through the ``on_event`` hook at a documented
persistence window, reconstructs a *new* :class:`MethodRuntime` from the same
run root, and resumes.  Completed external actions must never be re-requested,
re-sampled or re-accounted.

Everything is offline: proposer/inducer responses, gate facts and training
artifacts are injected doubles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from coco_attack.assets.artifacts import read_json
from coco_attack.method import implicit_then_literal as itl

from _itl_runtime_fakes import build_harness, make_inducer


class InterruptOnce:
    """Raise on the first ``on_event`` marker with the given prefix."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.hit = False
        self.observed: list[str] = []

    def __call__(self, marker: str) -> None:
        self.observed.append(marker)
        if not self.hit and marker.startswith(self.prefix):
            self.hit = True
            raise RuntimeError(f"simulated crash at {marker}")


class BadThenGoodInducer:
    """Return malformed JSON on call 1, valid JSON afterwards."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, messages: list[dict[str, str]], number: int) -> str:
        self.calls += 1
        if self.calls == 1:
            return "not json"
        return json.dumps(
            {
                "entries": [
                    {
                        "label": f"e{self.calls}",
                        "nature": "observation",
                        "description": "d",
                        "change": "c",
                        "evidence": [],
                        "uncertainty": "u",
                    }
                ],
                "summary": f"summary-{self.calls}",
            }
        )


def _load(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    assert isinstance(payload, dict), path
    return payload


def _run_root(harness: Any) -> Path:
    return Path(harness.config.run_root)


def _plan(harness: Any, round_index: int, stage: str) -> dict[str, Any]:
    return _load(_run_root(harness) / "rounds" / str(round_index) / stage / "plan.json")


def _record(harness: Any, round_index: int, stage: str, cid: str) -> dict[str, Any]:
    return _load(
        _run_root(harness)
        / "rounds"
        / str(round_index)
        / stage
        / "candidates"
        / cid
        / "record.json"
    )


def _resume_without_interrupt(harness: Any) -> dict[str, Any]:
    return harness.new_runtime(on_event=None).resume()


def _crash_first(harness: Any, prefix: str) -> InterruptOnce:
    interrupt = InterruptOnce(prefix)
    runtime = harness.new_runtime(on_event=interrupt)
    with pytest.raises(RuntimeError):
        runtime.run()
    assert interrupt.hit, f"expected marker {prefix!r} was never observed: {interrupt.observed}"
    return interrupt


# --------------------------------------------------------------------------- #
# 1. proposer response saved but candidate record missing
# --------------------------------------------------------------------------- #


def test_recovery_after_proposal_response_without_record(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    _crash_first(harness, "a_proposal_saved:")
    assert harness.proposer.call_count() == 1
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    assert not (
        _run_root(harness)
        / "rounds"
        / "1"
        / "A"
        / "candidates"
        / cid
        / "record.json"
    ).exists()

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    # The saved response is reused; the other four A slots call once.
    assert harness.proposer.call_count() == 30
    assert _record(harness, 1, "A", cid)["proposal_status"] == "materialized"


# --------------------------------------------------------------------------- #
# 2. check saved but local gate state missing
# --------------------------------------------------------------------------- #


def test_recovery_after_check_saved_without_gate_state(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1, check_workers=1)
    _crash_first(harness, "a_check_saved:")
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    gate_dir = (
        _run_root(harness)
        / "rounds"
        / "1"
        / "A"
        / "candidates"
        / cid
        / "gate"
    )
    cached = [example for example in (2, 3, 4) if (gate_dir / f"example{example}.json").is_file()]
    assert len(cached) == 1  # exactly the check whose completion triggered the crash
    # The saved check ran exactly once.  (Queued checks may still execute during
    # executor shutdown but their results are not cached.)
    assert harness.gate.for_candidate(cid)[cached[0]] == 1

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    # The durably cached example is reused and never re-executed; the other two
    # are the only ones the resume has to complete.
    assert harness.gate.for_candidate(cid)[cached[0]] == 1
    assert set(harness.gate.for_candidate(cid)) == {2, 3, 4}


# --------------------------------------------------------------------------- #
# 3. training complete but local status still "in training"
# --------------------------------------------------------------------------- #


def test_recovery_after_training_artifacts_without_record_update(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    _crash_first(harness, "training_artifacts_complete:")
    assert len(harness.trainer.calls) == 2  # baseline + A candidate 1

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    # The completed training is adopted from disk; no sample is re-run.
    assert len(harness.trainer.calls) == 1 + 5 + 25
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    assert _record(harness, 1, "A", cid)["training"]["completion"] == "complete"


# --------------------------------------------------------------------------- #
# 4. experience committed but local induct flag missing
# --------------------------------------------------------------------------- #


def test_recovery_after_induction_commit_without_record_flag(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    interrupt = _crash_first(harness, "induction_committed:")
    assert harness.inducer.call_count() == 1
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    assert _record(harness, 1, "A", cid)["inducted"] is False

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    # The committed induction is re-read, never re-issued.
    assert harness.inducer.call_count() == 5 + 25
    record = _record(harness, 1, "A", cid)
    assert record["inducted"] is True
    assert record["induction_status"] == "committed"
    # Only one induction record exists for that logical identity.
    induction_id = record["induction_id"]
    assert (
        _run_root(harness) / "experience" / "inductions" / f"{induction_id}.json"
    ).is_file()


# --------------------------------------------------------------------------- #
# 5. ranking written but stage commit missing
# --------------------------------------------------------------------------- #


def test_recovery_after_ranking_without_stage_commit(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    _crash_first(harness, "ranking_written:A:")
    ranking_path = _run_root(harness) / "rounds" / "1" / "A" / "ranking.json"
    commit_path = _run_root(harness) / "rounds" / "1" / "A" / "commit.json"
    assert ranking_path.is_file()
    assert not commit_path.is_file()
    ranking_bytes = ranking_path.read_bytes()
    assert harness.inducer.call_count() == 5

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    assert commit_path.is_file()
    # The ranking is deterministic and rewritten identically; the stage commit
    # is written exactly once (same ranking hash).
    assert ranking_path.read_bytes() == ranking_bytes
    assert harness.inducer.call_count() == 5 + 25


# --------------------------------------------------------------------------- #
# 6. stage commit written but round pointer not advanced
# --------------------------------------------------------------------------- #


def test_recovery_after_commit_without_round_advance(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=2)
    _crash_first(harness, "commit_written:B:")
    commit_path = _run_root(harness) / "rounds" / "1" / "B" / "commit.json"
    assert commit_path.is_file()
    commit_bytes = commit_path.read_bytes()
    state = _load(_run_root(harness) / "state.json")
    assert state["round_index"] == 1
    assert state["phase"] == itl.PHASE_B_INDUCT_COMMIT

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    assert summary["round_index"] == 2
    assert commit_path.read_bytes() == commit_bytes  # not rewritten
    assert harness.inducer.call_count() == 2 * (5 + 25)


# --------------------------------------------------------------------------- #
# 7. Completed round 5 re-run is idle
# --------------------------------------------------------------------------- #


def test_completed_five_round_run_reconstructed_returns_done(tmp_path: Path) -> None:
    harness = build_harness(tmp_path)
    assert harness.run()["phase"] == itl.PHASE_DONE
    before = (
        harness.proposer.call_count(),
        harness.inducer.call_count(),
        len(harness.trainer.calls),
        len(harness.gate.calls),
    )

    # A brand-new runtime object built from the same persisted state must not
    # start a sixth round or re-issue any service call.
    fresh = harness.new_runtime(on_event=None)
    summary = fresh.run()
    assert summary["phase"] == itl.PHASE_DONE
    assert summary["round_index"] == 5
    assert (
        harness.proposer.call_count(),
        harness.inducer.call_count(),
        len(harness.trainer.calls),
        len(harness.gate.calls),
    ) == before


# --------------------------------------------------------------------------- #
# 8. Explicit induction retry is the only fresh-request path
# --------------------------------------------------------------------------- #


def test_retry_induction_is_the_only_fresh_inducer_request_after_protocol_error(
    tmp_path: Path,
) -> None:
    bad = BadThenGoodInducer()
    harness = build_harness(tmp_path, rounds=1, inducer=make_inducer(bad))
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_INDUCT_COMMIT
    assert "protocol_error" in (summary["pause_reason"] or "")
    assert harness.inducer.call_count() == 1

    # Ordinary resume reuses the durable malformed response; no fresh request.
    resumed = _resume_without_interrupt(harness)
    assert resumed["phase"] == itl.PHASE_PAUSED
    assert "protocol_error" in (resumed["pause_reason"] or "")
    assert harness.inducer.call_count() == 1

    # Explicit content retry is the only path that issues a new request.
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    retried = harness.new_runtime(on_event=None).retry_induction(
        round_index=1, stage="A", candidate_id_value=cid
    )
    assert retried["phase"] == itl.PHASE_DONE
    # 1 malformed + 1 retry for candidate 1 + 4 remaining A + 25 B.
    assert harness.inducer.call_count() == 1 + 1 + 4 + 25

    state = _load(_run_root(harness) / "state.json")
    induction_id = itl.InductionIdentity(
        run_id=harness.config.run_id, round_index=1, stage="A", candidate_id=cid
    ).logical_id()
    assert state["retry_index"][induction_id] == 1


# --------------------------------------------------------------------------- #
# Reported blocking regressions (round 3)
# --------------------------------------------------------------------------- #


class InterruptNth:
    """Raise on the Nth ``on_event`` marker with the given prefix."""

    def __init__(self, prefix: str, n: int) -> None:
        self.prefix = prefix
        self.n = n
        self.count = 0
        self.observed: list[str] = []

    def __call__(self, marker: str) -> None:
        self.observed.append(marker)
        if marker.startswith(self.prefix):
            self.count += 1
            if self.count == self.n:
                raise RuntimeError(f"simulated crash at {marker}")


def test_recovery_after_second_induction_committed(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    interrupt = InterruptNth("induction_committed:", 2)
    with pytest.raises(RuntimeError):
        harness.new_runtime(on_event=interrupt).run()
    assert interrupt.count == 2

    # The second induction's experience version is already committed but the
    # local chain state may be stale; resume must adopt the committed facts
    # instead of raising an induction conflict.
    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    a_commit = _load(_run_root(harness) / "rounds" / "1" / "A" / "commit.json")
    assert a_commit["selected"]


def test_not_ready_check_is_retried_on_resume(tmp_path: Path) -> None:
    from _itl_runtime_fakes import MockGateRunner

    flag = {"first": True}

    def not_ready_for(request: Any) -> bool:
        if flag["first"] and "candidates/" in str(request.output_dir):
            flag["first"] = False
            return True
        return False

    harness = build_harness(
        tmp_path, rounds=1, gate=MockGateRunner(not_ready_for=not_ready_for)
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    calls_before = len(harness.gate.calls)

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_DONE
    # The incomplete check was not cached as a fact, so the resume re-runs it.
    assert len(harness.gate.calls) > calls_before


def test_recovery_rejects_committed_induction_with_deleted_evidence(
    tmp_path: Path,
) -> None:
    harness = build_harness(tmp_path, rounds=1)
    interrupt = InterruptNth("induction_committed:", 2)
    with pytest.raises(RuntimeError):
        harness.new_runtime(on_event=interrupt).run()
    assert interrupt.count == 2

    # Deleting the first committed candidate's evidence must not be hidden by
    # adopting the committed experience version.
    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    record = _record(harness, 1, "A", cid)
    output = Path(record["training"]["output_dir"])
    (output / "feedback.json").unlink()

    summary = _resume_without_interrupt(harness)
    assert summary["phase"] == itl.PHASE_PAUSED
    assert "evidence incomplete" in (summary["pause_reason"] or "")


# --------------------------------------------------------------------------- #
# 7. orphan role call: default pause, explicit opt-in retry
# --------------------------------------------------------------------------- #


def test_orphan_role_call_pauses_then_explicit_retry_completes(
    tmp_path: Path,
) -> None:
    """An orphan attempt is never auto-retried; explicit opt-in resumes it.

    The orphan window (``attempt_started`` with no durable response) must pause
    as ``paused_unknown`` on a default resume and only be retried when the caller
    passes ``allow_retry_after_unknown=True``.
    """

    from coco_attack.iteration.action_runtime import ActionStore

    harness = build_harness(tmp_path, rounds=1)
    # Crash right after the first B proposal response is durably saved, so the
    # B plan exists and the run is resumable.
    _crash_first(harness, "b_proposal_saved:")
    plan = _plan(harness, 1, "B")
    # Inject the crash window directly: an attempt_started with no durable
    # response for the second B proposal action.
    store = ActionStore(_run_root(harness) / "actions")
    orphan_action = plan["candidates"][1]["action_id"]
    store.record_attempt_started(orphan_action, 0)

    # Default resume must report the unknown window, not silently retry it.
    paused = _resume_without_interrupt(harness)
    assert paused["phase"] == itl.PHASE_PAUSED
    assert paused["paused_from"] == itl.PHASE_B_PROPOSE
    assert "paused_unknown" in (paused["pause_reason"] or "")
    calls_at_pause = harness.proposer.call_count()

    # The explicit opt-in retries the orphan and finishes the round.
    done = harness.new_runtime(on_event=None).resume(allow_retry_after_unknown=True)
    assert done["phase"] == itl.PHASE_DONE
    assert harness.proposer.call_count() > calls_at_pause


def test_retry_induction_honors_stop_after_checkpoint(tmp_path: Path) -> None:
    """An explicit retry can still stop at round_1_complete instead of round 2+."""

    bad = BadThenGoodInducer()
    harness = build_harness(tmp_path, rounds=2, inducer=make_inducer(bad))
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert "protocol_error" in (summary["pause_reason"] or "")

    cid = _plan(harness, 1, "A")["candidates"][0]["candidate_id"]
    retried = harness.new_runtime(on_event=None).retry_induction(
        round_index=1,
        stage="A",
        candidate_id_value=cid,
        stop_after="round_1_complete",
    )
    assert retried["phase"] == itl.PHASE_STOPPED
    assert retried["stop_reason"] == "checkpoint:round_1_complete"
    assert retried["round_index"] == 2
    assert not (_run_root(harness) / "rounds" / "2" / "A" / "plan.json").exists()
