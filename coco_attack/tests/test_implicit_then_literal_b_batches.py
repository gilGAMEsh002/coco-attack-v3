"""B feedback batches expose committed experience to the next proposals."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json
from coco_methods import implicit_then_literal as itl
from _itl_runtime_fakes import (build_harness, make_proposer, default_b_responder,
                                invalid_b_responder, global_b_index, MockTrainingRunner)


def _batch_harness(tmp_path, *, proposer=None, trainer=None, on_event=None, **overrides):
    source = build_harness(tmp_path / "a", rounds=1, a_slots=5, b_slots_per_seed=0, top_k=5,
                          config_overrides={"mode": "a_only", "enforce_formal_constants": False})
    source.run()
    selected = read_json(Path(source.config.run_root) / "rounds/1/A/commit.json")["selected"]
    config = {"mode": "b_only", "enforce_formal_constants": False, "b_batch_size": 5,
              "b_seeds": tuple({"source_run_dir": source.config.run_root, "round_index": 1, "candidate_id": cid} for cid in selected)}
    config.update(overrides)
    return build_harness(tmp_path / "b", rounds=1, a_slots=5, b_slots_per_seed=5, top_k=5,
                         proposer=proposer, trainer=trainer, on_event=on_event, config_overrides=config)


def _root(harness):
    return Path(harness.config.run_root)


def _plan(harness, round_index=1):
    return read_json(_root(harness) / f"rounds/{round_index}/B/plan.json")


def _batch(harness, index, round_index=1):
    return read_json(_root(harness) / f"rounds/{round_index}/B/batches/{index}.json")


def test_five_batches_keep_parents_and_use_last_batch_experience(tmp_path):
    harness = _batch_harness(tmp_path)
    result = harness.run()
    assert result["phase"] == itl.PHASE_DONE
    assert harness.proposer.call_count() == 25
    assert harness.inducer.call_count() == 25
    assert len(harness.trainer.calls) == 26
    assert result["counts"]["actual_victim_samples"] == 520
    plan = _plan(harness)
    assert plan["batch_count"] == 5
    for index in range(1, 6):
        batch = _batch(harness, index)
        assert batch["committed"] is True
        assert batch["training_count"] == 5
        assert len(batch["induction_ids"]) == 5
        slots = [slot for slot in plan["candidates"] if slot["batch_index"] == index]
        assert [slot["seed_index"] for slot in slots] == [1, 2, 3, 4, 5]
        assert all(slot["seed_slot"] == index for slot in slots)
        assert [slot["seed_candidate_id"] for slot in slots] == plan["seeds"]
        if index > 1:
            prior = _batch(harness, index - 1)
            assert batch["stage_entry_versions"] == prior["experience_versions"]
            for call in harness.proposer.calls[(index - 1) * 5:index * 5]:
                assert f"summary-{(index - 1) * 5}" in call[0]["content"]
    events = [event[0] for event in harness.timeline if event[0] in ("b_propose", "train", "induct")]
    # Baseline is followed by five blocks: proposals, training, induction.
    assert events == ["train"] + (["b_propose"] * 5 + ["train"] * 5 + ["induct"] * 5) * 5
    ranking = read_json(_root(harness) / "rounds/1/B/ranking.json")
    commit = read_json(_root(harness) / "rounds/1/B/commit.json")
    assert len(ranking["candidates"]) == 25
    assert len(commit["selected"]) == 5
    assert len(commit["inductions"]) == 25


@pytest.mark.parametrize("marker", ["b_batch_committed:1:1", "induction_committed"])
def test_batch_crash_resume_reuses_committed_actions_without_repeating_work(tmp_path, marker):
    seen = 0
    def interrupt(event):
        nonlocal seen
        if event.startswith(marker):
            seen += 1
            if seen == (1 if marker.startswith("b_batch") else 3):
                raise RuntimeError("test durable interruption")
    harness = _batch_harness(tmp_path, on_event=interrupt)
    with pytest.raises(RuntimeError, match="durable interruption"):
        harness.run()
    assert harness.proposer.call_count() == 5
    assert len(harness.trainer.calls) == 6
    if marker.startswith("b_batch"):
        assert _batch(harness, 1)["committed"] is True
        assert not (_root(harness) / "rounds/1/B/commit.json").exists()
    runtime = harness.new_runtime(on_event=None)
    assert runtime.resume()["phase"] == itl.PHASE_DONE
    assert harness.proposer.call_count() == 25
    assert len(harness.trainer.calls) == 26
    assert harness.inducer.call_count() == 25
    assert runtime.resume()["phase"] == itl.PHASE_DONE
    assert harness.inducer.call_count() == 25


def test_all_invalid_first_batch_keeps_experience_and_proposes_next_batch(tmp_path):
    proposer = make_proposer(b_responder=lambda messages, number:
        invalid_b_responder(messages, number) if global_b_index(messages[0]["content"]) <= 5 else default_b_responder(messages, number))
    harness = _batch_harness(tmp_path, proposer=proposer)
    assert harness.run()["phase"] == itl.PHASE_DONE
    first = _batch(harness, 1)
    assert first["status"] == "all_proposals_invalid"
    assert first["training_count"] == 0
    assert first["induction_ids"] == []
    assert first["experience_versions"] == first["stage_entry_versions"]
    assert _batch(harness, 2)["stage_entry_versions"] == first["experience_versions"]
    assert harness.proposer.call_count() == 25
    assert harness.inducer.call_count() == 20
    assert len(harness.trainer.calls) == 21


def test_all_batches_invalid_pause_only_after_all_slots_without_empty_experience(tmp_path):
    harness = _batch_harness(tmp_path, proposer=make_proposer(b_responder=invalid_b_responder))
    result = harness.run()
    assert result["phase"] == itl.PHASE_PAUSED
    assert "无可用的训练结果" in result["pause_reason"]
    assert harness.proposer.call_count() == 25
    assert harness.inducer.call_count() == 0
    assert len(harness.trainer.calls) == 1
    assert not (_root(harness) / "rounds/1/B/commit.json").exists()
    assert all(_batch(harness, index)["status"] == "all_proposals_invalid" for index in range(1, 6))


def test_later_batch_failures_do_not_change_first_batch_induction_locks(tmp_path):
    proposer = make_proposer(b_responder=lambda messages, number:
        invalid_b_responder(messages, number) if global_b_index(messages[0]["content"]) in (6, 21) else default_b_responder(messages, number))
    def interrupt(event):
        if event == "b_batch_committed:1:1":
            raise RuntimeError("snapshot first locks")
    harness = _batch_harness(tmp_path, proposer=proposer, on_event=interrupt)
    with pytest.raises(RuntimeError):
        harness.run()
    locks = {path.name: path.read_bytes() for path in (_root(harness) / "experience/inductions").glob("*.input.json")}
    assert len(locks) == 5
    assert harness.new_runtime(on_event=None).resume()["phase"] == itl.PHASE_DONE
    assert harness.inducer.call_count() == 23
    for name, content in locks.items():
        assert (_root(harness) / "experience/inductions" / name).read_bytes() == content


def test_incomplete_training_in_batch_pauses_before_later_batches(tmp_path):
    trainer = MockTrainingRunner(pending_first_for=lambda cfg: cfg.batch_id == "itl-r1B-c6")
    harness = _batch_harness(tmp_path, trainer=trainer)
    result = harness.run()
    assert result["phase"] == itl.PHASE_PAUSED
    assert result["paused_from"] == itl.PHASE_B_TRAIN
    assert harness.proposer.call_count() == 10
    assert harness.inducer.call_count() == 5
    assert not (_root(harness) / "rounds/1/B/batches/3.json").exists()
    assert harness.resume()["phase"] == itl.PHASE_DONE
    assert harness.proposer.call_count() == 25
    assert harness.inducer.call_count() == 25


def test_ab_b_stage_uses_batches_across_rounds_with_final_global_ranking(tmp_path):
    harness = build_harness(tmp_path, rounds=2, a_slots=2, b_slots_per_seed=2, top_k=2,
                          config_overrides={"enforce_formal_constants": False, "b_batch_size": 2})
    assert harness.run()["phase"] == itl.PHASE_DONE
    assert len(harness.trainer.calls) == 13  # baseline + two rounds of 2A + 4B
    assert harness.inducer.call_count() == 12
    for round_index in (1, 2):
        assert _plan(harness, round_index)["batch_count"] == 2
        assert _batch(harness, 2, round_index)["committed"] is True
        assert len(read_json(_root(harness) / f"rounds/{round_index}/B/commit.json")["selected"]) == 2


def test_batch_config_preserves_default_identity_and_rejects_invalid_values(tmp_path):
    base = build_harness(tmp_path).config
    assert "b_batch_size" not in base.to_json()
    assert itl.MethodRuntimeConfig.from_json(base.to_json()).config_sha256() == base.config_sha256()
    batch = replace(base, b_batch_size=5)
    assert itl.MethodRuntimeConfig.from_json(batch.to_json()) == batch
    assert batch.config_sha256() != base.config_sha256()
    for value in (0, -1, True, 1.5):
        with pytest.raises(itl.MethodRuntimeError):
            replace(base, b_batch_size=value)


def test_batch_status_is_read_only_and_legacy_status_omits_batch_navigation(tmp_path):
    from coco_methods.implicit_then_literal.preflight import build_status_report
    from coco_methods.implicit_then_literal.wiring import MethodRunConfig
    def interrupt(event):
        if event == "b_batch_committed:1:1":
            raise RuntimeError("at first batch boundary")
    harness = _batch_harness(tmp_path / "batch", on_event=interrupt)
    with pytest.raises(RuntimeError):
        harness.run()
    before = {str(path): path.read_bytes() for path in _root(harness).rglob("*") if path.is_file()}
    status = build_status_report(MethodRunConfig(str(tmp_path), harness.config)).to_json()
    assert status["b_feedback"] == {"b_batch_size": 5, "batch_index": 1, "batch_count": 5, "committed_batches": 1}
    assert {str(path): path.read_bytes() for path in _root(harness).rglob("*") if path.is_file()} == before
    old = build_harness(tmp_path / "old")
    assert "b_feedback" not in build_status_report(MethodRunConfig(str(tmp_path), old.config)).to_json()


def test_partial_last_batch_and_native_pause_keep_all_planned_slots(tmp_path):
    from coco_attack.assets.artifacts import write_json_atomic
    harness = _batch_harness(tmp_path, b_batch_size=7)
    write_json_atomic(_root(harness) / "pause_request.json", {"round_index": 1, "stage": "B", "candidate_index": 9, "reason": "inspect batch two"})
    stopped = harness.run()
    assert stopped["phase"] == itl.PHASE_STOPPED
    assert stopped["stopped_from"] == itl.PHASE_B_TRAIN
    assert harness.proposer.call_count() == 14
    assert harness.inducer.call_count() == 7
    assert read_json(_root(harness) / "state.json")["b_batch_index"] == 2
    assert harness.resume()["phase"] == itl.PHASE_DONE
    assert _plan(harness)["batch_count"] == 4
    assert _batch(harness, 4)["training_count"] == 4
    assert harness.proposer.call_count() == 25
    assert harness.inducer.call_count() == 25
    assert len(harness.trainer.calls) == 26


@pytest.mark.parametrize("mode", ["ab", "b_only"])
def test_round_two_plan_write_crash_does_not_skip_early_batches(tmp_path, monkeypatch, mode):
    if mode == "ab":
        harness = build_harness(tmp_path, rounds=2, a_slots=2, b_slots_per_seed=2, top_k=2,
                              config_overrides={"enforce_formal_constants": False, "b_batch_size": 2})
    else:
        proposer = make_proposer(b_responder=lambda messages, number: json.dumps({"modifications": [{"example": 3, "new_cot": f"batch cot {number}"}]}))
        harness = _batch_harness(tmp_path, rounds=2, b_slots_per_seed=2, proposer=proposer)
    original = harness.runtime._write_plan
    def interrupted_write(round_index, stage, plan):
        original(round_index, stage, plan)
        if round_index == 2 and stage == "B":
            raise RuntimeError("after round two plan before batch state")
    monkeypatch.setattr(harness.runtime, "_write_plan", interrupted_write)
    with pytest.raises(RuntimeError, match="after round two plan"):
        harness.run()
    state = read_json(_root(harness) / "state.json")
    assert state["round_index"] == 2
    assert state["b_batch_index"] == 1
    assert not (_root(harness) / "rounds/2/B/batches/1.json").exists()
    assert harness.new_runtime().resume()["phase"] == itl.PHASE_DONE
    plan = _plan(harness, 2)
    assert all(_batch(harness, index, 2)["committed"] for index in range(1, plan["batch_count"] + 1))
    records = [read_json(path) for path in (_root(harness) / "rounds/2/B/candidates").glob("*/record.json")]
    assert len(records) == len(plan["candidates"])
    assert all(record["inducted"] for record in records)
    expected_b = 8 if mode == "ab" else 20
    assert sum("modifications" in call[0]["content"] for call in harness.proposer.calls) == expected_b
