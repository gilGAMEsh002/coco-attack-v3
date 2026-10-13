"""One modern B round can stop at a training boundary and continue in a new run."""
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json, write_json_atomic
from coco_methods import implicit_then_literal as itl
from _itl_runtime_fakes import build_harness, MockTrainingRunner


def _bytes(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _source(tmp_path):
    a = build_harness(tmp_path / "a", rounds=1, a_slots=5, b_slots_per_seed=0, top_k=5,
                      config_overrides={"mode": "a_only", "enforce_formal_constants": False})
    a.run()
    commit = read_json(Path(a.config.run_root) / "rounds/1/A/commit.json")
    b = build_harness(tmp_path / "b", rounds=1, a_slots=5, b_slots_per_seed=5, top_k=5,
        config_overrides={"mode": "b_only", "enforce_formal_constants": False,
            "b_seeds": tuple({"source_run_dir": a.config.run_root, "round_index": 1, "candidate_id": cid} for cid in commit["selected"])})
    root = Path(b.config.run_root)
    root.mkdir(parents=True)
    write_json_atomic(root / "pause_request.json", {"round_index": 1, "stage": "B", "candidate_index": 7, "reason": "switch victim concurrency"})
    summary = b.run()
    assert summary["phase"] == itl.PHASE_STOPPED
    # Public fake trainer writes raw feedback but not its config; save the exact
    # actual baseline config so production identity validation is exercised.
    baseline = b.trainer.calls[0]
    write_json_atomic(Path(baseline.output_dir) / "loop_config.json", {**baseline.to_json(), "config_sha256": baseline.run_config_sha256()})
    return b


def _target(source, **overrides):
    state = read_json(Path(source.config.run_root) / "state.json")
    settings = dict(run_id="adaptive-continuation", run_root=str(Path(source.config.run_root).parent / "new-run"),
        baseline_training_path=state["baseline"]["output_dir"],
        b_continuation_source_run_dir=source.config.run_root, victim_concurrency_mode="adaptive", victim_min_concurrency=4, victim_max_concurrency=16)
    settings.update(overrides)
    config = replace(source.config, **settings)
    trainer = MockTrainingRunner()
    services = replace(source.services, training_runner=trainer)
    return replace(source, config=config, trainer=trainer, services=services, runtime=itl.MethodRuntime(config, services=services))


def test_pause_after_seven_does_not_start_eight(tmp_path):
    source = _source(tmp_path)
    root = Path(source.config.run_root)
    state = read_json(root / "state.json")
    assert state["stopped_from"] == itl.PHASE_B_TRAIN
    assert state["stop_reason"] == "switch victim concurrency"
    assert state["pause_request_applied"]["candidate_index"] == 7
    assert len(source.trainer.calls) == 8  # baseline plus seven candidates
    assert source.proposer.call_count() == 25
    assert source.inducer.call_count() == 0
    plan = read_json(root / "rounds/1/B/plan.json")
    eighth = root / "rounds/1/B/candidates" / plan["candidates"][7]["candidate_id"]
    assert not (eighth / "training").exists()
    assert read_json(eighth / "record.json")["training"] is None


def test_continuation_reuses_proposals_and_training_then_inducts_all_twenty_five(tmp_path):
    source = _source(tmp_path)
    old_root = Path(source.config.run_root)
    before = _bytes(old_root)
    target = _target(source)
    previous_proposals = source.proposer.call_count()
    result = target.run()
    assert result["phase"] == itl.PHASE_DONE
    assert len(target.trainer.calls) == 18
    assert all((cfg.concurrency_mode, cfg.min_concurrency, cfg.max_concurrency) == ("adaptive", 4, 16) for cfg in target.trainer.calls)
    assert source.proposer.call_count() == previous_proposals
    assert target.inducer.call_count() == 25
    counts = result["counts"]
    assert counts["actual_victim_samples"] == 520
    assert counts["reused_baseline_samples"] == 20
    assert counts["reused_b_training_samples"] == 140
    assert counts["reused_b_proposals"] == 25
    assert counts["new_victim_samples"] == 360
    assert counts["planned_new_victim_samples"] == 360
    new_root = Path(target.config.run_root)
    plan = read_json(new_root / "rounds/1/B/plan.json")
    for index, slot in enumerate(plan["candidates"], 1):
        record = read_json(new_root / "rounds/1/B/candidates" / slot["candidate_id"] / "record.json")
        assert record["candidate"]["run_id"] == "adaptive-continuation"
        assert record["inducted"] is True
        assert record["proposal_source"]["source_run_dir"] == str(old_root)
        assert record["proposal_source"]["candidate_id"] != record["candidate_id"]
        if index <= 7:
            assert record["training_source"]["source_run_dir"] == str(old_root)
            assert Path(record["training"]["output_dir"]).is_relative_to(old_root)
        else:
            assert Path(record["training"]["output_dir"]).is_relative_to(new_root)
    ranking = read_json(new_root / "rounds/1/B/ranking.json")
    assert len(ranking["candidates"]) == 25
    assert _bytes(old_root) == before


@pytest.mark.parametrize("change", ["running", "inducted", "model", "temperature", "repeats"])
def test_continuation_rejects_unstopped_inducted_or_research_changes(tmp_path, change):
    source = _source(tmp_path)
    root = Path(source.config.run_root)
    overrides = {}
    if change == "running":
        state = read_json(root / "state.json");state["phase"] = itl.PHASE_B_TRAIN;write_json_atomic(root / "state.json", state)
    elif change == "inducted":
        path = next(root.glob("rounds/1/B/candidates/*/record.json"))
        record = read_json(path);record["inducted"] = True;write_json_atomic(path, record)
    elif change == "model":
        overrides["victim_model"] = "different"
    elif change == "temperature":
        overrides["victim_temperature"] = 0.3
    else:
        overrides["victim_repeats"] = 2
    target = _target(source, **overrides)
    before = _bytes(root)
    with pytest.raises((itl.MethodRuntimeError, ValueError)):
        target.run()
    assert len(target.trainer.calls) == 0
    assert _bytes(root) == before


def test_continuation_optional_field_preserves_default_config_identity(tmp_path):
    base = build_harness(tmp_path).config
    assert "b_continuation_source_run_dir" not in base.to_json()
    assert itl.MethodRuntimeConfig.from_json(base.to_json()).config_sha256() == base.config_sha256()
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, b_continuation_source_run_dir="/source")


def test_continuation_preserves_old_sample_identity_and_resumes_without_reimport(tmp_path):
    source = _source(tmp_path)
    root = Path(source.config.run_root)
    source_plan = read_json(root / "rounds/1/B/plan.json")
    old_record = read_json(root / "rounds/1/B/candidates" / source_plan["candidates"][0]["candidate_id"] / "record.json")
    target = _target(source)
    target.run()
    target_root = Path(target.config.run_root)
    target_plan = read_json(target_root / "rounds/1/B/plan.json")
    new_record = read_json(target_root / "rounds/1/B/candidates" / target_plan["candidates"][0]["candidate_id"] / "record.json")
    assert new_record["training"]["candidate_hash"] == old_record["training"]["candidate_hash"]
    assert new_record["training"]["output_dir"] == old_record["training"]["output_dir"]
    assert new_record["metrics"] == old_record["metrics"]
    assert new_record["per_task"] == old_record["per_task"]
    previous = (len(target.trainer.calls), target.proposer.call_count(), target.inducer.call_count())
    assert target.runtime.resume()["phase"] == itl.PHASE_DONE
    assert previous == (len(target.trainer.calls), target.proposer.call_count(), target.inducer.call_count())


def test_continuation_preflight_rejects_existing_commit_before_any_new_action(tmp_path):
    source = _source(tmp_path)
    root = Path(source.config.run_root)
    write_json_atomic(root / "rounds/1/B/commit.json", {"selected": []})
    target = _target(source)
    before = _bytes(root)
    with pytest.raises(itl.MethodRuntimeError, match="ranking/commit"):
        target.run()
    assert target.trainer.calls == []
    assert _bytes(root) == before


def test_second_continuation_retains_original_proposal_and_ancestor_training_sources(tmp_path):
    source = _source(tmp_path)
    original_root = Path(source.config.run_root)
    middle = _target(source)
    middle_root = Path(middle.config.run_root)
    write_json_atomic(middle_root / "pause_request.json", {"round_index": 1, "stage": "B", "candidate_index": 9, "reason": "another transport change"})
    assert middle.run()["phase"] == itl.PHASE_STOPPED
    assert len(middle.trainer.calls) == 2
    before = (_bytes(original_root), _bytes(middle_root))
    final = _target(middle, run_id="second-continuation", run_root=str(tmp_path / "final-run"))
    summary = final.run()
    assert summary["phase"] == itl.PHASE_DONE
    assert len(final.trainer.calls) == 16
    assert summary["counts"]["reused_b_training_samples"] == 180
    assert summary["counts"]["new_victim_samples"] == 320
    assert summary["counts"]["reused_b_proposals"] == 25
    plan = read_json(Path(final.config.run_root) / "rounds/1/B/plan.json")
    for index, slot in enumerate(plan["candidates"], 1):
        record = read_json(Path(final.config.run_root) / "rounds/1/B/candidates" / slot["candidate_id"] / "record.json")
        assert record["proposal_source"]["source_run_dir"] == str(original_root)
        assert record["proposal_source"]["action_id"] is not None
        assert record["continuation_source"]["source_run_dir"] == str(middle_root)
        if index <= 7:
            assert record["training_source"]["source_run_dir"] == str(original_root)
        elif index <= 9:
            assert record["training_source"]["source_run_dir"] == str(middle_root)
    assert (_bytes(original_root), _bytes(middle_root)) == before
