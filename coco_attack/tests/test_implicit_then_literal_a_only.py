"""Offline A-only protocol, experience inheritance and durable recovery tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from coco_attack.assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_text,
    write_json_atomic,
)
from coco_methods import implicit_then_literal as itl
from coco_methods.implicit_then_literal import preflight
from coco_methods.implicit_then_literal import roles
from coco_methods.implicit_then_literal import runtime
from coco_methods.implicit_then_literal.wiring import MethodRunConfig

from _itl_runtime_fakes import (
    Harness,
    MockGateRunner,
    MockTrainingRunner,
    build_harness,
    experience_versions_in,
    template_sha_in,
)


def _a_only(tmp_path: Path, **kwargs: Any) -> Harness:
    return build_harness(
        tmp_path,
        rounds=6,
        a_slots=3,
        b_slots_per_seed=0,
        top_k=3,
        config_overrides={
            "mode": "a_only",
            "victim_model": "deepseek-v4-flash-0731",
            "proposer_config": replace(roles.proposer_config(runtime.A_PROTOCOL_VERSION), temperature=1.0),
            "enforce_formal_constants": True,
        },
        **kwargs,
    )


def _root(harness: Harness) -> Path:
    return Path(harness.config.run_root)


def _load(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    assert isinstance(payload, dict), path
    return payload


def _commit(harness: Harness, round_index: int) -> dict[str, Any]:
    return _load(_root(harness) / "rounds" / str(round_index) / "A" / "commit.json")


def _call_counts(harness: Harness) -> tuple[int, int, int, int]:
    return (
        harness.proposer.call_count(),
        harness.inducer.call_count(),
        len(harness.trainer.calls),
        len(harness.gate.calls),
    )


def _induction_commits(harness: Harness) -> list[Path]:
    return [
        path for path in (_root(harness) / "experience" / "inductions").glob("*.json")
        if not path.name.endswith(".input.json")
    ]


def _assert_no_b(harness: Harness) -> None:
    assert not list((_root(harness) / "rounds").glob("*/B"))
    assert not any("modifications" in call[0]["content"] for call in harness.proposer.calls)
    assert not any("B" in str(config.batch_id) for config in harness.trainer.calls)


def test_six_round_a_only_trains_and_inducts_every_candidate(tmp_path: Path) -> None:
    harness = _a_only(tmp_path)
    summary = harness.run()

    assert summary["phase"] == itl.PHASE_DONE
    assert summary["round_index"] == 6
    assert summary["counts"]["planned_victim_samples"] == 380
    assert summary["counts"]["actual_victim_samples"] == 380
    assert summary["counts"]["baseline_trainings"] == 1
    assert summary["counts"]["a_trainings"] == 18
    assert summary["counts"]["b_trainings"] == 0
    assert summary["counts"]["logical_inductions"] == 18
    assert _call_counts(harness) == (18, 18, 19, 54)
    assert all(config.repeats == 10 for config in harness.trainer.calls)
    assert all(config.model == "deepseek-v4-flash-0731" for config in harness.trainer.calls)
    for round_index in range(1, 7):
        commit = _commit(harness, round_index)
        assert len(commit["selected"]) == 3
        assert len(commit["inductions"]) == 3
    _assert_no_b(harness)

    # A fresh runtime must remain quiet after the sixth round has committed.
    counts = _call_counts(harness)
    assert harness.new_runtime().resume()["counts"] == summary["counts"]
    assert _call_counts(harness) == counts


def test_a_only_inherits_structure_experience_and_restarts_initial_template(tmp_path: Path) -> None:
    harness = _a_only(tmp_path)
    assert harness.run()["phase"] == itl.PHASE_DONE
    initial = {
        category: itl.ExperienceVersionReference.initial(category).to_json()
        for category in (itl.EXPERIENCE_CATEGORY_STRUCTURE, itl.EXPERIENCE_CATEGORY_LITERAL)
    }
    previous = initial
    seen_structure = {initial["structure"]["version_id"]}

    for round_index in range(1, 7):
        plan = _load(_root(harness) / "rounds" / str(round_index) / "A" / "plan.json")
        assert plan["parent_role"] == "initial_template"
        assert plan["parent_content_sha256"] == harness.initial_sha
        assert plan["stage_entry_versions"] == previous
        expected_versions = {reference["version_id"] for reference in previous.values()}
        messages = harness.proposer.calls[(round_index - 1) * 3 : round_index * 3]
        assert len(messages) == 3
        assert all(template_sha_in(call) == harness.initial_sha for call in messages)
        assert all(experience_versions_in(harness, call) == expected_versions for call in messages)
        for slot in plan["candidates"]:
            record = _load(
                _root(harness) / "rounds" / str(round_index) / "A"
                / "candidates" / slot["candidate_id"] / "record.json"
            )
            assert record["parent_content_sha256"] == harness.initial_sha
            assert record["content_sha256"] != harness.initial_sha
            assert record["induction_status"] == "committed"
        previous = _commit(harness, round_index)["experience_versions"]
        assert previous["literal"] == initial["literal"]
        structure_id = previous["structure"]["version_id"]
        assert structure_id not in seen_structure
        seen_structure.add(structure_id)
    _assert_no_b(harness)


@pytest.mark.parametrize("checkpoint", ["baseline_complete", "round_1_complete"])
def test_a_only_checkpoint_resume_does_not_repeat_completed_calls(
    tmp_path: Path, checkpoint: str,
) -> None:
    harness = _a_only(tmp_path)
    stopped = harness.runtime.run(stop_after=checkpoint)
    assert stopped["phase"] == itl.PHASE_STOPPED
    assert stopped["stop_reason"] == f"checkpoint:{checkpoint}"
    expected = (0, 0, 1, 0) if checkpoint == "baseline_complete" else (3, 3, 4, 9)
    assert _call_counts(harness) == expected
    if checkpoint == "round_1_complete":
        commit_path = _root(harness) / "rounds" / "1" / "A" / "commit.json"
        committed_bytes = commit_path.read_bytes()
        assert not (_root(harness) / "rounds" / "2").exists()
    _assert_no_b(harness)

    resumed = harness.new_runtime().resume()
    assert resumed["phase"] == itl.PHASE_DONE
    assert _call_counts(harness) == (18, 18, 19, 54)
    if checkpoint == "round_1_complete":
        assert commit_path.read_bytes() == committed_bytes
    _assert_no_b(harness)


@pytest.mark.parametrize("marker", ["commit_written:A:1", "induction_committed:"])
def test_a_only_recovers_saved_commit_and_induction_without_recalling_models(
    tmp_path: Path, marker: str,
) -> None:
    harness = _a_only(tmp_path)
    observed: list[str] = []

    def crash(event: str) -> None:
        observed.append(event)
        if event.startswith(marker):
            raise RuntimeError("simulated durable-state interruption")

    with pytest.raises(RuntimeError, match="durable-state interruption"):
        harness.new_runtime(on_event=crash).run()
    assert any(event.startswith(marker) for event in observed)
    if marker == "commit_written:A:1":
        commit_path = _root(harness) / "rounds" / "1" / "A" / "commit.json"
        committed_bytes = commit_path.read_bytes()
        assert _call_counts(harness) == (3, 3, 4, 9)
    else:
        assert harness.inducer.call_count() == 1
        induction_paths = _induction_commits(harness)
        assert len(induction_paths) == 1
        committed_bytes = induction_paths[0].read_bytes()

    assert harness.new_runtime().resume()["phase"] == itl.PHASE_DONE
    assert _call_counts(harness) == (18, 18, 19, 54)
    if marker == "commit_written:A:1":
        assert commit_path.read_bytes() == committed_bytes
    else:
        assert induction_paths[0].read_bytes() == committed_bytes
        assert len(_induction_commits(harness)) == 18
    _assert_no_b(harness)


def test_a_only_no_training_evidence_pauses_without_fabricating_experience(tmp_path: Path) -> None:
    harness = _a_only(tmp_path, gate=MockGateRunner(fail_for=lambda request: True))
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_INDUCT_COMMIT
    assert "无完整训练结果" in summary["pause_reason"]
    assert harness.inducer.call_count() == 0
    assert len(harness.trainer.calls) == 1  # Only the comparison baseline.
    assert not (_root(harness) / "rounds" / "1" / "A" / "commit.json").exists()
    assert not list((_root(harness) / "experience" / "inductions").glob("*.json"))
    state = _load(_root(harness) / "state.json")
    assert all(
        reference == itl.ExperienceVersionReference.initial(category).to_json()
        for category, reference in state["current_versions"].items()
    )
    _assert_no_b(harness)


def test_formal_real_a_only_config_round_trip_accepts_two_selected_training_tasks(tmp_path: Path) -> None:
    base = _a_only(tmp_path).config
    formal = replace(
        base,
        training_task_ids=("BigCodeBench/42", "BigCodeBench/43"),
        proposer_config=replace(base.proposer_config, source="dmx", temperature=1.0),
        inducer_config=replace(base.inducer_config, source="dmx"),
        victim_source="dmx",
        check_service="real",
    )
    restored = itl.MethodRuntimeConfig.from_json(json.loads(json.dumps(formal.to_json())))
    assert restored == formal
    assert restored.config_sha256() == formal.config_sha256()
    assert restored.mode == "a_only"
    assert restored.proposer_config.temperature == 1.0
    assert restored.training_task_ids == ("BigCodeBench/42", "BigCodeBench/43")
    assert restored.enforce_formal_constants is True


@pytest.mark.parametrize("overrides", [
    {"b_slots_per_seed": 1},
    {"victim_repeats": 9},
    {"training_task_ids": ("BigCodeBench/42",)},
    {"training_task_ids": ("BigCodeBench/42", "BigCodeBench/42")},
])
def test_formal_a_only_rejects_protocol_changes(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(itl.MethodRuntimeError):
        replace(_a_only(tmp_path).config, **overrides)


@pytest.mark.parametrize("overrides", [
    {"rounds": 6},
    {"a_slots": 3},
    {"b_slots_per_seed": 0},
    {"top_k": 3},
    {"victim_repeats": 9},
    {"victim_model": "deepseek-v4-flash-0731"},
    {"training_task_ids": ("BigCodeBench/42", "BigCodeBench/43")},
])
def test_default_ab_retains_fixed_formal_protocol(tmp_path: Path, overrides: dict[str, Any]) -> None:
    base = build_harness(tmp_path).config
    assert base.mode == "ab"
    assert base.baseline_training_path is None
    assert "baseline_training_path" not in base.to_json()
    legacy_payload = base.to_json()
    legacy_payload.pop("mode", None)
    assert itl.MethodRuntimeConfig.from_json(legacy_payload).mode == "ab"
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, **overrides)


def test_formal_real_a_only_preflight_accepts_mode_constants_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _a_only(tmp_path)
    data = Path(harness.config.prepared_data_dir)
    data.mkdir()
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(
        "rules:\n  - id: subprocess-shell-true\n    languages: [python]\n"
        "    message: test rule\n    severity: ERROR\n    pattern: subprocess.run(..., shell=True)\n",
        encoding="utf-8",
    )
    tasks = ("BigCodeBench/42", "BigCodeBench/43")
    method = replace(
        harness.config,
        training_task_ids=tasks,
        proposer_config=replace(harness.config.proposer_config, source="dmx", temperature=1.0),
        inducer_config=replace(harness.config.inducer_config, source="dmx"),
        victim_source="dmx",
        check_service="real",
        semgrep_config=str(rules),
    )
    monkeypatch.setattr(
        preflight, "load_comparison_baseline",
        lambda **kwargs: SimpleNamespace(
            reference=harness.baseline_loader.reference,
            content_sha256=harness.baseline_sha,
        ),
    )
    monkeypatch.setattr(
        preflight, "load_prepared_data",
        lambda path, combination_id: SimpleNamespace(task_by_id=lambda: dict.fromkeys(tasks)),
    )
    report = preflight.build_preflight_report(MethodRunConfig(project_root=str(tmp_path), method=method))
    assert report.offline_preflight_passed, report.errors
    assert report.sources["effective_models"]["victim"] == "openai/deepseek-v4-flash-0731"
    assert not _root(harness).exists()
    assert _call_counts(harness) == (0, 0, 0, 0)


class _BaselineWithOneEmptySample(MockTrainingRunner):
    """Keep a completed generation failure in the baseline's true denominator."""

    def _write(self, config: Any) -> dict[str, Any]:
        result = super()._write(config)
        if config.batch_id == "itl-baseline":
            output = Path(config.output_dir)
            feedback = _load(output / "feedback.json")
            audit = _load(output / "feedback_audit.json")
            feedback["samples"][-1].update(code="", verdict=None)
            audit["samples"][-1].update(
                generation_status="empty", final_code_sha256=sha256_text(""),
                verdict=None, asr_hit=False,
            )
            feedback["counts"]["generation_failures"] = 1
            write_json_atomic(output / "feedback.json", feedback)
            write_json_atomic(output / "feedback_audit.json", audit)
        return result


def _baseline_source(tmp_path: Path) -> tuple[Harness, Path]:
    source = _a_only(tmp_path / "source", trainer=_BaselineWithOneEmptySample())
    assert source.runtime.run(stop_after="baseline_complete")["phase"] == itl.PHASE_STOPPED
    output = _root(source) / "baseline" / "training"
    config = source.runtime._training_config(
        snapshot_path=source.config.comparison_baseline_path,
        output_dir=output,
        form=source.baseline.form,
        prompt_version=source.baseline.prompt_version,
        batch_id="itl-baseline",
    )
    write_json_atomic(
        output / "loop_config.json",
        {**config.to_json(), "config_sha256": config.run_config_sha256()},
    )
    return source, output


def _reusing_baseline(source: Harness, output: Path, **overrides: Any) -> Harness:
    config = replace(
        source.config,
        run_id="run-reuse-baseline",
        run_root=str(source.tmp_path.parent / "reused_run"),
        baseline_training_path=str(output),
        **overrides,
    )
    trainer = MockTrainingRunner()
    services = replace(source.services, training_runner=trainer)
    return replace(
        source, config=config, services=services, trainer=trainer,
        runtime=itl.MethodRuntime(config, services=services),
    )


def _directory_bytes(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob("*") if path.is_file()
    }


def test_baseline_reuse_is_read_only_and_resumes_new_a_candidates(tmp_path: Path) -> None:
    source, output = _baseline_source(tmp_path)
    old_bytes = _directory_bytes(_root(source))
    harness = _reusing_baseline(source, output)
    assert "baseline_training_path" not in source.config.to_json()
    assert itl.MethodRuntimeConfig.from_json(harness.config.to_json()) == harness.config
    assert harness.config.config_sha256() != source.config.config_sha256()

    stopped = harness.runtime.run(stop_after="baseline_complete")
    assert stopped["phase"] == itl.PHASE_STOPPED
    assert stopped["counts"]["reused_baseline_samples"] == 20
    assert stopped["counts"]["new_victim_samples"] == 0
    assert stopped["counts"]["planned_new_victim_samples"] == 360
    assert _call_counts(harness) == (0, 0, 0, 0)
    baseline = _load(_root(harness) / "state.json")["baseline"]
    assert baseline["output_dir"] == str(output)
    assert baseline["reuse_source"]
    assert str(output) in json.dumps(baseline["reuse_source"])
    metric = baseline["metrics"]["sample_hit_rate"]
    assert metric["numerator"] == 0
    assert metric["denominator"] == 20
    assert baseline["counts"]["generation_failures"] == 1
    assert not (_root(harness) / "baseline" / "training").exists()
    assert _directory_bytes(_root(source)) == old_bytes

    resumed = harness.new_runtime().resume(stop_after="round_1_complete")
    assert resumed["phase"] == itl.PHASE_STOPPED
    assert resumed["counts"]["reused_baseline_samples"] == 20
    assert resumed["counts"]["new_victim_samples"] == 60
    assert resumed["counts"]["planned_new_victim_samples"] == 360
    assert _call_counts(harness) == (3, 3, 3, 9)
    assert len(_commit(harness, 1)["inductions"]) == 3
    assert all(str(config.output_dir).startswith(str(_root(harness))) for config in harness.trainer.calls)
    assert _directory_bytes(_root(source)) == old_bytes
    assert _load(_root(harness) / "state.json")["baseline"] == baseline
    _assert_no_b(harness)


@pytest.mark.parametrize("overrides", [
    {"victim_model": "DeepSeek-V3.2"},
    {"victim_temperature": 0.1},
    {"training_task_ids": ("BigCodeBench/42", "BigCodeBench/43")},
    {"victim_max_tokens": 4096},
    {"victim_request_timeout": 31.0},
    {"prepared_data_dir": "/different/prepared/data"},
    {"semgrep_config": "/different/semgrep/rules"},
])
def test_baseline_reuse_rejects_victim_or_input_parameter_changes_without_sampling(
    tmp_path: Path, overrides: dict[str, Any],
) -> None:
    source, output = _baseline_source(tmp_path)
    harness = _reusing_baseline(source, output, **overrides)
    old_bytes = _directory_bytes(_root(source))
    with pytest.raises(itl.MethodRuntimeError):
        harness.runtime.run(stop_after="baseline_complete")
    assert _call_counts(harness) == (0, 0, 0, 0)
    assert _directory_bytes(_root(source)) == old_bytes
    assert not (_root(harness) / "baseline" / "training").exists()


@pytest.mark.parametrize("missing", ["loop_config.json", "feedback_audit.json"])
def test_baseline_reuse_rejects_missing_evidence_without_falling_back_to_training(
    tmp_path: Path, missing: str,
) -> None:
    source, output = _baseline_source(tmp_path)
    (output / missing).unlink()
    harness = _reusing_baseline(source, output)
    old_bytes = _directory_bytes(_root(source))
    with pytest.raises((itl.MethodRuntimeError, OSError)):
        harness.runtime.run(stop_after="baseline_complete")
    assert _call_counts(harness) == (0, 0, 0, 0)
    assert _directory_bytes(_root(source)) == old_bytes
    assert not (_root(harness) / "baseline" / "training").exists()


@pytest.mark.parametrize("field", [
    "mock_scenario", "baseline_static", "baseline_config", "baseline_data_dir",
    "baseline_evaluators_config", "baseline_evaluation_dir",
])
def test_baseline_reuse_rejects_different_evaluation_identity_without_sampling(
    tmp_path: Path, field: str,
) -> None:
    source, output = _baseline_source(tmp_path)
    loop_path = output / "loop_config.json"
    payload = _load(loop_path)
    payload.pop("config_sha256")
    payload[field] = "other-scenario" if field == "mock_scenario" else "/other/evaluation/input"
    payload["config_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    write_json_atomic(loop_path, payload)
    harness = _reusing_baseline(source, output)
    old_bytes = _directory_bytes(_root(source))
    with pytest.raises(itl.MethodRuntimeError):
        harness.runtime.run(stop_after="baseline_complete")
    assert _call_counts(harness) == (0, 0, 0, 0)
    assert _directory_bytes(_root(source)) == old_bytes
    assert not (_root(harness) / "baseline" / "training").exists()


@pytest.mark.parametrize("policy", [
    {"victim_max_concurrency": 3},
    {"victim_concurrency_mode": "adaptive", "victim_min_concurrency": 4, "victim_max_concurrency": 16},
])
def test_baseline_reuse_accepts_transport_policy_change_and_records_source(tmp_path: Path, policy: dict) -> None:
    source, output = _baseline_source(tmp_path)
    old_bytes = _directory_bytes(_root(source))
    harness = _reusing_baseline(source, output, **policy)
    summary = harness.runtime.run(stop_after="baseline_complete")
    assert summary["phase"] == itl.PHASE_STOPPED
    assert summary["counts"]["new_victim_samples"] == 0
    assert summary["counts"]["reused_baseline_samples"] == 20
    assert len(harness.trainer.calls) == 0
    baseline = _load(_root(harness) / "state.json")["baseline"]
    assert baseline["reuse_source"]["source_concurrency_policy"] == {
        "concurrency_mode": "fixed", "min_concurrency": 1, "max_concurrency": 4,
    }
    assert _directory_bytes(_root(source)) == old_bytes
    harness.runtime.resume(stop_after="round_1_complete")
    assert len(harness.trainer.calls) == 3
    assert all(cfg.concurrency_mode == harness.config.victim_concurrency_mode and cfg.max_concurrency == harness.config.victim_max_concurrency and cfg.min_concurrency == harness.config.victim_min_concurrency for cfg in harness.trainer.calls)
    assert _directory_bytes(_root(source)) == old_bytes
