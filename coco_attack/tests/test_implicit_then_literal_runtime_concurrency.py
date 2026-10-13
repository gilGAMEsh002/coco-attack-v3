"""Transport settings stay separate from research identity and sample evidence."""
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json, write_json_atomic
from coco_attack.generation.service import run_generate
from coco_attack.iteration.training_loop import run_training_loop
from coco_methods import implicit_then_literal as itl
from coco_methods.implicit_then_literal.runtime import runtime_concurrency, set_runtime_concurrency
from coco_methods.implicit_then_literal.preflight import build_status_report
from coco_methods.implicit_then_literal.wiring import MethodRunConfig, make_victim_runner
from _itl_runtime_fakes import build_harness
from test_training_loop import snapshot_store, _make_config, requires_prepared


def test_same_run_settings_take_effect_next_candidate_without_retraining_baseline(tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1,
                            config_overrides={"enforce_formal_constants": False})
    harness.runtime.run(stop_after="baseline_complete")
    root = Path(harness.config.run_root)
    config_bytes = (root / "config.json").read_bytes()
    config_hash = harness.config.config_sha256()
    first = set_runtime_concurrency(root, mode="fixed", minimum=1, maximum=48)
    settings = set_runtime_concurrency(root, mode="adaptive", minimum=4, maximum=32)
    assert len(first["changes"]) == 1
    assert len(settings["changes"]) == 2
    assert settings["changes"][-1]["recorded_at"]
    report = build_status_report(MethodRunConfig(str(tmp_path), harness.config)).to_json()
    assert report["runtime_concurrency"]["victim_max_concurrency"] == 32
    assert "current live batch is unchanged" in report["runtime_concurrency_applies"]
    result = harness.runtime.resume()
    assert result["phase"] == itl.PHASE_DONE
    assert len(harness.trainer.calls) == 3
    assert harness.trainer.calls[0].max_concurrency == 4
    assert all(cfg.max_concurrency == 32 for cfg in harness.trainer.calls[1:])
    assert (root / "config.json").read_bytes() == config_bytes
    assert read_json(root / "state.json")["config_sha256"] == config_hash
    assert replace(harness.config, victim_max_concurrency=128).victim_max_concurrency == 128


@pytest.mark.parametrize("policy", [
    {"mode": "bad", "minimum": 1, "maximum": 4},
    {"mode": "adaptive", "minimum": 8, "maximum": 4},
    {"mode": "adaptive", "minimum": True, "maximum": 4},
    {"mode": "fixed", "minimum": 2, "maximum": 32},
])
def test_invalid_settings_do_not_change_original_config_or_history(tmp_path, policy):
    harness = build_harness(tmp_path)
    harness.runtime._load_config_file()
    root = Path(harness.config.run_root)
    before = (root / "config.json").read_bytes()
    with pytest.raises(itl.MethodRuntimeError):
        set_runtime_concurrency(root, **policy)
    assert not (root / "runtime_settings.json").exists()
    assert (root / "config.json").read_bytes() == before


def test_runtime_settings_cannot_override_research_fields(tmp_path):
    harness = build_harness(tmp_path)
    root = Path(harness.config.run_root)
    write_json_atomic(root / "runtime_settings.json", {"victim_model": "different"})
    with pytest.raises(itl.MethodRuntimeError, match="only concurrency"):
        runtime_concurrency(harness.config)


def test_dmx_partial_saved_loop_keeps_hash_and_routes_sdk_prefix_once(tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1,
        config_overrides={"enforce_formal_constants": False, "victim_source": "dmx", "check_service": "real"})
    runtime = harness.runtime
    runtime._load_config_file()
    kwargs = dict(snapshot_path=harness.config.initial_template_path, output_dir=tmp_path / "partial",
                  form=harness.initial.form, prompt_version=harness.initial.prompt_version, batch_id="partial")
    original = replace(runtime._training_config(**kwargs), model="openai/" + harness.config.victim_model)
    loop_path = Path(original.output_dir) / "loop_config.json"
    write_json_atomic(loop_path, {**original.to_json(), "config_sha256": original.run_config_sha256()})
    generation = Path(original.output_dir) / "generation"
    write_json_atomic(generation / "run_config.json", {"source": "dmx"})
    before = loop_path.read_bytes()
    set_runtime_concurrency(runtime.run_root, mode="adaptive", minimum=4, maximum=32)
    resumed = runtime._training_config(**kwargs)
    assert resumed.model == harness.config.victim_model
    captured = []
    make_victim_runner(harness.config, training_loop=lambda cfg, **kw: captured.append(cfg) or {})(resumed)
    assert captured[0].model == original.model
    assert captured[0].run_config_sha256() == original.run_config_sha256()
    assert (generation / "concurrency_override.json").is_file()
    assert read_json(generation / "concurrency_override.json") == {"concurrency_mode": "adaptive", "min_concurrency": 4, "max_concurrency": 32}
    assert loop_path.read_bytes() == before
    with pytest.raises(itl.MethodRuntimeError, match="research configuration differs"):
        runtime._training_config(**{**kwargs, "batch_id": "different-research-batch"})


@requires_prepared
def test_saved_loop_before_first_generation_preserves_override_through_public_loop(tmp_path, snapshot_store):
    snapshot_path, snapshot = snapshot_store
    original = _make_config(tmp_path / "batch", snapshot_path, max_concurrency=4,
                            repo_dir=str(Path(__file__).resolve().parents[2]), model="DeepSeek-V3.2")
    harness = build_harness(tmp_path / "method", rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1,
        config_overrides={"enforce_formal_constants": False, "assets_root": original.assets_root,
            "prepared_data_dir": original.data_dir, "repository_root": original.repo_dir,
            "training_task_ids": original.task_ids, "victim_repeats": original.repeats,
            "victim_model": original.model})
    runtime = harness.runtime
    runtime._load_config_file()
    loop_path = Path(original.output_dir) / "loop_config.json"
    write_json_atomic(loop_path, {**original.to_json(), "config_sha256": original.run_config_sha256()})
    before = loop_path.read_bytes()
    set_runtime_concurrency(runtime.run_root, mode="adaptive", minimum=4, maximum=32)
    resumed = runtime._training_config(snapshot_path=original.snapshot_path, output_dir=Path(original.output_dir),
                                      form=original.form, prompt_version=original.prompt_version, batch_id=original.batch_id)
    assert resumed.run_config_sha256() == original.run_config_sha256()
    generation = Path(original.output_dir) / "generation"
    assert not (generation / "run_config.json").exists()
    observed = []
    def generate(config_path, data_dir, prompts_dir, run_dir, **kwargs):
        observed.append(read_json(Path(run_dir) / "concurrency_override.json"))
        return run_generate(config_path, data_dir, prompts_dir, run_dir, **kwargs)
    first_manifest = run_training_loop(resumed, generation_step=generate)
    summary = read_json(generation / "generation_summary.json")
    assert observed == [{"concurrency_mode": "adaptive", "min_concurrency": 4, "max_concurrency": 32}]
    assert summary["concurrency"]["max_concurrency"] == 32
    assert read_json(generation / "run_config.json")["config"]["max_concurrency"] == 4
    assert loop_path.read_bytes() == before
    raw_samples = (generation / "generations.jsonl").read_bytes()
    # A completed public loop skips generation entirely even with new settings.
    set_runtime_concurrency(runtime.run_root, mode="fixed", minimum=1, maximum=64)
    second = run_training_loop(resumed, generation_step=lambda *args, **kw: pytest.fail("completed samples must not be regenerated"))
    assert second == first_manifest  # complete cached loop returns its original manifest
    assert (generation / "generations.jsonl").read_bytes() == raw_samples
