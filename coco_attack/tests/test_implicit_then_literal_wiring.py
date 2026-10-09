"""Wiring/source tests for ``implicit_then_literal`` subplan 04-a (offline).

All tests are offline: credentials, provider construction and the generation
boundary are sentinels/spies that fail the test if the real path is reached.
No model, Docker, Semgrep or credential file is touched.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.iteration.action_runtime import RoleCallConfig, ScriptedMockSource
from coco_attack.iteration.training_loop import TrainingLoopConfig
from coco_attack.method import implicit_then_literal as itl

from _itl_runtime_fakes import build_harness


def _role_config(model: str, source: str) -> RoleCallConfig:
    return RoleCallConfig(
        role="implicit_then_literal_proposer", model=model, source=source
    )


def _training_config(*, source: str, model: str = "DeepSeek-V3.2") -> TrainingLoopConfig:
    return TrainingLoopConfig(
        snapshot_path="/tmp/itl/snapshot.json",
        assets_root="/tmp/itl/assets",
        data_dir="/tmp/itl/data",
        output_dir="/tmp/itl/out",
        task_ids=("BigCodeBench/13", "BigCodeBench/1105"),
        repeats=10,
        stage="search",
        form="poisoned_fewshot_cot",
        prompt_version="1",
        model=model,
        batch_id="itl-test",
        source=source,
    )


def test_effective_model_name_maps_provider_prefix_separately() -> None:
    assert itl.effective_model_name("deepseek-v4-flash") == "openai/deepseek-v4-flash"
    assert itl.effective_model_name("DeepSeek-V3.2") == "openai/DeepSeek-V3.2"
    # Unknown names get the standard prefix, never a silent substitution.
    assert itl.effective_model_name("other-model") == "openai/other-model"


def test_content_identity_reports_missing_and_hashes_files(tmp_path: Path) -> None:
    assert itl.content_identity(None) == "missing"
    assert itl.content_identity(tmp_path / "nope") == "missing"
    target = tmp_path / "a.json"
    target.write_text("{}", encoding="utf-8")
    first = itl.content_identity(target)
    target.write_text('{"x": 1}', encoding="utf-8")
    assert itl.content_identity(target) != first


def test_lazy_dmx_role_source_defers_credentials_and_build() -> None:
    calls = {"cred": 0, "build": 0}
    built: list[RoleCallConfig] = []

    def credential_loader() -> str:
        calls["cred"] += 1
        return "sentinel"

    def provider_builder(config: RoleCallConfig, api_key: str) -> ScriptedMockSource:
        calls["build"] += 1
        built.append(config)
        return ScriptedMockSource(["ok"])

    source = itl.LazyDmxRoleSource(
        _role_config("deepseek-v4-flash", "dmx"),
        credential_loader=credential_loader,
        provider_builder=provider_builder,
    )
    # Nothing is loaded/built until the first real request.
    assert (calls["cred"], calls["build"]) == (0, 0)
    assert source.build_count == 0 and source.credential_load_count == 0

    source.generate([{"role": "user", "content": "hi"}], rollout_id=1, attempt_index=0)
    assert (calls["cred"], calls["build"]) == (1, 1)
    assert source.build_count == 1
    assert built[0].model == "openai/deepseek-v4-flash"
    assert built[0].role == "implicit_then_literal_proposer"


def test_victim_runner_refuses_source_mismatch_and_forwards_hooks(tmp_path: Path) -> None:
    seen: list[TrainingLoopConfig] = []

    def fake_loop(config: TrainingLoopConfig, **kwargs: object) -> dict[str, object]:
        seen.append(config)
        return {"completion": "complete", "candidate_hash": "x"}

    harness = build_harness(tmp_path, rounds=1)
    runner = itl.make_victim_runner(harness.config, training_loop=fake_loop)

    runner(_training_config(source=harness.config.victim_source))
    assert seen and seen[0].source == harness.config.victim_source

    with pytest.raises(itl.WiringError):
        runner(_training_config(source="dmx"))  # no hardcoded mock fallback


def test_assemble_services_mock_requires_explicit_doubles(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    loaded = itl.MethodRunConfig(project_root=str(tmp_path), method=harness.config)
    with pytest.raises(itl.WiringError):
        itl.assemble_services(loaded)
    services = itl.assemble_services(
        loaded,
        doubles=itl.WiringDoubles(
            proposer_source=harness.proposer,
            inducer_source=harness.inducer,
            gate_runner=harness.gate,
            training_runner=harness.trainer,
        ),
    )
    assert services.proposer_source is harness.proposer
    assert services.inducer_source is harness.inducer


def test_assemble_services_real_builds_lazy_sources(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    method = replace(
        harness.config,
        proposer_config=replace(harness.config.proposer_config, source="dmx"),
        inducer_config=replace(harness.config.inducer_config, source="dmx"),
        victim_source="dmx",
        check_service="real",
    )
    loaded = itl.MethodRunConfig(project_root=str(tmp_path), method=method)
    built: list[RoleCallConfig] = []

    def provider_builder(config: RoleCallConfig, api_key: str) -> ScriptedMockSource:
        built.append(config)
        return ScriptedMockSource(["ok"])

    services = itl.assemble_services(
        loaded,
        doubles=itl.WiringDoubles(
            credential_loader=lambda: "sentinel",
            provider_builder=provider_builder,
            gate_runner=harness.gate,
            training_runner=harness.trainer,
            allow_mixed_sources=True,
        ),
    )
    assert isinstance(services.proposer_source, itl.LazyDmxRoleSource)
    assert services.proposer_source.build_count == 0
    services.proposer_source.generate(
        [{"role": "user", "content": "hi"}], rollout_id=1, attempt_index=0
    )
    assert services.proposer_source.build_count == 1
    assert built[0].model == "openai/deepseek-v4-flash"


def test_identity_change_on_same_run_path_is_rejected(tmp_path: Path) -> None:
    harness = build_harness(tmp_path / "run", rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE

    other = build_harness(tmp_path / "other", rounds=1)
    changed = replace(
        harness.config, initial_template_path=other.config.initial_template_path
    )
    runtime = itl.MethodRuntime(changed, services=harness.services)
    with pytest.raises(itl.MethodRuntimeError):
        runtime.run()


def test_run_config_round_trip_recomputes_input_binding(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    payload = {**harness.config.to_json(), "project_root": str(tmp_path)}
    loaded = itl.MethodRunConfig.from_json(payload)
    rebuilt = itl.MethodRunConfig.from_json(loaded.to_json())
    assert rebuilt.config_sha256() == loaded.config_sha256()
    assert dict(rebuilt.method.input_binding) == dict(loaded.method.input_binding)
    assert "initial_template" in dict(rebuilt.method.input_binding)


def test_victim_runner_applies_provider_prefix_for_dmx(tmp_path: Path) -> None:
    seen: list[TrainingLoopConfig] = []

    def fake_loop(config: TrainingLoopConfig, **kwargs: object) -> dict[str, object]:
        seen.append(config)
        return {"completion": "complete", "candidate_hash": "x"}

    harness = build_harness(tmp_path, rounds=1)
    method = replace(harness.config, victim_source="dmx", check_service="real")
    runner = itl.make_victim_runner(method, training_loop=fake_loop)
    runner(_training_config(source="dmx", model="DeepSeek-V3.2"))
    assert seen[0].model == "openai/DeepSeek-V3.2"


def test_assemble_services_real_rejects_mock_doubles(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    method = replace(
        harness.config,
        proposer_config=replace(harness.config.proposer_config, source="dmx"),
        inducer_config=replace(harness.config.inducer_config, source="dmx"),
        victim_source="dmx",
        check_service="real",
    )
    loaded = itl.MethodRunConfig(project_root=str(tmp_path), method=method)
    with pytest.raises(itl.WiringError):
        itl.assemble_services(
            loaded, doubles=itl.WiringDoubles(training_runner=harness.trainer)
        )
