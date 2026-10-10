"""CLI tests for ``implicit_then_literal`` subplan 04-b (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack import cli
from coco_attack.assets.artifacts import read_json, write_json_atomic
from coco_attack.iteration.action_runtime import RoleCallConfig
from coco_methods import implicit_then_literal as itl
from coco_methods.implicit_then_literal.wiring import MethodRunConfig

from _itl_runtime_fakes import build_harness

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "cocota_data_eval_result"
BASELINE_PATH = ASSETS / (
    "prompts_shared/experiments/cwe078/"
    "cwe078_initial_poisoned_code_shell_true_cot_clean/snapshot_store/cwe078-0/"
    "99fe015a51d0783b396513cfc821c6fb492c3b167e85c47309b90a32f3aae449/snapshot.json"
)
PREPARED = REPO / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
requires_assets = pytest.mark.skipif(
    not BASELINE_PATH.is_file() or not PREPARED.is_dir(),
    reason="read-only assets / prepared data are not present",
)


def _harness_config_file(tmp_path: Path, harness) -> Path:
    from dataclasses import replace

    method = replace(
        harness.config,
        repository_root=str(REPO),
        assets_root=str(ASSETS),
        prepared_data_dir=str(PREPARED),
        initial_template_path=str(BASELINE_PATH),
        comparison_baseline_path=str(BASELINE_PATH),
        semgrep_config=str(ASSETS / "third_party/semgrep"),
    )
    loaded = MethodRunConfig(project_root=str(REPO), method=method)
    path = tmp_path / "run_config.json"
    write_json_atomic(path, loaded.to_json())
    return path


def _real_config_file(tmp_path: Path, **overrides: object) -> Path:
    values: dict[str, object] = dict(
        run_id="cli-real",
        run_root=str(tmp_path / "real-run"),
        repository_root=str(REPO),
        assets_root=str(ASSETS),
        prepared_data_dir=str(PREPARED),
        initial_template_path=str(BASELINE_PATH),
        comparison_baseline_path=str(BASELINE_PATH),
        proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="mock"),
        inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="mock"),
    )
    values.update(overrides)
    loaded = MethodRunConfig(
        project_root=str(REPO), method=itl.MethodRuntimeConfig(**values)
    )
    path = tmp_path / "real_config.json"
    write_json_atomic(path, loaded.to_json())
    return path


def test_cli_usage_and_preflight_exit_codes(tmp_path: Path) -> None:
    # Missing config file -> usage error.
    assert cli.main(["implicit-then-literal-preflight", "--config", str(tmp_path / "nope.json")]) == cli.EXIT_USAGE


@requires_assets
def test_cli_preflight_passes_and_reports(tmp_path: Path) -> None:
    config_path = _real_config_file(tmp_path)
    assert (
        cli.main(
            [
                "implicit-then-literal-preflight",
                "--config",
                str(config_path),
                "--report",
                str(tmp_path / "preflight.json"),
            ]
        )
        == cli.EXIT_OK
    )
    report = read_json(tmp_path / "preflight.json")
    assert report["offline_preflight_passed"] is True
    assert not (tmp_path / "real-run" / "state.json").exists()


def _real_services(harness):
    from dataclasses import replace as _replace

    from coco_methods.implicit_then_literal import load_comparison_baseline

    return _replace(
        harness.services,
        baseline_loader=lambda **kwargs: load_comparison_baseline(
            repository_root=str(REPO)
        ),
    )


def test_cli_run_stop_resume_and_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = build_harness(tmp_path, rounds=2)
    config_path = _harness_config_file(tmp_path, harness)
    services = _real_services(harness)
    monkeypatch.setattr(
        cli, "_assemble_itl_services", lambda config, doubles=None: services
    )
    run_root = harness.config.run_root

    # Stop at the baseline checkpoint.
    assert (
        cli.main(
            ["implicit-then-literal-run", "--config", str(config_path), "--stop-after", "baseline_complete"]
        )
        == cli.EXIT_STOPPED
    )
    assert not (Path(run_root) / "rounds" / "1" / "A" / "plan.json").exists()

    # Read-only status must not advance the run.
    proposer_before = harness.proposer.call_count()
    assert cli.main(["implicit-then-literal-status", "--run-root", run_root]) == cli.EXIT_OK
    assert harness.proposer.call_count() == proposer_before

    # Resume to the round-1 checkpoint, then to completion.
    assert (
        cli.main(
            ["implicit-then-literal-resume", "--run-root", run_root, "--stop-after", "round_1_complete"]
        )
        == cli.EXIT_STOPPED
    )
    assert not (Path(run_root) / "rounds" / "2" / "A" / "plan.json").exists()
    assert cli.main(["implicit-then-literal-resume", "--run-root", run_root]) == cli.EXIT_OK
    state = read_json(Path(run_root) / "state.json")
    assert state["phase"] == "done"


def test_cli_retry_wrong_target_does_not_increment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = build_harness(tmp_path, rounds=1)
    config_path = _harness_config_file(tmp_path, harness)
    services = _real_services(harness)
    monkeypatch.setattr(
        cli, "_assemble_itl_services", lambda config, doubles=None: services
    )
    run_root = harness.config.run_root
    cli.main(["implicit-then-literal-run", "--config", str(config_path)])
    state_before = read_json(Path(run_root) / "state.json")
    retry_before = dict(state_before.get("retry_index") or {})

    # A completed run has no paused induction -> usage error, no retry bump.
    code = cli.main(
        [
            "implicit-then-literal-retry",
            "--run-root",
            run_root,
            "--round",
            "1",
            "--stage",
            "A",
            "--candidate-id",
            "not-a-real-candidate",
        ]
    )
    assert code == cli.EXIT_USAGE
    state_after = read_json(Path(run_root) / "state.json")
    assert dict(state_after.get("retry_index") or {}) == retry_before


def test_cli_run_refuses_output_inside_readonly_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    harness = build_harness(tmp_path, rounds=1)
    bad_run = ASSETS / "itl-should-not-be-created"
    method = replace(
        harness.config,
        run_root=str(bad_run),
        repository_root=str(REPO),
        assets_root=str(ASSETS),
        prepared_data_dir=str(PREPARED),
        initial_template_path=str(BASELINE_PATH),
        comparison_baseline_path=str(BASELINE_PATH),
        semgrep_config=str(ASSETS / "third_party/semgrep"),
    )
    loaded = MethodRunConfig(project_root=str(REPO), method=method)
    path = tmp_path / "bad.json"
    write_json_atomic(path, loaded.to_json())
    assembled = {"called": False}
    monkeypatch.setattr(
        cli,
        "_assemble_itl_services",
        lambda config, doubles=None: assembled.__setitem__("called", True),
    )
    try:
        assert cli.main(["implicit-then-literal-run", "--config", str(path)]) == cli.EXIT_BLOCKING
        assert assembled["called"] is False
        assert not bad_run.exists()
    finally:
        if bad_run.exists():
            import shutil

            shutil.rmtree(bad_run)


@requires_assets
def test_mock_cli_runs_cross_process(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    config = {
        "project_root": str(REPO),
        "run_id": "itl-cli-subprocess",
        "run_root": str(tmp_path / "run"),
        "repository_root": str(REPO),
        "assets_root": str(ASSETS),
        "prepared_data_dir": str(PREPARED),
        "initial_template_path": str(BASELINE_PATH),
        "comparison_baseline_path": str(BASELINE_PATH),
        "semgrep_config": str(ASSETS / "third_party/semgrep"),
        "execution_config_path": str(
            REPO / "coco_attack/configs/implicit_then_literal/execution.example.json"
        ),
        "proposer_config": {
            "role": "implicit_then_literal_proposer",
            "model": "deepseek-v4-flash",
            "source": "mock",
            "temperature": 0.7,
            "max_tokens": 384000,
            "request_timeout": 120.0,
            "max_request_attempts": 2,
            "protocol_version": "itl-a-proposal-v2",
        },
        "inducer_config": {
            "role": "implicit_then_literal_inducer",
            "model": "deepseek-v4-flash",
            "source": "mock",
            "temperature": 0.7,
            "max_tokens": 384000,
            "request_timeout": 120.0,
            "max_request_attempts": 2,
            "protocol_version": "itl-judge-induction-v2",
        },
        "victim_source": "mock",
        "victim_model": "DeepSeek-V3.2",
        "check_service": "mock",
        "rounds": 2,
        "a_slots": 5,
        "b_slots_per_seed": 5,
        "top_k": 5,
        "enforce_formal_constants": False,
    }
    config_path = tmp_path / "mock_config.json"
    write_json_atomic(config_path, config)
    env = {
        "PYTHONPATH": str(REPO / "coco_attack/src"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    doubles = "coco_methods.implicit_then_literal.mock_services"

    def run(args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "coco_attack", *args],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            env=env,
        )

    assert (
        run(
            [
                "implicit-then-literal-run",
                "--config",
                str(config_path),
                "--doubles-module",
                doubles,
                "--stop-after",
                "baseline_complete",
            ]
        ).returncode
        == cli.EXIT_STOPPED
    )
    assert not (tmp_path / "run" / "rounds" / "1" / "A" / "plan.json").exists()
    assert (
        run(
            [
                "implicit-then-literal-resume",
                "--run-root",
                str(tmp_path / "run"),
                "--doubles-module",
                doubles,
                "--stop-after",
                "round_1_complete",
            ]
        ).returncode
        == cli.EXIT_STOPPED
    )
    assert (
        run(
            [
                "implicit-then-literal-resume",
                "--run-root",
                str(tmp_path / "run"),
                "--doubles-module",
                doubles,
            ]
        ).returncode
        == cli.EXIT_OK
    )
    status = run(["implicit-then-literal-status", "--run-root", str(tmp_path / "run")])
    assert status.returncode == cli.EXIT_OK
    payload = read_json(tmp_path / "run" / "state.json")
    assert payload["phase"] == "done"


@requires_assets
def test_cli_real_config_rejects_mock_doubles_module(tmp_path: Path) -> None:
    config_path = _real_config_file(
        tmp_path,
        proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="dmx"),
        inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="dmx"),
        victim_source="dmx",
        check_service="real",
        semgrep_config=str(ASSETS / "third_party/semgrep"),
    )
    code = cli.main(
        [
            "implicit-then-literal-run",
            "--config",
            str(config_path),
            "--doubles-module",
            "coco_methods.implicit_then_literal.mock_services",
        ]
    )
    assert code == cli.EXIT_USAGE
    assert not (tmp_path / "real-run" / "state.json").exists()


def test_cli_resume_allow_unknown_retry_defaults_off() -> None:
    parser = cli.build_parser()
    default = parser.parse_args(["implicit-then-literal-resume", "--run-root", "/tmp/run"])
    assert default.allow_unknown_retry is False
    explicit = parser.parse_args(
        [
            "implicit-then-literal-resume",
            "--run-root",
            "/tmp/run",
            "--allow-unknown-retry",
        ]
    )
    assert explicit.allow_unknown_retry is True


def test_cli_resume_forwards_allow_unknown_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The explicit unknown-retry flag must reach ``MethodRuntime.resume``."""

    harness = build_harness(tmp_path, rounds=1)
    config_path = _harness_config_file(tmp_path, harness)
    services = _real_services(harness)
    monkeypatch.setattr(
        cli, "_assemble_itl_services", lambda config, doubles=None: services
    )
    run_root = harness.config.run_root
    assert (
        cli.main(
            [
                "implicit-then-literal-run",
                "--config",
                str(config_path),
                "--stop-after",
                "baseline_complete",
            ]
        )
        == cli.EXIT_STOPPED
    )

    captured: dict[str, object] = {}

    class FakeRuntime:
        def __init__(self, config, *, services):  # noqa: ANN001
            captured["config"] = config

        def resume(self, *, stop_after=None, allow_retry_after_unknown=False):
            captured["stop_after"] = stop_after
            captured["allow_retry_after_unknown"] = allow_retry_after_unknown
            return {"phase": "done"}

    monkeypatch.setattr(itl, "MethodRuntime", FakeRuntime)
    assert (
        cli.main(
            [
                "implicit-then-literal-resume",
                "--run-root",
                run_root,
                "--allow-unknown-retry",
            ]
        )
        == cli.EXIT_OK
    )
    assert captured["allow_retry_after_unknown"] is True


def test_cli_retry_accepts_run_control_flags() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "implicit-then-literal-retry",
            "--run-root",
            "/tmp/run",
            "--round",
            "1",
            "--stage",
            "B",
            "--candidate-id",
            "c",
            "--stop-after",
            "round_1_complete",
            "--allow-unknown-retry",
        ]
    )
    assert args.stop_after == "round_1_complete"
    assert args.allow_unknown_retry is True
