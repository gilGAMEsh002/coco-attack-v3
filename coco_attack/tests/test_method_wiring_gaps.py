"""Task-06 §6 G1–G3 regression tests (offline; no keys/models/Docker/Semgrep)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from coco_attack import cli
from coco_attack.iteration import training_loop
from coco_attack.iteration.training_loop import _generation_config, _subprocess_generation_step, _subprocess_resume_generation_step
from coco_attack.method.preflight import build_preflight_report
from coco_attack.method.single_candidate_ab import (
    MethodConfig,
    MethodRun,
    MutatorRole,
    VictimRole,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
C0_SNAPSHOT = (
    REPO_DIR
    / "cocota_runs/phase04/poison-materialize-v2/store/cwe078-0"
    / "a22ab2b85c36a243baf46318efb59e89bc74c222613df8bc33037effd65d6061"
)
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and C0_SNAPSHOT.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)


def _base_config(tmp_path: Path, **overrides: Any) -> MethodConfig:
    values: dict[str, Any] = {
        "run_dir": str(tmp_path / "run"),
        "snapshot_path": str(C0_SNAPSHOT),
        "snapshot_store": str(tmp_path / "snapshots"),
        "assets_root": str(ASSETS_DIR),
        "data_dir": str(PREPARED_DIR),
        "max_rounds": 1,
        "mutator": MutatorRole(source="dmx", model="review-mutator"),
        "victim": VictimRole(source="dmx", model="review-victim"),
    }
    values.update(overrides)
    return MethodConfig(**values)


# --------------------------------------------------------------------------- #
# G1: victim parameters and repo_dir reach the training/generation path
# --------------------------------------------------------------------------- #


def test_g1_training_config_carries_victim_request_and_semgrep_params(tmp_path: Path) -> None:
    config = _base_config(
        tmp_path,
        repo_dir=str(REPO_DIR),
        semgrep_timeout_seconds=180.0,
        victim=VictimRole(source="dmx", model="review-victim", request_timeout=123.0, max_request_attempts=7),
    )
    snapshot = SimpleNamespace(content_sha256=lambda: "a" * 64)
    training = MethodRun(config)._training_config(snapshot, 1, "A")

    assert training.repo_dir == str(REPO_DIR)
    assert training.request_timeout == 123.0
    assert training.max_request_attempts == 7
    assert training.semgrep_timeout_seconds == 180.0

    prepared = SimpleNamespace(combination_id="cwe078-0", oracle_id="cwe078-0")
    generation = _generation_config(training, prepared)
    assert generation.request_timeout == 123.0
    assert generation.max_request_attempts == 7


def test_g1_generation_subprocess_and_resume_pass_repo_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def _fake_run(command, capture_output, text):  # noqa: ANN001
        captured["command"] = list(command)

        class _Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Completed()

    monkeypatch.setattr(training_loop.subprocess, "run", _fake_run)
    _subprocess_generation_step("cfg", "data", "prompts", "out", repo_dir="/some/repo")
    assert "--repo-dir" in captured["command"] and "/some/repo" in captured["command"]
    _subprocess_resume_generation_step("/run-dir", repo_dir="/some/repo")
    assert "--repo-dir" in captured["command"] and "/some/repo" in captured["command"]


@requires_prepared
def test_g1_cli_repo_dir_flows_to_method_and_training(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI's effective repo_dir reaches both the method config and the training."""

    for index, mutator_source in enumerate(("dmx", "mock")):
        config = _base_config(
            tmp_path / f"g1-{index}",
            mutator=MutatorRole(source=mutator_source, model="review-mutator"),
            victim=VictimRole(source="dmx", model="review-victim"),
        )
        config_path = tmp_path / f"g1-{index}.json"
        config_path.write_text(json.dumps(config.to_json()), encoding="utf-8")
        script = tmp_path / "script.json"
        script.write_text("[]", encoding="utf-8")
        seen: dict[str, Any] = {}

        def _capture(config_obj: Any, **kwargs: Any) -> dict[str, Any]:
            training = MethodRun(config_obj)._training_config(
                SimpleNamespace(content_sha256=lambda: "a" * 64), 1, "A"
            )
            seen.update({"method": config_obj.repo_dir, "victim": training.repo_dir})
            return {"phase": "done"}

        monkeypatch.setattr(cli, "run_method", _capture)
        args = [
            "run-method-ab", "--config", str(config_path),
            "--repo-dir", str(REPO_DIR), "--mock-gate", "--allow-real-training",
        ]
        if mutator_source == "mock":
            args += ["--mutator-script", str(script)]
        code = cli.main(args)
        assert code == 0
        assert seen["method"] == str(REPO_DIR)
        assert seen["victim"] == str(REPO_DIR)  # mock mutator + DMX victim also receives it


@requires_prepared
def test_g1_conflicting_repo_dir_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _base_config(
        tmp_path,
        repo_dir=str(tmp_path / "other-repo"),
        mutator=MutatorRole(source="mock", model=""),
        victim=VictimRole(source="dmx", model="review-victim"),
    )
    (tmp_path / "other-repo").mkdir()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config.to_json()), encoding="utf-8")
    script = tmp_path / "script.json"
    script.write_text("[]", encoding="utf-8")
    called: dict[str, Any] = {}
    monkeypatch.setattr(cli, "run_method", lambda *a, **k: called.setdefault("run", True))
    code = cli.main(
        [
            "run-method-ab", "--config", str(config_path),
            "--repo-dir", str(REPO_DIR), "--mutator-source", "mock",
            "--mutator-script", str(script), "--mock-gate", "--allow-real-training",
        ]
    )
    assert code != 0
    assert "run" not in called


# --------------------------------------------------------------------------- #
# G2: CLI source override must match the configured role identity
# --------------------------------------------------------------------------- #


def _write_override_artifacts(tmp_path: Path, config: MethodConfig) -> tuple[Path, Path]:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config.to_json()), encoding="utf-8")
    script = tmp_path / "script.json"
    script.write_text("[]", encoding="utf-8")
    return config_path, script


def test_g2_source_override_mismatch_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _base_config(tmp_path, mutator=MutatorRole(source="dmx", model="review-mutator"))
    config_path, script = _write_override_artifacts(tmp_path, config)
    called: dict[str, Any] = {}

    def _fake_run_method(*args: Any, **kwargs: Any) -> dict[str, Any]:
        called["run"] = True
        return {"phase": "done"}

    monkeypatch.setattr(cli, "run_method", _fake_run_method)
    # config says dmx, CLI says mock -> rejected before any work.
    code = cli.main(
        [
            "run-method-ab", "--config", str(config_path),
            "--mutator-source", "mock", "--mutator-script", str(script),
            "--mock-gate", "--mock-training",
        ]
    )
    assert code != 0
    assert "run" not in called  # no source call, no state written
    assert not (Path(config.run_dir) / "state.json").exists()


def test_g2_reverse_source_override_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _base_config(tmp_path, mutator=MutatorRole(source="mock", model=""))
    config_path, _script = _write_override_artifacts(tmp_path, config)
    called: dict[str, Any] = {}
    monkeypatch.setattr(cli, "run_method", lambda *a, **k: called.setdefault("run", True))
    # config says mock, CLI says dmx -> rejected (before resolving --repo-dir).
    code = cli.main(
        [
            "run-method-ab", "--config", str(config_path),
            "--mutator-source", "dmx", "--repo-dir", str(REPO_DIR),
            "--mock-gate", "--mock-training",
        ]
    )
    assert code != 0
    assert "run" not in called


# --------------------------------------------------------------------------- #
# G3: preflight baseline/execution readiness and exit code
# --------------------------------------------------------------------------- #


@requires_prepared
def test_g3_missing_baseline_and_execution_config_is_not_ready(tmp_path: Path) -> None:
    config = _base_config(
        tmp_path,
        baseline_static=str(tmp_path / "missing.jsonl"),
        baseline_config=str(tmp_path / "missing-config.json"),
        execution_config=str(tmp_path / "missing-execution.json"),
        semgrep_config=None,
    )
    report = build_preflight_report(config)
    assert report["offline_preflight_passed"] is False
    assert report["readiness"] == "not_ready"
    assert report["baseline"]["compatible_with_victim"] is False
    assert report["baseline"]["real_research_delta_possible"] is False
    assert any("execution config" in item for item in report["errors"])
    assert any("baseline" in item for item in report["errors"])


STAGE03 = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2"
BASELINE_UNIT = STAGE03 / "units/cwe078-0__clean_fewshot_cot__t0.7r5/search"


def _real_baseline_config(tmp_path: Path, **overrides: Any) -> MethodConfig:
    values: dict[str, Any] = {
        "repo_dir": str(REPO_DIR),
        "mutator": MutatorRole(source="mock", model=""),
        "victim": VictimRole(source="dmx", model="openai/DeepSeek-V3.2", temperature=0.7, repeats=5),
        "baseline_static": str(BASELINE_UNIT / "static/evaluations.jsonl"),
        "baseline_config": str(BASELINE_UNIT / "configs/evaluation.json"),
        "baseline_data_dir": str(STAGE03 / "inputs/data"),
        "baseline_evaluators_config": str(BASELINE_UNIT / "configs/evaluators.json"),
        "baseline_evaluation_dir": str(BASELINE_UNIT / "evaluation"),
        "execution_config": str(REPO_DIR / "coco_attack/configs/execution.local.json"),
        "semgrep_config": str(ASSETS_DIR / "third_party/semgrep"),
    }
    values.update(overrides)
    return _base_config(tmp_path, **values)


@requires_prepared
def test_g3_valid_baseline_source_clears_the_blocker(tmp_path: Path) -> None:
    """A real schema result with the exact two-task matrix is comparable."""

    report = build_preflight_report(_real_baseline_config(tmp_path))
    assert report["baseline"]["matrix"]["ok"] is True
    assert report["baseline"]["matrix"]["observed"] == 10  # two tasks x 5 repeats
    assert report["baseline"]["compatible_with_victim"] is True
    assert report["baseline"]["real_research_delta_possible"] is True
    assert report["example_checks"]["execution_config_valid"] is True
    assert report["example_checks"]["semgrep_config_valid"] is True
    assert report["offline_preflight_passed"] is True


@requires_prepared
def test_g3_wrong_victim_and_missing_repeat_block(tmp_path: Path) -> None:
    wrong_model = build_preflight_report(
        _real_baseline_config(
            tmp_path / "wrong",
            victim=VictimRole(source="dmx", model="openai/Other-Model", temperature=0.7, repeats=5),
        )
    )
    assert wrong_model["baseline"]["compatible_with_victim"] is False
    assert any(
        item.get("key") == "model" for item in wrong_model["baseline"]["blocking"]
    )

    # A truncated result (missing one repeat) must fail the exact matrix.
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    rows = [
        json.loads(line)
        for line in (BASELINE_UNIT / "static/evaluations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    train_rows = [row for row in rows if row.get("task_id") in {"BigCodeBench/13", "BigCodeBench/1105"}]
    truncated = baseline / "evaluations.jsonl"
    truncated.write_text(
        "\n".join(json.dumps(row) for row in train_rows[:-1]) + "\n", encoding="utf-8"
    )
    manifest = json.loads((BASELINE_UNIT / "static/manifest.json").read_text(encoding="utf-8"))
    manifest["inputs"]["evaluations"]["sha256"] = _sha256(truncated)
    (baseline / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    truncated_report = build_preflight_report(
        _real_baseline_config(
            tmp_path / "truncated",
            baseline_static=str(truncated),
            baseline_config=str(BASELINE_UNIT / "configs/evaluation.json"),
        )
    )
    assert truncated_report["baseline"]["matrix"]["ok"] is False
    assert truncated_report["baseline"]["compatible_with_victim"] is False


@requires_prepared
def test_g3_invalid_execution_or_rules_are_not_ready(tmp_path: Path) -> None:
    empty_execution = tmp_path / "execution.json"
    empty_execution.write_text("{}", encoding="utf-8")
    empty_rules = tmp_path / "rules"
    empty_rules.mkdir()
    (empty_rules / "other.yml").write_text("- id: some-other-rule\n", encoding="utf-8")
    report = build_preflight_report(
        _real_baseline_config(
            tmp_path, execution_config=str(empty_execution), semgrep_config=str(empty_rules)
        )
    )
    assert report["example_checks"]["execution_config_valid"] is False
    assert report["example_checks"]["semgrep_config_valid"] is False
    assert report["offline_preflight_passed"] is False
    assert report["readiness"] == "not_ready"
    assert any("execution config" in item for item in report["errors"])
    assert any("Semgrep rules" in item for item in report["errors"])


@requires_prepared
def test_g3_cli_exit_code_follows_not_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _base_config(
        tmp_path,
        baseline_static=str(tmp_path / "missing.jsonl"),
        baseline_config=str(tmp_path / "missing-config.json"),
        execution_config=str(tmp_path / "missing-execution.json"),
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config.to_json()), encoding="utf-8")
    code = cli.main(["preflight-method", "--config", str(config_path), "--report", str(tmp_path / "p.json")])
    saved = json.loads((tmp_path / "p.json").read_text(encoding="utf-8"))
    assert saved["offline_preflight_passed"] is False
    assert code != 0  # not_ready is a non-zero exit


def _sha256(path: Path) -> str:
    from coco_attack.assets.artifacts import sha256_file

    return sha256_file(path)
