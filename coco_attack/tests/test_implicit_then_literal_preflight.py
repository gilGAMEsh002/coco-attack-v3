"""Read-only preflight tests for ``implicit_then_literal`` subplan 04-b."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_file, write_json_atomic
from coco_attack.iteration.action_runtime import RoleCallConfig
from coco_attack.method import implicit_then_literal as itl
from coco_attack.method.implicit_then_literal.wiring import MethodRunConfig

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "cocota_data_eval_result"
BASELINE_REL = (
    "prompts_shared/experiments/cwe078/"
    "cwe078_initial_poisoned_code_shell_true_cot_clean/snapshot_store/cwe078-0/"
    "99fe015a51d0783b396513cfc821c6fb492c3b167e85c47309b90a32f3aae449/snapshot.json"
)
BASELINE_PATH = ASSETS / BASELINE_REL
PREPARED = REPO / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
requires_assets = pytest.mark.skipif(
    not BASELINE_PATH.is_file() or not PREPARED.is_dir(),
    reason="read-only assets / prepared data are not present",
)


def _loaded(tmp_path: Path, **overrides: object) -> MethodRunConfig:
    values: dict[str, object] = dict(
        run_id="preflight-test",
        run_root=str(tmp_path / "run"),
        repository_root=str(REPO),
        assets_root=str(ASSETS),
        prepared_data_dir=str(PREPARED),
        initial_template_path=str(BASELINE_PATH),
        comparison_baseline_path=str(BASELINE_PATH),
        proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="mock"),
        inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="mock"),
    )
    values.update(overrides)
    return MethodRunConfig(project_root=str(REPO), method=itl.MethodRuntimeConfig(**values))


@requires_assets
def test_preflight_passes_for_real_paths(tmp_path: Path) -> None:
    report = itl.build_preflight_report(_loaded(tmp_path))
    assert report.offline_preflight_passed, report.errors
    assert report.baseline_status == "snapshot_prepared"
    assert report.initial_template_sha256 != "missing"
    assert report.comparison_baseline_sha256 == itl.FIXED_BASELINE_CONTENT_SHA256
    assert report.sources["effective_models"]["victim"] == "openai/DeepSeek-V3.2"
    assert any("real model connectivity" in item for item in report.not_checked)


@requires_assets
def test_preflight_missing_initial_template(tmp_path: Path) -> None:
    report = itl.build_preflight_report(
        _loaded(tmp_path, initial_template_path=str(tmp_path / "nope" / "snapshot.json"))
    )
    assert not report.offline_preflight_passed
    assert any("initial template" in error for error in report.errors)


@requires_assets
def test_preflight_wrong_baseline_is_rejected(tmp_path: Path) -> None:
    # A different (valid) snapshot is not the fixed comparison baseline.
    other = itl.MethodRunConfig(
        project_root=str(REPO),
        method=itl.MethodRuntimeConfig(
            run_id="x",
            run_root=str(tmp_path / "x"),
            repository_root=str(REPO),
            assets_root=str(ASSETS),
            prepared_data_dir=str(PREPARED),
            initial_template_path=str(BASELINE_PATH),
            comparison_baseline_path=None,
            proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="mock"),
            inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="mock"),
        ),
    )
    assert not itl.build_preflight_report(other).offline_preflight_passed
    assert any(
        "comparison_baseline" in error for error in itl.build_preflight_report(other).errors
    )


@requires_assets
def test_preflight_container_budget_and_formal_constants(tmp_path: Path) -> None:
    execution = tmp_path / "execution.json"
    write_json_atomic(execution, {"limits": {"max_parallel_containers": 1}})
    budget = itl.build_preflight_report(
        _loaded(
            tmp_path,
            check_workers=3,
            execution_config_path=str(execution),
        )
    )
    assert any("max_parallel_containers" in error for error in budget.errors)

    relaxed = itl.build_preflight_report(
        _loaded(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1, enforce_formal_constants=False)
    )
    # Formal-off is allowed (warning) for an explicit offline mock config ...
    assert not any("formal constants are disabled" in error for error in relaxed.errors)
    assert any("formal constants are disabled" in warning for warning in relaxed.warnings)

    # ... but rejected for a real-source config.
    real = itl.build_preflight_report(
        _loaded(
            tmp_path / "real",
            proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="dmx"),
            inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="dmx"),
            victim_source="dmx",
            check_service="real",
            semgrep_config=str(ASSETS / "third_party/semgrep"),
            rounds=1,
            a_slots=1,
            b_slots_per_seed=1,
            top_k=1,
            enforce_formal_constants=False,
        )
    )
    assert any("formal constants are disabled" in error for error in real.errors)


@requires_assets
def test_preflight_is_read_only(tmp_path: Path) -> None:
    before = sha256_file(BASELINE_PATH)
    loaded = _loaded(tmp_path)
    itl.build_preflight_report(loaded)
    assert sha256_file(BASELINE_PATH) == before
    assert not (tmp_path / "run" / "state.json").exists()
    assert not (tmp_path / "run" / "actions").exists()
    assert not (tmp_path / "run" / "experience").exists()


def test_status_report_not_started(tmp_path: Path) -> None:
    loaded = MethodRunConfig(
        project_root=str(tmp_path),
        method=itl.MethodRuntimeConfig(
            run_id="s",
            run_root=str(tmp_path / "run"),
            repository_root=str(tmp_path),
            assets_root=str(tmp_path / "assets"),
            prepared_data_dir=str(tmp_path / "data"),
            initial_template_path=str(tmp_path / "s.json"),
            comparison_baseline_path=None,
            proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="mock"),
            inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="mock"),
            enforce_formal_constants=False,
            rounds=1,
            a_slots=1,
            b_slots_per_seed=1,
            top_k=1,
        ),
    )
    status = itl.build_status_report(loaded)
    assert status.phase == "not_started"
    assert not (tmp_path / "run").exists()


@requires_assets
def test_preflight_rejects_empty_data_and_missing_real_rules(tmp_path: Path) -> None:
    empty = tmp_path / "empty_data"
    empty.mkdir()
    report = itl.build_preflight_report(_loaded(tmp_path, prepared_data_dir=str(empty)))
    assert not report.offline_preflight_passed
    assert any("prepared data" in error for error in report.errors)

    real = itl.build_preflight_report(
        _loaded(
            tmp_path / "real",
            proposer_config=RoleCallConfig(role="p", model="deepseek-v4-flash", source="dmx"),
            inducer_config=RoleCallConfig(role="i", model="deepseek-v4-flash", source="dmx"),
            victim_source="dmx",
            check_service="real",
            semgrep_config=None,
        )
    )
    assert any("semgrep_config is required" in error for error in real.errors)


@requires_assets
def test_baseline_empty_json_is_not_complete(tmp_path: Path) -> None:
    loaded = _loaded(tmp_path)
    training = Path(loaded.method.run_root) / "baseline" / "training"
    training.mkdir(parents=True)
    write_json_atomic(training / "feedback.json", {})
    write_json_atomic(training / "feedback_audit.json", {})
    report = itl.build_preflight_report(loaded)
    assert report.baseline_status == "snapshot_prepared"


@requires_assets
def test_status_aggregates_committed_rounds(tmp_path: Path) -> None:
    loaded = _loaded(tmp_path)
    run_root = Path(loaded.method.run_root)
    write_json_atomic(
        run_root / "state.json",
        {
            "config_sha256": loaded.method.config_sha256(),
            "phase": "stopped",
            "round_index": 2,
            "current_versions": {},
            "stop_reason": "round_1_complete",
        },
    )
    for round_number in (1, 2):
        directory = run_root / "rounds" / str(round_number) / "A"
        directory.mkdir(parents=True)
        write_json_atomic(directory / "commit.json", {"selected": [f"c{round_number}"]})
    report = itl.build_status_report(loaded)
    assert "r1A" in report.top5 and "r2A" in report.top5


@requires_assets
def test_preflight_rejects_empty_semgrep_rule_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    report = itl.build_preflight_report(_loaded(tmp_path, semgrep_config=str(empty)))
    assert not report.offline_preflight_passed
    assert any("does not contain target rules" in error for error in report.errors)


def _write_baseline(
    training: Path,
    template,
    task_ids: tuple[str, ...],
    repeats: int,
    *,
    tamper: str | None,
) -> None:
    from coco_attack.assets.artifacts import sha256_text

    audit_samples = []
    feedback_samples = []
    for task_index, task in enumerate(task_ids):
        for repeat in range(repeats):
            code = f"    return {repeat}\n"
            audit_samples.append(
                {
                    "sample_id": f"{task}__{repeat}",
                    "task_id": task,
                    "repeat_id": repeat,
                    "generation_status": "success",
                    "final_code_sha256": None if tamper == "fingerprint" else sha256_text(code),
                    "verdict": None if tamper == "verdict" else "pass",
                    "asr_hit": False,
                    "semgrep": {"status": "completed", "detected": False, "reason_code": None},
                }
            )
            feedback_samples.append(
                {
                    "task": f"训练题 {task_index + 1}",
                    "repeat": repeat,
                    "code": code,
                    "verdict": "pass",
                    "semgrep": {"status": "completed", "detected": False, "reason": None},
                }
            )
    if tamper == "empty_feedback":
        feedback_samples = []
    numerator = 999 if tamper == "metric" else 0
    denominator = 19 if tamper == "metric" else 2 * repeats
    write_json_atomic(
        training / "feedback.json",
        {
            "samples": feedback_samples,
            "metrics": {
                "sample_hit_rate": {
                    "defined": True,
                    "numerator": numerator,
                    "denominator": denominator,
                }
            },
        },
    )
    write_json_atomic(
        training / "feedback_audit.json",
        {
            "template_sha256": template.content_sha256(),
            "candidate_hash": "x",
            "samples": audit_samples,
        },
    )


@requires_assets
@pytest.mark.parametrize("tamper", ["verdict", "fingerprint", "empty_feedback", "metric"])
def test_baseline_tampered_evidence_is_not_complete(tmp_path: Path, tamper: str) -> None:
    from coco_attack.method.implicit_then_literal import load_comparison_baseline

    loaded = _loaded(tmp_path)
    template = load_comparison_baseline(repository_root=str(REPO)).snapshot
    training = Path(loaded.method.run_root) / "baseline" / "training"
    training.mkdir(parents=True)
    _write_baseline(
        training,
        template,
        loaded.method.training_task_ids,
        loaded.method.victim_repeats,
        tamper=tamper,
    )
    report = itl.build_preflight_report(loaded)
    assert report.baseline_status == "snapshot_prepared"


@requires_assets
def test_preflight_rejects_file_semgrep_source(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text("rules: []\n", encoding="utf-8")
    report = itl.build_preflight_report(_loaded(tmp_path, semgrep_config=str(rules_file)))
    assert not report.offline_preflight_passed
    assert any("must be a rules directory" in error for error in report.errors)
