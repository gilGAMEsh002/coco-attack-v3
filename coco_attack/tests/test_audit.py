"""Focused Phase-01 checks that feed the stage-level acceptance record.

These tests exercise the shared entry points rather than duplicating every
per-module behaviour. They read the real asset tree read-only and never write
into it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.cli import main
from coco_attack.assets.audit import (
    STANDARD_SCHEMA,
    AuditContext,
    _iter_jsonl_lenient,
    inspect_task_file,
    load_combinations_config,
)
from coco_attack.assets.paths import default_config_dir
from coco_attack.assets.metadata import normalize_task_metadata

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()

pytestmark = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)


def _run_audit(output_dir: Path) -> int:
    return main(
        [
            "audit-assets",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--output-dir",
            str(output_dir),
        ]
    )


def test_config_has_nine_unique_combinations() -> None:
    config, _ = load_combinations_config()
    combos = config["combinations"]
    assert len(combos) == 9
    assert len({combo["combination_id"] for combo in combos}) == 9
    assert len({combo["oracle_id"] for combo in combos}) == 9
    assert {combo["combination_id"] for combo in combos} == {
        "cwe022-0",
        "cwe078-0",
        "cwe089-0",
        "cwe094-0",
        "cwe295-0",
        "cwe295-1",
        "cwe367-0",
        "cwe400-0",
        "cwe502-0",
    }


def test_missing_arguments_exit_usage() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_help_does_not_touch_assets(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "audit-assets" in capsys.readouterr().out


def test_missing_assets_dir_is_usage_error(tmp_path: Path) -> None:
    exit_code = main(
        [
            "audit-assets",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(tmp_path / "does-not-exist"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 2


def test_output_inside_assets_is_rejected(tmp_path: Path) -> None:
    exit_code = main(
        [
            "audit-assets",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--output-dir",
            str(ASSETS_DIR / "audit-should-not-be-written"),
        ]
    )
    assert exit_code == 2
    assert not (ASSETS_DIR / "audit-should-not-be-written").exists()


def test_audit_reports_known_differences_and_writes_artifacts(tmp_path: Path) -> None:
    output_dir = tmp_path / "audit"
    exit_code = _run_audit(output_dir)

    # User rulings: label boundary, historical coverage gap and metadata
    # alignment are non-blocking observations, so the audit is clean.
    assert exit_code == 0
    for name in ("asset_manifest.json", "environment.json", "issues.json", "REPORT.md"):
        assert (output_dir / name).is_file(), name

    issues = json.loads((output_dir / "issues.json").read_text(encoding="utf-8"))
    codes = {issue["code"] for issue in issues["issues"]}
    assert "oracle.reference_label_boundary" in codes
    assert "reference_eval.historical_coverage_gap" in codes
    assert "tasks.metadata_normalized_from_registry" in codes
    assert "history_runs.boolean_hit_only" in codes
    # No errors and no unresolved pending decisions in the current snapshot.
    assert all(
        issue["severity"] in {"warning"} for issue in issues["issues"]
    ), issues["issues"]

    manifest = json.loads((output_dir / "asset_manifest.json").read_text(encoding="utf-8"))
    assert manifest["config"]["combination_count"] == 9
    assert set(manifest["combinations"]) == {
        "cwe022-0",
        "cwe078-0",
        "cwe089-0",
        "cwe094-0",
        "cwe295-0",
        "cwe295-1",
        "cwe367-0",
        "cwe400-0",
        "cwe502-0",
    }
    # cwe078 eval set must be the 27 tasks excluding the four examples, and the
    # authoritative task count includes BigCodeBench/205.
    cwe078 = manifest["combinations"]["cwe078-0"]
    assert cwe078["task"]["unique_task_ids"] == 31
    assert "BigCodeBench/205" not in cwe078["task"]["duplicate_task_ids"]
    assert len(cwe078["clean_assets"]["fewshot_test_ids"]) == 27
    assert cwe078["clean_assets"]["fewshot_test_ids"] == cwe078["clean_assets"]["zero_shot_test_ids"]

    # cwe022-0 effective metadata follows the registry, raw value is retained.
    cwe022 = manifest["combinations"]["cwe022-0"]["task"]
    assert cwe022["effective_experiment_types"] == ["control_flow"]
    assert cwe022["effective_decisions"] == ["qualified_control_flow"]
    assert cwe022["metadata_normalization"]["experiment_type"]["raw"] == [
        "hybrid_api_control_flow"
    ]


def test_manifest_is_byte_stable_across_runs(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _run_audit(first)
    _run_audit(second)
    assert (first / "asset_manifest.json").read_bytes() == (
        second / "asset_manifest.json"
    ).read_bytes()
    assert (first / "issues.json").read_bytes() == (second / "issues.json").read_bytes()


def _minimal_context(tmp_path: Path) -> AuditContext:
    return AuditContext(
        repo_dir=REPO_DIR,
        assets_root=tmp_path / "assets",
        output_dir=tmp_path / "out",
        config_dir=tmp_path,
        config_path=tmp_path / "combinations.json",
        config={"combinations": []},
    )


def test_config_discovery_is_independent_of_cwd(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_dir = default_config_dir()
    assert (config_dir / "combinations.json").is_file()


def test_type_violation_and_non_string_task_id_are_blocking(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    task_dir = assets / "data/BigCodeBench"
    task_dir.mkdir(parents=True)
    record = {field: "value" for field in STANDARD_SCHEMA}
    record["has_clean_pattern"] = "yes"  # wrong type
    record["task_id"] = 123  # non-string identity
    (task_dir / "CWE-XXX-0.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")

    ctx = _minimal_context(tmp_path)
    combo = {
        "combination_id": "cwe999-0",
        "registry_id": "CWE-999-0",
        "oracle_id": "cwe999-0",
        "task_file": "data/BigCodeBench/CWE-XXX-0.jsonl",
    }
    entry = inspect_task_file(ctx, combo, {"api_parameter"})
    codes = {issue.code for issue in ctx.issues}
    assert "tasks.type_violation" in codes
    assert "tasks.non_string_task_id" in codes
    assert entry["non_string_task_id_lines"] == ["1"]


def test_non_object_line_uses_caller_prefix(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_text("[1, 2]\n" + json.dumps({"ok": True}) + "\n", encoding="utf-8")
    ctx = _minimal_context(tmp_path)
    rows = list(_iter_jsonl_lenient(path, ctx, "records.jsonl", code_prefix="legacy_tasks"))
    assert [row[1] for row in rows] == [{"ok": True}]
    codes = {issue.code for issue in ctx.issues}
    assert "legacy_tasks.not_object" in codes
    assert not any(code.startswith("reference_eval") for code in codes)


def test_registry_metadata_normalization_keeps_raw_provenance() -> None:
    raw = {
        "statistical_cwe_id": "CWE-022-0",
        "experiment_type": "hybrid_api_control_flow",
        "decision": "qualified",
    }
    definition = {
        "registry_id": "CWE-022-0",
        "experiment_type": "control_flow",
        "decision": "qualified_control_flow",
    }
    effective, provenance = normalize_task_metadata(raw, definition)
    assert effective["experiment_type"] == "control_flow"
    assert effective["decision"] == "qualified_control_flow"
    assert provenance["experiment_type"] == {
        "raw": "hybrid_api_control_flow",
        "effective": "control_flow",
        "authority": "registry",
    }
    # The input record is never mutated.
    assert raw["experiment_type"] == "hybrid_api_control_flow"


def test_registry_metadata_already_aligned_has_no_provenance() -> None:
    raw = {"statistical_cwe_id": "CWE-078-0", "experiment_type": "api_parameter", "decision": "qualified"}
    definition = {"registry_id": "CWE-078-0", "experiment_type": "api_parameter", "decision": "qualified"}
    effective, provenance = normalize_task_metadata(raw, definition)
    assert effective == raw
    assert provenance == {}
