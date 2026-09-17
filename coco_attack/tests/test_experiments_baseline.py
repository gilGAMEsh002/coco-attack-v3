"""Baseline preparation and startup checks (phase 03, sub-task 01).

The end-to-end test runs the real offline preparation chain (prepare-data +
materialize-prompts + manifest + configs + lock) with the mock source.  It never
calls a model and never starts a container.  Skipped when the read-only assets
are unavailable.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.experiments import baseline as baseline_module
from coco_attack.experiments.baseline import (
    EXIT_BLOCKING,
    check_baseline,
    parse_dotenv,
    prepare_baseline,
)
from coco_attack.experiments.configgen import check_unit_configs
from coco_attack.experiments.manifest import load_manifest

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
EXECUTION_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "execution.local.json"
AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir() and EXECUTION_CONFIG.is_file()

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="assets/repo not available")


def _write_matrix(path: Path, **overrides) -> Path:
    payload = {
        "victim_model": "openai/gpt-4o",
        "judge_model": "openai/gpt-4o",
        "max_tokens": 256,
        "execution_config": str(EXECUTION_CONFIG),
        "repo_dir": str(REPO_DIR),
        "assets_dir": str(ASSETS_DIR),
        "source": "mock",
        "judge_source": "mock",
        "allow_dirty_worktree": True,
        "batch_tag": "test-baseline-v1",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_prepare_baseline_end_to_end(tmp_path) -> None:
    matrix_path = _write_matrix(tmp_path / "matrix.json")
    root = tmp_path / "baseline"

    assert prepare_baseline(matrix_path, root) == 0

    manifest = load_manifest(root / "manifest" / "run-manifest.json")
    assert len(manifest["units"]) == 24
    runs = [run for unit in manifest["units"].values() for run in unit["runs"]]
    assert len(runs) == 30

    expected_counts = {"cwe078-0": 27, "cwe094-0": 4, "cwe295-0": 33, "cwe502-0": 45}
    for unit in manifest["units"].values():
        assert unit["expected_task_count"] == expected_counts[unit["combination_id"]]
        assert unit["status"] == "configured"
        assert unit["max_tokens"] == 256
        assert unit["victim_model"] == "openai/gpt-4o"

    # input snapshots exist for all four combinations
    for combination_id in expected_counts:
        assert (root / "inputs" / "data" / combination_id / "split.json").is_file()
        assert (root / "inputs" / "prompts" / combination_id / "manifest.json").is_file()

    # all 30 configs load and check-pipeline agrees with the manifest counts
    summary = check_unit_configs(root, manifest)
    assert len(summary) == 30
    assert all(entry["ok"] for entry in summary.values()), summary

    # cwe078 lock exists with six locked units
    lock = json.loads((root / "locks" / "baseline-lock.json").read_text(encoding="utf-8"))
    assert lock["schema_version"] == "baseline-lock-v1"
    assert lock["combination_id"] == "cwe078-0"
    assert len(lock["unit_ids"]) == 6
    assert set(lock["prompt_hashes"]) == {
        "clean_0shot",
        "clean_fewshot_cot",
        "clean_fewshot_no_cot",
    }

    # startup check is written and passes in a mock/no-cost configuration
    assert check_baseline(root) == 0
    check = json.loads((root / "checks" / "baseline_check.json").read_text(encoding="utf-8"))
    assert check["blocking_issues"] == []
    assert check["ready"] is True


def test_prepare_baseline_refuses_dirty_worktree(tmp_path, monkeypatch) -> None:
    matrix_path = _write_matrix(tmp_path / "matrix.json", allow_dirty_worktree=False)
    monkeypatch.setattr(
        baseline_module,
        "git_worktree_status",
        lambda repo_dir: {
            "dirty": True,
            "status_sha256": "deadbeef",
            "status_lines": [" M coco_attack/src/coco_attack/evaluation/judge.py"],
        },
    )
    root = tmp_path / "baseline"
    assert prepare_baseline(matrix_path, root) == EXIT_BLOCKING
    assert not root.exists()


def test_prepare_baseline_refuses_non_fresh_root(tmp_path) -> None:
    matrix_path = _write_matrix(tmp_path / "matrix.json")
    root = tmp_path / "baseline"
    root.mkdir()
    (root / "keep").write_text("occupied", encoding="utf-8")
    assert prepare_baseline(matrix_path, root) == 2


def test_parse_dotenv_supports_export_and_quotes(tmp_path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "# comment\nexport DMX_API_KEY=secret-value\nOTHER='quoted value'\n",
        encoding="utf-8",
    )
    values = parse_dotenv(env)
    assert values["DMX_API_KEY"] == "secret-value"
    assert values["OTHER"] == "quoted value"
