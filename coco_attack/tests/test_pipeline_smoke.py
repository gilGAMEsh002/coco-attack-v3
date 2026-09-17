"""Unified pipeline offline smoke (mock, 2-task subset) for task 05.

Runs the full chain on real assets with the mock source: generation -> cleaning
-> static -> core checkpoint -> SAST/judge/dynamic/realism -> functional ->
report, then resumes and rebuilds the report.  Skipped without Docker/assets.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.assets.paths import default_config_dir
from coco_attack.cli import main
from coco_attack.evaluation.pipeline import resume_pipeline, run_pipeline

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
EXECUTION_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "execution.local.json"
AVAILABLE = shutil.which("docker") is not None and ASSETS_DIR.is_dir() and EXECUTION_CONFIG.is_file()
COMBINATION = "cwe078-0"
FORM = "clean_fewshot_cot"

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="docker/assets not available")


def _config(root: Path, prepared: Path, prompts: Path, task_ids: list[str], cache: Path) -> Path:
    payload = {
        "schema_version": "pipeline-config-v1",
        "run_id": "pipeline-smoke-1",
        "combination_id": COMBINATION,
        "oracle_id": COMBINATION,
        "stage": "search",
        "form": FORM,
        "source": "mock",
        "model": "openai/gpt-4o",
        "temperature": 0.0,
        "repeats": 1,
        "batch_id": "pipeline-smoke-batch-1",
        "prompt_version": "1",
        "task_ids": task_ids,
        "data_dir": str(prepared),
        "prompts_dir": str(prompts),
        "assets_dir": str(ASSETS_DIR),
        "output_dir": str(root / "run"),
        "execution_config": str(EXECUTION_CONFIG),
        "functional_cache_dir": str(cache),
        "enabled_layers": ["sast", "dynamic", "realism"],
        "sast_tools": ["bandit", "semgrep"],
        "semgrep_config": str(ASSETS_DIR / "third_party" / "semgrep"),
        "judge": None,
        "victim_temperature": 0.0,
        "victim_repeats": 1,
        "k": [1],
    }
    path = root / "pipeline.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_pipeline_full_chain_and_resume(tmp_path: Path) -> None:
    prepared = tmp_path / "prepared"
    assert main([
        "prepare-data", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--output-dir", str(prepared), "--split-config", str(default_config_dir() / "splits.json"),
        "--combination", COMBINATION,
    ]) == 0
    prompts = tmp_path / "prompts"
    assert main([
        "materialize-prompts", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--data-dir", str(prepared), "--combination", COMBINATION,
        "--oracle-id", COMBINATION, "--form", FORM, "--output-dir", str(prompts),
    ]) == 0

    split = json.loads((prepared / COMBINATION / "split.json").read_text(encoding="utf-8"))
    task_ids = list(split["search"][:2])
    assert len(task_ids) == 2

    config = _config(tmp_path, prepared, prompts, task_ids, tmp_path / "cache")
    run = tmp_path / "run"
    assert run_pipeline(config, run) == 0

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "complete"
    for relative in (
        "pipeline_config.json", "sample_manifest.json", "generation/generations.jsonl",
        "cleaning/cleaned_generations.jsonl", "static/evaluations.jsonl",
        "core/checkpoint.json", "evaluation/layers/sast.jsonl",
        "evaluation/layers/dynamic.jsonl", "evaluation/layers/realism.jsonl",
        "functional/functional_results.jsonl", "report/REPORT.md", "report/records.jsonl",
    ):
        assert (run / relative).is_file(), relative

    generations = [l for l in (run / "generation" / "generations.jsonl").read_text().splitlines() if l.strip()]
    assert len(generations) == 2
    checkpoint = json.loads((run / "core" / "checkpoint.json").read_text(encoding="utf-8"))
    assert len(checkpoint["expected_samples"]) == 2
    records = [l for l in (run / "report" / "records.jsonl").read_text().splitlines() if l.strip()]
    assert len(records) == 2

    # Resume must not repeat completed steps.
    actions_before = (run / "actions.jsonl").read_text(encoding="utf-8")
    assert resume_pipeline(run) == 0
    assert (run / "actions.jsonl").read_text(encoding="utf-8") == actions_before
    assert json.loads((run / "manifest.json").read_text(encoding="utf-8"))["status"] == "complete"
