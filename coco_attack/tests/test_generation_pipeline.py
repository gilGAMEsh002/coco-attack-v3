"""End-to-end offline generation smoke on the real stage-01 assets (AC-02/AC-03).

Runs prepare-data -> materialize-prompts -> check-generation -> generate (mock)
-> resume-generation -> clean-generations.  Skipped when the read-only assets
are not present.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.assets.paths import default_config_dir
from coco_attack.cli import main

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
SPLIT_CONFIG = default_config_dir() / "splits.json"

pytestmark = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)

COMBINATION = "cwe078-0"
FORM = "clean_fewshot_cot"


def _generation_config(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "mock",
                "model": "openai/gpt-4o",
                "batch_id": "pipeline-batch-1",
                "combination_id": COMBINATION,
                "oracle_id": COMBINATION,
                "stage": "search",
                "form": FORM,
                "prompt_version": "1",
                "candidate_hash": "",
                "temperature": 0.0,
                "repeats": 1,
                "max_tokens": 256,
                "request_timeout": 30.0,
                "max_concurrency": 4,
                "max_request_attempts": 2,
                "max_sample_retries": 0,
                "price_input_per_1k": 0.0,
                "price_output_per_1k": 0.0,
                "currency": "USD",
                "pricing_version": "mock",
                "mock_scenario": "normal",
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory) -> dict:
    root = tmp_path_factory.mktemp("generation02")
    prepared = root / "prepared"
    assert main([
        "prepare-data", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--output-dir", str(prepared), "--split-config", str(SPLIT_CONFIG),
        "--combination", COMBINATION,
    ]) == 0

    prompts = root / "prompts"
    assert main([
        "materialize-prompts", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--data-dir", str(prepared), "--combination", COMBINATION,
        "--oracle-id", COMBINATION, "--form", FORM, "--output-dir", str(prompts),
    ]) == 0

    config = root / "generation.json"
    _generation_config(config)
    return {"root": root, "prepared": prepared, "prompts": prompts, "config": config}


def test_check_generation_is_offline_and_validates_inputs(pipeline: dict) -> None:
    output = pipeline["root"] / "check"
    assert main([
        "check-generation", "--config", str(pipeline["config"]),
        "--data-dir", str(pipeline["prepared"]), "--prompts-dir", str(pipeline["prompts"]),
        "--output-dir", str(output),
    ]) == 0
    payload = json.loads((output / "generation_check.json").read_text(encoding="utf-8"))
    assert payload["inputs"]["sample_count"] == 18
    assert payload["checks"][0] == {"id": "config", "status": "pass"}


def test_generate_mock_then_resume_and_clean(pipeline: dict) -> None:
    run_dir = pipeline["root"] / "run"
    assert main([
        "generate", "--config", str(pipeline["config"]),
        "--data-dir", str(pipeline["prepared"]), "--prompts-dir", str(pipeline["prompts"]),
        "--output-dir", str(run_dir),
    ]) == 0

    rows = [
        json.loads(line)
        for line in (run_dir / "generations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 18
    assert all(row["status"] == "success" for row in rows)
    assert all(row["generation"] for row in rows)
    ledger_lines = (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(ledger_lines) >= 18 * 3  # started + response + finalized per sample
    summary = json.loads((run_dir / "generation_summary.json").read_text(encoding="utf-8"))
    assert summary["status_counts"] == {"success": 18}

    # Resume must skip all finalized samples and not add duplicate rows.
    assert main(["resume-generation", "--run-dir", str(run_dir)]) == 0
    assert len((run_dir / "generations.jsonl").read_text(encoding="utf-8").splitlines()) == 18

    # The projection feeds the existing cleaner without modification.
    cleaned = pipeline["root"] / "cleaned"
    assert main([
        "clean-generations", "--data-dir", str(pipeline["prepared"]),
        "--input-jsonl", str(run_dir / "generations.jsonl"),
        "--combination", COMBINATION, "--oracle-id", COMBINATION,
        "--output-dir", str(cleaned),
    ]) == 0
    cleaned_rows = [
        json.loads(line)
        for line in (cleaned / "cleaned_generations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(cleaned_rows) == 18
