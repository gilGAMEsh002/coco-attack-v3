"""Phase-05 reference calibration and historical comparison checks."""

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


@pytest.fixture(scope="module")
def prepared(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("prepared")
    assert main([
        "prepare-data", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--output-dir", str(output), "--split-config", str(SPLIT_CONFIG),
        "--combination", "all",
    ]) == 0
    return output


def test_reference_calibration_all_combinations(prepared: Path, tmp_path: Path) -> None:
    config_path = tmp_path / "calib.json"
    config_path.write_text(json.dumps({"schema_version": "1", "combinations": ["all"]}), encoding="utf-8")
    output = tmp_path / "calib"
    exit_code = main([
        "calibrate-references", "--assets-dir", str(ASSETS_DIR), "--data-dir", str(prepared),
        "--config", str(config_path), "--output-dir", str(output),
    ])
    assert exit_code == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert set(summary) == {
        "cwe022-0", "cwe078-0", "cwe089-0", "cwe094-0", "cwe295-0",
        "cwe295-1", "cwe367-0", "cwe400-0", "cwe502-0",
    }
    assert summary["cwe078-0"]["label_agreements"] == 31
    assert summary["cwe078-0"]["new_differences"] == 0
    # The single approved label boundary is read from the reference record.
    assert summary["cwe089-0"]["label_agreements"] == 4
    assert summary["cwe089-0"]["approved_boundaries"] == 1
    assert summary["cwe089-0"]["approved_boundary_task_ids"] == ["BigCodeBench/535"]
    assert summary["cwe089-0"]["new_differences"] == 0
    assert json.loads((output / "differences.json").read_text(encoding="utf-8"))["differences"] == []


def test_historical_comparison_clean_and_attack(prepared: Path, tmp_path: Path) -> None:
    config_path = tmp_path / "history.json"
    config_path.write_text(json.dumps({
        "schema_version": "1",
        "runs": [
            {
                "run_id": "deepseek-v3.2/rep1/cwe078_clean_fewshot_DeepSeek-V3_2_t0p7_r5",
                "combination_id": "cwe078-0", "oracle_id": "cwe078-0",
                "purpose": "clean", "temperature": 0.7, "repeats": 5,
            },
            {
                "run_id": "gpt-4o/rep1/cwe078_cocota_gpt-4o_t0p7_r5",
                "combination_id": "cwe078-0", "oracle_id": "cwe078-0",
                "purpose": "attack_diagnostic", "model": "gpt-4o",
                "temperature": 0.7, "repeats": 5,
            },
        ],
    }), encoding="utf-8")
    output = tmp_path / "history"
    exit_code = main([
        "compare-history", "--assets-dir", str(ASSETS_DIR), "--data-dir", str(prepared),
        "--config", str(config_path), "--output-dir", str(output),
    ])
    assert exit_code == 0  # only AST-equivalent (cosmetic) code differences remain
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))

    clean = summary["deepseek-v3.2/rep1/cwe078_clean_fewshot_DeepSeek-V3_2_t0p7_r5"]
    assert clean["counts"]["bool_mismatches"] == 0
    assert clean["counts"]["code_mismatches"] == 0
    assert clean["asr_comparison"]["asr@1"]["match"] is True

    attack = summary["gpt-4o/rep1/cwe078_cocota_gpt-4o_t0p7_r5"]
    # The oracle branch-merge revision resolves the 195/2 boolean difference.
    assert attack["counts"]["bool_mismatches"] == 0
    # Remaining code differences are AST-equivalent canonicalization differences.
    assert attack["counts"]["code_mismatches"] == 0
    assert attack["counts"]["code_cosmetic_differences"] == 3
    assert attack["asr_comparison"]["asr@1"]["match"] is True
    assert attack["asr_comparison"]["asr@5"]["match"] is True

    payload = json.loads((output / "differences.json").read_text(encoding="utf-8"))
    assert payload["differences"] == []
    assert len(payload["cosmetic_differences"]) >= 3

    # Historical three-state verdict is never invented.
    rows = (output / "gpt-4o__rep1__cwe078_cocota_gpt-4o_t0p7_r5/history_comparisons.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) == 135
    assert all(json.loads(row)["history_verdict"] is None for row in rows)
