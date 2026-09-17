"""Static-hit identity join and report completeness (batch-3).

Offline only.  Verifies that the report flags missing/extra samples against
the fixed manifest.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.evaluation.pipeline import _static_hits_from_run
from coco_attack.evaluation.reporting import collect_metrics


def test_static_hits_join_by_combination_task_repeat(tmp_path: Path) -> None:
    (tmp_path / "generation").mkdir()
    (tmp_path / "static").mkdir()
    (tmp_path / "generation" / "generations.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "sample_id": "s1",
                        "identity": {
                            "combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0,
                            "batch_id": "b1",
                        },
                    }
                ),
                json.dumps(
                    {
                        "sample_id": "s2",
                        "identity": {
                            "combination_id": "cwe078-0", "task_id": "T2", "repeat_id": 0,
                            "batch_id": "b1",
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    static = tmp_path / "static" / "evaluations.jsonl"
    static.write_text(
        json.dumps(
            {
                "combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0,
                "batch_id": "config-hash", "asr_hit": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Incomplete static set -> None (metric must report unavailable, not False).
    assert _static_hits_from_run(tmp_path, ["s1", "s2"]) is None
    static.write_text(
        json.dumps(
            {"combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0, "asr_hit": True}
        )
        + "\n"
        + json.dumps(
            {"combination_id": "cwe078-0", "task_id": "T2", "repeat_id": 0, "asr_hit": False}
        )
        + "\n",
        encoding="utf-8",
    )
    assert _static_hits_from_run(tmp_path, ["s1", "s2"]) == {"s1": True, "s2": False}


def test_static_hits_ambiguous_duplicate_key_returns_none(tmp_path: Path) -> None:
    (tmp_path / "generation").mkdir()
    (tmp_path / "static").mkdir()
    (tmp_path / "generation" / "generations.jsonl").write_text(
        json.dumps(
            {
                "sample_id": "s1",
                "identity": {
                    "combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0, "batch_id": "b1",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "static" / "evaluations.jsonl").write_text(
        json.dumps({"combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0, "asr_hit": True})
        + "\n"
        + json.dumps({"combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0, "asr_hit": False})
        + "\n",
        encoding="utf-8",
    )
    assert _static_hits_from_run(tmp_path, ["s1"]) is None


def test_collect_metrics_without_manifest_reports_extra(tmp_path: Path) -> None:
    metrics = collect_metrics(
        tmp_path, [{"sample_id": "s1", "static": {"verdict": "target_present"}}]
    )
    assert metrics["expected_sample_count"] is None
    assert metrics["extra_sample_ids"] == ["s1"]
    assert metrics["complete"] is False


def test_collect_metrics_flags_missing_and_extra(tmp_path: Path) -> None:
    (tmp_path / "sample_manifest.json").write_text(
        json.dumps({"expected_sample_ids": ["s1", "s2"]}), encoding="utf-8"
    )
    records = [
        {"sample_id": "s1", "static": {"verdict": "target_present"}},
        {"sample_id": "s3", "static": {"verdict": "target_absent"}},
    ]
    metrics = collect_metrics(tmp_path, records)
    assert metrics["expected_sample_count"] == 2
    assert metrics["missing_sample_ids"] == ["s2"]
    assert metrics["extra_sample_ids"] == ["s3"]
    assert metrics["complete"] is False


def test_collect_metrics_complete(tmp_path: Path) -> None:
    (tmp_path / "sample_manifest.json").write_text(
        json.dumps({"expected_sample_ids": ["s1"]}), encoding="utf-8"
    )
    metrics = collect_metrics(
        tmp_path, [{"sample_id": "s1", "static": {"verdict": "target_present"}}]
    )
    assert metrics["complete"] is True
    assert metrics["missing_sample_ids"] == []
    assert metrics["extra_sample_ids"] == []


def test_verify_existing_generation_rejects_model_mismatch(tmp_path: Path) -> None:
    from coco_attack.evaluation.pipeline import (
        PipelineConfig,
        PipelineConfigError,
        _verify_existing_generation,
    )

    run = tmp_path / "generation"
    run.mkdir()
    (run / "run_config.json").write_text(
        json.dumps(
            {
                "config": {
                    "model": "m1", "temperature": 0.0, "repeats": 1, "stage": "search",
                    "combination_id": "cwe078-0", "form": "clean_fewshot_cot",
                    "prompt_version": "1",
                }
            }
        ),
        encoding="utf-8",
    )
    config = PipelineConfig(
        run_id="r", combination_id="cwe078-0", oracle_id="cwe078-0",
        stage="search", form="clean_fewshot_cot",
        data_dir=str(tmp_path), prompts_dir=str(tmp_path), assets_dir=str(tmp_path),
        output_dir=str(tmp_path / "out"), execution_config=str(tmp_path / "e.json"),
        functional_cache_dir=str(tmp_path / "cache"), model="m2",
    )
    with pytest.raises(PipelineConfigError):
        _verify_existing_generation(config, run)
