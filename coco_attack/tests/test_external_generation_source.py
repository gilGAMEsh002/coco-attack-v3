"""External generation source resolution and report status propagation.

A pipeline may accept an external generation run instead of generating
internally.  Reporting, the core checkpoint and the static/evasion join must all
read the same resolved source, and the top-level status must not claim a complete
report when samples are missing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.evaluation.generation_source import (
    GenerationSourceError,
    resolve_generation_run,
)
from coco_attack.evaluation.pipeline import _pipeline_status, _static_hits_from_run
from coco_attack.evaluation.reporting import build_report, collect_records


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def _external_generation(root: Path) -> Path:
    external = root / "external-generation"
    _write_jsonl(
        external / "generations.jsonl",
        [
            {
                "sample_id": "s1",
                "identity": {"combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0},
                "status": "success",
            },
            {
                "sample_id": "s2",
                "identity": {"combination_id": "cwe078-0", "task_id": "T2", "repeat_id": 0},
                "status": "success",
            },
        ],
    )
    return external


def _pipeline_run(root: Path, external: Path, expected: list[str]) -> Path:
    run = root / "run"
    run.mkdir(parents=True, exist_ok=True)
    (run / "pipeline_config.json").write_text(
        json.dumps({"generation_run": str(external)}), encoding="utf-8"
    )
    (run / "sample_manifest.json").write_text(
        json.dumps({"expected_sample_ids": expected}), encoding="utf-8"
    )
    _write_jsonl(
        run / "cleaning" / "cleaned_generations.jsonl",
        [
            {"task_id": "T1", "repeat_id": 0, "cleaned": {"completed": True}},
            {"task_id": "T2", "repeat_id": 0, "cleaned": {"completed": True}},
        ],
    )
    _write_jsonl(
        run / "static" / "evaluations.jsonl",
        [
            {"combination_id": "cwe078-0", "task_id": "T1", "repeat_id": 0, "asr_hit": True},
            {"combination_id": "cwe078-0", "task_id": "T2", "repeat_id": 0, "asr_hit": False},
        ],
    )
    return run


def test_resolve_generation_run_prefers_external_reference(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2"])
    assert resolve_generation_run(run) == external.resolve()
    # Without a pipeline config, the internal generation directory is used.
    assert resolve_generation_run(tmp_path / "other-run") == (tmp_path / "other-run" / "generation")


def test_resolve_generation_run_internal_when_reference_absent(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "pipeline_config.json").write_text(
        json.dumps({"generation_run": None}), encoding="utf-8"
    )
    assert resolve_generation_run(run) == run / "generation"


def test_resolve_generation_run_rejects_malformed_config(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "pipeline_config.json").write_text("{not json", encoding="utf-8")
    # A present-but-unreadable config must fail loud, not silently report the
    # (empty) internal generation directory.
    with pytest.raises(GenerationSourceError):
        resolve_generation_run(run)


def test_collect_records_reads_external_generation(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2"])
    records = collect_records(run)
    assert [record["sample_id"] for record in records] == ["s1", "s2"]
    # Cleaning and static joined through the external identities.
    assert records[0]["cleaned"] == {"final_code_sha256": None, "extraction_path": None, "completed": True}
    assert records[0]["static"]["asr_hit"] is True
    assert records[1]["static"]["asr_hit"] is False


def test_static_hits_join_uses_external_generation(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2"])
    assert _static_hits_from_run(run, ["s1", "s2"]) == {"s1": True, "s2": False}


def test_build_report_marks_external_run_complete_and_indexes_source(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2"])
    manifest = build_report(run, run / "report")
    assert manifest["sample_count"] == 2
    assert manifest["complete"] is True
    assert manifest["status"] == "complete"
    indexed = manifest["artifacts"]["generation/generations.jsonl"]
    assert indexed["path"] == str(external / "generations.jsonl")
    assert _pipeline_status(run, 0) == "complete"


def test_report_status_is_incomplete_when_samples_missing(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2", "s3"])
    manifest = build_report(run, run / "report")
    assert manifest["sample_count"] == 2
    assert manifest["complete"] is False
    assert manifest["status"] == "incomplete"
    assert _pipeline_status(run, 0) == "incomplete"


def test_report_status_is_empty_when_nothing_joins(tmp_path: Path) -> None:
    external = _external_generation(tmp_path)
    run = _pipeline_run(tmp_path, external, ["s1", "s2"])
    (run / "pipeline_config.json").unlink()
    (external / "generations.jsonl").unlink()
    manifest = build_report(run, run / "report")
    assert manifest["sample_count"] == 0
    assert manifest["status"] == "empty"
    assert _pipeline_status(run, 0) == "incomplete"
