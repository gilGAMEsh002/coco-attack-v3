"""baseline-index-v1 construction, validation and strict query (phase 03, sub-task 03)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.experiments.index import (
    BRIEF_METRIC_NAMES,
    INDEX_SCHEMA_VERSION,
    build_index,
    query_index,
    validate_index,
    write_index,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = REPO_ROOT / "cocota_runs" / "phase03" / "baseline-DeepSeek-V3.2"
BASELINE_AVAILABLE = (BASELINE / "manifest" / "run-manifest.json").is_file()

_BRIEF = {"name": "x", "defined": False, "value": None, "numerator": None,
          "denominator": None, "reason": "n/a", "basis": None, "sampled_run": False,
          "denominator_definition": None, "availability": {}}


def _entry(split_mode: str, **overrides) -> dict:
    payload = {
        "entry_id": f"u::{split_mode}",
        "run_id": "u::search",
        "unit_id": "u",
        "combination_id": "cwe078-0",
        "oracle_id": "cwe078-0",
        "form": "clean_0shot",
        "model": "m",
        "temperature": 0.0,
        "repeats": 1,
        "k": [1, 3, 5],
        "enabled_layers": ["sast", "judge"],
        "sast_tools": ["bandit", "semgrep", "codeql"],
        "prompt_version": "1",
        "materialize_version": "prompt-materialize-v1",
        "data_contract": "bigcodebench-screened-v1",
        "cleaner_version": "cleaner-v3",
        "static_shell_version": "static-shell-v1",
        "harness_version": "functional-harness-v2",
        "image_digest": None,
        "judge_prompt_version": "singleclass-v1",
        "judge_detection_version": "target-cwe-v1",
        "split_mode": split_mode,
        "task_set": ["BigCodeBench/1"],
        "split_manifest_sha256": "0" * 64,
        "task_snapshot_sha256": "0" * 64,
        "run_dir": "units/u/search",
        "config_path": "configs/units/u.json",
        "status": "complete",
        "report_artifacts": {},
        "metrics": {name: dict(_BRIEF, name=name) for name in BRIEF_METRIC_NAMES},
        "registered_at": "2026-01-01T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _index(*entries: dict) -> dict:
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "baseline_root": "/tmp/x",
        "query_semantics": "strict-match",
        "entries": {entry["entry_id"]: entry for entry in entries},
        "gaps": [],
    }


def test_validate_index_accepts_minimal_entry() -> None:
    validate_index(_index(_entry("whole-set")))


def test_validate_index_rejects_bad_split_mode() -> None:
    with pytest.raises(ValueError):
        validate_index(_index(_entry("nonsense")))


def test_validate_index_rejects_derived_without_parent() -> None:
    derived = _entry("search", derived_from="missing::whole-set")
    with pytest.raises(ValueError):
        validate_index(_index(derived))


def test_query_index_is_strict() -> None:
    index = _index(_entry("whole-set"))
    assert len(query_index(index, combination_id="cwe078-0", form="clean_0shot",
                           split_mode="whole-set", model="m", temperature=0.0, repeats=1)) == 1
    # any口径 mismatch returns [] rather than the closest entry
    assert query_index(index, combination_id="cwe078-0", form="clean_0shot",
                       split_mode="whole-set", model="other", temperature=0.0, repeats=1) == []
    assert query_index(index, combination_id="cwe078-0", form="clean_0shot",
                       split_mode="holdout", model="m", temperature=0.0, repeats=1) == []


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_real_baseline_index_shape(tmp_path: Path) -> None:
    index = build_index(BASELINE)
    validate_index(index)
    entries = index["entries"]
    whole = [e for e in entries.values() if e["split_mode"] == "whole-set"]
    derived = [e for e in entries.values() if e.get("derived_from")]
    assert len(whole) == 24
    # cwe078 has 6 units, each deriving search-18 and holdout-9
    cwe078_derived = [e for e in derived if e["combination_id"] == "cwe078-0"]
    assert len(cwe078_derived) == 12
    for entry in cwe078_derived:
        assert len(entry["task_set"]) == (18 if entry["split_mode"] == "search" else 9)
        assert entry["derived_from"] in entries
    # whole-set asr is not copied onto the derived views
    parent = entries["cwe078-0__clean_0shot__t0r1::search::whole-set"]
    search = entries["cwe078-0__clean_0shot__t0r1::search::search"]
    assert parent["metrics"]["asr@1"]["denominator"] == 27
    assert search["metrics"]["asr@1"]["denominator"] == 18
    # write/reload round trip
    path = write_index(tmp_path, index)
    assert path.is_file()
