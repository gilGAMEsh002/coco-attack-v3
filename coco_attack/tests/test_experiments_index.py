"""baseline-index-v1 construction, validation and strict query (phase 03, sub-task 03)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.evaluation.metrics import (
    BASELINE_BLOCKING_KEYS,
    BASELINE_WARNING_KEYS,
)
from coco_attack.experiments.index import (
    BRIEF_METRIC_NAMES,
    INDEX_SCHEMA_VERSION,
    VERSION_NORMALIZATION_FILENAME,
    BaselineIndexError,
    baseline_key_from_entry,
    build_index,
    collect_baseline_key,
    query_index,
    validate_index,
    write_index,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = REPO_ROOT / "cocota_runs" / "phase03" / "baseline-DeepSeek-V3.2"
BASELINE_AVAILABLE = (BASELINE / "manifest" / "run-manifest.json").is_file()

_NORMALIZATION_TARGET = {
    "cleaner_version": "cleaner-v4",
    "harness_version": "functional-harness-v5",
    "image_digest": "sha256:80da393252772534cdf8f2e4b7ec8ef36d7474b05989ef13bd185e81b33314b1",
    "classifier_version": "functional-classifier-v2",
}

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
        "oracle_fingerprint_sha256": "0" * 64,
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


def _baseline_root_with_file(
    tmp_path: Path, payload: dict | None
) -> Path:
    """Symlink the real baseline into a tmp root, optionally adding the decision file.

    Symlinking keeps the test offline and leaves the real baseline (and its run
    directories/manifests) untouched while still exercising the real artifacts.
    """

    root = tmp_path / "baseline"
    root.mkdir()
    for child in BASELINE.iterdir():
        if child.name == VERSION_NORMALIZATION_FILENAME:
            continue
        (root / child.name).symlink_to(child, target_is_directory=child.is_dir())
    if payload is not None:
        (root / VERSION_NORMALIZATION_FILENAME).write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
    return root


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_build_index_applies_version_normalization(tmp_path: Path) -> None:
    payload = {
        "target": dict(_NORMALIZATION_TARGET),
        "decision": "unify compared version labels to the latest revision",
        "assumption": "unre-run samples are assumed to carry no version-related difference",
    }
    root = _baseline_root_with_file(tmp_path, payload)
    index = build_index(root)
    validate_index(index)

    normalization = index["version_normalization"]
    assert normalization["source"] == VERSION_NORMALIZATION_FILENAME
    assert normalization["target"] == _NORMALIZATION_TARGET
    assert normalization["decision"] == payload["decision"]
    assert normalization["assumption"] == payload["assumption"]
    assert len(normalization["sha256"]) == 64

    entries = index["entries"]
    whole = [e for e in entries.values() if e["split_mode"] == "whole-set"]
    assert len(whole) == 24
    # the 4 mixed dimensions are unified on every whole-set entry
    for entry in whole:
        for key, value in _NORMALIZATION_TARGET.items():
            assert entry[key] == value
    # every entry keeps the original per-unit values for traceability
    for entry in entries.values():
        assert set(entry["source_versions"]) == set(_NORMALIZATION_TARGET)
    assert entries["cwe078-0__clean_0shot__t0r1::search::whole-set"][
        "source_versions"
    ]["harness_version"] == "functional-harness-v3"
    assert entries["cwe502-0__clean_0shot__t0.7r5::search::whole-set"][
        "source_versions"
    ]["harness_version"] == "functional-harness-v5"
    assert entries["cwe502-0__clean_0shot__t0.7r5::search::whole-set"][
        "source_versions"
    ]["classifier_version"] == "functional-classifier-v2"


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_build_index_without_normalization_file_is_unchanged(tmp_path: Path) -> None:
    root = _baseline_root_with_file(tmp_path, None)
    index = build_index(root)
    validate_index(index)
    assert "version_normalization" not in index
    for entry in index["entries"].values():
        assert "source_versions" not in entry
    # the per-run (mixed) versions are still recorded verbatim
    assert index["entries"]["cwe078-0__clean_0shot__t0r1::search::whole-set"][
        "harness_version"
    ] == "functional-harness-v3"
    assert index["entries"]["cwe502-0__clean_0shot__t0.7r5::search::whole-set"][
        "harness_version"
    ] == "functional-harness-v5"


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_build_index_rejects_unknown_normalization_target_key(tmp_path: Path) -> None:
    root = _baseline_root_with_file(
        tmp_path,
        {"target": {"cleaner_version": "cleaner-v4", "not_a_version": "x"}},
    )
    with pytest.raises(BaselineIndexError):
        build_index(root)


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_build_index_rejects_empty_normalization_target(tmp_path: Path) -> None:
    root = _baseline_root_with_file(tmp_path, {"target": {}})
    with pytest.raises(BaselineIndexError):
        build_index(root)


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_baseline_key_from_entry_projects_real_whole_set_entries() -> None:
    index = build_index(BASELINE)
    validate_index(index)
    whole = [e for e in index["entries"].values() if e["split_mode"] == "whole-set"]
    assert len(whole) == 24
    expected_keys = set(BASELINE_BLOCKING_KEYS) | set(BASELINE_WARNING_KEYS)
    for entry in whole:
        key = baseline_key_from_entry(entry)
        assert set(key) == expected_keys
        assert key["combination_id"] == entry["combination_id"]
        assert key["split_mode"] == "whole-set"
        assert key["task_set"] == sorted(entry["task_set"])
        assert key["k"] == sorted(entry["k"])
        assert key["temperature"] == float(entry["temperature"])
        assert key["oracle_fingerprint_sha256"] == entry["oracle_fingerprint_sha256"]
        assert key["oracle_fingerprint_sha256"]


@pytest.mark.skipif(not BASELINE_AVAILABLE, reason="completed baseline artifacts not present")
def test_collect_baseline_key_matches_real_index_entries(tmp_path: Path) -> None:
    # The optional version_normalization.json is omitted: the index then carries
    # the raw per-run versions that ``collect_baseline_key`` reads back, so every
    # blocking and warning field must agree field-for-field.
    root = _baseline_root_with_file(tmp_path, None)
    index = build_index(root)
    validate_index(index)
    manifest = json.loads(
        (root / "manifest" / "run-manifest.json").read_text(encoding="utf-8")
    )
    version_fingerprint = manifest["version_fingerprint"]
    whole = [e for e in index["entries"].values() if e["split_mode"] == "whole-set"]
    assert len(whole) == 24
    for entry in whole:
        split_path = (
            root / "inputs" / "data" / entry["combination_id"] / "split.json"
        )
        collected = collect_baseline_key(
            root / entry["run_dir"],
            input_split_path=split_path,
            version_fingerprint=version_fingerprint,
        )
        projected = baseline_key_from_entry(entry)
        if collected != projected:
            differences = {
                name: (projected.get(name), collected.get(name))
                for name in projected
                if projected.get(name) != collected.get(name)
            }
            pytest.fail(f"{entry['entry_id']} mismatch: {differences}")
