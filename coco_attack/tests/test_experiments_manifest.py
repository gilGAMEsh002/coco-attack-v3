"""run-manifest-v1 building, validation and the status machine (phase 03)."""

from __future__ import annotations

import pytest

from coco_attack.experiments.manifest import (
    ManifestError,
    build_manifest,
    load_manifest,
    update_unit_status,
    validate_manifest,
    write_manifest,
    write_manifest_atomic,
)
from coco_attack.experiments.matrix import MatrixConfig, expand_units

from test_experiments_matrix import BASELINE_COMBINATIONS, _matrix, _prepared


def _manifest(tmp_path):
    matrix = _matrix()
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    units = expand_units(matrix, prepared)
    fingerprint = {"git_commit": "abc", "data_contract": "bigcodebench-screened-v1"}
    return matrix, units, build_manifest(matrix, units, fingerprint, tmp_path)


def test_manifest_structure(tmp_path) -> None:
    _matrix_value, units, manifest = _manifest(tmp_path)
    validate_manifest(manifest)
    assert manifest["schema_version"] == "run-manifest-v1"
    assert len(manifest["units"]) == 24
    runs = [run for unit in manifest["units"].values() for run in unit["runs"]]
    assert len(runs) == 30
    for unit in manifest["units"].values():
        assert unit["status"] == "configured"
        for run in unit["runs"]:
            assert run["status"] == "pending"
    cwe078 = manifest["units"]["cwe078-0__clean_0shot__t0r1"]
    assert cwe078["lock_ref"] == "locks/baseline-lock.json"
    other = manifest["units"]["cwe094-0__clean_0shot__t0r1"]
    assert other["lock_ref"] is None


def test_manifest_round_trip_and_atomic_write(tmp_path) -> None:
    _matrix_value, _units, manifest = _manifest(tmp_path)
    path = tmp_path / "manifest" / "run-manifest.json"
    write_manifest(path, manifest)
    loaded = load_manifest(path)
    assert loaded["units"].keys() == manifest["units"].keys()

    before = loaded["updated_at"]
    write_manifest_atomic(path, loaded)
    after = load_manifest(path)["updated_at"]
    assert after >= before


def test_invalid_status_rejected(tmp_path) -> None:
    _matrix_value, _units, manifest = _manifest(tmp_path)
    unit_id = next(iter(manifest["units"]))
    with pytest.raises(ManifestError, match="invalid status"):
        update_unit_status(manifest, unit_id, "nonsense")


def test_status_machine_complete_is_terminal(tmp_path) -> None:
    _matrix_value, _units, manifest = _manifest(tmp_path)
    unit_id = next(iter(manifest["units"]))
    update_unit_status(manifest, unit_id, "complete")
    validate_manifest(manifest)
    with pytest.raises(ManifestError, match="complete is terminal"):
        update_unit_status(manifest, unit_id, "running")


def test_validate_rejects_tampered_counts(tmp_path) -> None:
    _matrix_value, _units, manifest = _manifest(tmp_path)
    unit_id = next(iter(manifest["units"]))
    manifest["units"][unit_id]["expected_sample_count"] += 1
    with pytest.raises(ManifestError, match="expected_sample_count"):
        validate_manifest(manifest)


def test_validate_rejects_tampered_task_hash(tmp_path) -> None:
    _matrix_value, _units, manifest = _manifest(tmp_path)
    unit_id = next(iter(manifest["units"]))
    manifest["units"][unit_id]["task_ids_sha256"] = "0" * 64
    with pytest.raises(ManifestError, match="task_ids_sha256"):
        validate_manifest(manifest)
