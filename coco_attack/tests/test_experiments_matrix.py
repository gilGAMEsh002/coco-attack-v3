"""Matrix definition, strict validation and whole-set 24-unit/24-run expansion.

These tests are pure: they build synthetic ``PreparedCombination`` objects and
never touch the asset tree or call a model.
"""

from __future__ import annotations

import hashlib

import pytest

from coco_attack.assets.artifacts import canonical_json_bytes, sha256_bytes
from coco_attack.data.contracts import (
    DatasetSelection,
    PreparedCombination,
    SplitManifest,
)
from coco_attack.experiments.matrix import (
    BASELINE_COMBINATIONS,
    EXPECTED_TASK_COUNTS,
    MatrixConfig,
    MatrixError,
    expand_units,
    load_matrix_config,
)
from coco_attack.protocol.stages import SplitMode

SPLIT_COUNTS = {"cwe078-0": (18, 9)}


def _ids(prefix: str, count: int) -> tuple[str, ...]:
    return tuple(f"BigCodeBench/{prefix}{index}" for index in range(count))


def _prepared(
    combination_id: str, total: int | None = None, *, split: bool = False
) -> PreparedCombination:
    total = EXPECTED_TASK_COUNTS[combination_id] if total is None else total
    evaluation_ids = _ids(f"{combination_id}-", total)
    task_ids = _ids(f"{combination_id}-", total)
    if split:
        search_count, holdout_count = SPLIT_COUNTS[combination_id]
        assert search_count + holdout_count == total
        mode = SplitMode.SEARCH_HOLDOUT
        search_ids = evaluation_ids[:search_count]
        holdout_ids = evaluation_ids[search_count:]
        split_evaluation_ids: tuple[str, ...] = ()
    else:
        mode = SplitMode.WHOLE_SET
        search_ids = ()
        holdout_ids = ()
        split_evaluation_ids = evaluation_ids
    snapshot = sha256_bytes(canonical_json_bytes(list(task_ids)))
    selection = DatasetSelection(
        combination_id=combination_id,
        seed=42,
        example_ids=_ids("example-", 4),
        evaluation_ids=evaluation_ids,
        selection_source="test",
        selection_file="selection.json",
        selection_file_sha256="0" * 64,
        verification_sources=(),
        task_snapshot_sha256=snapshot,
    )
    split = SplitManifest(
        combination_id=combination_id,
        mode=mode,
        seed=42,
        algorithm_version="sha256-seed-taskid-v1",
        split_config_sha256="0" * 64,
        input_ids=evaluation_ids,
        input_ids_sha256="0" * 64,
        task_snapshot_sha256=snapshot,
        search_ids=search_ids,
        holdout_ids=holdout_ids,
        evaluation_ids=split_evaluation_ids,
    )
    return PreparedCombination(
        combination_id=combination_id,
        registry_id=combination_id,
        oracle_id=combination_id,
        data_contract="bigcodebench-screened-v1",
        records=(),
        selection=selection,
        split=split,
        manifest_sha256="0" * 64,
    )


def _matrix(**overrides) -> MatrixConfig:
    payload = {
        "victim_model": "dmx/test-victim",
        "judge_model": "dmx/test-judge",
        "max_tokens": 1024,
        "execution_config": "/tmp/nonexistent-execution.json",
        "repo_dir": "/tmp/nonexistent-repo",
        "assets_dir": "/tmp/nonexistent-assets",
    }
    payload.update(overrides)
    return MatrixConfig(**payload)


def test_defaults_match_baseline_contract() -> None:
    matrix = _matrix()
    assert matrix.combinations == BASELINE_COMBINATIONS
    assert matrix.enabled_layers == ("sast", "judge")
    assert matrix.source == "dmx"
    assert matrix.judge_source == "dmx"
    assert matrix.unit_concurrency == 1
    assert matrix.allow_dirty_worktree is False


def test_from_json_rejects_unknown_fields() -> None:
    payload = _matrix().to_json()
    payload["surprise"] = 1
    with pytest.raises(MatrixError, match="unknown fields"):
        MatrixConfig.from_json(payload)


def test_from_json_requires_required_fields() -> None:
    with pytest.raises(MatrixError, match="missing required fields"):
        MatrixConfig.from_json({"victim_model": "x"})


def test_out_of_scope_combination_rejected() -> None:
    with pytest.raises(MatrixError, match="outside the registered baseline set"):
        _matrix(combinations=("cwe078-0", "cwe022-0"))


def test_expand_units_counts() -> None:
    """Default (whole-set) baseline: 24 units / 24 runs, one 'search' run each."""

    matrix = _matrix()
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    units = expand_units(matrix, prepared)
    assert len(units) == 24
    runs = [entry for unit in units for entry in unit.entries]
    assert len(runs) == 24
    assert all(unit.split_mode == "whole-set" for unit in units)
    assert all(
        len(unit.entries) == 1 and unit.entries[0].stage == "search" for unit in units
    )

    cwe078_units = [unit for unit in units if unit.combination_id == "cwe078-0"]
    assert len(cwe078_units) == 6
    assert all(unit.expected_task_count == 27 for unit in cwe078_units)

    # sample counts: tasks x repeats
    for unit in units:
        assert unit.expected_sample_count == unit.expected_task_count * unit.repeats
        for entry in unit.entries:
            assert entry.expected_sample_count == len(entry.task_ids) * unit.repeats


def test_expand_units_split_branch_still_supported() -> None:
    """A search/holdout prepared split still expands to search+holdout entries."""

    matrix = _matrix()
    prepared = {cid: _prepared(cid, split=(cid == "cwe078-0")) for cid in BASELINE_COMBINATIONS}
    units = expand_units(matrix, prepared)
    runs = [entry for unit in units for entry in unit.entries]
    assert len(units) == 24
    assert len(runs) == 30
    cwe078_units = [unit for unit in units if unit.combination_id == "cwe078-0"]
    assert all(len(unit.entries) == 2 for unit in cwe078_units)
    search_run = next(
        entry
        for unit in cwe078_units
        for entry in unit.entries
        if entry.stage == "search" and unit.repeats == 1 and unit.temperature == 0.0
    )
    holdout_run = next(
        entry
        for unit in cwe078_units
        for entry in unit.entries
        if entry.stage == "holdout" and unit.repeats == 1 and unit.temperature == 0.0
    )
    assert len(search_run.task_ids) == 18
    assert len(holdout_run.task_ids) == 9


def test_unit_and_batch_identity_shape() -> None:
    matrix = _matrix(batch_tag="baseline-v1")
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    units = expand_units(matrix, prepared)
    unit = next(
        unit
        for unit in units
        if unit.combination_id == "cwe078-0"
        and unit.form == "clean_0shot"
        and unit.repeats == 5
    )
    assert unit.unit_id == "cwe078-0__clean_0shot__t0.7r5"
    assert unit.batch_id == "baseline-v1::cwe078-0__clean_0shot__t0.7r5"
    assert unit.task_ids_sha256 == sha256_bytes(canonical_json_bytes(list(unit.task_ids)))
    assert unit.entries[0].run_dir == f"units/{unit.unit_id}/search"
    assert unit.entries[0].config_path == f"configs/units/{unit.unit_id}::search.json"


def test_task_count_mismatch_rejected() -> None:
    matrix = _matrix()
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    prepared["cwe502-0"] = _prepared("cwe502-0", total=44)
    with pytest.raises(MatrixError, match="expected 45"):
        expand_units(matrix, prepared)


def test_load_matrix_config_round_trip(tmp_path) -> None:
    import json

    matrix = _matrix(baseline_root=str(tmp_path))
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(matrix.to_json()), encoding="utf-8")
    loaded = load_matrix_config(path)
    assert loaded == matrix
    # hashing a matrix must be deterministic
    assert hashlib.sha256(canonical_json_bytes(loaded.to_json())).hexdigest() == hashlib.sha256(
        canonical_json_bytes(matrix.to_json())
    ).hexdigest()
