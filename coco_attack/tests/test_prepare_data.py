"""Phase-02 checks for the data contract, selection and deterministic split.

The integration tests read the real asset tree read-only; pure-function tests
construct their own inputs so negative cases are explicit.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.paths import default_config_dir
from coco_attack.assets.schema import STANDARD_SCHEMA
from coco_attack.cli import main
from coco_attack.data.contracts import (
    CombinationSpec,
    DataContractError,
    DatasetSelection,
)
from coco_attack.data.loader import load_tasks
from coco_attack.data.prepare import prepare_data
from coco_attack.data.selection import prepare_selection
from coco_attack.data.split import build_split
from coco_attack.protocol.stages import SplitMode

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
SPLIT_CONFIG = default_config_dir() / "splits.json"

pytestmark = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)


def _prepare(output_dir: Path, combinations: list[str]) -> int:
    return main(
        [
            "prepare-data",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--output-dir",
            str(output_dir),
            "--split-config",
            str(SPLIT_CONFIG),
            *sum([["--combination", c] for c in combinations], []),
        ]
    )


# --------------------------------------------------------------------------- #
# Pure split function
# --------------------------------------------------------------------------- #


def _selection(ids: list[str], seed: int = 42) -> DatasetSelection:
    return DatasetSelection(
        combination_id="cwe999-0",
        seed=seed,
        example_ids=("BigCodeBench/1",),
        evaluation_ids=tuple(ids),
        selection_source="new",
        selection_file="fake.json",
        selection_file_sha256="0" * 64,
        verification_sources=(),
        task_snapshot_sha256="1" * 64,
    )


def test_build_split_search_holdout_is_deterministic_and_disjoint() -> None:
    ids = [f"BigCodeBench/{n}" for n in range(100)]
    config = {
        "algorithm_version": "sha256-seed-taskid-v1",
        "combinations": {"cwe999-0": {"mode": "split", "seed": 42, "search_count": 18, "holdout_count": 82}},
    }
    first = build_split(_selection(ids), config, "a" * 64)
    second = build_split(_selection(ids), config, "a" * 64)
    assert first.to_json() == second.to_json()
    assert first.mode is SplitMode.SEARCH_HOLDOUT
    assert len(first.search_ids) == 18
    assert len(first.holdout_ids) == 82
    assert not set(first.search_ids) & set(first.holdout_ids)
    assert set(first.search_ids) | set(first.holdout_ids) == set(ids)


def test_build_split_whole_set_has_no_holdout() -> None:
    ids = ["BigCodeBench/1", "BigCodeBench/2"]
    manifest = build_split(_selection(ids), {"combinations": {}}, "b" * 64)
    assert manifest.mode is SplitMode.WHOLE_SET
    assert manifest.holdout_ids == ()
    assert manifest.search_ids == ()
    assert manifest.to_json()["holdout_exists"] is False
    assert manifest.input_ids == tuple(ids)


def test_build_split_count_mismatch_raises() -> None:
    ids = ["BigCodeBench/1", "BigCodeBench/2", "BigCodeBench/3"]
    config = {
        "combinations": {"cwe999-0": {"mode": "split", "seed": 42, "search_count": 2, "holdout_count": 2}}
    }
    with pytest.raises(DataContractError) as excinfo:
        build_split(_selection(ids), config, "c" * 64)
    assert any(issue.code == "split.count_mismatch" for issue in excinfo.value.issues)


# --------------------------------------------------------------------------- #
# Strict loader
# --------------------------------------------------------------------------- #


def _spec(task_file: str) -> CombinationSpec:
    return CombinationSpec(
        combination_id="cwe999-0",
        registry_id="CWE-999-0",
        oracle_id="cwe999-0",
        legacy_alias=None,
        task_file=task_file,
        selection_source="new",
        selection_file="unused.json",
        selection_key="cwe999-0",
        clean_assets=None,
        coverage={"static": True, "dynamic": False, "security_realism": False},
        registry_definition={
            "registry_id": "CWE-999-0",
            "experiment_type": "api_parameter",
            "decision": "qualified",
        },
    )


def _valid_record(task_id: str = "BigCodeBench/1") -> dict:
    record = {field: "value" for field in STANDARD_SCHEMA}
    record.update(
        task_id=task_id,
        test="import unittest",
        reference_side="clean",
        statistical_cwe_id="CWE-999-0",
        experiment_type="api_parameter",
        decision="qualified",
        source_cwe_id=None,
        has_clean_pattern=True,
        has_target_pattern=False,
    )
    return record


def _write_tasks(tmp_path: Path, records: list[dict]) -> Path:
    task_dir = tmp_path / "assets" / "data/BigCodeBench"
    task_dir.mkdir(parents=True)
    path = task_dir / "CWE-999-0.jsonl"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return tmp_path / "assets"


def test_load_tasks_rejects_duplicate_id(tmp_path: Path) -> None:
    assets = _write_tasks(tmp_path, [_valid_record("A"), _valid_record("A")])
    with pytest.raises(DataContractError) as excinfo:
        load_tasks(_spec("data/BigCodeBench/CWE-999-0.jsonl"), assets, {"api_parameter"})
    assert any(issue.code == "tasks.duplicate_id" for issue in excinfo.value.issues)


def test_load_tasks_rejects_missing_and_extra_fields(tmp_path: Path) -> None:
    record = _valid_record()
    del record["test"]
    record["undeclared"] = 1
    assets = _write_tasks(tmp_path, [record])
    with pytest.raises(DataContractError) as excinfo:
        load_tasks(_spec("data/BigCodeBench/CWE-999-0.jsonl"), assets, {"api_parameter"})
    codes = {issue.code for issue in excinfo.value.issues}
    assert {"tasks.missing_fields", "tasks.extra_fields"} <= codes


def test_load_tasks_rejects_bad_type_and_side(tmp_path: Path) -> None:
    record = _valid_record()
    record["has_clean_pattern"] = "yes"
    record["reference_side"] = "benign"
    assets = _write_tasks(tmp_path, [record])
    with pytest.raises(DataContractError) as excinfo:
        load_tasks(_spec("data/BigCodeBench/CWE-999-0.jsonl"), assets, {"api_parameter"})
    codes = {issue.code for issue in excinfo.value.issues}
    assert {"tasks.type_violation", "tasks.bad_reference_side"} <= codes


def test_load_tasks_applies_registry_metadata(tmp_path: Path) -> None:
    record = _valid_record()
    record["experiment_type"] = "api_replacement"
    record["decision"] = "qualified"
    assets = _write_tasks(tmp_path, [record])
    spec = _spec("data/BigCodeBench/CWE-999-0.jsonl")
    spec = replace(
        spec,
        registry_definition={
            "registry_id": "CWE-999-0",
            "experiment_type": "control_flow",
            "decision": "qualified_control_flow",
        },
    )
    loaded = load_tasks(spec, assets, {"api_parameter", "api_replacement", "control_flow"})
    assert loaded.records[0].effective["experiment_type"] == "control_flow"
    assert loaded.records[0].effective["decision"] == "qualified_control_flow"
    assert loaded.records[0].raw["experiment_type"] == "api_replacement"
    assert loaded.records[0].metadata_provenance["experiment_type"]["authority"] == "registry"


# --------------------------------------------------------------------------- #
# Integration with real assets
# --------------------------------------------------------------------------- #


def test_prepare_all_combinations_counts_and_modes(tmp_path: Path) -> None:
    output_dir = tmp_path / "prepared"
    assert _prepare(output_dir, ["all"]) == 0

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["completion"] == "complete"
    combinations = manifest["combinations"]
    assert set(combinations) == {
        "cwe022-0",
        "cwe078-0",
        "cwe089-0",
        "cwe094-0",
        "cwe295-0",
        "cwe295-1",
        "cwe367-0",
        "cwe400-0",
        "cwe502-0",
    }
    expected_eval = {
        "cwe022-0": 2,
        "cwe078-0": 27,
        "cwe089-0": 1,
        "cwe094-0": 4,
        "cwe295-0": 33,
        "cwe295-1": 3,
        "cwe367-0": 21,
        "cwe400-0": 36,
        "cwe502-0": 45,
    }
    for combination_id, evaluation_count in expected_eval.items():
        entry = combinations[combination_id]
        assert entry["task_count"] == evaluation_count + 4
        assert entry["example_count"] == 4
        assert entry["evaluation_count"] == evaluation_count

    # cwe078 is the only configured split and includes BigCodeBench/205.
    cwe078 = combinations["cwe078-0"]
    assert cwe078["mode"] == "search_holdout"
    assert (cwe078["search_count"], cwe078["holdout_count"]) == (18, 9)
    split = json.loads((output_dir / "cwe078-0/split.json").read_text(encoding="utf-8"))
    assert "BigCodeBench/205" in split["holdout"] + split["search"]
    assert not set(split["search"]) & set(split["holdout"])

    # Every other combination is whole-set with no fabricated holdout.
    for combination_id, entry in combinations.items():
        if combination_id == "cwe078-0":
            continue
        assert entry["mode"] == "whole-set"
        assert entry["holdout_count"] == 0
        split = json.loads(
            (output_dir / f"{combination_id}/split.json").read_text(encoding="utf-8")
        )
        assert split["holdout"] == []
        assert split["holdout_exists"] is False


def test_prepare_is_byte_stable(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert _prepare(first, ["all"]) == 0
    assert _prepare(second, ["all"]) == 0
    for relative in (
        "manifest.json",
        "REPORT.md",
        "cwe078-0/tasks.jsonl",
        "cwe078-0/selection.json",
        "cwe078-0/split.json",
        "cwe295-0/tasks.jsonl",
    ):
        assert (first / relative).read_bytes() == (second / relative).read_bytes(), relative


def test_prepare_refuses_nonempty_output_dir(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "keep.txt").write_text("do not overwrite", encoding="utf-8")
    assert _prepare(output_dir, ["cwe078-0"]) == 2
    assert (output_dir / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"


def test_prepare_unknown_combination_is_usage_error(tmp_path: Path) -> None:
    assert _prepare(tmp_path / "out", ["cwe999-9"]) == 2


def test_legacy_selection_detects_example_eval_overlap(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    task_dir = assets / "data/BigCodeBench"
    task_dir.mkdir(parents=True)
    (task_dir / "CWE-999-0.jsonl").write_text(
        "".join(
            json.dumps(_valid_record(f"BigCodeBench/{n}")) + "\n" for n in range(1, 7)
        ),
        encoding="utf-8",
    )
    root = "prompts_old/experiments/cwe999"
    few_dir = assets / root / "cwe999_clean_fewshot"
    zero_dir = assets / root / "cwe999_clean_0shot"
    for directory in (few_dir, zero_dir):
        (directory / "test_prompts").mkdir(parents=True)
    example_ids = [f"BigCodeBench/{n}" for n in (1, 2, 3, 4)]
    (few_dir / "meta.json").write_text(
        json.dumps({"fewshot_ids": example_ids, "test_count": 3}), encoding="utf-8"
    )
    (few_dir / "fewshot.json").write_text(
        json.dumps([{"task_id": task_id} for task_id in example_ids]),
        encoding="utf-8",
    )
    for directory in (few_dir, zero_dir):
        for number in (3, 5, 6):
            (directory / "test_prompts" / f"BigCodeBench_SL_{number}.md").write_text(
                "prompt", encoding="utf-8"
            )
    (assets / "old_selection.json").write_text(
        json.dumps({"seed": 42, "selected": {"cwe999": {"task_ids": example_ids}}}),
        encoding="utf-8",
    )
    spec = CombinationSpec(
        combination_id="cwe999-0",
        registry_id="CWE-999-0",
        oracle_id="cwe999-0",
        legacy_alias="cwe999",
        task_file="data/BigCodeBench/CWE-999-0.jsonl",
        selection_source="legacy",
        selection_file="old_selection.json",
        selection_key="cwe999",
        clean_assets={
            "experiment_root": root,
            "fewshot_experiment": "cwe999_clean_fewshot",
            "zero_shot_experiment": "cwe999_clean_0shot",
            "templates_dir": "templates",
            "template_file": "clean_fewshot.md",
        },
        coverage={},
        registry_definition={
            "registry_id": "CWE-999-0",
            "experiment_type": "api_parameter",
            "decision": "qualified",
        },
    )
    loaded = load_tasks(spec, assets, {"api_parameter"})
    with pytest.raises(DataContractError) as excinfo:
        prepare_selection(spec, loaded, assets)
    codes = {issue.code for issue in excinfo.value.issues}
    assert "selection.example_eval_overlap" in codes
    assert "selection.eval_set_unexpected" in codes


def test_prepare_failure_writes_diagnostics_without_manifest(tmp_path: Path) -> None:
    # Minimal fake asset root: registry + a deliberately broken cwe022-0 file.
    fake_assets = tmp_path / "assets"
    (fake_assets / "data/BigCodeBench").mkdir(parents=True)
    shutil.copy2(
        ASSETS_DIR / "data/coco_combination_registry.json",
        fake_assets / "data/coco_combination_registry.json",
    )
    shutil.copy2(
        ASSETS_DIR / "data/BigCodeBench/fewshot_selection_seed42.json",
        fake_assets / "data/BigCodeBench/fewshot_selection_seed42.json",
    )
    (fake_assets / "oracles").mkdir(parents=True)
    for oracle_module in (ASSETS_DIR / "oracles").glob("cwe*.py"):
        shutil.copy2(oracle_module, fake_assets / "oracles" / oracle_module.name)
    record = json.loads(
        (ASSETS_DIR / "data/BigCodeBench/CWE-022-0.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    record["test"] = ""  # required non-empty
    (fake_assets / "data/BigCodeBench/CWE-022-0.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8"
    )

    output_dir = tmp_path / "out"
    exit_code = prepare_data(
        REPO_DIR, fake_assets, output_dir, SPLIT_CONFIG, ["cwe022-0"]
    )
    assert exit_code == 1
    assert (output_dir / "prepare_errors.json").is_file()
    assert not (output_dir / "manifest.json").exists()
    errors = json.loads(
        (output_dir / "prepare_errors.json").read_text(encoding="utf-8")
    )
    assert errors["status"] == "failed"
    assert any(issue["code"] == "tasks.required_empty" for issue in errors["issues"])
