"""Unified validation of a materialized prompt experiment (task 03)."""

from __future__ import annotations

from pathlib import Path

from ..assets.artifacts import read_json
from ..assets.issues import SEVERITY_ERROR, Issue
from ..data.contracts import DataContractError, PreparedCombination
from .contracts import ExperimentSpec, PromptExperiment, PromptSource
from .markdown import CLEAN_FORMS, FORM_CLEAN_0SHOT
from .materialize import index_prompt_dir


def load_experiment(
    experiment_dir: Path,
    prepared: PreparedCombination,
    expected_oracle_id: str,
) -> PromptExperiment:
    issues: list[Issue] = []

    meta_path = experiment_dir / "meta.json"
    if not meta_path.is_file():
        _fail(issues, "experiment.meta_missing", f"meta.json missing: {meta_path}", str(experiment_dir))
    meta = read_json(meta_path)

    def check(condition: bool, code: str, detail: str) -> None:
        if not condition:
            issues.append(
                Issue(
                    code=code,
                    severity=SEVERITY_ERROR,
                    scope="experiment",
                    detail=detail,
                    asset=str(meta_path),
                    location={"combination_id": prepared.combination_id},
                )
            )

    check(
        meta.get("combination_id") == prepared.combination_id,
        "experiment.combination_mismatch",
        f"meta combination_id {meta.get('combination_id')!r} != {prepared.combination_id!r}",
    )
    check(
        meta.get("oracle_id") == expected_oracle_id,
        "experiment.oracle_mismatch",
        f"meta oracle_id {meta.get('oracle_id')!r} != expected {expected_oracle_id!r}",
    )
    check(
        meta.get("form") in CLEAN_FORMS,
        "experiment.unknown_form",
        f"unknown form {meta.get('form')!r}",
    )
    check(
        meta.get("data_contract") == prepared.data_contract,
        "experiment.contract_mismatch",
        "meta data_contract does not match prepared data",
    )
    check(
        meta.get("task_snapshot_sha256") == prepared.selection.task_snapshot_sha256,
        "experiment.snapshot_mismatch",
        "meta task_snapshot_sha256 does not match prepared selection",
    )

    evaluation_ids = list(prepared.selection.evaluation_ids)
    example_ids = list(prepared.selection.example_ids)
    check(
        list(meta.get("evaluation_ids") or []) == evaluation_ids,
        "experiment.eval_ids_mismatch",
        "meta evaluation_ids does not match prepared selection",
    )
    check(
        list(meta.get("excluded_ids") or []) == example_ids,
        "experiment.excluded_ids_mismatch",
        "meta excluded_ids does not match prepared selection examples",
    )

    if issues:
        raise DataContractError(
            f"{prepared.combination_id}: experiment meta validation failed", issues
        )

    test_dir = experiment_dir / "test_prompts"
    try:
        source_map = index_prompt_dir(test_dir, evaluation_ids)
    except ValueError as error:
        _fail(
            issues,
            "experiment.prompt_set_invalid",
            str(error),
            str(test_dir),
        )
    leaked = sorted(set(example_ids) & set(source_map))
    if leaked:
        _fail(
            issues,
            "experiment.example_leak",
            f"example ids present in test_prompts: {leaked}",
            str(test_dir),
        )

    fewshot_path = experiment_dir / "fewshot.json"
    if not fewshot_path.is_file():
        _fail(issues, "experiment.fewshot_missing", "fewshot.json missing", str(experiment_dir))
    fewshot = read_json(fewshot_path)
    if not isinstance(fewshot, list):
        _fail(issues, "experiment.fewshot_invalid", "fewshot.json is not a list", str(fewshot_path))
    if meta.get("form") == FORM_CLEAN_0SHOT:
        if fewshot:
            _fail(
                issues,
                "experiment.zeroshot_examples",
                "clean_0shot must have an empty fewshot list",
                str(fewshot_path),
            )
    elif [sample.get("task_id") for sample in fewshot] != example_ids:
        _fail(
            issues,
            "experiment.fewshot_ids_mismatch",
            "fewshot.json task_id order does not match prepared examples",
            str(fewshot_path),
        )

    if issues:
        raise DataContractError(
            f"{prepared.combination_id}: experiment content validation failed", issues
        )

    prompts = {
        task_id: source_map[task_id].read_text(encoding="utf-8")
        for task_id in evaluation_ids
    }
    spec = ExperimentSpec(
        combination_id=prepared.combination_id,
        oracle_id=expected_oracle_id,
        form=meta["form"],
        example_ids=tuple(example_ids),
        excluded_ids=tuple(example_ids),
        evaluation_ids=tuple(evaluation_ids),
        data_contract=prepared.data_contract,
        task_snapshot_sha256=prepared.selection.task_snapshot_sha256,
        split_manifest_sha256=(prepared.files or {}).get("split.json", ""),
        selection_sha256=(prepared.files or {}).get("selection.json", ""),
        prompt_version=str(meta.get("prompt_version", "")),
        materialize_version=str(meta.get("materialize_version", "")),
        attack_config=dict(meta.get("attack_config") or {}),
    )
    sources = tuple(
        PromptSource(path=task_id, sha256="", kind="test_prompt")
        for task_id in evaluation_ids
    )
    return PromptExperiment(
        spec=spec,
        meta=meta,
        fewshot=tuple(fewshot),
        prompts=prompts,
        sources=sources,
    )


def _fail(issues: list[Issue], code: str, detail: str, asset: str) -> None:
    issues.append(
        Issue(
            code=code,
            severity=SEVERITY_ERROR,
            scope="experiment",
            detail=detail,
            asset=asset,
        )
    )
    raise DataContractError(detail, issues)
