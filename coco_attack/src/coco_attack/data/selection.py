"""Example and evaluation-set verification (``prepare_selection``).

Legacy combinations reuse the materialised clean prompt assets; the new five
combinations reuse the existing seed=42 selection records. Neither path
re-samples examples. Any inconsistency is an error: the code never silently
picks one source over another or intersects sets.
"""

from __future__ import annotations

from pathlib import Path

from ..assets.artifacts import read_json, sha256_file
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.paths import relative_to_root, resolve_within
from ..assets.schema import TEST_PROMPT_RE
from ..protocol.fingerprint import hash_task_snapshot
from ..protocol.stages import DEFAULT_SEED
from .contracts import (
    CombinationSpec,
    DataContractError,
    DatasetSelection,
    LoadedTasks,
)


def prepare_selection(
    spec: CombinationSpec,
    loaded: LoadedTasks,
    assets_root: Path,
) -> DatasetSelection:
    if spec.is_legacy:
        return _prepare_legacy_selection(spec, loaded, assets_root)
    return _prepare_new_selection(spec, loaded, assets_root)


def _task_snapshot_sha256(loaded: LoadedTasks) -> str:
    return hash_task_snapshot(
        (record.task_id, record.source.record_sha256) for record in loaded.records
    )


def _resolve_selection_record(
    spec: CombinationSpec, assets_root: Path
) -> tuple[dict, str, str, int, int | None]:
    path = resolve_within(assets_root, spec.selection_file)
    if not path.is_file():
        _fail(
            "selection.missing",
            f"selection record not found at {spec.selection_file}",
            spec.selection_file,
            spec.combination_id,
        )
    payload = read_json(path)
    selected = payload.get("selected") or {}
    record = selected.get(spec.selection_key)
    if not isinstance(record, dict):
        _fail(
            "selection.key_missing",
            f"selection key {spec.selection_key!r} absent from {spec.selection_file}",
            spec.selection_file,
            spec.combination_id,
        )
    return (
        record,
        sha256_file(path),
        spec.selection_file,
        payload.get("seed"),
        payload.get("count_per_cwe"),
    )


def _prepare_new_selection(
    spec: CombinationSpec,
    loaded: LoadedTasks,
    assets_root: Path,
) -> DatasetSelection:
    record, selection_sha, selection_rel, payload_seed, payload_count = (
        _resolve_selection_record(spec, assets_root)
    )
    seed = payload_seed if payload_seed is not None else DEFAULT_SEED
    example_ids = list(record.get("task_ids") or [])
    task_ids = set(loaded.task_ids)

    issues: list[Issue] = []
    if payload_count is not None and len(example_ids) != payload_count:
        issues.append(
            Issue(
                code="selection.count_mismatch",
                severity=SEVERITY_ERROR,
                scope="selection",
                detail=(
                    f"selection declares count_per_cwe={payload_count} but lists "
                    f"{len(example_ids)} example ids"
                ),
                asset=selection_rel,
                location={"combination_id": spec.combination_id},
            )
        )
    if seed != DEFAULT_SEED:
        issues.append(
            Issue(
                code="selection.unexpected_seed",
                severity=SEVERITY_ERROR,
                scope="selection",
                detail=f"selection declares seed={seed!r}, expected {DEFAULT_SEED}",
                asset=selection_rel,
                location={"combination_id": spec.combination_id},
            )
        )
    if len(example_ids) != len(set(example_ids)):
        issues.append(
            Issue(
                code="selection.duplicate_example",
                severity=SEVERITY_ERROR,
                scope="selection",
                detail=f"example ids repeat: {example_ids}",
                asset=selection_rel,
                location={"combination_id": spec.combination_id},
            )
        )
    unknown = sorted(set(example_ids) - task_ids)
    if unknown:
        issues.append(
            Issue(
                code="selection.example_not_in_tasks",
                severity=SEVERITY_ERROR,
                scope="selection",
                detail=f"example ids absent from standard tasks: {unknown}",
                asset=selection_rel,
                location={"combination_id": spec.combination_id},
            )
        )
    if issues:
        raise DataContractError(
            f"{spec.combination_id}: invalid example selection", issues
        )

    evaluation_ids = tuple(tid for tid in loaded.task_ids if tid not in set(example_ids))
    return DatasetSelection(
        combination_id=spec.combination_id,
        seed=int(seed),
        example_ids=tuple(example_ids),
        evaluation_ids=evaluation_ids,
        selection_source=spec.selection_source,
        selection_file=selection_rel,
        selection_file_sha256=selection_sha,
        verification_sources=(selection_rel,),
        task_snapshot_sha256=_task_snapshot_sha256(loaded),
    )


def _prepare_legacy_selection(
    spec: CombinationSpec,
    loaded: LoadedTasks,
    assets_root: Path,
) -> DatasetSelection:
    clean_assets = spec.clean_assets or {}
    root_rel = clean_assets.get("experiment_root")
    if not root_rel:
        _fail(
            "selection.clean_assets_missing",
            "legacy combination has no clean_assets declaration",
            spec.combination_id,
            spec.combination_id,
        )
    few_rel = f"{root_rel}/{clean_assets['fewshot_experiment']}"
    zero_rel = f"{root_rel}/{clean_assets['zero_shot_experiment']}"
    few_dir = resolve_within(assets_root, few_rel)
    zero_dir = resolve_within(assets_root, zero_rel)
    for rel, directory in ((few_rel, few_dir), (zero_rel, zero_dir)):
        if not directory.is_dir():
            _fail(
                "selection.clean_experiment_missing",
                f"clean prompt experiment directory missing: {rel}",
                rel,
                spec.combination_id,
            )

    meta_path = few_dir / "meta.json"
    fewshot_path = few_dir / "fewshot.json"
    for path, label in ((meta_path, "meta.json"), (fewshot_path, "fewshot.json")):
        if not path.is_file():
            _fail(
                "selection.clean_file_missing",
                f"required clean asset file missing: {label}",
                relative_to_root(assets_root, path),
                spec.combination_id,
            )

    meta = read_json(meta_path)
    fewshot = read_json(fewshot_path)
    if not isinstance(meta, dict):
        _fail("selection.invalid_meta", "meta.json is not an object", few_rel, spec.combination_id)
    if not isinstance(fewshot, list) or any(
        not isinstance(sample, dict) for sample in fewshot
    ):
        _fail(
            "selection.invalid_fewshot",
            "fewshot.json is not a list of sample objects",
            few_rel,
            spec.combination_id,
        )

    meta_ids = list(meta.get("fewshot_ids") or [])
    fewshot_ids = [sample.get("task_id") for sample in fewshot]
    legacy_record, selection_sha, selection_rel, legacy_payload_seed, legacy_payload_count = (
        _resolve_selection_record(spec, assets_root)
    )
    legacy_seed = (
        legacy_payload_seed if legacy_payload_seed is not None else DEFAULT_SEED
    )
    legacy_ids = list(legacy_record.get("task_ids") or [])

    few_test_ids, few_unparsable = _test_prompt_ids(few_dir / "test_prompts")
    zero_test_ids, zero_unparsable = _test_prompt_ids(zero_dir / "test_prompts")

    issues: list[Issue] = []
    if legacy_seed != DEFAULT_SEED:
        issues.append(
            _issue(
                "selection.unexpected_seed",
                f"legacy selection declares seed={legacy_seed!r}, expected {DEFAULT_SEED}",
                selection_rel,
                spec,
            )
        )
    if legacy_payload_count is not None and len(legacy_ids) != legacy_payload_count:
        issues.append(
            _issue(
                "selection.count_mismatch",
                f"legacy selection declares count_per_cwe={legacy_payload_count} but "
                f"lists {len(legacy_ids)} example ids",
                selection_rel,
                spec,
            )
        )
    if meta_ids != fewshot_ids:
        issues.append(
            _issue(
                "selection.meta_fewshot_mismatch",
                f"meta fewshot_ids {meta_ids} != fewshot.json order {fewshot_ids}",
                few_rel,
                spec,
            )
        )
    if legacy_ids != fewshot_ids:
        issues.append(
            _issue(
                "selection.legacy_record_mismatch",
                f"legacy seed record {legacy_ids} != fewshot.json order {fewshot_ids}",
                selection_rel,
                spec,
            )
        )
    if len(fewshot_ids) != len(set(fewshot_ids)):
        issues.append(
            _issue(
                "selection.duplicate_example",
                f"example ids repeat: {fewshot_ids}",
                few_rel,
                spec,
            )
        )
    if few_unparsable or zero_unparsable:
        issues.append(
            _issue(
                "selection.unparsable_test_prompt",
                "test_prompts filenames not matching BigCodeBench_SL_<n>.md: "
                f"fewshot={few_unparsable}, zero_shot={zero_unparsable}",
                root_rel,
                spec,
            )
        )
    if few_test_ids != zero_test_ids:
        issues.append(
            _issue(
                "selection.eval_set_mismatch",
                "few-shot and 0-shot evaluation sets differ: "
                f"fewshot_only={sorted(set(few_test_ids) - set(zero_test_ids))}, "
                f"zero_only={sorted(set(zero_test_ids) - set(few_test_ids))}",
                root_rel,
                spec,
            )
        )
    if meta.get("test_count") is not None and meta.get("test_count") != len(few_test_ids):
        issues.append(
            _issue(
                "selection.test_count_mismatch",
                f"meta test_count={meta.get('test_count')} but "
                f"{len(few_test_ids)} test_prompts files exist",
                few_rel,
                spec,
            )
        )

    task_ids = set(loaded.task_ids)
    unknown = sorted((set(fewshot_ids) | set(few_test_ids)) - task_ids)
    if unknown:
        issues.append(
            _issue(
                "selection.ids_not_in_tasks",
                f"clean-asset ids absent from standard tasks: {unknown}",
                root_rel,
                spec,
            )
        )
    overlap = sorted(set(few_test_ids) & set(fewshot_ids))
    if overlap:
        issues.append(
            _issue(
                "selection.example_eval_overlap",
                f"few-shot ids also present in evaluation set: {overlap}",
                root_rel,
                spec,
            )
        )
    expected_eval = task_ids - set(fewshot_ids)
    missing = sorted(expected_eval - set(few_test_ids))
    extra = sorted(set(few_test_ids) - expected_eval)
    if missing or extra:
        issues.append(
            _issue(
                "selection.eval_set_unexpected",
                "evaluation set != standard tasks minus examples: "
                f"missing={missing}, extra={extra}",
                root_rel,
                spec,
            )
        )
    if issues:
        raise DataContractError(
            f"{spec.combination_id}: legacy selection verification failed", issues
        )

    return DatasetSelection(
        combination_id=spec.combination_id,
        seed=int(legacy_seed),
        example_ids=tuple(fewshot_ids),
        evaluation_ids=tuple(few_test_ids),
        selection_source=spec.selection_source,
        selection_file=selection_rel,
        selection_file_sha256=selection_sha,
        verification_sources=(
            selection_rel,
            f"{few_rel}/meta.json",
            f"{few_rel}/fewshot.json",
            f"{few_rel}/test_prompts",
            f"{zero_rel}/test_prompts",
        ),
        task_snapshot_sha256=_task_snapshot_sha256(loaded),
        warnings=(),
    )


def _test_prompt_ids(directory: Path) -> tuple[list[str], list[str]]:
    if not directory.is_dir():
        return [], [f"<missing directory {directory}>"]
    ids: list[str] = []
    unparsable: list[str] = []
    for child in sorted(directory.iterdir()):
        if not child.is_file():
            continue
        match = TEST_PROMPT_RE.match(child.name)
        if match is None:
            unparsable.append(child.name)
        else:
            ids.append(f"BigCodeBench/{match.group(1)}")
    return ids, unparsable


def _issue(code: str, detail: str, asset: str, spec: CombinationSpec) -> Issue:
    return Issue(
        code=code,
        severity=SEVERITY_ERROR,
        scope="selection",
        detail=detail,
        asset=asset,
        location={"combination_id": spec.combination_id},
    )


def _fail(code: str, detail: str, asset: str, combination_id: str):
    raise DataContractError(
        detail,
        [
            Issue(
                code=code,
                severity=SEVERITY_ERROR,
                scope="selection",
                detail=detail,
                asset=asset,
                location={"combination_id": combination_id},
            )
        ],
    )
