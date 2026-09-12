"""Deterministic combination-level split (``build_split``).

``build_split`` is a pure function: it touches no model and no filesystem and
depends only on the verified selection and the split configuration. The only
configured split in this round is ``cwe078-0`` (seed=42, 18/9); every other
combination is ``whole-set``.
"""

from __future__ import annotations

from typing import Any

from ..assets.issues import SEVERITY_ERROR, Issue
from ..protocol.fingerprint import hash_id_sequence, split_sort_key
from ..protocol.stages import SPLIT_ALGORITHM_VERSION, SplitMode
from .contracts import DataContractError, DatasetSelection, SplitManifest


def build_split(
    selection: DatasetSelection,
    split_config: dict[str, Any],
    split_config_sha256: str,
) -> SplitManifest:
    combination_id = selection.combination_id
    entry = (split_config.get("combinations") or {}).get(combination_id)
    mode = (entry or {}).get("mode", "whole-set")
    algorithm_version = split_config.get("algorithm_version", SPLIT_ALGORITHM_VERSION)

    if mode == "whole-set":
        input_ids = tuple(selection.evaluation_ids)
        return SplitManifest(
            combination_id=combination_id,
            mode=SplitMode.WHOLE_SET,
            seed=None,
            algorithm_version=algorithm_version,
            split_config_sha256=split_config_sha256,
            input_ids=input_ids,
            input_ids_sha256=hash_id_sequence(input_ids),
            task_snapshot_sha256=selection.task_snapshot_sha256,
            search_ids=(),
            holdout_ids=(),
            evaluation_ids=input_ids,
        )

    if mode != "split":
        _fail(
            "split.unknown_mode",
            f"unknown split mode {mode!r} for {combination_id}",
            combination_id,
        )

    seed = entry.get("seed")
    search_count = entry.get("search_count")
    holdout_count = entry.get("holdout_count")
    if not all(isinstance(value, int) for value in (seed, search_count, holdout_count)):
        _fail(
            "split.invalid_config",
            f"{combination_id}: split requires integer seed/search_count/holdout_count",
            combination_id,
        )

    input_ids = tuple(selection.evaluation_ids)
    if len(input_ids) != search_count + holdout_count:
        _fail(
            "split.count_mismatch",
            (
                f"{combination_id}: {len(input_ids)} evaluation ids do not equal "
                f"search_count {search_count} + holdout_count {holdout_count}"
            ),
            combination_id,
        )
    ordered = sorted(input_ids, key=lambda task_id: split_sort_key(seed, task_id))
    search_ids = tuple(ordered[:search_count])
    holdout_ids = tuple(ordered[search_count:])
    if not search_ids or not holdout_ids:
        _fail(
            "split.empty_partition",
            f"{combination_id}: a partition is empty",
            combination_id,
        )
    if set(search_ids) & set(holdout_ids) or set(search_ids) | set(holdout_ids) != set(input_ids):
        _fail(
            "split.partition_invalid",
            f"{combination_id}: partitions overlap or do not cover the input set",
            combination_id,
        )

    return SplitManifest(
        combination_id=combination_id,
        mode=SplitMode.SEARCH_HOLDOUT,
        seed=seed,
        algorithm_version=algorithm_version,
        split_config_sha256=split_config_sha256,
        input_ids=input_ids,
        input_ids_sha256=hash_id_sequence(input_ids),
        task_snapshot_sha256=selection.task_snapshot_sha256,
        search_ids=search_ids,
        holdout_ids=holdout_ids,
        evaluation_ids=(),
    )


def validate_split_config_combinations(
    split_config: dict[str, Any], known_combination_ids: set[str]
) -> None:
    unknown = sorted(
        set((split_config.get("combinations") or {})) - known_combination_ids
    )
    if unknown:
        _fail(
            "split.unknown_combination",
            f"split config references unknown combinations: {unknown}",
            ",".join(unknown),
        )


def _fail(code: str, detail: str, combination_id: str):
    raise DataContractError(
        detail,
        [
            Issue(
                code=code,
                severity=SEVERITY_ERROR,
                scope="split",
                detail=detail,
                location={"combination_id": combination_id},
            )
        ],
    )
