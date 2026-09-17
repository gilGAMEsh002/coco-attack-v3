"""Stable artifact writers and readers for prepared data.

Writers are used by ``prepare-data``; the reader validates that a prepared
directory is complete and internally consistent before downstream prompt or
cleaning stages consume it. All files are written atomically from canonical,
sorted JSON; the completion manifest is written last so a partial run can never
look complete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.schema import STANDARD_SCHEMA
from ..protocol.fingerprint import hash_task_snapshot
from ..protocol.stages import DATA_CONTRACT_VERSION
from .contracts import (
    DataContractError,
    DatasetSelection,
    PreparedCombination,
    SplitManifest,
    TaskRecord,
    TaskSource,
)


def write_tasks_jsonl(path: Path, records: tuple[TaskRecord, ...]) -> str:
    lines = [
        canonical_json_bytes(record.snapshot()).decode("utf-8") for record in records
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, "".join(line + "\n" for line in lines))
    return sha256_file(path)


def write_selection(path: Path, selection: DatasetSelection) -> str:
    write_json_atomic(path, selection.to_json())
    return sha256_file(path)


def write_split(path: Path, split: SplitManifest) -> str:
    write_json_atomic(path, split.to_json())
    return sha256_file(path)


def write_manifest(path: Path, manifest: dict[str, Any]) -> str:
    write_json_atomic(path, manifest)
    return sha256_file(path)


def write_report(path: Path, report: str) -> str:
    write_text_atomic(path, report)
    return sha256_file(path)


def write_errors(path: Path, payload: dict[str, Any]) -> str:
    write_json_atomic(path, payload)
    return sha256_file(path)


def load_prepared_data(
    data_dir: Path,
    combination_id: str,
) -> PreparedCombination:
    """Read and validate one prepared combination.

    The snapshot is *not* fed to the strict raw-data loader: ``tasks.jsonl``
    carries effective 17-field records plus a ``_provenance`` block. Raw
    registry-normalized metadata values are restored from that provenance so the
    raw/effective distinction survives the round trip.
    """

    manifest_path = data_dir / "manifest.json"
    if not manifest_path.is_file():
        _fail(
            "prepared.manifest_missing",
            f"prepared manifest not found: {manifest_path}",
            str(data_dir),
        )
    manifest = read_json(manifest_path)
    if manifest.get("completion") != "complete":
        _fail(
            "prepared.incomplete",
            f"prepared manifest completion is {manifest.get('completion')!r}",
            str(manifest_path),
        )
    if manifest.get("data_contract") != DATA_CONTRACT_VERSION:
        _fail(
            "prepared.contract_mismatch",
            (
                f"prepared data_contract {manifest.get('data_contract')!r} != "
                f"{DATA_CONTRACT_VERSION!r}"
            ),
            str(manifest_path),
        )
    entry = (manifest.get("combinations") or {}).get(combination_id)
    if not isinstance(entry, dict):
        _fail(
            "prepared.combination_missing",
            f"combination {combination_id!r} not present in prepared manifest",
            str(manifest_path),
        )

    combo_dir = data_dir / combination_id
    for name in ("tasks.jsonl", "selection.json", "split.json"):
        path = combo_dir / name
        if not path.is_file():
            _fail("prepared.file_missing", f"prepared file missing: {path}", str(path))
        expected = (entry.get("files") or {}).get(name)
        actual = sha256_file(path)
        if expected != actual:
            _fail(
                "prepared.file_hash_mismatch",
                f"{name} sha256 {actual} != manifest {expected}",
                str(path),
            )

    records = _read_task_snapshots(combo_dir / "tasks.jsonl", combination_id)
    try:
        selection = DatasetSelection.from_json(read_json(combo_dir / "selection.json"))
        split = SplitManifest.from_json(read_json(combo_dir / "split.json"))
    except (KeyError, TypeError, ValueError) as error:
        _fail(
            "prepared.structure_invalid",
            f"selection/split structure is invalid: {error}",
            str(combo_dir),
        )

    if selection.combination_id != combination_id or split.combination_id != combination_id:
        _fail(
            "prepared.identity_mismatch",
            "selection/split combination_id does not match requested combination",
            str(combo_dir),
        )
    recomputed = hash_task_snapshot(
        (record.task_id, record.source.record_sha256) for record in records
    )
    if recomputed != selection.task_snapshot_sha256:
        _fail(
            "prepared.snapshot_hash_mismatch",
            "recomputed task snapshot hash does not match selection",
            str(combo_dir / "selection.json"),
        )
    if split.task_snapshot_sha256 != selection.task_snapshot_sha256:
        _fail(
            "prepared.split_snapshot_mismatch",
            "split task snapshot hash does not match selection",
            str(combo_dir / "split.json"),
        )
    if set(selection.evaluation_ids) != set(split.input_ids):
        _fail(
            "prepared.evaluation_set_mismatch",
            "split input_ids do not match selection evaluation_ids",
            str(combo_dir / "split.json"),
        )

    return PreparedCombination(
        combination_id=combination_id,
        registry_id=entry["registry_id"],
        oracle_id=entry["oracle_id"],
        data_contract=manifest["data_contract"],
        records=tuple(records),
        selection=selection,
        split=split,
        manifest_sha256=sha256_file(manifest_path),
        files=dict(entry.get("files") or {}),
    )


def _read_task_snapshots(path: Path, combination_id: str) -> list[TaskRecord]:
    expected_keys = set(STANDARD_SCHEMA) | {"_provenance"}
    records: list[TaskRecord] = []
    seen_ids: set[str] = set()
    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                _fail(
                    "prepared.invalid_json",
                    f"tasks.jsonl line {lineno}: {error}",
                    f"{path}:{lineno}",
                )
            if not isinstance(obj, dict) or set(obj) != expected_keys:
                _fail(
                    "prepared.snapshot_schema",
                    (
                        f"tasks.jsonl line {lineno} must carry exactly the 17 standard "
                        "fields plus _provenance"
                    ),
                    f"{path}:{lineno}",
                )
            provenance = obj["_provenance"]
            effective = {field: obj[field] for field in STANDARD_SCHEMA}
            task_id = effective["task_id"]
            if not isinstance(task_id, str):
                _fail(
                    "prepared.non_string_task_id",
                    f"tasks.jsonl line {lineno}: task_id must be a string",
                    f"{path}:{lineno}",
                )
            if task_id in seen_ids:
                _fail(
                    "prepared.duplicate_task",
                    f"tasks.jsonl line {lineno}: duplicate task_id {task_id!r}",
                    f"{path}:{lineno}",
                )
            seen_ids.add(task_id)
            raw_values = provenance.get("raw_metadata_values") or {}
            raw_record = dict(effective)
            raw_record.update(raw_values)
            records.append(
                TaskRecord(
                    combination_id=provenance["combination_id"],
                    task_id=effective["task_id"],
                    raw=raw_record,
                    effective=effective,
                    metadata_provenance=dict(provenance.get("metadata_provenance") or {}),
                    source=TaskSource(
                        combination_id=provenance["combination_id"],
                        source_path=provenance["source_path"],
                        source_file_sha256=provenance["source_file_sha256"],
                        line_number=provenance["source_line"],
                        schema=provenance["schema"],
                        record_sha256=provenance["record_sha256"],
                    ),
                )
            )
    return records


def _fail(code: str, detail: str, asset: str):
    raise DataContractError(
        detail,
        [Issue(code=code, severity=SEVERITY_ERROR, scope="prepared", detail=detail, asset=asset)],
    )


def split_manifest_sha256(data_dir: Path | str, combination_id: str) -> str:
    """Byte hash of the prepared split manifest for a combination."""

    path = Path(data_dir) / combination_id / "split.json"
    if not path.is_file():
        _fail(
            "prepared.split_manifest_missing",
            f"prepared split manifest not found: {path}",
            str(path),
        )
    return sha256_file(path)
