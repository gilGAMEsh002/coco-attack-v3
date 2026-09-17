"""Run manifest (``run-manifest-v1``) creation, validation and status updates.

The manifest is the single machine-readable record of the 24 units / 24 runs
(whole-set baseline).
It is fully persisted before any billable request and is updated in place by
sub-task 02; this module owns the schema, atomic writes and the status machine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    write_json_atomic,
)
from .matrix import MatrixConfig, RunUnit

RUN_MANIFEST_SCHEMA_VERSION = "run-manifest-v1"
UNIT_STATUSES = (
    "pending",
    "configured",
    "locked",
    "running",
    "complete",
    "incomplete",
    "blocked",
)

_UNIT_REQUIRED_FIELDS = (
    "unit_id",
    "combination_id",
    "oracle_id",
    "form",
    "split_mode",
    "temperature",
    "repeats",
    "batch_id",
    "task_ids",
    "task_ids_sha256",
    "expected_task_count",
    "expected_sample_count",
    "status",
    "lock_ref",
    "known_limitations",
    "enabled_layers",
    "sast_tools",
    "victim_model",
    "judge_model",
    "max_tokens",
    "functional_cache_dir",
    "runs",
)
_RUN_REQUIRED_FIELDS = (
    "run_id",
    "stage",
    "task_ids",
    "expected_sample_count",
    "status",
    "run_dir",
    "config_path",
    "result",
)


class ManifestError(ValueError):
    """A run-manifest schema, consistency or status-machine problem."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_manifest(
    matrix: MatrixConfig,
    units: tuple[RunUnit, ...],
    version_fingerprint: dict[str, Any],
    baseline_root: Path | str,
) -> dict[str, Any]:
    root = Path(baseline_root)
    functional_cache_dir = str(root / "cache" / "functional")
    timestamp = _utc_now()
    effective_layers = tuple(
        layer for layer in matrix.enabled_layers if matrix.judge_enabled or layer != "judge"
    )

    unit_payload: dict[str, Any] = {}
    for unit in units:
        runs = [
            {
                "run_id": entry.run_id,
                "stage": entry.stage,
                "task_ids": list(entry.task_ids),
                "expected_sample_count": entry.expected_sample_count,
                "status": "pending",
                "run_dir": entry.run_dir,
                "config_path": entry.config_path,
                "result": None,
            }
            for entry in unit.entries
        ]
        unit_payload[unit.unit_id] = {
            "unit_id": unit.unit_id,
            "combination_id": unit.combination_id,
            "oracle_id": unit.oracle_id,
            "form": unit.form,
            "split_mode": unit.split_mode,
            "temperature": unit.temperature,
            "repeats": unit.repeats,
            "batch_id": unit.batch_id,
            "task_ids": list(unit.task_ids),
            "task_ids_sha256": unit.task_ids_sha256,
            "expected_task_count": unit.expected_task_count,
            "expected_sample_count": unit.expected_sample_count,
            "status": "configured",
            "lock_ref": None,
            "known_limitations": [],
            "enabled_layers": list(effective_layers),
            "sast_tools": list(matrix.sast_tools),
            "victim_model": matrix.victim_model,
            "judge_model": matrix.judge_model,
            "max_tokens": matrix.max_tokens,
            "functional_cache_dir": functional_cache_dir,
            "runs": runs,
        }

    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "baseline_root": str(root),
        "created_at": timestamp,
        "updated_at": timestamp,
        "version_fingerprint": version_fingerprint,
        "matrix": matrix.to_json(),
        "units": unit_payload,
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be a JSON object")
    for key in ("schema_version", "baseline_root", "version_fingerprint", "matrix", "units"):
        if key not in manifest:
            raise ManifestError(f"manifest is missing required field: {key!r}")
    if manifest["schema_version"] != RUN_MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            f"manifest.schema_version {manifest['schema_version']!r} != "
            f"{RUN_MANIFEST_SCHEMA_VERSION!r}"
        )
    units = manifest["units"]
    if not isinstance(units, dict):
        raise ManifestError("manifest.units must be an object keyed by unit_id")

    for unit_id, unit in units.items():
        if not isinstance(unit, dict):
            raise ManifestError(f"unit {unit_id!r} must be an object")
        missing = [name for name in _UNIT_REQUIRED_FIELDS if name not in unit]
        if missing:
            raise ManifestError(f"unit {unit_id!r} is missing fields: {missing}")
        if unit["unit_id"] != unit_id:
            raise ManifestError(f"unit key {unit_id!r} does not match unit_id {unit['unit_id']!r}")
        if unit["status"] not in UNIT_STATUSES:
            raise ManifestError(f"unit {unit_id!r} has invalid status {unit['status']!r}")
        repeats = unit["repeats"]
        if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 1:
            raise ManifestError(f"unit {unit_id!r} has invalid repeats {repeats!r}")
        if unit["expected_sample_count"] != unit["expected_task_count"] * repeats:
            raise ManifestError(
                f"unit {unit_id!r} expected_sample_count {unit['expected_sample_count']} != "
                f"expected_task_count {unit['expected_task_count']} * repeats {repeats}"
            )
        task_ids = unit["task_ids"]
        if not isinstance(task_ids, list) or len(task_ids) != unit["expected_task_count"]:
            raise ManifestError(
                f"unit {unit_id!r} task_ids length {len(task_ids) if isinstance(task_ids, list) else 'n/a'} "
                f"!= expected_task_count {unit['expected_task_count']}"
            )
        expected_hash = sha256_bytes(canonical_json_bytes(list(task_ids)))
        if unit["task_ids_sha256"] != expected_hash:
            raise ManifestError(f"unit {unit_id!r} task_ids_sha256 does not match task_ids")

        runs = unit["runs"]
        if not isinstance(runs, list) or not runs:
            raise ManifestError(f"unit {unit_id!r} must contain at least one run")
        run_total = 0
        for run in runs:
            if not isinstance(run, dict):
                raise ManifestError(f"unit {unit_id!r} has a non-object run")
            run_missing = [name for name in _RUN_REQUIRED_FIELDS if name not in run]
            if run_missing:
                raise ManifestError(f"unit {unit_id!r} run is missing fields: {run_missing}")
            if run["status"] not in UNIT_STATUSES:
                raise ManifestError(f"run {run['run_id']!r} has invalid status {run['status']!r}")
            if not run["run_dir"] or not run["config_path"]:
                raise ManifestError(f"run {run['run_id']!r} has an empty run_dir/config_path")
            if not str(run["run_id"]).startswith(f"{unit_id}::"):
                raise ManifestError(f"run {run['run_id']!r} does not belong to unit {unit_id!r}")
            if run["stage"] not in ("search", "holdout"):
                raise ManifestError(f"run {run['run_id']!r} has invalid stage {run['stage']!r}")
            run_task_ids = run["task_ids"]
            if not isinstance(run_task_ids, list):
                raise ManifestError(f"run {run['run_id']!r} task_ids must be a list")
            if run["expected_sample_count"] != len(run_task_ids) * repeats:
                raise ManifestError(
                    f"run {run['run_id']!r} expected_sample_count {run['expected_sample_count']} != "
                    f"len(task_ids) {len(run_task_ids)} * repeats {repeats}"
                )
            run_total += run["expected_sample_count"]
        if run_total != unit["expected_sample_count"]:
            raise ManifestError(
                f"unit {unit_id!r} run sample total {run_total} != "
                f"unit expected_sample_count {unit['expected_sample_count']}"
            )


def write_manifest(path: Path | str, manifest: dict[str, Any]) -> None:
    validate_manifest(manifest)
    write_json_atomic(Path(path), manifest)


def write_manifest_atomic(path: Path | str, manifest: dict[str, Any]) -> None:
    manifest["updated_at"] = _utc_now()
    write_manifest(path, manifest)


def load_manifest(path: Path | str) -> dict[str, Any]:
    payload = read_json(Path(path))
    validate_manifest(payload)
    return payload


def update_unit_status(
    manifest: dict[str, Any],
    unit_id: str,
    status: str,
    *,
    run_id: str | None = None,
    result: Any = None,
    known_limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Mutate ``manifest`` in place, enforcing the status machine.

    ``complete`` is terminal: a completed unit/run may not be moved back to any
    other status.  Unknown statuses or unit/run ids raise.
    """

    if status not in UNIT_STATUSES:
        raise ManifestError(f"invalid status {status!r}; allowed: {UNIT_STATUSES}")
    units = manifest.get("units")
    if not isinstance(units, dict) or unit_id not in units:
        raise ManifestError(f"unknown unit {unit_id!r}")
    unit = units[unit_id]

    if unit.get("status") == "complete" and status != "complete":
        raise ManifestError(
            f"unit {unit_id!r} is complete; complete is terminal and cannot move to {status!r}"
        )

    if run_id is not None:
        runs = unit.get("runs") or []
        target = next((run for run in runs if run.get("run_id") == run_id), None)
        if target is None:
            raise ManifestError(f"unit {unit_id!r} has no run {run_id!r}")
        if target.get("status") == "complete" and status != "complete":
            raise ManifestError(
                f"run {run_id!r} is complete; complete is terminal and cannot move to {status!r}"
            )
        target["status"] = status
        if result is not None:
            target["result"] = result

    unit["status"] = status
    if known_limitations is not None:
        unit["known_limitations"] = list(known_limitations)
    return manifest


__all__ = [
    "RUN_MANIFEST_SCHEMA_VERSION",
    "UNIT_STATUSES",
    "ManifestError",
    "build_manifest",
    "validate_manifest",
    "write_manifest",
    "write_manifest_atomic",
    "load_manifest",
    "update_unit_status",
]
