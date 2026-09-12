"""Strict standard-task loader (``load_tasks``).

The loader is the only path that turns routed JSONL into ``TaskRecord``
objects. It never repairs a record: every schema, type, required-field,
identity, side or experiment-type problem becomes an error and the
combination is not published.

Effective screening metadata follows the combination registry (task 01 user
ruling); raw values are retained as provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..assets.artifacts import canonical_json_bytes, sha256_bytes, sha256_file
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.metadata import normalize_task_metadata
from ..assets.paths import resolve_within
from ..assets.schema import (
    BOOLEAN_FIELDS,
    REFERENCE_SIDES,
    REQUIRED_NONEMPTY,
    STANDARD_SCHEMA,
    STANDARD_SCHEMA_NAME,
)
from .contracts import (
    CombinationSpec,
    DataContractError,
    LoadedTasks,
    TaskRecord,
    TaskSource,
)

MAX_REPORTED_RECORD_ERRORS = 50


def load_tasks(
    spec: CombinationSpec,
    assets_root: Path,
    taxonomy: set[str],
) -> LoadedTasks:
    path = resolve_within(assets_root, spec.task_file)
    if not path.is_file():
        raise DataContractError(
            f"standard task file not found: {spec.task_file}",
            [
                Issue(
                    code="tasks.missing",
                    severity=SEVERITY_ERROR,
                    scope="tasks",
                    detail=f"standard task file not found at {spec.task_file}",
                    asset=spec.task_file,
                    location={"combination_id": spec.combination_id},
                )
            ],
        )

    file_sha256 = sha256_file(path)
    issues: list[Issue] = []
    warnings: list[Issue] = []
    records: list[TaskRecord] = []
    seen: set[str] = set()
    reported = 0

    def report(issue: Issue) -> None:
        nonlocal reported
        if reported < MAX_REPORTED_RECORD_ERRORS:
            issues.append(issue)
            reported += 1

    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            location = {"line": lineno, "combination_id": spec.combination_id}
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                report(
                    Issue(
                        code="tasks.invalid_json",
                        severity=SEVERITY_ERROR,
                        scope="tasks",
                        detail=f"invalid JSON record: {error}",
                        asset=spec.task_file,
                        location=location,
                    )
                )
                continue
            if not isinstance(obj, dict):
                report(
                    Issue(
                        code="tasks.not_object",
                        severity=SEVERITY_ERROR,
                        scope="tasks",
                        detail=f"record is not a JSON object (got {type(obj).__name__})",
                        asset=spec.task_file,
                        location=location,
                    )
                )
                continue

            record_errors = _validate_record(obj, spec, taxonomy, location, report)
            if record_errors:
                continue

            task_id = obj["task_id"]
            if task_id in seen:
                report(
                    Issue(
                        code="tasks.duplicate_id",
                        severity=SEVERITY_ERROR,
                        scope="tasks",
                        detail=f"duplicate task_id {task_id!r} inside combination",
                        asset=spec.task_file,
                        location=location,
                    )
                )
                continue
            seen.add(task_id)

            effective, provenance = normalize_task_metadata(obj, spec.registry_definition)
            if provenance:
                warnings.append(
                    Issue(
                        code="tasks.metadata_normalized_from_registry",
                        severity="warning",
                        scope="tasks",
                        detail=(
                            "effective metadata follows the registry definition; raw "
                            f"values retained as provenance: {provenance}"
                        ),
                        asset=spec.task_file,
                        location=location,
                    )
                )
            source = TaskSource(
                combination_id=spec.combination_id,
                source_path=spec.task_file,
                source_file_sha256=file_sha256,
                line_number=lineno,
                schema=STANDARD_SCHEMA_NAME,
                record_sha256=sha256_bytes(canonical_json_bytes(obj)),
            )
            records.append(
                TaskRecord(
                    combination_id=spec.combination_id,
                    task_id=task_id,
                    raw=dict(obj),
                    effective=dict(effective),
                    metadata_provenance=provenance,
                    source=source,
                )
            )

    if issues:
        raise DataContractError(
            f"{spec.combination_id}: {len(issues)} task record error(s)",
            issues,
        )
    return LoadedTasks(
        spec=spec,
        records=tuple(records),
        file_sha256=file_sha256,
        issues=warnings,
    )


def _validate_record(
    obj: dict,
    spec: CombinationSpec,
    taxonomy: set[str],
    location: dict,
    report,
) -> list[str]:
    errors: list[str] = []
    keys = set(obj)
    missing = sorted(set(STANDARD_SCHEMA) - keys)
    extra = sorted(keys - set(STANDARD_SCHEMA))
    if missing:
        errors.append("missing_fields")
        report(
            Issue(
                code="tasks.missing_fields",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"record missing declared schema fields: {missing}",
                asset=spec.task_file,
                location=location,
            )
        )
    if extra:
        errors.append("extra_fields")
        report(
            Issue(
                code="tasks.extra_fields",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"record carries undeclared fields: {extra}",
                asset=spec.task_file,
                location=location,
            )
        )
    if missing or extra:
        return errors

    for field_name in REQUIRED_NONEMPTY:
        if not obj.get(field_name):
            errors.append("required_empty")
            report(
                Issue(
                    code="tasks.required_empty",
                    severity=SEVERITY_ERROR,
                    scope="tasks",
                    detail=f"required field {field_name!r} is empty",
                    asset=spec.task_file,
                    location=location,
                )
            )
    for field_name in BOOLEAN_FIELDS:
        if not isinstance(obj.get(field_name), bool):
            errors.append("type_violation")
            report(
                Issue(
                    code="tasks.type_violation",
                    severity=SEVERITY_ERROR,
                    scope="tasks",
                    detail=f"{field_name!r} must be a boolean",
                    asset=spec.task_file,
                    location=location,
                )
            )
    source_cwe_id = obj.get("source_cwe_id")
    if not (source_cwe_id is None or isinstance(source_cwe_id, str)):
        errors.append("type_violation")
        report(
            Issue(
                code="tasks.type_violation",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail="source_cwe_id must be a string or null",
                asset=spec.task_file,
                location=location,
            )
        )
    for field_name in STANDARD_SCHEMA:
        if field_name in BOOLEAN_FIELDS or field_name == "source_cwe_id":
            continue
        if not isinstance(obj.get(field_name), str):
            errors.append("type_violation")
            report(
                Issue(
                    code="tasks.type_violation",
                    severity=SEVERITY_ERROR,
                    scope="tasks",
                    detail=f"{field_name!r} must be a string",
                    asset=spec.task_file,
                    location=location,
                )
            )
    if not isinstance(obj.get("task_id"), str):
        errors.append("non_string_task_id")
        report(
            Issue(
                code="tasks.non_string_task_id",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail="task_id must be a string",
                asset=spec.task_file,
                location=location,
            )
        )
    if obj.get("reference_side") not in REFERENCE_SIDES:
        errors.append("bad_reference_side")
        report(
            Issue(
                code="tasks.bad_reference_side",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"unexpected reference_side {obj.get('reference_side')!r}",
                asset=spec.task_file,
                location=location,
            )
        )
    if obj.get("experiment_type") not in taxonomy:
        errors.append("unknown_experiment_type")
        report(
            Issue(
                code="tasks.unknown_experiment_type",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=(
                    f"experiment_type {obj.get('experiment_type')!r} is outside the "
                    "registry taxonomy"
                ),
                asset=spec.task_file,
                location=location,
            )
        )
    return errors
