"""Orchestration for ``coco-attack clean-generations`` (task 03).

First version accepts final generation rows with ``task_id``, ``repeat_id``,
``status`` and ``generation`` fields. Attempt ledgers with multiple rows per
``(task_id, repeat_id)`` are rejected: they are not multiple repeats.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.issues import SEVERITY_ERROR, Issue
from ..data.contracts import DataContractError, PreparedCombination
from .cleaning import CLEANER_VERSION, clean_output

CLEAN_SCHEMA_VERSION = "1"


def clean_generations(
    prepared: PreparedCombination,
    input_jsonl: Path,
    output_dir: Path,
    legacy_alias: str | None = None,
) -> int:
    if not input_jsonl.is_file():
        _fail("cleaning.input_missing", f"input generations file not found: {input_jsonl}")

    spec_combination_id = prepared.combination_id
    spec_oracle_id = prepared.oracle_id
    tasks = prepared.task_by_id()
    expected_cwe = {
        value
        for value in (legacy_alias, spec_combination_id)
        if value is not None
    }
    seen: set[tuple[str, int]] = set()
    results: list[dict[str, Any]] = []
    issues: list[Issue] = []

    with open(input_jsonl, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                _fail(
                    "cleaning.invalid_json",
                    f"{input_jsonl}:{lineno}: invalid JSON: {error}",
                )
            if not isinstance(row, dict):
                _fail("cleaning.not_object", f"{input_jsonl}:{lineno}: not a JSON object")

            task_id = row.get("task_id")
            repeat_id = row.get("repeat_id")
            status = row.get("status")
            if not isinstance(task_id, str):
                _fail("cleaning.task_id_missing", f"{input_jsonl}:{lineno}: task_id required")
            if not isinstance(repeat_id, int) or isinstance(repeat_id, bool):
                _fail("cleaning.repeat_id_missing", f"{input_jsonl}:{lineno}: repeat_id required")
            if status is None:
                _fail("cleaning.status_missing", f"{input_jsonl}:{lineno}: status required")
            row_cwe = row.get("cwe")
            if row_cwe is not None and isinstance(row_cwe, str):
                if row_cwe.lower() not in {value.lower() for value in expected_cwe}:
                    _fail(
                        "cleaning.cwe_mismatch",
                        f"{input_jsonl}:{lineno}: cwe {row_cwe!r} not in {sorted(expected_cwe)}",
                    )
            task = tasks.get(task_id)
            if task is None:
                _fail(
                    "cleaning.unknown_task",
                    f"{input_jsonl}:{lineno}: task {task_id!r} is not in the evaluation set",
                )
            key = (task_id, repeat_id)
            if key in seen:
                _fail(
                    "cleaning.duplicate_sample",
                    f"{input_jsonl}:{lineno}: duplicate (task_id, repeat_id) {key}",
                )
            seen.add(key)

            try:
                cleaned = clean_output(row.get("generation"), task, status)
            except ValueError as error:
                _fail("cleaning.input_contract", f"{input_jsonl}:{lineno}: {error}")

            results.append(
                {
                    "combination_id": spec_combination_id,
                    "oracle_id": spec_oracle_id,
                    "task_id": task_id,
                    "repeat_id": repeat_id,
                    "source": {
                        "path": input_jsonl.name,
                        "line": lineno,
                        "line_sha256": sha256_bytes(raw),
                    },
                    "cleaned": cleaned.to_json(),
                }
            )

    if not results:
        _fail("cleaning.empty_input", "no generation records found")

    output_dir.mkdir(parents=True, exist_ok=True)
    cleaned_path = output_dir / "cleaned_generations.jsonl"
    lines = [
        json.dumps(record, ensure_ascii=False, sort_keys=True) for record in results
    ]
    write_bytes_atomic(cleaned_path, ("\n".join(lines) + "\n").encode("utf-8"))

    status_counts: dict[str, int] = {}
    path_counts: dict[str, int] = {}
    completed = 0
    for record in results:
        cleaned = record["cleaned"]
        status_counts[cleaned["generation_status"]] = (
            status_counts.get(cleaned["generation_status"], 0) + 1
        )
        path_counts[cleaned["extraction_path"]] = (
            path_counts.get(cleaned["extraction_path"], 0) + 1
        )
        completed += int(bool(cleaned["completed"]))

    manifest = {
        "schema_version": CLEAN_SCHEMA_VERSION,
        "completed": True,
        "combination_id": spec_combination_id,
        "oracle_id": spec_oracle_id,
        "cleaner_version": CLEANER_VERSION,
        "input": {
            "name": input_jsonl.name,
            "sha256": sha256_file(input_jsonl),
            "record_count": len(results),
        },
        "output": {
            "name": cleaned_path.name,
            "sha256": sha256_file(cleaned_path),
        },
        "generation_status_counts": dict(sorted(status_counts.items())),
        "extraction_path_counts": dict(sorted(path_counts.items())),
        "completed_count": completed,
    }
    report_text = _render_report(spec_combination_id, spec_oracle_id, manifest)
    write_json_atomic(output_dir / "manifest.json", manifest)
    write_text_atomic(output_dir / "REPORT.md", report_text)
    return 0


def _render_report(
    combination_id: str, oracle_id: str, manifest: dict[str, Any]
) -> str:
    lines = [
        "# Generation cleaning report",
        "",
        f"- Combination: `{combination_id}` (oracle `{oracle_id}`)",
        f"- Cleaner version: `{CLEANER_VERSION}`",
        f"- Input records: {manifest['input']['record_count']}",
        f"- Completed (entry defined): {manifest['completed_count']}",
        "",
        "## Generation status",
        "",
    ]
    for status, count in manifest["generation_status_counts"].items():
        lines.append(f"- `{status}`: {count}")
    lines.append("")
    lines.append("## Extraction paths")
    lines.append("")
    for path, count in manifest["extraction_path_counts"].items():
        lines.append(f"- `{path}`: {count}")
    lines.append("")
    lines.append(
        "Cleaning never returns an oracle verdict; generation failures keep empty "
        "code and remain in the denominator."
    )
    lines.append("")
    return "\n".join(lines)


def _fail(code: str, detail: str):
    raise DataContractError(
        detail,
        [Issue(code=code, severity=SEVERITY_ERROR, scope="cleaning", detail=detail)],
    )
