"""Reference calibration across all 9 combinations (task 05).

Each reference code is reconstructed as ``code_prompt + canonical_solution``
and judged by the reused static oracle. Two comparisons are reported
separately: current verdict vs the existing reference records, and current
verdict vs the screening ``reference_side`` label (with user-approved label
boundaries read from the reference record, never hard-coded).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    read_json,
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.audit import load_combinations_config
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.paths import resolve_within
from ..data.combination import load_combination_specs
from ..data.contracts import DataContractError
from ..data.snapshot import load_prepared_data
from .static import evaluate_static_sample, load_oracle_module, oracle_fingerprint

CALIBRATION_SCHEMA_VERSION = "1"
STATIC_APPROVED_BOUNDARY = "approved_label_boundary"
STATUS_CONSISTENT = "consistent"
STATUS_NEW_DIFFERENCE = "new_difference"
STATUS_MISSING_REFERENCE = "missing_reference"
STATUS_UNEXPECTED = "unexpected"


class CalibrationInputError(DataContractError):
    pass


def calibrate_references(
    assets_root: Path,
    data_dir: Path,
    config_path: Path,
    output_dir: Path,
) -> int:
    config = read_json(config_path)
    combos = list(config.get("combinations") or ["all"])
    app_config, _ = load_combinations_config()
    oracle_results_dir = app_config["oracle_results_dir"]

    specs, _config_path, _taxonomy = load_combination_specs(assets_root)
    requested = sorted(specs) if combos == ["all"] else combos
    unknown = sorted(set(requested) - set(specs))
    if unknown:
        _fail("config.unknown_combination", f"unknown combinations: {unknown}")

    output_dir.mkdir(parents=True, exist_ok=True)
    all_records: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    differences: list[dict[str, Any]] = []

    for combination_id in requested:
        spec = specs[combination_id]
        prepared = load_prepared_data(data_dir, combination_id)
        module = load_oracle_module(assets_root, spec.oracle_id)
        fingerprint = oracle_fingerprint(assets_root, spec.oracle_id)

        reference_rel = f"{oracle_results_dir}/{spec.registry_id}_reference.json"
        reference_path = resolve_within(assets_root, reference_rel)
        if not reference_path.is_file():
            _fail("reference.missing", f"reference record not found: {reference_rel}")
        reference = read_json(reference_path)
        rows_by_id = {
            row.get("task_id"): row for row in (reference.get("rows") or [])
        }

        combo_dir = output_dir / combination_id
        combo_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict[str, Any]] = []
        counts = {
            "total": 0,
            "clean": 0,
            "target": 0,
            "current_target_present": 0,
            "current_target_absent": 0,
            "current_parse_error": 0,
            "reference_target_present": 0,
            "reference_target_absent": 0,
            "reference_parse_error": 0,
            "label_agreements": 0,
            "approved_boundaries": 0,
            "new_differences": 0,
            "missing_references": 0,
        }
        for record in prepared.records:
            task_id = record.task_id
            reference_row = rows_by_id.get(task_id)
            if reference_row is None:
                counts["missing_references"] += 1
                status = STATUS_MISSING_REFERENCE
                reference_verdict = None
                reference_target = None
                expected_target = None
                approved = False
            else:
                reference_verdict = reference_row.get("verdict")
                reference_target = reference_row.get("target_present")
                expected_target = reference_row.get("expected_target")
                approved = reference_row.get("agrees_with_label") is False
                if reference_verdict == "target_present":
                    counts["reference_target_present"] += 1
                elif reference_verdict == "target_absent":
                    counts["reference_target_absent"] += 1
                elif reference_verdict == "parse_error":
                    counts["reference_parse_error"] += 1

            reference_code = record.effective["code_prompt"] + record.effective["canonical_solution"]
            current = evaluate_static_sample(reference_code, spec.oracle_id, module)
            current_target = current["target_present"]
            if current["verdict"] == "target_present":
                counts["current_target_present"] += 1
            elif current["verdict"] == "target_absent":
                counts["current_target_absent"] += 1
            else:
                counts["current_parse_error"] += 1

            side = record.effective.get("reference_side")
            counts["total"] += 1
            if side == "clean":
                counts["clean"] += 1
            elif side == "target":
                counts["target"] += 1

            agrees_with_reference = (
                reference_target is None or current_target == reference_target
            )
            if reference_row is None:
                agrees_with_label = None
            elif expected_target is None:
                agrees_with_label = True
            else:
                agrees_with_label = current_target == expected_target
            if reference_row is not None and agrees_with_label:
                counts["label_agreements"] += 1
            if approved and not agrees_with_label:
                counts["approved_boundaries"] += 1

            if reference_row is None:
                status = STATUS_MISSING_REFERENCE
            elif approved and not agrees_with_label:
                status = STATIC_APPROVED_BOUNDARY
            elif current["verdict"] == "parse_error" or not agrees_with_reference or not agrees_with_label:
                status = STATUS_NEW_DIFFERENCE
                counts["new_differences"] += 1
            else:
                status = STATUS_CONSISTENT

            record_row = {
                "combination_id": combination_id,
                "oracle_id": spec.oracle_id,
                "task_id": task_id,
                "reference_side": side,
                "reference_code_sha256": sha256_bytes(reference_code.encode("utf-8")),
                "code_prompt_sha256": sha256_bytes(record.effective["code_prompt"].encode("utf-8")),
                "canonical_solution_sha256": sha256_bytes(record.effective["canonical_solution"].encode("utf-8")),
                "reference_verdict": reference_verdict,
                "reference_target_present": reference_target,
                "expected_target": expected_target,
                "current_verdict": current["verdict"],
                "current_target_present": current_target,
                "current_oracle_id": current.get("oracle_id"),
                "agrees_with_reference": agrees_with_reference,
                "agrees_with_label": agrees_with_label,
                "approved_boundary": approved,
                "status": status,
            }
            records.append(record_row)
            if status == STATUS_NEW_DIFFERENCE:
                differences.append(
                    {
                        "category": "reference_calibration",
                        "combination_id": combination_id,
                        "task_id": task_id,
                        "reference_side": side,
                        "reference_verdict": reference_verdict,
                        "expected_target": expected_target,
                        "current_verdict": current["verdict"],
                        "evidence": f"{reference_rel}",
                    }
                )

        lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in records]
        comparisons_path = combo_dir / "reference_comparisons.jsonl"
        write_bytes_atomic(comparisons_path, ("\n".join(lines) + "\n").encode("utf-8"))
        all_records.extend(records)
        label_denominator = counts["total"] - counts["missing_references"]
        combo_summary = {
            **counts,
            "label_agreement_rate": (
                counts["label_agreements"] / label_denominator if label_denominator else None
            ),
            "oracle_fingerprint": fingerprint,
            "reference_file": reference_rel,
            "reference_file_sha256": sha256_file(reference_path),
            "comparisons_sha256": sha256_file(comparisons_path),
            "approved_boundary_task_ids": sorted(
                row["task_id"] for row in records if row["approved_boundary"]
            ),
        }
        summary[combination_id] = combo_summary
        write_json_atomic(combo_dir / "summary.json", combo_summary)

    write_json_atomic(output_dir / "summary.json", summary)
    write_json_atomic(
        output_dir / "differences.json",
        {"schema_version": CALIBRATION_SCHEMA_VERSION, "differences": differences},
    )
    manifest = {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "completion": "complete",
        "acceptance_status": "pending_review" if differences else "no_new_differences",
        "combinations": requested,
        "record_count": len(all_records),
        "new_difference_count": len(differences),
        "summary_sha256": sha256_file(output_dir / "summary.json"),
    }
    write_json_atomic(output_dir / "manifest.json", manifest)
    write_text_atomic(
        output_dir / "REPORT.md",
        render_calibration_report(requested, summary, differences),
    )
    return 1 if differences else 0


def render_calibration_report(
    combinations: list[str],
    summary: dict[str, Any],
    differences: list[dict[str, Any]],
) -> str:
    lines = ["# Reference calibration report", ""]
    lines.append(
        "Each reference code is `code_prompt + canonical_solution`, judged by the "
        "reused static oracle. `reference_side` is a screening label, not an ASR truth."
    )
    lines.append("")
    lines.append("| Combination | Total | clean | target | current T/A/P | label agreement | approved boundaries | new differences |")
    lines.append("|---|---:|---:|---:|---|---:|---:|---:|")
    for combination_id in combinations:
        entry = summary[combination_id]
        rate = entry["label_agreement_rate"]
        rate_text = "n/a" if rate is None else f"{entry['label_agreements']}/{entry['total']} = {rate:.4f}"
        current = (
            f"{entry['current_target_present']}/{entry['current_target_absent']}/"
            f"{entry['current_parse_error']}"
        )
        lines.append(
            f"| {combination_id} | {entry['total']} | {entry['clean']} | {entry['target']} | "
            f"{current} | {rate_text} | {entry['approved_boundaries']} | {entry['new_differences']} |"
        )
    lines.append("")
    if differences:
        lines.append("## New differences (pending review)")
        lines.append("")
        for difference in differences:
            lines.append(
                f"- `{difference['combination_id']}` `{difference['task_id']}` "
                f"({difference['reference_side']}): reference={difference['reference_verdict']!r} "
                f"expected={difference['expected_target']!r} current={difference['current_verdict']!r}"
            )
        lines.append("")
    lines.append(
        "Approved label boundaries are read from the reference records and are not "
        "removed from the denominator. New parse_error or target-side misses are "
        "never waived."
    )
    lines.append("")
    return "\n".join(lines)


def _fail(code: str, detail: str):
    raise CalibrationInputError(
        detail,
        [Issue(code=code, severity=SEVERITY_ERROR, scope="calibration", detail=detail)],
    )
