"""Historical run comparison (task 05).

Recomputes cleaning and static verdicts for a fixed list of historical clean /
attack-diagnostic runs and compares them with the historical boolean hit,
sample identity and aggregation. Historical records only carry a boolean hit
plus evidence, so the historical three-state verdict column is always null and
never invented.
"""

from __future__ import annotations

import ast
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
from ..data.contracts import DataContractError
from ..data.snapshot import load_prepared_data
from .cleaning import clean_output
from .metrics import asr_at_k
from .static import evaluate_static_sample, load_oracle_module

HISTORY_SCHEMA_VERSION = "1"


class HistoryInputError(DataContractError):
    pass


def compare_history(
    assets_root: Path,
    data_dir: Path,
    config_path: Path,
    output_dir: Path,
) -> int:
    config = read_json(config_path)
    runs = list(config.get("runs") or [])
    if not runs:
        _fail("config.no_runs", "history comparison config lists no runs")
    app_config, _ = load_combinations_config()
    history_runs_dir = app_config["history_runs_dir"]

    output_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {}
    differences: list[dict[str, Any]] = []
    cosmetic_differences: list[dict[str, Any]] = []

    for run_spec in runs:
        run_id = run_spec.get("run_id")
        combination_id = run_spec.get("combination_id")
        if not run_id or not combination_id:
            _fail("config.run_invalid", f"run entry missing run_id/combination_id: {run_spec!r}")
        prepared = load_prepared_data(data_dir, combination_id)
        if run_spec.get("oracle_id") and run_spec["oracle_id"] != prepared.oracle_id:
            _fail(
                "config.oracle_mismatch",
                f"{run_id}: config oracle {run_spec['oracle_id']!r} != prepared {prepared.oracle_id!r}",
            )
        module = load_oracle_module(assets_root, prepared.oracle_id)

        run_dir = resolve_within(assets_root, f"{history_runs_dir}/{run_id}")
        if not run_dir.is_dir():
            _fail("history.run_missing", f"historical run not found: {run_dir}")
        run_config_path = run_dir / "inputs/run_config.json"
        run_config = read_json(run_config_path) if run_config_path.is_file() else {}
        generations = _read_jsonl(run_dir / "outputs/generations.jsonl")
        records = _read_jsonl(run_dir / "eval/records.jsonl")
        summary_path = run_dir / "eval/summary.json"
        historical_summary = read_json(summary_path) if summary_path.is_file() else {}

        run_diffs: list[dict[str, Any]] = []
        _check_run_config(run_spec, run_config, combination_id, run_id, run_diffs)

        repeats = int(run_config.get("repeats") or run_spec.get("repeats") or 0)
        if repeats < 1:
            _fail("history.repeats_unknown", f"{run_id}: cannot determine repeats")
        model = run_config.get("model") or run_spec.get("model")
        temperature = run_config.get("temperature", run_spec.get("temperature"))
        task_ids = list(prepared.selection.evaluation_ids)
        tasks = prepared.task_by_id()

        gen_map = _index(generations)
        rec_map = _index(records)
        rows: list[dict[str, Any]] = []
        new_bool_records: list[dict[str, Any]] = []
        hist_bool_records: list[dict[str, Any]] = []
        counts = {
            "expected_samples": len(task_ids) * repeats,
            "generation_rows": len(generations),
            "record_rows": len(records),
            "missing_generation": 0,
            "missing_record": 0,
            "bool_comparisons": 0,
            "bool_mismatches": 0,
            "code_comparisons": 0,
            "code_mismatches": 0,
            "code_cosmetic_differences": 0,
            "missing_history_code": 0,
        }
        for task_id in task_ids:
            task = tasks[task_id]
            for repeat_id in range(repeats):
                key = (task_id, repeat_id)
                gen_row = gen_map.get(key)
                rec_row = rec_map.get(key)
                if gen_row is None:
                    counts["missing_generation"] += 1
                if rec_row is None:
                    counts["missing_record"] += 1
                history_asr_hit = None if rec_row is None else rec_row.get("asr_hit")
                history_evidence = None if rec_row is None else rec_row.get("asr_evidence")
                history_code = None if rec_row is None else rec_row.get("evaluation_code")

                new_verdict = None
                new_final_code = None
                new_code = None
                new_extraction_path = None
                new_completed = None
                if gen_row is not None:
                    status = gen_row.get("status")
                    cleaned = clean_output(gen_row.get("generation"), task, status)
                    new_verdict = _verdict_for(cleaned, module, prepared.oracle_id)
                    new_final_code = cleaned.final_code
                    new_code = cleaned.code
                    new_extraction_path = cleaned.extraction_path
                    new_completed = cleaned.completed
                if history_code is None and rec_row is not None:
                    counts["missing_history_code"] += 1

                bool_match = (
                    None
                    if history_asr_hit is None or new_verdict is None
                    else bool(history_asr_hit) == (new_verdict == "target_present")
                )
                if bool_match is not None:
                    counts["bool_comparisons"] += 1
                    if not bool_match:
                        counts["bool_mismatches"] += 1
                        run_diffs.append(
                            {
                                "category": "boolean_mismatch",
                                "combination_id": combination_id,
                                "run_id": run_id,
                                "task_id": task_id,
                                "repeat_id": repeat_id,
                                "history_asr_hit": bool(history_asr_hit),
                                "new_verdict": new_verdict,
                                "evidence": f"{history_runs_dir}/{run_id}/eval/records.jsonl",
                            }
                        )
                code_match = None
                code_ast_equivalent = None
                if history_code is not None and new_final_code is not None:
                    counts["code_comparisons"] += 1
                    code_match = history_code == new_final_code
                    if not code_match:
                        code_ast_equivalent = _ast_equivalent(history_code, new_final_code)
                        record = {
                            "category": "code_cosmetic_difference" if code_ast_equivalent else "code_mismatch",
                            "combination_id": combination_id,
                            "run_id": run_id,
                            "task_id": task_id,
                            "repeat_id": repeat_id,
                            "ast_equivalent": code_ast_equivalent,
                            "history_code_sha256": sha256_bytes(history_code.encode("utf-8")),
                            "new_final_code_sha256": sha256_bytes(new_final_code.encode("utf-8")),
                        }
                        if code_ast_equivalent:
                            counts["code_cosmetic_differences"] += 1
                            cosmetic_differences.append(record)
                        else:
                            counts["code_mismatches"] += 1
                            run_diffs.append(record)

                rows.append(
                    {
                        "run_id": run_id,
                        "combination_id": combination_id,
                        "task_id": task_id,
                        "repeat_id": repeat_id,
                        "in_generations": gen_row is not None,
                        "in_records": rec_row is not None,
                        "generation_status": None if gen_row is None else gen_row.get("status"),
                        "history_asr_hit": history_asr_hit,
                        "history_evidence_reason": (
                            history_evidence.get("reason")
                            if isinstance(history_evidence, dict)
                            else None
                        ),
                        "history_code_present": history_code is not None,
                        "new_extraction_path": new_extraction_path,
                        "new_completed": new_completed,
                        "new_verdict": new_verdict,
                        "new_asr_hit": None if new_verdict is None else new_verdict == "target_present",
                        "history_verdict": None,
                        "history_verdict_note": "not recorded in historical run",
                        "bool_match": bool_match,
                        "code_match": code_match,
                        "code_ast_equivalent": code_ast_equivalent,
                    }
                )
                if new_verdict is not None:
                    new_bool_records.append(
                        {"task_id": task_id, "repeat_id": repeat_id, "asr_hit": new_verdict == "target_present", "verdict": new_verdict}
                    )
                if history_asr_hit is not None:
                    hist_bool_records.append(
                        {"task_id": task_id, "repeat_id": repeat_id, "asr_hit": bool(history_asr_hit), "verdict": "target_present" if history_asr_hit else "target_absent"}
                    )

        sampling = {"model": model, "temperature": temperature, "repeats": repeats}
        asr1 = _compare_metric(hist_bool_records, new_bool_records, task_ids, 1, sampling)
        asr5 = _compare_metric(hist_bool_records, new_bool_records, task_ids, 5, sampling)
        slug = run_id.replace("/", "__")
        run_dir_out = output_dir / slug
        run_dir_out.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
        comparisons_path = run_dir_out / "history_comparisons.jsonl"
        write_bytes_atomic(comparisons_path, ("\n".join(lines) + "\n").encode("utf-8"))
        run_summary = {
            "run_id": run_id,
            "combination_id": combination_id,
            "purpose": run_spec.get("purpose"),
            "model": model,
            "temperature": temperature,
            "repeats": repeats,
            "counts": counts,
            "asr_comparison": {"asr@1": asr1, "asr@5": asr5},
            "historical_summary": historical_summary,
            "comparisons_sha256": sha256_file(comparisons_path),
            "run_config_sha256": sha256_file(run_config_path) if run_config_path.is_file() else None,
            "generations_sha256": sha256_file(run_dir / "outputs/generations.jsonl") if (run_dir / "outputs/generations.jsonl").is_file() else None,
            "records_sha256": sha256_file(run_dir / "eval/records.jsonl") if (run_dir / "eval/records.jsonl").is_file() else None,
        }
        summary[run_id] = run_summary
        write_json_atomic(run_dir_out / "summary.json", run_summary)
        differences.extend(run_diffs)

    write_json_atomic(output_dir / "summary.json", summary)
    write_json_atomic(
        output_dir / "differences.json",
        {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "differences": differences,
            "cosmetic_differences": cosmetic_differences,
        },
    )
    manifest = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "completion": "complete",
        "acceptance_status": "pending_review" if differences else "no_blocking_differences",
        "runs": [run.get("run_id") for run in runs],
        "record_count": sum(
            entry["counts"]["expected_samples"] for entry in summary.values()
        ),
        "difference_count": len(differences),
        "cosmetic_difference_count": len(cosmetic_differences),
        "summary_sha256": sha256_file(output_dir / "summary.json"),
    }
    write_json_atomic(output_dir / "manifest.json", manifest)
    write_text_atomic(
        output_dir / "REPORT.md",
        render_history_report(summary, differences, cosmetic_differences),
    )
    return 1 if differences else 0


def _verdict_for(cleaned, module, oracle_id: str) -> str:
    if cleaned.generation_status != "success":
        return "parse_error"
    if not cleaned.final_code.strip():
        return "parse_error"
    normalized = evaluate_static_sample(cleaned.final_code, oracle_id, module)
    return normalized["verdict"]


def _compare_metric(
    hist: list[dict[str, Any]],
    new: list[dict[str, Any]],
    task_ids: list[str],
    k: int,
    sampling: dict[str, Any],
) -> dict[str, Any]:
    if not hist:
        history_value: float | None = None
    else:
        result = asr_at_k(hist, task_ids, k, task_set="evaluation", sampling=sampling)
        history_value = result.value if result.defined else None
    if not new:
        new_value: float | None = None
    else:
        result = asr_at_k(new, task_ids, k, task_set="evaluation", sampling=sampling)
        new_value = result.value if result.defined else None
    return {
        "k": k,
        "history": history_value,
        "new": new_value,
        "match": (
            history_value is not None
            and new_value is not None
            and history_value == new_value
        ),
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "rb") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            rows.append(json.loads(raw.decode("utf-8")))
    return rows


def _index(rows: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        key = (row.get("task_id"), row.get("repeat_id"))
        indexed[key] = row
    return indexed


def _check_run_config(
    run_spec: dict[str, Any],
    run_config: dict[str, Any],
    combination_id: str,
    run_id: str,
    run_diffs: list[dict[str, Any]],
) -> None:
    for field_name in ("model", "temperature", "repeats"):
        declared = run_spec.get(field_name)
        actual = run_config.get(field_name)
        if declared is not None and actual is not None and declared != actual:
            run_diffs.append(
                {
                    "category": "history_config_conflict",
                    "combination_id": combination_id,
                    "run_id": run_id,
                    "field": field_name,
                    "config": declared,
                    "run_config": actual,
                }
            )


def _ast_equivalent(first: str, second: str) -> bool:
    try:
        return ast.dump(ast.parse(first)) == ast.dump(ast.parse(second))
    except SyntaxError:
        return False


def render_history_report(
    summary: dict[str, Any],
    differences: list[dict[str, Any]],
    cosmetic_differences: list[dict[str, Any]] | None = None,
) -> str:
    cosmetic_differences = cosmetic_differences or []
    lines = ["# Historical comparison report", ""]
    lines.append(
        "Recomputed cleaning and static verdicts are compared with historical "
        "boolean hits only. Historical three-state verdicts are not recorded and are "
        "shown as null. Code differences that are AST-equivalent (for example "
        "line-ending or boundary-whitespace canonicalization) are reported as "
        "cosmetic and are not blocking."
    )
    lines.append("")
    lines.append("| Run | Combination | Purpose | Model | t | r | Bool mismatches | Blocking code | Cosmetic code | ASR@1 hist/new | ASR@5 hist/new |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---|---|")
    for run_id, entry in summary.items():
        counts = entry["counts"]
        asr1 = entry["asr_comparison"]["asr@1"]
        asr5 = entry["asr_comparison"]["asr@5"]
        lines.append(
            f"| {run_id} | {entry['combination_id']} | {entry['purpose']} | {entry['model']} | "
            f"{entry['temperature']} | {entry['repeats']} | {counts['bool_mismatches']} | "
            f"{counts['code_mismatches']} | {counts['code_cosmetic_differences']} | "
            f"{asr1['history']}/{asr1['new']} | {asr5['history']}/{asr5['new']} |"
        )
    lines.append("")
    if differences:
        lines.append("## Blocking differences (pending review)")
        lines.append("")
        for difference in differences:
            lines.append(f"- `{difference['category']}` {json.dumps({k: v for k, v in difference.items() if k != 'category'}, ensure_ascii=False, sort_keys=True)}")
        lines.append("")
    if cosmetic_differences:
        lines.append("## Cosmetic code differences (AST-equivalent, informational)")
        lines.append("")
        for difference in cosmetic_differences:
            lines.append(f"- `{difference['task_id']}` repeat {difference['repeat_id']} in `{difference['run_id']}`")
        lines.append("")
    lines.append(
        "Aggregate equality can hide per-sample differences; the table therefore "
        "lists per-sample mismatch counts next to the ASR comparison."
    )
    lines.append("")
    return "\n".join(lines)


def _fail(code: str, detail: str):
    raise HistoryInputError(
        detail,
        [Issue(code=code, severity=SEVERITY_ERROR, scope="history", detail=detail)],
    )
