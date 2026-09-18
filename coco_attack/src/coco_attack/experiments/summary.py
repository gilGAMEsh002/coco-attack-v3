"""Baseline coverage checks, grouped reports and index export (phase 03, sub-task 03).

Read-only over the completed run artifacts.  This module builds the
``baseline-index-v1`` (see :mod:`.index`) and derives the grouped report plus the
AC-01..AC-04 check material.  It never re-runs an evaluator, calls a model or
writes cost.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json, write_json_atomic, write_text_atomic
from .baseline import EXIT_BLOCKING, EXIT_OK
from .index import (
    build_index,
    index_path,
    validate_index,
    write_index,
)

SUMMARY_SCHEMA_VERSION = "baseline-summary-v1"
COVERAGE_SCHEMA_VERSION = "baseline-coverage-v1"
REPORTS_DIRNAME = "reports"

# 01 §4.2 victim request baseline (the estimate, not a cost authorisation).
EXPECTED_VICTIM_REQUESTS = 1962

_METRIC_NAMES = (
    "asr@1", "asr@3", "asr@5",
    "pass@1", "pass@3", "pass@5",
    "sample_hit_rate",
    "bandit_evasion", "semgrep_evasion", "codeql_evasion",
    "llm_judge_rate",
)


class BaselineSummaryError(ValueError):
    pass


def _read_json_optional(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def _metric(entry: dict[str, Any], name: str) -> dict[str, Any] | None:
    value = (entry.get("metrics") or {}).get(name)
    return value if isinstance(value, dict) else None


def _metric_brief(entry: dict[str, Any], name: str) -> dict[str, Any]:
    metric = _metric(entry, name) or {}
    return {
        "name": name,
        "defined": bool(metric.get("defined")),
        "value": metric.get("value") if metric.get("defined") else None,
        "numerator": metric.get("numerator") if metric.get("defined") else None,
        "denominator": metric.get("denominator") if metric.get("defined") else None,
        "reason": metric.get("reason"),
    }


def _whole_set(index: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        entry
        for entry in index["entries"].values()
        if entry.get("split_mode") == "whole-set"
    ]


def _derived(index: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        entry for entry in index["entries"].values() if entry.get("derived_from")
    ]


# --------------------------------------------------------------------------- #
# AC-01/AC-02: coverage and denominators
# --------------------------------------------------------------------------- #


def _coverage(root: Path, index: dict[str, Any]) -> dict[str, Any]:
    units: list[dict[str, Any]] = []
    for entry in sorted(_whole_set(index), key=lambda item: str(item.get("unit_id"))):
        functional = entry.get("functional") or {}
        units.append(
            {
                "unit_id": entry.get("unit_id"),
                "entry_id": entry.get("entry_id"),
                "combination_id": entry.get("combination_id"),
                "form": entry.get("form"),
                "temperature": entry.get("temperature"),
                "repeats": entry.get("repeats"),
                "unit_status": entry.get("unit_status"),
                "status": entry.get("status"),
                "report_complete": entry.get("report_complete"),
                "expected_sample_count": entry.get("expected_sample_count"),
                "actual_sample_count": entry.get("actual_sample_count"),
                "missing_sample_ids": entry.get("missing_sample_ids") or [],
                "extra_sample_ids": entry.get("extra_sample_ids") or [],
                "functional_available": bool(functional.get("available")),
                "functional_reason": functional.get("reason"),
                "run_dir": entry.get("run_dir"),
                "config_path": entry.get("config_path"),
            }
        )
    incomplete = [
        unit for unit in units if unit["status"] != "complete"
    ]
    expected_total = sum(int(unit.get("expected_sample_count") or 0) for unit in units)
    actual_total = sum(int(unit.get("actual_sample_count") or 0) for unit in units)
    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "units_total": len(units),
        "units_complete": len(units) - len(incomplete),
        "incomplete_units": incomplete,
        "expected_sample_total": expected_total,
        "actual_sample_total": actual_total,
        "missing_sample_units": [u["unit_id"] for u in units if u["missing_sample_ids"]],
        "extra_sample_units": [u["unit_id"] for u in units if u["extra_sample_ids"]],
        "functional_metrics_undefined_units": [
            {
                "unit_id": u["unit_id"],
                "reason": u["functional_reason"],
            }
            for u in units
            if not u["functional_available"]
        ],
        "index_gaps": index.get("gaps") or [],
        "units": units,
    }


# --------------------------------------------------------------------------- #
# AC-02: metric applicability
# --------------------------------------------------------------------------- #


def _applicability(index: dict[str, Any]) -> dict[str, Any]:
    undefined_pass: list[dict[str, Any]] = []
    observed_metrics: list[dict[str, Any]] = []
    sast_states: dict[str, dict[str, Any]] = {}
    layer_states: dict[str, dict[str, Any]] = {}
    for entry in sorted(_whole_set(index), key=lambda item: str(item.get("unit_id"))):
        unit_id = entry.get("unit_id")
        for name in ("pass@3", "pass@5"):
            brief = _metric_brief(entry, name)
            if not brief["defined"]:
                undefined_pass.append(
                    {
                        "unit_id": unit_id,
                        "metric": name,
                        "reason": brief["reason"],
                    }
                )
        for name in ("bandit_evasion", "semgrep_evasion", "codeql_evasion", "llm_judge_rate"):
            brief = _metric_brief(entry, name)
            observed_metrics.append(
                {
                    "unit_id": unit_id,
                    "metric": name,
                    "defined": brief["defined"],
                    "value": brief["value"],
                    "reason": brief["reason"],
                    "basis": entry.get("basis"),
                    "sampled_run": entry.get("sampled_run"),
                }
            )
        for tool, state in (entry.get("sast_tool_states") or {}).items():
            sast_states.setdefault(str(entry.get("combination_id")), {})[tool] = state
        for layer, state in (entry.get("layer_states") or {}).items():
            layer_states.setdefault(layer, {}).setdefault(
                str(state.get("state")), 0
            )
            layer_states[layer][str(state.get("state"))] += 1
    return {
        "pass_k_undefined": undefined_pass,
        "observed_metrics": observed_metrics,
        "sast_tool_states": sast_states,
        "layer_states": layer_states,
        "notes": {
            "pass_k": "pass@k is undefined for any task with n<k (unbiased estimator).",
            "evasion_judge": "evasion/llm_judge_rate are observed proportions on this run's generated set.",
            "three_no_value_states": [
                "configured_disabled",
                "not_covered",
                "environment_unavailable",
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Grouped matrix view (whole-set cells + derived cwe078 views)
# --------------------------------------------------------------------------- #


def _matrix(index: dict[str, Any]) -> dict[str, Any]:
    cells: list[dict[str, Any]] = []
    for entry in sorted(
        _whole_set(index),
        key=lambda item: (
            str(item.get("combination_id")),
            str(item.get("form")),
            float(item.get("temperature") or 0.0),
            int(item.get("repeats") or 0),
        ),
    ):
        functional = entry.get("functional") or {}
        cell = {
            "entry_id": entry.get("entry_id"),
            "combination_id": entry.get("combination_id"),
            "form": entry.get("form"),
            "temperature": entry.get("temperature"),
            "repeats": entry.get("repeats"),
            "split_mode": "whole-set",
            "task_count": len(entry.get("task_set") or []),
            "unit_status": entry.get("unit_status"),
            "functional_available": bool(functional.get("available")),
            "functional_reason": functional.get("reason"),
        }
        for name in _METRIC_NAMES:
            cell[name] = _metric_brief(entry, name)
        cells.append(cell)

    derived_rows: list[dict[str, Any]] = []
    for entry in sorted(_derived(index), key=lambda item: str(item.get("entry_id"))):
        derived_rows.append(
            {
                "entry_id": entry.get("entry_id"),
                "combination_id": entry.get("combination_id"),
                "form": entry.get("form"),
                "temperature": entry.get("temperature"),
                "repeats": entry.get("repeats"),
                "split_mode": entry.get("split_mode"),
                "derived_from": entry.get("derived_from"),
                "task_count": len(entry.get("task_set") or []),
                "asr@1": _metric_brief(entry, "asr@1"),
                "pass@1": _metric_brief(entry, "pass@1"),
                "llm_judge_rate": _metric_brief(entry, "llm_judge_rate"),
            }
        )
    return {"whole_set_cells": cells, "derived_views": derived_rows}


# --------------------------------------------------------------------------- #
# Distributions / availability
# --------------------------------------------------------------------------- #


def _distributions(root: Path, index: dict[str, Any]) -> dict[str, Any]:
    verdicts: Counter[str] = Counter()
    functional_outcomes: Counter[str] = Counter()
    generation_status: Counter[str] = Counter()
    sast_tool_states: dict[str, dict[str, Any]] = {}
    layer_states: dict[str, dict[str, int]] = {}
    for entry in _whole_set(index):
        for verdict, count in (entry.get("static_verdict_counts") or {}).items():
            verdicts[str(verdict)] += int(count)
        run_dir = root / str(entry.get("run_dir"))
        functional_path = run_dir / "functional" / "functional_results.jsonl"
        if functional_path.is_file():
            for raw in functional_path.read_bytes().split(b"\n"):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw.decode("utf-8"))
                except ValueError:
                    continue
                functional_outcomes[str(row.get("outcome"))] += 1
        generation = _read_json_optional(run_dir / "generation" / "generation_summary.json")
        if isinstance(generation, dict):
            for status, count in (generation.get("status_counts") or {}).items():
                generation_status[str(status)] += int(count)
        for tool, state in (entry.get("sast_tool_states") or {}).items():
            sast_tool_states.setdefault(str(entry.get("combination_id")), {})[tool] = state
        for layer, state in (entry.get("layer_states") or {}).items():
            key = str(state.get("state"))
            layer_states.setdefault(layer, {})
            layer_states[layer][key] = layer_states[layer].get(key, 0) + 1
    return {
        "static_verdict_counts": dict(sorted(verdicts.items())),
        "functional_outcomes": dict(sorted(functional_outcomes.items())),
        "generation_status_counts": dict(sorted(generation_status.items())),
        "sast_tool_states": sast_tool_states,
        "layer_states": layer_states,
    }


# --------------------------------------------------------------------------- #
# Cost and versions
# --------------------------------------------------------------------------- #


def _cost(index: dict[str, Any]) -> dict[str, Any]:
    roles: dict[str, dict[str, Any]] = {}
    cache_hits = 0
    for entry in _whole_set(index):
        for role, value in ((entry.get("cost") or {}).get("roles") or {}).items():
            bucket = roles.setdefault(
                str(role),
                {"events": 0, "known": 0.0, "unknown": 0, "usage": Counter()},
            )
            bucket["events"] += int(value.get("events") or 0)
            cost = value.get("cost") or {}
            bucket["known"] += float(cost.get("known") or 0.0)
            if cost.get("known") is None:
                bucket["known"] += 0.0
            bucket["unknown"] += int(cost.get("unknown") or 0)
            for key, amount in (value.get("usage") or {}).items():
                if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                    bucket["usage"][str(key)] += amount
        cache_hits += int((entry.get("functional") or {}).get("cache_hits") or 0)
    victim_events = int((roles.get("victim") or {}).get("events") or 0)
    for bucket in roles.values():
        bucket["usage"] = dict(sorted(bucket["usage"].items()))
    return {
        "roles": roles,
        "functional_cache_hits": cache_hits,
        "victim_requests": victim_events,
        "expected_victim_requests": EXPECTED_VICTIM_REQUESTS,
        "victim_request_difference": victim_events - EXPECTED_VICTIM_REQUESTS,
        "note": "known cost only when a pricing rule was configured; unknown windows are counted, never zero-filled",
    }


def _versions(index: dict[str, Any]) -> dict[str, Any]:
    return index.get("version_fingerprint") or {}


# --------------------------------------------------------------------------- #
# AC-04: anomaly and declaration checks
# --------------------------------------------------------------------------- #


def _anomalies(index: dict[str, Any], distributions: dict[str, Any]) -> dict[str, Any]:
    parse_errors = [
        entry.get("unit_id")
        for entry in _whole_set(index)
        if int((entry.get("static_verdict_counts") or {}).get("parse_error") or 0) > 0
    ]
    generation_failures = {
        key: value
        for key, value in (distributions.get("generation_status_counts") or {}).items()
        if key != "success" and value
    }
    top_natural = sorted(
        (
            {
                "unit_id": entry.get("unit_id"),
                "combination_id": entry.get("combination_id"),
                "form": entry.get("form"),
                "temperature": entry.get("temperature"),
                "repeats": entry.get("repeats"),
                "asr@1": _metric_brief(entry, "asr@1"),
            }
            for entry in _whole_set(index)
        ),
        key=lambda row: (row["asr@1"].get("value") or -1.0),
        reverse=True,
    )[:5]
    return {
        "parse_error_units": parse_errors,
        "generation_status_non_success": generation_failures,
        "top_natural_hit_rate_units": top_natural,
        "human_review_note": "top natural-hit-rate units are listed for review, not judged automatically",
        "judge_non_target_cwe": "diagnostic labels live in evaluation/layers/judge.jsonl; not aggregated here",
        "dynamic_realism": "configured_disabled for this baseline; not counted as evasion or not_covered",
    }


def _declarations(index: dict[str, Any]) -> dict[str, Any]:
    derived = _derived(index)
    whole = _whole_set(index)
    linked = all(
        entry.get("derived_from") in index["entries"] for entry in derived
    )
    return {
        "whole_set_entries": len(whole),
        "derived_view_entries": len(derived),
        "derived_views_link_to_whole_set": linked,
        "whole_set_results_not_labelled_holdout": all(
            entry.get("split_mode") == "whole-set" for entry in whole
        ),
        "no_best_form_selection": "index queries use strict口径 matching; no automatic best-form selection",
        "holdout_usage": "derived cwe078 search/holdout views are post-hoc slices of one whole-set run; template selection must not use them",
    }


# --------------------------------------------------------------------------- #
# Assembly / writers
# --------------------------------------------------------------------------- #


def build_summary(baseline_root: Path | str, index: dict[str, Any] | None = None) -> dict[str, Any]:
    root = Path(baseline_root).expanduser().resolve()
    if index is None:
        index = build_index(root)
    validate_index(index)
    coverage = _coverage(root, index)
    distributions = _distributions(root, index)
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "baseline_root": str(root),
        "index_schema_version": index.get("schema_version"),
        "coverage": coverage,
        "applicability": _applicability(index),
        "matrix": _matrix(index),
        "distributions": distributions,
        "cost": _cost(index),
        "versions": _versions(index),
        "anomalies": _anomalies(index, distributions),
        "declarations": _declarations(index),
        "gaps": index.get("gaps") or [],
    }


def _render_markdown(summary: dict[str, Any]) -> str:
    coverage = summary["coverage"]
    lines: list[str] = []
    lines.append("# Clean baseline report")
    lines.append("")
    lines.append(f"- baseline root: `{summary['baseline_root']}`")
    lines.append(
        f"- units complete: {coverage['units_complete']}/{coverage['units_total']}; "
        f"samples: {coverage['actual_sample_total']}/{coverage['expected_sample_total']}"
    )
    cost = summary["cost"]
    lines.append(
        f"- victim requests: {cost['victim_requests']} "
        f"(baseline {cost['expected_victim_requests']}, diff {cost['victim_request_difference']})"
    )
    lines.append("")
    lines.append("## Whole-set matrix")
    lines.append("")
    lines.append(
        "| combination | form | temp | repeats | ASR@1 | ASR@5 | pass@1 | pass@3 | pass@5 | llm_judge_rate | functional |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")

    def fmt(brief: dict[str, Any]) -> str:
        if brief.get("defined"):
            value = brief.get("value")
            if isinstance(value, float):
                value = round(value, 4)
            return f"{value} ({brief.get('numerator')}/{brief.get('denominator')})"
        return "undefined"

    for cell in summary["matrix"]["whole_set_cells"]:
        lines.append(
            "| {combination} | {form} | {temp} | {repeats} | {a1} | {a5} | {p1} | {p3} | {p5} | {judge} | {functional} |".format(
                combination=cell["combination_id"],
                form=cell["form"],
                temp=cell["temperature"],
                repeats=cell["repeats"],
                a1=fmt(cell["asr@1"]),
                a5=fmt(cell["asr@5"]),
                p1=fmt(cell["pass@1"]),
                p3=fmt(cell["pass@3"]),
                p5=fmt(cell["pass@5"]),
                judge=fmt(cell["llm_judge_rate"]),
                functional=cell["functional_available"],
            )
        )
    lines.append("")
    lines.append("## Derived cwe078 split views (post-hoc slices of the whole-set run)")
    lines.append("")
    lines.append("| entry | split | tasks | ASR@1 | pass@1 |")
    lines.append("|---|---|---:|---:|---:|")
    for row in summary["matrix"]["derived_views"]:
        lines.append(
            "| {entry} | {split} | {tasks} | {a1} | {p1} |".format(
                entry=row["entry_id"],
                split=row["split_mode"],
                tasks=row["task_count"],
                a1=fmt(row["asr@1"]),
                p1=fmt(row["pass@1"]),
            )
        )
    lines.append("")
    lines.append("## Distribution and availability")
    lines.append("")
    lines.append(f"- static verdicts: {summary['distributions']['static_verdict_counts']}")
    lines.append(f"- functional outcomes: {summary['distributions']['functional_outcomes']}")
    lines.append(f"- generation statuses: {summary['distributions']['generation_status_counts']}")
    lines.append(f"- non-static layer states: {summary['distributions']['layer_states']}")
    lines.append("")
    lines.append("## Cost")
    lines.append("")
    for role, value in cost["roles"].items():
        lines.append(
            f"- {role}: events={value['events']} known={value['known']} unknown={value['unknown']}"
        )
    lines.append("")
    lines.append("## Versions")
    lines.append("")
    for key in (
        "git_commit", "dspy_version", "data_contract", "cleaner_version",
        "static_shell_version", "harness_version", "image_digest",
        "judge_prompt_version", "judge_detection_version",
    ):
        lines.append(f"- {key}: `{summary['versions'].get(key)}`")
    lines.append("")
    lines.append("## Anomalies / human review")
    lines.append("")
    lines.append(f"- parse_error units: {summary['anomalies']['parse_error_units']}")
    lines.append(f"- generation non-success: {summary['anomalies']['generation_status_non_success']}")
    for row in summary["anomalies"]["top_natural_hit_rate_units"]:
        lines.append(
            f"- top natural hit rate: {row['unit_id']} asr@1={row['asr@1'].get('value')}"
        )
    lines.append("")
    lines.append(
        "Whole-set results must not be presented as holdout validation; derived "
        "search/holdout entries are post-hoc slices and must not drive template selection."
    )
    lines.append("")
    return "\n".join(lines)


def write_summary(baseline_root: Path | str, summary: dict[str, Any]) -> dict[str, str]:
    root = Path(baseline_root).expanduser().resolve()
    reports = root / REPORTS_DIRNAME
    reports.mkdir(parents=True, exist_ok=True)
    report_json = reports / "baseline_report.json"
    report_md = reports / "baseline_report.md"
    coverage_json = reports / "coverage_check.json"
    write_json_atomic(report_json, summary)
    write_text_atomic(report_md, _render_markdown(summary))
    write_json_atomic(coverage_json, summary["coverage"])
    return {
        "report_json": str(report_json),
        "report_markdown": str(report_md),
        "coverage_check": str(coverage_json),
    }


def report_baseline(baseline_root: Path | str) -> int:
    """Build/validate the index and write the grouped report; offline, no calls."""

    root = Path(baseline_root).expanduser().resolve()
    try:
        index = build_index(root)
        validate_index(index)
        write_index(root, index)
        summary = build_summary(root, index=index)
        outputs = write_summary(root, summary)
    except (OSError, ValueError) as error:
        print(f"error: report-baseline failed: {type(error).__name__}: {error}")
        return EXIT_BLOCKING
    coverage = summary["coverage"]
    print(
        f"baseline: {root}\n"
        f"units complete: {coverage['units_complete']}/{coverage['units_total']}; "
        f"samples: {coverage['actual_sample_total']}/{coverage['expected_sample_total']}; "
        f"index entries: {len(index['entries'])}; gaps: {len(index.get('gaps') or [])}"
    )
    print(f"index: {index_path(root)}")
    print(f"report: {outputs['report_json']}")
    print(f"report(md): {outputs['report_markdown']}")
    print(f"coverage: {outputs['coverage_check']}")
    return EXIT_OK


__all__ = [
    "SUMMARY_SCHEMA_VERSION",
    "COVERAGE_SCHEMA_VERSION",
    "REPORTS_DIRNAME",
    "EXPECTED_VICTIM_REQUESTS",
    "BaselineSummaryError",
    "build_summary",
    "write_summary",
    "report_baseline",
]
