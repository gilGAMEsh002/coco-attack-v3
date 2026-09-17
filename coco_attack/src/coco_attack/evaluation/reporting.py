"""Unified pipeline reporting: strict join, metrics and cost summary (task 05).

Reads the immutable per-step artifacts of a pipeline run and produces the
combined per-sample records, metrics, cost summary and human report.  Reporting
never re-runs evaluators, never calls a model and never writes cost.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..runtime.ledger import EVENT_EXECUTION_RECORDED, EVENT_RESPONSE_RECEIVED
from .generation_source import resolve_generation_run
from .metrics import check_baseline_compatibility

REPORT_SCHEMA_VERSION = "pipeline-report-v1"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_bytes().split(b"\n"):
        if raw.strip():
            try:
                rows.append(json.loads(raw.decode("utf-8")))
            except ValueError:
                continue
    return rows


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = read_json(path)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def collect_records(run_dir: Path | str) -> list[dict[str, Any]]:
    """Join generation identity with cleaning, static, functional and other layers."""

    run = Path(run_dir)
    records: dict[str, dict[str, Any]] = {}
    generation_map: dict[tuple[str, int], str] = {}
    generation = _read_jsonl(resolve_generation_run(run) / "generations.jsonl")
    for row in generation:
        sample_id = str(row.get("sample_id"))
        identity = row.get("identity") or {}
        records[sample_id] = {
            "sample_id": sample_id,
            "identity": identity,
            "task_id": row.get("task_id") or identity.get("task_id"),
            "repeat_id": row.get("repeat_id", identity.get("repeat_id")),
            "generation_status": row.get("status"),
            "generation_sha256": row.get("generation_sha256"),
            "prompt_sha256": row.get("prompt_sha256"),
        }
        generation_map[(str(records[sample_id]["task_id"]), int(records[sample_id]["repeat_id"]))] = sample_id

    for row in _read_jsonl(run / "cleaning" / "cleaned_generations.jsonl"):
        key = (str(row.get("task_id")), int(row.get("repeat_id", -1)))
        sample_id = generation_map.get(key)
        if sample_id is None:
            continue
        cleaned = row.get("cleaned") or {}
        records[sample_id]["cleaned"] = {
            "final_code_sha256": cleaned.get("final_code_sha256"),
            "extraction_path": cleaned.get("extraction_path"),
            "completed": cleaned.get("completed"),
        }

    for row in _read_jsonl(run / "static" / "evaluations.jsonl"):
        key = (str(row.get("task_id")), int(row.get("repeat_id", -1)))
        sample_id = generation_map.get(key)
        if sample_id is None:
            continue
        records[sample_id]["static"] = {
            "verdict": row.get("verdict"),
            "asr_hit": row.get("asr_hit"),
            "oracle_id": row.get("oracle_id"),
        }

    for row in _read_jsonl(run / "functional" / "functional_results.jsonl"):
        sample_id = str(row.get("sample_id"))
        if sample_id in records:
            records[sample_id]["functional"] = {
                "outcome": row.get("outcome"),
                "passed": row.get("passed"),
                "cache_eligible": row.get("cache_eligible"),
                "reuse_source": row.get("reuse_source"),
            }

    for layer in ("sast", "judge", "dynamic", "realism"):
        for row in _read_jsonl(run / "evaluation" / "layers" / f"{layer}.jsonl"):
            sample_id = str(row.get("sample_id"))
            if sample_id not in records:
                continue
            records[sample_id].setdefault("layers", {})
            if layer == "sast":
                records[sample_id]["layers"].setdefault("sast", {})[row.get("tool")] = {
                    "status": row.get("status"),
                    "detected": row.get("detected"),
                    "reason_code": row.get("reason_code"),
                }
            else:
                records[sample_id]["layers"][layer] = {
                    "status": row.get("status"),
                    "verdict": row.get("verdict"),
                    "detected": row.get("detected"),
                }
    return [records[sample_id] for sample_id in sorted(records)]


def collect_metrics(run_dir: Path | str, records: list[dict[str, Any]]) -> dict[str, Any]:
    run = Path(run_dir)
    manifest = _read_json(run / "sample_manifest.json") or {}
    expected = [str(sample_id) for sample_id in (manifest.get("expected_sample_ids") or [])]
    present = {str(record.get("sample_id")) for record in records}
    missing = [sample_id for sample_id in expected if sample_id not in present]
    extra = sorted(present - set(expected))
    metrics: dict[str, Any] = {
        "sample_count": len(records),
        "expected_sample_count": len(expected) if expected else None,
        "missing_sample_ids": missing,
        "extra_sample_ids": extra,
        "complete": bool(expected) and not missing and not extra,
        "static": _read_json(run / "static" / "metrics.json"),
        "functional": _read_json(run / "functional" / "functional_metrics.json"),
        "other": _read_json(run / "evaluation" / "evaluator_metrics.json"),
    }
    verdict_counts: Counter[str] = Counter()
    for record in records:
        verdict_counts[str((record.get("static") or {}).get("verdict"))] += 1
    metrics["static_verdict_counts"] = dict(sorted(verdict_counts.items()))
    return metrics


def collect_costs(run_dir: Path | str) -> dict[str, Any]:
    run = Path(run_dir)
    by_role: dict[str, dict[str, Any]] = {}
    for ledger_path in (run / "ledger.jsonl", run / "generation" / "ledger.jsonl"):
        if not ledger_path.is_file():
            continue
        for raw in ledger_path.read_bytes().split(b"\n"):
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except ValueError:
                continue
            payload = event.get("payload") or {}
            if payload.get("reused_from"):
                # A cache reuse references an already-counted real response;
                # it must not add to the totals.
                continue
            if event.get("event_type") == EVENT_EXECUTION_RECORDED:
                role = str(payload.get("role") or "local_test")
                entry = by_role.setdefault(role, {"events": 0, "cost": {"known": 0.0, "unknown": 0}, "usage": {}})
                entry["events"] += 1
                cost = payload.get("cost") or {}
                if cost.get("amount") is None:
                    entry["cost"]["unknown"] += 1
                else:
                    entry["cost"]["known"] += float(cost["amount"])
                usage = payload.get("usage") or {}
                for key, value in usage.items():
                    if isinstance(value, (int, float)):
                        entry["usage"][key] = entry["usage"].get(key, 0) + value
            elif event.get("event_type") == EVENT_RESPONSE_RECEIVED:
                # Response events come from the victim generation ledger.
                cost = payload.get("cost") or {}
                if cost.get("reused_from_first_response"):
                    # A victim cache hit copies the first response's usage/cost;
                    # it references an already-counted real response and must
                    # not add to the totals.
                    continue
                entry = by_role.setdefault("victim", {"events": 0, "cost": {"known": 0.0, "unknown": 0}, "usage": {}})
                entry["events"] += 1
                if cost.get("amount") is None:
                    entry["cost"]["unknown"] += 1
                else:
                    entry["cost"]["known"] += float(cost["amount"])
                usage = payload.get("usage") or {}
                for key, value in usage.items():
                    if isinstance(value, (int, float)):
                        entry["usage"][key] = entry["usage"].get(key, 0) + value
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "roles": by_role,
        "note": "known cost only when a pricing rule was configured; unknown windows are listed, never zero-filled",
    }


def build_report(run_dir: Path | str, output_dir: Path | str | None = None) -> dict[str, Any]:
    run = Path(run_dir).resolve()
    output = Path(output_dir).resolve() if output_dir is not None else run / "report"
    output.mkdir(parents=True, exist_ok=True)
    records = collect_records(run)
    metrics = collect_metrics(run, records)
    costs = collect_costs(run)
    records_text = "".join(
        canonical_json_bytes(record).decode("utf-8") + "\n" for record in records
    )
    write_text_atomic(output / "records.jsonl", records_text)
    write_json_atomic(output / "metrics.json", metrics)
    write_json_atomic(output / "cost_summary.json", costs)
    manifest = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "run_dir": str(run),
        "sample_count": len(records),
        "complete": bool(metrics.get("complete")),
        "artifacts": _artifact_index(run),
        "status": "complete" if metrics.get("complete") else ("empty" if not records else "incomplete"),
    }
    write_json_atomic(output / "manifest.json", manifest)
    write_text_atomic(
        output / "REPORT.md",
        _render_report(run, records, metrics, costs),
    )
    return manifest


def _artifact_index(run: Path) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for relative in (
        "pipeline_config.json", "sample_manifest.json",
        "cleaning/cleaned_generations.jsonl",
        "static/metrics.json", "core/checkpoint.json",
        "functional/functional_metrics.json", "evaluation/evaluator_metrics.json",
        "ledger.jsonl",
    ):
        path = run / relative
        if path.is_file():
            index[relative] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    # The generation source may be an external directory referenced by
    # pipeline_config.json; record where it actually resolved to.
    generation_file = resolve_generation_run(run) / "generations.jsonl"
    if generation_file.is_file():
        index["generation/generations.jsonl"] = {
            "sha256": sha256_file(generation_file),
            "size": generation_file.stat().st_size,
            "path": str(generation_file),
        }
    return index


def _render_report(run: Path, records: list[dict[str, Any]], metrics: dict[str, Any], costs: dict[str, Any]) -> str:
    lines = [
        "# Pipeline report",
        "",
        f"- run: `{run}`",
        f"- samples: {len(records)}",
        f"- expected samples: {metrics.get('expected_sample_count')}",
        f"- complete vs manifest: {metrics.get('complete')}",
        f"- missing samples: {len(metrics.get('missing_sample_ids') or [])}",
        f"- extra samples: {len(metrics.get('extra_sample_ids') or [])}",
        f"- static verdicts: {metrics.get('static_verdict_counts')}",
    ]
    static_metrics = metrics.get("static") or {}
    lines.append(
        f"- ASR@1 (static authoritative; on a clean run this is the natural hit rate): "
        f"{static_metrics.get('asr@1', {}).get('value')}"
    )
    functional = metrics.get("functional") or {}
    lines.append(f"- pass@1: {functional.get('pass@1', {}).get('value')}")
    other = metrics.get("other") or {}
    lines.append(f"- other-evaluator metrics: {json.dumps({k: v.get('defined') for k, v in other.items()})}")
    lines.append(f"- cost roles: {sorted((costs.get('roles') or {}).keys())}")
    lines.append("")
    lines.append("Functional passed/failed and behaviour verdicts are reported separately and never replace static ASR.")
    lines.append("")
    return "\n".join(lines)


def check_report_compatibility(baseline: dict[str, Any], candidate: dict[str, Any]) -> tuple[bool, list[str]]:
    return check_baseline_compatibility(baseline, candidate)


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "collect_records",
    "collect_metrics",
    "collect_costs",
    "build_report",
    "check_report_compatibility",
]
