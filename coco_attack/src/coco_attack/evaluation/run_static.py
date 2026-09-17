"""Static evaluation batch orchestration (task 04).

Consumes ``prepare-data`` and ``clean-generations`` outputs plus an explicit
evaluation config, routes each sample to the reused static oracle, and writes
per-sample evaluations and metrics. SAST, judge, functional, dynamic and
realism layers are reported as not integrated rather than as zero.
"""

from __future__ import annotations

import json
import platform
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
from ..assets.issues import SEVERITY_ERROR, Issue
from ..data.contracts import DataContractError, PreparedCombination
from ..data.snapshot import load_prepared_data
from ..protocol.stages import SplitMode
from .contracts import (
    EvaluationConfig,
    EvaluationRecord,
    MetricResult,
)
from .metrics import (
    asr_at_k,
    llm_judge_rate,
    evasion,
    pass_at_k,
    sample_hit_rate,
    verdict_counts,
)
from .static import oracle_fingerprint, evaluate_static_sample, load_oracle_module

STATIC_SHELL_VERSION = "static-shell-v1"
EVAL_SCHEMA_VERSION = "1"


class EvaluationInputError(DataContractError):
    pass


def evaluate_static(
    assets_root: Path,
    data_dir: Path,
    cleaned_dir: Path,
    config_path: Path,
    output_dir: Path,
) -> int:
    try:
        config = EvaluationConfig.from_json(read_json(config_path))
    except (OSError, ValueError) as error:
        _fail("config.invalid", f"invalid evaluation config: {error}")

    prepared = load_prepared_data(data_dir, config.combination_id)
    if prepared.oracle_id != config.oracle_id:
        _fail(
            "config.oracle_mismatch",
            f"config oracle {config.oracle_id!r} != prepared oracle {prepared.oracle_id!r}",
        )

    cleaned_manifest, cleaned_rows = _load_cleaned(cleaned_dir, config)
    task_ids = _resolve_task_set(prepared, config.task_set)
    if config.task_ids:
        allowed = set(task_ids)
        unknown = [task_id for task_id in config.task_ids if task_id not in allowed]
        if unknown:
            _fail(
                "config.task_ids_out_of_scope",
                f"config task_ids are not in the {config.task_set} set: {unknown}",
            )
        task_ids = [task_id for task_id in task_ids if task_id in set(config.task_ids)]
    if not task_ids:
        _fail("config.empty_task_set", f"task_set {config.task_set!r} resolved to no tasks")

    expected_keys = [
        (task_id, repeat_id)
        for task_id in task_ids
        for repeat_id in range(config.repeats)
    ]
    by_key = _validate_matrix(cleaned_rows, expected_keys, task_ids, config)

    try:
        module = load_oracle_module(assets_root, config.oracle_id)
        fingerprint = oracle_fingerprint(assets_root, config.oracle_id)
    except (OSError, RuntimeError) as error:
        _fail("oracle.load_failed", str(error))

    evaluator_fingerprint = {
        "shell_version": STATIC_SHELL_VERSION,
        "cleaner_version": cleaned_manifest.get("cleaner_version"),
        "python": platform.python_version(),
        "oracle": fingerprint,
    }

    records: list[EvaluationRecord] = []
    for task_id, repeat_id in expected_keys:
        row = by_key[(task_id, repeat_id)]
        cleaned = row["cleaned"]
        records.append(
            _evaluate_row(
                config=config,
                task_id=task_id,
                repeat_id=repeat_id,
                row=row,
                cleaned=cleaned,
                module=module,
                fingerprint=evaluator_fingerprint,
            )
        )

    metrics = _compute_metrics(records, task_ids, config, prepared)
    batch_id = _batch_id(config, cleaned_manifest, prepared)

    output_dir.mkdir(parents=True, exist_ok=True)
    evaluations_path = output_dir / "evaluations.jsonl"
    lines = [json.dumps(record.to_json(), ensure_ascii=False, sort_keys=True) for record in records]
    write_bytes_atomic(evaluations_path, ("\n".join(lines) + "\n").encode("utf-8"))
    write_json_atomic(output_dir / "metrics.json", {m.name: m.to_json() for m in metrics})

    manifest = {
        "schema_version": EVAL_SCHEMA_VERSION,
        "completion": "complete",
        "batch_id": batch_id,
        "combination_id": config.combination_id,
        "oracle_id": config.oracle_id,
        "config": config.to_json(),
        "task_set": config.task_set,
        "task_count": len(task_ids),
        "record_count": len(records),
        "evaluator_fingerprint": evaluator_fingerprint,
        "inputs": {
            "cleaned_manifest": {
                "name": cleaned_manifest.get("output", {}).get("name"),
                "sha256": cleaned_manifest.get("input", {}).get("sha256"),
            },
            "evaluations": {"name": evaluations_path.name, "sha256": sha256_file(evaluations_path)},
        },
        "layer_availability": {
            "static": {"available": True},
            "sast": {"available": False, "reason": "not integrated in this task"},
            "judge": {"available": False, "reason": "not integrated in this task"},
            "functional": {"available": False, "reason": "not integrated in this task"},
            "dynamic": {"available": False, "reason": "not integrated in this task"},
            "realism": {"available": False, "reason": "not integrated in this task"},
        },
    }
    write_json_atomic(output_dir / "manifest.json", manifest)
    write_text_atomic(
        output_dir / "REPORT.md",
        render_static_report(config, task_ids, records, metrics, manifest),
    )
    return 0


def _load_cleaned(
    cleaned_dir: Path, config: EvaluationConfig
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = cleaned_dir / "manifest.json"
    if not manifest_path.is_file():
        _fail("cleaned.manifest_missing", f"cleaning manifest not found: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("completed") is not True:
        _fail("cleaned.incomplete", "cleaning manifest is not marked completed")
    if manifest.get("combination_id") != config.combination_id:
        _fail("cleaned.combination_mismatch", "cleaning manifest combination mismatch")
    if manifest.get("oracle_id") != config.oracle_id:
        _fail("cleaned.oracle_mismatch", "cleaning manifest oracle mismatch")
    output_name = manifest.get("output", {}).get("name")
    if not output_name:
        _fail("cleaned.output_name_missing", "cleaning manifest has no output name")
    cleaned_path = cleaned_dir / output_name
    if not cleaned_path.is_file():
        _fail("cleaned.output_missing", f"cleaned output not found: {cleaned_path}")
    expected_hash = manifest.get("output", {}).get("sha256")
    if expected_hash != sha256_file(cleaned_path):
        _fail("cleaned.output_hash_mismatch", "cleaned output hash does not match manifest")

    rows: list[dict[str, Any]] = []
    with open(cleaned_path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                _fail("cleaned.invalid_json", f"{cleaned_path}:{lineno}: {error}")
            if not isinstance(row, dict) or "cleaned" not in row:
                _fail("cleaned.invalid_record", f"{cleaned_path}:{lineno}: missing cleaned block")
            rows.append(row)
    if not rows:
        _fail("cleaned.empty", "cleaned output contains no records")
    return manifest, rows


def _resolve_task_set(prepared: PreparedCombination, task_set: str) -> list[str]:
    split = prepared.split
    if task_set == "evaluation":
        return list(prepared.selection.evaluation_ids)
    if task_set == "whole-set":
        return list(split.input_ids)
    if split.mode is SplitMode.WHOLE_SET:
        # Whole-set combinations have no partitions; they execute under the
        # scheduling stage "search" over the full evaluation set.  This mirrors
        # ``generation.inputs.select_stage_task_ids`` so the static layer sees the
        # same tasks the generation/functional layers produced.
        if task_set == "search":
            return list(split.input_ids)
        _fail(
            "config.task_set_unavailable",
            f"whole-set combination has no {task_set!r} partition",
        )
    if task_set == "search":
        return list(split.search_ids)
    if task_set == "holdout":
        return list(split.holdout_ids)
    _fail("config.unknown_task_set", f"unknown task_set {task_set!r}")
    return []


def _validate_matrix(
    rows: list[dict[str, Any]],
    expected_keys: list[tuple[str, int]],
    task_ids: list[str],
    config: EvaluationConfig,
) -> dict[tuple[str, int], dict[str, Any]]:
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    task_set = set(task_ids)
    for row in rows:
        task_id = row.get("task_id")
        repeat_id = row.get("repeat_id")
        if not isinstance(task_id, str) or not isinstance(repeat_id, int) or isinstance(repeat_id, bool):
            _fail("cleaned.identity_invalid", "cleaned record lacks task_id/repeat_id")
        if task_id not in task_set:
            # Extra records are rejected; the fixed task set is never reduced
            # and no rows are silently dropped.
            _fail(
                "cleaned.extra_task",
                f"task {task_id!r} is not in the declared task set {config.task_set!r}",
            )
        if repeat_id < 0 or repeat_id >= config.repeats:
            _fail(
                "cleaned.repeat_out_of_range",
                f"repeat_id {repeat_id} outside 0..{config.repeats - 1}",
            )
        key = (task_id, repeat_id)
        if key in by_key:
            _fail("cleaned.duplicate_sample", f"duplicate sample {key}")
        by_key[key] = row

    missing = [key for key in expected_keys if key not in by_key]
    if missing:
        _fail(
            "cleaned.incomplete_matrix",
            f"missing {len(missing)} expected samples, e.g. {missing[:5]}",
        )
    return by_key


def _evaluate_row(
    *,
    config: EvaluationConfig,
    task_id: str,
    repeat_id: int,
    row: dict[str, Any],
    cleaned: dict[str, Any],
    module: Any,
    fingerprint: dict[str, Any],
) -> EvaluationRecord:
    generation_status = cleaned.get("generation_status")
    final_code = cleaned.get("final_code", "")
    entry_present = bool(cleaned.get("entry_present"))
    syntax_ok = cleaned.get("syntax_ok")
    cleaning_source = {
        "path": (row.get("source") or {}).get("path"),
        "line": (row.get("source") or {}).get("line"),
        "line_sha256": (row.get("source") or {}).get("line_sha256"),
    }

    if generation_status != "success":
        verdict, target_present, source, raw = (
            "parse_error",
            False,
            "generation_failure",
            {},
        )
    elif not str(final_code).strip():
        verdict, target_present, source, raw = "parse_error", False, "empty_output", {}
    else:
        normalized = evaluate_static_sample(final_code, config.oracle_id, module)
        verdict = normalized["verdict"]
        target_present = normalized["target_present"]
        source = "oracle"
        raw = normalized

    return EvaluationRecord(
        combination_id=config.combination_id,
        oracle_id=config.oracle_id,
        task_id=task_id,
        repeat_id=repeat_id,
        batch_id=_batch_identity(config),
        final_code=final_code,
        final_code_sha256=sha256_bytes(str(final_code).encode("utf-8")),
        generation_status=generation_status,
        cleaning_source=cleaning_source,
        verdict=verdict,
        target_present=target_present,
        returned_oracle_id=raw.get("oracle_id", config.oracle_id) if raw else config.oracle_id,
        oracle_layer=raw.get("oracle_layer", "static") if raw else "static",
        raw_oracle_result=raw,
        target_present_source=source,
        entry_present=entry_present,
        syntax_ok=syntax_ok,
        evaluator_fingerprint=fingerprint,
        layer_availability={
            "static": True,
            "sast": False,
            "judge": False,
            "functional": False,
            "dynamic": False,
            "realism": False,
        },
    )


def _batch_identity(config: EvaluationConfig) -> str:
    payload = json.dumps(config.to_json(), sort_keys=True, ensure_ascii=False)
    return sha256_bytes(payload.encode("utf-8"))


def _batch_id(
    config: EvaluationConfig,
    cleaned_manifest: dict[str, Any],
    prepared: PreparedCombination,
) -> str:
    payload = {
        "config": config.to_json(),
        "cleaned_input_sha256": cleaned_manifest.get("input", {}).get("sha256"),
        "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
    }
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )


def _compute_metrics(
    records: list[EvaluationRecord],
    task_ids: list[str],
    config: EvaluationConfig,
    prepared: PreparedCombination,
) -> list[MetricResult]:
    sampling = config.sampling
    formal_asr1 = {"temperature": 0.0, "repeats": 1}
    formal_asr5 = {"temperature": 0.7, "repeats": 5}
    metrics = [
        asr_at_k(records, task_ids, 1, task_set=config.task_set, sampling=sampling, formal_spec=formal_asr1),
        asr_at_k(records, task_ids, 3, task_set=config.task_set, sampling=sampling),
        asr_at_k(records, task_ids, 5, task_set=config.task_set, sampling=sampling, formal_spec=formal_asr5),
        sample_hit_rate(records, task_set=config.task_set, sampling=sampling),
    ]
    for k in (1, 3, 5):
        metrics.append(
            MetricResult.undefined(
                f"pass@{k}",
                "functional test results are not integrated in this task",
                k=k,
                task_set=config.task_set,
                sampling=sampling,
                availability={"functional": {"available": False}},
            )
        )
    for tool in ("semgrep", "bandit", "codeql"):
        metrics.append(
            evasion(
                records,
                tool_name=tool,
                accessor=None,
                temperature=config.temperature,
                repeats=config.repeats,
                task_set=config.task_set,
                sampling=sampling,
            )
        )
    metrics.append(
        llm_judge_rate(
            records,
            accessor=None,
            temperature=config.temperature,
            repeats=config.repeats,
            task_set=config.task_set,
            sampling=sampling,
        )
    )
    return metrics


def render_static_report(
    config: EvaluationConfig,
    task_ids: list[str],
    records: list[EvaluationRecord],
    metrics: list[MetricResult],
    manifest: dict[str, Any],
) -> str:
    lines: list[str] = []
    lines.append("# Static evaluation report")
    lines.append("")
    lines.append(f"- Combination: `{config.combination_id}` (oracle `{config.oracle_id}`)")
    lines.append(f"- Model: `{config.model}`, temperature {config.temperature}, repeats {config.repeats}")
    lines.append(f"- Task set: `{config.task_set}` ({len(task_ids)} tasks)")
    lines.append(f"- Samples: {len(records)}")
    lines.append("")
    lines.append("## Verdict distribution")
    lines.append("")
    counts = verdict_counts(records)
    for verdict, count in counts.items():
        lines.append(f"- `{verdict}`: {count}")
    source_counts: dict[str, int] = {}
    for record in records:
        source_counts[record.target_present_source] = source_counts.get(record.target_present_source, 0) + 1
    lines.append("")
    lines.append("## target_present source")
    lines.append("")
    for source, count in sorted(source_counts.items()):
        lines.append(f"- `{source}`: {count}")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append("| Metric | Value | Defined | Reason | Numerator | Denominator |")
    lines.append("|---|---|---|---|---:|---:|")
    for metric in metrics:
        value = "undefined" if not metric.defined else f"{metric.value}"
        lines.append(
            f"| {metric.name} | {value} | {metric.defined} | {metric.reason or ''} | "
            f"{metric.numerator if metric.numerator is not None else ''} | "
            f"{metric.denominator if metric.denominator is not None else ''} |"
        )
    lines.append("")
    lines.append(
        "Only the static layer is integrated in this task; pass@k, SAST, judge, "
        "dynamic and realism metrics are undefined placeholders. `target_absent` "
        "means the target pattern was not detected, not that the code is safe."
    )
    lines.append("")
    return "\n".join(lines)


def _fail(code: str, detail: str):
    raise EvaluationInputError(
        detail,
        [Issue(code=code, severity=SEVERITY_ERROR, scope="evaluation", detail=detail)],
    )
