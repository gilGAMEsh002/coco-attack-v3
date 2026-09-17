"""Clean-baseline orchestration: run, resume and status (phase 03, sub-task 02).

The orchestrator owns *scheduling only*: it walks the run manifest in order,
invokes one ``run-pipeline`` (fresh) or ``resume-pipeline`` (recovery)
subprocess per unit, and writes the pipeline's self-reported terminal state
back to the manifest.  It never re-implements evaluation, cleaning, metrics or
prompt logic.

Key invariants (plan §1, §4, §6):

* a unit is ``complete`` only when the run's ``report/metrics.json`` says
  ``complete: true`` and the process exited 0;
* a unit whose run is not complete is never promoted;
* the manifest is persisted after every unit, so an interrupt is resumable;
* a single-writer, fsync-ed JSONL log records every transition;
* concurrency > 1 is refused explicitly instead of being pretended.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assets.artifacts import canonical_json_bytes, read_json, write_json_atomic
from .baseline import (
    EXIT_BLOCKING,
    EXIT_OK,
    EXIT_USAGE,
    BaselineError,
    check_baseline,
    code_tree_changed_since,
    git_commit,
    git_worktree_status,
)
from .manifest import (
    ManifestError,
    load_manifest,
    update_unit_status,
    write_manifest_atomic,
)
from .matrix import MatrixConfig, MatrixError

ORCHESTRATOR_LOG = "manifest/orchestrator-log.jsonl"
STATUS_SNAPSHOT = "manifest/status.json"
STATUS_SCHEMA_VERSION = "baseline-status-v1"

_LOG_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ends_without_newline(path: Path) -> bool:
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            return False
        handle.seek(-1, os.SEEK_END)
        return handle.read(1) != b"\n"


def append_orchestrator_log(root: Path | str, event: str, **fields: Any) -> dict[str, Any]:
    """Append one JSONL event to ``<root>/manifest/orchestrator-log.jsonl``.

    Single-writer, append-only and fsync-ed, mirroring the ledger write style.
    A leading separator is inserted when a previous crash left a complete
    record without its trailing newline.
    """

    path = Path(root) / ORCHESTRATOR_LOG
    record: dict[str, Any] = {"ts": _utc_now(), "event": event}
    record.update(fields)
    with _LOG_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        needs_separator = path.is_file() and _ends_without_newline(path)
        with open(path, "ab") as handle:
            if needs_separator:
                handle.write(b"\n")
            handle.write(canonical_json_bytes(record) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    return record


def _default_runner(argv: Sequence[str], cwd: Path | str | None = None) -> int:
    """Run one pipeline command as a child process; return its exit code.

    Injectable seam: tests monkeypatch this function instead of starting a
    real subprocess.  The child always uses the current interpreter and the
    package CLI entry (``python -m coco_attack ...``).
    """

    command = [sys.executable, "-m", "coco_attack", *(str(item) for item in argv)]
    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        check=False,
    )
    return int(proc.returncode)


def _read_json_optional(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def _pipeline_outcome(run_dir: Path) -> dict[str, Any]:
    """Read the pipeline's self-reported terminal state (plan §2)."""

    run_manifest = _read_json_optional(run_dir / "manifest.json")
    metrics = _read_json_optional(run_dir / "report" / "metrics.json")
    manifest_status = run_manifest.get("status") if isinstance(run_manifest, dict) else None
    report_complete = bool(metrics.get("complete")) if isinstance(metrics, dict) else False
    return {
        "manifest_status": manifest_status,
        "report_complete": report_complete,
        "sample_count": metrics.get("sample_count") if isinstance(metrics, dict) else None,
        "expected_sample_count": (
            metrics.get("expected_sample_count") if isinstance(metrics, dict) else None
        ),
        "missing_sample_ids": (
            metrics.get("missing_sample_ids") if isinstance(metrics, dict) else None
        ),
    }


def _base_result(
    run: dict[str, Any], *, exit_code: int | None, resumed: bool, attempts: int
) -> dict[str, Any]:
    return {
        "run_dir": run.get("run_dir"),
        "manifest_status": None,
        "report_complete": False,
        "sample_count": None,
        "expected_sample_count": run.get("expected_sample_count"),
        "missing_sample_ids": None,
        "exit_code": exit_code,
        "resumed": resumed,
        "attempts": attempts,
    }


def _execute_single_run(
    root: Path,
    run: dict[str, Any],
    *,
    resume: bool,
    attempts: int,
) -> tuple[str, dict[str, Any]]:
    """Invoke the pipeline for one run entry.

    Returns ``(status, result)`` where ``status`` is one of
    ``complete``/``incomplete``/``blocked``.
    """

    run_dir = root / run["run_dir"]
    config_path = root / run["config_path"]

    if run_dir.exists() and not run_dir.is_dir():
        result = _base_result(run, exit_code=None, resumed=False, attempts=attempts)
        result["reason"] = f"run_dir is not a directory: {run_dir}"
        return "blocked", result

    non_empty = run_dir.is_dir() and any(run_dir.iterdir())
    if non_empty:
        if not resume:
            result = _base_result(run, exit_code=None, resumed=False, attempts=attempts)
            result["reason"] = "resume_disabled"
            return "blocked", result
        if not (run_dir / "pipeline_config.json").is_file():
            result = _base_result(run, exit_code=None, resumed=False, attempts=attempts)
            result["reason"] = f"pipeline_config.json missing in {run_dir}"
            return "blocked", result
        argv = ["resume-pipeline", "--run-dir", str(run_dir)]
        resumed = True
        append_orchestrator_log(
            root,
            "unit_resume",
            run_id=run["run_id"],
            run_dir=run["run_dir"],
            attempt=attempts,
        )
    else:
        argv = [
            "run-pipeline",
            "--config",
            str(config_path),
            "--output-dir",
            str(run_dir),
        ]
        resumed = False

    try:
        exit_code = _default_runner(argv)
    except OSError as error:
        result = _base_result(run, exit_code=None, resumed=resumed, attempts=attempts)
        result["reason"] = f"runner_error: {type(error).__name__}: {error}"
        return "blocked", result

    outcome = _pipeline_outcome(run_dir)
    result = {
        "run_dir": run["run_dir"],
        "manifest_status": outcome["manifest_status"],
        "report_complete": outcome["report_complete"],
        "sample_count": outcome["sample_count"],
        "expected_sample_count": outcome["expected_sample_count"],
        "missing_sample_ids": outcome["missing_sample_ids"],
        "exit_code": exit_code,
        "resumed": resumed,
        "attempts": attempts,
    }
    if exit_code == 0 and outcome["report_complete"]:
        return "complete", result
    return "incomplete", result


def _add_limitation(unit: dict[str, Any], reason: str) -> list[str]:
    limitations = list(unit.get("known_limitations") or [])
    if reason not in limitations:
        limitations.append(reason)
    return limitations


def _select_units(
    manifest: dict[str, Any],
    *,
    only: set[str] | None,
    limit: int | None,
) -> list[str]:
    remaining: list[str] = []
    for unit_id, unit in manifest["units"].items():
        if only is not None and unit_id not in only:
            continue
        if unit.get("status") in ("complete", "blocked"):
            continue
        remaining.append(unit_id)
    if limit is not None:
        remaining = remaining[:limit]
    return remaining


def _block_all_not_complete(
    root: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
    reason: str,
) -> list[str]:
    blocked: list[str] = []
    for unit_id, unit in manifest["units"].items():
        if unit.get("status") == "complete":
            continue
        update_unit_status(
            manifest,
            unit_id,
            "blocked",
            known_limitations=_add_limitation(unit, reason),
        )
        blocked.append(unit_id)
    write_manifest_atomic(manifest_path, manifest)
    append_orchestrator_log(root, "version_blocked", reason=reason, units=blocked)
    return blocked


def run_baseline(
    baseline_root: Path | str,
    *,
    limit: int | None = None,
    only: Iterable[str] | None = None,
    resume: bool = True,
) -> int:
    """Execute/resume the whole-set baseline manifest; return a CLI exit code."""

    root = Path(baseline_root).expanduser().resolve()
    manifest_path = root / "manifest" / "run-manifest.json"

    only_set: set[str] | None = None
    if only is not None:
        only_set = {str(item) for item in only}
        if not only_set:
            print("error: --only was given without any unit id", file=sys.stderr)
            return EXIT_USAGE
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
    ):
        print(f"error: --limit must be a non-negative integer, got {limit!r}", file=sys.stderr)
        return EXIT_USAGE

    # 1. manifest
    if not manifest_path.is_file():
        print(f"error: run manifest missing: {manifest_path}", file=sys.stderr)
        return EXIT_BLOCKING
    try:
        manifest = load_manifest(manifest_path)
    except (ManifestError, OSError, ValueError) as error:
        print(f"error: invalid run manifest {manifest_path}: {error}", file=sys.stderr)
        return EXIT_BLOCKING

    # 2. matrix + concurrency guard
    try:
        matrix = MatrixConfig.from_json(manifest["matrix"])
    except MatrixError as error:
        print(f"error: invalid matrix embedded in the manifest: {error}", file=sys.stderr)
        append_orchestrator_log(root, "manifest_error", error=str(error))
        return EXIT_BLOCKING

    if only_set is not None:
        unknown = sorted(only_set - set(manifest["units"]))
        if unknown:
            print(f"error: --only references unknown units: {unknown}", file=sys.stderr)
            return EXIT_USAGE

    if matrix.unit_concurrency > 1:
        append_orchestrator_log(
            root,
            "concurrency_unsupported",
            unit_concurrency=matrix.unit_concurrency,
        )
        print(
            "error: unit_concurrency > 1 is not implemented; keep serial "
            f"(unit_concurrency=1), got {matrix.unit_concurrency}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    append_orchestrator_log(
        root,
        "run_start",
        baseline_root=str(root),
        units_total=len(manifest["units"]),
        limit=limit,
        only=sorted(only_set) if only_set is not None else None,
    )

    # 3. startup gate: never start a pipeline if check-baseline is not clean.
    check_code = check_baseline(root)
    append_orchestrator_log(
        root, "check_baseline", exit_code=check_code, ready=check_code == EXIT_OK
    )
    if check_code != EXIT_OK:
        print(
            "error: check-baseline reported blocking startup conditions; "
            "no pipeline run was started",
            file=sys.stderr,
        )
        append_orchestrator_log(
            root, "run_end", exit_code=EXIT_BLOCKING, reason="check_baseline_blocked"
        )
        return EXIT_BLOCKING

    # 4. version guard (same policy as baseline.check_baseline): a doc-only
    # advance is fine, a tracked-code change is not.
    fingerprint = manifest.get("version_fingerprint") or {}
    recorded_commit = fingerprint.get("git_commit")
    repo_dir = Path(matrix.repo_dir)
    version_reason: str | None = None
    try:
        worktree = git_worktree_status(repo_dir)
        current_commit = git_commit(repo_dir)
    except BaselineError as error:
        version_reason = f"version_check_failed: {error}"
    else:
        if current_commit != recorded_commit:
            code_changed = code_tree_changed_since(repo_dir, recorded_commit)
            if code_changed is True:
                version_reason = (
                    f"version_mismatch: HEAD {current_commit!r} != recorded "
                    f"{recorded_commit!r} and tracked coco_attack/dspy code changed"
                )
            elif code_changed is False:
                append_orchestrator_log(
                    root,
                    "version_guard",
                    recorded_commit=recorded_commit,
                    current_commit=current_commit,
                    code_changed=False,
                    doc_only_advance=True,
                )
            else:
                version_reason = (
                    f"version_unverifiable: HEAD {current_commit!r} != recorded "
                    f"{recorded_commit!r} and the code-tree diff could not be determined"
                )
        else:
            append_orchestrator_log(
                root,
                "version_guard",
                recorded_commit=recorded_commit,
                current_commit=current_commit,
                worktree_dirty=worktree["dirty"],
                code_changed=False,
            )

    if version_reason is not None:
        _block_all_not_complete(root, manifest, manifest_path, version_reason)
        print(f"error: {version_reason}", file=sys.stderr)
        append_orchestrator_log(
            root, "run_end", exit_code=EXIT_BLOCKING, reason="version_blocked"
        )
        return EXIT_BLOCKING

    # 5. per-unit scheduling, in manifest order.
    max_unit_retries = matrix.max_unit_retries
    remaining = _select_units(manifest, only=only_set, limit=limit)

    for unit_id in remaining:
        unit = manifest["units"][unit_id]
        runs = unit.get("runs") or []
        attempts = int(unit.get("attempts", 0)) + 1
        unit["attempts"] = attempts
        run = runs[0] if len(runs) == 1 else None

        try:
            if run is None:
                reason = f"expected exactly one run entry, found {len(runs)}"
                update_unit_status(
                    manifest,
                    unit_id,
                    "blocked",
                    known_limitations=_add_limitation(unit, reason),
                )
                write_manifest_atomic(manifest_path, manifest)
                append_orchestrator_log(
                    root, "unit_blocked", unit_id=unit_id, reason=reason, attempts=attempts
                )
                continue

            append_orchestrator_log(
                root,
                "unit_start",
                unit_id=unit_id,
                run_id=run["run_id"],
                attempt=attempts,
                max_unit_retries=max_unit_retries,
            )
            update_unit_status(manifest, unit_id, "running", run_id=run["run_id"])
            write_manifest_atomic(manifest_path, manifest)

            run_status, result = _execute_single_run(
                root, run, resume=resume, attempts=attempts
            )
            if run_status == "complete":
                unit_status = "complete"
            elif run_status == "blocked":
                unit_status = "blocked"
            elif attempts > max_unit_retries:
                unit_status = "blocked"
            else:
                unit_status = "incomplete"

            update_unit_status(
                manifest, unit_id, unit_status, run_id=run["run_id"], result=result
            )

        except KeyboardInterrupt:
            # Never promote on interrupt; leave a resumable trail.
            limitations = _add_limitation(unit, "interrupted")
            if run is not None and run.get("status") != "complete":
                update_unit_status(
                    manifest,
                    unit_id,
                    "incomplete",
                    run_id=run["run_id"],
                    result={"reason": "interrupted", "attempts": attempts},
                    known_limitations=limitations,
                )
            else:
                update_unit_status(
                    manifest, unit_id, "incomplete", known_limitations=limitations
                )
            write_manifest_atomic(manifest_path, manifest)
            append_orchestrator_log(
                root,
                "unit_interrupted",
                unit_id=unit_id,
                run_id=run["run_id"] if run is not None else None,
                attempt=attempts,
            )
            append_orchestrator_log(
                root, "run_end", exit_code=EXIT_BLOCKING, reason="interrupted"
            )
            return EXIT_BLOCKING

        write_manifest_atomic(manifest_path, manifest)
        run_result = run.get("result") if isinstance(run.get("result"), dict) else {}
        append_orchestrator_log(
            root,
            "unit_end",
            unit_id=unit_id,
            run_id=run["run_id"],
            status=unit_status,
            attempt=attempts,
            exit_code=run_result.get("exit_code"),
            report_complete=run_result.get("report_complete"),
        )
        if unit_status == "blocked":
            append_orchestrator_log(
                root,
                "unit_blocked",
                unit_id=unit_id,
                reason=run_result.get("reason") or "not_complete",
                attempts=attempts,
            )
        elif unit_status == "incomplete":
            append_orchestrator_log(
                root,
                "unit_retry",
                unit_id=unit_id,
                attempts=attempts,
                max_unit_retries=max_unit_retries,
            )

    # 7. final result
    non_complete = [
        unit_id
        for unit_id, unit in manifest["units"].items()
        if unit.get("status") != "complete"
    ]
    exit_code = EXIT_OK if not non_complete else EXIT_BLOCKING
    append_orchestrator_log(
        root,
        "run_end",
        exit_code=exit_code,
        complete=len(manifest["units"]) - len(non_complete),
        non_complete_units=non_complete,
    )
    if non_complete:
        print(
            "baseline not complete; non-complete units: "
            + ", ".join(sorted(non_complete)),
            file=sys.stderr,
        )
    return exit_code


# --------------------------------------------------------------------------- #
# status-baseline (read-only over pipeline artifacts; no model calls)
# --------------------------------------------------------------------------- #


def _cost_summary_totals(cost_summary: Any) -> dict[str, Any] | None:
    if not isinstance(cost_summary, dict):
        return None
    roles = cost_summary.get("roles") or {}
    known_total = 0.0
    unknown_windows = 0
    requests_by_role: dict[str, int | None] = {}
    for role, entry in roles.items():
        if not isinstance(entry, dict):
            continue
        requests_by_role[role] = entry.get("events")
        cost = entry.get("cost") or {}
        if isinstance(cost.get("known"), (int, float)) and not isinstance(cost.get("known"), bool):
            known_total += float(cost["known"])
        if isinstance(cost.get("unknown"), int) and not isinstance(cost.get("unknown"), bool):
            unknown_windows += int(cost["unknown"])
    return {
        "known_total": known_total,
        "unknown_windows": unknown_windows,
        "requests_by_role": requests_by_role,
    }


def _ledger_reuse_sources(run_dir: Path) -> dict[str, Any]:
    sources: set[str] = set()
    reuse_events = 0
    for ledger_path in (run_dir / "ledger.jsonl", run_dir / "generation" / "ledger.jsonl"):
        if not ledger_path.is_file():
            continue
        try:
            raw_lines = ledger_path.read_bytes().split(b"\n")
        except OSError:
            continue
        for raw in raw_lines:
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            payload = event.get("payload") if isinstance(event, dict) else None
            if not isinstance(payload, dict):
                continue
            reused_from = payload.get("reused_from")
            if reused_from:
                reuse_events += 1
                sources.add(str(reused_from))
            if payload.get("reused_from_first_response"):
                reuse_events += 1
                sources.add("response-cache")
    return {"reuse_events": reuse_events, "sources": sorted(sources)}


def _run_status_summary(root: Path, run: dict[str, Any]) -> dict[str, Any]:
    run_dir = root / run["run_dir"]
    cost = _cost_summary_totals(_read_json_optional(run_dir / "report" / "cost_summary.json"))
    functional_manifest = _read_json_optional(run_dir / "functional" / "manifest.json")
    generation_summary = _read_json_optional(run_dir / "generation" / "generation_summary.json")
    reuse = _ledger_reuse_sources(run_dir)
    return {
        "run_id": run.get("run_id"),
        "stage": run.get("stage"),
        "status": run.get("status"),
        "expected_sample_count": run.get("expected_sample_count"),
        "run_dir": run.get("run_dir"),
        "result": run.get("result"),
        "cost": cost,
        "functional": {
            "cache_hits": functional_manifest.get("cache_hits") if isinstance(functional_manifest, dict) else None,
            "executed": functional_manifest.get("executed") if isinstance(functional_manifest, dict) else None,
        },
        "generation": {
            "finalized_total": generation_summary.get("finalized_total") if isinstance(generation_summary, dict) else None,
            "status_counts": generation_summary.get("status_counts") if isinstance(generation_summary, dict) else None,
        },
        "reuse": reuse,
    }


def status_baseline(baseline_root: Path | str) -> int:
    """Summarize per-unit status/cost without starting any pipeline run."""

    root = Path(baseline_root).expanduser().resolve()
    manifest_path = root / "manifest" / "run-manifest.json"
    if not manifest_path.is_file():
        print(f"error: run manifest missing: {manifest_path}", file=sys.stderr)
        return EXIT_BLOCKING
    try:
        manifest = load_manifest(manifest_path)
    except (ManifestError, OSError, ValueError) as error:
        print(f"error: invalid run manifest {manifest_path}: {error}", file=sys.stderr)
        return EXIT_BLOCKING

    units_payload: dict[str, Any] = {}
    totals_known = 0.0
    totals_unknown = 0
    status_counts: dict[str, int] = {}
    non_complete: list[str] = []
    for unit_id, unit in manifest["units"].items():
        status = unit.get("status")
        status_counts[status] = status_counts.get(status, 0) + 1
        if status != "complete":
            non_complete.append(unit_id)
        runs = [_run_status_summary(root, run) for run in (unit.get("runs") or [])]
        for run in runs:
            cost = run.get("cost")
            if isinstance(cost, dict):
                totals_known += float(cost.get("known_total") or 0.0)
                totals_unknown += int(cost.get("unknown_windows") or 0)
        units_payload[unit_id] = {
            "status": status,
            "attempts": unit.get("attempts"),
            "combination_id": unit.get("combination_id"),
            "form": unit.get("form"),
            "temperature": unit.get("temperature"),
            "repeats": unit.get("repeats"),
            "expected_sample_count": unit.get("expected_sample_count"),
            "known_limitations": list(unit.get("known_limitations") or []),
            "runs": runs,
        }

    payload = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "baseline_root": str(root),
        "generated_at": _utc_now(),
        "status_counts": status_counts,
        "non_complete_units": non_complete,
        "totals": {
            "known_cost": totals_known,
            "unknown_windows": totals_unknown,
            "currency_note": "costs are per-run role totals; unknown windows are counted, never zero-filled",
        },
        "units": units_payload,
    }
    write_json_atomic(root / STATUS_SNAPSHOT, payload)

    print(f"baseline: {root}")
    print(
        "units: "
        + ", ".join(f"{name}={count}" for name, count in sorted(status_counts.items()))
    )
    for unit_id, entry in units_payload.items():
        line = f"  {unit_id}: {entry['status']}"
        if entry.get("attempts") is not None:
            line += f" (attempts={entry['attempts']})"
        print(line)
        if entry["status"] != "complete" and entry["known_limitations"]:
            print(f"    reason: {entry['known_limitations']}")
        for run in entry["runs"]:
            cost = run.get("cost")
            if isinstance(cost, dict):
                print(
                    f"    {run['run_id']}: cost known={cost['known_total']} "
                    f"unknown={cost['unknown_windows']} requests={cost['requests_by_role']}"
                )
            if run.get("reuse", {}).get("sources"):
                print(f"    {run['run_id']}: reuse sources={run['reuse']['sources']}")
    if non_complete:
        print("non-complete units: " + ", ".join(sorted(non_complete)))
    else:
        print("all units complete")
    return EXIT_OK


__all__ = [
    "ORCHESTRATOR_LOG",
    "STATUS_SCHEMA_VERSION",
    "STATUS_SNAPSHOT",
    "append_orchestrator_log",
    "run_baseline",
    "status_baseline",
]
