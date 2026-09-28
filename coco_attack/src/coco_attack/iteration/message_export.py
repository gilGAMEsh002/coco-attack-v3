"""Read-only forensic export of mutator role messages (task: explicit HTML + JSONL).

This service reconstructs, from a completed/in-progress ``run-method-ab`` run
directory, exactly what was sent to and received from the ``mutator`` role.  It
is a **pure reader**: it never calls a recovery function, a model provider, a
credential loader, Docker or Semgrep, and it never writes into the run directory.

Outputs (into a brand-new, non-overlapping directory):

* ``messages.jsonl`` -- one line per *logical action*, keyed by the durable
  ``actions.jsonl`` ledger and the per-attempt ``request_attempt_id`` (never by
  the provider-local ``attempt_index``).
* ``manifest.json`` -- ordering basis, source hashes, classification counts and
  every anomaly (missing/corrupt/identity-conflict/incomplete tail).  Nothing is
  silently dropped.
* ``index.html`` -- a self-contained, offline, escaped per-call view with long
  messages collapsed by default.

Fidelity rules: roles, message order, repeated history, code newlines, empty
responses, errors and usage/cost are preserved verbatim; a missing usage/cost is
recorded as unknown and is never filled with zero or inferred from a successful
response.  ``history.jsonl`` is attached only as an auxiliary cross-reference and
is never used to fabricate model reasoning that was not saved.

The service reuses the existing :class:`~coco_attack.iteration.action_runtime.ActionStore`
read API (``read_request``/``read_result``/``read_commit``/``events``/
``response_events``/paths) and adds no persistence.  The raw ``actions.jsonl`` is
additionally read once, tolerantly, to obtain the *physical line numbers* the
ordering rule requires (``ActionStore.events`` intentionally drops them), and the
response files are enumerated from ``ActionStore.responses_dir`` because
``durable_response`` raises on exactly the missing-file case this export must
report rather than hide.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..assets.artifacts import canonical_json_bytes, sha256_file
from .action_runtime import (
    ACTION_PLANNED,
    ATTEMPT_FAILED,
    ATTEMPT_STARTED,
    RESPONSE_SAVED,
    ActionStore,
)

EXPORT_SCHEMA_VERSION = "mutator-message-export-v1"

#: Ordering basis, from strongest to weakest evidence.
ORDER_ACTION_PLANNED = "action_planned_line"
ORDER_LEDGER_FIRST_EVENT = "ledger_first_event_line"
ORDER_METHOD_EVENTS = "method_events_line"
ORDER_REQUEST_CREATED_AT = "request_created_at"
ORDER_NONE = "none"

_ORDER_RANK = {
    ORDER_ACTION_PLANNED: 0,
    ORDER_LEDGER_FIRST_EVENT: 1,
    ORDER_METHOD_EVENTS: 2,
    ORDER_REQUEST_CREATED_AT: 3,
    ORDER_NONE: 4,
}

#: Per-attempt integrity classifications.
ORPHAN_ATTEMPT = "orphan_attempt"
FAILED_NO_RESPONSE = "failed_attempt_no_response"
RESPONSE_WITHOUT_EVENT = "response_without_event"
MISSING_RESPONSE_FILE = "missing_response_file"
DUPLICATE_EVENT = "duplicate_event"
CONFLICTING_EVENT = "conflicting_event"
MISSING_EVENTS = "missing_attempt_events"


class MessageExportError(ValueError):
    """Raised when the export cannot start (bad run dir / output dir)."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class _Anomaly:
    kind: str
    action_id: str | None
    request_attempt_id: str | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "action_id": self.action_id,
            "request_attempt_id": self.request_attempt_id,
            "detail": self.detail,
        }


def _read_jsonl_tolerant(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[_Anomaly]]:
    """Read a JSONL file preserving physical line numbers, tolerating a torn tail.

    A syntactically invalid line is reported as an anomaly instead of aborting the
    whole export.  An invalid *final* line is labelled an incomplete ledger tail;
    an invalid earlier line is a separate anomaly.  The whole file is read before
    classifying so iteration is never disturbed.
    """

    rows: list[tuple[int, dict[str, Any]]] = []
    anomalies: list[_Anomaly] = []
    if not path.is_file():
        return rows, anomalies
    with open(path, "rb") as handle:
        raw_lines = handle.readlines()
    non_blank = [index for index, raw in enumerate(raw_lines, start=1) if raw.strip()]
    last_non_blank = non_blank[-1] if non_blank else -1
    for lineno, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            kind = "incomplete_ledger_tail" if lineno == last_non_blank else "invalid_ledger_line"
            anomalies.append(_Anomaly(kind, None, None, f"{path.name}:{lineno}: {type(error).__name__}: {error}"))
            continue
        if not isinstance(obj, dict):
            anomalies.append(
                _Anomaly(
                    "invalid_ledger_line",
                    None,
                    None,
                    f"{path.name}:{lineno}: record is not a JSON object",
                )
            )
            continue
        rows.append((lineno, obj))
    return rows, anomalies


def _iter_source_files(run_dir: Path) -> list[Path]:
    files: list[Path] = []
    for name in ("actions.jsonl", "method_events.jsonl", "history.jsonl", "state.json"):
        candidate = run_dir / name
        if candidate.is_file():
            files.append(candidate)
    actions_dir = run_dir / "actions"
    if actions_dir.is_dir():
        files.extend(sorted(path for path in actions_dir.rglob("*") if path.is_file()))
    return files


def _hash_sources(run_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in _iter_source_files(run_dir):
        try:
            hashes[str(path.relative_to(run_dir))] = sha256_file(path)
        except OSError:
            hashes[str(path.relative_to(run_dir))] = "<unreadable>"
    return hashes


def _load_json_safe(path: Path, anomalies: list[_Anomaly], action_id: str | None, kind: str) -> Any:
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        anomalies.append(
            _Anomaly(kind, action_id, None, f"{path.name}: {type(error).__name__}: {error}")
        )
        return None


def _first(value: Any, key: str, default: Any = None) -> Any:
    return value.get(key) if isinstance(value, Mapping) else default


def _attempt_sort_key(attempt: dict[str, Any]) -> tuple[int, int, str]:
    line = attempt.get("first_ledger_line")
    if line is None:
        # A response file without events has no ledger position: keep it grouped
        # after event-bearing attempts, ordered by provider attempt index.
        index = attempt.get("attempt_index")
        return (1, int(index) if isinstance(index, int) else 10**9, attempt["request_attempt_id"])
    return (0, int(line), attempt["request_attempt_id"])


def export_mutator_messages(run_dir: Path | str, output_dir: Path | str) -> dict[str, Any]:
    """Export the mutator messages of ``run_dir`` into a fresh ``output_dir``."""

    run_dir = Path(run_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    if not run_dir.is_dir():
        raise MessageExportError(f"run dir is not an existing directory: {run_dir}")
    if not (run_dir / "actions.jsonl").is_file():
        raise MessageExportError(
            f"run dir has no actions.jsonl ledger; not a method run: {run_dir}"
        )
    if output_dir.exists():
        raise MessageExportError(f"output dir already exists; refusing to overwrite: {output_dir}")
    if output_dir == run_dir or output_dir in run_dir.parents or run_dir in output_dir.parents:
        raise MessageExportError(
            f"output dir must not overlap the run dir: run={run_dir} output={output_dir}"
        )

    anomalies: list[_Anomaly] = []
    hashes_before = _hash_sources(run_dir)
    store = ActionStore(run_dir)

    ledger, ledger_anomalies = _read_jsonl_tolerant(store.actions_path)
    anomalies.extend(ledger_anomalies)
    method_events, method_anomalies = _read_jsonl_tolerant(run_dir / "method_events.jsonl")
    anomalies.extend(method_anomalies)

    actions_dir = store.actions_dir
    dir_action_ids = (
        sorted(path.name for path in actions_dir.iterdir() if path.is_dir())
        if actions_dir.is_dir()
        else []
    )

    action_ids: list[str] = []
    for _lineno, event in ledger:
        action_id = event.get("action_id")
        if isinstance(action_id, str) and action_id not in action_ids:
            action_ids.append(action_id)
    for action_id in dir_action_ids:
        if action_id not in action_ids:
            action_ids.append(action_id)
    for _lineno, event in method_events:
        action_id = _first(event.get("payload"), "action_id")
        if isinstance(action_id, str) and action_id not in action_ids:
            action_ids.append(action_id)

    # -- ordering ------------------------------------------------------------ #
    planned_line: dict[str, int] = {}
    planned_ts: dict[str, str] = {}
    first_ledger_line: dict[str, int] = {}
    for lineno, event in ledger:
        action_id = event.get("action_id")
        if not isinstance(action_id, str):
            continue
        first_ledger_line.setdefault(action_id, lineno)
        if event.get("event_type") == ACTION_PLANNED and action_id not in planned_line:
            planned_line[action_id] = lineno
            planned_ts[action_id] = str(event.get("ts") or "")
    first_method_line: dict[str, int] = {}
    for lineno, event in method_events:
        action_id = _first(event.get("payload"), "action_id")
        if isinstance(action_id, str):
            first_method_line.setdefault(action_id, lineno)

    records: list[dict[str, Any]] = []
    for action_id in action_ids:
        records.append(
            _build_action_record(
                store,
                action_id,
                ledger,
                method_events,
                planned_line,
                planned_ts,
                first_ledger_line,
                first_method_line,
                anomalies,
            )
        )

    records.sort(
        key=lambda record: (
            _ORDER_RANK[record["order"]["basis"]],
            record["order"]["value"] if record["order"]["value"] is not None else "",
            record["action_id"],
        )
    )
    for index, record in enumerate(records, start=1):
        record["order"]["index"] = index

    # -- compose the export -------------------------------------------------- #
    counts = _counts(records)
    integrity = _integrity_summary(records, ledger_anomalies)
    hashes_after = _hash_sources(run_dir)
    sources_unchanged = hashes_before == hashes_after
    manifest = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": _utc_now(),
        "run_dir": str(run_dir),
        "output_dir": str(output_dir),
        "ordering": {
            "primary": ORDER_ACTION_PLANNED,
            "rule": "physical line of the first action_planned event in actions.jsonl",
            "fallbacks": [
                ORDER_LEDGER_FIRST_EVENT,
                ORDER_METHOD_EVENTS,
                ORDER_REQUEST_CREATED_AT,
                ORDER_NONE,
            ],
            "basis_counts": _counts_by(records, lambda r: r["order"]["basis"]),
            "incomplete_ordering": [
                {
                    "action_id": r["action_id"],
                    "basis": r["order"]["basis"],
                    "value": r["order"]["value"],
                }
                for r in records
                if r["order"]["basis"] != ORDER_ACTION_PLANNED
            ],
        },
        "counts": counts,
        "integrity": integrity,
        "sources": [
            {"path": rel, "sha256": sha, "sha256_after": hashes_after.get(rel)}
            for rel, sha in sorted(hashes_before.items())
        ],
        "sources_unchanged_during_export": sources_unchanged,
        "export_complete": sources_unchanged,
        "anomalies": [anomaly.to_json() for anomaly in anomalies],
        "notes": [
            "read-only export: no recovery function, model provider, credential loader, Docker or Semgrep is called",
            "history.jsonl is auxiliary and never used to reconstruct provider messages",
            "missing usage/cost stays unknown and is never zero-filled",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(output_dir / "messages.jsonl", records)
    _write_json(output_dir / "manifest.json", manifest)
    (output_dir / "index.html").write_text(_render_html(records, manifest), encoding="utf-8")
    return manifest


def _read_action_file(
    store: ActionStore, action_id: str, field: str, anomalies: list[_Anomaly]
) -> Any:
    """Read one action file through the ActionStore read API, tolerating corruption.

    A missing file returns ``None`` without an anomaly; a present-but-unreadable
    file is reported instead of aborting the export.
    """

    path = {
        "request": store.request_path,
        "result": store.result_path,
        "commit": store.commit_path,
    }[field](action_id)
    if not path.is_file():
        return None
    try:
        reader = {
            "request": store.read_request,
            "result": store.read_result,
            "commit": store.read_commit,
        }[field]
        return reader(action_id)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        anomalies.append(
            _Anomaly(f"corrupt_{field}_file", action_id, None, f"{path.name}: {type(error).__name__}: {error}")
        )
        return None


def _build_action_record(
    store: ActionStore,
    action_id: str,
    ledger: list[tuple[int, dict[str, Any]]],
    method_events: list[tuple[int, dict[str, Any]]],
    planned_line: dict[str, int],
    planned_ts: dict[str, str],
    first_ledger_line: dict[str, int],
    first_method_line: dict[str, int],
    anomalies: list[_Anomaly],
) -> dict[str, Any]:
    action_dir = store.action_dir(action_id)
    request = _read_action_file(store, action_id, "request", anomalies)
    result = _read_action_file(store, action_id, "result", anomalies)
    commit = _read_action_file(store, action_id, "commit", anomalies)
    if request is None and not store.request_path(action_id).is_file():
        anomalies.append(_Anomaly("missing_request_file", action_id, None, "no request.json for action"))

    if isinstance(request, Mapping) and isinstance(request.get("action_id"), str) and request["action_id"] != action_id:
        anomalies.append(
            _Anomaly(
                "request_identity_conflict",
                action_id,
                None,
                f"request.json action_id={request.get('action_id')!r} differs from directory {action_id!r}",
            )
        )

    # -- order --------------------------------------------------------------- #
    if action_id in planned_line:
        order = {"basis": ORDER_ACTION_PLANNED, "value": planned_line[action_id], "ts": planned_ts.get(action_id, "")}
    elif action_id in first_ledger_line:
        order = {"basis": ORDER_LEDGER_FIRST_EVENT, "value": first_ledger_line[action_id], "ts": ""}
    elif action_id in first_method_line:
        order = {"basis": ORDER_METHOD_EVENTS, "value": first_method_line[action_id], "ts": ""}
    elif isinstance(request, Mapping) and request.get("created_at"):
        order = {"basis": ORDER_REQUEST_CREATED_AT, "value": str(request["created_at"]), "ts": str(request["created_at"])}
    else:
        order = {"basis": ORDER_NONE, "value": None, "ts": ""}
        anomalies.append(_Anomaly("no_ordering_evidence", action_id, None, "no plan/ledger/method/created_at ordering evidence"))

    # -- attempts (keyed by request_attempt_id) ------------------------------ #
    action_ledger = [(lineno, e) for lineno, e in ledger if e.get("action_id") == action_id]
    attempts = _build_attempts(store, action_id, action_ledger, anomalies)
    attempts.sort(key=_attempt_sort_key)

    # -- auxiliary history cross-reference ----------------------------------- #
    aux_history = _aux_history(store.run_dir, action_id)

    return {
        "action_id": action_id,
        "order": order,
        "request": request,
        "attempts": attempts,
        "result": result,
        "commit": commit,
        "aux_history": aux_history,
    }


def _build_attempts(
    store: ActionStore,
    action_id: str,
    action_ledger: list[tuple[int, dict[str, Any]]],
    anomalies: list[_Anomaly],
) -> list[dict[str, Any]]:
    attempts: dict[str, dict[str, Any]] = {}
    duplicate_events: dict[tuple[str, str], int] = {}

    def attempt_for(attempt_id: str) -> dict[str, Any]:
        return attempts.setdefault(
            attempt_id,
            {
                "request_attempt_id": attempt_id,
                "attempt_index": None,
                "first_ledger_line": None,
                "started": None,
                "failure": None,
                "response_event": None,
                "response_file_payload": None,
                "response": None,
                "classifications": [],
            },
        )

    def note_line(entry: dict[str, Any], lineno: int) -> None:
        if entry["first_ledger_line"] is None or lineno < entry["first_ledger_line"]:
            entry["first_ledger_line"] = lineno

    for lineno, event in action_ledger:
        event_type = event.get("event_type")
        payload = event.get("payload") or {}
        attempt_id = payload.get("request_attempt_id")
        if not isinstance(attempt_id, str):
            continue
        entry = attempt_for(attempt_id)
        note_line(entry, lineno)
        if entry["attempt_index"] is None and isinstance(payload.get("attempt_index"), int):
            entry["attempt_index"] = payload["attempt_index"]
        if event_type == ATTEMPT_STARTED:
            if entry["started"] is None:
                entry["started"] = {"line": lineno, "ts": str(event.get("ts") or ""), "attempt_index": payload.get("attempt_index")}
            else:
                duplicate_events[(attempt_id, ATTEMPT_STARTED)] = duplicate_events.get((attempt_id, ATTEMPT_STARTED), 1) + 1
        elif event_type == ATTEMPT_FAILED:
            failure = {
                "line": lineno,
                "ts": str(event.get("ts") or ""),
                "attempt_index": payload.get("attempt_index"),
                "error_type": payload.get("error_type"),
                "error_reason": payload.get("error_reason"),
                "retryable": payload.get("retryable"),
            }
            if entry["failure"] is None:
                entry["failure"] = failure
            else:
                duplicate_events[(attempt_id, ATTEMPT_FAILED)] = duplicate_events.get((attempt_id, ATTEMPT_FAILED), 1) + 1
        elif event_type == RESPONSE_SAVED:
            saved = {
                "line": lineno,
                "ts": str(event.get("ts") or ""),
                "attempt_index": payload.get("attempt_index"),
                "status": payload.get("status"),
                "content_sha256": payload.get("content_sha256"),
                "usage": payload.get("usage"),
                "cost": payload.get("cost"),
                "cache_hit": payload.get("cache_hit"),
            }
            if entry["response_event"] is None:
                entry["response_event"] = saved
                if entry["response"] is None:
                    entry["response"] = saved
            elif entry["response_event"].get("content_sha256") != saved.get("content_sha256"):
                anomalies.append(
                    _Anomaly(
                        CONFLICTING_EVENT,
                        action_id,
                        attempt_id,
                        "multiple response_saved events disagree on content_sha256",
                    )
                )
            else:
                duplicate_events[(attempt_id, RESPONSE_SAVED)] = duplicate_events.get((attempt_id, RESPONSE_SAVED), 1) + 1

    for key, count in duplicate_events.items():
        attempt_id, event_type = key
        anomalies.append(
            _Anomaly(
                DUPLICATE_EVENT,
                action_id,
                attempt_id,
                f"{event_type} repeated {count} extra time(s); not counted as extra attempts",
            )
        )

    # Merge the durable response files (the response file is written before the
    # response_saved event, so a file can exist without an event).
    responses_dir = store.responses_dir(action_id)
    for path in sorted(responses_dir.glob("*.json")) if responses_dir.is_dir() else []:
        payload = _load_json_safe(path, anomalies, action_id, "corrupt_response_file")
        attempt_id = _first(payload, "request_attempt_id")
        if not isinstance(attempt_id, str):
            anomalies.append(
                _Anomaly("corrupt_response_file", action_id, None, f"{path.name}: missing request_attempt_id")
            )
            continue
        entry = attempt_for(attempt_id)
        if entry["attempt_index"] is None and isinstance(_first(payload, "attempt_index"), int):
            entry["attempt_index"] = payload["attempt_index"]
        if isinstance(payload, Mapping) and payload.get("action_id") not in (None, action_id):
            anomalies.append(
                _Anomaly(
                    "response_identity_conflict",
                    action_id,
                    attempt_id,
                    f"{path.name} action_id={payload.get('action_id')!r} differs from {action_id!r}",
                )
            )
        entry["response_file_payload"] = dict(payload) if isinstance(payload, Mapping) else {}
        entry["response"] = {
            "file": path.name,
            "content_source": "response_file",
            **(dict(payload) if isinstance(payload, Mapping) else {}),
        }

    for entry in attempts.values():
        _classify_attempt(entry)

    # Cross-direction coverage, both ways.
    for attempt_id, entry in attempts.items():
        response_event = entry["response_event"]
        response_file = entry["response_file_payload"]
        if response_event is not None and response_file is None:
            entry["classifications"].append(MISSING_RESPONSE_FILE)
            anomalies.append(
                _Anomaly(MISSING_RESPONSE_FILE, action_id, attempt_id, "response_saved event without a response file")
            )
        if response_file is not None:
            if entry["started"] is None:
                # A response file with no attempt_started event is listed, not dropped.
                if MISSING_EVENTS not in entry["classifications"]:
                    entry["classifications"].append(MISSING_EVENTS)
                anomalies.append(
                    _Anomaly(
                        MISSING_EVENTS,
                        action_id,
                        attempt_id,
                        "response file without an attempt_started event",
                    )
                )
            if response_event is None:
                if RESPONSE_WITHOUT_EVENT not in entry["classifications"]:
                    entry["classifications"].append(RESPONSE_WITHOUT_EVENT)
                anomalies.append(
                    _Anomaly(RESPONSE_WITHOUT_EVENT, action_id, attempt_id, "response file without a response_saved event")
                )

    return list(attempts.values())


def _classify_attempt(entry: dict[str, Any]) -> None:
    has_failure = entry["failure"] is not None
    has_response = entry["response_file_payload"] is not None or entry["response_event"] is not None
    if has_failure and not has_response and FAILED_NO_RESPONSE not in entry["classifications"]:
        entry["classifications"].append(FAILED_NO_RESPONSE)
    if entry["started"] is not None and not has_failure and not has_response:
        if ORPHAN_ATTEMPT not in entry["classifications"]:
            entry["classifications"].append(ORPHAN_ATTEMPT)
    if has_failure and has_response and CONFLICTING_EVENT not in entry["classifications"]:
        entry["classifications"].append(CONFLICTING_EVENT)


def _aux_history(run_dir: Path, action_id: str) -> list[dict[str, Any]]:
    path = run_dir / "history.jsonl"
    if not path.is_file():
        return []
    rows, _anomalies = _read_jsonl_tolerant(path)
    matched: list[dict[str, Any]] = []
    for _lineno, row in rows:
        row_action = row.get("action_id")
        if not isinstance(row_action, str):
            continue
        if row_action == action_id or row_action.startswith(f"{action_id}-"):
            matched.append(row)
    return matched


def _counts_by(records: list[dict[str, Any]], key: Any) -> dict[str, int]:
    """Count records by a string-valued key function (used for ordering basis)."""

    counts: dict[str, int] = {}
    for record in records:
        value = key(record)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _counts(records: list[dict[str, Any]]) -> dict[str, Any]:
    attempt_count = 0
    started = 0
    failed = 0
    failed_retryable = 0
    failed_by_type: dict[str, int] = {}
    response_events = 0
    response_files = 0
    responses_by_status: dict[str, int] = {}
    commits = 0
    results = 0
    orphan = 0
    result_status_counts: dict[str, int] = {}
    for record in records:
        if record.get("commit") is not None:
            commits += 1
        if record.get("result") is not None:
            results += 1
            status = record["result"].get("status") if isinstance(record["result"], Mapping) else None
            if isinstance(status, str):
                result_status_counts[status] = result_status_counts.get(status, 0) + 1
        for attempt in record["attempts"]:
            attempt_count += 1
            if attempt.get("started") is not None:
                started += 1
            if attempt.get("failure") is not None:
                failed += 1
                if attempt["failure"].get("retryable"):
                    failed_retryable += 1
                error_type = attempt["failure"].get("error_type") or "unknown"
                failed_by_type[error_type] = failed_by_type.get(error_type, 0) + 1
            response = attempt.get("response_event")
            if response is not None:
                response_events += 1
            if attempt.get("response_file_payload") is not None:
                response_files += 1
            merged = attempt.get("response")
            if merged is not None:
                status = merged.get("status")
                if isinstance(status, str):
                    responses_by_status[status] = responses_by_status.get(status, 0) + 1
            if ORPHAN_ATTEMPT in attempt.get("classifications", []):
                orphan += 1
    return {
        "actions": len(records),
        "attempts": attempt_count,
        "attempt_started_events": started,
        "attempt_failed_events": failed,
        "attempt_failed_retryable": failed_retryable,
        "attempt_failed_by_error_type": dict(sorted(failed_by_type.items())),
        "response_saved_events": response_events,
        "response_files": response_files,
        "responses_by_status": dict(sorted(responses_by_status.items())),
        "actions_with_commit": commits,
        "actions_with_result": results,
        "result_status_counts": dict(sorted(result_status_counts.items())),
        "patch_outcome": {
            "committed": commits,
            "result_without_commit": results - commits,
            "no_result": len(records) - results,
        },
        "orphan_attempts": orphan,
    }


def _integrity_summary(records: list[dict[str, Any]], ledger_anomalies: list[_Anomaly]) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        for attempt in record["attempts"]:
            for classification in attempt.get("classifications", []):
                buckets.setdefault(classification, []).append(
                    {
                        "action_id": record["action_id"],
                        "request_attempt_id": attempt["request_attempt_id"],
                    }
                )
    return {
        "orphan_attempts": buckets.get(ORPHAN_ATTEMPT, []),
        "failed_attempts_no_response": buckets.get(FAILED_NO_RESPONSE, []),
        "responses_without_event": buckets.get(RESPONSE_WITHOUT_EVENT, []),
        "missing_response_files": buckets.get(MISSING_RESPONSE_FILE, []),
        "attempts_without_events": buckets.get(MISSING_EVENTS, []),
        "incomplete_ledger_tail": any(a.kind == "incomplete_ledger_tail" for a in ledger_anomalies),
    }


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(obj))


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        for record in records:
            handle.write(canonical_json_bytes(record) + b"\n")


def _render_html(records: list[dict[str, Any]], manifest: Mapping[str, Any]) -> str:
    escape = html.escape
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="zh"><head><meta charset="utf-8">')
    parts.append("<title>mutator message export</title>")
    parts.append(
        "<style>"
        "body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;margin:1.5rem;color:#1b1b1b}"
        "h1{font-size:1.4rem}h2{font-size:1.1rem;border-bottom:1px solid #ddd;padding-bottom:.3rem;margin-top:2rem}"
        "h3{font-size:.95rem;margin:.8rem 0 .3rem}"
        ".meta{color:#555;font-size:.85rem}"
        ".msg{margin:.3rem 0}.msg summary{cursor:pointer;font-weight:600}"
        "pre{white-space:pre-wrap;word-break:break-word;background:#f6f6f6;padding:.6rem;border-radius:4px;overflow-x:auto}"
        ".bad{color:#a00}.warn{color:#a60}.ok{color:#070}"
        "table{border-collapse:collapse;font-size:.85rem}td,th{border:1px solid #ddd;padding:.25rem .5rem;text-align:left}"
        "</style></head><body>"
    )
    counts = manifest.get("counts", {})
    parts.append("<h1>Mutator message export</h1>")
    parts.append(
        f'<p class="meta">run: {escape(str(manifest.get("run_dir")))}<br>'
        f'exported: {escape(str(manifest.get("exported_at")))} · schema {escape(str(manifest.get("schema_version")))}<br>'
        f'export_complete={escape(str(manifest.get("export_complete")))} · '
        f'sources_unchanged={escape(str(manifest.get("sources_unchanged_during_export")))}</p>'
    )
    parts.append("<h2>Counts</h2><table><tr><th>key</th><th>value</th></tr>")
    for key, value in counts.items():
        parts.append(f"<tr><td>{escape(str(key))}</td><td>{escape(json.dumps(value, ensure_ascii=False))}</td></tr>")
    parts.append("</table>")
    integrity = manifest.get("integrity", {})
    parts.append("<h2>Integrity</h2><ul>")
    for key, value in integrity.items():
        css = "ok" if (value in (False, [], 0)) else "warn"
        parts.append(f'<li class="{css}">{escape(str(key))}: {escape(json.dumps(value, ensure_ascii=False))}</li>')
    parts.append("</ul>")

    for record in records:
        action_id = record["action_id"]
        order = record["order"]
        parts.append(f'<h2 id="{escape(action_id)}">{escape(action_id)}</h2>')
        request = record.get("request") or {}
        role = request.get("role")
        kind = request.get("kind")
        parts.append(
            f'<p class="meta">order #{escape(str(order.get("index")))} · basis {escape(str(order.get("basis")))} '
            f'· value {escape(str(order.get("value")))} · role {escape(str(role))} · kind {escape(str(kind))}</p>'
        )
        if record.get("result") is not None:
            parts.append('<h3>Result</h3><pre>' + escape(json.dumps(record["result"], ensure_ascii=False, indent=2)) + "</pre>")
        if record.get("commit") is not None:
            parts.append('<h3>Commit</h3><pre>' + escape(json.dumps(record["commit"], ensure_ascii=False, indent=2)) + "</pre>")
        parts.append("<h3>Messages (request)</h3>")
        messages = request.get("messages") if isinstance(request, Mapping) else None
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                msg_role = message.get("role") if isinstance(message, Mapping) else "?"
                content = message.get("content") if isinstance(message, Mapping) else ""
                label = f"#{index + 1} {msg_role} ({len(content)} chars)"
                body = escape(content) if content else "(empty)"
                parts.append(f'<details class="msg"><summary>{escape(label)}</summary><pre>{body}</pre></details>')
        else:
            parts.append('<p class="bad">no request messages saved</p>')
        parts.append("<h3>Attempts</h3>")
        for attempt in record["attempts"]:
            attempt_id = attempt["request_attempt_id"]
            classes = ", ".join(attempt.get("classifications", [])) or "none"
            parts.append(
                f'<p class="meta"><b>{escape(attempt_id)}</b> · attempt_index {escape(str(attempt.get("attempt_index")))} '
                f'· classifications: {escape(classes)}</p>'
            )
            if attempt.get("failure") is not None:
                parts.append('<pre class="bad">' + escape(json.dumps(attempt["failure"], ensure_ascii=False, indent=2)) + "</pre>")
            response = attempt.get("response")
            if response is not None:
                content = response.get("content")
                header = {
                    "status": response.get("status"),
                    "finish_reason": response.get("finish_reason"),
                    "usage": response.get("usage"),
                    "cost": response.get("cost"),
                    "content_sha256": response.get("content_sha256"),
                    "cache_hit": response.get("cache_hit"),
                }
                parts.append('<pre>' + escape(json.dumps(header, ensure_ascii=False, indent=2)) + "</pre>")
                if isinstance(content, str) and content:
                    parts.append(
                        f'<details class="msg"><summary>response content ({len(content)} chars)</summary>'
                        f"<pre>{escape(content)}</pre></details>"
                    )
                else:
                    parts.append('<p class="meta">response content: (empty/truncated)</p>')
                if response.get("file"):
                    parts.append(f'<p class="meta">response file: {escape(str(response["file"]))}</p>')
        if record.get("aux_history"):
            parts.append("<h3>Auxiliary history rows (not provider messages)</h3>")
            for row in record["aux_history"]:
                parts.append("<pre>" + escape(json.dumps(row, ensure_ascii=False, indent=2)) + "</pre>")

    parts.append("</body></html>")
    return "\n".join(parts)


__all__ = [
    "EXPORT_SCHEMA_VERSION",
    "MessageExportError",
    "export_mutator_messages",
]
