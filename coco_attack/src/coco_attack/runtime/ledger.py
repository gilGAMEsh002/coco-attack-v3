"""Single-writer, append-only request ledger (plan section 8).

The ledger is the audit source of truth for model generation.  Exactly one
writer (the coordinator) appends newline-delimited JSON events; each append is
flushed and ``fsync``-ed before the event is considered durable.  Where
``generations.jsonl`` is a rebuildable projection, the ledger keeps the first
response/usage/cost facts even when a later export step is interrupted.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..assets.artifacts import canonical_json_bytes

LEDGER_SCHEMA_VERSION = "1"

EVENT_ATTEMPT_STARTED = "attempt_started"
EVENT_RESPONSE_RECEIVED = "response_received"
EVENT_ATTEMPT_FAILED = "attempt_failed"
EVENT_SAMPLE_FINALIZED = "sample_finalized"
EVENT_RUN_PAUSED = "run_paused"
EVENT_EXECUTION_RECORDED = "execution_recorded"

KNOWN_EVENT_TYPES = (
    EVENT_ATTEMPT_STARTED,
    EVENT_RESPONSE_RECEIVED,
    EVENT_ATTEMPT_FAILED,
    EVENT_SAMPLE_FINALIZED,
    EVENT_RUN_PAUSED,
    EVENT_EXECUTION_RECORDED,
)


class LedgerError(ValueError):
    """Raised when the ledger cannot be read or written safely."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class LedgerReplay:
    events: tuple[dict[str, Any], ...]
    incomplete_tail_path: str | None = None
    # Byte offset of the end of the last complete record.  When a torn final
    # record was found this is the length of the valid prefix; the writer must
    # truncate to it before appending so the new event is not concatenated onto
    # the corrupt tail.
    valid_prefix_bytes: int | None = None

    def finalized_sample_ids(self) -> set[str]:
        return {
            str(event["sample_id"])
            for event in self.events
            if event.get("event_type") == EVENT_SAMPLE_FINALIZED and event.get("sample_id")
        }

    def first_usage_by_sample(self) -> dict[str, dict[str, Any]]:
        """First durable usage/cost facts per sample, keyed by sample id."""

        usage: dict[str, dict[str, Any]] = {}
        for event in self.events:
            if event.get("event_type") != EVENT_RESPONSE_RECEIVED:
                continue
            sample_id = event.get("sample_id")
            if sample_id and sample_id not in usage:
                usage[str(sample_id)] = dict(event.get("payload") or {})
        return usage

    def finalized_records(self) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        for event in self.events:
            if event.get("event_type") != EVENT_SAMPLE_FINALIZED:
                continue
            sample_id = event.get("sample_id")
            record = (event.get("payload") or {}).get("record")
            if sample_id and isinstance(record, dict):
                records[str(sample_id)] = record
        return records

    def responses_by_sample(self) -> dict[str, tuple[dict[str, Any], str | None]]:
        """Latest durable response payload and attempt id per sample.

        A crash can leave a ``response_received`` event without its
        ``sample_finalized`` counterpart.  The response bytes, usage and cost
        are already durable, so recovery can rebuild the record locally instead
        of re-issuing the request.  When several responses exist the last one
        wins; earlier attempts remain in the ledger for cumulative accounting.
        """

        responses: dict[str, tuple[dict[str, Any], str | None]] = {}
        for event in self.events:
            if event.get("event_type") != EVENT_RESPONSE_RECEIVED:
                continue
            sample_id = event.get("sample_id")
            if sample_id:
                responses[str(sample_id)] = (
                    dict(event.get("payload") or {}),
                    event.get("request_attempt_id"),
                )
        return responses


class Ledger:
    """Append-only ledger with a process-local single writer."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq = 0
        replay = self.replay()
        self._seq = max((int(event.get("seq", 0)) for event in replay.events), default=0)
        # A torn final record is preserved in the ``.tail`` sidecar by
        # ``replay``; the writer repairs (truncates) the valid prefix on the
        # first append so recovery never concatenates onto corrupt bytes.
        self._pending_repair_bytes = replay.valid_prefix_bytes

    def append(
        self,
        event_type: str,
        *,
        sample_id: str | None = None,
        request_attempt_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if event_type not in KNOWN_EVENT_TYPES:
            raise LedgerError(f"unknown ledger event type: {event_type!r}")
        with self._lock:
            self._seq += 1
            event: dict[str, Any] = {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "event_id": uuid.uuid4().hex,
                "seq": self._seq,
                "ts": _utc_now(),
                "event_type": event_type,
                "sample_id": sample_id,
                "request_attempt_id": request_attempt_id,
                "payload": payload or {},
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self._pending_repair_bytes is not None:
                self._repair_torn_tail(self._pending_repair_bytes)
                self._pending_repair_bytes = None
            with open(self.path, "ab") as handle:
                if self._needs_separator():
                    handle.write(b"\n")
                handle.write(canonical_json_bytes(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return event

    def _needs_separator(self) -> bool:
        """True when the ledger ends with a complete record lacking a newline.

        A crash can leave a fully flushed JSON record whose trailing newline
        never reached disk.  Appending directly would concatenate the new event
        onto it; a leading newline keeps both records separate.
        """

        if not self.path.is_file():
            return False
        with open(self.path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                return False
            handle.seek(-1, os.SEEK_END)
            return handle.read(1) != b"\n"

    def _repair_torn_tail(self, valid_prefix_bytes: int) -> None:
        """Drop a torn final record after its bytes were preserved in ``.tail``."""

        with open(self.path, "r+b") as handle:
            handle.truncate(valid_prefix_bytes)
            handle.flush()
            os.fsync(handle.fileno())

    def replay(self) -> LedgerReplay:
        if not self.path.is_file():
            return LedgerReplay(events=())
        data = self.path.read_bytes()
        lines = data.split(b"\n")
        ends_with_newline = data.endswith(b"\n")
        # A trailing newline yields a final empty element which is not a record.
        if ends_with_newline:
            lines = lines[:-1]
        events: list[dict[str, Any]] = []
        incomplete_tail: str | None = None
        valid_prefix_bytes: int | None = None
        offset = 0
        for index, raw in enumerate(lines):
            line_start = offset
            has_newline = index < len(lines) - 1 or ends_with_newline
            offset = line_start + len(raw) + (1 if has_newline else 0)
            is_last = index == len(lines) - 1
            if not raw.strip():
                # Blank separator lines are tolerated; a trailing all-whitespace
                # fragment with no newline is an incomplete tail.
                if is_last and raw and not has_newline:
                    tail_path = self.path.with_name(self.path.name + ".tail")
                    tail_path.write_bytes(raw)
                    incomplete_tail = str(tail_path)
                    valid_prefix_bytes = line_start
                    break
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                if is_last:
                    # Only a torn final record is tolerated; its raw bytes are
                    # preserved so the caller can inspect or repair them.
                    tail_path = self.path.with_name(self.path.name + ".tail")
                    tail_path.write_bytes(raw)
                    incomplete_tail = str(tail_path)
                    valid_prefix_bytes = line_start
                    break
                raise LedgerError(
                    f"ledger corruption before the final record at line {index + 1}: {error}"
                ) from error
            if not isinstance(event, dict):
                raise LedgerError(f"ledger line {index + 1} is not a JSON object")
            if "event_id" not in event or "event_type" not in event:
                raise LedgerError(f"ledger line {index + 1} is missing event identity")
            events.append(event)
        return LedgerReplay(
            events=tuple(events),
            incomplete_tail_path=incomplete_tail,
            valid_prefix_bytes=valid_prefix_bytes,
        )

    def read_events(self) -> Iterable[dict[str, Any]]:
        return self.replay().events
