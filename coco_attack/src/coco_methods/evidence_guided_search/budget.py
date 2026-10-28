"""Lightweight stage budget and read-only consumption aggregation.

The budget keeps only reservations and their settlement facts in one small JSON
file.  It is intentionally not a scheduler: callers reserve the request attempts
they are about to dispatch and later settle the known attempt count (or leave it
unknown).  A phase never borrows another phase's allocation.

``summarize_consumption`` re-reads the existing public ledgers instead of
copying their raw events.  It keeps new responses, cache references, API
attempts, failures/retries and known/unknown token and cost facts separate so
an unknown attempt is never reported as zero.
"""

from __future__ import annotations

import math
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping

from coco_attack.assets.artifacts import iter_jsonl, read_json, write_json_atomic
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.runtime.ledger import Ledger

__all__ = [
    "Budget",
    "BudgetError",
    "BudgetConflictError",
    "PHASES",
    "summarize_consumption",
]

PHASES = ("reference", "search", "retest")
_BUDGET_SCHEMA = "egs-budget-v1"
_STATE_RESERVED = "reserved"
_STATE_SETTLED = "settled"
_STATE_UNKNOWN = "unknown"

_ACTION_EVENT_TYPES = {"attempt_started", "attempt_failed", "response_saved"}
_LEDGER_ATTEMPT_EVENTS = {"attempt_started", "attempt_failed", "response_received"}


class BudgetError(ValueError):
    """The budget state or a budget operation is invalid."""


class BudgetConflictError(BudgetError):
    """A key or allocation was reused with different input."""


# A process-local lock per budget path.  Two Budget instances for the same file
# therefore serialize their read/modify/write cycles instead of losing a
# reservation.  The state write itself is atomic (temp file + replace).
_LOCKS: dict[Path, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.RLock:
    resolved = path.resolve()
    with _LOCKS_GUARD:
        lock = _LOCKS.get(resolved)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[resolved] = lock
        return lock


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_allocations(allocations: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(allocations, Mapping):
        raise BudgetError("allocations must be a mapping")
    result: dict[str, int] = {}
    for phase, amount in allocations.items():
        if phase not in PHASES:
            raise BudgetError(f"unknown budget phase: {phase!r}")
        if not _is_int(amount) or amount < 0:
            raise BudgetError(f"allocation for {phase!r} must be a non-negative integer")
        result[phase] = amount
    return {phase: result.get(phase, 0) for phase in PHASES}


def _empty_state(allocations: Mapping[str, int]) -> dict[str, Any]:
    return {
        "schema_version": _BUDGET_SCHEMA,
        "allocations": dict(allocations),
        "entries": {},
    }


def _validate_entry(key: Any, entry: Any, allocations: Mapping[str, int]) -> dict[str, Any]:
    if not isinstance(key, str) or not key:
        raise BudgetError("budget entry key must be a non-empty string")
    if not isinstance(entry, dict):
        raise BudgetError(f"budget entry {key!r} is not an object")
    phase = entry.get("phase")
    if phase not in allocations:
        raise BudgetError(f"budget entry {key!r} has an undeclared phase")
    amount = entry.get("amount")
    if not _is_int(amount) or amount <= 0:
        raise BudgetError(f"budget entry {key!r} has an invalid reservation amount")
    status = entry.get("status")
    actual = entry.get("actual")
    if status == _STATE_RESERVED:
        if actual is not None:
            raise BudgetError(f"unsettled budget entry {key!r} has an actual count")
    elif status == _STATE_SETTLED:
        if not _is_int(actual) or actual < 0:
            raise BudgetError(f"settled budget entry {key!r} has no valid actual count")
    elif status == _STATE_UNKNOWN:
        if actual is not None:
            raise BudgetError(f"unknown budget entry {key!r} has an actual count")
    else:
        raise BudgetError(f"budget entry {key!r} has an invalid status")
    return {
        "phase": phase,
        "amount": amount,
        "status": status,
        "actual": actual,
    }


class Budget:
    """Stage allocation with atomic reservations and explicit settlement."""

    def __init__(self, path: Path | str, allocations: Mapping[str, int]) -> None:
        self.path = Path(path)
        self.allocations = _validate_allocations(allocations)
        self._lock = _lock_for(self.path)
        # Fail early on an existing state written with different allocations or
        # on a corrupt file; construction still never creates the file.
        with self._lock:
            self._load()

    # -- persistence ------------------------------------------------------- #

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return _empty_state(self.allocations)
        try:
            state = read_json(self.path)
        except (OSError, ValueError) as exc:
            raise BudgetError(f"cannot read budget state {self.path}: {exc}") from exc
        if not isinstance(state, dict):
            raise BudgetError(f"budget state {self.path} is not an object")
        if state.get("schema_version") != _BUDGET_SCHEMA:
            raise BudgetError(f"unsupported budget schema in {self.path}")
        stored = state.get("allocations")
        if stored != self.allocations:
            raise BudgetConflictError(
                f"budget allocations differ for {self.path}: "
                f"stored={stored!r} requested={self.allocations!r}"
            )
        entries = state.get("entries")
        if not isinstance(entries, dict):
            raise BudgetError(f"budget entries in {self.path} are not an object")
        return {
            "schema_version": _BUDGET_SCHEMA,
            "allocations": dict(self.allocations),
            "entries": {
                key: _validate_entry(key, entry, self.allocations)
                for key, entry in entries.items()
            },
        }

    def _save(self, state: dict[str, Any]) -> None:
        write_json_atomic(self.path, state)

    @staticmethod
    def _phase_usage(
        entries: Mapping[str, dict[str, Any]], phase: str
    ) -> tuple[int, int, int, int]:
        known_used = 0
        unknown_occupied = 0
        inflight = 0
        unknown_count = 0
        for entry in entries.values():
            if entry["phase"] != phase:
                continue
            if entry["status"] == _STATE_RESERVED:
                inflight += entry["amount"]
            elif entry["status"] == _STATE_SETTLED:
                known_used += entry["actual"]
            else:
                unknown_occupied += entry["amount"]
                unknown_count += 1
        return known_used, unknown_occupied, inflight, unknown_count

    # -- public operations ------------------------------------------------- #

    def reserve(self, key: str, phase: str, amount: int) -> bool:
        """Reserve ``amount`` attempts for ``key`` in ``phase`` if it fits.

        Repeating the same ``(key, phase, amount)`` is a no-op success.  Reusing
        a key with a different phase or amount is a conflict rather than a
        second reservation.  Failure to fit returns ``False`` and leaves no
        partial reservation.
        """

        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        if phase not in self.allocations:
            raise ValueError(f"unknown budget phase: {phase!r}")
        if not _is_int(amount) or amount <= 0:
            raise ValueError("amount must be a positive integer")
        with self._lock:
            state = self._load()
            existing = state["entries"].get(key)
            if existing is not None:
                if existing["phase"] != phase or existing["amount"] != amount:
                    raise BudgetConflictError(
                        f"budget key {key!r} already reserved with different input"
                    )
                return True
            used, unknown_occupied, inflight, _ = self._phase_usage(
                state["entries"], phase
            )
            if used + unknown_occupied + inflight + amount > self.allocations[phase]:
                return False
            state["entries"][key] = {
                "phase": phase,
                "amount": amount,
                "status": _STATE_RESERVED,
                "actual": None,
            }
            self._save(state)
            return True

    def settle(self, key: str, actual: int | None) -> None:
        """Settle one reservation.

        A known ``actual`` attempt count releases the unused reservation.  An
        unknown outcome (``None``) keeps the whole reservation occupied and is
        marked unknown; it is never treated as zero.  Repeating the same
        settlement is idempotent, an unknown outcome may later be clarified to
        a known count, but an already known count cannot change.
        """

        if actual is not None and (not _is_int(actual) or actual < 0):
            raise ValueError("actual must be a non-negative integer or None")
        with self._lock:
            state = self._load()
            entry = state["entries"].get(key)
            if entry is None:
                raise BudgetError(f"budget key {key!r} has no reservation")
            if entry["status"] == _STATE_SETTLED:
                if actual is None or actual != entry["actual"]:
                    raise BudgetConflictError(
                        f"budget key {key!r} already has a different known actual"
                    )
                return
            if entry["status"] == _STATE_UNKNOWN and actual is None:
                return
            if actual is None:
                entry["status"] = _STATE_UNKNOWN
                entry["actual"] = None
            else:
                entry["status"] = _STATE_SETTLED
                entry["actual"] = actual
            self._save(state)

    def summary(self) -> dict[str, Any]:
        """Return allocations with known, unknown and in-flight occupancy split."""

        with self._lock:
            state = self._load()
        entries = state["entries"]
        phases: dict[str, dict[str, Any]] = {}
        total = {
            "allocated": 0,
            "used": 0,
            "known_used": 0,
            "unknown_occupied": 0,
            "reserved": 0,
            "available": 0,
            "unknown": 0,
            "overage": 0,
        }
        for phase in PHASES:
            allocated = self.allocations[phase]
            known_used, unknown_occupied, inflight, unknown = self._phase_usage(
                entries, phase
            )
            occupied = known_used + unknown_occupied + inflight
            available = allocated - occupied
            phases[phase] = {
                "allocated": allocated,
                "used": known_used,
                "known_used": known_used,
                "unknown_occupied": unknown_occupied,
                "reserved": inflight,
                "available": available,
                "unknown": unknown,
                "overage": max(0, occupied - allocated),
                "entries": sum(1 for entry in entries.values() if entry["phase"] == phase),
            }
            total["allocated"] += allocated
            total["used"] += known_used
            total["known_used"] += known_used
            total["unknown_occupied"] += unknown_occupied
            total["reserved"] += inflight
            total["available"] += available
            total["unknown"] += unknown
            total["overage"] += max(0, occupied - allocated)
        return {"path": str(self.path), "allocations": dict(self.allocations),
                "phases": phases, "total": total}


# --------------------------------------------------------------------------- #
# Consumption aggregation
# --------------------------------------------------------------------------- #


def _sniff_kind(path: Path) -> str | None:
    try:
        for _lineno, event in iter_jsonl(path):
            if isinstance(event.get("action_id"), str):
                return "actions"
            if "seq" in event or "sample_id" in event:
                return "ledger"
            return None
    except (OSError, ValueError):
        return None
    return None


def _file_kind(path: Path) -> str | None:
    if path.name == "actions.jsonl":
        return "actions"
    if path.name == "ledger.jsonl" or path.name.endswith("ledger.jsonl"):
        return "ledger"
    return _sniff_kind(path)


def _expanded_sources(paths: Iterable[str]) -> list[tuple[str, Path, str | None]]:
    expanded: list[tuple[str, Path, str | None]] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates: list[tuple[Path, str]] = []
            action_path = path / "actions.jsonl"
            ledger_path = path / "ledger.jsonl"
            if action_path.is_file():
                candidates.append((action_path, "actions"))
            if ledger_path.is_file():
                candidates.append((ledger_path, "ledger"))
            if candidates:
                for candidate, kind in candidates:
                    expanded.append((str(raw), candidate.resolve(), kind))
            else:
                expanded.append((str(raw), path.resolve(), None))
        else:
            expanded.append((str(raw), path.resolve(), _file_kind(path) if path.is_file() else None))
    return expanded


def _read_events(path: Path, kind: str) -> list[dict[str, Any]]:
    if kind == "actions" and path.name == "actions.jsonl":
        return ActionStore(path.parent).events()
    if kind == "actions":
        return [event for _lineno, event in iter_jsonl(path)]
    # Ledger replay is the public reader; it never appends or rewrites facts.
    return list(Ledger(path).replay().events)


def _token_total(usage: Any) -> int | None:
    if not isinstance(usage, dict) or not usage:
        return None
    total = usage.get("total_tokens")
    if _is_int(total):
        return total
    for prompt_key, completion_key in (
        ("prompt_tokens", "completion_tokens"),
        ("input_tokens", "output_tokens"),
    ):
        prompt = usage.get(prompt_key)
        completion = usage.get(completion_key)
        if _is_int(prompt) and _is_int(completion):
            return prompt + completion
    return None


def _cost_amount(cost: Any) -> tuple[float, str] | None:
    if not isinstance(cost, dict):
        return None
    amount = cost.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return None
    value = float(amount)
    if not math.isfinite(value):
        return None
    currency = cost.get("currency")
    return value, currency if isinstance(currency, str) and currency else "unspecified"


def summarize_consumption(paths: list[str]) -> dict[str, Any]:
    """Aggregate victim ledger and role-action consumption read-only.

    Each input may name a ledger JSONL file, an ``actions.jsonl`` file, or a
    directory containing either.  Events are deduplicated by resolved file path
    plus ``request_attempt_id``.  Cache hits are reported separately and are not
    counted as new API attempts, tokens or cost.  Missing, unreadable or
    unrecognised inputs stay in ``sources``/``unresolved`` with their raw refs.
    """

    expanded = _expanded_sources(paths)
    sources: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    for raw, canonical, kind in expanded:
        key = str(canonical)
        source = by_path.get(key)
        if source is None:
            source = {
                "refs": [],
                "path": key,
                "kind": kind,
                "status": "unknown",
                "events": 0,
                "error": None,
                "_raw_events": [],
            }
            by_path[key] = source
            sources.append(source)
        if raw not in source["refs"]:
            source["refs"].append(raw)
        if source["kind"] is None and kind is not None:
            source["kind"] = kind

    for source in sources:
        path = Path(source["path"])
        kind = source["kind"]
        if not path.exists():
            source["status"] = "missing"
            source["error"] = "path does not exist"
            continue
        if kind is None:
            source["status"] = "unrecognized"
            source["error"] = "path is neither a ledger nor an action event file"
            continue
        try:
            events = _read_events(path, kind)
        except (OSError, ValueError) as exc:
            source["status"] = "unreadable"
            source["error"] = f"{type(exc).__name__}: {exc}"
            continue
        source["status"] = "ok"
        source["events"] = len(events)
        source["_raw_events"] = events

    attempts_total = 0
    api_attempts = 0
    new_responses = 0
    cache_references = 0
    failed_attempts = 0
    retry_attempts = 0
    api_retries = 0
    cache_retries = 0
    unknown_outcomes = 0
    tokens_known = 0
    token_attempts_known = 0
    token_attempts_unknown = 0
    cost_known: dict[str, float] = {}
    cost_entries_known = 0
    cost_attempts_unknown = 0
    unresolved: list[dict[str, Any]] = []

    for source in sources:
        if source["status"] != "ok":
            for ref in source["refs"]:
                unresolved.append({
                    "ref": ref,
                    "reason": source["status"],
                    "detail": source["error"],
                })
            continue
        seen: dict[str, dict[str, Any]] = {}
        for event in source["_raw_events"]:
            event_type = event.get("event_type")
            if event_type not in _LEDGER_ATTEMPT_EVENTS | _ACTION_EVENT_TYPES:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                payload = {}
            attempt_id = event.get("request_attempt_id")
            if not isinstance(attempt_id, str) or not attempt_id:
                attempt_id = payload.get("request_attempt_id")
            if not isinstance(attempt_id, str) or not attempt_id:
                attempt_id = event.get("event_id") or f"seq:{event.get('seq')}"
            record = seen.setdefault(attempt_id, {
                "index": 0, "started": False, "response": None, "failed": None,
            })
            index = payload.get("attempt_index")
            if _is_int(index) and index >= 0:
                record["index"] = index
            if event_type == "attempt_started":
                record["started"] = True
            elif event_type in ("response_received", "response_saved"):
                record["response"] = payload
            elif event_type == "attempt_failed":
                record["failed"] = payload

        for attempt_id, record in seen.items():
            attempts_total += 1
            if record["index"] > 0:
                retry_attempts += 1
            response = record["response"]
            failed = record["failed"]
            cache_hit = bool(response is not None and response.get("cache_hit") is True)
            if record["index"] > 0:
                if cache_hit:
                    cache_retries += 1
                else:
                    api_retries += 1
            if cache_hit:
                cache_references += 1
            else:
                api_attempts += 1
            if response is not None and not cache_hit:
                new_responses += 1
            if failed is not None:
                failed_attempts += 1
            if response is None and failed is None:
                unknown_outcomes += 1
                unresolved.append({
                    "ref": source["path"],
                    "request_attempt_id": attempt_id,
                    "reason": "attempt_without_terminal",
                })
            if response is not None and failed is not None:
                unresolved.append({
                    "ref": source["path"],
                    "request_attempt_id": attempt_id,
                    "reason": "multiple_terminal_events",
                })
            if cache_hit:
                # Reused facts belong to the response that first paid for them.
                continue
            fact = response if response is not None else failed
            usage = fact.get("usage") if isinstance(fact, dict) else None
            tokens = _token_total(usage)
            if tokens is None:
                token_attempts_unknown += 1
            else:
                tokens_known += tokens
                token_attempts_known += 1
            cost = _cost_amount(fact.get("cost")) if isinstance(fact, dict) else None
            if cost is None:
                cost_attempts_unknown += 1
            else:
                amount, currency = cost
                cost_known[currency] = cost_known.get(currency, 0.0) + amount
                cost_entries_known += 1

    clean_sources = [
        {
            "refs": list(source["refs"]),
            "path": source["path"],
            "kind": source["kind"],
            "status": source["status"],
            "events": source["events"],
            "error": source["error"],
        }
        for source in sources
    ]
    return {
        "schema_version": "egs-consumption-v1",
        "sources": clean_sources,
        "attempts": {
            "total": attempts_total,
            "api": api_attempts,
            "new_responses": new_responses,
            "cache_references": cache_references,
            "failed": failed_attempts,
            "retries": retry_attempts,
            "api_retries": api_retries,
            "cache_retries": cache_retries,
            "sample_retries": None,
            "sample_retry_basis": "not separately recorded by the public ledgers",
            "unknown_outcomes": unknown_outcomes,
        },
        "tokens": {
            "known": tokens_known,
            "known_attempts": token_attempts_known,
            "unknown_attempts": token_attempts_unknown,
        },
        "cost": {
            "known": dict(sorted(cost_known.items())),
            "known_entries": cost_entries_known,
            "unknown_attempts": cost_attempts_unknown,
        },
        "unresolved": unresolved,
    }
