"""Role model calls, durable action state, patch post-processing and history (I2/I4/I5).

This module is the task-04 common service.  It gives a method layer the
primitives it needs to drive a multi-turn mutator conversation without the
common layer knowing anything about A/B stages, gates or iteration counts:

* ``RoleCallConfig`` / ``RoleCallSource`` -- a messages-based model call with an
  explicit role, sampling and protocol identity.  The mock source exercises the
  exact same persistence/audit boundary as the real DMX source.
* ``ActionStore`` -- an append-only action log plus atomic per-action files.  The
  request (including the *actual* messages) is persisted before the provider is
  contacted; the raw response, finish reason, response id, usage and cost are
  persisted before any parsing/applying/projection.
* ``run_role_call`` -- drives plan -> attempt(s) -> response persistence and
  refuses to call the provider again when a durable response already exists.
  An ``attempt_started`` with no durable response is reported as ``unknown``
  (no silent retry, no zero cost).
* ``parse_sparse_patch`` / ``commit_mutator_result`` -- patch parsing is pure
  post-processing; an invalid/out-of-range patch is recorded as a failure and
  never triggers a second "repair" request.
* ``HistoryStore`` / ``assemble_history`` -- deterministic shared-history
  assembly with token metering and compression of old interaction units.

The layer deliberately does not import the method modules; the caller supplies
roles, allowed fields, labels and method state.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from ..assets.artifacts import (
    append_jsonl,
    canonical_json_bytes,
    iter_jsonl,
    read_json,
    sha256_bytes,
    stable_json_bytes,
    write_json_atomic,
)
from ..generation.source import (
    DMX_BASE,
    ExtractedResponse,
    ResponseContractError,
    extract_response,
    is_retryable,
)
from ..runtime.limits import estimate_tokens
from .template_snapshot import (
    PatchPolicy,
    PatchResult,
    TemplateSnapshot,
    TemplateSnapshotError,
    apply_patch,
    write_snapshot,
)

ACTION_SCHEMA_VERSION = "action-runtime-v1"
HISTORY_SCHEMA_VERSION = "action-history-v1"
ROLE_SOURCE_CHOICES = ("mock", "dmx")

ACTION_PLANNED = "action_planned"
ATTEMPT_STARTED = "attempt_started"
ATTEMPT_FAILED = "attempt_failed"
RESPONSE_SAVED = "response_saved"
POSTPROCESS_DONE = "postprocess_done"
POSTPROCESS_FAILED = "postprocess_failed"
ACTION_COMMITTED = "action_committed"

#: Response statuses mirror the victim generation status vocabulary so the same
#: "empty/truncated/invalid never becomes success" rule holds here.
RESPONSE_STATUSES = ("success", "empty", "truncated", "invalid_response", "error")

#: Outcome states of one role call.
STATE_RESPONSE_REUSED = "response_reused"
STATE_RESPONSE_SAVED = "response_saved"
STATE_UNKNOWN_PAUSED = "unknown_paused"
STATE_FAILED = "failed"


class ActionRuntimeError(ValueError):
    """Raised when an action cannot be planned, executed or committed."""


class ActionConflictError(ActionRuntimeError):
    """Same action_id was reused with different request content."""


class ContextAssemblyError(ActionRuntimeError):
    """The fixed block cannot fit the configured context budget."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [row for _lineno, row in iter_jsonl(path)]


# --------------------------------------------------------------------------- #
# Role call configuration and sources
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RoleCallConfig:
    """Sampling/output identity for one role call.

    This is deliberately *not* a ``GenerationConfig``: a mutator/reasoning call
    has no victim task, sample or combination, so it must not fake one.
    """

    role: str
    model: str
    source: str = "mock"
    temperature: float = 0.7
    max_tokens: int = 8192
    request_timeout: float = 60.0
    max_request_attempts: int = 2
    api_base: str = DMX_BASE
    price_input_per_1k: float | None = None
    price_output_per_1k: float | None = None
    currency: str = "USD"
    pricing_version: str = "unset"
    mock_scenario: str = "normal"
    protocol_version: str = "1"

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not self.role:
            raise ActionRuntimeError("config.role must be a non-empty string")
        if self.source not in ROLE_SOURCE_CHOICES:
            raise ActionRuntimeError(f"config.source must be one of {ROLE_SOURCE_CHOICES}")
        if not isinstance(self.model, str) or not self.model:
            raise ActionRuntimeError("config.model must be a non-empty string")
        if isinstance(self.temperature, bool) or not isinstance(self.temperature, (int, float)):
            raise ActionRuntimeError("config.temperature must be a number")
        if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, int) or self.max_tokens < 1:
            raise ActionRuntimeError("config.max_tokens must be a positive integer")
        if isinstance(self.request_timeout, bool) or not isinstance(self.request_timeout, (int, float)) or self.request_timeout <= 0:
            raise ActionRuntimeError("config.request_timeout must be a positive number")
        if isinstance(self.max_request_attempts, bool) or not isinstance(self.max_request_attempts, int) or self.max_request_attempts < 1:
            raise ActionRuntimeError("config.max_request_attempts must be a positive integer")

    def to_json(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "model": self.model,
            "source": self.source,
            "temperature": float(self.temperature),
            "max_tokens": self.max_tokens,
            "request_timeout": float(self.request_timeout),
            "max_request_attempts": self.max_request_attempts,
            "api_base": self.api_base,
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "currency": self.currency,
            "pricing_version": self.pricing_version,
            "mock_scenario": self.mock_scenario,
            "protocol_version": self.protocol_version,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "RoleCallConfig":
        allowed = set(cls.__dataclass_fields__)
        extra = sorted(set(payload) - allowed)
        if extra:
            raise ActionRuntimeError(f"role call config has unknown fields: {extra}")
        return cls(**dict(payload))

    def config_sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.to_json()))


class RoleCallSource(Protocol):
    """Provider boundary: one synchronous call returning an extracted response."""

    kind: str

    def generate(
        self, messages: list[dict[str, str]], *, rollout_id: int, attempt_index: int
    ) -> ExtractedResponse: ...


class ScriptedMockSource:
    """Deterministic offline source that returns caller-supplied fixtures.

    ``responses`` maps ``attempt_index`` to the raw content (default: the entry
    at that index, else the last entry).  ``errors`` may map an attempt index to
    an exception to raise, so the retry/unknown paths can be exercised offline.
    """

    kind = "mock"

    def __init__(
        self,
        responses: Sequence[str] = (),
        *,
        errors: Mapping[int, BaseException] | None = None,
        content_builder: Callable[[list[dict[str, str]], int], str] | None = None,
        usage: Mapping[str, int] | None = None,
        finish_reason: str = "stop",
    ) -> None:
        self._responses = tuple(responses)
        self._errors = dict(errors or {})
        self._content_builder = content_builder
        self._usage = dict(usage or {"prompt_tokens": 11, "completion_tokens": 7})
        self._finish_reason = finish_reason
        self.calls: list[list[dict[str, str]]] = []

    def generate(
        self, messages: list[dict[str, str]], *, rollout_id: int, attempt_index: int
    ) -> ExtractedResponse:
        self.calls.append([dict(message) for message in messages])
        error = self._errors.get(attempt_index)
        if error is not None:
            raise error
        if self._content_builder is not None:
            content = self._content_builder(messages, attempt_index)
        elif self._responses:
            index = min(attempt_index, len(self._responses) - 1)
            content = self._responses[index]
        else:
            content = ""
        return ExtractedResponse(
            content=content,
            finish_reason=self._finish_reason,
            usage=dict(self._usage),
            cache_hit=False,
            response_id=f"mock-{uuid.uuid4().hex[:12]}",
            model="mock",
        )


class DspyRoleSource:
    """Real DMX source over the fixed synchronous ``dspy.LM.forward`` path.

    The LM construction mirrors :func:`coco_attack.generation.source.build_lm`
    without requiring a victim ``GenerationConfig``.  It is never exercised in
    this round (mock only); no API key is loaded unless explicitly requested.
    """

    kind = "dmx"

    def __init__(self, config: RoleCallConfig, api_key: str) -> None:
        import dspy

        self.config = config
        self._lm = dspy.LM(
            model=config.model,
            model_type="chat",
            cache=True,
            num_retries=0,
            api_base=config.api_base or DMX_BASE,
            api_key=api_key,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.request_timeout,
        )

    def generate(
        self, messages: list[dict[str, str]], *, rollout_id: int, attempt_index: int
    ) -> ExtractedResponse:
        response = self._lm.forward(messages=messages, rollout_id=rollout_id)
        return extract_response(response)


def resolve_role_source(
    config: RoleCallConfig,
    *,
    api_key: str | None = None,
    responses: Sequence[str] = (),
    errors: Mapping[int, BaseException] | None = None,
) -> RoleCallSource:
    """Build the provider for ``config``; mock never needs a key."""

    if config.source == "mock":
        return ScriptedMockSource(responses, errors=errors)
    if not api_key:
        raise ActionRuntimeError("a DMX api key is required for source='dmx'")
    return DspyRoleSource(config, api_key)


def _status_for_response(response: ExtractedResponse) -> str:
    if response.finish_reason == "length":
        return "truncated"
    if not response.content:
        return "empty"
    return "success"


def estimate_cost(config: RoleCallConfig, usage: Mapping[str, int]) -> dict[str, Any]:
    """Cost facts for one call; mock is marked as mock, unknown is never zero."""

    if config.source == "mock":
        return {
            "basis": "mock",
            "amount": None,
            "currency": config.currency,
            "pricing_version": "mock",
        }
    if not usage or config.price_input_per_1k is None or config.price_output_per_1k is None:
        return {
            "basis": "unknown",
            "amount": None,
            "currency": config.currency,
            "pricing_version": config.pricing_version,
        }
    amount = (
        int(usage.get("prompt_tokens", 0)) / 1000.0 * config.price_input_per_1k
        + int(usage.get("completion_tokens", 0)) / 1000.0 * config.price_output_per_1k
    )
    return {
        "basis": "estimated",
        "amount": amount,
        "currency": config.currency,
        "pricing_version": config.pricing_version,
    }


# --------------------------------------------------------------------------- #
# Action request and store
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RoleActionRequest:
    """A planned action: stable id, role/kind, actual messages and input refs.

    ``kind`` is ``"mutator"`` (its response is post-processed into a template
    patch) or ``"reasoning"`` (plain text; it creates no candidate).
    """

    action_id: str
    role: str
    kind: str
    messages: tuple[dict[str, str], ...]
    config: RoleCallConfig
    input_refs: Mapping[str, str] = None  # type: ignore[assignment]
    created_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not self.action_id:
            raise ActionRuntimeError("action_id must be a non-empty string")
        if self.kind not in ("mutator", "reasoning"):
            raise ActionRuntimeError("kind must be 'mutator' or 'reasoning'")
        if self.role != self.config.role:
            raise ActionRuntimeError("request.role must match config.role")
        messages = tuple(dict(message) for message in self.messages)
        if not messages:
            raise ActionRuntimeError("messages must not be empty")
        for message in messages:
            if set(message) != {"role", "content"} or not isinstance(message["role"], str) or not isinstance(message["content"], str):
                raise ActionRuntimeError("each message must be exactly {role:str, content:str}")
        object.__setattr__(self, "messages", messages)
        object.__setattr__(self, "input_refs", dict(self.input_refs or {}))

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": ACTION_SCHEMA_VERSION,
            "action_id": self.action_id,
            "role": self.role,
            "kind": self.kind,
            "messages": list(self.messages),
            "input_refs": dict(self.input_refs),
            "config": self.config.to_json(),
            "created_at": self.created_at,
        }

    def request_sha256(self) -> str:
        # ``created_at`` is stored for audit but excluded from the identity so a
        # reconstructed identical request is not a spurious conflict on resume.
        payload = self.to_json()
        payload.pop("created_at", None)
        return sha256_bytes(canonical_json_bytes(payload))


class ActionStore:
    """Append-only action log plus atomic per-action files under one run dir."""

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)
        self.actions_path = self.run_dir / "actions.jsonl"
        self.actions_dir = self.run_dir / "actions"

    # -- paths ------------------------------------------------------------- #

    def action_dir(self, action_id: str) -> Path:
        return self.actions_dir / action_id

    def request_path(self, action_id: str) -> Path:
        return self.action_dir(action_id) / "request.json"

    def result_path(self, action_id: str) -> Path:
        return self.action_dir(action_id) / "result.json"

    def commit_path(self, action_id: str) -> Path:
        return self.action_dir(action_id) / "commit.json"

    def responses_dir(self, action_id: str) -> Path:
        return self.action_dir(action_id) / "responses"

    # -- events ------------------------------------------------------------ #

    def events(self, action_id: str | None = None) -> list[dict[str, Any]]:
        rows = _read_jsonl(self.actions_path)
        if action_id is None:
            return rows
        return [row for row in rows if row.get("action_id") == action_id]

    def _append(self, event_type: str, action_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        event = {
            "schema_version": ACTION_SCHEMA_VERSION,
            "event_id": uuid.uuid4().hex,
            "ts": _utc_now(),
            "event_type": event_type,
            "action_id": action_id,
            "payload": payload,
        }
        append_jsonl(self.actions_path, event)
        return event

    # -- plan -------------------------------------------------------------- #

    def plan(self, request: RoleActionRequest) -> dict[str, Any]:
        """Persist the request before execution; idempotent on identical input."""

        path = self.request_path(request.action_id)
        digest = request.request_sha256()
        if path.is_file():
            existing = read_json(path)
            if existing.get("request_sha256") != digest:
                raise ActionConflictError(
                    f"action {request.action_id!r} already exists with different content; "
                    "use a new action_id"
                )
            return existing
        payload = {**request.to_json(), "request_sha256": digest}
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Exclusive create closes the check-then-write race for a new action.
            with open(path, "xb") as handle:
                handle.write(stable_json_bytes(payload))
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            existing = read_json(path)
            if existing.get("request_sha256") != digest:
                raise ActionConflictError(
                    f"action {request.action_id!r} already exists with different content; "
                    "use a new action_id"
                )
            return existing
        self._append(ACTION_PLANNED, request.action_id, {"request_sha256": digest})
        return payload

    def read_request(self, action_id: str) -> dict[str, Any] | None:
        path = self.request_path(action_id)
        return read_json(path) if path.is_file() else None

    # -- attempts / responses ---------------------------------------------- #

    def record_attempt_started(self, action_id: str, attempt_index: int) -> str:
        attempt_id = uuid.uuid4().hex
        self._append(
            ATTEMPT_STARTED,
            action_id,
            {"attempt_index": attempt_index, "request_attempt_id": attempt_id},
        )
        return attempt_id

    def record_attempt_failed(
        self, action_id: str, attempt_id: str, attempt_index: int, error: BaseException, retryable: bool
    ) -> None:
        self._append(
            ATTEMPT_FAILED,
            action_id,
            {
                "attempt_index": attempt_index,
                "request_attempt_id": attempt_id,
                "error_type": type(error).__name__,
                "error_reason": str(error),
                "retryable": retryable,
            },
        )

    def save_response(
        self,
        action_id: str,
        attempt_id: str,
        attempt_index: int,
        response: ExtractedResponse,
        *,
        cost: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist the raw response before any parsing/applying/projection."""

        payload = {
            "schema_version": ACTION_SCHEMA_VERSION,
            "action_id": action_id,
            "request_attempt_id": attempt_id,
            "attempt_index": attempt_index,
            "status": _status_for_response(response),
            "content": response.content,
            "content_sha256": sha256_bytes(response.content.encode("utf-8")),
            "finish_reason": response.finish_reason,
            "response_id": response.response_id,
            "model": response.model,
            "usage": dict(response.usage),
            "cost": dict(cost),
            "cache_hit": response.cache_hit,
        }
        directory = self.responses_dir(action_id)
        directory.mkdir(parents=True, exist_ok=True)
        write_json_atomic(directory / f"{attempt_id}.json", payload)
        self._append(
            RESPONSE_SAVED,
            action_id,
            {
                "attempt_index": attempt_index,
                "request_attempt_id": attempt_id,
                "content_sha256": payload["content_sha256"],
                "status": payload["status"],
                "usage": payload["usage"],
                "cost": payload["cost"],
                "cache_hit": payload["cache_hit"],
            },
        )
        return payload

    def response_events(self, action_id: str) -> list[dict[str, Any]]:
        return [event for event in self.events(action_id) if event["event_type"] == RESPONSE_SAVED]

    def _response_files(self, action_id: str) -> dict[str, dict[str, Any]]:
        """Read response files by attempt id.

        The response file is written before the ``RESPONSE_SAVED`` event, so a
        crash in that window leaves a durable response with no event.  Reading
        the files (not just the event log) keeps such a response recoverable.
        """

        directory = self.responses_dir(action_id)
        result: dict[str, dict[str, Any]] = {}
        if not directory.is_dir():
            return result
        for path in sorted(directory.glob("*.json")):
            try:
                payload = read_json(path)
            except (OSError, ValueError):
                continue
            if isinstance(payload, dict) and isinstance(payload.get("request_attempt_id"), str):
                result[payload["request_attempt_id"]] = payload
        return result

    def durable_response(self, action_id: str) -> dict[str, Any] | None:
        """The last durably persisted response for this action (or None).

        Considers response files as well as events so a response written just
        before a crash (file durable, event not appended) is still reused and the
        provider is never re-called.
        """

        candidates = self._response_files(action_id)
        for event in self.response_events(action_id):
            attempt_id = event["payload"]["request_attempt_id"]
            if attempt_id not in candidates:
                raise ActionRuntimeError(
                    f"action {action_id!r} records a saved response but its file is missing"
                )
        if not candidates:
            return None
        return max(candidates.values(), key=lambda payload: int(payload.get("attempt_index", -1)))

    def orphan_attempts(self, action_id: str) -> list[dict[str, Any]]:
        """Attempts that started but have no failure or durable response (crash window)."""

        response_files = set(self._response_files(action_id))
        started: dict[str, dict[str, Any]] = {}
        terminal: set[str] = set()
        for event in self.events(action_id):
            attempt = event["payload"].get("request_attempt_id")
            if event["event_type"] == ATTEMPT_STARTED:
                started[attempt] = event
            elif event["event_type"] in (ATTEMPT_FAILED, RESPONSE_SAVED):
                terminal.add(attempt)
        return [
            event
            for attempt, event in started.items()
            if attempt not in terminal and attempt not in response_files
        ]

    # -- result / commit ---------------------------------------------------- #

    def write_result(self, action_id: str, result: Mapping[str, Any]) -> dict[str, Any]:
        payload = {"schema_version": ACTION_SCHEMA_VERSION, "action_id": action_id, **dict(result)}
        write_json_atomic(self.result_path(action_id), payload)
        return payload

    def read_result(self, action_id: str) -> dict[str, Any] | None:
        path = self.result_path(action_id)
        return read_json(path) if path.is_file() else None

    def write_commit(self, action_id: str, commit: Mapping[str, Any]) -> dict[str, Any]:
        payload = {"schema_version": ACTION_SCHEMA_VERSION, "action_id": action_id, **dict(commit)}
        write_json_atomic(self.commit_path(action_id), payload)
        self._append(ACTION_COMMITTED, action_id, dict(commit))
        return payload

    def read_commit(self, action_id: str) -> dict[str, Any] | None:
        path = self.commit_path(action_id)
        return read_json(path) if path.is_file() else None

    def has_event(self, action_id: str, event_type: str) -> bool:
        return any(event["event_type"] == event_type for event in self.events(action_id))

    def ensure_committed_event(self, action_id: str, commit: Mapping[str, Any]) -> bool:
        """Append a missing ``ACTION_COMMITTED`` event for an already-written commit.

        ``write_commit`` writes ``commit.json`` before appending the event, so a
        crash in that window leaves the file without the log record.  Recovery
        appends the event at most once and never redoes the patch/history.
        """

        if self.has_event(action_id, ACTION_COMMITTED):
            return False
        self._append(ACTION_COMMITTED, action_id, dict(commit))
        return True


# --------------------------------------------------------------------------- #
# Role call execution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RoleCallOutcome:
    action_id: str
    state: str
    response_status: str | None
    response: dict[str, Any] | None
    usage: dict[str, int]
    cost: dict[str, Any]
    error: str | None
    attempts: int


def _rollout_id(request: RoleActionRequest) -> int:
    digest = sha256_bytes(request.request_sha256().encode("utf-8"))
    return int(digest[:16], 16)


def run_role_call(
    store: ActionStore,
    request: RoleActionRequest,
    *,
    source: RoleCallSource,
    allow_retry_after_unknown: bool = False,
) -> RoleCallOutcome:
    """Plan, execute and persist one role call.

    A durable response short-circuits execution (resume never re-calls the
    provider).  An orphan ``attempt_started`` (process died after the request may
    have been sent) is reported as ``unknown_paused`` unless the caller
    explicitly opts into a retry, so an unknown charge is never silently hidden.
    """

    store.plan(request)
    prior = store.durable_response(request.action_id)
    if prior is not None:
        return RoleCallOutcome(
            action_id=request.action_id,
            state=STATE_RESPONSE_REUSED,
            response_status=prior.get("status"),
            response=prior,
            usage=dict(prior.get("usage") or {}),
            cost=dict(prior.get("cost") or {}),
            error=None,
            attempts=0,
        )

    orphans = store.orphan_attempts(request.action_id)
    if orphans and not allow_retry_after_unknown:
        return RoleCallOutcome(
            action_id=request.action_id,
            state=STATE_UNKNOWN_PAUSED,
            response_status=None,
            response=None,
            usage={},
            cost={"basis": "unknown", "amount": None, "currency": request.config.currency},
            error=(
                f"{len(orphans)} attempt(s) started without a durable response; "
                "outcome and cost are unknown, retry must be explicit"
            ),
            attempts=len(orphans),
        )

    rollout_id = _rollout_id(request)
    messages = [dict(message) for message in request.messages]
    attempts = 0
    last_error: str | None = None
    for attempt_index in range(request.config.max_request_attempts):
        attempts += 1
        attempt_id = store.record_attempt_started(request.action_id, attempt_index)
        try:
            response = source.generate(
                messages, rollout_id=rollout_id, attempt_index=attempt_index
            )
        except ResponseContractError as error:
            store.record_attempt_failed(
                request.action_id, attempt_id, attempt_index, error, is_retryable(error)
            )
            if is_retryable(error) and attempt_index + 1 < request.config.max_request_attempts:
                continue
            return RoleCallOutcome(
                action_id=request.action_id,
                state=STATE_FAILED,
                response_status="invalid_response",
                response=None,
                usage={},
                cost={"basis": "unknown", "amount": None, "currency": request.config.currency},
                error=str(error),
                attempts=attempts,
            )
        except Exception as error:  # noqa: BLE001 - provider boundary
            retryable = is_retryable(error)
            store.record_attempt_failed(
                request.action_id, attempt_id, attempt_index, error, retryable
            )
            last_error = str(error)
            if retryable and attempt_index + 1 < request.config.max_request_attempts:
                continue
            return RoleCallOutcome(
                action_id=request.action_id,
                state=STATE_FAILED,
                response_status="error",
                response=None,
                usage={},
                cost={"basis": "unknown", "amount": None, "currency": request.config.currency},
                error=str(error),
                attempts=attempts,
            )
        cost = estimate_cost(request.config, response.usage)
        payload = store.save_response(
            request.action_id, attempt_id, attempt_index, response, cost=cost
        )
        return RoleCallOutcome(
            action_id=request.action_id,
            state=STATE_RESPONSE_SAVED,
            response_status=payload["status"],
            response=payload,
            usage=dict(payload["usage"]),
            cost=dict(payload["cost"]),
            error=None,
            attempts=attempts,
        )
    # Defensive: the loop always returns, so this is unreachable.
    return RoleCallOutcome(
        action_id=request.action_id,
        state=STATE_FAILED,
        response_status="error",
        response=None,
        usage={},
        cost={"basis": "unknown", "amount": None, "currency": request.config.currency},
        error=last_error or "no attempt executed",
        attempts=attempts,
    )


# --------------------------------------------------------------------------- #
# Patch parsing and mutation commit
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


@dataclass(frozen=True)
class PatchParseResult:
    patch: tuple[Mapping[str, Any], ...] | None
    error: str | None


def parse_sparse_patch(text: str) -> PatchParseResult:
    """Extract the sparse patch JSON; never repairs or guesses.

    Accepts a JSON array of ``{"example": int, "code"?: str, "cot"?: str}``
    objects, optionally inside a single fenced block or under a ``patch`` key.
    Field-level validity is enforced by :func:`apply_patch`, which is a separate
    post-processing step.
    """

    if not isinstance(text, str):
        return PatchParseResult(None, "response is not text")
    candidate = text.strip()
    match = _FENCE_RE.search(candidate)
    if match:
        candidate = match.group(1).strip()
    if not candidate:
        return PatchParseResult(None, "response is empty")
    try:
        parsed = json.loads(candidate)
    except ValueError as error:
        return PatchParseResult(None, f"invalid JSON: {error}")
    if isinstance(parsed, Mapping):
        if set(parsed) == {"patch"}:
            parsed = parsed["patch"]
        else:
            return PatchParseResult(None, "JSON object must contain only a 'patch' list")
    if not isinstance(parsed, list):
        return PatchParseResult(None, "patch must be a JSON list")
    for entry in parsed:
        if not isinstance(entry, Mapping):
            return PatchParseResult(None, "each patch entry must be an object")
    return PatchParseResult(tuple(parsed), None)


@dataclass(frozen=True)
class MutationOutcome:
    action_id: str
    status: str
    reason: str | None
    diff: tuple[Mapping[str, Any], ...]
    template_before: str
    template_after: str
    content_sha256: str


def commit_mutator_result(
    store: ActionStore,
    action_id: str,
    snapshot: TemplateSnapshot,
    policy: PatchPolicy,
    *,
    snapshot_store: Path | str,
    history: "HistoryStore | None" = None,
    summary: Mapping[str, Any] | None = None,
) -> MutationOutcome:
    """Post-process a durable mutator response into a committed template patch.

    Idempotent: a second call for the same action returns the stored commit and
    never re-applies the patch or re-appends history.  An invalid patch is
    recorded as a failure and the template is left unchanged; no repair request
    is issued here.
    """

    existing_commit = store.read_commit(action_id)
    if existing_commit is not None:
        # §0 fix: commit.json may be durable while ACTION_COMMITTED was not yet
        # appended (crash window).  Backfill the event once; never redo work.
        store.ensure_committed_event(
            action_id,
            {
                key: value
                for key, value in existing_commit.items()
                if key not in ("schema_version", "action_id")
            },
        )
        return MutationOutcome(
            action_id=action_id,
            status=existing_commit.get("status", "committed"),
            reason=existing_commit.get("reason"),
            diff=tuple(existing_commit.get("diff") or ()),
            template_before=existing_commit.get("template_before", snapshot.content_sha256()),
            template_after=existing_commit.get("template_after", snapshot.content_sha256()),
            content_sha256=existing_commit.get("content_sha256", snapshot.content_sha256()),
        )
    existing_result = store.read_result(action_id)
    if existing_result is not None:
        status = existing_result.get("status", "invalid_patch")
        if status != "patched":
            # A recorded failure/no-op is a completed (non-committing) post-process.
            return MutationOutcome(
                action_id=action_id,
                status=status,
                reason=existing_result.get("reason"),
                diff=(),
                template_before=snapshot.content_sha256(),
                template_after=snapshot.content_sha256(),
                content_sha256=snapshot.content_sha256(),
            )
        # The template version and result are durable but the commit pointer /
        # history unit was not written (crash between result and commit).  Finish
        # the missing steps exactly once from the stored result.
        template_before = str(existing_result.get("template_before") or snapshot.content_sha256())
        template_after = str(existing_result.get("template_after") or snapshot.content_sha256())
        diff = tuple(existing_result.get("diff") or ())
        if history is not None and action_id not in history.action_ids():
            response = store.durable_response(action_id)
            history.append_unit(
                HistoryUnit(
                    action_id=action_id,
                    role="mutator",
                    kind="mutator",
                    summary=dict(summary or {}),
                    user_content=_last_user_content(store, action_id),
                    assistant_content=str((response or {}).get("content") or ""),
                    request_sha256=str((store.read_request(action_id) or {}).get("request_sha256")),
                )
            )
        commit = {
            "status": "committed",
            "template_before": template_before,
            "template_after": template_after,
            "content_sha256": template_after,
            "diff": list(diff),
        }
        store.write_commit(action_id, commit)
        return MutationOutcome(
            action_id=action_id,
            status="committed",
            reason=None,
            diff=diff,
            template_before=template_before,
            template_after=template_after,
            content_sha256=template_after,
        )

    response = store.durable_response(action_id)
    if response is None:
        raise ActionRuntimeError(
            f"action {action_id!r} has no durable response to post-process"
        )

    parsed = parse_sparse_patch(str(response.get("content") or ""))
    if parsed.patch is None:
        store.write_result(action_id, {"status": "invalid_patch", "reason": parsed.error})
        return MutationOutcome(
            action_id=action_id,
            status="invalid_patch",
            reason=parsed.error,
            diff=(),
            template_before=snapshot.content_sha256(),
            template_after=snapshot.content_sha256(),
            content_sha256=snapshot.content_sha256(),
        )

    try:
        result: PatchResult = apply_patch(snapshot, list(parsed.patch), policy)
    except TemplateSnapshotError as error:
        store.write_result(action_id, {"status": "invalid_patch", "reason": str(error)})
        return MutationOutcome(
            action_id=action_id,
            status="invalid_patch",
            reason=str(error),
            diff=(),
            template_before=snapshot.content_sha256(),
            template_after=snapshot.content_sha256(),
            content_sha256=snapshot.content_sha256(),
        )

    if not result.changed:
        store.write_result(
            action_id,
            {
                "status": "no_change",
                "reason": "patch is a no-op",
                "template_content_sha256": snapshot.content_sha256(),
            },
        )
        return MutationOutcome(
            action_id=action_id,
            status="no_change",
            reason="patch is a no-op",
            diff=(),
            template_before=snapshot.content_sha256(),
            template_after=snapshot.content_sha256(),
            content_sha256=snapshot.content_sha256(),
        )

    # Template version + real diff + result land before the commit pointer.
    write_snapshot(
        snapshot_store,
        result.snapshot,
        action_id=action_id,
        parent_sha256=snapshot.content_sha256(),
        diff=result.diff,
    )
    store.write_result(
        action_id,
        {
            "status": "patched",
            "template_before": snapshot.content_sha256(),
            "template_after": result.content_sha256,
            "diff": result.diff,
        },
    )
    commit = {
        "status": "committed",
        "template_before": snapshot.content_sha256(),
        "template_after": result.content_sha256,
        "content_sha256": result.content_sha256,
        "diff": result.diff,
    }
    if history is not None:
        history.append_unit(
            HistoryUnit(
                action_id=action_id,
                role="mutator",
                kind="mutator",
                summary=dict(summary or {}),
                user_content=_last_user_content(store, action_id),
                assistant_content=str(response.get("content") or ""),
                request_sha256=str((store.read_request(action_id) or {}).get("request_sha256")),
            )
        )
    store.write_commit(action_id, commit)
    return MutationOutcome(
        action_id=action_id,
        status="committed",
        reason=None,
        diff=tuple(result.diff),
        template_before=snapshot.content_sha256(),
        template_after=result.content_sha256,
        content_sha256=result.content_sha256,
    )


def _last_user_content(store: ActionStore, action_id: str) -> str:
    request = store.read_request(action_id) or {}
    for message in reversed(list(request.get("messages") or [])):
        if message.get("role") == "user":
            return str(message.get("content") or "")
    return ""


# --------------------------------------------------------------------------- #
# Shared history and context metering
# --------------------------------------------------------------------------- #


class TokenCounter(Protocol):
    method: str

    def count(self, messages: Sequence[Mapping[str, str]]) -> int: ...


class HeuristicTokenCounter:
    """Deterministic local estimate; explicitly *not* a provider measurement."""

    method = "heuristic-chars-div-4-plus-role-overhead"

    def __init__(self, overhead_per_message: int = 4) -> None:
        self.overhead_per_message = overhead_per_message

    def count(self, messages: Sequence[Mapping[str, str]]) -> int:
        return sum(
            estimate_tokens(str(message.get("content") or "")) + self.overhead_per_message
            for message in messages
        )


@dataclass(frozen=True)
class ContextBudget:
    context_window_tokens: int
    output_reserve_tokens: int
    margin_tokens: int = 0

    def __post_init__(self) -> None:
        for name in ("context_window_tokens", "output_reserve_tokens", "margin_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ActionRuntimeError(f"budget.{name} must be a non-negative integer")

    @property
    def available(self) -> int:
        return self.context_window_tokens - self.output_reserve_tokens - self.margin_tokens


@dataclass(frozen=True)
class HistoryUnit:
    action_id: str
    role: str
    kind: str
    summary: Mapping[str, Any]
    user_content: str
    assistant_content: str | None
    request_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "action_id": self.action_id,
            "role": self.role,
            "kind": self.kind,
            "summary": dict(self.summary),
            "user_content": self.user_content,
            "assistant_content": self.assistant_content,
            "request_sha256": self.request_sha256,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "HistoryUnit":
        return cls(
            action_id=str(payload["action_id"]),
            role=str(payload.get("role") or ""),
            kind=str(payload.get("kind") or ""),
            summary=dict(payload.get("summary") or {}),
            user_content=str(payload.get("user_content") or ""),
            assistant_content=(
                str(payload["assistant_content"])
                if payload.get("assistant_content") is not None
                else None
            ),
            request_sha256=str(payload.get("request_sha256") or ""),
        )

    def one_line(self, *, label: str | None = None) -> str:
        """One-line summary for the model-visible compression message.

        The internal ``action_id`` is deliberately excluded: it is an audit
        identity.  Callers pass an ordinary role/sequence label instead.
        """

        facts = "; ".join(
            f"{key}={self.summary[key]}" for key in sorted(self.summary)
        )
        heading = label or self.role
        return f"[{heading}] {facts}".rstrip()

    def verbatim_messages(self) -> list[dict[str, str]]:
        messages = [{"role": "user", "content": self.user_content}]
        if self.assistant_content is not None:
            messages.append({"role": "assistant", "content": self.assistant_content})
        return messages


class HistoryStore:
    """Append-only committed shared history; idempotent per action id."""

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)
        self.history_path = self.run_dir / "history.jsonl"

    def units(self) -> list[HistoryUnit]:
        return [HistoryUnit.from_json(row) for _l, row in iter_jsonl(self.history_path)] if self.history_path.is_file() else []

    def action_ids(self) -> set[str]:
        return {unit.action_id for unit in self.units()}

    def append_unit(self, unit: HistoryUnit) -> HistoryUnit:
        for existing in self.units():
            if existing.action_id != unit.action_id:
                continue
            if existing.request_sha256 != unit.request_sha256:
                raise ActionConflictError(
                    f"history action {unit.action_id!r} already recorded with different content"
                )
            return existing
        append_jsonl(self.history_path, unit.to_json())
        return unit


@dataclass(frozen=True)
class HistoryAssembly:
    messages: tuple[dict[str, str], ...]
    total_tokens: int
    fixed_tokens: int
    compressed_action_ids: tuple[str, ...]
    counter_method: str


def _fixed_messages(system_block: str, current_user_content: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_block},
        {"role": "user", "content": current_user_content},
    ]


def assemble_history(
    *,
    system_block: str,
    current_user_content: str,
    units: Sequence[HistoryUnit],
    budget: ContextBudget,
    counter: TokenCounter,
) -> HistoryAssembly:
    """Assemble fixed block + (possibly compressed) history + current request.

    Deterministic: the same committed units, budget and counter always produce
    the same messages.  Compression only ever merges the *oldest* units into
    one-line summaries; the system block and the current request are never
    dropped.  If the fixed block alone does not fit, assembly fails explicitly.
    """

    fixed = _fixed_messages(system_block, current_user_content)
    fixed_tokens = counter.count(fixed)
    if fixed_tokens > budget.available:
        raise ContextAssemblyError(
            f"fixed system/template block needs {fixed_tokens} tokens but only "
            f"{budget.available} are available; adjust the context budget"
        )

    def build(verbatim_count: int) -> list[dict[str, str]]:
        compressed_units = list(units[: len(units) - verbatim_count])
        recent_units = list(units[len(units) - verbatim_count :])
        messages: list[dict[str, str]] = [fixed[0]]
        if compressed_units:
            messages.append(
                {
                    "role": "user",
                    "content": "\u8f83\u65e9\u8f6e\u6b21\u6458\u8981\uff08\u6bcf\u884c\u4e00\u8f6e\uff09:\n"
                    + "\n".join(
                        unit.one_line(label=f"\u4ea4\u4e92 {index + 1}")
                        for index, unit in enumerate(compressed_units)
                    ),
                }
            )
        for unit in recent_units:
            messages.extend(unit.verbatim_messages())
        messages.append(fixed[1])
        return messages

    full = build(len(units))
    if counter.count(full) <= budget.available:
        return HistoryAssembly(
            messages=tuple(full),
            total_tokens=counter.count(full),
            fixed_tokens=fixed_tokens,
            compressed_action_ids=(),
            counter_method=counter.method,
        )

    compressed: tuple[str, ...] = ()
    for verbatim_count in range(len(units) - 1, -1, -1):
        candidate = build(verbatim_count)
        tokens = counter.count(candidate)
        if tokens <= budget.available:
            compressed = tuple(unit.action_id for unit in units[: len(units) - verbatim_count])
            return HistoryAssembly(
                messages=tuple(candidate),
                total_tokens=tokens,
                fixed_tokens=fixed_tokens,
                compressed_action_ids=compressed,
                counter_method=counter.method,
            )
    raise ContextAssemblyError(
        "even fully compressed history does not fit the context budget; "
        "the fixed material is too large"
    )


__all__ = [
    "ACTION_SCHEMA_VERSION",
    "ActionConflictError",
    "ActionRuntimeError",
    "ActionStore",
    "ContextAssemblyError",
    "ContextBudget",
    "DspyRoleSource",
    "HeuristicTokenCounter",
    "HistoryAssembly",
    "HistoryStore",
    "HistoryUnit",
    "MutationOutcome",
    "PatchParseResult",
    "RoleActionRequest",
    "RoleCallConfig",
    "RoleCallOutcome",
    "RoleCallSource",
    "ScriptedMockSource",
    "assemble_history",
    "commit_mutator_result",
    "estimate_cost",
    "parse_sparse_patch",
    "resolve_role_source",
    "run_role_call",
]
