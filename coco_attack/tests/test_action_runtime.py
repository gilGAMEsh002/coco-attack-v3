"""Task-04 action runtime tests (I2/I4/I5).

These exercise the offline mock provider only: no real model, Docker or Semgrep
is called.  The template-dependent tests skip when the read-only assets are
absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.iteration.action_runtime import (
    ACTION_COMMITTED,
    STATE_FAILED,
    STATE_RESPONSE_REUSED,
    STATE_RESPONSE_SAVED,
    STATE_UNKNOWN_PAUSED,
    ActionConflictError,
    ActionRuntimeError,
    ActionStore,
    ContextAssemblyError,
    ContextBudget,
    HeuristicTokenCounter,
    HistoryStore,
    HistoryUnit,
    RoleActionRequest,
    RoleCallConfig,
    SPARSE_PATCH_PARSER_VERSION,
    ScriptedMockSource,
    assemble_history,
    commit_mutator_result,
    parse_sparse_patch,
    run_role_call,
)
from coco_attack.iteration.template_snapshot import (
    PatchPolicy,
    read_snapshot,
    snapshot_from_clean,
    write_snapshot,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = "poisoned_fewshot_cot"

#: Stored evidence from the R1-A1 run whose code values contain ```python fences.
R1_A1_RESPONSE_DIR = (
    REPO_DIR
    / "cocota_runs/phase04/method-ab-flash-v32-concurrent-r1/run/actions/R1-A1/responses"
)

ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)


def _config(**overrides) -> RoleCallConfig:
    values = {
        "role": "mutator",
        "model": "openai/DeepSeek-V3.2",
        "source": "mock",
        "temperature": 0.7,
        "max_tokens": 8192,
        "max_request_attempts": 2,
    }
    values.update(overrides)
    return RoleCallConfig(**values)


def _request(action_id: str, *, kind: str = "mutator", config: RoleCallConfig | None = None, content: str = "hello") -> RoleActionRequest:
    return RoleActionRequest(
        action_id=action_id,
        role=(config or _config()).role,
        kind=kind,
        messages=(
            {"role": "system", "content": "system block"},
            {"role": "user", "content": content},
        ),
        config=config or _config(),
        input_refs={"template": "a" * 64},
    )


VALID_PATCH = json.dumps([{"example": 2, "code": "def task_func():\n    return 42\n"}])


# --------------------------------------------------------------------------- #
# 1. Call + audit persistence
# --------------------------------------------------------------------------- #


def test_role_call_persists_request_and_response_before_return(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    source = ScriptedMockSource([VALID_PATCH], usage={"prompt_tokens": 100, "completion_tokens": 20})
    outcome = run_role_call(store, _request("a1"), source=source)

    assert outcome.state == STATE_RESPONSE_SAVED
    assert outcome.response_status == "success"
    assert outcome.usage == {"prompt_tokens": 100, "completion_tokens": 20}
    assert outcome.cost["basis"] == "mock"
    assert outcome.cost["amount"] is None  # mock never pretends a real cost
    assert not (tmp_path / "actions" / "a1" / "result.json").exists()  # no candidate yet

    request = store.read_request("a1")
    assert request["messages"][1]["content"] == "hello"
    assert request["request_sha256"]
    event_types = [event["event_type"] for event in store.events("a1")]
    assert event_types == ["action_planned", "attempt_started", "response_saved"]
    assert source.calls and source.calls[0][0]["role"] == "system"


def test_reasoning_action_needs_no_candidate_or_patch(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    source = ScriptedMockSource(["just a thought"])
    outcome = run_role_call(store, _request("r1", kind="reasoning"), source=source)
    assert outcome.state == STATE_RESPONSE_SAVED
    assert outcome.response["content"] == "just a thought"
    assert not (tmp_path / "actions" / "r1" / "commit.json").exists()
    assert not (tmp_path / "actions" / "r1" / "result.json").exists()


def test_resume_reuses_durable_response_without_calling_provider(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))

    class _Forbidden(ScriptedMockSource):
        def generate(self, messages, *, rollout_id, attempt_index):  # type: ignore[override]
            raise AssertionError("resume must not call the provider")

    outcome = run_role_call(store, _request("a1"), source=_Forbidden())
    assert outcome.state == STATE_RESPONSE_REUSED
    assert outcome.attempts == 0
    assert outcome.response["content"] == VALID_PATCH


def test_durable_response_file_without_event_is_reused(tmp_path: Path) -> None:
    """A response file written just before a crash (event not appended) is reused."""

    from coco_attack.assets.artifacts import write_json_atomic

    store = ActionStore(tmp_path)
    request = _request("a1")
    store.plan(request)
    attempt_id = store.record_attempt_started("a1", 0)
    payload = {
        "schema_version": "action-runtime-v1",
        "action_id": "a1",
        "request_attempt_id": attempt_id,
        "attempt_index": 0,
        "status": "success",
        "content": VALID_PATCH,
        "content_sha256": "d" * 64,
        "finish_reason": "stop",
        "response_id": "mock-x",
        "model": "mock",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "cost": {"basis": "mock", "amount": None, "currency": "USD", "pricing_version": "mock"},
        "cache_hit": False,
    }
    responses = store.responses_dir("a1")
    responses.mkdir(parents=True, exist_ok=True)
    write_json_atomic(responses / f"{attempt_id}.json", payload)

    class _Forbidden(ScriptedMockSource):
        def generate(self, messages, *, rollout_id, attempt_index):  # type: ignore[override]
            raise AssertionError("a durable response file must prevent a provider call")

    # Not an orphan: the response file is terminal even without the event.
    assert store.orphan_attempts("a1") == []
    outcome = run_role_call(store, request, source=_Forbidden())
    assert outcome.state == STATE_RESPONSE_REUSED
    assert outcome.response["content"] == VALID_PATCH


def test_conflicting_action_id_is_refused(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))
    with pytest.raises(ActionConflictError):
        run_role_call(store, _request("a1", content="different"), source=ScriptedMockSource(["x"]))


def test_request_identity_excludes_created_at(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    base = _request("a1")
    timestamped = RoleActionRequest(
        action_id="a1",
        role=base.role,
        kind=base.kind,
        messages=base.messages,
        config=base.config,
        input_refs=base.input_refs,
        created_at="2026-09-22T00:00:00+00:00",
    )
    assert base.request_sha256() == timestamped.request_sha256()
    store.plan(timestamped)
    # Same content (even with a different timestamp) is idempotent, not a conflict.
    store.plan(base)


def test_unknown_attempt_window_pauses_without_silent_retry(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    request = _request("a1")
    store.plan(request)
    store.record_attempt_started("a1", 0)  # crash after the request may have been sent

    source = ScriptedMockSource([VALID_PATCH])
    outcome = run_role_call(store, request, source=source)
    assert outcome.state == STATE_UNKNOWN_PAUSED
    assert source.calls == []  # no silent retry
    assert outcome.cost["basis"] == "unknown" and outcome.cost["amount"] is None

    retried = run_role_call(store, request, source=source, allow_retry_after_unknown=True)
    assert retried.state == STATE_RESPONSE_SAVED
    assert len(source.calls) == 1


def test_retryable_failure_then_success_records_two_attempts(tmp_path: Path) -> None:
    from coco_attack.generation.source import MockTransientError

    store = ActionStore(tmp_path)
    source = ScriptedMockSource([VALID_PATCH], errors={0: MockTransientError("rate limit")})
    outcome = run_role_call(store, _request("a1"), source=source)
    assert outcome.state == STATE_RESPONSE_SAVED
    assert outcome.attempts == 2
    types = [event["event_type"] for event in store.events("a1")]
    assert types.count("attempt_started") == 2
    assert "attempt_failed" in types


def test_permanent_failure_is_failed_without_persisted_response(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    source = ScriptedMockSource([VALID_PATCH], errors={0: ValueError("bad request")})
    outcome = run_role_call(store, _request("a1"), source=source)
    assert outcome.state == STATE_FAILED
    assert outcome.response is None
    assert outcome.response_status == "error"
    assert store.durable_response("a1") is None


def test_empty_response_is_retried_and_wasted_attempt_is_audited(tmp_path: Path) -> None:
    """An empty first response is incomplete: retry, audited usage, durable success."""

    store = ActionStore(tmp_path)
    source = ScriptedMockSource(
        ["", VALID_PATCH],
        usage={"prompt_tokens": 100, "completion_tokens": 0},
    )
    outcome = run_role_call(store, _request("a1"), source=source)

    assert outcome.state == STATE_RESPONSE_SAVED
    assert outcome.response_status == "success"
    assert outcome.response["content"] == VALID_PATCH
    assert outcome.attempts == 2
    assert len(source.calls) == 2

    failed = [e for e in store.events("a1") if e["event_type"] == "attempt_failed"]
    assert len(failed) == 1
    payload = failed[0]["payload"]
    assert payload["error_type"] == "IncompleteResponseError"
    assert payload["retryable"] is True
    assert payload["attempt_index"] == 0
    # The wasted tokens/cost are audited rather than dropped.
    assert payload["usage"] == {"prompt_tokens": 100, "completion_tokens": 0}
    assert payload["cost"]["basis"] == "mock"
    # No response was persisted for the incomplete attempt.
    assert store.response_events("a1")[0]["payload"]["attempt_index"] == 1
    durable = store.durable_response("a1")
    assert durable is not None and durable["content"] == VALID_PATCH
    assert store.orphan_attempts("a1") == []


def test_always_empty_response_is_never_a_silent_success(tmp_path: Path) -> None:
    """Exhausted attempts persist the last incomplete response (visible status)."""

    store = ActionStore(tmp_path)
    source = ScriptedMockSource([""], finish_reason="length")
    outcome = run_role_call(
        store, _request("a1", config=_config(max_request_attempts=2)), source=source
    )

    assert len(source.calls) == 2
    assert outcome.attempts == 2
    assert outcome.response_status == "truncated"
    assert outcome.response_status != "success"
    assert outcome.error  # explicit, not a silent success
    assert outcome.response is not None and outcome.response["content"] == ""

    event_types = [e["event_type"] for e in store.events("a1")]
    assert event_types.count("attempt_started") == 2
    assert event_types.count("attempt_failed") == 2
    assert event_types.count("response_saved") == 1
    assert store.orphan_attempts("a1") == []

    durable = store.durable_response("a1")
    assert durable["status"] == "truncated"
    assert durable["finish_reason"] == "length"
    assert durable["content"] == ""

    # Stable resume: the durable empty response is reused, never retried again.
    again = run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))
    assert again.state == STATE_RESPONSE_REUSED
    assert again.response_status == "truncated"
    assert again.attempts == 0


def test_always_whitespace_response_is_empty_not_success(tmp_path: Path) -> None:
    """Whitespace-only content must not be persisted with status ``success``."""

    store = ActionStore(tmp_path)
    source = ScriptedMockSource(["   \n  "], finish_reason="stop")
    outcome = run_role_call(
        store, _request("a1", config=_config(max_request_attempts=2)), source=source
    )

    assert len(source.calls) == 2
    assert outcome.attempts == 2
    assert outcome.response_status == "empty"
    assert outcome.response_status != "success"
    assert outcome.error  # explicit, not a silent success

    durable = store.durable_response("a1")
    assert durable is not None
    assert durable["status"] == "empty"
    assert durable["finish_reason"] == "stop"
    assert durable["content"].strip() == ""

    failed = [e for e in store.events("a1") if e["event_type"] == "attempt_failed"]
    assert len(failed) == 2
    assert {e["payload"]["error_type"] for e in failed} == {"IncompleteResponseError"}


def test_resume_after_empty_retry_does_not_double_count_cost(tmp_path: Path) -> None:
    store = ActionStore(tmp_path)
    source = ScriptedMockSource(["", VALID_PATCH])
    run_role_call(store, _request("a1"), source=source)
    response_events_before = len(store.response_events("a1"))
    failed_before = [e for e in store.events("a1") if e["event_type"] == "attempt_failed"]

    class _Forbidden(ScriptedMockSource):
        def generate(self, messages, *, rollout_id, attempt_index):  # type: ignore[override]
            raise AssertionError("resume must not call the provider")

    resumed = run_role_call(store, _request("a1"), source=_Forbidden())
    assert resumed.state == STATE_RESPONSE_REUSED
    assert len(store.response_events("a1")) == response_events_before
    assert [e for e in store.events("a1") if e["event_type"] == "attempt_failed"] == failed_before
    assert resumed.cost["basis"] == "mock"


# --------------------------------------------------------------------------- #
# 2. Patch post-processing
# --------------------------------------------------------------------------- #


def test_parse_sparse_patch_variants() -> None:
    assert parse_sparse_patch(VALID_PATCH).patch is not None
    assert parse_sparse_patch(f"```json\n{VALID_PATCH}\n```").patch is not None
    assert parse_sparse_patch(json.dumps({"patch": [{"example": 2, "code": "x"}]})).patch is not None
    assert parse_sparse_patch("not json").error
    assert parse_sparse_patch("[]").patch == ()
    assert parse_sparse_patch('{"other": []}').error
    assert parse_sparse_patch("[1, 2]").error


def test_sparse_patch_parser_version_is_exported() -> None:
    assert SPARSE_PATCH_PARSER_VERSION == "sparse-patch-v2"


def test_parse_sparse_patch_keeps_fences_inside_string_values() -> None:
    """R1-A1 regression: a valid array whose code values contain fences parses."""

    patch = json.dumps(
        [
            {"example": 2, "code": "```python\n    return 1\n```"},
            {"example": 3, "code": "```python\n    return 2\n```"},
        ]
    )
    result = parse_sparse_patch(patch)
    assert result.error is None
    assert result.patch is not None
    assert [entry["example"] for entry in result.patch] == [2, 3]
    assert result.patch[0]["code"].startswith("```python")
    assert result.patch[1]["code"].endswith("```")


def test_parse_sparse_patch_only_unwraps_a_whole_response_fence() -> None:
    body = json.dumps([{"example": 2, "code": "x"}])
    # Whole-response fences (with and without the json tag) are unwrapped.
    assert parse_sparse_patch(f"```json\n{body}\n```").patch is not None
    assert parse_sparse_patch(f"```\n{body}\n```").patch == parse_sparse_patch(body).patch
    # Prose around an embedded fence is not search-anywhere unwrapped.
    assert parse_sparse_patch(f"here it is:\n```json\n{body}\n```\nthanks").error
    assert parse_sparse_patch(f"prefix {body} suffix").error


def test_parse_sparse_patch_error_shapes_are_preserved() -> None:
    assert parse_sparse_patch("").error == "response is empty"
    assert parse_sparse_patch("   \n\t").error == "response is empty"
    prose = parse_sparse_patch("just some prose, no json here")
    assert prose.patch is None
    assert prose.error is not None and prose.error.startswith("invalid JSON: ")
    assert parse_sparse_patch(json.dumps({"patch": [{"example": 2}]})).patch is not None
    assert (
        parse_sparse_patch(json.dumps({"other": []})).error
        == "JSON object must contain only a 'patch' list"
    )
    assert parse_sparse_patch("[]").patch == ()
    assert parse_sparse_patch("[1, 2]").error == "each patch entry must be an object"
    assert parse_sparse_patch('["x"]').error == "each patch entry must be an object"
    assert parse_sparse_patch('{"patch": 3}').error == "patch must be a JSON list"


@pytest.mark.skipif(
    not R1_A1_RESPONSE_DIR.is_dir(),
    reason="stored R1-A1 run response is not present",
)
def test_parse_sparse_patch_accepts_stored_r1a1_response() -> None:
    """Read-only replay: the stored R1-A1 response is accepted by the new parser."""

    import hashlib

    files = sorted(R1_A1_RESPONSE_DIR.glob("*.json"))
    assert files
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}

    content = None
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("content"):
            content = payload["content"]
            break
    assert content, "no stored content found"
    result = parse_sparse_patch(content)
    assert result.error is None
    assert result.patch is not None
    assert len(result.patch) == 3
    assert all("```python" in str(entry.get("code") or "") for entry in result.patch)

    after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    assert before == after  # read-only: the evidence was not modified


@requires_prepared
def test_valid_patch_applies_and_commits_once(tmp_path: Path) -> None:
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    write_snapshot(store_root, snapshot, action_id="init")
    store = ActionStore(tmp_path / "run")
    history = HistoryStore(tmp_path / "run")
    run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))

    policy = PatchPolicy(allowed_examples=(2,), allowed_fields=("code",))
    outcome = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history,
        summary={"example": 2, "field": "code"},
    )
    assert outcome.status == "committed"
    assert outcome.template_after != outcome.template_before
    assert outcome.diff and outcome.diff[0]["example"] == 2
    new_snapshot = read_snapshot(store_root / COMBINATION / outcome.content_sha256)
    assert new_snapshot.content_sha256() == outcome.content_sha256
    assert [unit.action_id for unit in history.units()] == ["a1"]

    # Idempotent: re-committing does not append a second history unit or re-apply.
    again = commit_mutator_result(store, "a1", snapshot, policy, snapshot_store=store_root, history=history)
    assert again.content_sha256 == outcome.content_sha256
    assert [unit.action_id for unit in history.units()] == ["a1"]


@requires_prepared
def test_invalid_patch_leaves_template_unchanged_and_asks_no_repair(tmp_path: Path) -> None:
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    store = ActionStore(tmp_path / "run")
    source = ScriptedMockSource(["{broken json"])
    run_role_call(store, _request("a1"), source=source)

    outcome = commit_mutator_result(
        store, "a1", snapshot, PatchPolicy(allowed_examples=(2,), allowed_fields=("code",)),
        snapshot_store=store_root,
    )
    assert outcome.status == "invalid_patch"
    assert outcome.template_after == snapshot.content_sha256()
    assert store.read_commit("a1") is None
    # No second "repair" request was issued by the infrastructure.
    assert len(source.calls) == 1
    # No template version was written for a rejected patch.
    assert not list(store_root.glob(f"{COMBINATION}/*"))


@requires_prepared
def test_commit_finishes_missing_pointer_after_mid_commit_crash(tmp_path: Path) -> None:
    """Crash between result.json and commit.json: resume completes exactly once."""

    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    store = ActionStore(tmp_path / "run")
    history = HistoryStore(tmp_path / "run")
    run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))
    policy = PatchPolicy(allowed_examples=(2,), allowed_fields=("code",))
    first = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history,
        summary={"example": 2, "field": "code"},
    )
    # Simulate the crash window: the commit pointer and history unit never landed.
    store.commit_path("a1").unlink()
    history.history_path.write_text("", encoding="utf-8")

    resumed = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history,
        summary={"example": 2, "field": "code"},
    )
    assert resumed.status == "committed"
    assert resumed.template_after == first.template_after
    assert store.read_commit("a1") is not None
    assert [unit.action_id for unit in history.units()] == ["a1"]

    # Fully idempotent afterwards.
    again = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history
    )
    assert again.content_sha256 == first.content_sha256
    assert [unit.action_id for unit in history.units()] == ["a1"]


@requires_prepared
def test_commit_event_backfilled_once_after_crash(tmp_path: Path) -> None:
    """commit.json durable but ACTION_COMMITTED missing: backfill once, no redo."""

    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    store = ActionStore(tmp_path / "run")
    history = HistoryStore(tmp_path / "run")
    run_role_call(store, _request("a1"), source=ScriptedMockSource([VALID_PATCH]))
    policy = PatchPolicy(allowed_examples=(2,), allowed_fields=("code",))
    first = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history,
        summary={"example": 2, "field": "code"},
    )
    assert store.has_event("a1", ACTION_COMMITTED)

    # Simulate the crash window: drop the committed event line, keep commit.json.
    lines = [
        line
        for line in store.actions_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["event_type"] != ACTION_COMMITTED
    ]
    store.actions_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not store.has_event("a1", ACTION_COMMITTED)

    resumed = commit_mutator_result(
        store, "a1", snapshot, policy, snapshot_store=store_root, history=history
    )
    assert resumed.content_sha256 == first.content_sha256
    assert store.has_event("a1", ACTION_COMMITTED)
    assert [e for e in store.events("a1") if e["event_type"] == ACTION_COMMITTED].__len__() == 1
    assert [unit.action_id for unit in history.units()] == ["a1"]

    # A second recovery must not append the event again.
    commit_mutator_result(store, "a1", snapshot, policy, snapshot_store=store_root, history=history)
    assert [e for e in store.events("a1") if e["event_type"] == ACTION_COMMITTED].__len__() == 1


def test_demo_config_requires_output_reserve_to_cover_max_tokens(tmp_path: Path) -> None:
    from coco_attack.iteration.action_demo import DemoConfig

    base = dict(
        snapshot_path=str(tmp_path / "snap"),
        run_dir=str(tmp_path / "run"),
        assets_root=str(tmp_path),
        snapshot_store=str(tmp_path / "store"),
    )
    with pytest.raises(ValueError):
        DemoConfig(**base, max_tokens=8192, output_reserve_tokens=2048)
    accepted = DemoConfig(**base, max_tokens=8192, output_reserve_tokens=8192)
    assert accepted.output_reserve_tokens >= accepted.max_tokens


@requires_prepared
def test_out_of_range_patch_is_rejected(tmp_path: Path) -> None:
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store = ActionStore(tmp_path / "run")
    bad = json.dumps([{"example": 99, "code": "def task_func():\n    return 1\n"}])
    run_role_call(store, _request("a1"), source=ScriptedMockSource([bad]))
    outcome = commit_mutator_result(
        store, "a1", snapshot, PatchPolicy(allowed_examples=(2,), allowed_fields=("code",)),
        snapshot_store=tmp_path / "snapshots",
    )
    assert outcome.status == "invalid_patch"
    assert outcome.template_after == snapshot.content_sha256()


# --------------------------------------------------------------------------- #
# 3. Shared history and token budgeting
# --------------------------------------------------------------------------- #


def _unit(action_id: str, content: str = "code") -> HistoryUnit:
    return HistoryUnit(
        action_id=action_id,
        role="mutator",
        kind="mutator",
        summary={"example": 2, "escaped": False},
        user_content=content,
        assistant_content=f"patch-{action_id}",
        request_sha256="f" * 64,
    )


def test_history_store_is_idempotent_and_conflict_aware(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path)
    store.append_unit(_unit("a1"))
    store.append_unit(_unit("a1"))
    assert len(store.units()) == 1
    with pytest.raises(ActionConflictError):
        store.append_unit(
            HistoryUnit("a1", "mutator", "mutator", {}, "other", None, "e" * 64)
        )


def test_history_no_compression_when_it_fits(tmp_path: Path) -> None:
    units = [_unit(f"a{i}") for i in range(3)]
    counter = HeuristicTokenCounter()
    budget = ContextBudget(context_window_tokens=100000, output_reserve_tokens=100)
    assembly = assemble_history(
        system_block="sys", current_user_content="now", units=units, budget=budget, counter=counter
    )
    assert assembly.compressed_action_ids == ()
    assert [m["role"] for m in assembly.messages] == [
        "system", "user", "assistant", "user", "assistant", "user", "assistant", "user",
    ]
    assert any(m["content"] == "code" for m in assembly.messages)


def test_history_compresses_old_units_deterministically(tmp_path: Path) -> None:
    units = [_unit(f"a{i}", content="x" * 200) for i in range(6)]
    counter = HeuristicTokenCounter()
    budget = ContextBudget(context_window_tokens=400, output_reserve_tokens=50)
    first = assemble_history(
        system_block="sys", current_user_content="now", units=units, budget=budget, counter=counter
    )
    second = assemble_history(
        system_block="sys", current_user_content="now", units=units, budget=budget, counter=counter
    )
    assert first.messages == second.messages
    assert first.compressed_action_ids
    # The pinned system block and the current request survive every time.
    assert first.messages[0]["role"] == "system"
    assert first.messages[-1]["content"] == "now"
    # Summaries are one line per compressed unit.
    summary_message = first.messages[1]["content"]
    assert summary_message.count("example=2") == len(first.compressed_action_ids)
    # §0: the compressed, model-visible summary must not expose internal action ids
    # or audit hashes; it uses an ordinary sequence label instead.
    for unit in units:
        assert unit.action_id not in summary_message
    assert "request_sha256" not in summary_message
    assert "\u4ea4\u4e92 1" in summary_message


@requires_prepared
def test_offline_demo_two_interactions_with_interrupt_resume(tmp_path: Path) -> None:
    from coco_attack.iteration.action_demo import DemoConfig, run_offline_demo

    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "store"
    write_snapshot(store_root, snapshot, action_id="init")
    snapshot_path = store_root / COMBINATION / snapshot.content_sha256()

    demo = DemoConfig(
        snapshot_path=str(snapshot_path),
        run_dir=str(tmp_path / "run"),
        assets_root=str(ASSETS_DIR),
        snapshot_store=str(store_root),
    )
    report = run_offline_demo(demo)

    first, second = report["interactions"]
    # The first response was durable before the interrupt; resume reused it.
    assert first["state"] == STATE_RESPONSE_SAVED
    assert first["resume_state"] == STATE_RESPONSE_REUSED
    assert first["resume_provider_calls"] == 0
    assert first["commit_once"] is True
    assert first["diff"] and first["diff"][0]["example"] == 2
    # Template advanced and exactly one history unit per committed interaction.
    assert first["template_after"] != first["template_before"]
    assert second["state"] == STATE_RESPONSE_SAVED
    assert report["history_units"] == 2
    assert report["final_template"] == second["template_after"]


def test_history_fixed_block_over_budget_raises() -> None:
    counter = HeuristicTokenCounter()
    budget = ContextBudget(context_window_tokens=10, output_reserve_tokens=5)
    with pytest.raises(ContextAssemblyError):
        assemble_history(
            system_block="a" * 1000, current_user_content="b" * 1000, units=[], budget=budget, counter=counter
        )
