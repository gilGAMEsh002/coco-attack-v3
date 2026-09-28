"""Tests for the read-only mutator message export (``export-mutator-messages``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_file
from coco_attack.iteration.message_export import (
    MessageExportError,
    export_mutator_messages,
)

REPO_DIR = Path(__file__).resolve().parents[2]
REAL_RUN_DIR = (
    REPO_DIR
    / "cocota_runs/phase04/method-ab-flash-v32-concurrent-r1/run"
)
REAL_RUN_AVAILABLE = (REAL_RUN_DIR / "actions.jsonl").is_file()


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_event(run_dir: Path, action_id: str, event_type: str, payload: dict, ts: str = "2026-01-01T00:00:00+00:00") -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    row = {
        "schema_version": "action-runtime-v1",
        "event_id": f"{action_id}-{event_type}-{ts}",
        "ts": ts,
        "event_type": event_type,
        "action_id": action_id,
        "payload": payload,
    }
    with open(run_dir / "actions.jsonl", "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _request(run_dir: Path, action_id: str, messages: list[dict], *, created_at: str | None = None, role: str = "mutator", kind: str = "mutator") -> None:
    _write_json(
        run_dir / "actions" / action_id / "request.json",
        {
            "schema_version": "action-runtime-v1",
            "action_id": action_id,
            "role": role,
            "kind": kind,
            "messages": messages,
            "input_refs": {},
            "config": {"role": role, "model": "mock", "source": "mock"},
            "created_at": created_at,
            "request_sha256": "0" * 64,
        },
    )


def _response(run_dir: Path, action_id: str, attempt_id: str, attempt_index: int, *, status: str = "success", content: str = "", usage: dict | None = None, cost: dict | None = None, finish_reason: str = "stop") -> None:
    _write_json(
        run_dir / "actions" / action_id / "responses" / f"{attempt_id}.json",
        {
            "schema_version": "action-runtime-v1",
            "action_id": action_id,
            "request_attempt_id": attempt_id,
            "attempt_index": attempt_index,
            "status": status,
            "content": content,
            "content_sha256": __import__("hashlib").sha256(content.encode()).hexdigest(),
            "finish_reason": finish_reason,
            "response_id": f"resp-{attempt_id}",
            "model": "mock",
            "usage": usage if usage is not None else {},
            "cost": cost if cost is not None else {"basis": "unknown", "amount": None, "currency": "USD"},
            "cache_hit": False,
        },
    )


def _records(output_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (output_dir / "messages.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def _by_id(records: list[dict], action_id: str) -> dict:
    return next(record for record in records if record["action_id"] == action_id)


def test_ordering_uses_planning_line_not_timestamp_or_lexicographic(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    ts = "2026-01-01T00:00:00+00:00"
    # "R2" is planned first; "R10" second, with the *same* timestamp.  Lexicographic
    # order would put R10 first, so this proves the physical ledger line is used.
    for action_id in ("R2", "R10"):
        _request(run_dir, action_id, [{"role": "user", "content": action_id}], created_at=ts)
        _append_event(run_dir, action_id, "action_planned", {"request_sha256": "0" * 64}, ts=ts)
        attempt = f"attempt-{action_id}"
        _append_event(run_dir, action_id, "attempt_started", {"attempt_index": 0, "request_attempt_id": attempt}, ts=ts)
        _append_event(run_dir, action_id, "response_saved", {"attempt_index": 0, "request_attempt_id": attempt, "status": "success"}, ts=ts)
        _response(run_dir, action_id, attempt, 0, content=action_id)

    manifest = export_mutator_messages(run_dir, output)
    assert manifest["ordering"]["basis_counts"] == {"action_planned_line": 2}
    records = _records(output)
    assert [r["action_id"] for r in records] == ["R2", "R10"]
    assert [r["order"]["index"] for r in records] == [1, 2]


def test_ordering_fallbacks_are_marked_incomplete(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    ts = "2026-01-01T00:00:00+00:00"
    # P: normal planning event.
    _request(run_dir, "P", [{"role": "user", "content": "p"}], created_at=ts)
    _append_event(run_dir, "P", "action_planned", {"request_sha256": "0" * 64}, ts=ts)
    # L: no planning event, but has ledger events.
    _request(run_dir, "L", [{"role": "user", "content": "l"}], created_at=ts)
    _append_event(run_dir, "L", "attempt_started", {"attempt_index": 0, "request_attempt_id": "l-1"}, ts=ts)
    _append_event(run_dir, "L", "response_saved", {"attempt_index": 0, "request_attempt_id": "l-1", "status": "success"}, ts=ts)
    _response(run_dir, "L", "l-1", 0, content="l")
    # M: only a method_events row.
    _request(run_dir, "M", [{"role": "user", "content": "m"}], created_at=ts)
    with open(run_dir / "method_events.jsonl", "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event_type": "A_action", "payload": {"action_id": "M"}, "ts": ts}) + "\n")
    # C: only request.created_at.
    _request(run_dir, "C", [{"role": "user", "content": "c"}], created_at="2026-02-02T00:00:00+00:00")
    # N: no ordering evidence at all.
    _request(run_dir, "N", [{"role": "user", "content": "n"}], created_at=None)

    manifest = export_mutator_messages(run_dir, output)
    basis = manifest["ordering"]["basis_counts"]
    assert basis["action_planned_line"] == 1
    assert basis["ledger_first_event_line"] == 1
    assert basis["method_events_line"] == 1
    assert basis["request_created_at"] == 1
    assert basis["none"] == 1
    incomplete = {item["action_id"]: item["basis"] for item in manifest["ordering"]["incomplete_ordering"]}
    assert incomplete == {
        "L": "ledger_first_event_line",
        "M": "method_events_line",
        "C": "request_created_at",
        "N": "none",
    }
    assert [r["action_id"] for r in _records(output)] == ["P", "L", "M", "C", "N"]


def test_retry_attempts_keyed_by_request_attempt_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    _request(run_dir, "A", [{"role": "user", "content": "a"}])
    _append_event(run_dir, "A", "action_planned", {"request_sha256": "0" * 64})
    _append_event(run_dir, "A", "attempt_started", {"attempt_index": 0, "request_attempt_id": "a-0"})
    _append_event(run_dir, "A", "attempt_failed", {"attempt_index": 0, "request_attempt_id": "a-0", "error_type": "LMTimeoutError", "error_reason": "timeout", "retryable": True})
    _append_event(run_dir, "A", "attempt_started", {"attempt_index": 1, "request_attempt_id": "a-1"})
    _append_event(run_dir, "A", "attempt_failed", {"attempt_index": 1, "request_attempt_id": "a-1", "error_type": "LMTimeoutError", "error_reason": "timeout", "retryable": True})
    _append_event(run_dir, "A", "attempt_started", {"attempt_index": 2, "request_attempt_id": "a-2"})
    _append_event(run_dir, "A", "response_saved", {"attempt_index": 2, "request_attempt_id": "a-2", "status": "success"})
    _response(run_dir, "A", "a-2", 2, content="ok", usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})

    manifest = export_mutator_messages(run_dir, output)
    record = _by_id(_records(output), "A")
    assert [a["request_attempt_id"] for a in record["attempts"]] == ["a-0", "a-1", "a-2"]
    assert [a["classifications"] for a in record["attempts"]] == [
        ["failed_attempt_no_response"],
        ["failed_attempt_no_response"],
        [],
    ]
    assert record["attempts"][2]["response"]["content"] == "ok"
    assert manifest["counts"]["attempts"] == 3
    assert manifest["counts"]["attempt_failed_events"] == 2
    assert manifest["counts"]["attempt_failed_retryable"] == 2
    assert manifest["counts"]["attempt_failed_by_error_type"] == {"LMTimeoutError": 2}
    assert manifest["counts"]["orphan_attempts"] == 0


def test_duplicate_and_conflicting_events_are_diagnosed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    _request(run_dir, "D", [{"role": "user", "content": "d"}])
    _append_event(run_dir, "D", "action_planned", {"request_sha256": "0" * 64})
    # Duplicate attempt_started and identical response_saved must not create attempts.
    _append_event(run_dir, "D", "attempt_started", {"attempt_index": 0, "request_attempt_id": "d-0"})
    _append_event(run_dir, "D", "attempt_started", {"attempt_index": 0, "request_attempt_id": "d-0"})
    _append_event(run_dir, "D", "response_saved", {"attempt_index": 0, "request_attempt_id": "d-0", "status": "success", "content_sha256": "aa"})
    _append_event(run_dir, "D", "response_saved", {"attempt_index": 0, "request_attempt_id": "d-0", "status": "success", "content_sha256": "aa"})
    # A second attempt whose two response_saved events disagree on content_sha256.
    _append_event(run_dir, "D", "attempt_started", {"attempt_index": 1, "request_attempt_id": "d-1"})
    _append_event(run_dir, "D", "response_saved", {"attempt_index": 1, "request_attempt_id": "d-1", "status": "success", "content_sha256": "bb"})
    _append_event(run_dir, "D", "response_saved", {"attempt_index": 1, "request_attempt_id": "d-1", "status": "success", "content_sha256": "cc"})

    manifest = export_mutator_messages(run_dir, output)
    record = _by_id(_records(output), "D")
    assert len(record["attempts"]) == 2
    kinds = [anomaly["kind"] for anomaly in manifest["anomalies"]]
    assert "duplicate_event" in kinds
    assert "conflicting_event" in kinds
    assert manifest["counts"]["attempts"] == 2


def test_bidirectional_inconsistencies_and_true_orphan(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    _request(run_dir, "X", [{"role": "user", "content": "x"}])
    _append_event(run_dir, "X", "action_planned", {"request_sha256": "0" * 64})
    # event with no file
    _append_event(run_dir, "X", "attempt_started", {"attempt_index": 0, "request_attempt_id": "x-0"})
    _append_event(run_dir, "X", "response_saved", {"attempt_index": 0, "request_attempt_id": "x-0", "status": "success", "content_sha256": "aa"})
    # file with no event (and no attempt_started)
    _response(run_dir, "X", "x-0file", 1, content="file-only")
    # true orphan: started, no terminal, no file
    _append_event(run_dir, "X", "attempt_started", {"attempt_index": 2, "request_attempt_id": "x-orphan"})

    manifest = export_mutator_messages(run_dir, output)
    record = _by_id(_records(output), "X")
    classes = {a["request_attempt_id"]: a["classifications"] for a in record["attempts"]}
    assert "missing_response_file" in classes["x-0"]
    assert classes["x-0file"] == ["missing_attempt_events", "response_without_event"]
    assert classes["x-orphan"] == ["orphan_attempt"]
    assert manifest["counts"]["orphan_attempts"] == 1
    assert manifest["integrity"]["responses_without_event"] == [{"action_id": "X", "request_attempt_id": "x-0file"}]
    assert manifest["integrity"]["missing_response_files"] == [{"action_id": "X", "request_attempt_id": "x-0"}]
    assert manifest["integrity"]["orphan_attempts"] == [{"action_id": "X", "request_attempt_id": "x-orphan"}]


def test_corrupt_and_identity_conflicts_are_reported(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    # request action_id disagrees with its directory
    _request(run_dir, "Y", [{"role": "user", "content": "y"}])
    config = json.loads((run_dir / "actions" / "Y" / "request.json").read_text(encoding="utf-8"))
    config["action_id"] = "OTHER"
    _write_json(run_dir / "actions" / "Y" / "request.json", config)
    _append_event(run_dir, "Y", "action_planned", {"request_sha256": "0" * 64})
    # a valid response file whose action_id conflicts
    _response(run_dir, "Y", "y-0", 0, content="ok")
    response_path = run_dir / "actions" / "Y" / "responses" / "y-0.json"
    payload = json.loads(response_path.read_text(encoding="utf-8"))
    payload["action_id"] = "ELSEWHERE"
    _write_json(response_path, payload)
    _append_event(run_dir, "Y", "attempt_started", {"attempt_index": 0, "request_attempt_id": "y-0"})
    _append_event(run_dir, "Y", "response_saved", {"attempt_index": 0, "request_attempt_id": "y-0", "status": "success"})
    # a corrupt response file
    (run_dir / "actions" / "Y" / "responses" / "broken.json").write_text("{not json", encoding="utf-8")

    manifest = export_mutator_messages(run_dir, output)
    kinds = [anomaly["kind"] for anomaly in manifest["anomalies"]]
    assert "request_identity_conflict" in kinds
    assert "response_identity_conflict" in kinds
    assert "corrupt_response_file" in kinds


def test_incomplete_ledger_tail_is_reported(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    _request(run_dir, "A", [{"role": "user", "content": "a"}])
    _append_event(run_dir, "A", "action_planned", {"request_sha256": "0" * 64})
    with open(run_dir / "actions.jsonl", "a", encoding="utf-8") as handle:
        handle.write('{"action_id": "B", "event_type": "action_pl')  # torn tail

    manifest = export_mutator_messages(run_dir, output)
    assert manifest["integrity"]["incomplete_ledger_tail"] is True
    assert any(anomaly["kind"] == "incomplete_ledger_tail" for anomaly in manifest["anomalies"])


def test_content_fidelity_and_unknown_cost(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    chinese = "示例 2 的中文说明：间接化字面锚点。"
    code = "def task_func(x):\n    return x + 1\n"
    messages = [
        {"role": "system", "content": chinese},
        {"role": "user", "content": code},
        {"role": "user", "content": code},  # duplicated history preserved
    ]
    _request(run_dir, "F", messages)
    _append_event(run_dir, "F", "action_planned", {"request_sha256": "0" * 64})
    _append_event(run_dir, "F", "attempt_started", {"attempt_index": 0, "request_attempt_id": "f-0"})
    _append_event(run_dir, "F", "attempt_failed", {"attempt_index": 0, "request_attempt_id": "f-0", "error_type": "LMTimeoutError", "retryable": True})
    _append_event(run_dir, "F", "attempt_started", {"attempt_index": 1, "request_attempt_id": "f-1"})
    _append_event(run_dir, "F", "response_saved", {"attempt_index": 1, "request_attempt_id": "f-1", "status": "truncated", "content_sha256": "e3b0"})
    _response(run_dir, "F", "f-1", 1, status="truncated", content="", usage={"completion_tokens": 8192}, cost={"basis": "unknown", "amount": None, "currency": "USD"}, finish_reason="length")

    manifest = export_mutator_messages(run_dir, output)
    record = _by_id(_records(output), "F")
    assert record["request"]["messages"] == messages  # duplicates and order preserved verbatim
    assert record["attempts"][1]["response"]["content"] == ""  # empty response preserved
    assert record["attempts"][1]["response"]["finish_reason"] == "length"
    assert record["attempts"][1]["response"]["cost"]["amount"] is None
    assert manifest["counts"]["responses_by_status"] == {"truncated": 1}
    assert manifest["counts"]["attempt_failed_by_error_type"] == {"LMTimeoutError": 1}


def test_html_is_escaped_and_collapsed_by_default(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    dangerous = "<script>alert(1)</script> & <b>"
    fence = "```python\nsubprocess.run(cmd, shell=True)\n```"
    _request(run_dir, "H", [{"role": "user", "content": dangerous}, {"role": "user", "content": fence}])
    _append_event(run_dir, "H", "action_planned", {"request_sha256": "0" * 64})
    _append_event(run_dir, "H", "attempt_started", {"attempt_index": 0, "request_attempt_id": "h-0"})
    _append_event(run_dir, "H", "response_saved", {"attempt_index": 0, "request_attempt_id": "h-0", "status": "success"})
    _response(run_dir, "H", "h-0", 0, content="</pre><script>evil()</script>")

    export_mutator_messages(run_dir, output)
    html = (output / "index.html").read_text(encoding="utf-8")
    # Raw tags / ampersand / closing script must never appear unescaped.
    assert "<script>alert(1)</script>" not in html
    assert "<script>evil()</script>" not in html
    assert "</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html
    # A triple-backtick fence is ordinary text in the export, not a code block.
    assert fence in html  # literal text, no markdown rendering
    assert '<details class="msg">' in html
    assert '<details class="msg" open>' not in html


def test_source_files_unchanged_and_output_must_be_fresh(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    output = tmp_path / "export"
    _request(run_dir, "A", [{"role": "user", "content": "a"}])
    _append_event(run_dir, "A", "action_planned", {"request_sha256": "0" * 64})
    before = {p: sha256_file(p) for p in sorted(run_dir.rglob("*")) if p.is_file()}

    manifest = export_mutator_messages(run_dir, output)
    assert manifest["export_complete"] is True
    assert manifest["sources_unchanged_during_export"] is True
    after = {p: sha256_file(p) for p in sorted(run_dir.rglob("*")) if p.is_file()}
    assert before == after

    with pytest.raises(MessageExportError):
        export_mutator_messages(run_dir, output)  # already exists
    with pytest.raises(MessageExportError):
        export_mutator_messages(run_dir, run_dir / "nested-export")  # overlaps source
    with pytest.raises(MessageExportError):
        export_mutator_messages(run_dir, tmp_path)  # parent of the run dir overlaps


@pytest.mark.skipif(not REAL_RUN_AVAILABLE, reason="real method run product is not present")
def test_real_run_product_export_base_counts(tmp_path: Path) -> None:
    output = tmp_path / "real-export"
    manifest = export_mutator_messages(REAL_RUN_DIR, output)
    counts = manifest["counts"]
    assert counts["actions"] == 14
    assert counts["attempts"] == 20
    assert counts["attempt_failed_events"] == 6
    assert counts["attempt_failed_retryable"] == 6
    assert counts["attempt_failed_by_error_type"] == {"LMTimeoutError": 6}
    assert counts["responses_by_status"] == {"success": 13, "truncated": 1}
    assert counts["response_files"] == 14
    assert counts["orphan_attempts"] == 0
    # Six recorded timeouts have attempt_failed and must not be called orphans.
    assert manifest["integrity"]["orphan_attempts"] == []
    assert len(manifest["integrity"]["failed_attempts_no_response"]) == 6
    # The first empty/truncated response is preserved.
    records = _records(output)
    first = records[0]
    assert first["action_id"] == "R1-A0"
    responses = [a["response"] for a in first["attempts"] if a.get("response")]
    assert responses and responses[0]["content"] == ""
    assert responses[0]["status"] == "truncated"
    assert responses[0]["finish_reason"] == "length"
    # Patch layer is distinct from "successful response": a success response may
    # still be an invalid patch.
    assert counts["actions_with_commit"] == 12
    assert counts["result_status_counts"] == {"invalid_patch": 2, "patched": 12}
    assert counts["patch_outcome"]["committed"] == 12
    assert counts["patch_outcome"]["result_without_commit"] == 2
    # Read-only proof: every source file's before/after hash matches.
    for source in manifest["sources"]:
        assert source["sha256"] == source["sha256_after"], source["path"]
