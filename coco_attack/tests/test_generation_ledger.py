"""Ledger append/replay/recovery tests (stage 02, task 02)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.runtime.ledger import (
    EVENT_ATTEMPT_FAILED,
    EVENT_RESPONSE_RECEIVED,
    EVENT_SAMPLE_FINALIZED,
    Ledger,
    LedgerError,
)


def test_ledger_append_and_replay(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append(
        EVENT_RESPONSE_RECEIVED,
        sample_id="s1",
        request_attempt_id="a1",
        payload={"usage": {"prompt_tokens": 3}, "content": "x"},
    )
    ledger.append(EVENT_SAMPLE_FINALIZED, sample_id="s1", payload={"record": {"sample_id": "s1"}})

    replay = ledger.replay()
    assert [event["event_type"] for event in replay.events] == [
        EVENT_RESPONSE_RECEIVED,
        EVENT_SAMPLE_FINALIZED,
    ]
    assert [event["seq"] for event in replay.events] == [1, 2]
    assert replay.finalized_sample_ids() == {"s1"}
    assert replay.first_usage_by_sample()["s1"]["usage"]["prompt_tokens"] == 3
    assert replay.finalized_records()["s1"]["sample_id"] == "s1"


def test_ledger_tolerates_only_a_torn_final_record(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    ledger.append(EVENT_ATTEMPT_FAILED, sample_id="s1", payload={"error_type": "X"})
    with open(path, "ab") as handle:
        handle.write(b'{"event_id": "broken", "event_type": "response_received"')
        handle.flush()

    replay = ledger.replay()
    assert len(replay.events) == 1
    assert replay.incomplete_tail_path is not None
    assert Path(replay.incomplete_tail_path).read_bytes().startswith(b'{"event_id": "broken"')


def test_ledger_repairs_torn_tail_before_appending(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    ledger.append(EVENT_ATTEMPT_FAILED, sample_id="s1", payload={})
    torn = b'{"event_id": "broken", "event_type": "response_received"'
    with open(path, "ab") as handle:
        handle.write(torn)
        handle.flush()

    # Reopening as the recovery writer must preserve the torn bytes in ``.tail``
    # and truncate them before the next append, so the new event is durable.
    recovered = Ledger(path)
    assert recovered.replay().valid_prefix_bytes is not None
    recovered.append(
        EVENT_RESPONSE_RECEIVED,
        sample_id="s1",
        payload={"usage": {"total_tokens": 7}},
    )

    replay = Ledger(path).replay()
    assert [event["event_type"] for event in replay.events] == [
        EVENT_ATTEMPT_FAILED,
        EVENT_RESPONSE_RECEIVED,
    ]
    assert replay.first_usage_by_sample()["s1"]["usage"]["total_tokens"] == 7
    tail = path.with_name(path.name + ".tail")
    assert tail.read_bytes() == torn

    # A later append sees a clean ledger and stays parseable.
    Ledger(path).append(
        EVENT_SAMPLE_FINALIZED, sample_id="s1", payload={"record": {"sample_id": "s1"}}
    )
    assert len(Ledger(path).replay().events) == 3


def test_ledger_append_after_valid_record_without_newline(tmp_path: Path) -> None:
    # A crash can flush a complete JSON record whose trailing newline is lost.
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    ledger.append(EVENT_ATTEMPT_FAILED, sample_id="s1", payload={})
    data = path.read_bytes()
    assert data.endswith(b"\n")
    path.write_bytes(data[:-1])

    recovered = Ledger(path)
    recovered.append(
        EVENT_RESPONSE_RECEIVED, sample_id="s1", payload={"usage": {"total_tokens": 5}}
    )

    replay = Ledger(path).replay()
    assert [event["event_type"] for event in replay.events] == [
        EVENT_ATTEMPT_FAILED,
        EVENT_RESPONSE_RECEIVED,
    ]
    assert replay.first_usage_by_sample()["s1"]["usage"]["total_tokens"] == 5


def test_ledger_rejects_midfile_corruption(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    ledger.append(EVENT_ATTEMPT_FAILED, sample_id="s1", payload={})
    with open(path, "ab") as handle:
        handle.write(b"not json\n")
    ledger.append(EVENT_ATTEMPT_FAILED, sample_id="s2", payload={})

    with pytest.raises(LedgerError):
        Ledger(path).replay()


def test_ledger_rejects_unknown_event_type(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with pytest.raises(LedgerError):
        ledger.append("not_a_type", sample_id="s1")
