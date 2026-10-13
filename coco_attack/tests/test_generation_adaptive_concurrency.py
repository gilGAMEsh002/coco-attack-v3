"""Offline request scheduling, backoff, and replay for adaptive generation."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import canonical_json_bytes, sha256_bytes
from coco_attack.generation.contracts import GenerationConfig, GenerationContractError, SampleIdentity
from coco_attack.generation.inputs import GenerationInputs, GenerationSample
from coco_attack.generation.runner import GenerationRunner, _AdaptiveConcurrency
from coco_attack.generation.source import ExtractedResponse, ResponseContractError
from coco_attack.runtime.ledger import EVENT_RESPONSE_RECEIVED, Ledger


def _config(**changes) -> GenerationConfig:
    config = GenerationConfig(
        source="mock", model="test", batch_id="batch", combination_id="cwe078-0",
        oracle_id="cwe078-0", stage="search", form="clean_fewshot_cot", prompt_version="1",
        candidate_hash="", temperature=0.7, repeats=1, max_tokens=128,
        request_timeout=30, max_concurrency=16, max_request_attempts=2,
        max_sample_retries=0, concurrency_mode="adaptive", min_concurrency=4,
    )
    return replace(config, **changes)


def _inputs(count: int) -> GenerationInputs:
    samples = tuple(
        GenerationSample(
            SampleIdentity("search", "batch", "cwe078-0", f"BigCodeBench/{i}", 0, "1", "c" * 64),
            f"task {i}", "p" * 64,
        )
        for i in range(count)
    )
    return GenerationInputs("cwe078-0", "cwe078-0", "clean_fewshot_cot", "search",
                            "t" * 64, "m" * 64, "c" * 64, samples)


def _response(*, cached=False, content="print(1)", finish_reason="stop") -> ExtractedResponse:
    return ExtractedResponse(content, finish_reason, {}, cached, "response", "test")


class _Source:
    def __init__(self, *, first_wave=False, retry=False, cached=False) -> None:
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(4) if first_wave else None
        self.retry = retry
        self.cached = cached
        self.calls = []
        self.inflight = 0
        self.peak = 0

    def generate(self, messages, rollout_id, attempt_index):
        with self.lock:
            self.calls.append((rollout_id, attempt_index))
            number = len(self.calls)
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
        try:
            if self.barrier is not None and number <= 4:
                self.barrier.wait(timeout=5)
            time.sleep(0.01)
            if self.retry and attempt_index == 0:
                raise ConnectionError("offline simulated connection failure")
            return _response(cached=self.cached)
        finally:
            with self.lock:
                self.inflight -= 1


def _run(tmp_path: Path, source, count=32, config=None):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    runner = GenerationRunner(config or _config(), _inputs(count), ledger, source, tmp_path)
    return runner.run(), ledger


def test_adaptive_starts_at_four_grows_and_obeys_sixteen_ceiling(tmp_path):
    source = _Source(first_wave=True)
    summary, ledger = _run(tmp_path, source)
    assert summary["status_counts"] == {"success": 32}
    assert summary["concurrency"]["target"] == 16
    assert 4 < source.peak <= 16
    # Admission includes writing attempt_started before entering the source;
    # that brief preparation can make its peak exceed the stub's call peak.
    assert source.peak <= summary["concurrency"]["peak_inflight"] <= 16
    assert summary["concurrency"]["inflight"] == 0
    events = [json.loads(line) for line in (tmp_path / "concurrency_events.jsonl").read_text().splitlines()]
    assert events[0]["old_target"] is None
    assert events[0]["new_target"] == 4
    assert [event["new_target"] for event in events] == list(range(4, 17))
    assert len(ledger.replay().finalized_records()) == 32
    assert json.loads((tmp_path / "concurrency_state.json").read_text()) == summary["concurrency"]


def test_no_more_than_floor_requests_start_before_first_response(tmp_path):
    first_wave_ready = threading.Event()
    release_wave = threading.Event()

    class Source:
        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()

        def generate(self, *args):
            with self.lock:
                self.calls += 1
                if self.calls == 4:
                    first_wave_ready.set()
            assert release_wave.wait(timeout=5)
            return _response()

    source = Source()
    ledger = Ledger(tmp_path / "ledger.jsonl")
    runner = GenerationRunner(_config(), _inputs(20), ledger, source, tmp_path)
    result = []
    thread = threading.Thread(target=lambda: result.append(runner.run()), daemon=True)
    thread.start()
    try:
        assert first_wave_ready.wait(timeout=3)
        # All 16 worker threads may exist, but only 4 actual attempts have
        # started. This keeps the request ledger useful as a live monitor.
        assert source.calls == 4
        started = [event for event in ledger.replay().events if event["event_type"] == "attempt_started"]
        assert len(started) == 4
    finally:
        release_wave.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result[0]["status_counts"] == {"success": 20}


def test_halving_waits_for_inflight_without_cancelling_or_deadlock(tmp_path):
    controller = _AdaptiveConcurrency(4, 16, tmp_path)
    for _ in range(12):
        controller.acquire()
        controller.release(response=_response())
    for _ in range(12):
        controller.acquire()
    controller.release(error=ConnectionError())
    assert controller.target == 8 and controller.inflight == 11
    controller.release(error=TimeoutError())
    assert controller.target == 4 and controller.inflight == 10
    acquired = threading.Event()

    def waiting_request():
        controller.acquire()
        acquired.set()
        controller.release(response=_response(cached=True))

    waiter = threading.Thread(target=waiting_request, daemon=True)
    waiter.start()
    assert not acquired.wait(timeout=0.05)
    for _ in range(6):
        controller.release(response=_response(cached=True))
    assert controller.inflight == 4
    assert not acquired.wait(timeout=0.05)
    controller.release(response=_response(cached=True))
    assert acquired.wait(timeout=2)
    waiter.join(timeout=2)
    assert not waiter.is_alive()
    for _ in range(3):
        controller.release(response=_response(cached=True))
    assert controller.inflight == 0 and controller.target == 4


def test_retry_attempts_release_permits_and_keep_existing_attempt_budget(tmp_path):
    source = _Source(first_wave=True, retry=True)
    summary, ledger = _run(tmp_path, source, count=20)
    assert summary["status_counts"] == {"success": 20}
    assert len(source.calls) == 40
    assert all(record["retry_count"] == 1 for record in ledger.replay().finalized_records().values())
    assert source.inflight == summary["concurrency"]["inflight"] == 0
    assert source.peak <= 16


def test_cache_hits_do_not_inflate_capacity(tmp_path):
    summary, _ = _run(tmp_path, _Source(cached=True), count=20)
    assert summary["concurrency"]["target"] == 4
    assert summary["concurrency"]["peak_inflight"] <= 4
    assert len((tmp_path / "concurrency_events.jsonl").read_text().splitlines()) == 1


@pytest.mark.parametrize("content,finish_reason,status", [("", "stop", "empty"), ("code", "length", "truncated")])
def test_semantic_response_status_does_not_reduce_provider_capacity(tmp_path, content, finish_reason, status):
    class Source:
        def generate(self, *args):
            return _response(content=content, finish_reason=finish_reason)

    summary, _ = _run(tmp_path, Source(), count=4)
    assert summary["status_counts"] == {status: 4}
    assert summary["concurrency"]["target"] == 8


def test_invalid_response_shape_is_not_transport_congestion(tmp_path):
    class Source:
        def generate(self, *args):
            raise ResponseContractError("offline invalid shape")

    summary, _ = _run(tmp_path, Source(), count=8)
    assert summary["status_counts"] == {"invalid_response": 8}
    assert summary["concurrency"]["target"] == 4
    assert summary["concurrency"]["inflight"] == 0


def test_wrapped_http_rate_limit_decreases_target(tmp_path):
    class RateError(Exception):
        status_code = 429

    controller = _AdaptiveConcurrency(4, 16, tmp_path)
    for _ in range(8):
        controller.acquire()
        controller.release(response=_response())
    cause = RateError()
    error = RuntimeError("wrapped")
    error.__cause__ = cause
    controller.acquire()
    controller.release(error=error)
    assert controller.target == 6
    controller.acquire()
    controller.release(error=error)
    assert controller.target == 4


def test_resume_does_not_call_provider_for_finalized_or_unfinalized_durable_response(tmp_path):
    inputs = _inputs(2)
    source = _Source()
    _, ledger = _run(tmp_path, source, count=1)
    sample = inputs.samples[1]
    ledger.append(
        EVENT_RESPONSE_RECEIVED, sample_id=sample.sample_id, request_attempt_id="durable-attempt",
        payload={"content": "durable code", "finish_reason": "stop", "usage": {},
                 "cost": {"basis": "unknown", "amount": None}, "cache_hit": False,
                 "response_id": "durable", "model": "test", "attempt_index": 0},
    )

    class Forbidden:
        def generate(self, *args):
            raise AssertionError("no network request during response recovery")

    summary = GenerationRunner(_config(), inputs, ledger, Forbidden(), tmp_path).run()
    assert summary["generated"] == 0
    assert summary["skipped_finalized"] == 2
    assert summary["concurrency"]["target"] == 4
    assert summary["concurrency"]["peak_inflight"] == 0
    assert ledger.replay().finalized_records()[sample.sample_id]["generation"] == "durable code"


def test_fixed_serialization_and_hash_preserve_existing_identity(tmp_path):
    config = _config(concurrency_mode="fixed", min_concurrency=1, max_concurrency=4)
    payload = config.to_json()
    assert "concurrency_mode" not in payload and "min_concurrency" not in payload
    old_payload = {name: value for name, value in payload.items() if name not in ("concurrency_mode", "min_concurrency")}
    assert config.run_config_hash() == sha256_bytes(canonical_json_bytes(old_payload))
    assert GenerationConfig.from_json(payload) == config
    summary, _ = _run(tmp_path, _Source(), count=4, config=config)
    assert "concurrency" not in summary
    assert not (tmp_path / "concurrency_events.jsonl").exists()
    assert not (tmp_path / "concurrency_state.json").exists()
    adaptive = replace(config, concurrency_mode="adaptive", min_concurrency=4)
    assert adaptive.run_config_hash() != config.run_config_hash()
    assert GenerationConfig.from_json(adaptive.to_json()) == adaptive


@pytest.mark.parametrize("changes", [
    {"concurrency_mode": "unknown"}, {"concurrency_mode": True},
    {"min_concurrency": True}, {"min_concurrency": 0}, {"min_concurrency": 4.0},
    {"min_concurrency": 17}, {"max_concurrency": True},
    {"concurrency_mode": "fixed", "min_concurrency": 4},
])
def test_invalid_concurrency_policy_is_rejected(changes):
    with pytest.raises(GenerationContractError):
        _config(**changes)


def _write_override(tmp_path, *, mode="fixed", minimum=1, maximum=32, **extra):
    payload = {"concurrency_mode": mode, "min_concurrency": minimum,
               "max_concurrency": maximum, **extra}
    (tmp_path / "concurrency_override.json").write_text(json.dumps(payload))


def test_transport_override_resumes_pending_only_preserving_original_hash_and_samples(tmp_path):
    config = _config(concurrency_mode="fixed", min_concurrency=1, max_concurrency=4)
    original_bytes = canonical_json_bytes(config.to_json())
    config_path = tmp_path / "run_config.json"
    config_path.write_bytes(original_bytes)
    first_source = _Source()
    _, ledger = _run(tmp_path, first_source, count=2, config=config)
    saved_records = ledger.replay().finalized_records()
    _write_override(tmp_path, maximum=32)

    class Source(_Source):
        def __init__(self):
            super().__init__()
            self.wave = threading.Barrier(6)

        def generate(self, *args):
            # Six pending requests must all enter: the old fixed cap of four
            # would time out. No live provider or timing-based assertion.
            self.wave.wait(timeout=5)
            return super().generate(*args)

    source = Source()
    runner = GenerationRunner(config, _inputs(8), ledger, source, tmp_path)
    summary = runner.run()
    assert summary["generated"] == 6 and summary["skipped_finalized"] == 2
    assert len(source.calls) == 6
    final_records = ledger.replay().finalized_records()
    assert all(final_records[sample_id] == record for sample_id, record in saved_records.items())
    assert all(record["run_config_hash"] == config.run_config_hash() for record in final_records.values())
    assert config_path.read_bytes() == original_bytes
    assert runner.config == config and runner.effective_config.max_concurrency == 32
    assert summary["concurrency"]["mode"] == "fixed"
    assert summary["concurrency"]["target"] == 32
    assert summary["concurrency_override"]["original_policy"]["max_concurrency"] == 4
    assert json.loads((tmp_path / "concurrency_state.json").read_text())["max_concurrency"] == 32


def test_adaptive_override_accepts_maximum_above_sixteen(tmp_path):
    config = _config(concurrency_mode="fixed", min_concurrency=1, max_concurrency=4)
    _write_override(tmp_path, mode="adaptive", minimum=4, maximum=32, metadata={"reason": "transport tuning"})
    summary, ledger = _run(tmp_path, _Source(first_wave=True), count=32, config=config)
    assert summary["status_counts"] == {"success": 32}
    assert summary["concurrency"]["mode"] == "adaptive"
    assert summary["concurrency"]["target"] == 32
    assert summary["concurrency"]["max_concurrency"] == 32
    assert summary["concurrency"]["override"] == summary["concurrency_override"]
    assert all(record["run_config_hash"] == config.run_config_hash()
               for record in ledger.replay().finalized_records().values())
    state = json.loads((tmp_path / "concurrency_state.json").read_text())
    assert state == summary["concurrency"]
    events = [json.loads(line) for line in (tmp_path / "concurrency_events.jsonl").read_text().splitlines()]
    applied = [event for event in events if event["reason"] == "transport_override_applied"]
    assert len(applied) == 1
    assert applied[0]["effective_policy"]["max_concurrency"] == 32


def test_override_is_read_once_and_switches_adaptive_to_fixed(tmp_path):
    _write_override(tmp_path, maximum=8)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    source = _Source(first_wave=True)
    runner = GenerationRunner(_config(), _inputs(4), ledger, source, tmp_path)
    _write_override(tmp_path, maximum=1)
    summary = runner.run()
    assert summary["status_counts"] == {"success": 4}
    assert summary["concurrency"]["mode"] == "fixed"
    assert summary["concurrency"]["target"] == 8
    resumed = GenerationRunner(_config(), _inputs(4), ledger, object(), tmp_path).run()
    assert resumed["generated"] == 0
    assert resumed["concurrency"]["target"] == 1


@pytest.mark.parametrize("field,value", [
    ("model", "other-model"), ("temperature", 1), ("max_tokens", 1),
    ("source", "dmx"), ("task_ids", ["BigCodeBench/16"]),
])
def test_override_cannot_change_research_fields(tmp_path, field, value):
    _write_override(tmp_path, **{field: value})
    with pytest.raises(GenerationContractError, match="only change transport"):
        GenerationRunner(_config(), _inputs(1), Ledger(tmp_path / "ledger.jsonl"), object(), tmp_path)


@pytest.mark.parametrize("payload", [
    {"max_concurrency": 32},
    {"concurrency_mode": "fixed", "min_concurrency": 1, "max_concurrency": True},
    {"concurrency_mode": "adaptive", "min_concurrency": 8, "max_concurrency": 4},
    [],
])
def test_invalid_override_rejects_before_provider_calls(tmp_path, payload):
    (tmp_path / "concurrency_override.json").write_text(json.dumps(payload))
    with pytest.raises(GenerationContractError):
        GenerationRunner(_config(), _inputs(1), Ledger(tmp_path / "ledger.jsonl"), object(), tmp_path)
