"""Offline mock generation tests (stage 02, task 02).

These exercise the real ``dspy.LM.forward -> request_cache -> completion`` path
with only the LiteLLM completion boundary replaced, so retry, ledger and
projection behaviour are covered without network access.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_bytes
from coco_attack.generation.contracts import GenerationConfig, SampleIdentity
from coco_attack.generation.inputs import GenerationInputs, GenerationSample
from coco_attack.generation.runner import GenerationRunner
from coco_attack.generation.source import MockSource
from coco_attack.runtime.ledger import (
    EVENT_ATTEMPT_STARTED,
    EVENT_RESPONSE_RECEIVED,
    Ledger,
)


class _ForbiddenSource:
    """Fails the test if the runner re-issues a request during recovery."""

    def generate(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("provider must not be called for a durable response")


def _config(**overrides) -> GenerationConfig:
    base = dict(
        source="mock",
        model="openai/gpt-4o",
        batch_id="batch-1",
        combination_id="cwe078-0",
        oracle_id="cwe078-0",
        stage="search",
        form="clean_fewshot_cot",
        prompt_version="1",
        candidate_hash="",
        temperature=0.0,
        repeats=1,
        max_tokens=128,
        request_timeout=30.0,
        max_concurrency=1,
        max_request_attempts=3,
        max_sample_retries=0,
        mock_scenario="normal",
    )
    base.update(overrides)
    return GenerationConfig(**base)


def _inputs(count: int = 2, candidate_hash: str = "c" * 64) -> GenerationInputs:
    samples = []
    for index in range(count):
        identity = SampleIdentity(
            stage="search",
            batch_id="batch-1",
            combination_id="cwe078-0",
            task_id=f"BigCodeBench/{index + 1}",
            repeat_id=0,
            prompt_version="1",
            candidate_hash=candidate_hash,
        )
        prompt = f"# task {index + 1}\nwrite code\n"
        samples.append(
            GenerationSample(
                identity=identity,
                prompt=prompt,
                prompt_sha256="p" * 64,
            )
        )
    return GenerationInputs(
        combination_id="cwe078-0",
        oracle_id="cwe078-0",
        form="clean_fewshot_cot",
        stage="search",
        task_snapshot_sha256="t" * 64,
        prompt_manifest_sha256="m" * 64,
        candidate_hash=candidate_hash,
        samples=tuple(samples),
    )


def test_mock_normal_generation_finalizes_and_projects(tmp_path: Path) -> None:
    config = _config()
    inputs = _inputs(2)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        runner = GenerationRunner(config, inputs, ledger, source, tmp_path)
        summary = runner.run()

    assert summary["generated"] == 2
    assert summary["status_counts"] == {"success": 2}
    assert (tmp_path / "generations.jsonl").read_text(encoding="utf-8").count("\n") == 2
    replay = ledger.replay()
    assert len(replay.finalized_sample_ids()) == 2
    assert all("usage" in usage for usage in replay.first_usage_by_sample().values())


def test_mock_retries_then_succeeds(tmp_path: Path) -> None:
    config = _config(mock_scenario="error_once")
    inputs = _inputs(1)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        runner = GenerationRunner(config, inputs, ledger, source, tmp_path)
        runner.run()

    events = ledger.replay().events
    failed = [e for e in events if e["event_type"] == "attempt_failed"]
    assert len(failed) == 1
    assert failed[0]["payload"]["retryable"] is True
    records = ledger.replay().finalized_records()
    assert next(iter(records.values()))["status"] == "success"
    assert next(iter(records.values()))["retry_count"] == 1


def test_mock_terminal_failure_keeps_empty_generation(tmp_path: Path) -> None:
    config = _config(mock_scenario="always_error")
    inputs = _inputs(1)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        GenerationRunner(config, inputs, ledger, source, tmp_path).run()

    record = next(iter(ledger.replay().finalized_records().values()))
    assert record["status"] == "error"
    assert record["generation"] == ""
    assert record["usage"] == {}


@pytest.mark.parametrize(
    "scenario,status",
    [("empty", "empty"), ("truncated", "truncated"), ("invalid", "invalid_response"), ("dirty", "success")],
)
def test_mock_status_classification(tmp_path: Path, scenario: str, status: str) -> None:
    config = _config(mock_scenario=scenario)
    inputs = _inputs(1)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        GenerationRunner(config, inputs, ledger, source, tmp_path).run()
    record = next(iter(ledger.replay().finalized_records().values()))
    assert record["status"] == status


def test_resume_skips_finalized_samples(tmp_path: Path) -> None:
    config = _config()
    inputs = _inputs(2)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        GenerationRunner(config, inputs, ledger, source, tmp_path).run()
    with MockSource(config) as source:
        summary = GenerationRunner(config, inputs, ledger, source, tmp_path).run()
    assert summary["generated"] == 0
    assert summary["skipped_finalized"] == 2
    assert (tmp_path / "generations.jsonl").read_text(encoding="utf-8").count("\n") == 2


def test_resume_reexports_durable_response_without_recalling_provider(tmp_path: Path) -> None:
    """A crash between response_received and sample_finalized must recover locally."""

    config = _config()
    inputs = _inputs(1)
    sample = inputs.samples[0]
    content = "print('recovered')\n"
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append(
        EVENT_ATTEMPT_STARTED,
        sample_id=sample.sample_id,
        request_attempt_id="attempt-1",
        payload={"attempt_index": 0, "model": config.model, "source": config.source},
    )
    ledger.append(
        EVENT_RESPONSE_RECEIVED,
        sample_id=sample.sample_id,
        request_attempt_id="attempt-1",
        payload={
            "attempt_index": 0,
            "content": content,
            "content_sha256": sha256_bytes(content.encode("utf-8")),
            "finish_reason": "stop",
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            "cost": {"basis": "estimated", "amount": 0.001, "currency": "USD"},
            "cache_hit": False,
            "response_id": "resp-1",
            "model": config.model,
        },
    )
    # No sample_finalized event: the export step was interrupted.

    summary = GenerationRunner(
        config, inputs, ledger, _ForbiddenSource(), tmp_path
    ).run()

    assert summary["generated"] == 0
    assert summary["skipped_finalized"] == 1
    record = ledger.replay().finalized_records()[sample.sample_id]
    assert record["generation"] == content
    assert record["status"] == "success"
    assert record["usage"]["total_tokens"] == 8
    assert record["cost"]["amount"] == 0.001
    assert record["request_attempt_id"] == "attempt-1"
    rows = [
        json.loads(line)
        for line in (tmp_path / "generations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["sample_id"] for row in rows] == [sample.sample_id]


def test_recovery_only_handles_responses_without_a_finalized_record(tmp_path: Path) -> None:
    """Recovery must not duplicate a sample that already has a finalized record."""

    config = _config()
    inputs = _inputs(1)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    with MockSource(config) as source:
        GenerationRunner(config, inputs, ledger, source, tmp_path).run()
    before = (tmp_path / "generations.jsonl").read_text(encoding="utf-8").count("\n")
    with MockSource(config) as source:
        GenerationRunner(config, inputs, ledger, source, tmp_path).run()
    assert (tmp_path / "generations.jsonl").read_text(encoding="utf-8").count("\n") == before


def test_projection_append_inserts_separator_after_unterminated_record(tmp_path: Path) -> None:
    """A record written without its trailing newline must not swallow the next one."""

    config = _config()
    inputs = _inputs(1)
    ledger = Ledger(tmp_path / "ledger.jsonl")
    runner = GenerationRunner(config, inputs, ledger, object(), tmp_path)
    runner._append_projection({"sample_id": "a"})
    with open(tmp_path / "generations.jsonl", "ab") as handle:
        handle.write(b'{"sample_id":"b"}')  # crash before the newline reached disk
    runner._append_projection({"sample_id": "c"})
    rows = [
        json.loads(line)
        for line in (tmp_path / "generations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["sample_id"] for row in rows] == ["a", "b", "c"]


def test_mock_source_serves_repeat_from_cache(tmp_path: Path) -> None:
    config = _config()
    messages = [{"role": "user", "content": f"hello-{uuid.uuid4().hex}"}]
    with MockSource(config) as source:
        first = source.generate(messages, rollout_id=123, attempt_index=1)
        second = source.generate(messages, rollout_id=123, attempt_index=1)

    assert first.cache_hit is False
    assert first.usage
    assert second.cache_hit is True
    assert second.usage == {}
    assert second.content == first.content
