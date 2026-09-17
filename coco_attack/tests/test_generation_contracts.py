"""Contract tests for the generation records (stage 02, task 02)."""

from __future__ import annotations

import pytest

from coco_attack.generation.contracts import (
    GenerationConfig,
    GenerationContractError,
    GenerationRecord,
    SampleIdentity,
)


def _identity(**overrides) -> SampleIdentity:
    base = dict(
        stage="search",
        batch_id="batch-1",
        combination_id="cwe078-0",
        task_id="BigCodeBench/1",
        repeat_id=0,
        prompt_version="1",
        candidate_hash="c" * 64,
    )
    base.update(overrides)
    return SampleIdentity(**base)


def test_sample_identity_is_deterministic_and_distinct() -> None:
    first = _identity()
    second = _identity()
    assert first.sample_id() == second.sample_id()
    assert first.rollout_id() == second.rollout_id()
    other = _identity(repeat_id=1)
    assert other.sample_id() != first.sample_id()
    assert other.rollout_id() != first.rollout_id()
    assert len(first.sample_id()) == 64


def test_sample_identity_rejects_bad_fields() -> None:
    with pytest.raises(GenerationContractError):
        _identity(stage="holdout-x")
    with pytest.raises(GenerationContractError):
        _identity(repeat_id=-1)


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
        max_concurrency=2,
        max_request_attempts=3,
        max_sample_retries=0,
    )
    base.update(overrides)
    return GenerationConfig(**base)


def test_config_roundtrip_and_hash() -> None:
    config = _config()
    assert GenerationConfig.from_json(config.to_json()) == config
    assert config.run_config_hash() == _config().run_config_hash()
    assert config.run_config_hash() != _config(model="openai/gpt-4.1").run_config_hash()


def test_config_rejects_invalid_values() -> None:
    with pytest.raises(GenerationContractError):
        _config(source="other")
    with pytest.raises(GenerationContractError):
        _config(candidate_hash="not-a-hash")
    with pytest.raises(GenerationContractError):
        _config(repeats=0)
    with pytest.raises(GenerationContractError):
        _config(max_concurrency=0)


def test_generation_record_cleaner_row_and_failure_semantics() -> None:
    identity = _identity()
    record = GenerationRecord(
        identity=identity,
        sample_id=identity.sample_id(),
        rollout_id=identity.rollout_id(),
        combination_id=identity.combination_id,
        oracle_id="cwe078-0",
        source="mock",
        model="openai/gpt-4o",
        form="clean_fewshot_cot",
        run_config_hash="r" * 64,
        task_snapshot_sha256="t" * 64,
        prompt_sha256="p" * 64,
        status="success",
        generation="def f():\n    return 1\n",
        error_reason=None,
        response_id="resp",
        finish_reason="stop",
        request_attempt_id="att",
        retry_count=0,
        usage={"prompt_tokens": 1, "completion_tokens": 2},
        cost={"basis": "estimated", "amount": 0.0},
        cache_hit=False,
    )
    row = record.to_cleaner_row()
    assert row["task_id"] == "BigCodeBench/1"
    assert row["repeat_id"] == 0 and row["status"] == "success"
    assert GenerationRecord.from_json(record.to_json()).sample_id == identity.sample_id()

    failed = GenerationRecord(
        identity=identity,
        sample_id=identity.sample_id(),
        rollout_id=identity.rollout_id(),
        combination_id=identity.combination_id,
        oracle_id="cwe078-0",
        source="mock",
        model="openai/gpt-4o",
        form="clean_fewshot_cot",
        run_config_hash="r" * 64,
        task_snapshot_sha256="t" * 64,
        prompt_sha256="p" * 64,
        status="error",
        generation="",
        error_reason="boom",
        response_id=None,
        finish_reason=None,
        request_attempt_id=None,
        retry_count=2,
        usage={},
        cost={"basis": "unknown"},
        cache_hit=False,
    )
    assert failed.to_cleaner_row()["generation"] == ""

    with pytest.raises(GenerationContractError):
        GenerationRecord(
            identity=identity,
            sample_id=identity.sample_id(),
            rollout_id=identity.rollout_id(),
            combination_id=identity.combination_id,
            oracle_id="cwe078-0",
            source="mock",
            model="openai/gpt-4o",
            form="clean_fewshot_cot",
            run_config_hash="r" * 64,
            task_snapshot_sha256="t" * 64,
            prompt_sha256="p" * 64,
            status="error",
            generation="should be empty",
            error_reason=None,
            response_id=None,
            finish_reason=None,
            request_attempt_id=None,
            retry_count=0,
            usage={},
            cost={},
            cache_hit=False,
        )
