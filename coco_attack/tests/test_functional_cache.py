"""Functional cache tests (stage 02, task 03)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.evaluation.functional_cache import (
    FunctionalCache,
    FunctionalCacheError,
    compose_key,
    fingerprint_sha256,
    functional_fingerprint,
    parse_key,
)


def _fingerprint(stage: str = "search", **overrides) -> dict:
    fields = dict(
        sample_id="s1",
        stage=stage,
        batch_id="b1",
        combination_id="cwe078-0",
        oracle_id="cwe078-0",
        generation_status="success",
        run_config_bytes_sha256="a" * 64,
        prompt_sha256="p" * 64,
        raw_generation_sha256="r" * 64,
        final_code_sha256="f" * 64,
        task_snapshot_sha256="t" * 64,
        test_sha256="e" * 64,
        entry_point="task_func",
        fixture_sha256="x" * 64,
        cleaner_version="cleaner-v3",
        harness_version="functional-harness-v1",
        result_schema="functional-payload-v1",
        image_id="sha256:" + "i" * 64,
        dependency_lock_sha256="d" * 64,
        execution_semantics={"network": "none"},
        candidate_timeout_seconds=20.0,
    )
    fields.update(overrides)
    return functional_fingerprint(**fields)


def _result(fingerprint_sha256: str = "0" * 64) -> dict:
    return {
        "sample_id": "s1",
        "outcome": "passed",
        "passed": True,
        "cache_eligible": True,
        "fingerprint_sha256": fingerprint_sha256,
    }


def test_fingerprint_and_key_helpers() -> None:
    fingerprint = _fingerprint()
    digest = fingerprint_sha256(fingerprint)
    assert len(digest) == 64
    key = compose_key("s1", digest)
    assert parse_key(key) == ("s1", digest)


def test_fingerprint_includes_candidate_timeout() -> None:
    slow = fingerprint_sha256(_fingerprint(candidate_timeout_seconds=20.0))
    fast = fingerprint_sha256(_fingerprint(candidate_timeout_seconds=1.0))
    assert slow != fast


def test_store_and_lookup_roundtrip(tmp_path: Path) -> None:
    cache = FunctionalCache(tmp_path, "search")
    fingerprint = _fingerprint()
    digest = fingerprint_sha256(fingerprint)
    artifact = tmp_path / "payload.json"
    artifact.write_text("{}", encoding="utf-8")

    cache.store(
        sample_id="s1",
        fingerprint=fingerprint,
        result=_result(digest),
        execution={"container_id": "cid"},
        artifacts={"payload.json": str(artifact)},
        accounting_id="acc-1",
    )
    lookup = cache.lookup("s1", digest)
    assert lookup.hit is True
    assert lookup.value["result"]["passed"] is True
    assert lookup.value["reuse_source"] == "functional-cache:search"
    assert cache.get(compose_key("s1", digest)).hit is True
    assert cache.lookup("s1", "0" * 64).hit is False


def test_store_rejects_non_eligible(tmp_path: Path) -> None:
    cache = FunctionalCache(tmp_path, "search")
    fingerprint = _fingerprint()
    with pytest.raises(FunctionalCacheError):
        cache.store(
            sample_id="s1",
            fingerprint=fingerprint,
            result={"sample_id": "s1", "cache_eligible": False},
            execution={},
            artifacts={},
        )


def test_store_rejects_stage_mismatch(tmp_path: Path) -> None:
    cache = FunctionalCache(tmp_path, "search")
    with pytest.raises(FunctionalCacheError):
        cache.store(
            sample_id="s1",
            fingerprint=_fingerprint(stage="holdout"),
            result=_result(),
            execution={},
            artifacts={},
        )


def test_lookup_rejects_tampered_result_identity(tmp_path: Path) -> None:
    import json
    import sqlite3

    cache = FunctionalCache(tmp_path, "search")
    fingerprint = _fingerprint()
    digest = fingerprint_sha256(fingerprint)
    artifact = tmp_path / "payload.json"
    artifact.write_text("{}", encoding="utf-8")
    cache.store(
        sample_id="s1",
        fingerprint=fingerprint,
        result=_result(digest),
        execution={},
        artifacts={"payload.json": str(artifact)},
        accounting_id="a",
    )
    connection = sqlite3.connect(cache.index_path, isolation_level=None)
    connection.execute(
        "UPDATE results SET result_json=? WHERE sample_id='s1'",
        (json.dumps({**_result(digest), "sample_id": "someone-else"}),),
    )
    connection.close()
    lookup = cache.lookup("s1", digest)
    assert lookup.hit is False
    assert lookup.reason == "result_identity_mismatch"


def test_missing_artifact_is_a_miss(tmp_path: Path) -> None:
    cache = FunctionalCache(tmp_path, "search")
    fingerprint = _fingerprint()
    digest = fingerprint_sha256(fingerprint)
    cache.store(
        sample_id="s1",
        fingerprint=fingerprint,
        result=_result(digest),
        execution={},
        artifacts={},
        accounting_id=None,
    )
    # Corrupt one artifact by inserting a row with a missing file.
    artifacts_dir = cache.artifacts_dir / "s1" / digest
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    import sqlite3

    connection = sqlite3.connect(cache.index_path, isolation_level=None)
    connection.execute(
        "UPDATE results SET files_json=? WHERE sample_id='s1'",
        ('{"s1/missing/payload.json": "' + "0" * 64 + '"}',),
    )
    connection.close()
    lookup = cache.lookup("s1", digest)
    assert lookup.hit is False
    assert lookup.reason.startswith("artifact_missing")


def test_stage_directories_are_separate(tmp_path: Path) -> None:
    search = FunctionalCache(tmp_path, "search")
    holdout = FunctionalCache(tmp_path, "holdout")
    assert search.stage_root != holdout.stage_root
    assert search.index_path != holdout.index_path
