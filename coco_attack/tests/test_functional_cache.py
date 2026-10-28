"""Functional cache tests (stage 02, task 03)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.evaluation.functional_cache import (
    FunctionalCache,
    FunctionalCacheError,
    compose_key,
    execution_semantics,
    fingerprint_sha256,
    functional_fingerprint,
    parse_key,
)
from coco_attack.execution.contracts import ExecutionProfile, SandboxConfig, TmpfsSpec


def _profile() -> ExecutionProfile:
    return ExecutionProfile.from_json(
        {
            "schema_version": "1",
            "profile_id": "functional-cache-profile-v1",
            "executor_version": "executor-v1",
            "executor_source_sha256": "a" * 64,
            "image": {
                "reference": "coco-attack-evaluator:probe",
                "repo_digest": None,
                "image_id": "sha256:" + "b" * 64,
                "base_image": "python:3.14-slim",
                "base_digest": "sha256:" + "c" * 64,
                "platform": "linux/amd64",
                "python_version": "3.14.4",
                "dependency_lock_path": "requirements-eval.lock",
                "dependency_lock_sha256": "d" * 64,
            },
            "limits": {
                "memory_bytes": 536870912,
                "memory_swap_bytes": 536870912,
                "cpu_quota": 1.0,
                "pids_limit": 64,
                "max_parallel_containers": 1,
                "workspace_bytes": 67108864,
                "shm_bytes": 16777216,
                "output_storage_bytes": 268435456,
            },
            "timeouts": {
                "wall_clock_seconds": 60.0,
                "sigterm_grace_seconds": 5.0,
                "docker_control_timeout_seconds": 30.0,
            },
            "output_limits": {
                "stdout_bytes": 65536,
                "stderr_bytes": 65536,
                "result_file_bytes": 1048576,
                "single_file_bytes": 1048576,
                "total_artifact_bytes": 4194304,
            },
            "sandbox": {
                "uid": 10001,
                "gid": 10001,
                "network": "none",
                "read_only_rootfs": True,
                "cap_drop": ["ALL"],
                "no_new_privileges": True,
                "allowed_env": ["LANG", "LC_ALL", "TMPDIR"],
                "tmpfs_paths": ["/tmp", "/work", "/dev/shm"],
                "input_mount": "/in",
                "output_mount": "/out",
                "workdir": "/work",
            },
            "entries": [
                {"entry_id": "functional", "argv": ["python", "-m", "functional_runner"]},
            ],
        }
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
        classifier_version="functional-classifier-v2",
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


def test_execution_semantics_include_effective_tmpfs_mounts() -> None:
    profile = _profile()
    semantics = execution_semantics(profile)
    tmpfs = {item["target"]: item for item in semantics["tmpfs"]}

    assert set(tmpfs) == {"/tmp", "/work", "/dev/shm"}
    assert "exec" in tmpfs["/tmp"]["options"]
    assert tmpfs["/work"]["mode"] == "0755"
    assert f"uid={profile.sandbox.uid}" in tmpfs["/work"]["options"]
    assert f"gid={profile.sandbox.gid}" in tmpfs["/work"]["options"]
    assert "exec" not in tmpfs["/dev/shm"]["options"]


def test_cache_key_changes_when_tmpfs_semantics_are_fixed(monkeypatch) -> None:
    profile = _profile()
    fixed_semantics = execution_semantics(profile)
    fixed_key = fingerprint_sha256(_fingerprint(execution_semantics=fixed_semantics))

    # The pre-fix semantics did not describe the tmpfs mounts at all, so a
    # cached failure from the root-owned /work + noexec /tmp environment would
    # be reused.  Reconstruct that key and require a miss against the fixed one.
    legacy_semantics = {
        key: value for key, value in fixed_semantics.items() if key != "tmpfs"
    }
    legacy_key = fingerprint_sha256(_fingerprint(execution_semantics=legacy_semantics))
    assert fixed_key != legacy_key

    # A future regression that drops the workdir ownership or /tmp exec flag
    # must also produce a different key.
    original = SandboxConfig.tmpfs_specs

    def regressed(self, workspace_bytes: int, shm_bytes: int):
        specs = []
        for spec in original(self, workspace_bytes, shm_bytes):
            options = tuple(option for option in spec.options if option != "exec")
            options = tuple(option for option in options if not option.startswith("uid="))
            options = tuple(option for option in options if not option.startswith("gid="))
            specs.append(TmpfsSpec(spec.target, spec.size_bytes, spec.mode, options))
        return tuple(specs)

    monkeypatch.setattr(SandboxConfig, "tmpfs_specs", regressed)
    regressed_key = fingerprint_sha256(
        _fingerprint(execution_semantics=execution_semantics(profile))
    )
    assert regressed_key != fixed_key


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
