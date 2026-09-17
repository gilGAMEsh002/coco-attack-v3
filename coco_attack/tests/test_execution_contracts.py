"""Contract validation tests for the execution isolation service (Chunk 1)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from coco_attack.execution.contracts import (
    ERROR_CLASSES,
    EVALUATION_LAYERS,
    ContainerSpec,
    ExecutionConfigError,
    ExecutionProfile,
    ExecutionProfileError,
    ExecutionRequest,
    ExecutionResult,
    ImageIdentity,
    InputFile,
    MountSpec,
    ROLLOUT_IDENTITY_FIELDS,
    TmpfsSpec,
)


def _profile_payload(**overrides):
    payload = {
        "schema_version": "1",
        "profile_id": "probe-profile-v1",
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
            "max_parallel_containers": 2,
            "workspace_bytes": 67108864,
            "shm_bytes": 67108864,
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
            "allowed_env": ["LANG", "LC_ALL"],
            "tmpfs_paths": ["/tmp", "/work", "/dev/shm"],
            "input_mount": "/in",
            "output_mount": "/out",
            "workdir": "/work",
        },
        "entries": [
            {"entry_id": "functional", "argv": ["python", "-m", "entrypoint", "functional"]},
            {"entry_id": "probe", "argv": ["python", "-m", "entrypoint", "probe"]},
        ],
    }
    payload.update(overrides)
    return payload


def _profile() -> ExecutionProfile:
    return ExecutionProfile.from_json(_profile_payload())


def _valid_request(profile: ExecutionProfile, **overrides) -> ExecutionRequest:
    base = dict(
        sample_id="sample-1",
        attempt_id="attempt-1",
        stage="search",
        batch_id="batch-1",
        combination_id="cwe078-0",
        task_id="task-1",
        repeat_id=0,
        prompt_version="prompt-v1",
        candidate_hash="f" * 64,
        evaluation_layer="functional",
        entry="functional",
        entry_args=(),
        execution_profile_hash=profile.fingerprint(),
        purpose="evaluation",
        input_files=(),
        result_schema="execution-result-v1",
        harness_version="harness-v1",
    )
    base.update(overrides)
    return ExecutionRequest(**base)


# --------------------------------------------------------------------------- #
# Profile
# --------------------------------------------------------------------------- #


def test_profile_roundtrip_and_fingerprint_stable() -> None:
    profile = _profile()
    reparsed = ExecutionProfile.from_json(profile.to_json())
    assert profile == reparsed
    assert profile.fingerprint() == reparsed.fingerprint()
    assert profile.allowed_entries() == frozenset({"functional", "probe"})
    assert profile.to_json() == reparsed.to_json()


def test_profile_rejects_missing_and_unknown_fields() -> None:
    missing = _profile_payload()
    del missing["image"]
    with pytest.raises(ExecutionProfileError):
        ExecutionProfile.from_json(missing)

    unknown = _profile_payload()
    unknown["surprise"] = 1
    with pytest.raises(ExecutionProfileError):
        ExecutionProfile.from_json(unknown)

    nested_unknown = _profile_payload()
    nested_unknown["limits"]["surprise"] = 1
    with pytest.raises(ExecutionProfileError):
        ExecutionProfile.from_json(nested_unknown)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["limits"].__setitem__("memory_bytes", 0),
        lambda p: p["limits"].__setitem__("memory_bytes", -1),
        lambda p: p["limits"].__setitem__("memory_bytes", True),
        lambda p: p["limits"].__setitem__("cpu_quota", 0.0),
        lambda p: p["limits"].__setitem__("cpu_quota", float("nan")),
        lambda p: p["limits"].__setitem__("memory_swap_bytes", 1),
        lambda p: p["timeouts"].__setitem__("wall_clock_seconds", float("inf")),
        lambda p: p["timeouts"].__setitem__("sigterm_grace_seconds", 60.0),
        lambda p: p["timeouts"].__setitem__("sigterm_grace_seconds", -1.0),
        lambda p: p["output_limits"].__setitem__("result_file_bytes", 10_000_000),
        lambda p: p["image"].__setitem__("image_id", "sha256:nothex"),
        lambda p: p["image"].update({"repo_digest": None, "image_id": None}),
        lambda p: p["sandbox"].__setitem__("network", "host"),
        lambda p: p["sandbox"].__setitem__("read_only_rootfs", False),
        lambda p: p["sandbox"].__setitem__("cap_drop", []),
        lambda p: p["sandbox"].__setitem__("no_new_privileges", False),
        lambda p: p["sandbox"].__setitem__("tmpfs_paths", ["/tmp", "/work"]),
    ],
)
def test_profile_rejects_invalid_values(mutate) -> None:
    payload = _profile_payload()
    mutate(payload)
    with pytest.raises(ExecutionProfileError):
        ExecutionProfile.from_json(payload)


def test_profile_rejects_duplicate_entry_ids() -> None:
    payload = _profile_payload()
    payload["entries"] = [
        {"entry_id": "functional", "argv": ["python"]},
        {"entry_id": "functional", "argv": ["python"]},
    ]
    with pytest.raises(ExecutionProfileError):
        ExecutionProfile.from_json(payload)


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("field_name", ROLLOUT_IDENTITY_FIELDS)
def test_request_requires_rollout_identity(field_name: str) -> None:
    profile = _profile()
    request = _valid_request(profile)
    if field_name == "repeat_id":
        broken = replace(request, repeat_id=-1)
    else:
        broken = replace(request, **{field_name: ""})
    with pytest.raises(ExecutionConfigError):
        broken.validate_against(profile)


@pytest.mark.parametrize("field_name", ["sample_id", "attempt_id"])
def test_request_requires_execution_identity(field_name: str) -> None:
    profile = _profile()
    request = _valid_request(profile)
    with pytest.raises(ExecutionConfigError):
        replace(request, **{field_name: ""}).validate_against(profile)


def test_request_rejects_bad_profile_hash_and_entry() -> None:
    profile = _profile()
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, execution_profile_hash="0" * 64).validate_against(profile)
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, entry="missing").validate_against(profile)


def test_request_rejects_bad_entry_args() -> None:
    profile = _profile()
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, entry_args=("ok", "bad arg")).validate_against(profile)
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, entry_args=tuple(f"a{i}" for i in range(17))).validate_against(profile)


def test_request_purpose_constraints() -> None:
    profile = _profile()
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, purpose="isolation_probe", probe_id=None)
    probe = _valid_request(profile, purpose="isolation_probe", probe_id="probe.uid")
    probe.validate_against(profile)
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, purpose="evaluation", probe_id="probe.uid")
    with pytest.raises(ExecutionConfigError):
        _valid_request(profile, purpose="made_up")


def test_request_rejects_duplicate_input_names() -> None:
    profile = _profile()
    item = InputFile(name="code.py", kind="code", sha256="a" * 64, size=1)
    request = _valid_request(profile, input_files=(item, item))
    with pytest.raises(ExecutionConfigError):
        request.validate_against(profile)


def test_input_file_rejects_path_escape() -> None:
    for bad in ("../evil", "a/b", "/abs", "", "a" * 129):
        with pytest.raises(ExecutionConfigError):
            InputFile(name=bad, kind="code", sha256="a" * 64, size=0)


def test_request_roundtrip_and_fingerprint() -> None:
    profile = _profile()
    item = InputFile(name="code.py", kind="code", sha256="a" * 64, size=12)
    request = _valid_request(profile, input_files=(item,), entry_args=("--x=1", "flag"))
    reparsed = ExecutionRequest.from_json(request.to_json())
    assert reparsed == request
    assert reparsed.fingerprint() == request.fingerprint()


def test_request_from_json_rejects_unknown_field() -> None:
    payload = _valid_request(_profile()).to_json()
    payload["surprise"] = True
    with pytest.raises(ExecutionConfigError):
        ExecutionRequest.from_json(payload)


# --------------------------------------------------------------------------- #
# ExecutionResult
# --------------------------------------------------------------------------- #


def test_execution_result_roundtrip_and_predicate() -> None:
    result = ExecutionResult(
        sample_id="s",
        attempt_id="a",
        stage="search",
        request_hash="r" * 64,
        container_id="cid",
        image_reference="img:tag",
        image_id="sha256:" + "b" * 64,
        execution_profile_hash="p" * 64,
        supervisor_version="v1",
        harness_version="h1",
        result_valid=True,
        cleanup_complete=True,
        available=True,
        error_class="none",
    )
    assert result.ok_for_evaluation() is True
    assert ExecutionResult.from_json(result.to_json()) == result
    blocked = replace(result, error_class="timeout")
    assert blocked.ok_for_evaluation() is False


def test_execution_result_rejects_unknown_error_class() -> None:
    with pytest.raises(ExecutionConfigError):
        ExecutionResult(
            sample_id="s",
            attempt_id="a",
            stage="search",
            request_hash="r" * 64,
            container_id=None,
            image_reference="img",
            image_id=None,
            execution_profile_hash="p" * 64,
            supervisor_version="v1",
            harness_version="h1",
            error_class="not_a_class",
        )
    assert "result_corrupt" in ERROR_CLASSES
    assert "probe" in EVALUATION_LAYERS


# --------------------------------------------------------------------------- #
# Argument-injection hardening (reviewer L1-L3)
# --------------------------------------------------------------------------- #


def test_input_file_name_rejects_dot_and_dotdot() -> None:
    for bad in (".", "..", "a/b", "../x"):
        with pytest.raises(ExecutionConfigError):
            InputFile(name=bad, kind="code", sha256="a" * 64, size=1)


def test_mount_target_with_comma_is_rejected() -> None:
    with pytest.raises(ExecutionConfigError):
        MountSpec(source="/host/in", target="/in,x", read_only=True)


def test_tmpfs_target_with_colon_is_rejected() -> None:
    with pytest.raises(ExecutionConfigError):
        TmpfsSpec(target="/tmp:x", size_bytes=10, mode="1777")


def test_image_reference_starting_with_dash_is_rejected() -> None:
    with pytest.raises(ExecutionProfileError):
        ImageIdentity(
            reference="--privileged",
            base_image="python:3.14-slim",
            base_digest="sha256:" + "c" * 64,
            platform="linux/amd64",
            python_version="3.14",
            dependency_lock_path="lock",
            dependency_lock_sha256="d" * 64,
            image_id="sha256:" + "b" * 64,
        )


def test_container_spec_image_starting_with_dash_is_rejected() -> None:
    with pytest.raises(ExecutionConfigError):
        ContainerSpec(
            name="c",
            labels={},
            image="--privileged",
            argv=("alpine",),
            mounts=(),
            tmpfs=(),
            env=(),
            network="none",
            read_only_rootfs=True,
            cap_drop=("ALL",),
            no_new_privileges=True,
            uid=10001,
            gid=10001,
            workdir="/work",
            memory_bytes=1024,
            memory_swap_bytes=1024,
            cpu_quota=1.0,
            pids_limit=1,
        )
