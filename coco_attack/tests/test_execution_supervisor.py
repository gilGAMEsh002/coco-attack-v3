"""Host-supervisor lifecycle tests using an in-memory fake backend (Chunk 1)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    write_json_atomic,
)
from coco_attack.execution.contracts import (
    ContainerSpec,
    ContainerState,
    ExecutionBackendError,
    ExecutionConfigError,
    ExecutionProfile,
    ExecutionRequest,
    ExecutionResult,
    InputFile,
)
from coco_attack.execution.docker import LogResult
from coco_attack.execution.supervisor import ExecutionSupervisor

TEST_NONCE = "n" * 32


# --------------------------------------------------------------------------- #
# Contract builders
# --------------------------------------------------------------------------- #


def _profile_payload():
    return {
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
            "allowed_env": ["LANG"],
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


def _profile() -> ExecutionProfile:
    return ExecutionProfile.from_json(_profile_payload())


def _result_payload(request: ExecutionRequest, **overrides) -> dict:
    payload = {
        "schema_version": "1",
        "sample_id": request.sample_id,
        "attempt_id": request.attempt_id,
        "stage": request.stage,
        "result_schema": request.result_schema,
        "nonce": TEST_NONCE,
        "verdict": "ok",
    }
    payload.update(overrides)
    return payload


def _result_bytes(request: ExecutionRequest, **overrides) -> bytes:
    return canonical_json_bytes(_result_payload(request, **overrides))


def _state(
    *, running: bool, exit_code: int | None = 0, oom_killed: bool = False, cid: str = "cid-1"
) -> ContainerState:
    return ContainerState(
        container_id=cid,
        name="coco-attack-attempt-1",
        status="running" if running else "exited",
        running=running,
        exit_code=None if running else exit_code,
        oom_killed=oom_killed,
        started_at="2026-01-01T00:00:00Z",
        finished_at=None if running else "2026-01-01T00:00:05Z",
        labels={"coco-attack.managed": "true"},
        image_id="sha256:" + "b" * 64,
    )


class FakeDockerBackend:
    """In-memory backend: one primary container plus an optional recovery pool."""

    def __init__(
        self,
        *,
        states: list[ContainerState] | None = None,
        loop_last: bool = False,
        result_bytes: bytes | None = None,
        logs: LogResult | None = None,
        cleanup_error: Exception | None = None,
        pool: dict[str, ContainerState] | None = None,
        create_hook=None,
    ) -> None:
        self.actions: list[tuple] = []
        self.states = list(states) if states is not None else None
        self.loop_last = loop_last
        self.index = 0
        self.result_bytes = result_bytes
        self.logs_result = logs or LogResult("out", "err", False, False)
        self.cleanup_error = cleanup_error
        self.pool = dict(pool or {})
        self.removed: set[str] = set()
        self.stopped: set[str] = set()
        self.create_hook = create_hook
        self.last_spec: ContainerSpec | None = None
        self.last_labels: dict[str, str] | None = None

    # protocol ------------------------------------------------------------- #
    def probe(self) -> dict:
        return {"available": True}

    def image_inspect(self, reference: str):
        return None

    def inspect_raw(self, container_id: str):
        if container_id in self.removed:
            return None
        return {"Id": container_id, "HostConfig": {"ReadonlyRootfs": True}}

    def create(self, spec: ContainerSpec) -> str:
        self.actions.append(("create", spec.name))
        self.last_spec = spec
        if self.create_hook is not None:
            self.create_hook()
        return "cid-1"

    def start(self, container_id: str) -> None:
        self.actions.append(("start", container_id))

    def inspect(self, container_id: str) -> ContainerState | None:
        if container_id in self.removed:
            return None
        if container_id in self.stopped:
            return _state(running=False, exit_code=0, cid=container_id)
        if self.states is not None and container_id == "cid-1":
            if self.index < len(self.states):
                state = self.states[self.index]
                self.index += 1
                return state
            if self.loop_last and self.states:
                return self.states[-1]
            return None
        return self.pool.get(container_id)

    def wait(self, container_id: str, timeout_seconds: float) -> int | None:
        return 0

    def stop(self, container_id: str, grace_seconds: float) -> None:
        self.actions.append(("stop", container_id))
        self.stopped.add(container_id)

    def remove(self, container_id: str, force: bool) -> None:
        self.actions.append(("remove", container_id, force))
        if self.cleanup_error is not None:
            raise self.cleanup_error
        self.removed.add(container_id)
        self.pool.pop(container_id, None)

    def list_managed(self, labels: dict[str, str]) -> list[ContainerState]:
        self.last_labels = labels
        return [
            state
            for state in self.pool.values()
            if all(state.labels.get(key) == value for key, value in labels.items())
        ]

    def logs(self, container_id: str, stdout_max_bytes: int, stderr_max_bytes: int) -> LogResult:
        self.actions.append(("logs", container_id))
        return self.logs_result


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.run_dir = tmp_path / "run"
        self.staging = tmp_path / "staging"
        self.output = tmp_path / "output"
        self.staging.mkdir()
        self.output.mkdir()
        self.content = b"print('hello')\n"
        (self.staging / "code.py").write_bytes(self.content)
        self.profile = _profile()
        item = InputFile(
            name="code.py",
            kind="code",
            sha256=sha256_bytes(self.content),
            size=len(self.content),
        )
        self.request = self._request(input_files=(item,))

    def _request(self, **overrides) -> ExecutionRequest:
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
            execution_profile_hash=self.profile.fingerprint(),
            purpose="evaluation",
            input_files=(),
            result_schema="execution-result-v1",
            harness_version="harness-v1",
        )
        base.update(overrides)
        return ExecutionRequest(**base)

    @property
    def attempt_dir(self) -> Path:
        return self.run_dir / "attempts" / "attempt-1"


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def _supervisor(env: Env, backend: FakeDockerBackend) -> ExecutionSupervisor:
    return ExecutionSupervisor(
        env.profile, backend, env.run_dir, poll_interval_seconds=0, default_nonce=TEST_NONCE
    )


def _write_result(target_dir: Path, data: bytes) -> None:
    (target_dir / "result.json").write_bytes(data)


# --------------------------------------------------------------------------- #
# Normal lifecycle
# --------------------------------------------------------------------------- #


def test_execute_normal_path(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(
        states=[_state(running=True), _state(running=False, exit_code=0)],
    )
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request))

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is True
    assert result.timed_out is False
    assert result.exit_code == 0
    assert result.cleanup_complete is True
    assert result.error_class == "none"
    assert result.ok_for_evaluation() is True
    assert result.result_ref == "result.json"
    assert result.result_sha256 == sha256_bytes(_result_bytes(request))
    assert (env.attempt_dir / "result.json").read_bytes() == _result_bytes(request)
    assert result.stdout_ref == "stdout.log"
    assert result.stderr_ref == "stderr.log"
    assert (env.attempt_dir / "stdout.log").read_text(encoding="utf-8") == "out"
    assert (env.attempt_dir / "stderr.log").read_text(encoding="utf-8") == "err"
    assert (env.attempt_dir / "container_inspect.json").is_file()


def test_mount_permissions_are_widened_for_container_uid(env: Env) -> None:
    import os
    import stat as stat_module

    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(env.request))

    _supervisor(env, backend).execute(env.request, env.staging, env.output)

    assert stat_module.S_IMODE(os.stat(env.output).st_mode) == 0o777
    assert stat_module.S_IMODE(os.stat(env.staging / "code.py").st_mode) == 0o644


def test_execute_persists_request_before_create(env: Env) -> None:
    request = env.request
    observed: dict[str, bool] = {}

    def hook() -> None:
        observed["request"] = (env.attempt_dir / "request.json").is_file()
        observed["deadline"] = (env.attempt_dir / "deadline.json").is_file()
        _write_result(env.output, _result_bytes(request))

    backend = FakeDockerBackend(
        states=[_state(running=True), _state(running=False)],
        create_hook=hook,
    )
    _supervisor(env, backend).execute(request, env.staging, env.output)

    assert observed == {"request": True, "deadline": True}
    assert (env.attempt_dir / "container.json").is_file()
    assert (env.attempt_dir / "execution.json").is_file()
    assert (env.run_dir / "manifest.json").is_file()
    assert backend.last_spec is not None
    # The request is bound to this run/profile in the container labels.
    labels = backend.last_spec.labels
    assert labels["coco-attack.run"] == "run"
    assert labels["coco-attack.stage"] == "search"
    assert labels["coco-attack.attempt"] == "attempt-1"
    assert labels["coco-attack.profile"] == env.profile.fingerprint()


def test_container_spec_is_isolated_and_bounded(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])

    _supervisor(env, backend).execute(request, env.staging, env.output)

    spec = backend.last_spec
    assert spec is not None
    assert spec.network == "none"
    assert spec.read_only_rootfs is True
    assert "ALL" in spec.cap_drop
    assert spec.no_new_privileges is True
    assert spec.uid == 10001
    mount_targets = {mount.target for mount in spec.mounts}
    assert mount_targets == {"/in", "/out"}
    read_only = {mount.target: mount.read_only for mount in spec.mounts}
    assert read_only["/in"] is True
    assert read_only["/out"] is False


# --------------------------------------------------------------------------- #
# Timeout / result completeness coexistence
# --------------------------------------------------------------------------- #


def test_execute_timeout_path_cleans_up(env: Env) -> None:
    backend = FakeDockerBackend(states=[_state(running=True)], loop_last=True)

    result = _supervisor(env, backend).execute(
        env.request, env.staging, env.output, deadline=0.0
    )

    assert result.timed_out is True
    assert result.cleanup_complete is True
    assert result.result_valid is False
    assert result.validation_failure == "result_missing"
    assert any(action[0] == "stop" and action[1] == "cid-1" for action in backend.actions)


def test_complete_result_survives_timeout(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True)], loop_last=True)
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request))

    result = _supervisor(env, backend).execute(
        request, env.staging, env.output, deadline=0.0
    )

    assert result.result_valid is True
    assert result.timed_out is True
    assert result.error_class == "timeout"
    assert result.cleanup_complete is True
    assert (env.attempt_dir / "result.json").is_file()


def test_half_written_json_is_result_corrupt(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(env.output, b'{"sample_id": "sample-1"')

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure == "result_invalid_json"
    assert result.error_class == "result_corrupt"


def test_corrupt_result_does_not_erase_timeout_fact(env: Env) -> None:
    backend = FakeDockerBackend(states=[_state(running=True)], loop_last=True)
    backend.create_hook = lambda: _write_result(env.output, b"{not json")

    result = _supervisor(env, backend).execute(
        env.request, env.staging, env.output, deadline=0.0
    )

    assert result.result_valid is False
    assert result.timed_out is True
    assert result.error_class == "result_corrupt"


def test_identity_mismatch_is_rejected(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(
        env.output, _result_bytes(request, sample_id="other-sample")
    )

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure is not None
    assert "result_identity_mismatch" in result.validation_failure


def test_declared_result_hash_is_verified(env: Env) -> None:
    request = env.request
    body = _result_payload(request)
    declared = sha256_bytes(canonical_json_bytes(body))

    good = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    good.create_hook = lambda: _write_result(
        env.output, canonical_json_bytes({**body, "result_sha256": declared})
    )
    result = _supervisor(env, good).execute(request, env.staging, env.output)
    assert result.result_valid is True

    bad = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    bad.create_hook = lambda: _write_result(
        env.output, canonical_json_bytes({**body, "result_sha256": "0" * 64})
    )
    result = _supervisor(env, bad).execute(request, env.staging, env.output)
    assert result.result_valid is False
    assert result.validation_failure == "result_hash_mismatch"


def test_cleanup_failure_is_recorded(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(
        states=[_state(running=True), _state(running=False)],
        cleanup_error=ExecutionBackendError("cannot remove", error_class="cleanup_failed"),
    )
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request))

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.cleanup_complete is False
    assert result.still_needs_reclaim == ("cid-1",)
    assert result.error_class == "cleanup_failed"
    assert result.ok_for_evaluation() is False


def test_corrupt_result_takes_precedence_over_cleanup_failure(env: Env) -> None:
    backend = FakeDockerBackend(
        states=[_state(running=True), _state(running=False)],
        cleanup_error=ExecutionBackendError("cannot remove", error_class="cleanup_failed"),
    )
    backend.create_hook = lambda: _write_result(env.output, b"{not json")

    result = _supervisor(env, backend).execute(env.request, env.staging, env.output)

    assert result.result_valid is False
    assert result.error_class == "result_corrupt"
    assert result.cleanup_complete is False
    assert result.still_needs_reclaim == ("cid-1",)


# --------------------------------------------------------------------------- #
# Preflight failures still leave a record
# --------------------------------------------------------------------------- #


def test_config_rejection_is_recorded_on_disk(env: Env) -> None:
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    broken = replace(env.request, execution_profile_hash="0" * 64)

    result = _supervisor(env, backend).execute(broken, env.staging, env.output)

    assert result.error_class == "config_rejected"
    assert result.result_valid is False
    assert backend.actions == []
    assert (env.attempt_dir / "execution.json").is_file()
    persisted = ExecutionResult.from_json(read_json(env.attempt_dir / "execution.json"))
    assert persisted.error_class == "config_rejected"


def test_input_hash_mismatch_is_rejected(env: Env) -> None:
    item = InputFile(name="code.py", kind="code", sha256="0" * 64, size=len(env.content))
    broken = replace(env.request, input_files=(item,))
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])

    result = _supervisor(env, backend).execute(broken, env.staging, env.output)

    assert result.error_class == "config_rejected"
    assert backend.actions == []


def test_symlinked_input_is_rejected(env: Env) -> None:
    (env.staging / "link.py").symlink_to(env.staging / "code.py")
    item = InputFile(name="link.py", kind="code", sha256="a" * 64, size=1)
    broken = replace(env.request, input_files=(item,))
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])

    result = _supervisor(env, backend).execute(broken, env.staging, env.output)

    assert result.error_class == "config_rejected"
    assert backend.actions == []


# --------------------------------------------------------------------------- #
# Recovery
# --------------------------------------------------------------------------- #


def _recovery_env(tmp_path: Path, pool: dict[str, ContainerState]):
    profile = _profile()
    run_dir = tmp_path / "run"
    attempt = run_dir / "attempts" / "attempt-1"
    attempt.mkdir(parents=True)
    labels = {
        "coco-attack.managed": "true",
        "coco-attack.run": "run",
        "coco-attack.attempt": "attempt-1",
        "coco-attack.stage": "search",
    }
    result = ExecutionResult(
        sample_id="sample-1",
        attempt_id="attempt-1",
        stage="search",
        request_hash="r" * 64,
        container_id="cid-9",
        image_reference="img:tag",
        image_id=None,
        execution_profile_hash=profile.fingerprint(),
        supervisor_version="v1",
        harness_version="h1",
        result_valid=False,
        cleanup_complete=False,
        error_class="cleanup_failed",
        still_needs_reclaim=("cid-9",),
    )
    write_json_atomic(attempt / "execution.json", result.to_json())
    write_json_atomic(
        attempt / "container.json",
        {"container_id": "cid-9", "name": "coco-attack-attempt-1", "image": "img:tag", "labels": labels},
    )
    backend = FakeDockerBackend(pool=pool)
    return run_dir, attempt, backend, labels


def test_recover_only_touches_labeled_containers(tmp_path: Path) -> None:
    labels = {
        "coco-attack.managed": "true",
        "coco-attack.run": "run",
        "coco-attack.attempt": "attempt-1",
        "coco-attack.stage": "search",
    }
    owned = _state(running=True, cid="cid-9")
    owned = replace(owned, labels=labels)
    foreign = _state(running=True, cid="cid-foreign")
    foreign = replace(
        foreign,
        labels={"coco-attack.managed": "true", "coco-attack.run": "other-run"},
    )
    run_dir, attempt, backend, _ = _recovery_env(tmp_path, {"cid-9": owned, "cid-foreign": foreign})

    recovered = ExecutionSupervisor(
        _profile(), backend, run_dir, poll_interval_seconds=0
    ).recover()

    assert len(recovered) == 1
    assert recovered[0].cleanup_complete is True
    assert recovered[0].still_needs_reclaim == ()
    assert backend.last_labels["coco-attack.run"] == "run"
    assert backend.last_labels["coco-attack.managed"] == "true"
    assert backend.last_labels["coco-attack.attempt"] == "attempt-1"
    assert ("remove", "cid-9", True) in backend.actions
    assert "cid-foreign" in backend.pool
    assert "cid-foreign" not in backend.removed
    assert all("prune" not in str(action) for action in backend.actions)
    persisted = ExecutionResult.from_json(read_json(attempt / "execution.json"))
    assert persisted.cleanup_complete is True


def test_recover_reports_unconfirmed_cleanup(tmp_path: Path) -> None:
    labels = {
        "coco-attack.managed": "true",
        "coco-attack.run": "run",
        "coco-attack.attempt": "attempt-1",
        "coco-attack.stage": "search",
    }
    owned = replace(_state(running=True, cid="cid-9"), labels=labels)
    run_dir, attempt, backend, _ = _recovery_env(tmp_path, {"cid-9": owned})
    backend.cleanup_error = ExecutionBackendError("still running", error_class="cleanup_failed")

    recovered = ExecutionSupervisor(
        _profile(), backend, run_dir, poll_interval_seconds=0
    ).recover()

    assert recovered[0].cleanup_complete is False
    assert "cid-9" in recovered[0].still_needs_reclaim
    assert recovered[0].error_class == "cleanup_failed"
    assert "cid-9" in backend.pool


# --------------------------------------------------------------------------- #
# Reviewer regression fixes
# --------------------------------------------------------------------------- #


def test_create_failure_reports_docker_unavailable(env: Env) -> None:
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])

    def failing_create(spec: ContainerSpec) -> str:
        raise ExecutionBackendError("cannot connect to daemon", error_class="docker_unavailable")

    backend.create = failing_create  # type: ignore[method-assign]

    result = _supervisor(env, backend).execute(env.request, env.staging, env.output)

    assert result.available is False
    assert result.error_class == "docker_unavailable"
    assert result.validation_failure is None
    assert (env.attempt_dir / "execution.json").is_file()


def test_missing_inspect_after_create_is_not_treated_as_completion(env: Env) -> None:
    backend = FakeDockerBackend(states=[])

    result = _supervisor(env, backend).execute(env.request, env.staging, env.output)

    assert result.available is False
    assert result.error_class == "docker_unavailable"
    # The container was still force-removed even though the exit could not be confirmed.
    assert ("remove", "cid-1", True) in backend.actions
    assert result.cleanup_complete is True


def test_missing_result_schema_is_rejected(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(
        env.output, _result_bytes(request, result_schema=None)
    )

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure == "result_schema_missing"


def test_result_schema_mismatch_is_rejected(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(
        env.output, _result_bytes(request, result_schema="other-schema")
    )

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure == "result_schema_mismatch:other-schema"


def test_oversized_output_artifact_is_rejected(env: Env) -> None:
    request = env.request
    (env.output / "big.bin").write_bytes(b"x" * (env.profile.output_limits.single_file_bytes + 1))
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request))

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure is not None
    assert result.validation_failure.startswith("output_file_too_large")


def test_symlinked_output_artifact_is_rejected(env: Env) -> None:
    request = env.request
    target = env.output.parent / "outside.bin"
    target.write_bytes(b"data")
    (env.output / "link.bin").symlink_to(target)
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request))

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure is not None
    assert result.validation_failure.startswith("output_symlink_rejected")


def test_recover_reclaims_attempt_without_execution_record(tmp_path: Path) -> None:
    profile = _profile()
    run_dir = tmp_path / "run"
    attempt = run_dir / "attempts" / "attempt-1"
    attempt.mkdir(parents=True)
    labels = {
        "coco-attack.managed": "true",
        "coco-attack.run": "run",
        "coco-attack.attempt": "attempt-1",
        "coco-attack.stage": "search",
    }
    env_request = ExecutionRequest(
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
    write_json_atomic(attempt / "request.json", env_request.to_json())
    write_json_atomic(
        attempt / "container.json",
        {"container_id": "cid-9", "name": "coco-attack-attempt-1", "image": "img:tag", "labels": labels},
    )
    owned = replace(_state(running=True, cid="cid-9"), labels=labels)
    backend = FakeDockerBackend(pool={"cid-9": owned})

    recovered = ExecutionSupervisor(profile, backend, run_dir, poll_interval_seconds=0).recover()

    assert len(recovered) == 1
    assert recovered[0].cleanup_complete is True
    assert recovered[0].validation_failure == "recovered_without_execution_record"
    assert recovered[0].result_valid is False
    assert ("remove", "cid-9", True) in backend.actions
    assert (attempt / "execution.json").is_file()


def test_recover_ignores_forged_ownership_labels_in_container_json(tmp_path: Path) -> None:
    profile = _profile()
    run_dir = tmp_path / "run"
    attempt = run_dir / "attempts" / "attempt-1"
    attempt.mkdir(parents=True)
    forged = {
        "coco-attack.managed": "true",
        "coco-attack.run": "evil-run",
        "coco-attack.attempt": "evil-attempt",
        "coco-attack.stage": "search",
    }
    write_json_atomic(
        attempt / "container.json",
        {"container_id": "cid-9", "name": "coco-attack-attempt-1", "image": "img:tag", "labels": forged},
    )
    owned = replace(_state(running=True, cid="cid-9"), labels={
        "coco-attack.managed": "true",
        "coco-attack.run": "run",
        "coco-attack.attempt": "attempt-1",
        "coco-attack.stage": "search",
    })
    backend = FakeDockerBackend(pool={"cid-9": owned})

    ExecutionSupervisor(profile, backend, run_dir, poll_interval_seconds=0).recover()

    assert backend.last_labels["coco-attack.run"] == "run"
    assert backend.last_labels["coco-attack.attempt"] == "attempt-1"


def test_recover_warns_on_profile_mismatch(tmp_path: Path) -> None:
    profile = _profile()
    run_dir = tmp_path / "run"
    (run_dir / "attempts").mkdir(parents=True)
    write_json_atomic(run_dir / "manifest.json", {"profile_hash": "deadbeef"})
    backend = FakeDockerBackend()

    supervisor = ExecutionSupervisor(profile, backend, run_dir, poll_interval_seconds=0)
    recovered = supervisor.recover()

    assert recovered == []
    assert any("profile_version_mismatch" in item for item in supervisor.recovery_warnings)


def test_recover_reports_unconfirmed_when_list_managed_fails(tmp_path: Path) -> None:
    profile = _profile()
    run_dir, attempt, backend, _labels = _recovery_env(tmp_path, {})

    def failing_list(labels):
        raise ExecutionBackendError("docker ps failed", error_class="cleanup_failed")

    backend.list_managed = failing_list  # type: ignore[method-assign]

    recovered = ExecutionSupervisor(profile, backend, run_dir, poll_interval_seconds=0).recover()

    assert recovered[0].cleanup_complete is False
    assert recovered[0].still_needs_reclaim



def test_run_lock_rejects_second_holder(tmp_path: Path) -> None:
    from coco_attack.execution.supervisor import RunLock, RunLockedError

    run_dir = tmp_path / "run"
    first = RunLock(run_dir).acquire()
    try:
        with pytest.raises(RunLockedError):
            RunLock(run_dir).acquire()
    finally:
        first.release()
    RunLock(run_dir).acquire().release()


def test_result_nonce_mismatch_is_rejected(env: Env) -> None:
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])
    backend.create_hook = lambda: _write_result(env.output, _result_bytes(request, nonce="wrong"))

    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.result_valid is False
    assert result.validation_failure == "result_nonce_mismatch"


def test_output_artifacts_are_archived(tmp_path: Path) -> None:
    env = Env(tmp_path)
    request = env.request
    backend = FakeDockerBackend(states=[_state(running=True), _state(running=False)])

    def hook() -> None:
        _write_result(env.output, _result_bytes(request))
        (env.output / "extra.txt").write_text("artifact", encoding="utf-8")

    backend.create_hook = hook
    result = _supervisor(env, backend).execute(request, env.staging, env.output)

    assert result.attachments == ("extra.txt",)
    assert (env.attempt_dir / "artifacts" / "extra.txt").read_text(encoding="utf-8") == "artifact"
