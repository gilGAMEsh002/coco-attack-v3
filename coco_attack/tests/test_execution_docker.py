"""Docker argv construction and client plumbing tests (Chunk 1).

None of these tests require a Docker daemon.
"""

from __future__ import annotations

import json

import pytest

from coco_attack.execution import docker
from coco_attack.execution.contracts import (
    ContainerSpec,
    ExecutionBackendError,
    MountSpec,
    TmpfsSpec,
)
from coco_attack.execution.docker import CommandResult, DockerClient, LogResult


def _spec(**overrides) -> ContainerSpec:
    base = dict(
        name="coco-attack-attempt-1",
        labels={"coco-attack.managed": "true", "coco-attack.run": "run-1"},
        image="sha256:" + "b" * 64,
        argv=("python", "-m", "entrypoint", "functional", "--x=1"),
        mounts=(
            MountSpec(source="/host/in", target="/in", read_only=True),
            MountSpec(source="/host/out", target="/out", read_only=False),
        ),
        tmpfs=(
            TmpfsSpec(target="/tmp", size_bytes=1024, mode="1777", options=("rw", "nosuid", "nodev")),
            TmpfsSpec(target="/work", size_bytes=1024, mode="0755"),
        ),
        env=(("LANG", "C.UTF-8"), ("PROBE_TOKEN", "supersecret")),
        network="none",
        read_only_rootfs=True,
        cap_drop=("ALL",),
        no_new_privileges=True,
        uid=10001,
        gid=10001,
        workdir="/work",
        memory_bytes=536870912,
        memory_swap_bytes=536870912,
        cpu_quota=1.0,
        pids_limit=64,
    )
    base.update(overrides)
    return ContainerSpec(**base)


def test_build_create_argv_is_pure_and_complete() -> None:
    spec = _spec()
    first = docker.build_create_argv(spec)
    second = docker.build_create_argv(spec)
    assert first == second
    assert first[:2] == ["docker", "create"]
    assert first[2:4] == ["--name", spec.name]
    for flag in (
        "--network=none",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--user",
        "--workdir",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--pids-limit",
        "--stop-signal",
        "--mount",
        "--tmpfs",
        "--env",
    ):
        assert flag in first
    assert "--cap-drop" in first and "ALL" in first
    assert "10001:10001" in first
    assert "SIGTERM" in first
    assert "type=bind,source=/host/in,target=/in,readonly" in first
    assert "type=bind,source=/host/out,target=/out" in first
    assert any(value.startswith("/tmp:size=1024,mode=1777") for value in first)
    assert "LANG=C.UTF-8" in first
    # The image is followed directly by the entry argv.
    assert first[first.index(spec.image) + 1 :] == list(spec.argv)


def test_build_create_argv_aliases_agree() -> None:
    spec = _spec()
    assert docker._build_create_argv(spec) == docker.build_create_argv(spec)
    assert DockerClient._build_create_argv(spec) == docker.build_create_argv(spec)


def test_build_create_argv_never_emits_dangerous_flags() -> None:
    argv = docker.build_create_argv(_spec())
    joined = " ".join(argv)
    for forbidden in (
        "--privileged",
        "--pid=host",
        "--ipc=host",
        "--cap-add",
        "--device",
        "/var/run/docker.sock",
        "--network=host",
    ):
        assert forbidden not in joined
    assert "-v" not in argv


def test_sanitize_argv_for_log_masks_sensitive_env() -> None:
    argv = [
        "docker",
        "create",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "API_TOKEN=abc",
        "--env=SECRET=def",
        "image",
    ]
    assert docker.sanitize_argv_for_log(argv) == [
        "docker",
        "create",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "API_TOKEN=***",
        "--env=SECRET=***",
        "image",
    ]


# --------------------------------------------------------------------------- #
# DockerClient with an injected runner
# --------------------------------------------------------------------------- #


def _command(argv, *, returncode=0, stdout="", stderr="", timed_out=False) -> CommandResult:
    return CommandResult(tuple(argv), returncode, stdout, stderr, timed_out, 0.0)


def test_probe_reports_available_environment() -> None:
    version_json = json.dumps({"Client": {"Version": "27.0"}, "Server": {"Version": "27.1"}})
    info_json = json.dumps(
        {
            "OperatingSystem": "Linux",
            "Architecture": "x86_64",
            "KernelVersion": "6.1.0",
            "CgroupVersion": "2",
            "Driver": "overlay2",
            "SecurityOptions": ["name=seccomp", "name=rootless"],
        }
    )

    def runner(argv, timeout):
        if argv[1] == "version":
            return _command(argv, stdout=version_json)
        return _command(argv, stdout=info_json)

    probe = DockerClient(runner=runner).probe()
    assert probe["available"] is True
    assert probe["client_version"] == "27.0"
    assert probe["server_version"] == "27.1"
    assert probe["os"] == "Linux"
    assert probe["arch"] == "x86_64"
    assert probe["kernel"] == "6.1.0"
    assert probe["cgroup_version"] == "2"
    assert probe["storage_driver"] == "overlay2"
    assert probe["rootless"] is True


def test_probe_reports_unavailable_without_raising() -> None:
    def runner(argv, timeout):
        return _command(argv, returncode=1, stderr="Cannot connect to the Docker daemon")

    probe = DockerClient(runner=runner).probe()
    assert probe["available"] is False
    assert "Cannot connect" in probe["reason"]


def test_probe_reports_missing_executable() -> None:
    def runner(argv, timeout):
        return _command(argv, returncode=None, stderr="executable not found")

    probe = DockerClient(runner=runner).probe()
    assert probe["available"] is False
    assert probe["reason"]


def test_image_inspect_unwraps_list_and_returns_none_on_failure() -> None:
    def present(argv, timeout):
        return _command(argv, stdout=json.dumps([{"Id": "sha256:abc"}]))

    assert DockerClient(runner=present).image_inspect("img") == {"Id": "sha256:abc"}

    def absent(argv, timeout):
        return _command(argv, returncode=1, stderr="No such image")

    assert DockerClient(runner=absent).image_inspect("img") is None


def test_create_maps_failures_to_error_classes() -> None:
    def failing(argv, timeout):
        return _command(argv, returncode=1, stderr="name already in use")

    with pytest.raises(ExecutionBackendError) as error:
        DockerClient(runner=failing).create(_spec())
    assert error.value.error_class == "create_failed"

    def missing(argv, timeout):
        return _command(argv, returncode=None, stderr="executable not found")

    with pytest.raises(ExecutionBackendError) as error:
        DockerClient(runner=missing).create(_spec())
    assert error.value.error_class == "docker_unavailable"


def test_inspect_maps_container_state() -> None:
    payload = json.dumps(
        {
            "Id": "cid-1",
            "Name": "/coco-attack-attempt-1",
            "Image": "sha256:" + "b" * 64,
            "State": {
                "Status": "exited",
                "Running": False,
                "ExitCode": 3,
                "OOMKilled": True,
                "StartedAt": "2026-01-01T00:00:00Z",
                "FinishedAt": "2026-01-01T00:00:05Z",
            },
            "Config": {"Labels": {"coco-attack.managed": "true"}},
        }
    )

    def runner(argv, timeout):
        return _command(argv, stdout=payload)

    state = DockerClient(runner=runner).inspect("cid-1")
    assert state is not None
    assert state.container_id == "cid-1"
    assert state.name == "coco-attack-attempt-1"
    assert state.status == "exited"
    assert state.running is False
    assert state.exit_code == 3
    assert state.oom_killed is True
    assert state.labels == {"coco-attack.managed": "true"}


def test_logs_truncate_with_injected_runner() -> None:
    def runner(argv, timeout):
        return _command(argv, stdout="x" * 100, stderr="y" * 100)

    logs = DockerClient(runner=runner).logs("cid-1", 10, 20)
    assert isinstance(logs, LogResult)
    assert logs.stdout == "x" * 10
    assert logs.stderr == "y" * 20
    assert logs.stdout_truncated is True
    assert logs.stderr_truncated is True


def test_default_runner_hard_timeout_kills_process_group() -> None:
    client = DockerClient(executable="sleep", control_timeout_seconds=0.2)
    result = client._run(["sleep", "5"], 0.2)
    assert result.timed_out is True
    assert result.duration_seconds < 3.0
    assert result.returncode is not None
