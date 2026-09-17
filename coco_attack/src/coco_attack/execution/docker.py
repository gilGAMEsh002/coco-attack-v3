"""Docker control client for the execution-isolation service (task 01).

The client never runs a shell, never inherits the ambient environment and gives
every control command a hard timeout that kills the whole process group on
expiry.  ``_build_create_argv`` is a pure function so the security-critical
argument construction can be unit tested without Docker.
"""

from __future__ import annotations

import json
import math
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, Sequence

from .contracts import (
    ContainerSpec,
    ContainerState,
    ExecutionBackendError,
)

__all__ = [
    "CommandResult",
    "LogResult",
    "DockerBackend",
    "DockerClient",
    "build_create_argv",
    "sanitize_argv_for_log",
]

_PROCESS_KILL_GRACE_SECONDS = 1.0
_LOG_READ_CHUNK = 65536
_SENSITIVE_ENV_MARKERS = ("PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "APIKEY")

# Environment variables that may be forwarded to the Docker CLI.  Everything
# else from the host environment is dropped; DOCKER_HOST is only forwarded when
# the caller explicitly supplies it.
_ENV_WHITELIST = ("PATH", "HOME")


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


@dataclass(frozen=True)
class LogResult:
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


class DockerBackend(Protocol):
    def probe(self) -> dict[str, Any]: ...

    def image_inspect(self, reference: str) -> dict[str, Any] | None: ...

    def inspect_raw(self, container_id: str) -> dict[str, Any] | None: ...

    def create(self, spec: ContainerSpec) -> str: ...

    def start(self, container_id: str) -> None: ...

    def inspect(self, container_id: str) -> ContainerState | None: ...

    def wait(self, container_id: str, timeout_seconds: float) -> int | None: ...

    def stop(self, container_id: str, grace_seconds: float) -> None: ...

    def remove(self, container_id: str, force: bool) -> None: ...

    def list_managed(self, labels: dict[str, str]) -> list[ContainerState]: ...

    def logs(
        self, container_id: str, stdout_max_bytes: int, stderr_max_bytes: int
    ) -> LogResult: ...


# --------------------------------------------------------------------------- #
# Pure argv construction
# --------------------------------------------------------------------------- #


def _format_number(value: float) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def build_create_argv(spec: ContainerSpec, name: str | None = None) -> list[str]:
    """Build the ``docker create`` argv for ``spec``.

    Pure: it only reads ``spec`` (and the optional explicit ``name``) and never
    consults the environment or the file system.  The emitted argument list is
    deliberately restrictive; a whole family of dangerous flags is never
    produced because :class:`ContainerSpec` already rejects them.
    """

    container_name = name if name is not None else spec.name
    argv: list[str] = ["docker", "create", "--name", container_name]

    for key in sorted(spec.labels):
        argv += ["--label", f"{key}={spec.labels[key]}"]

    argv += ["--network=none"]
    if spec.read_only_rootfs:
        argv += ["--read-only"]
    for cap in spec.cap_drop:
        argv += ["--cap-drop", cap]
    if spec.no_new_privileges:
        argv += ["--security-opt=no-new-privileges"]
    argv += ["--user", f"{spec.uid}:{spec.gid}"]
    argv += ["--workdir", spec.workdir]
    argv += ["--memory", str(spec.memory_bytes)]
    argv += ["--memory-swap", str(spec.memory_swap_bytes)]
    argv += ["--cpus", _format_number(spec.cpu_quota)]
    argv += ["--pids-limit", str(spec.pids_limit)]
    argv += ["--stop-signal", spec.stop_signal]

    for mount in spec.mounts:
        value = f"type=bind,source={mount.source},target={mount.target}"
        if mount.read_only:
            value += ",readonly"
        argv += ["--mount", value]

    for tmpfs in spec.tmpfs:
        value = f"{tmpfs.target}:size={tmpfs.size_bytes},mode={tmpfs.mode}"
        for option in tmpfs.options:
            value += f",{option}"
        argv += ["--tmpfs", value]

    for key, value in spec.env:
        argv += ["--env", f"{key}={value}"]

    argv.append(spec.image)
    argv.extend(spec.argv)
    return argv


# The design names the pure helper ``_build_create_argv``; keep that spelling
# available in addition to the public name.
def _build_create_argv(spec: ContainerSpec, name: str | None = None) -> list[str]:
    return build_create_argv(spec, name)


def sanitize_argv_for_log(argv: Sequence[str]) -> list[str]:
    """Return a copy of ``argv`` with sensitive ``--env`` values masked."""

    sanitized: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--env" and index + 1 < len(argv):
            sanitized += ["--env", _mask_env_assignment(argv[index + 1])]
            index += 2
            continue
        if token.startswith("--env="):
            sanitized.append("--env=" + _mask_env_assignment(token[len("--env=") :]))
            index += 1
            continue
        sanitized.append(token)
        index += 1
    return sanitized


def _mask_env_assignment(assignment: str) -> str:
    key, separator, value = assignment.partition("=")
    if separator and any(marker in key.upper() for marker in _SENSITIVE_ENV_MARKERS):
        return f"{key}=***"
    return assignment


# --------------------------------------------------------------------------- #
# DockerClient
# --------------------------------------------------------------------------- #


Runner = Callable[[Sequence[str], float], CommandResult]


class DockerClient:
    """Concrete :class:`DockerBackend` backed by the ``docker`` CLI."""

    def __init__(
        self,
        executable: str = "docker",
        control_timeout_seconds: float = 30.0,
        runner: Runner | None = None,
        clock: Callable[[], float] = time.monotonic,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(control_timeout_seconds, (int, float)) or control_timeout_seconds <= 0:
            raise ValueError("control_timeout_seconds must be a positive number")
        self._executable = executable
        self.control_timeout_seconds = float(control_timeout_seconds)
        self._runner = runner
        self._clock = clock
        self._explicit_env = dict(env) if env else {}

    # The design names the pure helper ``_build_create_argv(spec, name)``; the
    # module-level function is the single implementation, exposed here too so
    # callers that expect it as a client method keep working.
    _build_create_argv = staticmethod(build_create_argv)

    # -- process plumbing -------------------------------------------------- #

    def _subprocess_env(self) -> dict[str, str]:
        env: dict[str, str] = {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
        for name in _ENV_WHITELIST:
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
        env.update(self._explicit_env)
        return env

    def _run(self, argv: Sequence[str], timeout: float | None = None) -> CommandResult:
        effective_timeout = self.control_timeout_seconds if timeout is None else float(timeout)
        if self._runner is not None:
            return self._runner(list(argv), effective_timeout)
        return self._default_runner(list(argv), effective_timeout)

    def _default_runner(self, argv: list[str], timeout: float) -> CommandResult:
        start = self._clock()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=self._subprocess_env(),
            )
        except FileNotFoundError as error:
            return CommandResult(
                tuple(argv),
                None,
                "",
                f"executable not found: {error}",
                False,
                self._clock() - start,
            )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return CommandResult(
                tuple(argv),
                process.returncode,
                _decode(stdout),
                _decode(stderr),
                False,
                self._clock() - start,
            )
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            try:
                stdout, stderr = process.communicate(
                    timeout=_PROCESS_KILL_GRACE_SECONDS * 2
                )
            except subprocess.TimeoutExpired:
                # A descendant escaped the process group and still holds the
                # pipe; do not block forever on a control command.
                _kill_process_group(process)
                stdout, stderr = b"", b""
            return CommandResult(
                tuple(argv),
                process.returncode,
                _decode(stdout),
                _decode(stderr),
                True,
                self._clock() - start,
            )

    # -- DockerBackend ----------------------------------------------------- #

    def probe(self) -> dict[str, Any]:
        version_argv = [self._executable, "version", "--format", "{{json .}}"]
        info_argv = [self._executable, "info", "--format", "{{json .}}"]
        version = self._run(version_argv)
        info = self._run(info_argv)

        reasons: list[str] = []
        available = True
        if version.timed_out:
            available = False
            reasons.append("docker version timed out")
        elif version.returncode is None:
            available = False
            reasons.append(version.stderr.strip() or "docker executable not found")
        elif version.returncode != 0:
            available = False
            reasons.append(version.stderr.strip() or "docker version failed")

        if info.timed_out:
            available = False
            reasons.append("docker info timed out")
        elif info.returncode is None:
            available = False
            reasons.append(info.stderr.strip() or "docker executable not found")
        elif info.returncode != 0:
            available = False
            reasons.append(info.stderr.strip() or "docker info failed")

        version_json = _parse_json(version.stdout) or {}
        info_json = _parse_json(info.stdout) or {}
        client = version_json.get("Client") if isinstance(version_json, dict) else None
        server = version_json.get("Server") if isinstance(version_json, dict) else None
        client_version = client.get("Version") if isinstance(client, dict) else None
        server_version = None
        if isinstance(server, dict):
            server_version = server.get("Version")
        if server_version is None and isinstance(info_json, dict):
            server_version = info_json.get("ServerVersion")

        security_options = []
        if isinstance(info_json, dict):
            security_options = info_json.get("SecurityOptions") or []
        rootless = any("rootless" in str(option).lower() for option in security_options)

        return {
            "available": available,
            "client_version": client_version,
            "server_version": server_version,
            "os": info_json.get("OperatingSystem") if isinstance(info_json, dict) else None,
            "arch": info_json.get("Architecture") if isinstance(info_json, dict) else None,
            "kernel": info_json.get("KernelVersion") if isinstance(info_json, dict) else None,
            "cgroup_version": info_json.get("CgroupVersion") if isinstance(info_json, dict) else None,
            "storage_driver": info_json.get("Driver") if isinstance(info_json, dict) else None,
            "rootless": rootless,
            "reason": "; ".join(reason for reason in reasons if reason) or None,
        }

    def image_inspect(self, reference: str) -> dict[str, Any] | None:
        argv = [self._executable, "image", "inspect", "--format", "{{json .}}", reference]
        result = self._run(argv)
        if result.timed_out or result.returncode != 0:
            return None
        parsed = _parse_json(result.stdout)
        if isinstance(parsed, list):
            if not parsed:
                return None
            first = parsed[0]
            return first if isinstance(first, dict) else None
        return parsed if isinstance(parsed, dict) else None

    def inspect_raw(self, container_id: str) -> dict[str, Any] | None:
        """Return the full ``docker inspect`` document for a container.

        The raw document is needed to verify the *actual* security and resource
        settings (HostConfig/Mounts) rather than trusting the probe's own
        self-report.
        """

        argv = [self._executable, "inspect", "--format", "{{json .}}", container_id]
        result = self._run(argv)
        if result.timed_out or result.returncode != 0:
            return None
        parsed = _parse_json(result.stdout)
        if isinstance(parsed, list):
            if not parsed:
                return None
            first = parsed[0]
            return first if isinstance(first, dict) else None
        return parsed if isinstance(parsed, dict) else None

    def create(self, spec: ContainerSpec) -> str:
        argv = build_create_argv(spec, spec.name)
        result = self._run(argv)
        if result.timed_out:
            raise ExecutionBackendError(
                f"docker create timed out: {' '.join(sanitize_argv_for_log(argv))}",
                error_class="create_failed",
            )
        if result.returncode is None:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker executable not found",
                error_class="docker_unavailable",
            )
        if result.returncode != 0:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker create failed",
                error_class="create_failed",
            )
        container_id = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
        if not container_id:
            raise ExecutionBackendError("docker create returned no container id", error_class="create_failed")
        return container_id

    def start(self, container_id: str) -> None:
        result = self._run([self._executable, "start", container_id])
        if result.timed_out:
            raise ExecutionBackendError(
                f"docker start timed out for {container_id}", error_class="start_failed"
            )
        if result.returncode is None:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker executable not found",
                error_class="docker_unavailable",
            )
        if result.returncode != 0:
            raise ExecutionBackendError(
                result.stderr.strip() or f"docker start failed for {container_id}",
                error_class="start_failed",
            )

    def inspect(self, container_id: str) -> ContainerState | None:
        argv = [self._executable, "inspect", "--format", "{{json .}}", container_id]
        result = self._run(argv)
        if result.timed_out or result.returncode != 0:
            return None
        parsed = _parse_json(result.stdout)
        if not isinstance(parsed, dict):
            return None
        return _state_from_inspect(parsed)

    def wait(self, container_id: str, timeout_seconds: float) -> int | None:
        argv = [self._executable, "wait", container_id]
        result = self._run(argv, timeout=timeout_seconds)
        if result.timed_out or result.returncode != 0:
            return None
        text = result.stdout.strip()
        try:
            return int(text)
        except ValueError:
            return None

    def stop(self, container_id: str, grace_seconds: float) -> None:
        grace = max(0, int(math.ceil(grace_seconds)))
        argv = [self._executable, "stop", "--time", str(grace), container_id]
        result = self._run(argv, timeout=self.control_timeout_seconds + grace + _PROCESS_KILL_GRACE_SECONDS)
        if result.timed_out:
            raise ExecutionBackendError(
                f"docker stop timed out for {container_id}", error_class="cleanup_failed"
            )
        if result.returncode is None:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker executable not found",
                error_class="docker_unavailable",
            )
        if result.returncode != 0:
            raise ExecutionBackendError(
                result.stderr.strip() or f"docker stop failed for {container_id}",
                error_class="cleanup_failed",
            )

    def remove(self, container_id: str, force: bool) -> None:
        argv = [self._executable, "rm"]
        if force:
            argv.append("-f")
        argv.append(container_id)
        result = self._run(argv)
        if result.timed_out:
            raise ExecutionBackendError(
                f"docker rm timed out for {container_id}", error_class="cleanup_failed"
            )
        if result.returncode is None:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker executable not found",
                error_class="docker_unavailable",
            )
        if result.returncode != 0:
            raise ExecutionBackendError(
                result.stderr.strip() or f"docker rm failed for {container_id}",
                error_class="cleanup_failed",
            )

    def list_managed(self, labels: dict[str, str]) -> list[ContainerState]:
        argv = [self._executable, "ps", "-a", "--no-trunc", "--quiet"]
        for key in sorted(labels):
            argv += ["--filter", f"label={key}={labels[key]}"]
        result = self._run(argv)
        if result.timed_out:
            raise ExecutionBackendError("docker ps timed out", error_class="cleanup_failed")
        if result.returncode is None:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker executable not found",
                error_class="docker_unavailable",
            )
        if result.returncode != 0:
            raise ExecutionBackendError(
                result.stderr.strip() or "docker ps failed", error_class="cleanup_failed"
            )
        states: list[ContainerState] = []
        for line in result.stdout.splitlines():
            container_id = line.strip()
            if not container_id:
                continue
            state = self.inspect(container_id)
            if state is not None:
                states.append(state)
        return states

    def logs(
        self, container_id: str, stdout_max_bytes: int, stderr_max_bytes: int
    ) -> LogResult:
        argv = [self._executable, "logs", container_id]
        if self._runner is not None:
            # Injected runners are synchronous; ask for the whole (bounded) log
            # and truncate in memory.  The default path streams instead.
            result = self._runner(argv, self.control_timeout_seconds)
            stdout = result.stdout
            stderr = result.stderr
            stdout_truncated = len(stdout.encode("utf-8")) > stdout_max_bytes
            stderr_truncated = len(stderr.encode("utf-8")) > stderr_max_bytes
            return LogResult(
                _truncate_text(stdout, stdout_max_bytes),
                _truncate_text(stderr, stderr_max_bytes),
                stdout_truncated,
                stderr_truncated,
            )
        return self._stream_logs(argv, stdout_max_bytes, stderr_max_bytes)

    def _stream_logs(
        self, argv: list[str], stdout_max_bytes: int, stderr_max_bytes: int
    ) -> LogResult:
        start = self._clock()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=self._subprocess_env(),
            )
        except FileNotFoundError:
            return LogResult("", "docker executable not found", False, False)

        assert process.stdout is not None and process.stderr is not None
        buffers = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
        truncated = {process.stdout.fileno(): False, process.stderr.fileno(): False}
        limits = {
            process.stdout.fileno(): max(0, stdout_max_bytes),
            process.stderr.fileno(): max(0, stderr_max_bytes),
        }
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, data="stdout")
        selector.register(process.stderr, selectors.EVENT_READ, data="stderr")
        try:
            while selector.get_map():
                remaining_time = self.control_timeout_seconds - (self._clock() - start)
                if remaining_time <= 0:
                    _kill_process_group(process)
                    break
                events = selector.select(timeout=remaining_time)
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                for key, _mask in events:
                    stream = key.fileobj
                    file_descriptor = stream.fileno()
                    chunk = os.read(file_descriptor, _LOG_READ_CHUNK)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    room = limits[file_descriptor] - len(buffers[file_descriptor])
                    if room > 0:
                        buffers[file_descriptor].extend(chunk[:room])
                    if len(chunk) > room:
                        truncated[file_descriptor] = True
        finally:
            selector.close()
        if process.poll() is None:
            _kill_process_group(process)
        process.wait()
        return LogResult(
            buffers[process.stdout.fileno()].decode("utf-8", errors="replace"),
            buffers[process.stderr.fileno()].decode("utf-8", errors="replace"),
            truncated[process.stdout.fileno()],
            truncated[process.stderr.fileno()],
        )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def _truncate_text(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _parse_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _state_from_inspect(payload: dict[str, Any]) -> ContainerState:
    state = payload.get("State") if isinstance(payload.get("State"), dict) else {}
    config = payload.get("Config") if isinstance(payload.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    exit_code = state.get("ExitCode")
    return ContainerState(
        container_id=str(payload.get("Id", "")) or str(payload.get("ID", "")),
        name=str(payload.get("Name", "")).lstrip("/"),
        status=str(state.get("Status", "")),
        running=bool(state.get("Running", False)),
        exit_code=exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
        oom_killed=bool(state.get("OOMKilled", False)),
        started_at=state.get("StartedAt"),
        finished_at=state.get("FinishedAt"),
        labels={str(k): str(v) for k, v in labels.items()},
        image_id=payload.get("Image") if isinstance(payload.get("Image"), str) else None,
    )


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
