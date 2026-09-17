"""Host-side container lifecycle supervisor (task 01).

The supervisor is the only component allowed to drive a backend for a request.
It persists the request and deadline *before* creating a container, keeps
timeout/exit facts independent from result completeness, and always writes an
``execution.json`` record even when an exception escapes.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import shutil
import stat
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
)
from .contracts import (
    ERROR_CLASSES,
    ContainerSpec,
    ExecutionBackendError,
    ExecutionConfigError,
    ExecutionError,
    ExecutionProfile,
    ExecutionRequest,
    ExecutionResult,
    MountSpec,
    TmpfsSpec,
)
from .docker import DockerBackend

__all__ = ["ExecutionSupervisor"]

DEFAULT_SUPERVISOR_VERSION = "execution-supervisor-v1"

NONCE_PLACEHOLDER = "__NONCE__"


class RunLockedError(ExecutionConfigError):
    """Another controlling process already owns this run directory."""

    def __init__(self, reason: str = "run directory is locked by another process") -> None:
        super().__init__(reason, error_class="config_rejected")


class RunLock:
    """A minimal local mutex over a run directory.

    The second controlling process that tries to operate on the same run
    directory is rejected rather than coordinated with; there is no distributed
    locking and no cross-host coordination.
    """

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)
        self._fd: int | None = None

    def acquire(self) -> "RunLock":
        self.run_dir.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(self.run_dir / ".runlock"), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise RunLockedError(
                f"run directory is locked by another process: {self.run_dir}"
            ) from error
        self._fd = descriptor
        return self

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "RunLock":
        return self.acquire()

    def __exit__(self, *exc_info: Any) -> None:
        self.release()

_PHASE_ERROR_CLASS = {
    "preflight": "config_rejected",
    "create": "create_failed",
    "start": "start_failed",
    "run": "timeout",
    "collect": "result_corrupt",
    "cleanup": "cleanup_failed",
}

_DEFAULT_ENV_VALUES = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}

_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _safe_component(value: str) -> str:
    cleaned = _COMPONENT_RE.sub("-", value or "").strip(".-")
    return cleaned or "attempt"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ExecutionSupervisor:
    def __init__(
        self,
        profile: ExecutionProfile,
        backend: DockerBackend,
        run_dir: Path | str,
        *,
        clock: Callable[[], float] = time.monotonic,
        supervisor_version: str = DEFAULT_SUPERVISOR_VERSION,
        poll_interval_seconds: float = 0.05,
        sleep: Callable[[float], None] = time.sleep,
        default_nonce: str | None = None,
    ) -> None:
        if not isinstance(profile, ExecutionProfile):
            raise ExecutionConfigError("supervisor requires an ExecutionProfile")
        if not isinstance(supervisor_version, str) or not supervisor_version:
            raise ExecutionConfigError("supervisor_version must be a non-empty string")
        if poll_interval_seconds < 0:
            raise ExecutionConfigError("poll_interval_seconds must be >= 0")
        self.profile = profile
        self.backend = backend
        self.run_dir = Path(run_dir)
        self.clock = clock
        self.supervisor_version = supervisor_version
        self.poll_interval_seconds = float(poll_interval_seconds)
        self._sleep = sleep
        self.default_nonce = default_nonce
        self.recovery_warnings: list[str] = []
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "attempts").mkdir(parents=True, exist_ok=True)

    # -- public API -------------------------------------------------------- #

    @property
    def run_id(self) -> str:
        return self.run_dir.name or "run"

    def execute(
        self,
        request: ExecutionRequest,
        staging_dir: Path | str,
        output_dir: Path | str,
        *,
        deadline: float | None = None,
        nonce: str | None = None,
    ) -> ExecutionResult:
        attempt_component = _safe_component(request.attempt_id)
        attempt_dir = self.run_dir / "attempts" / attempt_component
        started_at = _utc_now()
        start_monotonic = self.clock()
        deadline_at = (
            float(deadline)
            if deadline is not None
            else start_monotonic + self.profile.timeouts.wall_clock_seconds
        )
        run_nonce = nonce or self.default_nonce or secrets.token_hex(16)

        facts: dict[str, Any] = {
            "container_id": None,
            "image_id": None,
            "nonce": run_nonce,
            "exit_code": None,
            "timed_out": False,
            "oom_killed": False,
            "output_truncated": False,
            "signals": [],
            "reclaim_note": None,
            "result_valid": False,
            "result_ref": None,
            "result_sha256": None,
            "attachments": [],
            "validation_failure": None,
            "available": True,
            "error_class": "none",
            "error_reason": None,
            "cleanup_failure": None,
            "cleanup_complete": False,
            "stdout_ref": None,
            "stderr_ref": None,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "still_needs_reclaim": [],
            "retry_of_attempt": None,
            "phase": "preflight",
        }

        container_id: str | None = None
        cleanup_done = False
        try:
            self._preflight(request, staging_dir, output_dir)
            self._prepare_mount_permissions(Path(staging_dir), Path(output_dir))
            attempt_dir.mkdir(parents=True, exist_ok=True)
            container_name = self._container_name(request.attempt_id)
            # Persist request/deadline BEFORE the container is created so a
            # crash cannot leave a running container with no owner record.
            write_json_atomic(attempt_dir / "request.json", request.to_json())
            write_json_atomic(
                attempt_dir / "deadline.json",
                {
                    "attempt_id": request.attempt_id,
                    "container_name": container_name,
                    "profile_hash": self.profile.fingerprint(),
                    "wall_clock_seconds": self.profile.timeouts.wall_clock_seconds,
                    "deadline_monotonic": deadline_at,
                },
            )

            spec = self._build_container_spec(
                request, Path(staging_dir), Path(output_dir), container_name, run_nonce
            )

            facts["phase"] = "create"
            container_id = self.backend.create(spec)
            facts["container_id"] = container_id
            write_json_atomic(
                attempt_dir / "container.json",
                {
                    "container_id": container_id,
                    "name": spec.name,
                    "image": spec.image,
                    "labels": spec.labels,
                },
            )

            facts["phase"] = "start"
            self.backend.start(container_id)

            facts["phase"] = "run"
            state, timed_out = self._wait_for_exit(container_id, deadline_at)
            if state is not None:
                facts["image_id"] = state.image_id
                if not state.running:
                    facts["exit_code"] = state.exit_code
                    facts["oom_killed"] = state.oom_killed
            if timed_out:
                facts["timed_out"] = True
                facts["signals"] = ["SIGTERM"]

            facts["phase"] = "collect"
            self._collect_result(request, Path(output_dir), attempt_dir, facts)

            self._collect_logs(container_id, attempt_dir, facts)
            self._archive_output(Path(output_dir), attempt_dir, facts)
        except ExecutionError as error:
            facts = self._apply_error(facts, error)
        except Exception as error:  # noqa: BLE001 - must be recorded, never swallowed
            facts = self._apply_error(facts, error)
        finally:
            if container_id is not None and not cleanup_done:
                try:
                    self._capture_inspect(container_id, attempt_dir)
                except Exception:  # noqa: BLE001 - audit evidence is best effort
                    pass
                try:
                    self._cleanup(container_id, facts)
                except Exception as error:  # noqa: BLE001 - cleanup must never mask the result
                    facts["cleanup_complete"] = False
                    facts["still_needs_reclaim"] = [container_id]
                    if facts.get("cleanup_failure") is None:
                        facts["cleanup_failure"] = (
                            "cleanup_failed",
                            f"cleanup raised {type(error).__name__}: {error}",
                        )
                cleanup_done = True

        result = self._compose_result(request, facts, started_at, start_monotonic)
        try:
            write_json_atomic(attempt_dir / "execution.json", result.to_json())
        except OSError as error:  # pragma: no cover - disk failure
            result = replace(result, reclaim_note=f"execution_record_write_failed: {error}")
        try:
            self._write_manifest()
        except OSError:  # pragma: no cover - manifest is an index, not the record
            pass
        return result

    def recover(self, run_dir: Path | str | None = None) -> list[ExecutionResult]:
        target = Path(run_dir) if run_dir is not None else self.run_dir
        run_id = target.name or "run"
        self.recovery_warnings = []

        # A run is recovered by ownership, not by exact executor version.  A
        # mismatch is reported as a warning; cleanup only proceeds when the
        # run/attempt ownership is clear from persisted records and labels.
        manifest_path = target / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = read_json(manifest_path)
            except (OSError, ValueError):
                manifest = None
            if isinstance(manifest, dict):
                recorded = manifest.get("profile_hash")
                if recorded and recorded != self.profile.fingerprint():
                    self.recovery_warnings.append(
                        "profile_version_mismatch: "
                        f"manifest={recorded} current={self.profile.fingerprint()}"
                    )

        attempts_dir = target / "attempts"
        recovered: list[ExecutionResult] = []
        if not attempts_dir.is_dir():
            return recovered

        for attempt_dir in sorted(entry for entry in attempts_dir.iterdir() if entry.is_dir()):
            execution_path = attempt_dir / "execution.json"
            request_path = attempt_dir / "request.json"
            container_path = attempt_dir / "container.json"

            result: ExecutionResult | None = None
            if execution_path.is_file():
                try:
                    result = ExecutionResult.from_json(read_json(execution_path))
                except (ExecutionError, ValueError, KeyError, TypeError, OSError):
                    result = None

            container_id: str | None = None
            stored_labels: dict[str, str] = {}
            if container_path.is_file():
                try:
                    container = read_json(container_path)
                except (OSError, ValueError):
                    container = None
                if isinstance(container, dict):
                    if container.get("container_id") is not None:
                        container_id = str(container["container_id"])
                    if isinstance(container.get("labels"), dict):
                        stored_labels = {
                            str(key): str(value)
                            for key, value in container["labels"].items()
                        }

            if result is None and container_id is None:
                continue

            # Ownership labels are always taken from this run/attempt directory.
            # Stored labels may only contribute non-ownership keys; a foreign or
            # stale container.json can never redirect recovery at another run.
            labels = {
                "coco-attack.managed": "true",
                "coco-attack.run": run_id,
                "coco-attack.attempt": attempt_dir.name,
            }
            for key, value in stored_labels.items():
                if key in ("coco-attack.managed", "coco-attack.run", "coco-attack.attempt"):
                    continue
                labels[key] = value

            list_failed = False
            try:
                managed = self.backend.list_managed(labels)
            except ExecutionError:
                managed = []
                list_failed = True
            except Exception:  # noqa: BLE001
                managed = []
                list_failed = True

            cleaned = not list_failed
            for state in managed:
                try:
                    self.backend.stop(
                        state.container_id, self.profile.timeouts.sigterm_grace_seconds
                    )
                    self.backend.remove(state.container_id, force=True)
                except Exception:  # noqa: BLE001
                    cleaned = False
                cleaned = self._confirm_removed(state.container_id) and cleaned

            if container_id is not None:
                cleaned = self._confirm_removed(container_id) and cleaned

            if result is None:
                # A crash after create/start but before execution.json was
                # written: reclaim the container and persist an explicit
                # recovery record; never fabricate a successful evaluation.
                result = self._synthesize_recovery_result(
                    request_path, container_id, cleaned, list_failed
                )
                if result is None:
                    continue
                write_json_atomic(execution_path, result.to_json())
            else:
                updated = _with_cleanup(result, cleaned, container_id)
                if list_failed and updated.cleanup_complete:
                    updated = _with_cleanup(result, False, container_id)
                write_json_atomic(execution_path, updated.to_json())
                result = updated
            recovered.append(result)

        self._write_manifest(target)
        return recovered

    def _synthesize_recovery_result(
        self,
        request_path: Path,
        container_id: str | None,
        cleaned: bool,
        list_failed: bool,
    ) -> ExecutionResult | None:
        if not request_path.is_file():
            return None
        try:
            request = ExecutionRequest.from_json(read_json(request_path))
        except (ExecutionError, ValueError, KeyError, TypeError, OSError):
            return None
        still: tuple[str, ...] = ()
        if not cleaned and container_id is not None:
            still = (container_id,)
        return ExecutionResult(
            sample_id=request.sample_id,
            attempt_id=request.attempt_id,
            stage=request.stage,
            request_hash=request.fingerprint(),
            container_id=container_id,
            image_reference=self.profile.image.reference,
            image_id=self.profile.image.image_id,
            execution_profile_hash=self.profile.fingerprint(),
            supervisor_version=self.supervisor_version,
            harness_version=request.harness_version,
            result_valid=False,
            validation_failure="recovered_without_execution_record",
            error_class="none" if cleaned else "cleanup_failed",
            cleanup_complete=cleaned,
            still_needs_reclaim=still,
            reclaim_note=(
                "list_managed failed during recovery" if list_failed else None
            ),
        )

    # -- execute internals -------------------------------------------------- #

    def _preflight(
        self, request: ExecutionRequest, staging_dir: Path | str, output_dir: Path | str
    ) -> None:
        request.validate_against(self.profile)
        staging = Path(staging_dir)
        output = Path(output_dir)
        if not staging.is_dir():
            raise ExecutionConfigError(f"staging directory does not exist: {staging}")
        if not output.is_dir():
            raise ExecutionConfigError(f"output directory does not exist: {output}")
        for item in request.input_files:
            path = staging / item.name
            try:
                file_stat = os.lstat(path)
            except FileNotFoundError as error:
                raise ExecutionConfigError(f"input file missing from staging: {item.name}") from error
            if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
                raise ExecutionConfigError(
                    f"input file must be a regular file (no symlinks/devices/FIFOs): {item.name}"
                )
            if file_stat.st_size != item.size:
                raise ExecutionConfigError(
                    f"input file size mismatch for {item.name}: "
                    f"declared {item.size}, actual {file_stat.st_size}"
                )
            actual_hash = sha256_file(path)
            if actual_hash != item.sha256:
                raise ExecutionConfigError(
                    f"input file sha256 mismatch for {item.name}: "
                    f"declared {item.sha256}, actual {actual_hash}"
                )

    def _capture_inspect(self, container_id: str, attempt_dir: Path) -> None:
        """Persist the raw ``docker inspect`` document for the attempt.

        This is the authoritative record of the container's actual HostConfig
        and mounts; preflight derives the security claims from it rather than
        from the probe's self-report.
        """

        raw_inspect = getattr(self.backend, "inspect_raw", None)
        if raw_inspect is None:
            return
        payload = raw_inspect(container_id)
        if not isinstance(payload, dict):
            return
        write_json_atomic(attempt_dir / "container_inspect.json", payload)

    def _prepare_mount_permissions(self, staging_dir: Path, output_dir: Path) -> None:
        """Make staging readable and the output directory writable by the sandbox uid.

        The container runs as a fixed non-root uid that does not own the host
        directories, so the trusted host must widen modes explicitly.  The
        per-attempt directories live under the operator-owned run root; the
        output directory is the only writable mount and is quota-bounded by the
        result collector.
        """

        os.chmod(output_dir, 0o777)
        for root, _dirs, files in os.walk(staging_dir):
            os.chmod(root, 0o755)
            for name in files:
                os.chmod(os.path.join(root, name), 0o644)

    def _container_name(self, attempt_id: str) -> str:
        component = _safe_component(attempt_id)
        name = f"coco-attack-{component}"
        if len(name) > 128:
            raise ExecutionConfigError(f"container name too long for attempt {attempt_id!r}")
        return name

    def _build_container_spec(
        self,
        request: ExecutionRequest,
        staging_dir: Path,
        output_dir: Path,
        container_name: str,
        nonce: str,
    ) -> ContainerSpec:
        entry = next(
            (item for item in self.profile.entries if item.entry_id == request.entry), None
        )
        if entry is None:  # already checked by validate_against
            raise ExecutionConfigError(f"unknown entry {request.entry!r}")
        sandbox = self.profile.sandbox
        limits = self.profile.limits
        labels = {
            "coco-attack.managed": "true",
            "coco-attack.run": self.run_id,
            "coco-attack.stage": request.stage,
            "coco-attack.attempt": request.attempt_id,
            "coco-attack.sample": request.sample_id,
            "coco-attack.profile": self.profile.fingerprint(),
        }
        mounts = (
            MountSpec(
                source=str(staging_dir.resolve()),
                target=sandbox.input_mount,
                read_only=True,
            ),
            MountSpec(
                source=str(output_dir.resolve()),
                target=sandbox.output_mount,
                read_only=False,
            ),
        )
        tmpfs = _tmpfs_specs(sandbox.tmpfs_paths, limits.workspace_bytes, limits.shm_bytes)
        env = tuple(
            sorted(
                (name, _DEFAULT_ENV_VALUES[name])
                for name in sandbox.allowed_env
                if name in _DEFAULT_ENV_VALUES
            )
        )
        entry_argv = tuple(
            nonce if token == NONCE_PLACEHOLDER else token for token in entry.argv
        )
        return ContainerSpec(
            name=container_name,
            labels=labels,
            image=self.profile.image.image_id or self.profile.image.reference,
            argv=entry_argv + tuple(request.entry_args),
            mounts=mounts,
            tmpfs=tmpfs,
            env=env,
            network=sandbox.network,
            read_only_rootfs=sandbox.read_only_rootfs,
            cap_drop=sandbox.cap_drop,
            no_new_privileges=sandbox.no_new_privileges,
            uid=sandbox.uid,
            gid=sandbox.gid,
            workdir=sandbox.workdir,
            memory_bytes=limits.memory_bytes,
            memory_swap_bytes=limits.memory_swap_bytes,
            cpu_quota=limits.cpu_quota,
            pids_limit=limits.pids_limit,
        )

    def _wait_for_exit(self, container_id: str, deadline_at: float) -> tuple[Any, bool]:
        state = self.backend.inspect(container_id)
        if state is None:
            raise ExecutionBackendError(
                f"container {container_id} disappeared before exit could be confirmed",
                error_class="docker_unavailable",
            )
        timed_out = False
        while state is not None and state.running:
            if self.clock() >= deadline_at:
                timed_out = True
                break
            if self.poll_interval_seconds > 0:
                self._sleep(self.poll_interval_seconds)
            state = self.backend.inspect(container_id)
            if state is None:
                raise ExecutionBackendError(
                    f"container {container_id} disappeared while waiting for exit",
                    error_class="docker_unavailable",
                )
        if timed_out:
            try:
                self.backend.stop(container_id, self.profile.timeouts.sigterm_grace_seconds)
            except Exception as error:  # noqa: BLE001 - reported as a stop failure
                raise ExecutionBackendError(
                    f"docker stop failed for {container_id}: "
                    f"{getattr(error, 'reason', None) or error}",
                    error_class="cleanup_failed",
                ) from error
            state = self.backend.inspect(container_id)
            if state is not None and state.running:
                raise ExecutionBackendError(
                    f"container {container_id} is still running after stop",
                    error_class="cleanup_failed",
                )
        return state, timed_out

    def _collect_result(
        self,
        request: ExecutionRequest,
        output_dir: Path,
        attempt_dir: Path,
        facts: dict[str, Any],
    ) -> None:
        quota_problem = self._output_quota_problem(output_dir)
        if quota_problem is not None:
            facts["validation_failure"] = quota_problem
            return
        path = output_dir / "result.json"
        try:
            file_stat = os.lstat(path)
        except FileNotFoundError:
            facts["validation_failure"] = "result_missing"
            return
        except OSError as error:
            facts["validation_failure"] = f"result_unreadable:{error}"
            return
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            facts["validation_failure"] = "result_not_regular_file"
            return
        limit = self.profile.output_limits.result_file_bytes
        if file_stat.st_size > limit:
            facts["validation_failure"] = f"result_too_large:{file_stat.st_size}>{limit}"
            return
        try:
            raw = path.read_bytes()
        except OSError as error:
            facts["validation_failure"] = f"result_unreadable:{error}"
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            facts["validation_failure"] = "result_invalid_json"
            return
        if not isinstance(payload, dict):
            facts["validation_failure"] = "result_not_object"
            return
        for field_name in ("sample_id", "attempt_id", "stage"):
            if payload.get(field_name) != getattr(request, field_name):
                facts["validation_failure"] = f"result_identity_mismatch:{field_name}"
                return
        declared_schema = payload.get("result_schema")
        if declared_schema is None:
            facts["validation_failure"] = "result_schema_missing"
            return
        if declared_schema != request.result_schema:
            facts["validation_failure"] = f"result_schema_mismatch:{declared_schema}"
            return
        if payload.get("nonce") != facts.get("nonce"):
            facts["validation_failure"] = "result_nonce_mismatch"
            return
        declared = payload.get("result_sha256")
        if declared is not None:
            body = {key: value for key, value in payload.items() if key != "result_sha256"}
            expected = sha256_bytes(canonical_json_bytes(body))
            if declared != expected:
                facts["validation_failure"] = "result_hash_mismatch"
                return
        try:
            write_bytes_atomic(attempt_dir / "result.json", raw)
        except OSError as error:
            facts["validation_failure"] = f"result_archive_failed:{error}"
            return
        facts["result_valid"] = True
        facts["result_ref"] = "result.json"
        facts["result_sha256"] = sha256_bytes(raw)

    def _archive_output(
        self, output_dir: Path, attempt_dir: Path, facts: dict[str, Any]
    ) -> None:
        """Copy validated output artifacts to persistent storage.

        The per-run output area lives on a temporary tmpfs; every regular file
        (except the primary ``result.json``) is archived under the attempt
        directory before the caller releases the tmpfs.  Symlinks and
        non-regular files are skipped as part of the collection boundary check.
        """

        artifacts_dir = attempt_dir / "artifacts"
        single_limit = self.profile.output_limits.single_file_bytes
        total_limit = self.profile.output_limits.total_artifact_bytes
        total = 0
        attachments: list[str] = []
        for root, _dirs, files in os.walk(output_dir):
            for name in sorted(files):
                source = Path(root) / name
                if source.parent == output_dir and name == "result.json":
                    continue
                try:
                    file_stat = os.lstat(source)
                except OSError:
                    continue
                if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
                    continue
                if file_stat.st_size > single_limit:
                    continue
                total += file_stat.st_size
                if total > total_limit:
                    break
                relative = source.relative_to(output_dir)
                destination = artifacts_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copyfile(source, destination)
                except OSError:
                    continue
                attachments.append(relative.as_posix())
        facts["attachments"] = sorted(attachments)

    def _output_quota_problem(self, output_dir: Path) -> str | None:
        """Reject symlinks/non-regular files and enforce storage quotas.

        The per-attempt output directory is the only writable host bind mount;
        bounding it here keeps a candidate from escaping its storage budget even
        when it never writes a valid result.
        """

        single_limit = self.profile.output_limits.single_file_bytes
        total_limit = self.profile.output_limits.total_artifact_bytes
        max_files = self.profile.output_tmpfs.max_files if self.profile.output_tmpfs else None
        total = 0
        file_count = 0
        stack = [output_dir]
        while stack:
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError as error:
                return f"output_unreadable:{error}"
            for entry in entries:
                if entry.is_symlink():
                    return f"output_symlink_rejected:{entry.name}"
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    return f"output_not_regular_file:{entry.name}"
                file_count += 1
                if max_files is not None and file_count > max_files:
                    return f"output_file_count_exceeded:{file_count}>{max_files}"
                size = entry.stat(follow_symlinks=False).st_size
                if size > single_limit:
                    return f"output_file_too_large:{entry.name}:{size}>{single_limit}"
                total += size
                if total > total_limit:
                    return f"output_total_too_large:{total}>{total_limit}"
        return None

    def _collect_logs(
        self, container_id: str | None, attempt_dir: Path, facts: dict[str, Any]
    ) -> None:
        if not container_id:
            return
        try:
            logs = self.backend.logs(
                container_id,
                self.profile.output_limits.stdout_bytes,
                self.profile.output_limits.stderr_bytes,
            )
        except Exception as error:  # noqa: BLE001 - logs are best effort
            facts["reclaim_note"] = f"logs_unavailable:{error}"
            return
        try:
            write_bytes_atomic(attempt_dir / "stdout.log", logs.stdout.encode("utf-8"))
            write_bytes_atomic(attempt_dir / "stderr.log", logs.stderr.encode("utf-8"))
        except OSError as error:
            facts["reclaim_note"] = f"log_write_failed:{error}"
            return
        facts["stdout_ref"] = "stdout.log"
        facts["stderr_ref"] = "stderr.log"
        facts["stdout_truncated"] = bool(logs.stdout_truncated)
        facts["stderr_truncated"] = bool(logs.stderr_truncated)
        facts["output_truncated"] = bool(logs.stdout_truncated or logs.stderr_truncated)

    def _cleanup(self, container_id: str | None, facts: dict[str, Any]) -> None:
        facts["phase"] = "cleanup"
        if not container_id:
            facts["cleanup_complete"] = True
            return
        try:
            self.backend.remove(container_id, force=True)
        except Exception as error:  # noqa: BLE001
            facts["cleanup_complete"] = False
            facts["still_needs_reclaim"] = [container_id]
            cleanup_class = getattr(error, "error_class", None) or "cleanup_failed"
            if cleanup_class not in ERROR_CLASSES:
                cleanup_class = "cleanup_failed"
            facts["cleanup_failure"] = (
                cleanup_class,
                getattr(error, "reason", None) or str(error),
            )
            return
        try:
            remaining = self.backend.inspect(container_id)
        except Exception as error:  # noqa: BLE001
            facts["cleanup_complete"] = False
            facts["still_needs_reclaim"] = [container_id]
            facts["reclaim_note"] = f"cleanup_confirm_failed:{error}"
            facts["cleanup_failure"] = ("cleanup_failed", f"cleanup_confirm_failed:{error}")
            return
        if remaining is None:
            facts["cleanup_complete"] = True
            facts["still_needs_reclaim"] = []
        else:
            facts["cleanup_complete"] = False
            facts["still_needs_reclaim"] = [container_id]
            facts["cleanup_failure"] = (
                "cleanup_failed",
                f"container still present after remove: {container_id}",
            )

    def _confirm_removed(self, container_id: str) -> bool:
        try:
            return self.backend.inspect(container_id) is None
        except Exception:  # noqa: BLE001
            return False

    def _apply_error(self, facts: dict[str, Any], error: Exception) -> dict[str, Any]:
        if facts["error_class"] != "none":
            if facts["error_reason"] is None:
                facts["error_reason"] = getattr(error, "reason", None) or str(error)
            return facts
        error_class = getattr(error, "error_class", None)
        if error_class is None or error_class not in ERROR_CLASSES:
            error_class = _PHASE_ERROR_CLASS.get(facts["phase"], "config_rejected")
        facts["error_class"] = error_class
        facts["error_reason"] = getattr(error, "reason", None) or str(error)
        if error_class in ("docker_unavailable", "image_unavailable"):
            facts["available"] = False
        if facts["container_id"] is not None and not facts["cleanup_complete"]:
            container_id = facts["container_id"]
            if container_id not in facts["still_needs_reclaim"]:
                facts["still_needs_reclaim"] = [*facts["still_needs_reclaim"], container_id]
        return facts

    def _compose_result(
        self,
        request: ExecutionRequest,
        facts: dict[str, Any],
        started_at: str,
        start_monotonic: float,
    ) -> ExecutionResult:
        error_class = facts["error_class"]
        error_reason = facts["error_reason"]
        if error_class == "none":
            validation_failure = facts.get("validation_failure") or ""
            if validation_failure.startswith("output_"):
                error_class = "limit_exceeded"
            elif not facts["result_valid"]:
                error_class = "result_corrupt"
            elif facts["cleanup_failure"] is not None:
                error_class = facts["cleanup_failure"][0]
                if error_reason is None:
                    error_reason = facts["cleanup_failure"][1]
            elif facts["timed_out"]:
                error_class = "timeout"
            elif facts["oom_killed"]:
                error_class = "limit_exceeded"
        return ExecutionResult(
            sample_id=request.sample_id,
            attempt_id=request.attempt_id,
            stage=request.stage,
            request_hash=request.fingerprint(),
            container_id=facts["container_id"],
            image_reference=self.profile.image.reference,
            image_id=facts["image_id"],
            execution_profile_hash=self.profile.fingerprint(),
            supervisor_version=self.supervisor_version,
            harness_version=request.harness_version,
            started_at=started_at,
            finished_at=_utc_now(),
            duration_seconds=max(0.0, self.clock() - start_monotonic),
            exit_code=facts["exit_code"],
            timed_out=facts["timed_out"],
            oom_killed=facts["oom_killed"],
            output_truncated=facts["output_truncated"],
            signals=tuple(facts["signals"]),
            reclaim_note=facts["reclaim_note"],
            result_valid=facts["result_valid"],
            result_ref=facts["result_ref"],
            result_sha256=facts["result_sha256"],
            attachments=tuple(facts["attachments"]),
            validation_failure=facts["validation_failure"],
            available=facts["available"],
            error_class=error_class,
            error_reason=error_reason,
            cleanup_complete=facts["cleanup_complete"],
            stdout_ref=facts["stdout_ref"],
            stderr_ref=facts["stderr_ref"],
            stdout_truncated=facts["stdout_truncated"],
            stderr_truncated=facts["stderr_truncated"],
            still_needs_reclaim=tuple(facts["still_needs_reclaim"]),
            retry_of_attempt=facts["retry_of_attempt"],
        )

    def _write_manifest(self, target: Path | None = None) -> None:
        target = target or self.run_dir
        attempts_dir = target / "attempts"
        names = sorted(
            entry.name for entry in attempts_dir.iterdir() if entry.is_dir()
        ) if attempts_dir.is_dir() else []
        write_json_atomic(
            target / "manifest.json",
            {
                "run_id": target.name or "run",
                "profile_id": self.profile.profile_id,
                "profile_hash": self.profile.fingerprint(),
                "supervisor_version": self.supervisor_version,
                "attempts": names,
            },
        )


def _tmpfs_specs(
    tmpfs_paths: tuple[str, ...], workspace_bytes: int, shm_bytes: int
) -> tuple[TmpfsSpec, ...]:
    specs: list[TmpfsSpec] = []
    for path in tmpfs_paths:
        size = shm_bytes if path == "/dev/shm" else workspace_bytes
        mode = "1777" if path in ("/tmp", "/dev/shm") else "0755"
        specs.append(
            TmpfsSpec(target=path, size_bytes=size, mode=mode, options=("rw", "nosuid", "nodev"))
        )
    return tuple(specs)


def _with_cleanup(result: ExecutionResult, cleaned: bool, container_id: str | None) -> ExecutionResult:
    if cleaned:
        if result.cleanup_complete and not result.still_needs_reclaim:
            return result
        error_class = result.error_class
        if error_class == "cleanup_failed":
            if not result.result_valid:
                error_class = "result_corrupt"
            elif result.timed_out:
                error_class = "timeout"
            elif result.oom_killed:
                error_class = "limit_exceeded"
            else:
                error_class = "none"
        return replace(
            result,
            cleanup_complete=True,
            still_needs_reclaim=(),
            error_class=error_class,
        )
    still = result.still_needs_reclaim
    if container_id is not None and container_id not in still:
        still = still + (container_id,)
    error_class = result.error_class
    if error_class not in ("result_corrupt", "timeout", "limit_exceeded"):
        error_class = "cleanup_failed"
    return replace(
        result,
        cleanup_complete=False,
        still_needs_reclaim=still,
        error_class=error_class,
    )
