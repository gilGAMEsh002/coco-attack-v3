"""Data contracts for the Docker execution-isolation service (task 01).

This module is deliberately side-effect free: it only defines immutable records,
their validation and JSON round-tripping.  Anything that touches the file
system or spawns a process lives in :mod:`coco_attack.execution.docker` or
:mod:`coco_attack.execution.supervisor`.

Only the standard library, :mod:`coco_attack.assets.artifacts` and
:mod:`coco_attack.protocol.stages` may be imported here (never DSPy).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from ..assets.artifacts import canonical_json_bytes, sha256_bytes
from ..protocol.stages import Stage

# --------------------------------------------------------------------------- #
# String enums (plain strings so JSON stays simple)
# --------------------------------------------------------------------------- #

ERROR_CLASSES = (
    "none",
    "config_rejected",
    "docker_unavailable",
    "image_unavailable",
    "create_failed",
    "start_failed",
    "limit_exceeded",
    "result_corrupt",
    "timeout",
    "cleanup_failed",
)

AVAILABILITY = ("available", "unavailable", "unknown")

PURPOSES = ("evaluation", "isolation_probe")

STAGES = tuple(stage.value for stage in Stage)  # ("search", "holdout")

# Execution layers accepted in *this* service.  The design says the request
# ``evaluation_layer`` is a subset of the project evaluation layers and that
# this sub-task uses ``"functional"`` or ``"probe"``; ``probe`` is not part of
# the phase-01 evaluator layer list, so it is declared explicitly here.
EVALUATION_LAYERS = (
    "static",
    "sast",
    "judge",
    "functional",
    "dynamic",
    "realism",
    "probe",
)

INPUT_FILE_KINDS = ("code", "tests", "fixture", "request")

# ``stage/batch_id/combination_id/task_id/repeat_id/prompt_version/candidate_hash``
# are the seven rollout identity fields; ``sample_id``/``attempt_id`` are the
# execution identity.  All nine must be present.
ROLLOUT_IDENTITY_FIELDS = (
    "stage",
    "batch_id",
    "combination_id",
    "task_id",
    "repeat_id",
    "prompt_version",
    "candidate_hash",
)
EXECUTION_IDENTITY_FIELDS = ("sample_id", "attempt_id")

INPUT_NAME_RE = re.compile(r"^(?!\.\.?$)[A-Za-z0-9._-]{1,128}$")
ENTRY_ARG_RE = re.compile(r"^[A-Za-z0-9._:=/-]{1,256}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

MAX_ENTRY_ARGS = 16


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #


class ExecutionError(Exception):
    """Base class for execution-service failures.

    ``reason`` is always a human-readable string; ``error_class`` is one of
    :data:`ERROR_CLASSES` (or ``None`` when the backend does not classify it).
    """

    def __init__(self, reason: str, *, error_class: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.error_class = error_class


class ExecutionConfigError(ExecutionError):
    """Invalid configuration, profile or request (no infrastructure implied)."""

    def __init__(self, reason: str, *, error_class: str = "config_rejected") -> None:
        super().__init__(reason, error_class=error_class)


class ExecutionProfileError(ExecutionConfigError):
    """A profile (or one of its nested records) failed strict parsing."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, error_class="config_rejected")


class ExecutionBackendError(ExecutionError):
    """Docker/daemon/infrastructure failure while controlling a container."""

    def __init__(self, reason: str, *, error_class: str | None = None) -> None:
        super().__init__(reason, error_class=error_class)


# --------------------------------------------------------------------------- #
# Small validation helpers
# --------------------------------------------------------------------------- #


def _require_mapping(value: Any, where: str, error_cls: type[ExecutionError]) -> dict:
    if not isinstance(value, dict):
        raise error_cls(f"{where} must be a JSON object, got {type(value).__name__}")
    return value


def _require_fields(
    payload: dict, required: tuple[str, ...], where: str, error_cls: type[ExecutionError]
) -> None:
    missing = [name for name in required if name not in payload]
    if missing:
        raise error_cls(f"{where} is missing required fields: {missing}")


def _reject_unknown(
    payload: dict, allowed: tuple[str, ...], where: str, error_cls: type[ExecutionError]
) -> None:
    unknown = sorted(set(payload) - set(allowed))
    if unknown:
        raise error_cls(f"{where} has unknown fields: {unknown}")


def _parse_str(
    value: Any,
    where: str,
    error_cls: type[ExecutionError],
    *,
    allow_none: bool = False,
) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str):
        raise error_cls(f"{where} must be a string, got {type(value).__name__}")
    return value


def _parse_bool(value: Any, where: str, error_cls: type[ExecutionError]) -> bool:
    if not isinstance(value, bool):
        raise error_cls(f"{where} must be a boolean, got {type(value).__name__}")
    return value


def _parse_int(value: Any, where: str, error_cls: type[ExecutionError]) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise error_cls(f"{where} must be an integer, got {type(value).__name__}")
    return value


def _parse_number(value: Any, where: str, error_cls: type[ExecutionError]) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_cls(f"{where} must be a number, got {type(value).__name__}")
    return float(value)


def _parse_str_tuple(value: Any, where: str, error_cls: type[ExecutionError]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise error_cls(f"{where} must be an array of strings, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, str):
            raise error_cls(f"{where} entries must be strings, got {type(item).__name__}")
    return tuple(value)


def _positive_int(value: Any, where: str, error_cls: type[ExecutionError]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise error_cls(f"{where} must be a positive integer, got {value!r}")
    return value


def _non_negative_int(value: Any, where: str, error_cls: type[ExecutionError]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise error_cls(f"{where} must be a non-negative integer, got {value!r}")
    return value


def _positive_number(value: Any, where: str, error_cls: type[ExecutionError]) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise error_cls(f"{where} must be a positive finite number, got {value!r}")
    return float(value)


def _non_empty_str(
    value: Any, where: str, error_cls: type[ExecutionError] = ExecutionProfileError
) -> str:
    if not isinstance(value, str) or not value:
        raise error_cls(f"{where} must be a non-empty string, got {value!r}")
    return value


# --------------------------------------------------------------------------- #
# ImageIdentity
# --------------------------------------------------------------------------- #

_IMAGE_REQUIRED = (
    "reference",
    "base_image",
    "base_digest",
    "platform",
    "python_version",
    "dependency_lock_path",
    "dependency_lock_sha256",
)
_IMAGE_OPTIONAL = ("repo_digest", "image_id")


@dataclass(frozen=True)
class ImageIdentity:
    reference: str
    base_image: str
    base_digest: str
    platform: str
    python_version: str
    dependency_lock_path: str
    dependency_lock_sha256: str
    repo_digest: str | None = None
    image_id: str | None = None

    def __post_init__(self) -> None:
        _non_empty_str(self.reference, "image.reference")
        if self.reference.startswith("-") or any(ch.isspace() for ch in self.reference):
            raise ExecutionProfileError(
                f"image.reference must be a valid image reference, got {self.reference!r}"
            )
        _non_empty_str(self.base_image, "image.base_image")
        _non_empty_str(self.base_digest, "image.base_digest")
        _non_empty_str(self.platform, "image.platform")
        _non_empty_str(self.python_version, "image.python_version")
        _non_empty_str(self.dependency_lock_path, "image.dependency_lock_path")
        _non_empty_str(self.dependency_lock_sha256, "image.dependency_lock_sha256")
        if not (self.repo_digest or self.image_id):
            raise ExecutionProfileError(
                "image identity requires at least one of repo_digest or image_id"
            )
        if self.repo_digest is not None:
            _non_empty_str(self.repo_digest, "image.repo_digest")
        if self.image_id is not None:
            if not isinstance(self.image_id, str) or not IMAGE_ID_RE.match(self.image_id):
                raise ExecutionProfileError(
                    f"image.image_id must match 'sha256:<64 hex>', got {self.image_id!r}"
                )

    def to_json(self) -> dict[str, Any]:
        return {
            "reference": self.reference,
            "repo_digest": self.repo_digest,
            "image_id": self.image_id,
            "base_image": self.base_image,
            "base_digest": self.base_digest,
            "platform": self.platform,
            "python_version": self.python_version,
            "dependency_lock_path": self.dependency_lock_path,
            "dependency_lock_sha256": self.dependency_lock_sha256,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ImageIdentity":
        payload = _require_mapping(payload, "image", ExecutionProfileError)
        _require_fields(payload, _IMAGE_REQUIRED, "image", ExecutionProfileError)
        _reject_unknown(payload, _IMAGE_REQUIRED + _IMAGE_OPTIONAL, "image", ExecutionProfileError)
        return cls(
            reference=_parse_str(payload["reference"], "image.reference", ExecutionProfileError),
            base_image=_parse_str(payload["base_image"], "image.base_image", ExecutionProfileError),
            base_digest=_parse_str(payload["base_digest"], "image.base_digest", ExecutionProfileError),
            platform=_parse_str(payload["platform"], "image.platform", ExecutionProfileError),
            python_version=_parse_str(
                payload["python_version"], "image.python_version", ExecutionProfileError
            ),
            dependency_lock_path=_parse_str(
                payload["dependency_lock_path"], "image.dependency_lock_path", ExecutionProfileError
            ),
            dependency_lock_sha256=_parse_str(
                payload["dependency_lock_sha256"],
                "image.dependency_lock_sha256",
                ExecutionProfileError,
            ),
            repo_digest=_parse_str(
                payload.get("repo_digest"), "image.repo_digest", ExecutionProfileError, allow_none=True
            ),
            image_id=_parse_str(
                payload.get("image_id"), "image.image_id", ExecutionProfileError, allow_none=True
            ),
        )


# --------------------------------------------------------------------------- #
# ResourceLimits
# --------------------------------------------------------------------------- #

_LIMIT_INTS = (
    "memory_bytes",
    "memory_swap_bytes",
    "pids_limit",
    "max_parallel_containers",
    "workspace_bytes",
    "shm_bytes",
    "output_storage_bytes",
)
_LIMIT_FIELDS = _LIMIT_INTS + ("cpu_quota",)


@dataclass(frozen=True)
class ResourceLimits:
    memory_bytes: int
    memory_swap_bytes: int
    cpu_quota: float
    pids_limit: int
    max_parallel_containers: int
    workspace_bytes: int
    shm_bytes: int
    output_storage_bytes: int

    def __post_init__(self) -> None:
        for name in _LIMIT_INTS:
            _positive_int(getattr(self, name), f"limits.{name}", ExecutionProfileError)
        _positive_number(self.cpu_quota, "limits.cpu_quota", ExecutionProfileError)
        if self.memory_swap_bytes < self.memory_bytes:
            raise ExecutionProfileError(
                "limits.memory_swap_bytes must be >= limits.memory_bytes "
                "(equal disables swap)"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "memory_bytes": self.memory_bytes,
            "memory_swap_bytes": self.memory_swap_bytes,
            "cpu_quota": self.cpu_quota,
            "pids_limit": self.pids_limit,
            "max_parallel_containers": self.max_parallel_containers,
            "workspace_bytes": self.workspace_bytes,
            "shm_bytes": self.shm_bytes,
            "output_storage_bytes": self.output_storage_bytes,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ResourceLimits":
        payload = _require_mapping(payload, "limits", ExecutionProfileError)
        _require_fields(payload, _LIMIT_FIELDS, "limits", ExecutionProfileError)
        _reject_unknown(payload, _LIMIT_FIELDS, "limits", ExecutionProfileError)
        return cls(
            memory_bytes=_parse_int(payload["memory_bytes"], "limits.memory_bytes", ExecutionProfileError),
            memory_swap_bytes=_parse_int(
                payload["memory_swap_bytes"], "limits.memory_swap_bytes", ExecutionProfileError
            ),
            cpu_quota=_parse_number(payload["cpu_quota"], "limits.cpu_quota", ExecutionProfileError),
            pids_limit=_parse_int(payload["pids_limit"], "limits.pids_limit", ExecutionProfileError),
            max_parallel_containers=_parse_int(
                payload["max_parallel_containers"],
                "limits.max_parallel_containers",
                ExecutionProfileError,
            ),
            workspace_bytes=_parse_int(
                payload["workspace_bytes"], "limits.workspace_bytes", ExecutionProfileError
            ),
            shm_bytes=_parse_int(payload["shm_bytes"], "limits.shm_bytes", ExecutionProfileError),
            output_storage_bytes=_parse_int(
                payload["output_storage_bytes"], "limits.output_storage_bytes", ExecutionProfileError
            ),
        )


# --------------------------------------------------------------------------- #
# TimeoutConfig
# --------------------------------------------------------------------------- #

_TIMEOUT_FIELDS = (
    "wall_clock_seconds",
    "sigterm_grace_seconds",
    "docker_control_timeout_seconds",
)


@dataclass(frozen=True)
class TimeoutConfig:
    wall_clock_seconds: float
    sigterm_grace_seconds: float
    docker_control_timeout_seconds: float

    def __post_init__(self) -> None:
        _positive_number(self.wall_clock_seconds, "timeouts.wall_clock_seconds", ExecutionProfileError)
        _positive_number(self.sigterm_grace_seconds, "timeouts.sigterm_grace_seconds", ExecutionProfileError)
        _positive_number(
            self.docker_control_timeout_seconds,
            "timeouts.docker_control_timeout_seconds",
            ExecutionProfileError,
        )
        if self.sigterm_grace_seconds >= self.wall_clock_seconds:
            raise ExecutionProfileError(
                "timeouts.sigterm_grace_seconds must be < timeouts.wall_clock_seconds"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "wall_clock_seconds": self.wall_clock_seconds,
            "sigterm_grace_seconds": self.sigterm_grace_seconds,
            "docker_control_timeout_seconds": self.docker_control_timeout_seconds,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "TimeoutConfig":
        payload = _require_mapping(payload, "timeouts", ExecutionProfileError)
        _require_fields(payload, _TIMEOUT_FIELDS, "timeouts", ExecutionProfileError)
        _reject_unknown(payload, _TIMEOUT_FIELDS, "timeouts", ExecutionProfileError)
        return cls(
            wall_clock_seconds=_parse_number(
                payload["wall_clock_seconds"], "timeouts.wall_clock_seconds", ExecutionProfileError
            ),
            sigterm_grace_seconds=_parse_number(
                payload["sigterm_grace_seconds"], "timeouts.sigterm_grace_seconds", ExecutionProfileError
            ),
            docker_control_timeout_seconds=_parse_number(
                payload["docker_control_timeout_seconds"],
                "timeouts.docker_control_timeout_seconds",
                ExecutionProfileError,
            ),
        )


# --------------------------------------------------------------------------- #
# OutputLimits
# --------------------------------------------------------------------------- #

_OUTPUT_FIELDS = (
    "stdout_bytes",
    "stderr_bytes",
    "result_file_bytes",
    "single_file_bytes",
    "total_artifact_bytes",
)


@dataclass(frozen=True)
class OutputLimits:
    stdout_bytes: int
    stderr_bytes: int
    result_file_bytes: int
    single_file_bytes: int
    total_artifact_bytes: int

    def __post_init__(self) -> None:
        for name in _OUTPUT_FIELDS:
            _positive_int(getattr(self, name), f"output_limits.{name}", ExecutionProfileError)
        if self.single_file_bytes > self.total_artifact_bytes:
            raise ExecutionProfileError(
                "output_limits.single_file_bytes must be <= total_artifact_bytes"
            )
        if self.result_file_bytes > self.single_file_bytes:
            raise ExecutionProfileError(
                "output_limits.result_file_bytes must be <= single_file_bytes"
            )

    def to_json(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _OUTPUT_FIELDS}

    @classmethod
    def from_json(cls, payload: Any) -> "OutputLimits":
        payload = _require_mapping(payload, "output_limits", ExecutionProfileError)
        _require_fields(payload, _OUTPUT_FIELDS, "output_limits", ExecutionProfileError)
        _reject_unknown(payload, _OUTPUT_FIELDS, "output_limits", ExecutionProfileError)
        return cls(
            **{
                name: _parse_int(payload[name], f"output_limits.{name}", ExecutionProfileError)
                for name in _OUTPUT_FIELDS
            }
        )


# --------------------------------------------------------------------------- #
# OutputTmpfs
# --------------------------------------------------------------------------- #

_OUTPUT_TMPFS_FIELDS = ("path", "budget_bytes", "max_files")


@dataclass(frozen=True)
class OutputTmpfs:
    """Host pre-mounted tmpfs used as the temporary per-run output area.

    The hard capacity limit is the tmpfs mount itself; ``budget_bytes`` and
    ``max_files`` are the configured slice this run may use and are validated
    against the actual mount.  Results are archived to persistent storage before
    the caller releases the tmpfs.
    """

    path: str
    budget_bytes: int
    max_files: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise ExecutionProfileError("output_tmpfs.path must be an absolute host path")
        _positive_int(self.budget_bytes, "output_tmpfs.budget_bytes", ExecutionProfileError)
        _positive_int(self.max_files, "output_tmpfs.max_files", ExecutionProfileError)

    def to_json(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _OUTPUT_TMPFS_FIELDS}

    @classmethod
    def from_json(cls, payload: Any) -> "OutputTmpfs":
        payload = _require_mapping(payload, "output_tmpfs", ExecutionProfileError)
        _require_fields(payload, _OUTPUT_TMPFS_FIELDS, "output_tmpfs", ExecutionProfileError)
        _reject_unknown(payload, _OUTPUT_TMPFS_FIELDS, "output_tmpfs", ExecutionProfileError)
        return cls(
            path=_parse_str(payload["path"], "output_tmpfs.path", ExecutionProfileError),
            budget_bytes=_parse_int(
                payload["budget_bytes"], "output_tmpfs.budget_bytes", ExecutionProfileError
            ),
            max_files=_parse_int(
                payload["max_files"], "output_tmpfs.max_files", ExecutionProfileError
            ),
        )


# --------------------------------------------------------------------------- #
# SandboxConfig
# --------------------------------------------------------------------------- #

_SANDBOX_REQUIRED = ("uid", "gid")
_SANDBOX_OPTIONAL = (
    "network",
    "read_only_rootfs",
    "cap_drop",
    "no_new_privileges",
    "allowed_env",
    "tmpfs_paths",
    "input_mount",
    "output_mount",
    "workdir",
)
_MANDATORY_TMPFS = ("/tmp", "/work", "/dev/shm")


@dataclass(frozen=True)
class SandboxConfig:
    uid: int
    gid: int
    network: str = "none"
    read_only_rootfs: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    allowed_env: tuple[str, ...] = ()
    tmpfs_paths: tuple[str, ...] = _MANDATORY_TMPFS
    input_mount: str = "/in"
    output_mount: str = "/out"
    workdir: str = "/work"

    def __post_init__(self) -> None:
        _positive_int(self.uid, "sandbox.uid", ExecutionProfileError)
        _positive_int(self.gid, "sandbox.gid", ExecutionProfileError)
        if self.network != "none":
            raise ExecutionProfileError(
                f"sandbox.network must be 'none' (got {self.network!r})"
            )
        if self.read_only_rootfs is not True:
            raise ExecutionProfileError("sandbox.read_only_rootfs must be True")
        if "ALL" not in tuple(self.cap_drop):
            raise ExecutionProfileError("sandbox.cap_drop must contain 'ALL'")
        if self.no_new_privileges is not True:
            raise ExecutionProfileError("sandbox.no_new_privileges must be True")
        for path in _MANDATORY_TMPFS:
            if path not in tuple(self.tmpfs_paths):
                raise ExecutionProfileError(f"sandbox.tmpfs_paths must contain {path!r}")
        for path in tuple(self.tmpfs_paths):
            if not isinstance(path, str) or not path.startswith("/"):
                raise ExecutionProfileError(
                    f"sandbox.tmpfs_paths entries must be absolute container paths: {path!r}"
                )
            if "," in path or ":" in path or any(ch.isspace() for ch in path):
                raise ExecutionProfileError(
                    f"sandbox.tmpfs_paths entry must not contain ',', ':' or whitespace: {path!r}"
                )
        for name in ("input_mount", "output_mount", "workdir"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith("/"):
                raise ExecutionProfileError(f"sandbox.{name} must be an absolute container path")
            if "," in value or any(ch.isspace() for ch in value):
                raise ExecutionProfileError(
                    f"sandbox.{name} must not contain ',' or whitespace: {value!r}"
                )
            if name != "workdir" and any(path == value for path in _MANDATORY_TMPFS):
                # mounts and tmpfs targets must not collide
                raise ExecutionProfileError(f"sandbox.{name} collides with a tmpfs path")

    def to_json(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "gid": self.gid,
            "network": self.network,
            "read_only_rootfs": self.read_only_rootfs,
            "cap_drop": list(self.cap_drop),
            "no_new_privileges": self.no_new_privileges,
            "allowed_env": list(self.allowed_env),
            "tmpfs_paths": list(self.tmpfs_paths),
            "input_mount": self.input_mount,
            "output_mount": self.output_mount,
            "workdir": self.workdir,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "SandboxConfig":
        payload = _require_mapping(payload, "sandbox", ExecutionProfileError)
        _require_fields(payload, _SANDBOX_REQUIRED, "sandbox", ExecutionProfileError)
        _reject_unknown(
            payload, _SANDBOX_REQUIRED + _SANDBOX_OPTIONAL, "sandbox", ExecutionProfileError
        )
        defaults = {
            "network": "none",
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "allowed_env": [],
            "tmpfs_paths": list(_MANDATORY_TMPFS),
            "input_mount": "/in",
            "output_mount": "/out",
            "workdir": "/work",
        }
        merged = {**defaults, **payload}
        return cls(
            uid=_parse_int(merged["uid"], "sandbox.uid", ExecutionProfileError),
            gid=_parse_int(merged["gid"], "sandbox.gid", ExecutionProfileError),
            network=_parse_str(merged["network"], "sandbox.network", ExecutionProfileError),
            read_only_rootfs=_parse_bool(
                merged["read_only_rootfs"], "sandbox.read_only_rootfs", ExecutionProfileError
            ),
            cap_drop=_parse_str_tuple(merged["cap_drop"], "sandbox.cap_drop", ExecutionProfileError),
            no_new_privileges=_parse_bool(
                merged["no_new_privileges"], "sandbox.no_new_privileges", ExecutionProfileError
            ),
            allowed_env=_parse_str_tuple(
                merged["allowed_env"], "sandbox.allowed_env", ExecutionProfileError
            ),
            tmpfs_paths=_parse_str_tuple(
                merged["tmpfs_paths"], "sandbox.tmpfs_paths", ExecutionProfileError
            ),
            input_mount=_parse_str(merged["input_mount"], "sandbox.input_mount", ExecutionProfileError),
            output_mount=_parse_str(
                merged["output_mount"], "sandbox.output_mount", ExecutionProfileError
            ),
            workdir=_parse_str(merged["workdir"], "sandbox.workdir", ExecutionProfileError),
        )


# --------------------------------------------------------------------------- #
# EntrySpec / ExecutionProfile
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EntrySpec:
    entry_id: str
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        _non_empty_str(self.entry_id, "entry.entry_id")
        argv = tuple(self.argv)
        if not argv:
            raise ExecutionProfileError(f"entry {self.entry_id!r} argv must not be empty")
        for item in argv:
            if not isinstance(item, str) or not item:
                raise ExecutionProfileError(f"entry {self.entry_id!r} argv items must be non-empty strings")
        object.__setattr__(self, "argv", argv)

    def to_json(self) -> dict[str, Any]:
        return {"entry_id": self.entry_id, "argv": list(self.argv)}

    @classmethod
    def from_json(cls, payload: Any) -> "EntrySpec":
        payload = _require_mapping(payload, "entry", ExecutionProfileError)
        _require_fields(payload, ("entry_id", "argv"), "entry", ExecutionProfileError)
        _reject_unknown(payload, ("entry_id", "argv"), "entry", ExecutionProfileError)
        return cls(
            entry_id=_parse_str(payload["entry_id"], "entry.entry_id", ExecutionProfileError),
            argv=_parse_str_tuple(payload["argv"], "entry.argv", ExecutionProfileError),
        )


_PROFILE_FIELDS = (
    "schema_version",
    "profile_id",
    "executor_version",
    "executor_source_sha256",
    "image",
    "limits",
    "timeouts",
    "output_limits",
    "sandbox",
    "entries",
    "output_tmpfs",
)


@dataclass(frozen=True)
class ExecutionProfile:
    schema_version: str
    profile_id: str
    executor_version: str
    executor_source_sha256: str
    image: ImageIdentity
    limits: ResourceLimits
    timeouts: TimeoutConfig
    output_limits: OutputLimits
    sandbox: SandboxConfig
    entries: tuple[EntrySpec, ...]
    output_tmpfs: OutputTmpfs | None = None

    def __post_init__(self) -> None:
        _non_empty_str(self.schema_version, "profile.schema_version")
        _non_empty_str(self.profile_id, "profile.profile_id")
        _non_empty_str(self.executor_version, "profile.executor_version")
        _non_empty_str(self.executor_source_sha256, "profile.executor_source_sha256")
        if not isinstance(self.image, ImageIdentity):
            raise ExecutionProfileError("profile.image must be an ImageIdentity")
        if not isinstance(self.limits, ResourceLimits):
            raise ExecutionProfileError("profile.limits must be a ResourceLimits")
        if not isinstance(self.timeouts, TimeoutConfig):
            raise ExecutionProfileError("profile.timeouts must be a TimeoutConfig")
        if not isinstance(self.output_limits, OutputLimits):
            raise ExecutionProfileError("profile.output_limits must be an OutputLimits")
        if not isinstance(self.sandbox, SandboxConfig):
            raise ExecutionProfileError("profile.sandbox must be a SandboxConfig")
        if self.output_tmpfs is not None and not isinstance(self.output_tmpfs, OutputTmpfs):
            raise ExecutionProfileError("profile.output_tmpfs must be an OutputTmpfs or null")
        entries = tuple(self.entries)
        for entry in entries:
            if not isinstance(entry, EntrySpec):
                raise ExecutionProfileError("profile.entries must contain EntrySpec records")
        ids = [entry.entry_id for entry in entries]
        if len(set(ids)) != len(ids):
            raise ExecutionProfileError(f"profile.entries has duplicate entry_id values: {ids}")
        object.__setattr__(self, "entries", entries)

    def allowed_entries(self) -> frozenset[str]:
        return frozenset(entry.entry_id for entry in self.entries)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "executor_version": self.executor_version,
            "executor_source_sha256": self.executor_source_sha256,
            "image": self.image.to_json(),
            "limits": self.limits.to_json(),
            "timeouts": self.timeouts.to_json(),
            "output_limits": self.output_limits.to_json(),
            "sandbox": self.sandbox.to_json(),
            "entries": [entry.to_json() for entry in self.entries],
            "output_tmpfs": self.output_tmpfs.to_json() if self.output_tmpfs else None,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ExecutionProfile":
        payload = _require_mapping(payload, "profile", ExecutionProfileError)
        _require_fields(
            payload,
            tuple(field for field in _PROFILE_FIELDS if field != "output_tmpfs"),
            "profile",
            ExecutionProfileError,
        )
        _reject_unknown(payload, _PROFILE_FIELDS, "profile", ExecutionProfileError)
        entries_payload = payload["entries"]
        if not isinstance(entries_payload, (list, tuple)):
            raise ExecutionProfileError(
                f"profile.entries must be an array, got {type(entries_payload).__name__}"
            )
        return cls(
            schema_version=_parse_str(
                payload["schema_version"], "profile.schema_version", ExecutionProfileError
            ),
            profile_id=_parse_str(payload["profile_id"], "profile.profile_id", ExecutionProfileError),
            executor_version=_parse_str(
                payload["executor_version"], "profile.executor_version", ExecutionProfileError
            ),
            executor_source_sha256=_parse_str(
                payload["executor_source_sha256"],
                "profile.executor_source_sha256",
                ExecutionProfileError,
            ),
            image=ImageIdentity.from_json(payload["image"]),
            limits=ResourceLimits.from_json(payload["limits"]),
            timeouts=TimeoutConfig.from_json(payload["timeouts"]),
            output_limits=OutputLimits.from_json(payload["output_limits"]),
            sandbox=SandboxConfig.from_json(payload["sandbox"]),
            entries=tuple(EntrySpec.from_json(item) for item in entries_payload),
            output_tmpfs=(
                OutputTmpfs.from_json(payload["output_tmpfs"])
                if payload.get("output_tmpfs") is not None
                else None
            ),
        )

    def fingerprint(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.to_json()))


# --------------------------------------------------------------------------- #
# InputFile / ExecutionRequest
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class InputFile:
    name: str
    kind: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not INPUT_NAME_RE.match(self.name):
            raise ExecutionConfigError(
                f"input file name must match {INPUT_NAME_RE.pattern!r} (no '/', no '..'), "
                f"got {self.name!r}"
            )
        if self.kind not in INPUT_FILE_KINDS:
            raise ExecutionConfigError(
                f"input file kind must be one of {INPUT_FILE_KINDS}, got {self.kind!r}"
            )
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ExecutionConfigError(
                f"input file sha256 must be 64 lowercase hex characters, got {self.sha256!r}"
            )
        _non_negative_int(self.size, f"input_files[{self.name}].size", ExecutionConfigError)

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "sha256": self.sha256, "size": self.size}

    @classmethod
    def from_json(cls, payload: Any) -> "InputFile":
        payload = _require_mapping(payload, "input_file", ExecutionConfigError)
        _require_fields(payload, ("name", "kind", "sha256", "size"), "input_file", ExecutionConfigError)
        _reject_unknown(payload, ("name", "kind", "sha256", "size"), "input_file", ExecutionConfigError)
        return cls(
            name=_parse_str(payload["name"], "input_file.name", ExecutionConfigError),
            kind=_parse_str(payload["kind"], "input_file.kind", ExecutionConfigError),
            sha256=_parse_str(payload["sha256"], "input_file.sha256", ExecutionConfigError),
            size=_parse_int(payload["size"], "input_file.size", ExecutionConfigError),
        )


_REQUEST_REQUIRED = (
    "sample_id",
    "attempt_id",
    "stage",
    "batch_id",
    "combination_id",
    "task_id",
    "repeat_id",
    "prompt_version",
    "candidate_hash",
    "evaluation_layer",
    "entry",
    "entry_args",
    "execution_profile_hash",
    "purpose",
    "input_files",
    "result_schema",
    "harness_version",
)
_REQUEST_OPTIONAL = ("probe_id",)


@dataclass(frozen=True)
class ExecutionRequest:
    sample_id: str
    attempt_id: str
    stage: str
    batch_id: str
    combination_id: str
    task_id: str
    repeat_id: int
    prompt_version: str
    candidate_hash: str
    evaluation_layer: str
    entry: str
    entry_args: tuple[str, ...]
    execution_profile_hash: str
    purpose: str
    input_files: tuple[InputFile, ...]
    result_schema: str
    harness_version: str
    probe_id: str | None = None

    def __post_init__(self) -> None:
        if self.purpose not in PURPOSES:
            raise ExecutionConfigError(f"request.purpose must be one of {PURPOSES}, got {self.purpose!r}")
        if self.evaluation_layer not in EVALUATION_LAYERS:
            raise ExecutionConfigError(
                f"request.evaluation_layer must be one of {EVALUATION_LAYERS}, "
                f"got {self.evaluation_layer!r}"
            )
        if isinstance(self.repeat_id, bool) or not isinstance(self.repeat_id, int):
            raise ExecutionConfigError(
                f"request.repeat_id must be an integer, got {type(self.repeat_id).__name__}"
            )
        if self.purpose == "isolation_probe":
            if not isinstance(self.probe_id, str) or not self.probe_id:
                raise ExecutionConfigError("request.probe_id is required when purpose='isolation_probe'")
        else:
            if self.probe_id is not None:
                raise ExecutionConfigError("request.probe_id must be None when purpose='evaluation'")
        args = tuple(self.entry_args)
        for arg in args:
            if not isinstance(arg, str):
                raise ExecutionConfigError("request.entry_args entries must be strings")
        object.__setattr__(self, "entry_args", args)
        files = tuple(self.input_files)
        for item in files:
            if not isinstance(item, InputFile):
                raise ExecutionConfigError("request.input_files must contain InputFile records")
        object.__setattr__(self, "input_files", files)

    def validate_against(self, profile: ExecutionProfile) -> None:
        if not isinstance(profile, ExecutionProfile):
            raise ExecutionConfigError("validate_against requires an ExecutionProfile")
        for name in ROLLOUT_IDENTITY_FIELDS:
            value = getattr(self, name)
            if name == "repeat_id":
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ExecutionConfigError("request.repeat_id must be an integer >= 0")
                continue
            if not isinstance(value, str) or not value:
                raise ExecutionConfigError(f"request.{name} is required and must be non-empty")
        for name in EXECUTION_IDENTITY_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ExecutionConfigError(f"request.{name} is required and must be non-empty")
        if self.stage not in STAGES:
            raise ExecutionConfigError(f"request.stage must be one of {STAGES}, got {self.stage!r}")
        if self.entry not in profile.allowed_entries():
            raise ExecutionConfigError(
                f"request.entry {self.entry!r} is not in the profile entry registry "
                f"{sorted(profile.allowed_entries())}"
            )
        if self.execution_profile_hash != profile.fingerprint():
            raise ExecutionConfigError(
                "request.execution_profile_hash does not match the supplied profile fingerprint"
            )
        if len(self.entry_args) > MAX_ENTRY_ARGS:
            raise ExecutionConfigError(
                f"request.entry_args must have at most {MAX_ENTRY_ARGS} items"
            )
        for arg in self.entry_args:
            if not ENTRY_ARG_RE.match(arg):
                raise ExecutionConfigError(f"request.entry_args item is invalid: {arg!r}")
        names = [item.name for item in self.input_files]
        if len(set(names)) != len(names):
            raise ExecutionConfigError(f"request.input_files names must be unique: {names}")

    def to_json(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "attempt_id": self.attempt_id,
            "stage": self.stage,
            "batch_id": self.batch_id,
            "combination_id": self.combination_id,
            "task_id": self.task_id,
            "repeat_id": self.repeat_id,
            "prompt_version": self.prompt_version,
            "candidate_hash": self.candidate_hash,
            "evaluation_layer": self.evaluation_layer,
            "entry": self.entry,
            "entry_args": list(self.entry_args),
            "execution_profile_hash": self.execution_profile_hash,
            "purpose": self.purpose,
            "probe_id": self.probe_id,
            "input_files": [item.to_json() for item in self.input_files],
            "result_schema": self.result_schema,
            "harness_version": self.harness_version,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ExecutionRequest":
        payload = _require_mapping(payload, "request", ExecutionConfigError)
        _require_fields(payload, _REQUEST_REQUIRED, "request", ExecutionConfigError)
        _reject_unknown(
            payload, _REQUEST_REQUIRED + _REQUEST_OPTIONAL, "request", ExecutionConfigError
        )
        files_payload = payload["input_files"]
        if not isinstance(files_payload, (list, tuple)):
            raise ExecutionConfigError("request.input_files must be an array")
        return cls(
            sample_id=_parse_str(payload["sample_id"], "request.sample_id", ExecutionConfigError),
            attempt_id=_parse_str(payload["attempt_id"], "request.attempt_id", ExecutionConfigError),
            stage=_parse_str(payload["stage"], "request.stage", ExecutionConfigError),
            batch_id=_parse_str(payload["batch_id"], "request.batch_id", ExecutionConfigError),
            combination_id=_parse_str(
                payload["combination_id"], "request.combination_id", ExecutionConfigError
            ),
            task_id=_parse_str(payload["task_id"], "request.task_id", ExecutionConfigError),
            repeat_id=_parse_int(payload["repeat_id"], "request.repeat_id", ExecutionConfigError),
            prompt_version=_parse_str(
                payload["prompt_version"], "request.prompt_version", ExecutionConfigError
            ),
            candidate_hash=_parse_str(
                payload["candidate_hash"], "request.candidate_hash", ExecutionConfigError
            ),
            evaluation_layer=_parse_str(
                payload["evaluation_layer"], "request.evaluation_layer", ExecutionConfigError
            ),
            entry=_parse_str(payload["entry"], "request.entry", ExecutionConfigError),
            entry_args=_parse_str_tuple(
                payload["entry_args"], "request.entry_args", ExecutionConfigError
            ),
            execution_profile_hash=_parse_str(
                payload["execution_profile_hash"],
                "request.execution_profile_hash",
                ExecutionConfigError,
            ),
            purpose=_parse_str(payload["purpose"], "request.purpose", ExecutionConfigError),
            probe_id=_parse_str(
                payload.get("probe_id"), "request.probe_id", ExecutionConfigError, allow_none=True
            ),
            input_files=tuple(InputFile.from_json(item) for item in files_payload),
            result_schema=_parse_str(
                payload["result_schema"], "request.result_schema", ExecutionConfigError
            ),
            harness_version=_parse_str(
                payload["harness_version"], "request.harness_version", ExecutionConfigError
            ),
        )

    def fingerprint(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.to_json()))


# --------------------------------------------------------------------------- #
# Container records
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MountSpec:
    source: str
    target: str
    read_only: bool

    def __post_init__(self) -> None:
        _non_empty_str(self.source, "mount.source", ExecutionConfigError)
        _non_empty_str(self.target, "mount.target", ExecutionConfigError)
        if not self.source.startswith("/"):
            raise ExecutionConfigError(f"mount.source must be an absolute host path: {self.source!r}")
        if not self.target.startswith("/"):
            raise ExecutionConfigError(f"mount.target must be an absolute container path: {self.target!r}")
        for label, value in (("source", self.source), ("target", self.target)):
            if "," in value or any(ch.isspace() for ch in value):
                raise ExecutionConfigError(
                    f"mount.{label} must not contain ',' or whitespace: {value!r}"
                )
        if not isinstance(self.read_only, bool):
            raise ExecutionConfigError("mount.read_only must be a boolean")


@dataclass(frozen=True)
class TmpfsSpec:
    target: str
    size_bytes: int
    mode: str
    options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _non_empty_str(self.target, "tmpfs.target", ExecutionConfigError)
        if not self.target.startswith("/"):
            raise ExecutionConfigError(f"tmpfs.target must be an absolute container path: {self.target!r}")
        if "," in self.target or ":" in self.target or any(ch.isspace() for ch in self.target):
            raise ExecutionConfigError(
                f"tmpfs.target must not contain ',', ':' or whitespace: {self.target!r}"
            )
        _positive_int(self.size_bytes, "tmpfs.size_bytes", ExecutionConfigError)
        _non_empty_str(self.mode, "tmpfs.mode", ExecutionConfigError)
        object.__setattr__(self, "options", tuple(self.options))


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    labels: dict[str, str]
    image: str
    argv: tuple[str, ...]
    mounts: tuple[MountSpec, ...]
    tmpfs: tuple[TmpfsSpec, ...]
    env: tuple[tuple[str, str], ...]
    network: str
    read_only_rootfs: bool
    cap_drop: tuple[str, ...]
    no_new_privileges: bool
    uid: int
    gid: int
    workdir: str
    memory_bytes: int
    memory_swap_bytes: int
    cpu_quota: float
    pids_limit: int
    stop_signal: str = "SIGTERM"

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", self.name):
            raise ExecutionConfigError(f"container name is not Docker-legal: {self.name!r}")
        if not isinstance(self.labels, dict):
            raise ExecutionConfigError("container labels must be a mapping")
        for key, value in self.labels.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ExecutionConfigError("container labels must map strings to strings")
        _non_empty_str(self.image, "container.image", ExecutionConfigError)
        if self.image.startswith("-") or any(ch.isspace() for ch in self.image):
            raise ExecutionConfigError(
                f"container.image is not a valid image reference: {self.image!r}"
            )
        argv = tuple(self.argv)
        if not argv or any(not isinstance(item, str) for item in argv):
            raise ExecutionConfigError("container.argv must be a non-empty tuple of strings")
        object.__setattr__(self, "argv", argv)
        if self.network != "none":
            raise ExecutionConfigError("container.network must be 'none'")
        if self.read_only_rootfs is not True:
            raise ExecutionConfigError("container.read_only_rootfs must be True")
        cap_drop = tuple(self.cap_drop)
        if "ALL" not in cap_drop:
            raise ExecutionConfigError("container.cap_drop must contain 'ALL'")
        object.__setattr__(self, "cap_drop", cap_drop)
        if self.no_new_privileges is not True:
            raise ExecutionConfigError("container.no_new_privileges must be True")
        _positive_int(self.uid, "container.uid", ExecutionConfigError)
        _positive_int(self.gid, "container.gid", ExecutionConfigError)
        _non_empty_str(self.workdir, "container.workdir", ExecutionConfigError)
        _positive_int(self.memory_bytes, "container.memory_bytes", ExecutionConfigError)
        _positive_int(self.memory_swap_bytes, "container.memory_swap_bytes", ExecutionConfigError)
        if self.memory_swap_bytes < self.memory_bytes:
            raise ExecutionConfigError("container.memory_swap_bytes must be >= memory_bytes")
        _positive_number(self.cpu_quota, "container.cpu_quota", ExecutionConfigError)
        _positive_int(self.pids_limit, "container.pids_limit", ExecutionConfigError)
        _non_empty_str(self.stop_signal, "container.stop_signal", ExecutionConfigError)


@dataclass(frozen=True)
class ContainerState:
    container_id: str
    name: str
    status: str
    running: bool
    exit_code: int | None
    oom_killed: bool
    started_at: str | None
    finished_at: str | None
    labels: dict[str, str]
    image_id: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "container_id": self.container_id,
            "name": self.name,
            "status": self.status,
            "running": self.running,
            "exit_code": self.exit_code,
            "oom_killed": self.oom_killed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "labels": dict(sorted(self.labels.items())),
            "image_id": self.image_id,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ContainerState":
        payload = _require_mapping(payload, "container_state", ExecutionConfigError)
        return cls(
            container_id=_parse_str(
                payload["container_id"], "container_state.container_id", ExecutionConfigError
            ),
            name=_parse_str(payload["name"], "container_state.name", ExecutionConfigError),
            status=_parse_str(payload["status"], "container_state.status", ExecutionConfigError),
            running=_parse_bool(payload["running"], "container_state.running", ExecutionConfigError),
            exit_code=payload.get("exit_code"),
            oom_killed=_parse_bool(
                payload.get("oom_killed", False), "container_state.oom_killed", ExecutionConfigError
            ),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            labels=payload.get("labels") or {},
            image_id=payload.get("image_id"),
        )


# --------------------------------------------------------------------------- #
# ExecutionResult
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExecutionResult:
    # Identity and version
    sample_id: str
    attempt_id: str
    stage: str
    request_hash: str
    container_id: str | None
    image_reference: str
    image_id: str | None
    execution_profile_hash: str
    supervisor_version: str
    harness_version: str
    # Execution facts
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float = 0.0
    exit_code: int | None = None
    timed_out: bool = False
    oom_killed: bool = False
    output_truncated: bool = False
    signals: tuple[str, ...] = ()
    reclaim_note: str | None = None
    # Result completeness
    result_valid: bool = False
    result_ref: str | None = None
    result_sha256: str | None = None
    attachments: tuple[str, ...] = ()
    validation_failure: str | None = None
    # Environment and error
    available: bool = True
    error_class: str = "none"
    error_reason: str | None = None
    # Cleanup
    cleanup_complete: bool = False
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    still_needs_reclaim: tuple[str, ...] = ()
    retry_of_attempt: str | None = None

    def __post_init__(self) -> None:
        if self.error_class not in ERROR_CLASSES:
            raise ExecutionConfigError(
                f"execution result error_class must be one of {ERROR_CLASSES}, got {self.error_class!r}"
            )
        object.__setattr__(self, "signals", tuple(self.signals))
        object.__setattr__(self, "attachments", tuple(self.attachments))
        object.__setattr__(self, "still_needs_reclaim", tuple(self.still_needs_reclaim))

    def ok_for_evaluation(self) -> bool:
        """Whether the upper layer may treat this record as usable evidence.

        The backend never decides functional pass/fail; this is only a
        convenience predicate over execution facts.
        """

        return (
            self.available
            and self.result_valid
            and self.cleanup_complete
            and self.error_class == "none"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "sample_id": self.sample_id,
            "attempt_id": self.attempt_id,
            "stage": self.stage,
            "request_hash": self.request_hash,
            "container_id": self.container_id,
            "image_reference": self.image_reference,
            "image_id": self.image_id,
            "execution_profile_hash": self.execution_profile_hash,
            "supervisor_version": self.supervisor_version,
            "harness_version": self.harness_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "output_truncated": self.output_truncated,
            "signals": list(self.signals),
            "reclaim_note": self.reclaim_note,
            "result_valid": self.result_valid,
            "result_ref": self.result_ref,
            "result_sha256": self.result_sha256,
            "attachments": list(self.attachments),
            "validation_failure": self.validation_failure,
            "available": self.available,
            "error_class": self.error_class,
            "error_reason": self.error_reason,
            "cleanup_complete": self.cleanup_complete,
            "stdout_ref": self.stdout_ref,
            "stderr_ref": self.stderr_ref,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "still_needs_reclaim": list(self.still_needs_reclaim),
            "retry_of_attempt": self.retry_of_attempt,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ExecutionResult":
        payload = _require_mapping(payload, "execution_result", ExecutionConfigError)
        required = (
            "sample_id",
            "attempt_id",
            "stage",
            "request_hash",
            "container_id",
            "image_reference",
            "image_id",
            "execution_profile_hash",
            "supervisor_version",
            "harness_version",
            "started_at",
            "finished_at",
            "duration_seconds",
            "exit_code",
            "timed_out",
            "oom_killed",
            "output_truncated",
            "signals",
            "reclaim_note",
            "result_valid",
            "result_ref",
            "result_sha256",
            "attachments",
            "validation_failure",
            "available",
            "error_class",
            "error_reason",
            "cleanup_complete",
            "stdout_ref",
            "stderr_ref",
            "stdout_truncated",
            "stderr_truncated",
            "still_needs_reclaim",
            "retry_of_attempt",
        )
        _require_fields(payload, required, "execution_result", ExecutionConfigError)
        return cls(
            sample_id=_parse_str(payload["sample_id"], "execution_result.sample_id", ExecutionConfigError),
            attempt_id=_parse_str(payload["attempt_id"], "execution_result.attempt_id", ExecutionConfigError),
            stage=_parse_str(payload["stage"], "execution_result.stage", ExecutionConfigError),
            request_hash=_parse_str(payload["request_hash"], "execution_result.request_hash", ExecutionConfigError),
            container_id=_parse_str(
                payload["container_id"], "execution_result.container_id", ExecutionConfigError, allow_none=True
            ),
            image_reference=_parse_str(
                payload["image_reference"], "execution_result.image_reference", ExecutionConfigError
            ),
            image_id=_parse_str(
                payload["image_id"], "execution_result.image_id", ExecutionConfigError, allow_none=True
            ),
            execution_profile_hash=_parse_str(
                payload["execution_profile_hash"],
                "execution_result.execution_profile_hash",
                ExecutionConfigError,
            ),
            supervisor_version=_parse_str(
                payload["supervisor_version"], "execution_result.supervisor_version", ExecutionConfigError
            ),
            harness_version=_parse_str(
                payload["harness_version"], "execution_result.harness_version", ExecutionConfigError
            ),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            duration_seconds=float(payload.get("duration_seconds") or 0.0),
            exit_code=payload.get("exit_code"),
            timed_out=_parse_bool(payload["timed_out"], "execution_result.timed_out", ExecutionConfigError),
            oom_killed=_parse_bool(
                payload["oom_killed"], "execution_result.oom_killed", ExecutionConfigError
            ),
            output_truncated=_parse_bool(
                payload["output_truncated"], "execution_result.output_truncated", ExecutionConfigError
            ),
            signals=_parse_str_tuple(
                payload["signals"], "execution_result.signals", ExecutionConfigError
            ),
            reclaim_note=payload.get("reclaim_note"),
            result_valid=_parse_bool(
                payload["result_valid"], "execution_result.result_valid", ExecutionConfigError
            ),
            result_ref=payload.get("result_ref"),
            result_sha256=payload.get("result_sha256"),
            attachments=_parse_str_tuple(
                payload["attachments"], "execution_result.attachments", ExecutionConfigError
            ),
            validation_failure=payload.get("validation_failure"),
            available=_parse_bool(
                payload["available"], "execution_result.available", ExecutionConfigError
            ),
            error_class=_parse_str(
                payload["error_class"], "execution_result.error_class", ExecutionConfigError
            ),
            error_reason=payload.get("error_reason"),
            cleanup_complete=_parse_bool(
                payload["cleanup_complete"], "execution_result.cleanup_complete", ExecutionConfigError
            ),
            stdout_ref=payload.get("stdout_ref"),
            stderr_ref=payload.get("stderr_ref"),
            stdout_truncated=_parse_bool(
                payload["stdout_truncated"],
                "execution_result.stdout_truncated",
                ExecutionConfigError,
            ),
            stderr_truncated=_parse_bool(
                payload["stderr_truncated"],
                "execution_result.stderr_truncated",
                ExecutionConfigError,
            ),
            still_needs_reclaim=_parse_str_tuple(
                payload["still_needs_reclaim"],
                "execution_result.still_needs_reclaim",
                ExecutionConfigError,
            ),
            retry_of_attempt=payload.get("retry_of_attempt"),
        )


__all__ = [
    "ERROR_CLASSES",
    "AVAILABILITY",
    "PURPOSES",
    "STAGES",
    "EVALUATION_LAYERS",
    "INPUT_FILE_KINDS",
    "ROLLOUT_IDENTITY_FIELDS",
    "EXECUTION_IDENTITY_FIELDS",
    "ExecutionError",
    "ExecutionConfigError",
    "ExecutionProfileError",
    "ExecutionBackendError",
    "ImageIdentity",
    "ResourceLimits",
    "TimeoutConfig",
    "OutputLimits",
    "SandboxConfig",
    "EntrySpec",
    "ExecutionProfile",
    "InputFile",
    "ExecutionRequest",
    "MountSpec",
    "TmpfsSpec",
    "ContainerSpec",
    "ContainerState",
    "ExecutionResult",
]
