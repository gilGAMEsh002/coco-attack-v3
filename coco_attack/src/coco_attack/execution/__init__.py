"""Docker execution-isolation service (phase 02, task 01).

The package is intentionally free of DSPy and optimiser imports.  It exposes
the immutable contracts, the Docker control client and the host-side
supervisor used to run fixed probes (and, later, functional harnesses) inside a
locked-down container.
"""

from __future__ import annotations

from .contracts import (
    AVAILABILITY,
    ERROR_CLASSES,
    EVALUATION_LAYERS,
    PURPOSES,
    STAGES,
    ContainerSpec,
    ContainerState,
    EntrySpec,
    ExecutionBackendError,
    ExecutionConfigError,
    ExecutionError,
    ExecutionProfile,
    ExecutionProfileError,
    ExecutionRequest,
    ExecutionResult,
    ImageIdentity,
    InputFile,
    MountSpec,
    OutputLimits,
    OutputTmpfs,
    ResourceLimits,
    SandboxConfig,
    TimeoutConfig,
    TmpfsSpec,
)
from .docker import (
    CommandResult,
    DockerBackend,
    DockerClient,
    LogResult,
    build_create_argv,
    sanitize_argv_for_log,
)
from .supervisor import ExecutionSupervisor

__all__ = [
    "AVAILABILITY",
    "ERROR_CLASSES",
    "EVALUATION_LAYERS",
    "PURPOSES",
    "STAGES",
    "CommandResult",
    "ContainerSpec",
    "ContainerState",
    "DockerBackend",
    "DockerClient",
    "EntrySpec",
    "ExecutionBackendError",
    "ExecutionConfigError",
    "ExecutionError",
    "ExecutionProfile",
    "ExecutionProfileError",
    "ExecutionRequest",
    "ExecutionResult",
    "ExecutionSupervisor",
    "ImageIdentity",
    "InputFile",
    "LogResult",
    "MountSpec",
    "OutputLimits",
    "OutputTmpfs",
    "ResourceLimits",
    "SandboxConfig",
    "TimeoutConfig",
    "TmpfsSpec",
    "build_create_argv",
    "sanitize_argv_for_log",
]
