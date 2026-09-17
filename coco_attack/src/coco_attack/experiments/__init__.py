"""Clean-baseline experiment orchestration (phase 03, sub-task 01).

Public API for the fixed experiment matrix, run manifest, per-unit pipeline
config generation and baseline preparation/startup checks.  This package never
calls a model or a DMX API.
"""

from __future__ import annotations

from .baseline import (
    ASSET_MANIFEST_SCHEMA_VERSION,
    BASELINE_CHECK_SCHEMA_VERSION,
    BaselineBlockedError,
    BaselineError,
    BaselineUsageError,
    check_baseline,
    collect_version_fingerprint,
    git_commit,
    git_worktree_status,
    known_limitations_for,
    parse_dotenv,
    prepare_baseline,
)
from .configgen import (
    DMX_API_BASE,
    build_pipeline_config,
    check_unit_configs,
    write_unit_configs,
)
from .manifest import (
    RUN_MANIFEST_SCHEMA_VERSION,
    UNIT_STATUSES,
    ManifestError,
    build_manifest,
    load_manifest,
    update_unit_status,
    validate_manifest,
    write_manifest,
    write_manifest_atomic,
)
from .matrix import (
    BASELINE_COMBINATIONS,
    CLEAN_FORMS,
    EXPECTED_TASK_COUNTS,
    MATRIX_SCHEMA_VERSION,
    SAMPLING_CONFIGS,
    MatrixConfig,
    MatrixError,
    MatrixUsageError,
    RunEntry,
    RunUnit,
    expand_units,
    load_matrix_config,
)
from .orchestrate import (
    ORCHESTRATOR_LOG,
    STATUS_SCHEMA_VERSION,
    STATUS_SNAPSHOT,
    append_orchestrator_log,
    run_baseline,
    status_baseline,
)

__all__ = [
    "ASSET_MANIFEST_SCHEMA_VERSION",
    "BASELINE_CHECK_SCHEMA_VERSION",
    "BASELINE_COMBINATIONS",
    "CLEAN_FORMS",
    "DMX_API_BASE",
    "EXPECTED_TASK_COUNTS",
    "MATRIX_SCHEMA_VERSION",
    "ORCHESTRATOR_LOG",
    "RUN_MANIFEST_SCHEMA_VERSION",
    "SAMPLING_CONFIGS",
    "STATUS_SCHEMA_VERSION",
    "STATUS_SNAPSHOT",
    "UNIT_STATUSES",
    "BaselineBlockedError",
    "BaselineError",
    "BaselineUsageError",
    "ManifestError",
    "MatrixConfig",
    "MatrixError",
    "MatrixUsageError",
    "RunEntry",
    "RunUnit",
    "append_orchestrator_log",
    "build_manifest",
    "build_pipeline_config",
    "check_baseline",
    "check_unit_configs",
    "collect_version_fingerprint",
    "expand_units",
    "git_commit",
    "git_worktree_status",
    "known_limitations_for",
    "load_manifest",
    "load_matrix_config",
    "parse_dotenv",
    "prepare_baseline",
    "run_baseline",
    "status_baseline",
    "update_unit_status",
    "validate_manifest",
    "write_manifest",
    "write_manifest_atomic",
    "write_unit_configs",
]
