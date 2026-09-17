"""Host-side preflight and isolation evidence for the Docker execution service.

Three trusted-operator commands share this module:

* ``check-execution`` — verify Docker, the pinned image, the dependency lock and
  the resource/storage preconditions, and record the machine-readable inventory;
* ``verify-isolation`` — run the fixed, human-written probes through the same
  production backend and write AC-01 evidence;
* ``recover-executions`` — reconcile leftover containers owned by an existing
  run without touching anything else.

All three accept an injectable backend so the orchestration can be tested
without a Docker daemon.  When Docker is unavailable the commands fail loudly
with an explicit blocker; they never fall back to running generated code
directly on the host.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Sequence

from ..assets.artifacts import (
    canonical_json_bytes,
    iter_jsonl,
    read_json,
    sha256_bytes,
    sha256_file,
    sha256_text,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.paths import default_config_dir
from .contracts import (
    ExecutionConfigError,
    ExecutionProfile,
    ExecutionRequest,
    ExecutionResult,
    ImageIdentity,
)
from .docker import DockerBackend, DockerClient
from .supervisor import ExecutionSupervisor, RunLock

PREFLIGHT_SCHEMA_VERSION = "1"
CHECK_EXECUTION = "check-execution"
VERIFY_ISOLATION = "verify-isolation"
RECOVER_EXECUTIONS = "recover-executions"

ZERO_SHA256 = "0" * 64
ZERO_IMAGE_ID = "sha256:" + ZERO_SHA256

EXECUTOR_SOURCE_FILES = ("contracts.py", "docker.py", "supervisor.py", "preflight.py")

# Import name -> PyPI distribution, for the dependency inventory.  Only
# non-identity mappings are listed; identity mappings fall back to the import
# name itself.  ``cgi`` maps to ``legacy-cgi`` because the stdlib module was
# removed in Python 3.13.
DISTRIBUTION_MAP = {
    "bs4": "beautifulsoup4",
    "PIL": "Pillow",
    "flask": "Flask",
    "flask_restful": "Flask-RESTful",
    "sklearn": "scikit-learn",
    "cgi": "legacy-cgi",
    "requests_mock": "requests-mock",
}

SDIST_ONLY = ("tempdir", "wget")


# --------------------------------------------------------------------------- #
# Probe registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProbeSpec:
    probe_id: str
    description: str
    entry: str
    entry_args: tuple[str, ...]
    expectation: str
    requires_sentinel: bool = False


PROBE_REGISTRY: tuple[ProbeSpec, ...] = (
    ProbeSpec(
        "identity",
        "non-root uid/gid, dropped capabilities, read-only rootfs, writable /out",
        "probe",
        ("--probe", "identity", "--payload", "/out/payload.json"),
        "result_valid",
    ),
    ProbeSpec(
        "host_access",
        "host sentinel/traversal/credential/docker-socket access is denied",
        "probe",
        ("--probe", "host_access", "--payload", "/out/payload.json", "--sentinel", "__SENTINEL__"),
        "result_valid",
        requires_sentinel=True,
    ),
    ProbeSpec(
        "network",
        "external network and DNS are unreachable; loopback works",
        "probe",
        ("--probe", "network", "--payload", "/out/payload.json"),
        "result_valid",
    ),
    ProbeSpec(
        "resources",
        "cgroup limits and bounded tmpfs are visible inside the container",
        "probe",
        ("--probe", "resources", "--payload", "/out/payload.json"),
        "result_valid",
    ),
    ProbeSpec(
        "hang_after_result",
        "a complete result survives a process that ignores SIGTERM",
        "probe",
        ("--probe", "hang_after_result", "--payload", "/out/payload.json"),
        "result_valid_and_timed_out",
    ),
    ProbeSpec(
        "hang_ignoring_sigterm",
        "SIGTERM-ignoring process with a new-session descendant is reclaimed",
        "probe",
        ("--probe", "hang_ignoring_sigterm", "--payload", "/out/payload.json"),
        "timed_out_and_cleaned",
    ),
    ProbeSpec(
        "partial_payload",
        "a half-written payload is rejected while the envelope stays valid",
        "probe",
        ("--probe", "partial_payload", "--payload", "/out/payload.json"),
        "payload_invalid",
    ),
    ProbeSpec(
        "wrong_identity",
        "a forged result identity is rejected by the host",
        "probe_raw",
        ("--probe", "wrong_identity"),
        "identity_rejected",
    ),
)

EXPECTATIONS = (
    "result_valid",
    "result_valid_and_timed_out",
    "timed_out_and_cleaned",
    "payload_invalid",
    "identity_rejected",
)


# --------------------------------------------------------------------------- #
# Profile loading / placeholder resolution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LoadedProfile:
    profile: ExecutionProfile
    config_path: Path
    config_sha256: str
    project_root: Path
    resolved: dict[str, bool]
    warnings: tuple[str, ...] = ()


def _is_zero_sha256(value: str | None) -> bool:
    return value is None or value == ZERO_SHA256


def _is_zero_image_id(value: str | None) -> bool:
    return value is None or value == ZERO_IMAGE_ID


def _project_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return Path(explicit).resolve()
    return default_config_dir().parent


def executor_source_sha256(project_root: Path) -> str:
    root = Path(project_root) / "src" / "coco_attack" / "execution"
    entries: list[list[str]] = []
    for name in EXECUTOR_SOURCE_FILES:
        path = root / name
        if not path.is_file():
            raise ExecutionConfigError(f"executor source missing: {path}")
        entries.append([name, sha256_file(path)])
    return sha256_bytes(canonical_json_bytes(entries))


def load_profile(
    config_path: Path | str, *, project_root: Path | str | None = None
) -> LoadedProfile:
    path = Path(config_path).expanduser().resolve()
    if not path.is_file():
        raise ExecutionConfigError(f"execution config is not a file: {path}")
    profile = ExecutionProfile.from_json(read_json(path))
    root = _project_root(Path(project_root) if project_root is not None else None)

    resolved = {"image_id": True, "dependency_lock": True, "executor_source": True}
    warnings: list[str] = []
    image = profile.image

    if _is_zero_image_id(image.image_id):
        resolved["image_id"] = False
    if image.repo_digest is None and _is_zero_image_id(image.image_id):
        resolved["image_id"] = False

    lock_path = (root / image.dependency_lock_path).resolve()
    if not lock_path.is_file():
        raise ExecutionConfigError(f"dependency lock file missing: {lock_path}")
    actual_lock = sha256_file(lock_path)
    if _is_zero_sha256(image.dependency_lock_sha256):
        resolved["dependency_lock"] = False
        image = replace(image, dependency_lock_sha256=actual_lock)
    elif image.dependency_lock_sha256 != actual_lock:
        raise ExecutionConfigError(
            "image.dependency_lock_sha256 does not match the actual lock file "
            f"({image.dependency_lock_sha256} != {actual_lock})"
        )

    actual_executor = executor_source_sha256(root)
    if _is_zero_sha256(profile.executor_source_sha256):
        resolved["executor_source"] = False
        profile = replace(profile, executor_source_sha256=actual_executor)
    elif profile.executor_source_sha256 != actual_executor:
        raise ExecutionConfigError(
            "executor_source_sha256 does not match the actual execution sources "
            f"({profile.executor_source_sha256} != {actual_executor})"
        )

    profile = replace(profile, image=image)
    return LoadedProfile(
        profile=profile,
        config_path=path,
        config_sha256=sha256_file(path),
        project_root=root,
        resolved=resolved,
        warnings=tuple(warnings),
    )


# --------------------------------------------------------------------------- #
# Dependency inventory
# --------------------------------------------------------------------------- #


def _distribution_for(import_name: str, known_distributions: set[str]) -> str | None:
    if import_name in DISTRIBUTION_MAP:
        return DISTRIBUTION_MAP[import_name]
    normalized = import_name.lower().replace("-", "_")
    if normalized in known_distributions:
        return import_name
    return None


def _normalize_distribution(name: str) -> str:
    token = re.split(r"[<>=;\[\] ]", name.strip(), maxsplit=1)[0]
    return token.strip().lower().replace("-", "_")


def _classify_imports(
    aggregate: dict[str, int], known_distributions: set[str]
) -> dict[str, Any]:
    stdlib: list[str] = []
    distributions: dict[str, str] = {}
    unresolved: list[str] = []
    for name in sorted(aggregate):
        if name in sys.stdlib_module_names or name in sys.builtin_module_names:
            stdlib.append(name)
            continue
        distribution = _distribution_for(name, known_distributions)
        if distribution:
            distributions[name] = distribution
        else:
            unresolved.append(name)
    return {
        "stdlib": stdlib,
        "distributions": dict(sorted(distributions.items())),
        "sdist_only": list(SDIST_ONLY),
        "unresolved": unresolved,
    }


def _lock_packages(lock_path: Path) -> list[str]:
    packages: list[str] = []
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        packages.append(line)
    return packages


def build_dependency_inventory(
    loaded: LoadedProfile, audit_dir: Path
) -> dict[str, Any]:
    manifest_path = Path(audit_dir) / "asset_manifest.json"
    if not manifest_path.is_file():
        raise ExecutionConfigError(
            f"audit directory has no asset_manifest.json: {audit_dir}"
        )
    manifest = read_json(manifest_path)
    requirements = manifest.get("python_requirements") or {}
    aggregate = requirements.get("aggregate") or {}
    per_combination = requirements.get("per_combination") or {}

    lock_path = (loaded.project_root / loaded.profile.image.dependency_lock_path).resolve()
    environment_path = Path(audit_dir) / "environment.json"
    lock_packages = _lock_packages(lock_path)
    known_distributions = {_normalize_distribution(line) for line in lock_packages}
    known_distributions.update(
        _normalize_distribution(value) for value in DISTRIBUTION_MAP.values()
    )
    return {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "sources": {
            "asset_manifest": {
                "path": str(manifest_path),
                "sha256": sha256_file(manifest_path),
            },
            "environment": {
                "path": str(environment_path) if environment_path.is_file() else None,
                "sha256": sha256_file(environment_path) if environment_path.is_file() else None,
            },
            "audit_schema_version": manifest.get("schema_version"),
        },
        "aggregate": aggregate,
        "per_combination": per_combination,
        "classification": _classify_imports(aggregate, known_distributions),
        "lock": {
            "path": str(lock_path),
            "declared_sha256": loaded.profile.image.dependency_lock_sha256,
            "sha256": sha256_file(lock_path),
            "packages": lock_packages,
            "verified": loaded.resolved["dependency_lock"],
        },
        "notes": [
            "stdlib classification uses sys.stdlib_module_names of the running host interpreter",
            "the lock is a candidate until a Docker build regenerates exact hashes",
            "sdist-only pure-Python packages are recorded but not installed by default",
        ],
    }


# --------------------------------------------------------------------------- #
# Probe request helpers
# --------------------------------------------------------------------------- #


def _build_probe_request(
    profile: ExecutionProfile,
    spec: ProbeSpec,
    *,
    entry_args: Sequence[str],
    attempt_id: str,
) -> ExecutionRequest:
    return ExecutionRequest(
        sample_id=f"probe:{spec.probe_id}",
        attempt_id=attempt_id,
        stage="search",
        batch_id="isolation-probes",
        combination_id="isolation-probe",
        task_id=spec.probe_id,
        repeat_id=0,
        prompt_version="isolation-probe-v1",
        candidate_hash=sha256_text(f"probe:{spec.probe_id}"),
        evaluation_layer="probe",
        entry=spec.entry,
        entry_args=tuple(entry_args),
        execution_profile_hash=profile.fingerprint(),
        purpose="isolation_probe",
        input_files=(),
        result_schema="isolation-probe-payload-v1",
        harness_version="isolation-probes-v1",
        probe_id=spec.probe_id,
    )


def _tmpfs_output_root(profile: ExecutionProfile, run_dir: Path) -> Path | None:
    """Return a run-scoped subdirectory of the configured tmpfs, if any."""

    if profile.output_tmpfs is None:
        return None
    root = Path(profile.output_tmpfs.path)
    root.mkdir(parents=True, exist_ok=True)
    digest = sha256_bytes(str(run_dir.resolve()).encode("utf-8"))[:16]
    scoped = root / f"{run_dir.name}-{digest}"
    scoped.mkdir(parents=True, exist_ok=True)
    return scoped


def _run_probe(
    profile: ExecutionProfile,
    backend: DockerBackend,
    root: Path,
    spec: ProbeSpec,
    entry_args: Sequence[str],
    *,
    attempt_id: str | None = None,
    output_root: Path | None = None,
) -> tuple[ExecutionResult, dict[str, Any] | None, dict[str, Any] | None]:
    attempt = attempt_id or f"probe-{spec.probe_id}"
    request = _build_probe_request(profile, spec, entry_args=entry_args, attempt_id=attempt)
    staging = root / "staging" / attempt
    output = (output_root if output_root is not None else root / "outputs") / attempt
    staging.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    write_json_atomic(staging / "request.json", request.to_json())
    supervisor = ExecutionSupervisor(profile, backend, root / "run")
    try:
        result = supervisor.execute(request, staging, output)
        attempt_dir = root / "run" / "attempts" / attempt
        envelope = _read_json_object(attempt_dir / "result.json")
        inspect_payload = _read_json_object(attempt_dir / "container_inspect.json")
    finally:
        # The temporary output area is released after the result/artifacts were
        # archived to the persistent attempt directory.
        if output_root is not None:
            shutil.rmtree(output, ignore_errors=True)
    return result, envelope, inspect_payload


def _read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


# --------------------------------------------------------------------------- #
# Probe expectation evaluation
# --------------------------------------------------------------------------- #


def _payload_checks(
    envelope: dict[str, Any] | None,
    spec: ProbeSpec | None = None,
) -> tuple[bool, list[str]]:
    if not isinstance(envelope, dict):
        return False, ["envelope_missing"]
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, ["payload_missing"]
    if spec is not None:
        declared = payload.get("probe_id")
        if declared is not None and declared != spec.probe_id:
            return False, [f"payload_probe_id_mismatch:{declared}"]
    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        return False, ["payload_checks_missing"]
    failed = [
        str(item.get("check"))
        for item in checks
        if not isinstance(item, dict) or not item.get("ok")
    ]
    return (not failed), failed


def _check_observed(payload: dict[str, Any] | None, name: str) -> Any:
    if not isinstance(payload, dict):
        return None
    for item in payload.get("checks") or []:
        if isinstance(item, dict) and item.get("check") == name:
            return item.get("observed")
    return None


def resources_against_profile(
    profile: ExecutionProfile, payload: dict[str, Any] | None
) -> list[str]:
    """Return mismatch descriptions between observed cgroup/tmpfs values and the profile."""

    mismatches: list[str] = []
    observed = _check_observed(payload, "cgroup_limits_readable") or {}
    if observed.get("memory.max") != str(profile.limits.memory_bytes):
        mismatches.append(f"memory.max={observed.get('memory.max')} != {profile.limits.memory_bytes}")
    if observed.get("pids.max") != str(profile.limits.pids_limit):
        mismatches.append(f"pids.max={observed.get('pids.max')} != {profile.limits.pids_limit}")
    cpu_max = observed.get("cpu.max")
    if isinstance(cpu_max, str):
        parts = cpu_max.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit() and int(parts[1]) > 0:
            quota = int(parts[0]) / int(parts[1])
            if abs(quota - profile.limits.cpu_quota) > 1e-6:
                mismatches.append(f"cpu.max={cpu_max} != {profile.limits.cpu_quota} cpus")
    workspace = _check_observed(payload, "workspace_bounded") or {}
    for path in ("/tmp", "/work"):
        entry = workspace.get(path) if isinstance(workspace, dict) else None
        total = entry.get("total_bytes") if isinstance(entry, dict) else None
        if total != profile.limits.workspace_bytes:
            mismatches.append(f"{path}.total_bytes={total} != {profile.limits.workspace_bytes}")
    shm = _check_observed(payload, "shm_bounded") or {}
    shm_total = shm.get("total_bytes") if isinstance(shm, dict) else None
    if shm_total != profile.limits.shm_bytes:
        mismatches.append(f"/dev/shm.total_bytes={shm_total} != {profile.limits.shm_bytes}")
    return mismatches


def assess_hardening(
    profile: ExecutionProfile, inspect_payload: dict[str, Any] | None
) -> dict[str, Any]:
    """Verify the container's actual HostConfig/Mounts against the profile."""

    if not isinstance(inspect_payload, dict):
        return {"ok": False, "checks": {}, "reason": "container_inspect_missing"}
    host = inspect_payload.get("HostConfig") or {}
    mounts = inspect_payload.get("Mounts") or []
    cap_drop = host.get("CapDrop") or []
    security = host.get("SecurityOpt") or []
    nano_cpus = host.get("NanoCpus")
    checks = {
        "readonly_rootfs": host.get("ReadonlyRootfs") is True,
        "network_none": host.get("NetworkMode") == "none",
        "cap_drop_all": "ALL" in cap_drop,
        "no_new_privileges": any("no-new-privileges" in str(item) for item in security),
        "memory": host.get("Memory") == profile.limits.memory_bytes,
        "memory_swap": host.get("MemorySwap") == profile.limits.memory_swap_bytes,
        "pids_limit": host.get("PidsLimit") == profile.limits.pids_limit,
        "cpu_quota": (
            isinstance(nano_cpus, int)
            and abs(nano_cpus / 1_000_000_000 - profile.limits.cpu_quota) < 1e-6
        ),
        "image_matches": bool(inspect_payload.get("Image")) and (
            profile.image.image_id is None
            or inspect_payload.get("Image") == profile.image.image_id
        ),
    }
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        destination = mount.get("Destination")
        if destination == profile.sandbox.input_mount:
            checks["input_mount_read_only"] = mount.get("RW") is False
        elif destination == profile.sandbox.output_mount:
            checks["output_mount_writable"] = mount.get("RW") is True
    checks.setdefault("input_mount_read_only", False)
    checks.setdefault("output_mount_writable", False)
    failed = [name for name, ok in checks.items() if not ok]
    return {"ok": not failed, "checks": checks, "failed": failed}


def evaluate_probe(
    spec: ProbeSpec,
    result: ExecutionResult,
    envelope: dict[str, Any] | None,
    profile: ExecutionProfile | None = None,
    forbidden_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Return ``{"status": "pass"|"fail", "reason": str, "observed": {...}}``."""

    checks_ok, failed_checks = _payload_checks(envelope, spec)
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    resource_mismatches: list[str] = []
    if spec.probe_id == "resources" and profile is not None and isinstance(payload, dict):
        resource_mismatches = resources_against_profile(profile, payload)
    mount_violations: list[str] = []
    if spec.probe_id == "host_access" and isinstance(payload, dict):
        mounts = _check_observed(payload, "mount_inventory") or []
        for entry in mounts:
            haystack = f"{entry.get('point', '')} {entry.get('source', '')}"
            for marker in forbidden_paths:
                if marker and marker in haystack:
                    mount_violations.append(f"{marker} in {haystack}")
    observed = {
        "result_valid": result.result_valid,
        "timed_out": result.timed_out,
        "cleanup_complete": result.cleanup_complete,
        "error_class": result.error_class,
        "validation_failure": result.validation_failure,
        "payload_valid": envelope.get("payload_valid") if isinstance(envelope, dict) else None,
        "payload": payload,
        "payload_failed_checks": failed_checks,
        "resource_mismatches": resource_mismatches,
        "mount_violations": mount_violations,
        "available": result.available,
    }

    def outcome(ok: bool, reason: str) -> dict[str, Any]:
        return {"status": "pass" if ok else "fail", "reason": reason, "observed": observed}

    if spec.expectation == "result_valid":
        ok = bool(
            result.result_valid
            and not result.timed_out
            and result.cleanup_complete
            and checks_ok
            and not resource_mismatches
            and not mount_violations
        )
        return outcome(ok, "complete result with all payload checks passing" if ok else "result/envelope incomplete")
    if spec.expectation == "result_valid_and_timed_out":
        ok = bool(result.result_valid and result.timed_out and result.cleanup_complete and checks_ok)
        return outcome(ok, "complete result preserved alongside timeout" if ok else "complete-result-survives-timeout not observed")
    if spec.expectation == "timed_out_and_cleaned":
        ok = bool(result.timed_out and result.cleanup_complete and checks_ok)
        return outcome(ok, "timeout observed and container reclaimed" if ok else "timeout/reclaim not observed")
    if spec.expectation == "payload_invalid":
        payload_valid = envelope.get("payload_valid") if isinstance(envelope, dict) else None
        ok = bool(result.result_valid and payload_valid is False)
        return outcome(ok, "invalid payload rejected while envelope stayed valid" if ok else "invalid payload not distinguished")
    if spec.expectation == "identity_rejected":
        failure = result.validation_failure or ""
        ok = bool(
            not result.result_valid
            and failure.startswith("result_identity_mismatch")
            and result.cleanup_complete
        )
        return outcome(ok, "forged identity rejected and container reclaimed" if ok else "forged identity not rejected")
    return outcome(False, f"unknown expectation {spec.expectation!r}")


# --------------------------------------------------------------------------- #
# check-execution
# --------------------------------------------------------------------------- #


def _backend_for(profile: ExecutionProfile, backend: DockerBackend | None) -> DockerBackend:
    if backend is not None:
        return backend
    return DockerClient(control_timeout_seconds=profile.timeouts.docker_control_timeout_seconds)


def _platform_matches(platform: str, arch: str | None) -> bool:
    if not arch:
        return False
    normalized = arch.lower()
    mapping = {
        "linux/amd64": {"x86_64", "amd64"},
        "linux/arm64": {"aarch64", "arm64"},
    }
    return normalized in mapping.get(platform, {platform.split("/")[-1].lower()})


def _entry_grace(entry: Any) -> float | None:
    argv = list(entry.argv)
    for index, token in enumerate(argv):
        if token == "--grace" and index + 1 < len(argv):
            try:
                return float(argv[index + 1])
            except ValueError:
                return None
        if token.startswith("--grace="):
            try:
                return float(token.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _check(check_id: str, status: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


def _write_report(path: Path, title: str, lines: Sequence[str]) -> None:
    body = "\n".join([f"# {title}", "", *lines, ""])
    write_text_atomic(path, body)


def _output_hashes(output_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for child in sorted(output_dir.iterdir()):
        if child.is_file():
            hashes[child.name] = sha256_file(child)
    return hashes


def _host_mount_for(path: Path) -> dict[str, Any] | None:
    """Return the host mount entry covering ``path`` (from /proc/mounts)."""

    target = str(Path(path).resolve())
    try:
        text = Path("/proc/mounts").read_text(encoding="utf-8")
    except OSError:
        return None
    best: dict[str, Any] | None = None
    best_length = -1
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        point = parts[1].replace("\\040", " ").rstrip("/") or "/"
        if point == target or point == "/" or target.startswith(point + "/"):
            if len(point) > best_length:
                best_length = len(point)
                best = {
                    "point": point,
                    "source": parts[0],
                    "fstype": parts[2],
                    "options": parts[3].split(","),
                }
    return best


def _mem_available_bytes() -> int | None:
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _tmpfs_checks(profile: ExecutionProfile, tmpfs_path: Path) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    path = Path(tmpfs_path)
    if not path.is_dir():
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            return [_check("output_tmpfs_present", "block", f"cannot create {path}: {error}")]
    mount = _host_mount_for(path)
    if mount is None or mount.get("fstype") != "tmpfs":
        return [
            _check(
                "output_tmpfs_present",
                "block",
                f"{path} is not on a tmpfs mount (mount={mount})",
            )
        ]
    checks.append(_check("output_tmpfs_present", "pass", f"{mount['point']} ({mount['source']})"))
    tmpfs = profile.output_tmpfs
    if tmpfs is None:
        return checks
    try:
        stats = os.statvfs(path)
    except OSError as error:
        checks.append(_check("output_tmpfs_capacity", "block", f"statvfs failed: {error}"))
        return checks
    total_bytes = stats.f_blocks * stats.f_frsize
    checks.append(
        _check(
            "output_tmpfs_capacity",
            "pass" if total_bytes >= tmpfs.budget_bytes else "block",
            f"mount_total={total_bytes} budget={tmpfs.budget_bytes}",
        )
    )
    checks.append(
        _check(
            "output_tmpfs_files",
            "pass" if stats.f_files >= tmpfs.max_files else "block",
            f"mount_inodes={stats.f_files} max_files={tmpfs.max_files}",
        )
    )
    available = _mem_available_bytes()
    if available is None:
        checks.append(_check("output_tmpfs_memory_budget", "warn", "MemAvailable unreadable"))
    else:
        requested = tmpfs.budget_bytes * profile.limits.max_parallel_containers
        checks.append(
            _check(
                "output_tmpfs_memory_budget",
                "pass" if requested <= available // 4 else "block",
                f"requested={requested} mem_available={available}",
            )
        )
    return checks


def run_check_execution(
    config_path: Path | str,
    audit_dir: Path | str,
    output_dir: Path | str,
    *,
    backend: DockerBackend | None = None,
    project_root: Path | str | None = None,
) -> int:
    loaded = load_profile(config_path, project_root=project_root)
    audit = Path(audit_dir).expanduser().resolve()
    if not audit.is_dir():
        raise ExecutionConfigError(f"--audit-dir is not a directory: {audit}")
    manifest_path = audit / "asset_manifest.json"
    if not manifest_path.is_file():
        raise ExecutionConfigError(f"--audit-dir has no asset_manifest.json: {audit}")

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    inventory = build_dependency_inventory(loaded, audit)
    write_json_atomic(output / "dependency_inventory.json", inventory)

    active_backend = _backend_for(loaded.profile, backend)
    probe = active_backend.probe()
    checks: list[dict[str, str]] = []
    checks.append(
        _check(
            "docker_available",
            "pass" if probe.get("available") else "block",
            probe.get("reason") or ("docker daemon reachable" if probe.get("available") else "docker unavailable"),
        )
    )
    grace_conflicts = [
        f"{entry.entry_id}={_entry_grace(entry)}"
        for entry in loaded.profile.entries
        if (_entry_grace(entry) is not None)
        and _entry_grace(entry) >= loaded.profile.timeouts.sigterm_grace_seconds
    ]
    checks.append(
        _check(
            "entry_grace_budget",
            "block" if grace_conflicts else "pass",
            f"conflicts={grace_conflicts} host_sigterm_grace={loaded.profile.timeouts.sigterm_grace_seconds}",
        )
    )
    if probe.get("available"):
        checks.append(
            _check(
                "platform",
                "pass" if _platform_matches(loaded.profile.image.platform, probe.get("arch")) else "block",
                f"profile={loaded.profile.image.platform} host_arch={probe.get('arch')}",
            )
        )
        checks.append(
            _check(
                "cgroup",
                "pass" if probe.get("cgroup_version") else "warn",
                f"cgroup_version={probe.get('cgroup_version')}",
            )
        )

    image_manifest: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "reference": loaded.profile.image.reference,
        "resolved_image_id": None,
        "repo_digest": loaded.profile.image.repo_digest,
        "base_image": loaded.profile.image.base_image,
        "base_digest": loaded.profile.image.base_digest,
        "platform": loaded.profile.image.platform,
        "python_version": loaded.profile.image.python_version,
        "dependency_lock": {
            "path": str((loaded.project_root / loaded.profile.image.dependency_lock_path).resolve()),
            "sha256": loaded.profile.image.dependency_lock_sha256,
        },
        "image_inspect": None,
        "available": bool(probe.get("available")),
        "reason": probe.get("reason"),
    }

    resolved_profile = loaded.profile
    if probe.get("available"):
        inspect = active_backend.image_inspect(loaded.profile.image.reference)
        if inspect is None:
            checks.append(_check("image_present", "block", f"image not found: {loaded.profile.image.reference}"))
        else:
            image_manifest["image_inspect"] = inspect
            actual_id = inspect.get("Id") or inspect.get("ID")
            image_manifest["resolved_image_id"] = actual_id
            declared_id = loaded.profile.image.image_id
            if not _is_zero_image_id(declared_id):
                if actual_id != declared_id:
                    checks.append(
                        _check(
                            "image_identity",
                            "block",
                            f"declared image_id {declared_id} != actual {actual_id}",
                        )
                    )
                else:
                    checks.append(_check("image_identity", "pass", f"image_id={actual_id}"))
            elif actual_id:
                resolved_profile = replace(
                    resolved_profile, image=replace(resolved_profile.image, image_id=actual_id)
                )
                checks.append(
                    _check("image_identity", "pass", f"resolved local image id {actual_id}")
                )
            else:
                checks.append(_check("image_identity", "block", "could not resolve an image id"))

            repo_digests = inspect.get("RepoDigests") or []
            if loaded.profile.image.repo_digest and loaded.profile.image.repo_digest not in repo_digests:
                checks.append(
                    _check(
                        "image_repo_digest",
                        "block",
                        f"declared repo_digest {loaded.profile.image.repo_digest} not in {repo_digests}",
                    )
                )

            labels = (inspect.get("Config") or {}).get("Labels") or {}
            base_label = labels.get("org.coco.base-digest")
            declared_base = loaded.profile.image.base_digest
            if not declared_base or "PIN" in declared_base.upper():
                checks.append(
                    _check("base_image_pinned", "block", f"base_digest is a placeholder: {declared_base!r}")
                )
            elif base_label is None:
                checks.append(
                    _check("base_image_pinned", "block", "image carries no org.coco.base-digest label")
                )
            elif base_label != declared_base:
                checks.append(
                    _check(
                        "base_image_pinned",
                        "block",
                        f"label {base_label!r} != profile {declared_base!r}",
                    )
                )
            else:
                checks.append(_check("base_image_pinned", "pass", base_label))

            image_os = inspect.get("Os")
            image_arch = inspect.get("Architecture")
            platform_ok = _platform_matches(loaded.profile.image.platform, image_arch) and image_os in (
                None,
                "linux",
            )
            checks.append(
                _check(
                    "image_platform",
                    "pass" if platform_ok else "block",
                    f"profile={loaded.profile.image.platform} image={image_os}/{image_arch}",
                )
            )

        try:
            usage = shutil.disk_usage(output)
            enough = usage.free >= loaded.profile.limits.output_storage_bytes
            checks.append(
                _check(
                    "output_storage",
                    "pass" if enough else "block",
                    f"free={usage.free} required={loaded.profile.limits.output_storage_bytes}",
                )
            )
        except OSError as error:
            checks.append(_check("output_storage", "block", f"cannot stat output filesystem: {error}"))

        if loaded.profile.output_tmpfs is not None:
            checks.extend(_tmpfs_checks(resolved_profile, Path(loaded.profile.output_tmpfs.path)))
        else:
            checks.append(
                _check(
                    "output_tmpfs_present",
                    "warn",
                    "no output_tmpfs configured; host-directory output has no hard capacity cap",
                )
            )

        # Trusted dependency probe: runs the pinned image under the same limits.
        run_root = output / "dependency-probe"
        run_root.mkdir(parents=True, exist_ok=True)
        dependency_spec = ProbeSpec(
            "dependencies",
            "pinned runtime imports and Python version inside the image",
            "dependency_probe",
            ("--payload", "/out/payload.json"),
            "result_valid",
        )
        try:
            with RunLock(run_root / "run"):
                dependency_output = _tmpfs_output_root(resolved_profile, run_root / "run")
                result, envelope, container_inspect = _run_probe(
                    resolved_profile,
                    active_backend,
                    run_root,
                    dependency_spec,
                    dependency_spec.entry_args,
                    output_root=dependency_output,
                )
            payload_ok, failed_payload_checks = _payload_checks(envelope, dependency_spec)
            hardening = assess_hardening(resolved_profile, container_inspect)
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            python_observed = _check_observed(payload, "python_version")
            python_ok = isinstance(python_observed, str) and python_observed.startswith(
                resolved_profile.image.python_version
            )
            ok = bool(
                result.result_valid
                and result.cleanup_complete
                and payload_ok
                and hardening.get("ok")
                and python_ok
            )
            checks.append(
                _check(
                    "dependency_probe",
                    "pass" if ok else "block",
                    f"result_valid={result.result_valid} error_class={result.error_class} "
                    f"failed_checks={failed_payload_checks} hardening_failed={hardening.get('failed')} "
                    f"python={python_observed}",
                )
            )
        except Exception as error:  # noqa: BLE001 - recorded as a blocking fact
            checks.append(_check("dependency_probe", "block", f"{type(error).__name__}: {error}"))
    else:
        checks.append(_check("image_present", "block", "docker unavailable; image not inspected"))
        checks.append(_check("dependency_probe", "block", "docker unavailable; not run"))

    blocked = any(item["status"] == "block" for item in checks)
    exit_code = 1 if blocked else 0

    write_json_atomic(
        output / "execution_profile.json",
        {
            "schema_version": PREFLIGHT_SCHEMA_VERSION,
            "profile": resolved_profile.to_json(),
            "profile_fingerprint": resolved_profile.fingerprint(),
            "resolved_placeholders": loaded.resolved,
        },
    )
    image_manifest["profile_fingerprint"] = resolved_profile.fingerprint()
    write_json_atomic(output / "image_manifest.json", image_manifest)

    manifest = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "command": CHECK_EXECUTION,
        "status": "block" if blocked else "pass",
        "exit_code": exit_code,
        "config": {"path": str(loaded.config_path), "sha256": loaded.config_sha256},
        "audit_dir": {"path": str(audit), "asset_manifest_sha256": sha256_file(manifest_path)},
        "resolved_placeholders": loaded.resolved,
        "host": probe,
        "checks": checks,
        "outputs": _output_hashes(output),
    }
    write_json_atomic(output / "manifest.json", manifest)
    _write_report(
        output / "REPORT.md",
        "check-execution",
        [
            f"- status: **{manifest['status']}** (exit {exit_code})",
            f"- docker available: {probe.get('available')}",
            f"- image reference: {loaded.profile.image.reference}",
            "",
            "## Checks",
            "",
            *[
                f"- `{item['id']}`: **{item['status']}** — {item['detail']}"
                for item in checks
            ],
            "",
            "This command never executes generated code. Docker-unavailable results are blocking; "
            "the run must not fall back to host execution.",
            "",
        ],
    )
    return exit_code


# --------------------------------------------------------------------------- #
# verify-isolation
# --------------------------------------------------------------------------- #


def run_verify_isolation(
    config_path: Path | str,
    audit_dir: Path | str,
    output_dir: Path | str,
    *,
    backend: DockerBackend | None = None,
    project_root: Path | str | None = None,
) -> int:
    loaded = load_profile(config_path, project_root=project_root)
    audit = Path(audit_dir).expanduser().resolve()
    if not (audit / "asset_manifest.json").is_file():
        raise ExecutionConfigError(f"--audit-dir has no asset_manifest.json: {audit}")

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    active_backend = _backend_for(loaded.profile, backend)
    probe = active_backend.probe()

    profile = loaded.profile
    blockers: list[str] = []
    if not probe.get("available"):
        blockers.append(f"docker unavailable: {probe.get('reason')}")
    else:
        inspect = active_backend.image_inspect(profile.image.reference)
        if inspect is None:
            blockers.append(f"image not found: {profile.image.reference}")
        else:
            actual_id = inspect.get("Id") or inspect.get("ID")
            if actual_id:
                profile = replace(profile, image=replace(profile.image, image_id=actual_id))
            if _is_zero_image_id(loaded.profile.image.image_id) and not actual_id:
                blockers.append("could not resolve an image id")
            elif not _is_zero_image_id(loaded.profile.image.image_id) and actual_id != loaded.profile.image.image_id:
                blockers.append(
                    f"declared image_id {loaded.profile.image.image_id} != actual {actual_id}"
                )

    checks: list[dict[str, Any]] = []
    sentinel_path: Path | None = None
    sentinel_sha: str | None = None
    if blockers:
        for spec in PROBE_REGISTRY:
            checks.append(
                {
                    "probe_id": spec.probe_id,
                    "description": spec.description,
                    "expectation": spec.expectation,
                    "status": "blocked",
                    "reason": "; ".join(blockers),
                    "observed": {},
                    "hardening": {},
                    "attempt_dir": None,
                }
            )
    else:
        sentinel_dir = Path(tempfile.mkdtemp(prefix="coco-sentinel-"))
        os.chmod(sentinel_dir, 0o755)
        sentinel_path = sentinel_dir / "never-mounted.sentinel"
        sentinel_path.write_text(f"sentinel-{os.urandom(16).hex()}", encoding="utf-8")
        os.chmod(sentinel_path, 0o644)
        sentinel_sha = sha256_file(sentinel_path)
        forbidden_markers = (str(loaded.project_root), ".env", "docker.sock", ".git")
        tmpfs_output = _tmpfs_output_root(profile, output / "run")
        lock = RunLock(output / "run")
        lock.acquire()
        try:
            for spec in PROBE_REGISTRY:
                entry_args = tuple(
                    str(sentinel_path) if item == "__SENTINEL__" else item
                    for item in spec.entry_args
                )
                attempt = f"probe-{spec.probe_id}"
                try:
                    result, envelope, container_inspect = _run_probe(
                        profile,
                        active_backend,
                        output,
                        spec,
                        entry_args,
                        attempt_id=attempt,
                        output_root=tmpfs_output,
                    )
                    evaluation = evaluate_probe(
                        spec, result, envelope, profile, forbidden_markers
                    )
                    hardening = assess_hardening(profile, container_inspect)
                except Exception as error:  # noqa: BLE001 - blocked probe
                    evaluation = {
                        "status": "blocked",
                        "reason": f"{type(error).__name__}: {error}",
                        "observed": {},
                    }
                    hardening = {"ok": False, "checks": {}, "failed": [f"{type(error).__name__}: {error}"]}
                status = evaluation["status"]
                reason = evaluation["reason"]
                if status == "pass" and not hardening.get("ok"):
                    status = "fail"
                    reason = (
                        "container hardening check failed: "
                        f"{hardening.get('failed') or hardening.get('reason')}"
                    )
                checks.append(
                    {
                        "probe_id": spec.probe_id,
                        "description": spec.description,
                        "expectation": spec.expectation,
                        "status": status,
                        "reason": reason,
                        "observed": evaluation["observed"],
                        "hardening": hardening,
                        "attempt_dir": f"run/attempts/{attempt}",
                    }
                )
        finally:
            lock.release()
            if sentinel_path is not None:
                shutil.rmtree(sentinel_path.parent, ignore_errors=True)

    failed = [item for item in checks if item["status"] != "pass"]
    exit_code = 1 if failed else 0
    isolation_checks = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "profile_fingerprint": profile.fingerprint(),
        "image_id": profile.image.image_id,
        "sentinel_sha256": sentinel_sha,
        "blockers": blockers,
        "probes": checks,
    }
    write_json_atomic(output / "isolation_checks.json", isolation_checks)
    write_json_atomic(
        output / "manifest.json",
        {
            "schema_version": PREFLIGHT_SCHEMA_VERSION,
            "command": VERIFY_ISOLATION,
            "status": "pass" if not failed else ("block" if blockers else "fail"),
            "exit_code": exit_code,
            "config": {"path": str(loaded.config_path), "sha256": loaded.config_sha256},
            "audit_dir": {"path": str(audit), "asset_manifest_sha256": sha256_file(audit / "asset_manifest.json")},
            "host": probe,
            "profile_fingerprint": profile.fingerprint(),
            "blockers": blockers,
            "probe_status": {item["probe_id"]: item["status"] for item in checks},
            "outputs": _output_hashes(output),
        },
    )
    _write_report(
        output / "REPORT.md",
        "verify-isolation",
        [
            f"- status: **{'pass' if not failed else ('block' if blockers else 'fail')}** (exit {exit_code})",
            f"- profile: `{profile.fingerprint()}`",
            "",
            *([f"- blocker: {item}" for item in blockers] if blockers else []),
            "## Probes",
            "",
            *[
                f"- `{item['probe_id']}`: **{item['status']}** — {item['reason']}"
                for item in checks
            ],
            "",
            "These probes are fixed, human-written checks. They do not run dataset code "
            "and do not establish functional pass/fail.",
            "",
        ],
    )
    return exit_code


# --------------------------------------------------------------------------- #
# recover-executions
# --------------------------------------------------------------------------- #


def run_recover_executions(
    config_path: Path | str,
    run_dir: Path | str,
    *,
    backend: DockerBackend | None = None,
    project_root: Path | str | None = None,
) -> int:
    loaded = load_profile(config_path, project_root=project_root)
    target = Path(run_dir).expanduser().resolve()
    if not target.is_dir():
        raise ExecutionConfigError(f"--run-dir is not an existing directory: {target}")
    active_backend = _backend_for(loaded.profile, backend)

    profile = loaded.profile
    warnings: list[str] = []
    if _is_zero_image_id(profile.image.image_id):
        inspect = active_backend.image_inspect(profile.image.reference)
        actual_id = (inspect or {}).get("Id") or (inspect or {}).get("ID")
        if actual_id:
            profile = replace(profile, image=replace(profile.image, image_id=actual_id))
        else:
            warnings.append("image_id_unresolved: clean-up still scoped by run/attempt ownership")

    supervisor = ExecutionSupervisor(profile, active_backend, target)
    recovered = supervisor.recover()
    warnings.extend(getattr(supervisor, "recovery_warnings", []))
    unresolved = [item.attempt_id for item in recovered if not item.cleanup_complete]
    payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "command": RECOVER_EXECUTIONS,
        "run_dir": str(target),
        "profile_fingerprint": profile.fingerprint(),
        "recovery_warnings": warnings,
        "recovered": [
            {
                "attempt_id": item.attempt_id,
                "container_id": item.container_id,
                "cleanup_complete": item.cleanup_complete,
                "still_needs_reclaim": list(item.still_needs_reclaim),
            }
            for item in recovered
        ],
        "unresolved_attempts": unresolved,
        "status": "pass" if not unresolved else "block",
    }
    write_json_atomic(target / "recover_manifest.json", payload)
    _write_report(
        target / "RECOVER_REPORT.md",
        "recover-executions",
        [
            f"- run directory: `{target}`",
            f"- recovered attempts: {len(recovered)}",
            f"- unresolved: {unresolved}",
            "",
            "Only containers carrying this run's ownership labels were touched. No global prune was issued.",
            "",
        ],
    )
    return 0 if not unresolved else 1


__all__ = [
    "LoadedProfile",
    "ProbeSpec",
    "PROBE_REGISTRY",
    "EXPECTATIONS",
    "load_profile",
    "executor_source_sha256",
    "build_dependency_inventory",
    "evaluate_probe",
    "run_check_execution",
    "run_verify_isolation",
    "run_recover_executions",
]
