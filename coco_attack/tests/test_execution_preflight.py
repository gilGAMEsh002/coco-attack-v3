"""Offline tests for the Docker execution preflight orchestration (Chunk 2).

None of these tests require a Docker daemon.  ``SimBackend`` simulates the
container side well enough to exercise the host orchestration: it writes result
envelopes into the mounted output directory, honours the timeout probes, and can
be told to produce a bad result.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json, sha256_bytes, write_json_atomic
from coco_attack.cli import main
from coco_attack.execution.contracts import (
    ContainerSpec,
    ContainerState,
    ExecutionBackendError,
    ExecutionConfigError,
    ExecutionResult,
)
from coco_attack.execution.docker import LogResult
from coco_attack.execution.preflight import (
    PROBE_REGISTRY,
    ProbeSpec,
    evaluate_probe,
    load_profile,
    run_check_execution,
    run_recover_executions,
    run_verify_isolation,
)

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "execution.example.json"
BASE_DIGEST = "public.ecr.aws/docker/library/python@sha256:" + "d" * 64


def _config_payload() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _write_config(tmp_path: Path, **timeout_overrides) -> Path:
    payload = _config_payload()
    payload["profile_id"] = "test-profile"
    payload["image"]["base_image"] = BASE_DIGEST.split("@")[0]
    payload["image"]["base_digest"] = BASE_DIGEST
    payload["timeouts"]["wall_clock_seconds"] = timeout_overrides.get("wall_clock_seconds", 0.6)
    payload["timeouts"]["sigterm_grace_seconds"] = timeout_overrides.get("sigterm_grace_seconds", 0.2)
    for entry in payload.get("entries", []):
        argv = entry.get("argv", [])
        for index, token in enumerate(argv):
            if token == "--grace" and index + 1 < len(argv):
                argv[index + 1] = "0.05"
    # Keep the tmpfs check hermetic: use /dev/shm when available, else disable.
    shm = Path("/dev/shm")
    if shm.is_dir() and os.access(shm, os.W_OK):
        payload["output_tmpfs"] = {
            "path": str(shm / f"coco-test-{tmp_path.name}"),
            "budget_bytes": 67108864,
            "max_files": 1024,
        }
    else:
        payload["output_tmpfs"] = None
    path = tmp_path / "execution.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _state(cid: str, *, running: bool) -> ContainerState:
    return ContainerState(
        container_id=cid,
        name=f"coco-attack-{cid}",
        status="running" if running else "exited",
        running=running,
        exit_code=None if running else 0,
        oom_killed=False,
        started_at="2026-01-01T00:00:00Z",
        finished_at=None if running else "2026-01-01T00:00:01Z",
        labels={"coco-attack.managed": "true"},
        image_id="sha256:" + "b" * 64,
    )


class SimBackend:
    """Container simulator backed by the host output directory."""

    def __init__(self, *, available: bool = True, image_id: str = "sha256:" + "b" * 64) -> None:
        self.available = available
        self.image_id = image_id
        self.actions: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.specs: dict[str, ContainerSpec] = {}
        self.removed: set[str] = set()
        self.force_bad_result: set[str] = set()
        self.last_spec: ContainerSpec | None = None

    # protocol ------------------------------------------------------------- #
    def probe(self) -> dict:
        if not self.available:
            return {"available": False, "reason": "docker daemon unreachable"}
        return {
            "available": True,
            "arch": "x86_64",
            "cgroup_version": "2",
            "client_version": "27.0",
            "server_version": "27.0",
            "reason": None,
        }

    def image_inspect(self, reference: str):
        if not self.available:
            return None
        return {
            "Id": self.image_id,
            "RepoDigests": [f"{reference}@sha256:" + "c" * 64],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Labels": {"org.coco.base-digest": BASE_DIGEST}},
        }

    def inspect_raw(self, container_id: str):
        if container_id not in self.containers:
            return None
        return {
            "Id": container_id,
            "Image": self.image_id,
            "HostConfig": {
                "ReadonlyRootfs": True,
                "NetworkMode": "none",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 536870912,
                "MemorySwap": 536870912,
                "PidsLimit": 64,
                "NanoCpus": 1_000_000_000,
            },
            "Mounts": [
                {"Destination": "/in", "RW": False},
                {"Destination": "/out", "RW": True},
            ],
        }

    def create(self, spec: ContainerSpec) -> str:
        self.actions.append(("create", spec.name))
        self.last_spec = spec
        probe_id = self._probe_id(spec)
        cid = f"cid-{probe_id}"
        output = self._mount_source(spec, "/out")
        staging = self._mount_source(spec, "/in")
        self.specs[cid] = spec
        self.containers[cid] = {
            "probe": probe_id,
            "output": output,
            "staging": staging,
            "hang": probe_id in ("hang_after_result", "hang_ignoring_sigterm"),
            "finished": False,
        }
        if not self.containers[cid]["hang"]:
            self._finish(cid)
        return cid

    def start(self, container_id: str) -> None:
        self.actions.append(("start", container_id))

    def inspect(self, container_id: str) -> ContainerState | None:
        if container_id in self.removed:
            return None
        info = self.containers.get(container_id)
        if info is None:
            return None
        return _state(container_id, running=not info["finished"])

    def wait(self, container_id: str, timeout_seconds: float) -> int | None:
        return 0

    def stop(self, container_id: str, grace_seconds: float) -> None:
        self.actions.append(("stop", container_id))
        info = self.containers.get(container_id)
        if info is not None and not info["finished"]:
            self._finish(container_id)

    def remove(self, container_id: str, force: bool) -> None:
        self.actions.append(("remove", container_id, force))
        self.removed.add(container_id)

    def list_managed(self, labels: dict[str, str]) -> list[ContainerState]:
        return []

    def logs(self, container_id: str, stdout_max_bytes: int, stderr_max_bytes: int) -> LogResult:
        return LogResult("", "", False, False)

    # helpers -------------------------------------------------------------- #
    def _probe_id(self, spec: ContainerSpec) -> str:
        argv = list(spec.argv)
        if "--raw-envelope" in argv:
            for index, token in enumerate(argv):
                if token == "--probe" and index + 1 < len(argv):
                    return argv[index + 1]
            return "wrong_identity"
        for index, token in enumerate(argv):
            if token == "--probe" and index + 1 < len(argv):
                return argv[index + 1]
        return "unknown"

    def _mount_source(self, spec: ContainerSpec, target: str) -> str:
        for mount in spec.mounts:
            if mount.target == target:
                return mount.source
        raise AssertionError(f"no mount for {target}")

    def _finish(self, cid: str) -> None:
        info = self.containers[cid]
        info["finished"] = True
        request = json.loads(Path(f"{info['staging']}/request.json").read_text(encoding="utf-8"))
        probe = info["probe"]
        argv = list(self.specs[cid].argv)
        nonce = None
        if "--nonce" in argv:
            index = argv.index("--nonce")
            if index + 1 < len(argv):
                nonce = argv[index + 1]
        if probe == "resources":
            checks = [
                {
                    "check": "cgroup_limits_readable",
                    "ok": True,
                    "observed": {
                        "memory.max": "536870912",
                        "memory.swap.max": "536870912",
                        "pids.max": "64",
                        "cpu.max": "100000 100000",
                    },
                },
                {
                    "check": "workspace_bounded",
                    "ok": True,
                    "observed": {
                        "/tmp": {"total_bytes": 67108864},
                        "/work": {"total_bytes": 67108864},
                    },
                },
                {
                    "check": "shm_bounded",
                    "ok": True,
                    "observed": {"total_bytes": 16777216},
                },
            ]
        elif probe == "dependencies":
            checks = [
                {"check": "third_party_imports", "ok": True, "observed": {"missing": []}},
                {"check": "python_version", "ok": True, "observed": "3.14.7"},
            ]
        else:
            checks = [{"check": "sim", "ok": True}]
        envelope: dict = {
            "schema_version": "1",
            "sample_id": request["sample_id"],
            "attempt_id": request["attempt_id"],
            "stage": request["stage"],
            "result_schema": request["result_schema"],
            "nonce": nonce,
            "supervisor": {"exit_code": 0, "timed_out": False},
            "payload_valid": True,
            "payload": {"probe_id": probe, "checks": checks},
            "payload_error": None,
        }
        if probe == "wrong_identity":
            envelope["sample_id"] = "forged-sample-id"
        elif probe == "partial_payload":
            envelope["payload"] = None
            envelope["payload_valid"] = False
            envelope["payload_error"] = "invalid_json"
        elif probe in self.force_bad_result:
            envelope["result_schema"] = "wrong-schema"
        write_json_atomic(Path(info["output"]) / "result.json", envelope)


# --------------------------------------------------------------------------- #
# load_profile
# --------------------------------------------------------------------------- #


def test_load_profile_resolves_placeholders(tmp_path: Path) -> None:
    loaded = load_profile(_write_config(tmp_path))

    assert loaded.resolved == {"image_id": False, "dependency_lock": False, "executor_source": False}
    assert loaded.profile.image.dependency_lock_sha256 != "0" * 64
    assert loaded.profile.executor_source_sha256 != "0" * 64
    assert loaded.profile.fingerprint()


def test_load_profile_rejects_stale_lock_hash(tmp_path: Path) -> None:
    path = _write_config(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["image"]["dependency_lock_sha256"] = "1" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ExecutionConfigError):
        load_profile(path)


# --------------------------------------------------------------------------- #
# check-execution
# --------------------------------------------------------------------------- #


def test_check_execution_blocked_without_docker(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "check"
    backend = SimBackend(available=False)

    exit_code = run_check_execution(config, audit, output, backend=backend)

    assert exit_code == 1
    assert backend.actions == []
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "block"
    assert manifest["checks"][0]["id"] == "docker_available"
    assert manifest["checks"][0]["status"] == "block"


def test_check_execution_pass_with_sim_backend(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "check"
    backend = SimBackend()

    exit_code = run_check_execution(config, audit, output, backend=backend)

    assert exit_code == 0, read_json(output / "manifest.json")["checks"]
    for name in (
        "dependency_inventory.json",
        "execution_profile.json",
        "image_manifest.json",
        "manifest.json",
        "REPORT.md",
    ):
        assert (output / name).is_file(), name
    image_manifest = read_json(output / "image_manifest.json")
    assert image_manifest["resolved_image_id"] == backend.image_id
    profile_payload = read_json(output / "execution_profile.json")["profile"]
    from coco_attack.execution.contracts import ExecutionProfile

    assert ExecutionProfile.from_json(profile_payload).fingerprint() == read_json(
        output / "execution_profile.json"
    )["profile_fingerprint"]
    assert any(action[0] == "create" for action in backend.actions)


# --------------------------------------------------------------------------- #
# verify-isolation
# --------------------------------------------------------------------------- #


def test_verify_isolation_all_pass(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "isolation"
    backend = SimBackend()

    exit_code = run_verify_isolation(config, audit, output, backend=backend)

    assert exit_code == 0, read_json(output / "isolation_checks.json")
    checks = read_json(output / "isolation_checks.json")
    assert [item["status"] for item in checks["probes"]] == ["pass"] * len(PROBE_REGISTRY)
    assert len(backend.actions) >= len(PROBE_REGISTRY)


def test_verify_isolation_fails_on_bad_probe_result(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "isolation"
    backend = SimBackend()
    backend.force_bad_result = {"identity"}

    exit_code = run_verify_isolation(config, audit, output, backend=backend)

    assert exit_code == 1
    statuses = {item["probe_id"]: item["status"] for item in read_json(output / "isolation_checks.json")["probes"]}
    assert statuses["identity"] == "fail"
    assert statuses["network"] == "pass"


def test_verify_isolation_blocked_without_docker(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "isolation"
    backend = SimBackend(available=False)

    exit_code = run_verify_isolation(config, audit, output, backend=backend)

    assert exit_code == 1
    assert backend.actions == []
    checks = read_json(output / "isolation_checks.json")
    assert checks["blockers"]
    assert all(item["status"] == "blocked" for item in checks["probes"])


def test_verify_isolation_fails_on_wrong_host_config(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = _audit_dir(tmp_path)
    output = tmp_path / "isolation"
    backend = SimBackend()

    def bad_inspect(container_id: str):
        return {
            "Id": container_id,
            "Image": backend.image_id,
            "HostConfig": {
                "ReadonlyRootfs": False,
                "NetworkMode": "none",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 536870912,
                "MemorySwap": 536870912,
                "PidsLimit": 64,
                "NanoCpus": 1_000_000_000,
            },
            "Mounts": [
                {"Destination": "/in", "RW": False},
                {"Destination": "/out", "RW": True},
            ],
        }

    backend.inspect_raw = bad_inspect  # type: ignore[method-assign]

    exit_code = run_verify_isolation(config, audit, output, backend=backend)

    assert exit_code == 1
    checks = read_json(output / "isolation_checks.json")
    assert all(item["status"] == "fail" for item in checks["probes"])
    assert all(not item["hardening"]["ok"] for item in checks["probes"])


# --------------------------------------------------------------------------- #
# evaluate_probe
# --------------------------------------------------------------------------- #


def _result(**overrides) -> ExecutionResult:
    base = dict(
        sample_id="s1",
        attempt_id="a1",
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
    )
    base.update(overrides)
    return ExecutionResult(**base)


def _spec(expectation: str) -> ProbeSpec:
    return ProbeSpec("p", "d", "probe", (), expectation)


def _envelope(checks_ok: bool = True, payload_valid: bool = True) -> dict:
    return {
        "payload_valid": payload_valid,
        "payload": {"checks": [{"check": "c", "ok": checks_ok}]},
    }


def test_evaluate_probe_result_valid() -> None:
    assert evaluate_probe(_spec("result_valid"), _result(), _envelope())["status"] == "pass"
    assert evaluate_probe(_spec("result_valid"), _result(timed_out=True), _envelope())["status"] == "fail"
    assert evaluate_probe(_spec("result_valid"), _result(), _envelope(checks_ok=False))["status"] == "fail"


def test_evaluate_probe_result_valid_and_timed_out() -> None:
    spec = _spec("result_valid_and_timed_out")
    assert evaluate_probe(spec, _result(timed_out=True), _envelope())["status"] == "pass"
    assert evaluate_probe(spec, _result(), _envelope())["status"] == "fail"


def test_evaluate_probe_timed_out_and_cleaned() -> None:
    spec = _spec("timed_out_and_cleaned")
    assert evaluate_probe(spec, _result(timed_out=True), _envelope())["status"] == "pass"
    assert evaluate_probe(spec, _result(timed_out=True, cleanup_complete=False), None)["status"] == "fail"


def test_evaluate_probe_payload_invalid() -> None:
    spec = _spec("payload_invalid")
    assert evaluate_probe(spec, _result(), _envelope(payload_valid=False))["status"] == "pass"
    assert evaluate_probe(spec, _result(), _envelope())["status"] == "fail"


def test_evaluate_probe_identity_rejected() -> None:
    spec = _spec("identity_rejected")
    rejected = _result(result_valid=False, validation_failure="result_identity_mismatch:sample_id")
    assert evaluate_probe(spec, rejected, None)["status"] == "pass"
    assert evaluate_probe(spec, _result(), None)["status"] == "fail"


# --------------------------------------------------------------------------- #
# recover-executions wrapper and CLI usage
# --------------------------------------------------------------------------- #


def test_recover_executions_writes_manifest(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    run_dir = tmp_path / "run"
    (run_dir / "attempts").mkdir(parents=True)

    exit_code = run_recover_executions(config, run_dir, backend=SimBackend())

    assert exit_code == 0
    assert (run_dir / "recover_manifest.json").is_file()
    assert (run_dir / "RECOVER_REPORT.md").is_file()


def test_cli_check_execution_missing_config_is_usage_error(tmp_path: Path) -> None:
    exit_code = main([
        "check-execution",
        "--config", str(tmp_path / "missing.json"),
        "--audit-dir", str(tmp_path),
        "--output-dir", str(tmp_path / "out"),
    ])
    assert exit_code == 2


def test_cli_check_execution_missing_audit_manifest_is_usage_error(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    exit_code = main([
        "check-execution",
        "--config", str(config),
        "--audit-dir", str(audit),
        "--output-dir", str(tmp_path / "out"),
    ])
    assert exit_code == 2


def _audit_dir(tmp_path: Path) -> Path:
    audit = tmp_path / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    write_json_atomic(
        audit / "asset_manifest.json",
        {
            "schema_version": "1",
            "python_requirements": {
                "aggregate": {"os": 3, "bs4": 2, "sklearn": 1, "cgi": 1, "unknown_pkg": 1},
                "per_combination": {"cwe078-0": {"os": 3}},
            },
        },
    )
    return audit
