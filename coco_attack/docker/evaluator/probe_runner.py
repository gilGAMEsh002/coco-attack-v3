#!/usr/bin/env python3
"""Fixed, human-written probes executed inside the evaluation container.

The host selects a probe by id through a trusted entry registry; the container
never runs dataset code here.  Each probe writes a JSON payload with an explicit
list of ``checks``; the host decides pass/fail, not the probe.

``--raw-envelope`` is a deliberately unguarded mode used only for negative
tests: it writes a result envelope directly (for example with a forged
identity) so the host-side rejection path can be exercised.
"""

from __future__ import annotations

import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

CREDENTIAL_MARKERS = (
    "DMX_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY",
    "AWS_SECRET",
    "PASSWORD",
    "SECRET",
    "CREDENTIAL",
    "COCO_ATTACK_TOKEN",
)

DEFAULT_SENTINEL = "/coco-sentinel/never-mounted.sentinel"


def _check(name: str, expected: Any, observed: Any, ok: bool) -> dict[str, Any]:
    return {"check": name, "expected": expected, "observed": observed, "ok": bool(ok)}


def _atomic_write(path: str | Path, text: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _write_json(path: str | Path, payload: dict[str, Any]) -> None:
    _atomic_write(
        path,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
    )


def _read_status_field(name: str) -> str | None:
    try:
        text = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(f"{name}:"):
            return line.split(":", 1)[1].strip()
    return None


def _can_write(path: Path) -> bool:
    try:
        probe = path / ".coco-write-probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _can_read(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes() is not None
    except OSError:
        return False


def _mount_options(mount_point: str) -> list[str]:
    """Return the mount options for the longest mount covering ``mount_point``."""

    target = mount_point.rstrip("/") or "/"
    try:
        text = Path("/proc/self/mounts").read_text(encoding="utf-8")
    except OSError:
        return []
    best_length = -1
    best_options: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        point = parts[1].rstrip("/") or "/"
        if point == target or point == "/" or target.startswith(point + "/"):
            if len(point) > best_length:
                best_length = len(point)
                best_options = parts[3].split(",")
    return best_options


def _is_numeric(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"\d+", value) is not None


def _mount_inventory() -> list[dict[str, str]]:
    try:
        text = Path("/proc/self/mounts").read_text(encoding="utf-8")
    except OSError:
        return []
    inventory: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        inventory.append(
            {
                "source": parts[0].replace("\\040", " "),
                "point": parts[1].replace("\\040", " "),
                "fstype": parts[2],
            }
        )
    return inventory


def probe_identity(_args: dict[str, Any]) -> list[dict[str, Any]]:
    uid = os.getuid()
    gid = os.getgid()
    no_new_privs = _read_status_field("NoNewPrivs")
    capabilities = _read_status_field("CapEff")
    caps_value = (capabilities or "").strip()
    caps_ok = bool(caps_value) and re.fullmatch(r"0+", caps_value) is not None
    root_options = _mount_options("/")
    input_options = _mount_options("/in")
    return [
        _check("uid_reported", "non-root uid > 0", uid, uid > 0),
        _check("gid_reported", "non-root gid > 0", gid, gid > 0),
        _check("no_new_privs", "NoNewPrivs == 1", no_new_privs, no_new_privs == "1"),
        _check("caps_dropped", "CapEff is all-zero (non-empty)", capabilities, caps_ok),
        # Check the mount flags, not the uid's write permission: a non-root uid
        # cannot write a root-owned rootfs even without --read-only.
        _check(
            "rootfs_read_only",
            "root mount options contain 'ro'",
            root_options,
            "ro" in root_options,
        ),
        _check(
            "input_read_only",
            "/in mount options contain 'ro'",
            input_options,
            "ro" in input_options,
        ),
        _check("output_writable", "write to /out allowed", None, _can_write(Path("/out"))),
        _check(
            "docker_socket_absent",
            "/var/run/docker.sock absent",
            None,
            not Path("/var/run/docker.sock").exists(),
        ),
    ]


def probe_host_access(args: dict[str, Any]) -> list[dict[str, Any]]:
    sentinel = Path(args.get("sentinel") or DEFAULT_SENTINEL)
    sentinel_readable = _can_read(sentinel)
    traversal_target = Path("/in") / ".." / sentinel.name
    traversal_readable = _can_read(traversal_target)
    # Positive control: the same read mechanism must succeed on a known-mounted
    # file, so a broken probe cannot make the sentinel check pass vacuously.
    control_readable = _can_read(Path("/in/request.json"))
    credential_env = sorted(
        name
        for name in os.environ
        if any(marker in name.upper() for marker in CREDENTIAL_MARKERS)
    )
    mounts = _mount_inventory()
    return [
        _check(
            "read_control_ok",
            "positive control: /in/request.json readable",
            control_readable,
            control_readable,
        ),
        _check("sentinel_unreadable", "unmounted sentinel not readable", str(sentinel), not sentinel_readable),
        _check(
            "traversal_confined",
            "/in/../<sentinel> not readable",
            str(traversal_target),
            not traversal_readable,
        ),
        _check("no_credential_env", "no credential env vars", credential_env, not credential_env),
        _check(
            "docker_socket_absent",
            "/var/run/docker.sock absent",
            None,
            not Path("/var/run/docker.sock").exists(),
        ),
        _check("mount_inventory", "container mount list recorded", mounts, bool(mounts)),
    ]


def probe_network(_args: dict[str, Any]) -> list[dict[str, Any]]:
    targets = (("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53))
    connect_results: dict[str, str] = {}
    for host, port in targets:
        key = f"{host}:{port}"
        try:
            with socket.create_connection((host, port), timeout=2):
                connect_results[key] = "connected"
        except OSError as error:
            connect_results[key] = type(error).__name__

    names = ("example.com", "one.one.one.one")
    dns_results: dict[str, str] = {}
    for name in names:
        try:
            socket.getaddrinfo(name, 80)
            dns_results[name] = "resolved"
        except OSError as error:
            dns_results[name] = type(error).__name__

    loopback_ok = False
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        connection, _address = server.accept()
        client.close()
        connection.close()
        server.close()
        loopback_ok = True
    except OSError:
        loopback_ok = False

    external_blocked = all(value != "connected" for value in connect_results.values())
    dns_blocked = all(value != "resolved" for value in dns_results.values())
    return [
        _check("external_blocked", "all external connects fail", connect_results, external_blocked),
        _check("dns_blocked", "all DNS lookups fail", dns_results, dns_blocked),
        _check("loopback_ok", "loopback connect succeeds", loopback_ok, loopback_ok),
    ]


def _read_cgroup_value(name: str) -> str | None:
    try:
        return Path(f"/sys/fs/cgroup/{name}").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _statvfs(path: str) -> dict[str, Any] | None:
    try:
        stats = os.statvfs(path)
    except OSError:
        return None
    return {
        "path": path,
        "total_bytes": stats.f_blocks * stats.f_frsize,
        "free_bytes": stats.f_bavail * stats.f_frsize,
    }


def probe_resources(_args: dict[str, Any]) -> list[dict[str, Any]]:
    memory_max = _read_cgroup_value("memory.max")
    memory_swap_max = _read_cgroup_value("memory.swap.max")
    pids_max = _read_cgroup_value("pids.max")
    cpu_max = _read_cgroup_value("cpu.max")
    filesystems = {path: _statvfs(path) for path in ("/tmp", "/work", "/dev/shm", "/out")}
    workspace_ok = all(
        filesystems[path] is not None and filesystems[path]["total_bytes"] > 0
        for path in ("/tmp", "/work")
    )
    shm_ok = (
        filesystems["/dev/shm"] is not None
        and filesystems["/dev/shm"]["total_bytes"] > 0
    )
    return [
        _check(
            "cgroup_limits_readable",
            "memory.max and pids.max are numeric (not the literal 'max')",
            {
                "memory.max": memory_max,
                "memory.swap.max": memory_swap_max,
                "pids.max": pids_max,
                "cpu.max": cpu_max,
            },
            _is_numeric(memory_max) and _is_numeric(pids_max),
        ),
        _check(
            "workspace_bounded",
            "/tmp and /work have positive bounded totals",
            {path: filesystems[path] for path in ("/tmp", "/work")},
            workspace_ok,
        ),
        _check(
            "shm_bounded",
            "/dev/shm has a positive bounded total",
            filesystems["/dev/shm"],
            shm_ok,
        ),
    ]


def probe_dependencies(_args: dict[str, Any]) -> list[dict[str, Any]]:
    modules = (
        "requests",
        "pandas",
        "bs4",
        "numpy",
        "matplotlib",
        "seaborn",
        "PIL",
        "cgi",
        "chardet",
        "lxml",
        "flask",
        "flask_restful",
        "psutil",
        "rsa",
        "nltk",
        "pyquery",
        "sklearn",
        "faker",
        "requests_mock",
    )
    import importlib

    missing: list[str] = []
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    return [
        _check(
            "third_party_imports",
            "all declared runtime imports succeed",
            {"missing": missing},
            not missing,
        ),
        _check("python_version", "3.14.x", platform.python_version(), platform.python_version().startswith("3.14")),
    ]


def probe_hang_after_result(args: dict[str, Any]) -> list[dict[str, Any]]:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    checks = [_check("payload_written", "payload fully written", True, True)]
    _write_json(args["payload"], {"schema_version": "1", "probe_id": "hang_after_result", "checks": checks})
    while True:
        time.sleep(1)


def probe_hang_ignoring_sigterm(args: dict[str, Any]) -> list[dict[str, Any]]:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    grandchild = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)",
        ],
        start_new_session=True,
    )
    checks = [
        _check("grandchild_started", "grandchild in a new session", grandchild.pid, grandchild.poll() is None)
    ]
    _write_json(
        args["payload"],
        {"schema_version": "1", "probe_id": "hang_ignoring_sigterm", "checks": checks},
    )
    while True:
        time.sleep(1)


def probe_partial_payload(args: dict[str, Any]) -> list[dict[str, Any]]:
    # Write deliberately truncated JSON and exit immediately so the runner does
    # not replace it with a well-formed payload.
    _atomic_write(
        args["payload"],
        '{"schema_version": "1", "probe_id": "partial_payload", "checks": [',
    )
    raise SystemExit(0)


PROBES = {
    "identity": probe_identity,
    "host_access": probe_host_access,
    "network": probe_network,
    "resources": probe_resources,
    "dependencies": probe_dependencies,
    "hang_after_result": probe_hang_after_result,
    "hang_ignoring_sigterm": probe_hang_ignoring_sigterm,
    "partial_payload": probe_partial_payload,
}


def _write_raw_envelope(args: dict[str, Any]) -> int:
    request: dict[str, Any] = {}
    try:
        request = json.loads(Path(args["request"]).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        request = {}
    envelope = {
        "schema_version": "1",
        "sample_id": "forged-sample-id",
        "attempt_id": request.get("attempt_id"),
        "stage": request.get("stage"),
        "result_schema": request.get("result_schema"),
        "nonce": args.get("nonce"),
        "supervisor": {"exit_code": 0, "timed_out": False},
        "payload_valid": True,
        "payload": {"probe_id": args.get("probe"), "checks": []},
        "payload_error": None,
    }
    _write_json(args["result"], envelope)
    return 0


def _parse_args(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {
        "probe": None,
        "payload": None,
        "raw_envelope": False,
        "request": None,
        "result": None,
        "sentinel": None,
        "nonce": None,
    }
    index = 0
    flags = {"--raw-envelope": "raw_envelope"}
    valued = {
        "--probe": "probe",
        "--payload": "payload",
        "--request": "request",
        "--result": "result",
        "--sentinel": "sentinel",
        "--nonce": "nonce",
    }
    while index < len(argv):
        token = argv[index]
        key, separator, inline = token.partition("=")
        if key in flags:
            options[flags[key]] = True
            index += 1
            continue
        if key not in valued:
            raise ValueError(f"unknown option: {token!r}")
        if separator:
            options[valued[key]] = inline
            index += 1
        else:
            if index + 1 >= len(argv):
                raise ValueError(f"option {key!r} requires a value")
            options[valued[key]] = argv[index + 1]
            index += 2
    return options


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        options = _parse_args(argv)
    except ValueError as error:
        print(f"probe error: {error}", file=sys.stderr)
        return 2

    if options["raw_envelope"]:
        if not options["result"]:
            print("probe error: --raw-envelope requires --result", file=sys.stderr)
            return 2
        return _write_raw_envelope(options)

    probe_id = options["probe"]
    payload_path = options["payload"]
    if probe_id not in PROBES:
        print(f"probe error: unknown probe {probe_id!r}", file=sys.stderr)
        return 2
    if not payload_path:
        print("probe error: --payload is required", file=sys.stderr)
        return 2
    options["payload"] = payload_path
    result = PROBES[probe_id](options)
    _write_json(
        payload_path,
        {"schema_version": "1", "probe_id": probe_id, "checks": result, "probe_error": None},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
