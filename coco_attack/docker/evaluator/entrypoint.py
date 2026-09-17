#!/usr/bin/env python3
"""Container-side supervisor for the CoCo-Attack evaluation image.

The host mounts a staging directory read-only at ``/in`` (containing
``request.json``) and a per-attempt writable directory at ``/out``.  This
process is the container's PID 1: it runs a registered child entry in its own
session/process group, forwards ``SIGTERM`` and escalates to ``SIGKILL`` after a
grace period, then publishes a structured *result envelope* atomically.

The envelope carries the request identity at the top level so the host
supervisor can reject a mismatched or tampered result.  It also embeds the
child's own payload (read from ``/out/payload.json``) so that a half-written or
missing payload stays distinguishable from a complete one.

Only ``/out`` and tmpfs are writable; the root file system is read-only and the
process runs as a non-root user.  No network access is required.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_SUPERVISOR_ERROR = 70

DEFAULT_OUT_DIR = "/out"
DEFAULT_GRACE_SECONDS = 2.0
DEFAULT_MAX_PAYLOAD_BYTES = 1_048_576
DEFAULT_ENVELOPE_MAX_BYTES = 2_097_152
POLL_SECONDS = 0.02


def _split_child_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        raise ValueError("missing '--' separator before the child argv")
    index = argv.index("--")
    return argv[:index], argv[index + 1 :]


def _parse_options(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {
        "request": None,
        "result": None,
        "out_dir": DEFAULT_OUT_DIR,
        "grace": DEFAULT_GRACE_SECONDS,
        "max_payload_bytes": DEFAULT_MAX_PAYLOAD_BYTES,
        "envelope_max_bytes": DEFAULT_ENVELOPE_MAX_BYTES,
        "nonce": None,
    }
    index = 0
    value_options = {
        "--request": ("request", str),
        "--result": ("result", str),
        "--out-dir": ("out_dir", str),
        "--grace": ("grace", float),
        "--max-payload-bytes": ("max_payload_bytes", int),
        "--envelope-max-bytes": ("envelope_max_bytes", int),
        "--nonce": ("nonce", str),
    }
    while index < len(argv):
        token = argv[index]
        key, separator, inline = token.partition("=")
        if key not in value_options:
            raise ValueError(f"unknown option: {token!r}")
        name, caster = value_options[key]
        if separator:
            raw = inline
            index += 1
        else:
            if index + 1 >= len(argv):
                raise ValueError(f"option {key!r} requires a value")
            raw = argv[index + 1]
            index += 2
        options[name] = caster(raw)
    if not options["request"] or not options["result"]:
        raise ValueError("--request and --result are required")
    if options["grace"] < 0:
        raise ValueError("--grace must be >= 0")
    if options["max_payload_bytes"] <= 0 or options["envelope_max_bytes"] <= 0:
        raise ValueError("byte limits must be positive")
    return options


def _read_request_identity(request_path: str | None) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "sample_id": None,
        "attempt_id": None,
        "stage": None,
        "result_schema": None,
    }
    if not request_path:
        return identity
    try:
        payload = json.loads(Path(request_path).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return identity
    if isinstance(payload, dict):
        for name in identity:
            value = payload.get(name)
            if isinstance(value, str):
                identity[name] = value
    return identity


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    data = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # The host operator does not own this file; make the published artifact
        # readable outside the container's uid.
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _relax_permissions(directory: Path) -> None:
    """Make everything the child wrote host-readable (best effort)."""

    for root, dirs, files in os.walk(directory):
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), 0o755)
            except OSError:
                pass
        for name in files:
            try:
                os.chmod(os.path.join(root, name), 0o644)
            except OSError:
                pass


def _read_payload(out_dir: Path, max_payload_bytes: int) -> tuple[Any, bool, str | None]:
    path = out_dir / "payload.json"
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        return None, False, "missing"
    except OSError:
        return None, False, "unreadable"
    if not os.path.isfile(path) or os.path.islink(path):
        return None, False, "not_regular_file"
    if file_stat.st_size > max_payload_bytes:
        return None, False, "too_large"
    try:
        raw = path.read_bytes()
    except OSError:
        return None, False, "unreadable"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, False, "invalid_json"
    if not isinstance(payload, dict):
        return None, False, "not_object"
    return payload, True, None


def _kill_process_group(pid: int, signum: int) -> bool:
    try:
        os.killpg(pid, signum)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _run_child(
    child_argv: list[str], grace_seconds: float
) -> tuple[int | None, bool, bool, bool, float]:
    """Run the child and return ``(exit_code, timed_out, forwarded, escalated, duration)``."""

    stop_requested = False

    def _handle_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    start = time.monotonic()
    child = subprocess.Popen(child_argv, start_new_session=True)
    forwarded = False
    escalated = False
    timed_out = False
    grace_deadline = 0.0
    exit_code: int | None = None

    while True:
        exit_code = child.poll()
        if exit_code is not None:
            break
        if stop_requested:
            if not forwarded:
                _kill_process_group(child.pid, signal.SIGTERM)
                forwarded = True
                grace_deadline = time.monotonic() + max(0.0, grace_seconds)
            elif time.monotonic() >= grace_deadline:
                _kill_process_group(child.pid, signal.SIGKILL)
                escalated = True
                timed_out = True
        time.sleep(POLL_SECONDS)

    try:
        child.wait(timeout=5.0)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        _kill_process_group(child.pid, signal.SIGKILL)
        child.wait()
        escalated = True
        timed_out = True

    return exit_code, timed_out, forwarded, escalated, time.monotonic() - start


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        head, child_argv = _split_child_argv(argv)
    except ValueError as error:
        print(f"entrypoint error: {error}", file=sys.stderr)
        return EXIT_SUPERVISOR_ERROR
    if not child_argv:
        print("entrypoint error: empty child argv", file=sys.stderr)
        return EXIT_SUPERVISOR_ERROR

    try:
        options = _parse_options(head)
    except ValueError as error:
        print(f"entrypoint error: {error}", file=sys.stderr)
        return EXIT_SUPERVISOR_ERROR

    out_dir = Path(options["out_dir"])
    result_path = Path(options["result"])
    identity = _read_request_identity(options["request"])

    exit_code, timed_out, forwarded, escalated, duration = _run_child(
        child_argv, options["grace"]
    )

    payload, payload_valid, payload_error = _read_payload(
        out_dir, int(options["max_payload_bytes"])
    )
    envelope: dict[str, Any] = {
        "schema_version": "1",
        **identity,
        "nonce": options.get("nonce"),
        "supervisor": {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "sigterm_forwarded": forwarded,
            "sigkill_escalated": escalated,
            "duration_seconds": duration,
        },
        "child_argv": child_argv,
        "payload_valid": payload_valid,
        "payload": payload,
        "payload_error": payload_error,
    }
    encoded = json.dumps(
        envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > int(options["envelope_max_bytes"]):
        envelope["payload"] = None
        envelope["payload_valid"] = False
        envelope["payload_error"] = "too_large"

    try:
        _atomic_write_json(result_path, envelope)
    except OSError as error:
        print(f"entrypoint error: cannot write result: {error}", file=sys.stderr)
        return EXIT_SUPERVISOR_ERROR
    _relax_permissions(out_dir)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
