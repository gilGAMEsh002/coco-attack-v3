#!/usr/bin/env python3
"""Container-side restricted search caller (subtask 02, plan section 5.2).

Runs inside the evaluation container with only the search view mounted read-only
at ``/in/view``.  It reports what the caller can and cannot reach so the host can
build AC-04 evidence: holdout files, cache directories, credentials and the
Docker socket must be absent, and the search view manifest must contain only the
allowed search tasks.

The caller never decides authorization; the host-side dispatcher does.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

IN_DIR = Path("/in")
VIEW_DIR = IN_DIR / "view"

CREDENTIAL_MARKERS = (
    "DMX_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY",
    "AWS_SECRET",
    "PASSWORD",
    "SECRET",
    "CREDENTIAL",
)

FORBIDDEN_PATHS = (
    "/in/holdout.json",
    "/in/view/holdout.json",
    "/in/ledger.jsonl",
    "/in/generations.jsonl",
    "/in/dspy-cache",
    "/dspy-cache",
    "/cache",
    "/root/.dspy_cache",
    "/home/coco/.dspy_cache",
    "/var/run/docker.sock",
)


def _check(name: str, expected: Any, observed: Any, ok: bool) -> dict[str, Any]:
    return {"check": name, "expected": expected, "observed": observed, "ok": bool(ok)}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _parse(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {"payload": None, "request": None, "view": str(VIEW_DIR)}
    index = 0
    while index < len(argv):
        token = argv[index]
        key, sep, inline = token.partition("=")
        names = {"--payload": "payload", "--request": "request", "--view": "view"}
        if key not in names:
            raise ValueError(f"unknown option: {token!r}")
        if sep:
            options[names[key]] = inline
            index += 1
        else:
            options[names[key]] = argv[index + 1]
            index += 2
    return options


def main(argv: list[str] | None = None) -> int:
    options = _parse(list(argv if argv is not None else __import__("sys").argv[1:]))
    if not options["payload"]:
        print("search_client error: --payload is required", file=__import__("sys").stderr)
        return 2
    view_dir = Path(str(options["view"]))
    manifest = _read_json(view_dir / "manifest.json")
    allowed = sorted((manifest or {}).get("allowed_task_ids") or [])

    forbidden_seen = [path for path in FORBIDDEN_PATHS if Path(path).exists()]
    credential_env = sorted(
        name for name in os.environ if any(marker in name.upper() for marker in CREDENTIAL_MARKERS)
    )
    client_request = _read_json(Path(str(options["request"]))) if options.get("request") else None

    checks = [
        _check("view_manifest_readable", "search view manifest is readable", manifest is not None, manifest is not None),
        _check("view_stage_search", "view stage is search", (manifest or {}).get("stage"), (manifest or {}).get("stage") == "search"),
        _check("view_has_allowed_tasks", "at least one allowed task", allowed, bool(allowed)),
        _check("forbidden_paths_absent", "holdout/cache/ledger/socket paths absent", forbidden_seen, not forbidden_seen),
        _check("no_credential_env", "no credential env vars", credential_env, not credential_env),
        _check(
            "client_request_present",
            "structured request is present",
            client_request is not None,
            client_request is not None,
        ),
    ]
    payload = {
        "schema_version": "1",
        "probe_id": "generation_boundary",
        "checks": checks,
        "allowed_task_ids": allowed,
        "client_request": client_request,
        "forbidden_paths_seen": forbidden_seen,
    }
    _atomic_write(Path(str(options["payload"])), payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
