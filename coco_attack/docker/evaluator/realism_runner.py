#!/usr/bin/env python3
"""Container-side realism-layer runner (stage 02, task 04).

Builds the reviewed direct-input driver and bundled-test variant for one
sample, runs them through the instrumented dynamic execution, and returns the
raw variant executions plus the task threat model.  The approved verdict
mapping and variant selection stay on the trusted host.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse(argv: list[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    names = {"--request": "request", "--payload": "payload"}
    index = 0
    while index < len(argv):
        key, sep, inline = argv[index].partition("=")
        if key not in names:
            raise ValueError(f"unknown option: {key!r}")
        if sep:
            options[names[key]] = inline
            index += 1
        else:
            options[names[key]] = argv[index + 1]
            index += 2
    for required in ("request", "payload"):
        if required not in options:
            raise ValueError(f"missing --{required}")
    return options


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
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


def main(argv: list[str] | None = None) -> int:
    options = _parse(list(argv if argv is not None else sys.argv[1:]))
    request = json.loads(Path(options["request"]).read_bytes().decode("utf-8"))
    import oracles.dynamic.runner as dynamic
    from oracles.dynamic.runner import _OptionalDependencyModule

    dynamic._install_optional_dependency_stubs()
    stubs = sorted(
        name for name, module in sys.modules.items() if isinstance(module, _OptionalDependencyModule)
    )
    from oracles.security_realism.attack_tests import build_attack_test
    from oracles.security_realism.direct_drivers import build_direct_driver
    from oracles.security_realism.task_catalog import get_task_threat_model

    oracle_id = request["oracle_id"]
    task_id = request["task_id"]
    code = request["code"]
    test = request["test"]
    model = get_task_threat_model(oracle_id, task_id)

    jobs: list[dict[str, Any]] = []
    driver = build_direct_driver(task_id, oracle_id, code)
    if driver:
        jobs.append({"code": code, "test_code": driver, "oracle_id": oracle_id, "security_driver": "direct_input"})
    jobs.append(
        {
            "code": code,
            "test_code": build_attack_test(test, oracle_id),
            "oracle_id": oracle_id,
            "security_driver": "bundled_input_variant",
        }
    )
    executions = dynamic.evaluate_many(jobs, timeout=float(request.get("timeout", 20)), parallel=1)
    variants = [
        {
            "security_driver": job["security_driver"],
            "execution": {
                "execution_status": execution.get("execution_status"),
                "suite_completed": execution.get("suite_completed"),
                "tests_run": execution.get("tests_run"),
                "tests_passed": execution.get("tests_passed"),
                "instrumented_sites": execution.get("instrumented_sites"),
                "events": (execution.get("events") or [])[:200],
                "issues": execution.get("issues"),
                "error": execution.get("error"),
            },
        }
        for job, execution in zip(jobs, executions)
    ]
    payload = {
        "schema_version": "1",
        "layer": "realism",
        "sample_id": request.get("sample_id"),
        "attempt_id": request.get("attempt_id"),
        "oracle_id": oracle_id,
        "task_id": task_id,
        "code_sha256": _sha(code),
        "test_sha256": _sha(test),
        "threat_model": {
            "oracle_id": model.oracle_id,
            "task_id": model.task_id,
            "source_kind": model.source_kind,
            "attacker_controlled": model.attacker_controlled,
            "source_description": model.source_description,
            "cwe078_sequence_first_element_controlled": model.cwe078_sequence_first_element_controlled,
        },
        "stubs": stubs,
        "variants": variants,
    }
    _atomic_write(Path(options["payload"]), payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
