#!/usr/bin/env python3
"""Container-side functional test harness (stage 02, task 03).

Assembles ``solution + "\\n" + tests`` in a single ``__test__`` module, loads the
task's ``TestCases`` via ``unittest`` and runs the full suite with failfast off.
The candidate and tests run entirely inside the isolation container; the host
never imports or executes generated code.

Output is a structured payload that the host validates before it can become a
cacheable functional result.  The harness never decides a pass from a printed
"OK" or candidate-authored JSON.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import multiprocessing
import os
import signal
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

# Python 3.14 changed the Linux default multiprocessing start method from ``fork``
# to ``forkserver``.  The harness executes the candidate + tests as a synthetic
# ``__test__`` module that exists only in this process's ``sys.modules``; a
# forkserver worker cannot unpickle a function defined there and dies with
# ``ModuleNotFoundError: No module named '__test__'``, hanging the pool until the
# wall-clock timeout (observed on BigCodeBench/205).  Force ``fork`` so workers
# inherit the loaded module, matching pre-3.14 semantics.
try:
    multiprocessing.set_start_method("fork", force=True)
    _START_METHOD_ERROR: str | None = None
except (RuntimeError, ValueError) as _error:  # already set or unavailable
    _START_METHOD_ERROR = f"{type(_error).__name__}: {_error}"

PAYLOAD_SCHEMA = "functional-payload-v1"
HARNESS_VERSION = "functional-harness-v4"
MAX_DETAILS = 10
MAX_DETAIL_CHARS = 800


class _CandidateTimeout(KeyboardInterrupt):
    """Raised by the SIGALRM handler when a candidate exceeds its budget.

    ``unittest`` re-raises ``KeyboardInterrupt`` from a running test instead of
    recording it as a test error, so the deadline reaches the harness.
    """


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
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


def _parse(argv: list[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    names = {
        "--solution": "solution",
        "--tests": "tests",
        "--request": "request",
        "--payload": "payload",
    }
    index = 0
    while index < len(argv):
        token = argv[index]
        key, sep, inline = token.partition("=")
        if key not in names:
            raise ValueError(f"unknown option: {token!r}")
        if sep:
            options[names[key]] = inline
            index += 1
        else:
            options[names[key]] = argv[index + 1]
            index += 2
    for required in ("solution", "tests", "request", "payload"):
        if required not in options:
            raise ValueError(f"missing --{required}")
    return options


def _compiles(text: str) -> tuple[bool, str | None]:
    try:
        compile(text, "__solution__.py", "exec")
    except SyntaxError as error:
        return False, f"{error.msg} (line {error.lineno})"
    except ValueError as error:
        return False, str(error)
    return True, None


def _run(options: dict[str, str]) -> dict[str, Any]:
    solution_text = Path(options["solution"]).read_bytes().decode("utf-8", errors="replace")
    tests_text = Path(options["tests"]).read_bytes().decode("utf-8", errors="replace")
    request = json.loads(Path(options["request"]).read_bytes().decode("utf-8"))

    code_sha256 = _sha256_bytes(solution_text.encode("utf-8"))
    tests_sha256 = _sha256_bytes(tests_text.encode("utf-8"))
    entry_point = request.get("entry_point", "")

    load: dict[str, Any] = {
        "solution_compiled": False,
        "solution_error": None,
        "entry_present": False,
        "tests_compiled": False,
        "tests_error": None,
        "loader_error": None,
        "tests_discovered": 0,
    }
    run: dict[str, Any] = {
        "tests_run": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
        "suite_completed": False,
        "failure_stage": None,
        "candidate_timeout": False,
    }
    details: list[dict[str, Any]] = []

    solution_ok, solution_error = _compiles(solution_text)
    tests_ok, tests_error = _compiles(tests_text)
    load["solution_compiled"] = solution_ok
    load["solution_error"] = solution_error
    load["tests_compiled"] = tests_ok
    load["tests_error"] = tests_error

    full_code = solution_text + "\n" + tests_text
    try:
        compiled = compile(full_code, "__test__.py", "exec")
    except SyntaxError:
        run["failure_stage"] = "compile" if not solution_ok else "tests_compile"
        return _payload(request, code_sha256, tests_sha256, load, run, details)

    module = types.ModuleType("__test__")
    module_file = Path(tempfile.gettempdir()) / "__test__.py"
    if _START_METHOD_ERROR is not None or multiprocessing.get_start_method() != "fork":
        # Fallback when ``fork`` is unavailable: make ``__test__`` importable from
        # disk so spawn/forkserver workers can unpickle functions defined in it.
        try:
            module_file.write_text(full_code, encoding="utf-8")
            if str(module_file.parent) not in sys.path:
                sys.path.insert(0, str(module_file.parent))
        except OSError:
            module_file = Path("__test__.py")
    module.__dict__.update(
        {
            "__builtins__": builtins,
            "__file__": str(module_file),
            "__package__": None,
            "__doc__": None,
        }
    )
    timeout = request.get("candidate_timeout_seconds")
    timeout_active = (
        isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and timeout > 0
    )

    def _on_alarm(signum, frame):  # noqa: ANN001 - signal signature
        raise _CandidateTimeout()

    def _arm_timeout() -> object | None:
        if not timeout_active:
            return None
        previous = signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, float(timeout))
        return previous

    def _disarm_timeout(previous: object | None) -> None:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)  # type: ignore[arg-type]

    # The candidate timeout must also cover module load/exec: a candidate that
    # calls a blocking function at module level (e.g. ``serve_forever()``) would
    # otherwise escape the alarm and hang until the outer wall-clock kill, which
    # produces no payload and is recorded as unresolved (fix A).
    previous_handler = _arm_timeout()
    try:
        exec(compiled, module.__dict__)  # noqa: S102 - isolated container, by design
        sys.modules["__test__"] = module
    except _CandidateTimeout:
        run["candidate_timeout"] = True
        run["failure_stage"] = "exec"
        load["loader_error"] = "candidate_timeout_at_exec"
        return _payload(request, code_sha256, tests_sha256, load, run, details)
    except ImportError as error:  # candidate/test import failure at load time
        load["missing_module"] = getattr(error, "name", None)
        load["loader_error"] = f"{type(error).__name__}: {error}"
        run["failure_stage"] = "exec"
        return _payload(request, code_sha256, tests_sha256, load, run, details)
    except BaseException as error:  # noqa: BLE001 - candidate/test load failure
        load["loader_error"] = f"{type(error).__name__}: {error}"
        run["failure_stage"] = "exec"
        return _payload(request, code_sha256, tests_sha256, load, run, details)
    finally:
        _disarm_timeout(previous_handler)

    load["entry_present"] = callable(module.__dict__.get(entry_point))
    try:
        test_cases = module.__dict__["TestCases"]
    except KeyError:
        load["loader_error"] = "TestCases_missing"
        run["failure_stage"] = "load"
        return _payload(request, code_sha256, tests_sha256, load, run, details)

    try:
        suite = unittest.TestLoader().loadTestsFromTestCase(test_cases)
    except BaseException as error:  # noqa: BLE001
        load["loader_error"] = f"loader:{type(error).__name__}: {error}"
        run["failure_stage"] = "load"
        return _payload(request, code_sha256, tests_sha256, load, run, details)

    load["tests_discovered"] = int(suite.countTestCases())
    result = unittest.TestResult()
    previous_handler = _arm_timeout()
    try:
        suite.run(result)
        run["suite_completed"] = True
    except _CandidateTimeout:
        run["candidate_timeout"] = True
        run["suite_completed"] = False
        run["failure_stage"] = "run"
    except BaseException as error:  # noqa: BLE001 - harness-level failure
        run["suite_completed"] = False
        run["failure_stage"] = "run"
        load["loader_error"] = f"run:{type(error).__name__}: {error}"
    finally:
        _disarm_timeout(previous_handler)
    run["tests_run"] = int(result.testsRun)
    run["failures"] = len(result.failures)
    run["errors"] = len(result.errors)
    run["skipped"] = len(result.skipped)
    run["expected_failures"] = len(getattr(result, "expectedFailures", []))
    run["unexpected_successes"] = len(getattr(result, "unexpectedSuccesses", []))
    for test, trace in list(result.failures)[:MAX_DETAILS]:
        details.append({"test": test.id().split(".")[-1], "status": "failure", "message": trace[-MAX_DETAIL_CHARS:]})
    for test, trace in list(result.errors)[:MAX_DETAILS]:
        details.append({"test": test.id().split(".")[-1], "status": "error", "message": trace[-MAX_DETAIL_CHARS:]})
    return _payload(request, code_sha256, tests_sha256, load, run, details)


def _payload(
    request: dict[str, Any],
    code_sha256: str,
    tests_sha256: str,
    load: dict[str, Any],
    run: dict[str, Any],
    details: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "functional_schema": PAYLOAD_SCHEMA,
        "harness_version": HARNESS_VERSION,
        "sample_id": request.get("sample_id"),
        "attempt_id": request.get("attempt_id"),
        "entry_point": request.get("entry_point"),
        "code_sha256": code_sha256,
        "tests_sha256": tests_sha256,
        "load": load,
        "run": run,
        "test_details": details,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        options = _parse(list(argv if argv is not None else sys.argv[1:]))
    except ValueError as error:
        print(f"functional_runner error: {error}", file=sys.stderr)
        return 2
    try:
        payload = _run(options)
    except BaseException as error:  # noqa: BLE001 - always publish a diagnosis
        payload = {
            "schema_version": "1",
            "functional_schema": PAYLOAD_SCHEMA,
            "harness_version": HARNESS_VERSION,
            "sample_id": None,
            "attempt_id": None,
            "entry_point": None,
            "code_sha256": None,
            "tests_sha256": None,
            "load": {"solution_compiled": False, "solution_error": None, "entry_present": False,
                     "tests_compiled": False, "tests_error": None, "loader_error": f"harness:{type(error).__name__}: {error}",
                     "missing_module": None, "tests_discovered": 0},
            "run": {"tests_run": 0, "failures": 0, "errors": 0, "skipped": 0, "expected_failures": 0,
                    "unexpected_successes": 0, "suite_completed": False, "failure_stage": "harness",
                    "candidate_timeout": False},
            "test_details": [],
        }
    _atomic_write_json(Path(options["payload"]), payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
