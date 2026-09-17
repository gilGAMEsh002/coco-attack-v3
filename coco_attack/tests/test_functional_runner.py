"""Direct functional harness tests (host subprocess, no Docker)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[1] / "docker" / "evaluator" / "functional_runner.py"
PYTHON = sys.executable


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(
    tmp_path: Path, solution: str, tests: str, entry: str = "task_func",
    candidate_timeout_seconds: float | None = None,
) -> dict:
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(tests, encoding="utf-8")
    request = {
        "sample_id": "s1",
        "attempt_id": "a1",
        "entry_point": entry,
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(tests),
    }
    if candidate_timeout_seconds is not None:
        request["candidate_timeout_seconds"] = candidate_timeout_seconds
    request_path.write_text(json.dumps(request), encoding="utf-8")
    proc = subprocess.run(
        [
            PYTHON, str(RUNNER),
            "--solution", str(solution_path),
            "--tests", str(tests_path),
            "--request", str(request_path),
            "--payload", str(payload_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(payload_path.read_text(encoding="utf-8"))


def test_runner_passing_suite(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def task_func():\n    return 1\n",
        "import unittest\nclass TestCases(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(task_func(), 1)\n",
    )
    assert payload["load"]["solution_compiled"] is True
    assert payload["load"]["entry_present"] is True
    assert payload["load"]["tests_discovered"] == 1
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["tests_run"] == 1
    assert payload["run"]["failures"] == 0


def test_runner_failing_assertion(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def task_func():\n    return 2\n",
        "import unittest\nclass TestCases(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(task_func(), 1)\n",
    )
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["failures"] == 1


def test_runner_candidate_syntax_error(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def task_func(:\n    return 1\n",
        "import unittest\nclass TestCases(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
    )
    assert payload["load"]["solution_compiled"] is False
    assert payload["run"]["failure_stage"] == "compile"


def test_runner_missing_entry(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def other():\n    return 1\n",
        "import unittest\nclass TestCases(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
    )
    assert payload["load"]["entry_present"] is False


def test_runner_tests_syntax_error(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def task_func():\n    return 1\n",
        "import unittest\nclass TestCases(unittest.TestCase:\n",
    )
    assert payload["load"]["tests_compiled"] is False


def test_runner_records_missing_module(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "import definitely_not_installed_module_xyz\n\ndef task_func():\n    return 1\n",
        "import unittest\nclass TestCases(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(task_func(), 1)\n",
    )
    assert payload["run"]["failure_stage"] == "exec"
    assert payload["load"]["missing_module"] == "definitely_not_installed_module_xyz"


def test_runner_candidate_timeout_is_flagged(tmp_path: Path) -> None:
    payload = _run(
        tmp_path,
        "def task_func():\n    return 1\n",
        (
            "import time\nimport unittest\n"
            "class TestCases(unittest.TestCase):\n"
            "    def test_slow(self):\n        time.sleep(5)\n"
        ),
        candidate_timeout_seconds=0.5,
    )
    assert payload["run"]["candidate_timeout"] is True
    assert payload["run"]["suite_completed"] is False
    assert payload["run"]["failure_stage"] == "run"
