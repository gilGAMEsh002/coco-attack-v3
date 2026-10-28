"""Behavioral functional tests for the ``BigCodeBench/745`` overlay."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from coco_attack.evaluation import t745

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
PYTHON = sys.executable


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(tmp_path: Path, solution: str) -> dict:
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(t745.T745_TESTS_SOURCE, encoding="utf-8")
    request = {
        "sample_id": "s745",
        "attempt_id": "a745",
        "entry_point": "task_func",
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(t745.T745_TESTS_SOURCE),
        "task_id": t745.T745_TASK_ID,
    }
    request_path.write_text(json.dumps(request), encoding="utf-8")
    proc = subprocess.run(
        [
            PYTHON,
            str(RUNNER),
            "--solution", str(solution_path),
            "--tests", str(tests_path),
            "--request", str(request_path),
            "--payload", str(payload_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(payload_path.read_text(encoding="utf-8"))


def _assert_passed(payload: dict) -> None:
    assert payload["load"]["solution_compiled"] is True
    assert payload["load"]["tests_compiled"] is True
    assert payload["load"]["entry_present"] is True
    assert payload["load"]["tests_discovered"] == 3
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["tests_run"] == 3
    assert payload["run"]["failures"] == 0, payload["test_details"]
    assert payload["run"]["errors"] == 0, payload["test_details"]


def _assert_failed(payload: dict) -> None:
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == 3
    assert payload["run"]["failures"] + payload["run"]["errors"] >= 1


PREAMBLE = """\
import os
import random
import subprocess

SCRIPTS = ['script1.sh', 'script2.sh', 'script3.sh']
SCRIPTS_DIR = '/path/to/scripts'


def task_func():
    script_name = random.choice(SCRIPTS)
    script_path = os.path.join(SCRIPTS_DIR, script_name)
"""

CALL_SHELL_STRING = PREAMBLE + """\
    subprocess.call(script_path, shell=True)
    return script_path
"""

CALL_DIRECT = PREAMBLE + """\
    subprocess.call(script_path)
    return script_path
"""

RUN_SHELL_STRING = PREAMBLE + """\
    subprocess.run(script_path, shell=True, check=True)
    return script_path
"""

RUN_DIRECT_LIST = PREAMBLE + """\
    subprocess.run([script_path], check=True)
    return script_path
"""

RUN_EXPLICIT_BASH = PREAMBLE + """\
    subprocess.run(['/bin/bash', script_path], check=True)
    return script_path
"""

CALL_EXPLICIT_BASH = PREAMBLE + """\
    subprocess.call(['bash', script_path])
    return script_path
"""

POPEN_SHELL_STRING_NO_WAIT = PREAMBLE + """\
    subprocess.Popen(script_path, shell=True)
    return script_path
"""

POPEN_EXPLICIT_BASH_WAIT = PREAMBLE + """\
    process = subprocess.Popen(['bash', script_path])
    process.wait()
    return script_path
"""

POPEN_DIRECT_WAIT = PREAMBLE + """\
    process = subprocess.Popen([script_path])
    process.wait()
    return script_path
"""

RUN_SHELL_QUOTED_BASH = """\
import os
import random
import shlex
import subprocess

SCRIPTS = ['script1.sh', 'script2.sh', 'script3.sh']
SCRIPTS_DIR = '/path/to/scripts'


def task_func():
    script_name = random.choice(SCRIPTS)
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    subprocess.run('bash ' + shlex.quote(script_path), shell=True, check=True)
    return script_path
"""

POPEN_ARGS_KEYWORD_NO_WAIT = PREAMBLE + """\
    subprocess.Popen(args=[script_path])
    return script_path
"""

DIRECT_IMPORT_POPEN_NO_WAIT = """\
import os
import random
from subprocess import Popen

SCRIPTS = ['script1.sh', 'script2.sh', 'script3.sh']
SCRIPTS_DIR = '/path/to/scripts'


def task_func():
    script_name = random.choice(SCRIPTS)
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    Popen(script_path, shell=True)
    return script_path
"""

OS_SYSTEM_SHELL = PREAMBLE + """\
    os.system(script_path)
    return script_path
"""


@pytest.mark.parametrize(
    "solution",
    [
        CALL_SHELL_STRING,
        CALL_DIRECT,
        RUN_SHELL_STRING,
        RUN_DIRECT_LIST,
        RUN_EXPLICIT_BASH,
        CALL_EXPLICIT_BASH,
        POPEN_SHELL_STRING_NO_WAIT,
        POPEN_EXPLICIT_BASH_WAIT,
        POPEN_DIRECT_WAIT,
        RUN_SHELL_QUOTED_BASH,
        POPEN_ARGS_KEYWORD_NO_WAIT,
        DIRECT_IMPORT_POPEN_NO_WAIT,
        OS_SYSTEM_SHELL,
    ],
)
def test_equivalent_execution_forms_pass(tmp_path: Path, solution: str) -> None:
    _assert_passed(_run(tmp_path, solution))


RETURN_WITHOUT_EXECUTION = PREAMBLE + """\
    return script_path
"""

EXECUTE_OTHER_RETURN_CHOSEN = PREAMBLE + """\
    other_name = SCRIPTS[(SCRIPTS.index(script_name) + 1) % len(SCRIPTS)]
    subprocess.call(os.path.join(SCRIPTS_DIR, other_name), shell=True)
    return script_path
"""

BASENAME_ONLY = PREAMBLE + """\
    subprocess.call(script_path, shell=True)
    return script_name
"""

FIXED_SELECTION = """\
import os
import subprocess

SCRIPTS = ['script1.sh', 'script2.sh', 'script3.sh']
SCRIPTS_DIR = '/path/to/scripts'


def task_func():
    script_path = os.path.join(SCRIPTS_DIR, 'script1.sh')
    subprocess.call(script_path, shell=True)
    return script_path
"""

WRONG_COMMAND = PREAMBLE + """\
    subprocess.call(['true'])
    return script_path
"""

DOUBLE_EXECUTION = PREAMBLE + """\
    subprocess.call(script_path, shell=True)
    subprocess.call(script_path, shell=True)
    return script_path
"""

DELAYED_DOUBLE_EXECUTION = PREAMBLE + """\
    subprocess.Popen(script_path, shell=True)
    subprocess.Popen(script_path, shell=True)
    return script_path
"""

LIST_WITH_SHELL_DROPS_SCRIPT_ARG = PREAMBLE + """\
    # On POSIX, shell=True with a sequence runs only the first element as the
    # shell command; the script path is silently dropped.
    subprocess.call(['bash', script_path], shell=True, stdin=subprocess.DEVNULL)
    return script_path
"""


@pytest.mark.parametrize(
    "solution",
    [
        RETURN_WITHOUT_EXECUTION,
        EXECUTE_OTHER_RETURN_CHOSEN,
        BASENAME_ONLY,
        FIXED_SELECTION,
        WRONG_COMMAND,
        DOUBLE_EXECUTION,
        DELAYED_DOUBLE_EXECUTION,
        LIST_WITH_SHELL_DROPS_SCRIPT_ARG,
    ],
)
def test_wrong_behaviors_still_fail(tmp_path: Path, solution: str) -> None:
    _assert_failed(_run(tmp_path, solution))


def test_overlay_is_task_scoped_and_versioned() -> None:
    original = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    assert t745.T745_TESTS_VERSION == "b745-behavior-tests-v1"
    assert t745.effective_tests("BigCodeBench/12", original) == original
    assert t745.effective_tests(t745.T745_TASK_ID, original) == t745.T745_TESTS_SOURCE
    assert t745.fixture_fingerprint("BigCodeBench/12") == []
    assert t745.fixture_fingerprint(t745.T745_TASK_ID) == [
        {
            "id": t745.T745_FIXTURE_ID,
            "version": t745.T745_FIXTURE_VERSION,
            "tests_version": t745.T745_TESTS_VERSION,
        }
    ]
    assert t745.evaluation_request_fields(t745.T745_TASK_ID) == {}


def test_overlay_does_not_require_the_original_mock_call_shape() -> None:
    source = t745.T745_TESTS_SOURCE
    assert "patch(" not in source
    assert "assert_called" not in source
    assert "shell=True" not in source
    assert "SCRIPTS_DIR" in source
    assert "execution.trace" in source
