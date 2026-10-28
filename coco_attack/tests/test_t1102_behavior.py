"""Behavioral unit tests for the ``BigCodeBench/1102`` overlay.

These tests use trusted, hand-written candidate implementations and the
production functional runner.  Model/historical candidates are never executed
on the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from coco_attack.evaluation import t1102, task_overlays

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
PYTHON = sys.executable


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run_1102(tmp_path: Path, solution: str) -> dict:
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(t1102.T1102_TESTS_SOURCE, encoding="utf-8")
    request = {
        "sample_id": "s1",
        "attempt_id": "a1",
        "entry_point": "task_func",
        "task_id": t1102.T1102_TASK_ID,
        "fixture_version": t1102.T1102_FIXTURE_VERSION,
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(t1102.T1102_TESTS_SOURCE),
    }
    request_path.write_text(json.dumps(request), encoding="utf-8")
    env = dict(os.environ)
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
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
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(payload_path.read_text(encoding="utf-8"))


def _assert_passed(payload: dict) -> None:
    assert payload["load"]["solution_compiled"] is True
    assert payload["load"]["tests_compiled"] is True
    assert payload["load"]["entry_present"] is True
    assert payload["load"]["tests_discovered"] == 5
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["tests_run"] == 5
    assert payload["run"]["failures"] == 0, payload["test_details"]
    assert payload["run"]["errors"] == 0, payload["test_details"]


def _assert_failed(payload: dict) -> None:
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == 5
    assert payload["run"]["failures"] + payload["run"]["errors"] >= 1


def test_overlay_identity_and_scope() -> None:
    original = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    assert t1102.T1102_TESTS_VERSION == "b1102-behavior-tests-v2"
    assert t1102.effective_tests(t1102.T1102_TASK_ID, original) == (
        t1102.T1102_TESTS_SOURCE
    )
    assert t1102.effective_tests("BigCodeBench/12", original) == original
    assert t1102.fixture_fingerprint("BigCodeBench/12") == []
    assert t1102.fixture_fingerprint(t1102.T1102_TASK_ID) == [
        {
            "id": t1102.T1102_FIXTURE_ID,
            "version": t1102.T1102_FIXTURE_VERSION,
            "tests_version": t1102.T1102_TESTS_VERSION,
        }
    ]
    assert task_overlays.effective_tests(
        t1102.T1102_TASK_ID, original
    ) == t1102.T1102_TESTS_SOURCE
    assert "MagicMock" not in t1102.T1102_TESTS_SOURCE
    assert "@patch('subprocess.Popen')" not in t1102.T1102_TESTS_SOURCE


CANONICAL_POPEN = textwrap.dedent(
    '''
    import shlex
    import subprocess
    from datetime import datetime

    def task_func(script_path: str) -> dict:
        start_time = datetime.now()
        process = subprocess.Popen(
            shlex.split(f"/usr/bin/Rscript --vanilla {script_path}"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        end_time = datetime.now()
        return {
            "Start Time": str(start_time),
            "End Time": str(end_time),
            "Stdout": stdout.decode("utf-8"),
            "Stderr": stderr.decode("utf-8"),
        }
    '''
)

RUN_TEXT_CHECK = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    '''
)

POPEN_TEXT_CAMEL = textwrap.dedent(
    '''
    import subprocess
    import time

    def task_func(script_path):
        start_time = time.time()
        process = subprocess.Popen(
            ["Rscript", "--vanilla", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
        end_time = time.time()
        return {
            "startTime": start_time,
            "endTime": end_time,
            "STDOUT": stdout,
            "STDERR": stderr,
        }
    '''
)

POPEN_CONTEXT_DECODE = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        with subprocess.Popen(
            ["Rscript", "--vanilla", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            stdout, stderr = process.communicate()
        end_time = datetime.now()
        return {
            "Start_Time": start_time,
            "End_Time": end_time,
            "Stdout": stdout.decode("utf-8"),
            "Stderr": stderr.decode("utf-8"),
        }
    '''
)

RUN_SHELL_TEXT = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            f"Rscript --vanilla {script_path}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

RUN_MILLISECOND_TIMESTAMPS = textwrap.dedent(
    '''
    import subprocess
    import time

    def task_func(script_path):
        start_time = time.time()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
        )
        end_time = time.time()
        return {
            "start_time": int(start_time * 1000),
            "end_time": int(end_time * 1000),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    '''
)

RUN_KEYWORD_ARGS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            args=["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

POPEN_KEYWORD_ARGS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        process = subprocess.Popen(
            args=["Rscript", "--vanilla", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": stdout.decode("utf-8"),
            "Stderr": stderr.decode("utf-8"),
        }
    '''
)

FROM_IMPORT_POPEN_HARDCODED = textwrap.dedent(
    '''
    from datetime import datetime
    from subprocess import PIPE, Popen

    def task_func(script_path):
        start_time = datetime.now()
        process = Popen(
            ["/usr/bin/Rscript", "--vanilla", script_path],
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = process.communicate()
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": stdout.decode("utf-8"),
            "Stderr": stderr.decode("utf-8"),
        }
    '''
)

FROM_IMPORT_RUN_HARDCODED = textwrap.dedent(
    '''
    from datetime import datetime
    from subprocess import run as run_command

    def task_func(script_path):
        start_time = datetime.now()
        completed = run_command(
            ["/usr/bin/Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

STRFTIME_SECONDS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "Start Time": start_time,
            "End Time": end_time,
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

CTIME_ASCTIME = textwrap.dedent(
    '''
    import subprocess
    import time

    def task_func(script_path):
        start_time = time.ctime()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = time.asctime()
        return {
            "Start Time": start_time,
            "End Time": end_time,
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

DUPLICATE_EQUAL_KEYS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        start_text = start_time.isoformat()
        end_text = end_time.isoformat()
        return {
            "Start Time": start_text,
            "start_time": start_text,
            "End Time": end_text,
            "End_Time": end_text,
            "Stdout": completed.stdout,
            "stdout": completed.stdout,
            "Stderr": completed.stderr,
            "stderr": completed.stderr,
        }
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        CANONICAL_POPEN,
        RUN_TEXT_CHECK,
        POPEN_TEXT_CAMEL,
        POPEN_CONTEXT_DECODE,
        RUN_SHELL_TEXT,
        RUN_MILLISECOND_TIMESTAMPS,
        RUN_KEYWORD_ARGS,
        POPEN_KEYWORD_ARGS,
        FROM_IMPORT_POPEN_HARDCODED,
        FROM_IMPORT_RUN_HARDCODED,
        STRFTIME_SECONDS,
        CTIME_ASCTIME,
        DUPLICATE_EQUAL_KEYS,
    ],
)
def test_legal_implementations_pass(tmp_path: Path, solution: str) -> None:
    _assert_passed(_run_1102(tmp_path, solution))


FABRICATED_WITHOUT_EXECUTION = textwrap.dedent(
    '''
    import os
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        end_time = datetime.now()
        name = os.path.basename(script_path)
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": "STDOUT[" + name + "] café-雪 " + script_path + "\\n",
            "Stderr": "STDERR[" + name + "] warning-λ " + script_path + "\\n",
        }
    '''
)

WRONG_SCRIPT = textwrap.dedent(
    '''
    import os
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path + ".wrong"],
            capture_output=True,
            text=True,
        )
        end_time = datetime.now()
        name = os.path.basename(script_path)
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": "STDOUT[" + name + "] café-雪 " + script_path + "\\n",
            "Stderr": "STDERR[" + name + "] warning-λ " + script_path + "\\n",
        }
    '''
)

SWAPPED_STREAMS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stderr,
            "Stderr": completed.stdout,
        }
    '''
)

UNDECODED_BYTES = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        process = subprocess.Popen(
            ["Rscript", "--vanilla", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": stdout,
            "Stderr": stderr,
        }
    '''
)

MISSING_FIELD = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
        }
    '''
)

AMBIGUOUS_KEYS = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
            "stdout": completed.stdout + " conflicting duplicate",
            "Stderr": completed.stderr,
        }
    '''
)

WRONG_KEY_NAMES = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Begin": start_time.isoformat(),
            "Finish": end_time.isoformat(),
            "Output": completed.stdout,
            "Errors": completed.stderr,
        }
    '''
)

BAD_TIME_ORDER = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = datetime.now()
        return {
            "Start Time": end_time.isoformat(),
            "End Time": start_time.isoformat(),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

HARDCODED_TIMES = textwrap.dedent(
    '''
    import subprocess

    def task_func(script_path):
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            "Start Time": "2000-01-01T00:00:00",
            "End Time": "2000-01-01T00:00:01",
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

BAD_SECOND_LEVEL_ORDER = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime, timedelta

    def task_func(script_path):
        start_time = datetime.now()
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        end_time = start_time - timedelta(seconds=5)
        return {
            "Start Time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "End Time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

UNPARSEABLE_TIMES = textwrap.dedent(
    '''
    import subprocess

    def task_func(script_path):
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            "Start Time": "now",
            "End Time": "later",
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)

START_RECORDED_AFTER_EXECUTION = textwrap.dedent(
    '''
    import subprocess
    from datetime import datetime

    def task_func(script_path):
        completed = subprocess.run(
            ["Rscript", "--vanilla", script_path],
            capture_output=True,
            text=True,
            check=True,
        )
        start_time = datetime.now()
        end_time = datetime.now()
        return {
            "Start Time": start_time.isoformat(),
            "End Time": end_time.isoformat(),
            "Stdout": completed.stdout,
            "Stderr": completed.stderr,
        }
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        FABRICATED_WITHOUT_EXECUTION,
        WRONG_SCRIPT,
        SWAPPED_STREAMS,
        UNDECODED_BYTES,
        MISSING_FIELD,
        AMBIGUOUS_KEYS,
        WRONG_KEY_NAMES,
        BAD_TIME_ORDER,
        BAD_SECOND_LEVEL_ORDER,
        HARDCODED_TIMES,
        UNPARSEABLE_TIMES,
        START_RECORDED_AFTER_EXECUTION,
    ],
)
def test_incorrect_behavior_fails(tmp_path: Path, solution: str) -> None:
    _assert_failed(_run_1102(tmp_path, solution))
