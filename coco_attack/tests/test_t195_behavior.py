"""Behavioral tests for the ``BigCodeBench/195`` overlay.

Hand-written candidate solutions are executed through the real container-side
functional runner on the host.  Positive cases cover the legal command forms
and subprocess APIs; negative cases cover the implementation shapes that only
looked correct under the old ``MagicMock`` assertions.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from coco_attack.evaluation import t195

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
PYTHON = sys.executable
EXPECTED_TESTS = 8


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(tmp_path: Path, solution: str) -> dict:
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(t195.T195_TESTS_SOURCE, encoding="utf-8")
    request = {
        "sample_id": "s1",
        "attempt_id": "a1",
        "entry_point": "task_func",
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(t195.T195_TESTS_SOURCE),
        "task_id": t195.T195_TASK_ID,
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
    assert payload["load"]["tests_discovered"] == EXPECTED_TESTS
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["tests_run"] == EXPECTED_TESTS
    assert payload["run"]["failures"] == 0, payload["test_details"]
    assert payload["run"]["errors"] == 0, payload["test_details"]


def _assert_failed(payload: dict) -> None:
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == EXPECTED_TESTS
    assert payload["run"]["failures"] + payload["run"]["errors"] >= 1


def test_overlay_identity_is_the_new_behavior_fixture() -> None:
    assert t195.T195_TESTS_VERSION == "b195-behavior-tests-v2"
    assert t195.T195_FIXTURE_VERSION == "b195-browser-behavior-overlay-v2"
    assert t195.fixture_fingerprint("BigCodeBench/12") == []
    assert t195.effective_tests("BigCodeBench/12", "raw") == "raw"
    assert t195.effective_tests(t195.T195_TASK_ID, "raw") == t195.T195_TESTS_SOURCE
    assert "MagicMock" not in t195.T195_TESTS_SOURCE


DIRECT_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

SHELL_STRING = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Windows":
            command = 'start "" "%s"' % url
        elif system == "Darwin":
            command = 'open "%s"' % url
        else:
            command = 'xdg-open "%s"' % url
        process = subprocess.Popen(command, shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

RUN_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        completed = subprocess.run(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        return completed.returncode
    '''
)

CALL_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        return subprocess.call(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
    '''
)

WAIT_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        process.wait()
        return process.returncode
    '''
)

COMMUNICATE_CONTEXT = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        with subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=(system == "Windows"),
        ) as process:
            process.communicate()
        return process.returncode
    '''
)

WINDOWS_CMD_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            argv = ["open", url]
        elif system == "Windows":
            argv = ["cmd", "/c", "start", "", url]
        else:
            argv = ["xdg-open", url]
        process = subprocess.Popen(argv)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_CMD_STRING = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            command = 'open "%s"' % url
        elif system == "Windows":
            command = 'cmd /c start "" "%s"' % url
        else:
            command = 'xdg-open "%s"' % url
        process = subprocess.Popen(command, shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

ABSOLUTE_POSIX_TOOL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "/usr/bin/open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "/usr/bin/xdg-open"
        process = subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_CMD_STRING_NO_SHELL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Windows":
            process = subprocess.Popen('cmd /c start "" "%s"' % url, shell=False)
        elif system == "Darwin":
            process = subprocess.Popen(["open", url])
        else:
            process = subprocess.Popen(["xdg-open", url])
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

POSIX_SINGLE_ELEMENT_SHELL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Windows":
            process = subprocess.Popen('start "" "%s"' % url, shell=True)
        elif system == "Darwin":
            process = subprocess.Popen(['open "%s"' % url], shell=True)
        else:
            process = subprocess.Popen(['xdg-open "%s"' % url], shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

ALIASED_IMPORTS = textwrap.dedent(
    '''
    import time
    from platform import system as get_system
    from subprocess import Popen


    def task_func(url):
        system = get_system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

EXECUTABLE_SHELL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Windows":
            process = subprocess.Popen(
                'start "" "%s"' % url, shell=True, executable="cmd.exe"
            )
        elif system == "Darwin":
            process = subprocess.Popen(
                ['open "%s"' % url], shell=True, executable="/bin/sh"
            )
        else:
            process = subprocess.Popen(
                ['xdg-open "%s"' % url], shell=True, executable="/bin/sh"
            )
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)


WINDOWS_OPTIONS_AFTER_TITLE = SHELL_STRING.replace('start "" "%s"', 'start "" /b "%s"')


@pytest.mark.parametrize(
    "solution",
    [
        DIRECT_LIST,
        SHELL_STRING,
        RUN_LIST,
        CALL_LIST,
        WAIT_LIST,
        COMMUNICATE_CONTEXT,
        WINDOWS_CMD_LIST,
        WINDOWS_CMD_STRING,
        ABSOLUTE_POSIX_TOOL,
        WINDOWS_CMD_STRING_NO_SHELL,
        POSIX_SINGLE_ELEMENT_SHELL,
        ALIASED_IMPORTS,
        EXECUTABLE_SHELL,
        WINDOWS_OPTIONS_AFTER_TITLE,
    ],
)
def test_legal_candidate_forms_pass(tmp_path: Path, solution: str) -> None:
    _assert_passed(_run(tmp_path, solution))


WRONG_TOOL = textwrap.dedent(
    '''
    import subprocess


    def task_func(url):
        process = subprocess.Popen(["true", url])
        process.wait()
        return process.returncode
    '''
)

WRONG_URL = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen(
            [tool, "https://wrong.example"],
            shell=(system == "Windows"),
        )
        process.wait()
        return process.returncode
    '''
)

BOOLEAN_RESULT = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        ).wait()
        return True
    '''
)

CONSTANT_ZERO = textwrap.dedent(
    '''
    def task_func(url):
        return 0
    '''
)

CONSTANT_ZERO_AFTER_LAUNCH = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        ).wait()
        return 0
    '''
)

POLL_ONCE = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen(
            ('start "" "%s"' % url) if system == "Windows" else [tool, url],
            shell=(system == "Windows"),
        )
        process.poll()
        return process.returncode
    '''
)

POSIX_SHELL_TRUE_LIST = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen([tool, url], shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

STRING_WITHOUT_SHELL = textwrap.dedent(
    '''
    import platform
    import subprocess


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen("%s %s" % (tool, url))
        process.wait()
        return process.returncode
    '''
)

UNQUOTED_SHELL_URL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            tool = "open"
        elif system == "Windows":
            tool = "start"
        else:
            tool = "xdg-open"
        process = subprocess.Popen("%s %s" % (tool, url), shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_QUOTED_URL_AS_TITLE = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            command = 'open "%s"' % url
        elif system == "Windows":
            command = 'start "%s"' % url
        else:
            command = 'xdg-open "%s"' % url
        process = subprocess.Popen(command, shell=True)
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_START_SHELL_FALSE = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            process = subprocess.Popen(["open", url])
        elif system == "Windows":
            process = subprocess.Popen(["start", url], shell=False)
        else:
            process = subprocess.Popen(["xdg-open", url])
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_START_STRING_NO_SHELL = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            process = subprocess.Popen(["open", url])
        elif system == "Windows":
            process = subprocess.Popen('start "%s"' % url, shell=False)
        else:
            process = subprocess.Popen(["xdg-open", url])
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

WINDOWS_SPACE_URL_NO_TITLE = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Darwin":
            process = subprocess.Popen(["open", url])
        elif system == "Windows":
            process = subprocess.Popen(["start", url], shell=True)
        else:
            process = subprocess.Popen(["xdg-open", url])
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)

EXECUTABLE_WRONG = textwrap.dedent(
    '''
    import platform
    import subprocess
    import time


    def task_func(url):
        system = platform.system()
        if system == "Windows":
            process = subprocess.Popen(
                ["cmd", "/c", "start", "", url], executable="powershell.exe"
            )
        elif system == "Darwin":
            process = subprocess.Popen(["open", url], executable="/bin/true")
        else:
            process = subprocess.Popen(["xdg-open", url], executable="/bin/true")
        while process.poll() is None:
            time.sleep(0.01)
        return process.returncode
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        WRONG_TOOL,
        WRONG_URL,
        BOOLEAN_RESULT,
        CONSTANT_ZERO,
        CONSTANT_ZERO_AFTER_LAUNCH,
        POLL_ONCE,
        POSIX_SHELL_TRUE_LIST,
        STRING_WITHOUT_SHELL,
        UNQUOTED_SHELL_URL,
        WINDOWS_QUOTED_URL_AS_TITLE,
        WINDOWS_START_SHELL_FALSE,
        WINDOWS_START_STRING_NO_SHELL,
        WINDOWS_SPACE_URL_NO_TITLE,
        EXECUTABLE_WRONG,
    ],
)
def test_wrong_behavior_still_fails(tmp_path: Path, solution: str) -> None:
    _assert_failed(_run(tmp_path, solution))
