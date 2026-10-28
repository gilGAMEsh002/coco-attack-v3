"""Versioned behavioral-test overlay for ``BigCodeBench/1102``.

The raw task/test data is never rewritten.  The original tests patched
``subprocess.Popen`` with ``unittest.mock.Mock`` and configured only
``communicate``; that form accidentally required one particular
implementation shape (a direct ``Popen`` call) and never observed whether an R
script was actually executed.

This overlay checks the behavior stated by the task instead:

* the requested R script is executed exactly once through a real, executable
  fake ``Rscript`` placed first on ``PATH``;
* the returned dictionary contains start time, end time, decoded stdout and
  decoded stderr under one of the explicit key spellings
  ``Start Time``/``start_time``/``startTime``, ``End Time``/``end_time``/
  ``endTime``, ``Stdout``/``stdout``/``STDOUT`` and ``Stderr``/``stderr``.
  Normalization is limited to case plus spaces/underscores/hyphens inside
  those names; there is no natural-language synonym guessing.  Duplicate keys
  for the same field are accepted only when their values are exactly equal.
* stdout/stderr match the dynamic Unicode output of the executed script;
* the reported times bracket the real execution.

Only the hard-coded ``/usr/bin/Rscript`` path from the canonical solution is
redirected to the same fake executable; subprocess results are never
simulated.  The fixture identity is versioned so the functional cache cannot
reuse results from the old mock-shaped tests.
"""

from __future__ import annotations

T1102_TASK_ID = "BigCodeBench/1102"
# Uniform task identifier used by the task-overlay dispatcher.
TASK_ID = T1102_TASK_ID
T1102_TESTS_VERSION = "b1102-behavior-tests-v2"
T1102_FIXTURE_ID = "b1102-behavior-overlay"
T1102_FIXTURE_VERSION = "b1102-behavior-overlay-v2"

T1102_TESTS_SOURCE = r"""import atexit as _atexit
import datetime as _datetime
import json as _json
import math as _math
import os as _os
import re as _re
import shutil as _shutil
import subprocess as _subprocess
import sys as _sys
import tempfile as _tempfile
import time as _time
import unittest as _unittest


_BASE = _tempfile.mkdtemp(prefix="t1102-behavior-")
_BIN = _os.path.join(_BASE, "bin")
_os.makedirs(_BIN, exist_ok=True)
_FAKE_RSCRIPT = _os.path.join(_BIN, "Rscript")
_LOG = _os.path.join(_BASE, "calls.jsonl")
_atexit.register(lambda: _shutil.rmtree(_BASE, ignore_errors=True))

_os.environ["T1102_RSCRIPT_LOG"] = _LOG
_os.environ["PATH"] = _BIN + _os.pathsep + _os.environ.get("PATH", "")
_os.environ.setdefault("PYTHONIOENCODING", "utf-8")

_FAKE_SOURCE = "#!" + _sys.executable + "\n" + r'''import json
import os
import sys
import time

log_path = os.environ["T1102_RSCRIPT_LOG"]
argv = sys.argv[1:]
script = None
for token in argv:
    if not token.startswith("-"):
        script = token
if script is None:
    sys.stderr.write("Rscript fixture: missing script path\n")
    raise SystemExit(2)
name = os.path.basename(script)
stdout_text = "STDOUT[" + name + "] café-雪 " + script + "\n"
stderr_text = "" if "quiet" in name else "STDERR[" + name + "] warning-λ " + script + "\n"
started_at = time.time()
if not os.path.exists(script):
    sys.stderr.write("Rscript fixture: script not found: " + script + "\n")
    raise SystemExit(2)
sys.stdout.buffer.write(stdout_text.encode("utf-8"))
sys.stdout.buffer.flush()
if stderr_text:
    sys.stderr.buffer.write(stderr_text.encode("utf-8"))
    sys.stderr.buffer.flush()
finished_at = time.time()
with open(log_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "script": script,
        "argv": argv,
        "started_at": started_at,
        "finished_at": finished_at,
    }, ensure_ascii=False) + "\n")
raise SystemExit(0)
'''

with open(_FAKE_RSCRIPT, "w", encoding="utf-8") as _handle:
    _handle.write(_FAKE_SOURCE)
_os.chmod(_FAKE_RSCRIPT, 0o755)

# Candidates that follow the canonical solution hard-code /usr/bin/Rscript.
# Redirect only that executable token to the real fake binary; outputs still
# come from an executed process, not from a simulated Popen object.
_REAL_POPEN = _subprocess.Popen
_HARDCODED_RSCRIPT = "/usr/bin/Rscript"


def _rewrite_executable(command):
    if isinstance(command, bytes):
        hard = _os.fsencode(_HARDCODED_RSCRIPT)
        fake = _os.fsencode(_FAKE_RSCRIPT)
        if command == hard or command.startswith(hard + b" "):
            return fake + command[len(hard):]
        return command
    if isinstance(command, str):
        if command == _HARDCODED_RSCRIPT or command.startswith(_HARDCODED_RSCRIPT + " "):
            return _FAKE_RSCRIPT + command[len(_HARDCODED_RSCRIPT):]
        return command
    if isinstance(command, (list, tuple)) and command:
        first = command[0]
        if isinstance(first, bytes):
            if first == _os.fsencode(_HARDCODED_RSCRIPT):
                items = list(command)
                items[0] = _os.fsencode(_FAKE_RSCRIPT)
                return items
        else:
            try:
                first_text = _os.fspath(first)
            except TypeError:
                return command
            if first_text == _HARDCODED_RSCRIPT:
                items = list(command)
                items[0] = _FAKE_RSCRIPT
                return items
    return command


def _popen(*popenargs, **kwargs):
    '''Redirect only the hard-coded interpreter path.

    ``subprocess.run(args=[...])`` reaches ``Popen`` with the command in the
    ``args`` keyword, while direct calls pass it positionally.  Extract the
    command from exactly one place; leave genuinely duplicate arguments to the
    real ``Popen`` so its normal ``TypeError`` is preserved.
    '''

    if "args" in kwargs and not popenargs:
        kwargs["args"] = _rewrite_executable(kwargs["args"])
        return _REAL_POPEN(**kwargs)
    if "args" in kwargs:
        return _REAL_POPEN(*popenargs, **kwargs)
    if popenargs:
        popenargs = (_rewrite_executable(popenargs[0]),) + popenargs[1:]
    return _REAL_POPEN(*popenargs, **kwargs)


# A candidate that binds ``Popen`` with ``from subprocess import Popen`` at
# import time keeps a direct reference to the class.  Rewrite at the class
# boundary as well; this still executes the real process, it only changes the
# interpreter path.
_ORIGINAL_POPEN_INIT = _REAL_POPEN.__init__


def _popen_init(self, args, *rest, **kwargs):
    return _ORIGINAL_POPEN_INIT(self, _rewrite_executable(args), *rest, **kwargs)


_REAL_POPEN.__init__ = _popen_init
_subprocess.Popen = _popen

_KEY_ALIASES = {
    "starttime": "start",
    "endtime": "end",
    "stdout": "stdout",
    "stderr": "stderr",
}
_EXECUTION_TOLERANCE_SECONDS = 0.05


def _semantic_key(key):
    if not isinstance(key, str):
        return None
    compact = _re.sub(r"[\s_\-]+", "", key).lower()
    return _KEY_ALIASES.get(compact)


def _numeric_precision(text):
    compact = text.strip().lower()
    if "e" in compact:
        return 1e-6
    if "." in compact:
        digits = len(compact.split(".", 1)[1])
        return 10.0 ** (-digits)
    return None


def _parse_timestamp(value):
    '''Return ``(POSIX seconds, representation resolution in seconds)``.

    The resolution is used as the tolerance when checking that the reported
    times bracket execution, so second-level ``strftime`` output is not
    rejected merely because it truncates sub-second precision.
    '''

    if isinstance(value, bool):
        raise ValueError("boolean is not a time value: " + repr(value))
    if isinstance(value, _datetime.datetime):
        timestamp = value.timestamp()
        precision = 1e-6 if value.microsecond else 1.0
    elif isinstance(value, (int, float)):
        raw = float(value)
        scale = 1000.0 if abs(raw) > 1e11 else 1.0
        precision_units = 1.0 if isinstance(value, int) else 1e-6
        precision = precision_units / scale
        timestamp = raw / scale
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty time value")
        try:
            raw = float(text)
        except ValueError:
            iso = text[:-1] + "+00:00" if text.endswith("Z") else text
            try:
                parsed = _datetime.datetime.fromisoformat(iso)
            except ValueError:
                try:
                    parsed_struct = _time.strptime(text)
                except ValueError as error:
                    raise ValueError(
                        "not a datetime, ctime/asctime or numeric timestamp: "
                        + repr(value)
                    ) from error
                timestamp = _time.mktime(parsed_struct)
                return timestamp, 1.0
            if not _re.search(r"\d{2}:\d{2}:\d{2}", text):
                raise ValueError("time value must include seconds: " + repr(value))
            match = _re.search(r"[.,](\d+)", text)
            if match:
                precision = 10.0 ** (-len(match.group(1)))
            else:
                precision = 1.0
            timestamp = parsed.timestamp()
        else:
            scale = 1000.0 if abs(raw) > 1e11 else 1.0
            decimal_precision = _numeric_precision(text)
            precision_units = 1.0 if decimal_precision is None else decimal_precision
            precision = precision_units / scale
            timestamp = raw / scale
    else:
        raise ValueError("unsupported time value: " + repr(value))
    if not _math.isfinite(timestamp):
        raise ValueError("non-finite time value: " + repr(value))
    return timestamp, precision


class TestCases(_unittest.TestCase):
    def _make_script(self, name):
        path = _os.path.join(_BASE, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("# fake R script for the behavior test\n")
        return path

    def _expected_output(self, script):
        name = _os.path.basename(script)
        stdout = "STDOUT[" + name + "] café-雪 " + script + "\n"
        stderr = "" if "quiet" in name else "STDERR[" + name + "] warning-λ " + script + "\n"
        return stdout, stderr

    def _assert_result(self, script):
        with open(_LOG, "w", encoding="utf-8"):
            pass
        before = _time.time()
        result = task_func(script)
        after = _time.time()

        with open(_LOG, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        self.assertEqual(
            len(lines),
            1,
            "task_func must execute the requested R script exactly once.",
        )
        call = _json.loads(lines[0])
        self.assertEqual(
            call["script"],
            script,
            "task_func must execute the script path it was given.",
        )
        self.assertGreaterEqual(
            call["started_at"],
            before - _EXECUTION_TOLERANCE_SECONDS,
            "the script was executed before this task_func call, not during it.",
        )
        self.assertLessEqual(
            call["finished_at"],
            after + _EXECUTION_TOLERANCE_SECONDS,
            "the script was still running after task_func returned.",
        )

        self.assertIsInstance(result, dict, "task_func must return a dictionary.")
        fields = {}
        for key, value in result.items():
            semantic = _semantic_key(key)
            if semantic is None:
                continue
            if semantic in fields:
                if fields[semantic] != value:
                    self.fail(
                        "conflicting duplicate field for "
                        + semantic
                        + ": "
                        + repr(key)
                    )
                continue
            fields[semantic] = value
        for name in ("start", "end", "stdout", "stderr"):
            self.assertIn(name, fields, "missing required field: " + name)

        for name in ("stdout", "stderr"):
            self.assertIsInstance(
                fields[name],
                str,
                name + " must be decoded text, not bytes or another type.",
            )
        expected_stdout, expected_stderr = self._expected_output(script)
        self.assertEqual(fields["stdout"], expected_stdout, "decoded stdout mismatch")
        self.assertEqual(fields["stderr"], expected_stderr, "decoded stderr mismatch")

        try:
            start, start_precision = _parse_timestamp(fields["start"])
            end, end_precision = _parse_timestamp(fields["end"])
        except ValueError as error:
            self.fail(str(error))
        self.assertGreaterEqual(
            end + end_precision,
            start,
            "start time must not be after end time.",
        )
        self.assertGreaterEqual(
            start,
            before - start_precision,
            "start time is not from this execution.",
        )
        self.assertLessEqual(
            end,
            after + end_precision,
            "end time is not from this execution.",
        )
        self.assertLessEqual(
            start,
            call["started_at"] + start_precision,
            "start time is after the script began.",
        )
        self.assertGreaterEqual(
            end,
            call["finished_at"] - end_precision,
            "end time is before the script finished.",
        )

    def test_case_1(self):
        self._assert_result(self._make_script("first.r"))

    def test_case_2(self):
        self._assert_result(self._make_script("second-quiet.r"))

    def test_case_3(self):
        self._assert_result(self._make_script("third.r"))

    def test_case_4(self):
        self._assert_result(self._make_script("fourth-quiet.r"))

    def test_case_5(self):
        self._assert_result(self._make_script("fifth.r"))
"""


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    if task_id == T1102_TASK_ID:
        return T1102_TESTS_SOURCE
    return tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    if task_id != T1102_TASK_ID:
        return []
    return [
        {
            "id": T1102_FIXTURE_ID,
            "version": T1102_FIXTURE_VERSION,
            "tests_version": T1102_TESTS_VERSION,
        }
    ]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container; this overlay is host-side only."""

    return {}


__all__ = [
    "T1102_FIXTURE_ID",
    "T1102_FIXTURE_VERSION",
    "T1102_TASK_ID",
    "T1102_TESTS_SOURCE",
    "TASK_ID",
    "T1102_TESTS_VERSION",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
