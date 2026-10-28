"""Versioned functional-test overlays for three process-oriented tasks.

The raw task/test data is never rewritten.  The three original fixtures mocked
only one subprocess entry point and, in places, configured the mock with
mutually inconsistent state:

* ``BigCodeBench/12`` patched only ``subprocess.call``; a valid ``run`` or
  ``Popen`` implementation therefore executed a fictitious host path.
* ``BigCodeBench/320`` set ``wait.return_value`` to ``None`` while also setting
  ``returncode`` to 0/1, and its random-selection test referenced ``os`` without
  importing it.  It also accepted only a positional string command.
* ``BigCodeBench/326`` configured a ``MagicMock`` whose ``wait`` return value
  never reached ``returncode`` and whose third process raised from ``wait``.

Each overlay keeps the original scenarios and expected values, but installs a
consistent process lifecycle at ``subprocess.Popen`` so ``Popen``, ``run`` and
``call`` candidates all observe the same completion/exception state.  The
fixtures are self-contained (standard library only) because they are exec'd in
the container together with the candidate.
"""

from __future__ import annotations

B12_TASK_ID = "BigCodeBench/12"
B320_TASK_ID = "BigCodeBench/320"
B326_TASK_ID = "BigCodeBench/326"

TASK_IDS = (B12_TASK_ID, B320_TASK_ID, B326_TASK_ID)

B12_TESTS_VERSION = "b12-process-behavior-tests-v1"
B12_FIXTURE_ID = "b12-process-behavior-overlay"
B12_FIXTURE_VERSION = "b12-process-behavior-overlay-v1"

B320_TESTS_VERSION = "b320-process-behavior-tests-v1"
B320_FIXTURE_ID = "b320-process-behavior-overlay"
B320_FIXTURE_VERSION = "b320-process-behavior-overlay-v1"

B326_TESTS_VERSION = "b326-process-behavior-tests-v1"
B326_FIXTURE_ID = "b326-process-behavior-overlay"
B326_FIXTURE_VERSION = "b326-process-behavior-overlay-v1"


B12_TESTS_SOURCE = r"""import json
import os
import shlex
import subprocess
import unittest
from contextlib import contextmanager
from unittest.mock import mock_open, patch

_T12_REAL_POPEN = subprocess.Popen


class _T12Rejected(ValueError):
    pass


def _t12_command_from(popenargs, kwargs):
    missing = object()
    keyword = kwargs.get("args", missing)
    if popenargs:
        if len(popenargs) != 1:
            raise TypeError(
                "t12 fixture: expected one command argument, got %d"
                % len(popenargs)
            )
        if keyword is not missing:
            raise TypeError("t12 fixture: command given both positionally and as args=")
        return popenargs[0]
    if keyword is missing:
        raise TypeError("t12 fixture: missing required argument 'args'")
    return keyword


def _t12_basename(value):
    return os.path.basename(value.replace("\\", "/"))


def _t12_targets_script(command, script_name, kwargs):
    # A filename appearing in argv (for example, echo backup.sh) is not proof
    # that the script runs.  Recognize direct execution and common shells.
    scalar = isinstance(command, (str, bytes, os.PathLike))
    shell = bool(kwargs.get("shell"))
    if shell:
        text = os.fsdecode(command if scalar else command[0])
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
        if any(token in {";", "&&", "||", "|", "&", ">", "<"} for token in tokens):
            return False
    else:
        tokens = [os.fsdecode(command)] if scalar else [os.fsdecode(p) for p in command]
    if not tokens:
        return False
    if kwargs.get("executable") is not None:
        # Unrelated executable overrides must not masquerade as the script.
        executable = os.fsdecode(kwargs["executable"])
        if shell:
            if _t12_basename(executable) not in {"sh", "bash", "dash", "ksh", "zsh"}:
                return False
        elif os.path.abspath(executable) != os.path.abspath(tokens[0]) and not (
            os.path.dirname(tokens[0]) == ""
            and _t12_basename(executable) == tokens[0]
        ):
            return False
    target = tokens[0]
    if _t12_basename(target) in {"sh", "bash", "dash", "ksh", "zsh"}:
        rest = tokens[1:]
        while rest and rest[0] in {"-e", "-u", "-x", "-v", "-f", "--"}:
            rest = rest[1:]
        if not rest or rest[0].startswith("-"):
            return False
        target = rest[0]
    return os.path.abspath(target) == os.path.abspath(os.fsdecode(script_name))


class _T12Process:
    def __init__(self, args, returncode, kwargs):
        self.args = args
        self.pid = 1212
        self.returncode = None
        self._final_returncode = int(returncode)
        self._done = False
        self._remaining_polls = 1
        text = bool(
            kwargs.get("text")
            or kwargs.get("universal_newlines")
            or kwargs.get("encoding")
            or kwargs.get("errors")
        )
        self.stdout = self._stream(kwargs.get("stdout"), text)
        self.stderr = self._stream(kwargs.get("stderr"), text)

    @staticmethod
    def _stream(target, text):
        if target != subprocess.PIPE:
            return None
        import io

        return io.StringIO("") if text else io.BytesIO(b"")

    def wait(self, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        self._done = True
        self.returncode = self._final_returncode
        return self.returncode

    def poll(self):
        if self._done:
            return self.returncode
        if self._remaining_polls > 0:
            self._remaining_polls -= 1
            return None
        self._done = True
        self.returncode = self._final_returncode
        return self.returncode

    def communicate(self, input=None, timeout=None):
        self.wait(timeout)
        stdout = None if self.stdout is None else self.stdout.read()
        stderr = None if self.stderr is None else self.stderr.read()
        return stdout, stderr

    def check_returncode(self):
        code = self.wait()
        if code:
            raise subprocess.CalledProcessError(code, self.args)
        return None

    def kill(self):
        return None

    def terminate(self):
        return None

    def send_signal(self, sig):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.wait()
        return False


class _T12Simulation:
    def __init__(self, script_name, returncode=0, error=None):
        self.script_name = script_name
        self.returncode = returncode
        self.error = error
        self.launches = []
        self.rejected = []

    def popen(self, *popenargs, **kwargs):
        try:
            command = _t12_command_from(popenargs, kwargs)
            if not _t12_targets_script(command, self.script_name, kwargs):
                raise _T12Rejected(
                    "t12 fixture: expected execution of %r, got %r"
                    % (self.script_name, command)
                )
        except BaseException as error:
            self.rejected.append((popenargs, dict(kwargs), repr(error)))
            raise
        self.launches.append(command)
        if self.error is not None:
            raise self.error
        return _T12Process(command, self.returncode, kwargs)


@contextmanager
def _t12_simulated_process(script_name, returncode=0, error=None):
    simulation = _T12Simulation(script_name, returncode, error)
    namespace = getattr(globals().get("task_func"), "__globals__", None)
    saved = {}
    if isinstance(namespace, dict):
        for name, value in list(namespace.items()):
            if name.startswith("_T12") or name.startswith("_t12"):
                continue
            if value is _T12_REAL_POPEN:
                saved[name] = value
                namespace[name] = simulation.popen
    try:
        with patch("subprocess.Popen", new=simulation.popen):
            yield simulation
    finally:
        for name, value in saved.items():
            namespace[name] = value


class TestCases(unittest.TestCase):
    def _run(self, script_name="backup.sh", log_file="/home/user/backup_log.json",
             returncode=0, error=None, exists=True, use_defaults=True):
        with patch("os.path.isfile", return_value=exists), patch(
            "builtins.open", mock_open(read_data="{}")
        ):
            with _t12_simulated_process(script_name, returncode, error) as simulation:
                if use_defaults:
                    result = task_func()
                else:
                    result = task_func(script_name, log_file)
        return result, simulation

    def _assert_one_launch(self, simulation, script_name="backup.sh"):
        self.assertFalse(
            simulation.rejected,
            "the script command must be recognized: %r" % (simulation.rejected,),
        )
        self.assertEqual(
            1,
            len(simulation.launches),
            "expected exactly one script execution, got %r" % (simulation.launches,),
        )

    def test_default_values_successful_script(self):
        result, simulation = self._run()
        self._assert_one_launch(simulation)
        self.assertIn("start_time", result)
        self.assertIn("end_time", result)
        self.assertEqual(result["exit_status"], 0)

    def test_script_does_not_exist(self):
        with patch("os.path.isfile", return_value=False), patch(
            "builtins.open", mock_open(read_data="{}")
        ):
            with _t12_simulated_process("backup.sh", 0) as simulation:
                with self.assertRaises(FileNotFoundError):
                    task_func()
        self.assertEqual([], simulation.launches)
        self.assertEqual([], simulation.rejected)

    def test_script_execution_failure(self):
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.open", mock_open(read_data="{}")
        ):
            with _t12_simulated_process(
                "backup.sh", 0, Exception("Script failed")
            ) as simulation:
                with self.assertRaises(RuntimeError):
                    task_func()
        self.assertFalse(simulation.rejected)
        self.assertEqual(1, len(simulation.launches))

    def test_custom_values_successful_script(self):
        script_name = "custom_backup.sh"
        log_file = "/home/user/custom_backup_log.json"
        result, simulation = self._run(script_name, log_file, use_defaults=False)
        self._assert_one_launch(simulation, script_name)
        self.assertIn("start_time", result)
        self.assertIn("end_time", result)
        self.assertEqual(result["exit_status"], 0)

    def test_log_data_format(self):
        result, simulation = self._run()
        self._assert_one_launch(simulation)
        self.assertTrue(result["start_time"].count(":") == 2)
        self.assertTrue(result["end_time"].count(":") == 2)

    def test_non_zero_exit_status(self):
        result, simulation = self._run(returncode=1)
        self._assert_one_launch(simulation)
        self.assertEqual(result["exit_status"], 1)
"""


B320_TESTS_SOURCE = r"""import os
import random
import subprocess
import unittest
from contextlib import contextmanager
from unittest.mock import patch

_T320_REAL_POPEN = subprocess.Popen
_T320_REAL_CHOICE = random.choice


class _T320Rejected(ValueError):
    pass


def _t320_command_from(popenargs, kwargs):
    missing = object()
    keyword = kwargs.get("args", missing)
    if popenargs:
        if len(popenargs) != 1:
            raise TypeError(
                "t320 fixture: expected one command argument, got %d"
                % len(popenargs)
            )
        if keyword is not missing:
            raise TypeError("t320 fixture: command given both positionally and as args=")
        return popenargs[0]
    if keyword is missing:
        raise TypeError("t320 fixture: missing required argument 'args'")
    return keyword


def _t320_target(command):
    if isinstance(command, (str, bytes, os.PathLike)):
        return os.fsdecode(command)
    try:
        parts = list(command)
    except TypeError:
        return os.fsdecode(command)
    if len(parts) != 1:
        raise _T320Rejected(
            "t320 fixture: expected a path or a single-element argv, got %r"
            % (command,)
        )
    return os.fsdecode(parts[0])


class _T320Process:
    def __init__(self, args, returncode, kwargs):
        self.args = args
        self.pid = 3200
        self.returncode = int(returncode)
        self._final_returncode = int(returncode)
        self._done = True
        self._remaining_polls = 1
        text = bool(
            kwargs.get("text")
            or kwargs.get("universal_newlines")
            or kwargs.get("encoding")
            or kwargs.get("errors")
        )
        self.stdout = self._stream(kwargs.get("stdout"), text)
        self.stderr = self._stream(kwargs.get("stderr"), text)

    @staticmethod
    def _stream(target, text):
        if target != subprocess.PIPE:
            return None
        import io

        return io.StringIO("") if text else io.BytesIO(b"")

    def wait(self, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        self._done = True
        self.returncode = self._final_returncode
        return self.returncode

    def poll(self):
        if self._done:
            return self.returncode
        if self._remaining_polls > 0:
            self._remaining_polls -= 1
            return None
        self._done = True
        self.returncode = self._final_returncode
        return self.returncode

    def communicate(self, input=None, timeout=None):
        self.wait(timeout)
        stdout = None if self.stdout is None else self.stdout.read()
        stderr = None if self.stderr is None else self.stderr.read()
        return stdout, stderr

    def check_returncode(self):
        code = self.wait()
        if code:
            raise subprocess.CalledProcessError(code, self.args)
        return None

    def kill(self):
        return None

    def terminate(self):
        return None

    def send_signal(self, sig):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.wait()
        return False


class _T320Choice:
    def __init__(self, values):
        self.values = list(values)
        self.index = 0

    def __call__(self, sequence):
        if self.index >= len(self.values):
            raise StopIteration("t320 fixture: random.choice exhausted")
        value = self.values[self.index]
        self.index += 1
        if value not in sequence:
            raise _T320Rejected(
                "t320 fixture: selected value %r is not in %r"
                % (value, sequence)
            )
        return value


class _T320Simulation:
    def __init__(self, returncode=0, error=None, choices=None):
        self.returncode = returncode
        self.error = error
        self.choices = None if choices is None else _T320Choice(choices)
        self.launches = []
        self.rejected = []

    def popen(self, *popenargs, **kwargs):
        try:
            command = _t320_command_from(popenargs, kwargs)
            target = _t320_target(command)
            target = os.path.abspath(os.path.join(os.fspath(kwargs.get("cwd") or ""), target))
        except BaseException as error:
            self.rejected.append((popenargs, dict(kwargs), repr(error)))
            raise
        self.launches.append(target)
        if self.error is not None:
            raise self.error
        return _T320Process(command, self.returncode, kwargs)


@contextmanager
def _t320_simulated_process(returncode=0, error=None, choices=None):
    simulation = _T320Simulation(returncode, error, choices)
    namespace = getattr(globals().get("task_func"), "__globals__", None)
    saved = {}
    if isinstance(namespace, dict):
        for name, value in list(namespace.items()):
            if name.startswith("_T320") or name.startswith("_t320"):
                continue
            if value is _T320_REAL_POPEN:
                saved[name] = value
                namespace[name] = simulation.popen
            elif simulation.choices is not None and value is _T320_REAL_CHOICE:
                saved[name] = value
                namespace[name] = simulation.choices
    try:
        with patch("subprocess.Popen", new=simulation.popen):
            if simulation.choices is None:
                yield simulation
            else:
                with patch("random.choice", new=simulation.choices):
                    yield simulation
    finally:
        for name, value in saved.items():
            namespace[name] = value


class TestCases(unittest.TestCase):
    def _assert_return_code(self, result, expected):
        # These original scenarios describe an already-completed process.
        # The task permits None for a running process, not for these states.
        self.assertIs(
            type(result),
            int,
            "a completed process must yield an integer exit code, got %r" % (result,),
        )
        self.assertEqual(expected, result)

    def test_valid_input(self):
        random.seed(0)
        directory = "valid_dir"
        file_list = ["script1.bat", "script2.bat"]
        with _t320_simulated_process(returncode=0) as simulation:
            result = task_func(directory, file_list)
        self._assert_return_code(result, 0)
        self.assertEqual(1, len(simulation.launches))
        self.assertIn(simulation.launches[0], [os.path.abspath(os.path.join(directory, name)) for name in file_list])

    def test_empty_file_list(self):
        random.seed(0)
        directory = "valid_dir"
        file_list = []
        with _t320_simulated_process(returncode=0) as simulation:
            result = task_func(directory, file_list)
        self.assertIsNone(result)
        self.assertEqual([], simulation.launches)

    def test_invalid_directory(self):
        random.seed(0)
        directory = "invalid_dir"
        file_list = ["script1.bat"]
        with _t320_simulated_process(error=Exception("Error")):
            result = task_func(directory, file_list)
        self.assertIsNone(result)

    def test_non_zero_exit_code(self):
        random.seed(0)
        directory = "valid_dir"
        file_list = ["script3.bat"]
        with _t320_simulated_process(returncode=1) as simulation:
            result = task_func(directory, file_list)
        self._assert_return_code(result, 1)
        self.assertEqual(1, len(simulation.launches))
        self.assertEqual(os.path.abspath(os.path.join(directory, file_list[0])), simulation.launches[0])

    def test_random_file_selection(self):
        random.seed(0)
        directory = "valid_dir"
        file_list = ["script1.bat", "script2.bat", "script3.bat"]
        with _t320_simulated_process(returncode=0, choices=file_list) as simulation:
            for position, expected_file in enumerate(file_list, start=1):
                result = task_func(directory, file_list)
                self._assert_return_code(result, 0)
                self.assertEqual(
                    position,
                    len(simulation.launches),
                    "each call must start exactly one process",
                )
                self.assertEqual(
                    os.path.abspath(os.path.join(directory, expected_file)),
                    simulation.launches[-1],
                    "the process must target the randomly selected file",
                )
"""


B326_TESTS_SOURCE = r"""import glob
import os
import subprocess
import unittest
from contextlib import contextmanager
from unittest.mock import patch

_T326_REAL_POPEN = subprocess.Popen
_T326_REAL_GLOB = glob.glob


class _T326Rejected(ValueError):
    pass


class _T326SpawnFailure:
    def __init__(self, error):
        self.error = error


def _t326_command_from(popenargs, kwargs):
    missing = object()
    keyword = kwargs.get("args", missing)
    if popenargs:
        if len(popenargs) != 1:
            raise TypeError(
                "t326 fixture: expected one command argument, got %d"
                % len(popenargs)
            )
        if keyword is not missing:
            raise TypeError("t326 fixture: command given both positionally and as args=")
        return popenargs[0]
    if keyword is missing:
        raise TypeError("t326 fixture: missing required argument 'args'")
    return keyword


def _t326_target(command):
    if isinstance(command, (str, bytes, os.PathLike)):
        return os.fsdecode(command)
    try:
        parts = list(command)
    except TypeError:
        return os.fsdecode(command)
    if len(parts) != 1:
        raise _T326Rejected(
            "t326 fixture: expected a path or a single-element argv, got %r"
            % (command,)
        )
    return os.fsdecode(parts[0])


class _T326Process:
    def __init__(self, args, outcome, kwargs):
        self.args = args
        self.pid = 3260
        self.returncode = None
        self._outcome = outcome
        self._completed = False
        self.completion_attempted = False
        self._poll_count = 0
        text = bool(
            kwargs.get("text")
            or kwargs.get("universal_newlines")
            or kwargs.get("encoding")
            or kwargs.get("errors")
        )
        self.stdout = self._stream(kwargs.get("stdout"), text)
        self.stderr = self._stream(kwargs.get("stderr"), text)

    @staticmethod
    def _stream(target, text):
        if target != subprocess.PIPE:
            return None
        import io

        return io.StringIO("") if text else io.BytesIO(b"")

    def _finish(self):
        self.completion_attempted = True
        if isinstance(self._outcome, BaseException):
            # A genuine execution failure must stay an exception.  It must not
            # be turned into a successful exit code or an early None.
            raise self._outcome
        self._completed = True
        self.returncode = int(self._outcome)
        return self.returncode

    def wait(self, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        return self._finish()

    def poll(self):
        if self._completed:
            return self.returncode
        self._poll_count += 1
        if self._poll_count == 1:
            # The process has just started and is not finished yet.
            return None
        return self._finish()

    def communicate(self, input=None, timeout=None):
        self._finish()
        stdout = None if self.stdout is None else self.stdout.read()
        stderr = None if self.stderr is None else self.stderr.read()
        return stdout, stderr

    def check_returncode(self):
        code = self.wait()
        if code:
            raise subprocess.CalledProcessError(code, self.args)
        return None

    def kill(self):
        return None

    def terminate(self):
        return None

    def send_signal(self, sig):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.wait()
        return False


class _T326Simulation:
    def __init__(self, directory, entries):
        self.directory = directory
        self.entries = list(entries)
        self.index = 0
        self.launches = []
        self.processes = []
        self.patterns = []
        self.rejected = []

    def glob(self, pathname, *, root_dir=None, dir_fd=None, recursive=False, include_hidden=False):
        if dir_fd is not None:
            raise _T326Rejected("t326 fixture does not simulate directory file descriptors")
        pattern = os.path.normpath(os.path.join(os.fspath(root_dir or ""), os.fspath(pathname)))
        self.patterns.append(pattern)
        expected = os.path.join(self.directory, "*.bat")
        if os.path.abspath(pattern) != os.path.abspath(expected):
            raise _T326Rejected(
                "t326 fixture: expected glob pattern %r, got %r"
                % (expected, pattern)
            )
        return [path for path, _outcome in self.entries]

    def popen(self, *popenargs, **kwargs):
        if self.index >= len(self.entries):
            raise _T326Rejected("t326 fixture: unexpected extra process launch")
        expected_path, outcome = self.entries[self.index]
        try:
            command = _t326_command_from(popenargs, kwargs)
            target = _t326_target(command)
            resolved = os.path.abspath(os.path.join(os.fspath(kwargs.get("cwd") or ""), target))
            expected_paths = {
                os.path.abspath(expected_path),
                os.path.abspath(os.path.join(self.directory, expected_path)),
            }
            if resolved not in expected_paths:
                raise _T326Rejected(
                    "t326 fixture: expected %r in result order, got %r"
                    % (expected_path, target)
                )
        except BaseException as error:
            self.rejected.append((popenargs, dict(kwargs), repr(error)))
            raise
        self.launches.append(target)
        self.index += 1
        if isinstance(outcome, _T326SpawnFailure):
            raise outcome.error
        process = _T326Process(command, outcome, kwargs)
        self.processes.append(process)
        return process


@contextmanager
def _t326_simulated_process(directory, entries):
    simulation = _T326Simulation(directory, entries)
    namespace = getattr(globals().get("task_func"), "__globals__", None)
    saved = {}
    if isinstance(namespace, dict):
        for name, value in list(namespace.items()):
            if name.startswith("_T326") or name.startswith("_t326"):
                continue
            if value is _T326_REAL_POPEN:
                saved[name] = value
                namespace[name] = simulation.popen
            elif value is _T326_REAL_GLOB:
                saved[name] = value
                namespace[name] = simulation.glob
    try:
        with patch("glob.glob", new=simulation.glob), patch(
            "subprocess.Popen", new=simulation.popen
        ):
            yield simulation
    finally:
        for name, value in saved.items():
            namespace[name] = value


class TestCases(unittest.TestCase):
    def _assert_all_completed(self, simulation):
        self.assertFalse(
            simulation.rejected,
            "the execution commands must be recognized: %r" % (simulation.rejected,),
        )
        self.assertEqual(
            len(simulation.entries),
            simulation.index,
            "every discovered .bat file must be started exactly once",
        )
        for process in simulation.processes:
            self.assertTrue(
                process.completion_attempted,
                "task_func must obtain a final state from each process; "
                "returning Popen.returncode before completion is not enough",
            )

    def test_no_bat_files(self):
        directory = "path/to/directory"
        with _t326_simulated_process(directory, []) as simulation:
            result = task_func(directory)
        self.assertEqual(result, [])
        self.assertEqual([], simulation.launches)
        self.assertEqual([os.path.join(directory, "*.bat")], simulation.patterns)

    def test_single_bat_file_success(self):
        directory = "path/to/directory"
        entries = [("file1.bat", 0)]
        with _t326_simulated_process(directory, entries) as simulation:
            result = task_func(directory)
        self.assertEqual(result, [("file1.bat", 0)])
        self._assert_all_completed(simulation)

    def test_single_bat_file_failure(self):
        directory = "path/to/directory"
        entries = [("file1.bat", 1)]
        with _t326_simulated_process(directory, entries) as simulation:
            result = task_func(directory)
        self.assertEqual(result, [("file1.bat", 1)])
        self._assert_all_completed(simulation)

    def test_multiple_bat_files_mixed_results(self):
        directory = "path/to/directory"
        entries = [
            ("file1.bat", 0),
            ("file2.bat", 1),
            ("file3.bat", Exception("Mocked exception")),
        ]
        with _t326_simulated_process(directory, entries) as simulation:
            result = task_func(directory)
        self.assertEqual(
            result,
            [("file1.bat", 0), ("file2.bat", 1), ("file3.bat", None)],
        )
        self._assert_all_completed(simulation)

    def test_exception_handling(self):
        directory = "path/to/directory"
        entries = [
            ("file1.bat", _T326SpawnFailure(Exception("Mocked exception"))),
        ]
        with _t326_simulated_process(directory, entries) as simulation:
            result = task_func(directory)
        self.assertEqual(result, [("file1.bat", None)])
        self.assertEqual(1, simulation.index)
        self.assertEqual([], simulation.processes)
        self.assertEqual([os.path.join(directory, "*.bat")], simulation.patterns)
"""


_SOURCES = {
    B12_TASK_ID: B12_TESTS_SOURCE,
    B320_TASK_ID: B320_TESTS_SOURCE,
    B326_TASK_ID: B326_TESTS_SOURCE,
}

_FINGERPRINTS = {
    B12_TASK_ID: {
        "id": B12_FIXTURE_ID,
        "version": B12_FIXTURE_VERSION,
        "tests_version": B12_TESTS_VERSION,
    },
    B320_TASK_ID: {
        "id": B320_FIXTURE_ID,
        "version": B320_FIXTURE_VERSION,
        "tests_version": B320_TESTS_VERSION,
    },
    B326_TASK_ID: {
        "id": B326_FIXTURE_ID,
        "version": B326_FIXTURE_VERSION,
        "tests_version": B326_TESTS_VERSION,
    },
}


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    replacement = _SOURCES.get(task_id)
    if replacement is None:
        return tests
    if tests == replacement:
        return tests
    return replacement


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    entry = _FINGERPRINTS.get(task_id)
    if entry is None:
        return []
    return [dict(entry)]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container; these overlays are self-contained."""

    return {}


__all__ = [
    "B12_FIXTURE_ID",
    "B12_FIXTURE_VERSION",
    "B12_TASK_ID",
    "B12_TESTS_SOURCE",
    "B12_TESTS_VERSION",
    "B320_FIXTURE_ID",
    "B320_FIXTURE_VERSION",
    "B320_TASK_ID",
    "B320_TESTS_SOURCE",
    "B320_TESTS_VERSION",
    "B326_FIXTURE_ID",
    "B326_FIXTURE_VERSION",
    "B326_TASK_ID",
    "B326_TESTS_SOURCE",
    "B326_TESTS_VERSION",
    "TASK_IDS",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
