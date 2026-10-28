"""Versioned test repair for BigCodeBench/322.

Consistent completed-process mocks; original five scenarios retained.
A sixth case checks a nonzero process exit code. Filesystem/copy mocks remain
scoped to the original APIs; the large-file scenario also marks the file executable.
Raw prepared data and historical results are never rewritten.
"""

from __future__ import annotations

TASK_ID = "BigCodeBench/322"
T322_TESTS_VERSION = "b322-process-fixture-tests-v1"
T322_FIXTURE_ID = "b322-process-fixture-repair"
T322_FIXTURE_VERSION = "b322-process-fixture-repair-v1"

T322_TESTS_SOURCE = r'''import io as _t322_io
import subprocess as _t322_subprocess
from contextlib import contextmanager as _t322_contextmanager
from unittest.mock import MagicMock, patch

_T322_REAL_POPEN = _t322_subprocess.Popen


def _t322_completed_process(args, kwargs, returncode):
    process = MagicMock()
    process.args = args
    process.returncode = returncode
    process.wait.return_value = returncode
    process.poll.return_value = returncode
    text = bool(kwargs.get("text") or kwargs.get("universal_newlines")
                or kwargs.get("encoding") or kwargs.get("errors"))
    def output(key):
        if kwargs.get(key) != _t322_subprocess.PIPE:
            return None
        return "" if text else b""
    stdout, stderr = output("stdout"), output("stderr")
    process.communicate.return_value = (stdout, stderr)
    process.stdout = None if stdout is None else (
        _t322_io.StringIO(stdout) if text else _t322_io.BytesIO(stdout)
    )
    process.stderr = None if stderr is None else (
        _t322_io.StringIO(stderr) if text else _t322_io.BytesIO(stderr)
    )
    process.__enter__.return_value = process
    process.__exit__.return_value = False
    return process


@_t322_contextmanager
def _t322_processes(returncode=0):
    # A new completed process for every launch.  Existing success scenarios
    # observed poll()==0, so all supported APIs must expose that same state.
    def spawn(*args, **kwargs):
        command = args[0] if args else kwargs["args"]
        return _t322_completed_process(command, kwargs, returncode)
    factory = MagicMock(side_effect=spawn)
    namespace = task_func.__globals__
    saved = {name: value for name, value in list(namespace.items())
             if value is _T322_REAL_POPEN and not name.startswith(("_t322", "_T322"))}
    try:
        for name in saved:
            namespace[name] = factory
        with patch("subprocess.Popen", new=factory):
            yield factory
    finally:
        namespace.update(saved)


import unittest
import os
from unittest.mock import patch, mock_open, MagicMock
class TestCases(unittest.TestCase):
    def test_successful_execution(self):
        # Test with a valid file that exists in the DIRECTORY and can be executed
        test_filename = 'valid_file.bat'
        with patch('os.path.exists', return_value=True):
            with patch('os.access', return_value=True):
                with patch('shutil.copy', return_value=None):  # Mock shutil.copy to avoid actual file operations
                    with _t322_processes() as mock_popen:
                        result = task_func(test_filename)
        self.assertEqual(result, 0)
    def test_failed_backup_nonexistent_file(self):
        # Test with a non-existent file to simulate backup failure
        test_filename = 'nonexistent_file.bat'
        with patch('os.path.exists', return_value=False):
            result = task_func(test_filename)
        self.assertEqual(result, -1)
    def test_failed_backup_non_executable_file(self):
        # Test with an existing but non-executable file
        test_filename = 'non_executable_file.txt'
        with patch('os.path.exists', return_value=True):
            with patch('os.access', return_value=False):
                with patch('shutil.copy', return_value=None):  # Mock shutil.copy to avoid actual file operations
                    with _t322_processes() as mock_popen:
                        mock_popen.side_effect = FileNotFoundError("File not executable")
                        result = task_func(test_filename)
        self.assertNotEqual(result, 0)
    def test_backup_of_large_file(self):
        # Test backing up a large file (size testing)
        test_filename = 'large_file.dat'
        with patch('os.path.exists', return_value=True):
            with patch('os.path.getsize', return_value=1024*1024*10), patch('os.access', return_value=True):  # 10 MB
                with patch('shutil.copy', return_value=None):  # Mock shutil.copy to avoid actual file operations
                    with _t322_processes() as mock_popen:
                        result = task_func(test_filename)
        self.assertEqual(result, 0)
    def test_backup_with_special_characters(self):
        # Test with a file name containing special characters
        test_filename = 'special_#&@.bat'
        with patch('os.path.exists', return_value=True):
            with patch('os.access', return_value=True):
                 with patch('shutil.copy', side_effect=Exception("Special character failed")):  # Mock shutil.copy to simulate backup failure
                    with _t322_processes() as mock_popen:
                        result = task_func(test_filename)
        self.assertEqual(result, -1)
    def test_nonzero_process_exit_code(self):
        with patch("os.path.exists", return_value=True), patch("os.access", return_value=True):
            with patch("shutil.copy", return_value=None), _t322_processes(returncode=7):
                result = task_func("nonzero_file.bat")
        self.assertEqual(result, 7)
'''


def effective_tests(task_id: str, tests: str) -> str:
    return T322_TESTS_SOURCE if task_id == TASK_ID else tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    if task_id != TASK_ID:
        return []
    return [{"id": T322_FIXTURE_ID, "version": T322_FIXTURE_VERSION,
             "tests_version": T322_TESTS_VERSION}]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    return {}
