"""Versioned, task-scoped repairs for four raw BigCodeBench functional tests.

The raw prepared task data is never rewritten.  Each repair below is a
deliberate, minimal version copy of the original test module:

* ``BigCodeBench/17``: the three ``Popen.assert_called_once_with(<target>)``
  assertions required one exact argument shape.  They now accept the same
  target as a string, a single-element argv list/tuple, a ``os.PathLike``
  string, or the ``args=`` keyword, while still requiring exactly one launch
  of the correct target with no extra arguments, termination of every old
  process, and the original return messages.
* ``BigCodeBench/350``: ``test_case_4`` claims an empty source folder but
  never removed the three files created by ``setUp``.  That test now removes
  those files before calling the candidate; every original success/message/
  failed-files assertion and the exact ``ValueError`` messages are preserved.
  The test module imports its own ``os``/``shutil`` instead of relying on the
  candidate's globals.
* ``BigCodeBench/715``: all five tests ignored the documented return value.
  They now assert the returned version string and restore ``sys.path`` in a
  ``finally`` block; the original ``subprocess.run`` and ``sys.path``
  assertions remain.
* ``BigCodeBench/15``: the failure test only checked that some text was
  present.  It now uses two controlled commands whose exit codes (7 and 13)
  do not appear in their command text and requires each output file to report
  the actual numeric code, while keeping the original
  ``Error executing command`` assertion.  Descriptive wording is allowed.

Unlisted tasks keep their raw tests unchanged.
"""

from __future__ import annotations

T17_TASK_ID = "BigCodeBench/17"
T350_TASK_ID = "BigCodeBench/350"
T715_TASK_ID = "BigCodeBench/715"
T15_TASK_ID = "BigCodeBench/15"

TASK_IDS = (T17_TASK_ID, T350_TASK_ID, T715_TASK_ID, T15_TASK_ID)

T17_TESTS_VERSION = "b17-popen-target-tests-v1"
T17_FIXTURE_ID = "b17-popen-target-repair"
T17_FIXTURE_VERSION = "b17-popen-target-repair-v1"

T350_TESTS_VERSION = "b350-empty-source-tests-v1"
T350_FIXTURE_ID = "b350-empty-source-repair"
T350_FIXTURE_VERSION = "b350-empty-source-repair-v1"

T715_TESTS_VERSION = "b715-return-value-tests-v1"
T715_FIXTURE_ID = "b715-return-value-repair"
T715_FIXTURE_VERSION = "b715-return-value-repair-v1"

T15_TESTS_VERSION = "b15-exit-code-tests-v1"
T15_FIXTURE_ID = "b15-exit-code-repair"
T15_FIXTURE_VERSION = "b15-exit-code-repair-v1"

_FIXTURES = {
    T17_TASK_ID: {
        "id": T17_FIXTURE_ID,
        "version": T17_FIXTURE_VERSION,
        "tests_version": T17_TESTS_VERSION,
    },
    T350_TASK_ID: {
        "id": T350_FIXTURE_ID,
        "version": T350_FIXTURE_VERSION,
        "tests_version": T350_TESTS_VERSION,
    },
    T715_TASK_ID: {
        "id": T715_FIXTURE_ID,
        "version": T715_FIXTURE_VERSION,
        "tests_version": T715_TESTS_VERSION,
    },
    T15_TASK_ID: {
        "id": T15_FIXTURE_ID,
        "version": T15_FIXTURE_VERSION,
        "tests_version": T15_TESTS_VERSION,
    },
}


T17_TESTS_SOURCE = r"""import os as _t17_os
import subprocess as _t17_subprocess
import unittest
from unittest.mock import MagicMock, patch

import psutil as _t17_psutil

_T17_REAL_POPEN = _t17_subprocess.Popen


def _t17_install_popen(fake):
    # A candidate may bind ``Popen`` directly (``from subprocess import Popen``)
    # before the tests run, so patching ``subprocess.Popen`` alone would leave
    # that alias pointing at the real class.  Rebind only module-level aliases
    # that still refer to the real class.
    namespace = getattr(task_func, "__globals__", {})
    saved = {}
    for name, value in list(namespace.items()):
        if name.startswith("_t17") or name.startswith("_T17"):
            continue
        if value is _T17_REAL_POPEN:
            saved[name] = value
            namespace[name] = fake
    return saved


def _t17_restore_popen(saved):
    namespace = getattr(task_func, "__globals__", {})
    for name, value in saved.items():
        namespace[name] = value


def _t17_matches_target(value, target):
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            return False
        value = value[0]
    if isinstance(value, str):
        return value == target
    if isinstance(value, _t17_os.PathLike):
        return _t17_os.fspath(value) == target
    return False


class TestCases(unittest.TestCase):
    def _assert_single_launch(self, mock_popen, target):
        self.assertEqual(
            1,
            mock_popen.call_count,
            "expected exactly one Popen call for %r, got %r"
            % (target, mock_popen.call_args_list),
        )
        call = mock_popen.call_args
        args, kwargs = call
        missing = object()
        keyword = kwargs.get("args", missing)
        if args:
            self.assertEqual(
                1,
                len(args),
                "Popen must receive only the process target, got %r" % (args,),
            )
            self.assertIs(
                keyword,
                missing,
                "Popen target must not be given both positionally and as args=",
            )
            value = args[0]
        else:
            self.assertIsNot(
                keyword,
                missing,
                "Popen must be called with the process target",
            )
            value = keyword
        unexpected = set(kwargs) - {"args"}
        self.assertFalse(
            unexpected,
            "Popen must not receive extra keyword arguments: %r" % (sorted(unexpected),),
        )
        self.assertTrue(
            _t17_matches_target(value, target),
            "Popen target must be %r (or a single-element argv/Path form), got %r"
            % (target, value),
        )

    @patch('psutil.process_iter')
    @patch('subprocess.Popen')
    def test_process_not_found_starts_process(self, mock_popen, mock_process_iter):
        # Simulating no running process
        mock_process_iter.return_value = []
        saved = _t17_install_popen(mock_popen)
        try:
            result = task_func('random_non_existent_process')
        finally:
            _t17_restore_popen(saved)
        self.assertEqual(result, "Process not found. Starting random_non_existent_process.")
        self._assert_single_launch(mock_popen, 'random_non_existent_process')

    @patch('psutil.process_iter')
    @patch('subprocess.Popen')
    def test_process_found_restarts_process(self, mock_popen, mock_process_iter):
        # Simulating a running process
        process = MagicMock()
        process.name.return_value = 'notepad'
        mock_process_iter.return_value = [process]
        saved = _t17_install_popen(mock_popen)
        try:
            result = task_func('notepad')
        finally:
            _t17_restore_popen(saved)
        self.assertEqual(result, "Process found. Restarting notepad.")
        # Expecting terminate called on the process and then restarted
        process.terminate.assert_called_once()
        self._assert_single_launch(mock_popen, 'notepad')

    @patch('psutil.process_iter')
    @patch('subprocess.Popen')
    def test_process_terminates_and_restarts_multiple_instances(self, mock_popen, mock_process_iter):
        # Simulating multiple instances of a running process
        process1 = MagicMock()
        process2 = MagicMock()
        process1.name.return_value = 'multi_instance'
        process2.name.return_value = 'multi_instance'
        mock_process_iter.return_value = [process1, process2]
        saved = _t17_install_popen(mock_popen)
        try:
            result = task_func('multi_instance')
        finally:
            _t17_restore_popen(saved)
        self.assertEqual(result, "Process found. Restarting multi_instance.")
        process1.terminate.assert_called_once()
        process2.terminate.assert_called_once()
        self._assert_single_launch(mock_popen, 'multi_instance')
"""


T350_TESTS_SOURCE = r'''import unittest
import doctest
import tempfile
import os as _t350_os
import shutil as _t350_shutil
class TestCases(unittest.TestCase):
    def setUp(self):
        self.base_tmp_dir = tempfile.mkdtemp()
        self.src_folder_path = f"{self.base_tmp_dir}/test/source_folder"
        self.dst_folder_path = f"{self.base_tmp_dir}/test/destination_folder"
        
        # Reset the test folders before each test
        _t350_os.makedirs(self.src_folder_path, exist_ok=True)
        _t350_os.makedirs(self.dst_folder_path, exist_ok=True)
        # Create source and destination folders if they don't exist
        _t350_os.makedirs(self.src_folder_path, exist_ok=True)
        _t350_os.makedirs(self.dst_folder_path, exist_ok=True)
        # Create some sample files in the source folder
        self.file_contents = ["This is file 1.", "This is file 2.", "This is file 3."]
        file_paths = []
        for idx, content in enumerate(self.file_contents, 1):
            file_path = _t350_os.path.join(self.src_folder_path, f"file{idx}.txt")
            with open(file_path, "w") as file:
                file.write(content)
            file_paths.append(file_path)
    def tearDown(self):
        # Reset the test folders after each test
        if _t350_os.path.exists(self.base_tmp_dir):
            _t350_shutil.rmtree(self.base_tmp_dir, ignore_errors=True)
    def test_case_1(self):
        """Test basic functionality."""
        # Create some sample files in the source folder
        for idx, content in enumerate(self.file_contents, 1):
            file_path = _t350_os.path.join(self.src_folder_path, f"file{idx}.txt")
            with open(file_path, "w") as file:
                file.write(content)
        
        result = task_func(self.src_folder_path, self.dst_folder_path)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'All files compressed and moved successfully.')
        self.assertEqual(result['failed_files'], [])
        for idx in range(1, 4):
            self.assertTrue(_t350_os.path.exists(_t350_os.path.join(self.dst_folder_path, f"file{idx}.txt.gz")))
    def test_case_2(self):
        """Test non-existent source folder."""
        with self.assertRaises(ValueError) as context:
            task_func("/non/existent/path", self.dst_folder_path)
        self.assertEqual(str(context.exception), "Source folder '/non/existent/path' does not exist.")
    def test_case_3(self):
        """Test non-existent destination folder."""
        with self.assertRaises(ValueError) as context:
            task_func(self.src_folder_path, "/non/existent/path")
        self.assertEqual(str(context.exception), "Destination folder '/non/existent/path' does not exist.")
    def test_case_4(self):
        """Test empty source folder."""
        # setUp creates three source files for the other cases.  This case
        # claims an empty source folder, so remove those files first.
        for idx in range(1, 4):
            file_path = _t350_os.path.join(self.src_folder_path, f"file{idx}.txt")
            if _t350_os.path.exists(file_path):
                _t350_os.remove(file_path)
        result = task_func(self.src_folder_path, self.dst_folder_path)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'All files compressed and moved successfully.')
        self.assertEqual(result['failed_files'], [])
    
    def test_case_5(self):
        """Test with destination folder having some files."""
        # Create some files in the destination folder
        with open(_t350_os.path.join(self.dst_folder_path, "existing_file.txt"), "w") as file:
            file.write("This is an existing file.")
        with open(_t350_os.path.join(self.dst_folder_path, "existing_file.txt.gz"), "w") as file:
            file.write("This is an existing compressed file.")
        
        # Create some sample files in the source folder
        for idx, content in enumerate(self.file_contents, 1):
            file_path = _t350_os.path.join(self.src_folder_path, f"file{idx}.txt")
            with open(file_path, "w") as file:
                file.write(content)
        
        result = task_func(self.src_folder_path, self.dst_folder_path)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'All files compressed and moved successfully.')
        self.assertEqual(result['failed_files'], [])
        for idx in range(1, 4):
            self.assertTrue(_t350_os.path.exists(_t350_os.path.join(self.dst_folder_path, f"file{idx}.txt.gz")))
        self.assertTrue(_t350_os.path.exists(_t350_os.path.join(self.dst_folder_path, "existing_file.txt")))
        self.assertTrue(_t350_os.path.exists(_t350_os.path.join(self.dst_folder_path, "existing_file.txt.gz")))
'''


T715_TESTS_SOURCE = r"""import sys
import unittest
from unittest.mock import patch
class TestCases(unittest.TestCase):
    @patch('subprocess.run')
    def test_switch_to_default_python_version(self, mock_run):
        original_path_length = len(sys.path)
        try:
            result = task_func()
            mock_run.assert_called_with(['pyenv', 'global', '3.8'], check=True)
            self.assertEqual(sys.path[-1], '/path/to/whatever')
            self.assertEqual(result, '3.8')
        finally:
            sys.path = sys.path[:original_path_length]  # Reset sys.path to original state
    @patch('subprocess.run')
    def test_switch_to_python_3_7(self, mock_run):
        original_path_length = len(sys.path)
        try:
            result = task_func('3.7', '/another/path')
            mock_run.assert_called_with(['pyenv', 'global', '3.7'], check=True)
            self.assertEqual(sys.path[-1], '/another/path')
            self.assertEqual(result, '3.7')
        finally:
            sys.path = sys.path[:original_path_length]
    @patch('subprocess.run')
    def test_switch_to_python_3_9(self, mock_run):
        original_path_length = len(sys.path)
        try:
            result = task_func('3.9')
            mock_run.assert_called_with(['pyenv', 'global', '3.9'], check=True)
            self.assertEqual(sys.path[-1], '/path/to/whatever')
            self.assertEqual(result, '3.9')
        finally:
            sys.path = sys.path[:original_path_length]
    @patch('subprocess.run')
    def test_switch_to_python_2_7(self, mock_run):
        original_path_length = len(sys.path)
        try:
            result = task_func('2.7')
            mock_run.assert_called_with(['pyenv', 'global', '2.7'], check=True)
            self.assertEqual(sys.path[-1], '/path/to/whatever')
            self.assertEqual(result, '2.7')
        finally:
            sys.path = sys.path[:original_path_length]
    @patch('subprocess.run')
    def test_switch_to_python_3_6(self, mock_run):
        original_path_length = len(sys.path)
        try:
            result = task_func('3.6', '/different/path')
            mock_run.assert_called_with(['pyenv', 'global', '3.6'], check=True)
            self.assertEqual(sys.path[-1], '/different/path')
            self.assertEqual(result, '3.6')
        finally:
            sys.path = sys.path[:original_path_length]
"""


T15_TESTS_SOURCE = r"""import unittest
import tempfile
import shutil
import os
import csv
import re as _t15_re
class TestCases(unittest.TestCase):
    def setUp(self):
        # Setup temporary directories for outputs and inputs
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir_path = tempfile.mkdtemp()
    def tearDown(self):
        # Remove temporary directories after each test
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.output_dir_path)
    def test_successful_command_execution(self):
        # Create a CSV file with valid commands
        commands_path = os.path.join(self.temp_dir, "valid_commands.csv")
        with open(commands_path, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["echo Hello"])
        result = task_func(commands_path, self.output_dir_path)
        self.assertEqual(len(result), 1)
        with open(os.path.join(self.output_dir_path, result[0]), "r") as f:
            content = f.read()
            self.assertIn("Hello", content)
    def test_file_not_found(self):
        # Testing for FileNotFoundError with an invalid file path
        with self.assertRaises(FileNotFoundError):
            task_func(os.path.join(self.temp_dir, "nonexistent.csv"), self.output_dir_path)
    def test_invalid_command(self):
        # Create a CSV file with an invalid command
        commands_path = os.path.join(self.temp_dir, "invalid_command.csv")
        with open(commands_path, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["invalid_command_xyz"])
        result = task_func(commands_path, self.output_dir_path)
        self.assertEqual(len(result), 1)
        with open(os.path.join(self.output_dir_path, result[0]), "r") as f:
            content = f.read()
            self.assertIn("invalid_command_xyz", content)
            self.assertIn("not found", content)
    def test_empty_csv_file(self):
        # Test with an empty CSV file
        empty_commands_path = os.path.join(self.temp_dir, "empty.csv")
        with open(empty_commands_path, "w", newline='') as file:
            pass
        result = task_func(empty_commands_path, self.output_dir_path)
        self.assertEqual(len(result), 0)
    def test_mixed_commands(self):
        # Test with a mix of valid and invalid commands
        commands_path = os.path.join(self.temp_dir, "mixed_commands.csv")
        with open(commands_path, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["echo Mixed Commands"])
            writer.writerow(["invalid_command_abc"])
        result = task_func(commands_path, self.output_dir_path)
        self.assertEqual(len(result), 2)
        with open(os.path.join(self.output_dir_path, result[1]), "r") as f:
            content = f.read()
            self.assertIn("invalid_command_abc", content)
            self.assertIn("not found", content)
    
    def test_command_failure_with_specific_exit_code(self):
        # Neither command spells its expected exit code.  Two different codes
        # also reject a candidate that always logs a fixed numeric code.
        commands_path = os.path.join(self.temp_dir, "failing_commands.csv")
        for command, code in [("exit $((2+5))", 7), ("exit $((8+5))", 13)]:
            with self.subTest(exit_code=code):
                with open(commands_path, "w", newline='') as file:
                    csv.writer(file).writerow([command])
                output_dir = tempfile.mkdtemp(dir=self.temp_dir)
                result = task_func(commands_path, output_dir)
                self.assertEqual(len(result), 1)
                with open(os.path.join(output_dir, result[0]), "r") as f:
                    content = f.read()
                self.assertIn("Error executing command", content)
                reported_codes = [
                    int(token)
                    for token in _t15_re.findall(r"(?<![\w.+-])[+-]?[0-9]+(?!\w|\.\d)", content)
                ]
                self.assertIn(
                    code,
                    reported_codes,
                    "the output must report the actual exit code %d, got %r"
                    % (code, content),
                )
"""


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    if task_id == T17_TASK_ID:
        return T17_TESTS_SOURCE
    if task_id == T350_TASK_ID:
        return T350_TESTS_SOURCE
    if task_id == T715_TASK_ID:
        return T715_TESTS_SOURCE
    if task_id == T15_TASK_ID:
        return T15_TESTS_SOURCE
    return tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    fixture = _FIXTURES.get(task_id)
    if fixture is None:
        return []
    return [dict(fixture)]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container; these repairs are self-contained."""

    return {}


__all__ = [
    "T15_FIXTURE_ID",
    "T15_FIXTURE_VERSION",
    "T15_TASK_ID",
    "T15_TESTS_SOURCE",
    "T15_TESTS_VERSION",
    "T350_FIXTURE_ID",
    "T350_FIXTURE_VERSION",
    "T350_TASK_ID",
    "T350_TESTS_SOURCE",
    "T350_TESTS_VERSION",
    "T715_FIXTURE_ID",
    "T715_FIXTURE_VERSION",
    "T715_TASK_ID",
    "T715_TESTS_SOURCE",
    "T715_TESTS_VERSION",
    "T17_FIXTURE_ID",
    "T17_FIXTURE_VERSION",
    "T17_TASK_ID",
    "T17_TESTS_SOURCE",
    "T17_TESTS_VERSION",
    "TASK_IDS",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
