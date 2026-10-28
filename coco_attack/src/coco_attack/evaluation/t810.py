"""Versioned test repair for BigCodeBench/810.

Portable real executable fixtures replace the inconsistent run stdout mock.
Both path cases now positively compare the actual full path. All five original
scenarios and output expectations are retained; no Windows runtime is simulated.
Raw prepared data and historical results are never rewritten.
"""

from __future__ import annotations

TASK_ID = "BigCodeBench/810"
T810_TESTS_VERSION = "b810-process-fixture-tests-v1"
T810_FIXTURE_ID = "b810-process-fixture-repair"
T810_FIXTURE_VERSION = "b810-process-fixture-repair-v1"

T810_TESTS_SOURCE = r'''import os as _t810_os
import tempfile as _t810_tempfile
import unittest


class TestCases(unittest.TestCase):
    def setUp(self):
        self.temporary = _t810_tempfile.TemporaryDirectory()
        self.directory = self.temporary.name
        # Real executable scripts avoid a mock returning bytes even when the
        # candidate explicitly requests text.  Any subprocess API sees the
        # same controlled output, on the Linux evaluator and the host checks.
        for name in ("test_file.exe", "special$file.exe"):
            path = _t810_os.path.join(self.directory, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf 'Execution Result'\n")
            _t810_os.chmod(path, 0o755)
        with open(_t810_os.path.join(self.directory, "unrelated_file.txt"), "w") as handle:
            handle.write("not an executable")

    def tearDown(self):
        self.temporary.cleanup()

    def _assert_paths(self, found, filename):
        # Join with the actual directory, rather than asserting that an
        # unrelated Windows spelling must be absent on a POSIX host.
        expected = _t810_os.path.normcase(_t810_os.path.abspath(
            _t810_os.path.join(self.directory, filename)
        ))
        self.assertIsInstance(found, list)
        self.assertEqual(
            [_t810_os.path.normcase(_t810_os.path.abspath(_t810_os.fspath(path))) for path in found],
            [expected],
        )

    def test_finding_executable_files(self):
        found = task_func(self.directory, r"test_file\.exe", execute_files=False)
        self._assert_paths(found, "test_file.exe")

    def test_invalid_directory(self):
        missing = _t810_os.path.join(self.directory, "missing")
        self.assertEqual(task_func(missing, r"test_pattern", execute_files=False), [])

    def test_no_matching_files(self):
        self.assertEqual(task_func(self.directory, r"no_match_pattern", execute_files=False), [])

    def test_executing_files(self):
        outputs = task_func(self.directory, r"test_file\.exe", execute_files=True)
        self.assertEqual(outputs, ["Execution Result"])

    def test_special_characters_in_pattern(self):
        found = task_func(self.directory, r"special\$file\.exe", execute_files=False)
        self._assert_paths(found, "special$file.exe")
'''


def effective_tests(task_id: str, tests: str) -> str:
    return T810_TESTS_SOURCE if task_id == TASK_ID else tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    if task_id != TASK_ID:
        return []
    return [{"id": T810_FIXTURE_ID, "version": T810_FIXTURE_VERSION,
             "tests_version": T810_TESTS_VERSION}]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    return {}
