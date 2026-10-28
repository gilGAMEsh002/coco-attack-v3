"""Versioned functional-test overlay for ``BigCodeBench/745``.

The raw task/test data is never rewritten.  The task statement only asks the
candidate to run one randomly selected bash script from ``SCRIPTS`` in
``SCRIPTS_DIR`` and return that script's full path.  The original tests instead
patch ``subprocess.call`` and require that exact API shape (``call`` with
``shell=True``), and they additionally require exception propagation and an
untouched environment, none of which the task statement asks for.

The overlay keeps the stated behavior and drops those undeclared implementation
constraints.  Every call gets its own temporary script directory and its own
trace file, so a delayed child started by an earlier call cannot write into the
next call's trace.  Each script appends a fresh random token generated for that
call, so the trace cannot be precomputed or forged by returning a path alone.
The test wraps the real ``subprocess.Popen.__init__`` only to remember started
child processes and wait for them with a bounded deadline; it never simulates
their output.  This covers ``call``/``run``/``Popen`` and direct
``from subprocess import Popen`` aliases, while ``os.system`` and other
synchronous writers are still observed through the trace.

Each call must run exactly the returned script once; repeated calls must not
always select the same script.  The 32-call diversity check rejects fixed
selection while a healthy uniform implementation has only
``3 * (1/3) ** 32 = 3 ** -31`` (approximately 1.62e-15) probability of
accidentally returning one script every time; it is a selection-diversity
check, not proof of true randomness.  ``subprocess.call``, ``subprocess.run``,
``subprocess.Popen``, direct execution and explicit ``bash`` interpreters are
all observed identically because only the real execution trace is inspected.
"""

from __future__ import annotations

T745_TASK_ID = "BigCodeBench/745"
# Uniform task identifier used by the task-overlay dispatcher.
TASK_ID = T745_TASK_ID
T745_TESTS_VERSION = "b745-behavior-tests-v1"
T745_FIXTURE_ID = "b745-behavior-tests"
T745_FIXTURE_VERSION = "b745-behavior-tests-v1"

T745_TESTS_SOURCE = r"""import os
import shutil
import subprocess as _subprocess
import tempfile
import time
import unittest


_ACTIVE_PROCESSES = []
_REAL_POPEN_INIT = _subprocess.Popen.__init__


def _tracked_popen_init(self, *args, **kwargs):
    # Record real child processes only; outputs and exit codes still come from
    # the actual process.  Wrapping the class's __init__ also covers callers
    # that did ``from subprocess import Popen`` before this test module loaded.
    _REAL_POPEN_INIT(self, *args, **kwargs)
    _ACTIVE_PROCESSES.append(self)


_subprocess.Popen.__init__ = _tracked_popen_init

_SCRIPT_DELAY_SECONDS = 0.01


class TestCases(unittest.TestCase):
    SCRIPT_NAMES = ("script1.sh", "script2.sh", "script3.sh")

    def setUp(self):
        self.base_dir = tempfile.mkdtemp(prefix="b745-scripts-")
        self._call_number = 0
        self.current_tokens = {}
        self.current_script_paths = set()
        self.current_script_dir = ""
        self.current_process_timeout = False

    def tearDown(self):
        self._reap_processes()
        try:
            shutil.rmtree(self.base_dir)
        except OSError:
            pass

    def _reap_processes(self):
        processes = list(_ACTIVE_PROCESSES)
        _ACTIVE_PROCESSES.clear()
        timed_out = []
        deadline = time.monotonic() + 2.0
        for process in processes:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except _subprocess.TimeoutExpired:
                timed_out.append(process)
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=0.5)
                except (_subprocess.TimeoutExpired, OSError):
                    pass
            except (OSError, ValueError):
                pass
        return timed_out

    def _install_scripts(self, call_dir):
        trace_path = os.path.join(call_dir, "execution.trace")
        tokens = {}
        script_paths = set()
        for index, name in enumerate(self.SCRIPT_NAMES):
            token = "b745-%d-%s" % (index, os.urandom(8).hex())
            script_path = os.path.join(call_dir, name)
            script = (
                "#!/usr/bin/env bash\n"
                "sleep %s\n"
                "printf '%%s\\n' %r >> %r\n"
            ) % (_SCRIPT_DELAY_SECONDS, token, trace_path)
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write(script)
            os.chmod(script_path, 0o755)
            tokens[token] = script_path
            script_paths.add(script_path)
        return trace_path, tokens, script_paths

    def _read_trace(self, trace_path):
        try:
            with open(trace_path, encoding="utf-8") as handle:
                return [line.strip() for line in handle if line.strip()]
        except FileNotFoundError:
            return []

    def _wait_for_trace(self, trace_path):
        deadline = time.monotonic() + 1.0
        last_lines = None
        stable_since = None
        while time.monotonic() < deadline:
            lines = self._read_trace(trace_path)
            if lines:
                if lines == last_lines:
                    if time.monotonic() - stable_since >= 0.1:
                        return lines
                else:
                    last_lines = list(lines)
                    stable_since = time.monotonic()
            time.sleep(0.02)
        return self._read_trace(trace_path)

    def _call_and_collect_trace(self):
        self._reap_processes()
        self._call_number += 1
        call_dir = os.path.join(self.base_dir, "call-%03d" % self._call_number)
        os.makedirs(call_dir)
        trace_path, tokens, script_paths = self._install_scripts(call_dir)
        self.current_tokens = tokens
        self.current_script_paths = script_paths
        self.current_script_dir = call_dir
        self.current_process_timeout = False
        # The task's constants are inputs supplied by the caller/test, not
        # implementation details: point them at this call's controlled dir.
        globals()["SCRIPTS"] = list(self.SCRIPT_NAMES)
        globals()["SCRIPTS_DIR"] = call_dir
        try:
            result = task_func()
        except BaseException:
            self._reap_processes()
            raise
        timed_out = self._reap_processes()
        self.current_process_timeout = bool(timed_out)
        return result, self._wait_for_trace(trace_path)

    def _assert_single_execution_of_returned_script(self, result, lines):
        self.assertFalse(
            self.current_process_timeout,
            "A child process started by task_func did not finish within the test deadline.",
        )
        self.assertIsInstance(result, str)
        self.assertTrue(os.path.isabs(result), "The returned script path must be absolute.")
        self.assertIn(result, self.current_script_paths)
        self.assertTrue(os.path.isfile(result))
        self.assertEqual(
            len(lines),
            1,
            "Each task_func() call must execute exactly one script exactly once.",
        )
        self.assertIn(lines[0], self.current_tokens)
        self.assertEqual(
            self.current_tokens[lines[0]],
            result,
            "The executed script must be the script whose full path was returned.",
        )

    def test_executes_returned_script_exactly_once(self):
        for _ in range(6):
            result, lines = self._call_and_collect_trace()
            self._assert_single_execution_of_returned_script(result, lines)

    def test_returns_full_path_of_an_available_script(self):
        result, lines = self._call_and_collect_trace()
        self.assertFalse(
            self.current_process_timeout,
            "A child process started by task_func did not finish within the test deadline.",
        )
        self.assertIsInstance(result, str)
        self.assertTrue(os.path.isabs(result), "The returned script path must be absolute.")
        self.assertEqual(result, os.path.join(self.current_script_dir, os.path.basename(result)))
        self.assertIn(result, self.current_script_paths)
        self.assertEqual(len(lines), 1)

    def test_selection_is_random(self):
        # Selection-diversity check, not a proof of true randomness.
        selected = set()
        for _ in range(32):
            result, lines = self._call_and_collect_trace()
            self._assert_single_execution_of_returned_script(result, lines)
            selected.add(os.path.basename(result))
        self.assertGreater(
            len(selected),
            1,
            "Script selection must not be fixed to one script.",
        )
"""


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    if task_id == T745_TASK_ID:
        return T745_TESTS_SOURCE
    return tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    if task_id != T745_TASK_ID:
        return []
    return [
        {
            "id": T745_FIXTURE_ID,
            "version": T745_FIXTURE_VERSION,
            "tests_version": T745_TESTS_VERSION,
        }
    ]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container; this overlay is host-side only."""

    return {}


__all__ = [
    "T745_FIXTURE_ID",
    "T745_FIXTURE_VERSION",
    "T745_TASK_ID",
    "T745_TESTS_SOURCE",
    "TASK_ID",
    "T745_TESTS_VERSION",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
