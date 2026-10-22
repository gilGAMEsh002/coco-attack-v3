"""BigCodeBench/146 functional-test adaptation (fixture + versioned overlay)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from coco_attack.evaluation import t146

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
FIXTURE = EVALUATOR_DIR / "t146_ping_fixture.py"
PYTHON = sys.executable


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(
    tmp_path: Path,
    solution: str,
    tests: str,
    *,
    task_id: str | None = None,
    fixture_version: str | None = None,
    entry: str = "task_func",
    env: dict[str, str] | None = None,
) -> dict:
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(tests, encoding="utf-8")
    request = {
        "sample_id": "s1",
        "attempt_id": "a1",
        "entry_point": entry,
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(tests),
    }
    if task_id is not None:
        request["task_id"] = task_id
    if fixture_version is not None:
        request["fixture_version"] = fixture_version
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
        timeout=60,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(payload_path.read_text(encoding="utf-8"))


def _run_t146(tmp_path: Path, solution: str) -> dict:
    return _run(
        tmp_path,
        solution,
        t146.T146_TESTS_SOURCE,
        task_id=t146.T146_TASK_ID,
        fixture_version=t146.T146_FIXTURE_VERSION,
    )


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


CANONICAL = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.check_output(f"ping -c 1 {ip}", shell=True)
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

CHECK_OUTPUT_ALIAS = textwrap.dedent(
    '''
    from ipaddress import IPv4Network
    from subprocess import check_output as ping

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                ping(["ping", "-c", "1", str(ip)])
                active_ips[str(ip)] = True
            except Exception:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

RUN_CHECK_TRUE = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.run(["ping", "-c", "1", str(ip)], check=True, capture_output=True)
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

RUN_CHECK_FALSE = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            completed = subprocess.run(
                ["ping", "-c", "1", str(ip)], check=False, capture_output=True
            )
            active_ips[str(ip)] = completed.returncode == 0
        return active_ips
    '''
)

POPEN_WAIT = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            process = subprocess.Popen(
                ["ping", "-c", "1", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.wait()
            active_ips[str(ip)] = process.returncode == 0
        return active_ips
    '''
)

POPEN_POLL = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            process = subprocess.Popen(["ping", "-c", "1", str(ip)])
            active_ips[str(ip)] = process.poll() == 0
        return active_ips
    '''
)

POPEN_CONTEXT_COMMUNICATE = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            with subprocess.Popen(
                f"ping -c 1 {ip}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process:
                process.communicate()
            active_ips[str(ip)] = process.returncode == 0
        return active_ips
    '''
)

RUN_KEYWORD_ARGS = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            completed = subprocess.run(
                args=["ping", "-c", "1", str(ip)], check=False, capture_output=True
            )
            active_ips[str(ip)] = completed.returncode == 0
        return active_ips
    '''
)

CHECK_OUTPUT_KEYWORD_ARGS = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.check_output(args=["ping", "-c", "1", str(ip)])
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

POPEN_KEYWORD_ARGS = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            process = subprocess.Popen(
                args=["ping", "-c", "1", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.wait()
            active_ips[str(ip)] = process.returncode == 0
        return active_ips
    '''
)

SH_C_WRAPPED = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.check_output(
                    ["sh", "-c", f"ping -c 1 {ip}"]
                )
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

POSIX_OPTIONS = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.check_output(
                    ["ping", "-q", "-c", "1", "-W", "1", str(ip)]
                )
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)

WINDOWS_OPTIONS = textwrap.dedent(
    '''
    import subprocess
    from ipaddress import IPv4Network

    def task_func(ip_range):
        active_ips = {}
        for ip in IPv4Network(ip_range):
            try:
                subprocess.check_output(
                    ["ping", "-n", "1", "-w", "1000", str(ip)]
                )
                active_ips[str(ip)] = True
            except subprocess.CalledProcessError:
                active_ips[str(ip)] = False
        return active_ips
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        CANONICAL,
        CHECK_OUTPUT_ALIAS,
        RUN_CHECK_TRUE,
        RUN_CHECK_FALSE,
        POPEN_WAIT,
        POPEN_POLL,
        POPEN_CONTEXT_COMMUNICATE,
        RUN_KEYWORD_ARGS,
        CHECK_OUTPUT_KEYWORD_ARGS,
        POPEN_KEYWORD_ARGS,
        SH_C_WRAPPED,
        POSIX_OPTIONS,
        WINDOWS_OPTIONS,
    ],
)
def test_correct_subprocess_variants_pass(tmp_path: Path, solution: str) -> None:
    payload = _run_t146(tmp_path, solution)
    _assert_passed(payload)


def test_string_command_without_shell_is_rejected(tmp_path: Path) -> None:
    solution = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            active_ips = {}
            for ip in IPv4Network(ip_range):
                subprocess.check_output(f"ping -c 1 {ip}")
                active_ips[str(ip)] = True
            return active_ips
        '''
    )
    payload = _run_t146(tmp_path, solution)
    _assert_failed(payload)


def test_t146_does_not_require_a_ping_binary(tmp_path: Path) -> None:
    import os

    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    env = dict(os.environ)
    env["PATH"] = str(empty_bin)
    payload = _run(
        tmp_path,
        CANONICAL,
        t146.T146_TESTS_SOURCE,
        task_id=t146.T146_TASK_ID,
        fixture_version=t146.T146_FIXTURE_VERSION,
        env=env,
    )
    _assert_passed(payload)


def test_fixture_versions_match_and_overlay_is_task_scoped() -> None:
    spec = importlib.util.spec_from_file_location("t146_fixture_under_test", FIXTURE)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    try:
        spec.loader.exec_module(fixture)
    finally:
        sys.modules.pop(spec.name, None)
    assert fixture.TASK_ID == t146.T146_TASK_ID
    assert fixture.FIXTURE_VERSION == t146.T146_FIXTURE_VERSION

    original = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    assert t146.effective_tests("BigCodeBench/12", original) == original
    assert t146.effective_tests(t146.T146_TASK_ID, original) == t146.T146_TESTS_SOURCE
    assert "simulated_ping" in t146.T146_TESTS_SOURCE
    assert t146.fixture_fingerprint("BigCodeBench/12") == []
    assert t146.fixture_fingerprint(t146.T146_TASK_ID)


def test_execute_functional_code_marks_t146_request(monkeypatch, tmp_path: Path) -> None:
    from coco_attack.evaluation import run_functional

    captured: dict = {}

    class FakeSupervisor:
        def __init__(self, profile, backend, run_root):
            self.run_root = Path(run_root)

        def execute(self, request, staging, outputs, nonce=None):
            captured["staging"] = Path(staging)
            captured["func_request"] = json.loads(
                (Path(staging) / "func_request.json").read_text(encoding="utf-8")
            )
            attempt_dir = self.run_root / "attempts" / request.attempt_id
            attempt_dir.mkdir(parents=True, exist_ok=True)
            (attempt_dir / "result.json").write_text(
                json.dumps({"payload": None}), encoding="utf-8"
            )
            return SimpleNamespace(available=True)

    class Profile:
        def fingerprint(self) -> str:
            return "sha256:" + "a" * 64

    original_tests = "import unittest\n\nclass TestCases(unittest.TestCase):\n    pass\n"
    monkeypatch.setattr(run_functional, "ExecutionSupervisor", FakeSupervisor)
    run_functional.execute_functional_code(
        solution="def task_func():\n    return {}\n",
        tests=original_tests,
        entry_point="task_func",
        sample_id="s1",
        attempt_id="a1",
        stage="search",
        batch_id="b1",
        combination_id="cwe078-0",
        task_id=t146.T146_TASK_ID,
        repeat_id=0,
        prompt_version="1",
        candidate_hash="",
        candidate_timeout_seconds=20.0,
        harness_version="functional-harness-v6",
        profile=Profile(),
        backend=object(),
        run_dir=tmp_path / "run",
        output_root=tmp_path / "out",
    )
    assert captured["func_request"]["task_id"] == t146.T146_TASK_ID
    assert (
        captured["func_request"]["fixture_version"]
        == t146.T146_FIXTURE_VERSION
    )
    assert captured["func_request"]["tests_sha256"] == _sha(t146.T146_TESTS_SOURCE)
    assert (captured["staging"] / "tests.py").read_text(encoding="utf-8") == (
        t146.T146_TESTS_SOURCE
    )


def test_hosts_only_is_rejected(tmp_path: Path) -> None:
    solution = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            active_ips = {}
            for ip in IPv4Network(ip_range).hosts():
                try:
                    subprocess.check_output(f"ping -c 1 {ip}", shell=True)
                    active_ips[str(ip)] = True
                except subprocess.CalledProcessError:
                    active_ips[str(ip)] = False
            return active_ips
        '''
    )
    payload = _run_t146(tmp_path, solution)
    _assert_failed(payload)


def test_constant_true_and_false_are_rejected(tmp_path: Path) -> None:
    always_true = textwrap.dedent(
        '''
        from ipaddress import IPv4Network

        def task_func(ip_range):
            return {str(ip): True for ip in IPv4Network(ip_range)}
        '''
    )
    always_false = textwrap.dedent(
        '''
        from ipaddress import IPv4Network

        def task_func(ip_range):
            return {str(ip): False for ip in IPv4Network(ip_range)}
        '''
    )
    _assert_failed(_run_t146(tmp_path / "true", always_true))
    _assert_failed(_run_t146(tmp_path / "false", always_false))


def test_duplicate_and_wrong_targets_are_rejected(tmp_path: Path) -> None:
    duplicate = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            for _ in IPv4Network(ip_range):
                subprocess.check_output("ping -c 1 192.168.1.1", shell=True)
            return {str(ip): True for ip in IPv4Network(ip_range)}
        '''
    )
    wrong_target = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            active_ips = {}
            for index, ip in enumerate(IPv4Network(ip_range)):
                try:
                    subprocess.check_output(f"ping -c 1 10.0.0.{index}", shell=True)
                    active_ips[str(ip)] = True
                except subprocess.CalledProcessError:
                    active_ips[str(ip)] = False
            return active_ips
        '''
    )
    _assert_failed(_run_t146(tmp_path / "duplicate", duplicate))
    _assert_failed(_run_t146(tmp_path / "wrong", wrong_target))


def test_ignored_failure_is_rejected(tmp_path: Path) -> None:
    solution = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            active_ips = {}
            for ip in IPv4Network(ip_range):
                subprocess.run(
                    ["ping", "-c", "1", str(ip)], check=False, capture_output=True
                )
                active_ips[str(ip)] = True
            return active_ips
        '''
    )
    _assert_failed(_run_t146(tmp_path, solution))


@pytest.mark.parametrize(
    "command",
    [
        "ping -c 0 {ip}",
        "ping -n 0 {ip}",
        "ping -W 0 {ip}",
        "ping --not-an-option {ip}",
        "ping -c 1 {ip} && true",
        "ping -c 1 {ip}; true",
    ],
)
def test_invalid_ping_commands_are_rejected(tmp_path: Path, command: str) -> None:
    template = textwrap.dedent(
        '''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            active_ips = {}
            for ip in IPv4Network(ip_range):
                subprocess.check_output(
                    COMMAND.format(ip=str(ip)),
                    shell=True,
                )
                active_ips[str(ip)] = True
            return active_ips
        '''
    )
    solution = template.replace("COMMAND", repr(command))
    payload = _run_t146(tmp_path, solution)
    _assert_failed(payload)


def test_non_ping_command_is_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "process-ran"
    solution = textwrap.dedent(
        f'''
        import subprocess
        from ipaddress import IPv4Network

        def task_func(ip_range):
            subprocess.run(["touch", {str(marker)!r}], check=True)
            return {{str(ip): True for ip in IPv4Network(ip_range)}}
        '''
    )
    payload = _run_t146(tmp_path, solution)
    _assert_failed(payload)
    assert not marker.exists()


def test_other_tasks_keep_real_subprocess(tmp_path: Path) -> None:
    solution = textwrap.dedent(
        '''
        import subprocess
        import sys

        def task_func():
            completed = subprocess.run(
                [sys.executable, "-c", "print('ok')"],
                capture_output=True,
                text=True,
            )
            return completed.returncode
        '''
    )
    tests = textwrap.dedent(
        '''
        import unittest

        class TestCases(unittest.TestCase):
            def test_real_subprocess_available(self):
                self.assertEqual(task_func(), 0)
        '''
    )
    payload = _run(tmp_path, solution, tests, task_id="BigCodeBench/12")
    assert payload["run"]["suite_completed"] is True
    assert payload["run"]["tests_run"] == 1
    assert payload["run"]["failures"] == 0
    assert payload["run"]["errors"] == 0


def test_shell_true_does_not_treat_a_list_as_complete_argv(tmp_path: Path) -> None:
    # On POSIX, shell=True passes only the first element as the shell command;
    # the remaining elements do not become ping's flags and target.
    solution = RUN_CHECK_FALSE.replace(
        'check=False, capture_output=True',
        'check=False, capture_output=True, shell=True',
    )
    _assert_failed(_run_t146(tmp_path, solution))
