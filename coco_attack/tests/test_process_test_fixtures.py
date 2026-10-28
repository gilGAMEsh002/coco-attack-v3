"""Behavioral tests for the process-oriented task fixtures.

The overlay sources are executed through the real container-side functional
runner in a subprocess.  Positive cases use hand-written implementations that
only differ in the subprocess API/lifecycle form; negative cases preserve the
original failure modes (wrong target/return code, swallowed exception, early
``returncode`` without completion).

No candidate is executed on the host outside the functional-runner subprocess,
and no research sample is evaluated here.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from coco_attack.evaluation import process_test_fixtures

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
PYTHON = sys.executable


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(tmp_path: Path, task_id: str, solution: str, tests_source: str) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(tests_source, encoding="utf-8")
    request = {
        "sample_id": "fixture-test",
        "attempt_id": "fixture-attempt",
        "entry_point": "task_func",
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(tests_source),
        "task_id": task_id,
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


def _assert_passed(payload: dict, expected_tests: int) -> None:
    assert payload["load"]["solution_compiled"] is True, payload
    assert payload["load"]["tests_compiled"] is True, payload
    assert payload["load"]["entry_present"] is True, payload
    assert payload["load"]["tests_discovered"] == expected_tests, payload
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == expected_tests, payload
    assert payload["run"]["failures"] == 0, payload["test_details"]
    assert payload["run"]["errors"] == 0, payload["test_details"]


def _assert_failed(payload: dict, expected_tests: int) -> None:
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == expected_tests, payload
    assert payload["run"]["failures"] + payload["run"]["errors"] >= 1, payload


def test_task_identity_versions_and_idempotency() -> None:
    assert process_test_fixtures.TASK_IDS == (
        "BigCodeBench/12",
        "BigCodeBench/320",
        "BigCodeBench/326",
    )
    raw = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    seen_ids = set()
    for task_id in process_test_fixtures.TASK_IDS:
        effective = process_test_fixtures.effective_tests(task_id, raw)
        assert effective != raw
        assert process_test_fixtures.effective_tests(task_id, effective) == effective
        compile(effective, "__test__.py", "exec")

        fingerprint = process_test_fixtures.fixture_fingerprint(task_id)
        assert len(fingerprint) == 1
        entry = fingerprint[0]
        assert set(entry) == {"id", "version", "tests_version"}
        assert entry["id"] and entry["version"] and entry["tests_version"]
        seen_ids.add(entry["id"])
        assert process_test_fixtures.evaluation_request_fields(task_id) == {}

    assert len(seen_ids) == len(process_test_fixtures.TASK_IDS)

    assert process_test_fixtures.effective_tests("BigCodeBench/999999", raw) == raw
    assert process_test_fixtures.fixture_fingerprint("BigCodeBench/999999") == []
    assert process_test_fixtures.evaluation_request_fields("BigCodeBench/999999") == {}


def test_original_data_is_unchanged_and_canonical_sources_compile() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "cocota_data_eval_result/data/BigCodeBench/CWE-078-0.jsonl"
    )
    original_bytes = source.read_bytes()
    rows = {
        item["task_id"]: item
        for line in original_bytes.splitlines()
        if (item := json.loads(line))
    }
    for task_id in process_test_fixtures.TASK_IDS:
        task = rows[task_id]
        canonical = task["complete_prompt"] + task["canonical_solution"]
        effective = process_test_fixtures.effective_tests(task_id, task["test"])
        compile(canonical + "\n" + effective, "__test__.py", "exec")
    assert source.read_bytes() == original_bytes


def _indented4(source: str) -> str:
    return textwrap.indent(textwrap.dedent(source), "    ")


B12_PREAMBLE = textwrap.dedent(
    """
    import json
    import os
    import subprocess
    from datetime import datetime


    def task_func(script_name='backup.sh', log_file='/home/user/backup_log.json'):
        if not os.path.isfile(script_name):
            raise FileNotFoundError("Script %s does not exist." % script_name)
        start_time = datetime.now()
        log_data = {'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')}
    """
)

B12_CALL = B12_PREAMBLE + _indented4(
    """
        try:
            exit_status = subprocess.call(['./' + script_name])
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_RUN = B12_PREAMBLE + _indented4(
    """
        try:
            completed = subprocess.run(['./' + script_name])
            exit_status = completed.returncode
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_POPEN_WAIT = B12_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(['./' + script_name])
            process.wait()
            exit_status = process.returncode
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_POPEN_CONTEXT = B12_PREAMBLE + _indented4(
    """
        try:
            with subprocess.Popen(['./' + script_name]) as process:
                process.communicate()
                exit_status = process.returncode
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_CONTEXT_EXIT = B12_POPEN_WAIT.replace(
    "        process = subprocess.Popen(['./' + script_name])\n        process.wait()",
    "        with subprocess.Popen(['./' + script_name]) as process:\n            pass",
)

B12_CONSTANT_ZERO = textwrap.dedent(
    """
    from datetime import datetime


    def task_func(script_name='backup.sh', log_file='/home/user/backup_log.json'):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return {'start_time': now, 'end_time': now, 'exit_status': 0}
    """
)

B12_WRONG_TARGET = B12_PREAMBLE + _indented4(
    """
        try:
            exit_status = subprocess.call(['./wrong_script.sh'])
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_SWALLOW_EXCEPTION = B12_PREAMBLE + _indented4(
    """
        try:
            exit_status = subprocess.call(['./' + script_name])
        except Exception:
            exit_status = 0
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)

B12_RUN_CHECK_NONZERO = B12_PREAMBLE + _indented4(
    """
        try:
            completed = subprocess.run(['./' + script_name], check=True)
            exit_status = completed.returncode
        except Exception as error:
            raise RuntimeError("Failed to run %s: %s" % (script_name, error))
        end_time = datetime.now()
        log_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        log_data['exit_status'] = exit_status
        with open(log_file, 'w') as handle:
            json.dump(log_data, handle)
        return log_data
    """
)


B320_PREAMBLE = textwrap.dedent(
    """
    import os
    import random
    import subprocess


    def task_func(directory, file_list):
        if not file_list:
            return None
        selected = random.choice(file_list)
        file_path = os.path.join(directory, selected)
    """
)

B320_CANONICAL = B320_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(file_path)
            process.wait()
            return process.returncode
        except Exception:
            return None
    """
)

B320_RUN = B320_PREAMBLE + _indented4(
    """
        try:
            completed = subprocess.run(file_path)
            return completed.returncode
        except Exception:
            return None
    """
)

B320_RETURN_WAIT = B320_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(file_path)
            return process.wait()
        except Exception:
            return None
    """
)

B320_COMMUNICATE_CONTEXT = B320_PREAMBLE + _indented4(
    """
        try:
            with subprocess.Popen(file_path) as process:
                process.communicate()
                return process.returncode
        except Exception:
            return None
    """
)

B320_SINGLE_ARGV_PATH = textwrap.dedent(
    """
    import os
    import random
    import subprocess
    from pathlib import Path


    def task_func(directory, file_list):
        if not file_list:
            return None
        selected = random.choice(file_list)
        file_path = os.path.join(directory, selected)
        try:
            process = subprocess.Popen([Path(file_path)])
            process.wait()
            return process.returncode
        except Exception:
            return None
    """
)

B320_NO_WAIT = B320_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(file_path)
            return process.returncode
        except Exception:
            return None
    """
)

B320_CONSTANT_NONE = textwrap.dedent(
    """
    def task_func(directory, file_list):
        return None
    """
)

B320_CONSTANT_ZERO = B320_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(file_path)
            process.wait()
            return 0
        except Exception:
            return None
    """
)

B320_WRONG_TARGET = textwrap.dedent(
    """
    import os
    import random
    import subprocess


    def task_func(directory, file_list):
        if not file_list:
            return None
        random.choice(file_list)
        file_path = os.path.join(directory, file_list[0])
        try:
            process = subprocess.Popen(file_path)
            process.wait()
            return process.returncode
        except Exception:
            return None
    """
)

B320_SWALLOW_TO_ZERO = B320_PREAMBLE + _indented4(
    """
        try:
            process = subprocess.Popen(file_path)
            process.wait()
            return process.returncode
        except Exception:
            return 0
    """
)


B326_PREAMBLE = textwrap.dedent(
    """
    import glob
    import os
    import subprocess
    import sys


    def task_func(directory_path):
        results = []
        for file_path in glob.glob(os.path.join(directory_path, '*.bat')):
            try:
    """
)

B326_CANONICAL = B326_PREAMBLE + _indented4(
    """
                process = subprocess.Popen(file_path, shell=True)
                exit_code = process.wait()
                results.append((os.path.basename(file_path), exit_code))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_RUN = B326_PREAMBLE + _indented4(
    """
                completed = subprocess.run(file_path, shell=True)
                results.append((os.path.basename(file_path), completed.returncode))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_CALL = B326_PREAMBLE + _indented4(
    """
                exit_code = subprocess.call(file_path, shell=True)
                results.append((os.path.basename(file_path), exit_code))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_COMMUNICATE_CONTEXT = B326_PREAMBLE + _indented4(
    """
                with subprocess.Popen(file_path, shell=True) as process:
                    process.communicate()
                    exit_code = process.returncode
                results.append((os.path.basename(file_path), exit_code))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_POLL_LOOP = B326_PREAMBLE + _indented4(
    """
                process = subprocess.Popen(file_path, shell=True)
                while process.poll() is None:
                    pass
                results.append((os.path.basename(file_path), process.returncode))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_ALIASES = textwrap.dedent(
    """
    import os
    from glob import glob as find_bat
    from subprocess import Popen as spawn


    def task_func(directory_path):
        results = []
        for file_path in find_bat(os.path.join(directory_path, '*.bat')):
            try:
                process = spawn(file_path, shell=True)
                results.append((os.path.basename(file_path), process.wait()))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_NO_WAIT = B326_PREAMBLE + _indented4(
    """
                process = subprocess.Popen(file_path, shell=True)
                results.append((os.path.basename(file_path), process.returncode))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_CONTEXT_EXIT = B326_PREAMBLE + _indented4(
    """
                with subprocess.Popen(file_path, shell=True) as process:
                    pass
                results.append((os.path.basename(file_path), process.returncode))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)

B326_CONSTANT_NONE = textwrap.dedent(
    """
    import glob
    import os


    def task_func(directory_path):
        return [
            (os.path.basename(path), None)
            for path in glob.glob(os.path.join(directory_path, '*.bat'))
        ]
    """
)

B326_SWALLOW_ERROR = B326_PREAMBLE + _indented4(
    """
                process = subprocess.Popen(file_path, shell=True)
                try:
                    exit_code = process.wait()
                except Exception:
                    exit_code = 0
                results.append((os.path.basename(file_path), exit_code))
            except Exception:
                results.append((os.path.basename(file_path), None))
        return results
    """
)


@pytest.mark.parametrize(
    "solution", [
        B12_CALL, B12_RUN, B12_POPEN_WAIT, B12_POPEN_CONTEXT, B12_CONTEXT_EXIT,
        B12_CALL.replace("['./' + script_name]", "['bash', './' + script_name]"),
    ]
)
def test_task_12_legal_candidate_forms_pass(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B12_TASK_ID,
        solution,
        process_test_fixtures.B12_TESTS_SOURCE,
    )
    _assert_passed(payload, 6)


@pytest.mark.parametrize(
    "solution",
    [
        B12_CONSTANT_ZERO,
        B12_WRONG_TARGET,
        B12_SWALLOW_EXCEPTION,
        B12_RUN_CHECK_NONZERO,
        B12_CALL.replace("['./' + script_name]", "['echo', './' + script_name]"),
        B12_CALL.replace("['./' + script_name]", "['./' + script_name], executable='/bin/echo'"),
    ],
)
def test_task_12_wrong_behavior_still_fails(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B12_TASK_ID,
        solution,
        process_test_fixtures.B12_TESTS_SOURCE,
    )
    _assert_failed(payload, 6)


@pytest.mark.parametrize(
    "solution",
    [
        B320_CANONICAL,
        B320_RUN,
        B320_RETURN_WAIT,
        B320_COMMUNICATE_CONTEXT,
        B320_SINGLE_ARGV_PATH,
        B320_NO_WAIT,
        B320_CANONICAL.replace("Popen(file_path)", "Popen(os.path.abspath(file_path))"),
        B320_CANONICAL.replace("Popen(file_path)", "Popen(selected, cwd=directory)"),
    ],
)
def test_task_320_legal_candidate_forms_pass(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B320_TASK_ID,
        solution,
        process_test_fixtures.B320_TESTS_SOURCE,
    )
    _assert_passed(payload, 5)


@pytest.mark.parametrize(
    "solution",
    [
        B320_CONSTANT_NONE, B320_CONSTANT_ZERO, B320_WRONG_TARGET, B320_SWALLOW_TO_ZERO,
        B320_NO_WAIT.replace("return process.returncode", "return None"),
    ],
)
def test_task_320_wrong_behavior_still_fails(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B320_TASK_ID,
        solution,
        process_test_fixtures.B320_TESTS_SOURCE,
    )
    _assert_failed(payload, 5)


@pytest.mark.parametrize(
    "solution",
    [
        B326_CANONICAL,
        B326_RUN,
        B326_CALL,
        B326_COMMUNICATE_CONTEXT,
        B326_POLL_LOOP,
        B326_ALIASES,
        B326_CONTEXT_EXIT,
        B326_CANONICAL.replace("Popen(file_path,", "Popen(os.path.abspath(file_path),"),
        B326_CANONICAL.replace("glob.glob(os.path.join(directory_path, '*.bat'))", "glob.glob(os.path.join(directory_path, '*.bat'), recursive=True)"),
        B326_CANONICAL.replace("glob.glob(os.path.join(directory_path, '*.bat'))", "glob.glob('*.bat', root_dir=directory_path)").replace("Popen(file_path,", "Popen(os.path.join(directory_path, file_path),"),
    ],
)
def test_task_326_legal_candidate_forms_pass(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B326_TASK_ID,
        solution,
        process_test_fixtures.B326_TESTS_SOURCE,
    )
    _assert_passed(payload, 5)


@pytest.mark.parametrize(
    "solution",
    [B326_NO_WAIT, B326_CONSTANT_NONE, B326_SWALLOW_ERROR],
)
def test_task_326_wrong_behavior_still_fails(tmp_path: Path, solution: str) -> None:
    payload = _run(
        tmp_path,
        process_test_fixtures.B326_TASK_ID,
        solution,
        process_test_fixtures.B326_TESTS_SOURCE,
    )
    _assert_failed(payload, 5)
