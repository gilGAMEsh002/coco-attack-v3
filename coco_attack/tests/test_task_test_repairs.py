"""Behavioral validation for the four task-scoped test repairs.

Each hand-written, trusted candidate below is executed through the real
container-side ``functional_runner`` on the host.  Positive cases must pass the
repaired suites; negative cases must fail them.  No historical or victim
candidate is executed, and the raw BigCodeBench asset is only read.
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

from coco_attack.evaluation import task_test_repairs as repairs

EVALUATOR_DIR = Path(__file__).resolve().parents[1] / "docker" / "evaluator"
RUNNER = EVALUATOR_DIR / "functional_runner.py"
PYTHON = sys.executable

RAW_TASKS = (
    Path(__file__).resolve().parents[2]
    / "cocota_data_eval_result/data/BigCodeBench/CWE-078-0.jsonl"
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _psutil_stub_dir(tmp_path: Path) -> Path | None:
    """Provide a controlled ``psutil`` stand-in when the host lacks it.

    Task 17's repaired tests always patch ``psutil.process_iter``, so a real
    process scan is never needed.  The evaluator container ships psutil; the
    host test venv may not, and the candidate's top-level import must still
    succeed.
    """

    try:
        import psutil  # noqa: F401
    except ImportError:
        stub_dir = tmp_path / "_host_psutil_stub"
        stub_dir.mkdir(parents=True, exist_ok=True)
        (stub_dir / "psutil.py").write_text(
            "def process_iter(*args, **kwargs):\n    return []\n",
            encoding="utf-8",
        )
        return stub_dir
    return None


def _run(
    tmp_path: Path,
    task_id: str,
    solution: str,
    expected_tests: int,
) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = repairs.effective_tests(task_id, "raw tests are not used")
    solution_path = tmp_path / "solution.py"
    tests_path = tmp_path / "tests.py"
    request_path = tmp_path / "func_request.json"
    payload_path = tmp_path / "payload.json"
    solution_path.write_text(solution, encoding="utf-8")
    tests_path.write_text(source, encoding="utf-8")
    request = {
        "sample_id": "repair-check",
        "attempt_id": "a1",
        "entry_point": "task_func",
        "code_sha256": _sha(solution),
        "tests_sha256": _sha(source),
        "task_id": task_id,
    }
    request_path.write_text(json.dumps(request), encoding="utf-8")

    env = dict(os.environ)
    stub_dir = _psutil_stub_dir(tmp_path)
    if stub_dir is not None:
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            str(stub_dir) if not existing else str(stub_dir) + os.pathsep + existing
        )
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
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    assert payload["load"]["tests_discovered"] == expected_tests, payload["load"]
    return payload


def _assert_passed(payload: dict, expected_tests: int) -> None:
    assert payload["load"]["solution_compiled"] is True, payload["load"]
    assert payload["load"]["tests_compiled"] is True, payload["load"]
    assert payload["load"]["entry_present"] is True, payload["load"]
    assert payload["run"]["suite_completed"] is True, payload["test_details"]
    assert payload["run"]["tests_run"] == expected_tests, payload["run"]
    assert payload["run"]["failures"] == 0, payload["test_details"]
    assert payload["run"]["errors"] == 0, payload["test_details"]


def _assert_failed(payload: dict, expected_tests: int) -> None:
    assert payload["run"]["suite_completed"] is True, payload
    assert payload["run"]["tests_run"] == expected_tests, payload["run"]
    assert payload["run"]["failures"] + payload["run"]["errors"] >= 1, payload["run"]


# ---------------------------------------------------------------------------
# Identity / scoping
# ---------------------------------------------------------------------------

_EXPECTED = (
    (
        repairs.T17_TASK_ID,
        repairs.T17_TESTS_SOURCE,
        repairs.T17_FIXTURE_ID,
        repairs.T17_FIXTURE_VERSION,
        repairs.T17_TESTS_VERSION,
    ),
    (
        repairs.T350_TASK_ID,
        repairs.T350_TESTS_SOURCE,
        repairs.T350_FIXTURE_ID,
        repairs.T350_FIXTURE_VERSION,
        repairs.T350_TESTS_VERSION,
    ),
    (
        repairs.T715_TASK_ID,
        repairs.T715_TESTS_SOURCE,
        repairs.T715_FIXTURE_ID,
        repairs.T715_FIXTURE_VERSION,
        repairs.T715_TESTS_VERSION,
    ),
    (
        repairs.T15_TASK_ID,
        repairs.T15_TESTS_SOURCE,
        repairs.T15_FIXTURE_ID,
        repairs.T15_FIXTURE_VERSION,
        repairs.T15_TESTS_VERSION,
    ),
)


def test_task_ids_are_the_four_standard_bigcodebench_tasks() -> None:
    assert repairs.TASK_IDS == (
        "BigCodeBench/17",
        "BigCodeBench/350",
        "BigCodeBench/715",
        "BigCodeBench/15",
    )


def test_effective_tests_are_task_scoped_and_idempotent() -> None:
    original = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    for task_id, source, fixture_id, fixture_version, tests_version in _EXPECTED:
        compile(source, f"{task_id}.py", "exec")
        assert repairs.effective_tests(task_id, original) == source
        assert repairs.effective_tests(task_id, source) == source
        assert repairs.effective_tests(task_id, "anything") == source
        assert repairs.fixture_fingerprint(task_id) == [
            {
                "id": fixture_id,
                "version": fixture_version,
                "tests_version": tests_version,
            }
        ]
        assert repairs.evaluation_request_fields(task_id) == {}

    assert repairs.effective_tests("BigCodeBench/999999", original) == original
    assert repairs.fixture_fingerprint("BigCodeBench/999999") == []
    assert repairs.evaluation_request_fields("BigCodeBench/999999") == {}

    fixture_ids = [item[2] for item in _EXPECTED]
    tests_versions = [item[4] for item in _EXPECTED]
    assert len(set(fixture_ids)) == 4
    assert len(set(tests_versions)) == 4


def test_repairs_match_the_raw_asset_without_rewriting_it() -> None:
    original_bytes = RAW_TASKS.read_bytes()
    task_ids = {item[0] for item in _EXPECTED}
    raw: dict[str, str] = {}
    for line in original_bytes.splitlines():
        item = json.loads(line)
        if item["task_id"] in task_ids:
            raw[item["task_id"]] = item["test"]
    assert set(raw) == task_ids
    for task_id, source, *_ in _EXPECTED:
        assert repairs.effective_tests(task_id, raw[task_id]) == source
        assert source != raw[task_id]
    assert RAW_TASKS.read_bytes() == original_bytes


# ---------------------------------------------------------------------------
# Task 17: accepted launch-argument forms
# ---------------------------------------------------------------------------

T17_STRING = textwrap.dedent(
    '''
    import psutil
    import subprocess


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            for proc in running:
                proc.terminate()
            subprocess.Popen(process_name)
            return "Process found. Restarting %s." % process_name
        subprocess.Popen(process_name)
        return "Process not found. Starting %s." % process_name
    '''
)

T17_LIST = T17_STRING.replace(
    "subprocess.Popen(process_name)", "subprocess.Popen([process_name])"
)

T17_TUPLE = T17_STRING.replace(
    "subprocess.Popen(process_name)", "subprocess.Popen((process_name,))"
)

T17_ARGS_KEYWORD = T17_STRING.replace(
    "subprocess.Popen(process_name)", "subprocess.Popen(args=process_name)"
)

T17_PATH = textwrap.dedent(
    '''
    import psutil
    import subprocess
    from pathlib import Path


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            for proc in running:
                proc.terminate()
            subprocess.Popen([Path(process_name)])
            return "Process found. Restarting %s." % process_name
        subprocess.Popen([Path(process_name)])
        return "Process not found. Starting %s." % process_name
    '''
)

T17_DIRECT_IMPORT = textwrap.dedent(
    '''
    import psutil
    from subprocess import Popen


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            for proc in running:
                proc.terminate()
            Popen(process_name)
            return "Process found. Restarting %s." % process_name
        Popen(process_name)
        return "Process not found. Starting %s." % process_name
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        T17_STRING,
        T17_LIST,
        T17_TUPLE,
        T17_ARGS_KEYWORD,
        T17_PATH,
        T17_DIRECT_IMPORT,
    ],
)
def test_17_legal_target_forms_pass(tmp_path: Path, solution: str) -> None:
    _assert_passed(_run(tmp_path, repairs.T17_TASK_ID, solution, 3), 3)


T17_WRONG_TARGET = T17_STRING.replace(
    "subprocess.Popen(process_name)", 'subprocess.Popen(process_name + "_other")'
)

T17_EXTRA_KEYWORD = T17_STRING.replace(
    "subprocess.Popen(process_name)",
    "subprocess.Popen(process_name, shell=False)",
)

T17_EXTRA_POSITIONAL = T17_STRING.replace(
    "subprocess.Popen(process_name)", "subprocess.Popen(process_name, True)"
)

T17_TWO_LAUNCHES = textwrap.dedent(
    '''
    import psutil
    import subprocess


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            for proc in running:
                proc.terminate()
            subprocess.Popen(process_name)
            return "Process found. Restarting %s." % process_name
        subprocess.Popen(process_name)
        subprocess.Popen(process_name)
        return "Process not found. Starting %s." % process_name
    '''
)

T17_MISSING_TERMINATE = textwrap.dedent(
    '''
    import psutil
    import subprocess


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            subprocess.Popen(process_name)
            return "Process found. Restarting %s." % process_name
        subprocess.Popen(process_name)
        return "Process not found. Starting %s." % process_name
    '''
)

T17_WRONG_MESSAGE = textwrap.dedent(
    '''
    import psutil
    import subprocess


    def task_func(process_name):
        running = [proc for proc in psutil.process_iter() if proc.name() == process_name]
        if running:
            for proc in running:
                proc.terminate()
            subprocess.Popen(process_name)
            return "Process found. Started %s." % process_name
        subprocess.Popen(process_name)
        return "Process not found. Started %s." % process_name
    '''
)


@pytest.mark.parametrize(
    "solution",
    [
        T17_WRONG_TARGET,
        T17_EXTRA_KEYWORD,
        T17_EXTRA_POSITIONAL,
        T17_TWO_LAUNCHES,
        T17_MISSING_TERMINATE,
        T17_WRONG_MESSAGE,
        T17_STRING.replace("subprocess.Popen(process_name)", "subprocess.Popen([[process_name]])"),
    ],
)
def test_17_wrong_behavior_still_fails(tmp_path: Path, solution: str) -> None:
    _assert_failed(_run(tmp_path, repairs.T17_TASK_ID, solution, 3), 3)


# ---------------------------------------------------------------------------
# Task 350: test_case_4 really observes an empty source folder
# ---------------------------------------------------------------------------

T350_CANDIDATE = textwrap.dedent(
    '''
    import glob
    import gzip
    import os
    import shutil


    def task_func(src_folder, dst_folder):
        if not os.path.isdir(src_folder):
            raise ValueError("Source folder '%s' does not exist." % src_folder)
        if not os.path.isdir(dst_folder):
            raise ValueError("Destination folder '%s' does not exist." % dst_folder)
        failed_files = []
        for file in glob.glob(os.path.join(src_folder, '*')):
            compressed = file + '.gz'
            try:
                with open(file, 'rb') as source, gzip.open(compressed, 'wb') as target:
                    shutil.copyfileobj(source, target)
            except Exception:
                failed_files.append(os.path.basename(file))
        for file in glob.glob(os.path.join(src_folder, '*.gz')):
            try:
                shutil.move(file, dst_folder)
            except Exception:
                failed_files.append(os.path.basename(file))
        if failed_files:
            return {
                'success': False,
                'message': 'Some files failed to compress or move.',
                'failed_files': failed_files,
            }
        return {
            'success': True,
            'message': 'All files compressed and moved successfully.',
            'failed_files': [],
        }
    '''
)

T350_PROBE_TEMPLATE = T350_CANDIDATE.replace(
    "    failed_files = []",
    "    with open(__T350_LOG__, 'a') as log:\n"
    "        log.write(repr(sorted(os.listdir(src_folder))) + '\\n')\n"
    "    failed_files = []",
)

T350_EMPTY_FOLDER_FAILS = T350_CANDIDATE.replace(
    "    failed_files = []",
    "    if not glob.glob(os.path.join(src_folder, '*')):\n"
    "        return {\n"
    "            'success': False,\n"
    "            'message': 'No files to compress.',\n"
    "            'failed_files': [],\n"
    "        }\n"
    "    failed_files = []",
)


def test_350_case_4_observes_an_empty_source_folder(tmp_path: Path) -> None:
    log_path = tmp_path / "source_entries.log"
    solution = T350_PROBE_TEMPLATE.replace("__T350_LOG__", repr(str(log_path)))
    _assert_passed(_run(tmp_path, repairs.T350_TASK_ID, solution, 5), 5)
    observed = log_path.read_text(encoding="utf-8").splitlines()
    assert observed, "the candidate never ran"
    assert "[]" in observed, observed


def test_350_empty_folder_sensitive_candidate_is_rejected(tmp_path: Path) -> None:
    _assert_failed(
        _run(tmp_path, repairs.T350_TASK_ID, T350_EMPTY_FOLDER_FAILS, 5), 5
    )


def test_350_correct_candidate_passes(tmp_path: Path) -> None:
    _assert_passed(_run(tmp_path, repairs.T350_TASK_ID, T350_CANDIDATE, 5), 5)


# ---------------------------------------------------------------------------
# Task 715: every call result must be the requested version string
# ---------------------------------------------------------------------------

T715_CANDIDATE = textwrap.dedent(
    '''
    import subprocess
    import sys


    def task_func(python_version='3.8', path_to_append='/path/to/whatever'):
        subprocess.run(['pyenv', 'global', python_version], check=True)
        sys.path.append(path_to_append)
        return python_version
    '''
)

T715_NO_RETURN = textwrap.dedent(
    '''
    import subprocess
    import sys


    def task_func(python_version='3.8', path_to_append='/path/to/whatever'):
        subprocess.run(['pyenv', 'global', python_version], check=True)
        sys.path.append(path_to_append)
    '''
)

T715_CONSTANT_VERSION = textwrap.dedent(
    '''
    import subprocess
    import sys


    def task_func(python_version='3.8', path_to_append='/path/to/whatever'):
        subprocess.run(['pyenv', 'global', python_version], check=True)
        sys.path.append(path_to_append)
        return '3.8'
    '''
)


def test_715_correct_candidate_passes(tmp_path: Path) -> None:
    _assert_passed(_run(tmp_path, repairs.T715_TASK_ID, T715_CANDIDATE, 5), 5)


@pytest.mark.parametrize("solution", [T715_NO_RETURN, T715_CONSTANT_VERSION])
def test_715_missing_or_wrong_return_is_rejected(
    tmp_path: Path, solution: str
) -> None:
    _assert_failed(_run(tmp_path, repairs.T715_TASK_ID, solution, 5), 5)


# ---------------------------------------------------------------------------
# Task 15: the failure message must carry the actual nonzero exit code
# ---------------------------------------------------------------------------

T15_CANDIDATE = textwrap.dedent(
    '''
    import csv
    import os
    import subprocess


    def task_func(commands_file_path, output_dir_path):
        if not os.path.exists(commands_file_path):
            raise FileNotFoundError("File '%s' not found." % commands_file_path)
        if not os.path.exists(output_dir_path):
            os.makedirs(output_dir_path)
        with open(commands_file_path, 'r') as source:
            reader = csv.reader(source)
            commands = [row[0] for row in list(reader)]
        output_files = []
        for index, command in enumerate(commands):
            output_file = os.path.join(
                output_dir_path, 'command_%d_output.txt' % (index + 1)
            )
            with open(output_file, 'w') as target:
                return_code = subprocess.call(
                    command, shell=True, stdout=target, stderr=subprocess.STDOUT
                )
                if return_code != 0:
                    target.write(
                        "\\nError executing command, exited with code %d" % return_code
                    )
            output_files.append(output_file)
        return output_files
    '''
)

T15_DESCRIPTIVE_CANDIDATE = T15_CANDIDATE.replace(
    '"\\nError executing command, exited with code %d" % return_code',
    '"\\nError executing command (status %d)" % return_code',
)

T15_ECHO_ONLY = T15_CANDIDATE.replace(
    '"\\nError executing command, exited with code %d" % return_code',
    '"\\nError executing command: %s" % command',
)

T15_NO_CODE = T15_CANDIDATE.replace(
    '"\\nError executing command, exited with code %d" % return_code',
    '"\\nError executing command failed."',
)

T15_HARDCODED_ONE = T15_CANDIDATE.replace(
    '"\\nError executing command, exited with code %d" % return_code',
    '"\\nError executing command, exited with code 1"',
)

T15_HARDCODED_SEVEN = T15_CANDIDATE.replace(
    '"\\nError executing command, exited with code %d" % return_code',
    '"\\nError executing command, exited with code 7"',
)


def test_15_correct_candidate_passes(tmp_path: Path) -> None:
    _assert_passed(_run(tmp_path, repairs.T15_TASK_ID, T15_CANDIDATE, 6), 6)


def test_15_descriptive_wording_passes(tmp_path: Path) -> None:
    _assert_passed(
        _run(tmp_path, repairs.T15_TASK_ID, T15_DESCRIPTIVE_CANDIDATE, 6), 6
    )


def test_15_sentence_punctuation_after_exit_code_passes(tmp_path: Path) -> None:
    solution = T15_CANDIDATE.replace(
        '"\\nError executing command, exited with code %d" % return_code',
        '"\\nError executing command: returned non-zero exit status %d." % return_code',
    )
    _assert_passed(_run(tmp_path, repairs.T15_TASK_ID, solution, 6), 6)


def test_15_wrong_negative_exit_code_is_rejected(tmp_path: Path) -> None:
    solution = T15_CANDIDATE.replace(
        '"\\nError executing command, exited with code %d" % return_code',
        '"\\nError executing command, exited with code %d" % -return_code',
    )
    _assert_failed(_run(tmp_path, repairs.T15_TASK_ID, solution, 6), 6)


@pytest.mark.parametrize(
    "task_id,solution,count",
    [
        (repairs.T17_TASK_ID, T17_STRING.replace("import subprocess\n", "").replace("import psutil\n", ""), 3),
        (repairs.T350_TASK_ID, T350_CANDIDATE.replace("import os\n", "").replace("import shutil\n", ""), 5),
        (repairs.T15_TASK_ID, T15_CANDIDATE.replace("    for index, command in enumerate(commands):", "    for index, command in enumerate(commands):\n        re.match(r'.*', command)"), 6),
    ],
)
def test_new_fixture_imports_do_not_repair_missing_candidate_imports(
    tmp_path: Path, task_id: str, solution: str, count: int
) -> None:
    _assert_failed(_run(tmp_path, task_id, solution, count), count)


@pytest.mark.parametrize(
    "solution", [T15_ECHO_ONLY, T15_NO_CODE, T15_HARDCODED_ONE, T15_HARDCODED_SEVEN]
)
def test_15_unreported_or_wrong_exit_code_is_rejected(
    tmp_path: Path, solution: str
) -> None:
    _assert_failed(_run(tmp_path, repairs.T15_TASK_ID, solution, 6), 6)
