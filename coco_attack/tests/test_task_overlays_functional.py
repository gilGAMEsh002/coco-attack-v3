"""Task overlay scoping, version identity and production-path integration.

Behavioral positive/negative cases live in each task-specific test module.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_bytes
from coco_attack.evaluation import t1102, t146, t195, t745, task_overlays


def test_overlays_are_task_scoped_and_versioned() -> None:
    original = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    cases = [
        (t146.T146_TASK_ID, t146.T146_TESTS_SOURCE),
        (t195.T195_TASK_ID, t195.T195_TESTS_SOURCE),
        (t745.T745_TASK_ID, t745.T745_TESTS_SOURCE),
        (t1102.T1102_TASK_ID, t1102.T1102_TESTS_SOURCE),
    ]
    for task_id, expected in cases:
        assert task_overlays.effective_tests(task_id, original) == expected
        assert task_overlays.fixture_fingerprint(task_id)
    assert task_overlays.effective_tests("BigCodeBench/999999", original) == original
    assert task_overlays.fixture_fingerprint("BigCodeBench/999999") == []
    assert task_overlays.evaluation_request_fields("BigCodeBench/999999") == {}
    assert task_overlays.evaluation_request_fields(t195.T195_TASK_ID) == {}
    assert task_overlays.evaluation_request_fields(t1102.T1102_TASK_ID) == {}
    assert task_overlays.evaluation_request_fields(t745.T745_TASK_ID) == {}
    assert (
        task_overlays.evaluation_request_fields(t146.T146_TASK_ID)["fixture_version"]
        == t146.T146_FIXTURE_VERSION
    )

    assert task_overlays.fixture_fingerprint(t195.T195_TASK_ID) == [
        {
            "id": t195.T195_FIXTURE_ID,
            "version": t195.T195_FIXTURE_VERSION,
            "tests_version": t195.T195_TESTS_VERSION,
        }
    ]
    assert task_overlays.fixture_fingerprint(t1102.T1102_TASK_ID) == [
        {
            "id": t1102.T1102_FIXTURE_ID,
            "version": t1102.T1102_FIXTURE_VERSION,
            "tests_version": t1102.T1102_TESTS_VERSION,
        }
    ]
    assert task_overlays.fixture_fingerprint(t745.T745_TASK_ID)


def test_overlay_changes_the_test_hash_used_by_the_cache_fingerprint() -> None:
    from coco_attack.assets.artifacts import canonical_json_bytes

    raw_195 = "import unittest\nclass TestCases(unittest.TestCase):\n    pass\n"
    overlaid_195 = task_overlays.effective_tests(t195.T195_TASK_ID, raw_195)
    overlaid_1102 = task_overlays.effective_tests(
        t1102.T1102_TASK_ID, raw_195
    )
    assert sha256_bytes(overlaid_195.encode("utf-8")) != sha256_bytes(
        raw_195.encode("utf-8")
    )
    assert sha256_bytes(overlaid_1102.encode("utf-8")) != sha256_bytes(
        raw_195.encode("utf-8")
    )
    assert overlaid_195 == t195.T195_TESTS_SOURCE
    assert overlaid_1102 == t1102.T1102_TESTS_SOURCE
    # fixture_sha256 is part of the functional cache fingerprint; a versioned
    # overlay must not collapse to the no-fixture value.
    no_fixture = sha256_bytes(canonical_json_bytes([]))
    for task_id in (t195.T195_TASK_ID, t745.T745_TASK_ID, t1102.T1102_TASK_ID):
        fixture = sha256_bytes(
            canonical_json_bytes(task_overlays.fixture_fingerprint(task_id))
        )
        assert fixture != no_fixture


def test_functional_and_iteration_paths_share_the_dispatcher() -> None:
    from coco_attack.evaluation import run_functional
    from coco_attack.iteration import code_check

    for task_id, expected in (
        (t195.T195_TASK_ID, t195.T195_TESTS_SOURCE),
        (t745.T745_TASK_ID, t745.T745_TESTS_SOURCE),
        (t1102.T1102_TASK_ID, t1102.T1102_TESTS_SOURCE),
    ):
        assert run_functional.effective_tests(task_id, "raw") == expected
        assert code_check.effective_tests(task_id, "raw") == expected
        assert (
            run_functional.fixture_fingerprint(task_id)
            == task_overlays.fixture_fingerprint(task_id)
        )


@pytest.mark.parametrize("number", [12, 17, 320, 322, 326, 350, 715, 810, 15])
def test_repaired_raw_tasks_use_the_same_version_in_both_production_paths(number: int) -> None:
    from coco_attack.assets.artifacts import canonical_json_bytes
    from coco_attack.evaluation import run_functional
    from coco_attack.iteration import code_check

    source = (
        Path(__file__).resolve().parents[2]
        / "cocota_data_eval_result/data/BigCodeBench/CWE-078-0.jsonl"
    )
    original_bytes = source.read_bytes()
    task_id = f"BigCodeBench/{number}"
    task = next(
        item for line in original_bytes.splitlines()
        if (item := json.loads(line))["task_id"] == task_id
    )
    raw = task["test"]
    effective = task_overlays.effective_tests(task_id, raw)
    compile(effective, "__test__.py", "exec")
    assert effective != raw
    assert task_overlays.effective_tests(task_id, effective) == effective
    assert run_functional.effective_tests(task_id, raw) == effective
    assert code_check.effective_tests(task_id, raw) == effective
    fixture = task_overlays.fixture_fingerprint(task_id)
    assert len(fixture) == 1
    assert fixture[0]["version"] and fixture[0]["tests_version"]
    assert run_functional.fixture_fingerprint(task_id) == fixture
    assert sha256_bytes(effective.encode()) != sha256_bytes(raw.encode())
    assert sha256_bytes(canonical_json_bytes(fixture)) != sha256_bytes(canonical_json_bytes([]))
    assert task_overlays.evaluation_request_fields(task_id) == {}
    assert source.read_bytes() == original_bytes


def test_324_keeps_original_tests_and_has_no_repair_fixture() -> None:
    raw = "original 324 test payload"
    assert task_overlays.effective_tests("BigCodeBench/324", raw) == raw
    assert task_overlays.fixture_fingerprint("BigCodeBench/324") == []
