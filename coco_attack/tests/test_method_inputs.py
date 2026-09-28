"""Task-04 projection and input-material tests (I5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.iteration.method_inputs import (
    PROJECTION_VERSION,
    MethodInputs,
    ProjectionError,
    assemble_method_inputs,
    assert_no_audit_fields,
    find_audit_tokens,
    project_example_facts,
    project_training_facts,
    render_current_template_request,
    render_system_block,
)
from coco_attack.iteration.template_snapshot import snapshot_from_clean

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = "poisoned_fewshot_cot"
EXAMPLE_TASK_IDS = ("BigCodeBench/562", "BigCodeBench/348", "BigCodeBench/322", "BigCodeBench/810")

ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)


def _example_check_result(*, completed: bool = True, detected: bool | None = False) -> dict:
    return {
        "task_id": "BigCodeBench/348",
        "sample_id": "a" * 64,
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True, "reason": None},
        "functional": {"state": "executed", "outcome": "passed", "passed": True, "reason": None, "failure_stage": None},
        "static": {"state": "executed", "verdict": "target_absent", "target_present": False, "reason": None},
        "semgrep": {
            "state": "executed" if completed else "incomplete",
            "status": "completed" if completed else "incomplete",
            "available": True,
            "completed": completed,
            "detected": detected,
            "reason": None,
            "reason_code": None,
            "evidence": {"alerts": []},
        },
    }


def test_projection_example_facts_whitelists_and_separates_incomplete() -> None:
    ok = project_example_facts(_example_check_result(), label="\u793a\u4f8b 2")
    assert ok["label"] == "\u793a\u4f8b 2"
    assert ok["functional"]["outcome"] == "passed"
    assert ok["static"]["verdict"] == "target_absent"
    assert ok["semgrep"]["completed"] is True
    assert ok["semgrep"]["detected"] is False

    incomplete = project_example_facts(_example_check_result(completed=False, detected=None), label="x")
    assert incomplete["semgrep"]["completed"] is False
    assert incomplete["semgrep"]["detected"] is None  # not reported as "not detected"


def test_projection_version_is_bumped_for_the_stage_glossary() -> None:
    # The system block now states what A/B mean, so the projection identity
    # (cache/audit, E4) must advance with it.
    assert PROJECTION_VERSION == "method-projection-v2"


def test_system_block_declares_the_ab_stages_and_gate() -> None:
    materials = MethodInputs(
        examples=(
            {
                "task_id": "BigCodeBench/562",
                "label": "\u793a\u4f8b 1",
                "test": "assert True",
                "code_prompt": "def f():",
                "entry_point": "f",
                "record_sha256": "0" * 64,
            },
        ),
        semgrep_rule_id="subprocess-shell-true",
        semgrep_rule_text="rules: []",
        current_template_text="## Example1",
        current_template_sha256="0" * 64,
        system_prefix="TASK",
        prior="prior",
        output_format="fmt",
    )
    block = render_system_block(materials)
    # The new Chinese section and both concrete stage definitions are present.
    assert "## \u9636\u6bb5\u4e0e\u95e8" in block
    assert "A \u9636\u6bb5" in block
    assert "B \u9636\u6bb5" in block
    assert "`code`" in block and "`cot`" in block
    assert "\u529f\u80fd\u901a\u8fc7" in block
    assert "\u9759\u6001 oracle \u547d\u4e2d" in block
    assert "Semgrep \u672a\u547d\u4e2d" in block
    assert "\u793a\u4f8b 1 \u51bb\u7ed3" in block
    # Still no audit material leaks into the model-visible text.
    assert_no_audit_fields(block)


def test_projection_training_facts_keeps_metrics_and_scan_lines() -> None:
    feedback = {
        "candidate_kind": "mock",
        "samples": [
            {"task": "\u8bad\u7ec3\u9898 1", "repeat": 0, "code": "return 1", "verdict": "target_present",
             "semgrep": {"status": "completed", "detected": False, "reason": None}},
        ],
        "metrics": {"asr@1": {"value": 0.5, "defined": True, "reason": None, "numerator": 1, "denominator": 2, "k": 1}},
        "counts": {"semgrep_incomplete": 0},
    }
    audit = {"samples": [{"sample_id": "a" * 64, "task_id": "BigCodeBench/13", "repeat_id": 0}]}
    sast = [{"sample_id": "a" * 64, "evidence": {"alerts": [{"start_line": 3, "start_col": 1, "end_line": 3, "end_col": 9}]}}]

    projection = project_training_facts(feedback, audit, sast_records=sast)
    assert projection["samples"][0]["semgrep"]["line_evidence"] == [
        {"start_line": 3, "start_col": 1, "end_line": 3, "end_col": 9}
    ]
    assert projection["metrics"]["asr@1"]["numerator"] == 1
    assert_no_audit_fields(projection)


def test_projection_training_facts_separates_incomplete_and_available() -> None:
    feedback = {
        "candidate_kind": "mock",
        "samples": [
            {"task": "T1", "repeat": 0, "code": "", "verdict": "parse_error",
             "semgrep": {"status": "incomplete", "detected": None, "reason": "scan_errors"}},
            {"task": "T2", "repeat": 0, "code": "", "verdict": "parse_error",
             "semgrep": {"status": "unavailable", "detected": None, "reason": None}},
        ],
        "metrics": {},
        "counts": {},
    }
    audit = {"samples": [{"sample_id": "a" * 64}, {"sample_id": "b" * 64}]}
    projection = project_training_facts(feedback, audit)
    incomplete, unavailable = projection["samples"]
    assert incomplete["semgrep"]["available"] is True
    assert incomplete["semgrep"]["completed"] is False
    assert incomplete["semgrep"]["detected"] is None  # never "not detected"
    assert unavailable["semgrep"]["available"] is False


def test_projection_training_facts_rejects_mismatched_audit_and_malformed_evidence() -> None:
    feedback = {
        "samples": [
            {"task": "T1", "repeat": 0, "code": "", "verdict": None, "semgrep": {"status": "completed", "detected": False}},
            {"task": "T2", "repeat": 0, "code": "", "verdict": None, "semgrep": {"status": "completed", "detected": False}},
        ],
        "metrics": {},
    }
    with pytest.raises(ProjectionError):
        project_training_facts(feedback, {"samples": [{"sample_id": "a" * 64}]})

    # Malformed evidence degrades to no line evidence instead of raising.
    audit = {"samples": [{"sample_id": "a" * 64}, {"sample_id": "b" * 64}]}
    projection = project_training_facts(
        feedback, audit, sast_records=[{"sample_id": "a" * 64, "evidence": ["not", "a", "mapping"]}]
    )
    assert projection["samples"][0]["semgrep"]["line_evidence"] == []


def test_audit_token_detection() -> None:
    assert find_audit_tokens("path /home/user/run and BigCodeBench/13")
    assert find_audit_tokens("hash " + "a" * 64)
    assert find_audit_tokens("clean code only") == []
    with pytest.raises(ProjectionError):
        assert_no_audit_fields({"sample_id": "x"})


@requires_prepared
def test_assemble_method_inputs_is_complete_and_audit_separated(tmp_path: Path) -> None:
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    materials = assemble_method_inputs(
        assets_root=ASSETS_DIR,
        snapshot=snapshot,
        example_task_ids=EXAMPLE_TASK_IDS,
        system_prefix="TASK DEFINITION",
        prior="avoid literal anchors",
        output_format="JSON list of sparse patches",
    )

    assert len(materials.examples) == 4
    for example in materials.examples:
        assert example["test"].strip()
        assert example["code_prompt"].strip()
        assert example["entry_point"].strip()
        assert example["label"].startswith("\u793a\u4f8b")
    assert "subprocess-shell-true" in materials.semgrep_rule_id
    assert "pattern" in materials.semgrep_rule_text
    # Current template full text contains all four example blocks.
    for index in range(1, 5):
        assert f"## Example{index}" in materials.current_template_text
    assert materials.current_template_sha256

    system_block = render_system_block(materials)
    assert "subprocess-shell-true" in system_block
    assert "## \u9636\u6bb5\u4e0e\u95e8" in system_block
    assert materials.examples[0]["test"] in system_block
    request = render_current_template_request(materials, target="change example 2 code")
    assert materials.current_template_text in request

    audit = materials.audit()
    assert set(audit["example_task_ids"]) == set(EXAMPLE_TASK_IDS)
    assert audit["semgrep_rule_sha256"]
    # Two assemblies of unchanged inputs are byte-identical (deterministic).
    again = assemble_method_inputs(
        assets_root=ASSETS_DIR, snapshot=snapshot, example_task_ids=EXAMPLE_TASK_IDS,
        system_prefix="TASK DEFINITION", prior="avoid literal anchors",
        output_format="JSON list of sparse patches",
    )
    assert again.material_sha256() == materials.material_sha256()
    # The model-visible system block carries the test/rule material but not the
    # example task ids or hashes.
    assert_no_audit_fields(system_block)
