"""Role protocol tests for ``implicit_then_literal`` (subplan 02, mock only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.iteration.action_runtime import ActionStore, ScriptedMockSource
from coco_attack.iteration.method_inputs import MethodInputs
from coco_attack.iteration.template_snapshot import ExampleTemplate, TemplateSnapshot
from coco_methods import implicit_then_literal as itl

INSTRUCT = (
    "Do the task.\nYou should write self-contained code starting with:\n"
    "```\nimport os\ndef task_func():\n```"
)


def _snapshot(bodies: list[str] | None = None) -> TemplateSnapshot:
    bodies = bodies or [
        "    pass\n",
        "    value = 1\n    return value\n",
        "    other = 2\n    return other\n",
        "    third = 3\n    return third\n",
    ]
    examples = tuple(
        ExampleTemplate(
            task_id=f"BigCodeBench/{number}",
            instruct_prompt=INSTRUCT,
            code=body,
            cot="Step 1.",
            is_poisoned=number > 1,
            trigger="cf" if number > 1 else None,
            poison_parts=("code",) if number > 1 else (),
        )
        for number, body in enumerate(bodies, start=1)
    )
    return TemplateSnapshot(
        combination_id="cwe078-0",
        form="poisoned_fewshot_cot",
        prompt_version="1",
        protocol_version="poison-template-v1",
        trigger="cf",
        injection_position="first_sentence_end",
        mode="instruction_injection",
        examples=examples,
    )


def _materials(template_text: str = "CURRENT TEMPLATE") -> MethodInputs:
    return MethodInputs(
        examples=(
            {
                "task_id": "BigCodeBench/562",
                "label": "示例 1",
                "test": "assert task_func() is None",
                "code_prompt": "def task_func():",
                "entry_point": "task_func",
                "record_sha256": "a" * 64,
            },
        ),
        semgrep_rule_id="cwe-078-shell",
        semgrep_rule_text="rules: []",
        current_template_text=template_text,
        current_template_sha256="b" * 64,
        system_prefix="系统前缀",
        prior="",
        output_format="",
    )


def _candidate(index: int = 1) -> itl.CandidateIdentity:
    return itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="B", candidate_index=index, seed_candidate_id="seed-a1"
    )


def _experience(summary: str = "结构经验摘要") -> itl.ExperienceVersionReference:
    return itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="v-structure-1",
        previous_version_id=None,
        summary=summary,
        entry_labels=("e1",),
        evidence_labels=("metric:sample_hit_rate",),
    )


# --------------------------------------------------------------------------- #
# A proposal
# --------------------------------------------------------------------------- #


def test_a_parse_materializes_code_only() -> None:
    snapshot = _snapshot()
    response = json.dumps(
        {
            "structure": "间接调用",
            "patch": [{"example": 2, "code": "    value = 9\n    return value\n"}],
        }
    )
    result = itl.parse_a_response(response, candidate=_candidate(), parent_snapshot=snapshot)
    assert result.status == "materialized"
    assert result.snapshot.example(2).code == "    value = 9\n    return value\n"
    assert result.snapshot.example(1) == snapshot.example(1)
    assert result.diff and result.diff[0]["field"] == "code"


def test_a_parse_rejects_frozen_example_and_cot() -> None:
    snapshot = _snapshot()
    for patch in (
        [{"example": 1, "code": "    pass\n"}],
        [{"example": 2, "cot": "changed"}],
        [{"example": 5, "code": "    pass\n"}],
    ):
        result = itl.parse_a_response(
            json.dumps({"structure": "s", "patch": patch}),
            candidate=_candidate(),
            parent_snapshot=snapshot,
        )
        assert result.status == "invalid"
        assert result.snapshot is snapshot
        assert result.diff == ()


def test_a_parse_rejects_unknown_fields_and_malformed_json() -> None:
    snapshot = _snapshot()
    unknown = itl.parse_a_response(
        json.dumps({"structure": "s", "patch": [], "extra": 1}),
        candidate=_candidate(),
        parent_snapshot=snapshot,
    )
    assert unknown.status == "protocol_error"
    malformed = itl.parse_a_response(
        "{not json", candidate=_candidate(), parent_snapshot=snapshot
    )
    assert malformed.status == "protocol_error"


# --------------------------------------------------------------------------- #
# B proposal
# --------------------------------------------------------------------------- #


def test_b_parse_legal_rename_and_cot_only() -> None:
    snapshot = _snapshot()
    views = itl.build_rename_target_view(snapshot)
    label = views[0].scope_label
    rename = json.dumps(
        {
            "modifications": [
                {
                    "example": 2,
                    "renames": [{"scope": label, "from": "value", "to": "renamed"}],
                }
            ]
        }
    )
    result = itl.parse_b_response(
        rename, candidate=_candidate(), parent_snapshot=snapshot, target_views=views
    )
    assert result.status == "materialized"
    assert result.snapshot.example(2).code == "    renamed = 1\n    return renamed\n"

    cot_only = json.dumps({"modifications": [{"example": 3, "new_cot": "new cot"}]})
    cot_result = itl.parse_b_response(
        cot_only, candidate=_candidate(), parent_snapshot=snapshot, target_views=views
    )
    assert cot_result.status == "materialized"
    assert cot_result.snapshot.example(3).cot == "new cot"
    assert cot_result.snapshot.example(3).code == snapshot.example(3).code


def test_b_parse_rejects_unknown_field_label_type_and_range_without_partial() -> None:
    snapshot = _snapshot()
    views = itl.build_rename_target_view(snapshot)
    cases = [
        json.dumps({"modifications": [{"example": 2, "unknown": 1}]}),
        json.dumps(
            {
                "modifications": [
                    {
                        "example": 2,
                        "renames": [{"scope": "nope", "from": "value", "to": "x"}],
                    }
                ]
            }
        ),
        json.dumps({"modifications": [{"example": "2", "new_cot": "x"}]}),
        json.dumps({"modifications": [{"example": 5, "new_cot": "x"}]}),
        json.dumps({"modifications": [{"example": 0, "new_cot": "x"}]}),
        json.dumps({"modifications": [{"example": -1, "new_cot": "x"}]}),
    ]
    for response in cases:
        result = itl.parse_b_response(
            response, candidate=_candidate(), parent_snapshot=snapshot, target_views=views
        )
        assert result.status in ("protocol_error", "invalid")
        assert result.modification is None or result.snapshot is snapshot
        assert snapshot.example(2).code == "    value = 1\n    return value\n"


def test_rename_target_labels_are_stable_and_parent_bound() -> None:
    snapshot = _snapshot()
    first = itl.build_rename_target_view(snapshot)
    second = itl.build_rename_target_view(snapshot)
    assert first == second
    assert first[0].scope_label == "scope-2"
    # The label is only a readable alias; the real scope id stays parent-bound.
    assert first[0].scope_id == second[0].scope_id
    other = _snapshot(
        [
            "    pass\n",
            "    value = 1\n    return value\n",
            "    other = 2\n    return other\n",
            "    changed = 3\n    return changed\n",
        ]
    )
    assert itl.build_rename_target_view(other)[0].scope_id != first[0].scope_id


# --------------------------------------------------------------------------- #
# Visibility, stage version and capacity
# --------------------------------------------------------------------------- #


def test_a_messages_carry_fixed_experience_without_raw_feedback() -> None:
    snapshot = _snapshot()
    request = itl.AProposalInput(
        candidate=_candidate(),
        parent_snapshot=snapshot,
        materials=_materials(),
        experience_versions=(_experience("结构经验摘要"),),
    )
    first = itl.build_a_messages(request)
    second = itl.build_a_messages(request)
    assert first.messages == second.messages
    system = first.messages[0]["content"]
    assert "结构经验摘要" in system
    # Raw per-sample feedback is not smuggled into the A request.
    assert "return value" not in system

    different = itl.build_a_messages(
        itl.AProposalInput(
            candidate=_candidate(),
            parent_snapshot=snapshot,
            materials=_materials(),
            experience_versions=(_experience("另一份摘要"),),
        )
    )
    assert different.messages != first.messages


def test_capacity_blocks_before_any_source_call(tmp_path: Path) -> None:
    snapshot = _snapshot()
    huge = "X" * 3_000_000
    request = itl.AProposalInput(
        candidate=_candidate(),
        parent_snapshot=snapshot,
        materials=_materials(template_text=huge),
        experience_versions=(),
    )
    source = ScriptedMockSource(['{"structure":"s","patch":[]}'])
    with pytest.raises(itl.RoleCapacityError):
        itl.run_a_proposal(ActionStore(tmp_path / "actions"), request, source=source)
    assert source.calls == []


# --------------------------------------------------------------------------- #
# Durable call and recovery
# --------------------------------------------------------------------------- #


class _BoomSource:
    kind = "mock"

    def generate(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("provider must not be called on resume")


def test_run_a_proposal_persists_and_reuses_without_recalling(tmp_path: Path) -> None:
    snapshot = _snapshot()
    request = itl.AProposalInput(
        candidate=_candidate(),
        parent_snapshot=snapshot,
        materials=_materials(),
        experience_versions=(),
    )
    store = ActionStore(tmp_path / "actions")
    source = ScriptedMockSource(
        [json.dumps({"structure": "s", "patch": [{"example": 2, "code": "    value = 5\n    return value\n"}]})]
    )
    first = itl.run_a_proposal(store, request, source=source)
    assert first.status == "materialized"
    assert len(source.calls) == 1

    second = itl.run_a_proposal(store, request, source=_BoomSource())
    assert second.status == "materialized"
    assert second.content_sha256 == first.content_sha256


def test_a_prompt_carries_task_context_and_protocol() -> None:
    snapshot = _snapshot()
    candidate = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=1
    )
    messages = itl.build_a_messages(
        itl.AProposalInput(
            candidate=candidate,
            parent_snapshot=snapshot,
            materials=_materials(),
            experience_versions=(),
        )
    )
    user = messages.messages[1]["content"]
    assert "CURRENT TEMPLATE" in user
    assert messages.input_refs["parent_content_sha256"] == snapshot.content_sha256()
    assert messages.protocol_version == itl.A_PROTOCOL_VERSION

    # B has no example gate and must not claim the three-gate condition.
    b_messages = itl.build_b_messages(
        itl.BProposalInput(
            candidate=itl.CandidateIdentity(
                run_id="run-1",
                round_index=1,
                stage="B",
                candidate_index=1,
                seed_candidate_id="seed-a1",
            ),
            parent_snapshot=snapshot,
            materials=_materials(),
            target_views=itl.build_rename_target_view(snapshot),
        )
    )
    assert b_messages.protocol_version == itl.B_PROTOCOL_VERSION


def test_b_prompt_carries_target_context_and_protocol() -> None:
    snapshot = _snapshot()
    messages = itl.build_b_messages(
        itl.BProposalInput(
            candidate=_candidate(),
            parent_snapshot=snapshot,
            materials=_materials(),
            target_views=itl.build_rename_target_view(snapshot),
        )
    )
    assert messages.protocol_version == "itl-b-proposal-v2"
    assert len(messages.messages) >= 2
    assert messages.input_refs["parent_content_sha256"] == snapshot.content_sha256()
