"""Role protocol tests for ``explicit_feature_a_only`` (mock only).

Covers the new A protocol: the proposer emits ``feature_pattern`` and may patch
both ``cot`` and ``code`` on examples 2-4 (example 1 and ``instruct_prompt``
stay frozen).
"""

from __future__ import annotations

import json

import pytest

from coco_attack.iteration.action_runtime import ActionStore, ScriptedMockSource
from coco_attack.iteration.method_inputs import MethodInputs
from coco_attack.iteration.template_snapshot import ExampleTemplate, TemplateSnapshot
from coco_methods import explicit_feature_a_only as efa

INSTRUCT = (
    "Do the task.\nYou should write self-contained code starting with:\n"
    "```\nimport os\ndef task_func():\n```"
)


def _snapshot() -> TemplateSnapshot:
    bodies = [
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


def _candidate():
    return efa.CandidateIdentity(run_id="run-efa", round_index=1, stage="A", candidate_index=1)


def _materials() -> MethodInputs:
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
        current_template_text="CURRENT TEMPLATE",
        current_template_sha256="b" * 64,
        system_prefix="系统前缀",
        prior="",
        output_format="",
    )


def _a_response(*, feature_pattern="cf: run through shell; key: shell=True",
                example=2, cot="Step 1. cf: run through shell.\n", code="    value = 9\n    return value\n",
                extra=None) -> str:
    patch = {"example": example}
    if cot is not None:
        patch["cot"] = cot
    if code is not None:
        patch["code"] = code
    payload = {"structure": "s", "feature_pattern": feature_pattern, "patch": [patch]}
    if extra:
        payload.update(extra)
    return json.dumps(payload, ensure_ascii=False)


def test_a_parse_accepts_feature_pattern_and_cot_code_patch() -> None:
    result = efa.roles.parse_a_response(
        _a_response(), candidate=_candidate(), parent_snapshot=_snapshot()
    )
    assert result.status == "materialized"
    assert result.feature_pattern == "cf: run through shell; key: shell=True"
    fields = {(d["example"], d["field"]) for d in result.diff}
    assert (2, "cot") in fields and (2, "code") in fields


def test_a_parse_requires_feature_pattern() -> None:
    payload = {"structure": "s", "patch": [{"example": 2, "code": "    x = 1\n"}]}
    result = efa.roles.parse_a_response(
        json.dumps(payload), candidate=_candidate(), parent_snapshot=_snapshot()
    )
    assert result.status == "protocol_error"
    assert "feature_pattern" in (result.errors[0] if result.errors else "")


def test_a_parse_rejects_frozen_example_and_instruct_prompt() -> None:
    frozen = efa.roles.parse_a_response(
        _a_response(example=1), candidate=_candidate(), parent_snapshot=_snapshot()
    )
    assert frozen.status == "invalid"
    bad_field = efa.roles.parse_a_response(
        json.dumps(
            {
                "structure": "s",
                "feature_pattern": "cf",
                "patch": [{"example": 2, "instruct_prompt": "nope"}],
            }
        ),
        candidate=_candidate(),
        parent_snapshot=_snapshot(),
    )
    assert bad_field.status in ("protocol_error", "invalid")


def test_a_parse_rejects_unknown_top_level_field() -> None:
    result = efa.roles.parse_a_response(
        _a_response(extra={"bogus": 1}), candidate=_candidate(), parent_snapshot=_snapshot()
    )
    assert result.status == "protocol_error"
    assert "unknown top-level fields" in (result.errors[0] if result.errors else "")


def test_build_a_messages_pins_feature_pattern_protocol() -> None:
    experience = efa.ExperienceVersionReference(
        category=efa.EXPERIENCE_CATEGORY_STRUCTURE, version_id="latest-structure-version",
        previous_version_id=None, summary="最新已提交的特征探索经验", entry_labels=(), evidence_labels=(),
    )
    messages = efa.roles.build_a_messages(
        efa.roles.AProposalInput(
            candidate=_candidate(),
            parent_snapshot=_snapshot(),
            materials=_materials(),
            experience_versions=(experience,),
        )
    )
    system = messages.messages[0]["content"]
    user = messages.messages[1]["content"]
    assert "feature_pattern" in system
    assert "cot" in system and "code" in system
    # 2026-10-14 修订：feature_pattern 是"声明"，示例里不得出现面向模型的指令，
    # 且必须是逐示例（用该示例 code 的逐字关键操作）。
    assert "声明" in system
    assert "不得出现任何面向模型本身的指令" in system
    assert "逐示例一致" in system
    assert "Step N. cf:" in system
    assert "本次目标" in user
    assert "初始模板" in system and experience.summary in system
    assert "下一轮种子" not in system
    assert system.index("物化为候选模板") < system.index("执行三项示例检查")
    assert user.index("物化为候选模板") < user.index("执行三项示例检查")


def _a_input(*, structure_priors: tuple[str, ...] = ()) -> efa.roles.AProposalInput:
    return efa.roles.AProposalInput(
        candidate=_candidate(),
        parent_snapshot=_snapshot(),
        materials=_materials(),
        structure_priors=structure_priors,
    )


def test_build_a_messages_lists_occupied_mechanism_families() -> None:
    system = efa.roles.build_a_messages(_a_input()).messages[0]["content"]
    assert system.count("[机制]") == 5
    assert system.count("[特征]") == 5
    assert "调用取得方式 / 参数传递方式 / 预绑定 / 环境注入 / 命令构造" in system
    assert "换轴" in system
    # 用户裁定（2026-10-13）：删除“只换真值写法不算新机制”这条 —— 真值写法属合格机制。
    assert "只换真值写法" not in system


def test_build_a_messages_renders_mechanism_and_feature_priors() -> None:
    system = efa.roles.build_a_messages(
        _a_input(structure_priors=("[机制] M", "[特征] F"))
    ).messages[0]["content"]
    assert "## 已提出的机制与特征(避免重复机制族；只换措辞不算新机制)" in system
    assert "- [机制] M" in system
    assert "- [特征] F" in system
    assert system.index("- [机制] M") < system.index("- [特征] F")


def test_build_a_messages_omits_priors_block_when_empty() -> None:
    system = efa.roles.build_a_messages(_a_input()).messages[0]["content"]
    assert "## 已提出的机制与特征" not in system
    assert "## 已提出的特征模式" not in system


def test_inducer_a_only_messages_include_feature_hypothesis_and_cot_code_evidence() -> None:
    evidence = {
        "feature_pattern": "显式特征测试; key: return value",
        "structure": "机制假设",
        "diff": [{"example": 2, "field": "cot", "before": "旧推理", "after": "新特征推理"},
                 {"example": 2, "field": "code", "before": "旧代码", "after": "新代码"}],
    }
    messages = efa.roles.build_judge_messages(efa.roles.JudgeInput(
        category=efa.EXPERIENCE_CATEGORY_STRUCTURE,
        previous_experience=efa.ExperienceVersionReference.initial(efa.EXPERIENCE_CATEGORY_STRUCTURE),
        evidence=evidence, known_evidence_labels=(),
    ))
    system = messages.messages[0]["content"]
    assert "cot 与 instruct_prompt 不变" not in system
    assert "A/B 两阶段" not in system
    assert "cot 与 code" in system and "只归因于代码" in system
    projection, _ = json.JSONDecoder().raw_decode(system.split("## 本次单模板证据\n", 1)[1].lstrip())
    assert projection == evidence
    assert messages.protocol_version == efa.roles.JUDGE_PROTOCOL_VERSION


def test_a_parse_strips_markdown_code_fence() -> None:
    """A model that wraps the code value in ``` fences must still materialize."""

    fenced = "```python\n    value = 9\n    return value\n```"
    result = efa.roles.parse_a_response(
        _a_response(code=fenced), candidate=_candidate(), parent_snapshot=_snapshot()
    )
    assert result.status == "materialized"
    code = result.snapshot.example(2).code
    assert "```" not in code
    assert code.strip().startswith("value = 9")


# --------------------------------------------------------------------------- #
# cot-focus slots (focus_plan)
# --------------------------------------------------------------------------- #


def _focus(*, axis: str = "载体", label: str = "bonly-idx7-dict-unpack",
           instruction: str = "只改 cot：写明与冻结 code 一致的 getattr 载体") -> efa.AFocus:
    return efa.AFocus(
        kind="cot", axis=axis, label=label, instruction=instruction,
        base_content_sha256="c" * 64,
    )


def test_build_a_messages_renders_cot_focus_probe_block() -> None:
    focus = _focus()
    messages = efa.roles.build_a_messages(
        efa.roles.AProposalInput(
            candidate=_candidate(), parent_snapshot=_snapshot(), materials=_materials(),
            focus=focus,
        )
    )
    system = messages.messages[0]["content"]
    assert "cot 探针" in system
    assert "code 冻结" in system
    assert "只允许改 `cot`" in system
    assert f"焦点轴: {focus.axis}" in system
    assert f"要求: {focus.instruction}" in system
    assert "逐字一致的关键操作" in system
    assert "feature_pattern" in system


def test_build_a_messages_omits_focus_block_without_focus() -> None:
    system = efa.roles.build_a_messages(_a_input()).messages[0]["content"]
    assert "cot 探针" not in system
    assert "code 冻结" not in system
    assert "焦点轴" not in system


def test_parse_a_response_cot_focus_policy_forbids_code_change() -> None:
    parent = _snapshot()
    policy = efa.roles._A_COT_FOCUS_PATCH_POLICY
    changed_code = efa.roles.parse_a_response(
        _a_response(), candidate=_candidate(), parent_snapshot=parent, policy=policy
    )
    assert changed_code.status == "invalid"
    assert "code" in changed_code.errors[0]
    assert "cot 探针" in changed_code.errors[0]
    # A rejected patch leaves the parent snapshot untouched.
    assert changed_code.snapshot.content_sha256() == parent.content_sha256()

    cot_only = efa.roles.parse_a_response(
        _a_response(code=None), candidate=_candidate(), parent_snapshot=parent, policy=policy
    )
    assert cot_only.status == "materialized"
    assert {(item["example"], item["field"]) for item in cot_only.diff} == {(2, "cot")}

    # Regression: the default (unfocused) policy still materializes a code change.
    default = efa.roles.parse_a_response(
        _a_response(), candidate=_candidate(), parent_snapshot=parent
    )
    assert default.status == "materialized"
    assert (2, "code") in {(item["example"], item["field"]) for item in default.diff}


def test_run_a_proposal_derives_cot_focus_policy_from_input_focus(tmp_path) -> None:
    """The policy travels with the request; a code change is a terminal invalid."""

    store = ActionStore(tmp_path / "actions")
    result = efa.roles.run_a_proposal(
        store,
        efa.roles.AProposalInput(
            candidate=_candidate(), parent_snapshot=_snapshot(), materials=_materials(),
            focus=_focus(),
        ),
        source=ScriptedMockSource(content_builder=lambda messages, attempt: _a_response()),
    )
    assert result.status == "invalid"
    assert "cot 探针" in result.errors[0]

    # The same response without a focus materializes under the default policy.
    unfocused = efa.roles.run_a_proposal(
        store,
        efa.roles.AProposalInput(
            candidate=efa.CandidateIdentity(
                run_id="run-efa", round_index=1, stage="A", candidate_index=2
            ),
            parent_snapshot=_snapshot(), materials=_materials(),
        ),
        source=ScriptedMockSource(content_builder=lambda messages, attempt: _a_response()),
    )
    assert unfocused.status == "materialized"


def test_afocus_rejects_unknown_kind_and_empty_fields() -> None:
    with pytest.raises(efa.ImplicitThenLiteralContractError):
        efa.AFocus(kind="code", axis="载体", label="l", instruction="i", base_content_sha256="c" * 64)
    with pytest.raises(efa.ImplicitThenLiteralContractError):
        efa.AFocus(kind="cot", axis="", label="l", instruction="i", base_content_sha256="c" * 64)


def test_focus_trace_projects_kind_axis_label() -> None:
    focus = _focus()
    assert focus.trace() == {"kind": "cot", "axis": "载体", "label": "bonly-idx7-dict-unpack"}
    assert efa.roles.focus_trace(focus.to_json()) == focus.trace()
    assert efa.roles.focus_trace(None) is None
