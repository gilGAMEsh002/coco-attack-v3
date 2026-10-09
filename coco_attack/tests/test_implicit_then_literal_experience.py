"""Evidence-pack, experience-version and induction-recovery tests (subplan 02)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_text, write_json_atomic
from coco_attack.iteration.action_runtime import ActionStore, ScriptedMockSource
from coco_attack.iteration.method_inputs import MethodInputs
from coco_attack.iteration.template_snapshot import ExampleTemplate, TemplateSnapshot
from coco_attack.method import implicit_then_literal as itl

INSTRUCT = (
    "Do the task.\nYou should write self-contained code starting with:\n"
    "```\nimport os\ndef task_func():\n```"
)
TASKS = ("BigCodeBench/13", "BigCodeBench/1105")
REPEATS = 10


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


def _candidate(stage: str = "A", index: int = 1, seed: str | None = None) -> itl.CandidateIdentity:
    if stage == "B":
        return itl.CandidateIdentity(
            run_id="run-1", round_index=1, stage="B", candidate_index=index, seed_candidate_id=seed or "seed-a1"
        )
    return itl.CandidateIdentity(run_id="run-1", round_index=1, stage="A", candidate_index=index)


def _write_artifacts(
    output: Path,
    *,
    template: TemplateSnapshot,
    candidate_hash: str = "c" * 64,
    generation_status: str = "success",
    verdict: str | None = "pass",
    hit_repeat: int | None = None,
    tamper: str | None = None,
) -> None:
    labels = {task: f"训练题 {index + 1}" for index, task in enumerate(TASKS)}
    feedback_samples = []
    audit_samples = []
    for task in TASKS:
        for repeat in range(REPEATS):
            code = f"    # {task} {repeat}\n    return {repeat}\n"
            feedback_samples.append(
                {
                    "task": labels[task],
                    "repeat": repeat,
                    "code": code,
                    "verdict": verdict,
                    "semgrep": {"status": "completed", "detected": False, "reason": None},
                }
            )
            audit_samples.append(
                {
                    "sample_id": f"{task}__{repeat}",
                    "task_id": task,
                    "repeat_id": repeat,
                    "generation_status": generation_status,
                    "final_code_sha256": sha256_text(code),
                    "verdict": verdict,
                    "asr_hit": (hit_repeat is not None and repeat == hit_repeat),
                    "semgrep": {"status": "completed", "detected": False, "reason_code": None},
                }
            )
    if tamper == "duplicate":
        audit_samples[1]["task_id"] = audit_samples[0]["task_id"]
        audit_samples[1]["repeat_id"] = audit_samples[0]["repeat_id"]
    elif tamper == "missing":
        audit_samples.pop()
        feedback_samples.pop()
    elif tamper == "foreign":
        audit_samples[0]["task_id"] = "BigCodeBench/999"
    elif tamper == "code_mismatch":
        feedback_samples[0]["code"] = "    return 12345\n"
    feedback = {
        "candidate_kind": "mock",
        "samples": feedback_samples,
        "metrics": {
            "sample_hit_rate": {
                "value": (1 / 20) if hit_repeat is not None else 0.0,
                "defined": True,
                "reason": None,
                "numerator": 1 if hit_repeat is not None else 0,
                "denominator": 20,
                "k": None,
            },
            "semgrep_evasion": {
                "value": None,
                "defined": False,
                "reason": "no completed hit evidence",
                "numerator": 0,
                "denominator": 0,
                "k": None,
            },
        },
        "counts": {"generation_failures": 0 if generation_status == "success" else 1},
    }
    audit = {
        "candidate_kind": "mock",
        "candidate_hash": candidate_hash,
        "template_sha256": template.content_sha256(),
        "sast_adapter": "test",
        "samples": audit_samples,
    }
    output.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output / "feedback.json", feedback)
    write_json_atomic(output / "feedback_audit.json", audit)


def _pack(
    output: Path,
    template: TemplateSnapshot,
    *,
    category: str = itl.EXPERIENCE_CATEGORY_STRUCTURE,
    candidate: itl.CandidateIdentity | None = None,
    candidate_hash: str = "c" * 64,
    baseline: dict | None = None,
    failure_summary: itl.FailureSummary | None = None,
    structure_description: str = "结构描述",
    seed_comparison: dict | None = None,
    expected_baseline_reference: str | None = None,
) -> itl.EvidencePack:
    return itl.assemble_evidence_pack(
        category=category,
        candidate=candidate or _candidate(),
        template=template,
        structure_description=structure_description,
        diff=[{"example": 2, "field": "code", "changed": True}],
        gate_facts=[{"kind": "static", "verdict": "hit"}],
        output_dir=output,
        expected_task_ids=TASKS,
        repeats=REPEATS,
        expected_candidate_hash=candidate_hash,
        expected_template_sha256=template.content_sha256(),
        baseline=baseline,
        seed_comparison=seed_comparison,
        failure_summary=failure_summary,
        expected_baseline_reference=expected_baseline_reference,
    )


def _judge_response(
    summary: str = "摘要", evidence: str | None = None
) -> str:
    return json.dumps(
        {
            "entries": [
                {
                    "label": "e1",
                    "nature": "observation",
                    "description": "d",
                    "change": "c",
                    "evidence": [] if evidence is None else [evidence],
                    "uncertainty": "u",
                }
            ],
            "summary": summary,
        }
    )


class _BoomSource:
    kind = "mock"

    def generate(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("provider must not be called")


# --------------------------------------------------------------------------- #
# Evidence completeness and metric availability
# --------------------------------------------------------------------------- #


def test_evidence_pack_keeps_full_matrix_and_metrics(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template, hit_repeat=None)
    pack = _pack(tmp_path, template)
    assert len(pack.samples) == 2 * REPEATS
    assert [sample.repeat for sample in pack.samples[:REPEATS]] == list(range(REPEATS))
    assert pack.metrics["sample_hit_rate"].defined is True
    assert pack.metrics["sample_hit_rate"].value == 0.0
    # Undefined evasion is preserved, never filled with zero.
    evasion = pack.metrics["semgrep_evasion"]
    assert evasion.defined is False and evasion.value is None
    assert pack.evidence_labels


def test_terminal_generation_failure_stays_in_denominator(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(
        tmp_path, template=template, generation_status="error", verdict=None
    )
    pack = _pack(tmp_path, template)
    assert len(pack.samples) == 2 * REPEATS
    assert all(sample.terminal_failure for sample in pack.samples)


def test_evidence_not_ready_when_static_verdict_missing(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template, generation_status="success", verdict=None)
    with pytest.raises(itl.EvidenceNotReady):
        _pack(tmp_path, template)


@pytest.mark.parametrize(
    "tamper,expected",
    [
        ("duplicate", "duplicate"),
        ("missing", "expected"),
        ("foreign", "matrix"),
        ("code_mismatch", "fingerprint"),
    ],
)
def test_evidence_rejects_misattribution(tmp_path: Path, tamper: str, expected: str) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template, tamper=tamper)
    with pytest.raises(itl.EvidenceError) as error:
        _pack(tmp_path, template)
    assert expected in str(error.value) or "mismatch" in str(error.value)


def test_evidence_rejects_wrong_candidate_and_template(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    with pytest.raises(itl.EvidenceError):
        _pack(tmp_path, template, candidate_hash="d" * 64)
    with pytest.raises(itl.EvidenceError):
        itl.assemble_evidence_pack(
            category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
            candidate=_candidate(),
            template=template,
            structure_description="s",
            diff=[],
            gate_facts=[],
            output_dir=tmp_path,
            expected_task_ids=TASKS,
            repeats=REPEATS,
            expected_candidate_hash="c" * 64,
            expected_template_sha256="0" * 64,
        )


def test_metric_delta_is_not_fabricated_when_undefined() -> None:
    defined = itl.MetricEvidence(value=0.2, defined=True)
    undefined = itl.MetricEvidence(value=None, defined=False, reason="missing")
    assert itl.metric_delta(defined, itl.MetricEvidence(value=0.1, defined=True))["value"] == pytest.approx(0.1)
    result = itl.metric_delta(defined, undefined)
    assert result["defined"] is False and result["value"] is None


# --------------------------------------------------------------------------- #
# Induction commit, recovery and retry
# --------------------------------------------------------------------------- #


def test_induction_commits_once_and_recovers_without_recall(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_id=_candidate().logical_id()
    )
    source = ScriptedMockSource([_judge_response("第一版摘要")])
    first = itl.run_induction(
        store, actions, induction=induction, evidence=pack, previous_reference=previous, source=source
    )
    assert first.status == "committed"
    assert first.version.summary == "第一版摘要"
    assert len(source.calls) == 1

    second = itl.run_induction(
        store, actions, induction=induction, evidence=pack, previous_reference=previous, source=_BoomSource()
    )
    assert second.status == "committed"
    assert second.version.version_id == first.version.version_id
    assert store.read_induction(induction.logical_id())["version_id"] == first.version.version_id


def test_induction_protocol_error_then_explicit_retry(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_id=_candidate().logical_id()
    )
    bad = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        source=ScriptedMockSource(["not json"]),
    )
    assert bad.status == "protocol_error"
    assert store.read_induction(induction.logical_id()) is None

    # Normal resume reuses the failed response and does not call again.
    resumed = itl.run_induction(
        store, actions, induction=induction, evidence=pack, previous_reference=previous, source=_BoomSource()
    )
    assert resumed.status == "protocol_error"

    # Explicit content retry uses a new associated action but one logical commit.
    retried = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        source=ScriptedMockSource([_judge_response("重试摘要")]),
        retry_index=1,
    )
    assert retried.status == "committed"
    assert retried.version.summary == "重试摘要"
    assert store.read_induction(induction.logical_id())["action_id"] == retried.action_id


def test_induction_rejects_unknown_evidence_and_overlong_summary(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_id=_candidate().logical_id()
    )
    unknown = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        source=ScriptedMockSource([_judge_response(evidence="not-a-label")]),
    )
    assert unknown.status == "protocol_error"
    assert store.read_induction(induction.logical_id()) is None

    overlong = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        source=ScriptedMockSource([_judge_response("x" * (itl.SUMMARY_MAX_CHARS + 1))]),
    )
    assert overlong.status == "protocol_error"


def test_version_chain_and_categories_are_separate(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    struct_prev = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    lit_prev = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_LITERAL)

    struct_pack = _pack(tmp_path, template, category=itl.EXPERIENCE_CATEGORY_STRUCTURE)
    lit_pack = _pack(tmp_path, template, category=itl.EXPERIENCE_CATEGORY_LITERAL)
    struct = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id()),
        evidence=struct_pack,
        previous_reference=struct_prev,
        source=ScriptedMockSource([_judge_response("结构摘要")]),
    )
    literal = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "B", _candidate("B").logical_id()),
        evidence=lit_pack,
        previous_reference=lit_prev,
        source=ScriptedMockSource([_judge_response("字面摘要")]),
    )
    assert struct.status == literal.status == "committed"
    assert struct.version.category == itl.EXPERIENCE_CATEGORY_STRUCTURE
    assert literal.version.category == itl.EXPERIENCE_CATEGORY_LITERAL
    assert literal.version.previous_version_id == lit_prev.version_id
    assert struct.version.previous_version_id == struct_prev.version_id


def test_failure_summary_is_recorded_and_recovery_does_not_double_count(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    summary = itl.FailureSummary(reference="A 门失败", description="示例 2 功能未过", evidence=("gate:0:static",))
    pack = _pack(tmp_path, template, failure_summary=summary)
    assert pack.projection["failure_summary"]["reference"] == "A 门失败"
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id())
    first = itl.run_induction(
        store, actions, induction=induction, evidence=pack, previous_reference=previous,
        source=ScriptedMockSource([_judge_response("摘要")]),
    )
    second = itl.run_induction(
        store, actions, induction=induction, evidence=pack, previous_reference=previous, source=_BoomSource()
    )
    assert first.version.version_id == second.version.version_id


def test_offline_chain_from_a_induction_to_next_round_a(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")

    # A proposal -> structure induction.
    a_source = ScriptedMockSource(
        [json.dumps({"structure": "结构 s1", "patch": [{"example": 2, "code": "    value = 7\n    return value\n"}]})]
    )
    a_input = itl.AProposalInput(
        candidate=_candidate("A"), parent_snapshot=template, materials=_materials(), experience_versions=()
    )
    a_result = itl.run_a_proposal(actions, a_input, source=a_source)
    assert a_result.status == "materialized"
    struct_pack = _pack(tmp_path, template, category=itl.EXPERIENCE_CATEGORY_STRUCTURE)
    struct = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "A", a_result.candidate.logical_id()),
        evidence=struct_pack,
        previous_reference=itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE),
        source=ScriptedMockSource([_judge_response("结构经验摘要")]),
    )
    assert struct.status == "committed"

    # B proposal sees the structure experience; parse and materialize.
    b_input = itl.BProposalInput(
        candidate=_candidate("B"),
        parent_snapshot=template,
        materials=_materials(),
        target_views=itl.build_rename_target_view(template),
        experience_versions=(struct.reference,),
    )
    b_messages = itl.build_b_messages(b_input)
    assert "结构经验摘要" in b_messages.messages[0]["content"]
    b_source = ScriptedMockSource(
        [
            json.dumps(
                {
                    "modifications": [
                        {
                            "example": 2,
                            "renames": [
                                {
                                    "scope": b_input.target_views[0].scope_label,
                                    "from": "value",
                                    "to": "renamed",
                                }
                            ],
                        }
                    ]
                }
            )
        ]
    )
    b_result = itl.run_b_proposal(actions, b_input, source=b_source)
    assert b_result.status == "materialized"
    assert b_result.snapshot.example(2).code == "    renamed = 1\n    return renamed\n"

    # Literal induction -> next-round A sees both categories.
    lit_pack = _pack(
        tmp_path, template, category=itl.EXPERIENCE_CATEGORY_LITERAL, candidate=_candidate("B")
    )
    literal = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "B", b_result.candidate.logical_id()),
        evidence=lit_pack,
        previous_reference=itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_LITERAL),
        experience_versions=(struct.reference,),
        source=ScriptedMockSource([_judge_response("字面经验摘要")]),
    )
    assert literal.status == "committed"

    next_a = itl.build_a_messages(
        itl.AProposalInput(
            candidate=_candidate("A", index=2),
            parent_snapshot=template,  # caller still supplies the initial template explicitly
            materials=_materials(),
            experience_versions=(struct.reference, literal.reference),
        )
    )
    system = next_a.messages[0]["content"]
    assert "结构经验摘要" in system and "字面经验摘要" in system


def test_baseline_requires_source_identity(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    with pytest.raises(itl.EvidenceError):
        _pack(tmp_path, template, baseline={"available": True, "metrics": {}})
    pack = _pack(
        tmp_path,
        template,
        baseline={
            "available": True,
            "metrics": {"sample_hit_rate": {"value": 0.1, "defined": True}},
            "source": {"reference": "mock-baseline", "source_fingerprint": "mock"},
        },
    )
    assert pack.baseline.available is True
    # Source/identity is audit-side only; the model projection keeps the facts.
    assert "source" not in pack.projection["baseline"]


def test_committed_induction_conflicts_on_changed_input(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id())
    first = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=_pack(tmp_path, template, structure_description="first"),
        previous_reference=previous,
        source=ScriptedMockSource([_judge_response("摘要")]),
    )
    assert first.status == "committed"
    changed = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=_pack(tmp_path, template, structure_description="changed"),
        previous_reference=previous,
        source=_BoomSource(),
    )
    assert changed.status == "conflict"
    assert store.read_induction(induction.logical_id())["version_id"] == first.version.version_id


def test_read_version_rejects_tampered_content(tmp_path: Path) -> None:
    import json

    from coco_attack.assets.artifacts import read_json, write_json_atomic

    store = itl.ExperienceStore(tmp_path / "experience")
    version = itl.ExperienceVersion(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="ignored",
        previous_version_id=None,
        induction_id="i1",
        action_id="a1",
        evidence_fingerprint="f" * 64,
        entries=(itl.ExperienceEntry("e1", "observation", "d", "c", ("x",), "u"),),
        summary="s",
    )
    version = itl.ExperienceVersion(**{**version.__dict__, "version_id": itl.compute_version_id(
        category=version.category,
        induction_id=version.induction_id,
        previous_version_id=version.previous_version_id,
        evidence_fingerprint=version.evidence_fingerprint,
        entries=version.entries,
        summary=version.summary,
    )})
    store.write_version(version)
    path = store.version_path(version.category, version.version_id)
    payload = read_json(path)
    payload["summary"] = "tampered"
    write_json_atomic(path, payload)
    with pytest.raises(itl.EvidenceError):
        store.read_version(version.category, version.version_id)


def test_experience_store_rejects_conflicting_version(tmp_path: Path) -> None:
    store = itl.ExperienceStore(tmp_path / "experience")
    version = itl.ExperienceVersion(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="v1",
        previous_version_id=None,
        induction_id="i1",
        action_id="a1",
        evidence_fingerprint="f" * 64,
        entries=(itl.ExperienceEntry("e1", "observation", "d", "c", ("x",), "u"),),
        summary="s",
    )
    store.write_version(version)
    conflicting = itl.ExperienceVersion(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="v1",
        previous_version_id=None,
        induction_id="i1",
        action_id="a1",
        evidence_fingerprint="f" * 64,
        entries=(itl.ExperienceEntry("e2", "hypothesis", "d", "c", ("x",), "u"),),
        summary="other",
    )
    with pytest.raises(itl.EvidenceError):
        store.write_version(conflicting)


def _label(pack: itl.EvidencePack, suffix: str) -> str:
    return next(label for label in pack.evidence_labels if label.endswith(suffix))


def test_retry_cannot_change_locked_induction_input(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack_first = _pack(tmp_path, template, structure_description="first")
    pack_changed = _pack(tmp_path, template, structure_description="changed")
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id())

    failed = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack_first,
        previous_reference=previous,
        source=ScriptedMockSource(["not json"]),
    )
    assert failed.status == "protocol_error"
    assert store.read_input_lock(induction.logical_id())["evidence_fingerprint"] == (
        pack_first.evidence_fingerprint
    )

    # A retry cannot swap in different evidence for the same logical induction.
    conflict = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack_changed,
        previous_reference=previous,
        source=_BoomSource(),
        retry_index=1,
    )
    assert conflict.status == "conflict"

    committed = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack_first,
        previous_reference=previous,
        source=ScriptedMockSource([_judge_response("摘要")]),
        retry_index=1,
    )
    assert committed.status == "committed"


def test_labels_are_candidate_namespaced_and_history_citable(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack_a = _pack(tmp_path, template, candidate=_candidate("A"))
    pack_b = _pack(tmp_path, template, candidate=_candidate("B"))
    sample_a = _label(pack_a, ":sample:训练题 1:r0")
    sample_b = _label(pack_b, ":sample:训练题 1:r0")
    assert sample_a != sample_b
    assert sample_a.startswith("cand-r1A1") and sample_b.startswith("cand-r1B1")

    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    first = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "A", _candidate("A").logical_id()),
        evidence=pack_a,
        previous_reference=itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE),
        source=ScriptedMockSource([_judge_response("结构摘要", evidence=_label(pack_a, ":metric:sample_hit_rate"))]),
    )
    assert first.status == "committed"
    assert _label(pack_a, ":metric:sample_hit_rate") in first.version.evidence_labels()

    # The next induction may cite a traceable label from the previous version.
    second = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 2, "A", _candidate("A", index=2).logical_id()),
        evidence=pack_b,
        previous_reference=first.reference,
        source=ScriptedMockSource(
            [_judge_response("新摘要", evidence=_label(pack_a, ":metric:sample_hit_rate"))]
        ),
    )
    assert second.status == "committed"


def test_judge_reads_both_categories_and_current_template(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template, category=itl.EXPERIENCE_CATEGORY_LITERAL)
    structure_ref = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="v-structure",
        previous_version_id=None,
        summary="结构经验摘要",
        entry_labels=("e-struct",),
        evidence_labels=(),
    )
    literal_ref = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_LITERAL,
        version_id="v-literal",
        previous_version_id=None,
        summary="字面经验摘要",
        entry_labels=("e-lit",),
        evidence_labels=(),
    )
    messages = itl.build_judge_messages(
        itl.JudgeInput(
            category=itl.EXPERIENCE_CATEGORY_LITERAL,
            previous_experience=literal_ref,
            experience_versions=(structure_ref, literal_ref),
            evidence=pack.model_visible(),
            known_evidence_labels=pack.evidence_labels,
        )
    )
    system = messages.messages[0]["content"]
    assert "结构经验摘要" in system and "字面经验摘要" in system
    assert "template_examples" in system and "value = 1" in system


def test_judge_prompt_lists_revisable_entry_labels(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template, category=itl.EXPERIENCE_CATEGORY_LITERAL)
    structure_ref = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        version_id="v-structure",
        previous_version_id=None,
        summary="结构经验摘要",
        entry_labels=("e-struct",),
        evidence_labels=(),
    )
    literal_ref = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_LITERAL,
        version_id="v-literal",
        previous_version_id=None,
        summary="字面经验摘要",
        entry_labels=("e-lit",),
        evidence_labels=(),
    )
    messages = itl.build_judge_messages(
        itl.JudgeInput(
            category=itl.EXPERIENCE_CATEGORY_LITERAL,
            previous_experience=literal_ref,
            experience_versions=(structure_ref, literal_ref),
            evidence=pack.model_visible(),
            known_evidence_labels=pack.evidence_labels,
        )
    )
    assert messages.protocol_version == "itl-judge-induction-v2"
    system = messages.messages[0]["content"]
    assert "不得引用版本 id" in system
    assert "## 本次类别可修订旧条目标签" in system
    revisable = system.split("## 本次类别可修订旧条目标签", 1)[1].split("##", 1)[0]
    assert "- e-lit" in revisable
    # Only the current category's labels are revisable; the other category's
    # labels must not be offered as revision targets.
    assert "e-struct" not in revisable

    initial = itl.build_judge_messages(
        itl.JudgeInput(
            category=itl.EXPERIENCE_CATEGORY_LITERAL,
            previous_experience=itl.ExperienceVersionReference.initial(
                itl.EXPERIENCE_CATEGORY_LITERAL
            ),
            evidence=pack.model_visible(),
            known_evidence_labels=pack.evidence_labels,
        )
    )
    assert "无可修订旧条目" in initial.messages[0]["content"]


def test_seed_and_baseline_comparison_identity_validated(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    b_candidate = _candidate("B")
    with pytest.raises(itl.EvidenceError):
        _pack(
            tmp_path,
            template,
            candidate=b_candidate,
            seed_comparison={"seed_candidate_id": "WRONG-SEED", "metrics": {}, "source_fingerprint": "s"},
        )
    ok_seed = _pack(
        tmp_path,
        template,
        candidate=b_candidate,
        seed_comparison={"seed_candidate_id": "seed-a1", "metrics": {}, "source_fingerprint": "s"},
    )
    assert ok_seed.audit["comparison_identity"]["seed"]["seed_candidate_id"] == "seed-a1"

    with pytest.raises(itl.EvidenceError):
        _pack(
            tmp_path,
            template,
            baseline={
                "available": True,
                "metrics": {},
                "source": {"reference": "WRONG", "source_fingerprint": "s"},
            },
            expected_baseline_reference="fixed-baseline",
        )
    ok_baseline = _pack(
        tmp_path,
        template,
        baseline={
            "available": True,
            "metrics": {},
            "source": {"reference": "fixed-baseline", "source_fingerprint": "s"},
        },
        expected_baseline_reference="fixed-baseline",
    )
    assert ok_baseline.audit["comparison_identity"]["baseline"]["reference"] == "fixed-baseline"


def test_retry_cannot_change_context_experience_or_config(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    literal_v1 = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_LITERAL,
        version_id="lit-v1",
        previous_version_id=None,
        summary="字面 v1",
        entry_labels=(),
        evidence_labels=(),
    )
    literal_v2 = itl.ExperienceVersionReference(
        category=itl.EXPERIENCE_CATEGORY_LITERAL,
        version_id="lit-v2",
        previous_version_id=None,
        summary="字面 v2",
        entry_labels=(),
        evidence_labels=(),
    )
    induction = itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id())
    failed = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        experience_versions=(literal_v1,),
        source=ScriptedMockSource(["not json"]),
    )
    assert failed.status == "protocol_error"

    changed_context = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        experience_versions=(literal_v2,),
        source=_BoomSource(),
        retry_index=1,
    )
    assert changed_context.status == "conflict"

    committed = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        experience_versions=(literal_v1,),
        source=ScriptedMockSource([_judge_response("摘要")]),
        retry_index=1,
    )
    assert committed.status == "committed"

    # The committed path also rejects a changed request-affecting config.
    from coco_attack.method.implicit_then_literal import roles

    changed_config = itl.run_induction(
        store,
        actions,
        induction=induction,
        evidence=pack,
        previous_reference=previous,
        experience_versions=(literal_v1,),
        source=_BoomSource(),
        config=roles.inducer_config(temperature=0.1),
    )
    assert changed_config.status == "conflict"


def test_evidence_references_accumulate_along_version_chain(tmp_path: Path) -> None:
    template = _snapshot()
    _write_artifacts(tmp_path, template=template)
    pack = _pack(tmp_path, template)
    label_x = _label(pack, ":metric:sample_hit_rate")
    label_y = _label(pack, ":sample:训练题 1:r0")
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    initial = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)

    v1 = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 1, "A", _candidate().logical_id()),
        evidence=pack,
        previous_reference=initial,
        source=ScriptedMockSource([_judge_response("v1", evidence=label_x)]),
    )
    assert label_x in v1.reference.evidence_labels

    # v2 keeps X in its summary but its new entry cites only Y.
    v2 = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 2, "A", _candidate("A", index=2).logical_id()),
        evidence=pack,
        previous_reference=v1.reference,
        source=ScriptedMockSource([_judge_response("v2", evidence=label_y)]),
    )
    assert v2.status == "committed"
    assert label_x in v2.reference.evidence_labels
    assert label_y in v2.reference.evidence_labels

    # v3 may cite the older X again because the chain index is cumulative.
    v3 = itl.run_induction(
        store,
        actions,
        induction=itl.InductionIdentity("run-1", 3, "A", _candidate("A", index=3).logical_id()),
        evidence=pack,
        previous_reference=v2.reference,
        source=ScriptedMockSource([_judge_response("v3", evidence=label_x)]),
    )
    assert v3.status == "committed"
