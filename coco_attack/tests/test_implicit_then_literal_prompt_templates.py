from __future__ import annotations

from pathlib import Path
import json

import pytest
from jinja2 import UndefinedError

from coco_methods.implicit_then_literal import prompt_renderer
from coco_methods import implicit_then_literal as itl
import test_implicit_then_literal_roles as role_fixtures


def test_prompt_renderer_requires_declared_template_and_all_variables() -> None:
    with pytest.raises(FileNotFoundError):
        prompt_renderer.render("missing.md.j2")
    with pytest.raises(UndefinedError):
        prompt_renderer.render("a.user.md.j2")


def test_template_identity_covers_nested_file_names_and_bytes(monkeypatch, tmp_path: Path) -> None:
    templates = tmp_path / "templates"
    (templates / "a").mkdir(parents=True)
    (templates / "manifest.json").write_text(
        '{"roles":{"a.system.md.j2":"a/system.md.j2"}}', encoding="utf-8"
    )
    prompt = templates / "a" / "system.md.j2"
    prompt.write_bytes(b"one")
    monkeypatch.setattr(prompt_renderer, "_ROOT", templates)
    first = prompt_renderer.template_identity()
    prompt.write_bytes(b"two")
    second = prompt_renderer.template_identity()
    assert first != second


def test_prompt_copy_can_change_prose_for_each_role_without_losing_inputs() -> None:
    from coco_methods.implicit_then_literal.prompt_renderer import PromptBundle

    original = prompt_renderer.load_packaged_bundle()
    files = dict(original.contents)
    files["a/system.md.j2"] = "Edited A system header\n" + files["a/system.md.j2"]
    files["b/system.md.j2"] = "Edited B system header\n" + files["b/system.md.j2"]
    files["inducer/system.md.j2"] = "Edited induction system header\n" + files["inducer/system.md.j2"]

    bundle = PromptBundle(files)
    assert bundle.sha256 != original.sha256
    parent = role_fixtures._snapshot()
    materials = role_fixtures._materials()
    experience = role_fixtures._experience("task-specific experience")
    a_request = itl.AProposalInput(
        candidate=itl.CandidateIdentity(run_id="run-1", round_index=1, stage="A", candidate_index=1),
        parent_snapshot=parent, materials=materials,
        experience_versions=(experience,),
    )
    b_request = itl.BProposalInput(
        candidate=role_fixtures._candidate(), parent_snapshot=parent, materials=materials,
        experience_versions=(experience,),
        target_views=itl.build_rename_target_view(parent),
    )
    judge_request = itl.JudgeInput(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        previous_experience=experience,
        experience_versions=(experience,),
        evidence={"fact": "distinctive evidence fact"},
        known_evidence_labels=(),
        failure_summary={"reference": "ref", "description": "details", "evidence": ["x"]},
    )
    with prompt_renderer.use_prompt_bundle(bundle):
        a_result = itl.build_a_messages(a_request)
        b_result = itl.build_b_messages(b_request)
        judge_result = itl.build_judge_messages(judge_request)

    for result in (a_result, b_result, judge_result):
        rendered = "\n".join(message["content"] for message in result.messages)
        assert "task-specific experience" in rendered
    a_rendered = "\n".join(message["content"] for message in a_result.messages)
    b_rendered = "\n".join(message["content"] for message in b_result.messages)
    judge_rendered = "\n".join(message["content"] for message in judge_result.messages)
    assert "Edited A system header" in a_rendered
    assert "Edited B system header" in b_rendered
    assert "Edited induction system header" in judge_rendered
    assert "distinctive evidence fact" in judge_rendered
    assert a_result.protocol_version == itl.A_PROTOCOL_VERSION
    assert b_result.protocol_version == itl.B_PROTOCOL_VERSION
    assert judge_result.protocol_version == itl.JUDGE_PROTOCOL_VERSION


def test_material_sections_are_independently_renderable() -> None:
    material = role_fixtures._materials()
    tests = prompt_renderer.render("shared.example-tests.md.j2", examples=material.examples)
    rules = prompt_renderer.render("shared.semgrep-rules.md.j2", semgrep_rule_text=material.semgrep_rule_text)
    assert material.examples[0]["test"] in tests
    assert material.semgrep_rule_text in rules
