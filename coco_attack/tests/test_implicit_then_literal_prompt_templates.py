from __future__ import annotations

from pathlib import Path
import hashlib
import json
from dataclasses import replace

import pytest
from jinja2 import UndefinedError

from coco_attack.method.implicit_then_literal import prompt_renderer
from coco_attack.method import implicit_then_literal as itl
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


def test_refactored_prompts_match_pre_refactor_golden_messages() -> None:
    golden_path = Path(__file__).parent / "data/implicit_then_literal_prompt_golden.json"
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    expected = {row["case"]: row for row in golden["cases"]}
    parent = role_fixtures._snapshot()
    candidate = role_fixtures._candidate()
    references = [
        (),
        (role_fixtures._experience(),),
        (
            role_fixtures._experience(""),
            replace(
                role_fixtures._experience('{{ untouched }}\n{% include "x" %}\n<&> 中文'),
                version_id="v2",
            ),
        ),
    ]
    materials = [
        role_fixtures._materials(),
        replace(
            role_fixtures._materials('def f():\n  return {"x": "{{ raw }}"}\n'),
            system_prefix="",
            examples=(),
            semgrep_rule_text="rules: []\n\n",
        ),
    ]
    priors = [(), ("one", "two\n{{ raw }}")]
    views = [
        (),
        itl.build_rename_target_view(parent),
        itl.build_rename_target_view(role_fixtures._snapshot(["    pass\n"] * 4)),
    ]

    def check(case: str, result) -> None:
        row = expected[case]
        payload = json.dumps(
            result.messages, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        assert hashlib.sha256(payload).hexdigest() == row["messages_sha256"]
        assert result.estimated_input_tokens == row["estimated_input_tokens"]

    for mi, material in enumerate(materials):
        for ei, experience in enumerate(references):
            for pi, prior in enumerate(priors):
                common = dict(
                    candidate=candidate,
                    parent_snapshot=parent,
                    materials=material,
                    experience_versions=experience,
                    structure_priors=prior,
                )
                check(f"a:{mi}:{ei}:{pi}", itl.build_a_messages(itl.AProposalInput(**common)))
                for vi, targets in enumerate(views):
                    check(
                        f"b:{mi}:{ei}:{pi}:{vi}",
                        itl.build_b_messages(itl.BProposalInput(**common, target_views=targets)),
                    )
    for ei, experience in enumerate(references):
        for si, failure in enumerate(
            [None, {}, {"中文": "test {{ intact }}", "value": "line\nnext"}]
        ):
            for ri, previous in enumerate(
                [
                    role_fixtures._experience(),
                    replace(
                        role_fixtures._experience(""),
                        entry_labels=(),
                        previous_version_id="older",
                    ),
                ]
            ):
                check(
                    f"judge:{ei}:{si}:{ri}",
                    itl.build_judge_messages(
                        itl.JudgeInput(
                            category="structure",
                            previous_experience=previous,
                            experience_versions=experience,
                            evidence={"code": "{{ x }}", "samples": []},
                            known_evidence_labels=(),
                            failure_summary=failure,
                        )
                    ),
                )
