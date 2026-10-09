"""Offline regressions for prompt versions, pinned runs and legacy recovery."""
from dataclasses import replace
import json
import shutil

import pytest

from coco_attack.assets.artifacts import canonical_json_bytes, sha256_bytes, write_json_atomic
from coco_attack.iteration.action_runtime import ActionStore, ScriptedMockSource
from coco_attack.method import implicit_then_literal as itl
from coco_attack.method.implicit_then_literal import prompt_renderer as prompts
from coco_attack.method.implicit_then_literal import runtime as rt
from coco_attack.method.implicit_then_literal import experience as exp
from coco_attack.method.implicit_then_literal import roles
import test_implicit_then_literal_roles as role_fixtures
from _itl_runtime_fakes import build_harness
import test_implicit_then_literal_experience as evidence_fixtures


def _changed_templates(monkeypatch, tmp_path):
    root = tmp_path / "edited-templates"
    shutil.copytree(prompts._ROOT, root)
    path = root / "a/system.md.j2"
    path.write_text(path.read_text() + "\nEDITED-PROMPT-MARKER", encoding="utf-8")
    monkeypatch.setattr(prompts, "_ROOT", root)
    return root


def test_resume_uses_pinned_copy_after_packaged_templates_change(monkeypatch, tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    assert harness.runtime.run(stop_after="baseline_complete")["phase"] == "stopped"
    bundle_path = harness.runtime.run_root / "prompt_bundle.json"
    frozen = bundle_path.read_bytes()
    assert json.loads(frozen)["sha256"] == harness.config.prompt_template_sha256
    _changed_templates(monkeypatch, tmp_path)
    assert prompts.template_identity() != harness.config.prompt_template_sha256
    persisted = json.loads(harness.runtime.config_path.read_text())
    config = rt.MethodRuntimeConfig.from_json(persisted)
    assert config.config_sha256() == harness.config.config_sha256()
    assert rt.MethodRuntime(config, services=harness.services).resume()["phase"] == "done"
    assert bundle_path.read_bytes() == frozen
    assert all("EDITED-PROMPT-MARKER" not in str(call) for call in harness.proposer.calls)
    assert replace(config, run_id="fresh", prompt_template_sha256=prompts.template_identity()).config_sha256() != config.config_sha256()


def test_bundle_tamper_blocks_before_actions_or_state_write(tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    harness.runtime.run(stop_after="baseline_complete")
    state = harness.runtime.state_path.read_bytes()
    path = harness.runtime.run_root / "prompt_bundle.json"
    data = json.loads(path.read_text())
    data["files"]["a/system.md.j2"] += "tampered"
    write_json_atomic(path, data)
    with pytest.raises(rt.MethodRuntimeError, match="content hash mismatch"):
        harness.new_runtime().resume()
    assert harness.runtime.state_path.read_bytes() == state
    assert harness.proposer.calls == []


def test_legacy_config_identity_and_read_only_load_survive_template_edit(monkeypatch, tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    payload = harness.config.to_json()
    payload.pop("prompt_template_sha256")
    old_sha = sha256_bytes(canonical_json_bytes(payload))
    payload["config_sha256"] = old_sha
    legacy = rt.MethodRuntimeConfig.from_json(payload)
    assert legacy.prompt_template_sha256 is None
    assert legacy.config_sha256() == old_sha
    runtime = rt.MethodRuntime(legacy, services=harness.services)
    assert runtime.run(stop_after="baseline_complete")["phase"] == "stopped"
    assert not (runtime.run_root / "prompt_bundle.json").exists()
    config_bytes = runtime.config_path.read_bytes()
    state_bytes = runtime.state_path.read_bytes()
    _changed_templates(monkeypatch, tmp_path)
    reloaded = rt.MethodRuntimeConfig.from_json(json.loads(config_bytes))
    assert reloaded.config_sha256() == old_sha
    with pytest.raises(rt.MethodRuntimeError, match="legacy run"):
        rt.MethodRuntime(reloaded, services=harness.services).resume()
    assert runtime.config_path.read_bytes() == config_bytes
    assert runtime.state_path.read_bytes() == state_bytes
    assert harness.proposer.calls == []


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_induction_lock_and_committed_adoption_pin_prompt_bundle(tmp_path, monkeypatch, committed, legacy):
    template = evidence_fixtures._snapshot()
    evidence_fixtures._write_artifacts(tmp_path, template=template)
    pack = evidence_fixtures._pack(tmp_path, template)
    store = itl.ExperienceStore(tmp_path / "experience")
    actions = ActionStore(tmp_path / "actions")
    previous = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    induction = itl.InductionIdentity(
        run_id="run-1", round_index=1, stage="A",
        candidate_id=evidence_fixtures._candidate().logical_id(),
    )
    kwargs = dict(induction=induction, evidence=pack, previous_reference=previous)
    response = evidence_fixtures._judge_response("summary") if committed else "not json"
    with monkeypatch.context() as patch:
        if legacy:
            patch.setattr(exp, "_action_input_refs", lambda store, aid, refs: {
                key: value for key, value in refs.items() if key != "prompt_template_sha256"
            })
        result = itl.run_induction(store, actions, source=ScriptedMockSource([response]), **kwargs)
    assert result.status == ("committed" if committed else "protocol_error")
    paths = [store.input_lock_path(induction.logical_id())]
    if committed:
        paths.append(store.induction_path(induction.logical_id()))
    for path in paths:
        data = json.loads(path.read_text())
        assert data["prompt_template_sha256"] == prompts.template_identity()
        if legacy:
            data.pop("prompt_template_sha256")
            write_json_atomic(path, data)
    files = dict(prompts.current_bundle().contents)
    files["a/system.md.j2"] += "\nchanged"
    source = ScriptedMockSource([])
    with prompts.use_prompt_bundle(prompts.PromptBundle(files)):
        conflict = itl.run_induction(store, actions, source=source, retry_index=1, **kwargs)
    assert conflict.status == "conflict"
    assert source.calls == []
    recovered = itl.run_induction(store, actions, source=source, **kwargs)
    assert recovered.status == result.status
    assert source.calls == []


def test_one_bundle_remains_immutable_and_context_does_not_leak(monkeypatch, tmp_path):
    original = prompts.current_bundle()
    original_user = original.render("a.user.md.j2", template_text="{{ not_a_template }}", goal="goal")
    _changed_templates(monkeypatch, tmp_path)
    with prompts.use_prompt_bundle(original):
        assert prompts.template_identity() == original.sha256
        assert prompts.render("a.user.md.j2", template_text="{{ not_a_template }}", goal="goal") == original_user
    assert prompts.template_identity() != original.sha256


@pytest.mark.parametrize("stage", ["A", "B"])
def test_legacy_proposal_action_reuses_unchanged_request(tmp_path, monkeypatch, stage):
    store = ActionStore(tmp_path / "actions")
    parent = role_fixtures._snapshot()
    common = dict(
        candidate=itl.CandidateIdentity(run_id="legacy", round_index=1, stage=stage,
            candidate_index=1, seed_candidate_id="seed" if stage == "B" else None),
        parent_snapshot=parent, materials=role_fixtures._materials(),
    )
    if stage == "A":
        request = roles.AProposalInput(**common)
        run = roles.run_a_proposal
        response = '{"structure":"one","patch":[{"example":2,"code":"    return 7"}]}'
    else:
        request = roles.BProposalInput(**common, target_views=roles.build_rename_target_view(parent))
        run = roles.run_b_proposal
        response = '{"modifications":[{"example":2,"new_cot":"new thought"}]}'
    with monkeypatch.context() as patch:
        patch.setattr(roles, "_action_input_refs", lambda store, aid, refs: {
            key: value for key, value in refs.items() if key != "prompt_template_sha256"
        })
        original = run(store, request, source=ScriptedMockSource([response]))
    empty = ScriptedMockSource([])
    resumed = run(store, request, source=empty)
    assert resumed.status == original.status == "materialized"
    assert empty.calls == []
    # Adding a template elsewhere also changes the bundle identity, and must
    # not exploit legacy compatibility even if this role's text stays equal.
    bundle_files = dict(prompts.current_bundle().contents)
    bundle_files["inducer/user.md.j2"] += "\nchanged"
    from coco_attack.iteration.action_runtime import ActionConflictError
    with prompts.use_prompt_bundle(prompts.PromptBundle(bundle_files)):
        with pytest.raises(ActionConflictError):
            run(store, request, source=empty)
    assert empty.calls == []
