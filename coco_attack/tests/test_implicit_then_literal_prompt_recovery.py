"""Offline checks for pinned prompt recovery and historical run handling."""

import json
import shutil

import pytest

from coco_attack.assets.artifacts import canonical_json_bytes, sha256_bytes, write_json_atomic
from coco_methods import implicit_then_literal as itl
from coco_methods.implicit_then_literal import prompt_renderer as prompts
from coco_methods.implicit_then_literal import runtime as rt
from coco_methods.implicit_then_literal.wiring import MethodRunConfig
from _itl_runtime_fakes import build_harness


def _changed_templates(monkeypatch, tmp_path):
    root = tmp_path / "edited-templates"
    shutil.copytree(prompts._ROOT, root)
    path = root / "a/system.md.j2"
    path.write_text(path.read_text() + "\nEDITED-PROMPT-MARKER", encoding="utf-8")
    monkeypatch.setattr(prompts, "_ROOT", root)


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


def test_unpinned_historical_run_is_readable_but_cannot_execute(tmp_path):
    harness = build_harness(tmp_path, rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    payload = harness.config.to_json()
    payload.pop("prompt_template_sha256")
    payload["config_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    legacy = rt.MethodRuntimeConfig.from_json(payload)
    runtime = rt.MethodRuntime(legacy, services=harness.services)
    # Existing JSON remains available to inspection tools and is not modified.
    runtime.run_root.mkdir(parents=True, exist_ok=True)
    runtime.config_path.write_text(json.dumps(payload), encoding="utf-8")
    runtime.state_path.write_text('{"phase":"stopped"}', encoding="utf-8")
    config_before = runtime.config_path.read_bytes()
    state_before = runtime.state_path.read_bytes()
    assert json.loads(runtime.config_path.read_text())["run_id"] == legacy.run_id
    assert json.loads(runtime.state_path.read_text())["phase"] == "stopped"
    status = itl.build_status_report(
        MethodRunConfig(project_root=str(tmp_path), method=legacy)
    )
    assert status.phase == "stopped"
    assert status.next_command is None
    for operation in (runtime.run, runtime.resume):
        with pytest.raises(rt.MethodRuntimeError, match="history only and create a new run"):
            operation()
    assert runtime.config_path.read_bytes() == config_before
    assert runtime.state_path.read_bytes() == state_before
    assert harness.proposer.calls == []


def test_new_run_can_use_edited_templates_while_pinned_run_keeps_original(monkeypatch, tmp_path):
    harness = build_harness(tmp_path / "old", rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    assert harness.runtime.run(stop_after="baseline_complete")["phase"] == "stopped"
    old_sha = harness.config.prompt_template_sha256
    _changed_templates(monkeypatch, tmp_path)
    fresh = build_harness(tmp_path / "new", rounds=1, a_slots=1, b_slots_per_seed=1, top_k=1)
    assert fresh.config.prompt_template_sha256 == prompts.template_identity()
    assert fresh.config.prompt_template_sha256 != old_sha
    # New run uses current source; continuing old run still reads its snapshot.
    assert fresh.runtime.run()["phase"] == "done"
    assert any("EDITED-PROMPT-MARKER" in str(call) for call in fresh.proposer.calls)
    assert harness.new_runtime().resume()["phase"] == "done"
