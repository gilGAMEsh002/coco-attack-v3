"""Offline preflight/assembly agreement and snapshot-ordered A materials."""

from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack.iteration.code_check import build_example_check_request
from coco_attack.iteration.method_inputs import assemble_method_inputs
from coco_attack.iteration.template_snapshot import read_snapshot, write_snapshot
from coco_methods.explicit_feature_a_only.contracts import CandidateIdentity
from coco_methods.explicit_feature_a_only.mock_services import build_doubles
from coco_methods.explicit_feature_a_only.preflight import build_preflight_report
from coco_methods.explicit_feature_a_only.roles import AProposalInput, build_a_messages
from coco_methods.explicit_feature_a_only.runtime import MethodRuntime
from coco_methods.explicit_feature_a_only.wiring import (
    LazyDmxRoleSource,
    MethodRunConfig,
    WiringError,
    assemble_services,
    load_method_run_config,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def mock_config(tmp_path):
    config = load_method_run_config(
        REPO / "coco_attack/configs/explicit_feature_a_only/mock.example.json",
        project_root=REPO,
    )
    return replace(config, method=replace(config.method, run_root=str(tmp_path / "run")))


def _real_config(config):
    method = config.method
    return replace(config, method=replace(
        method,
        proposer_config=replace(method.proposer_config, source="dmx"),
        inducer_config=replace(method.inducer_config, source="dmx"),
        victim_source="dmx",
        check_service="real",
        enforce_formal_constants=True,
    ))


@pytest.mark.parametrize("real", [False, True])
def test_uniform_sources_pass_preflight_and_assemble_without_requests(mock_config, real):
    config = _real_config(mock_config) if real else mock_config
    report = build_preflight_report(config)
    assert report.offline_preflight_passed, report.errors
    services = assemble_services(config, doubles=None if real else build_doubles(config))
    if real:
        for source in (services.proposer_source, services.inducer_source):
            assert isinstance(source, LazyDmxRoleSource)
            assert source.build_count == source.credential_load_count == 0
    assert not config.run_root.exists()


@pytest.mark.parametrize("changed", ["proposer", "inducer", "victim", "victim_and_gate"])
def test_mixed_sources_are_rejected_by_preflight_and_production_assembly(mock_config, changed):
    config = _real_config(mock_config)
    method = config.method
    if changed in ("proposer", "inducer"):
        field = f"{changed}_config"
        method = replace(method, **{field: replace(getattr(method, field), source="mock")})
    else:
        method = replace(method, victim_source="mock", **(
            {"check_service": "mock"} if changed == "victim_and_gate" else {}
        ))
    config = replace(config, method=method)
    report = build_preflight_report(config)
    with pytest.raises(WiringError, match="mixed sources") as rejected:
        assemble_services(config)
    assert not report.offline_preflight_passed
    assert str(rejected.value) in report.errors
    assert next(check for check in report.checks if check.code == "sources").level != "ok"
    assert not config.run_root.exists()


def test_explicit_offline_doubles_can_still_assemble_mixed_sources(mock_config):
    config = _real_config(mock_config)
    config = replace(config, method=replace(
        config.method, proposer_config=replace(config.method.proposer_config, source="mock")
    ))
    doubles = replace(build_doubles(config), allow_mixed_sources=True)
    services = assemble_services(config, doubles=doubles)
    assert services.proposer_source is doubles.proposer_source
    assert services.inducer_source is doubles.inducer_source
    assert services.gate_runner is doubles.gate_runner
    assert services.training_runner is doubles.training_runner
    assert not build_preflight_report(config).offline_preflight_passed
    assert not config.run_root.exists()


@pytest.mark.parametrize("injected_builder", [False, True])
def test_reordered_snapshot_aligns_a_materials_messages_and_gate(mock_config, tmp_path, injected_builder):
    initial = read_snapshot(mock_config.method.initial_template_path)
    examples = list(initial.examples)
    examples[1], examples[2] = examples[2], examples[1]
    snapshot = replace(initial, examples=tuple(examples))
    stored = write_snapshot(
        tmp_path / "snapshots", snapshot, action_id="test-reordered-examples",
        parent_sha256=initial.content_sha256(), diff=[],
    )
    config = MethodRunConfig.from_json(
        {**mock_config.to_json(), "initial_template_path": str(stored / "snapshot.json")},
        project_root=REPO,
    )
    report = build_preflight_report(config)
    assert report.offline_preflight_passed, report.errors
    doubles = build_doubles(config)
    observed = []
    if injected_builder:
        def builder(**kwargs):
            observed.append(tuple(kwargs["example_task_ids"]))
            return assemble_method_inputs(**kwargs)
        doubles = replace(doubles, materials_builder=builder)
    runtime = MethodRuntime(config.method, services=assemble_services(config, doubles=doubles))
    materials = runtime._materials(snapshot)
    assert tuple(item["task_id"] for item in materials.examples) == snapshot.example_ids()
    if injected_builder:
        assert observed == [snapshot.example_ids()]
    messages = build_a_messages(AProposalInput(
        candidate=CandidateIdentity(run_id=config.method.run_id, round_index=1, stage="A", candidate_index=1),
        parent_snapshot=snapshot, materials=materials,
    ))
    system = messages.messages[0]["content"]
    for number, material in enumerate(materials.examples, 1):
        section = system.split(f"### 示例 {number}\n", 1)[1].split("### 示例", 1)[0]
        assert material["test"] in section
        assert material["code_prompt"] in section
        request = build_example_check_request(
            snapshot, number, assets_root=config.method.assets_root,
            action_id=f"test-gate-{number}", output_dir=tmp_path / f"gate-{number}",
        )
        assert request.task_id == material["task_id"]
        assert request.code == snapshot.example(number).code
    assert not config.run_root.exists()


# --------------------------------------------------------------------------- #
# opt-in cot-focus plan (``focus_plan``)
# --------------------------------------------------------------------------- #


def _focus_plan(mock_config, tmp_path):
    """Build a 2-round x 3-slot cot-focus plan on temporary base snapshots."""

    initial = read_snapshot(mock_config.method.initial_template_path)
    store = tmp_path / "focus-bases"
    bases = []
    for index, label in enumerate(("base-carrier", "base-distribution", "base-attribution")):
        examples = list(initial.examples)
        examples[1] = replace(examples[1], cot=f"Step 1. {label}.\n")
        snapshot = replace(initial, examples=tuple(examples))
        stored = write_snapshot(
            store, snapshot, action_id=f"preflight-focus-{index}",
            parent_sha256=initial.content_sha256(), diff=[],
        )
        bases.append({"path": str(stored / "snapshot.json"), "label": label})
    return tuple(
        {
            "round": round_index,
            "slots": [
                {"snapshot": base["path"], "label": base["label"],
                 "axis": f"axis-{index}", "focus": f"round {round_index} cot only {index}"}
                for index, base in enumerate(bases)
            ],
        }
        for round_index in (1, 2)
    )


def test_preflight_reports_focus_plan_not_enabled_by_default(mock_config):
    report = build_preflight_report(mock_config)
    assert report.offline_preflight_passed, report.errors
    finding = next(item for item in report.checks if item.code == "focus_plan")
    assert finding.level == "ok"
    assert "未启用" in finding.detail
    assert "focus_plan" not in mock_config.method.to_json()


def test_preflight_reports_focus_plan_bases_and_base_readability(mock_config, tmp_path):
    focus_plan = _focus_plan(mock_config, tmp_path)
    config = replace(mock_config, method=replace(mock_config.method, focus_plan=focus_plan))
    report = build_preflight_report(config)
    assert report.offline_preflight_passed, report.errors
    finding = next(item for item in report.checks if item.code == "focus_plan")
    assert finding.level == "ok"
    assert "focus_plan: cot, 2 rounds x 3 slots" in finding.detail
    for label in ("base-carrier", "base-distribution", "base-attribution"):
        assert label in finding.detail

    broken_slots = [dict(slot) for slot in focus_plan[0]["slots"]]
    broken_slots[0]["snapshot"] = str(tmp_path / "does-not-exist" / "snapshot.json")
    broken = replace(
        mock_config,
        method=replace(
            mock_config.method,
            focus_plan=({"round": 1, "slots": broken_slots}, {"round": 2, "slots": broken_slots}),
        ),
    )
    broken_report = build_preflight_report(broken)
    assert not broken_report.offline_preflight_passed
    assert any("does-not-exist" in error for error in broken_report.errors)
    assert next(item for item in broken_report.checks if item.code == "focus_plan").level == "error"


def test_preflight_reports_frozen_slot_kind_and_validates_frozen_source(mock_config, tmp_path):
    focus_plan = _focus_plan(mock_config, tmp_path)
    first_round = [dict(slot) for slot in focus_plan[0]["slots"]]
    frozen = first_round[-1]
    frozen.pop("focus")
    frozen.update({
        "label": "frozen-control",
        "frozen_cot": {"2": "a", "3": "b", "4": "c"},
        "provenance": "experimenter-frozen: probe",
    })
    plan = tuple(
        {"round": entry["round"],
         "slots": tuple(first_round if entry["round"] == 1 else entry["slots"])}
        for entry in focus_plan
    )
    config = replace(mock_config, method=replace(mock_config.method, focus_plan=plan))
    report = build_preflight_report(config)
    assert report.offline_preflight_passed, report.errors
    finding = next(item for item in report.checks if item.code == "focus_plan")
    assert finding.level == "ok"
    assert "cot_frozen(provenance=experimenter-frozen: probe)" in finding.detail
    assert "r1 slots=[cot, cot, cot_frozen(provenance=experimenter-frozen: probe)]" in finding.detail

    # An unreadable frozen source is accepted by the shape-only config check but
    # reported as a preflight error (never silently ignored).
    broken_frozen = dict(frozen)
    broken_frozen.pop("frozen_cot")
    broken_frozen["frozen_cot_from_snapshot"] = str(
        tmp_path / "missing-frozen-source" / "snapshot.json"
    )
    broken_plan = tuple(
        {"round": entry["round"],
         "slots": tuple(
             (first_round[:-1] + [broken_frozen]) if entry["round"] == 1 else entry["slots"]
         )}
        for entry in focus_plan
    )
    broken = replace(mock_config, method=replace(mock_config.method, focus_plan=broken_plan))
    broken_report = build_preflight_report(broken)
    assert not broken_report.offline_preflight_passed
    assert any("frozen_cot_from_snapshot" in error for error in broken_report.errors)
    assert any("missing-frozen-source" in error for error in broken_report.errors)
    assert next(item for item in broken_report.checks if item.code == "focus_plan").level == "error"
