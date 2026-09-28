"""Task-06 role wiring + offline preflight tests (offline, no keys/models/Docker)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from coco_attack.iteration.template_snapshot import snapshot_from_clean, write_snapshot
from coco_attack.method.preflight import build_preflight_report
from coco_attack.method.single_candidate_ab import (
    MethodConfig,
    MethodRun,
    MutatorRole,
    ScriptedMutator,
    VictimRole,
    mutator_role_config,
    run_method,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = "poisoned_fewshot_cot"

ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)


def _snapshot(tmp_path: Path):
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store = tmp_path / "snapshots"
    write_snapshot(store, snapshot, action_id="init")
    return snapshot, store


def _config(tmp_path: Path, snapshot, store, **overrides: Any) -> MethodConfig:
    values: dict[str, Any] = {
        "run_dir": str(tmp_path / "run"),
        "snapshot_path": str(store / COMBINATION / snapshot.content_sha256()),
        "snapshot_store": str(store),
        "assets_root": str(ASSETS_DIR),
        "data_dir": str(PREPARED_DIR),
        "max_rounds": 1,
    }
    values.update(overrides)
    return MethodConfig(**values)


def _patch(example: int, **fields: str) -> str:
    return json.dumps([{"example": example, **fields}])


def test_mutator_and_victim_roles_are_independent(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        type("S", (), {"content_sha256": lambda self: "a" * 64})(),
        tmp_path / "store",
        mutator=MutatorRole(source="mock", model="mutator-model", temperature=0.3, max_tokens=4096,
                            context_window_tokens=20000, output_reserve_tokens=4096),
        victim=VictimRole(source="mock", model="victim-model", temperature=0.9, repeats=3, max_tokens=2048),
    )
    role = mutator_role_config(config)
    assert role.role == "mutator"
    assert role.model == "mutator-model"
    assert role.temperature == 0.3
    assert role.max_tokens == 4096

    run = MethodRun(config)
    training = run._training_config  # bound for the call below
    # _training_config only needs a snapshot object with content_sha256(); use a stub.
    snapshot = type("S2", (), {"content_sha256": lambda self: "b" * 64})()
    training_config = training(snapshot, 1, "A")
    assert training_config.model == "victim-model"
    assert training_config.temperature == 0.9
    assert training_config.repeats == 3
    assert training_config.max_tokens == 2048
    assert training_config.source == "mock"
    # Changing the mutator role cannot leak into the victim configuration.
    assert training_config.model != role.model


@requires_prepared
def test_deferred_factory_not_built_when_saved_response_resumes(tmp_path: Path) -> None:
    snapshot, store = _snapshot(tmp_path)
    config = _config(tmp_path, snapshot, store)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    from coco_attack.method.single_candidate_ab import MethodInterrupted

    # Interrupt after the B raw response is durable but before its commit; the
    # whole resume then only needs saved responses (no new provider call).
    with pytest.raises(MethodInterrupted):
        run_method(
            config, mutator_source=mutator, example_check_runner=_AlwaysPassChecker(),
            training_runner=_MockTrainingStub(), interrupts=["after_B_response"],
        )

    built: list[int] = []

    def factory():
        built.append(1)
        raise AssertionError("the deferred factory must not be built on a saved-response resume")

    state = run_method(
        config, mutator_source_factory=factory, example_check_runner=_AlwaysPassChecker(),
        training_runner=_MockTrainingStub(),
    )
    assert state["phase"] == "done"
    assert built == []  # the durable A response was reused without building the source


@requires_prepared
def test_mutator_cache_configured_once_per_run(tmp_path: Path) -> None:
    snapshot, store = _snapshot(tmp_path)
    config = _config(tmp_path, snapshot, store)
    calls: list[int] = []
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    run_method(
        config, mutator_source=mutator, example_check_runner=_AlwaysPassChecker(),
        training_runner=_MockTrainingStub(), cache_configurer=lambda: calls.append(1),
    )
    assert calls == [1]


@requires_prepared
def test_preflight_context_overflow_is_not_ready(tmp_path: Path) -> None:
    snapshot, store = _snapshot(tmp_path)
    config = _config(
        tmp_path, snapshot, store,
        mutator=MutatorRole(source="mock", model="m", max_tokens=1000, output_reserve_tokens=1000,
                            context_window_tokens=1200),
    )
    report = build_preflight_report(config)
    assert report["offline_preflight_passed"] is False
    assert report["readiness"] == "not_ready"
    assert report["context"]["fits"] is False
    assert any("tokens" in item for item in report["errors"])
    # The new input-budget check is warning-only: the pre-existing context error
    # remains the sole reason for not-ready, and the warning never becomes error.
    assert any("mutator input budget is tight" in item for item in report["warnings"])
    assert not any("mutator input budget is tight" in item for item in report["errors"])


@requires_prepared
def test_preflight_produces_report_with_guarded_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, store = _snapshot(tmp_path)
    config = _config(tmp_path, snapshot, store)

    def _forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("preflight must not load keys or call provider/Docker/Semgrep")

    monkeypatch.setattr("coco_attack.generation.service.load_dmx_api_key", _forbidden)
    monkeypatch.setattr("coco_attack.evaluation.sast.scan_sample", _forbidden)

    report = build_preflight_report(config)
    assert report["schema_version"] == "method-preflight-v1"
    assert report["offline_preflight_passed"] is True
    assert report["context"]["fits"] is True
    assert report["roles"]["mutator"]["source"] == "mock"
    assert report["run_scope"]["twenty_five_task_test_used"] is False


@requires_prepared
def test_preflight_warns_on_tight_mutator_input_budget_only(tmp_path: Path) -> None:
    """A tight input+max_tokens budget warns without changing readiness/errors."""

    snapshot, store = _snapshot(tmp_path)
    # A roomy window first, only to measure the assembled fixed block.
    roomy = _config(
        tmp_path, snapshot, store,
        mutator=MutatorRole(source="mock", model="m", max_tokens=8192,
                            output_reserve_tokens=8192, context_window_tokens=10_000_000),
    )
    roomy_report = build_preflight_report(roomy)
    fixed = roomy_report["context"]["fixed_block_tokens"]
    assert fixed > 0
    # Comfortably within budget: no tight-budget warning here.
    assert not any("mutator input budget is tight" in w for w in roomy_report["warnings"])

    # Tight: the fixed block still fits the existing reserve check (no context
    # error) but leaves less than the documented headroom, so the warning fires.
    tight_window = fixed + 8192 + 100
    tight = _config(
        tmp_path, snapshot, store,
        mutator=MutatorRole(source="mock", model="m", max_tokens=8192,
                            output_reserve_tokens=8192, context_window_tokens=tight_window),
    )
    report = build_preflight_report(tight)
    assert report["context"]["fits"] is True
    assert not any("tokens" in error for error in report["errors"])
    assert any("mutator input budget is tight" in w for w in report["warnings"])
    context = report["context"]
    assert context["mutator_input_estimate_tokens"] == fixed
    assert context["mutator_input_plus_max_tokens"] == fixed + 8192
    assert context["mutator_input_headroom_tokens"] < context["mutator_input_headroom_threshold_tokens"]
    # Warning-only: readiness is driven by errors, which stay absent.
    assert report["offline_preflight_passed"] is True
    assert report["readiness"] in (
        "offline_ready",
        "offline_ready_with_undecided_runtime_parameters",
    )


@requires_prepared
def test_preflight_no_tight_budget_warning_when_comfortable(tmp_path: Path) -> None:
    snapshot, store = _snapshot(tmp_path)
    config = _config(
        tmp_path, snapshot, store,
        mutator=MutatorRole(source="mock", model="m", max_tokens=8192,
                            output_reserve_tokens=8192, context_window_tokens=1_000_000),
    )
    report = build_preflight_report(config)
    assert not any("mutator input budget is tight" in w for w in report["warnings"])
    assert report["context"]["mutator_input_headroom_tokens"] >= report["context"][
        "mutator_input_headroom_threshold_tokens"
    ]
    # The absence of the warning does not change readiness either.
    assert report["offline_preflight_passed"] is True
    assert report["readiness"] in (
        "offline_ready",
        "offline_ready_with_undecided_runtime_parameters",
    )


# -- lightweight doubles (avoid importing the full test module) -------------- #


def _always_pass() -> dict[str, Any]:
    return {
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True, "reason": None},
        "functional": {"state": "executed", "outcome": "passed", "passed": True, "reason": None, "failure_stage": None},
        "static": {"state": "executed", "verdict": "target_present", "target_present": True, "reason": None},
        "semgrep": {
            "state": "executed", "status": "completed", "available": True, "completed": True,
            "detected": False, "reason": None, "evidence": {"alerts": []},
        },
    }


class _AlwaysPassChecker:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, request: Any) -> dict[str, Any]:
        self.calls.append(request)
        return _always_pass()


class _MockTrainingStub:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, config: Any) -> dict[str, Any]:
        self.calls.append(config)
        return {"completion": "complete", "source": "mock-double", "candidate_hash": "stub"}
