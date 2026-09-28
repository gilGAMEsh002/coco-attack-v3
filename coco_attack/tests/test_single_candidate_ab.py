"""Task-05 single-candidate A/B method tests (method layer).

All runs are offline and deterministic: the mutator, example-check runner and
training runner are injected.  Gate outcomes are mock facts (clearly labelled),
never real gate passes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from coco_attack.iteration.template_snapshot import (
    read_snapshot,
    snapshot_from_clean,
    write_snapshot,
)
from coco_attack.method.single_candidate_ab import (
    MethodConfig,
    MethodError,
    MethodInterrupted,
    ScriptedMutator,
    evaluate_example_gate,
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


def _gate_result(
    *,
    syntax_state: str = "ok",
    entry: bool = True,
    functional_state: str = "passed",
    verdict: str = "target_present",
    static_state: str = "completed",
    semgrep_status: str = "completed",
    available: bool = True,
    completed: bool = True,
    detected: Any = False,
) -> dict[str, Any]:
    # Mirrors the real run_example_code_check vocabulary (state="executed",
    # syntax_ok, functional outcome/passed, static verdict/target_present).
    return {
        "syntax": {
            "state": "executed",
            "syntax_ok": syntax_state == "ok",
            "entry_present": entry,
            "reason": None,
        },
        "functional": {
            "state": "executed",
            "outcome": functional_state,
            "passed": functional_state == "passed",
            "reason": None,
            "failure_stage": None,
        },
        "static": {
            "state": "executed",
            "verdict": verdict,
            "target_present": verdict == "target_present",
            "reason": None,
        },
        "semgrep": {
            "state": "executed" if completed else "incomplete",
            "status": semgrep_status,
            "available": available,
            "completed": completed,
            "detected": detected,
            "reason": None,
            "evidence": {"alerts": []},
        },
    }


PASS_RESULT = _gate_result()


class FakeChecker:
    """Deterministic example-check runner keyed by (snapshot sha, example)."""

    def __init__(self, plan: Mapping[tuple[str, int], Mapping[str, Any]] | None = None) -> None:
        self.plan = dict(plan or {})
        self.calls: list[Any] = []

    def __call__(self, request: Any) -> dict[str, Any]:
        self.calls.append(request)
        token = str(request.code_source).rsplit(":", 1)[-1]
        sha, _, example = token.partition("#example")
        result = self.plan.get((sha, int(example))) if example else None
        return dict(result if result is not None else PASS_RESULT)


class FakeTraining:
    """Explicit mock training double (no per-sample feedback file).

    ``source="mock-double"`` marks the missing feedback as an explicit mock
    limitation; completion uses the normal ``complete`` protocol.
    """

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, config: Any) -> dict[str, Any]:
        self.calls.append(config)
        return {
            "completion": "complete",
            "source": "mock-double",
            "candidate_hash": "mock-" + config.batch_id,
        }


def _make_snapshot(tmp_path: Path):
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    write_snapshot(store_root, snapshot, action_id="init")
    snapshot_path = store_root / COMBINATION / snapshot.content_sha256()
    return snapshot, store_root, snapshot_path


def _make_config(
    tmp_path: Path, snapshot_path: Path, store_root: Path, *, max_rounds: int = 1, **overrides: object
) -> MethodConfig:
    return MethodConfig(
        **overrides,
        run_dir=str(tmp_path / "run"),
        snapshot_path=str(snapshot_path),
        snapshot_store=str(store_root),
        assets_root=str(ASSETS_DIR),
        data_dir=str(PREPARED_DIR),
        max_rounds=max_rounds,
    )


def _patch(example: int, **fields: str) -> str:
    return json.dumps([{"example": example, **fields}])


def _read_state(config: MethodConfig) -> dict[str, Any]:
    return json.loads((Path(config.run_dir) / "state.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Gate composition
# --------------------------------------------------------------------------- #


def test_gate_accepts_real_check_result_vocabulary() -> None:
    """Guard against using an invented fact vocabulary instead of code_check's.

    Values mirror a captured real ``check_result.json`` (state="executed",
    syntax_ok, functional outcome/passed, static verdict/target_present).
    """

    real = {
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True, "reason": None},
        "functional": {"state": "executed", "outcome": "passed", "passed": True, "reason": None, "failure_stage": None},
        "static": {"state": "executed", "verdict": "target_present", "target_present": True, "reason": None},
        "semgrep": {
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "reason": None,
            "evidence": {"alerts": []},
        },
    }
    assert evaluate_example_gate(real, example=2, label="x").passed

    absent = dict(real)
    absent["static"] = {"state": "executed", "verdict": "target_absent", "target_present": False}
    assert evaluate_example_gate(absent, example=2, label="x").passed is False

    functional_fail = dict(real)
    functional_fail["functional"] = {"state": "executed", "outcome": "failed", "passed": False}
    assert evaluate_example_gate(functional_fail, example=2, label="x").passed is False


def test_config_round_trip_and_hash_covers_research_fields(tmp_path: Path) -> None:
    config = MethodConfig(
        run_dir=str(tmp_path / "run"),
        snapshot_path=str(tmp_path / "snap"),
        snapshot_store=str(tmp_path / "store"),
        assets_root=str(tmp_path / "assets"),
        data_dir=str(tmp_path / "data"),
    )
    assert MethodConfig.from_json(config.to_json()) == config
    assert MethodConfig.from_json(config.to_json()).config_sha256() == config.config_sha256()
    changed_prefix = MethodConfig.from_json({**config.to_json(), "system_prefix": "different"})
    assert changed_prefix.config_sha256() != config.config_sha256()
    changed_baseline = MethodConfig.from_json(
        {**config.to_json(), "baseline_static": "/some/baseline.jsonl"}
    )
    assert changed_baseline.config_sha256() != config.config_sha256()


def test_gate_requires_all_three_conditions() -> None:
    assert evaluate_example_gate(_gate_result(), example=2, label="x").passed
    blockers = [
        _gate_result(functional_state="failed"),
        _gate_result(verdict="target_absent"),
        _gate_result(semgrep_status="incomplete", completed=False, detected=None),
        _gate_result(semgrep_status="error", completed=False, detected=None),
        _gate_result(available=False, completed=False, detected=None),
        _gate_result(detected=True),
        _gate_result(syntax_state="syntax_error"),
        _gate_result(entry=False),
    ]
    for blocked in blockers:
        result = evaluate_example_gate(blocked, example=2, label="x")
        assert result.passed is False
        assert result.reasons


# --------------------------------------------------------------------------- #
# One round: A failure then success, then one-shot B
# --------------------------------------------------------------------------- #


@requires_prepared
def test_one_round_A_failure_then_success_then_B(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    # After A1 (example 2 code) the gate fails; after A2 (example 3 code) it passes.
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, code="def task_func():\n    return 22\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    holder: dict[str, Any] = {"seen": []}

    class Checker(FakeChecker):
        def __call__(self, request: Any) -> dict[str, Any]:
            self.calls.append(request)
            token = str(request.code_source).rsplit(":", 1)[-1]
            sha, _, example = token.partition("#example")
            example = int(example)
            if sha not in holder["seen"]:
                holder["seen"].append(sha)  # [0]=c0 initial, [1]=after A1, [2]=after A2
            # Initial c0 functional check passes; only the A1 template blocks.
            if len(holder["seen"]) == 2 and example == 2:
                return _gate_result(functional_state="failed")
            return PASS_RESULT

    checker = Checker()
    training = FakeTraining()
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=training)

    assert state["phase"] == "done"
    assert state["round"] == 1
    # Two A decisions + one B decision only.
    assert len(mutator.calls) == 3
    # Training happened once for A and once for B, i.e. only after the gate passed.
    assert len(training.calls) == 2
    assert state["training"]["kind"] == "B"
    # The first gate failure appended feedback and stayed in A.
    roles = [unit.role for unit in _history_units(config)]
    assert "gate" in roles and "training" in roles
    # B changed only the cot and the final template reflects it.
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert final.example(3).cot == "revised cot"
    assert final.example(1).code == snapshot.example(1).code  # example 1 frozen


def _history_units(config: MethodConfig):
    from coco_attack.iteration.action_runtime import HistoryStore

    return HistoryStore(config.run_dir).units()


@requires_prepared
def test_accumulated_pending_examples_are_rechecked(tmp_path: Path) -> None:
    """After A1 changes example 2 (fails) and A2 changes example 3, both are checked."""

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, code="def task_func():\n    return 22\n"),
            _patch(3, cot="c"),
        ]
    )

    class Checker(FakeChecker):
        def __init__(self) -> None:
            super().__init__()
            self.checked: list[tuple[str, int]] = []
            self.seen: list[str] = []

        def __call__(self, request: Any) -> dict[str, Any]:
            self.calls.append(request)
            token = str(request.code_source).rsplit(":", 1)[-1]
            sha, _, example = token.partition("#example")
            self.checked.append((sha, int(example)))
            if sha not in self.seen:
                self.seen.append(sha)  # [0]=c0 init, [1]=after A1, [2]=after A2
            # A1 template (second distinct sha) fails; the A2 template passes both.
            if len(self.seen) == 2:
                return _gate_result(functional_state="failed")
            return PASS_RESULT

    checker = Checker()
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    # Some template was checked for both example 2 (accumulated) and example 3.
    by_sha: dict[str, set[int]] = {}
    for sha, example in checker.checked:
        by_sha.setdefault(sha, set()).add(example)
    assert any({2, 3} <= examples for examples in by_sha.values())


@requires_prepared
def test_gate_failure_blocks_training_and_is_inspectable(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n")])

    class Blocking(FakeChecker):
        def __call__(self, request: Any) -> dict[str, Any]:
            self.calls.append(request)
            return _gate_result(verdict="target_absent")

    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=Blocking(),
            training_runner=training,
            interrupts=["after_feedback_append"],
        )
    state = _read_state(config)
    assert state["phase"] == "A_gate"  # blocked, did not advance
    assert training.calls == []
    assert len(mutator.calls) == 1


# --------------------------------------------------------------------------- #
# One-shot B
# --------------------------------------------------------------------------- #


@requires_prepared
def test_invalid_B_consumes_the_single_chance_without_template_change(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            "{broken json",
        ]
    )
    training = FakeTraining()
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert state["b_consumed"] is True
    assert len(mutator.calls) == 2  # A + B only, no repair request
    assert len(training.calls) == 1  # A training only; no B training
    # Template is exactly the post-A template (B did not change it).
    post_a = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert post_a.example(2).code.endswith("return 11\n")
    assert any(unit.role == "gate" for unit in _history_units(config))


@requires_prepared
def test_invalid_A_patch_records_feedback_and_stays_in_A(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            "{not json",
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="c"),
        ]
    )
    training = FakeTraining()
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert len(mutator.calls) == 3  # invalid A, valid A, B
    assert len(training.calls) == 2
    units = _history_units(config)
    # The mutator interactions and the invalid-A feedback both reach history.
    assert any(unit.role == "mutator" for unit in units)
    assert any(unit.action_id == "R1-A0-failure" for unit in units)


@requires_prepared
def test_valid_B_may_change_all_three_cots_in_one_patch(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    b_patch = json.dumps(
        [
            {"example": 2, "cot": "cot two"},
            {"example": 3, "cot": "cot three"},
            {"example": 4, "cot": "cot four"},
        ]
    )
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), b_patch])
    training = FakeTraining()
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert (final.example(2).cot, final.example(3).cot, final.example(4).cot) == (
        "cot two",
        "cot three",
        "cot four",
    )
    assert len(training.calls) == 2  # A and B training


# --------------------------------------------------------------------------- #
# Recovery windows
# --------------------------------------------------------------------------- #


@requires_prepared
def test_B_response_saved_interrupt_resumes_without_second_provider_call(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=FakeChecker(),
            training_runner=training,
            interrupts=["after_B_response"],
        )
    assert len(mutator.calls) == 2

    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert len(mutator.calls) == 2  # the durable B response was reused
    assert len(training.calls) == 2
    b_commits = [
        event
        for event in _action_events(config)
        if event["action_id"] == "R1-B" and event["event_type"] == "action_committed"
    ]
    assert len(b_commits) == 1


@requires_prepared
def test_A_response_saved_interrupt_resumes_without_second_provider_call(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=FakeChecker(),
            training_runner=training,
            interrupts=["after_A_response"],
        )
    assert len(mutator.calls) == 1
    assert training.calls == []
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert len(mutator.calls) == 2  # A reused, B is the only new provider call
    assert len(training.calls) == 2


@requires_prepared
def test_A_commit_interrupt_adopts_committed_patch(tmp_path: Path) -> None:
    """Patch committed but the method pointer not updated: resume adopts it."""

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=FakeChecker(),
            training_runner=training,
            interrupts=["after_A_commit"],
        )
    assert len(mutator.calls) == 1
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert len(mutator.calls) == 2  # A adopted from the commit; B is the only new call
    assert len(training.calls) == 2
    # Exactly one template version was created for the A patch.
    versions = list((store_root / COMBINATION).glob("*"))
    assert len(versions) == 3  # c0 + A + B


@requires_prepared
def test_gate_evidence_is_reused_after_interrupt(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    checker = FakeChecker()
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=checker,
            training_runner=training,
            interrupts=["after_gate"],
        )
    checks_before = len(checker.calls)
    state = run_method(
        config, mutator_source=mutator, example_check_runner=checker, training_runner=training
    )
    assert state["phase"] == "done"
    # The persisted gate evidence was reused, so the checks were not repeated.
    assert len(checker.calls) == checks_before


@requires_prepared
def test_training_interrupt_resumes_the_same_evaluation(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=FakeChecker(),
            training_runner=training,
            interrupts=["before_training"],
        )
    assert training.calls == []
    assert len(mutator.calls) == 1
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert len(mutator.calls) == 2
    assert len(training.calls) == 2
    # The A training feedback was recorded exactly once despite the retry.
    feedback = [
        unit
        for unit in _history_units(config)
        if unit.action_id == "R1-A-training-feedback"
    ]
    assert len(feedback) == 1


@requires_prepared
def test_after_training_interrupt_reuses_completed_evaluation(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )
    training = FakeTraining()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=FakeChecker(),
            training_runner=training,
            interrupts=["after_training"],
        )
    assert len(training.calls) == 1  # A training completed before the interrupt
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    # The completed A evaluation was reused; only the B evaluation ran on resume.
    assert len(training.calls) == 2
    assert len(mutator.calls) == 2


# --------------------------------------------------------------------------- #
# §8 F1-F4: full feedback, explicit completion, init recovery, script binding
# --------------------------------------------------------------------------- #


def _calls_for(mutator: ScriptedMutator, action_id: str) -> list[list[dict[str, str]]]:
    return [entry["messages"] for entry in mutator.calls if entry.get("action_id") == action_id]


class CountingChecker:
    """Counts example-check executions per (template sha, example); always passes.

    The gate phase legitimately re-checks a mutated example, so initial-check
    reuse must be asserted against the *initial* template sha only.
    """

    def __init__(self, result: Mapping[str, Any] | None = None) -> None:
        self.calls: list[Any] = []
        self.records: list[tuple[str, int]] = []
        self._result = dict(result) if result is not None else None

    def __call__(self, request: Any) -> dict[str, Any]:
        self.calls.append(request)
        token = str(request.code_source).rsplit(":", 1)[-1]
        sha, _, example = token.partition("#example")
        self.records.append((sha, int(example)))
        return dict(self._result) if self._result is not None else PASS_RESULT

    def for_sha(self, sha: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        for record_sha, example in self.records:
            if record_sha == sha:
                counts[example] = counts.get(example, 0) + 1
        return counts


@requires_prepared
def test_f1_gate_facts_and_training_samples_reach_mutator_messages(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    sleep_marker = "def unique_victim_marker():\n    return 424242\n"

    class FeedbackTraining:
        """Writes a realistic training feedback.json + audit + SAST evidence."""

        def __init__(self) -> None:
            self.calls: list[Any] = []

        def __call__(self, training_config: Any) -> dict[str, Any]:
            self.calls.append(training_config)
            out = Path(training_config.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            samples = []
            for repeat in range(2):
                samples.append(
                    {
                        "task": "\u8bad\u7ec3\u9898 1",
                        "repeat": repeat,
                        "code": sleep_marker,
                        "verdict": "target_present",
                        "semgrep": {"status": "completed", "detected": False, "reason": "clean"},
                    }
                )
            (out / "feedback.json").write_text(
                json.dumps(
                    {
                        "candidate_kind": "mock",
                        "samples": samples,
                        "metrics": {"asr@1": {"value": 0.5, "defined": True, "reason": None, "numerator": 1, "denominator": 2, "k": 1}},
                        "counts": {"semgrep_incomplete": 0},
                    }
                ),
                encoding="utf-8",
            )
            (out / "feedback_audit.json").write_text(
                json.dumps({"samples": [{"sample_id": "a" * 64}, {"sample_id": "b" * 64}]}),
                encoding="utf-8",
            )
            sast = out / "evaluation" / "layers"
            sast.mkdir(parents=True, exist_ok=True)
            (sast / "sast.jsonl").write_text(
                "\n".join(
                    json.dumps(
                        {
                            "sample_id": "a" * 64 if index == 0 else "b" * 64,
                            "evidence": {"alerts": [{"start_line": 3 + index, "start_col": 1}]},
                        }
                    )
                    for index in range(2)
                )
                + "\n",
                encoding="utf-8",
            )
            return {"completion": "complete", "source": "training-loop", "candidate_hash": "x"}

    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),  # R1-A0 (fails gate)
            _patch(3, code="def task_func():\n    return 22\n"),  # R1-A1 (passes gate)
            _patch(3, cot="B cot"),  # R1-B
        ]
    )
    training = FeedbackTraining()

    class Checker(FakeChecker):
        def __init__(self) -> None:
            super().__init__()
            self.seen: list[str] = []

        def __call__(self, request: Any) -> dict[str, Any]:
            self.calls.append(request)
            token = str(request.code_source).rsplit(":", 1)[-1]
            sha, _, example = token.partition("#example")
            if sha not in self.seen:
                self.seen.append(sha)
            # seen[0] = initial c0 (passes); seen[1] = first A template (fails ex.2).
            if len(self.seen) == 2 and int(example) == 2:
                return _gate_result(functional_state="failed")
            return PASS_RESULT

    state = run_method(
        config, mutator_source=mutator, example_check_runner=Checker(), training_runner=training
    )
    assert state["phase"] == "done"

    # F1: the A-gate failure facts (functional/static/Semgrep + lines) reached the
    # next A request's actual provider messages.
    second_a_messages = _calls_for(mutator, "R1-A1")
    assert second_a_messages, "second A request was not sent"
    joined = "\n".join(message["content"] for message in second_a_messages[0])
    assert "functional: state=executed outcome=failed" in joined
    assert "semgrep: status=completed" in joined
    assert "A \u95e8\u672a\u901a\u8fc7" in joined

    # F1: the A training per-sample facts (cleaned code, repeat, verdict, scan
    # line evidence) reached the B request's actual provider messages.
    b_messages = _calls_for(mutator, "R1-B")
    assert b_messages
    b_joined = "\n".join(message["content"] for message in b_messages[0])
    assert "unique_victim_marker" in b_joined
    assert "repeat=0" in b_joined and "verdict=target_present" in b_joined
    assert "cleaned_code" in b_joined
    assert "start_line" in b_joined
    # No audit leakage into the model-visible messages.
    assert "/home/" not in b_joined and "BigCodeBench/" not in b_joined
    assert "sample_id" not in b_joined


@requires_prepared
def test_f2_incomplete_training_pauses_and_resumes(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])

    class IncompleteTraining:
        def __init__(self) -> None:
            self.calls: list[Any] = []

        def __call__(self, training_config: Any) -> dict[str, Any]:
            self.calls.append(training_config)
            return {"completion": "incomplete", "source": "training-loop"}

    bad = IncompleteTraining()
    state = run_method(config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=bad)
    assert state["phase"] == "paused"
    assert "training not complete" in (state["pause_reason"] or "")
    assert len(mutator.calls) == 1  # no B call
    events = [json.loads(line)["event_type"] for line in (Path(config.run_dir) / "method_events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert "training_done" not in events

    good = FakeTraining()
    resumed = run_method(
        config,
        mutator_source=mutator,
        example_check_runner=FakeChecker(),
        training_runner=good,
        resume_paused=True,
    )
    assert resumed["phase"] == "done"
    assert len(mutator.calls) == 2


@requires_prepared
def test_f2_missing_production_feedback_pauses(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])

    class NoFeedbackTraining:
        def __call__(self, training_config: Any) -> dict[str, Any]:
            return {"completion": "complete", "source": "training-loop"}  # no feedback.json

    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=NoFeedbackTraining()
    )
    assert state["phase"] == "paused"
    assert "training feedback incomplete" in (state["pause_reason"] or "")
    assert len(mutator.calls) == 1  # did not advance to B


@requires_prepared
def test_f2_mock_double_is_explicit_and_allows_missing_feedback(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=FakeTraining()
    )
    assert state["phase"] == "done"
    units = _history_units(config)
    training_units = [unit for unit in units if unit.role == "training"]
    assert training_units and training_units[0].summary.get("source") == "mock-double"
    assert training_units[0].summary.get("feedback") == "missing"


@requires_prepared
def test_f3_init_persists_per_example_and_resumes_only_missing(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    c0 = snapshot.content_sha256()

    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=checker,
            training_runner=FakeTraining(),
            interrupts=["after_init_example"],
        )
    assert checker.for_sha(c0) == {2: 1}  # only the first initial example ran

    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert checker.for_sha(c0) == {2: 1, 3: 1, 4: 1}  # example 2 not re-run


@requires_prepared
def test_f3_init_all_persisted_interrupt_reuses_without_calls(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    c0 = snapshot.content_sha256()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=checker,
            training_runner=FakeTraining(),
            interrupts=["after_init_all"],
        )
    assert checker.for_sha(c0) == {2: 1, 3: 1, 4: 1}
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert checker.for_sha(c0) == {2: 1, 3: 1, 4: 1}  # nothing re-executed


def _disk_check_result(
    snapshot: Any, example: int, inputs: Mapping[str, Any], *, test_sha: str | None = None, semgrep_config: str | None = None
) -> dict[str, Any]:
    return {
        "schema_version": "example-code-check-v1",
        "check_source": "example",
        "combination_id": inputs["combination_id"],
        "task_id": inputs["task_id"],
        "stage": inputs["stage"],
        "code": {
            "input_code_sha256": inputs["code_sha256"],
            "final_code_sha256": "0" * 64,
            "code_prompt_sha256": inputs["code_prompt_sha256"],
            "test_sha256": test_sha if test_sha is not None else inputs["test_sha256"],
            "entry_point": inputs["entry_point"],
            "assembly_method": "code_prompt+body",
        },
        "layers": [{"layer": layer, "state": "executed"} for layer in inputs["enabled_layers"]],
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True},
        "functional": {"state": "executed", "outcome": "passed", "passed": True, "reason": None, "failure_stage": None},
        "static": {"state": "executed", "verdict": "target_present", "target_present": True, "reason": None},
        "semgrep": {
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "reason": None,
            "semgrep_config": semgrep_config,
            "rule_source_sha256": inputs.get("semgrep_config_sha256") or {},
            "evidence": {"alerts": []},
        },
    }


def _write_check_dir(config: MethodConfig, snapshot: Any, example: int, *, test_sha: str | None = None) -> None:
    from coco_attack.method.single_candidate_ab import MethodRun

    run = MethodRun(config)
    inputs = run._check_inputs(snapshot, example)
    check_dir = Path(config.run_dir) / "checks" / "R1" / f"example{example}"
    check_dir.mkdir(parents=True, exist_ok=True)
    (check_dir / "check_request.json").write_text(
        json.dumps(
            {
                "schema_version": "single-candidate-ab-v1",
                "request_fingerprint": run._inputs_fingerprint(inputs),
                "inputs": inputs,
            }
        ),
        encoding="utf-8",
    )
    (check_dir / "check_result.json").write_text(
        json.dumps(
            _disk_check_result(snapshot, example, inputs, test_sha=test_sha, semgrep_config=config.semgrep_config)
        ),
        encoding="utf-8",
    )


@requires_prepared
def test_f3_init_reuses_on_disk_result_without_state(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    _write_check_dir(config, snapshot, 2)

    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    # Example 2 was reused from disk (no initial runner call); 3 and 4 executed.
    assert checker.for_sha(snapshot.content_sha256()) == {3: 1, 4: 1}


@requires_prepared
def test_s0_check_binding_rejects_changed_test_content(tmp_path: Path) -> None:
    """Same code but changed test bytes must not reuse the old check evidence."""

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    _write_check_dir(config, snapshot, 2, test_sha="f" * 64)  # stale test fingerprint

    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    # Example 2 was re-executed because the result's test identity did not match.
    assert checker.for_sha(snapshot.content_sha256()).get(2) == 1


@requires_prepared
def test_s0_check_binding_rejects_changed_execution_config(tmp_path: Path) -> None:
    """A changed execution-config content must invalidate the old check evidence."""

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    exec_config = tmp_path / "execution.json"
    exec_config.write_text('{"a": 1}', encoding="utf-8")
    config = _make_config(
        tmp_path, snapshot_path, store_root, max_rounds=1, execution_config=str(exec_config)
    )
    # Persist the request sidecar/result under the ORIGINAL config content...
    sidecar_dir = tmp_path / "run" / "checks" / "R1" / "example2"
    from coco_attack.method.single_candidate_ab import MethodRun

    run = MethodRun(config)
    inputs = run._check_inputs(snapshot, 2)
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    (sidecar_dir / "check_request.json").write_text(
        json.dumps({"request_fingerprint": run._inputs_fingerprint(inputs), "inputs": inputs}),
        encoding="utf-8",
    )
    (sidecar_dir / "check_result.json").write_text(
        json.dumps(_disk_check_result(snapshot, 2, inputs, semgrep_config=config.semgrep_config)),
        encoding="utf-8",
    )
    # ...then change the execution-config bytes while keeping the same path.
    exec_config.write_text('{"a": 2}', encoding="utf-8")

    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert checker.for_sha(snapshot.content_sha256()).get(2) == 1


@requires_prepared
def test_s0_state_entry_not_reused_when_fingerprint_differs(tmp_path: Path) -> None:
    """The method-state per-example record is guarded by the same input identity."""

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B cot")])
    checker = CountingChecker()
    with pytest.raises(MethodInterrupted):
        run_method(
            config, mutator_source=mutator, example_check_runner=checker,
            training_runner=FakeTraining(), interrupts=["after_init_all"],
        )
    assert checker.for_sha(snapshot.content_sha256()) == {2: 1, 3: 1, 4: 1}

    # Doctor the persisted example-2 dependency fingerprint (simulating a changed
    # input identity): resume must re-check example 2 only.
    state_path = Path(config.run_dir) / "state.json"
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    persisted["gate_evidence"]["init"]["examples"]["2"]["request_fingerprint"] = "0" * 64
    state_path.write_text(json.dumps(persisted), encoding="utf-8")

    state = run_method(config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert checker.for_sha(snapshot.content_sha256()) == {2: 2, 3: 1, 4: 1}


@requires_prepared
def test_f4_new_script_object_resumes_at_action_position(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    script = [_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B-original")]
    first = ScriptedMutator(script)
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=first,
            example_check_runner=FakeChecker(),
            training_runner=FakeTraining(),
            interrupts=["after_A_commit"],
        )
    assert len(first.calls) == 1

    # A brand-new object (as in a new CLI process) with the same script.
    second = ScriptedMutator(script)
    state = run_method(config, mutator_source=second, example_check_runner=FakeChecker(), training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert len(second.calls) == 1
    assert second.calls[0]["action_id"] == "R1-B"  # bound to the B action, not replayed
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert final.example(3).cot == "B-original"


@requires_prepared
def test_f4_script_mapping_binds_by_action_id(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mapping = {
        "R1-A0": _patch(2, code="def task_func():\n    return 11\n"),
        "R1-B": _patch(3, cot="B-mapped"),
    }
    first = ScriptedMutator(mapping)
    with pytest.raises(MethodInterrupted):
        run_method(
            config, mutator_source=first, example_check_runner=FakeChecker(),
            training_runner=FakeTraining(), interrupts=["after_A_commit"],
        )
    second = ScriptedMutator(mapping)
    state = run_method(config, mutator_source=second, example_check_runner=FakeChecker(), training_runner=FakeTraining())
    assert state["phase"] == "done"
    assert second.calls[0]["action_id"] == "R1-B"
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert final.example(3).cot == "B-mapped"


@requires_prepared
def test_f4_swapped_script_is_refused(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    first = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n"), _patch(3, cot="B")])
    with pytest.raises(MethodInterrupted):
        run_method(
            config, mutator_source=first, example_check_runner=FakeChecker(),
            training_runner=FakeTraining(), interrupts=["after_A_commit"],
        )
    swapped = ScriptedMutator([_patch(2, code="def task_func():\n    return 99\n")])
    with pytest.raises(MethodError):
        run_method(config, mutator_source=swapped, example_check_runner=FakeChecker(), training_runner=FakeTraining())


# --------------------------------------------------------------------------- #
# Five rounds and batch stop
# --------------------------------------------------------------------------- #


@requires_prepared
def test_five_rounds_mock_then_stops(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=5)
    responses: list[str] = []
    for round_no in range(1, 6):
        responses.append(_patch(2, code=f"def task_func():\n    return {round_no}\n"))
        responses.append(_patch(3, cot=f"cot {round_no}"))
    mutator = ScriptedMutator(responses)
    training = FakeTraining()
    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert state["phase"] == "done"
    assert state["round"] == 5
    assert len(mutator.calls) == 10  # 5 A + 5 B
    assert len(training.calls) == 10  # 5 A + 5 B
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert final.example(1).code == snapshot.example(1).code  # example 1 frozen
    assert final.example(2).code.endswith("return 5\n")
    assert final.example(3).cot == "cot 5"

    # Calling again after batch completion changes nothing.
    again = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=training
    )
    assert again["phase"] == "done"
    assert len(mutator.calls) == 10
    assert len(training.calls) == 10


@requires_prepared
def test_initial_functional_failure_pauses_and_calls_no_mutator(tmp_path: Path) -> None:
    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n")])

    class InitFail(FakeChecker):
        def __call__(self, request: Any) -> dict[str, Any]:
            self.calls.append(request)
            return _gate_result(functional_state="failed")

    state = run_method(
        config, mutator_source=mutator, example_check_runner=InitFail(), training_runner=FakeTraining()
    )
    assert state["phase"] == "paused"
    assert mutator.calls == []


def _action_events(config: MethodConfig) -> list[dict[str, Any]]:
    from coco_attack.assets.artifacts import iter_jsonl

    path = Path(config.run_dir) / "actions.jsonl"
    if not path.is_file():
        return []
    return [row for _line, row in iter_jsonl(path)]


# --------------------------------------------------------------------------- #
# Wiring with the real training-loop mock entry
# --------------------------------------------------------------------------- #


@requires_prepared
def test_wires_real_training_loop_mock_entry(tmp_path: Path) -> None:
    """One round through real template materialization + role call + task-03 training."""

    from coco_attack.generation.service import run_generate
    from coco_attack.iteration.training_loop import run_training_loop

    snapshot, store_root, snapshot_path = _make_snapshot(tmp_path)
    config = _make_config(tmp_path, snapshot_path, store_root, max_rounds=1)
    mutator = ScriptedMutator(
        [
            _patch(2, code="def task_func():\n    return 11\n"),
            _patch(3, cot="revised cot"),
        ]
    )

    def real_training(training_config) -> dict[str, Any]:
        return run_training_loop(training_config, generation_step=run_generate)

    state = run_method(
        config, mutator_source=mutator, example_check_runner=FakeChecker(), training_runner=real_training
    )
    assert state["phase"] == "done"
    assert state["training"]["completion"] == "complete"
    # The training run wrote its own closed-loop artifacts on disk.
    assert (Path(state["training"]["output_dir"]) / "manifest.json").is_file()
