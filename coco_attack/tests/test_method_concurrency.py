"""Task-07 concurrency tests (bounded example checks + victim sampling).

All runs are offline: the mutator, example-check runner and training runner are
injected, and the victim-generation concurrency is exercised through a
blocking/event-controlled source that proves *actual overlap* and the peak
bound rather than merely the presence of a config field.

Real models, Docker and Semgrep are never invoked here.
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any, Mapping

import pytest

from coco_attack.generation.contracts import GenerationConfig, SampleIdentity
from coco_attack.generation.inputs import GenerationInputs, GenerationSample
from coco_attack.generation.runner import GenerationRunner
from coco_attack.generation.source import ExtractedResponse
from coco_attack.iteration.template_snapshot import (
    read_snapshot,
    snapshot_from_clean,
    write_snapshot,
)
from coco_attack.iteration.training_loop import TrainingLoopConfig
from coco_methods.single_candidate_ab import (
    MethodConfig,
    MethodError,
    MethodInterrupted,
    MethodRun,
    ScriptedMutator,
    VictimRole,
    run_method,
)
from coco_attack.runtime.ledger import (
    EVENT_RESPONSE_RECEIVED,
    EVENT_SAMPLE_FINALIZED,
    Ledger,
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


# --------------------------------------------------------------------------- #
# Shared doubles
# --------------------------------------------------------------------------- #


def _gate_result(
    *,
    functional_state: str = "passed",
    verdict: str = "target_present",
) -> dict[str, Any]:
    return {
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True, "reason": None},
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
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "reason": None,
            "evidence": {"alerts": []},
        },
    }


PASS_RESULT = _gate_result()


class FakeTraining:
    """Mock training double (no per-sample feedback file, explicit mock marker)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, config: Any) -> dict[str, Any]:
        self.calls.append(config)
        return {
            "completion": "complete",
            "source": "mock-double",
            "candidate_hash": "mock-" + config.batch_id,
        }


class CountingChecker:
    """Thread-safe per-(template sha, example) execution counter; always passes."""

    def __init__(self, result: Mapping[str, Any] | None = None) -> None:
        self.calls: list[Any] = []
        self.records: list[tuple[str, int]] = []
        self._result = dict(result) if result is not None else None
        self._lock = threading.Lock()

    def __call__(self, request: Any) -> dict[str, Any]:
        token = str(request.code_source).rsplit(":", 1)[-1]
        sha, _, example = token.partition("#example")
        with self._lock:
            self.calls.append(request)
            self.records.append((sha, int(example)))
        return dict(self._result) if self._result is not None else dict(PASS_RESULT)

    def for_sha(self, sha: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        with self._lock:
            for record_sha, example in self.records:
                if record_sha == sha:
                    counts[example] = counts.get(example, 0) + 1
        return counts


class GatedChecker:
    """Blocks until ``expected`` workers overlap, recording the actual peak.

    ``entered`` is set once the expected number of calls are concurrently inside
    ``__call__``; the caller releases them with ``release``.  This measures real
    overlap instead of trusting a config field.
    """

    def __init__(self, expected: int, result: Mapping[str, Any] | None = None) -> None:
        self.expected = expected
        self.result = dict(result) if result is not None else dict(PASS_RESULT)
        self.calls: list[Any] = []
        self.active = 0
        self.peak = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, request: Any) -> dict[str, Any]:
        with self._lock:
            self.calls.append(request)
            self.active += 1
            self.peak = max(self.peak, self.active)
            if self.active >= self.expected:
                self.entered.set()
        if self.expected > 1:
            self.release.wait(timeout=5)
        with self._lock:
            self.active -= 1
        return dict(self.result)


class GatedGenerationSource:
    """Blocking generation source that records the real concurrent peak."""

    def __init__(self, expected: int) -> None:
        self.expected = expected
        self.active = 0
        self.peak = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    def generate(self, messages: list[dict[str, str]], rollout_id: int, attempt_index: int) -> ExtractedResponse:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            if self.active >= self.expected:
                self.entered.set()
        if self.expected > 1:
            self.release.wait(timeout=5)
        with self._lock:
            self.active -= 1
        prompt = messages[0]["content"] if messages else ""
        content = f"# {prompt[:24]}\nreturn 1\n"
        return ExtractedResponse(
            content=content,
            finish_reason="stop",
            usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            cache_hit=False,
            response_id=f"resp-{uuid.uuid4().hex}",
            model="mock",
        )


# --------------------------------------------------------------------------- #
# Victim generation concurrency (GenerationRunner / GenerationConfig)
# --------------------------------------------------------------------------- #


def _gen_config(**overrides: Any) -> GenerationConfig:
    base: dict[str, Any] = dict(
        source="mock",
        model="openai/gpt-4o",
        batch_id="batch-1",
        combination_id="cwe078-0",
        oracle_id="cwe078-0",
        stage="search",
        form="clean_fewshot_cot",
        prompt_version="1",
        candidate_hash="",
        temperature=0.7,
        repeats=1,
        max_tokens=128,
        request_timeout=30.0,
        max_concurrency=1,
        max_request_attempts=1,
        max_sample_retries=0,
        mock_scenario="normal",
    )
    base.update(overrides)
    return GenerationConfig(**base)


def _gen_inputs(count: int) -> GenerationInputs:
    samples = []
    for index in range(count):
        identity = SampleIdentity(
            stage="search",
            batch_id="batch-1",
            combination_id="cwe078-0",
            task_id=f"BigCodeBench/{index + 1}",
            repeat_id=0,
            prompt_version="1",
            candidate_hash="c" * 64,
        )
        samples.append(
            GenerationSample(
                identity=identity,
                prompt=f"# task {index + 1}\nwrite code\n",
                prompt_sha256="p" * 64,
            )
        )
    return GenerationInputs(
        combination_id="cwe078-0",
        oracle_id="cwe078-0",
        form="clean_fewshot_cot",
        stage="search",
        task_snapshot_sha256="t" * 64,
        prompt_manifest_sha256="m" * 64,
        candidate_hash="c" * 64,
        samples=tuple(samples),
    )


def _run_runner_in_thread(config: GenerationConfig, inputs: GenerationInputs, source: Any, run_dir: Path) -> dict[str, Any]:
    ledger = Ledger(run_dir / "ledger.jsonl")
    holder: dict[str, Any] = {}

    def _run() -> None:
        holder["summary"] = GenerationRunner(config, inputs, ledger, source, run_dir).run()

    thread = threading.Thread(target=_run)
    thread.start()
    try:
        assert source.entered.wait(5), "generation workers never overlapped"
    finally:
        source.release.set()
    thread.join(15)
    assert not thread.is_alive(), "generation run did not finish after release"
    if "error" in holder:
        raise holder["error"]
    return holder["summary"]


def test_generation_runner_peak_is_bounded_and_overlaps(tmp_path: Path) -> None:
    config = _gen_config(max_concurrency=4)
    inputs = _gen_inputs(10)
    source = GatedGenerationSource(expected=4)
    summary = _run_runner_in_thread(config, inputs, source, tmp_path)

    assert 1 < source.peak <= config.max_concurrency
    assert source.peak == 4
    assert summary["generated"] == 10

    replay = Ledger(tmp_path / "ledger.jsonl").replay()
    finalized = replay.finalized_records()
    assert len(finalized) == 10
    assert len(set(finalized)) == 10
    assert all(record["status"] == "success" for record in finalized.values())
    responses = [event for event in replay.events if event["event_type"] == EVENT_RESPONSE_RECEIVED]
    assert len(responses) == 10
    assert len({event["sample_id"] for event in responses}) == 10
    lines = [line for line in (tmp_path / "generations.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 10
    assert len({json.loads(line)["sample_id"] for line in lines}) == 10


def test_generation_runner_default_peak_is_one(tmp_path: Path) -> None:
    config = _gen_config(max_concurrency=1)
    inputs = _gen_inputs(3)
    source = GatedGenerationSource(expected=1)
    summary = _run_runner_in_thread(config, inputs, source, tmp_path)
    assert source.peak == 1
    assert summary["generated"] == 3


def test_generation_runner_resume_does_not_duplicate_samples_or_cost(tmp_path: Path) -> None:
    config = _gen_config(max_concurrency=4)
    inputs = _gen_inputs(10)
    _run_runner_in_thread(config, inputs, GatedGenerationSource(expected=4), tmp_path)

    resume_source = GatedGenerationSource(expected=1)
    resume_source.release.set()
    holder: dict[str, Any] = {}
    ledger = Ledger(tmp_path / "ledger.jsonl")

    def _run() -> None:
        holder["summary"] = GenerationRunner(config, inputs, ledger, resume_source, tmp_path).run()

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join(15)
    assert not thread.is_alive()
    assert holder["summary"]["generated"] == 0
    assert holder["summary"]["skipped_finalized"] == 10

    replay = ledger.replay()
    responses = [event for event in replay.events if event["event_type"] == EVENT_RESPONSE_RECEIVED]
    finalized = [event for event in replay.events if event["event_type"] == EVENT_SAMPLE_FINALIZED]
    assert len(responses) == 10  # no second model call / no double cost
    assert len(finalized) == 10
    lines = [line for line in (tmp_path / "generations.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 10


# --------------------------------------------------------------------------- #
# Method -> TrainingLoopConfig -> GenerationConfig parameter pass-through
# --------------------------------------------------------------------------- #


def _make_snapshot(tmp_path: Path):
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR, combination_id=COMBINATION, form=FORM, experiment=EXPERIMENT
    )
    store_root = tmp_path / "snapshots"
    write_snapshot(store_root, snapshot, action_id="init")
    return snapshot, store_root


def _method_config(tmp_path: Path, snapshot: Any, store_root: Path, **overrides: Any) -> MethodConfig:
    values: dict[str, Any] = dict(
        run_dir=str(tmp_path / "run"),
        snapshot_path=str(store_root / COMBINATION / snapshot.content_sha256()),
        snapshot_store=str(store_root),
        assets_root=str(ASSETS_DIR),
        data_dir=str(PREPARED_DIR),
        max_rounds=1,
    )
    values.update(overrides)
    return MethodConfig(**values)


def test_concurrency_fields_are_part_of_method_config_identity(tmp_path: Path) -> None:
    base = MethodConfig(
        run_dir=str(tmp_path / "run"),
        snapshot_path=str(tmp_path / "snap"),
        snapshot_store=str(tmp_path / "store"),
        assets_root=str(tmp_path / "assets"),
        data_dir=str(tmp_path / "data"),
    )
    changed_victim = MethodConfig.from_json(
        {**base.to_json(), "victim": {**base.victim.to_json(), "max_concurrency": 4}}
    )
    changed_workers = MethodConfig.from_json({**base.to_json(), "example_check_workers": 3})
    assert changed_victim.victim.max_concurrency == 4
    assert changed_workers.example_check_workers == 3
    assert changed_victim.config_sha256() != base.config_sha256()
    assert changed_workers.config_sha256() != base.config_sha256()
    assert MethodConfig.from_json(changed_victim.to_json()) == changed_victim

    with pytest.raises(MethodError):
        VictimRole(max_concurrency=0)
    with pytest.raises(MethodError):
        MethodConfig(
            run_dir=str(tmp_path / "run"),
            snapshot_path=str(tmp_path / "snap"),
            snapshot_store=str(tmp_path / "store"),
            assets_root=str(tmp_path / "assets"),
            data_dir=str(tmp_path / "data"),
            example_check_workers=0,
        )


def test_training_loop_config_round_trips_max_concurrency(tmp_path: Path) -> None:
    config = TrainingLoopConfig(
        snapshot_path=str(tmp_path / "snap"),
        assets_root=str(tmp_path / "assets"),
        data_dir=str(tmp_path / "data"),
        output_dir=str(tmp_path / "out"),
        task_ids=("BigCodeBench/13",),
        repeats=1,
        stage="search",
        form=FORM,
        prompt_version="1",
        model="openai/DeepSeek-V3.2",
        batch_id="b",
        max_concurrency=4,
    )
    assert config.to_json()["max_concurrency"] == 4
    assert TrainingLoopConfig.from_json(config.to_json()).max_concurrency == 4
    assert TrainingLoopConfig.from_json(config.to_json()).run_config_sha256() == config.run_config_sha256()


def test_run_method_refuses_workers_above_container_budget(tmp_path: Path) -> None:
    config = MethodConfig(
        run_dir=str(tmp_path / "run"),
        snapshot_path=str(tmp_path / "snap"),
        snapshot_store=str(tmp_path / "store"),
        assets_root=str(tmp_path / "assets"),
        data_dir=str(tmp_path / "data"),
        example_check_workers=3,
        execution_config=str(_execution_config_with(tmp_path, 1)),
    )
    with pytest.raises(MethodError, match="max_parallel_containers"):
        run_method(
            config,
            mutator_source=ScriptedMutator([]),
            example_check_runner=lambda request: dict(PASS_RESULT),
            training_runner=FakeTraining(),
        )
    # Refused before any run state was created.
    assert not (tmp_path / "run" / "state.json").exists()



@requires_prepared
def test_method_threads_victim_concurrency_into_generation(tmp_path: Path) -> None:
    from coco_attack.generation.service import run_generate
    from coco_attack.iteration.training_loop import run_training_loop

    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(
        tmp_path,
        snapshot,
        store_root,
        victim=VictimRole(source="mock", model="victim-model", max_concurrency=4),
    )
    run = MethodRun(config)
    training_config = run._training_config(snapshot, 1, "A")
    assert training_config.max_concurrency == 4

    manifest = run_training_loop(training_config, generation_step=run_generate)
    assert manifest["completion"] == "complete"

    output = Path(training_config.output_dir)
    generation_json = json.loads((output / "configs" / "generation.json").read_text(encoding="utf-8"))
    assert generation_json["max_concurrency"] == 4
    run_config = json.loads((output / "generation" / "run_config.json").read_text(encoding="utf-8"))
    assert run_config["config"]["max_concurrency"] == 4
    summary = json.loads((output / "generation" / "generation_summary.json").read_text(encoding="utf-8"))
    assert summary["finalized_total"] == 10

    # A resume must reuse the original generation config (no silent concurrency
    # change) and must not re-issue requests for the finalized samples.
    again = run_training_loop(training_config, generation_step=run_generate)
    assert again["completion"] == "complete"
    run_config = json.loads((output / "generation" / "run_config.json").read_text(encoding="utf-8"))
    assert run_config["config"]["max_concurrency"] == 4
    responses = [
        line
        for line in (output / "generation" / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["event_type"] == EVENT_RESPONSE_RECEIVED
    ]
    assert len(responses) == 10


# --------------------------------------------------------------------------- #
# Example-check concurrency (init + A gate)
# --------------------------------------------------------------------------- #


def _patch_many(entries: list[tuple[int, str, str]]) -> str:
    return json.dumps([{"example": example, field: value} for example, field, value in entries])


def _patch(example: int, **fields: str) -> str:
    return json.dumps([{"example": example, **fields}])


def _run_method_in_thread(config: MethodConfig, checker: Any, mutator: ScriptedMutator, training: Any) -> dict[str, Any]:
    holder: dict[str, Any] = {}

    def _run() -> None:
        try:
            holder["state"] = run_method(
                config, mutator_source=mutator, example_check_runner=checker, training_runner=training
            )
        except BaseException as error:  # noqa: BLE001 - re-raised in the test thread
            holder["error"] = error

    thread = threading.Thread(target=_run)
    thread.start()
    try:
        assert checker.entered.wait(5), "example-check workers never overlapped"
    finally:
        checker.release.set()
    thread.join(20)
    assert not thread.is_alive(), "method run did not finish after release"
    if "error" in holder:
        raise holder["error"]
    return holder["state"]


@requires_prepared
def test_example_check_workers_overlap_and_peak_is_bounded(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=3)
    mutator = ScriptedMutator(
        [
            _patch_many(
                [
                    (2, "code", "def task_func():\n    return 11\n"),
                    (3, "code", "def task_func():\n    return 22\n"),
                    (4, "code", "def task_func():\n    return 33\n"),
                ]
            ),
            _patch(2, cot="B cot"),
        ]
    )
    checker = GatedChecker(expected=3)
    state = _run_method_in_thread(config, checker, mutator, FakeTraining())

    assert 1 < checker.peak <= 3
    assert checker.peak == 3
    assert state["phase"] == "done"


@requires_prepared
def test_example_check_workers_one_and_three_agree(tmp_path: Path) -> None:
    def _exercise(workers: int) -> tuple[dict[str, Any], int]:
        run_dir = tmp_path / f"workers{workers}"
        snapshot, store_root = _make_snapshot(run_dir)
        config = _method_config(run_dir, snapshot, store_root, example_check_workers=workers)
        mutator = ScriptedMutator(
            [
                _patch_many(
                    [
                        (2, "code", "def task_func():\n    return 11\n"),
                        (3, "code", "def task_func():\n    return 22\n"),
                        (4, "code", "def task_func():\n    return 33\n"),
                    ]
                ),
                _patch(2, cot="B cot"),
            ]
        )
        if workers == 1:
            checker: Any = GatedChecker(expected=1)
            state = run_method(
                config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining()
            )
            peak = checker.peak
        else:
            checker = GatedChecker(expected=workers)
            state = _run_method_in_thread(config, checker, mutator, FakeTraining())
            peak = checker.peak
        functional = state["gate_evidence"]["init"]["functional"]
        return functional, peak

    serial_functional, serial_peak = _exercise(1)
    concurrent_functional, concurrent_peak = _exercise(3)
    assert serial_peak == 1
    assert 1 < concurrent_peak <= 3
    assert serial_functional == concurrent_functional


@requires_prepared
def test_example_check_failure_blocks_advancement(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=3)
    mutator = ScriptedMutator([_patch(2, code="def task_func():\n    return 11\n")])
    checker = GatedChecker(expected=3, result=_gate_result(functional_state="failed"))
    state = _run_method_in_thread(config, checker, mutator, FakeTraining())

    assert 1 < checker.peak <= 3
    assert state["phase"] == "paused"
    assert mutator.calls == []  # never reached A
    assert "initial functional check failed" in (state["pause_reason"] or "")


@requires_prepared
def test_completion_order_does_not_change_gate_feedback_order(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=3)

    class OrderedFailChecker:
        """c1 fails all examples; example 2 completes last (order 4,3,2)."""

        def __init__(self) -> None:
            self.seen: list[str] = []
            self.completion_order: list[int] = []
            self._lock = threading.Lock()
            self._done = 0
            self._two_done = threading.Event()

        def __call__(self, request: Any) -> dict[str, Any]:
            token = str(request.code_source).rsplit(":", 1)[-1]
            sha, _, example = token.partition("#example")
            example = int(example)
            with self._lock:
                if sha not in self.seen:
                    self.seen.append(sha)
                index = self.seen.index(sha)
            if index == 1:  # first A template
                if example == 2:
                    self._two_done.wait(timeout=5)
                result = _gate_result(verdict="target_absent")
                with self._lock:
                    self.completion_order.append(example)
                    if example != 2:
                        self._done += 1
                        if self._done >= 2:
                            self._two_done.set()
                return result
            return dict(PASS_RESULT)

    checker = OrderedFailChecker()
    mutator = ScriptedMutator(
        [
            _patch_many(
                [
                    (2, "code", "def task_func():\n    return 11\n"),
                    (3, "code", "def task_func():\n    return 22\n"),
                    (4, "code", "def task_func():\n    return 33\n"),
                ]
            ),
            _patch(2, code="def task_func():\n    return 44\n"),
            _patch(2, cot="B cot"),
        ]
    )
    state = run_method(
        config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining()
    )
    assert state["phase"] == "done"
    # example 2 really completed last, but the feedback lists examples in order.
    assert checker.completion_order and checker.completion_order[-1] == 2

    from coco_attack.iteration.action_runtime import HistoryStore

    units = HistoryStore(config.run_dir).units()
    gate_units = [
        unit
        for unit in units
        if unit.role == "gate" and unit.user_content and "A \u95e8\u672a\u901a\u8fc7" in unit.user_content
    ]
    assert gate_units, "the A-gate failure feedback was not recorded"
    text = gate_units[0].user_content
    positions = [text.index(f"\u793a\u4f8b {example}:") for example in (2, 3, 4)]
    assert positions == sorted(positions)


@requires_prepared
def test_gate_partial_persisted_interrupt_resumes_only_missing(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=1)
    mutator = ScriptedMutator(
        [
            _patch_many(
                [
                    (2, "code", "def task_func():\n    return 11\n"),
                    (3, "code", "def task_func():\n    return 22\n"),
                    (4, "code", "def task_func():\n    return 33\n"),
                ]
            ),
            _patch(2, cot="B cot"),
        ]
    )
    checker = CountingChecker()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=checker,
            training_runner=FakeTraining(),
            interrupts=["after_gate_example"],
        )
    a_template = json.loads((Path(config.run_dir) / "state.json").read_text(encoding="utf-8"))["current_template"]
    assert checker.for_sha(a_template)  # at least one A-gate example completed & persisted

    state = run_method(
        config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining()
    )
    assert state["phase"] == "done"
    # The already-persisted example is not re-executed; each runs exactly once.
    assert checker.for_sha(a_template) == {2: 1, 3: 1, 4: 1}


def _disk_check_result(inputs: Mapping[str, Any]) -> dict[str, Any]:
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
            "test_sha256": inputs["test_sha256"],
            "entry_point": inputs["entry_point"],
            "assembly_method": "code_prompt+body",
        },
        "layers": [{"layer": layer, "state": "executed"} for layer in inputs["enabled_layers"]],
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True},
        "functional": {"state": "executed", "outcome": "passed", "passed": True, "reason": None},
        "static": {"state": "executed", "verdict": "target_present", "target_present": True, "reason": None},
        "semgrep": {
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "reason": None,
            "rule_source_sha256": inputs.get("semgrep_config_sha256") or {},
        },
    }


@requires_prepared
def test_check_worker_reuses_disk_result_without_calling_runner(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root)
    run = MethodRun(config)
    inputs = run._check_inputs(snapshot, 2)
    fingerprint = run._inputs_fingerprint(inputs)
    check_dir = Path(config.run_dir) / "checks" / "R1" / "example2"
    check_dir.mkdir(parents=True, exist_ok=True)
    (check_dir / "check_request.json").write_text(
        json.dumps(
            {
                "schema_version": "single-candidate-ab-v1",
                "request_fingerprint": fingerprint,
                "inputs": inputs,
            }
        ),
        encoding="utf-8",
    )
    (check_dir / "check_result.json").write_text(
        json.dumps(_disk_check_result(inputs)), encoding="utf-8"
    )

    calls: list[Any] = []
    run.example_check_runner = lambda request: calls.append(request) or dict(PASS_RESULT)
    payload = run._execute_check_job(snapshot, 2, 1, fingerprint)
    assert payload["source"] == "reused_disk"
    assert calls == []


class DiskWritingChecker:
    """Passing checker that also writes a reusable ``check_result.json``.

    This mirrors the real ``run_example_code_check`` behavior the worker relies
    on: a completed check leaves a durable per-example result, so an in-flight
    worker finished after a coordinator crash can be reused on resume instead of
    being executed again.
    """

    def __init__(self) -> None:
        self.records: list[tuple[str, int]] = []
        self._lock = threading.Lock()

    def __call__(self, request: Any) -> dict[str, Any]:
        token = str(request.code_source).rsplit(":", 1)[-1]
        sha, _, example = token.partition("#example")
        with self._lock:
            self.records.append((sha, int(example)))
        check_dir = Path(request.output_dir)
        sidecar = json.loads((check_dir / "check_request.json").read_text(encoding="utf-8"))
        (check_dir / "check_result.json").write_text(
            json.dumps(_disk_check_result(sidecar["inputs"])), encoding="utf-8"
        )
        return dict(PASS_RESULT)

    def for_sha(self, sha: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        with self._lock:
            for record_sha, example in self.records:
                if record_sha == sha:
                    counts[example] = counts.get(example, 0) + 1
        return counts


@requires_prepared
def test_gate_partial_interrupt_concurrent_reuses_disk_results(tmp_path: Path) -> None:
    """workers>1: a coordinator crash after one commit must not re-run finished work."""

    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=3)
    mutator = ScriptedMutator(
        [
            _patch_many(
                [
                    (2, "code", "def task_func():\n    return 11\n"),
                    (3, "code", "def task_func():\n    return 22\n"),
                    (4, "code", "def task_func():\n    return 33\n"),
                ]
            ),
            _patch(2, cot="B cot"),
        ]
    )
    checker = DiskWritingChecker()
    with pytest.raises(MethodInterrupted):
        run_method(
            config,
            mutator_source=mutator,
            example_check_runner=checker,
            training_runner=FakeTraining(),
            interrupts=["after_gate_example"],
        )
    a_template = json.loads((Path(config.run_dir) / "state.json").read_text(encoding="utf-8"))["current_template"]

    state = run_method(
        config, mutator_source=mutator, example_check_runner=checker, training_runner=FakeTraining()
    )
    assert state["phase"] == "done"
    # Every pending example ran exactly once across the crash and the resume:
    # the in-flight workers' durable results were reused, not re-executed.
    assert checker.for_sha(a_template) == {2: 1, 3: 1, 4: 1}



@requires_prepared
def test_final_snapshot_is_readable_after_concurrent_round(tmp_path: Path) -> None:
    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(tmp_path, snapshot, store_root, example_check_workers=3)
    mutator = ScriptedMutator(
        [
            _patch_many(
                [
                    (2, "code", "def task_func():\n    return 11\n"),
                    (3, "code", "def task_func():\n    return 22\n"),
                    (4, "code", "def task_func():\n    return 33\n"),
                ]
            ),
            _patch(2, cot="B cot"),
        ]
    )
    checker = GatedChecker(expected=3)
    state = _run_method_in_thread(config, checker, mutator, FakeTraining())
    final = read_snapshot(store_root / COMBINATION / state["current_template"])
    assert final.example(2).code.endswith("return 11\n")
    assert final.example(2).cot == "B cot"


# --------------------------------------------------------------------------- #
# Preflight concurrency report / budget consistency
# --------------------------------------------------------------------------- #


def _execution_config_with(tmp_path: Path, max_parallel: int) -> Path:
    from coco_attack.assets.artifacts import read_json

    payload = read_json(REPO_DIR / "coco_attack" / "configs" / "execution.local.json")
    payload["limits"]["max_parallel_containers"] = max_parallel
    path = tmp_path / f"execution-{max_parallel}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@requires_prepared
def test_preflight_flags_workers_above_container_budget(tmp_path: Path) -> None:
    from coco_methods.preflight import build_preflight_report

    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(
        tmp_path,
        snapshot,
        store_root,
        example_check_workers=3,
        semgrep_config=str(ASSETS_DIR / "third_party" / "semgrep"),
        execution_config=str(_execution_config_with(tmp_path, 1)),
    )
    report = build_preflight_report(config, check_service="real", training_service="mock")
    assert any("max_parallel_containers" in error for error in report["errors"])
    assert report["concurrency"]["execution_max_parallel_containers"] == 1
    assert report["concurrency"]["container_workers_needed"] == 3


@requires_prepared
def test_preflight_reports_aligned_concurrency_budget(tmp_path: Path) -> None:
    from coco_methods.preflight import build_preflight_report

    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(
        tmp_path,
        snapshot,
        store_root,
        example_check_workers=3,
        victim=VictimRole(source="mock", model="victim-model", max_concurrency=4),
        semgrep_config=str(ASSETS_DIR / "third_party" / "semgrep"),
        execution_config=str(_execution_config_with(tmp_path, 3)),
    )
    report = build_preflight_report(config, check_service="real", training_service="mock")
    assert not any("max_parallel_containers" in error for error in report["errors"])
    concurrency = report["concurrency"]
    assert concurrency["example_check_workers"] == 3
    assert concurrency["victim_max_concurrency"] == 4
    assert concurrency["mutator_max_concurrency"] == 1
    assert concurrency["output_tmpfs_total_demand_bytes"] == 3 * 16_777_216
    assert concurrency["output_tmpfs_budget_bytes"] == 268_435_456
    assert concurrency["max_parallel_containers_is_a_scheduler"] is False
    assert report["roles"]["victim"]["max_concurrency"] == 4


@requires_prepared
def test_preflight_warns_on_worker_budget_with_mock_service(tmp_path: Path) -> None:
    from coco_methods.preflight import build_preflight_report

    snapshot, store_root = _make_snapshot(tmp_path)
    config = _method_config(
        tmp_path,
        snapshot,
        store_root,
        example_check_workers=3,
        execution_config=str(_execution_config_with(tmp_path, 1)),
    )
    report = build_preflight_report(config, check_service="mock", training_service="mock")
    assert any("max_parallel_containers" in warning for warning in report["warnings"])
    assert not any("max_parallel_containers" in error for error in report["errors"])


