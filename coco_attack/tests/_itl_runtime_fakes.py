"""Offline doubles shared by the implicit_then_literal runtime tests.

Everything here is deterministic and offline: the proposer/inducer are
caller-supplied callables, the gate runner and training runner are plain Python
objects, and the baseline loader returns a snapshot written to a temporary
content-addressed store.  No model, Docker, Semgrep or credential path is
reachable.

It is intentionally *not* named ``test_*`` so pytest does not collect it; the
two runtime test modules import the builder from here.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from coco_attack.assets.artifacts import sha256_text, write_json_atomic
from coco_attack.generation.source import ExtractedResponse
from coco_attack.iteration.action_runtime import RoleCallConfig
from coco_attack.iteration.method_inputs import MethodInputs
from coco_attack.iteration.template_snapshot import (
    ExampleTemplate,
    TemplateSnapshot,
    read_snapshot,
    write_snapshot,
)
from coco_attack.method.implicit_then_literal import roles as itl_roles
from coco_attack.method.implicit_then_literal import runtime as rt
from coco_attack.method.implicit_then_literal.contracts import (
    SNAPSHOT_ROLE_COMPARISON,
    read_snapshot_reference,
)

INSTRUCT = (
    "Do the task.\nYou should write self-contained code starting with:\n"
    "```\nimport os\ndef task_func():\n```"
)
TASKS = ("BigCodeBench/13", "BigCodeBench/1105")
REPEATS = 10

_GLOBAL_INDEX_RE = re.compile(r"候选序号[:：]\s*(\d+)")
_EXPERIENCE_VERSION_RE = re.compile(r"^- 版本：([0-9a-f]{64})$", re.MULTILINE)
_TEMPLATE_SHA_RE = re.compile(r"ITL-TEMPLATE ([0-9a-f]{64})")


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #


def initial_snapshot() -> TemplateSnapshot:
    """A neutral 4-example template with a parseable ``def task_func()`` prefix."""

    bodies = [
        "    pass\n",
        "    alpha = 1\n    return alpha\n",
        "    beta = 2\n    return beta\n",
        "    gamma = 3\n    return gamma\n",
    ]
    examples = tuple(
        ExampleTemplate(
            task_id=f"BigCodeBench/{number}",
            instruct_prompt=INSTRUCT,
            code=body,
            cot=f"Step {number}.",
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


def baseline_snapshot() -> TemplateSnapshot:
    """A distinct-role comparison snapshot.

    The content may coincidentally equal the initial template; the role
    reference is what keeps them apart (the plan requires distinct roles even
    for identical content).
    """

    return initial_snapshot()


def materials_builder(
    *,
    assets_root: Any,
    snapshot: TemplateSnapshot,
    example_task_ids: Any,
    system_prefix: str,
    prior: str,
    output_format: str,
) -> MethodInputs:
    """A tiny fake material block that embeds the *parent* content hash.

    The resumption tests parse ``ITL-TEMPLATE <sha>`` from the prompt to prove
    which snapshot the proposer actually saw.
    """

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
        current_template_text=f"ITL-TEMPLATE {snapshot.content_sha256()}",
        current_template_sha256=snapshot.content_sha256(),
        system_prefix=system_prefix,
        prior=prior,
        output_format=output_format,
    )


# --------------------------------------------------------------------------- #
# Role sources
# --------------------------------------------------------------------------- #


class OfflineSource:
    """Deterministic role source driven by a ``responder(messages, call_no)``.

    ``call_no`` is the 1-based global call count (not the retry attempt index),
    which lets a fixture return a malformed response exactly once and valid
    responses afterwards while still exercising the durable-response path.
    """

    kind = "mock"

    def __init__(self, responder: Callable[[list[dict[str, str]], int], str]) -> None:
        self.responder = responder
        self.calls: list[list[dict[str, str]]] = []
        self._lock = threading.Lock()

    def call_count(self) -> int:
        with self._lock:
            return len(self.calls)

    def generate(
        self, messages: list[dict[str, str]], *, rollout_id: int, attempt_index: int
    ) -> ExtractedResponse:
        snapshot = [dict(message) for message in messages]
        with self._lock:
            self.calls.append(snapshot)
            number = len(self.calls)
        content = self.responder(snapshot, number)
        return ExtractedResponse(
            content=content,
            finish_reason="stop",
            usage={"prompt_tokens": 11, "completion_tokens": 7},
            cache_hit=False,
            response_id=f"mock-{number}",
            model="mock",
        )


def _is_b_stage(system: str) -> bool:
    return "modifications" in system


def default_a_responder(messages: list[dict[str, str]], number: int) -> str:
    """Every A candidate proposes the same real code change (materialized)."""

    return json.dumps(
        {
            "structure": f"structure-{number}",
            "patch": [{"example": 2, "code": "    value = 1\n    return value\n"}],
        }
    )


def global_b_index(system: str) -> int:
    match = _GLOBAL_INDEX_RE.search(system)
    return int(match.group(1)) if match else 1


def default_b_responder(messages: list[dict[str, str]], number: int) -> str:
    """Five legal B variants per seed, including a CoT-only and a no_change."""

    index = global_b_index(messages[0]["content"])
    variant = ((index - 1) % 5) + 1
    if variant == 1:
        body: dict[str, Any] = {
            "modifications": [
                {
                    "example": 2,
                    "renames": [
                        {"scope": "scope-2", "from": "value", "to": "renamed"}
                    ],
                }
            ]
        }
    elif variant == 2:
        body = {"modifications": [{"example": 3, "new_cot": "new cot b"}]}
    elif variant == 3:
        body = {
            "modifications": [
                {
                    "example": 2,
                    "renames": [
                        {"scope": "scope-2", "from": "value", "to": "value"}
                    ],
                }
            ]
        }
    elif variant == 4:
        body = {
            "modifications": [
                {
                    "example": 2,
                    "renames": [
                        {"scope": "scope-2", "from": "value", "to": "renamed_x"}
                    ],
                }
            ]
        }
    else:
        body = {"modifications": [{"example": 4, "new_cot": "new cot d"}]}
    return json.dumps(body)


def invalid_b_responder(messages: list[dict[str, str]], number: int) -> str:
    """A permanently illegal B request (out-of-range example)."""

    return json.dumps({"modifications": [{"example": 9, "new_cot": "x"}]})


def make_proposer(
    a_responder: Callable[..., str] | None = None,
    b_responder: Callable[..., str] | None = None,
    *,
    timeline: list[tuple[str, Any]] | None = None,
) -> OfflineSource:
    a_responder = a_responder or default_a_responder
    b_responder = b_responder or default_b_responder

    def responder(messages: list[dict[str, str]], number: int) -> str:
        system = messages[0]["content"]
        if _is_b_stage(system):
            result = b_responder(messages, number)
            if timeline is not None:
                timeline.append(("b_propose", global_b_index(system)))
        else:
            result = a_responder(messages, number)
            if timeline is not None:
                timeline.append(("a_propose", number))
        return result

    return OfflineSource(responder)


def default_inducer_responder(messages: list[dict[str, str]], number: int) -> str:
    return json.dumps(
        {
            "entries": [
                {
                    "label": f"e{number}",
                    "nature": "observation",
                    "description": "d",
                    "change": "c",
                    "evidence": [],
                    "uncertainty": "u",
                }
            ],
            "summary": f"summary-{number}",
        }
    )


def make_inducer(
    responder: Callable[..., str] | None = None,
    *,
    timeline: list[tuple[str, Any]] | None = None,
) -> OfflineSource:
    responder = responder or default_inducer_responder

    def wrapped(messages: list[dict[str, str]], number: int) -> str:
        if timeline is not None:
            timeline.append(("induct", number))
        return responder(messages, number)

    return OfflineSource(wrapped)


# --------------------------------------------------------------------------- #
# Gate runner
# --------------------------------------------------------------------------- #


def gate_result(*, passed: bool = True, not_ready: bool = False) -> dict[str, Any]:
    return {
        "syntax": {
            "state": "executed",
            "syntax_ok": True,
            "entry_present": True,
            "reason": None,
        },
        "functional": {
            "state": "executed",
            "outcome": "passed" if passed else "failed",
            "passed": passed,
            "reason": None,
            "failure_stage": None,
        },
        "static": {
            "state": "executed",
            "verdict": "target_present",
            "target_present": True,
            "reason": None,
        },
        "semgrep": {
            "state": "executed" if not not_ready else "unavailable",
            "status": "completed" if not not_ready else "unavailable",
            "available": not not_ready,
            "completed": not not_ready,
            "detected": None if not_ready else False,
            "reason": None if not_ready else None,
            "evidence": {"alerts": []},
        },
    }


class MockGateRunner:
    """Thread-safe gate double with a per-example call ledger and a real peak.

    ``fail_for`` may mark selected candidates as a definite functional failure.
    """

    def __init__(
        self,
        *,
        fail_for: Callable[[Any], bool] | None = None,
        not_ready_for: Callable[[Any], bool] | None = None,
        block_until: int = 0,
        release: threading.Event | None = None,
        timeline: list[tuple[str, Any]] | None = None,
    ) -> None:
        self.calls: list[Any] = []
        self.records: list[tuple[str, int]] = []
        self.candidate_records: list[tuple[str, int]] = []
        self.active = 0
        self.peak = 0
        self.fail_for = fail_for
        self.not_ready_for = not_ready_for
        self.block_until = block_until
        self.release = release or threading.Event()
        self.entered = threading.Event()
        self.timeline = timeline
        self._lock = threading.Lock()

    def __call__(self, request: Any) -> dict[str, Any]:
        token = str(request.code_source).rsplit(":", 1)[-1]
        sha, _, example = token.partition("#example")
        example_number = int(example) if example else 0
        cid = ""
        parts = str(request.output_dir).split("candidates/")
        if len(parts) == 2:
            cid = parts[1].split("/")[0]
        with self._lock:
            self.calls.append(request)
            self.records.append((sha, example_number))
            self.candidate_records.append((cid, example_number))
            self.active += 1
            self.peak = max(self.peak, self.active)
            if self.block_until and self.active >= self.block_until:
                self.entered.set()
                self.release.set()
        if self.timeline is not None:
            self.timeline.append(("gate", (sha, example_number)))
        if self.block_until:
            self.release.wait(timeout=5)
        with self._lock:
            self.active -= 1
        failed = bool(self.fail_for and self.fail_for(request))
        if self.not_ready_for and self.not_ready_for(request):
            return gate_result(passed=True, not_ready=True)
        return gate_result(passed=not failed)

    def for_sha(self, sha: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        with self._lock:
            for record_sha, example in self.records:
                if record_sha == sha:
                    counts[example] = counts.get(example, 0) + 1
        return counts

    def for_candidate(self, cid: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        with self._lock:
            for record_cid, example in self.candidate_records:
                if record_cid == cid:
                    counts[example] = counts.get(example, 0) + 1
        return counts


# --------------------------------------------------------------------------- #
# Training runner
# --------------------------------------------------------------------------- #


def default_hits(config: Any) -> int:
    match = re.search(r"-c(\d+)$", str(config.batch_id))
    index = int(match.group(1)) if match else 0
    return (index * 3) % 21


def _batch_index(config: Any) -> int:
    match = re.search(r"-c(\d+)$", str(config.batch_id))
    return int(match.group(1)) if match else 0


class MockTrainingRunner:
    """Writes public-format ``feedback.json`` / ``feedback_audit.json``.

    The metrics are always consistent with the per-sample ``asr_hit`` facts and
    the fixed 2-task x ``repeats`` matrix.  Optional tampering modes let a test
    exercise the evidence-completeness branches.
    """

    def __init__(
        self,
        *,
        hits_for: Callable[[Any], int] | None = None,
        terminal_for: Callable[[Any], bool] | None = None,
        omit_last_sample_for: Callable[[Any], bool] | None = None,
        missing_static_for: Callable[[Any], bool] | None = None,
        wrong_template_for: Callable[[Any], bool] | None = None,
        pending_first_for: Callable[[Any], bool] | None = None,
        summary_completion: str = "complete",
        timeline: list[tuple[str, Any]] | None = None,
    ) -> None:
        self.calls: list[Any] = []
        self.active = 0
        self.peak = 0
        self.hits_for = hits_for or default_hits
        self.terminal_for = terminal_for or (lambda config: False)
        self.omit_last_sample_for = omit_last_sample_for or (lambda config: False)
        self.missing_static_for = missing_static_for or (lambda config: False)
        self.wrong_template_for = wrong_template_for or (lambda config: False)
        self.pending_first_for = pending_first_for or (lambda config: False)
        self._batch_seen: dict[str, int] = {}
        self.summary_completion = summary_completion
        self.timeline = timeline
        self._lock = threading.Lock()

    def __call__(self, config: Any) -> dict[str, Any]:
        with self._lock:
            self.calls.append(config)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.timeline is not None:
                self.timeline.append(("train", str(config.batch_id)))
            return self._write(config)
        finally:
            with self._lock:
                self.active -= 1

    def _write(self, config: Any) -> dict[str, Any]:
        snapshot = read_snapshot(config.snapshot_path)
        terminal = bool(self.terminal_for(config))
        pending = False
        if self.pending_first_for(config):
            seen = self._batch_seen.get(str(config.batch_id), 0)
            self._batch_seen[str(config.batch_id)] = seen + 1
            pending = seen == 0
        hits = 0 if (terminal or pending) else max(0, min(2 * config.repeats, int(self.hits_for(config))))
        missing_static = bool(self.missing_static_for(config))
        feedback_samples: list[dict[str, Any]] = []
        audit_samples: list[dict[str, Any]] = []
        total = 0
        for task_index, task in enumerate(config.task_ids):
            for repeat in range(config.repeats):
                code = f"    # {task} {repeat}\n    return {repeat}\n"
                if pending:
                    status = "pending"
                else:
                    status = "error" if terminal else "success"
                verdict: str | None = None if (pending or terminal or (missing_static and total == 0)) else "pass"
                asr = None if (pending or terminal) else (total < hits)
                feedback_samples.append(
                    {
                        "task": f"训练题 {task_index + 1}",
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
                        "generation_status": status,
                        "final_code_sha256": sha256_text(code),
                        "verdict": verdict,
                        "asr_hit": asr,
                        "semgrep": {"status": "completed", "detected": False, "reason_code": None},
                    }
                )
                total += 1
        if self.omit_last_sample_for(config):
            feedback_samples.pop()
            audit_samples.pop()
        matrix = 2 * config.repeats
        feedback = {
            "candidate_kind": "mock",
            "samples": feedback_samples,
            "metrics": {
                "sample_hit_rate": {
                    "value": (hits / matrix) if hits else 0.0,
                    "defined": True,
                    "reason": None,
                    "numerator": hits,
                    "denominator": matrix,
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
            "counts": {
                "generation_failures": matrix if terminal else 0,
            },
        }
        candidate_hash = "mockcand-" + str(config.batch_id)
        template_sha = (
            "0" * 64 if self.wrong_template_for(config) else snapshot.content_sha256()
        )
        audit = {
            "candidate_kind": "mock",
            "candidate_hash": candidate_hash,
            "template_sha256": template_sha,
            "sast_adapter": "test",
            "samples": audit_samples,
        }
        output = Path(config.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        write_json_atomic(output / "feedback.json", feedback)
        write_json_atomic(output / "feedback_audit.json", audit)
        return {
            "completion": self.summary_completion,
            "candidate_hash": candidate_hash,
            "source": "mock-double",
        }


# --------------------------------------------------------------------------- #
# Baseline loader + harness
# --------------------------------------------------------------------------- #


class FakeBaselineLoader:
    def __init__(self, reference: Any, snapshot: TemplateSnapshot) -> None:
        self.reference = reference
        self.snapshot = snapshot
        self.calls = 0

    def __call__(self, **kwargs: Any) -> "FakeBaselineLoader":
        self.calls += 1
        return self


@dataclass
class Harness:
    tmp_path: Path
    config: rt.MethodRuntimeConfig
    services: rt.RuntimeServices
    runtime: rt.MethodRuntime
    initial: TemplateSnapshot
    baseline: TemplateSnapshot
    initial_sha: str
    baseline_sha: str
    proposer: OfflineSource
    inducer: OfflineSource
    gate: Any
    trainer: Any
    baseline_loader: FakeBaselineLoader
    timeline: list[tuple[str, Any]] = field(default_factory=list)

    def run(self) -> dict[str, Any]:
        return self.runtime.run()

    def resume(self) -> dict[str, Any]:
        return self.runtime.resume()

    def new_runtime(
        self,
        *,
        on_event: Callable[[str], None] | None = None,
        services: rt.RuntimeServices | None = None,
    ) -> rt.MethodRuntime:
        active = services or replace(self.services, on_event=on_event)
        return rt.MethodRuntime(self.config, services=active)


def build_harness(
    tmp_path: Path,
    *,
    run_id: str = "run-itl",
    rounds: int = 5,
    a_slots: int = 5,
    b_slots_per_seed: int = 5,
    top_k: int = 5,
    check_workers: int = 3,
    victim_max_concurrency: int = 4,
    proposer: OfflineSource | None = None,
    inducer: OfflineSource | None = None,
    gate: Any | None = None,
    trainer: Any | None = None,
    on_event: Callable[[str], None] | None = None,
    config_overrides: Mapping[str, Any] | None = None,
) -> Harness:
    timeline: list[tuple[str, Any]] = []
    initial = initial_snapshot()
    baseline = baseline_snapshot()
    initial_dir = write_snapshot(tmp_path / "initial", initial)
    baseline_dir = write_snapshot(tmp_path / "baseline_store", baseline)
    baseline_path = baseline_dir / "snapshot.json"
    reference = read_snapshot_reference(
        baseline_path, role=SNAPSHOT_ROLE_COMPARISON, root=tmp_path
    )
    baseline_loader = FakeBaselineLoader(reference, baseline)

    proposer = proposer or make_proposer(timeline=timeline)
    inducer = inducer or make_inducer(timeline=timeline)
    gate = gate if gate is not None else MockGateRunner(timeline=timeline)
    trainer = trainer if trainer is not None else MockTrainingRunner(timeline=timeline)

    values: dict[str, Any] = dict(
        run_id=run_id,
        run_root=str(tmp_path / "run"),
        repository_root=str(tmp_path),
        assets_root=str(tmp_path / "assets"),
        prepared_data_dir=str(tmp_path / "data"),
        initial_template_path=str(initial_dir / "snapshot.json"),
        comparison_baseline_path=str(baseline_path),
        proposer_config=itl_roles.proposer_config(rt.A_PROTOCOL_VERSION),
        inducer_config=itl_roles.inducer_config(itl_roles.JUDGE_PROTOCOL_VERSION),
        rounds=rounds,
        a_slots=a_slots,
        b_slots_per_seed=b_slots_per_seed,
        top_k=top_k,
        check_workers=check_workers,
        victim_max_concurrency=victim_max_concurrency,
        # Reduced-scale tests must opt out of the fixed formal constants
        # explicitly; the full five-round harness keeps them enforced.
        enforce_formal_constants=(
            rounds == rt.MAX_ROUNDS
            and a_slots == rt.MAX_SLOTS
            and b_slots_per_seed == rt.MAX_SLOTS
            and top_k == rt.MAX_SLOTS
        ),
    )
    if config_overrides:
        values.update(config_overrides)
    config = rt.MethodRuntimeConfig(**values)
    services = rt.RuntimeServices(
        proposer_source=proposer,
        inducer_source=inducer,
        gate_runner=gate,
        training_runner=trainer,
        materials_builder=materials_builder,
        baseline_loader=baseline_loader,
        on_event=on_event,
    )
    runtime = rt.MethodRuntime(config, services=services)
    return Harness(
        tmp_path=tmp_path,
        config=config,
        services=services,
        runtime=runtime,
        initial=initial,
        baseline=baseline,
        initial_sha=initial.content_sha256(),
        baseline_sha=baseline.content_sha256(),
        proposer=proposer,
        inducer=inducer,
        gate=gate,
        trainer=trainer,
        baseline_loader=baseline_loader,
        timeline=timeline,
    )


def experience_versions_in(system: str) -> set[str]:
    return set(_EXPERIENCE_VERSION_RE.findall(system))


def template_sha_in(messages: Sequence[Mapping[str, str]]) -> str:
    for message in messages:
        match = _TEMPLATE_SHA_RE.search(str(message.get("content") or ""))
        if match:
            return match.group(1)
    return ""


__all__ = [
    "INSTRUCT",
    "TASKS",
    "REPEATS",
    "initial_snapshot",
    "baseline_snapshot",
    "materials_builder",
    "OfflineSource",
    "default_a_responder",
    "default_b_responder",
    "invalid_b_responder",
    "default_inducer_responder",
    "make_proposer",
    "make_inducer",
    "global_b_index",
    "gate_result",
    "MockGateRunner",
    "MockTrainingRunner",
    "default_hits",
    "FakeBaselineLoader",
    "Harness",
    "build_harness",
    "experience_versions_in",
    "template_sha_in",
]
