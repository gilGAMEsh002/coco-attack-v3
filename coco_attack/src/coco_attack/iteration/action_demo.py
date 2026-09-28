"""Offline mutator-action demo (task 04).

Runs two ordinary mock mutator interactions through the real persistence/audit
boundary, with an explicit simulated interrupt *after* the first raw response is
durable and *before* the template/history commit.  The resume path must not call
the provider again, and the template diff and history unit are committed exactly
once.

This is a wiring demonstration, not a research A/B run: it contains no gate, no
candidate pool and no iteration loop.  It never calls a real model, Docker or
Semgrep.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json
from .action_runtime import (
    STATE_RESPONSE_REUSED,
    ActionStore,
    ContextBudget,
    HeuristicTokenCounter,
    HistoryStore,
    RoleActionRequest,
    RoleCallConfig,
    ScriptedMockSource,
    assemble_history,
    commit_mutator_result,
    run_role_call,
)
from .method_inputs import (
    MethodInputs,
    assemble_method_inputs,
    render_current_template_request,
    render_system_block,
)
from .template_snapshot import PatchPolicy, read_snapshot

DEMO_VERSION = "mutator-action-demo-v1"
MUTATOR_ROLE = "mutator"

#: Clearly-labelled mock fixtures (example index + field), not a research policy.
MOCK_PATCH_1 = json.dumps([{"example": 2, "code": "def task_func():\n    return 42\n"}])
MOCK_PATCH_2 = json.dumps([{"example": 3, "cot": "step one\nstep two"}])


@dataclass(frozen=True)
class DemoConfig:
    snapshot_path: str
    run_dir: str
    assets_root: str
    snapshot_store: str
    example_task_ids: tuple[str, ...] = (
        "BigCodeBench/562",
        "BigCodeBench/348",
        "BigCodeBench/322",
        "BigCodeBench/810",
    )
    target: str = "\u6839\u636e\u5f53\u524d\u6a21\u677f\u7ed9\u51fa\u7a00\u758f\u4fee\u6539"
    system_prefix: str = (
        "You are a security-aware code mutator. Propose sparse edits to the "
        "current few-shot template that preserve functionality."
    )
    prior: str = (
        "\u95f4\u63a5\u5316\u5b57\u9762\u951a\u70b9\uff1b\u4fdd\u6301\u8bed\u4e49\u7b49\u4ef7\uff1b"
        "\u4e0d\u7834\u574f\u53ef\u8bfb\u6027\u3002"
    )
    output_format: str = (
        "Return a JSON list of objects {\"example\": <1-based int>, \"code\"?: str, \"cot\"?: str}."
    )
    allowed_examples: tuple[int, ...] = (2, 3, 4)
    allowed_fields: tuple[str, ...] = ("code", "cot")
    context_window_tokens: int = 32768
    output_reserve_tokens: int = 8192
    model: str = "openai/DeepSeek-V3.2"
    temperature: float = 0.7
    max_tokens: int = 8192

    def __post_init__(self) -> None:
        # The output reserve must cover the actual per-call output cap, otherwise
        # the context check would admit a request that cannot fit its response.
        if self.output_reserve_tokens < self.max_tokens:
            raise ValueError(
                "output_reserve_tokens must be at least max_tokens "
                f"({self.output_reserve_tokens} < {self.max_tokens})"
            )


def _mutator_config(config: DemoConfig, role: str = MUTATOR_ROLE) -> RoleCallConfig:
    return RoleCallConfig(
        role=role,
        model=config.model,
        source="mock",
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        max_request_attempts=2,
    )


def _assemble_messages(
    materials: MethodInputs,
    history: HistoryStore,
    config: DemoConfig,
) -> tuple[list[dict[str, str]], tuple[str, ...], int]:
    assembly = assemble_history(
        system_block=render_system_block(materials),
        current_user_content=render_current_template_request(materials, config.target),
        units=history.units(),
        budget=ContextBudget(
            context_window_tokens=config.context_window_tokens,
            output_reserve_tokens=config.output_reserve_tokens,
        ),
        counter=HeuristicTokenCounter(),
    )
    return list(assembly.messages), assembly.compressed_action_ids, assembly.total_tokens


class _ForbiddenSource:
    """Resume evidence: any provider call is a test failure."""

    kind = "mock"

    def generate(self, messages, *, rollout_id, attempt_index):  # type: ignore[no-untyped-def]
        raise AssertionError("resume must not call the provider")


def run_offline_demo(config: DemoConfig) -> dict[str, Any]:
    """Run both mock interactions with the interrupt/resume boundary."""

    snapshot = read_snapshot(config.snapshot_path)
    run_dir = Path(config.run_dir)
    snapshot_store = Path(config.snapshot_store)
    store = ActionStore(run_dir)
    history = HistoryStore(run_dir)
    policy = PatchPolicy(
        allowed_examples=config.allowed_examples, allowed_fields=config.allowed_fields
    )
    report: dict[str, Any] = {
        "demo_version": DEMO_VERSION,
        "source": "mock",
        "interactions": [],
    }

    # -- interaction 1: plan -> response durable -> INTERRUPT ------------------ #
    materials = assemble_method_inputs(
        assets_root=config.assets_root,
        snapshot=snapshot,
        example_task_ids=config.example_task_ids,
        system_prefix=config.system_prefix,
        prior=config.prior,
        output_format=config.output_format,
    )
    messages, compressed, tokens = _assemble_messages(materials, history, config)
    request = RoleActionRequest(
        action_id="mutator-1",
        role=MUTATOR_ROLE,
        kind="mutator",
        messages=tuple(messages),
        config=_mutator_config(config),
        input_refs={"template": snapshot.content_sha256()},
    )
    source1 = ScriptedMockSource([MOCK_PATCH_1])
    outcome1 = run_role_call(store, request, source=source1)
    report["interactions"].append(
        {
            "action_id": "mutator-1",
            "state": outcome1.state,
            "response_status": outcome1.response_status,
            "provider_calls_before_interrupt": len(source1.calls),
            "history_compressed_before": list(compressed),
            "messages_tokens": tokens,
        }
    )

    # -- resume: durable response is reused, no provider call ------------------ #
    resume_outcome = run_role_call(store, request, source=_ForbiddenSource())  # type: ignore[arg-type]
    assert resume_outcome.state == STATE_RESPONSE_REUSED
    mutation1 = commit_mutator_result(
        store, "mutator-1", snapshot, policy, snapshot_store=snapshot_store,
        history=history, summary={"example": 2, "field": "code"},
    )
    mutation1_again = commit_mutator_result(
        store, "mutator-1", snapshot, policy, snapshot_store=snapshot_store, history=history
    )
    snapshot2 = read_snapshot(snapshot_store / snapshot.combination_id / mutation1.content_sha256)
    report["interactions"][0].update(
        {
            "resume_state": resume_outcome.state,
            "resume_provider_calls": 0,
            "resume_status": mutation1.status,
            "template_before": mutation1.template_before,
            "template_after": mutation1.template_after,
            "diff": list(mutation1.diff),
            "commit_once": mutation1_again.content_sha256 == mutation1.content_sha256,
            "history_units_after_commit": len(history.units()),
        }
    )

    # -- interaction 2: re-assembled from the advanced template + history ------ #
    materials2 = assemble_method_inputs(
        assets_root=config.assets_root,
        snapshot=snapshot2,
        example_task_ids=config.example_task_ids,
        system_prefix=config.system_prefix,
        prior=config.prior,
        output_format=config.output_format,
    )
    messages2, compressed2, tokens2 = _assemble_messages(materials2, history, config)
    request2 = RoleActionRequest(
        action_id="mutator-2",
        role=MUTATOR_ROLE,
        kind="mutator",
        messages=tuple(messages2),
        config=_mutator_config(config),
        input_refs={"template": snapshot2.content_sha256()},
    )
    source2 = ScriptedMockSource([MOCK_PATCH_2])
    outcome2 = run_role_call(store, request2, source=source2)
    mutation2 = commit_mutator_result(
        store, "mutator-2", snapshot2, policy, snapshot_store=snapshot_store,
        history=history, summary={"example": 3, "field": "cot"},
    )
    report["interactions"].append(
        {
            "action_id": "mutator-2",
            "state": outcome2.state,
            "response_status": outcome2.response_status,
            "provider_calls": len(source2.calls),
            "history_compressed_before": list(compressed2),
            "messages_tokens": tokens2,
            "template_before": mutation2.template_before,
            "template_after": mutation2.template_after,
            "status": mutation2.status,
            "history_units_after_commit": len(history.units()),
        }
    )
    report["final_template"] = mutation2.content_sha256
    report["history_units"] = len(history.units())
    report["ledger_events"] = len(store.events())
    return report


def load_demo_config(path: Path | str) -> DemoConfig:
    payload = read_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError("demo config must be a JSON object")
    return DemoConfig(**payload)


__all__ = [
    "DEMO_VERSION",
    "DemoConfig",
    "load_demo_config",
    "run_offline_demo",
]
