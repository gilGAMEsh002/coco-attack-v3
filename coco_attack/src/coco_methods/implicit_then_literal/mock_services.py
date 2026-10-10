"""Explicit offline mock services for ``implicit_then_literal`` (04 dev/offline).

This module is production code (not a test helper) that lets the mock CLI path run
end-to-end without any model, Docker, Semgrep or credential access.  It is opt-in
via ``implicit-then-literal-run --doubles-module
coco_methods.implicit_then_literal.mock_services``.

It writes real public-format ``feedback.json``/``feedback_audit.json`` artifacts
so 02/03 evidence validation still runs; it does not return a fixed score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from coco_attack.assets.artifacts import read_json, sha256_text, write_json_atomic
from coco_attack.iteration.action_runtime import ScriptedMockSource
from coco_attack.iteration.template_snapshot import read_snapshot
from .wiring import WiringDoubles

_A_CODE = "    value = 1\n    return value\n"
_B_COT = "Step 1. mock cot.\n"


def _proposer_responder(messages: list[dict[str, str]], attempt_index: int) -> str:
    system = str(messages[0].get("content") if messages else "")
    if "modifications" in system:
        return json.dumps(
            {
                "modifications": [
                    {
                        "example": 2,
                        "renames": [
                            {"scope": "scope-2", "from": "value", "to": "renamed"}
                        ],
                        "new_cot": _B_COT,
                    }
                ]
            }
        )
    return json.dumps(
        {"structure": "mock structure", "patch": [{"example": 2, "code": _A_CODE}]}
    )


def _inducer_responder(messages: list[dict[str, str]], attempt_number: int) -> str:
    return json.dumps(
        {
            "entries": [
                {
                    "label": f"mock-e{attempt_number}",
                    "nature": "observation",
                    "description": "offline mock observation",
                    "change": "mock",
                    "evidence": [],
                    "uncertainty": "offline mock",
                }
            ],
            "summary": f"offline mock summary {attempt_number}",
        }
    )


def _mock_gate(request: Any) -> Mapping[str, Any]:
    return {
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True, "reason": None},
        "functional": {
            "state": "executed",
            "outcome": "passed",
            "passed": True,
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
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "reason": None,
            "evidence": {"alerts": []},
        },
    }


def _mock_training(config: Any) -> Mapping[str, Any]:
    snapshot = read_snapshot(config.snapshot_path)
    matrix = 2 * config.repeats
    feedback_samples: list[dict[str, Any]] = []
    audit_samples: list[dict[str, Any]] = []
    for task_index, task in enumerate(config.task_ids):
        for repeat in range(config.repeats):
            code = f"    # {task} {repeat}\n    return {repeat}\n"
            feedback_samples.append(
                {
                    "task": f"训练题 {task_index + 1}",
                    "repeat": repeat,
                    "code": code,
                    "verdict": "pass",
                    "semgrep": {"status": "completed", "detected": False, "reason": None},
                }
            )
            audit_samples.append(
                {
                    "sample_id": f"{task}__{repeat}",
                    "task_id": task,
                    "repeat_id": repeat,
                    "generation_status": "success",
                    "final_code_sha256": sha256_text(code),
                    "verdict": "pass",
                    "asr_hit": False,
                    "semgrep": {"status": "completed", "detected": False, "reason_code": None},
                }
            )
    candidate_hash = "mock-" + str(config.batch_id)
    output = Path(config.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_json_atomic(
        output / "feedback.json",
        {
            "candidate_kind": "mock",
            "samples": feedback_samples,
            "metrics": {
                "sample_hit_rate": {
                    "value": 0.0,
                    "defined": True,
                    "reason": None,
                    "numerator": 0,
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
            "counts": {"generation_failures": 0},
        },
    )
    write_json_atomic(
        output / "feedback_audit.json",
        {
            "candidate_kind": "mock",
            "candidate_hash": candidate_hash,
            "template_sha256": snapshot.content_sha256(),
            "sast_adapter": "offline-mock",
            "samples": audit_samples,
        },
    )
    return {"completion": "complete", "candidate_hash": candidate_hash, "source": "offline-mock"}


def build_doubles(config: Any) -> WiringDoubles:
    """Return explicit offline doubles for a mock run config."""

    return WiringDoubles(
        proposer_source=ScriptedMockSource(content_builder=_proposer_responder),
        inducer_source=ScriptedMockSource(content_builder=_inducer_responder),
        gate_runner=_mock_gate,
        training_runner=_mock_training,
        baseline_loader=None,  # the runtime default load_comparison_baseline is read-only
    )


__all__ = ["build_doubles"]
