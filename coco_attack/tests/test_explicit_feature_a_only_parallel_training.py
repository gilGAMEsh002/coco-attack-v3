"""Offline tests for A-candidate training parallelism in ``explicit_feature_a_only``.

The runtime may train a round's gate-passed A candidates concurrently (up to
``config.candidate_training_workers``) while keeping the example-check gates
bounded and sequential.  These tests use only the production offline doubles
(no Docker, Semgrep, network or credential access).  Overlap is proven with a
``threading.Barrier`` (threads, not elapsed time); partial failures are proven
to keep the other candidates' completed training on disk and to be reused on a
resume; the cot-focus plan keeps working under the parallel path.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path

from coco_attack.assets.artifacts import read_json
from coco_attack.iteration.action_runtime import ScriptedMockSource
from coco_attack.iteration.template_snapshot import read_snapshot, write_snapshot
from coco_methods import explicit_feature_a_only as efa
from coco_methods.explicit_feature_a_only import mock_services
from coco_methods.explicit_feature_a_only.wiring import (
    assemble_services,
    load_method_run_config,
)

REPO = Path(__file__).resolve().parents[2]
MOCK_CONFIG = REPO / "coco_attack/configs/explicit_feature_a_only/mock.example.json"


# --------------------------------------------------------------------------- #
# offline wiring helpers
# --------------------------------------------------------------------------- #


def _temp_config(tmp_path: Path, **overrides) -> Path:
    payload = json.loads(MOCK_CONFIG.read_text(encoding="utf-8"))
    payload["run_id"] = "efa-parallel-test"
    payload["run_root"] = str(tmp_path / "efa-run")
    payload.update(overrides)
    path = tmp_path / "run_config.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _method_with_workers(method: efa.MethodRuntimeConfig, workers: int) -> efa.MethodRuntimeConfig:
    return replace(method, candidate_training_workers=workers)


def _runtime(
    config_path: Path,
    *,
    workers: int,
    training_runner,
    proposer_source=None,
):
    resolved = load_method_run_config(config_path, project_root=REPO)
    method = _method_with_workers(resolved.method, workers)
    doubles = mock_services.build_doubles(resolved)
    doubles.training_runner = training_runner
    if proposer_source is not None:
        doubles.proposer_source = proposer_source
    return efa.MethodRuntime(method, services=assemble_services(resolved, doubles=doubles))


def _records(run_root: Path):
    return sorted(
        (read_json(path) for path in (run_root / "rounds/1/A/candidates").glob("*/record.json")),
        key=lambda record: record["candidate_index"],
    )


# --------------------------------------------------------------------------- #
# concurrency
# --------------------------------------------------------------------------- #


def test_gate_passed_candidates_train_concurrently(tmp_path: Path) -> None:
    parties = 3
    barrier = threading.Barrier(parties, timeout=15)
    peak = {"now": 0, "value": 0}
    lock = threading.Lock()

    def training(config):
        if config.batch_id == "efa-baseline":
            return mock_services._mock_training(config)
        with lock:
            peak["now"] += 1
            peak["value"] = max(peak["value"], peak["now"])
        try:
            # All three candidates must be open at the same time: a serial run
            # can never release this barrier and fails instead of passing.
            barrier.wait()
        finally:
            with lock:
                peak["now"] -= 1
        return mock_services._mock_training(config)

    runtime = _runtime(_temp_config(tmp_path, rounds=1), workers=parties, training_runner=training)
    events: list[str] = []
    runtime.services.on_event = events.append

    result = runtime.run()

    assert result["phase"] == "done"
    assert peak["value"] == parties
    artifacts = [event for event in events if event.startswith("training_artifacts_complete:")]
    assert len(artifacts) == parties
    assert all(record["training"]["completion"] == "complete" for record in _records(runtime.run_root))


# --------------------------------------------------------------------------- #
# partial failure + resume
# --------------------------------------------------------------------------- #


def test_partial_training_failure_is_retained_and_resume_reuses_complete(tmp_path: Path) -> None:
    config_path = _temp_config(tmp_path, rounds=1, a_slots=3, top_k=3)
    calls: list[str] = []

    def training(config):
        calls.append(config.batch_id)
        if config.batch_id == "efa-baseline":
            return mock_services._mock_training(config)
        if config.batch_id.endswith("-c2"):
            return {"completion": "incomplete"}
        return mock_services._mock_training(config)

    runtime = _runtime(config_path, workers=3, training_runner=training)
    result = runtime.run()

    assert result["phase"] == "paused"
    records = _records(runtime.run_root)
    assert [record["training"]["completion"] for record in records] == [
        "complete",
        "incomplete",
        "complete",
    ]
    # The other two gate-passed candidates kept their completed training, and the
    # round did not commit while a gate-passed candidate is untrained.
    assert all(record["gate"]["status"] == "passed" for record in records)
    assert not (runtime.run_root / "rounds/1/A/commit.json").exists()

    resume_calls: list[str] = []

    def resume_training(config):
        resume_calls.append(config.batch_id)
        return mock_services._mock_training(config)

    resumed = _runtime(config_path, workers=3, training_runner=resume_training).resume()

    assert resumed["phase"] == "done"
    # Only the incomplete candidate is retrained; the baseline is skipped and the
    # two completed candidates are reused from disk.
    assert resume_calls == ["efa-r1A-c2"]
    assert all(record["training"]["completion"] == "complete" for record in _records(Path(runtime.run_root)))


# --------------------------------------------------------------------------- #
# focus bases under the parallel path
# --------------------------------------------------------------------------- #

_FOCUS_BASES = (
    ("载体", "bonly-idx7-dict-unpack", "Step 1. base carrier.\n"),
    ("分布", "bonly-idx11-alias", "Step 1. base distribution.\n"),
)


def _focus_base_specs(tmp_path: Path, initial):
    store = tmp_path / "focus-bases"
    specs = []
    for index, (axis, label, cot) in enumerate(_FOCUS_BASES):
        examples = list(initial.examples)
        examples[1] = replace(examples[1], cot=cot)
        snapshot = replace(initial, examples=tuple(examples))
        stored = write_snapshot(
            store,
            snapshot,
            action_id=f"par-focus-base-{index}",
            parent_sha256=initial.content_sha256(),
            diff=[],
        )
        specs.append(
            {
                "axis": axis,
                "label": label,
                "snapshot_path": str(stored / "snapshot.json"),
                "content_sha256": snapshot.content_sha256(),
            }
        )
    return specs


def _cot_only_proposer(messages, attempt_index) -> str:
    return json.dumps(
        {
            "structure": "parallel focus structure",
            "feature_pattern": "parallel focus feature; key: shell=True",
            "patch": [{"example": 2, "cot": "Step 1. focus cot rewritten.\n"}],
        },
        ensure_ascii=False,
    )


def test_parallel_training_keeps_focus_bases(tmp_path: Path) -> None:
    config_path = _temp_config(tmp_path, rounds=1, a_slots=2, top_k=2)
    initial = read_snapshot(
        load_method_run_config(config_path, project_root=REPO).method.initial_template_path
    )
    specs = _focus_base_specs(tmp_path, initial)
    payload = read_json(config_path)
    payload["candidate_induction_workers"] = 2
    payload["focus_plan"] = [
        {
            "round": 1,
            "slots": [
                {
                    "snapshot": spec["snapshot_path"],
                    "label": spec["label"],
                    "axis": spec["axis"],
                    "focus": f"只改 cot：写出 {spec['axis']} 的要求",
                }
                for spec in specs
            ],
        }
    ]
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    runtime = _runtime(
        config_path,
        workers=2,
        training_runner=mock_services._mock_training,
        proposer_source=ScriptedMockSource(content_builder=_cot_only_proposer),
    )
    result = runtime.run()

    assert result["phase"] == "done"
    stage = runtime.run_root / "rounds/1/A"
    plan = read_json(stage / "plan.json")
    slots = sorted(plan["candidates"], key=lambda slot: slot["candidate_index"])
    assert len(slots) == 2
    for slot, spec in zip(slots, specs):
        record = read_json(stage / "candidates" / slot["candidate_id"] / "record.json")
        assert record["focus"]["axis"] == spec["axis"]
        assert record["focus"]["label"] == spec["label"]
        assert record["parent_content_sha256"] == spec["content_sha256"]
        assert record["training"]["completion"] == "complete"
    commit = read_json(stage / "commit.json")
    assert commit["selected"]
    merged = read_json(stage / "round_experience.json")
    action_id = runtime.experience.read_induction(merged["induction_id"])["action_id"]
    system = read_json(runtime.actions.request_path(action_id))["messages"][0]["content"]
    evidence, _ = json.JSONDecoder().raw_decode(system.split("## 本次单模板证据\n", 1)[1].lstrip())
    assert [report["focus"]["axis"] for report in evidence["candidate_reports"]] == [spec["axis"] for spec in specs]
    assert [report["focus"]["label"] for report in evidence["candidate_reports"]] == [spec["label"] for spec in specs]
