"""Parallel reports share a parent and one merged experience feeds the next round."""

import json
import re
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json
from coco_attack.iteration.action_runtime import ScriptedMockSource
from coco_methods import explicit_feature_a_only as efa
from coco_methods.explicit_feature_a_only import mock_services
from coco_methods.explicit_feature_a_only.experience import InductionIdentity
from coco_methods.explicit_feature_a_only.preflight import build_status_report
from coco_methods.explicit_feature_a_only.wiring import (
    LazyDmxRoleSource, assemble_services, load_method_run_config,
)

REPO = Path(__file__).resolve().parents[2]


def _evidence(messages):
    text = messages[0]["content"].split("## 本次单模板证据\n", 1)[1].lstrip()
    return json.JSONDecoder().raw_decode(text)[0]


def _response(evidence):
    merged = evidence.get("kind") == "round_experience_merge"
    if merged:
        reports = evidence["candidate_reports"]
        summary = "MERGED: " + " / ".join(report["summary"] for report in reports)
        labels = [label for label in evidence["evidence_labels"] if label.endswith((":feature_pattern", ":proposal_status"))]
        revision = reports[0]["entries"][0]["label"]
        label = "merged-round"
    else:
        citation = next(label for label in evidence["evidence_labels"] if label.endswith((":feature_pattern", ":proposal_status")))
        round_number, index = re.search(r"cand-r(\d+)A(\d+):", citation).groups()
        label = f"entry-r{round_number}-c{index}"
        summary = f"CLAIM_R{round_number}_C{index}"
        labels = [citation]
        revision = None
    return json.dumps({"entries": [{
        "label": label, "nature": "hypothesis", "description": summary,
        "change": "offline", "evidence": labels, "uncertainty": "offline only",
        "revision_of": revision,
    }], "summary": summary})


def _runtime(tmp_path, responder, *, rounds=1, gate=None):
    payload = read_json(REPO / "coco_attack/configs/explicit_feature_a_only/mock.example.json")
    payload.update(run_id="parallel-induction-test", run_root=str(tmp_path / "run"), rounds=rounds,
                   candidate_training_workers=3, candidate_induction_workers=3)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    config = load_method_run_config(path, project_root=REPO)
    doubles = mock_services.build_doubles(config)
    doubles.inducer_source = ScriptedMockSource(content_builder=responder)
    if gate:
        doubles.gate_runner = gate
    return efa.MethodRuntime(config.method, services=assemble_services(config, doubles=doubles)), config


def _records(runtime):
    return sorted((read_json(path) for path in (runtime.run_root / "rounds/1/A/candidates").glob("*/record.json")),
                  key=lambda record: record["candidate_index"])


def test_parallel_reports_overlap_and_all_feed_the_next_round(tmp_path):
    barrier = threading.Barrier(3, timeout=10)
    merge_inputs = []

    def respond(messages, index):
        evidence = _evidence(messages)
        if evidence.get("kind") == "round_experience_merge":
            merge_inputs.append(evidence)
        else:
            barrier.wait()  # A serial implementation cannot release this barrier.
        return _response(evidence)

    runtime, config = _runtime(tmp_path, respond, rounds=2)
    result = runtime.run()
    assert result["phase"] == "done" and result["counts"]["logical_inductions"] == 8
    assert len(runtime.services.inducer_source.calls) == 8 and len(merge_inputs) == 2
    for number in (1, 2):
        stage = runtime.run_root / "rounds" / str(number) / "A"
        records = [read_json(path) for path in (stage / "candidates").glob("*/record.json")]
        requests = [read_json(runtime.actions.request_path(
            runtime.experience.read_induction(record["induction_id"])["action_id"])) for record in records]
        assert len({request["input_refs"]["previous_version_id"] for request in requests}) == 1
        commit = read_json(stage / "commit.json")
        summary = read_json(stage / "round_experience.json")
        assert commit["round_experience"]["version_id"] == summary["version_id"]
        assert commit["experience_versions"]["structure"]["version_id"] == summary["version_id"]
        assert len(summary["candidate_version_ids"]) == 3
        merged = runtime.experience.read_version("structure", summary["version_id"])
        for index in (1, 2, 3):
            assert f"CLAIM_R{number}_C{index}" in merged.summary
            assert f"cand-r{number}A{index}:feature_pattern" in merged.evidence_labels()
    first_commit = read_json(runtime.run_root / "rounds/1/A/commit.json")
    for path in (runtime.run_root / "rounds/2/A/candidates").glob("*/record.json"):
        request = read_json(runtime.actions.request_path(read_json(path)["action_id"]))
        assert first_commit["experience_versions"]["structure"]["summary"] in request["messages"][0]["content"]
    assert build_status_report(config).counts["logical_inductions"] == 8


@pytest.mark.parametrize("fail_merge", [False, True])
def test_failed_parallel_report_or_merge_retries_without_repeating_paid_calls(tmp_path, fail_merge):
    calls = Counter()

    def respond(messages, index):
        evidence = _evidence(messages)
        if evidence.get("kind") == "round_experience_merge":
            key = "merge"
        else:
            key = next(label for label in evidence["evidence_labels"] if label.endswith(":feature_pattern"))
        calls[key] += 1
        should_fail = key == "merge" if fail_merge else key == "cand-r1A2:feature_pattern"
        if should_fail and calls[key] == 1:
            return "bad JSON"
        return _response(evidence)

    runtime, _ = _runtime(tmp_path, respond)
    assert runtime.run()["phase"] == "paused"
    before = calls.copy()
    assert runtime.resume()["phase"] == "paused" and calls == before
    if fail_merge:
        target = "round-summary"
        assert all(record["inducted"] for record in _records(runtime))
    else:
        assert [record["inducted"] for record in _records(runtime)] == [True, False, True]
        target = _records(runtime)[1]["candidate_id"]
        assert "merge" not in calls
    result = runtime.retry_induction(round_index=1, stage="A", candidate_id_value=target)
    assert result["phase"] == "done" and result["counts"]["logical_inductions"] == 4
    assert calls["cand-r1A1:feature_pattern"] == calls["cand-r1A3:feature_pattern"] == 1
    assert calls["merge"] == (2 if fail_merge else 1)
    assert calls["cand-r1A2:feature_pattern"] == (1 if fail_merge else 2)


def test_durable_parallel_merge_survives_crash_before_state_update(tmp_path):
    runtime, _ = _runtime(tmp_path, lambda messages, index: _response(_evidence(messages)))
    merge_id = InductionIdentity(runtime.config.run_id, 1, "A", "round-summary").logical_id()

    def crash(marker):
        if marker == f"induction_committed:{merge_id}":
            raise RuntimeError("crash after merge")

    runtime.services.on_event = crash
    with pytest.raises(RuntimeError, match="crash after merge"):
        runtime.run()
    assert len(runtime.services.inducer_source.calls) == 4
    assert not (runtime.run_root / "rounds/1/A/round_experience.json").exists()
    runtime.services.on_event = None
    assert runtime.resume()["phase"] == "done"
    assert len(runtime.services.inducer_source.calls) == 4


@pytest.mark.parametrize("rejection", ["gate", "protocol"])
def test_parallel_rejected_reports_merge_without_fake_training_metrics(tmp_path, monkeypatch, rejection):
    merge_inputs = []
    if rejection == "protocol":
        monkeypatch.setattr(mock_services, "_proposer_responder", lambda messages, index: "{}")

    def gate(request):
        result = mock_services._mock_gate(request)
        result["functional"].update(outcome="failed", passed=False, reason="offline rejection")
        return result

    def respond(messages, index):
        evidence = _evidence(messages)
        if evidence.get("kind") == "round_experience_merge":
            merge_inputs.append(evidence)
        else:
            assert evidence["training_status"] == "not_run" and evidence["metrics"] == {}
        return _response(evidence)

    runtime, _ = _runtime(tmp_path, respond, gate=gate)
    result = runtime.run()
    assert result["phase"] == "done" and result["counts"]["a_trainings"] == 0
    assert result["counts"]["actual_victim_samples"] == 20
    assert len(merge_inputs) == 1
    assert all(report["training_status"] == "not_run" and report["metrics"] == {}
               for report in merge_inputs[0]["candidate_reports"])


def test_lazy_provider_initializes_once_and_does_not_serialize_requests():
    barrier = threading.Barrier(3, timeout=10)
    loads, builds = [], []

    class Provider:
        def generate(self, messages, **kwargs):
            barrier.wait()
            return "offline response"

    def build(config, key):
        builds.append(config)
        return Provider()

    def load():
        loads.append(True)
        return "offline-key"

    source = LazyDmxRoleSource(efa.roles.inducer_config(source="dmx"), credential_loader=load, provider_builder=build)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(source.generate, [], rollout_id=index, attempt_index=1) for index in range(3)]
        assert [future.result() for future in futures] == ["offline response"] * 3
    assert source.build_count == source.credential_load_count == len(loads) == len(builds) == 1
