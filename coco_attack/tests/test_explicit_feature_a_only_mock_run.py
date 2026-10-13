"""End-to-end offline mock run for ``explicit_feature_a_only``.

Runs the real CLI with the production mock doubles module: no key, network,
Docker or Semgrep is used.  Verifies the A-only loop completes and that the new
A protocol (``feature_pattern`` + cot/code patch) is persisted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack import cli
from coco_attack.assets.artifacts import read_json
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.iteration.template_snapshot import read_snapshot
from coco_methods import explicit_feature_a_only as efa
from coco_methods.explicit_feature_a_only import mock_services
from coco_methods.explicit_feature_a_only.wiring import load_method_run_config, assemble_services

REPO = Path(__file__).resolve().parents[2]
MOCK_CONFIG = REPO / "coco_attack/configs/explicit_feature_a_only/mock.example.json"
DOUBLES = "coco_methods.explicit_feature_a_only.mock_services"


def _temp_config(tmp_path: Path) -> Path:
    payload = json.loads(MOCK_CONFIG.read_text(encoding="utf-8"))
    payload["run_id"] = "efa-mock-test"
    payload["run_root"] = str(tmp_path / "efa-run")
    path = tmp_path / "run_config.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _message_evidence(messages) -> dict:
    system = messages[0]["content"]
    payload = system.split("## 本次单模板证据\n", 1)[1].lstrip()
    return json.JSONDecoder().raw_decode(payload)[0]


def _judge_evidence(run_root: Path, record: dict) -> dict:
    induction = efa.ExperienceStore(run_root / "experience").read_induction(record["induction_id"])
    request = ActionStore(run_root / "actions").request_path(induction["action_id"])
    return _message_evidence(read_json(request)["messages"])


def test_mock_a_only_run_completes_and_persists_feature_pattern(tmp_path: Path, monkeypatch) -> None:
    original_inducer = mock_services._inducer_responder

    def cite_feature(messages, attempt_number):
        evidence = _message_evidence(messages)
        label = next(label for label in evidence["evidence_labels"] if label.endswith(":feature_pattern"))
        response = json.loads(original_inducer(messages, attempt_number))
        response["entries"][0]["evidence"] = [label]
        return json.dumps(response)

    monkeypatch.setattr(mock_services, "_inducer_responder", cite_feature)
    config_path = _temp_config(tmp_path)
    code = cli.main(
        [
            "explicit-feature-a-only-run",
            "--config",
            str(config_path),
            "--project-root",
            str(REPO),
            "--doubles-module",
            DOUBLES,
        ]
    )
    assert code == cli.EXIT_OK
    run_root = Path(json.loads(config_path.read_text())["run_root"])
    state = read_json(run_root / "state.json")
    assert state["phase"] == "done"
    records = sorted((run_root / "rounds" / "1" / "A" / "candidates").glob("*/record.json"))
    assert len(records) == 3
    first = read_json(records[0])
    assert first["feature_pattern"]
    fields = {(d["example"], d["field"]) for d in first["diff"]}
    assert (2, "cot") in fields and (2, "code") in fields
    assert (run_root / "rounds" / "1" / "A" / "commit.json").is_file()
    evidence = _judge_evidence(run_root, first)
    assert evidence["feature_pattern"] == first["feature_pattern"]
    assert evidence["diff"] == first["diff"]
    feature_label = f"cand-r1A{first['candidate_index']}:feature_pattern"
    assert feature_label in evidence["evidence_labels"]
    version = efa.ExperienceStore(run_root / "experience").read_version("structure", first["version_id"])
    assert feature_label in version.entries[0].evidence

    # Round 2 consumes the last committed experience, while keeping the initial
    # template as the parent of every proposal.
    commit = read_json(run_root / "rounds" / "1" / "A" / "commit.json")
    plan = read_json(run_root / "rounds" / "2" / "A" / "plan.json")
    assert plan["stage_entry_versions"] == commit["experience_versions"]
    assert plan["parent_content_sha256"] == first["parent_content_sha256"]
    latest_summary = commit["experience_versions"]["structure"]["summary"]
    assert latest_summary
    assert feature_label in plan["stage_entry_versions"]["structure"]["evidence_labels"]
    for path in (run_root / "rounds" / "2" / "A" / "candidates").glob("*/record.json"):
        record = read_json(path)
        assert record["parent_content_sha256"] == first["parent_content_sha256"]
        request = read_json(ActionStore(run_root / "actions").request_path(record["action_id"]))
        assert latest_summary in request["messages"][0]["content"]
    assert not (run_root / "rounds" / "1" / "B").exists()


def test_mock_a_only_round_feeds_mechanism_and_feature_priors_to_second_candidate(tmp_path: Path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    payload["rounds"] = 1
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    records = sorted(
        (read_json(path) for path in (run_root / "rounds" / "1" / "A" / "candidates").glob("*/record.json")),
        key=lambda record: record["candidate_index"],
    )
    assert len(records) >= 2
    store = ActionStore(run_root / "actions")
    first = read_json(store.request_path(records[0]["action_id"]))["messages"][0]["content"]
    second = read_json(store.request_path(records[1]["action_id"]))["messages"][0]["content"]
    # The first candidate is proposed before any prior exists.
    assert "- [机制] mock structure" not in first
    assert "- [特征] mock feature; key: shell=True" not in first
    # Later candidates in the same round must see both prior columns, mechanism first.
    assert "- [机制] mock structure" in second
    assert "- [特征] mock feature; key: shell=True" in second
    assert second.index("- [机制] mock structure") < second.index("- [特征] mock feature; key: shell=True")


def test_metadata_only_feature_reaches_inducer_and_changes_evidence_identity(tmp_path, monkeypatch):
    pattern = "METADATA_ONLY_PATTERN; key: return value"

    def propose(messages, attempt_index):
        return json.dumps({
            "structure": "code-only proposal",
            "feature_pattern": pattern,
            "patch": [{"example": 2, "code": "    value = 9\n    return value\n"}],
        })

    monkeypatch.setattr(mock_services, "_proposer_responder", propose)
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    payload.update(rounds=1, a_slots=1, top_k=1)
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    root = Path(payload["run_root"])
    record = read_json(next((root / "rounds" / "1" / "A" / "candidates").glob("*/record.json")))
    template = read_snapshot(root / "snapshots" / "cwe078-0" / record["content_sha256"])
    assert all(pattern not in example.cot and pattern not in example.code for example in template.examples)
    assert _judge_evidence(root, record)["feature_pattern"] == pattern
    identity = efa.CandidateIdentity(**{
        key: record["candidate"][key]
        for key in ("run_id", "round_index", "stage", "candidate_index", "seed_candidate_id")
    })
    args = dict(
        category="structure", candidate=identity,
        template=template, structure_description=record["structure"],
        diff=record["diff"], gate_facts=tuple(record["gate"]["facts"].values()),
        output_dir=record["training"]["output_dir"], expected_task_ids=payload["training_task_ids"],
        repeats=payload["victim_repeats"], expected_candidate_hash=record["training"]["candidate_hash"],
    )
    pack = efa.assemble_evidence_pack(**args, feature_pattern=pattern)
    changed = efa.assemble_evidence_pack(**args, feature_pattern="different declared pattern")
    assert pack.to_json()["feature_pattern"] == pack.model_visible()["feature_pattern"] == pattern
    assert "cand-r1A1:feature_pattern" in pack.evidence_labels
    absent = efa.assemble_evidence_pack(**args, feature_pattern="")
    assert "cand-r1A1:feature_pattern" not in absent.evidence_labels
    assert pack.evidence_fingerprint != changed.evidence_fingerprint
    assert pack.model_visible()["samples"] == changed.model_visible()["samples"]
    assert pack.metrics == changed.metrics


def test_failure_summary_carries_declared_pattern_without_inventing_missing_patterns(tmp_path, monkeypatch):
    failed_pattern = "FAILED_FEATURE; key: return 2"
    responses = iter([
        {"structure": "gate fails", "feature_pattern": failed_pattern,
         "patch": [{"example": 2, "code": "    return 2\n"}]},
        {"structure": "missing feature", "patch": []},
        {"structure": "gate passes", "feature_pattern": "TRAINED_FEATURE; key: return 3",
         "patch": [{"example": 2, "code": "    return 3\n"}]},
    ])
    monkeypatch.setattr(mock_services, "_proposer_responder", lambda messages, attempt_index: json.dumps(next(responses)))
    original_gate = mock_services._mock_gate

    def gate(request):
        result = original_gate(request)
        if request.code.strip() == "return 2":
            result["functional"].update(outcome="failed", passed=False, reason="mock functional failure")
        return result

    monkeypatch.setattr(mock_services, "_mock_gate", gate)
    original_inducer = mock_services._inducer_responder

    def cite_failure(messages, attempt_number):
        evidence = _message_evidence(messages)
        labels = [label for label in evidence["evidence_labels"]
                  if label.endswith((":failure_summary", ":feature_pattern"))]
        assert len(labels) == 2
        response = json.loads(original_inducer(messages, attempt_number))
        response["entries"][0]["evidence"] = labels
        return json.dumps(response)

    monkeypatch.setattr(mock_services, "_inducer_responder", cite_failure)
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    payload["rounds"] = 1
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    root = Path(payload["run_root"])
    records = sorted(
        (read_json(path) for path in (root / "rounds" / "1" / "A" / "candidates").glob("*/record.json")),
        key=lambda record: record["candidate_index"],
    )
    assert records[0]["gate"]["status"] == "failed"
    assert records[1]["proposal_status"] == "protocol_error"
    assert records[0]["training"] is records[1]["training"] is None
    evidence = _judge_evidence(root, records[2])
    summary = evidence["failure_summary"]
    assert "functional" in summary["description"] and "c2:protocol_error" in summary["description"]
    assert failed_pattern in summary["description"]
    assert any(failed_pattern in part for part in summary["evidence"])
    missing_feature_part = next(part for part in summary["evidence"] if part.startswith("c2:"))
    assert "feature_pattern" not in missing_feature_part
    version = efa.ExperienceStore(root / "experience").read_version("structure", records[2]["version_id"])
    assert "cand-r1A3:failure_summary" in version.entries[0].evidence
    assert "cand-r1A3:feature_pattern" in version.entries[0].evidence


def _fail_all_gates(monkeypatch):
    original = mock_services._mock_gate

    def fail(request):
        result = original(request)
        result["functional"].update(outcome="failed", passed=False, reason="offline rejection")
        return result

    monkeypatch.setattr(mock_services, "_mock_gate", fail)


def _runtime(tmp_path):
    config = load_method_run_config(_temp_config(tmp_path), project_root=REPO)
    return efa.MethodRuntime(config.method, services=assemble_services(config, doubles=mock_services.build_doubles(config)))


@pytest.mark.parametrize("rejection", ["gate", "protocol", "invalid"])
def test_entirely_rejected_rounds_induct_and_advance_without_training(tmp_path, monkeypatch, rejection):
    if rejection == "gate":
        _fail_all_gates(monkeypatch)
    else:
        payload = {"structure": "rejected mechanism", "patch": []}
        if rejection == "invalid":
            payload.update(feature_pattern="rejected feature", patch=[{"example": 1, "cot": "frozen"}])
        monkeypatch.setattr(mock_services, "_proposer_responder", lambda messages, index: json.dumps(payload))
    original = mock_services._inducer_responder

    def cite_rejection(messages, index):
        evidence = _message_evidence(messages)
        assert evidence["training_status"] == "not_run"
        assert evidence["samples"] == [] and evidence["metrics"] == {}
        assert evidence["counts"]["victim_samples"] == 0
        assert evidence["template_role"] == ("candidate" if rejection == "gate" else "parent")
        label = next(label for label in evidence["evidence_labels"] if label.endswith(":proposal_status"))
        response = json.loads(original(messages, index))
        response["entries"][0]["evidence"] = [label]
        return json.dumps(response)

    monkeypatch.setattr(mock_services, "_inducer_responder", cite_rejection)
    runtime = _runtime(tmp_path)
    result = runtime.run()
    assert result["phase"] == "done"
    assert result["counts"]["a_trainings"] == 0
    assert result["counts"]["actual_victim_samples"] == 20  # baseline only
    assert result["counts"]["logical_inductions"] == 6
    for round_index in (1, 2):
        stage = runtime.run_root / "rounds" / str(round_index) / "A"
        ranking, commit = read_json(stage / "ranking.json"), read_json(stage / "commit.json")
        assert ranking["selected"] == ranking["ranked_candidate_ids"] == []
        assert ranking["status"] == commit["status"] == "rejected_before_training"
        assert len(ranking["untrained_candidate_ids"]) == len(commit["inductions"]) == 3
        records = [read_json(path) for path in (stage / "candidates").glob("*/record.json")]
        assert all(record["training"] is None and record["inducted"] for record in records)
        assert all("metrics" not in record for record in records)
        assert not list((stage / "candidates").glob("*/training/feedback.json"))
        if round_index == 2:
            prior = read_json(runtime.run_root / "rounds" / "1" / "A" / "commit.json")
            plan = read_json(stage / "plan.json")
            assert plan["stage_entry_versions"] == prior["experience_versions"]
            summary = prior["experience_versions"]["structure"]["summary"]
            for record in records:
                request = read_json(runtime.actions.request_path(record["action_id"]))
                assert summary in request["messages"][0]["content"]


def test_rejected_round_checkpoint_resumes_into_successful_training(tmp_path, monkeypatch):
    original = mock_services._mock_gate

    def gate(request):
        result = original(request)
        if "/rounds/1/" in str(request.output_dir):
            result["functional"].update(outcome="failed", passed=False, reason="round 1 rejection")
        return result

    monkeypatch.setattr(mock_services, "_mock_gate", gate)
    runtime = _runtime(tmp_path)
    stopped = runtime.run(stop_after="round_1_complete")
    assert stopped["phase"] == "stopped" and stopped["round_index"] == 2
    assert len(runtime.services.inducer_source.calls) == 3
    assert not (runtime.run_root / "rounds" / "2").exists()
    resumed = runtime.resume()
    assert resumed["phase"] == "done" and resumed["counts"]["a_trainings"] == 3
    assert len(runtime.services.inducer_source.calls) == 6
    assert read_json(runtime.run_root / "rounds/2/A/ranking.json")["selected"]


def test_rejection_induction_recovers_commit_without_calling_inducer_twice(tmp_path, monkeypatch):
    _fail_all_gates(monkeypatch)
    runtime = _runtime(tmp_path)

    def crash(marker):
        if marker.startswith("induction_committed:"):
            raise RuntimeError("crash after durable induction")

    runtime.services.on_event = crash
    with pytest.raises(RuntimeError, match="crash after durable induction"):
        runtime.run()
    assert len(runtime.services.inducer_source.calls) == 1
    runtime.services.on_event = None
    assert runtime.resume()["phase"] == "done"
    assert len(runtime.services.inducer_source.calls) == 6
    assert len(list((runtime.run_root / "experience/versions/structure").glob("*.json"))) == 6


def test_rejected_round_inducer_protocol_error_can_be_explicitly_retried(tmp_path, monkeypatch):
    _fail_all_gates(monkeypatch)
    original = mock_services._inducer_responder
    attempts = []

    def respond(messages, index):
        attempts.append(messages)
        return "bad JSON" if len(attempts) == 1 else original(messages, index)

    monkeypatch.setattr(mock_services, "_inducer_responder", respond)
    runtime = _runtime(tmp_path)
    assert runtime.run()["phase"] == "paused"
    assert runtime.resume()["phase"] == "paused"
    assert len(attempts) == 1
    records = [read_json(path) for path in (runtime.run_root / "rounds/1/A/candidates").glob("*/record.json")]
    target = next(record for record in records if record.get("induction_status") == "protocol_error")
    result = runtime.retry_induction(round_index=1, stage="A", candidate_id_value=target["candidate_id"])
    assert result["phase"] == "done" and len(attempts) == 7


@pytest.mark.parametrize("incomplete", ["gate", "training"])
def test_incomplete_work_is_not_treated_as_a_rejected_round(tmp_path, monkeypatch, incomplete):
    if incomplete == "gate":
        monkeypatch.setattr(mock_services, "_mock_gate", lambda request: None)
    else:
        original = mock_services._mock_training

        def train(config):
            return original(config) if config.batch_id == "efa-baseline" else {"completion": "incomplete"}

        monkeypatch.setattr(mock_services, "_mock_training", train)
    runtime = _runtime(tmp_path)
    result = runtime.run()
    assert result["phase"] == "paused" and result["round_index"] == 1
    assert result["counts"]["logical_inductions"] == 0
    assert not (runtime.run_root / "rounds/1/A/commit.json").exists()
