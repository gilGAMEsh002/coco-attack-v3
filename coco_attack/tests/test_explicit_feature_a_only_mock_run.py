"""End-to-end offline mock run for ``explicit_feature_a_only``.

Runs the real CLI with the production mock doubles module: no key, network,
Docker or Semgrep is used.  Verifies the A-only loop completes and that the new
A protocol (``feature_pattern`` + cot/code patch) is persisted.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from coco_attack import cli
from coco_attack.assets.artifacts import read_json
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.iteration.template_snapshot import read_snapshot, write_snapshot
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


# --------------------------------------------------------------------------- #
# opt-in cot-focus plan (``focus_plan``)
# --------------------------------------------------------------------------- #

_FOCUS_BASES = (
    ("载体", "bonly-idx7-dict-unpack", "Step 1. base carrier.\n"),
    ("分布", "bonly-idx11-alias", "Step 1. base distribution.\n"),
    ("归因框架", "efa-r2idx2-const-input", "Step 1. base attribution.\n"),
)
#: Which declared base each slot uses per round (a rotated axis assignment).
_FOCUS_ORDER = {1: (0, 1, 2), 2: (2, 0, 1)}


def _focus_base_specs(tmp_path: Path, initial) -> list[dict]:
    """Write one distinct base snapshot per axis into a temporary store."""

    store = tmp_path / "focus-bases"
    specs = []
    for index, (axis, label, cot) in enumerate(_FOCUS_BASES):
        examples = list(initial.examples)
        examples[1] = replace(examples[1], cot=cot)
        snapshot = replace(initial, examples=tuple(examples))
        stored = write_snapshot(
            store, snapshot, action_id=f"focus-base-{index}",
            parent_sha256=initial.content_sha256(), diff=[],
        )
        specs.append({
            "axis": axis,
            "label": label,
            "snapshot_path": str(stored / "snapshot.json"),
            "content_sha256": snapshot.content_sha256(),
        })
    return specs


def _focus_plan_payload(specs: list[dict]) -> list[dict]:
    return [
        {
            "round": round_index,
            "slots": [
                {
                    "snapshot": specs[index]["snapshot_path"],
                    "label": specs[index]["label"],
                    "axis": specs[index]["axis"],
                    "focus": f"round {round_index} 只改 cot：写出 {specs[index]['axis']} 的要求",
                }
                for index in order
            ],
        }
        for round_index, order in sorted(_FOCUS_ORDER.items())
    ]


def _cot_only_proposer(messages, attempt_index) -> str:
    return json.dumps(
        {
            "structure": "mock focus structure",
            "feature_pattern": "mock focus feature; key: shell=True",
            "patch": [{"example": 2, "cot": "Step 1. focus cot rewritten by the probe.\n"}],
        },
        ensure_ascii=False,
    )


def test_mock_focus_plan_run_uses_each_slots_base_snapshot(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(mock_services, "_proposer_responder", _cot_only_proposer)
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    resolved = load_method_run_config(config_path, project_root=REPO)
    initial = read_snapshot(resolved.method.initial_template_path)
    specs = _focus_base_specs(tmp_path, initial)
    payload.update(rounds=2, a_slots=3, top_k=3)
    payload["focus_plan"] = _focus_plan_payload(specs)
    config_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    assert read_json(run_root / "state.json")["phase"] == "done"
    store = ActionStore(run_root / "actions")

    for round_index, order in sorted(_FOCUS_ORDER.items()):
        stage = run_root / "rounds" / str(round_index) / "A"
        plan = read_json(stage / "plan.json")
        # The plan's top-level parent keeps its "initial template" meaning.
        assert plan["parent_role"] == "initial_template"
        assert plan["parent_content_sha256"] == initial.content_sha256()
        slots = sorted(plan["candidates"], key=lambda slot: slot["candidate_index"])
        assert len(slots) == 3
        commit = read_json(stage / "commit.json")
        ranking = read_json(stage / "ranking.json")
        for position, (slot, spec_index) in enumerate(zip(slots, order), 1):
            spec = specs[spec_index]
            focus = slot["focus"]
            assert focus["kind"] == "cot"
            assert focus["axis"] == spec["axis"]
            assert focus["label"] == spec["label"]
            assert focus["instruction"] == f"round {round_index} 只改 cot：写出 {spec['axis']} 的要求"
            assert focus["base_content_sha256"] == spec["content_sha256"]
            assert slot["parent_role"] == "focus_base"
            assert slot["parent_content_sha256"] == spec["content_sha256"]
            assert slot["base_source"] == {
                "snapshot_path": spec["snapshot_path"],
                "content_sha256": spec["content_sha256"],
                "label": spec["label"],
            }
            # The base is readable from *this* run's content-addressed store.
            imported = run_root / "snapshots" / initial.combination_id / spec["content_sha256"]
            assert read_snapshot(imported).content_sha256() == spec["content_sha256"]

            record = read_json(stage / "candidates" / slot["candidate_id"] / "record.json")
            assert record["parent_content_sha256"] == spec["content_sha256"]
            assert record["parent_content_sha256"] != initial.content_sha256()
            assert record["focus"] == focus
            assert record["base_source"]["label"] == spec["label"]
            assert record["base_source"]["content_sha256"] == spec["content_sha256"]
            assert record["proposal_status"] == "materialized"
            system = read_json(store.request_path(record["action_id"]))["messages"][0]["content"]
            assert "焦点轴" in system and f"焦点轴: {spec['axis']}" in system and "cot 探针" in system
            if position > 1:
                # Later slots see the earlier slot's prior tagged with its axis.
                earlier = specs[order[position - 2]]
                assert f"- [轴] {earlier['axis']} [机制] mock focus structure" in system
            # ranking and commit carry the short focus identity, nothing else changes.
            entry = next(item for item in ranking["candidates"]
                         if item["candidate_id"] == slot["candidate_id"])
            assert entry["focus"] == {"kind": "cot", "axis": spec["axis"], "label": spec["label"]}
        assert ranking["selected"] == commit["selected"]
        induction = next(item for item in commit["inductions"]
                         if item["candidate_id"] == slots[0]["candidate_id"])
        first_spec = specs[order[0]]
        assert induction["focus"] == {
            "kind": "cot", "axis": first_spec["axis"], "label": first_spec["label"],
        }


def test_focus_slot_code_change_is_terminal_invalid_and_does_not_pause(tmp_path, monkeypatch) -> None:
    """An unfocused mock proposer (cot+code) is rejected, not silently tolerated."""

    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    resolved = load_method_run_config(config_path, project_root=REPO)
    initial = read_snapshot(resolved.method.initial_template_path)
    specs = _focus_base_specs(tmp_path, initial)
    payload.update(rounds=1, a_slots=1, top_k=1)
    payload["focus_plan"] = [{"round": 1, "slots": [
        {"snapshot": specs[0]["snapshot_path"], "label": specs[0]["label"],
         "axis": specs[0]["axis"], "focus": "只改 cot"},
    ]}]
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # The stock mock proposer patches example 2's code and cot -> forbidden here.
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    state = read_json(run_root / "state.json")
    assert state["phase"] == "done"  # terminal invalid, never a pause
    records = list((run_root / "rounds" / "1" / "A" / "candidates").glob("*/record.json"))
    assert len(records) == 1
    record = read_json(records[0])
    assert record["proposal_status"] == "invalid"
    assert "cot 探针" in record["errors"][0]
    assert record["training"] is None
    ranking = read_json(run_root / "rounds" / "1" / "A" / "ranking.json")
    assert ranking["status"] == "rejected_before_training"
    assert ranking["selected"] == []


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda plan: plan[:1], "must cover every round"),
        (lambda plan: [{"round": 1, "slots": plan[0]["slots"][:2]}, plan[1]], "a_slots=3"),
        (lambda plan: plan + [{"round": 3, "slots": plan[0]["slots"]}], "must cover every round"),
    ],
)
def test_focus_plan_shape_is_validated_at_construction(tmp_path, mutate, match) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = read_snapshot(
        load_method_run_config(config_path, project_root=REPO).method.initial_template_path
    )
    payload.update(rounds=2, a_slots=3, top_k=3)
    payload["focus_plan"] = _focus_plan_payload(_focus_base_specs(tmp_path, initial))
    payload["focus_plan"] = mutate(payload["focus_plan"])
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(efa.MethodRuntimeError, match=match):
        load_method_run_config(config_path, project_root=REPO)


def test_focus_plan_is_refused_outside_a_only_mode(tmp_path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = read_snapshot(
        load_method_run_config(config_path, project_root=REPO).method.initial_template_path
    )
    payload.update(rounds=2, a_slots=3, top_k=3)
    payload["focus_plan"] = _focus_plan_payload(_focus_base_specs(tmp_path, initial))
    payload.update(mode="ab", b_slots_per_seed=5)
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(efa.MethodRuntimeError, match="only allowed for mode='a_only'"):
        load_method_run_config(config_path, project_root=REPO)


def test_default_config_does_not_declare_focus_plan(tmp_path) -> None:
    """No plan -> the new field stays out of the config identity."""

    resolved = load_method_run_config(_temp_config(tmp_path), project_root=REPO)
    assert resolved.method.focus_plan == ()
    assert "focus_plan" not in resolved.method.to_json()


def test_focus_plan_survives_config_round_trip(tmp_path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = read_snapshot(
        load_method_run_config(config_path, project_root=REPO).method.initial_template_path
    )
    payload.update(rounds=2, a_slots=3, top_k=3)
    payload["focus_plan"] = _focus_plan_payload(_focus_base_specs(tmp_path, initial))
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    resolved = load_method_run_config(config_path, project_root=REPO)
    dumped = resolved.method.to_json()
    assert [entry["round"] for entry in dumped["focus_plan"]] == [1, 2]
    assert dumped["focus_plan"][0]["slots"][0]["axis"] == "载体"
    again = efa.MethodRuntimeConfig.from_json(dumped)
    assert again.focus_plan == resolved.method.focus_plan
    assert again.config_sha256() == resolved.method.config_sha256()


# --------------------------------------------------------------------------- #
# configuration-frozen cot control slots (``frozen_cot`` / ``frozen_cot_from_snapshot``)
# --------------------------------------------------------------------------- #

_FROZEN_COT = {
    "2": "cf: 2; key: getattr.\n",
    "3": "cf: 3; key: setattr.\n",
    "4": "cf: 4; key: delattr.\n",
}
_FROZEN_PROVENANCE = "experimenter-frozen: manual v6 probe 5e3251498c85"


def _frozen_base_specs(tmp_path: Path, initial, count: int = 3) -> list[dict]:
    """Write one distinct cot-only base snapshot per index into a temporary store."""

    store = tmp_path / "frozen-bases"
    specs = []
    for index in range(count):
        examples = list(initial.examples)
        examples[1] = replace(examples[1], cot=f"Step 1. base {index}.\n")
        snapshot = replace(initial, examples=tuple(examples))
        stored = write_snapshot(
            store, snapshot, action_id=f"frozen-base-{index}",
            parent_sha256=initial.content_sha256(), diff=[],
        )
        specs.append({
            "axis": f"axis-{index}",
            "label": f"base-{index}",
            "snapshot_path": str(stored / "snapshot.json"),
            "content_sha256": snapshot.content_sha256(),
        })
    return specs


def _normal_focus_slot(spec: dict, index: int) -> dict:
    return {
        "snapshot": spec["snapshot_path"],
        "label": spec["label"],
        "axis": spec["axis"],
        "focus": f"只改 cot {index}",
    }


def _frozen_focus_slot(spec: dict, **extra) -> dict:
    slot = {
        "snapshot": spec["snapshot_path"],
        "label": "frozen-control",
        "axis": "逐字形态",
        "frozen_cot": dict(_FROZEN_COT),
        "frozen_structure": "FROZEN-MECHANISM",
        "frozen_feature_pattern": "FROZEN-FEATURE; key: getattr",
        "provenance": _FROZEN_PROVENANCE,
    }
    slot.update(extra)
    return slot


def _rewrite_config(config_path: Path, payload: dict) -> None:
    config_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _initial_template(config_path: Path):
    return read_snapshot(load_method_run_config(config_path, project_root=REPO).method.initial_template_path)


def _numbering_proposer(calls: list):
    """A cot-only proposer that tags each returned mechanism/feature with its call order."""

    def respond(messages, attempt_index):
        calls.append(messages)
        number = len(calls)
        return json.dumps(
            {
                "structure": f"mock structure {number}",
                "feature_pattern": f"mock feature {number}; key: shell=True",
                "patch": [{"example": 2, "cot": f"Step 1. rewritten {number}.\n"}],
            },
            ensure_ascii=False,
        )

    return respond


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda slot: {**slot, "frozen_cot_from_snapshot": "elsewhere/snapshot.json"},
         "mutually exclusive"),
        (lambda slot: {**slot, "frozen_cot": {"2": "a", "3": "b"}}, "cover examples"),
        (lambda slot: {**slot, "frozen_cot": {"2": "a", "3": "b", "4": ""}},
         "non-empty string"),
        (lambda slot: {**slot, "frozen_structure": ""}, "non-empty string"),
    ],
)
def test_frozen_slot_shape_is_validated_at_construction(tmp_path, mutate, match) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    specs = _frozen_base_specs(tmp_path, _initial_template(config_path), 1)
    payload.update(rounds=1, a_slots=1, top_k=1)
    payload["focus_plan"] = [{"round": 1, "slots": [mutate(_frozen_focus_slot(specs[0]))]}]
    _rewrite_config(config_path, payload)
    with pytest.raises(efa.MethodRuntimeError, match=match):
        load_method_run_config(config_path, project_root=REPO)


def test_frozen_only_metadata_is_refused_on_an_unfocused_slot(tmp_path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    specs = _frozen_base_specs(tmp_path, _initial_template(config_path), 1)
    payload.update(rounds=1, a_slots=1, top_k=1)
    slot = _normal_focus_slot(specs[0], 0)
    slot["frozen_structure"] = "not allowed here"
    payload["focus_plan"] = [{"round": 1, "slots": [slot]}]
    _rewrite_config(config_path, payload)
    with pytest.raises(efa.MethodRuntimeError, match="only allowed on a frozen slot"):
        load_method_run_config(config_path, project_root=REPO)


def test_frozen_focus_plan_is_refused_outside_a_only_mode(tmp_path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    specs = _frozen_base_specs(tmp_path, _initial_template(config_path), 1)
    payload.update(rounds=1, a_slots=1, top_k=1, mode="ab", b_slots_per_seed=5)
    payload["focus_plan"] = [{"round": 1, "slots": [_frozen_focus_slot(specs[0])]}]
    _rewrite_config(config_path, payload)
    with pytest.raises(efa.MethodRuntimeError, match="only allowed for mode='a_only'"):
        load_method_run_config(config_path, project_root=REPO)


def test_frozen_focus_plan_survives_config_round_trip(tmp_path) -> None:
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    specs = _frozen_base_specs(tmp_path, _initial_template(config_path), 1)
    payload.update(rounds=1, a_slots=1, top_k=1)
    payload["focus_plan"] = [{"round": 1, "slots": [_frozen_focus_slot(specs[0])]}]
    _rewrite_config(config_path, payload)
    resolved = load_method_run_config(config_path, project_root=REPO)
    dumped = resolved.method.to_json()
    slot = dumped["focus_plan"][0]["slots"][0]
    assert slot["frozen_cot"] == _FROZEN_COT
    assert slot["frozen_structure"] == "FROZEN-MECHANISM"
    assert slot["provenance"] == _FROZEN_PROVENANCE
    again = efa.MethodRuntimeConfig.from_json(dumped)
    assert again.focus_plan == resolved.method.focus_plan
    assert again.config_sha256() == resolved.method.config_sha256()


def test_mock_frozen_cot_slot_skips_proposal_and_injects_verbatim(tmp_path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(mock_services, "_proposer_responder", _numbering_proposer(calls))
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = _initial_template(config_path)
    specs = _frozen_base_specs(tmp_path, initial, 3)
    payload.update(rounds=1, a_slots=3, top_k=3)
    payload["focus_plan"] = [{"round": 1, "slots": [
        _normal_focus_slot(specs[0], 0),
        _normal_focus_slot(specs[1], 1),
        _frozen_focus_slot(specs[2]),
    ]}]
    _rewrite_config(config_path, payload)
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    assert read_json(run_root / "state.json")["phase"] == "done"

    plan = read_json(run_root / "rounds" / "1" / "A" / "plan.json")
    slots = sorted(plan["candidates"], key=lambda slot: slot["candidate_index"])
    frozen_slot = slots[2]
    assert frozen_slot["action_id"] is None
    assert frozen_slot["parent_role"] == "focus_base"
    assert frozen_slot["focus"]["kind"] == "cot_frozen"
    assert frozen_slot["focus"]["provenance"] == _FROZEN_PROVENANCE
    assert frozen_slot["focus"]["base_content_sha256"] == specs[2]["content_sha256"]
    assert frozen_slot["frozen_cot"] == _FROZEN_COT

    # No proposal action exists for the frozen slot: exactly the two normal
    # slots made a proposer call, and no action dir is keyed by the frozen slot.
    proposer_requests = [
        read_json(path) for path in (run_root / "actions" / "actions").glob("*/request.json")
        if read_json(path).get("role") == "explicit_feature_a_only_proposer"
    ]
    assert len(proposer_requests) == len(calls) == 2
    assert not (run_root / "actions" / "actions" / str(frozen_slot["action_id"])).exists()

    record = read_json(
        run_root / "rounds" / "1" / "A" / "candidates" / frozen_slot["candidate_id"] / "record.json"
    )
    assert record["action_id"] is None
    assert record["proposal_source"] == "frozen"
    assert record["focus"]["kind"] == "cot_frozen"
    assert record["focus"]["provenance"] == _FROZEN_PROVENANCE
    assert record["structure"] == "FROZEN-MECHANISM"
    assert record["feature_pattern"] == "FROZEN-FEATURE; key: getattr"
    assert record["frozen_cot"] == _FROZEN_COT
    # The frozen slot takes the same gate/train/induction path as a focus slot.
    assert record["proposal_status"] == "materialized"
    assert record["gate"]["status"] == "passed"
    assert record["training"]["completion"] == "complete"
    assert record["inducted"] is True
    assert record["version_id"] is not None

    template = read_snapshot(
        run_root / "snapshots" / initial.combination_id / record["content_sha256"]
    )
    assert template.examples[1].cot == _FROZEN_COT["2"]
    assert template.examples[2].cot == _FROZEN_COT["3"]
    assert template.examples[3].cot == _FROZEN_COT["4"]
    base = read_snapshot(specs[2]["snapshot_path"])
    assert [example.code for example in template.examples] == [
        example.code for example in base.examples
    ]

    # The frozen mechanism/feature is never fed back as a prior line.
    for request in proposer_requests:
        system = request["messages"][0]["content"]
        prior_lines = [
            line for line in system.splitlines()
            if line.startswith(("- [机制]", "- [特征]"))
        ]
        assert not any(
            "FROZEN-MECHANISM" in line or "FROZEN-FEATURE" in line for line in prior_lines
        )

    # The frozen control arm still reaches ranking, induction and experience.
    ranking = read_json(run_root / "rounds" / "1" / "A" / "ranking.json")
    entry = next(
        item for item in ranking["candidates"]
        if item["candidate_id"] == frozen_slot["candidate_id"]
    )
    assert entry["focus"] == {
        "kind": "cot_frozen", "axis": "逐字形态", "label": "frozen-control",
    }
    commit = read_json(run_root / "rounds" / "1" / "A" / "commit.json")
    assert frozen_slot["candidate_id"] in [
        item["candidate_id"] for item in commit["inductions"]
    ]
    version = efa.ExperienceStore(run_root / "experience").read_version(
        "structure", record["version_id"]
    )
    assert version.version_id == record["version_id"]


def test_mock_frozen_cot_from_snapshot_copies_source_cot_verbatim(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(mock_services, "_proposer_responder", _cot_only_proposer)
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = _initial_template(config_path)
    specs = _frozen_base_specs(tmp_path, initial, 3)
    # A distinct source snapshot whose examples 2/3/4 cot must be copied verbatim.
    source_examples = list(initial.examples)
    for example in (2, 3, 4):
        source_examples[example - 1] = replace(
            source_examples[example - 1], cot=f"source cot example {example}\n"
        )
    source_snapshot = replace(initial, examples=tuple(source_examples))
    source_stored = write_snapshot(
        tmp_path / "frozen-source", source_snapshot, action_id="frozen-source",
        parent_sha256=initial.content_sha256(), diff=[],
    )
    payload.update(rounds=1, a_slots=3, top_k=3)
    frozen = _frozen_focus_slot(specs[2])
    frozen.pop("frozen_cot")
    frozen["frozen_cot_from_snapshot"] = str(source_stored / "snapshot.json")
    payload["focus_plan"] = [{"round": 1, "slots": [
        _normal_focus_slot(specs[0], 0),
        _normal_focus_slot(specs[1], 1),
        frozen,
    ]}]
    _rewrite_config(config_path, payload)
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    plan = read_json(run_root / "rounds" / "1" / "A" / "plan.json")
    frozen_slot = sorted(plan["candidates"], key=lambda slot: slot["candidate_index"])[2]
    assert frozen_slot["action_id"] is None
    assert frozen_slot["focus"]["kind"] == "cot_frozen"
    record = read_json(
        run_root / "rounds" / "1" / "A" / "candidates" / frozen_slot["candidate_id"] / "record.json"
    )
    assert record["action_id"] is None
    assert record["proposal_source"] == "frozen"
    template = read_snapshot(
        run_root / "snapshots" / initial.combination_id / record["content_sha256"]
    )
    for example in (2, 3, 4):
        assert template.examples[example - 1].cot == source_snapshot.examples[example - 1].cot
    base = read_snapshot(specs[2]["snapshot_path"])
    assert [example.code for example in template.examples] == [
        example.code for example in base.examples
    ]


def test_frozen_slot_is_excluded_from_the_same_round_priors(tmp_path, monkeypatch) -> None:
    """A frozen slot in the middle never leaks its [机制]/[特征] into later prompts."""

    calls: list = []
    monkeypatch.setattr(mock_services, "_proposer_responder", _numbering_proposer(calls))
    config_path = _temp_config(tmp_path)
    payload = read_json(config_path)
    initial = _initial_template(config_path)
    specs = _frozen_base_specs(tmp_path, initial, 3)
    payload.update(rounds=1, a_slots=3, top_k=3)
    payload["focus_plan"] = [{"round": 1, "slots": [
        _normal_focus_slot(specs[0], 0),
        _frozen_focus_slot(specs[1]),
        _normal_focus_slot(specs[2], 2),
    ]}]
    _rewrite_config(config_path, payload)
    assert cli.main([
        "explicit-feature-a-only-run", "--config", str(config_path),
        "--project-root", str(REPO), "--doubles-module", DOUBLES,
    ]) == cli.EXIT_OK
    run_root = Path(payload["run_root"])
    assert len(calls) == 2  # only the two normal slots call the proposer
    store = ActionStore(run_root / "actions")
    records = {
        record["candidate_index"]: record
        for record in (
            read_json(path)
            for path in (run_root / "rounds" / "1" / "A" / "candidates").glob("*/record.json")
        )
    }
    second_prompt = read_json(store.request_path(records[3]["action_id"]))["messages"][0]["content"]
    prior_lines = [
        line for line in second_prompt.splitlines()
        if line.startswith(("- [机制]", "- [特征]", "- [轴]"))
    ]
    # The earlier model-driven slot's prior is present in the later slot's prompt
    # (tagged with its declared focus axis), proving the priors channel works.
    assert any("mock structure 1" in line for line in prior_lines)
    assert any("mock feature 1; key: shell=True" in line for line in prior_lines)
    # The frozen control slot's [机制]/[特征] is not.
    assert prior_lines
    assert not any(
        "FROZEN-MECHANISM" in line or "FROZEN-FEATURE" in line for line in prior_lines
    )
    # The frozen slot still reaches induction/experience.
    commit = read_json(run_root / "rounds" / "1" / "A" / "commit.json")
    frozen_record = records[2]
    assert frozen_record["proposal_source"] == "frozen"
    assert frozen_record["candidate_id"] in [
        item["candidate_id"] for item in commit["inductions"]
    ]
