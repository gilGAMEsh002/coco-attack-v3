"""Closed-loop runtime tests for ``implicit_then_literal`` (subplan 03).

All runs are fully offline: proposer/inducer responses are scripted, the gate
runner and training runner are injected Python doubles, and the baseline loader
returns a snapshot written to a temporary store.  No model, Docker, Semgrep or
credential path is reachable.

The single real-service wiring test (:func:`test_public_run_training_loop_...`)
injects the offline generation service and a fake SAST scanner, so it also never
runs a real tool.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from coco_attack.assets.artifacts import read_json, write_json_atomic
from coco_attack.iteration.template_snapshot import write_snapshot
from coco_attack.method import implicit_then_literal as itl

from _itl_runtime_fakes import (
    REPEATS,
    TASKS,
    Harness,
    MockGateRunner,
    MockTrainingRunner,
    build_harness,
    default_a_responder,
    experience_versions_in,
    gate_result,
    invalid_b_responder,
    make_proposer,
    template_sha_in,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)


# --------------------------------------------------------------------------- #
# Disk helpers
# --------------------------------------------------------------------------- #


def _load(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    assert isinstance(payload, dict), path
    return payload


def _run_root(harness: Harness) -> Path:
    return Path(harness.config.run_root)


def _plan(harness: Harness, round_index: int, stage: str) -> dict[str, Any]:
    return _load(_run_root(harness) / "rounds" / str(round_index) / stage / "plan.json")


def _record(harness: Harness, round_index: int, stage: str, cid: str) -> dict[str, Any]:
    return _load(
        _run_root(harness)
        / "rounds"
        / str(round_index)
        / stage
        / "candidates"
        / cid
        / "record.json"
    )


def _ranking(harness: Harness, round_index: int, stage: str) -> dict[str, Any]:
    return _load(
        _run_root(harness) / "rounds" / str(round_index) / stage / "ranking.json"
    )


def _commit(harness: Harness, round_index: int, stage: str) -> dict[str, Any]:
    return _load(
        _run_root(harness) / "rounds" / str(round_index) / stage / "commit.json"
    )


def _all_records(harness: Harness, round_index: int, stage: str) -> list[dict[str, Any]]:
    plan = _plan(harness, round_index, stage)
    return [
        _record(harness, round_index, stage, slot["candidate_id"])
        for slot in plan["candidates"]
    ]


def _a_messages(source: Any) -> list[list[dict[str, str]]]:
    return [call for call in source.calls if "modifications" not in call[0]["content"]]


def _b_messages(source: Any) -> list[list[dict[str, str]]]:
    return [call for call in source.calls if "modifications" in call[0]["content"]]


def _commit_versions(commit: dict[str, Any]) -> set[str]:
    return {ref["version_id"] for ref in commit["experience_versions"].values()}


# --------------------------------------------------------------------------- #
# 1. Full five-round scale + quiet after done
# --------------------------------------------------------------------------- #


def test_full_five_round_mock_pass_and_quiet_after_done(tmp_path: Path) -> None:
    harness = build_harness(tmp_path)
    summary = harness.run()

    assert summary["phase"] == itl.PHASE_DONE
    counts = summary["counts"]
    assert counts["planned_victim_samples"] == 3020
    assert counts["actual_victim_samples"] == 3020
    assert counts["baseline_trainings"] == 1
    assert counts["a_trainings"] == 25
    assert counts["b_trainings"] == 125
    assert counts["logical_inductions"] == 150

    assert harness.proposer.call_count() == 150  # 25 A + 125 B
    assert harness.inducer.call_count() == 150
    assert len(harness.trainer.calls) == 151  # 1 baseline + 150 candidates
    assert len(harness.gate.calls) == 25 * 3  # only A candidates run the gate

    before = (
        harness.proposer.call_count(),
        harness.inducer.call_count(),
        len(harness.trainer.calls),
        len(harness.gate.calls),
    )
    again = harness.run()
    assert again["phase"] == itl.PHASE_DONE
    assert again["counts"] == counts
    assert (
        harness.proposer.call_count(),
        harness.inducer.call_count(),
        len(harness.trainer.calls),
        len(harness.gate.calls),
    ) == before


# --------------------------------------------------------------------------- #
# 2. Batch barriers + fixed stage-entry experience
# --------------------------------------------------------------------------- #


def test_batch_barriers_and_fixed_stage_entry_experience(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE

    # A: all five proposals terminal before the first candidate check/train of
    # the stage (the one fixed baseline training is excluded).
    first_execution = next(
        index
        for index, event in enumerate(harness.timeline)
        if event[0] == "gate"
        or (event[0] == "train" and event[1] != "itl-baseline")
    )
    a_proposals = [i for i, event in enumerate(harness.timeline) if event[0] == "a_propose"]
    assert len(a_proposals) == 5
    assert max(a_proposals) < first_execution

    # B: all 25 variants across every seed terminal before the first B training.
    first_b_train = next(
        index
        for index, event in enumerate(harness.timeline)
        if event[0] == "train" and str(event[1]).startswith("itl-r1B")
    )
    b_proposals = [i for i, event in enumerate(harness.timeline) if event[0] == "b_propose"]
    assert len(b_proposals) == 25
    assert max(b_proposals) < first_b_train

    # The stage-entry experience is frozen for every proposer call in a stage:
    # training/induction inside the stage never leaks into the same-stage A/B
    # proposer input.
    a_sets = [experience_versions_in(call[0]["content"]) for call in _a_messages(harness.proposer)]
    b_sets = [experience_versions_in(call[0]["content"]) for call in _b_messages(harness.proposer)]
    assert len(set(map(frozenset, a_sets))) == 1
    assert len(set(map(frozenset, b_sets))) == 1
    # A's stage entry is the initial experience; after A induction the B stage
    # entry differs (the structure version was committed).
    assert a_sets[0] != b_sets[0]


# --------------------------------------------------------------------------- #
# 3. Parent template + experience inheritance
# --------------------------------------------------------------------------- #


def test_parent_template_and_feedback_chain(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=2)
    assert harness.run()["phase"] == itl.PHASE_DONE

    a_messages = _a_messages(harness.proposer)
    b_messages = _b_messages(harness.proposer)
    assert len(a_messages) == 10
    assert len(b_messages) == 50

    # Every round's A candidates start from the *fixed* initial template.
    assert all(template_sha_in(call) == harness.initial_sha for call in a_messages)

    # Each B request names an A seed (never the fixed initial template); verify
    # per seed on disk that all five variants share that seed's content sha.
    for round_index in (1, 2):
        a_records = _all_records(harness, round_index, "A")
        a_shas = {record["content_sha256"] for record in a_records}
        assert harness.initial_sha not in a_shas
        b_plan = _plan(harness, round_index, "B")
        by_seed: dict[str, list[dict[str, Any]]] = {}
        for slot in b_plan["candidates"]:
            by_seed.setdefault(slot["seed_candidate_id"], []).append(slot)
        assert len(by_seed) == 5
        for seed_id, slots in by_seed.items():
            assert len(slots) == 5
            seed = _record(harness, round_index, "A", seed_id)
            for slot in slots:
                record = _record(harness, round_index, "B", slot["candidate_id"])
                assert record["parent_content_sha256"] == seed["content_sha256"]

    # Each round's 25 B prompt materials carry one of that round's A seed shas.
    for round_index in (1, 2):
        chunk = b_messages[(round_index - 1) * 25 : round_index * 25]
        a_shas = {
            record["content_sha256"]
            for record in _all_records(harness, round_index, "A")
        }
        assert {template_sha_in(call) for call in chunk} <= a_shas

    # Next-round A inherits exactly the two committed experience categories
    # from the previous round's B stage commit.
    a_commit = _commit(harness, 1, "A")
    b_commit = _commit(harness, 1, "B")
    a_round1 = experience_versions_in(a_messages[0][0]["content"])
    b_round1 = experience_versions_in(b_messages[0][0]["content"])
    a_round2 = experience_versions_in(a_messages[5][0]["content"])
    initial_versions = {
        itl.ExperienceVersionReference.initial(
            itl.EXPERIENCE_CATEGORY_STRUCTURE
        ).version_id,
        itl.ExperienceVersionReference.initial(
            itl.EXPERIENCE_CATEGORY_LITERAL
        ).version_id,
    }
    assert a_round1 == initial_versions
    assert b_round1 == _commit_versions(a_commit)
    assert a_round2 == _commit_versions(b_commit)


# --------------------------------------------------------------------------- #
# 4. A gate / B boundary
# --------------------------------------------------------------------------- #


def test_a_gate_boundary_and_b_has_no_gate(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE

    # All three modifiable examples are checked for every legal A candidate.
    shas = {sha for sha, _example in harness.gate.records}
    assert len(shas) == 1  # the default A patch is identical for all slots
    # Five A candidates, each checked on examples 2, 3 and 4 exactly once.
    assert harness.gate.for_sha(next(iter(shas))) == {2: 5, 3: 5, 4: 5}
    assert len(harness.gate.calls) == 15

    # The gate is never called once B proposal starts.
    last_gate = max(
        i for i, event in enumerate(harness.timeline) if event[0] == "gate"
    )
    first_b_propose = min(
        i for i, event in enumerate(harness.timeline) if event[0] == "b_propose"
    )
    assert last_gate < first_b_propose

    # B really contains a CoT-only change and a no_change candidate.
    records = _all_records(harness, 1, "B")
    assert any(record["proposal_status"] == "no_change" for record in records)
    cot_only = [
        record
        for record in records
        if record["proposal_status"] == "materialized"
        and record["diff"]
        and {entry["field"] for entry in record["diff"]} == {"cot"}
    ]
    assert cot_only


def test_a_gate_failure_occupies_slot_without_training(tmp_path: Path) -> None:
    def a_responder(messages: list[dict[str, str]], number: int) -> str:
        if number == 1:
            return json.dumps(
                {
                    "structure": "failing",
                    "patch": [
                        {"example": 2, "code": "    value = 1\n    return 'FAILGATE'\n"}
                    ],
                }
            )
        return default_a_responder(messages, number)

    harness = build_harness(
        tmp_path,
        rounds=1,
        proposer=make_proposer(a_responder=a_responder),
        gate=MockGateRunner(fail_for=lambda request: "FAILGATE" in request.code),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_DONE

    plan = _plan(harness, 1, "A")
    assert len(plan["candidates"]) == 5  # the slot is occupied, never refilled
    records = _all_records(harness, 1, "A")
    failed = [record for record in records if record["proposal_status"] == "materialized"]
    assert summary["counts"]["a_trainings"] == 4
    assert summary["counts"]["b_trainings"] == 20  # four seeds x five variants
    assert summary["counts"]["logical_inductions"] == 4 + 20
    assert any(record["gate"] and record["gate"]["status"] == "failed" for record in records)
    assert all(
        record["training"] is None
        for record in records
        if record["gate"] and record["gate"]["status"] == "failed"
    )
    assert failed

    # The failure summary is attached to the first valid induction, once.
    assert harness.inducer.calls
    first_system = harness.inducer.calls[0][0]["content"]
    assert "本阶段失败概要" in first_system


# --------------------------------------------------------------------------- #
# 5. Ranking helpers
# --------------------------------------------------------------------------- #


def _rank_record(
    index: int,
    numerator: int,
    denominator: int,
    *,
    evasion_defined: bool = False,
    evasion_value: float | None = None,
    seed: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "candidate_index": index,
        "candidate_id": f"c{index}",
        "hit": {
            "defined": True,
            "numerator": numerator,
            "denominator": denominator,
            "value": numerator / denominator,
        },
        "evasion": {"defined": evasion_defined, "value": evasion_value},
        "expectation": True,
    }
    if seed is not None:
        record["seed_candidate_id"] = seed
    return record


def test_ranking_prefers_hit_ignores_evasion_and_breaks_ties_by_index() -> None:
    # hit order and evasion order are deliberately opposite; there is a
    # cross-seed tie on the hit fraction.
    records = [
        _rank_record(1, 2, 10, evasion_defined=True, evasion_value=0.9, seed="s1"),
        _rank_record(5, 2, 10, evasion_defined=True, evasion_value=0.1, seed="s2"),
        _rank_record(2, 0, 10, evasion_defined=True, evasion_value=0.5),
        _rank_record(3, 7, 10, evasion_defined=True, evasion_value=0.2, seed="s1"),
        _rank_record(4, 7, 10, evasion_defined=True, evasion_value=0.8, seed="s2"),
        _rank_record(6, 1, 10, evasion_defined=True, evasion_value=0.99),
    ]
    ranking = itl.rank_candidate_records(records, top_k=5)
    assert ranking["ranked_candidate_ids"] == ["c3", "c4", "c1", "c5", "c6", "c2"]
    assert ranking["selected"] == ["c3", "c4", "c1", "c5", "c6"]

    # rank_key must agree with the stable fraction/order comparison.
    ordered = sorted(records, key=itl.rank_key)
    assert [record["candidate_id"] for record in ordered] == ranking["ranked_candidate_ids"]


def test_ranking_keeps_hit_zero_and_does_not_refill() -> None:
    records = [
        _rank_record(1, 0, 10),
        _rank_record(2, 0, 10),
        _rank_record(3, 0, 10),
    ]
    ranking = itl.rank_candidate_records(records, top_k=5)
    assert set(ranking["selected"]) == {"c1", "c2", "c3"}
    assert len(ranking["selected"]) == 3  # fewer than five is never refilled
    assert all(entry["eligible"] for entry in ranking["candidates"])

    # An incomplete candidate is listed with a reason and never selected.
    incomplete = _rank_record(9, 5, 10)
    incomplete["expectation"] = False
    incomplete["reason"] = "denominator_or_counts_do_not_match_persisted_samples"
    mixed = itl.rank_candidate_records(records + [incomplete], top_k=5)
    assert "c9" not in mixed["selected"]
    assert any(
        entry["candidate_id"] == "c9" and entry["eligible"] is False
        for entry in mixed["candidates"]
    )


def test_global_b_top5_can_all_come_from_one_seed(tmp_path: Path) -> None:
    def hits_for(config: Any) -> int:
        if "r1B" in str(config.batch_id):
            match = str(config.batch_id).rsplit("-c", 1)[-1]
            return 20 if int(match) <= 5 else 0
        return 0

    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(hits_for=hits_for),
    )
    assert harness.run()["phase"] == itl.PHASE_DONE

    ranking = _ranking(harness, 1, "B")
    assert len(ranking["selected"]) == 5
    seeds = {
        record["seed_candidate_id"]
        for record in _all_records(harness, 1, "B")
        if record["candidate_id"] in ranking["selected"]
    }
    assert len(seeds) == 1  # all five from one seed: no per-seed quota
    assert len(ranking["ranked_candidate_ids"]) == 25


# --------------------------------------------------------------------------- #
# 6. Evidence completeness
# --------------------------------------------------------------------------- #


def test_terminal_generation_failure_stays_at_n_20(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(terminal_for=lambda config: "r1" in config.batch_id),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_DONE
    # Terminal generation failures are still fully accounted for and inducted.
    assert summary["counts"]["a_trainings"] == 5
    assert summary["counts"]["b_trainings"] == 25
    assert summary["counts"]["logical_inductions"] == 30

    plan = _plan(harness, 1, "A")
    cid = plan["candidates"][0]["candidate_id"]
    audit = _load(
        _run_root(harness)
        / "rounds"
        / "1"
        / "A"
        / "candidates"
        / cid
        / "training"
        / "feedback_audit.json"
    )
    assert len(audit["samples"]) == 2 * REPEATS
    assert all(sample["generation_status"] == "error" for sample in audit["samples"])


def test_missing_sample_and_missing_static_block_induction(tmp_path: Path) -> None:
    missing_sample = build_harness(
        tmp_path / "sample",
        rounds=1,
        trainer=MockTrainingRunner(
            omit_last_sample_for=lambda config: config.batch_id == "itl-r1A-c1"
        ),
    )
    summary = missing_sample.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    assert "not complete" in (summary["pause_reason"] or "")
    assert missing_sample.inducer.call_count() == 0
    # Resume re-enters the public training path instead of reusing a bogus
    # "complete" local flag.
    calls_before = len(missing_sample.trainer.calls)
    resumed = missing_sample.resume()
    assert resumed["phase"] == itl.PHASE_PAUSED
    assert len(missing_sample.trainer.calls) > calls_before

    missing_static = build_harness(
        tmp_path / "static",
        rounds=1,
        trainer=MockTrainingRunner(
            missing_static_for=lambda config: config.batch_id == "itl-r1A-c1"
        ),
    )
    summary = missing_static.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    assert "not complete" in (summary["pause_reason"] or "")


def test_wrong_template_blocks_training_adoption(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(
            wrong_template_for=lambda config: config.batch_id == "itl-r1A-c1",
            # A runner summary alone must not bypass the artifact identity check.
            summary_completion="incomplete",
        ),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    assert "not complete" in (summary["pause_reason"] or "")
    assert harness.inducer.call_count() == 0


def _write_pack_artifacts(
    tmp_path: Path, snapshot: itl.TemplateSnapshot, batch: str = "itl-pack"
) -> tuple[Path, str]:
    directory = write_snapshot(tmp_path / "packstore", snapshot)
    config = SimpleNamespace(
        snapshot_path=str(directory / "snapshot.json"),
        output_dir=str(tmp_path / "packout"),
        task_ids=TASKS,
        repeats=REPEATS,
        batch_id=batch,
        semgrep_config=None,
    )
    runner = MockTrainingRunner()
    summary = runner(config)
    return tmp_path / "packout", summary["candidate_hash"]


def test_evidence_rejects_wrong_candidate_template_seed_and_baseline(
    tmp_path: Path,
) -> None:
    from _itl_runtime_fakes import initial_snapshot

    snapshot = initial_snapshot()
    output, candidate_hash = _write_pack_artifacts(tmp_path, snapshot)
    common: dict[str, Any] = dict(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        template=snapshot,
        structure_description="s",
        diff=[],
        gate_facts=[],
        output_dir=output,
        expected_task_ids=TASKS,
        repeats=REPEATS,
    )

    # Wrong candidate hash.
    with pytest.raises(itl.EvidenceError):
        itl.assemble_evidence_pack(
            **common,
            candidate=itl.CandidateIdentity(
                run_id="r", round_index=1, stage="A", candidate_index=1
            ),
            expected_candidate_hash="0" * 64,
        )

    # Wrong template hash.
    with pytest.raises(itl.EvidenceError):
        itl.assemble_evidence_pack(
            **common,
            candidate=itl.CandidateIdentity(
                run_id="r", round_index=1, stage="A", candidate_index=1
            ),
            expected_candidate_hash=candidate_hash,
            expected_template_sha256="0" * 64,
        )

    # Wrong fixed-baseline source reference (same metric numbers).
    with pytest.raises(itl.EvidenceError):
        itl.assemble_evidence_pack(
            **common,
            candidate=itl.CandidateIdentity(
                run_id="r", round_index=1, stage="A", candidate_index=1
            ),
            expected_candidate_hash=candidate_hash,
            baseline={
                "available": True,
                "metrics": {},
                "source": {"reference": "other-baseline", "source_fingerprint": "x"},
            },
            expected_baseline_reference="expected-baseline",
        )

    # Wrong seed comparison for a B candidate.
    b_candidate = itl.CandidateIdentity(
        run_id="r", round_index=1, stage="B", candidate_index=1, seed_candidate_id="seed-a"
    )
    with pytest.raises(itl.EvidenceError):
        itl.assemble_evidence_pack(
            category=itl.EXPERIENCE_CATEGORY_LITERAL,
            candidate=b_candidate,
            template=snapshot,
            structure_description="s",
            diff=[],
            gate_facts=[],
            output_dir=output,
            expected_task_ids=TASKS,
            repeats=REPEATS,
            expected_candidate_hash=candidate_hash,
            seed_comparison={
                "seed_candidate_id": "seed-b",
                "metrics": {},
                "source_fingerprint": "s",
            },
        )


def test_undefined_evasion_is_preserved_and_hit_rankable(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE
    ranking = _ranking(harness, 1, "A")
    assert ranking["selected"]
    for entry in ranking["candidates"]:
        assert entry["evasion"]["defined"] is False
        assert entry["evasion"]["value"] is None
        assert entry["eligible"] is True


# --------------------------------------------------------------------------- #
# 7. Failure branches
# --------------------------------------------------------------------------- #


def test_all_a_gate_fail_pauses_without_inducer(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path, rounds=1, gate=MockGateRunner(fail_for=lambda request: True)
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_INDUCT_COMMIT
    assert "无完整训练结果" in (summary["pause_reason"] or "")
    assert harness.inducer.call_count() == 0
    assert len(harness.trainer.calls) == 1  # baseline only
    assert harness.proposer.call_count() == 5  # B never proposed


def test_all_b_illegal_pauses_without_inducer(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        proposer=make_proposer(b_responder=invalid_b_responder),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_B_TRAIN
    assert "全部变体非法" in (summary["pause_reason"] or "")
    assert harness.inducer.call_count() == 5  # A induction only, no B induction
    assert summary["counts"]["b_trainings"] == 0


def test_partial_seed_invalid_continues_and_inducer_covers_all(tmp_path: Path) -> None:
    def b_responder(messages: list[dict[str, str]], number: int) -> str:
        from _itl_runtime_fakes import default_b_responder, global_b_index

        if global_b_index(messages[0]["content"]) <= 5:
            return invalid_b_responder(messages, number)
        return default_b_responder(messages, number)

    harness = build_harness(
        tmp_path, rounds=1, proposer=make_proposer(b_responder=b_responder)
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_DONE
    assert summary["counts"]["a_trainings"] == 5
    assert summary["counts"]["b_trainings"] == 20
    # All 25 B slots still exist; the five illegal ones are not refilled.
    assert len(_plan(harness, 1, "B")["candidates"]) == 25
    # One seed is entirely invalid, the others continue.
    invalid_seed_records = [
        record
        for record in _all_records(harness, 1, "B")
        if record["seed_index"] == 1
    ]
    assert len(invalid_seed_records) == 5
    assert all(record["proposal_status"] == "invalid" for record in invalid_seed_records)
    # The inducer covers every trained template, not only the top five.
    assert harness.inducer.call_count() == 5 + 20
    assert len(_ranking(harness, 1, "B")["selected"]) == 5


# --------------------------------------------------------------------------- #
# 8. Concurrency bounds
# --------------------------------------------------------------------------- #


def test_concurrency_bounds_across_the_run(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE
    assert harness.gate.peak <= harness.config.check_workers
    assert harness.gate.peak >= 1
    assert harness.trainer.peak <= harness.config.victim_max_concurrency
    for config in harness.trainer.calls:
        assert config.max_concurrency <= harness.config.victim_max_concurrency


def test_gate_workers_really_overlap_up_to_three(tmp_path: Path) -> None:
    gate = MockGateRunner(block_until=3)
    harness = build_harness(tmp_path, rounds=1, gate=gate)
    assert harness.run()["phase"] == itl.PHASE_DONE
    assert gate.entered.is_set()
    assert gate.peak == 3


# --------------------------------------------------------------------------- #
# 9. Config identity
# --------------------------------------------------------------------------- #


def test_experience_reference_json_round_trip() -> None:
    reference = itl.ExperienceVersionReference.initial(itl.EXPERIENCE_CATEGORY_STRUCTURE)
    assert itl.ExperienceVersionReference.from_json(reference.to_json()) == reference


def test_config_json_round_trip_and_identity_rejection(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    config = harness.config
    assert itl.MethodRuntimeConfig.from_json(config.to_json()) == config
    assert (
        itl.MethodRuntimeConfig.from_json(config.to_json()).config_sha256()
        == config.config_sha256()
    )
    assert harness.run()["phase"] == itl.PHASE_DONE

    # A different identity on the same run root is refused.
    changed = replace(config, run_id="run-changed")
    assert changed.config_sha256() != config.config_sha256()
    with pytest.raises(itl.MethodRuntimeError):
        itl.MethodRuntime(changed, services=harness.services).run()

    # The same configuration on a fresh root runs normally.
    alternative = build_harness(tmp_path / "alt", run_id="run-alt", rounds=1)
    assert alternative.run()["phase"] == itl.PHASE_DONE


# --------------------------------------------------------------------------- #
# 10. Gate classification (three independent facts)
# --------------------------------------------------------------------------- #


def test_evaluate_a_gate_classifies_pass_fail_and_not_ready() -> None:
    assert itl.evaluate_a_gate(gate_result(), example=2) == ("passed", ())
    failed = gate_result()
    failed["functional"] = {
        "state": "executed",
        "outcome": "failed",
        "passed": False,
        "reason": None,
    }
    status, reasons = itl.evaluate_a_gate(failed, example=2)
    assert status == "failed" and reasons

    incomplete = gate_result()
    incomplete["semgrep"] = {
        "state": "incomplete",
        "status": "incomplete",
        "available": True,
        "completed": False,
        "detected": None,
    }
    assert itl.evaluate_a_gate(incomplete, example=2)[0] == "not_ready"

    detected = gate_result()
    detected["semgrep"]["detected"] = True
    assert itl.evaluate_a_gate(detected, example=2)[0] == "failed"

    assert itl.evaluate_a_gate({}, example=2)[0] == "not_ready"


# --------------------------------------------------------------------------- #
# 11. Real public training-loop wiring (offline generation + scan doubles)
# --------------------------------------------------------------------------- #


def _fake_sast_scan(sample: Any, **kwargs: Any):
    from coco_attack.evaluation.layers import (
        COVERAGE_COVERED,
        LAYER_SCHEMA_VERSION,
        STATUS_COMPLETED,
        LayerRecord,
    )
    from coco_attack.evaluation.sast import SAST_LAYER

    return LayerRecord(
        schema_version=LAYER_SCHEMA_VERSION,
        evaluation_id=kwargs["evaluation_id"],
        action_id=kwargs["action_id"],
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        stage=sample.identity.stage,
        combination_id=sample.identity.combination_id,
        oracle_id=sample.oracle_id,
        layer=SAST_LAYER,
        tool=kwargs["tool"],
        coverage=COVERAGE_COVERED,
        status=STATUS_COMPLETED,
        available=True,
        completed=True,
        reason_code=None,
        detected=False,
        verdict=None,
        sources={
            "final_code_sha256": sample.final_code_sha256,
            "task_snapshot_sha256": sample.task_snapshot_sha256,
            "sast_adapter_version": "test",
        },
        evidence={"alerts": []},
    )


@requires_prepared
def test_public_run_training_loop_artifacts_feed_evidence_pack(tmp_path: Path) -> None:
    from coco_attack.generation.service import run_generate
    from coco_attack.iteration.template_snapshot import read_snapshot
    from coco_attack.iteration.training_loop import TrainingLoopConfig, run_training_loop
    from coco_attack.iteration.action_runtime import ActionStore, ScriptedMockSource

    snapshot_path = REPO_DIR / itl.FIXED_BASELINE_RELATIVE_PATH
    snapshot = read_snapshot(snapshot_path)
    config = TrainingLoopConfig(
        snapshot_path=str(snapshot_path),
        assets_root=str(ASSETS_DIR),
        data_dir=str(PREPARED_DIR),
        output_dir=str(tmp_path / "training"),
        task_ids=TASKS,
        repeats=REPEATS,
        stage="search",
        form=snapshot.form,
        prompt_version=snapshot.prompt_version,
        model="mock",
        batch_id="itl-wiring",
        source="mock",
        semgrep_config=None,
        repo_dir=str(REPO_DIR),
    )
    manifest = run_training_loop(config, generation_step=run_generate, sast_scan=_fake_sast_scan)
    assert manifest["completion"] == "complete"

    candidate = itl.CandidateIdentity(
        run_id="wiring", round_index=1, stage="A", candidate_index=1
    )
    pack = itl.assemble_evidence_pack(
        category=itl.EXPERIENCE_CATEGORY_STRUCTURE,
        candidate=candidate,
        template=read_snapshot(config.snapshot_path),
        structure_description="wiring",
        diff=[],
        gate_facts=[],
        output_dir=tmp_path / "training",
        expected_task_ids=TASKS,
        repeats=REPEATS,
        expected_candidate_hash=manifest["candidate_hash"],
        expected_template_sha256=snapshot.content_sha256(),
    )
    assert len(pack.samples) == 2 * REPEATS
    assert pack.metrics["sample_hit_rate"].defined is not None

    outcome = itl.run_induction(
        itl.ExperienceStore(tmp_path / "experience"),
        ActionStore(tmp_path / "actions"),
        induction=itl.InductionIdentity("wiring", 1, "A", candidate.logical_id()),
        evidence=pack,
        previous_reference=itl.ExperienceVersionReference.initial(
            itl.EXPERIENCE_CATEGORY_STRUCTURE
        ),
        source=ScriptedMockSource(
            [
                json.dumps(
                    {
                        "entries": [
                            {
                                "label": "e1",
                                "nature": "observation",
                                "description": "d",
                                "change": "c",
                                "evidence": [],
                                "uncertainty": "u",
                            }
                        ],
                        "summary": "real-artifact summary",
                    }
                )
            ]
        ),
    )
    assert outcome.status == "committed"


# --------------------------------------------------------------------------- #
# Reported blocking regressions (round 3)
# --------------------------------------------------------------------------- #


def test_config_enforces_formal_constants_and_service_caps(tmp_path: Path) -> None:
    base = build_harness(tmp_path / "base").config
    # Service concurrency is a research constant, never a scale knob.
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, victim_max_concurrency=9)
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, check_workers=4)
    # The default formal configuration must not be silently shrunk.
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, rounds=1)
    with pytest.raises(itl.MethodRuntimeError):
        replace(base, victim_repeats=5)
    # Reduced-scale offline tests opt out explicitly.
    reduced = replace(
        base,
        rounds=1,
        a_slots=1,
        b_slots_per_seed=1,
        top_k=1,
        enforce_formal_constants=False,
    )
    assert reduced.rounds == 1


def test_baseline_requires_complete_matrix(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(
            omit_last_sample_for=lambda config: config.batch_id == "itl-baseline"
        ),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_BASELINE
    assert harness.inducer.call_count() == 0
    state = _load(_run_root(harness) / "state.json")
    assert not state.get("baseline")


class _BadMetricRunner(MockTrainingRunner):
    """Complete 20-sample matrix but a metric denominator that disagrees."""

    def _write(self, config: Any) -> dict[str, Any]:
        summary = super()._write(config)
        if str(config.batch_id).startswith("itl-r1A"):
            path = Path(config.output_dir) / "feedback.json"
            payload = read_json(path)
            payload["metrics"]["sample_hit_rate"]["denominator"] = 19
            write_json_atomic(path, payload)
        return summary


def test_invalid_metric_denominator_blocks_a_commit(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1, trainer=_BadMetricRunner())
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    # The unified completion check rejects the inconsistent metric before the
    # candidate is ever marked trained.
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    assert "not complete" in (summary["pause_reason"] or "")
    # No A commit and no B plan/induction from an invalid stage.
    assert not (_run_root(harness) / "rounds" / "1" / "A" / "commit.json").exists()
    assert not (_run_root(harness) / "rounds" / "1" / "B" / "plan.json").exists()
    assert harness.inducer.call_count() == 0


def test_all_legal_b_has_no_failure_summary(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, rounds=1)
    assert harness.run()["phase"] == itl.PHASE_DONE
    for call in harness.inducer.calls:
        system = str(call[0]["content"])
        assert "B 阶段失败概要" not in system


def test_baseline_pending_status_is_not_complete_and_resume_recovers(
    tmp_path: Path,
) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(
            pending_first_for=lambda config: config.batch_id == "itl-baseline"
        ),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_BASELINE
    # On resume the runner is re-entered and the now-complete baseline is fixed.
    summary = harness.resume()
    assert summary["phase"] == itl.PHASE_DONE


def test_candidate_pending_is_not_adopted_and_resume_recovers(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path,
        rounds=1,
        trainer=MockTrainingRunner(
            pending_first_for=lambda config: config.batch_id == "itl-r1A-c1"
        ),
    )
    summary = harness.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert summary["paused_from"] == itl.PHASE_A_CHECK_TRAIN
    # Resume must re-enter the public training path, not reuse the pending
    # artifacts as if the candidate were complete.
    summary = harness.resume()
    assert summary["phase"] == itl.PHASE_DONE


def test_container_budget_rejects_before_any_action(tmp_path: Path) -> None:
    execution_path = tmp_path / "execution.json"
    write_json_atomic(execution_path, {"limits": {"max_parallel_containers": 1}})
    harness = build_harness(
        tmp_path / "run",
        rounds=1,
        check_workers=3,
        config_overrides={"execution_config_path": str(execution_path)},
    )
    with pytest.raises(itl.MethodRuntimeError):
        harness.run()
    assert harness.proposer.call_count() == 0
    assert len(harness.gate.calls) == 0
