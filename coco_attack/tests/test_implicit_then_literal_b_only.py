"""Offline B-only protocol, external-seed import and inheritance tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from coco_attack.assets.artifacts import read_json
from coco_methods import implicit_then_literal as itl
from coco_methods.implicit_then_literal import preflight
from coco_methods.implicit_then_literal.wiring import MethodRunConfig

from _itl_runtime_fakes import build_harness


def _root(harness: Any) -> Path:
    return Path(harness.config.run_root)


def _load(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    assert isinstance(payload, dict), path
    return payload


def _commit(harness: Any, round_index: int, stage: str) -> dict[str, Any]:
    return _load(_root(harness) / "rounds" / str(round_index) / stage / "commit.json")


def _plan(harness: Any, round_index: int, stage: str) -> dict[str, Any]:
    return _load(_root(harness) / "rounds" / str(round_index) / stage / "plan.json")


def _record(harness: Any, round_index: int, stage: str, cid: str) -> dict[str, Any]:
    return _load(
        _root(harness) / "rounds" / str(round_index) / stage / "candidates" / cid / "record.json"
    )


def _source_run(tmp_path: Path) -> tuple[Any, str, dict[str, Any]]:
    source = build_harness(
        tmp_path / "source",
        rounds=1,
        a_slots=1,
        b_slots_per_seed=0,
        top_k=1,
        config_overrides={"mode": "a_only", "enforce_formal_constants": False},
    )
    assert source.runtime.run()["phase"] == itl.PHASE_DONE
    cid = _commit(source, 1, "A")["selected"][0]
    return source, cid, _record(source, 1, "A", cid)


def _b_only(tmp_path: Path, source: Any, cid: str, **overrides: Any) -> Any:
    cfg: dict[str, Any] = {
        "mode": "b_only",
        "enforce_formal_constants": False,
        "b_seeds": (
            {"source_run_dir": str(_root(source)), "round_index": 1, "candidate_id": cid},
        ),
    }
    cfg.update(overrides)
    return build_harness(
        tmp_path,
        rounds=1,
        a_slots=1,
        b_slots_per_seed=2,
        top_k=1,
        config_overrides=cfg,
    )


def _b_only_config(tmp_path: Path) -> itl.MethodRuntimeConfig:
    return build_harness(
        tmp_path,
        rounds=1,
        a_slots=1,
        b_slots_per_seed=2,
        top_k=1,
        config_overrides={
            "mode": "b_only",
            "enforce_formal_constants": False,
            "b_seeds": (
                {"source_run_dir": "/some/source", "round_index": 1, "candidate_id": "c-1"},
            ),
        },
    ).config


def test_b_only_imports_external_seed_and_skips_a_stage(tmp_path: Path) -> None:
    source, cid, source_record = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid)
    summary = b.run()

    assert summary["phase"] == itl.PHASE_DONE
    assert summary["round_index"] == 1
    assert not (_root(b) / "rounds" / "1" / "A").exists()

    plan = _plan(b, 1, "B")
    assert plan["seeds"] == [cid]
    assert len(plan["candidates"]) == 2
    for slot in plan["candidates"]:
        record = _record(b, 1, "B", slot["candidate_id"])
        assert record["seed_candidate_id"] == cid
        assert record["parent_content_sha256"] == source_record["content_sha256"]
        assert record["structure"] == source_record["structure"]

    imported = (
        _root(b) / "snapshots" / "cwe078-0" / source_record["content_sha256"] / "snapshot.json"
    )
    assert imported.is_file()

    assert len(b.gate.calls) == 0
    assert len(b.trainer.calls) == 3
    assert b.proposer.call_count() == 2
    assert all("modifications" in call[0]["content"] for call in b.proposer.calls)
    assert b.inducer.call_count() == 2

    counts = summary["counts"]
    assert counts["actual_victim_samples"] == 60
    assert counts["a_trainings"] == 0
    assert counts["b_trainings"] == 2
    assert counts["logical_inductions"] == 2
    assert counts["baseline_trainings"] == 1


def test_b_only_round_two_inherits_previous_b_commit(tmp_path: Path) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid, rounds=2)
    assert b.run()["phase"] == itl.PHASE_DONE

    r1_commit = _commit(b, 1, "B")
    assert len(r1_commit["selected"]) == 1
    r1_selected = r1_commit["selected"][0]

    plan = _plan(b, 2, "B")
    assert plan["seeds"] == r1_commit["selected"]
    assert not list((_root(b) / "rounds").glob("*/A"))

    parent = _record(b, 1, "B", r1_selected)
    for slot in plan["candidates"]:
        record = _record(b, 2, "B", slot["candidate_id"])
        assert record["seed_candidate_id"] == r1_selected
        assert record["parent_content_sha256"] == parent["content_sha256"]


@pytest.mark.parametrize("overrides", [
    {"b_seeds": ()},
    {"enforce_formal_constants": True},
    {"b_slots_per_seed": 0},
])
def test_b_only_rejects_invalid_configuration(
    tmp_path: Path, overrides: dict[str, Any],
) -> None:
    with pytest.raises(itl.MethodRuntimeError):
        replace(_b_only_config(tmp_path), **overrides)


def test_ab_rejects_b_seeds(tmp_path: Path) -> None:
    with pytest.raises(itl.MethodRuntimeError):
        replace(
            build_harness(tmp_path).config,
            b_seeds=({"source_run_dir": "/x", "round_index": 1, "candidate_id": "c"},),
        )


def test_a_only_rejects_b_seeds(tmp_path: Path) -> None:
    base = build_harness(
        tmp_path,
        rounds=1,
        a_slots=1,
        b_slots_per_seed=0,
        top_k=1,
        config_overrides={"mode": "a_only", "enforce_formal_constants": False},
    ).config
    with pytest.raises(itl.MethodRuntimeError):
        replace(
            base,
            b_seeds=({"source_run_dir": "/x", "round_index": 1, "candidate_id": "c"},),
        )


@pytest.mark.parametrize("seed", [
    {"source_run_dir": "/x", "round_index": 1},
    {"source_run_dir": "/x", "round_index": 0, "candidate_id": "c"},
    {"source_run_dir": "", "round_index": 1, "candidate_id": "c"},
    {"source_run_dir": "/x", "round_index": True, "candidate_id": "c"},
])
def test_b_only_rejects_malformed_seeds(tmp_path: Path, seed: dict[str, Any]) -> None:
    with pytest.raises(itl.MethodRuntimeError):
        replace(_b_only_config(tmp_path), b_seeds=(seed,))


def test_b_only_config_round_trip(tmp_path: Path) -> None:
    base = _b_only_config(tmp_path)
    restored = itl.MethodRuntimeConfig.from_json(json.loads(json.dumps(base.to_json())))
    assert restored == base
    assert restored.config_sha256() == base.config_sha256()
    assert isinstance(restored.b_seeds, tuple)
    assert restored.b_seeds == (
        {"source_run_dir": "/some/source", "round_index": 1, "candidate_id": "c-1"},
    )


def test_b_only_preflight_accepts_external_seed_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid)
    Path(b.config.prepared_data_dir).mkdir()
    monkeypatch.setattr(
        preflight, "load_comparison_baseline",
        lambda **kwargs: SimpleNamespace(
            reference=b.baseline_loader.reference,
            content_sha256=b.baseline_sha,
        ),
    )
    monkeypatch.setattr(
        preflight, "load_prepared_data",
        lambda path, combination_id: SimpleNamespace(
            task_by_id=lambda: dict.fromkeys(b.config.training_task_ids)
        ),
    )
    report = preflight.build_preflight_report(
        MethodRunConfig(project_root=str(tmp_path), method=b.config)
    )
    assert report.offline_preflight_passed, report.errors
    assert not _root(b).exists()


def test_b_only_preflight_reports_missing_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(
        tmp_path / "b",
        source,
        cid,
        b_seeds=(
            {"source_run_dir": str(_root(source)), "round_index": 1, "candidate_id": "bogus-cid"},
        ),
    )
    Path(b.config.prepared_data_dir).mkdir()
    monkeypatch.setattr(
        preflight, "load_comparison_baseline",
        lambda **kwargs: SimpleNamespace(
            reference=b.baseline_loader.reference,
            content_sha256=b.baseline_sha,
        ),
    )
    monkeypatch.setattr(
        preflight, "load_prepared_data",
        lambda path, combination_id: SimpleNamespace(
            task_by_id=lambda: dict.fromkeys(b.config.training_task_ids)
        ),
    )
    report = preflight.build_preflight_report(
        MethodRunConfig(project_root=str(tmp_path), method=b.config)
    )
    assert not report.offline_preflight_passed
    assert any("b_seed record missing" in error for error in report.errors)


def test_b_only_keeps_external_seed_comparisons_and_real_budget(tmp_path: Path) -> None:
    source, cid, source_record = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid, a_slots=5)
    summary = b.run()
    assert summary["counts"]["planned_victim_samples"] == 60
    ranking = _load(_root(b) / "rounds" / "1" / "B" / "ranking.json")
    record = _record(b, 1, "B", _plan(b, 1, "B")["candidates"][0]["candidate_id"])
    comparison = b.runtime._seed_comparison(1, record)
    assert comparison["training_complete"] is True
    assert comparison["metrics"] == source_record["metrics"]
    assert comparison["per_task"] == source_record["per_task"]
    assert record["seed_source"]["source_run_dir"] == str(_root(source))
    # Ranking schema stores candidate evidence under entries, independent of selection.
    assert any(entry["seed_comparison"]["training_complete"] for entry in ranking["candidates"])


def test_b_only_accepts_gate_passed_seed_without_training_and_preserves_unknown(tmp_path: Path) -> None:
    source, cid, source_record = _source_run(tmp_path)
    path = _root(source) / "rounds" / "1" / "A" / "candidates" / cid / "record.json"
    source_record.update(training=None, metrics=None, per_task=None, evidence_fingerprint=None)
    path.write_text(json.dumps(source_record))
    original = {p: p.read_bytes() for p in _root(source).rglob("*") if p.is_file()}
    b = _b_only(tmp_path / "b", source, cid)
    assert b.run()["phase"] == itl.PHASE_DONE
    record = _record(b, 1, "B", _plan(b, 1, "B")["candidates"][0]["candidate_id"])
    comparison = b.runtime._seed_comparison(1, record)
    assert comparison["training_complete"] is False
    assert comparison["metrics"] == {}
    assert comparison["per_task"] == {}
    assert comparison["deltas"]["sample_hit_rate"]["defined"] is False
    assert {p: p.read_bytes() for p in _root(source).rglob("*") if p.is_file()} == original


@pytest.mark.parametrize("field,value", [("gate", {"status": "failed"}), ("candidate_id", "other")])
def test_b_only_rejects_external_seed_gate_or_identity_mismatch(tmp_path: Path, field: str, value: Any) -> None:
    source, cid, source_record = _source_run(tmp_path)
    path = _root(source) / "rounds" / "1" / "A" / "candidates" / cid / "record.json"
    source_record[field] = value
    path.write_text(json.dumps(source_record))
    b = _b_only(tmp_path / "b", source, cid)
    summary = b.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert "seed invalid" in summary["pause_reason"]
    assert b.proposer.call_count() == 0


def test_b_only_wiring_resolves_and_binds_only_referenced_external_inputs(tmp_path: Path) -> None:
    source, cid, record = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid)
    config = b.config.to_json()
    config["b_seeds"][0]["source_run_dir"] = str(_root(source).relative_to(tmp_path))
    loaded = MethodRunConfig.from_json(config, project_root=tmp_path)
    assert loaded.method.b_seeds[0]["source_run_dir"] == str(_root(source))
    bindings = dict(loaded.method.input_binding)
    assert bindings["b_seed_1_record"] != "missing"
    assert bindings["b_seed_1_snapshot"] != "missing"
    unrelated = _root(source) / "unrelated.log"
    unrelated.write_text("unrelated execution history")
    assert MethodRunConfig.from_json(config, project_root=tmp_path).config_sha256() == loaded.config_sha256()
    path = _root(source) / "rounds" / "1" / "A" / "candidates" / cid / "record.json"
    record["note"] = "seed changed"
    path.write_text(json.dumps(record))
    assert MethodRunConfig.from_json(config, project_root=tmp_path).config_sha256() != loaded.config_sha256()


def test_b_only_preflight_allows_real_exploratory_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid, victim_source="dmx", check_service="real")
    Path(b.config.prepared_data_dir).mkdir()
    rules = tmp_path / "rules"
    rules.mkdir()
    b.config = replace(b.config, semgrep_config=str(rules))
    monkeypatch.setattr(preflight, "semgrep_rule_ids", lambda path: preflight.semgrep_target_rules("cwe078-0"))
    monkeypatch.setattr(preflight, "load_comparison_baseline", lambda **kwargs: SimpleNamespace(reference=b.baseline_loader.reference, content_sha256=b.baseline_sha))
    monkeypatch.setattr(preflight, "load_prepared_data", lambda path, combination_id: SimpleNamespace(task_by_id=lambda: dict.fromkeys(b.config.training_task_ids)))
    report = preflight.build_preflight_report(MethodRunConfig(project_root=str(tmp_path), method=b.config))
    assert report.offline_preflight_passed, report.errors
    assert any("B-only exploratory" in warning for warning in report.warnings)


def test_b_only_round_two_compares_to_previous_b_seed(tmp_path: Path) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid, rounds=2)
    b.run()
    record = _record(b, 2, "B", _plan(b, 2, "B")["candidates"][0]["candidate_id"])
    comparison = b.runtime._seed_comparison(2, record)
    assert comparison["training_complete"] is True
    assert comparison["seed_candidate_label"].startswith("cand-r1B")


def test_b_only_five_external_seeds_five_variants_has_no_a_sample_budget(tmp_path: Path) -> None:
    source = build_harness(tmp_path / "source", rounds=1, a_slots=5, b_slots_per_seed=0, top_k=5, config_overrides={"mode": "a_only", "enforce_formal_constants": False})
    source.run()
    selected = _commit(source, 1, "A")["selected"]
    assert len(selected) == 5
    b = build_harness(tmp_path / "b", rounds=1, a_slots=5, b_slots_per_seed=5, top_k=5, config_overrides={
        "mode": "b_only", "enforce_formal_constants": False,
        "b_seeds": tuple({"source_run_dir": str(_root(source)), "round_index": 1, "candidate_id": cid} for cid in selected),
    })
    summary = b.run()
    assert summary["phase"] == itl.PHASE_DONE
    assert summary["counts"]["planned_victim_samples"] == 520
    assert summary["counts"]["actual_victim_samples"] == 520
    assert summary["counts"]["a_trainings"] == 0
    assert summary["counts"]["b_trainings"] == 25
    assert b.proposer.call_count() == 25
    assert b.inducer.call_count() == 25
    assert not list((_root(b) / "rounds").glob("*/A"))


def test_b_only_rejects_corrupted_external_snapshot_before_role_calls(tmp_path: Path) -> None:
    source, cid, record = _source_run(tmp_path)
    path = _root(source) / "snapshots" / "cwe078-0" / record["content_sha256"] / "snapshot.json"
    snapshot = _load(path)
    snapshot["content_sha256"] = "0" * 64
    path.write_text(json.dumps(snapshot))
    b = _b_only(tmp_path / "b", source, cid)
    summary = b.run()
    assert summary["phase"] == itl.PHASE_PAUSED
    assert "hash mismatch" in summary["pause_reason"]
    assert b.proposer.call_count() == 0


@pytest.mark.parametrize("overrides", [{"check_service": "mock"}, {"victim_repeats": 2}])
def test_b_only_real_victim_keeps_required_checks_and_repeats(tmp_path: Path, overrides: dict[str, Any]) -> None:
    config = _b_only_config(tmp_path)
    with pytest.raises(itl.MethodRuntimeError, match="real B-only"):
        replace(config, **{"victim_source": "dmx", "check_service": "real", **overrides})


def test_b_only_forwards_adaptive_policy_to_baseline_and_variants(tmp_path: Path) -> None:
    source, cid, _ = _source_run(tmp_path)
    b = _b_only(tmp_path / "b", source, cid, victim_concurrency_mode="adaptive", victim_min_concurrency=4, victim_max_concurrency=16)
    assert b.run()["phase"] == itl.PHASE_DONE
    assert len(b.trainer.calls) == 3
    assert all((cfg.concurrency_mode, cfg.min_concurrency, cfg.max_concurrency) == ("adaptive", 4, 16) for cfg in b.trainer.calls)
