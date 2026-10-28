"""Targeted checks for the EGS public-service adapter.

Public service internals are not re-tested here.  Generation is a subprocess
boundary and every public evaluation service is replaced by a fixed response
that writes the same raw artifact shape the real service writes.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from coco_attack.iteration.template_snapshot import TemplateSnapshot
from coco_methods.evidence_guided_search import public_services as ps

COMBINATION = "cwe078-0"
SEARCH = ("t1", "t2")
HOLDOUT = ("t3", "t4")


def _prepared():
    return SimpleNamespace(
        combination_id=COMBINATION,
        oracle_id=COMBINATION,
        split=SimpleNamespace(search_ids=SEARCH, holdout_ids=HOLDOUT),
    )


def _snapshot():
    return TemplateSnapshot(
        COMBINATION, "poisoned_fewshot_cot", "1", "poison-template-v1",
        "cf", "first_sentence_end", "instruction_injection", (),
    )


def _settings(tmp_path: Path, **overrides):
    settings = {
        "assets_root": str(tmp_path / "assets"),
        "data_dir": str(tmp_path / "data"),
        "task_ids": list(SEARCH),
        "repeats": 1,
        "stage": "search",
        "generation": {
            "source": "mock", "model": "mock-model", "batch_id": "batch-1",
            "temperature": 0.0, "max_tokens": 32, "request_timeout": 5.0,
            "max_concurrency": 1, "max_request_attempts": 1,
            "max_sample_retries": 0,
        },
        "evaluators": {
            "sast_tools": ["semgrep"], "semgrep_config": None,
            "codeql_executable": None, "codeql_search_path": None,
        },
        "functional": {
            "k": [1], "harness_version": "test-harness",
            "candidate_timeout_seconds": 1.0,
        },
        "execution_config_path": str(tmp_path / "execution.json"),
        "cache_dir": str(tmp_path / "cache"),
    }
    settings.update(overrides)
    return settings


def _write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _install_fakes(monkeypatch, tmp_path: Path):
    calls: dict[str, list] = {"generation": [], "materialize": [], "cleaning": [],
                              "static": [], "sast": [], "functional": []}

    def fake_materialize(**kwargs):
        calls["materialize"].append(kwargs)
        _write_json(Path(kwargs["output_dir"]) / "manifest.json", {"completion": "complete"})
        return {"task_ids": list(kwargs["task_ids"])}

    def fake_run(args, **kwargs):
        command = args[3]
        calls["generation"].append(command)
        output = Path(args[args.index("--output-dir") + 1]) if command == "generate" else Path(
            args[args.index("--run-dir") + 1]
        )
        _write_json(output / "run_config.json", {"config": {"stage": "search"}})
        _write_jsonl(output / "ledger.jsonl", [])
        _write_jsonl(output / "generations.jsonl", [
            {"task_id": task_id, "repeat_id": 0, "status": "success",
             "generation": f"code-{task_id}", "cwe": COMBINATION}
            for task_id in SEARCH
        ])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_clean(prepared, input_jsonl, output_dir, legacy_alias=None):
        calls["cleaning"].append(str(output_dir))
        _write_jsonl(Path(output_dir) / "cleaned_generations.jsonl", [
            {"task_id": task_id, "repeat_id": 0, "cleaned": {"final_code": "x"}}
            for task_id in SEARCH
        ])
        _write_json(Path(output_dir) / "manifest.json", {"completed": True})
        return 0

    def fake_static(assets_root, data_dir, cleaned_dir, config_path, output_dir):
        calls["static"].append(str(output_dir))
        _write_jsonl(Path(output_dir) / "evaluations.jsonl", [
            {"task_id": task_id, "repeat_id": 0, "verdict": "target_present"}
            for task_id in SEARCH
        ])
        _write_json(Path(output_dir) / "manifest.json", {"completion": "complete"})
        return 0

    def fake_sast(config_path, data_dir, generation_run, cleaned_dir, ledger_path,
                  output_dir, **kwargs):
        calls["sast"].append("evaluate-other")
        _write_jsonl(Path(output_dir) / "layers" / "sast.jsonl", [
            {"task_id": task_id, "tool": "semgrep", "detected": False}
            for task_id in SEARCH
        ])
        _write_json(Path(output_dir) / "manifest.json", {"status": "complete"})
        return 0

    def fake_sast_resume(run_dir):
        calls["sast"].append("resume-other")
        _write_jsonl(Path(run_dir) / "layers" / "sast.jsonl", [
            {"task_id": task_id, "tool": "semgrep", "detected": False}
            for task_id in SEARCH
        ])
        return 0

    def fake_functional(config_path, data_dir, generation_run, cleaned_dir,
                        execution_config_path, cache_dir, output_dir, **kwargs):
        calls["functional"].append("evaluate-functional")
        _write_json(Path(output_dir) / "functional_config.json", {"config": {}})
        _write_jsonl(Path(output_dir) / "functional_results.jsonl", [
            {"task_id": task_id, "passed": True} for task_id in SEARCH
        ])
        _write_json(Path(output_dir) / "manifest.json", {"status": "complete"})
        return 0

    def fake_functional_resume(run_dir):
        calls["functional"].append("resume-functional")
        _write_jsonl(Path(run_dir) / "functional_results.jsonl", [
            {"task_id": task_id, "passed": True} for task_id in SEARCH
        ])
        return 0

    monkeypatch.setattr(ps, "load_prepared_data", lambda *a, **k: _prepared())
    monkeypatch.setattr(ps, "materialize_poisoned", fake_materialize)
    monkeypatch.setattr(ps.subprocess, "run", fake_run)
    monkeypatch.setattr(ps, "clean_generations", fake_clean)
    monkeypatch.setattr(ps, "evaluate_static", fake_static)
    monkeypatch.setattr(ps, "run_evaluate_other", fake_sast)
    monkeypatch.setattr(ps, "run_resume_other", fake_sast_resume)
    monkeypatch.setattr(ps, "run_evaluate_functional", fake_functional)
    monkeypatch.setattr(ps, "run_resume_functional", fake_functional_resume)
    return calls


def test_public_measure_returns_raw_layers_and_resumes(tmp_path, monkeypatch):
    calls = _install_fakes(monkeypatch, tmp_path)
    result = ps.public_measure(_snapshot(), tmp_path / "out", _settings(tmp_path))

    assert result["gaps"] == []
    assert len(result["generation_rows"]) == 2
    assert len(result["cleaned_rows"]) == 2
    assert len(result["static_rows"]) == 2
    assert len(result["sast_rows"]) == 2
    assert len(result["functional_rows"]) == 2
    assert calls["generation"] == ["generate"]
    assert calls["materialize"][0]["task_ids"] == list(SEARCH)
    assert any(ref.endswith("generation/ledger.jsonl") for ref in result["consumption_refs"])

    # Re-entry uses the public resume entry points and does not call generate again.
    again = ps.public_measure(_snapshot(), tmp_path / "out", _settings(tmp_path))
    assert again["gaps"] == []
    assert calls["generation"] == ["generate", "resume-generation"]
    assert calls["sast"][-1] == "resume-other"
    assert calls["functional"][-1] == "resume-functional"


def test_public_measure_rejects_task_ids_outside_stage_split(tmp_path, monkeypatch):
    _install_fakes(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="not in the public search split"):
        ps.public_measure(
            _snapshot(), tmp_path / "out",
            _settings(tmp_path, task_ids=list(HOLDOUT)),
        )


def test_public_measure_refuses_changed_fixed_config(tmp_path, monkeypatch):
    _install_fakes(monkeypatch, tmp_path)
    ps.public_measure(_snapshot(), tmp_path / "out", _settings(tmp_path))
    changed = _settings(tmp_path)
    changed["generation"]["temperature"] = 0.7
    with pytest.raises(ValueError, match="different configuration"):
        ps.public_measure(_snapshot(), tmp_path / "out", changed)


def test_functional_failure_keeps_oracle_and_sast_rows(tmp_path, monkeypatch):
    _install_fakes(monkeypatch, tmp_path)

    def broken_functional(*args, **kwargs):
        raise RuntimeError("docker unavailable")

    monkeypatch.setattr(ps, "run_evaluate_functional", broken_functional)
    result = ps.public_measure(_snapshot(), tmp_path / "out", _settings(tmp_path))

    assert len(result["static_rows"]) == 2
    assert len(result["sast_rows"]) == 2
    assert result["functional_rows"] == []
    assert any(gap.startswith("functional: RuntimeError: docker unavailable")
               for gap in result["gaps"])
