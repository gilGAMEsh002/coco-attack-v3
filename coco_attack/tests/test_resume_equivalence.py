"""Resume equivalence and evaluation identity (batch-2 B6/B10).

Offline only: no Docker and no model request.  These assert that a resumed
other-evaluator run restores its persisted execution context and evaluation
identity, and that the evaluation identity is stable per run directory.
"""

from __future__ import annotations

import json
from pathlib import Path

from coco_attack.evaluation.run_other import _derive_evaluation_id, run_resume_other


def test_derive_evaluation_id_is_stable_per_directory(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    run_a.mkdir()
    run_b.mkdir()
    assert _derive_evaluation_id(run_a) == _derive_evaluation_id(run_a)
    assert _derive_evaluation_id(run_a) != _derive_evaluation_id(run_b)
    assert _derive_evaluation_id(run_a).startswith("ev-")


def test_resume_other_restores_execution_context(tmp_path: Path, monkeypatch) -> None:
    import coco_attack.evaluation.run_other as run_other

    run = tmp_path / "run"
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "evaluation_id": "ev-abc",
                "inputs": {
                    "data_dir": str(tmp_path / "data"),
                    "generation_run": str(tmp_path / "generation"),
                    "cleaned_dir": str(tmp_path / "cleaned"),
                    "execution_config": "/persist/exec.json",
                    "evaluation_id": "ev-abc",
                    "ledger": "/persist/ledger.jsonl",
                },
            }
        ),
        encoding="utf-8",
    )
    (run / "config.json").write_text(
        json.dumps(
            {"combination_id": "cwe078-0", "oracle_id": "cwe078-0", "stage": "search"}
        ),
        encoding="utf-8",
    )
    captured: dict = {}

    def _fake(*args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(run_other, "run_evaluate_other", _fake)
    assert run_other.run_resume_other(run) == 0
    assert captured["execution_config_path"] == "/persist/exec.json"
    assert captured["evaluation_id"] == "ev-abc"
    # The 5th positional argument to run_evaluate_other is the ledger path.
    assert captured["args"][4] == "/persist/ledger.jsonl"
