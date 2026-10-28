"""Offline CLI tests for the evidence_guided_search commands."""

from __future__ import annotations

import json
from pathlib import Path

from coco_attack.cli import EXIT_BLOCKING, EXIT_USAGE, build_parser, main

_REPO = Path(__file__).resolve().parents[1]
_PENDING = _REPO / "configs/evidence_guided_search/pending.json"


def test_egs_commands_are_registered() -> None:
    parser = build_parser()

    check = parser.parse_args(
        [
            "check-evidence-guided-search",
            "--config",
            str(_PENDING),
            "--project-root",
            str(_REPO),
            "--stage",
            "run",
        ]
    )
    assert check.command == "check-evidence-guided-search"
    assert check.stage == "run"

    run = parser.parse_args(
        [
            "run-evidence-guided-search",
            "--config",
            str(_PENDING),
            "--project-root",
            str(_REPO),
            "--run-dir",
            "run",
        ]
    )
    assert run.command == "run-evidence-guided-search"

    for command in (
        "resume-evidence-guided-search",
        "status-evidence-guided-search",
        "pause-evidence-guided-search",
    ):
        args = parser.parse_args([command, "--run-dir", "run"])
        assert args.command == command


def test_check_pending_template_reports_gaps_as_json(capsys) -> None:
    code = main(
        [
            "check-evidence-guided-search",
            "--config",
            str(_PENDING),
            "--project-root",
            str(_REPO),
            "--stage",
            "run",
        ]
    )

    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_BLOCKING
    assert out["status"] == "blocked"
    assert out["stage"] == "run"
    assert out["gaps"]


def test_check_pending_template_at_roles_stage_is_blocked(capsys) -> None:
    code = main(
        [
            "check-evidence-guided-search",
            "--config",
            str(_PENDING),
            "--project-root",
            str(_REPO),
            "--stage",
            "roles",
        ]
    )

    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_BLOCKING
    assert any("template_dir" in gap for gap in out["gaps"])


def test_run_blocks_before_initialize_when_config_is_incomplete(
    tmp_path: Path, capsys
) -> None:
    run_dir = tmp_path / "run"

    code = main(
        [
            "run-evidence-guided-search",
            "--config",
            str(_PENDING),
            "--project-root",
            str(_REPO),
            "--run-dir",
            str(run_dir),
        ]
    )

    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_BLOCKING
    assert out["status"] == "blocked"
    assert out["gaps"]
    assert not run_dir.exists()


def test_status_rejects_a_directory_without_run_json(tmp_path: Path, capsys) -> None:
    code = main(
        ["status-evidence-guided-search", "--run-dir", str(tmp_path)]
    )

    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "run.json" in captured.err
