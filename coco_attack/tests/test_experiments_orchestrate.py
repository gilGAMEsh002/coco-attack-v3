"""Baseline orchestration: scheduling, recovery and status (phase 03, sub-task 02).

Everything here is offline: the pipeline CLI is replaced by an injected runner
and the baseline root is a synthetic temp manifest built with
``build_manifest`` + ``write_unit_configs``.  No model, Docker or asset access.
"""

from __future__ import annotations

import json
from pathlib import Path

from coco_attack.assets.artifacts import write_json_atomic
from coco_attack.experiments import orchestrate
from coco_attack.experiments.configgen import write_unit_configs
from coco_attack.experiments.manifest import (
    build_manifest,
    load_manifest,
    update_unit_status,
    write_manifest_atomic,
)
from coco_attack.experiments.matrix import expand_units
from coco_attack.experiments.orchestrate import (
    ORCHESTRATOR_LOG,
    run_baseline,
    status_baseline,
)

from test_experiments_matrix import BASELINE_COMBINATIONS, _matrix, _prepared

BASE_COMMIT = "base123"


def _build_root(tmp_path: Path, *, max_unit_retries: int = 2) -> tuple[dict, dict, Path]:
    matrix = _matrix(max_unit_retries=max_unit_retries, baseline_root=str(tmp_path))
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    units = expand_units(matrix, prepared)
    manifest = build_manifest(matrix, units, {"git_commit": BASE_COMMIT}, tmp_path)
    write_unit_configs(tmp_path, matrix, units)
    manifest_path = tmp_path / "manifest" / "run-manifest.json"
    write_manifest_atomic(manifest_path, manifest)
    # ``write_json_atomic`` sorts keys, so read back the persisted order; this is
    # the order ``run_baseline`` iterates.
    return matrix, load_manifest(manifest_path), manifest_path


def _gate(
    monkeypatch,
    *,
    current_commit: str = BASE_COMMIT,
    code_changed: bool | None = False,
) -> None:
    """Bypass the real check-baseline/version probes (no assets/git in tests)."""

    monkeypatch.setattr(orchestrate, "check_baseline", lambda root: 0)
    monkeypatch.setattr(
        orchestrate,
        "git_worktree_status",
        lambda repo_dir: {"dirty": False, "status_sha256": "x", "status_lines": []},
    )
    monkeypatch.setattr(orchestrate, "git_commit", lambda repo_dir: current_commit)
    if code_changed is not None:
        monkeypatch.setattr(
            orchestrate, "code_tree_changed_since", lambda repo_dir, base: code_changed
        )


class FakeRunner:
    """Records argv and lets the test decide what artifacts/exit code to write."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd=None) -> int:
        self.calls.append([str(item) for item in argv])
        if argv[0] == "run-pipeline":
            run_dir = Path(argv[argv.index("--output-dir") + 1])
            resumed = False
        else:
            run_dir = Path(argv[argv.index("--run-dir") + 1])
            resumed = True
        return self.handler(argv, run_dir, resumed)

    def commands(self) -> list[str]:
        return [call[0] for call in self.calls]


def _complete_handler(expected: int = 7):
    def handler(argv, run_dir: Path, resumed: bool) -> int:
        run_dir.mkdir(parents=True, exist_ok=True)
        write_json_atomic(run_dir / "pipeline_config.json", {"run_dir": str(run_dir)})
        write_json_atomic(
            run_dir / "manifest.json",
            {"status": "complete", "report": {"status": "complete"}},
        )
        write_json_atomic(
            run_dir / "report" / "metrics.json",
            {
                "complete": True,
                "sample_count": expected,
                "expected_sample_count": expected,
                "missing_sample_ids": [],
            },
        )
        return 0

    return handler


def _failing_handler():
    def handler(argv, run_dir: Path, resumed: bool) -> int:
        run_dir.mkdir(parents=True, exist_ok=True)
        # run_pipeline writes the frozen config before running any step, so a
        # failed attempt leaves a resumable directory behind.
        write_json_atomic(run_dir / "pipeline_config.json", {"run_dir": str(run_dir)})
        write_json_atomic(run_dir / "manifest.json", {"status": "blocked"})
        return 1

    return handler


def _unit_ids(manifest: dict) -> list[str]:
    return list(manifest["units"])


# --------------------------------------------------------------------------- #
# all-pending fresh execution
# --------------------------------------------------------------------------- #


def test_all_pending_runs_each_fresh_once_and_completes(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    assert run_baseline(tmp_path) == 0

    assert len(runner.calls) == 24
    assert set(runner.commands()) == {"run-pipeline"}
    # manifest persisted with terminal state
    on_disk = load_manifest(manifest_path)
    assert len(on_disk["units"]) == 24
    assert all(unit["status"] == "complete" for unit in on_disk["units"].values())
    for unit in on_disk["units"].values():
        assert unit["attempts"] == 1
        for run in unit["runs"]:
            assert run["status"] == "complete"
            assert run["result"]["exit_code"] == 0
            assert run["result"]["report_complete"] is True
            assert run["result"]["resumed"] is False
            assert run["result"]["attempts"] == 1
    # every unit has unit_start and unit_end events
    events = [
        json.loads(line)
        for line in (tmp_path / ORCHESTRATOR_LOG).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kinds = [event["event"] for event in events]
    assert kinds[0] == "run_start"
    assert kinds[-1] == "run_end"
    assert kinds.count("unit_start") == 24
    assert kinds.count("unit_end") == 24
    assert events[-1]["non_complete_units"] == []


# --------------------------------------------------------------------------- #
# recovery path
# --------------------------------------------------------------------------- #


def test_existing_run_dir_uses_resume_pipeline(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, _path = _build_root(tmp_path)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    unit_id = _unit_ids(manifest)[0]
    run = manifest["units"][unit_id]["runs"][0]
    run_dir = tmp_path / run["run_dir"]
    run_dir.mkdir(parents=True)
    write_json_atomic(run_dir / "pipeline_config.json", {"run_dir": str(run_dir)})

    assert run_baseline(tmp_path) == 0

    assert runner.commands()[0] == "resume-pipeline"
    assert sum(1 for command in runner.commands() if command == "resume-pipeline") == 1
    assert sum(1 for command in runner.commands() if command == "run-pipeline") == 23
    on_disk = load_manifest(tmp_path / "manifest" / "run-manifest.json")
    resumed_result = on_disk["units"][unit_id]["runs"][0]["result"]
    assert resumed_result["resumed"] is True
    assert on_disk["units"][unit_id]["status"] == "complete"


# --------------------------------------------------------------------------- #
# bounded retries -> blocked, loop continues
# --------------------------------------------------------------------------- #


def test_nonzero_exit_retries_then_blocks_and_continues(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path, max_unit_retries=1)
    _gate(monkeypatch)
    failing_unit = _unit_ids(manifest)[0]
    next_unit = _unit_ids(manifest)[1]
    failing_prefix = manifest["units"][failing_unit]["runs"][0]["run_dir"]

    def handler(argv, run_dir: Path, resumed: bool) -> int:
        if str(run_dir).endswith(failing_prefix):
            return _failing_handler()(argv, run_dir, resumed)
        return _complete_handler()(argv, run_dir, resumed)

    runner = FakeRunner(handler)
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    # attempt 1: not complete, below the retry cap -> incomplete, loop continues
    assert run_baseline(tmp_path) == 1
    on_disk = load_manifest(manifest_path)
    assert on_disk["units"][failing_unit]["status"] == "incomplete"
    assert on_disk["units"][failing_unit]["attempts"] == 1
    assert on_disk["units"][next_unit]["status"] == "complete"
    assert runner.commands().count("run-pipeline") == 24  # 23 others + first failing attempt

    # attempt 2 exceeds max_unit_retries=1 -> blocked
    assert run_baseline(tmp_path) == 1
    on_disk = load_manifest(manifest_path)
    assert on_disk["units"][failing_unit]["status"] == "blocked"
    assert on_disk["units"][failing_unit]["attempts"] == 2
    assert on_disk["units"][failing_unit]["runs"][0]["result"]["exit_code"] == 1
    assert on_disk["units"][failing_unit]["runs"][0]["result"]["report_complete"] is False
    # second invocation of the failing unit used the recovery path
    assert runner.commands()[-1] == "resume-pipeline"

    log_events = [
        json.loads(line)
        for line in (tmp_path / ORCHESTRATOR_LOG).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        event["event"] == "unit_blocked" and event["unit_id"] == failing_unit
        for event in log_events
    )


# --------------------------------------------------------------------------- #
# version guard
# --------------------------------------------------------------------------- #


def test_version_mismatch_blocks_all_incomplete_without_running(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path)
    first_unit = _unit_ids(manifest)[0]
    update_unit_status(manifest, first_unit, "complete")
    write_manifest_atomic(manifest_path, manifest)

    _gate(monkeypatch, current_commit="new456", code_changed=True)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    assert run_baseline(tmp_path) == 1
    assert runner.calls == []

    on_disk = load_manifest(manifest_path)
    assert on_disk["units"][first_unit]["status"] == "complete"
    for unit_id, unit in on_disk["units"].items():
        if unit_id == first_unit:
            continue
        assert unit["status"] == "blocked"
        assert any("version_mismatch" in item for item in unit["known_limitations"])


def test_doc_only_advance_does_not_block(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path)
    _gate(monkeypatch, current_commit="new456", code_changed=False)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    assert run_baseline(tmp_path) == 0
    assert len(runner.calls) == 24
    on_disk = load_manifest(manifest_path)
    assert all(unit["status"] == "complete" for unit in on_disk["units"].values())


# --------------------------------------------------------------------------- #
# status-baseline
# --------------------------------------------------------------------------- #


def test_status_baseline_writes_snapshot_without_runner(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path)
    unit_id = _unit_ids(manifest)[0]
    run = manifest["units"][unit_id]["runs"][0]
    run_dir = tmp_path / run["run_dir"]
    run_dir.mkdir(parents=True)
    write_json_atomic(
        run_dir / "report" / "cost_summary.json",
        {
            "roles": {
                "victim": {"events": 3, "cost": {"known": 1.5, "unknown": 1}},
                "local_test": {"events": 2, "cost": {"known": 0.0, "unknown": 0}},
            }
        },
    )
    write_json_atomic(
        run_dir / "functional" / "manifest.json",
        {"cache_hits": 2, "executed": 5, "status": "complete"},
    )
    (run_dir / "ledger.jsonl").write_text(
        json.dumps({"payload": {"reused_from": "resp-1"}}) + "\n"
        + json.dumps({"payload": {"reused_from_first_response": True}}) + "\n",
        encoding="utf-8",
    )
    update_unit_status(manifest, unit_id, "complete")
    write_manifest_atomic(manifest_path, manifest)

    calls: list[list[str]] = []

    def forbidden(argv, cwd=None):
        calls.append(list(argv))
        raise AssertionError("status-baseline must not start a pipeline")

    monkeypatch.setattr(orchestrate, "_default_runner", forbidden)

    assert status_baseline(tmp_path) == 0
    assert calls == []

    snapshot = json.loads(
        (tmp_path / "manifest" / "status.json").read_text(encoding="utf-8")
    )
    assert snapshot["units"][unit_id]["status"] == "complete"
    assert snapshot["totals"]["known_cost"] == 1.5
    assert snapshot["totals"]["unknown_windows"] == 1
    assert snapshot["units"][unit_id]["runs"][0]["cost"]["requests_by_role"] == {
        "victim": 3,
        "local_test": 2,
    }
    assert snapshot["units"][unit_id]["runs"][0]["functional"]["cache_hits"] == 2
    assert snapshot["units"][unit_id]["runs"][0]["reuse"]["reuse_events"] == 2


# --------------------------------------------------------------------------- #
# limit / only selection
# --------------------------------------------------------------------------- #


def test_limit_and_only_select_the_right_units(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, _path = _build_root(tmp_path)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)

    ids = _unit_ids(manifest)
    assert run_baseline(tmp_path, only=[ids[0], ids[1]], limit=1) == 1
    assert len(runner.calls) == 1
    first_run_dir = manifest["units"][ids[0]]["runs"][0]["run_dir"]
    assert str(tmp_path / first_run_dir) in runner.calls[0]

    runner.calls.clear()
    # A scoped invocation reflects its own scope: ids[2] completes, so --only ids[2]
    # exits 0 even though ids[0]/ids[1] remain incomplete.
    assert run_baseline(tmp_path, only=[ids[2]]) == 0
    assert len(runner.calls) == 1
    third_run_dir = manifest["units"][ids[2]]["runs"][0]["run_dir"]
    assert str(tmp_path / third_run_dir) in runner.calls[0]


def test_canary_scope_exit_code_reflects_selected_unit(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, _path = _build_root(tmp_path)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)
    ids = _unit_ids(manifest)
    # a single-unit canary exits 0 even though the whole manifest is unfinished
    assert run_baseline(tmp_path, only=[ids[0]]) == 0
    assert len(runner.calls) == 1


def test_unknown_only_is_usage_error(tmp_path, monkeypatch) -> None:
    _matrix_value, _manifest, _path = _build_root(tmp_path)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)
    assert run_baseline(tmp_path, only=["no-such-unit"]) == 2
    assert runner.calls == []


def test_concurrency_above_one_refused(tmp_path, monkeypatch) -> None:
    _matrix_value, manifest, manifest_path = _build_root(tmp_path)
    manifest["matrix"]["unit_concurrency"] = 2
    write_manifest_atomic(manifest_path, manifest)
    _gate(monkeypatch)
    runner = FakeRunner(_complete_handler())
    monkeypatch.setattr(orchestrate, "_default_runner", runner)
    assert run_baseline(tmp_path) == 2
    assert runner.calls == []
