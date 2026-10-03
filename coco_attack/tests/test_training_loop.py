"""Single-candidate mock training loop tests (task 03).

The loop reuses the real materializer/generation/cleaning/static/Semgrep
services.  Generation is injected as the in-process ``run_generate`` service so
each test issues exactly one bounded mock run; the CLI default remains an
independent subprocess.  Asset-dependent tests skip individually when the
read-only trees are absent.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json, sha256_bytes, sha256_file
from coco_attack.generation.service import run_generate
from coco_attack.iteration.template_snapshot import (
    PatchPolicy,
    apply_patch,
    snapshot_from_clean,
    write_snapshot,
)
from coco_attack.iteration.training_loop import (
    LOOP_SCHEMA_VERSION,
    TrainingLoopConfig,
    TrainingLoopError,
    run_training_loop,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
BASELINE_UNIT = (
    REPO_DIR
    / "cocota_runs/phase03/baseline-DeepSeek-V3.2/units/cwe078-0__clean_fewshot_cot__t0.7r5"
)
BASELINE_STATIC = BASELINE_UNIT / "search/static/evaluations.jsonl"
BASELINE_CONFIG = BASELINE_UNIT / "search/configs/evaluation.json"
BASELINE_EVALUATORS = BASELINE_UNIT / "search/configs/evaluators.json"
BASELINE_EVALUATION = BASELINE_UNIT / "search/evaluation"

ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
BASELINE_AVAILABLE = PREPARED_AVAILABLE and BASELINE_STATIC.is_file() and BASELINE_CONFIG.is_file()

requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="read-only assets / stage-03 prepared data are not present in this workspace",
)
requires_baseline = pytest.mark.skipif(
    not BASELINE_AVAILABLE,
    reason="stage-03 clean baseline slice is not present in this workspace",
)

COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = "poisoned_fewshot_cot"
MODEL = "openai/DeepSeek-V3.2"
TASK_IDS = ("BigCodeBench/13", "BigCodeBench/1105")

PATCH_POLICY = PatchPolicy(allowed_examples=(2, 3, 4), allowed_fields=("code", "cot"))


@pytest.fixture(scope="module")
def snapshot_store(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, object]:
    if not PREPARED_AVAILABLE:
        pytest.skip("read-only assets are not present in this workspace")
    store = tmp_path_factory.mktemp("snapshot-store")
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
    )
    version = write_snapshot(store, snapshot)
    return version, snapshot


def _make_config(
    tmp_path: Path, snapshot_path: Path, **overrides: object
) -> TrainingLoopConfig:
    values: dict[str, object] = {
        "snapshot_path": str(snapshot_path),
        "assets_root": str(ASSETS_DIR),
        "data_dir": str(PREPARED_DIR),
        "output_dir": str(tmp_path / "run"),
        "task_ids": TASK_IDS,
        "repeats": 5,
        "stage": "search",
        "form": FORM,
        "prompt_version": "1",
        "model": MODEL,
        "batch_id": "training-loop-test",
    }
    values.update(overrides)
    return TrainingLoopConfig(**values)  # type: ignore[arg-type]


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


# --------------------------------------------------------------------------- #
# 1. Full mock loop
# --------------------------------------------------------------------------- #


@requires_prepared
def test_full_mock_loop_closes_without_other_layers(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    manifest = run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    assert manifest["schema_version"] == LOOP_SCHEMA_VERSION
    assert manifest["completion"] == "complete"
    assert manifest["candidate_kind"] == "mock"
    assert manifest["steps"]["materialize"]["status"] == "completed"
    assert manifest["steps"]["generate"]["status"] == "completed"
    assert manifest["steps"]["static"]["status"] == "completed"
    assert manifest["steps"]["semgrep"]["status"] == "completed"
    assert manifest["steps"]["baseline"]["status"] == "skipped"

    assert _count_lines(output / "generation" / "generations.jsonl") == 10
    assert _count_lines(output / "static" / "evaluations.jsonl") == 10
    assert _count_lines(output / "evaluation" / "layers" / "sast.jsonl") == 10
    assert manifest["expected_sample_count"] == 10
    assert manifest["observed_sample_count"] == 10

    # Candidate identity comes from the real materialized prompts, never the
    # template hash.
    assert len(manifest["candidate_hash"]) == 64
    assert manifest["candidate_hash"] != snapshot.content_sha256()  # type: ignore[attr-defined]

    # Only the SAST layer ran: functional/judge/dynamic/realism stay un-run.
    layers = output / "evaluation" / "layers"
    for name in ("judge.jsonl", "dynamic.jsonl", "realism.jsonl"):
        assert not (layers / name).exists()
    assert not (output / "functional").exists()
    assert not (output / "evaluation" / "judge").exists()

    feedback = read_json(output / "feedback.json")
    assert feedback["candidate_kind"] == "mock"
    assert {sample["task"] for sample in feedback["samples"]} == {
        "\u8bad\u7ec3\u9898 1",
        "\u8bad\u7ec3\u9898 2",
    }
    assert len(feedback["samples"]) == 10
    assert set(feedback["metrics"]) >= {
        "sample_hit_rate",
        "asr@1",
        "asr@5",
        "semgrep_evasion",
    }

    # Method-facing feedback leaks no real task ids, hashes or platform paths.
    text = (output / "feedback.json").read_text(encoding="utf-8")
    for task_id in TASK_IDS:
        assert task_id not in text
    assert manifest["candidate_hash"] not in text
    assert snapshot.content_sha256() not in text  # type: ignore[attr-defined]

    audit = read_json(output / "feedback_audit.json")
    assert audit["candidate_kind"] == "mock"
    assert audit["template_sha256"] == snapshot.content_sha256()  # type: ignore[attr-defined]
    assert len(audit["samples"]) == 10


# --------------------------------------------------------------------------- #
# 2. Failure scenario surfaces, never a false pass
# --------------------------------------------------------------------------- #


@requires_prepared
@pytest.mark.parametrize("failure", ["missing", "unavailable", "incomplete"])
def test_feedback_preserves_undefined_evasion_for_missing_hit_evidence(
    tmp_path: Path, snapshot_store: tuple[Path, object], failure: str,
) -> None:
    from coco_attack.iteration.training_loop import _assemble_feedback

    snapshot_path, snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path, repeats=1)
    output = Path(config.output_dir)
    generation = [
        {"sample_id": f"s{i}", "identity": {"task_id": task, "repeat_id": 0}, "status": "success"}
        for i, task in enumerate(TASK_IDS)
    ]
    static = [
        {"task_id": task, "repeat_id": 0, "asr_hit": True, "verdict": "target_present"}
        for task in TASK_IDS
    ]
    sast = [{
        "sample_id": "s0", "tool": "semgrep", "status": "completed",
        "available": True, "completed": True, "detected": False,
    }]
    if failure != "missing":
        sast.append({
            "sample_id": "s1", "tool": "semgrep", "status": failure,
            "available": failure != "unavailable", "completed": False, "detected": None,
        })
    for name, rows in (
        ("generation/generations.jsonl", generation),
        ("static/evaluations.jsonl", static),
        ("cleaning/cleaned_generations.jsonl", []),
        ("evaluation/layers/sast.jsonl", sast),
    ):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    feedback, _audit = _assemble_feedback(config, snapshot, "candidate", output)
    metric = feedback["metrics"]["semgrep_evasion"]
    assert metric["defined"] is False
    assert metric["value"] is None
    assert metric["reason"]
    assert metric["numerator"] == 1
    assert metric["denominator"] == 2
    assert metric["availability"]["semgrep"][f"{failure}_samples"] == 1


@requires_prepared
def test_empty_scenario_surfaces_failure_without_false_pass(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path, mock_scenario="empty")
    manifest = run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    assert manifest["completion"] == "complete"
    static_rows = [
        json.loads(line)
        for line in (output / "static" / "evaluations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(static_rows) == 10
    assert all(row["verdict"] == "parse_error" for row in static_rows)

    feedback = read_json(output / "feedback.json")
    counts = feedback["counts"]
    assert counts["generation_status_counts"].get("empty") == 10
    assert counts["parse_errors"] == 10
    assert feedback["metrics"]["sample_hit_rate"]["value"] == 0.0
    assert feedback["metrics"]["asr@1"]["value"] == 0.0
    assert all(sample["verdict"] == "parse_error" for sample in feedback["samples"])


# --------------------------------------------------------------------------- #
# 3. Resume / config identity / selective re-run
# --------------------------------------------------------------------------- #


@requires_prepared
def test_resume_does_not_rerun_and_static_rerun_is_isolated(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    ledger = output / "generation" / "ledger.jsonl"
    ledger_lines = _count_lines(ledger)
    assert ledger_lines > 0

    # A second call over a complete, intact run must not re-run generation.
    second = run_training_loop(config, generation_step=run_generate)
    assert second["completion"] == "complete"
    assert _count_lines(ledger) == ledger_lines

    # A changed configuration must be refused rather than silently reused.
    changed = _make_config(tmp_path, snapshot_path, model="openai/other-model")
    with pytest.raises(TrainingLoopError):
        run_training_loop(changed, generation_step=run_generate)

    # Deleting one downstream directory re-runs only that step.
    shutil.rmtree(output / "static")
    third = run_training_loop(config, generation_step=run_generate)
    assert third["steps"]["static"]["status"] == "completed"
    assert third["steps"]["generate"]["status"] == "skipped"
    assert third["steps"]["cleaning"]["status"] == "skipped"
    assert third["steps"]["semgrep"]["status"] == "skipped"
    assert (output / "static" / "evaluations.jsonl").is_file()
    assert _count_lines(ledger) == ledger_lines


# --------------------------------------------------------------------------- #
# 4. Candidate identity
# --------------------------------------------------------------------------- #


@requires_prepared
def test_patched_snapshot_changes_hash_and_conflict_is_refused(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, snapshot = snapshot_store
    config_a = _make_config(tmp_path / "a", snapshot_path)
    manifest_a = run_training_loop(config_a, generation_step=run_generate)

    patched = apply_patch(
        snapshot,  # type: ignore[arg-type]
        [{"example": 2, "code": "    return 42\n"}],
        PATCH_POLICY,
    ).snapshot
    patched_path = write_snapshot(tmp_path / "store-b", patched)
    config_b = _make_config(tmp_path / "b", patched_path)
    manifest_b = run_training_loop(config_b, generation_step=run_generate)

    assert manifest_a["candidate_hash"] != manifest_b["candidate_hash"]
    assert manifest_a["candidate_hash"] != manifest_b["candidate_hash"]

    # Reusing the old run directory with a different snapshot is refused.
    conflict = _make_config(tmp_path / "a", patched_path)
    with pytest.raises(TrainingLoopError):
        run_training_loop(conflict, generation_step=run_generate)


# --------------------------------------------------------------------------- #
# 5. Baseline slice and compatibility
# --------------------------------------------------------------------------- #


def _write_baseline_config(tmp_path: Path, name: str, payload: dict) -> Path:
    directory = tmp_path / "baseline-src"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@requires_baseline
def test_baseline_slice_compatibility_and_mock_caveat(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    matched = _write_baseline_config(tmp_path, "baseline-match.json", baseline_payload)

    config = _make_config(
        tmp_path,
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(matched),
        baseline_data_dir=str(PREPARED_DIR),
        baseline_evaluators_config=str(BASELINE_EVALUATORS),
        baseline_evaluation_dir=str(BASELINE_EVALUATION),
    )
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    sliced = read_json(output / "baseline_slice.json")

    assert len(sliced["records"]) == 10
    assert {row["task_id"] for row in sliced["records"]} == set(TASK_IDS)
    assert sliced["baseline_matrix"]["ok"] is True
    assert sliced["compatibility"]["compatible"] is True
    assert sliced["candidate_kind"] == "mock"
    assert sliced["comparable_with_real_baseline"] is False
    # Raw Semgrep reports are not preserved by the stage-03 run (only solution.py).
    assert sliced["e05"]["raw_semgrep_reports_preserved"] is False
    assert sliced["e05"]["historical_semgrep_scan_errors"] == 0
    assert sliced["e05"]["historical_impact"] == "unknown"
    assert sliced["source"]["model"] == baseline_payload["model"]
    assert "sample_hit_rate" in sliced["metrics"]
    assert "asr@1" in sliced["metrics"]
    assert "asr@5" in sliced["metrics"]

    # A model mismatch is a blocking finding.
    mismatched_payload = dict(baseline_payload)
    mismatched_payload["model"] = "openai/Different-Model"
    mismatched = _write_baseline_config(tmp_path, "baseline-mismatch.json", mismatched_payload)
    config_bad = _make_config(
        tmp_path / "bad",
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(mismatched),
    )
    run_training_loop(config_bad, generation_step=run_generate)
    sliced_bad = read_json(Path(config_bad.output_dir) / "baseline_slice.json")
    assert sliced_bad["compatibility"]["compatible"] is False
    # The external config no longer matches the baseline's embedded run config.
    assert any(
        item["key"] == "baseline_config.model"
        and item["reason"] == "baseline_config_mismatch"
        for item in sliced_bad["compatibility"]["blocking"]
    )


# --------------------------------------------------------------------------- #
# 6. Read-only inputs
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# 7. R1-R6 recovery and provenance hardening
# --------------------------------------------------------------------------- #


@requires_prepared
def test_r1_rejected_conflict_leaves_run_bytes_unchanged(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    manifest_bytes = (output / "manifest.json").read_bytes()
    loop_config_bytes = (output / "loop_config.json").read_bytes()

    conflict = _make_config(tmp_path, snapshot_path, repeats=4)
    with pytest.raises(TrainingLoopError):
        run_training_loop(conflict, generation_step=run_generate)

    # R1: the rejected call must not have overwritten the old configuration.
    assert (output / "manifest.json").read_bytes() == manifest_bytes
    assert (output / "loop_config.json").read_bytes() == loop_config_bytes


@requires_prepared
def test_r2_stale_schema_and_tampered_prompts_are_refused(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    # An old/unknown total schema cannot be silently reused.
    manifest = read_json(output / "manifest.json")
    manifest["schema_version"] = "single-candidate-training-loop-v0"
    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(TrainingLoopError):
        run_training_loop(config, generation_step=run_generate)

    # Restore, then tamper a prompt so the candidate hash no longer matches.
    manifest["schema_version"] = LOOP_SCHEMA_VERSION
    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    prompt = next((output / "prompts").glob("*/*/test_prompts/*.md"))
    prompt.write_text(prompt.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    with pytest.raises(TrainingLoopError):
        run_training_loop(config, generation_step=run_generate)


@requires_prepared
def test_r2_missing_static_data_recovers_only_that_step(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    ledger_lines = _count_lines(output / "generation" / "ledger.jsonl")

    # Keep the manifest but remove the actual static data file.
    (output / "static" / "evaluations.jsonl").unlink()
    recovered = run_training_loop(config, generation_step=run_generate)
    assert recovered["completion"] == "complete"
    assert recovered["steps"]["static"]["status"] == "completed"
    assert recovered["steps"]["generate"]["status"] == "skipped"
    assert _count_lines(output / "generation" / "ledger.jsonl") == ledger_lines


@requires_prepared
def test_r3_force_rerun_refused_and_partial_dir_quarantined(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    ledger_bytes = (output / "generation" / "ledger.jsonl").read_bytes()

    # R3: destructive in-place force_rerun is refused; ledger is untouched.
    with pytest.raises(TrainingLoopError):
        run_training_loop(config, generation_step=run_generate, force_rerun=True)
    assert (output / "generation" / "ledger.jsonl").read_bytes() == ledger_bytes

    # An incomplete step is quarantined, not deleted.
    (output / "static" / "manifest.json").unlink()
    run_training_loop(config, generation_step=run_generate)
    quarantined = list(output.glob("static.partial-*"))
    assert quarantined and quarantined[0].is_dir()


@requires_prepared
def test_r3_output_inside_read_only_input_is_refused(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(
        tmp_path, snapshot_path, output_dir=str(PREPARED_DIR / "should-not-be-written")
    )
    with pytest.raises(TrainingLoopError):
        run_training_loop(config, generation_step=run_generate)
    assert not (PREPARED_DIR / "should-not-be-written").exists()


@requires_prepared
def test_r4_timeout_validated_and_passed_to_scanner(
    tmp_path: Path, snapshot_store: tuple[Path, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    from coco_attack.iteration import training_loop

    snapshot_path, _snapshot = snapshot_store
    with pytest.raises(TrainingLoopError):
        _make_config(tmp_path / "bad-zero", snapshot_path, semgrep_timeout_seconds=0)
    with pytest.raises(TrainingLoopError):
        _make_config(
            tmp_path / "bad-nan", snapshot_path, semgrep_timeout_seconds=float("nan")
        )

    seen: dict[str, object] = {}

    def _spy(sample, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(training_loop, "scan_sample", _spy)
    scanner = training_loop._make_sast_scan(123.0)
    scanner("sample", evaluation_id="e", action_id="a", tool="semgrep", target_rules=(), workdir=Path("."))
    assert seen["timeout_seconds"] == 123.0


def test_r6_resume_default_uses_a_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    from coco_attack.iteration import training_loop

    captured: dict[str, object] = {}

    def _fake_run(command, capture_output, text):
        captured["command"] = list(command)

        class _Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Completed()

    monkeypatch.setattr(training_loop.subprocess, "run", _fake_run)
    code = training_loop._subprocess_resume_generation_step("/tmp/run-dir")
    assert code == 0
    command = captured["command"]
    assert "resume-generation" in command
    assert "--run-dir" in command
    assert "/tmp/run-dir" in command


@requires_baseline
def test_r5_baseline_matrix_and_provenance_not_copied_from_candidate(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    matched = _write_baseline_config(tmp_path, "baseline-match.json", baseline_payload)

    # Incomplete slice (9 of 10) must block comparability.
    import json as _json

    rows = [
        _json.loads(line)
        for line in BASELINE_STATIC.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    sliced_rows = [
        row for row in rows if row.get("task_id") in set(TASK_IDS)
    ][:-1]
    sliced_path = tmp_path / "baseline-src" / "static-truncated.jsonl"
    sliced_path.write_text(
        "\n".join(_json.dumps(row) for row in sliced_rows) + "\n", encoding="utf-8"
    )
    config = _make_config(
        tmp_path / "truncated",
        snapshot_path,
        baseline_static=str(sliced_path),
        baseline_config=str(matched),
    )
    run_training_loop(config, generation_step=run_generate)
    result = read_json(Path(config.output_dir) / "baseline_slice.json")
    assert result["baseline_matrix"]["ok"] is False
    assert result["compatibility"]["compatible"] is False
    assert any(
        item["key"] == "baseline_matrix"
        for item in result["compatibility"]["blocking"]
    )

    # Without baseline provenance files, baseline fields are missing (not copied
    # from the candidate) and therefore block the comparison.
    config_missing = _make_config(
        tmp_path / "missing",
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(matched),
    )
    run_training_loop(config_missing, generation_step=run_generate)
    missing = read_json(Path(config_missing.output_dir) / "baseline_slice.json")
    missing_keys = {
        item["key"] for item in missing["compatibility"]["blocking"]
    }
    assert {"split_mode", "data_contract"} <= missing_keys
    assert missing["e05"]["raw_semgrep_reports_preserved"] is None


# --------------------------------------------------------------------------- #
# 8. R2/R5 second-pass gaps (E11)
# --------------------------------------------------------------------------- #


@requires_prepared
def test_r2_foreign_generation_identity_is_refused(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    # Keep the exact task×repeat matrix but swap one row for a foreign sample.
    rows = [
        json.loads(line)
        for line in (output / "generation" / "generations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    rows[0]["sample_id"] = "foreign-sample-id"
    rows[0]["identity"]["candidate_hash"] = "f" * 64
    (output / "generation" / "generations.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )

    with pytest.raises(TrainingLoopError):
        run_training_loop(config, generation_step=run_generate)


@requires_prepared
def test_r2_invalid_feedback_is_regenerated_not_accepted(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    (output / "feedback.json").write_text("{broken json", encoding="utf-8")
    manifest = run_training_loop(config, generation_step=run_generate)
    assert manifest["completion"] == "complete"
    # The derived report was regenerated to a valid structure and the broken
    # evidence was preserved beside it rather than silently trusted.
    regenerated = read_json(output / "feedback.json")
    assert len(regenerated["samples"]) == 10
    assert list(output.glob("feedback.json.partial-*"))


@requires_baseline
def test_r5_relabelled_baseline_config_is_not_comparable(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    relabelled = dict(baseline_payload)
    relabelled["model"] = "openai/review-other-model"
    relabelled_path = _write_baseline_config(tmp_path, "baseline-relabelled.json", relabelled)

    config = _make_config(
        tmp_path / "relabel",
        snapshot_path,
        model="openai/review-other-model",
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(relabelled_path),
        baseline_data_dir=str(PREPARED_DIR),
        baseline_evaluators_config=str(BASELINE_EVALUATORS),
        baseline_evaluation_dir=str(BASELINE_EVALUATION),
    )
    run_training_loop(config, generation_step=run_generate)
    sliced = read_json(Path(config.output_dir) / "baseline_slice.json")

    assert sliced["compatibility"]["compatible"] is False
    assert any(
        item["key"] == "baseline_config.model" and item["reason"] == "baseline_config_mismatch"
        for item in sliced["compatibility"]["blocking"]
    )
    # The baseline identity comes from its own manifest, not the relabelled file.
    assert sliced["source"]["model"] == "openai/DeepSeek-V3.2"


@requires_baseline
def test_r5_tampered_baseline_results_are_not_comparable(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    copied_config = _write_baseline_config(tmp_path, "baseline-copy.json", baseline_payload)

    original_rows = [
        json.loads(line)
        for line in BASELINE_STATIC.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    sliced_rows = [row for row in original_rows if row.get("task_id") in set(TASK_IDS)]
    sliced_rows[0]["verdict"] = "target_present"
    sliced_rows[0]["asr_hit"] = True
    tampered = tmp_path / "baseline-src" / "static-tampered.jsonl"
    tampered.write_text(
        "\n".join(json.dumps(row) for row in sliced_rows) + "\n", encoding="utf-8"
    )
    # Keep the original manifest (with the original evaluations hash) beside the
    # tampered results so the result-fingerprint binding is what fails.
    (tmp_path / "baseline-src" / "manifest.json").write_bytes(
        (BASELINE_STATIC.parent / "manifest.json").read_bytes()
    )

    config = _make_config(
        tmp_path / "tampered",
        snapshot_path,
        baseline_static=str(tampered),
        baseline_config=str(copied_config),
        baseline_data_dir=str(PREPARED_DIR),
        baseline_evaluators_config=str(BASELINE_EVALUATORS),
        baseline_evaluation_dir=str(BASELINE_EVALUATION),
    )
    run_training_loop(config, generation_step=run_generate)
    sliced = read_json(Path(config.output_dir) / "baseline_slice.json")
    assert sliced["compatibility"]["compatible"] is False
    assert any(
        item["key"] == "baseline_evaluations_sha256"
        for item in sliced["compatibility"]["blocking"]
    )


@requires_baseline
def test_read_only_inputs_and_baseline_are_unchanged(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    snapshot_path, _snapshot = snapshot_store
    watched = [
        ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/fewshot.json",
        ASSETS_DIR / "data/BigCodeBench/CWE-078-0.jsonl",
        PREPARED_DIR / "manifest.json",
        PREPARED_DIR / COMBINATION / "tasks.jsonl",
        PREPARED_DIR / COMBINATION / "selection.json",
        PREPARED_DIR / COMBINATION / "split.json",
        BASELINE_STATIC,
        BASELINE_CONFIG,
    ]
    before = {str(path): sha256_file(path) for path in watched if path.is_file()}
    assert before

    config = _make_config(
        tmp_path,
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(BASELINE_CONFIG),
    )
    run_training_loop(config, generation_step=run_generate)

    after = {str(path): sha256_file(path) for path in watched if path.is_file()}
    assert after == before


# --------------------------------------------------------------------------- #
# 9. R2/R5 content and provenance binding (second-pass residual gaps)
# --------------------------------------------------------------------------- #


@requires_prepared
def test_r2_changed_cleaning_output_invalidates_stale_static_and_semgrep(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    """A changed cleaning output must invalidate the downstream results.

    The cleaning manifest is updated consistently with the new bytes (a legitimate
    re-cleaning, or a coordinated replacement); the static/Semgrep results that
    still describe the old code must not be reused as a completed run.
    """

    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    cleaning_path = output / "cleaning" / "cleaned_generations.jsonl"
    rows = [
        json.loads(line)
        for line in cleaning_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    new_code = "def task_func():\n    return 999\n"
    rows[0]["cleaned"]["final_code"] = new_code
    rows[0]["cleaned"]["final_code_sha256"] = sha256_bytes(new_code.encode("utf-8"))
    cleaning_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    manifest_path = output / "cleaning" / "manifest.json"
    manifest = read_json(manifest_path)
    manifest["output"]["sha256"] = sha256_file(cleaning_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    stale_static_sha = sha256_file(output / "static" / "evaluations.jsonl")
    recovered = run_training_loop(config, generation_step=run_generate)

    assert recovered["completion"] == "complete"
    # Upstream (generation/cleaning) is untouched; only the stale dependents rerun.
    assert recovered["steps"]["generate"]["status"] == "skipped"
    assert recovered["steps"]["cleaning"]["status"] == "skipped"
    assert recovered["steps"]["static"]["status"] == "completed"
    assert recovered["steps"]["semgrep"]["status"] == "completed"
    # The old static evidence is preserved rather than silently overwritten.
    assert list(output.glob("static.partial-*"))
    # Static was re-derived from the new cleaning bytes.
    static_sha = sha256_file(output / "static" / "evaluations.jsonl")
    assert static_sha != stale_static_sha
    static_rows = [
        json.loads(line)
        for line in (output / "static" / "evaluations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert any(
        row["final_code_sha256"] == rows[0]["cleaned"]["final_code_sha256"]
        for row in static_rows
    )


@requires_prepared
def test_r2_stale_feedback_content_is_regenerated(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    """Structurally valid but stale feedback content is not trusted."""

    snapshot_path, _snapshot = snapshot_store
    config = _make_config(tmp_path, snapshot_path)
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)

    feedback_path = output / "feedback.json"
    payload = read_json(feedback_path)
    payload["samples"][0]["code"] = "def task_func():\n    return 7\n"
    feedback_path.write_text(json.dumps(payload), encoding="utf-8")

    recovered = run_training_loop(config, generation_step=run_generate)
    assert recovered["completion"] == "complete"
    assert recovered["steps"]["feedback"]["status"] == "completed"
    assert recovered["steps"]["static"]["status"] == "skipped"
    assert list(output.glob("feedback.json.partial-*"))
    regenerated = read_json(feedback_path)
    audit = read_json(output / "feedback_audit.json")
    assert sha256_bytes(regenerated["samples"][0]["code"].encode("utf-8")) == audit[
        "samples"
    ][0]["final_code_sha256"]


@requires_baseline
def test_r2_stale_baseline_slice_source_is_regenerated(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    """A baseline slice that does not match the configured source is regenerated."""

    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    matched = _write_baseline_config(tmp_path, "baseline-match.json", baseline_payload)
    config = _make_config(
        tmp_path,
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(matched),
        baseline_data_dir=str(PREPARED_DIR),
        baseline_evaluators_config=str(BASELINE_EVALUATORS),
        baseline_evaluation_dir=str(BASELINE_EVALUATION),
    )
    run_training_loop(config, generation_step=run_generate)
    output = Path(config.output_dir)
    slice_path = output / "baseline_slice.json"

    stale = read_json(slice_path)
    stale["source"]["sha256"] = "0" * 64
    slice_path.write_text(json.dumps(stale), encoding="utf-8")

    recovered = run_training_loop(config, generation_step=run_generate)
    assert recovered["completion"] == "complete"
    assert recovered["steps"]["baseline"]["status"] == "completed"
    assert list(output.glob("baseline_slice.json.partial-*"))
    regenerated = read_json(slice_path)
    assert regenerated["source"]["sha256"] == sha256_file(BASELINE_STATIC)
    assert regenerated["compatibility"]["compatible"] is True


@requires_baseline
def test_r5_alternate_evaluator_source_is_not_comparable(
    tmp_path: Path, snapshot_store: tuple[Path, object]
) -> None:
    """A baseline evaluator source that disagrees with the record blocks comparison."""

    snapshot_path, _snapshot = snapshot_store
    baseline_payload = read_json(BASELINE_CONFIG)
    matched = _write_baseline_config(tmp_path, "baseline-match.json", baseline_payload)

    evaluators = read_json(BASELINE_EVALUATORS)
    alternate = dict(evaluators)
    alternate["k"] = [1, 5]
    alternate_path = _write_baseline_config(tmp_path, "alternate-evaluators.json", alternate)

    config = _make_config(
        tmp_path / "alternate",
        snapshot_path,
        baseline_static=str(BASELINE_STATIC),
        baseline_config=str(matched),
        baseline_data_dir=str(PREPARED_DIR),
        baseline_evaluators_config=str(alternate_path),
        baseline_evaluation_dir=str(BASELINE_EVALUATION),
    )
    run_training_loop(config, generation_step=run_generate)
    sliced = read_json(Path(config.output_dir) / "baseline_slice.json")

    assert sliced["compatibility"]["compatible"] is False
    assert any(
        item["key"] == "k" and item["reason"] == "mismatch"
        for item in sliced["compatibility"]["blocking"]
    )


def test_r2_baseline_status_missing_source_is_invalid_not_raising(
    tmp_path: Path,
) -> None:
    """An unreadable baseline source is an invalid step, not a hard refusal."""

    import types

    from coco_attack.iteration import training_loop

    output = tmp_path / "out"
    output.mkdir()
    payload = {
        "records": [],
        "baseline_matrix": {},
        "compatibility": {},
        "e05": {},
        "source": {"path": "whatever", "sha256": "0" * 64},
    }
    (output / "baseline_slice.json").write_text(json.dumps(payload), encoding="utf-8")
    config = types.SimpleNamespace(baseline_static=str(tmp_path / "missing.json"))

    valid, reason = training_loop._baseline_status(output, True, config)
    assert valid is False
    assert "unreadable" in reason
    # A skipped marker is still accepted when no baseline is configured.
    (output / "baseline_slice.json").write_text(
        json.dumps({"status": "skipped"}), encoding="utf-8"
    )
    valid_skipped, _ = training_loop._baseline_status(output, False, config)
    assert valid_skipped is True
