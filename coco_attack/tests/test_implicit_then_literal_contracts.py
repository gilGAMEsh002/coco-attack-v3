"""Contract/identity/baseline tests for ``implicit_then_literal`` (subplan 01).

Asset-dependent baseline checks are gated individually so the pure contract
logic still runs when the read-only CoCo-Attack assets are absent.  Hashes are
recomputed from real bytes; the real baseline is never written to.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_file
from coco_attack.iteration.template_snapshot import (
    ExampleTemplate,
    TemplateSnapshot,
    write_snapshot,
)
from coco_methods import implicit_then_literal as itl

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_AVAILABLE = (REPO_DIR / "cocota_data_eval_result").is_dir()
requires_assets = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)

EXPERIMENT_REL = (
    "cocota_data_eval_result/prompts_shared/experiments/cwe078/"
    "cwe078_initial_poisoned_code_shell_true_cot_clean"
)
SNAPSHOT_REL = (
    EXPERIMENT_REL
    + "/snapshot_store/cwe078-0/"
    + itl.FIXED_BASELINE_CONTENT_SHA256
    + "/snapshot.json"
)


def _synthetic_snapshot() -> TemplateSnapshot:
    examples = tuple(
        ExampleTemplate(
            task_id=f"BigCodeBench/{number}",
            instruct_prompt="placeholder",
            code="    pass\n",
            cot="Step 1.",
            is_poisoned=False,
            trigger=None,
            poison_parts=(),
        )
        for number in range(1, 5)
    )
    return TemplateSnapshot(
        combination_id="cwe078-0",
        form="poisoned_fewshot_cot",
        prompt_version="1",
        protocol_version="poison-template-v1",
        trigger="cf",
        injection_position="first_sentence_end",
        mode="instruction_injection",
        examples=examples,
    )


def _copy_baseline(tmp_path: Path) -> Path:
    source = REPO_DIR / EXPERIMENT_REL
    destination = tmp_path / EXPERIMENT_REL
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    return tmp_path


# --------------------------------------------------------------------------- #
# Method / protocol identity
# --------------------------------------------------------------------------- #


def test_method_identity_is_distinct_from_the_old_method() -> None:
    from coco_methods.single_candidate_ab import (
        METHOD_PROTOCOL_VERSION,
        METHOD_SCHEMA_VERSION,
    )

    assert itl.IMPLICIT_THEN_LITERAL_METHOD_ID == "implicit_then_literal"
    assert itl.IMPLICIT_THEN_LITERAL_METHOD_ID != "single_candidate_ab"
    assert itl.IMPLICIT_THEN_LITERAL_SCHEMA_VERSION != METHOD_SCHEMA_VERSION
    assert itl.IMPLICIT_THEN_LITERAL_PROTOCOL_VERSION != METHOD_PROTOCOL_VERSION
    assert itl.METHOD_STAGES == ("A", "B")


def test_importing_the_new_package_keeps_the_old_top_level_surface() -> None:
    import coco_methods as method_top

    # The old frozen public list must not gain or lose names because of the new
    # package import.
    assert len(method_top.__all__) == 20
    assert method_top.__all__ == [
        "METHOD_PROTOCOL_VERSION",
        "METHOD_SCHEMA_VERSION",
        "PREFLIGHT_SCHEMA_VERSION",
        "GateResult",
        "MethodConfig",
        "MethodError",
        "MethodInterrupted",
        "MethodRun",
        "MockGateChecker",
        "MockTraining",
        "MutatorRole",
        "ScriptedMutator",
        "VictimRole",
        "build_preflight_report",
        "dmx_mutator_source_factory",
        "evaluate_example_gate",
        "load_method_config",
        "mutator_cache_configurer",
        "mutator_role_config",
        "run_method",
    ]
    for name in method_top.__all__:
        assert hasattr(method_top, name), name


# --------------------------------------------------------------------------- #
# Logical candidate identity
# --------------------------------------------------------------------------- #


def test_candidate_identity_is_deterministic() -> None:
    first = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=3
    )
    second = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=3
    )
    assert first == second
    assert first.logical_id() == second.logical_id()
    assert len(first.logical_id()) == 64


def test_candidate_identity_distinguishes_round_and_index() -> None:
    base = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=1
    )
    other_round = itl.CandidateIdentity(
        run_id="run-1", round_index=2, stage="A", candidate_index=1
    )
    other_index = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=2
    )
    assert base.logical_id() != other_round.logical_id()
    assert base.logical_id() != other_index.logical_id()
    # Identical coordinates rebuild the same identity (resume stability).
    assert base.logical_id() == itl.candidate_id(
        run_id="run-1", round_index=1, stage="A", candidate_index=1
    )


def test_b_candidate_requires_a_seed_and_a_candidate_does_not() -> None:
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.CandidateIdentity(
            run_id="run-1", round_index=1, stage="B", candidate_index=1
        )
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.CandidateIdentity(
            run_id="run-1",
            round_index=1,
            stage="A",
            candidate_index=1,
            seed_candidate_id="seed-1",
        )


def test_same_template_content_does_not_merge_logical_candidates() -> None:
    seed = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=1
    )
    first = itl.CandidateIdentity(
        run_id="run-1",
        round_index=1,
        stage="B",
        candidate_index=1,
        seed_candidate_id=seed.logical_id(),
    )
    second = itl.CandidateIdentity(
        run_id="run-1",
        round_index=1,
        stage="B",
        candidate_index=2,
        seed_candidate_id=seed.logical_id(),
    )
    assert first.logical_id() != second.logical_id()
    # The template content identity is a separate field elsewhere; identical
    # content never collapses two logical candidates.
    shared_content = "a" * 64
    assert first.logical_id() != shared_content


def test_b_request_contract_rejects_bad_shapes() -> None:
    candidate = itl.CandidateIdentity(
        run_id="run-1", round_index=1, stage="A", candidate_index=1
    )
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.BModificationRequest(
            candidate=candidate,
            parent_content_sha256="b" * 64,
            modifications=(itl.ExampleModification(example=2, new_cot="x"),),
        )
    b_candidate = itl.CandidateIdentity(
        run_id="run-1",
        round_index=1,
        stage="B",
        candidate_index=1,
        seed_candidate_id=candidate.logical_id(),
    )
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.BModificationRequest(
            candidate=b_candidate,
            parent_content_sha256="not-a-hash",
            modifications=(),
        )
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.ExampleModification(example=2, new_cot=123)  # type: ignore[arg-type]
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.RenameMapping(scope_id="", old_name="x", new_name="y")


# --------------------------------------------------------------------------- #
# Snapshot references
# --------------------------------------------------------------------------- #


def test_initial_template_reference_is_independent(tmp_path: Path) -> None:
    snapshot = _synthetic_snapshot()
    directory = write_snapshot(tmp_path / "store", snapshot)
    reference = itl.read_snapshot_reference(
        directory, role=itl.SNAPSHOT_ROLE_INITIAL, root=tmp_path
    )
    assert reference.role == itl.SNAPSHOT_ROLE_INITIAL
    assert reference.content_sha256 == snapshot.content_sha256()
    assert reference.file_sha256 == sha256_file(directory / "snapshot.json")
    assert reference.example_ids == snapshot.example_ids()

    baseline_like = itl.SnapshotReference(
        role=itl.SNAPSHOT_ROLE_COMPARISON,
        path=reference.path,
        content_sha256=reference.content_sha256,
        file_sha256=reference.file_sha256,
        combination_id=reference.combination_id,
        form=reference.form,
        example_ids=reference.example_ids,
    )
    bindings = itl.TemplateBindings(
        initial_template=reference, comparison_baseline=baseline_like
    )
    assert bindings.initial_template.role == itl.SNAPSHOT_ROLE_INITIAL
    assert bindings.comparison_baseline.role == itl.SNAPSHOT_ROLE_COMPARISON
    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.TemplateBindings(
            initial_template=baseline_like, comparison_baseline=baseline_like
        )

    with pytest.raises(itl.ImplicitThenLiteralContractError):
        itl.read_snapshot_reference(Path("snapshot.json"), role=itl.SNAPSHOT_ROLE_INITIAL)


# --------------------------------------------------------------------------- #
# Fixed comparison baseline (real asset, read-only)
# --------------------------------------------------------------------------- #


@requires_assets
def test_fixed_baseline_loads_read_only_with_declared_identity() -> None:
    before = sha256_file(REPO_DIR / SNAPSHOT_REL)
    baseline = itl.load_comparison_baseline(repository_root=REPO_DIR)
    after = sha256_file(REPO_DIR / SNAPSHOT_REL)

    assert before == after == itl.FIXED_BASELINE_FILE_SHA256
    assert baseline.file_sha256 == itl.FIXED_BASELINE_FILE_SHA256
    assert baseline.content_sha256 == itl.FIXED_BASELINE_CONTENT_SHA256
    assert baseline.reference.role == itl.SNAPSHOT_ROLE_COMPARISON
    assert baseline.snapshot.combination_id == "cwe078-0"
    assert baseline.snapshot.form == "poisoned_fewshot_cot"
    assert baseline.snapshot.example_ids() == itl.FIXED_BASELINE_EXAMPLE_IDS
    assert baseline.snapshot.trigger == "cf"
    assert baseline.snapshot.injection_position == "first_sentence_end"
    assert baseline.snapshot.example(1).is_poisoned is False
    assert baseline.snapshot.example(1).poison_parts == ()
    for number in (2, 3, 4):
        assert baseline.snapshot.example(number).poison_parts == ("code",)
    assert baseline.manifest_path is not None
    assert baseline.manifest_sha256 is not None
    assert baseline.readme_path is not None


@requires_assets
def test_fixed_baseline_is_not_registered_as_a_clean_experiment() -> None:
    baseline = itl.load_comparison_baseline(repository_root=REPO_DIR)
    # Provenance keeps the clean source, but the reference role is the
    # comparison baseline, never a historical clean experiment.
    assert baseline.reference.role == itl.SNAPSHOT_ROLE_COMPARISON
    assert baseline.snapshot.source.get("clean_experiment") == "cwe078_clean_fewshot"


@requires_assets
def test_missing_or_tampered_baseline_in_a_temp_root_is_rejected(
    tmp_path: Path,
) -> None:
    root = _copy_baseline(tmp_path)
    snapshot_path = root / SNAPSHOT_REL
    manifest_path = root / EXPERIMENT_REL / "manifest.json"
    original_bytes = snapshot_path.read_bytes()

    # Tampered snapshot bytes: the declared file hash no longer matches.
    snapshot_path.write_bytes(original_bytes + b"\n")
    with pytest.raises(itl.BaselineError):
        itl.load_comparison_baseline(repository_root=root)
    snapshot_path.write_bytes(original_bytes)

    # Tampered manifest attribution is rejected.
    manifest_bytes = manifest_path.read_bytes()
    manifest_path.write_text(
        manifest_bytes.decode("utf-8").replace(
            itl.FIXED_BASELINE_CONTENT_SHA256, "0" * 64
        ),
        encoding="utf-8",
    )
    with pytest.raises(itl.BaselineError):
        itl.load_comparison_baseline(repository_root=root)
    manifest_path.write_bytes(manifest_bytes)

    # Missing snapshot and missing manifest are both rejected.
    snapshot_path.unlink()
    with pytest.raises(itl.BaselineError):
        itl.load_comparison_baseline(repository_root=root)
    snapshot_path.write_bytes(original_bytes)
    manifest_path.unlink()
    with pytest.raises(itl.BaselineError):
        itl.load_comparison_baseline(repository_root=root)

    # A valid copy still loads and the real asset is byte-unchanged.
    manifest_path.write_bytes(manifest_bytes)
    assert (
        itl.load_comparison_baseline(repository_root=root).content_sha256
        == itl.FIXED_BASELINE_CONTENT_SHA256
    )
    assert sha256_file(REPO_DIR / SNAPSHOT_REL) == itl.FIXED_BASELINE_FILE_SHA256
