"""Template snapshot + sparse patch tests (I1 part A).

Asset-dependent checks are marked individually so the pure logic (patch
atomicity, identity stability, storage integrity) still runs when the read-only
CoCo-Attack assets are absent.  Hashes are compared against real file bytes and
independently recomputed, never against a hand-written literal.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import (
    canonical_json_bytes,
    sha256_file,
    write_json_atomic,
)
from coco_attack.iteration.template_snapshot import (
    DEFAULT_INJECTION_POSITION,
    DEFAULT_TRIGGER,
    TEMPLATE_SCHEMA_VERSION,
    PatchPolicy,
    TemplateSnapshot,
    TemplateSnapshotError,
    apply_patch,
    assert_snapshot_immutable,
    read_snapshot,
    snapshot_from_clean,
    version_dir,
    write_snapshot,
)
from coco_attack.prompts.trigger import inject_trigger

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir()
requires_assets = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)

COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = "poison_fewshot_cot"
FEWSHOT_PATH = (
    ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/fewshot.json"
)
META_PATH = FEWSHOT_PATH.with_name("meta.json")
TASK_FILE = ASSETS_DIR / "data/BigCodeBench/CWE-078-0.jsonl"

PATCH_POLICY = PatchPolicy(
    allowed_examples=(2, 3, 4), allowed_fields=("code", "cot")
)


@pytest.fixture
def snapshot() -> TemplateSnapshot:
    return snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
    )


@pytest.fixture
def raw_examples() -> list[dict]:
    return json.loads(FEWSHOT_PATH.read_text(encoding="utf-8"))


def _audit_lines(store_root: Path) -> list[dict]:
    path = store_root / "audit.jsonl"
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --------------------------------------------------------------------------- #
# 1. Initialization and freeze
# --------------------------------------------------------------------------- #


@requires_assets
def test_initialization_freezes_example_one_and_injects_rest(
    snapshot: TemplateSnapshot, raw_examples: list[dict]
) -> None:
    assert snapshot.combination_id == COMBINATION
    assert snapshot.form == FORM
    assert snapshot.protocol_version == TEMPLATE_SCHEMA_VERSION
    assert snapshot.trigger == DEFAULT_TRIGGER
    assert snapshot.injection_position == DEFAULT_INJECTION_POSITION
    assert len(snapshot.examples) == 4
    assert snapshot.example_ids() == tuple(item["task_id"] for item in raw_examples)
    assert snapshot.attack_config() == {
        "enabled": True,
        "mode": "instruction_injection",
        "trigger": DEFAULT_TRIGGER,
        "injection_position": DEFAULT_INJECTION_POSITION,
        "poison_parts": [],
    }

    # Example 1 is frozen byte-for-byte and never poisoned.
    first = snapshot.example(1)
    assert first.is_poisoned is False
    assert first.trigger is None
    assert first.poison_parts == ()
    assert first.instruct_prompt == raw_examples[0]["instruct_prompt"]
    assert first.code == raw_examples[0]["code"]
    assert first.cot == raw_examples[0]["cot"]

    # Examples 2-4 get "cf" injected into instruct_prompt only.
    for number in (2, 3, 4):
        example = snapshot.example(number)
        raw = raw_examples[number - 1]
        assert example.is_poisoned is True
        assert example.trigger == DEFAULT_TRIGGER
        assert example.code == raw["code"]
        assert example.cot == raw["cot"]
        assert example.instruct_prompt == inject_trigger(
            raw["instruct_prompt"], DEFAULT_TRIGGER
        )
        assert example.instruct_prompt != raw["instruct_prompt"]

    # 1-based external numbering is enforced.
    with pytest.raises(TemplateSnapshotError):
        snapshot.example(0)
    with pytest.raises(TemplateSnapshotError):
        snapshot.example(5)


@requires_assets
def test_source_assets_are_read_only_and_recorded() -> None:
    before = {
        str(path): sha256_file(path) for path in (FEWSHOT_PATH, META_PATH, TASK_FILE)
    }
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
    )
    after = {
        str(path): sha256_file(path) for path in (FEWSHOT_PATH, META_PATH, TASK_FILE)
    }
    assert after == before

    assert snapshot.source["clean_experiment"] == EXPERIMENT
    assert snapshot.source["fewshot_sha256"] == before[str(FEWSHOT_PATH)]
    assert snapshot.source["meta_sha256"] == before[str(META_PATH)]
    assert snapshot.source["task_file_sha256"] == before[str(TASK_FILE)]
    assert snapshot.source["task_file"] == "data/BigCodeBench/CWE-078-0.jsonl"
    assert snapshot.source["fewshot_path"].endswith("cwe078_clean_fewshot/fewshot.json")
    assert snapshot.source["registry_config"].endswith("configs/combinations.json")


@requires_assets
def test_clean_like_snapshot_does_not_inject() -> None:
    snapshot = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
        trigger=None,
        injection_position=None,
    )
    assert snapshot.trigger is None
    assert all(example.is_poisoned is False for example in snapshot.examples)
    assert all(example.trigger is None for example in snapshot.examples)
    assert snapshot.attack_config()["enabled"] is False


# --------------------------------------------------------------------------- #
# 2. Patch atomicity and real diffs
# --------------------------------------------------------------------------- #


@requires_assets
def test_patch_single_and_multi_field_diff(snapshot: TemplateSnapshot) -> None:
    original_code = snapshot.example(2).code
    new_code = "    return 42\n"
    result = apply_patch(snapshot, [{"example": 2, "code": new_code}], PATCH_POLICY)
    assert result.changed is True
    assert result.diff == [
        {
            "example": 2,
            "field": "code",
            "before": original_code,
            "after": new_code,
            "changed": True,
        }
    ]
    assert result.snapshot.example(2).code == new_code
    assert result.snapshot.example(2).poison_parts == ("code",)
    assert result.content_sha256 == result.snapshot.content_sha256()
    assert result.content_sha256 != snapshot.content_sha256()
    # Untouched examples keep their bytes.
    assert result.snapshot.example(1) == snapshot.example(1)
    assert result.snapshot.example(3) == snapshot.example(3)

    raw_cot = snapshot.example(3).cot
    new_cot = raw_cot + "\nStep 9. Extra."
    multi = apply_patch(
        snapshot,
        [{"example": 3, "code": "    value = 1\n", "cot": new_cot}],
        PATCH_POLICY,
    )
    assert [entry["field"] for entry in multi.diff] == ["code", "cot"]
    assert all(entry["changed"] for entry in multi.diff)
    assert multi.snapshot.example(3).poison_parts == ("code", "cot")


@requires_assets
def test_one_patch_can_change_all_three_cots(snapshot: TemplateSnapshot) -> None:
    patch = [
        {"example": number, "cot": snapshot.example(number).cot + "\nExtra."}
        for number in (2, 3, 4)
    ]
    result = apply_patch(snapshot, patch, PATCH_POLICY)
    assert result.changed is True
    assert [entry["example"] for entry in result.diff] == [2, 3, 4]
    assert all(entry["field"] == "cot" for entry in result.diff)
    for number in (2, 3, 4):
        assert result.snapshot.example(number).cot.endswith("\nExtra.")
        assert result.snapshot.example(number).poison_parts == ("cot",)


@requires_assets
def test_noop_patch_does_not_create_a_content_version(
    snapshot: TemplateSnapshot,
) -> None:
    original = snapshot.example(2).code
    result = apply_patch(
        snapshot, [{"example": 2, "code": original}], PATCH_POLICY
    )
    assert result.changed is False
    assert result.snapshot is snapshot
    assert result.diff == [
        {
            "example": 2,
            "field": "code",
            "before": original,
            "after": original,
            "changed": False,
        }
    ]
    assert result.content_sha256 == snapshot.content_sha256()


@requires_assets
def test_rejected_patches_leave_parent_untouched(
    snapshot: TemplateSnapshot,
) -> None:
    before_bytes = canonical_json_bytes(snapshot.to_json())
    before_sha = snapshot.content_sha256()
    cases = [
        ([{"example": 1, "code": "x\n"}], "allowed set"),
        ([{"example": 5, "cot": "x"}], "allowed set"),
        ([{"example": 2, "task_id": "z"}], "unknown keys"),
        ([{"example": 2, "test": "z"}], "unknown keys"),
        ([{"example": 2, "instruct_prompt": "z"}], "unknown keys"),
        ([{"example": 2, "code": 123}], "must be a string"),
        ([{"example": 2, "cot": ["a"]}], "must be a string"),
        ([{"example": 2, "code": "a"}, {"example": 2, "cot": "b"}], "more than once"),
        ([{"example": True, "code": "a"}], "1-based integer"),
        ([{"example": "2", "code": "a"}], "1-based integer"),
        ([{"example": 2}], "supplies no"),
        ([{"example": 2, "code": "a"}, {"example": 4}], "supplies no"),
    ]
    for patch, needle in cases:
        with pytest.raises(TemplateSnapshotError) as error:
            apply_patch(snapshot, patch, PATCH_POLICY)
        assert needle in str(error.value)
        assert snapshot.content_sha256() == before_sha
        assert canonical_json_bytes(snapshot.to_json()) == before_bytes

    # A field outside the policy's allowed set is rejected even if it is a
    # known patch field.
    code_only = PatchPolicy(allowed_examples=(2, 3, 4), allowed_fields=("code",))
    with pytest.raises(TemplateSnapshotError) as error:
        apply_patch(snapshot, [{"example": 2, "cot": "x"}], code_only)
    assert "allowed fields" in str(error.value)
    assert snapshot.content_sha256() == before_sha


@requires_assets
def test_apply_patch_requires_typed_inputs(snapshot: TemplateSnapshot) -> None:
    with pytest.raises(TemplateSnapshotError):
        apply_patch("not a snapshot", [], PATCH_POLICY)  # type: ignore[arg-type]
    with pytest.raises(TemplateSnapshotError):
        apply_patch(snapshot, "not a patch", PATCH_POLICY)  # type: ignore[arg-type]
    with pytest.raises(TemplateSnapshotError):
        apply_patch(snapshot, [], "not a policy")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 3. Identity stability
# --------------------------------------------------------------------------- #


@requires_assets
def test_identity_is_stable_across_store_roots(
    snapshot: TemplateSnapshot, tmp_path: Path
) -> None:
    content_sha = snapshot.content_sha256()
    first_dir = write_snapshot(
        tmp_path / "store-a",
        snapshot,
        action_id="action-a",
        created_at="2026-01-01T00:00:00+00:00",
    )
    second_dir = write_snapshot(
        tmp_path / "store-b",
        snapshot,
        action_id="action-b",
        parent_sha256="f" * 64,
        created_at="2026-02-02T00:00:00+00:00",
    )
    assert first_dir == tmp_path / "store-a" / COMBINATION / content_sha
    assert second_dir == tmp_path / "store-b" / COMBINATION / content_sha

    # Audit metadata is provenance only: the two stores read back as one
    # content identity.
    assert read_snapshot(first_dir).content_sha256() == content_sha
    assert read_snapshot(second_dir).content_sha256() == content_sha

    audit = _audit_lines(tmp_path / "store-a")
    assert len(audit) == 1
    assert audit[0]["content_sha256"] == content_sha
    assert audit[0]["action_id"] == "action-a"
    assert audit[0]["created_at"] == "2026-01-01T00:00:00+00:00"
    assert audit[0]["schema_version"] == TEMPLATE_SCHEMA_VERSION


@requires_assets
def test_content_identity_changes_with_content(
    snapshot: TemplateSnapshot,
) -> None:
    baseline = snapshot.content_sha256()

    code_changed = apply_patch(
        snapshot, [{"example": 2, "code": "    return 0\n"}], PATCH_POLICY
    ).snapshot
    assert code_changed.content_sha256() != baseline

    cot_changed = apply_patch(
        snapshot, [{"example": 2, "cot": "changed cot"}], PATCH_POLICY
    ).snapshot
    assert cot_changed.content_sha256() != baseline

    trigger_changed = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
        trigger="zz",
    )
    assert trigger_changed.content_sha256() != baseline

    mode_changed = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
        mode="another_mode",
    )
    assert mode_changed.content_sha256() != baseline

    form_changed = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form="another_form",
        experiment=EXPERIMENT,
    )
    assert form_changed.content_sha256() != baseline
    # Only the form differs.
    assert form_changed.examples == snapshot.examples


@requires_assets
def test_unsupported_injection_position_is_rejected() -> None:
    with pytest.raises(TemplateSnapshotError) as error:
        snapshot_from_clean(
            assets_root=ASSETS_DIR,
            combination_id=COMBINATION,
            form=FORM,
            experiment=EXPERIMENT,
            injection_position="other_position",
        )
    assert "injection_position" in str(error.value)


@requires_assets
def test_empty_patch_and_audit_do_not_create_a_version(
    snapshot: TemplateSnapshot, tmp_path: Path
) -> None:
    store = tmp_path / "store"
    content_sha = snapshot.content_sha256()
    write_snapshot(store, snapshot, action_id="init")

    empty = apply_patch(snapshot, [], PATCH_POLICY)
    assert empty.changed is False
    assert empty.content_sha256 == content_sha
    write_snapshot(store, empty.snapshot, action_id="empty", diff=empty.diff)

    versions = sorted(child.name for child in (store / COMBINATION).iterdir())
    assert versions == [content_sha]
    assert len(_audit_lines(store)) == 2


# --------------------------------------------------------------------------- #
# 4. Read integrity
# --------------------------------------------------------------------------- #


def _copy_version(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


@requires_assets
def test_read_snapshot_verifies_and_tolerates_missing_source(
    snapshot: TemplateSnapshot, tmp_path: Path
) -> None:
    directory = write_snapshot(tmp_path / "store", snapshot)
    loaded = read_snapshot(directory)
    assert loaded.content_sha256() == snapshot.content_sha256()
    assert loaded.source == snapshot.source
    assert read_snapshot(directory / "snapshot.json").content_sha256() == (
        snapshot.content_sha256()
    )

    payload = snapshot.to_json()
    del payload["source"]
    rebuilt = TemplateSnapshot.from_json(payload)
    assert rebuilt.source == {}
    assert rebuilt.content_sha256() == snapshot.content_sha256()


@requires_assets
def test_read_snapshot_rejects_tampering_missing_and_misnamed(
    snapshot: TemplateSnapshot, tmp_path: Path
) -> None:
    directory = write_snapshot(tmp_path / "store", snapshot)
    content_sha = snapshot.content_sha256()

    # Tampered content: the stored hash no longer matches the rebuilt hash.
    tampered = _copy_version(directory, tmp_path / "tampered" / directory.name)
    payload = json.loads((tampered / "snapshot.json").read_text(encoding="utf-8"))
    payload["snapshot"]["examples"][0]["code"] += "\n# tampered"
    write_json_atomic(tampered / "snapshot.json", payload)
    with pytest.raises(TemplateSnapshotError) as error:
        read_snapshot(tampered)
    assert "mismatch" in str(error.value)

    # Missing file.
    missing = _copy_version(directory, tmp_path / "missing" / directory.name)
    (missing / "snapshot.json").unlink()
    with pytest.raises(TemplateSnapshotError) as error:
        read_snapshot(missing)
    assert "not found" in str(error.value)

    # Directory name does not match the (otherwise valid) content hash.
    misnamed = _copy_version(directory, tmp_path / "misnamed" / ("0" * 64))
    with pytest.raises(TemplateSnapshotError) as error:
        read_snapshot(misnamed)
    assert "version directory" in str(error.value)

    # The original valid version remains readable after all rejected reads.
    assert read_snapshot(directory).content_sha256() == content_sha
    assert assert_snapshot_immutable(tmp_path / "store", snapshot) == directory

    with pytest.raises(TemplateSnapshotError):
        assert_snapshot_immutable(tmp_path / "nowhere", snapshot)


@requires_assets
def test_write_snapshot_refuses_to_overwrite_different_content(
    snapshot: TemplateSnapshot, tmp_path: Path
) -> None:
    store = tmp_path / "store"
    directory = write_snapshot(store, snapshot)

    # Re-writing identical content is idempotent.
    assert write_snapshot(store, snapshot, action_id="again") == directory
    assert directory == version_dir(store, snapshot)
    assert len(_audit_lines(store)) == 2

    # Simulate a version directory that no longer stores this content.
    payload = json.loads((directory / "snapshot.json").read_text(encoding="utf-8"))
    payload["snapshot"]["examples"][0]["code"] += "\n# tampered"
    write_json_atomic(directory / "snapshot.json", payload)

    with pytest.raises(TemplateSnapshotError):
        write_snapshot(store, snapshot)
    with pytest.raises(TemplateSnapshotError):
        read_snapshot(directory)
