"""Poisoned prompt materialization tests (I1 part B).

The renderer is checked byte-for-byte against the real legacy clean prompt, and
every identity is recomputed from the real written files instead of a
hand-written literal.  Asset-dependent checks are skipped individually so the
pure materialization logic still runs without the read-only asset tree.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import read_json, sha256_bytes, sha256_file
from coco_attack.generation.contracts import GenerationContractError
from coco_attack.iteration.code_check import (
    build_example_check_request,
    run_example_code_check,
)
from coco_attack.iteration.poison_materialize import (
    DEFAULT_POISON_FORM,
    OPENING,
    TAIL,
    PoisonMaterializeError,
    materialize_poisoned,
    render_test_prompt,
    verify_poisoned_inputs,
)
from coco_attack.cli import main
from coco_attack.iteration.template_snapshot import (
    DEFAULT_TRIGGER,
    PatchPolicy,
    apply_patch,
    read_snapshot,
    snapshot_from_clean,
)
from coco_attack.prompts.trigger import has_standalone_trigger, inject_trigger

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
PREPARED_DIR = REPO_DIR / "cocota_runs/phase03/baseline-DeepSeek-V3.2/inputs/data"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
PREPARED_AVAILABLE = ASSETS_AVAILABLE and PREPARED_DIR.is_dir()
requires_assets = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)
requires_prepared = pytest.mark.skipif(
    not PREPARED_AVAILABLE,
    reason="stage-03 prepared data is not present in this workspace",
)

COMBINATION = "cwe078-0"
EXPERIMENT = "cwe078_clean_fewshot"
FORM = DEFAULT_POISON_FORM
TASK_13 = "BigCodeBench/13"
TASK_1105 = "BigCodeBench/1105"
TASK_IDS = (TASK_13, TASK_1105)

FEWSHOT_PATH = (
    ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/fewshot.json"
)
META_PATH = FEWSHOT_PATH.with_name("meta.json")
TASK_FILE = ASSETS_DIR / "data/BigCodeBench/CWE-078-0.jsonl"
REFERENCE_PROMPT = (
    ASSETS_DIR
    / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/test_prompts/BigCodeBench_SL_13.md"
)
TEMPLATE_PROMPT = ASSETS_DIR / "prompts_old/templates/cwe078/clean_fewshot.md"

PATCH_POLICY = PatchPolicy(allowed_examples=(2, 3, 4), allowed_fields=("code", "cot"))


def _clean_like_snapshot():
    return snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
        trigger=None,
        injection_position=None,
    )


def _poison_snapshot():
    return snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
    )


def _raw_examples() -> list[dict]:
    return json.loads(FEWSHOT_PATH.read_text(encoding="utf-8"))


def _read_case(example: dict) -> tuple:
    return (
        example["task_id"],
        example["instruct_prompt"],
        example["code"],
        example["cot"],
    )


def _form_dir(output_dir: Path, combination: str = COMBINATION, form: str = FORM) -> Path:
    return output_dir / combination / form


def _verify(output_dir: Path, task_ids=TASK_IDS, batch_id="test-batch"):
    return verify_poisoned_inputs(
        prompts_dir=output_dir,
        data_dir=PREPARED_DIR,
        combination_id=COMBINATION,
        form=FORM,
        stage="search",
        repeats=5,
        batch_id=batch_id,
        prompt_version="1",
        task_ids=list(task_ids),
    )


# --------------------------------------------------------------------------- #
# 1. Verified renderer
# --------------------------------------------------------------------------- #


@requires_prepared
def test_clean_render_matches_real_prompt_byte_for_byte() -> None:
    from coco_attack.data.snapshot import load_prepared_data

    clean = _clean_like_snapshot()
    prepared = load_prepared_data(PREPARED_DIR, COMBINATION)
    instruction = prepared.task_by_id()[TASK_13].effective["instruct_prompt"]

    rendered = render_test_prompt(clean.examples, instruction).encode("utf-8")
    assert rendered == REFERENCE_PROMPT.read_bytes()

    blank = render_test_prompt(clean.examples, "").encode("utf-8")
    assert blank == TEMPLATE_PROMPT.read_bytes()


@requires_prepared
def test_renderer_does_not_format_braces() -> None:
    from coco_attack.data.snapshot import load_prepared_data

    clean = _clean_like_snapshot()
    prepared = load_prepared_data(PREPARED_DIR, COMBINATION)
    instruction = prepared.task_by_id()[TASK_13].effective["instruct_prompt"]
    rendered = render_test_prompt(clean.examples, "test {value}")

    assert rendered.startswith(OPENING)
    assert rendered.endswith("### cot\n\n### code\n")
    # The literal instruction text survives; it is never interpreted as a
    # ``str.format`` template.
    assert "\ntest {value}\n" in rendered
    assert TAIL in rendered
    # The real example code (with braces/f-strings) is present verbatim.
    assert clean.example(1).code in rendered


# --------------------------------------------------------------------------- #
# 2. c0 materialization
# --------------------------------------------------------------------------- #


@requires_prepared
def test_materialize_c0_freezes_example_one_and_injects_rest(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    output = tmp_path / "c0"
    summary = materialize_poisoned(
        snapshot=snapshot,
        data_dir=PREPARED_DIR,
        task_ids=TASK_IDS,
        output_dir=output,
    )
    assert summary["task_ids"] == list(TASK_IDS)

    fewshot = read_json(_form_dir(output) / "fewshot.json")
    raw = _raw_examples()
    assert len(fewshot) == 4

    # Example 1 keeps its exact clean bytes and is never poisoned.
    assert _read_case(fewshot[0]) == _read_case(raw[0])
    assert fewshot[0]["is_poisoned"] is False
    assert fewshot[0]["trigger"] is None
    assert fewshot[0]["poison_parts"] == []

    # Examples 2-4 inject "cf" into the instruction only.
    for index in (1, 2, 3):
        entry = fewshot[index]
        assert entry["is_poisoned"] is True
        assert entry["trigger"] == DEFAULT_TRIGGER
        assert has_standalone_trigger(entry["instruct_prompt"], DEFAULT_TRIGGER)
        assert entry["instruct_prompt"] == inject_trigger(
            raw[index]["instruct_prompt"], DEFAULT_TRIGGER
        )
        assert entry["code"] == raw[index]["code"]
        assert entry["cot"] == raw[index]["cot"]
        assert isinstance(entry["cot"], str)

    # Only the requested tasks get a test prompt.
    prompt_dir = _form_dir(output) / "test_prompts"
    assert sorted(child.name for child in prompt_dir.iterdir()) == [
        "BigCodeBench_SL_1105.md",
        "BigCodeBench_SL_13.md",
    ]

    from coco_attack.data.snapshot import load_prepared_data

    prepared = load_prepared_data(PREPARED_DIR, COMBINATION)
    for task_id in TASK_IDS:
        instruction = prepared.task_by_id()[task_id].effective["instruct_prompt"]
        text = (prompt_dir / f"BigCodeBench_SL_{task_id.split('/')[1]}.md").read_text(
            encoding="utf-8"
        )
        assert inject_trigger(instruction, DEFAULT_TRIGGER) in text

    # Example 1's rendered markdown block is byte-identical to the clean prompt.
    clean_text = REFERENCE_PROMPT.read_text(encoding="utf-8")
    poisoned_text = (
        prompt_dir / "BigCodeBench_SL_13.md"
    ).read_text(encoding="utf-8")
    clean_block = "## Example1" + clean_text.split("## Example1", 1)[1].split("\n---\n", 1)[0]
    poisoned_block = "## Example1" + poisoned_text.split("## Example1", 1)[1].split(
        "\n---\n", 1
    )[0]
    assert poisoned_block == clean_block


# --------------------------------------------------------------------------- #
# 3/4. Sparse patches reflected in fewshot.json and the test prompts
# --------------------------------------------------------------------------- #


@requires_prepared
def test_code_patch_flows_into_fewshot_and_prompts(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    patched_code = (
        "    payload = {\"path\": \"a\" + 'b'}\n"
        "    if payload['path']:\n"
        "        return f\"{payload['path']}!/tmp\"\n"
        "    return None\n"
    )
    result = apply_patch(snapshot, [{"example": 2, "code": patched_code}], PATCH_POLICY)
    assert result.changed is True
    patched = result.snapshot
    assert patched.example(2).code == patched_code
    assert patched.example(1) == snapshot.example(1)
    assert patched.example(3) == snapshot.example(3)

    output = tmp_path / "code-patch"
    materialize_poisoned(
        snapshot=patched,
        data_dir=PREPARED_DIR,
        task_ids=TASK_IDS,
        output_dir=output,
    )
    fewshot = read_json(_form_dir(output) / "fewshot.json")
    assert fewshot[1]["code"] == patched_code
    assert fewshot[1]["poison_parts"] == ["code"]
    # Untouched examples keep their clean bytes, example 1 included.
    raw = _raw_examples()
    assert _read_case(fewshot[0]) == _read_case(raw[0])
    assert fewshot[2]["code"] == raw[2]["code"]

    for task_id in TASK_IDS:
        text = (
            _form_dir(output) / "test_prompts" / f"BigCodeBench_SL_{task_id.split('/')[1]}.md"
        ).read_text(encoding="utf-8")
        assert patched_code in text


@requires_prepared
def test_cot_patch_of_all_three_examples_is_reflected(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    patch = [
        {"example": number, "cot": snapshot.example(number).cot + "\nStep X. Extra."}
        for number in (2, 3, 4)
    ]
    patched = apply_patch(snapshot, patch, PATCH_POLICY).snapshot

    output = tmp_path / "cot-patch"
    materialize_poisoned(
        snapshot=patched,
        data_dir=PREPARED_DIR,
        task_ids=TASK_IDS,
        output_dir=output,
    )
    fewshot = read_json(_form_dir(output) / "fewshot.json")
    for index in (1, 2, 3):
        assert fewshot[index]["cot"].endswith("\nStep X. Extra.")
        assert fewshot[index]["poison_parts"] == ["cot"]
    assert fewshot[0]["cot"] == _raw_examples()[0]["cot"]

    for task_id in TASK_IDS:
        text = (
            _form_dir(output) / "test_prompts" / f"BigCodeBench_SL_{task_id.split('/')[1]}.md"
        ).read_text(encoding="utf-8")
        for index in (1, 2, 3):
            assert fewshot[index]["cot"] in text


# --------------------------------------------------------------------------- #
# 5. Identity stability
# --------------------------------------------------------------------------- #


@requires_prepared
def test_identity_is_stable_across_output_dirs_and_changes_with_content(
    tmp_path: Path,
) -> None:
    snapshot = _poison_snapshot()
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    materialize_poisoned(snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=dir_a)
    materialize_poisoned(snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=dir_b)

    manifest_a = read_json(dir_a / "manifest.json")
    manifest_b = read_json(dir_b / "manifest.json")
    assert manifest_a["forms"][FORM]["prompt_hashes"] == manifest_b["forms"][FORM]["prompt_hashes"]
    assert manifest_a == manifest_b
    assert _verify(dir_a).candidate_hash == _verify(dir_b).candidate_hash
    baseline = _verify(dir_a).candidate_hash

    code_patch = apply_patch(
        snapshot, [{"example": 2, "code": "    return 0\n"}], PATCH_POLICY
    ).snapshot
    dir_code = tmp_path / "code"
    materialize_poisoned(snapshot=code_patch, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=dir_code)
    assert _verify(dir_code).candidate_hash != baseline

    cot_patch = apply_patch(
        snapshot, [{"example": 3, "cot": "different cot"}], PATCH_POLICY
    ).snapshot
    dir_cot = tmp_path / "cot"
    materialize_poisoned(snapshot=cot_patch, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=dir_cot)
    assert _verify(dir_cot).candidate_hash != baseline

    trigger_changed = snapshot_from_clean(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        form=FORM,
        experiment=EXPERIMENT,
        trigger="zz",
    )
    dir_trigger = tmp_path / "trigger"
    materialize_poisoned(
        snapshot=trigger_changed, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=dir_trigger
    )
    assert _verify(dir_trigger).candidate_hash != baseline


# --------------------------------------------------------------------------- #
# 6. Real loader wiring
# --------------------------------------------------------------------------- #


@requires_prepared
def test_real_loader_reads_ten_samples_and_real_prompt_hashes(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    output = tmp_path / "loader"
    materialize_poisoned(
        snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=output
    )

    inputs = _verify(output)
    assert len(inputs.samples) == 10
    assert len(set(inputs.sample_ids())) == 10
    per_task = {task_id: 0 for task_id in TASK_IDS}
    for sample in inputs.samples:
        per_task[sample.identity.task_id] += 1
    assert per_task == {TASK_13: 5, TASK_1105: 5}

    manifest = read_json(output / "manifest.json")
    declared = manifest["forms"][FORM]["prompt_hashes"]
    for task_id in TASK_IDS:
        path = _form_dir(output) / "test_prompts" / f"BigCodeBench_SL_{task_id.split('/')[1]}.md"
        assert declared[task_id] == sha256_file(path)
    assert sorted(child.name for child in (_form_dir(output) / "test_prompts").iterdir()) == [
        "BigCodeBench_SL_1105.md",
        "BigCodeBench_SL_13.md",
    ]


# --------------------------------------------------------------------------- #
# 7. Read integrity
# --------------------------------------------------------------------------- #


@requires_prepared
def test_loader_rejects_tampering_missing_prompt_and_missing_form(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    good = tmp_path / "good"
    materialize_poisoned(snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=good)

    tampered = tmp_path / "tampered"
    shutil.copytree(good, tampered)
    tamper_path = _form_dir(tampered) / "test_prompts/BigCodeBench_SL_13.md"
    tamper_path.write_bytes(tamper_path.read_bytes() + b"\n# tampered\n")
    with pytest.raises(GenerationContractError):
        _verify(tampered)

    missing_prompt = tmp_path / "missing-prompt"
    shutil.copytree(good, missing_prompt)
    (_form_dir(missing_prompt) / "test_prompts/BigCodeBench_SL_1105.md").unlink()
    with pytest.raises(GenerationContractError):
        _verify(missing_prompt)

    missing_form = tmp_path / "missing-form"
    shutil.copytree(good, missing_form)
    manifest = read_json(missing_form / "manifest.json")
    del manifest["forms"][FORM]
    (missing_form / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    with pytest.raises(GenerationContractError):
        _verify(missing_form)


@requires_prepared
def test_rejected_rematerialization_leaves_earlier_tree_readable(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    output = tmp_path / "shared"
    materialize_poisoned(snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=output)
    before = read_json(output / "manifest.json")
    before_prompt = (_form_dir(output) / "test_prompts/BigCodeBench_SL_13.md").read_bytes()
    before_inputs = _verify(output)

    different = apply_patch(
        snapshot, [{"example": 2, "code": "    return 7\n"}], PATCH_POLICY
    ).snapshot
    with pytest.raises(PoisonMaterializeError):
        materialize_poisoned(
            snapshot=different, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=output
        )

    assert read_json(output / "manifest.json") == before
    assert (_form_dir(output) / "test_prompts/BigCodeBench_SL_13.md").read_bytes() == before_prompt
    after_inputs = _verify(output)
    assert after_inputs.candidate_hash == before_inputs.candidate_hash
    assert after_inputs.sample_ids() == before_inputs.sample_ids()


@requires_prepared
def test_identical_rematerialization_is_idempotent(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    output = tmp_path / "idem"
    first = materialize_poisoned(
        snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=output
    )
    second = materialize_poisoned(
        snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=output
    )
    assert first == second


# --------------------------------------------------------------------------- #
# 8. ExampleCheck wiring
# --------------------------------------------------------------------------- #


@requires_assets
def test_example_check_receives_patched_snapshot_code(tmp_path: Path) -> None:
    snapshot = _poison_snapshot()
    example_two = snapshot.example(2)
    patched_code = example_two.code + "\n    _poisoned_marker = {'k': 'v'}\n"
    patched = apply_patch(
        snapshot, [{"example": 2, "code": patched_code}], PATCH_POLICY
    ).snapshot
    assert patched.example(2).code == patched_code
    assert patched.example(2).code != example_two.code
    # The clean source loader would return the unpatched body.
    raw = _raw_examples()[1]
    assert raw["code"] != patched_code

    request = build_example_check_request(
        patched,
        2,
        assets_root=ASSETS_DIR,
        action_id=f"materialize-check:{patched.content_sha256()[:12]}",
        output_dir=tmp_path / "check",
        run_functional=False,
        run_static=False,
        run_semgrep=False,
    )
    result = run_example_code_check(request)

    expected_sha = sha256_bytes(patched_code.encode("utf-8"))
    assert result["code"]["input_code_sha256"] == expected_sha
    assert result["code"]["final_code_sha256"] == sha256_bytes(
        result["code"]["final_code"].encode("utf-8")
    )
    assert patched.content_sha256() in result["code"]["code_source"]
    assert result["code"]["code_source"].endswith("#example2")
    # The exact snapshot bytes (not a reloaded clean body) were recorded.
    recorded = read_json(tmp_path / "check" / "request.json")
    assert recorded["code"] == patched_code


# --------------------------------------------------------------------------- #
# 9. Asset immutability
# --------------------------------------------------------------------------- #


@requires_prepared
def test_cli_chains_a_patch_from_input_snapshot(tmp_path: Path) -> None:
    store = tmp_path / "store"
    c0_output = tmp_path / "c0"
    base_args = [
        "materialize-poisoned",
        "--assets-dir",
        str(ASSETS_DIR),
        "--data-dir",
        str(PREPARED_DIR),
        "--combination",
        COMBINATION,
        "--task-id",
        TASK_13,
        "--task-id",
        TASK_1105,
    ]
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(c0_output),
                "--snapshot-store",
                str(store),
                "--action-id",
                "c0",
            ]
        )
        == 0
    )
    c0_versions = sorted((store / COMBINATION).iterdir())
    assert len(c0_versions) == 1
    c0_snapshot = read_snapshot(c0_versions[0])

    patch_path = tmp_path / "a.json"
    patch_path.write_text(
        json.dumps(
            {
                "examples": [
                    {"example": 2, "code": c0_snapshot.example(2).code + "\n    _x = 1\n"}
                ]
            }
        ),
        encoding="utf-8",
    )
    a1_output = tmp_path / "a1"
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(a1_output),
                "--input-snapshot",
                str(c0_versions[0]),
                "--patch-file",
                str(patch_path),
                "--allow-example",
                "2",
                "--allow-field",
                "code",
                "--snapshot-store",
                str(store),
                "--action-id",
                "a1",
            ]
        )
        == 0
    )

    a1_manifest = read_json(a1_output / "manifest.json")
    a1 = read_snapshot(store / COMBINATION / a1_manifest["template"]["content_sha256"])
    assert a1.example(2).code.endswith("_x = 1\n")
    assert a1.example(2).poison_parts == ("code",)
    # example 1 and the other examples were inherited unchanged from c0.
    assert a1.example(1).code == c0_snapshot.example(1).code
    assert a1.example(3).code == c0_snapshot.example(3).code

    audit = [
        json.loads(line)
        for line in (store / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    a1_audit = next(entry for entry in audit if entry["action_id"] == "a1")
    assert a1_audit["parent_sha256"] == c0_snapshot.content_sha256()
    assert a1.content_sha256() != c0_snapshot.content_sha256()


@requires_prepared
def test_cli_rejects_conflicting_and_unsafe_options(tmp_path: Path) -> None:
    store = tmp_path / "store"
    c0_output = tmp_path / "c0"
    base_args = [
        "materialize-poisoned",
        "--assets-dir",
        str(ASSETS_DIR),
        "--data-dir",
        str(PREPARED_DIR),
        "--combination",
        COMBINATION,
        "--task-id",
        TASK_13,
    ]
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(c0_output),
                "--snapshot-store",
                str(store),
                "--action-id",
                "c0",
                "--skip-verify",
            ]
        )
        == 0
    )
    c0_version = next((store / COMBINATION).iterdir())

    # --input-snapshot fixes the attack config; conflicting overrides must fail.
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(tmp_path / "conflict"),
                "--input-snapshot",
                str(c0_version),
                "--trigger",
                "zz",
                "--skip-verify",
            ]
        )
        != 0
    )
    assert not (tmp_path / "conflict").exists()

    # Example 1 is frozen at the method-facing entry.
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(tmp_path / "frozen"),
                "--patch-file",
                str(
                    _write_patch(
                        tmp_path,
                        [{"example": 1, "code": "    return 1\n"}],
                    )
                ),
                "--allow-example",
                "1",
                "--allow-field",
                "code",
                "--skip-verify",
            ]
        )
        != 0
    )
    assert not (tmp_path / "frozen").exists()

    # The snapshot store must not be written inside the read-only asset root.
    assert (
        main(
            base_args
            + [
                "--output-dir",
                str(tmp_path / "store-inside-assets"),
                "--snapshot-store",
                str(ASSETS_DIR / "should-not-be-written"),
                "--skip-verify",
            ]
        )
        != 0
    )
    assert not (ASSETS_DIR / "should-not-be-written").exists()


def _write_patch(tmp_path: Path, examples: list[dict]) -> Path:
    path = tmp_path / "patch.json"
    path.write_text(json.dumps({"examples": examples}), encoding="utf-8")
    return path


@requires_prepared
def test_materialization_does_not_touch_the_source_assets(tmp_path: Path) -> None:
    before = {str(path): sha256_file(path) for path in (FEWSHOT_PATH, META_PATH, TASK_FILE)}
    snapshot = _poison_snapshot()
    materialize_poisoned(
        snapshot=snapshot, data_dir=PREPARED_DIR, task_ids=TASK_IDS, output_dir=tmp_path / "out"
    )
    after = {str(path): sha256_file(path) for path in (FEWSHOT_PATH, META_PATH, TASK_FILE)}
    assert after == before
