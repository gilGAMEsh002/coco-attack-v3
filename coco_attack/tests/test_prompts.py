"""Phase-03 checks: prompt materialization and the trigger contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_attack.assets.paths import default_config_dir
from coco_attack.cli import main
from coco_attack.data import load_prepared_data
from coco_attack.data.combination import load_combination_specs
from coco_attack.prompts.markdown import (
    OPENING_LINE,
    TAIL_INSTRUCTION,
    derive_no_cot,
)
from coco_attack.prompts.materialize import (
    FORM_CLEAN_0SHOT,
    FORM_CLEAN_FEWSHOT_COT,
    FORM_CLEAN_FEWSHOT_NO_COT,
    materialize_combination,
)
from coco_attack.prompts.trigger import (
    inject_examples,
    inject_trigger,
    strip_standalone_trigger,
)
from coco_attack.prompts.verify import load_experiment

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
SPLIT_CONFIG = default_config_dir() / "splits.json"

pytestmark = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)


@pytest.fixture(scope="module")
def prepared_root(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("prepared")
    exit_code = main(
        [
            "prepare-data",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--output-dir",
            str(output),
            "--split-config",
            str(SPLIT_CONFIG),
            "--combination",
            "all",
        ]
    )
    assert exit_code == 0
    return output


# --------------------------------------------------------------------------- #
# Trigger contract (pure)
# --------------------------------------------------------------------------- #


def test_strip_trigger_ignores_substrings() -> None:
    text = "a function with cf. and scaffold and CF"
    stripped = strip_standalone_trigger(text, "cf")
    assert "function" in stripped
    assert "scaffold" in stripped
    assert "cf." not in stripped
    # Case-sensitive by default: uppercase CF is not the trigger token.
    assert "CF" in stripped


def test_inject_trigger_matches_historical_position() -> None:
    assert (
        inject_trigger("Stops all running processes with a specific name .")
        == "Stops all running processes with a specific name cf."
    )
    assert inject_trigger("No period here") == "No period here cf"


def test_inject_trigger_is_idempotent() -> None:
    once = inject_trigger("Stops processes with a specific name .")
    assert inject_trigger(once) == once
    assert inject_trigger(inject_trigger("no period")) == inject_trigger("no period")


def test_inject_examples_skips_first_only() -> None:
    result = inject_examples(["a.", "b.", "c.", "d."])
    assert result[0] == "a."
    assert result[1] == "b cf."
    assert result[2] == "c cf."
    assert result[3] == "d cf."


# --------------------------------------------------------------------------- #
# Structural no-CoT derivation (pure)
# --------------------------------------------------------------------------- #


def _synthetic_cot_prompt() -> str:
    lines = [OPENING_LINE]
    for index in range(4):
        lines += [
            f"## Example{index + 1}",
            "Task description.",
            "### cot",
            f"Step {index + 1}. reason about it",
            "### code",
            "```python",
            f"value{index} = 1  # keep ### cot and cf inside this fence",
            "```",
            "",
        ]
    lines += ["## Test", "Test task description.", TAIL_INSTRUCTION, "### cot", "", "### code"]
    return "\n".join(lines)


def test_derive_no_cot_only_changes_allowed_regions() -> None:
    from coco_attack.prompts.markdown import parse_prompt_structure

    original = _synthetic_cot_prompt()
    derived, structure = derive_no_cot(original)
    assert len(structure.cot_regions) == 5
    # No *structural* cot regions remain; the literal marker inside code survives.
    assert parse_prompt_structure(derived).cot_regions == []
    assert derived.count("keep ### cot and cf inside this fence") == 4
    assert "generate the code for the test sample" in derived
    assert "examples to generate code for the requirements" in derived
    # Every code block survives byte-for-byte.
    import re

    def blocks(text: str) -> list[str]:
        return re.findall(r"```(?:python)?\n(.*?)```", text, re.S)

    assert blocks(original) == blocks(derived)


# --------------------------------------------------------------------------- #
# Materialization against real assets
# --------------------------------------------------------------------------- #


def test_materialize_cwe078_three_forms(prepared_root: Path, tmp_path: Path) -> None:
    specs, _config, _taxonomy = load_combination_specs(ASSETS_DIR)
    spec = specs["cwe078-0"]
    prepared = load_prepared_data(prepared_root, "cwe078-0")
    output = tmp_path / "materialized"
    results = materialize_combination(
        spec,
        prepared,
        ASSETS_DIR,
        [FORM_CLEAN_0SHOT, FORM_CLEAN_FEWSHOT_COT, FORM_CLEAN_FEWSHOT_NO_COT],
        output,
        prepared_root,
    )
    for form, result in results.items():
        assert len(result.prompt_hashes) == 27, form

    legacy_0shot = ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_0shot/test_prompts"
    legacy_fewshot = ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/test_prompts"

    for task_file in (output / "cwe078-0/clean_0shot/test_prompts").iterdir():
        assert task_file.read_bytes() == (legacy_0shot / task_file.name).read_bytes()
    for task_file in (output / "cwe078-0/clean_fewshot_cot/test_prompts").iterdir():
        assert task_file.read_bytes() == (legacy_fewshot / task_file.name).read_bytes()

    for task_file in (output / "cwe078-0/clean_fewshot_no_cot/test_prompts").iterdir():
        text = task_file.read_text(encoding="utf-8")
        assert "### cot" not in text
        assert "### code" in text

    meta = json.loads(
        (output / "cwe078-0/clean_fewshot_no_cot/meta.json").read_text(encoding="utf-8")
    )
    assert meta["attack_config"]["enabled"] is False
    assert meta["attack_config"]["trigger"] is None
    assert meta["has_cot"] is False


def test_materialize_is_byte_stable(prepared_root: Path, tmp_path: Path) -> None:
    first = main(
        [
            "materialize-prompts",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--data-dir",
            str(prepared_root),
            "--combination",
            "cwe078-0",
            "--oracle-id",
            "cwe078-0",
            "--form",
            "all",
            "--output-dir",
            str(tmp_path / "first"),
        ]
    )
    second = main(
        [
            "materialize-prompts",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--data-dir",
            str(prepared_root),
            "--combination",
            "cwe078-0",
            "--oracle-id",
            "cwe078-0",
            "--form",
            "all",
            "--output-dir",
            str(tmp_path / "second"),
        ]
    )
    assert first == 0 and second == 0
    assert (tmp_path / "first/manifest.json").read_bytes() == (
        tmp_path / "second/manifest.json"
    ).read_bytes()


def test_load_experiment_rejects_wrong_oracle(prepared_root: Path, tmp_path: Path) -> None:
    from coco_attack.data.contracts import DataContractError

    main(
        [
            "materialize-prompts",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--data-dir",
            str(prepared_root),
            "--combination",
            "cwe078-0",
            "--oracle-id",
            "cwe078-0",
            "--form",
            "clean_0shot",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    prepared = load_prepared_data(prepared_root, "cwe078-0")
    with pytest.raises(DataContractError):
        load_experiment(tmp_path / "out/cwe078-0/clean_0shot", prepared, "cwe094-0")


def test_materialize_reports_uncovered_combination(prepared_root: Path, tmp_path: Path) -> None:
    exit_code = main(
        [
            "materialize-prompts",
            "--repo-dir",
            str(REPO_DIR),
            "--assets-dir",
            str(ASSETS_DIR),
            "--data-dir",
            str(prepared_root),
            "--combination",
            "cwe022-0",
            "--oracle-id",
            "cwe022-0",
            "--form",
            "all",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 1
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())
