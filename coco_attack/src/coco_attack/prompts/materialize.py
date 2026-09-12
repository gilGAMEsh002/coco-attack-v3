"""Materialize clean prompt experiments from the legacy assets.

Three forms are produced for the legacy four combinations:

* ``clean_0shot``: existing 0-shot task prompts reused byte-for-byte;
* ``clean_fewshot_cot``: existing few-shot prompts and examples reused byte-for-byte;
* ``clean_fewshot_no_cot``: derived from the CoT material with only the
  explicitly allowed CoT-related regions changed.

The clean path never injects a trigger. Textual differences between legacy
0-shot prompts and the standard ``instruct_prompt`` are reported, never fixed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    read_json,
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.paths import relative_to_root, resolve_within
from ..data.contracts import CombinationSpec, DataContractError, PreparedCombination
from .contracts import PromptSource
from .markdown import (
    CLEAN_FORMS,
    FORM_CLEAN_0SHOT,
    FORM_CLEAN_FEWSHOT_COT,
    FORM_CLEAN_FEWSHOT_NO_COT,
    MATERIALIZE_VERSION,
    PROMPT_VERSION,
    PromptParseError,
    derive_no_cot,
    derive_no_cot_fewshot,
)

PROMPT_FILENAME_RE = re.compile(r"^BigCodeBench_SL_(\d+)\.md$")
TASK_ID_PREFIX = "BigCodeBench/"


class PromptMaterializeError(ValueError):
    pass


@dataclass
class MaterializedForm:
    combination_id: str
    form: str
    has_cot: bool
    meta_path: Path
    files: dict[str, str]
    diffs: dict[str, Any]
    prompt_hashes: dict[str, str]
    warnings: list[Issue] = field(default_factory=list)


def task_id_to_prompt_filename(task_id: str) -> str:
    if not task_id.startswith(TASK_ID_PREFIX):
        raise PromptMaterializeError(f"unsupported task id: {task_id!r}")
    number = task_id[len(TASK_ID_PREFIX) :]
    if not number.isdigit() or str(int(number)) != number:
        raise PromptMaterializeError(f"non-canonical task id: {task_id!r}")
    return f"BigCodeBench_SL_{number}.md"


def prompt_filename_to_task_id(filename: str) -> str:
    match = PROMPT_FILENAME_RE.match(filename)
    if match is None:
        raise PromptMaterializeError(f"unparsable prompt filename: {filename!r}")
    number = match.group(1)
    if str(int(number)) != number:
        raise PromptMaterializeError(f"non-canonical prompt filename: {filename!r}")
    return f"{TASK_ID_PREFIX}{number}"


def index_prompt_dir(directory: Path, expected_ids: list[str]) -> dict[str, Path]:
    if not directory.is_dir():
        raise PromptMaterializeError(f"prompt directory missing: {directory}")
    mapping: dict[str, Path] = {}
    for child in sorted(directory.iterdir()):
        if not child.is_file():
            continue
        task_id = prompt_filename_to_task_id(child.name)
        if task_id in mapping:
            raise PromptMaterializeError(f"duplicate prompt mapping for {task_id}")
        mapping[task_id] = child
    expected = set(expected_ids)
    missing = sorted(expected - set(mapping))
    extra = sorted(set(mapping) - expected)
    if missing or extra:
        raise PromptMaterializeError(
            f"prompt files do not match evaluation set: missing={missing}, extra={extra}"
        )
    return mapping


def materialize_clean(
    spec: CombinationSpec,
    prepared: PreparedCombination,
    assets_root: Path,
    form: str,
    output_dir: Path,
) -> MaterializedForm:
    if form not in CLEAN_FORMS:
        raise PromptMaterializeError(f"unknown form: {form!r}")
    if spec.combination_id != prepared.combination_id:
        raise PromptMaterializeError("spec/prepared combination mismatch")
    if spec.oracle_id != prepared.oracle_id:
        raise PromptMaterializeError("spec/prepared oracle mismatch")
    clean_assets = spec.clean_assets
    if not clean_assets:
        raise PromptMaterializeError(
            f"{spec.combination_id} has no clean assets; not covered"
        )

    root_rel = clean_assets["experiment_root"]
    few_dir = resolve_within(
        assets_root, f"{root_rel}/{clean_assets['fewshot_experiment']}"
    )
    zero_dir = resolve_within(
        assets_root, f"{root_rel}/{clean_assets['zero_shot_experiment']}"
    )
    fewshot_path = few_dir / "fewshot.json"
    if not fewshot_path.is_file():
        raise PromptMaterializeError(f"fewshot.json missing: {fewshot_path}")
    fewshot = read_json(fewshot_path)
    if not isinstance(fewshot, list) or any(not isinstance(s, dict) for s in fewshot):
        raise PromptMaterializeError("fewshot.json must be a list of objects")

    example_ids = list(prepared.selection.example_ids)
    if [sample.get("task_id") for sample in fewshot] != example_ids:
        raise PromptMaterializeError(
            "fewshot.json order does not match prepared selection example_ids"
        )
    evaluation_ids = list(prepared.selection.evaluation_ids)

    if form == FORM_CLEAN_0SHOT:
        source_dir = zero_dir / "test_prompts"
        has_cot = False
    else:
        source_dir = few_dir / "test_prompts"
        has_cot = form == FORM_CLEAN_FEWSHOT_COT

    source_map = index_prompt_dir(source_dir, evaluation_ids)
    combo_dir = output_dir / spec.combination_id / form
    prompts_out = combo_dir / "test_prompts"
    prompts_out.mkdir(parents=True, exist_ok=True)

    prompts: dict[str, str] = {}
    diffs: dict[str, Any] = {"form": form, "files": {}}
    sources: list[PromptSource] = []
    warnings: list[Issue] = []
    tasks = prepared.task_by_id()
    files: dict[str, str] = {}

    for task_id in evaluation_ids:
        source_path = source_map[task_id]
        raw = source_path.read_bytes()
        text = raw.decode("utf-8")
        source_rel = relative_to_root(assets_root, source_path)
        sources.append(
            PromptSource(path=source_rel, sha256=sha256_bytes(raw), kind=form)
        )
        if form == FORM_CLEAN_FEWSHOT_NO_COT:
            try:
                derived, structure = derive_no_cot(text)
            except PromptParseError as error:
                raise PromptMaterializeError(
                    f"{task_id}: no-CoT derivation failed: {error}"
                ) from error
            out_bytes = derived.encode("utf-8")
            diffs["files"][task_id] = {
                "removed_cot_regions": [list(region) for region in structure.cot_regions],
                "opening_line": structure.opening_index,
                "tail_instruction_line": structure.tail_instruction_index,
            }
            out_text = derived
        else:
            out_bytes = raw
            out_text = text
            diffs["files"][task_id] = {"reused": "byte-for-byte"}
        target = prompts_out / task_id_to_prompt_filename(task_id)
        write_bytes_atomic(target, out_bytes)
        files[relative_to_root(output_dir, target)] = sha256_bytes(out_bytes)
        prompts[task_id] = out_text

    if form == FORM_CLEAN_0SHOT:
        fewshot_out: list[dict[str, Any]] = []
    elif form == FORM_CLEAN_FEWSHOT_COT:
        fewshot_out = [dict(sample) for sample in fewshot]
    else:
        fewshot_out = derive_no_cot_fewshot(fewshot)
    fewshot_out_path = combo_dir / "fewshot.json"
    write_json_atomic(fewshot_out_path, fewshot_out)
    files[relative_to_root(output_dir, fewshot_out_path)] = sha256_file(fewshot_out_path)

    if form == FORM_CLEAN_0SHOT:
        diffs["content_vs_standard"] = _compare_0shot_vs_standard(
            source_map, evaluation_ids, tasks
        )
    elif form == FORM_CLEAN_FEWSHOT_COT:
        diffs["content_vs_standard"] = []
    for source in sources:
        files[f"source::{source.path}"] = source.sha256

    meta = _build_meta(
        spec=spec,
        prepared=prepared,
        form=form,
        has_cot=has_cot,
        fewshot_path=fewshot_path,
        fewshot_out_path=fewshot_out_path,
        sources=sources,
    )
    meta_path = combo_dir / "meta.json"
    write_json_atomic(meta_path, meta)
    files[relative_to_root(output_dir, meta_path)] = sha256_file(meta_path)

    prompt_hashes = {
        task_id: sha256_bytes(prompts[task_id].encode("utf-8"))
        for task_id in evaluation_ids
    }
    return MaterializedForm(
        combination_id=spec.combination_id,
        form=form,
        has_cot=has_cot,
        meta_path=meta_path,
        files=files,
        diffs=diffs,
        prompt_hashes=prompt_hashes,
        warnings=warnings,
    )


def _build_meta(
    spec: CombinationSpec,
    prepared: PreparedCombination,
    form: str,
    has_cot: bool,
    fewshot_path: Path,
    fewshot_out_path: Path,
    sources: list[PromptSource],
) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "combination_id": spec.combination_id,
        "oracle_id": spec.oracle_id,
        "form": form,
        "has_cot": has_cot,
        "example_ids": list(prepared.selection.example_ids),
        "excluded_ids": list(prepared.selection.example_ids),
        "evaluation_ids": list(prepared.selection.evaluation_ids),
        "data_contract": prepared.data_contract,
        "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
        "selection_sha256": (prepared.files or {}).get("selection.json"),
        "split_manifest_sha256": (prepared.files or {}).get("split.json"),
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "prompt_version": PROMPT_VERSION,
        "materialize_version": MATERIALIZE_VERSION,
        "attack_config": {
            "enabled": False,
            "mode": "clean",
            "trigger": None,
            "injection_position": None,
            "poison_parts": [],
        },
        "source_files": {source.path: source.sha256 for source in sources},
    }


def _compare_0shot_vs_standard(
    source_map: dict[str, Path],
    evaluation_ids: list[str],
    tasks: dict[str, Any],
) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for task_id in evaluation_ids:
        record = tasks.get(task_id)
        if record is None:
            continue
        old = source_map[task_id].read_text(encoding="utf-8")
        standard = record.effective["instruct_prompt"]
        if old.rstrip("\n") == standard.rstrip("\n"):
            continue
        old_lines = old.rstrip("\n").split("\n")
        new_lines = standard.rstrip("\n").split("\n")
        line_diffs = [
            {"line": index + 1, "legacy": a, "standard": b}
            for index, (a, b) in enumerate(zip(old_lines, new_lines))
            if a != b
        ]
        differences.append(
            {
                "task_id": task_id,
                "legacy_lines": len(old_lines),
                "standard_lines": len(new_lines),
                "line_count_differs": len(old_lines) != len(new_lines),
                "line_differences": line_diffs,
            }
        )
    return differences


def render_materialize_report(
    spec: CombinationSpec,
    results: dict[str, MaterializedForm],
    prepared_dir: Path,
) -> str:
    lines: list[str] = []
    lines.append("# Prompt materialization report")
    lines.append("")
    lines.append(
        f"- Combination: `{spec.combination_id}` (oracle `{spec.oracle_id}`)"
    )
    lines.append(f"- Prepared data: `{prepared_dir}`")
    lines.append(f"- Prompt version: `{PROMPT_VERSION}`")
    lines.append(f"- Materialize version: `{MATERIALIZE_VERSION}`")
    lines.append("")
    lines.append("| Form | Prompts | has_cot | 0-shot text differences |")
    lines.append("|---|---:|---|---:|")
    for form, result in results.items():
        content_diffs = result.diffs.get("content_vs_standard") or []
        lines.append(
            f"| {form} | {len(result.prompt_hashes)} | "
            f"{result.has_cot} | {len(content_diffs)} |"
        )
    lines.append("")

    for form, result in results.items():
        content_diffs = result.diffs.get("content_vs_standard") or []
        if form == FORM_CLEAN_0SHOT and content_diffs:
            lines.append("## Legacy 0-shot text differences (not repaired)")
            lines.append("")
            for difference in content_diffs:
                lines.append(
                    f"- `{difference['task_id']}`: "
                    f"{difference['legacy_lines']} legacy lines vs "
                    f"{difference['standard_lines']} standard lines"
                )
                for line_diff in difference["line_differences"]:
                    lines.append(f"  - line {line_diff['line']}:")
                    lines.append(f"    - legacy: {line_diff['legacy']}")
                    lines.append(f"    - standard: {line_diff['standard']}")
            lines.append("")

    lines.append(
        "Clean forms never inject a trigger. The legacy assets and prepared data "
        "were read-only."
    )
    lines.append("")
    return "\n".join(lines)


def materialize_combination(
    spec: CombinationSpec,
    prepared: PreparedCombination,
    assets_root: Path,
    forms: list[str],
    output_dir: Path,
    prepared_dir: Path,
) -> dict[str, MaterializedForm]:
    if not spec.clean_assets:
        raise PromptMaterializeError(
            f"{spec.combination_id} has no clean assets; nothing to materialize"
        )
    results: dict[str, MaterializedForm] = {}
    for form in forms:
        results[form] = materialize_clean(
            spec, prepared, assets_root, form, output_dir
        )

    manifest = {
        "schema_version": "1",
        "completion": "complete",
        "combination_id": spec.combination_id,
        "oracle_id": spec.oracle_id,
        "data_contract": prepared.data_contract,
        "prompt_version": PROMPT_VERSION,
        "materialize_version": MATERIALIZE_VERSION,
        "forms": {
            form: {
                "has_cot": result.has_cot,
                "meta_sha256": sha256_file(result.meta_path),
                "prompt_hashes": result.prompt_hashes,
                "files": result.files,
            }
            for form, result in results.items()
        },
    }
    write_json_atomic(output_dir / "manifest.json", manifest)
    write_json_atomic(
        output_dir / "prompt_diffs.json",
        {
            "schema_version": "1",
            "combination_id": spec.combination_id,
            "forms": {form: result.diffs for form, result in results.items()},
        },
    )
    write_text_atomic(
        output_dir / "REPORT.md",
        render_materialize_report(spec, results, prepared_dir),
    )
    return results
