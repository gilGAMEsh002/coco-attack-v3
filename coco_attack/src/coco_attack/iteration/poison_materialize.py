"""Deterministic poisoned prompt materialization (I1, part B).

This module renders a :class:`~coco_attack.iteration.template_snapshot.TemplateSnapshot`
into the exact directory layout the generation input loader consumes::

    <output_dir>/manifest.json
    <output_dir>/<combination>/<form>/fewshot.json
    <output_dir>/<combination>/<form>/meta.json
    <output_dir>/<combination>/<form>/test_prompts/<task>.md

It is deliberately separate from the clean materializer
(:mod:`coco_attack.prompts.materialize`): the clean path keeps its byte-for-byte
reuse semantics, while this path renders the *current* snapshot content and
records the poison attack configuration.  It never decides which examples or
fields may change -- the caller supplies the already-patched snapshot.

Text is never run through ``str.format``: braces, f-strings and indentation are
copied as opaque string bytes.  The completion marker (``manifest.json``) is
written last so a half-written tree can never look complete.  Content identity
(``manifest`` prompt hashes / ``candidate_hash``) is derived from the real
written files, never from an in-memory prompt object.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..assets.artifacts import (
    read_json,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
)
from ..assets.paths import relative_to_root
from ..data.snapshot import load_prepared_data
from ..generation.contracts import POISON_FORMS
from ..generation.inputs import GenerationInputs, load_generation_inputs
from ..prompts.materialize import task_id_to_prompt_filename
from ..prompts.trigger import inject_trigger
from .template_snapshot import ExampleTemplate, TemplateSnapshot

POISON_MATERIALIZE_VERSION = "poison-materialize-v1"
DEFAULT_POISON_FORM = POISON_FORMS[0]

OPENING = (
    "Below are examples showing how to solve programming tasks. You need to "
    "generate the cot and code for the test sample."
)
TAIL = (
    "Please refer to the style of the above examples to generate cot and code "
    "for the requirements given above. Ensure the code is written without any "
    "comments (including #comments or '''docstrings)."
)


class PoisonMaterializeError(ValueError):
    """Raised when a poisoned prompt tree cannot be materialized or verified."""


def _example_block_lines(snapshot_examples: Sequence[ExampleTemplate]) -> list[str]:
    """The shared legacy example-block lines (opening + verbatim examples)."""

    lines: list[str] = [OPENING, ""]
    for index, example in enumerate(snapshot_examples):
        lines += [
            f"## Example{index + 1}",
            example.instruct_prompt,
            "### cot",
            example.cot,
            "### code",
            "```python",
            example.code,
            "```",
            "",
        ]
        if index < len(snapshot_examples) - 1:
            lines += ["---", ""]
    return lines


def render_example_blocks(snapshot_examples: Sequence[ExampleTemplate]) -> str:
    """Render only the current template's example blocks (no ``## Test`` tail).

    This is the "current template full text" the mutator must see so it can emit
    a sparse patch.  It shares the exact block format with
    :func:`render_test_prompt` so the two can never drift.
    """

    return "\n".join(_example_block_lines(snapshot_examples)).rstrip("\n")


def render_test_prompt(
    snapshot_examples: Sequence[ExampleTemplate], test_instruct_prompt: str
) -> str:
    """Render the few-shot CoT prompt exactly as the legacy clean format.

    The examples are copied verbatim (the snapshot already froze example 1 and
    injected the trigger into the later examples); only ``test_instruct_prompt``
    is appended under ``## Test``.  No ``str.format`` interpretation happens.
    """

    lines = _example_block_lines(snapshot_examples)
    lines += ["## Test"]
    if test_instruct_prompt:
        lines += [test_instruct_prompt]
    lines += ["", TAIL, "### cot", "", "### code", ""]
    return "\n".join(lines)


def _validate_task_ids(task_ids: Sequence[str], known: dict[str, Any]) -> list[str]:
    requested = list(task_ids)
    if not requested:
        raise PoisonMaterializeError("task_ids must not be empty")
    duplicates = sorted(
        {task_id for task_id in requested if requested.count(task_id) > 1}
    )
    if duplicates:
        raise PoisonMaterializeError(f"duplicate task_ids requested: {duplicates}")
    unknown = [task_id for task_id in requested if task_id not in known]
    if unknown:
        raise PoisonMaterializeError(
            f"requested task_ids are absent from the prepared data: {unknown}"
        )
    return requested


def _source_files(snapshot: TemplateSnapshot) -> dict[str, str]:
    """Record the read-only clean sources the snapshot was built from."""

    source = snapshot.source or {}
    pairs = (
        (source.get("fewshot_path"), source.get("fewshot_sha256")),
        (source.get("meta_path"), source.get("meta_sha256")),
        (source.get("task_file"), source.get("task_file_sha256")),
    )
    return {str(path): str(digest) for path, digest in pairs if path and digest}


def _build_meta(
    *,
    snapshot: TemplateSnapshot,
    prepared: Any,
    prompt_version: str,
    materialize_version: str,
) -> dict[str, Any]:
    example_ids = list(prepared.selection.example_ids)
    files = prepared.files or {}
    return {
        "schema_version": "1",
        "combination_id": snapshot.combination_id,
        "oracle_id": prepared.oracle_id,
        "form": snapshot.form,
        "has_cot": True,
        "example_ids": example_ids,
        "excluded_ids": list(example_ids),
        "evaluation_ids": list(prepared.selection.evaluation_ids),
        "data_contract": prepared.data_contract,
        "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
        "selection_sha256": files.get("selection.json"),
        "split_manifest_sha256": files.get("split.json"),
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "prompt_version": prompt_version,
        "materialize_version": materialize_version,
        "attack_config": snapshot.attack_config(),
        "source_files": _source_files(snapshot),
        "template": {
            "content_sha256": snapshot.content_sha256(),
            "protocol_version": snapshot.protocol_version,
            "trigger": snapshot.trigger,
            "injection_position": snapshot.injection_position,
            "mode": snapshot.mode,
        },
    }


def _check_immutable(
    manifest_path: Path,
    *,
    combination_id: str,
    form: str,
    template_sha256: str,
) -> None:
    """Refuse to overwrite a tree that records a different template or form.

    Identical re-materialization is idempotent (same bytes are rewritten).
    """

    if not manifest_path.is_file():
        return
    try:
        existing = read_json(manifest_path)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise PoisonMaterializeError(
            f"existing prompt manifest {manifest_path} is unreadable: {error}"
        ) from error
    if not isinstance(existing, dict):
        raise PoisonMaterializeError(
            f"existing prompt manifest {manifest_path} is not a JSON object"
        )
    existing_template = (existing.get("template") or {}).get("content_sha256")
    existing_forms = set((existing.get("forms") or {}).keys())
    existing_combination = existing.get("combination_id")
    if (
        existing_template != template_sha256
        or existing_forms != {form}
        or existing_combination != combination_id
    ):
        raise PoisonMaterializeError(
            f"refusing to overwrite {manifest_path}: it records template "
            f"{existing_template!r} forms {sorted(existing_forms)} for combination "
            f"{existing_combination!r}, but template {template_sha256!r} form "
            f"{form!r} was requested"
        )


def materialize_poisoned(
    *,
    snapshot: TemplateSnapshot,
    data_dir: Path | str,
    task_ids: Sequence[str],
    output_dir: Path | str,
    prompt_version: str = "1",
    materialize_version: str = POISON_MATERIALIZE_VERSION,
) -> dict[str, Any]:
    """Write a poisoned prompt tree for ``task_ids`` from ``snapshot``.

    The snapshot is expected to be already patched; this function records the
    real snapshot content (including a real ``attack_config``) and renders only
    the requested test tasks.  Every file is written before ``manifest.json``,
    which carries the completion marker and per-file hashes.
    """

    if not isinstance(snapshot, TemplateSnapshot):
        raise PoisonMaterializeError("materialize_poisoned requires a TemplateSnapshot")

    prepared = load_prepared_data(Path(data_dir), snapshot.combination_id)
    tasks = prepared.task_by_id()
    requested = _validate_task_ids(task_ids, tasks)

    try:
        filenames = {
            task_id: task_id_to_prompt_filename(task_id) for task_id in requested
        }
    except ValueError as error:
        raise PoisonMaterializeError(str(error)) from error

    # Render everything and validate immutability before touching the tree.
    output_root = Path(output_dir)
    combo_dir = output_root / snapshot.combination_id / snapshot.form
    prompts_dir = combo_dir / "test_prompts"
    manifest_path = output_root / "manifest.json"
    template_sha256 = snapshot.content_sha256()
    _check_immutable(
        manifest_path,
        combination_id=snapshot.combination_id,
        form=snapshot.form,
        template_sha256=template_sha256,
    )

    fewshot_payload = [example.content_json() for example in snapshot.examples]
    meta_payload = _build_meta(
        snapshot=snapshot,
        prepared=prepared,
        prompt_version=prompt_version,
        materialize_version=materialize_version,
    )

    combo_dir.mkdir(parents=True, exist_ok=True)
    prompts_dir.mkdir(parents=True, exist_ok=True)
    # The directory must hold exactly the requested tasks; drop stale prompts
    # from an earlier, otherwise-compatible materialization.
    for child in prompts_dir.iterdir():
        if child.is_file() and child.name not in set(filenames.values()):
            child.unlink()

    write_json_atomic(combo_dir / "fewshot.json", fewshot_payload)
    write_json_atomic(combo_dir / "meta.json", meta_payload)
    for task_id in requested:
        test_prompt = tasks[task_id].effective["instruct_prompt"]
        if snapshot.trigger is not None:
            test_prompt = inject_trigger(test_prompt, snapshot.trigger)
        rendered = render_test_prompt(snapshot.examples, test_prompt)
        write_bytes_atomic(prompts_dir / filenames[task_id], rendered.encode("utf-8"))

    fewshot_path = combo_dir / "fewshot.json"
    meta_path = combo_dir / "meta.json"
    prompt_hashes = {
        task_id: sha256_file(prompts_dir / filenames[task_id]) for task_id in requested
    }
    files: dict[str, str] = {
        relative_to_root(output_root, fewshot_path): sha256_file(fewshot_path),
        relative_to_root(output_root, meta_path): sha256_file(meta_path),
    }
    for task_id in requested:
        path = prompts_dir / filenames[task_id]
        files[relative_to_root(output_root, path)] = sha256_file(path)

    manifest = {
        "schema_version": "1",
        "completion": "complete",
        "combination_id": snapshot.combination_id,
        "oracle_id": prepared.oracle_id,
        "data_contract": prepared.data_contract,
        "prompt_version": prompt_version,
        "materialize_version": materialize_version,
        "template": {
            "content_sha256": template_sha256,
            "protocol_version": snapshot.protocol_version,
            "form": snapshot.form,
        },
        "forms": {
            snapshot.form: {
                "has_cot": True,
                "meta_sha256": sha256_file(meta_path),
                "prompt_hashes": prompt_hashes,
                "files": files,
            }
        },
    }
    # Completion marker last: a half-written tree has no usable manifest.
    write_json_atomic(manifest_path, manifest)

    return {
        "combination_id": snapshot.combination_id,
        "form": snapshot.form,
        "template_sha256": template_sha256,
        "meta_sha256": sha256_file(meta_path),
        "prompt_hashes": prompt_hashes,
        "fewshot_sha256": sha256_file(fewshot_path),
        "output_dir": str(output_root),
        "task_ids": requested,
    }


def verify_poisoned_inputs(
    *,
    prompts_dir: Path | str,
    data_dir: Path | str,
    combination_id: str,
    form: str,
    stage: str,
    repeats: int,
    batch_id: str,
    prompt_version: str,
    task_ids: Sequence[str],
) -> GenerationInputs:
    """Reuse the real generation loader so tests/CLI share one read path."""

    return load_generation_inputs(
        data_dir=data_dir,
        prompts_dir=prompts_dir,
        combination_id=combination_id,
        form=form,
        stage=stage,
        repeats=repeats,
        batch_id=batch_id,
        prompt_version=prompt_version,
        task_ids=list(task_ids),
    )


__all__ = [
    "POISON_MATERIALIZE_VERSION",
    "DEFAULT_POISON_FORM",
    "OPENING",
    "TAIL",
    "PoisonMaterializeError",
    "render_test_prompt",
    "materialize_poisoned",
    "verify_poisoned_inputs",
]
