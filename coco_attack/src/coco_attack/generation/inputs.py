"""Read-only validation of generation inputs and the sample manifest.

Generation consumes the stage-01 prepared data and materialized prompt
snapshots.  It never re-samples, re-materializes or mutates those assets; every
hash is re-verified before a sample manifest is built.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)
from ..assets.schema import TEST_PROMPT_RE
from ..data.snapshot import load_prepared_data
from ..protocol.stages import SplitMode
from .contracts import GenerationContractError, SampleIdentity

INPUTS_SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class GenerationSample:
    identity: SampleIdentity
    prompt: str
    prompt_sha256: str

    @property
    def sample_id(self) -> str:
        return self.identity.sample_id()

    @property
    def rollout_id(self) -> int:
        return self.identity.rollout_id()


@dataclass(frozen=True)
class GenerationInputs:
    combination_id: str
    oracle_id: str
    form: str
    stage: str
    task_snapshot_sha256: str
    prompt_manifest_sha256: str
    candidate_hash: str
    samples: tuple[GenerationSample, ...]

    def sample_ids(self) -> tuple[str, ...]:
        return tuple(sample.sample_id for sample in self.samples)


def _prompt_filename(task_id: str) -> str:
    prefix = "BigCodeBench/"
    if not task_id.startswith(prefix):
        raise GenerationContractError(f"unexpected task id shape: {task_id!r}")
    number = task_id[len(prefix):]
    return f"BigCodeBench_SL_{number}.md"


def _task_ids_from_prompt_dir(directory: Path) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    if not directory.is_dir():
        raise GenerationContractError(f"prompt directory missing: {directory}")
    for child in sorted(directory.iterdir()):
        if not child.is_file():
            continue
        match = TEST_PROMPT_RE.match(child.name)
        if match is None:
            raise GenerationContractError(f"unexpected prompt filename: {child.name}")
        mapping[f"BigCodeBench/{match.group(1)}"] = child
    return mapping


def select_stage_task_ids(prepared, stage: str) -> tuple[str, ...]:
    """Return the fixed task ids belonging to ``stage`` for a prepared dataset.

    ``search`` maps to the search split (or the whole evaluation set for
    whole-set combinations); ``holdout`` maps to the holdout split and is only
    valid for search/holdout combinations.
    """

    if stage not in ("search", "holdout"):
        raise GenerationContractError(f"invalid stage: {stage!r}")
    split = prepared.split
    if split.mode is SplitMode.SEARCH_HOLDOUT:
        if stage == "search":
            return tuple(split.search_ids)
        return tuple(split.holdout_ids)
    # whole-set: no holdout exists; the scheduling stage is search.
    if stage != "search":
        raise GenerationContractError(
            "whole-set combinations have no holdout split; stage must be 'search'"
        )
    return tuple(split.evaluation_ids)


def compute_candidate_hash(
    *,
    combination_id: str,
    form: str,
    prompt_version: str,
    prompt_hashes: dict[str, str],
    meta_sha256: str,
    fewshot_sha256: str,
) -> str:
    """Stable clean-template identity; no time/paths/randomness."""

    payload = {
        "schema_version": INPUTS_SCHEMA_VERSION,
        "combination_id": combination_id,
        "form": form,
        "prompt_version": prompt_version,
        "meta_sha256": meta_sha256,
        "fewshot_sha256": fewshot_sha256,
        "prompt_hashes": dict(sorted(prompt_hashes.items())),
    }
    return sha256_bytes(canonical_json_bytes(payload))


def load_generation_inputs(
    data_dir: Path | str,
    prompts_dir: Path | str,
    *,
    combination_id: str,
    form: str,
    stage: str,
    repeats: int,
    batch_id: str,
    prompt_version: str,
    task_ids: Sequence[str] | None = None,
) -> GenerationInputs:
    if repeats < 1:
        raise GenerationContractError("repeats must be >= 1")
    prepared = load_prepared_data(Path(data_dir), combination_id)
    if prepared.oracle_id and not prepared.oracle_id:
        raise GenerationContractError("prepared oracle id missing")

    prompts_root = Path(prompts_dir)
    manifest_path = prompts_root / "manifest.json"
    if not manifest_path.is_file():
        raise GenerationContractError(f"prompt manifest missing: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("completion") != "complete":
        raise GenerationContractError("prompt manifest is not complete")
    if manifest.get("combination_id") != combination_id:
        raise GenerationContractError(
            f"prompt manifest combination {manifest.get('combination_id')!r} != {combination_id!r}"
        )
    manifest_prompt_version = manifest.get("prompt_version")
    if prompt_version != str(manifest_prompt_version):
        # The requested version must match the materialized snapshot.
        raise GenerationContractError(
            f"prompt_version {prompt_version!r} != manifest {manifest_prompt_version!r}"
        )
    forms = manifest.get("forms") or {}
    if form not in forms:
        raise GenerationContractError(f"form {form!r} not present in prompt manifest")
    form_entry = forms[form]
    prompt_hashes = form_entry.get("prompt_hashes") or {}

    combo_dir = prompts_root / combination_id / form
    meta_path = combo_dir / "meta.json"
    fewshot_path = combo_dir / "fewshot.json"
    if not meta_path.is_file() or not fewshot_path.is_file():
        raise GenerationContractError(f"materialized form incomplete under {combo_dir}")
    if sha256_file(meta_path) != form_entry.get("meta_sha256"):
        raise GenerationContractError("meta.json hash does not match prompt manifest")

    files = _task_ids_from_prompt_dir(combo_dir / "test_prompts")
    selected = select_stage_task_ids(prepared, stage)
    if task_ids is not None:
        allowed = set(selected)
        requested = list(dict.fromkeys(task_ids))
        unknown = [task_id for task_id in requested if task_id not in allowed]
        if unknown:
            raise GenerationContractError(
                f"requested task_ids are not in the {stage} set: {unknown}"
            )
        selected = tuple(requested)
    tasks = prepared.task_by_id()
    missing = [task_id for task_id in selected if task_id not in tasks]
    if missing:
        raise GenerationContractError(f"selected task ids absent from prepared data: {missing}")
    missing_prompts = [task_id for task_id in selected if task_id not in files]
    if missing_prompts:
        raise GenerationContractError(
            f"selected tasks have no materialized prompt: {missing_prompts}"
        )

    candidate_hash = compute_candidate_hash(
        combination_id=combination_id,
        form=form,
        prompt_version=prompt_version,
        prompt_hashes={task_id: prompt_hashes.get(task_id, "") for task_id in selected},
        meta_sha256=str(form_entry.get("meta_sha256") or ""),
        fewshot_sha256=sha256_file(fewshot_path),
    )

    samples: list[GenerationSample] = []
    for task_id in selected:
        prompt_bytes = files[task_id].read_bytes()
        actual_hash = sha256_bytes(prompt_bytes)
        declared = prompt_hashes.get(task_id)
        if declared is not None and declared != actual_hash:
            raise GenerationContractError(
                f"prompt hash mismatch for {task_id}: manifest {declared} != actual {actual_hash}"
            )
        prompt = prompt_bytes.decode("utf-8")
        for repeat_id in range(repeats):
            identity = SampleIdentity(
                stage=stage,
                batch_id=batch_id,
                combination_id=combination_id,
                task_id=task_id,
                repeat_id=repeat_id,
                prompt_version=prompt_version,
                candidate_hash=candidate_hash,
            )
            samples.append(
                GenerationSample(identity=identity, prompt=prompt, prompt_sha256=actual_hash)
            )

    return GenerationInputs(
        combination_id=combination_id,
        oracle_id=prepared.oracle_id,
        form=form,
        stage=stage,
        task_snapshot_sha256=prepared.selection.task_snapshot_sha256,
        prompt_manifest_sha256=sha256_file(manifest_path),
        candidate_hash=candidate_hash,
        samples=tuple(samples),
    )
