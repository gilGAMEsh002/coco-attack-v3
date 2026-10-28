"""Thin method adapter over the existing generation/evaluation services.

This module deliberately does not own any public semantics.  It only fixes the
request configuration for one materialized template, invokes the public
generate/clean/static/SAST/functional services, and returns their raw records.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from coco_attack.assets.artifacts import canonical_json_bytes, read_json, write_json_atomic
from coco_attack.data.snapshot import load_prepared_data
from coco_attack.evaluation.contracts import EvaluationConfig
from coco_attack.evaluation.run_cleaning import clean_generations
from coco_attack.evaluation.run_functional import (
    FunctionalConfig,
    run_evaluate_functional,
    run_resume_functional,
)
from coco_attack.evaluation.run_other import (
    EvaluatorsConfig,
    run_evaluate_other,
    run_resume_other,
)
from coco_attack.evaluation.run_static import evaluate_static
from coco_attack.generation.contracts import GenerationConfig
from coco_attack.iteration.poison_materialize import materialize_poisoned
from coco_attack.iteration.template_snapshot import TemplateSnapshot

_GENERATION_EXPLICIT = (
    "source", "model", "batch_id", "temperature", "max_tokens", "request_timeout",
    "max_concurrency", "max_request_attempts", "max_sample_retries",
)
_LAYER_ROW_FILES = {
    "generation": Path("generation/generations.jsonl"),
    "cleaning": Path("cleaning/cleaned_generations.jsonl"),
    "static": Path("static/evaluations.jsonl"),
    "sast": Path("sast/layers/sast.jsonl"),
    "functional": Path("functional/functional_results.jsonl"),
}


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"settings.{where} must be a mapping")
    return dict(value)


def _require_path(value: Any, where: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise ValueError(f"settings.{where} must be a non-empty path")
    return Path(value)


def _check_equal(payload: dict[str, Any], key: str, expected: Any) -> None:
    if key in payload and payload[key] != expected:
        raise ValueError(
            f"settings.generation.{key}={payload[key]!r} conflicts with the "
            f"measurement identity {expected!r}"
        )


def _generation_config(
    settings: Mapping[str, Any], snapshot: TemplateSnapshot, prepared: Any
) -> GenerationConfig:
    raw = _require_mapping(settings["generation"], "generation")
    missing = [key for key in _GENERATION_EXPLICIT if key not in raw]
    if missing:
        raise ValueError(f"settings.generation is missing explicit fields: {missing}")
    if raw['max_sample_retries'] != 0:
        raise ValueError('current public generator supports request retries only; max_sample_retries must explicitly be 0')
    for key in ("combination_id", "oracle_id", "stage", "form", "prompt_version", "repeats"):
        expected = {
            "combination_id": prepared.combination_id,
            "oracle_id": prepared.oracle_id,
            "stage": settings["stage"],
            "form": snapshot.form,
            "prompt_version": snapshot.prompt_version,
            "repeats": settings["repeats"],
        }[key]
        _check_equal(raw, key, expected)
    if "task_ids" in raw and tuple(raw["task_ids"]) != tuple(settings["task_ids"]):
        raise ValueError("settings.generation.task_ids conflicts with settings.task_ids")

    allowed = set(GenerationConfig.__dataclass_fields__)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"settings.generation has unknown fields: {unknown}")
    payload = dict(raw)
    payload.update(
        combination_id=prepared.combination_id,
        oracle_id=prepared.oracle_id,
        stage=settings["stage"],
        form=snapshot.form,
        prompt_version=snapshot.prompt_version,
        repeats=settings["repeats"],
        task_ids=tuple(settings["task_ids"]),
    )
    payload.setdefault("candidate_hash", "")
    return GenerationConfig(**payload)


def _evaluation_config(
    settings: Mapping[str, Any], snapshot: TemplateSnapshot, prepared: Any,
    generation: GenerationConfig,
) -> EvaluationConfig:
    return EvaluationConfig(
        combination_id=prepared.combination_id,
        oracle_id=prepared.oracle_id,
        model=generation.model,
        temperature=generation.temperature,
        repeats=generation.repeats,
        task_set=settings["stage"],
        prompt_form=snapshot.form,
        task_ids=tuple(settings["task_ids"]),
    )


def _evaluators_config(
    settings: Mapping[str, Any], prepared: Any, generation: GenerationConfig
) -> EvaluatorsConfig:
    raw = _require_mapping(settings["evaluators"], "evaluators")
    for key in ("sast_tools", "semgrep_config", "codeql_executable", "codeql_search_path"):
        if key not in raw:
            raise ValueError(f"settings.evaluators must explicitly provide {key}")
    if "enabled_layers" in raw and tuple(raw["enabled_layers"]) != ("sast",):
        raise ValueError("settings.evaluators may only enable the sast layer")
    if "task_ids" in raw and tuple(raw["task_ids"]) != tuple(settings["task_ids"]):
        raise ValueError("settings.evaluators.task_ids conflicts with settings.task_ids")
    allowed = set(EvaluatorsConfig.__dataclass_fields__)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"settings.evaluators has unknown fields: {unknown}")
    payload = dict(raw)
    payload.update(
        combination_id=prepared.combination_id,
        oracle_id=prepared.oracle_id,
        stage=settings["stage"],
        enabled_layers=("sast",),
        task_ids=tuple(settings["task_ids"]),
        victim_temperature=generation.temperature,
        victim_repeats=generation.repeats,
        batch_id=generation.batch_id,
        model=generation.model,
    )
    return EvaluatorsConfig(**payload)


def _functional_config(
    settings: Mapping[str, Any], prepared: Any, generation: GenerationConfig
) -> FunctionalConfig:
    raw = _require_mapping(settings["functional"], "functional")
    for key in ("k", "harness_version", "candidate_timeout_seconds"):
        if key not in raw:
            raise ValueError(f"settings.functional must explicitly provide {key}")
    if "task_ids" in raw and tuple(raw["task_ids"]) != tuple(settings["task_ids"]):
        raise ValueError("settings.functional.task_ids conflicts with settings.task_ids")
    allowed = set(FunctionalConfig.__dataclass_fields__)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"settings.functional has unknown fields: {unknown}")
    payload = dict(raw)
    payload.update(
        combination_id=prepared.combination_id,
        oracle_id=prepared.oracle_id,
        stage=settings["stage"],
        task_ids=tuple(settings["task_ids"]),
        batch_id=generation.batch_id,
        model=generation.model,
        temperature=generation.temperature,
        repeats=generation.repeats,
    )
    return FunctionalConfig(**payload)


def _write_fixed(path: Path, payload: Any) -> None:
    if path.is_file():
        try:
            existing = read_json(path)
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"existing configuration is unreadable: {path}: {error}") from error
        if canonical_json_bytes(existing) != canonical_json_bytes(payload):
            raise ValueError(
                f"{path} already records a different configuration; refusing to overwrite it"
            )
        return
    write_json_atomic(path, payload)


def _read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise ValueError(f"{path}:{lineno}: invalid JSONL record: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{lineno}: record is not a JSON object")
            rows.append(row)
    return rows


def _run_generation_cli(
    command: str, *, config_path: Path | None, data_dir: Path | None,
    prompts_dir: Path | None, run_dir: Path, repo_dir: Path | None,
) -> Any:
    args = [sys.executable, "-m", "coco_attack", command]
    if command == "generate":
        args += [
            "--config", str(config_path), "--data-dir", str(data_dir),
            "--prompts-dir", str(prompts_dir), "--output-dir", str(run_dir),
        ]
    else:
        args += ["--run-dir", str(run_dir)]
    if repo_dir is not None:
        args += ["--repo-dir", str(repo_dir)]
    return subprocess.run(args, capture_output=True, text=True)


def _tail(value: Any, limit: int = 500) -> str:
    text = value if isinstance(value, str) else ""
    text = text.strip()
    return text[-limit:]


def _count_gap(layer: str, rows: Sequence[Any], expected: int, gaps: list[str]) -> None:
    if len(rows) != expected:
        gaps.append(f"{layer}: expected {expected} raw rows, found {len(rows)}")


def public_measure(
    snapshot: TemplateSnapshot, output_dir: Path, settings: dict
) -> dict[str, Any]:
    """Run the public measurement stack for ``snapshot`` and return raw layers.

    Required ``settings`` keys are ``assets_root``, ``data_dir``, ``task_ids``
    (exactly two task IDs), ``repeats``, ``stage`` (``search``/``holdout``),
    ``generation``, ``evaluators``, ``functional``, ``execution_config_path``
    and ``cache_dir``.  An optional ``repo_dir`` is forwarded to the generation
    subprocess for real (dmx) runs.
    """

    if not isinstance(settings, Mapping):
        raise ValueError("settings must be a mapping")
    missing = [
        key for key in (
            "assets_root", "data_dir", "task_ids", "repeats", "stage", "generation",
            "evaluators", "functional", "execution_config_path", "cache_dir",
        ) if key not in settings
    ]
    if missing:
        raise ValueError(f"settings is missing required keys: {missing}")
    task_ids = settings["task_ids"]
    if (
        not isinstance(task_ids, (list, tuple)) or len(task_ids) != 2
        or any(not isinstance(task_id, str) or not task_id for task_id in task_ids)
        or len(set(task_ids)) != 2
    ):
        raise ValueError("settings.task_ids must contain exactly two distinct task IDs")
    stage = settings["stage"]
    if stage not in ("search", "holdout"):
        raise ValueError("settings.stage must be 'search' or 'holdout'")
    repeats = settings["repeats"]
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 1:
        raise ValueError("settings.repeats must be a positive integer")
    assets_root = _require_path(settings["assets_root"], "assets_root")
    data_dir = _require_path(settings["data_dir"], "data_dir")
    execution_config_path = _require_path(
        settings["execution_config_path"], "execution_config_path"
    )
    cache_dir = _require_path(settings["cache_dir"], "cache_dir")
    repo_dir = Path(settings["repo_dir"]) if settings.get("repo_dir") else None

    prepared = load_prepared_data(data_dir, snapshot.combination_id)
    allowed_ids = prepared.split.search_ids if stage == "search" else prepared.split.holdout_ids
    unknown = sorted(set(task_ids) - set(allowed_ids))
    if unknown:
        raise ValueError(
            f"settings.task_ids are not in the public {stage} split: {unknown}"
        )

    generation = _generation_config(settings, snapshot, prepared)
    evaluation = _evaluation_config(settings, snapshot, prepared, generation)
    evaluators = _evaluators_config(settings, prepared, generation)
    functional = _functional_config(settings, prepared, generation)

    output = Path(output_dir)
    configs_dir = output / "configs"
    prompts_dir = output / "prompts"
    generation_dir = output / "generation"
    cleaning_dir = output / "cleaning"
    static_dir = output / "static"
    sast_dir = output / "sast"
    functional_dir = output / "functional"
    config_paths = {
        "generation": configs_dir / "generation.json",
        "evaluation": configs_dir / "evaluation.json",
        "evaluators": configs_dir / "evaluators.json",
        "functional": configs_dir / "functional.json",
    }
    _write_fixed(config_paths["generation"], generation.to_json())
    _write_fixed(config_paths["evaluation"], evaluation.to_json())
    _write_fixed(config_paths["evaluators"], evaluators.to_json())
    _write_fixed(config_paths["functional"], functional.to_json())

    materialize_poisoned(
        snapshot=snapshot, data_dir=data_dir, task_ids=list(task_ids),
        output_dir=prompts_dir, prompt_version=snapshot.prompt_version,
    )

    gaps: list[str] = []
    rows: dict[str, list[dict[str, Any]]] = {name: [] for name in _LAYER_ROW_FILES}
    expected_samples = len(task_ids) * repeats
    generation_finished = False

    # 1. Victim generation: a new run uses ``generate``; an existing run uses
    # the public resume entry point so finalized samples are never re-sampled.
    try:
        if (generation_dir / "run_config.json").is_file():
            from coco_attack.runtime.ledger import Ledger
            replay = Ledger(generation_dir / "ledger.jsonl").replay()
            finalized = replay.finalized_sample_ids()
            responses = set(replay.responses_by_sample())
            unresolved = {e['sample_id'] for e in replay.events if e['event_type'] == 'attempt_started'} - finalized - responses
            if unresolved:
                raise ValueError('prior victim attempts lack a durable response/final result; implicit retry is disabled')
            completed = _run_generation_cli(
                "resume-generation", config_path=None, data_dir=None,
                prompts_dir=None, run_dir=generation_dir, repo_dir=repo_dir,
            )
        elif generation_dir.exists():
            raise ValueError(
                f"{generation_dir} exists without run_config.json; cannot resume or "
                "start a fresh generation run"
            )
        else:
            completed = _run_generation_cli(
                "generate", config_path=config_paths["generation"], data_dir=data_dir,
                prompts_dir=prompts_dir, run_dir=generation_dir, repo_dir=repo_dir,
            )
        rows["generation"] = _read_rows(generation_dir / "generations.jsonl")
        if completed.returncode != 0:
            gaps.append(
                f"generation: subprocess exited {completed.returncode}: "
                f"{_tail(completed.stderr)}"
            )
        else:
            generation_finished = True
            _count_gap("generation", rows["generation"], expected_samples, gaps)
    except Exception as error:  # noqa: BLE001 - preserve the layer failure as a gap
        gaps.append(f"generation: {type(error).__name__}: {error}")

    # 2. Cleaning.
    if rows["generation"]:
        try:
            clean_generations(prepared, generation_dir / "generations.jsonl", cleaning_dir)
            rows["cleaning"] = _read_rows(cleaning_dir / "cleaned_generations.jsonl")
            _count_gap("cleaning", rows["cleaning"], expected_samples, gaps)
        except Exception as error:  # noqa: BLE001
            gaps.append(f"cleaning: {type(error).__name__}: {error}")
    else:
        gaps.append("cleaning: skipped because generation produced no rows")

    # 3. Static oracle.
    if rows["cleaning"]:
        try:
            evaluate_static(
                assets_root, data_dir, cleaning_dir,
                config_paths["evaluation"], static_dir,
            )
            rows["static"] = _read_rows(static_dir / "evaluations.jsonl")
            _count_gap("static", rows["static"], expected_samples, gaps)
        except Exception as error:  # noqa: BLE001
            gaps.append(f"static: {type(error).__name__}: {error}")
    else:
        gaps.append("static: skipped because no cleaned rows are available")

    # 4. SAST only (explicit tools/rules).
    if rows["cleaning"]:
        try:
            if (sast_dir / "manifest.json").is_file():
                run_resume_other(sast_dir)
            else:
                run_evaluate_other(
                    config_paths["evaluators"], data_dir, generation_dir, cleaning_dir,
                    None, sast_dir, execution_config_path=execution_config_path,
                )
            rows["sast"] = _read_rows(sast_dir / "layers" / "sast.jsonl")
            _count_gap(
                "sast", rows["sast"], expected_samples * len(evaluators.sast_tools), gaps
            )
        except Exception as error:  # noqa: BLE001
            gaps.append(f"sast: {type(error).__name__}: {error}")
    else:
        gaps.append("sast: skipped because no cleaned rows are available")

    # 5. Functional.  Its failure never removes the oracle/SAST rows above.
    if rows["cleaning"]:
        try:
            if (functional_dir / "functional_config.json").is_file():
                run_resume_functional(functional_dir)
            else:
                run_evaluate_functional(
                    config_paths["functional"], data_dir, generation_dir, cleaning_dir,
                    execution_config_path, cache_dir, functional_dir,
                )
            rows["functional"] = _read_rows(functional_dir / "functional_results.jsonl")
            _count_gap("functional", rows["functional"], expected_samples, gaps)
        except Exception as error:  # noqa: BLE001 - functional faults are gaps, not passes
            gaps.append(f"functional: {type(error).__name__}: {error}")
    else:
        gaps.append("functional: skipped because no cleaned rows are available")

    # Even an interrupted layer may already have durable per-sample facts.
    for layer, relative in _LAYER_ROW_FILES.items():
        if not rows[layer] and (output / relative).is_file():
            rows[layer] = _read_rows(output / relative)
    consumption_candidates = [
        generation_dir / "ledger.jsonl",
        sast_dir / "ledger.jsonl",
        functional_dir / "ledger.jsonl",
    ]
    consumption_refs = list(dict.fromkeys(
        str(path) for path in consumption_candidates if path.is_file()
    ))
    return {
        "complete": generation_finished and all(
            len(rows[layer]) == expected_samples * (len(evaluators.sast_tools) if layer == "sast" else 1)
            for layer in _LAYER_ROW_FILES
        ),
        "generation_rows": rows["generation"],
        "cleaned_rows": rows["cleaning"],
        "static_rows": rows["static"],
        "sast_rows": rows["sast"],
        "functional_rows": rows["functional"],
        "consumption_refs": consumption_refs,
        "gaps": gaps,
    }


__all__ = ["public_measure"]
