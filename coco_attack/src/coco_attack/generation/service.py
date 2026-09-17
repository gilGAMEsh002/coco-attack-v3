"""Orchestration for the generation CLI commands (plan section 9).

This module keeps ``cli.py`` thin: it loads/validates configuration, builds the
sample manifest, owns the run directory and the ledger, selects the model
source, and writes the run artifacts.  Importing it must not load credentials,
create an LM or touch the DSPy cache.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    assert_fresh_dir,
    read_json,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..execution.supervisor import RunLock
from ..runtime.cache import assert_physical_separation, configure_stage_cache, namespace_path
from ..runtime.ledger import Ledger
from .contracts import GenerationConfig, GenerationContractError
from .inputs import load_generation_inputs
from .runner import GenerationRunner
from .source import MockSource

GENERATION_SCHEMA_VERSION = "1"
DMX_BASE = "https://www.dmxapi.cn/v1"


def load_generation_config(config_path: Path | str) -> GenerationConfig:
    path = Path(config_path)
    if not path.is_file():
        raise GenerationContractError(f"generation config is not a file: {path}")
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise GenerationContractError("generation config must be a JSON object")
    return GenerationConfig.from_json(payload)


def load_dmx_api_key(repo_dir: Path | str | None) -> str:
    if repo_dir is None:
        raise GenerationContractError("--repo-dir is required for real (dmx) generation")
    env_path = Path(repo_dir) / ".env"
    if not env_path.is_file():
        raise GenerationContractError(f".env not found under --repo-dir: {env_path}")
    try:
        from dotenv import dotenv_values
    except ImportError as error:  # pragma: no cover - dependency declared
        raise GenerationContractError("python-dotenv is required to read .env") from error
    values = dotenv_values(env_path)
    key = values.get("DMX_API_KEY")
    if not key:
        raise GenerationContractError("DMX_API_KEY is not set in .env")
    return str(key)


def _build_inputs(config: GenerationConfig, data_dir: Path, prompts_dir: Path):
    return load_generation_inputs(
        data_dir,
        prompts_dir,
        combination_id=config.combination_id,
        form=config.form,
        stage=config.stage,
        repeats=config.repeats,
        batch_id=config.batch_id,
        prompt_version=config.prompt_version,
        task_ids=config.task_ids or None,
    )


def _resolve_config(config: GenerationConfig, inputs) -> GenerationConfig:
    """Adopt the candidate hash computed from the materialized prompt snapshot."""

    if config.candidate_hash and config.candidate_hash != inputs.candidate_hash:
        raise GenerationContractError(
            "config.candidate_hash does not match the materialized prompt snapshot"
        )
    return replace(config, candidate_hash=inputs.candidate_hash)


def _activate_cache(config: GenerationConfig, run_dir: Path) -> Path:
    """Assign and activate a source/stage-scoped DSPy cache namespace."""

    cache_root = run_dir / "dspy-cache"
    path = configure_stage_cache(cache_root, config.source, config.stage)
    assert_physical_separation(
        [
            namespace_path(cache_root, "dmx", "search"),
            namespace_path(cache_root, "dmx", "holdout"),
            namespace_path(cache_root, "mock", "search"),
            namespace_path(cache_root, "mock", "holdout"),
        ]
    )
    return path


def _run_config_payload(
    config: GenerationConfig,
    inputs,
    data_dir: Path,
    prompts_dir: Path,
    cache_dir: Path,
) -> dict[str, Any]:
    return {
        "schema_version": GENERATION_SCHEMA_VERSION,
        "config": config.to_json(),
        "run_config_hash": config.run_config_hash(),
        "cache_dir": str(cache_dir),
        "inputs": {
            "data_dir": str(Path(data_dir).resolve()),
            "prompts_dir": str(Path(prompts_dir).resolve()),
            "combination_id": inputs.combination_id,
            "oracle_id": inputs.oracle_id,
            "form": inputs.form,
            "stage": inputs.stage,
            "candidate_hash": inputs.candidate_hash,
            "task_snapshot_sha256": inputs.task_snapshot_sha256,
            "prompt_manifest_sha256": inputs.prompt_manifest_sha256,
            "sample_count": len(inputs.samples),
        },
    }


def _write_report(path: Path, lines: list[str]) -> None:
    write_text_atomic(path, "\n".join(["# Generation report", "", *lines, ""]))


def _summary_from_ledger(ledger: Ledger) -> dict[str, Any]:
    replay = ledger.replay()
    records = replay.finalized_records()
    status_counts: dict[str, int] = {}
    for record in records.values():
        status = str(record.get("status"))
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "finalized_total": len(records),
        "status_counts": dict(sorted(status_counts.items())),
        "incomplete_tail": replay.incomplete_tail_path,
    }


def _run_generation(
    *,
    config: GenerationConfig,
    inputs,
    run_dir: Path,
    source,
) -> dict[str, Any]:
    ledger = Ledger(run_dir / "ledger.jsonl")
    runner = GenerationRunner(config, inputs, ledger, source, run_dir)
    outcome = runner.run()
    summary = {
        "schema_version": GENERATION_SCHEMA_VERSION,
        "run_config_hash": config.run_config_hash(),
        **outcome,
        **_summary_from_ledger(ledger),
    }
    write_json_atomic(run_dir / "generation_summary.json", summary)
    _write_report(
        run_dir / "REPORT.md",
        [
            f"- source: `{config.source}` model `{config.model}`",
            f"- plan: requested {summary['requested']}, generated {summary['generated']}, "
            f"skipped {summary['skipped_finalized']}",
            f"- status counts: {summary['status_counts']}",
        ],
    )
    return summary


def run_check_generation(
    config_path: Path | str,
    data_dir: Path | str,
    prompts_dir: Path | str,
    output_dir: Path | str,
) -> int:
    config = load_generation_config(config_path)
    inputs = _build_inputs(config, Path(data_dir), Path(prompts_dir))
    config = _resolve_config(config, inputs)
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": GENERATION_SCHEMA_VERSION,
        "config_path": str(Path(config_path).resolve()),
        "config": config.to_json(),
        "run_config_hash": config.run_config_hash(),
        "inputs": {
            "combination_id": inputs.combination_id,
            "oracle_id": inputs.oracle_id,
            "form": inputs.form,
            "stage": inputs.stage,
            "candidate_hash": inputs.candidate_hash,
            "sample_count": len(inputs.samples),
            "task_ids": sorted({s.identity.task_id for s in inputs.samples}),
            "repeats": config.repeats,
            "task_snapshot_sha256": inputs.task_snapshot_sha256,
            "prompt_manifest_sha256": inputs.prompt_manifest_sha256,
        },
        "checks": [
            {"id": "config", "status": "pass"},
            {"id": "inputs", "status": "pass"},
            {"id": "credentials", "status": "pass" if config.source == "mock" else "not_sent"},
        ],
    }
    write_json_atomic(output / "generation_check.json", payload)
    _write_report(
        output / "REPORT.md",
        [
            f"- source: `{config.source}` (no model request is sent by this command)",
            f"- samples: {len(inputs.samples)}",
            f"- candidate hash: `{inputs.candidate_hash}`",
            f"- prompt manifest: `{inputs.prompt_manifest_sha256}`",
        ],
    )
    return 0


def run_generate(
    config_path: Path | str,
    data_dir: Path | str,
    prompts_dir: Path | str,
    output_dir: Path | str,
    *,
    repo_dir: Path | str | None = None,
) -> int:
    config = load_generation_config(config_path)
    inputs = _build_inputs(config, Path(data_dir), Path(prompts_dir))
    config = _resolve_config(config, inputs)
    run_dir = Path(output_dir).resolve()
    assert_fresh_dir(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = _activate_cache(config, run_dir)
    write_json_atomic(
        run_dir / "run_config.json",
        _run_config_payload(
            config,
            inputs,
            Path(data_dir),
            Path(prompts_dir),
            cache_dir,
        ),
    )
    with RunLock(run_dir):
        if config.source == "mock":
            with MockSource(config) as source:
                summary = _run_generation(
                    config=config, inputs=inputs, run_dir=run_dir, source=source
                )
        elif config.source == "dmx":
            from .source import DspyLMSource

            api_key = load_dmx_api_key(repo_dir)
            summary = _run_generation(
                config=config,
                inputs=inputs,
                run_dir=run_dir,
                source=DspyLMSource(config, api_key),
            )
        else:  # pragma: no cover - validated by contracts
            raise GenerationContractError(f"unsupported source: {config.source}")
    return 0


def run_resume_generation(
    run_dir: Path | str,
    *,
    repo_dir: Path | str | None = None,
) -> int:
    run_path = Path(run_dir).resolve()
    run_config_path = run_path / "run_config.json"
    if not run_config_path.is_file():
        raise GenerationContractError(f"run_config.json not found: {run_config_path}")
    payload = read_json(run_config_path)
    config = GenerationConfig.from_json(payload["config"])
    if config.run_config_hash() != payload.get("run_config_hash"):
        raise GenerationContractError("run_config_hash does not match its config")
    inputs_block = payload.get("inputs") or {}
    data_dir = inputs_block.get("data_dir")
    prompts_dir = inputs_block.get("prompts_dir")
    if not data_dir or not prompts_dir:
        raise GenerationContractError("run_config.json is missing input paths")
    inputs = _build_inputs(config, Path(data_dir), Path(prompts_dir))
    config = _resolve_config(config, inputs)
    if inputs.candidate_hash != inputs_block.get("candidate_hash"):
        raise GenerationContractError(
            "input candidate hash changed since the run was created; refusing to resume"
        )
    _activate_cache(config, run_path)
    with RunLock(run_path):
        if config.source == "mock":
            with MockSource(config) as source:
                summary = _run_generation(
                    config=config, inputs=inputs, run_dir=run_path, source=source
                )
        elif config.source == "dmx":
            from .source import DspyLMSource

            api_key = load_dmx_api_key(repo_dir)
            summary = _run_generation(
                config=config,
                inputs=inputs,
                run_dir=run_path,
                source=DspyLMSource(config, api_key),
            )
        else:  # pragma: no cover
            raise GenerationContractError(f"unsupported source: {config.source}")
    return 0


__all__ = [
    "load_generation_config",
    "load_dmx_api_key",
    "run_check_generation",
    "run_generate",
    "run_resume_generation",
]
