"""Per-run ``PipelineConfig`` generation and batch ``check-pipeline`` execution.

Config generation never creates the run directories: ``run_pipeline`` requires a
fresh output directory, so a pre-created unit directory would make the actual
run fail.  Only the config tree (``configs/units/<run_id>.json``) is written.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json, write_json_atomic
from ..evaluation.pipeline import (
    PipelineConfig,
    check_pipeline,
    load_pipeline_config,
)
from .manifest import ManifestError
from .matrix import MatrixConfig, RunEntry, RunUnit

DMX_API_BASE = "https://www.dmxapi.cn/v1"
JUDGE_MOCK_SCENARIO = "cwe"


def _judge_dict(matrix: MatrixConfig) -> dict[str, Any]:
    return {
        "source": matrix.judge_source,
        "model": matrix.judge_model,
        "temperature": matrix.judge_temperature,
        "max_tokens": matrix.judge_max_tokens,
        "request_timeout": matrix.judge_request_timeout,
        "api_base": DMX_API_BASE,
        "mock_scenario": JUDGE_MOCK_SCENARIO,
        "price_input_per_1k": matrix.judge_price_input_per_1k,
        "price_output_per_1k": matrix.judge_price_output_per_1k,
        "currency": matrix.judge_currency,
        "pricing_version": matrix.judge_pricing_version,
    }


def _enabled_layers(matrix: MatrixConfig) -> tuple[str, ...]:
    layers = tuple(matrix.enabled_layers)
    if not matrix.judge_enabled:
        layers = tuple(layer for layer in layers if layer != "judge")
    return layers


def build_pipeline_config(
    matrix: MatrixConfig,
    unit: RunUnit,
    entry: RunEntry,
    baseline_root: Path | str,
) -> PipelineConfig:
    root = Path(baseline_root)
    return PipelineConfig(
        run_id=entry.run_id,
        combination_id=unit.combination_id,
        oracle_id=unit.oracle_id,
        stage=entry.stage,
        form=unit.form,
        data_dir=str(root / "inputs" / "data"),
        prompts_dir=str(root / "inputs" / "prompts" / unit.combination_id),
        assets_dir=matrix.assets_dir,
        output_dir=str(root / entry.run_dir),
        execution_config=matrix.execution_config,
        functional_cache_dir=str(root / "cache" / "functional"),
        source=matrix.source,
        model=matrix.victim_model,
        temperature=unit.temperature,
        repeats=unit.repeats,
        batch_id=unit.batch_id,
        prompt_version=matrix.prompt_version,
        task_ids=tuple(entry.task_ids),
        generation_run=None,
        repo_dir=matrix.repo_dir,
        ledger_path=None,
        mock_scenario="normal",
        max_concurrency=matrix.generation_max_concurrency,
        max_tokens=matrix.max_tokens,
        request_timeout=matrix.request_timeout,
        max_request_attempts=matrix.max_request_attempts,
        requests_per_minute=matrix.requests_per_minute,
        tokens_per_minute=matrix.tokens_per_minute,
        price_input_per_1k=matrix.price_input_per_1k,
        price_output_per_1k=matrix.price_output_per_1k,
        currency=matrix.currency,
        pricing_version=matrix.pricing_version,
        enabled_layers=_enabled_layers(matrix),
        sast_tools=tuple(matrix.sast_tools),
        semgrep_config=matrix.semgrep_config,
        codeql_executable=matrix.codeql_executable,
        codeql_search_path=matrix.codeql_search_path,
        judge=_judge_dict(matrix) if matrix.judge_enabled else None,
        victim_temperature=unit.temperature,
        victim_repeats=unit.repeats,
        k=tuple(matrix.k),
    )


def write_unit_configs(
    baseline_root: Path | str,
    matrix: MatrixConfig,
    units: tuple[RunUnit, ...],
) -> dict[str, str]:
    """Write one config per run entry; never create the run directories."""

    root = Path(baseline_root)
    written: dict[str, str] = {}
    for unit in units:
        for entry in unit.entries:
            config = build_pipeline_config(matrix, unit, entry, root)
            write_json_atomic(root / entry.config_path, config.to_json())
            written[entry.run_id] = entry.config_path
    return written


def check_unit_configs(
    baseline_root: Path | str,
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Validate every run config and run ``check-pipeline`` for it.

    Returns a JSON-serialisable summary keyed by ``run_id``.  A failing run is
    reported (``ok=False``) rather than raising, so a single broken config does
    not hide the others; the caller treats any failure as blocking.
    """

    root = Path(baseline_root)
    summary: dict[str, dict[str, Any]] = {}
    units = manifest.get("units") or {}
    for unit in units.values():
        for run in unit.get("runs") or []:
            run_id = run["run_id"]
            manifest_count = int(run["expected_sample_count"])
            entry: dict[str, Any] = {
                "ok": False,
                "expected_sample_count": manifest_count,
                "error": None,
            }
            try:
                config_path = root / run["config_path"]
                if not config_path.is_file():
                    raise FileNotFoundError(f"config not found: {config_path}")
                load_pipeline_config(config_path)
                check_dir = root / "checks" / "pipeline" / run_id
                code = check_pipeline(config_path, check_dir)
                if code != 0:
                    raise RuntimeError(f"check_pipeline exited {code}")
                payload = read_json(check_dir / "pipeline_check.json")
                actual = int(payload.get("expected_sample_count"))
                if actual != manifest_count:
                    raise ManifestError(
                        f"check-pipeline expected_sample_count {actual} != manifest {manifest_count}"
                    )
                entry["ok"] = True
                entry["expected_sample_count"] = actual
            except (OSError, ValueError, RuntimeError) as error:
                entry["error"] = f"{type(error).__name__}: {error}"
            summary[run_id] = entry
    return summary


__all__ = [
    "DMX_API_BASE",
    "build_pipeline_config",
    "write_unit_configs",
    "check_unit_configs",
]
