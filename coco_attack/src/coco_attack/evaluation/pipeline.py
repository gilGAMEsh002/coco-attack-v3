"""Unified pipeline orchestration: config, steps, checkpoint, resume (task 05).

Reuses the per-step services (generation, cleaning, static, other evaluators,
functional) rather than re-implementing them.  Steps are guarded by a batch
barrier, recorded append-only in ``actions.jsonl``, and can be resumed from the
same run directory without re-issuing completed work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    assert_fresh_dir,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..data.combination import legacy_alias_for
from ..data.snapshot import load_prepared_data
from ..execution.supervisor import RunLock
from ..generation.contracts import GenerationConfig
from ..generation.inputs import load_generation_inputs
from ..generation.service import run_generate
from .contracts import EvaluationConfig
from .generation_source import resolve_generation_run
from .reporting import build_report
from .run_cleaning import clean_generations
from .run_functional import FunctionalConfig, run_evaluate_functional
from .run_other import EvaluatorsConfig, run_evaluate_other
from .run_static import evaluate_static

PIPELINE_SCHEMA_VERSION = "pipeline-config-v1"
PIPELINE_STEPS = (
    "generation",
    "cleaning",
    "static",
    "core_checkpoint",
    "other",
    "functional",
    "report",
)
CORE_LAYERS = ("generation", "cleaning", "static", "other")


class PipelineConfigError(ValueError):
    pass


@dataclass(frozen=True)
class PipelineConfig:
    run_id: str
    combination_id: str
    oracle_id: str
    stage: str
    form: str
    data_dir: str
    prompts_dir: str
    assets_dir: str
    output_dir: str
    execution_config: str
    functional_cache_dir: str
    source: str = "mock"
    model: str = "openai/gpt-4o"
    temperature: float = 0.0
    repeats: int = 1
    batch_id: str = "pipeline-batch-1"
    prompt_version: str = "1"
    task_ids: tuple[str, ...] = ()
    generation_run: str | None = None
    repo_dir: str | None = None
    ledger_path: str | None = None
    mock_scenario: str = "normal"
    max_concurrency: int = 4
    max_tokens: int = 1024
    request_timeout: float = 60.0
    max_request_attempts: int = 3
    requests_per_minute: float | None = None
    tokens_per_minute: int | None = None
    price_input_per_1k: float | None = None
    price_output_per_1k: float | None = None
    currency: str = "USD"
    pricing_version: str = "unset"
    enabled_layers: tuple[str, ...] = ("sast", "judge", "dynamic", "realism")
    sast_tools: tuple[str, ...] = ("bandit", "semgrep", "codeql")
    semgrep_config: str | None = None
    codeql_executable: str | None = None
    codeql_search_path: str | None = None
    judge: dict[str, Any] | None = None
    victim_temperature: float = 0.0
    victim_repeats: int = 1
    k: tuple[int, ...] = (1, 3, 5)
    schema_version: str = PIPELINE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("run_id", "combination_id", "oracle_id", "stage", "form"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise PipelineConfigError(f"pipeline.{name} must be a non-empty string")
        for name in ("data_dir", "prompts_dir", "assets_dir", "execution_config", "functional_cache_dir"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise PipelineConfigError(f"pipeline.{name} must be a non-empty path")

    def to_json(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "stage": self.stage,
            "form": self.form,
            "source": self.source,
            "model": self.model,
            "temperature": self.temperature,
            "repeats": self.repeats,
            "batch_id": self.batch_id,
            "prompt_version": self.prompt_version,
            "task_ids": list(self.task_ids),
            "data_dir": self.data_dir,
            "prompts_dir": self.prompts_dir,
            "assets_dir": self.assets_dir,
            "output_dir": self.output_dir,
            "execution_config": self.execution_config,
            "functional_cache_dir": self.functional_cache_dir,
            "generation_run": self.generation_run,
            "repo_dir": self.repo_dir,
            "ledger_path": self.ledger_path,
            "mock_scenario": self.mock_scenario,
            "max_concurrency": self.max_concurrency,
            "max_tokens": self.max_tokens,
            "request_timeout": self.request_timeout,
            "max_request_attempts": self.max_request_attempts,
            "requests_per_minute": self.requests_per_minute,
            "tokens_per_minute": self.tokens_per_minute,
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "currency": self.currency,
            "pricing_version": self.pricing_version,
            "enabled_layers": list(self.enabled_layers),
            "sast_tools": list(self.sast_tools),
            "semgrep_config": self.semgrep_config,
            "codeql_executable": self.codeql_executable,
            "codeql_search_path": self.codeql_search_path,
            "judge": self.judge,
            "victim_temperature": self.victim_temperature,
            "victim_repeats": self.victim_repeats,
            "k": list(self.k),
        }
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "PipelineConfig":
        allowed = set(cls.__dataclass_fields__)
        extra = sorted(set(payload) - allowed)
        if extra:
            raise PipelineConfigError(f"pipeline config has unknown fields: {extra}")
        coerced = dict(payload)
        for name in ("task_ids", "enabled_layers", "sast_tools", "k"):
            if name in coerced and coerced[name] is not None:
                coerced[name] = tuple(coerced[name])
        return cls(**coerced)


def load_pipeline_config(path: Path | str) -> PipelineConfig:
    payload = read_json(Path(path))
    if not isinstance(payload, dict):
        raise PipelineConfigError("pipeline config must be a JSON object")
    return PipelineConfig.from_json(payload)


def _mark(run: Path, step: str, status: str, detail: str) -> None:
    import os

    record = {"step": step, "status": status, "detail": detail}
    run.joinpath("actions.jsonl").parent.mkdir(parents=True, exist_ok=True)
    with open(run / "actions.jsonl", "ab") as handle:
        handle.write(json.dumps(record, sort_keys=True).encode("utf-8") + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _completed_steps(run: Path) -> set[str]:
    done: set[str] = set()
    path = run / "actions.jsonl"
    if not path.is_file():
        return done
    for raw in path.read_bytes().split(b"\n"):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw.decode("utf-8"))
        except ValueError:
            continue
        if row.get("status") == "completed":
            done.add(str(row.get("step")))
    return done


def _expected_samples(config: PipelineConfig) -> list[str]:
    inputs = load_generation_inputs(
        Path(config.data_dir),
        Path(config.prompts_dir),
        combination_id=config.combination_id,
        form=config.form,
        stage=config.stage,
        repeats=config.repeats,
        batch_id=config.batch_id,
        prompt_version=config.prompt_version,
        task_ids=config.task_ids or None,
    )
    return [sample.sample_id for sample in inputs.samples]


def _static_hits_from_run(run: Path, expected_sample_ids: list[str]) -> dict[str, bool] | None:
    """Join static verdicts to sample identities for the evasion denominator.

    Returns ``None`` when the mapping is incomplete so the metric reports
    "unavailable" rather than silently dropping samples or defaulting to False.
    """

    gen_path = resolve_generation_run(run) / "generations.jsonl"
    static_path = run / "static" / "evaluations.jsonl"
    if not gen_path.is_file() or not static_path.is_file():
        return None
    identity_by_sample: dict[str, tuple] = {}
    for raw in gen_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get("sample_id") is None:
            continue
        ident = row.get("identity") or {}
        identity_by_sample[str(row["sample_id"])] = (
            ident.get("combination_id"),
            ident.get("task_id"),
            ident.get("repeat_id"),
        )
    hits_by_key: dict[tuple, bool] = {}
    for raw in static_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        key = (row.get("combination_id"), row.get("task_id"), row.get("repeat_id"))
        if key in hits_by_key:
            # Ambiguous across batches; refuse rather than guess.
            return None
        hits_by_key[key] = bool(row.get("asr_hit"))
    hits: dict[str, bool] = {}
    for sample_id in expected_sample_ids:
        key = identity_by_sample.get(sample_id)
        if key is None or key not in hits_by_key:
            return None
        hits[sample_id] = hits_by_key[key]
    return hits


def check_pipeline(config_path: Path | str, output_dir: Path | str) -> int:
    config = load_pipeline_config(config_path)
    for name in ("data_dir", "prompts_dir", "assets_dir"):
        if not Path(getattr(config, name)).is_dir():
            raise PipelineConfigError(f"{name} is not a directory: {getattr(config, name)}")
    for name in ("execution_config",):
        if not Path(getattr(config, name)).is_file():
            raise PipelineConfigError(f"{name} is not a file: {getattr(config, name)}")
    expected = _expected_samples(config)
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "config": config.to_json(),
        "expected_sample_count": len(expected),
        "task_ids": sorted({sample for sample in expected}),
        "steps": list(PIPELINE_STEPS),
        "generation_mode": "existing" if config.generation_run else "run",
        "note": "check-pipeline never calls a model or executes a candidate",
    }
    write_json_atomic(output / "pipeline_check.json", payload)
    return 0


def _generation_config(config: PipelineConfig) -> GenerationConfig:
    return GenerationConfig(
        source=config.source,
        model=config.model,
        batch_id=config.batch_id,
        combination_id=config.combination_id,
        oracle_id=config.oracle_id,
        stage=config.stage,
        form=config.form,
        prompt_version=config.prompt_version,
        candidate_hash="",
        temperature=config.temperature,
        repeats=config.repeats,
        max_tokens=config.max_tokens,
        request_timeout=config.request_timeout,
        max_concurrency=config.max_concurrency,
        max_request_attempts=config.max_request_attempts,
        requests_per_minute=config.requests_per_minute,
        tokens_per_minute=config.tokens_per_minute,
        price_input_per_1k=config.price_input_per_1k,
        price_output_per_1k=config.price_output_per_1k,
        currency=config.currency,
        pricing_version=config.pricing_version,
        max_sample_retries=0,
        mock_scenario=config.mock_scenario,
        task_ids=config.task_ids,
    )


def _verify_existing_generation(config: PipelineConfig, generation_run: Path) -> None:
    """Require an accepted generation run to match the pipeline's model/sampling."""

    run_config = generation_run / "run_config.json"
    if not run_config.is_file():
        raise PipelineConfigError(f"generation run has no run_config.json: {run_config}")
    payload = read_json(run_config)
    gen_config = (payload or {}).get("config") or {}
    for name in ("model", "temperature", "repeats", "stage", "combination_id", "form", "prompt_version"):
        expected = getattr(config, name)
        actual = gen_config.get(name)
        if str(actual) != str(expected):
            raise PipelineConfigError(
                f"generation run {name}={actual!r} does not match pipeline {expected!r}"
            )


def _run_steps(
    config: PipelineConfig,
    run: Path,
    completed: set[str],
) -> int:
    prepared = load_prepared_data(Path(config.data_dir), config.combination_id)
    generation_run = Path(config.generation_run).resolve() if config.generation_run else run / "generation"
    # The per-run ledger is canonical; the generation ledger lives under
    # generation/ and is merged during reporting.  A caller-supplied path that
    # falls outside this run would split the audit trail across runs.
    ledger_path = str(run / "ledger.jsonl")

    with RunLock(run):
        if "generation" not in completed:
            if config.generation_run:
                if not (generation_run / "generations.jsonl").is_file():
                    raise PipelineConfigError(f"generation run has no generations.jsonl: {generation_run}")
                _verify_existing_generation(config, generation_run)
            else:
                generation_config_path = run / "configs" / "generation.json"
                write_json_atomic(generation_config_path, _generation_config(config).to_json())
                code = run_generate(
                    generation_config_path, config.data_dir, config.prompts_dir, generation_run,
                    repo_dir=config.repo_dir,
                )
                if code != 0:
                    _mark(run, "generation", "blocked", f"generate exited {code}")
                    return code
            _mark(run, "generation", "completed", str(generation_run))

        if "cleaning" not in completed:
            cleaning_dir = run / "cleaning"
            if cleaning_dir.exists() and any(cleaning_dir.iterdir()):
                raise PipelineConfigError(f"cleaning directory is not fresh: {cleaning_dir}")
            clean_generations(
                prepared, generation_run / "generations.jsonl", cleaning_dir,
                legacy_alias_for(config.combination_id),
            )
            _mark(run, "cleaning", "completed", str(cleaning_dir))

        if "static" not in completed:
            static_config = EvaluationConfig(
                combination_id=config.combination_id, oracle_id=config.oracle_id,
                model=config.model, temperature=config.temperature, repeats=config.repeats,
                task_set=config.stage, prompt_form=config.form, task_ids=config.task_ids,
            )
            static_config_path = run / "configs" / "evaluation.json"
            write_json_atomic(static_config_path, static_config.to_json())
            evaluate_static(Path(config.assets_dir), Path(config.data_dir), run / "cleaning", static_config_path, run / "static")
            _mark(run, "static", "completed", str(run / "static"))

        if "core_checkpoint" not in completed:
            _publish_core_checkpoint(config, run)
            _mark(run, "core_checkpoint", "completed", str(run / "core" / "checkpoint.json"))

        if "other" not in completed:
            judge_config = None
            if config.judge is not None:
                from .judge import JudgeConfig

                judge_config = config.judge if isinstance(config.judge, JudgeConfig) else JudgeConfig(
                    source=config.judge["source"],
                    model=config.judge["model"],
                    temperature=float(config.judge.get("temperature", 0.0)),
                    max_tokens=int(config.judge.get("max_tokens", 1024)),
                    request_timeout=float(config.judge.get("request_timeout", 120.0)),
                    api_base=config.judge.get("api_base", "https://www.dmxapi.cn/v1"),
                    mock_scenario=config.judge.get("mock_scenario", "cwe"),
                    price_input_per_1k=config.judge.get("price_input_per_1k"),
                    price_output_per_1k=config.judge.get("price_output_per_1k"),
                    currency=config.judge.get("currency", "USD"),
                    pricing_version=config.judge.get("pricing_version", "unset"),
                )
            evaluators = EvaluatorsConfig(
                combination_id=config.combination_id, oracle_id=config.oracle_id, stage=config.stage,
                enabled_layers=config.enabled_layers, sast_tools=config.sast_tools,
                judge=judge_config, semgrep_config=config.semgrep_config,
                codeql_executable=config.codeql_executable, codeql_search_path=config.codeql_search_path,
                k=config.k, victim_temperature=config.victim_temperature,
                victim_repeats=config.victim_repeats, task_ids=config.task_ids,
                batch_id=config.batch_id, model=config.model,
            )
            evaluators_path = run / "configs" / "evaluators.json"
            write_json_atomic(evaluators_path, evaluators.to_json())
            judge_factory = None
            if judge_config is not None and judge_config.source == "dmx":
                def judge_factory():  # noqa: E306 - small local factory
                    from ..generation.service import load_dmx_api_key
                    from .judge import JudgeRunner

                    key = load_dmx_api_key(config.repo_dir)
                    return JudgeRunner(judge_config, api_key=key)

            code = run_evaluate_other(
                evaluators_path, config.data_dir, generation_run, run / "cleaning",
                ledger_path, run / "evaluation",
                execution_config_path=config.execution_config,
                judge_runner_factory=judge_factory,
                static_hits=_static_hits_from_run(run, _expected_samples(config)),
            )
            if code != 0:
                _mark(run, "other", "blocked", f"evaluate-other exited {code}")
                return code
            _mark(run, "other", "completed", str(run / "evaluation"))

        if "functional" not in completed:
            functional = FunctionalConfig(
                combination_id=config.combination_id, oracle_id=config.oracle_id, stage=config.stage,
                k=config.k, task_ids=config.task_ids, batch_id=config.batch_id,
                model=config.model, temperature=config.temperature, repeats=config.repeats,
            )
            functional_path = run / "configs" / "functional.json"
            write_json_atomic(functional_path, functional.to_json())
            code = run_evaluate_functional(
                functional_path, config.data_dir, generation_run, run / "cleaning",
                config.execution_config, config.functional_cache_dir, run / "functional",
                ledger_path=ledger_path,
            )
            if code != 0:
                _mark(run, "functional", "blocked", f"evaluate-functional exited {code}")
                return code
            _mark(run, "functional", "completed", str(run / "functional"))

        if "report" not in completed:
            build_report(run, run / "report")
            _mark(run, "report", "completed", str(run / "report"))
    return 0


def _publish_core_checkpoint(config: PipelineConfig, run: Path) -> None:
    core_dir = run / "core"
    core_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, Any] = {}
    for relative in (
        "cleaning/cleaned_generations.jsonl",
        "static/evaluations.jsonl",
        "static/metrics.json",
    ):
        path = run / relative
        if path.is_file():
            artifacts[relative] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    # The generation source may be internal or an external run referenced by
    # pipeline_config.json; record its actual location and hash.
    generation_file = resolve_generation_run(run) / "generations.jsonl"
    if generation_file.is_file():
        artifacts["generation/generations.jsonl"] = {
            "sha256": sha256_file(generation_file),
            "size": generation_file.stat().st_size,
            "path": str(generation_file),
        }
    checkpoint = {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "evaluation_id": config.run_id,
        "expected_samples": _expected_samples(config),
        "artifacts": artifacts,
        "config_sha256": sha256_bytes(json.dumps(config.to_json(), sort_keys=True).encode("utf-8")),
        "note": "core checkpoint records reliably completed core actions; not a safety or acceptance verdict",
    }
    # Only publish after the core artifacts exist.  Generation may live outside
    # the run directory, so it is not required to be run-relative.
    missing = [
        name
        for name in ("generation/generations.jsonl", "cleaning/cleaned_generations.jsonl", "static/evaluations.jsonl")
        if name not in artifacts
    ]
    if missing:
        raise PipelineConfigError(f"core checkpoint missing artifacts: {missing}")
    write_json_atomic(core_dir / "checkpoint.json", checkpoint)


def _pipeline_status(run: Path, code: int) -> str:
    """Top-level status: step completion alone cannot claim a complete report."""

    if code != 0:
        return "blocked"
    metrics_path = run / "report" / "metrics.json"
    if not metrics_path.is_file():
        return "incomplete"
    try:
        metrics = read_json(metrics_path)
    except (OSError, ValueError):
        return "incomplete"
    if isinstance(metrics, dict) and metrics.get("complete") is True:
        return "complete"
    return "incomplete"


def _finalize_manifest(config: PipelineConfig, run: Path, status: str) -> None:
    report = None
    metrics_path = run / "report" / "metrics.json"
    if metrics_path.is_file():
        try:
            metrics = read_json(metrics_path)
        except (OSError, ValueError):
            metrics = None
        if isinstance(metrics, dict):
            report = {
                "status": "complete" if metrics.get("complete") else "incomplete",
                "sample_count": metrics.get("sample_count"),
                "expected_sample_count": metrics.get("expected_sample_count"),
                "missing_sample_ids": metrics.get("missing_sample_ids"),
                "extra_sample_ids": metrics.get("extra_sample_ids"),
            }
    write_json_atomic(
        run / "manifest.json",
        {
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "run_id": config.run_id,
            "combination_id": config.combination_id,
            "stage": config.stage,
            "status": status,
            "report": report,
            "steps": list(PIPELINE_STEPS),
            "completed_steps": sorted(_completed_steps(run)),
        },
    )


def run_pipeline(
    config_path: Path | str,
    output_dir: Path | str,
    *,
    accept_existing_generation: bool = False,
) -> int:
    config = load_pipeline_config(config_path)
    if accept_existing_generation and not config.generation_run:
        raise PipelineConfigError("accept_existing_generation requires generation_run in the config")
    run = Path(output_dir).resolve()
    assert_fresh_dir(run)
    run.mkdir(parents=True, exist_ok=True)
    if config.generation_run:
        # Freeze the external reference as an absolute path so a later resume or
        # report run from a different working directory resolves the same source.
        config = replace(config, generation_run=str(Path(config.generation_run).resolve()))
    write_json_atomic(run / "pipeline_config.json", config.to_json())
    write_json_atomic(
        run / "sample_manifest.json",
        {
            "run_id": config.run_id,
            "combination_id": config.combination_id,
            "stage": config.stage,
            "form": config.form,
            "task_ids": list(config.task_ids),
            "expected_sample_ids": _expected_samples(config),
        },
    )
    code = _run_steps(config, run, completed=set())
    _finalize_manifest(config, run, _pipeline_status(run, code))
    return code


def resume_pipeline(run_dir: Path | str) -> int:
    run = Path(run_dir).resolve()
    config_path = run / "pipeline_config.json"
    if not config_path.is_file():
        raise PipelineConfigError(f"pipeline_config.json not found: {config_path}")
    config = load_pipeline_config(config_path)
    completed = _completed_steps(run)
    code = _run_steps(config, run, completed=completed)
    _finalize_manifest(config, run, _pipeline_status(run, code))
    return code


def report_pipeline(
    run_dir: Path | str,
    output_dir: Path | str | None = None,
) -> int:
    run = Path(run_dir).resolve()
    config_path = run / "pipeline_config.json"
    if not config_path.is_file():
        raise PipelineConfigError(f"report requires pipeline_config.json: {config_path}")
    build_report(run_dir, output_dir)
    return 0


__all__ = [
    "PIPELINE_SCHEMA_VERSION",
    "PIPELINE_STEPS",
    "PipelineConfig",
    "PipelineConfigError",
    "load_pipeline_config",
    "check_pipeline",
    "run_pipeline",
    "resume_pipeline",
    "report_pipeline",
]
