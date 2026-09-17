"""Other-evaluator orchestration (stage 02, task 04).

Runs SAST tools and the LLM judge over the shared ``final_code`` and records the
dynamic/realism coverage status.  All other-evaluator layers use the disabled
evaluation cache: a new ``evaluation_id`` always re-evaluates; only the DSPy
model response cache can serve judge requests.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    write_json_atomic,
    write_text_atomic,
)
from ..runtime.ledger import EVENT_EXECUTION_RECORDED, Ledger
from .cache import DisabledCache
from .dynamic import build_dynamic_record, classify_dynamic, pending_dynamic_record
from .judge import JudgeConfig, JudgeRequest, JudgeRunner
from .layers import (
    COVERAGE_COVERED,
    COVERAGE_NOT_COVERED,
    DYNAMIC_LAYER,
    JUDGE_LAYER,
    LAYERS,
    REALISM_LAYER,
    SAST_LAYER,
    STATUS_COMPLETED,
    coverage_for,
    not_covered_record,
)
from .metrics import evasion, llm_judge_rate
from .realism import (
    SEMANTICS_CONFLICTS,
    ThreatModel,
    build_realism_record,
    classify_realism,
    pending_realism_record,
    select_variant,
)
from .sast import sast_coverage_matrix
from .run_functional import FunctionalInputError, _build_inputs

EVALUATORS_CONFIG_SCHEMA = "evaluators-config-v1"
EVALUATORS_CHECK_SCHEMA = "evaluators-check-v1"
EVALUATORS_RUN_SCHEMA = "evaluators-run-v1"
ALL_LAYERS = (SAST_LAYER, JUDGE_LAYER, DYNAMIC_LAYER, REALISM_LAYER)
DEFAULT_SAST_TOOLS = ("bandit", "semgrep", "codeql")


@dataclass(frozen=True)
class EvaluatorsConfig:
    combination_id: str
    oracle_id: str
    stage: str
    enabled_layers: tuple[str, ...] = (SAST_LAYER, JUDGE_LAYER, DYNAMIC_LAYER, REALISM_LAYER)
    sast_tools: tuple[str, ...] = DEFAULT_SAST_TOOLS
    judge: JudgeConfig | None = None
    semgrep_config: str | None = None
    codeql_executable: str | None = None
    codeql_search_path: str | None = None
    k: tuple[int, ...] = (1, 3, 5)
    task_ids: tuple[str, ...] = ()
    victim_temperature: float = 0.0
    victim_repeats: int = 1
    batch_id: str | None = None
    model: str | None = None

    def __post_init__(self) -> None:
        for layer in self.enabled_layers:
            if layer not in ALL_LAYERS:
                raise FunctionalInputError(f"unknown layer: {layer!r}")
        for tool in self.sast_tools:
            if tool not in ("bandit", "semgrep", "codeql"):
                raise FunctionalInputError(f"unknown SAST tool: {tool!r}")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": EVALUATORS_CONFIG_SCHEMA,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "stage": self.stage,
            "enabled_layers": list(self.enabled_layers),
            "sast_tools": list(self.sast_tools),
            "judge": None if self.judge is None else {
                "source": self.judge.source,
                "model": self.judge.model,
                "temperature": self.judge.temperature,
                "max_tokens": self.judge.max_tokens,
                "request_timeout": self.judge.request_timeout,
                "api_base": self.judge.api_base,
                "mock_scenario": self.judge.mock_scenario,
                "price_input_per_1k": self.judge.price_input_per_1k,
                "price_output_per_1k": self.judge.price_output_per_1k,
                "currency": self.judge.currency,
                "pricing_version": self.judge.pricing_version,
            },
            "semgrep_config": self.semgrep_config,
            "codeql_executable": self.codeql_executable,
            "codeql_search_path": self.codeql_search_path,
            "k": list(self.k),
            "victim_temperature": self.victim_temperature,
            "victim_repeats": self.victim_repeats,
            "task_ids": list(self.task_ids),
            "batch_id": self.batch_id,
            "model": self.model,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "EvaluatorsConfig":
        judge_payload = payload.get("judge")
        judge = None
        if judge_payload is not None:
            judge = JudgeConfig(
                source=judge_payload["source"],
                model=judge_payload["model"],
                temperature=float(judge_payload["temperature"]),
                max_tokens=int(judge_payload["max_tokens"]),
                request_timeout=float(judge_payload["request_timeout"]),
                api_base=judge_payload.get("api_base", "https://www.dmxapi.cn/v1"),
                mock_scenario=judge_payload.get("mock_scenario", "cwe"),
                price_input_per_1k=judge_payload.get("price_input_per_1k"),
                price_output_per_1k=judge_payload.get("price_output_per_1k"),
                currency=judge_payload.get("currency", "USD"),
                pricing_version=judge_payload.get("pricing_version", "unset"),
            )
        return cls(
            combination_id=payload["combination_id"],
            oracle_id=payload["oracle_id"],
            stage=payload["stage"],
            enabled_layers=tuple(payload.get("enabled_layers", ALL_LAYERS)),
            sast_tools=tuple(payload.get("sast_tools", DEFAULT_SAST_TOOLS)),
            judge=judge,
            semgrep_config=payload.get("semgrep_config"),
            codeql_executable=payload.get("codeql_executable"),
            codeql_search_path=payload.get("codeql_search_path"),
            k=tuple(int(k) for k in payload.get("k", (1, 3, 5))),
            victim_temperature=float(payload.get("victim_temperature", 0.0)),
            victim_repeats=int(payload.get("victim_repeats", 1)),
            task_ids=tuple(payload.get("task_ids") or ()),
            batch_id=payload.get("batch_id"),
            model=payload.get("model"),
        )


def load_evaluators_config(config_path: Path | str) -> EvaluatorsConfig:
    payload = read_json(Path(config_path))
    if not isinstance(payload, dict):
        raise FunctionalInputError("evaluators config must be a JSON object")
    return EvaluatorsConfig.from_json(payload)


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_separator = False
    if path.is_file() and path.stat().st_size > 0:
        with open(path, "rb") as handle:
            handle.seek(-1, os.SEEK_END)
            needs_separator = handle.read(1) != b"\n"
    with open(path, "ab") as handle:
        if needs_separator:
            handle.write(b"\n")
        handle.write(canonical_json_bytes(payload) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a layer JSONL file, tolerating only a torn final line.

    A non-empty final line without a trailing newline is preserved in a
    ``.tail`` sidecar and skipped; any earlier malformed line is reported as
    corruption instead of being silently dropped (plan 05 §5.2).
    """

    if not path.is_file():
        return []
    data = path.read_bytes()
    lines = data.split(b"\n")
    ends_with_newline = data.endswith(b"\n")
    if ends_with_newline:
        lines = lines[:-1]
    rows: list[dict[str, Any]] = []
    repair_at: int | None = None
    for index, raw in enumerate(lines):
        if not raw.strip():
            continue
        try:
            rows.append(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as error:
            is_last = index == len(lines) - 1
            if is_last and not ends_with_newline:
                # Preserve the torn bytes, then drop them so the next append
                # cannot be concatenated onto a corrupt line.
                path.with_name(path.name + ".tail").write_bytes(raw)
                repair_at = len(data) - len(raw)
                break
            raise FunctionalInputError(
                f"corrupt layer row at {path}:{index + 1}: {error}"
            ) from error
    if repair_at is not None:
        with open(path, "r+b") as handle:
            handle.truncate(repair_at)
            handle.flush()
            os.fsync(handle.fileno())
    return rows


def run_check_evaluators(
    config_path: Path | str,
    data_dir: Path | str,
    generation_run: Path | str,
    cleaned_dir: Path | str,
    output_dir: Path | str,
) -> int:
    from .sast import (
        rule_mapping_trace,
        sast_coverage_matrix,
        tool_available,
        validate_semgrep_mapping,
    )

    config = load_evaluators_config(config_path)
    inputs = _build_inputs(Path(data_dir), Path(generation_run).resolve(), Path(cleaned_dir).resolve(), config)
    coverage = {layer: coverage_for(config.combination_id, layer) for layer in ALL_LAYERS}
    tools = {
        tool: tool_available(tool, codeql_executable=config.codeql_executable)
        for tool in config.sast_tools
    }
    sast_coverage = sast_coverage_matrix(config.combination_id, config.sast_tools)
    semgrep_mismatches = (
        validate_semgrep_mapping(config.semgrep_config) if config.semgrep_config else []
    )
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        rule_trace = rule_mapping_trace(config.combination_id)
    except KeyError:
        rule_trace = {"combination_id": config.combination_id, "bandit_target_rules": []}
    payload = {
        "schema_version": EVALUATORS_CHECK_SCHEMA,
        "config": config.to_json(),
        "sample_count": len(inputs),
        "coverage": coverage,
        "tool_availability": tools,
        "sast_coverage": sast_coverage,
        "semgrep_mapping_mismatches": semgrep_mismatches,
        "rule_mapping": rule_trace,
        "layer_not_run_note": "check-evaluators never calls a model or executes a candidate",
    }
    write_json_atomic(output / "evaluators_check.json", payload)
    write_text_atomic(
        output / "REPORT.md",
        "\n".join(
            [
                "# Evaluator input check",
                "",
                f"- samples: {len(inputs)}",
                f"- layer coverage: {coverage}",
                f"- tool availability: {tools}",
                f"- SAST coverage (tool x combination): {sast_coverage}",
                f"- Semgrep mapping mismatches: {semgrep_mismatches}",
                f"- rule mapping: {rule_trace}",
                "",
            ]
        ),
    )
    return 0


def _derive_evaluation_id(output: Path) -> str:
    """Stable per-run evaluation identity derived from the run directory.

    The same run directory resumes under the same ``evaluation_id`` while a new
    directory starts a new evaluation.
    """

    digest = sha256_bytes(str(output.resolve()).encode("utf-8"))
    return f"ev-{digest[:16]}"


def _judge_cost(
    config: EvaluatorsConfig,
    usage: dict[str, Any] | None,
    *,
    model_cache_hit: bool | None = None,
) -> dict[str, Any]:
    if model_cache_hit or not isinstance(usage, dict) or not usage:
        # A cache hit or an empty usage (DSPy clears usage on replay) must not
        # be turned into a known zero cost.
        return {"basis": "unknown", "amount": None}
    judge = config.judge
    if judge is None:
        return {"basis": "unknown", "amount": None}
    price_in = judge.price_input_per_1k
    price_out = judge.price_output_per_1k
    if price_in is None or price_out is None:
        return {"basis": "unknown", "amount": None}
    prompt_tokens = usage.get("prompt_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or 0
    amount = (prompt_tokens / 1000.0) * price_in + (completion_tokens / 1000.0) * price_out
    return {
        "basis": "configured",
        "amount": amount,
        "currency": judge.currency,
        "pricing_version": judge.pricing_version,
    }


def _judge_accounting(
    ledger: Ledger,
    *,
    evaluation_id: str,
    action_id: str,
    sample_id: str,
    config: EvaluatorsConfig,
    info: dict[str, Any],
    physical_attempt_id: str,
) -> None:
    """Record each physical judge response's usage/cost before any parsing.

    The accounting id includes a per-response physical attempt id so a request
    re-issued after an interruption (booked but not persisted) is counted again
    rather than silently de-duplicated by logical action (plan 05 §6.1).
    """

    cache_hit = bool(info.get("model_cache_hit"))
    source = _prior_judge_response(ledger, action_id) if cache_hit else None
    source_id = source.get("accounting_id") if source is not None else None
    if cache_hit:
        # Bind the reuse identity to the actual source response so a later real
        # response produces a new reuse reference, while repeated recovery from
        # the same source de-duplicates.
        accounting_id = (
            f"judge:{evaluation_id}:{action_id}:{physical_attempt_id}:{source_id or 'unknown'}"
        )
    else:
        accounting_id = f"judge:{evaluation_id}:{action_id}:{physical_attempt_id}"
    for event in ledger.replay().events:
        if event.get("event_type") == EVENT_EXECUTION_RECORDED:
            if (event.get("payload") or {}).get("accounting_id") == accounting_id:
                return
    reused_from: str | None = None
    if cache_hit:
        if source is None:
            # No recorded real response anywhere: keep a single unknown-cost
            # entry (stable id de-duplicates later recoveries).
            usage = None
            cost = {"basis": "unknown", "amount": None}
        else:
            # Reuse the original response by reference; do not carry usage/cost
            # here so cost aggregation cannot double count it.
            usage = None
            cost = {}
            reused_from = source_id
    else:
        usage = info.get("usage")
        cost = _judge_cost(config, usage, model_cache_hit=False)
    payload: dict[str, Any] = {
        "role": "judge",
        "accounting_id": accounting_id,
        "evaluation_id": evaluation_id,
        "sample_id": sample_id,
        "action_id": action_id,
        "model": None if config.judge is None else config.judge.model,
        "outcome": "received",
        "detected": None,
        "model_cache_hit": cache_hit,
        "finish_reason": info.get("finish_reason"),
        "usage": usage,
        "cost": cost,
    }
    if reused_from is not None:
        payload["reused_from"] = reused_from
    ledger.append(
        EVENT_EXECUTION_RECORDED,
        sample_id=sample_id,
        request_attempt_id=action_id,
        payload=payload,
    )


def _prior_judge_response(ledger: Ledger, action_id: str) -> dict[str, Any] | None:
    """Return the most recent real (non-cache) response payload for an action."""

    latest: dict[str, Any] | None = None
    for event in ledger.replay().events:
        if event.get("event_type") != EVENT_EXECUTION_RECORDED:
            continue
        payload = event.get("payload") or {}
        if (
            payload.get("role") == "judge"
            and payload.get("action_id") == action_id
            and not payload.get("model_cache_hit")
        ):
            latest = payload
    return latest


def _container_layer_payload(
    *,
    profile: Any,
    backend: Any,
    output: Path,
    entry: str,
    entry_args: tuple[str, ...],
    request_files: dict[str, dict[str, Any]],
    sample: Any,
    oracle_id: str,
    stage: str,
    combination_id: str,
    result_schema: str,
    attempt_id: str,
    nonce: str | None = None,
) -> tuple[Any, dict[str, Any] | None]:
    from ..execution.contracts import ExecutionRequest
    from ..execution.supervisor import ExecutionSupervisor

    staging = output / "staging" / attempt_id
    staging.mkdir(parents=True, exist_ok=True)
    for name, content in request_files.items():
        (staging / name).write_bytes(json.dumps(content, sort_keys=True).encode("utf-8"))
    request = ExecutionRequest(
        sample_id=sample.sample_id,
        attempt_id=attempt_id,
        stage=stage,
        batch_id=sample.identity.to_json()["batch_id"],
        combination_id=combination_id,
        task_id=sample.identity.task_id,
        repeat_id=sample.identity.repeat_id,
        prompt_version=sample.identity.to_json()["prompt_version"],
        candidate_hash=sample.identity.to_json()["candidate_hash"],
        evaluation_layer="dynamic" if entry == "dynamic" else "realism",
        entry=entry,
        entry_args=entry_args,
        execution_profile_hash=profile.fingerprint(),
        purpose="evaluation",
        input_files=(),
        result_schema=result_schema,
        harness_version="layer-harness-v1",
    )
    (staging / "request.json").write_bytes(json.dumps(request.to_json(), sort_keys=True).encode("utf-8"))
    outputs = output / "outputs" / attempt_id
    outputs.mkdir(parents=True, exist_ok=True)
    supervisor = ExecutionSupervisor(profile, backend, output / "run")
    result = supervisor.execute(request, staging, outputs, nonce=nonce)
    envelope = _read_json_object(output / "run" / "attempts" / attempt_id / "result.json")
    payload = (envelope or {}).get("payload")
    return result, payload if isinstance(payload, dict) else None


def _read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def run_evaluate_other(
    config_path: Path | str,
    data_dir: Path | str,
    generation_run: Path | str,
    cleaned_dir: Path | str,
    ledger_path: Path | str | None,
    output_dir: Path | str,
    *,
    judge_runner_factory=None,
    sast_scan=None,
    static_hits: dict[str, bool] | None = None,
    execution_config_path: Path | str | None = None,
    backend: Any = None,
    layer_payload_runner: Any = None,
    evaluation_id: str | None = None,
) -> int:
    from .layers import LayerRecord
    from .sast import scan_sample

    config = load_evaluators_config(config_path)
    data_dir = Path(data_dir).resolve()
    generation_run = Path(generation_run).resolve()
    cleaned_dir = Path(cleaned_dir).resolve()
    inputs = _build_inputs(data_dir, generation_run, cleaned_dir, config)
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    effective_ledger = (
        str(Path(ledger_path).resolve())
        if ledger_path
        else str((output / "ledger.jsonl").resolve())
    )
    ledger = Ledger(effective_ledger)
    cache = DisabledCache()

    layers_dir = output / "layers"
    evaluation_id = evaluation_id or _derive_evaluation_id(output)
    config_sha = sha256_bytes(canonical_json_bytes(config.to_json()))
    # Refuse to silently continue a *different* evaluation in an existing
    # directory: a changed config or identity must start a new evaluation
    # (plan 05 §5.2), otherwise completed actions would be skipped as if this
    # were a resume.
    prior_config_path = output / "config.json"
    if prior_config_path.is_file():
        prior_payload = read_json(prior_config_path)
        if isinstance(prior_payload, dict):
            prior_eval = prior_payload.get("evaluation_id")
            if prior_eval and prior_eval != evaluation_id:
                raise FunctionalInputError(
                    f"existing run uses evaluation_id {prior_eval!r}; start a new evaluation directory"
                )
            prior_config_sha = prior_payload.get("config_sha256")
            if prior_config_sha and prior_config_sha != config_sha:
                raise FunctionalInputError(
                    "existing run config changed since it was created; start a new evaluation"
                )
    records: dict[str, list[LayerRecord]] = {layer: [] for layer in ALL_LAYERS}
    existing_actions: set[str] = set()
    for layer in ALL_LAYERS:
        for row in _read_jsonl(layers_dir / f"{layer}.jsonl"):
            try:
                prior = LayerRecord.from_json(row)
            except (ValueError, KeyError, TypeError) as error:
                raise FunctionalInputError(
                    f"corrupt {layer} layer record in {layers_dir / f'{layer}.jsonl'}: {error}"
                ) from error
            records[layer].append(prior)
            existing_actions.add(prior.action_id)
    execution_config_value = (
        str(Path(execution_config_path).resolve()) if execution_config_path else None
    )
    # Persist resume references before any layer runs so an interrupted first
    # evaluation can be resumed with its full execution context and identity.
    write_json_atomic(
        output / "config.json",
        {
            **config.to_json(),
            "evaluation_id": evaluation_id,
            "config_sha256": config_sha,
            "execution_config": execution_config_value,
            "ledger": effective_ledger,
        },
    )
    write_json_atomic(
        output / "manifest.json",
        {
            "schema_version": EVALUATORS_RUN_SCHEMA,
            "evaluation_id": evaluation_id,
            "config_sha256": config_sha,
            "config": config.to_json(),
            "inputs": {
                "data_dir": str(data_dir),
                "generation_run": str(generation_run),
                "cleaned_dir": str(cleaned_dir),
                "execution_config": execution_config_value,
                "evaluation_id": evaluation_id,
                "ledger": effective_ledger,
            },
            "sample_count": len(inputs),
            "layer_counts": {layer: len(items) for layer, items in records.items()},
            "cache": {"enabled": False, "reason": "cache_disabled"},
            "status": "running",
        },
    )

    profile = None
    active_backend = backend
    if execution_config_path is not None:
        from ..execution.preflight import load_profile

        loaded = load_profile(execution_config_path)
        profile = loaded.profile
        if active_backend is None:
            from ..execution.docker import DockerClient

            active_backend = DockerClient(
                control_timeout_seconds=profile.timeouts.docker_control_timeout_seconds
            )
        if profile.image.image_id in (None, "sha256:" + "0" * 64):
            inspect = active_backend.image_inspect(profile.image.reference)
            actual_id = (inspect or {}).get("Id") or (inspect or {}).get("ID")
            if actual_id:
                from dataclasses import replace

                profile = replace(profile, image=replace(profile.image, image_id=actual_id))

    judge_runner = None
    if SAST_LAYER in config.enabled_layers:
        for sample in inputs:
            for tool in config.sast_tools:
                action_id = f"{SAST_LAYER}:{tool}:{evaluation_id}:{sample.sample_id}"
                if action_id in existing_actions:
                    continue
                target_rules = _sast_target_rules(config, tool, sample)
                scanner = sast_scan or scan_sample
                record = scanner(
                    sample,
                    evaluation_id=evaluation_id,
                    action_id=action_id,
                    tool=tool,
                    target_rules=target_rules,
                    workdir=output / "sast" / sample.sample_id / tool,
                    semgrep_config=config.semgrep_config,
                    codeql_executable=config.codeql_executable,
                    codeql_search_path=config.codeql_search_path,
                )
                assert cache.get(action_id).hit is False
                records[SAST_LAYER].append(record)
                _append_jsonl(layers_dir / f"{SAST_LAYER}.jsonl", record.to_json())

    if JUDGE_LAYER in config.enabled_layers and config.judge is not None:
        factory = judge_runner_factory or (lambda: JudgeRunner(config.judge))
        judge_runner = factory()
        try:
            for sample in inputs:
                action_id = f"{JUDGE_LAYER}:{config.judge.model}:{evaluation_id}:{sample.sample_id}"
                if action_id in existing_actions:
                    continue
                request = JudgeRequest(
                    evaluation_id=evaluation_id,
                    action_id=action_id,
                    sample_id=sample.sample_id,
                    identity=sample.identity.to_json(),
                    stage=sample.identity.stage,
                    combination_id=config.combination_id,
                    oracle_id=config.oracle_id,
                    final_code=sample.final_code,
                    final_code_sha256=sample.final_code_sha256,
                    target_cwe=config.combination_id.split("-")[0].replace("cwe", "CWE-"),
                )

                def _on_judge_response(
                    info: dict[str, Any],
                    _action_id: str = action_id,
                    _sample_id: str = sample.sample_id,
                ) -> None:
                    # A real response gets a fresh physical id (so a re-issued
                    # request is counted); a cache hit uses a stable id so it is
                    # not booked repeatedly across recoveries.
                    physical = "cache" if info.get("model_cache_hit") else uuid.uuid4().hex
                    _judge_accounting(
                        ledger,
                        evaluation_id=evaluation_id,
                        action_id=_action_id,
                        sample_id=_sample_id,
                        config=config,
                        info=info,
                        physical_attempt_id=physical,
                    )

                record, evidence = judge_runner.evaluate(
                    request, on_response=_on_judge_response
                )
                records[JUDGE_LAYER].append(record)
                _append_jsonl(layers_dir / f"{JUDGE_LAYER}.jsonl", record.to_json())
                evidence_path = output / "judge" / f"{action_id.replace(':', '_')}.json"
                write_json_atomic(evidence_path, evidence)
        finally:
            close = getattr(judge_runner, "close", None)
            if callable(close):
                close()

    for sample in inputs:
        for layer in (DYNAMIC_LAYER, REALISM_LAYER):
            if layer not in config.enabled_layers:
                continue
            action_id = f"{layer}:{evaluation_id}:{sample.sample_id}"
            if action_id in existing_actions:
                continue
            coverage = coverage_for(sample.identity.combination_id, layer)
            if coverage == COVERAGE_NOT_COVERED:
                record = not_covered_record(
                    evaluation_id=evaluation_id, action_id=action_id, sample_id=sample.sample_id,
                    identity=sample.identity.to_json(), stage=sample.identity.stage,
                    combination_id=sample.identity.combination_id, oracle_id=config.oracle_id,
                    layer=layer, tool=f"{layer}-oracle",
                )
            else:
                record = _execute_layer(
                    layer=layer,
                    sample=sample,
                    config=config,
                    action_id=action_id,
                    evaluation_id=evaluation_id,
                    output=output,
                    profile=profile,
                    active_backend=active_backend,
                    layer_payload_runner=layer_payload_runner,
                )
            records[layer].append(record)
            _append_jsonl(layers_dir / f"{layer}.jsonl", record.to_json())

    metrics = _evaluator_metrics(
        records,
        static_hits,
        expected_sample_ids=[sample.sample_id for sample in inputs],
        victim_temperature=config.victim_temperature,
        victim_repeats=config.victim_repeats,
        coverage=sast_coverage_matrix(config.combination_id, config.sast_tools)
        if SAST_LAYER in config.enabled_layers
        else None,
    )
    write_json_atomic(output / "evaluator_metrics.json", metrics)
    write_json_atomic(
        output / "manifest.json",
        {
            "schema_version": EVALUATORS_RUN_SCHEMA,
            "evaluation_id": evaluation_id,
            "config_sha256": config_sha,
            "config": config.to_json(),
            "inputs": {
                "data_dir": str(data_dir),
                "generation_run": str(generation_run),
                "cleaned_dir": str(cleaned_dir),
                "execution_config": execution_config_value,
                "evaluation_id": evaluation_id,
                "ledger": effective_ledger,
            },
            "sample_count": len(inputs),
            "layer_counts": {layer: len(items) for layer, items in records.items()},
            "cache": {"enabled": False, "reason": "cache_disabled"},
            "semantics_conflicts": list(SEMANTICS_CONFLICTS),
            "status": "complete",
        },
    )
    write_text_atomic(
        output / "REPORT.md",
        "\n".join(
            [
                "# Other-evaluator report",
                "",
                f"- samples: {len(inputs)}",
                f"- layer counts: {json.dumps({k: len(v) for k, v in records.items()})}",
                f"- metrics: {json.dumps({k: v.get('value') for k, v in metrics.items()})}",
                "- other-evaluator layers use DisabledCache; a new evaluation_id always re-evaluates.",
                "- realism records are semantics_pending until the classifier conflict is adjudicated.",
                "",
            ]
        ),
    )
    return 0


def _execute_layer(
    *,
    layer: str,
    sample: Any,
    config: EvaluatorsConfig,
    action_id: str,
    evaluation_id: str,
    output: Path,
    profile: Any,
    active_backend: Any,
    layer_payload_runner: Any,
):
    attempt_id = f"{layer}-{sample.sample_id[:12]}-{sha256_bytes(action_id.encode('utf-8'))[:8]}"
    request = {
        "sample_id": sample.sample_id,
        "attempt_id": attempt_id,
        "oracle_id": config.oracle_id,
        "task_id": sample.identity.task_id,
        "code": sample.final_code,
        "test": sample.selected_test,
        "timeout": 20,
    }
    payload: dict[str, Any] | None = None
    if layer_payload_runner is not None:
        payload = layer_payload_runner(
            layer=layer, request=request, sample=sample, attempt_id=attempt_id
        )
    elif profile is not None and active_backend is not None:
        _result, payload = _container_layer_payload(
            profile=profile,
            backend=active_backend,
            output=output,
            entry=layer,
            entry_args=("--request", "/in/layer_request.json", "--payload", "/out/payload.json"),
            request_files={"layer_request.json": request},
            sample=sample,
            oracle_id=config.oracle_id,
            stage=config.stage,
            combination_id=config.combination_id,
            result_schema=f"{layer}-payload-v1",
            attempt_id=attempt_id,
        )
    if not isinstance(payload, dict):
        if layer == DYNAMIC_LAYER:
            return pending_dynamic_record(
                evaluation_id=evaluation_id, action_id=action_id, sample=sample,
                reason="layer_execution_unavailable",
            )
        return pending_realism_record(evaluation_id=evaluation_id, action_id=action_id, sample=sample)

    if layer == DYNAMIC_LAYER:
        verdict = classify_dynamic(payload.get("events") or [], payload.get("execution_status") or "")
        return build_dynamic_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample,
            outcome={
                "verdict": verdict,
                "status": STATUS_COMPLETED,
                "coverage": "covered",
                "available": True,
                "oracle_id": config.oracle_id,
                "evidence": {
                    "execution_status": payload.get("execution_status"),
                    "suite_completed": payload.get("suite_completed"),
                    "tests_run": payload.get("tests_run"),
                    "instrumented_sites": payload.get("instrumented_sites"),
                    "event_count": len(payload.get("events") or []),
                    "stubs": payload.get("stubs"),
                    "error": payload.get("error"),
                },
            },
        )

    model = ThreatModel(**payload["threat_model"])
    stubs = payload.get("stubs") or []
    classified = []
    for variant in payload.get("variants") or []:
        execution = variant.get("execution") or {}
        security = classify_realism(model, execution, stubs=stubs)
        classified.append((variant.get("security_driver"), execution, security))
    driver, _execution, security = select_variant(model, classified)
    return build_realism_record(
        evaluation_id=evaluation_id, action_id=action_id, sample=sample,
        outcome={
            "verdict": security["security_verdict"],
            "status": STATUS_COMPLETED,
            "coverage": "covered",
            "available": True,
            "evidence": {
                "selected_driver": driver,
                "security_reason": security["security_reason"],
                "adapter_version": security["adapter_version"],
                "stub_downgrade": security["stub_downgrade"],
                "stubs": stubs,
                "variants": [
                    {
                        "driver": item[0],
                        "verdict": item[2]["security_verdict"],
                        "execution_status": item[1].get("execution_status"),
                    }
                    for item in classified
                ],
            },
        },
    )


def _sast_target_rules(config: EvaluatorsConfig, tool: str, sample: Any) -> tuple[str, ...]:
    if tool == "bandit":
        try:
            from .sast import bandit_target_rules

            return bandit_target_rules(sample.identity.combination_id)
        except KeyError:
            return ()
    if tool == "semgrep":
        try:
            from .sast import semgrep_target_rules

            return semgrep_target_rules(sample.identity.combination_id)
        except KeyError:
            return ()
    return ()


def _evaluator_metrics(
    records: dict[str, list[Any]],
    static_hits: dict[str, bool] | None = None,
    *,
    expected_sample_ids: list[str] | None = None,
    victim_temperature: float = 0.0,
    victim_repeats: int = 1,
    coverage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sampling = {"temperature": victim_temperature, "repeats": victim_repeats}
    metrics: dict[str, Any] = {}
    sast_by_tool: dict[str, dict[str, Any]] = {}
    for record in records[SAST_LAYER]:
        sast_by_tool.setdefault(record.tool, {})[record.sample_id] = record
    total_expected = len(expected_sample_ids) if expected_sample_ids is not None else None
    for tool, rows in sast_by_tool.items():
        if coverage is not None and not (coverage.get(tool) or {}).get("covered", True):
            metrics[f"{tool}_evasion"] = {
                "name": f"{tool}_evasion",
                "defined": False,
                "value": None,
                "reason": "target_rules_uncovered",
                "availability": {tool: {"available": True}},
            }
            continue
        if static_hits is None or expected_sample_ids is None:
            metrics[f"{tool}_evasion"] = {
                "name": f"{tool}_evasion",
                "defined": False,
                "value": None,
                "reason": "static_hits_unavailable",
                "availability": {tool: {"available": True}},
            }
            continue
        # The denominator set is the full expected sample set; a missing static
        # verdict is never defaulted to False (F6 / plan 05 §7.2).
        missing = [sample_id for sample_id in expected_sample_ids if sample_id not in static_hits]
        if missing:
            metrics[f"{tool}_evasion"] = {
                "name": f"{tool}_evasion",
                "defined": False,
                "value": None,
                "reason": f"static_hits_incomplete:{len(missing)}/{total_expected}",
                "availability": {tool: {"available": True}},
            }
            continue
        shim = [
            {"sample_id": sample_id, "asr_hit": bool(static_hits[sample_id])}
            for sample_id in expected_sample_ids
        ]

        def accessor(_record, _rows=rows):
            layer = _rows.get(_record["sample_id"])
            if layer is None:
                return None
            return {
                "available": layer.available,
                "completed": layer.completed,
                "detected": layer.detected,
            }

        result = evasion(
            shim,
            tool_name=tool,
            accessor=accessor,
            temperature=victim_temperature,
            repeats=victim_repeats,
            task_set="evaluation",
            sampling=sampling,
        )
        metrics[f"{tool}_evasion"] = result.to_json()
    judge_rows = list({record.sample_id: record for record in records[JUDGE_LAYER]}.values())
    if judge_rows:
        judge_sample_ids = {record.sample_id for record in judge_rows}
        judge_missing = (
            [sample_id for sample_id in expected_sample_ids if sample_id not in judge_sample_ids]
            if expected_sample_ids is not None
            else []
        )
        if judge_missing:
            metrics["llm_judge_rate"] = {
                "name": "llm_judge_rate",
                "defined": False,
                "value": None,
                "reason": f"judge_rows_incomplete:{len(judge_missing)}/{total_expected}",
                "availability": {"judge": {"available": True}},
            }
        else:
            metrics["llm_judge_rate"] = llm_judge_rate(
                judge_rows,
                accessor=lambda record: {
                    "available": record.detected is not None,
                    "detected": bool(record.detected),
                },
                temperature=victim_temperature,
                repeats=victim_repeats,
                task_set="evaluation",
                sampling=sampling,
            ).to_json()
    if judge_rows and static_hits is not None and expected_sample_ids is not None:
        static_missing = [sid for sid in expected_sample_ids if sid not in static_hits]
        if static_missing:
            metrics["llm_evasion"] = {
                "name": "llm_evasion",
                "defined": False,
                "value": None,
                "reason": f"static_hits_incomplete:{len(static_missing)}/{total_expected}",
                "availability": {"llm": {"available": True}},
            }
        else:
            llm_shim = [
                {"sample_id": sample_id, "asr_hit": bool(static_hits[sample_id])}
                for sample_id in expected_sample_ids
            ]
            judge_by_sample = {record.sample_id: record for record in judge_rows}

            def _llm_accessor(_record, _rows=judge_by_sample):
                layer = _rows.get(_record["sample_id"])
                if layer is None:
                    return None
                return {
                    "available": layer.available,
                    "completed": layer.completed,
                    "detected": layer.detected,
                }

            metrics["llm_evasion"] = evasion(
                llm_shim,
                tool_name="llm",
                accessor=_llm_accessor,
                temperature=victim_temperature,
                repeats=victim_repeats,
                task_set="evaluation",
                sampling=sampling,
            ).to_json()
    elif judge_rows:
        metrics["llm_evasion"] = {
            "name": "llm_evasion",
            "defined": False,
            "value": None,
            "reason": "static_hits_unavailable",
            "availability": {"llm": {"available": True}},
        }
    return metrics


def run_resume_other(
    run_dir: Path | str,
    *,
    judge_runner_factory=None,
    sast_scan=None,
) -> int:
    run_path = Path(run_dir).resolve()
    manifest = read_json(run_path / "manifest.json")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise FunctionalInputError(
            "resume requires the original input references; re-run evaluate-other"
        )
    config_path = run_path / "config.json"
    if not config_path.is_file():
        raise FunctionalInputError("resume requires config.json in the run directory")
    persisted_config = read_json(config_path)
    if not isinstance(persisted_config, dict):
        raise FunctionalInputError("resume config.json is not a JSON object")
    execution_config = inputs.get("execution_config") or persisted_config.get(
        "execution_config"
    )
    evaluation_id = (
        inputs.get("evaluation_id")
        or persisted_config.get("evaluation_id")
        or manifest.get("evaluation_id")
    )
    restored_ledger = (
        inputs.get("ledger")
        or persisted_config.get("ledger")
        or str(run_path / "ledger.jsonl")
    )
    return run_evaluate_other(
        config_path,
        Path(inputs["data_dir"]),
        Path(inputs["generation_run"]),
        Path(inputs["cleaned_dir"]),
        restored_ledger,
        run_path,
        judge_runner_factory=judge_runner_factory,
        sast_scan=sast_scan,
        execution_config_path=execution_config,
        evaluation_id=evaluation_id,
    )


__all__ = [
    "EvaluatorsConfig",
    "load_evaluators_config",
    "run_check_evaluators",
    "run_evaluate_other",
    "run_resume_other",
    "SEMANTICS_CONFLICTS",
]
