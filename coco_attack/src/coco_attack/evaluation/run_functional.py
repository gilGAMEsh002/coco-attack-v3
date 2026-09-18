"""Functional evaluation orchestration and cache integration (task 03)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..data.snapshot import load_prepared_data
from ..execution.contracts import ExecutionRequest
from ..execution.docker import DockerBackend, DockerClient
from ..execution.preflight import load_profile
from ..execution.supervisor import ExecutionSupervisor, RunLock
from ..generation.contracts import GenerationContractError, SampleIdentity
from ..generation.inputs import select_stage_task_ids
from ..runtime.ledger import EVENT_EXECUTION_RECORDED, Ledger
from .cleaning import CLEANER_VERSION
from .functional import (
    FUNCTIONAL_CLASSIFIER_VERSION,
    FUNCTIONAL_PAYLOAD_SCHEMA,
    HARNESS_VERSION,
    FunctionalResult,
    classify_payload,
    deterministic_input_outcome,
    fingerprint_sha256 as result_fingerprint_sha256,
    validate_payload,
)
from .functional_cache import (
    FunctionalCache,
    functional_fingerprint,
    fingerprint_sha256,
    execution_semantics,
)
from .metrics import pass_at_k

FUNCTIONAL_CONFIG_SCHEMA = "functional-config-v1"
FUNCTIONAL_CHECK_SCHEMA = "functional-check-v1"
FUNCTIONAL_RUN_SCHEMA = "functional-run-v1"
FUNCTIONAL_ENTRY = "functional"
DEFAULT_K = (1, 3, 5)


class FunctionalInputError(ValueError):
    pass


@dataclass(frozen=True)
class FunctionalConfig:
    combination_id: str
    oracle_id: str
    stage: str
    k: tuple[int, ...] = DEFAULT_K
    harness_version: str = HARNESS_VERSION
    task_ids: tuple[str, ...] = ()
    candidate_timeout_seconds: float = 20.0
    batch_id: str | None = None
    model: str | None = None
    temperature: float = 0.0
    repeats: int = 1

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": FUNCTIONAL_CONFIG_SCHEMA,
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "stage": self.stage,
            "k": list(self.k),
            "harness_version": self.harness_version,
            "task_ids": list(self.task_ids),
            "candidate_timeout_seconds": self.candidate_timeout_seconds,
            "batch_id": self.batch_id,
            "model": self.model,
            "temperature": self.temperature,
            "repeats": self.repeats,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "FunctionalConfig":
        return cls(
            combination_id=payload["combination_id"],
            oracle_id=payload["oracle_id"],
            stage=payload["stage"],
            k=tuple(int(k) for k in payload.get("k", DEFAULT_K)),
            harness_version=payload.get("harness_version", HARNESS_VERSION),
            task_ids=tuple(payload.get("task_ids") or ()),
            candidate_timeout_seconds=float(payload.get("candidate_timeout_seconds", 20.0)),
            batch_id=payload.get("batch_id"),
            model=payload.get("model"),
            temperature=float(payload.get("temperature", 0.0)),
            repeats=int(payload.get("repeats", 1)),
        )


@dataclass(frozen=True)
class SampleInput:
    identity: SampleIdentity
    sample_id: str
    oracle_id: str
    generation_status: str
    generation_text: str
    raw_generation_sha256: str
    final_code: str
    final_code_sha256: str
    prompt_sha256: str
    selected_test: str
    test_sha256: str
    entry_point: str
    task_snapshot_sha256: str
    declared_modules: tuple[str, ...] = ()


def load_functional_config(config_path: Path | str) -> FunctionalConfig:
    payload = read_json(Path(config_path))
    if not isinstance(payload, dict):
        raise FunctionalInputError("functional config must be a JSON object")
    return FunctionalConfig.from_json(payload)


def _load_generation_lines(path: Path) -> list[tuple[int, bytes, dict[str, Any]]]:
    rows: list[tuple[int, bytes, dict[str, Any]]] = []
    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise FunctionalInputError(f"{path}:{lineno}: invalid JSON: {error}") from error
            if not isinstance(obj, dict):
                raise FunctionalInputError(f"{path}:{lineno}: not a JSON object")
            rows.append((lineno, raw, obj))
    return rows


def _build_inputs(
    data_dir: Path,
    generation_run: Path,
    cleaned_dir: Path,
    config: FunctionalConfig,
) -> list[SampleInput]:
    prepared = load_prepared_data(data_dir, config.combination_id)
    tasks = prepared.task_by_id()
    try:
        stage_task_ids = set(select_stage_task_ids(prepared, config.stage))
    except GenerationContractError as error:
        raise FunctionalInputError(f"invalid stage {config.stage!r}: {error}") from error
    allowed_task_ids = set(config.task_ids) if config.task_ids else None
    if allowed_task_ids is not None and not allowed_task_ids <= stage_task_ids:
        unknown = sorted(allowed_task_ids - stage_task_ids)
        raise FunctionalInputError(
            f"requested task_ids are not in the {config.stage} set: {unknown}"
        )
    generation_path = generation_run / "generations.jsonl"
    if not generation_path.is_file():
        raise FunctionalInputError(f"generations file missing: {generation_path}")
    cleaned_path = cleaned_dir / "cleaned_generations.jsonl"
    if not cleaned_path.is_file():
        raise FunctionalInputError(f"cleaned generations missing: {cleaned_path}")
    cleaned_manifest = read_json(cleaned_dir / "manifest.json")
    if cleaned_manifest.get("completed") is not True:
        raise FunctionalInputError("cleaned manifest is not completed")

    cleaned_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for lineno, raw, row in _load_generation_lines(cleaned_path):
        key = (str(row.get("task_id")), int(row.get("repeat_id", -1)))
        if key in cleaned_by_key:
            raise FunctionalInputError(f"duplicate cleaned sample {key}")
        cleaned_by_key[key] = row

    inputs: list[SampleInput] = []
    seen: set[str] = set()
    observed_models: set[str] = set()
    observed_repeat_ids: set[int] = set()
    for lineno, raw, row in _load_generation_lines(generation_path):
        identity = SampleIdentity.from_json(row["identity"])
        if identity.combination_id != config.combination_id:
            raise FunctionalInputError(
                f"sample {identity.task_id!r} combination {identity.combination_id!r} does not "
                f"match config combination {config.combination_id!r}"
            )
        if config.batch_id and identity.batch_id != config.batch_id:
            raise FunctionalInputError(
                f"sample {identity.task_id!r} batch {identity.batch_id!r} does not match "
                f"config batch {config.batch_id!r}"
            )
        if identity.stage != config.stage:
            raise FunctionalInputError(
                f"sample {identity.task_id!r} stage {identity.stage!r} does not match "
                f"config stage {config.stage!r}"
            )
        if identity.task_id not in stage_task_ids:
            raise FunctionalInputError(
                f"task {identity.task_id!r} is not in the {config.stage} set"
            )
        observed_repeat_ids.add(identity.repeat_id)
        row_model = row.get("model")
        if isinstance(row_model, str) and row_model:
            observed_models.add(row_model)
        if allowed_task_ids is not None and identity.task_id not in allowed_task_ids:
            continue
        sample_id = str(row["sample_id"])
        if sample_id in seen:
            raise FunctionalInputError(f"duplicate sample_id in generations: {sample_id}")
        seen.add(sample_id)
        key = (identity.task_id, identity.repeat_id)
        cleaned_row = cleaned_by_key.get(key)
        if cleaned_row is None:
            raise FunctionalInputError(f"no cleaned row for sample {key}")
        cleaned = cleaned_row["cleaned"]
        if cleaned.get("raw_sha256") != sha256_bytes(str(row.get("generation", "")).encode("utf-8")):
            raise FunctionalInputError(f"raw generation hash mismatch for {key}")
        if cleaned_row["source"]["line_sha256"] != sha256_bytes(raw):
            raise FunctionalInputError(f"cleaned source line hash mismatch for {key}")
        task = tasks.get(identity.task_id)
        if task is None:
            raise FunctionalInputError(f"task {identity.task_id!r} missing from prepared data")
        if not task.test:
            raise FunctionalInputError(f"task {identity.task_id!r} has no functional test")
        final_code = str(cleaned.get("final_code") or "")
        if sha256_bytes(final_code.encode("utf-8")) != cleaned.get("final_code_sha256"):
            raise FunctionalInputError(f"final_code hash mismatch for {key}")
        inputs.append(
            SampleInput(
                identity=identity,
                sample_id=sample_id,
                oracle_id=prepared.oracle_id,
                generation_status=str(row.get("status")),
                generation_text=str(row.get("generation", "")),
                raw_generation_sha256=str(cleaned.get("raw_sha256")),
                final_code=final_code,
                final_code_sha256=str(cleaned.get("final_code_sha256")),
                prompt_sha256=str(row.get("prompt_sha256")),
                selected_test=task.test,
                test_sha256=sha256_bytes(task.test.encode("utf-8")),
                entry_point=task.entry_point,
                task_snapshot_sha256=prepared.selection.task_snapshot_sha256,
                declared_modules=tuple(task.get("libs") or ()),
            )
        )
    if not inputs:
        raise FunctionalInputError("no samples joined for functional evaluation")
    observed_model = getattr(config, "model", None)
    observed_repeats = getattr(config, "repeats", None)
    if observed_repeats is None:
        observed_repeats = getattr(config, "victim_repeats", 1)
    if observed_model is not None and observed_models and observed_models != {observed_model}:
        raise FunctionalInputError(
            f"generation records model {sorted(observed_models)} does not match "
            f"config model {observed_model!r}"
        )
    expected_repeats = set(range(int(observed_repeats))) if int(observed_repeats) > 0 else None
    if expected_repeats is not None and observed_repeat_ids and observed_repeat_ids != expected_repeats:
        raise FunctionalInputError(
            f"observed repeats {sorted(observed_repeat_ids)} do not match config repeats "
            f"{observed_repeats}"
        )
    return inputs


def _fingerprint(
    sample: SampleInput,
    *,
    config: FunctionalConfig,
    profile: Any,
    generation_run: Path,
) -> dict[str, Any]:
    return functional_fingerprint(
        sample_id=sample.sample_id,
        stage=config.stage,
        batch_id=sample.identity.batch_id,
        combination_id=config.combination_id,
        oracle_id=config.oracle_id,
        generation_status=sample.generation_status,
        run_config_bytes_sha256=sha256_file(generation_run / "run_config.json"),
        prompt_sha256=sample.prompt_sha256,
        raw_generation_sha256=sample.raw_generation_sha256,
        final_code_sha256=sample.final_code_sha256,
        task_snapshot_sha256=sample.task_snapshot_sha256,
        test_sha256=sample.test_sha256,
        entry_point=sample.entry_point,
        fixture_sha256=sha256_bytes(canonical_json_bytes([])),
        cleaner_version=CLEANER_VERSION,
        harness_version=config.harness_version,
        classifier_version=FUNCTIONAL_CLASSIFIER_VERSION,
        result_schema=FUNCTIONAL_PAYLOAD_SCHEMA,
        image_id=profile.image.image_id,
        dependency_lock_sha256=profile.image.dependency_lock_sha256,
        execution_semantics=execution_semantics(profile),
        candidate_timeout_seconds=config.candidate_timeout_seconds,
    )


def run_check_functional(
    config_path: Path | str,
    data_dir: Path | str,
    generation_run: Path | str,
    cleaned_dir: Path | str,
    execution_config_path: Path | str,
    output_dir: Path | str,
    *,
    project_root: Path | str | None = None,
) -> int:
    config = load_functional_config(config_path)
    generation_run = Path(generation_run).resolve()
    cleaned_dir = Path(cleaned_dir).resolve()
    inputs = _build_inputs(Path(data_dir), generation_run, cleaned_dir, config)
    loaded_profile = load_profile(execution_config_path, project_root=project_root)
    profile = loaded_profile.profile
    if FUNCTIONAL_ENTRY not in profile.allowed_entries():
        raise FunctionalInputError(f"execution profile has no {FUNCTIONAL_ENTRY!r} entry")

    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    deterministic = 0
    for sample in inputs:
        if deterministic_input_outcome(sample.generation_status, sample.final_code) is not None:
            deterministic += 1
    payload = {
        "schema_version": FUNCTIONAL_CHECK_SCHEMA,
        "config": config.to_json(),
        "checks": [
            {"id": "inputs", "status": "pass"},
            {"id": "execution_entry", "status": "pass"},
            {"id": "tests_present", "status": "pass"},
        ],
        "combination_id": config.combination_id,
        "oracle_id": config.oracle_id,
        "sample_count": len(inputs),
        "deterministic_failure_count": deterministic,
        "task_snapshot_sha256": inputs[0].task_snapshot_sha256,
        "run_config_bytes_sha256": sha256_file(generation_run / "run_config.json"),
    }
    write_json_atomic(output / "functional_check.json", payload)
    write_text_atomic(
        output / "REPORT.md",
        "\n".join(
            [
                "# Functional input check",
                "",
                f"- samples: {len(inputs)}",
                f"- deterministic failures/empty: {deterministic}",
                "- no candidate code was executed by this command",
                "",
            ]
        ),
    )
    return 0


def _execute_sample(
    *,
    sample: SampleInput,
    config: FunctionalConfig,
    profile: Any,
    backend: DockerBackend,
    run_dir: Path,
    output_root: Path,
    fingerprint_sha: str,
    nonce: str | None = None,
) -> tuple[FunctionalResult, dict[str, Any]]:
    # The attempt identity includes the fingerprint so a re-execution under a
    # changed fingerprint does not overwrite the previous attempt's evidence.
    attempt_id = f"functional-{sample.sample_id[:12]}-{fingerprint_sha[:8]}"
    staging = run_dir / "staging" / attempt_id
    staging.mkdir(parents=True, exist_ok=True)
    solution_bytes = sample.final_code.encode("utf-8")
    tests_bytes = sample.selected_test.encode("utf-8")
    (staging / "solution.py").write_bytes(solution_bytes)
    (staging / "tests.py").write_bytes(tests_bytes)
    func_request = {
        "sample_id": sample.sample_id,
        "attempt_id": attempt_id,
        "entry_point": sample.entry_point,
        "code_sha256": sha256_bytes(solution_bytes),
        "tests_sha256": sha256_bytes(tests_bytes),
        "candidate_timeout_seconds": config.candidate_timeout_seconds,
    }
    (staging / "func_request.json").write_bytes(
        json.dumps(func_request, sort_keys=True).encode("utf-8")
    )
    request = ExecutionRequest(
        sample_id=sample.sample_id,
        attempt_id=attempt_id,
        stage=config.stage,
        batch_id=sample.identity.batch_id,
        combination_id=config.combination_id,
        task_id=sample.identity.task_id,
        repeat_id=sample.identity.repeat_id,
        prompt_version=sample.identity.prompt_version,
        candidate_hash=sample.identity.candidate_hash,
        evaluation_layer="functional",
        entry=FUNCTIONAL_ENTRY,
        entry_args=(
            "--solution", "/in/solution.py",
            "--tests", "/in/tests.py",
            "--request", "/in/func_request.json",
            "--payload", "/out/payload.json",
        ),
        execution_profile_hash=profile.fingerprint(),
        purpose="evaluation",
        input_files=(),
        result_schema=FUNCTIONAL_PAYLOAD_SCHEMA,
        harness_version=config.harness_version,
    )
    (staging / "request.json").write_bytes(
        json.dumps(request.to_json(), sort_keys=True).encode("utf-8")
    )
    outputs = output_root / attempt_id
    outputs.mkdir(parents=True, exist_ok=True)
    supervisor = ExecutionSupervisor(profile, backend, run_dir / "run")
    result = supervisor.execute(request, staging, outputs, nonce=nonce)
    envelope = _read_json_object(run_dir / "run" / "attempts" / attempt_id / "result.json")
    payload = (envelope or {}).get("payload")
    payload_sha = sha256_bytes(canonical_json_bytes(payload)) if isinstance(payload, dict) else None
    return result, {"envelope": envelope, "payload": payload, "payload_sha256": payload_sha, "attempt_id": attempt_id}


def _read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _functional_result(
    *,
    sample: SampleInput,
    config: FunctionalConfig,
    fingerprint: dict[str, Any],
    execution_result: Any,
    payload: dict[str, Any] | None,
    payload_sha256: str | None,
    attempt_id: str | None,
) -> FunctionalResult:
    problems = (
        validate_payload(
            payload,
            sample_id=sample.sample_id,
            attempt_id=attempt_id or "",
            code_sha256=sample.final_code_sha256,
            tests_sha256=sample.test_sha256,
            entry_point=sample.entry_point,
        )
        if isinstance(payload, dict)
        else ["payload_missing"]
    )
    outcome, passed, reason, cache_eligible = classify_payload(
        payload,
        validation_problems=problems,
        execution_available=bool(execution_result.available),
        execution_timed_out=bool(execution_result.timed_out),
        execution_incomplete=not bool(execution_result.result_valid),
        declared_modules=sample.declared_modules,
    )
    load = (payload or {}).get("load") or {}
    run = (payload or {}).get("run") or {}
    execution = {
        "container_id": execution_result.container_id,
        "exit_code": execution_result.exit_code,
        "timed_out": execution_result.timed_out,
        "oom_killed": execution_result.oom_killed,
        "cleanup_complete": execution_result.cleanup_complete,
        "error_class": execution_result.error_class,
        "image_id": execution_result.image_id,
        "execution_profile_hash": execution_result.execution_profile_hash,
        "validation_failure": execution_result.validation_failure,
    }
    if not cache_eligible:
        pass
    return FunctionalResult(
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        combination_id=config.combination_id,
        oracle_id=config.oracle_id,
        attempt_id=attempt_id,
        outcome=outcome,
        passed=passed,
        reason=reason,
        tests_discovered=int(load.get("tests_discovered", 0)),
        tests_run=int(run.get("tests_run", 0)),
        failures=int(run.get("failures", 0)),
        errors=int(run.get("errors", 0)),
        skipped=int(run.get("skipped", 0)),
        expected_failures=int(run.get("expected_failures", 0)),
        unexpected_successes=int(run.get("unexpected_successes", 0)),
        suite_completed=bool(run.get("suite_completed")),
        failure_stage=run.get("failure_stage"),
        test_details=tuple((payload or {}).get("test_details") or ()),
        execution=execution,
        fingerprint=fingerprint,
        fingerprint_sha256=fingerprint_sha256(fingerprint),
        payload_sha256=payload_sha256,
        cache_eligible=cache_eligible,
        accounting_id=f"functional:{config.stage}:{sample.sample_id}:{attempt_id}",
    )


def _deterministic_result(
    *,
    sample: SampleInput,
    config: FunctionalConfig,
    fingerprint: dict[str, Any],
) -> FunctionalResult:
    decision = deterministic_input_outcome(sample.generation_status, sample.final_code)
    assert decision is not None
    outcome, passed, reason, cache_eligible = decision
    return FunctionalResult(
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        combination_id=config.combination_id,
        oracle_id=config.oracle_id,
        attempt_id=None,
        outcome=outcome,
        passed=passed,
        reason=reason,
        tests_discovered=0,
        tests_run=0,
        failures=0,
        errors=0,
        skipped=0,
        expected_failures=0,
        unexpected_successes=0,
        suite_completed=False,
        failure_stage=None,
        test_details=(),
        execution={},
        fingerprint=fingerprint,
        fingerprint_sha256=fingerprint_sha256(fingerprint),
        payload_sha256=None,
        cache_eligible=cache_eligible,
    )


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


def _ledger_has_accounting_id(ledger: Ledger, accounting_id: str) -> bool:
    for event in ledger.replay().events:
        if event.get("event_type") == EVENT_EXECUTION_RECORDED:
            payload = event.get("payload") or {}
            if payload.get("accounting_id") == accounting_id:
                return True
    return False


def _resolve_profile_and_backend(
    execution_config_path: Path | str,
    backend: DockerBackend | None,
    project_root: Path | str | None,
) -> tuple[Any, DockerBackend]:
    loaded_profile = load_profile(execution_config_path, project_root=project_root)
    profile = loaded_profile.profile
    if FUNCTIONAL_ENTRY not in profile.allowed_entries():
        raise FunctionalInputError(f"execution profile has no {FUNCTIONAL_ENTRY!r} entry")
    active_backend = backend or DockerClient(
        control_timeout_seconds=profile.timeouts.docker_control_timeout_seconds
    )
    if profile.image.image_id in (None, "sha256:" + "0" * 64):
        inspect = active_backend.image_inspect(profile.image.reference)
        actual_id = (inspect or {}).get("Id") or (inspect or {}).get("ID")
        if not actual_id:
            raise FunctionalInputError(f"could not resolve image id for {profile.image.reference}")
        from dataclasses import replace

        profile = replace(profile, image=replace(profile.image, image_id=actual_id))
    return profile, active_backend


def _evaluate_core(
    *,
    config: FunctionalConfig,
    inputs: list[SampleInput],
    profile: Any,
    backend: DockerBackend,
    output: Path,
    cache: FunctionalCache,
    ledger: Ledger,
    generation_run: Path,
    skip_sample_ids: set[str],
    existing_results_path: Path | None = None,
) -> list[FunctionalResult]:
    results: list[FunctionalResult] = []
    with RunLock(output / "run"):
        # Read (and repair) prior results under the run lock so a torn tail
        # cannot be truncated while another controller is appending.
        prior_by_sample: dict[str, FunctionalResult] = {}
        if existing_results_path is not None:
            prior_by_sample = {
                result.sample_id: result
                for result in _read_results(existing_results_path)
            }
        results.extend(prior_by_sample.values())
        for sample in inputs:
            fingerprint = _fingerprint(
                sample, config=config, profile=profile, generation_run=generation_run
            )
            fingerprint_sha = fingerprint_sha256(fingerprint)
            # A prior result is reused only when it matches the *current* F1
            # fingerprint; a changed run_config/image/code forces re-evaluation.
            prior = prior_by_sample.get(sample.sample_id)
            if prior is not None and prior.fingerprint_sha256 == fingerprint_sha:
                continue
            if sample.sample_id in skip_sample_ids:
                continue
            lookup = cache.lookup(sample.sample_id, fingerprint_sha)
            if lookup.hit:
                cached = FunctionalResult.from_json(lookup.value["result"])
                from dataclasses import replace

                hit = replace(cached, reuse_source=lookup.value["reuse_source"])
                results.append(hit)
                _append_jsonl(output / "functional_results.jsonl", hit.to_json())
                continue
            decision = deterministic_input_outcome(sample.generation_status, sample.final_code)
            if decision is not None:
                result = _deterministic_result(sample=sample, config=config, fingerprint=fingerprint)
                results.append(result)
                _append_jsonl(output / "functional_results.jsonl", result.to_json())
                continue
            execution_result, extra = _execute_sample(
                sample=sample,
                config=config,
                profile=profile,
                backend=backend,
                run_dir=output,
                output_root=output / "outputs",
                fingerprint_sha=fingerprint_sha,
            )
            result = _functional_result(
                sample=sample,
                config=config,
                fingerprint=fingerprint,
                execution_result=execution_result,
                payload=extra["payload"],
                payload_sha256=extra["payload_sha256"],
                attempt_id=extra["attempt_id"],
            )
            if result.cache_eligible:
                cache.store(
                    sample_id=sample.sample_id,
                    fingerprint=fingerprint,
                    result=result.to_json(),
                    execution=result.execution,
                    artifacts={
                        "result.json": str(
                            output / "run" / "attempts" / extra["attempt_id"] / "result.json"
                        ),
                    },
                    accounting_id=result.accounting_id,
                )
            _record_local_test(ledger, result)
            results.append(result)
            _append_jsonl(output / "functional_results.jsonl", result.to_json())
    return results


def _read_results(path: Path) -> list[FunctionalResult]:
    """Read functional results, tolerating only a torn final line.

    A non-empty final line without a trailing newline that cannot be parsed is
    preserved in a ``.tail`` sidecar and dropped from the file so the next
    append cannot be concatenated onto a corrupt line.  Any earlier malformed
    line is reported as corruption instead of being silently dropped.
    """

    if not path.is_file():
        return []
    data = path.read_bytes()
    lines = data.split(b"\n")
    ends_with_newline = data.endswith(b"\n")
    if ends_with_newline:
        lines = lines[:-1]
    results: list[FunctionalResult] = []
    repair_at: int | None = None
    for index, raw in enumerate(lines):
        if not raw.strip():
            continue
        try:
            results.append(FunctionalResult.from_json(json.loads(raw.decode("utf-8"))))
        except (ValueError, KeyError, TypeError) as error:
            is_last = index == len(lines) - 1
            if is_last and not ends_with_newline:
                # Preserve the torn bytes, then drop them so the next append
                # cannot be concatenated onto a corrupt line.
                path.with_name(path.name + ".tail").write_bytes(raw)
                repair_at = len(data) - len(raw)
                break
            raise FunctionalInputError(
                f"corrupt functional result at {path}:{index + 1}: {error}"
            ) from error
    if repair_at is not None:
        with open(path, "r+b") as handle:
            handle.truncate(repair_at)
            handle.flush()
            os.fsync(handle.fileno())
    return results


def _finish(
    output: Path,
    config: FunctionalConfig,
    inputs: list[SampleInput],
    results: list[FunctionalResult],
) -> None:
    metrics = _aggregate(results, inputs, config)
    write_json_atomic(output / "functional_metrics.json", metrics)
    write_json_atomic(
        output / "manifest.json",
        {
            "schema_version": FUNCTIONAL_RUN_SCHEMA,
            "config": config.to_json(),
            "combination_id": config.combination_id,
            "oracle_id": config.oracle_id,
            "sample_count": len(inputs),
            "result_count": len(results),
            "cache_hits": sum(1 for r in results if r.reuse_source),
            "executed": sum(1 for r in results if not r.reuse_source and r.execution),
            "harness_version": config.harness_version,
            "classifier_version": FUNCTIONAL_CLASSIFIER_VERSION,
            "status": "complete" if len(results) == len(inputs) else "incomplete",
        },
    )
    write_text_atomic(
        output / "REPORT.md",
        "\n".join(
            [
                "# Functional evaluation report",
                "",
                f"- samples: {len(inputs)}",
                f"- results: {len(results)}",
                f"- cache hits: {sum(1 for r in results if r.reuse_source)}",
                "- pass@k: "
                + json.dumps(
                    {key: value.get("value") for key, value in metrics.items() if key.startswith("pass@")}
                ),
                "",
            ]
        ),
    )


def run_evaluate_functional(
    config_path: Path | str,
    data_dir: Path | str,
    generation_run: Path | str,
    cleaned_dir: Path | str,
    execution_config_path: Path | str,
    cache_dir: Path | str,
    output_dir: Path | str,
    *,
    ledger_path: Path | str | None = None,
    backend: DockerBackend | None = None,
    project_root: Path | str | None = None,
) -> int:
    config = load_functional_config(config_path)
    data_dir = Path(data_dir).resolve()
    generation_run = Path(generation_run).resolve()
    cleaned_dir = Path(cleaned_dir).resolve()
    inputs = _build_inputs(data_dir, generation_run, cleaned_dir, config)
    profile, active_backend = _resolve_profile_and_backend(
        execution_config_path, backend, project_root
    )
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    cache = FunctionalCache(Path(cache_dir), config.stage)
    ledger = Ledger(ledger_path) if ledger_path else Ledger(output / "ledger.jsonl")

    write_json_atomic(
        output / "functional_config.json",
        {
            "schema_version": FUNCTIONAL_RUN_SCHEMA,
            "config": config.to_json(),
            "data_dir": str(data_dir),
            "generation_run": str(generation_run),
            "cleaned_dir": str(cleaned_dir),
            "execution_config": str(Path(execution_config_path).resolve()),
            "cache_root": str(Path(cache_dir).resolve()),
            "ledger_path": str(Path(ledger_path).resolve()) if ledger_path else str(output / "ledger.jsonl"),
        },
    )
    results = _evaluate_core(
        config=config,
        inputs=inputs,
        profile=profile,
        backend=active_backend,
        output=output,
        cache=cache,
        ledger=ledger,
        generation_run=generation_run,
        skip_sample_ids=set(),
    )
    _finish(output, config, inputs, results)
    return 0


def run_resume_functional(
    run_dir: Path | str,
    *,
    backend: DockerBackend | None = None,
    project_root: Path | str | None = None,
) -> int:
    run_path = Path(run_dir).resolve()
    run_config = _read_json_object(run_path / "functional_config.json")
    if run_config is None:
        raise FunctionalInputError(
            f"functional run config missing: {run_path / 'functional_config.json'}"
        )
    config = FunctionalConfig.from_json(run_config["config"])
    data_dir = Path(run_config.get("data_dir", ""))
    if not data_dir.is_dir():
        raise FunctionalInputError("functional run config has no usable data_dir")
    generation_run = Path(run_config["generation_run"])
    cleaned_dir = Path(run_config["cleaned_dir"])
    inputs = _build_inputs(data_dir, generation_run, cleaned_dir, config)
    profile, active_backend = _resolve_profile_and_backend(
        run_config["execution_config"], backend, project_root
    )
    cache = FunctionalCache(Path(run_config["cache_root"]), config.stage)
    ledger = Ledger(run_config["ledger_path"])
    all_results = _evaluate_core(
        config=config,
        inputs=inputs,
        profile=profile,
        backend=active_backend,
        output=run_path,
        cache=cache,
        ledger=ledger,
        generation_run=generation_run,
        skip_sample_ids=set(),
        existing_results_path=run_path / "functional_results.jsonl",
    )
    by_sample = {result.sample_id: result for result in all_results}
    ordered = [by_sample[sample.sample_id] for sample in inputs if sample.sample_id in by_sample]
    _finish(run_path, config, inputs, ordered)
    return 0


__all__ = [
    "FunctionalConfig",
    "FunctionalInputError",
    "load_functional_config",
    "run_check_functional",
    "run_evaluate_functional",
    "run_resume_functional",
]


def _record_local_test(ledger: Ledger, result: FunctionalResult) -> None:
    if result.accounting_id and not _ledger_has_accounting_id(ledger, result.accounting_id):
        ledger.append(
            EVENT_EXECUTION_RECORDED,
            sample_id=result.sample_id,
            request_attempt_id=result.attempt_id,
            payload={
                "role": "local_test",
                "accounting_id": result.accounting_id,
                "sample_id": result.sample_id,
                "attempt_id": result.attempt_id,
                "outcome": result.outcome,
                "duration_seconds": result.duration_seconds,
                "execution": result.execution,
                "cost": result.cost,
            },
        )


def _aggregate(
    results: list[FunctionalResult],
    inputs: list[SampleInput],
    config: FunctionalConfig,
) -> dict[str, Any]:
    by_sample = {result.sample_id: result for result in results}
    per_task: dict[str, dict[str, int]] = {}
    gaps: list[str] = []
    unresolved: list[str] = []
    for sample in inputs:
        task_id = sample.identity.task_id
        counts = per_task.setdefault(task_id, {"n": 0, "c": 0})
        counts["n"] += 1
        result = by_sample.get(sample.sample_id)
        if result is None:
            gaps.append(sample.sample_id)
            continue
        if result.passed is True:
            counts["c"] += 1
        elif result.passed is None:
            unresolved.append(sample.sample_id)
    task_ids = sorted(per_task)
    sampling = {"stage": config.stage}
    metrics: dict[str, Any] = {
        "sample_count": len(inputs),
        "result_count": len(results),
        "per_task": per_task,
        "gaps": gaps,
        "unresolved": unresolved,
    }
    for k in config.k:
        if gaps or unresolved:
            metrics[f"pass@{k}"] = {
                "name": f"pass@{k}",
                "defined": False,
                "value": None,
                "reason": f"incomplete_or_unresolved_samples:gaps={len(gaps)},unresolved={len(unresolved)}",
            }
            continue
        metric = pass_at_k(per_task, task_ids, k, task_set=config.stage, sampling=sampling)
        metrics[f"pass@{k}"] = metric.to_json()
    return metrics
