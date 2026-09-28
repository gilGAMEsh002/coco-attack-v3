"""Direct example code check (I3).

A directly callable service that accepts one explicit example task plus its code
and returns independent per-layer **facts**:

* syntax / entry-point state (:mod:`ast` only, no execution);
* the full normalized static-oracle result plus its fingerprint;
* the Semgrep SAST alert record (positions preserved);
* the functional test result produced by the real isolation container.

The service is generic: it contains no A/B stages, no gate boolean, no
"allowed into B" decision, no attack-success verdict and no candidate pool.  It
also never adds the example task to ``evaluation_ids``/``search_ids`` and never
calls ``run_static.evaluate_static``/``run_other.run_evaluate_other`` (those
require a cleaned-generation matrix).  The method layer combines these facts
itself.

The functional path deliberately does **not** read or write the functional
result cache: an explicit direct check always re-executes.  The example is not a
victim sample, so a distinct ``example-check:`` ``sample_id`` namespace and a
``check_source="example"`` marker are used throughout.
"""

from __future__ import annotations

import ast
import re
import subprocess
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from ..data.contracts import DataContractError
from ..data.loader import load_tasks
from ..evaluation.cleaning import assemble_prefix_and_body
from ..evaluation.functional import (
    FUNCTIONAL_CLASSIFIER_VERSION,
    HARNESS_VERSION,
    classify_payload,
    validate_payload,
)
from ..evaluation.run_functional import (
    execute_functional_code,
    resolve_functional_profile,
)
from ..evaluation.sast import (
    SAST_ADAPTER_VERSION,
    _semgrep_executable,
    scan_sample,
    semgrep_target_rules,
    tool_available,
)
from ..evaluation.static import (
    evaluate_static_sample,
    load_oracle_module,
    oracle_fingerprint,
)
from ..execution.supervisor import RunLock
from ..generation.contracts import SampleIdentity
from ..runtime.ledger import EVENT_EXECUTION_RECORDED, Ledger
from .fewshot import (
    FewshotError,
    FewshotExample,
    load_fewshot_example,
    load_fewshot_examples,
    load_specs,
)

SCHEMA_VERSION = "example-code-check-v1"
CHECK_SOURCE = "example"
STAGE_NOTE = (
    "stage is only the execution namespace required by ExecutionRequest "
    "(search/holdout); this direct check is not an A/B stage and the example is "
    "not a victim sample."
)
CODE_INPUT_MODES = ("example_body", "final_code")
_ALLOWED_STAGES = ("search", "holdout")

_CACHE_REASON = (
    "example-code-check never reads or writes the functional result cache; the "
    "explicit check always re-executes."
)

# Layer ``status`` -> top-level ``state``.  Semgrep keeps its own ``incomplete``.
_STATE_BY_STATUS = {
    "completed": "executed",
    "incomplete": "incomplete",
    "skipped": "skipped",
    "unavailable": "unavailable",
    "error": "error",
}


# The few-shot loader moved to :mod:`coco_attack.iteration.fewshot`; it raises
# the same exception class.  Keeping the historical public name as an alias
# means callers that catch ``CodeCheckInputError`` (including the CLI) continue
# to see loader failures unchanged.
CodeCheckInputError = FewshotError


@dataclass(frozen=True)
class ExampleCheckRequest:
    """One explicit example-code check request.

    ``code_input_mode="example_body"`` treats ``code`` as a candidate function
    body to be assembled under the trusted registry ``code_prompt``;
    ``code_input_mode="final_code"`` executes ``code`` verbatim.
    """

    combination_id: str
    task_id: str
    code: str
    code_source: str
    action_id: str
    output_dir: Path
    assets_root: Path
    code_input_mode: str = "example_body"
    stage: str = "search"
    batch_id: str = "example-check"
    repeat_id: int = 0
    code_prompt: str | None = None
    entry_point: str | None = None
    test: str | None = None
    execution_config_path: Path | None = None
    semgrep_config: Path | None = None
    semgrep_timeout_seconds: float = 60.0
    candidate_timeout_seconds: float = 20.0
    run_functional: bool = True
    run_static: bool = True
    run_semgrep: bool = True
    backend: Any = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_record(
    spec: Any, assets_root: Path, taxonomy: set[str], task_id: str
) -> Any:
    try:
        loaded = load_tasks(spec, assets_root, taxonomy)
    except DataContractError as error:
        raise CodeCheckInputError(
            f"cannot load tasks for {spec.combination_id!r}: {error}"
        ) from error
    record = loaded.by_id().get(task_id)
    if record is None:
        raise CodeCheckInputError(
            f"unknown task_id {task_id!r} in combination {spec.combination_id!r}"
        )
    return record


def _require_trusted(name: str, trusted: Any, context: str) -> str:
    if not isinstance(trusted, str) or not trusted:
        raise CodeCheckInputError(
            f"trusted {name} for {context} is missing or empty; refusing to run"
        )
    return trusted


def _check_attribution(name: str, provided: Any, trusted: str, context: str) -> None:
    if provided is not None and provided != trusted:
        raise CodeCheckInputError(
            f"provided {name} does not byte-equal the trusted registry value for "
            f"{context}; refusing mis-attribution"
        )


def _assemble(request: ExampleCheckRequest, code_prompt: str) -> tuple[str, str]:
    if request.code_input_mode == "final_code":
        return request.code, "final_code_as_is"
    final_code = assemble_prefix_and_body(code_prompt, request.code)
    if final_code is None:
        if not request.code.strip():
            raise CodeCheckInputError("example_body input is empty; nothing to assemble")
        if "'''" in request.code or '"""' in request.code:
            raise CodeCheckInputError(
                "example_body contains a triple-quoted string; assembly under the "
                "trusted code_prompt is ambiguous"
            )
        raise CodeCheckInputError(
            "example_body could not be assembled under the trusted code_prompt"
        )
    return final_code, "code_prompt+body"


def _task_snapshot_sha256(record: Any) -> str:
    return sha256_bytes(canonical_json_bytes(record.snapshot()))


def _run_syntax_layer(final_code: str, entry_point: str) -> dict[str, Any]:
    tree: ast.AST | None = None
    syntax_error: dict[str, Any] | None = None
    try:
        tree = ast.parse(final_code)
        syntax_ok: bool | None = True
    except SyntaxError as error:
        syntax_ok = False
        syntax_error = {
            "message": error.msg,
            "lineno": error.lineno,
            "offset": error.offset,
        }
    entry_present = bool(
        tree is not None
        and any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == entry_point
            for node in tree.body
        )
    )
    return {
        "state": "executed",
        "reason": None,
        "syntax_ok": syntax_ok,
        "syntax_error": syntax_error,
        "entry_present": entry_present,
        "entry_expected": entry_point,
    }


def _run_static_layer(
    request: ExampleCheckRequest,
    spec: Any,
    *,
    final_code: str,
    final_code_sha256: str,
    test_sha256: str,
    entry_point: str,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "state": "executed",
        "reason": None,
        "status": "executed",
        "oracle_id": spec.oracle_id,
        "final_code_sha256": final_code_sha256,
        "test_sha256": test_sha256,
        "entry_point": entry_point,
        "oracle_fingerprint": None,
        "verdict": None,
        "target_present": None,
        "target_pattern": None,
        "matches": None,
        "error": None,
        "oracle_layer": None,
    }
    if not request.run_static:
        return {**base, "state": "skipped", "status": "skipped", "reason": "disabled"}
    try:
        fingerprint = oracle_fingerprint(request.assets_root, spec.oracle_id)
        module = load_oracle_module(request.assets_root, spec.oracle_id)
        normalized = evaluate_static_sample(final_code, spec.oracle_id, module)
    except Exception as error:  # noqa: BLE001 - one layer's failure must not lose the others
        return {
            **base,
            "state": "error",
            "status": "error",
            "reason": f"oracle_load_failed:{type(error).__name__}:{error}",
        }
    return {**base, "oracle_fingerprint": fingerprint, **normalized}


def _rule_source_info(rules_dir: Path, target_rules: tuple[str, ...]) -> dict[str, Any]:
    """Hash the YAML rule files that declare this combination's target ids.

    Method: for every ``*.yml``/``*.yaml`` directly under ``rules_dir`` the raw
    bytes are SHA-256 hashed.  Files whose text declares at least one target rule
    id are reported; when none declares a target id the full directory set is
    reported instead and the method says so.
    """

    all_files: dict[str, str] = {}
    declaring: list[str] = []
    for path in sorted(rules_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".yml", ".yaml"):
            continue
        digest = sha256_file(path)
        all_files[path.name] = digest
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Structural: only the declared ``- id:`` values count, so a rule id in
        # a comment or another rule's message text is not treated as a match.
        declared = set(re.findall(r"^\s*-\s*id:\s*(\S+)", text, re.MULTILINE))
        if target_rules and declared.intersection(target_rules):
            declaring.append(path.name)
    if declaring:
        method = "sha256_per_yaml_rule_file_declaring_target_ids"
        selected = {name: all_files[name] for name in declaring}
    else:
        method = "sha256_per_yaml_rule_file_all_in_directory"
        declaring = sorted(all_files)
        selected = dict(all_files)
    return {
        "rule_source_hash_method": method,
        "rule_source_declaring_files": declaring,
        "rule_source_sha256": selected,
    }


def _semgrep_version() -> str | None:
    executable = _semgrep_executable()
    if executable is None:
        return None
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return proc.stdout.strip().splitlines()[0]


class _SemgrepSample:
    """Duck-typed sample for ``sast.scan_sample`` (facts only, no execution)."""

    def __init__(
        self,
        *,
        final_code: str,
        sample_id: str,
        oracle_id: str,
        final_code_sha256: str,
        task_snapshot_sha256: str,
        identity: SampleIdentity,
    ) -> None:
        self.final_code = final_code
        self.sample_id = sample_id
        self.oracle_id = oracle_id
        self.final_code_sha256 = final_code_sha256
        self.task_snapshot_sha256 = task_snapshot_sha256
        self.identity = identity


def _run_semgrep_layer(
    request: ExampleCheckRequest,
    spec: Any,
    *,
    final_code: str,
    final_code_sha256: str,
    task_snapshot_sha256: str,
    sample_id: str,
    prompt_version: str,
    candidate_hash: str,
    output_dir: Path,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "state": "skipped",
        "reason": None,
        "status": "skipped",
        "detected": None,
        "final_code_sha256": final_code_sha256,
        "semgrep_config": None,
        "target_rules": [],
        "rule_source": None,
        "rule_source_sha256": {},
        "rule_source_hash_method": None,
        "rule_source_declaring_files": [],
        "workdir": None,
        "semgrep_version": None,
    }
    if not request.run_semgrep:
        return {**base, "reason": "disabled"}
    if request.semgrep_config is None:
        return {**base, "state": "unavailable", "status": "unavailable", "reason": "semgrep_config_missing"}
    rules_dir = Path(request.semgrep_config)
    base["semgrep_config"] = str(rules_dir)
    if not rules_dir.is_dir():
        return {
            **base,
            "state": "unavailable",
            "status": "unavailable",
            "reason": f"rule_source_not_a_directory:{rules_dir}",
        }
    try:
        target_rules = semgrep_target_rules(spec.combination_id)
    except KeyError:
        return {
            **base,
            "state": "unavailable",
            "status": "unavailable",
            "reason": "no_rule_mapping",
        }

    identity = SampleIdentity(
        stage=request.stage,
        batch_id=request.batch_id,
        combination_id=spec.combination_id,
        task_id=request.task_id,
        repeat_id=request.repeat_id,
        prompt_version=prompt_version,
        candidate_hash=candidate_hash,
    )
    sample = _SemgrepSample(
        final_code=final_code,
        sample_id=sample_id,
        oracle_id=spec.oracle_id,
        final_code_sha256=final_code_sha256,
        task_snapshot_sha256=task_snapshot_sha256,
        identity=identity,
    )
    workdir = output_dir / "semgrep"
    evaluation_id = f"example-check:{spec.combination_id}:{request.task_id}"
    record = scan_sample(
        sample,
        evaluation_id=evaluation_id,
        action_id=request.action_id,
        tool="semgrep",
        target_rules=target_rules,
        workdir=workdir,
        timeout_seconds=request.semgrep_timeout_seconds,
        semgrep_config=str(rules_dir),
    )
    source_info = _rule_source_info(rules_dir, tuple(target_rules))
    return {
        **record.to_json(),
        **source_info,
        "state": _STATE_BY_STATUS.get(record.status, record.status),
        "reason": record.reason_code,
        "final_code_sha256": final_code_sha256,
        "semgrep_config": str(rules_dir),
        "target_rules": list(target_rules),
        "rule_source": str(rules_dir),
        "workdir": str(workdir),
        "semgrep_version": _semgrep_version(),
    }


def _empty_consumption() -> dict[str, Any]:
    return {
        "local_test_executions": 0,
        "accounting_ids": [],
        "model_calls": 0,
        "model_tokens": None,
        "cost_usd": None,
    }


def _ledger_has_accounting_id(ledger: Ledger, accounting_id: str) -> bool:
    for event in ledger.replay().events:
        if event.get("event_type") != EVENT_EXECUTION_RECORDED:
            continue
        if (event.get("payload") or {}).get("accounting_id") == accounting_id:
            return True
    return False


def _run_functional_layer(
    request: ExampleCheckRequest,
    spec: Any,
    *,
    final_code: str,
    final_code_sha256: str,
    test: str,
    entry_point: str,
    libs: Any,
    sample_id: str,
    prompt_version: str,
    candidate_hash: str,
    output_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    base: dict[str, Any] = {
        "state": "skipped",
        "reason": None,
        "outcome": None,
        "passed": None,
        "cache_eligible": False,
        "attempt_id": None,
        "payload_sha256": None,
        "tests_discovered": 0,
        "tests_run": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
        "suite_completed": False,
        "failure_stage": None,
        "test_details": [],
        "execution": {},
        "container_source": {},
        "duration_seconds": None,
        "execution_profile_hash": None,
        "image_id": None,
        "final_code_sha256": final_code_sha256,
        "test_sha256": sha256_bytes(test.encode("utf-8")),
        "entry_point": entry_point,
        "cache": "not_used_rerun",
        "cache_reason": _CACHE_REASON,
    }
    if not request.run_functional:
        return {**base, "reason": "disabled"}, _empty_consumption()
    if request.execution_config_path is None:
        return {**base, "reason": "execution_config_missing"}, _empty_consumption()

    try:
        profile, backend = resolve_functional_profile(
            request.execution_config_path, request.backend
        )
    except Exception as error:  # noqa: BLE001 - any profile/Docker failure is a fact
        return {
            **base,
            "state": "unavailable",
            "reason": f"execution_unavailable:{type(error).__name__}:{error}",
        }, _empty_consumption()

    # A fresh attempt identity per invocation: this service never reuses a
    # result, so a repeated explicit check is a *new* real execution and must be
    # counted once more, while the ledger guard still prevents double-recording
    # a single execution.
    attempt_id = f"example-check-{sample_id[-12:]}-{uuid.uuid4().hex[:8]}"
    try:
        with RunLock(output_dir / "run"):
            result, extra = execute_functional_code(
                solution=final_code,
                tests=test,
                entry_point=entry_point,
                sample_id=sample_id,
                attempt_id=attempt_id,
                stage=request.stage,
                batch_id=request.batch_id,
                combination_id=spec.combination_id,
                task_id=request.task_id,
                repeat_id=request.repeat_id,
                prompt_version=prompt_version,
                candidate_hash=candidate_hash,
                candidate_timeout_seconds=request.candidate_timeout_seconds,
                harness_version=HARNESS_VERSION,
                profile=profile,
                backend=backend,
                run_dir=output_dir,
                output_root=output_dir / "functional",
            )
    except Exception as error:  # noqa: BLE001 - preserve other layers on failure
        return {
            **base,
            "state": "unavailable",
            "reason": f"execution_unavailable:{type(error).__name__}:{error}",
        }, _empty_consumption()

    payload = extra.get("payload")
    problems = (
        validate_payload(
            payload,
            sample_id=sample_id,
            attempt_id=attempt_id,
            code_sha256=sha256_bytes(final_code.encode("utf-8")),
            tests_sha256=sha256_bytes(test.encode("utf-8")),
            entry_point=entry_point,
        )
        if isinstance(payload, dict)
        else ["payload_missing"]
    )
    outcome, passed, reason, cache_eligible = classify_payload(
        payload,
        validation_problems=problems,
        execution_available=bool(result.available),
        execution_timed_out=bool(result.timed_out),
        execution_incomplete=not bool(result.result_valid),
        declared_modules=tuple(libs),
    )
    load = (payload or {}).get("load") or {}
    run = (payload or {}).get("run") or {}
    execution = {
        "container_id": result.container_id,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "oom_killed": result.oom_killed,
        "cleanup_complete": result.cleanup_complete,
        "error_class": result.error_class,
        "error_reason": result.error_reason,
        "image_id": result.image_id,
        "execution_profile_hash": result.execution_profile_hash,
        "validation_failure": result.validation_failure,
    }
    if not result.available and outcome == "unavailable":
        state = "unavailable"
    elif outcome == "error":
        state = "error"
    else:
        state = "executed"
    functional = {
        **base,
        "state": state,
        "reason": reason,
        "outcome": outcome,
        "passed": passed,
        "cache_eligible": cache_eligible,
        "attempt_id": extra.get("attempt_id"),
        "payload_sha256": extra.get("payload_sha256"),
        "tests_discovered": int(load.get("tests_discovered", 0)),
        "tests_run": int(run.get("tests_run", 0)),
        "failures": int(run.get("failures", 0)),
        "errors": int(run.get("errors", 0)),
        "skipped": int(run.get("skipped", 0)),
        "expected_failures": int(run.get("expected_failures", 0)),
        "unexpected_successes": int(run.get("unexpected_successes", 0)),
        "suite_completed": bool(run.get("suite_completed")),
        "failure_stage": run.get("failure_stage"),
        "test_details": list((payload or {}).get("test_details") or []),
        "execution": execution,
        "container_source": {
            "kind": "docker",
            "entry": "functional",
            "staging_dir": str(output_dir / "staging" / attempt_id),
            "attempt_dir": str(output_dir / "run" / "attempts" / attempt_id),
            "output_dir": str(output_dir / "functional" / attempt_id),
            "result_ref": result.result_ref,
            "result_sha256": result.result_sha256,
            "supervisor_version": result.supervisor_version,
        },
        "duration_seconds": result.duration_seconds,
        "final_code_sha256": final_code_sha256,
        "test_sha256": sha256_bytes(test.encode("utf-8")),
        "entry_point": entry_point,
        "execution_profile_hash": result.execution_profile_hash,
        "image_id": result.image_id,
    }

    accounting_id = f"example-check:{spec.combination_id}:{request.task_id}:{attempt_id}"
    executed = bool(result.available or result.container_id is not None)
    consumption = _empty_consumption()
    if executed:
        ledger = Ledger(output_dir / "ledger.jsonl")
        if not _ledger_has_accounting_id(ledger, accounting_id):
            ledger.append(
                EVENT_EXECUTION_RECORDED,
                sample_id=sample_id,
                request_attempt_id=attempt_id,
                payload={
                    "role": "local_test",
                    "accounting_id": accounting_id,
                    "sample_id": sample_id,
                    "attempt_id": attempt_id,
                    "outcome": outcome,
                    "duration_seconds": result.duration_seconds,
                    "execution": execution,
                    "cost": {},
                },
            )
        consumption = {
            "local_test_executions": 1,
            "accounting_ids": [accounting_id],
            "model_calls": 0,
            "model_tokens": None,
            "cost_usd": None,
        }
    return functional, consumption


def _request_payload(
    *,
    request: ExampleCheckRequest,
    spec: Any,
    record: Any,
    registry_config: Path,
    sample_id: str,
    prompt_version: str,
    candidate_hash: str,
    final_code: str,
    assembly_method: str,
    task_snapshot_sha256: str,
    input_code_sha256: str,
    code_prompt_sha256: str,
    final_code_sha256: str,
    test_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "check_source": CHECK_SOURCE,
        "action_id": request.action_id,
        "stage": request.stage,
        "stage_note": STAGE_NOTE,
        "combination_id": spec.combination_id,
        "oracle_id": spec.oracle_id,
        "task_id": request.task_id,
        "sample_id": sample_id,
        "prompt_version": prompt_version,
        "candidate_hash": candidate_hash,
        "task_snapshot_sha256": task_snapshot_sha256,
        "code_source": request.code_source,
        "code_input_mode": request.code_input_mode,
        "assembly_method": assembly_method,
        "code": request.code,
        "final_code": final_code,
        "fingerprints": {
            "input_code_sha256": input_code_sha256,
            "code_prompt_sha256": code_prompt_sha256,
            "final_code_sha256": final_code_sha256,
            "test_sha256": test_sha256,
        },
        "provenance": {
            "registry_config": str(registry_config),
            "source_path": record.source.source_path,
            "source_file_sha256": record.source.source_file_sha256,
            "source_line": record.source.line_number,
            "record_sha256": record.source.record_sha256,
            "code_prompt": record.code_prompt,
            "test": record.test,
        },
        "combination_spec": {
            "combination_id": spec.combination_id,
            "registry_id": spec.registry_id,
            "oracle_id": spec.oracle_id,
            "legacy_alias": spec.legacy_alias,
            "task_file": spec.task_file,
            "selection_source": spec.selection_source,
            "selection_file": spec.selection_file,
            "selection_key": spec.selection_key,
            "clean_assets": spec.clean_assets,
        },
        "request": {
            "combination_id": request.combination_id,
            "task_id": request.task_id,
            "code_source": request.code_source,
            "action_id": request.action_id,
            "code_input_mode": request.code_input_mode,
            "stage": request.stage,
            "batch_id": request.batch_id,
            "repeat_id": request.repeat_id,
            "code_prompt": request.code_prompt,
            "entry_point": request.entry_point,
            "test": request.test,
            "execution_config_path": (
                str(request.execution_config_path)
                if request.execution_config_path is not None
                else None
            ),
            "semgrep_config": (
                str(request.semgrep_config) if request.semgrep_config is not None else None
            ),
            "semgrep_timeout_seconds": request.semgrep_timeout_seconds,
            "candidate_timeout_seconds": request.candidate_timeout_seconds,
            "run_functional": request.run_functional,
            "run_static": request.run_static,
            "run_semgrep": request.run_semgrep,
        },
        "layers_requested": {
            "syntax": True,
            "static": request.run_static,
            "semgrep": request.run_semgrep,
            "functional": request.run_functional,
        },
    }


def run_example_code_check(request: ExampleCheckRequest) -> dict[str, Any]:
    """Run the requested layers for one explicit example task and return facts."""

    started_at = _utc_now()
    assets_root = Path(request.assets_root)
    output_dir = Path(request.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if request.code_input_mode not in CODE_INPUT_MODES:
        raise CodeCheckInputError(
            f"unknown code_input_mode {request.code_input_mode!r}; "
            f"expected one of {CODE_INPUT_MODES}"
        )
    if request.stage not in _ALLOWED_STAGES:
        raise CodeCheckInputError(
            f"invalid stage {request.stage!r}; expected one of {_ALLOWED_STAGES}"
        )

    specs, registry_config, taxonomy = load_specs(assets_root)
    spec = specs.get(request.combination_id)
    if spec is None:
        raise CodeCheckInputError(
            f"unknown combination {request.combination_id!r}; known: {sorted(specs)}"
        )
    record = _load_record(spec, assets_root, taxonomy, request.task_id)

    context = f"{spec.combination_id}/{request.task_id}"
    code_prompt = _require_trusted("code_prompt", record.code_prompt, context)
    entry_point = _require_trusted("entry_point", record.entry_point, context)
    test = _require_trusted("test", record.test, context)
    libs = record.get("libs") or ()
    _check_attribution("code_prompt", request.code_prompt, code_prompt, context)
    _check_attribution("entry_point", request.entry_point, entry_point, context)
    _check_attribution("test", request.test, test, context)

    final_code, assembly_method = _assemble(request, code_prompt)

    input_code_sha256 = sha256_bytes(request.code.encode("utf-8"))
    code_prompt_sha256 = sha256_bytes(code_prompt.encode("utf-8"))
    final_code_sha256 = sha256_bytes(final_code.encode("utf-8"))
    test_sha256 = sha256_bytes(test.encode("utf-8"))
    sample_id = "example-check:" + sha256_bytes(
        canonical_json_bytes(
            {
                "combination_id": spec.combination_id,
                "task_id": request.task_id,
                "code_source": request.code_source,
                "input_code_sha256": input_code_sha256,
                "final_code_sha256": final_code_sha256,
                "code_input_mode": request.code_input_mode,
            }
        )
    )[:32]
    prompt_version = "example-check:" + sha256_bytes(
        canonical_json_bytes(
            {
                "task_id": request.task_id,
                "code_prompt_sha256": code_prompt_sha256,
                "test_sha256": test_sha256,
            }
        )
    )[:16]
    candidate_hash = final_code_sha256
    task_snapshot_sha256 = _task_snapshot_sha256(record)

    write_json_atomic(
        output_dir / "request.json",
        _request_payload(
            request=request,
            spec=spec,
            record=record,
            registry_config=registry_config,
            sample_id=sample_id,
            prompt_version=prompt_version,
            candidate_hash=candidate_hash,
            final_code=final_code,
            assembly_method=assembly_method,
            task_snapshot_sha256=task_snapshot_sha256,
            input_code_sha256=input_code_sha256,
            code_prompt_sha256=code_prompt_sha256,
            final_code_sha256=final_code_sha256,
            test_sha256=test_sha256,
        ),
    )

    syntax = _run_syntax_layer(final_code, entry_point)
    static = _run_static_layer(
        request,
        spec,
        final_code=final_code,
        final_code_sha256=final_code_sha256,
        test_sha256=test_sha256,
        entry_point=entry_point,
    )
    semgrep = _run_semgrep_layer(
        request,
        spec,
        final_code=final_code,
        final_code_sha256=final_code_sha256,
        task_snapshot_sha256=task_snapshot_sha256,
        sample_id=sample_id,
        prompt_version=prompt_version,
        candidate_hash=candidate_hash,
        output_dir=output_dir,
    )
    functional, consumption = _run_functional_layer(
        request,
        spec,
        final_code=final_code,
        final_code_sha256=final_code_sha256,
        test=test,
        entry_point=entry_point,
        libs=libs,
        sample_id=sample_id,
        prompt_version=prompt_version,
        candidate_hash=candidate_hash,
        output_dir=output_dir,
    )

    oracle_fingerprint_value = static.get("oracle_fingerprint") or {}
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "check_source": CHECK_SOURCE,
        "action_id": request.action_id,
        "stage": request.stage,
        "stage_note": STAGE_NOTE,
        "combination_id": spec.combination_id,
        "oracle_id": spec.oracle_id,
        "task_id": request.task_id,
        "sample_id": sample_id,
        "code": {
            "code_source": request.code_source,
            "code_input_mode": request.code_input_mode,
            "assembly_method": assembly_method,
            "input_code_sha256": input_code_sha256,
            "code_prompt_sha256": code_prompt_sha256,
            "final_code_sha256": final_code_sha256,
            "final_code": final_code,
            "test_sha256": test_sha256,
            "entry_point": entry_point,
        },
        "provenance": {
            "registry_config": str(registry_config),
            "source_path": record.source.source_path,
            "source_file_sha256": record.source.source_file_sha256,
            "source_line": record.source.line_number,
            "record_sha256": record.source.record_sha256,
            "code_prompt": code_prompt,
            "test": test,
        },
        "syntax": syntax,
        "static": static,
        "semgrep": semgrep,
        "functional": functional,
        "layers": [
            {"layer": "syntax", "state": syntax["state"], "reason": syntax["reason"]},
            {"layer": "static", "state": static["state"], "reason": static["reason"]},
            {"layer": "semgrep", "state": semgrep["state"], "reason": semgrep["reason"]},
            {
                "layer": "functional",
                "state": functional["state"],
                "reason": functional["reason"],
            },
        ],
        "consumption": consumption,
        "tool_versions": {
            "oracle_version": oracle_fingerprint_value.get("oracle_version"),
            "harness_version": HARNESS_VERSION,
            "classifier_version": FUNCTIONAL_CLASSIFIER_VERSION,
            "execution_profile_hash": functional.get("execution_profile_hash"),
            "image_id": functional.get("image_id"),
            "semgrep_version_or_null": semgrep.get("semgrep_version"),
            "sast_adapter_version": SAST_ADAPTER_VERSION,
        },
        "artifacts": {
            "request": str(output_dir / "request.json"),
            "result": str(output_dir / "check_result.json"),
            "report": str(output_dir / "REPORT.md"),
            "ledger": str(output_dir / "ledger.jsonl"),
            "semgrep_workdir": str(output_dir / "semgrep"),
            "functional_outputs": str(output_dir / "functional"),
        },
        "started_at": started_at,
        "finished_at": _utc_now(),
    }
    write_json_atomic(output_dir / "check_result.json", result)
    write_text_atomic(output_dir / "REPORT.md", _render_report(result))
    return result


def _render_report(result: dict[str, Any]) -> str:
    syntax = result["syntax"]
    static = result["static"]
    semgrep = result["semgrep"]
    functional = result["functional"]
    consumption = result["consumption"]
    lines = [
        "# Example code check",
        "",
        f"- check source: `{result['check_source']}` (an example, not a victim sample)",
        f"- combination / oracle / task: `{result['combination_id']}` / "
        f"`{result['oracle_id']}` / `{result['task_id']}`",
        f"- action id: `{result['action_id']}`",
        f"- sample id: `{result['sample_id']}`",
        f"- code source: `{result['code']['code_source']}` "
        f"(`{result['code']['code_input_mode']}`, {result['code']['assembly_method']})",
        f"- final_code sha256: `{result['code']['final_code_sha256']}`",
        "",
        "## Layer facts (no combined verdict)",
        "",
        f"- syntax: ok={syntax['syntax_ok']} entry_present={syntax['entry_present']}"
        + (f" error={syntax['syntax_error']}" if syntax.get("syntax_error") else ""),
        f"- static: verdict={static.get('verdict')} "
        f"target_present={static.get('target_present')} reason={static.get('reason')}",
        f"- semgrep: status={semgrep.get('status')} detected={semgrep.get('detected')} "
        f"reason={semgrep.get('reason')} alerts={len(semgrep.get('evidence', {}).get('alerts', []))}",
        f"- functional: outcome={functional.get('outcome')} passed={functional.get('passed')} "
        f"state={functional.get('state')} reason={functional.get('reason')}",
        "",
        "## Consumption",
        "",
        f"- local_test_executions: {consumption['local_test_executions']}",
        f"- model_calls: {consumption['model_calls']} (tokens/cost not applicable)",
        f"- cache: {functional.get('cache')} - {functional.get('cache_reason')}",
        "",
    ]
    return "\n".join(lines)


def build_example_check_request(
    snapshot: Any,
    example: int,
    *,
    assets_root: Path | str,
    action_id: str,
    output_dir: Path | str,
    **overrides: Any,
) -> ExampleCheckRequest:
    """Build an :class:`ExampleCheckRequest` from the CURRENT snapshot example.

    ``example`` uses the snapshot's external 1-based numbering.  The code is
    taken from the snapshot (already patched), never reloaded from the clean
    asset, and ``code_source``/``action_id`` reference the exact template
    version so a result can be traced back to the snapshot that produced it.
    """

    from .template_snapshot import TemplateSnapshot

    if not isinstance(snapshot, TemplateSnapshot):
        raise CodeCheckInputError("build_example_check_request requires a TemplateSnapshot")
    template = snapshot.example(example)
    content_sha = snapshot.content_sha256()
    request = ExampleCheckRequest(
        combination_id=snapshot.combination_id,
        task_id=template.task_id,
        code=template.code,
        code_source=f"poisoned-snapshot:{content_sha}#example{example}",
        action_id=action_id,
        output_dir=Path(output_dir),
        assets_root=Path(assets_root),
        code_input_mode="example_body",
    )
    if not overrides:
        return request
    return replace(request, **overrides)


__all__ = [
    "SCHEMA_VERSION",
    "CHECK_SOURCE",
    "STAGE_NOTE",
    "CODE_INPUT_MODES",
    "CodeCheckInputError",
    "ExampleCheckRequest",
    "FewshotExample",
    "build_example_check_request",
    "load_fewshot_example",
    "load_fewshot_examples",
    "run_example_code_check",
]
