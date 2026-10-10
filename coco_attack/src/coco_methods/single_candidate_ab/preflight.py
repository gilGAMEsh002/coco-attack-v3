"""Offline preflight for the single-candidate A/B method (task 06).

Reads and validates the explicit configuration, read-only assets and interfaces
and emits a reviewable report.  It performs **no** model request, no credential
load, no Docker/Semgrep execution and does not create a resumable "experiment
started" state; it only writes an explicit report path when asked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from coco_attack.assets.artifacts import read_json, sha256_file
from coco_attack.data.loader import load_tasks
from coco_attack.data.snapshot import load_prepared_data
from coco_attack.evaluation.metrics import assess_baseline_compatibility
from coco_attack.evaluation.sast import semgrep_rule_ids, semgrep_target_rules
from coco_attack.execution.preflight import load_profile
from coco_attack.iteration.code_check import SCHEMA_VERSION as CHECK_SCHEMA_VERSION
from coco_attack.iteration.method_inputs import (
    assemble_method_inputs,
    render_current_template_request,
    render_system_block,
)
from coco_attack.iteration.action_runtime import HeuristicTokenCounter
from coco_attack.iteration.fewshot import load_specs
from coco_attack.iteration.template_snapshot import read_snapshot
from coco_attack.iteration.training_loop import _expected_keys, _matrix_ok, _read_jsonl
from .runtime import A_FIELD, B_FIELD, MethodConfig, MutatorRole, VictimRole

PREFLIGHT_SCHEMA_VERSION = "method-preflight-v1"

#: Warning-only headroom (tokens) for the mutator input budget.  ``fixed_tokens``
#: (the assembled system block + a representative current-template request) plus
#: the configured ``max_tokens`` is compared against ``context_window_tokens``
#: minus ``context_margin_tokens``.  The frozen run's R5 prompt grew to ~23.3k
#: tokens once history accumulated, leaving very little slack against a 32768
#: window with ``max_tokens=8192``; preflight cannot know the future history, so
#: it flags a fixed block that already leaves less than this headroom.  This
#: threshold only decides whether a ``warnings`` entry is emitted: it never
#: produces an error and never changes readiness or the exit code.
_MUTATOR_INPUT_HEADROOM_TOKENS = 2048


def _safe_load(path: str | None) -> Any:
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        return read_json(candidate)
    except (OSError, ValueError):
        return None


def _load_initial_snapshot(config: MethodConfig):
    path = Path(config.snapshot_path)
    if path.is_dir() and (path / "snapshot.json").is_file():
        return read_snapshot(path)
    # A snapshot store layout: <store>/<combination>/<content-sha>
    candidate = Path(config.snapshot_store) / config.combination_id / path.name
    if candidate.is_dir():
        return read_snapshot(candidate)
    return read_snapshot(path)


def _role_report(role: MutatorRole | VictimRole) -> dict[str, Any]:
    payload = role.to_json()
    # Never reveal any credential material; roles carry none, but be explicit.
    return {key: value for key, value in payload.items() if "key" not in key.lower() and "secret" not in key.lower()}


def _baseline_report(config: MethodConfig, *, required: bool) -> dict[str, Any]:
    """Validate the baseline's own sources and bind them to the victim role.

    Reuses the same identity rules as the training baseline slice: the embedded
    `static/manifest.json` config plus the actual `evaluations.jsonl` fingerprint,
    and the external config must agree with it.  Ledger/manifest presence alone is
    never treated as a valid source.
    """

    baseline: dict[str, Any] = {
        "applicable": required,
        "provided": bool(config.baseline_static and config.baseline_config),
        "compatible_with_victim": None,
        "real_research_delta_possible": None,
        "warnings": [],
        "missing": [],
        "mismatches": [],
    }
    if not required:
        baseline["note"] = (
            "mock victim: a baseline comparison is not applicable and cannot yield a real research delta"
        )
        baseline["real_research_delta_possible"] = False
        return baseline

    if not config.baseline_static:
        baseline["missing"].append("baseline_static")
    if not config.baseline_config:
        baseline["missing"].append("baseline_config")
    if baseline["missing"]:
        baseline["compatible_with_victim"] = False
        baseline["real_research_delta_possible"] = False
        return baseline

    static_path = Path(config.baseline_static)
    config_path = Path(config.baseline_config)
    if not static_path.is_file():
        baseline["missing"].append("baseline_static_file")
    if not config_path.is_file():
        baseline["missing"].append("baseline_config_file")
    manifest = _safe_load(str(static_path.parent / "manifest.json"))
    if not isinstance(manifest, Mapping):
        baseline["missing"].append("baseline_static_manifest")
    if baseline["missing"]:
        baseline["compatible_with_victim"] = False
        baseline["real_research_delta_possible"] = False
        return baseline

    embedded = manifest.get("config") if isinstance(manifest.get("config"), Mapping) else {}
    baseline["baseline_model"] = embedded.get("model")
    baseline["baseline_temperature"] = embedded.get("temperature")
    baseline["baseline_repeats"] = embedded.get("repeats")
    baseline["baseline_task_ids"] = embedded.get("task_ids")
    if not isinstance(embedded.get("task_ids"), list):
        baseline["missing"].append("baseline_config.task_ids")
    declared = (manifest.get("inputs") or {}).get("evaluations") or {}
    if declared.get("sha256") != sha256_file(static_path):
        baseline["missing"].append("baseline_evaluations_sha256")
    external = _safe_load(str(config_path))
    if not isinstance(external, Mapping):
        baseline["missing"].append("baseline_config_json")
    else:
        for field in ("model", "temperature", "repeats", "task_set", "combination_id", "oracle_id", "prompt_form"):
            if field in embedded and external.get(field) != embedded.get(field):
                baseline["mismatches"].append(
                    {"key": f"baseline_config.{field}", "baseline": embedded.get(field), "external": external.get(field)}
                )

    embedded_tasks = embedded.get("task_ids")
    if isinstance(embedded_tasks, list) and not set(config.train_task_ids) <= {str(task) for task in embedded_tasks}:
        baseline["mismatches"].append(
            {"key": "task_ids", "baseline": embedded_tasks, "victim": list(config.train_task_ids)}
        )

    # Parse the actual per-sample results and require the exact two-task matrix.
    try:
        rows = _read_jsonl(static_path)
    except Exception as error:  # noqa: BLE001 - invalid JSONL is a missing source
        rows = []
        baseline["missing"].append(f"baseline_evaluations_jsonl:{type(error).__name__}")
    total_rows = len(rows)
    # Slice to the current train tasks, exactly as the training baseline slice does.
    train_set = set(config.train_task_ids)
    rows = [row for row in rows if str(row.get("task_id")) in train_set]
    baseline_repeats = embedded.get("repeats")
    if (
        isinstance(baseline_repeats, int)
        and not isinstance(baseline_repeats, bool)
        and baseline_repeats >= 1
    ):
        expected = _expected_keys(config.train_task_ids, baseline_repeats)
        matrix_ok, matrix_reason = _matrix_ok(rows, expected)
    else:
        expected = None
        matrix_ok, matrix_reason = False, "baseline repeats unavailable"
    baseline["matrix"] = {
        "expected": len(expected) if expected is not None else None,
        "observed": len(rows),
        "total_rows": total_rows,
        "ok": matrix_ok,
        "reason": matrix_reason,
    }

    # Reuse the training comparison: blocking identity (model/temperature/repeats/
    # task set/k/data contract) vs warnings (version/environment).
    prepared_current = _prepared_provenance(config.data_dir, config.combination_id)
    prepared_baseline = _prepared_provenance(config.baseline_data_dir, config.combination_id)
    baseline_k = None
    evaluators = _safe_load(config.baseline_evaluators_config)
    if isinstance(evaluators, Mapping):
        baseline_k = evaluators.get("k")
    baseline_payload = {
        "combination_id": embedded.get("combination_id"),
        "model": embedded.get("model"),
        "temperature": embedded.get("temperature"),
        "repeats": embedded.get("repeats"),
        "task_set": embedded.get("task_set"),
        "form": embedded.get("prompt_form") or embedded.get("form"),
        "k": baseline_k,
        "split_mode": prepared_baseline.get("split_mode"),
        "data_contract": prepared_baseline.get("data_contract"),
        "task_snapshot_sha256": prepared_baseline.get("task_snapshot_sha256"),
        "split_manifest_sha256": prepared_baseline.get("split_manifest_sha256"),
    }
    candidate_payload = {
        "combination_id": config.combination_id,
        "model": config.victim.model,
        "temperature": config.victim.temperature,
        "repeats": config.victim.repeats,
        "task_set": config.stage,
        "form": config.form,
        "k": [1, 3, 5],
        "split_mode": prepared_current.get("split_mode"),
        "data_contract": prepared_current.get("data_contract"),
        "task_snapshot_sha256": prepared_current.get("task_snapshot_sha256"),
        "split_manifest_sha256": prepared_current.get("split_manifest_sha256"),
    }
    assessment = assess_baseline_compatibility(baseline_payload, candidate_payload)
    blocking = assessment.get("blocking") or []
    warnings = assessment.get("warnings") or []
    baseline["blocking"] = blocking
    baseline["warnings"] = warnings
    for item in blocking:
        if item.get("reason") == "missing":
            baseline["missing"].append(item.get("key"))
        else:
            baseline["mismatches"].append(item)
    baseline["victim"] = {
        "model": config.victim.model,
        "temperature": config.victim.temperature,
        "repeats": config.victim.repeats,
    }

    baseline["compatible_with_victim"] = (
        not baseline["missing"] and not baseline["mismatches"] and matrix_ok
    )
    baseline["real_research_delta_possible"] = bool(baseline["compatible_with_victim"])
    return baseline


def _prepared_provenance(data_dir: str | None, combination_id: str) -> dict[str, Any]:
    if not data_dir:
        return {}
    try:
        prepared = load_prepared_data(Path(data_dir), combination_id)
        mode = getattr(prepared.split, "mode", None)
        return {
            "split_mode": mode.value if hasattr(mode, "value") else (str(mode) if mode else None),
            "data_contract": prepared.data_contract,
            "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
            "split_manifest_sha256": (prepared.files or {}).get("split.json"),
        }
    except Exception:  # noqa: BLE001 - unavailable provenance is reported as missing
        return {}


def _infer_service(config: MethodConfig) -> str:
    """Infer the real/mock service choice from the configured role sources."""

    return "real" if (config.mutator.source == "dmx" or config.victim.source == "dmx") else "mock"


def build_preflight_report(
    config: MethodConfig,
    *,
    check_service: str | None = None,
    training_service: str | None = None,
) -> dict[str, Any]:
    """Assemble the offline preflight report; never touches provider/Docker/Semgrep.

    ``check_service``/``training_service`` are ``"mock"`` or ``"real"``; when not
    given they are inferred from the configured role sources.  A real service
    selection makes its required sources (execution config / Semgrep rules /
    baseline) blocking for readiness.
    """

    resolved_check = check_service or _infer_service(config)
    resolved_training = training_service or ("real" if config.victim.source == "dmx" else "mock")
    report: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "method_protocol": config.protocol_version,
        "config_sha256": config.config_sha256(),
        "services": {"checks": resolved_check, "training": resolved_training},
        # Offline preflight passing is not real-environment availability.
        "offline_preflight_passed": False,
        "real_environment_available": "not_verified",
        "undecided": [],
        "errors": [],
        "warnings": [],
    }

    # -- run scope ---------------------------------------------------------- #
    report["run_scope"] = {
        "combination_id": config.combination_id,
        "stage": config.stage,
        "form": config.form,
        "prompt_version": config.prompt_version,
        "train_task_ids": list(config.train_task_ids),
        "example_task_ids": list(config.example_task_ids),
        "mutable_examples": list(config.mutable_examples),
        "frozen_example": 1,
        "a_field": A_FIELD,
        "b_field": B_FIELD,
        "max_rounds": config.max_rounds,
        "twenty_five_task_test_used": False,
    }

    # -- model sources ------------------------------------------------------ #
    report["roles"] = {
        "mutator": _role_report(config.mutator),
        "victim": _role_report(config.victim),
        "mixed_sources": config.mutator.source != config.victim.source,
        "note": (
            "mixed sources cannot yield a real research delta; use explicit mock/double markers"
            if config.mutator.source != config.victim.source
            else "mutator and victim share the same source selection"
        ),
        "mutator_cache": {
            "scope": "process",
            "configured_once": True,
            "namespace": "dspy-cache-namespace-v1/<mutator.source>/<stage>",
        },
        "victim_generation_process": "independent subprocess (training loop default)",
    }

    # -- read assets / tasks ------------------------------------------------ #
    try:
        spec_map, _cfg, taxonomy = load_specs(Path(config.assets_root))
        spec = spec_map.get(config.combination_id)
        if spec is None:
            report["errors"].append(f"unknown combination {config.combination_id!r}")
        else:
            loaded = load_tasks(spec, Path(config.assets_root), taxonomy)
            available = set(loaded.by_id())
            missing_examples = [task for task in config.example_task_ids if task not in available]
            missing_train = [task for task in config.train_task_ids if task not in available]
            report["assets"] = {
                "combination_present": True,
                "missing_example_tasks": missing_examples,
                "missing_train_tasks": missing_train,
            }
            if missing_examples:
                report["errors"].append(f"example tasks absent from prepared data: {missing_examples}")
            if missing_train:
                report["errors"].append(f"train tasks absent from prepared data: {missing_train}")
    except Exception as error:  # noqa: BLE001 - report, never crash
        report["assets"] = {"combination_present": False, "error": f"{type(error).__name__}: {error}"}
        report["errors"].append(f"cannot load assets/tasks: {error}")

    # -- context budget ----------------------------------------------------- #
    try:
        snapshot = _load_initial_snapshot(config)
        materials = assemble_method_inputs(
            assets_root=config.assets_root,
            snapshot=snapshot,
            example_task_ids=config.example_task_ids,
            system_prefix=config.system_prefix,
            prior=config.prior,
            output_format=config.output_format,
        )
        counter = HeuristicTokenCounter()
        system_block = render_system_block(materials)
        current_user = render_current_template_request(materials, "(preflight)")
        fixed_tokens = counter.count(
            [{"role": "system", "content": system_block}, {"role": "user", "content": current_user}]
        )
        available = (
            config.mutator.context_window_tokens
            - config.mutator.output_reserve_tokens
            - config.mutator.context_margin_tokens
        )
        report["context"] = {
            "counter_method": counter.method,
            "fixed_block_tokens": fixed_tokens,
            "available_tokens": available,
            "context_window_tokens": config.mutator.context_window_tokens,
            "output_reserve_tokens": config.mutator.output_reserve_tokens,
            "margin_tokens": config.mutator.context_margin_tokens,
            "fits": fixed_tokens <= available,
            "counter_is_exact": False,
        }
        if fixed_tokens > available:
            report["errors"].append(
                f"fixed material needs {fixed_tokens} tokens but only {available} are available"
            )
        # B1-c: warning-only projection of the whole mutator request budget.
        # ``fixed_tokens`` (system block + a representative current-template
        # request) plus the configured output budget is compared against the
        # window minus the optional safety margin.  This never adds an error and
        # is not part of readiness; it only flags a budget that is so tight that
        # a truncated/empty mutator response becomes likely.
        window_after_margin = (
            config.mutator.context_window_tokens - config.mutator.context_margin_tokens
        )
        projected = fixed_tokens + config.mutator.max_tokens
        headroom = window_after_margin - projected
        report["context"]["mutator_input_estimate_tokens"] = fixed_tokens
        report["context"]["mutator_input_plus_max_tokens"] = projected
        report["context"]["window_after_margin_tokens"] = window_after_margin
        report["context"]["mutator_input_headroom_tokens"] = headroom
        report["context"]["mutator_input_headroom_threshold_tokens"] = (
            _MUTATOR_INPUT_HEADROOM_TOKENS
        )
        if projected > window_after_margin or headroom < _MUTATOR_INPUT_HEADROOM_TOKENS:
            report["warnings"].append(
                "mutator input budget is tight: estimated input "
                f"{fixed_tokens} + max_tokens {config.mutator.max_tokens} = {projected} tokens "
                f"vs context_window {config.mutator.context_window_tokens} - margin "
                f"{config.mutator.context_margin_tokens} = {window_after_margin} "
                f"(headroom {headroom} < threshold {_MUTATOR_INPUT_HEADROOM_TOKENS}); "
                "a truncated/empty mutator response becomes more likely"
            )
    except Exception as error:  # noqa: BLE001 - report, never crash
        report["context"] = {"error": f"{type(error).__name__}: {error}"}
        report["errors"].append(f"cannot assemble context material: {error}")

    # -- example checks ----------------------------------------------------- #
    # Validate the actual configuration content with the existing read-only
    # parsers (no Docker/Semgrep execution).
    execution_ok = False
    execution_error: str | None = None
    container_limits: dict[str, Any] | None = None
    if config.execution_config:
        try:
            profile = load_profile(config.execution_config)
            execution_ok = True
            execution_profile = type(profile.profile).__name__ if hasattr(profile, "profile") else None
            loaded_limits = profile.profile.limits
            container_limits = {
                "max_parallel_containers": loaded_limits.max_parallel_containers,
                "memory_bytes": loaded_limits.memory_bytes,
                "memory_swap_bytes": loaded_limits.memory_swap_bytes,
                "cpu_quota": loaded_limits.cpu_quota,
                "pids_limit": loaded_limits.pids_limit,
                "workspace_bytes": loaded_limits.workspace_bytes,
                "shm_bytes": loaded_limits.shm_bytes,
                "output_storage_bytes": loaded_limits.output_storage_bytes,
                "sandbox_tmpfs_paths": list(profile.profile.sandbox.tmpfs_paths),
                "output_limits": profile.profile.output_limits.to_json(),
                "output_tmpfs": (
                    profile.profile.output_tmpfs.to_json()
                    if profile.profile.output_tmpfs is not None
                    else None
                ),
            }
        except Exception as error:  # noqa: BLE001 - invalid config is a blocker
            execution_error = f"{type(error).__name__}: {error}"
            execution_profile = None
    else:
        execution_profile = None
    semgrep_ok = False
    semgrep_error: str | None = None
    semgrep_declared: list[str] = []
    if config.semgrep_config:
        try:
            declared = semgrep_rule_ids(config.semgrep_config)
            semgrep_declared = sorted(declared)
            targets = semgrep_target_rules(config.combination_id)
            if not declared:
                semgrep_error = "no rules declared under the configured directory"
            elif not set(targets) <= declared:
                semgrep_error = f"target rules not declared: {sorted(set(targets) - declared)}"
            else:
                semgrep_ok = True
        except Exception as error:  # noqa: BLE001 - invalid rules are a blocker
            semgrep_error = f"{type(error).__name__}: {error}"

    report["example_checks"] = {
        "check_protocol": CHECK_SCHEMA_VERSION,
        "service": resolved_check,
        "execution_config": config.execution_config,
        "execution_config_valid": execution_ok,
        "execution_config_error": execution_error,
        "execution_profile": execution_profile,
        "semgrep_config": config.semgrep_config,
        "semgrep_config_valid": semgrep_ok,
        "semgrep_config_error": semgrep_error,
        "semgrep_declared_rules": semgrep_declared,
        "semgrep_timeout_seconds": config.semgrep_timeout_seconds,
        "candidate_timeout_seconds": config.candidate_timeout_seconds,
        "enabled_layers": ["functional", "static", "semgrep"],
        "docker_semgrep_verified": False,
        "note": (
            "configuration parsed read-only with the existing loaders; this is not a claim "
            "that Docker/Semgrep actually work"
        ),
    }
    if resolved_check == "real":
        if not execution_ok:
            report["errors"].append(
                f"real example checks require a valid execution config: {execution_error or config.execution_config!r}"
            )
        if not semgrep_ok:
            report["errors"].append(
                f"real example checks require valid Semgrep rules: {semgrep_error or config.semgrep_config!r}"
            )

    # -- concurrency scheduling (method-owned) ------------------------------ #
    # The method's bounded worker pool is the actual limit.  The execution
    # profile's ``limits.max_parallel_containers`` is a resource declaration used
    # by ``check-execution`` for its memory-budget estimate; it does not schedule
    # anything.  Report the effective workers, the per-container limits and the
    # amplified output-tmpfs demand, and refuse a configuration that asks for more
    # concurrent containers than the execution config declares.
    example_workers = int(config.example_check_workers)
    victim_concurrency = int(config.victim.max_concurrency)
    concurrency: dict[str, Any] = {
        "example_check_workers": example_workers,
        "victim_max_concurrency": victim_concurrency,
        "mutator_max_concurrency": 1,
        "a_b_decisions_serial": True,
        "container_workers_needed": example_workers,
        "max_parallel_containers_is_a_scheduler": False,
        "note": (
            "only the functional example checks use Docker containers; victim "
            "generation reuses the GenerationRunner thread pool, and mutator/A/B "
            "decisions stay serial. max_parallel_containers only declares a budget."
        ),
    }
    if container_limits is not None:
        per_container = {
            "memory_bytes": container_limits["memory_bytes"],
            "memory_swap_bytes": container_limits["memory_swap_bytes"],
            "pids_limit": container_limits["pids_limit"],
            "cpu_quota": container_limits["cpu_quota"],
            "output_storage_bytes": container_limits["output_storage_bytes"],
            "workspace_bytes": container_limits["workspace_bytes"],
            "shm_bytes": container_limits["shm_bytes"],
            "sandbox_tmpfs_paths": container_limits["sandbox_tmpfs_paths"],
            "output_artifact_total_bytes": container_limits["output_limits"]["total_artifact_bytes"],
            "output_artifact_single_file_bytes": container_limits["output_limits"]["single_file_bytes"],
        }
        per_container_tmpfs = int(container_limits["output_limits"]["total_artifact_bytes"])
        total_tmpfs_demand = example_workers * per_container_tmpfs
        tmpfs_budget = (
            int(container_limits["output_tmpfs"]["budget_bytes"])
            if container_limits["output_tmpfs"] is not None
            else None
        )
        concurrency.update(
            {
                "execution_max_parallel_containers": container_limits["max_parallel_containers"],
                "per_container_limits": per_container,
                "output_tmpfs_total_demand_bytes": total_tmpfs_demand,
                "output_tmpfs_total_demand_basis": (
                    "example_check_workers * output_limits.total_artifact_bytes"
                ),
                "output_tmpfs_budget_bytes": tmpfs_budget,
                "output_tmpfs_configured": container_limits["output_tmpfs"] is not None,
            }
        )
        if example_workers > int(container_limits["max_parallel_containers"]):
            message = (
                f"example_check_workers ({example_workers}) exceeds execution "
                f"limits.max_parallel_containers ({container_limits['max_parallel_containers']}); "
                "the method must stay within the declared container budget or the "
                "execution config must be raised"
            )
            if resolved_check == "real":
                report["errors"].append(message)
            else:
                report["warnings"].append(message)
        if tmpfs_budget is not None and total_tmpfs_demand > tmpfs_budget:
            message = (
                f"example-check concurrency needs {total_tmpfs_demand} output-tmpfs bytes "
                f"but the execution config declares budget_bytes={tmpfs_budget}"
            )
            if resolved_check == "real":
                report["errors"].append(message)
            else:
                report["warnings"].append(message)
    report["concurrency"] = concurrency

    # -- repo_dir for real roles -------------------------------------------- #
    repo_dir_present = bool(config.repo_dir) and Path(config.repo_dir).expanduser().is_dir()
    report["repo_dir"] = {
        "value": config.repo_dir,
        "present": repo_dir_present,
        "note": "the .env key is never read here; only the path is checked",
    }
    if (config.mutator.source == "dmx" or config.victim.source == "dmx") and not repo_dir_present:
        report["errors"].append(
            f"real (dmx) roles require an existing repo_dir: {config.repo_dir!r}"
        )

    # -- baseline ----------------------------------------------------------- #
    baseline = _baseline_report(config, required=resolved_training == "real")
    report["baseline"] = baseline
    if resolved_training == "real" and not baseline.get("compatible_with_victim"):
        detail = list(baseline.get("missing") or []) + [item.get("key") for item in baseline.get("mismatches") or []]
        report["errors"].append(
            "real training requires a valid baseline bound to the victim role; "
            f"missing/mismatched: {detail}"
        )

    # -- request scope ------------------------------------------------------ #
    per_training = len(config.train_task_ids) * config.victim.repeats
    report["request_scope"] = {
        "planned_samples_per_training": per_training,
        "planned_trainings_per_round": 2,
        "max_rounds": config.max_rounds,
        "max_planned_training_samples": per_training * 2 * config.max_rounds,
        "a_attempts_fixed": False,
        "note": "scale description only; not a cost authorisation",
    }

    # -- undecided real-run parameters ------------------------------------- #
    # Only genuinely unspecified/blocking items are listed; a value that is
    # present and validated is not marked undecided again.
    undecided = report["undecided"]
    if config.mutator.source == "dmx" and not config.mutator.model:
        undecided.append("mutator.model")
    if config.victim.source == "dmx" and not config.victim.model:
        undecided.append("victim.model")
    if resolved_training == "real" and not baseline.get("compatible_with_victim"):
        undecided.append("victim model/sampling alignment with a validated baseline source")
    if resolved_check == "real":
        undecided.append("whether the real example checks have been executed in this environment")

    report["offline_preflight_passed"] = not report["errors"]
    report["readiness"] = "offline_ready" if not report["errors"] else "not_ready"
    if undecided and report["offline_preflight_passed"]:
        report["readiness"] = "offline_ready_with_undecided_runtime_parameters"
    return report


__all__ = ["PREFLIGHT_SCHEMA_VERSION", "build_preflight_report"]
