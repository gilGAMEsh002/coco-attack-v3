"""Read-only preflight and status reports for ``implicit_then_literal`` (04-b).

The preflight shares the runtime's config parsing/validation (via
``MethodRunConfig``) and never creates a run, loads credentials, touches the
network, runs docker/semgrep or executes candidate code.  File existence is not
tool/model availability: connectivity and tool state are reported as
``not_checked``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from coco_attack.assets.artifacts import read_json, sha256_file
from coco_attack.data.snapshot import load_prepared_data
from coco_attack.evaluation.sast import semgrep_rule_ids, semgrep_target_rules
from coco_attack.iteration.template_snapshot import TemplateSnapshot, TemplateSnapshotError, read_snapshot
from .baseline import BaselineError, load_comparison_baseline
from .contracts import (
    B_STATUSES,
    EXPERIENCE_CATEGORY_LITERAL,
    EXPERIENCE_CATEGORY_STRUCTURE,
)
from .runtime import (
    MAX_ROUNDS,
    MAX_SLOTS,
    PHASE_DONE,
    PHASE_PAUSED,
    PHASE_STOPPED,
    MethodRuntimeConfig,
    assert_container_budget,
    validate_feedback_matrix,
)
from .wiring import MethodRunConfig, content_identity, effective_model_name

PREFLIGHT_SCHEMA_VERSION = "itl-method-preflight-v1"
STATUS_SCHEMA_VERSION = "itl-method-status-v1"

_REAL_MODEL = "deepseek-v4-flash"
_VICTIM_MODEL = "DeepSeek-V3.2"


@dataclass(frozen=True)
class PreflightFinding:
    level: str  # "ok" | "warning" | "not_checked"
    code: str
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {"level": self.level, "code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class PreflightReport:
    schema_version: str
    run_id: str
    config_sha256: str
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    not_checked: tuple[str, ...]
    checks: tuple[PreflightFinding, ...]
    sources: Mapping[str, Any]
    baseline_status: str
    offline_preflight_passed: bool
    initial_template_sha256: str
    comparison_baseline_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "not_checked": list(self.not_checked),
            "checks": [check.to_json() for check in self.checks],
            "sources": dict(self.sources),
            "baseline_status": self.baseline_status,
            "offline_preflight_passed": self.offline_preflight_passed,
            "initial_template_sha256": self.initial_template_sha256,
            "comparison_baseline_sha256": self.comparison_baseline_sha256,
        }


def _load_initial_template(path: str) -> tuple[TemplateSnapshot | None, str | None]:
    candidate = Path(path)
    if not candidate.exists():
        return None, f"initial template not found: {candidate}"
    try:
        return read_snapshot(candidate), None
    except TemplateSnapshotError as error:
        return None, f"initial template is not a valid snapshot: {error}"


def _baseline_status(
    run_root: Path, task_ids: tuple[str, ...], repeats: int, snapshot_sha: str
) -> str:
    """Distinguish "snapshot prepared" from "this run's samples are complete".

    Reuses the runtime's full evidence check, so missing static verdicts, code
    fingerprints, feedback samples or an inconsistent metric are not complete.
    """

    output = run_root / "baseline" / "training"
    if validate_feedback_matrix(
        output, task_ids=task_ids, repeats=repeats, snapshot_sha=snapshot_sha
    ):
        return "run_samples_complete"
    return "snapshot_prepared"


def build_preflight_report(config: MethodRunConfig) -> PreflightReport:
    """Build a structured, read-only preflight for one loaded run config."""

    if not isinstance(config, MethodRunConfig):
        raise TypeError("build_preflight_report requires a MethodRunConfig")
    method = config.method
    errors: list[str] = []
    warnings: list[str] = []
    not_checked: list[str] = [
        "real model connectivity (DMX)",
        "Docker / execution environment",
        "Semgrep tool availability",
    ]
    checks: list[PreflightFinding] = []

    # 1. Initial template (caller-provided) and fixed baseline are separate roles.
    initial, initial_error = _load_initial_template(method.initial_template_path)
    initial_sha = content_identity(method.initial_template_path)
    if initial_error is not None:
        errors.append(initial_error)
    else:
        assert initial is not None
        if len(initial.examples) != 4:
            errors.append(f"initial template must have 4 examples, got {len(initial.examples)}")
        if initial.example(1).is_poisoned:
            errors.append("initial template example 1 must be frozen")
        checks.append(
            PreflightFinding("ok", "initial_template", f"loaded {initial_sha[:12]}")
        )

    baseline_sha = "missing"
    try:
        comparison = load_comparison_baseline(repository_root=method.repository_root)
        baseline_sha = comparison.content_sha256
        if content_identity(method.comparison_baseline_path) != comparison.reference.file_sha256:
            errors.append(
                "comparison_baseline_path does not point at the fixed baseline asset"
            )
        checks.append(
            PreflightFinding("ok", "comparison_baseline", f"fixed baseline {baseline_sha[:12]}")
        )
    except BaselineError as error:
        errors.append(f"fixed comparison baseline is not verifiable: {error}")

    if Path(method.initial_template_path).resolve() == Path(
        method.comparison_baseline_path or ""
    ).resolve():
        warnings.append(
            "initial template and comparison baseline point at the same path; roles must stay distinct"
        )

    # 2. Prepared data / execution config / rule readability and attribution.
    for label, path in (
        ("prepared_data_dir", method.prepared_data_dir),
        ("execution_config_path", method.execution_config_path),
    ):
        if path is None:
            continue
        if not Path(path).exists():
            errors.append(f"{label} not found: {path}")
        else:
            checks.append(PreflightFinding("ok", label, str(path)))
    if method.semgrep_config is None:
        if method.check_service == "real":
            errors.append("semgrep_config is required for real checks")
    else:
        config_path = Path(method.semgrep_config)
        if not config_path.exists():
            errors.append(f"semgrep_config not found: {method.semgrep_config}")
        elif not config_path.is_dir():
            # The check adapter only accepts a rules directory; a file source
            # would make every A gate return rule_source_not_a_directory.
            errors.append(
                f"semgrep_config must be a rules directory, got a file: {config_path}"
            )
        else:
            checks.append(PreflightFinding("ok", "semgrep_config", str(config_path)))

    if initial is not None:
        combination_id = initial.combination_id
        try:
            prepared = load_prepared_data(Path(method.prepared_data_dir), combination_id)
            by_id = prepared.task_by_id()
        except Exception as error:  # noqa: BLE001 - report the exact reason
            by_id = {}
            errors.append(f"prepared data for {combination_id} is not usable: {error}")
        missing_tasks = [task for task in method.training_task_ids if task not in by_id]
        if missing_tasks:
            errors.append(f"prepared data is missing training tasks {missing_tasks}")
        elif by_id:
            checks.append(
                PreflightFinding("ok", "prepared_tasks", ",".join(method.training_task_ids))
            )
        try:
            rules = semgrep_target_rules(combination_id)
        except Exception:  # noqa: BLE001
            rules = ()
        if not rules:
            errors.append(f"no Semgrep target rule for {combination_id}")
        else:
            checks.append(PreflightFinding("ok", "semgrep_rule", ",".join(rules)))
            config_path = Path(method.semgrep_config) if method.semgrep_config else None
            if config_path is not None and config_path.is_dir():
                available = semgrep_rule_ids(config_path)
                missing_rules = [rule for rule in rules if rule not in available]
                if missing_rules:
                    errors.append(
                        f"semgrep_config {config_path} does not contain target rules "
                        f"{missing_rules}"
                    )
                else:
                    checks.append(
                        PreflightFinding("ok", "semgrep_rule_dir", str(config_path))
                    )
    else:
        not_checked.append("prepared data / rule attribution (initial template unavailable)")

    # 3. Sources / models / params / formal constants / concurrency.
    sources = {
        "proposer": method.proposer_config.source,
        "inducer": method.inducer_config.source,
        "victim": method.victim_source,
        "check_service": method.check_service,
        "effective_models": {
            "proposer": effective_model_name(method.proposer_config.model),
            "inducer": effective_model_name(method.inducer_config.model),
            "victim": effective_model_name(method.victim_model),
        },
    }
    real_mode = (
        "dmx" in {method.proposer_config.source, method.inducer_config.source, method.victim_source}
        or method.check_service == "real"
    )
    if method.enforce_formal_constants:
        if (method.rounds, method.a_slots, method.b_slots_per_seed, method.top_k) != (
            MAX_ROUNDS,
            MAX_SLOTS,
            MAX_SLOTS,
            MAX_SLOTS,
        ):
            errors.append("formal constants are not the fixed 5/5/5/5 values")
        if method.victim_repeats != 10:
            errors.append("formal runs fix victim_repeats=10")
    elif real_mode:
        errors.append(
            "formal constants are disabled; real runs must keep enforce_formal_constants=True"
        )
    else:
        warnings.append("formal constants are disabled (explicit offline mock run)")
    try:
        assert_container_budget(method)
    except Exception as error:  # noqa: BLE001 - surface the exact reason
        errors.append(str(error))
    checks.append(PreflightFinding("ok", "sources", json.dumps(sources, sort_keys=True)))

    # 4. Run-path isolation and existing-directory recovery identity.
    run_root = Path(method.run_root)
    for read_only in (method.assets_root, method.prepared_data_dir):
        try:
            if run_root.resolve().is_relative_to(Path(read_only).resolve()):
                errors.append(f"run_root must not live inside read-only input {read_only}")
        except (OSError, ValueError):
            pass
    config_path = run_root / "config.json"
    if config_path.is_file():
        existing = read_json(config_path)
        if not isinstance(existing, Mapping) or existing.get("config_sha256") != method.config_sha256():
            errors.append(
                "run_root already contains a run with a different configuration; use a new run root"
            )
        else:
            checks.append(PreflightFinding("ok", "run_identity", "existing run matches config"))

    # 5. Baseline status: snapshot prepared vs this run's samples generated.
    status = _baseline_status(
        run_root, method.training_task_ids, method.victim_repeats, baseline_sha
    )

    report = PreflightReport(
        schema_version=PREFLIGHT_SCHEMA_VERSION,
        run_id=method.run_id,
        config_sha256=method.config_sha256(),
        errors=tuple(errors),
        warnings=tuple(warnings),
        not_checked=tuple(not_checked),
        checks=tuple(checks),
        sources=sources,
        baseline_status=status,
        offline_preflight_passed=not errors,
        initial_template_sha256=initial_sha,
        comparison_baseline_sha256=baseline_sha,
    )
    return report


# --------------------------------------------------------------------------- #
# Read-only status report
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StatusReport:
    schema_version: str
    run_id: str
    phase: str
    round_index: int | None
    pause_reason: str | None
    stop_reason: str | None
    config_sha256: str | None
    top5: Mapping[str, Any]
    experience_versions: Mapping[str, Any]
    counts: Mapping[str, Any]
    output_locations: Mapping[str, str]
    next_command: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "phase": self.phase,
            "round_index": self.round_index,
            "pause_reason": self.pause_reason,
            "stop_reason": self.stop_reason,
            "config_sha256": self.config_sha256,
            "top5": dict(self.top5),
            "experience_versions": dict(self.experience_versions),
            "counts": dict(self.counts),
            "output_locations": dict(self.output_locations),
            "next_command": self.next_command,
        }


def _read_state(run_root: Path) -> Mapping[str, Any] | None:
    path = run_root / "state.json"
    if not path.is_file():
        return None
    payload = read_json(path)
    return payload if isinstance(payload, Mapping) else None


def _read_json_if_present(path: Path) -> Mapping[str, Any] | None:
    if not path.is_file():
        return None
    payload = read_json(path)
    return payload if isinstance(payload, Mapping) else None


def build_status_report(config: MethodRunConfig) -> StatusReport:
    """Read only persisted facts; never calls run/resume or repairs commits."""

    if not isinstance(config, MethodRunConfig):
        raise TypeError("build_status_report requires a MethodRunConfig")
    method = config.method
    run_root = Path(method.run_root)
    state = _read_state(run_root)
    if state is None:
        return StatusReport(
            schema_version=STATUS_SCHEMA_VERSION,
            run_id=method.run_id,
            phase="not_started",
            round_index=None,
            pause_reason=None,
            stop_reason=None,
            config_sha256=None,
            top5={},
            experience_versions={},
            counts={},
            output_locations={"run_root": str(run_root)},
            next_command=f"implicit-then-literal-run --config <config>",
        )

    phase = str(state.get("phase") or "unknown")
    stored_config = _read_json_if_present(run_root / "config.json")
    historical_unpinned = (
        stored_config is not None and "prompt_template_sha256" not in stored_config
    )
    round_index = state.get("round_index")
    # Aggregate every committed round, not just the current pointer: after a
    # round-1 stop the pointer has already advanced to round 2.
    top5: dict[str, Any] = {}
    counts = {"a_trainings": 0, "b_trainings": 0, "logical_inductions": 0}
    for round_number in range(1, method.rounds + 1):
        for stage in ("A", "B"):
            commit = _read_json_if_present(
                run_root / "rounds" / str(round_number) / stage / "commit.json"
            )
            if commit is not None:
                top5[f"r{round_number}{stage}"] = commit.get("selected")
            plan = _read_json_if_present(
                run_root / "rounds" / str(round_number) / stage / "plan.json"
            )
            if plan is None:
                continue
            for slot in plan.get("candidates", []):
                record = _read_json_if_present(
                    run_root
                    / "rounds"
                    / str(round_number)
                    / stage
                    / "candidates"
                    / str(slot.get("candidate_id"))
                    / "record.json"
                )
                if record is None:
                    continue
                training = record.get("training") or {}
                if isinstance(training, Mapping) and training.get("completion") == "complete":
                    counts["a_trainings" if stage == "A" else "b_trainings"] += 1
                if record.get("inducted"):
                    counts["logical_inductions"] += 1
    experience = state.get("current_versions") or {}
    if historical_unpinned or phase == PHASE_DONE:
        next_command = None
    elif phase == PHASE_STOPPED:
        next_command = "implicit-then-literal-resume --run-root <run> [--stop-after ...]"
    elif phase == PHASE_PAUSED:
        next_command = "implicit-then-literal-resume --run-root <run>"
    else:
        next_command = "implicit-then-literal-resume --run-root <run>"
    return StatusReport(
        schema_version=STATUS_SCHEMA_VERSION,
        run_id=method.run_id,
        phase=phase,
        round_index=round_index if isinstance(round_index, int) else None,
        pause_reason=state.get("pause_reason"),
        stop_reason=state.get("stop_reason"),
        config_sha256=state.get("config_sha256"),
        top5=top5,
        experience_versions=dict(experience) if isinstance(experience, Mapping) else {},
        counts=counts,
        output_locations={
            "run_root": str(run_root),
            "state": str(run_root / "state.json"),
        },
        next_command=next_command,
    )


__all__ = [
    "PREFLIGHT_SCHEMA_VERSION",
    "STATUS_SCHEMA_VERSION",
    "PreflightFinding",
    "PreflightReport",
    "StatusReport",
    "build_preflight_report",
    "build_status_report",
]
