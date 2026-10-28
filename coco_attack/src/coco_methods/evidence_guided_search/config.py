"""Configuration loading and staged readiness checks for evidence-guided search.

The loader is deliberately small: it resolves the explicitly supplied project
root, resolves the declared input paths against that root, and checks the
structural shape of the role materials.  It never fills research choices from
environment variables, historical runs or code defaults.  An undecided value is
kept as ``None`` and is reported by :func:`check_config`.

Stages are cumulative: ``measurement`` includes the role checks, ``search``
includes measurement, and so on.  Stage-specific parameters live in the
sections actually read by the runner (``measurement``,
``reference_measurement``, ``retest_measurement``, ``example_check``,
``search``, ``selection``, ``roles``, ``budget``, ``concurrency``); a missing or
``null`` entry is reported as undetermined rather than replaced by a default.
Checks are read-only and do not sample, call models or run tools.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "ConfigError",
    "ROLE_TEMPLATE_FILES",
    "STAGES",
    "check_config",
    "load_config",
]


class ConfigError(ValueError):
    """The configuration is malformed or cannot be resolved unambiguously."""


#: The six editable role templates, relative to ``template_dir``.  This mirrors
#: the method documentation; it is not a second editable template source.
ROLE_TEMPLATE_FILES: tuple[str, ...] = (
    "候选生成/system.md.j2",
    "候选生成/user.md.j2",
    "独立归纳/system.md.j2",
    "独立归纳/user.md.j2",
    "统一汇总/system.md.j2",
    "统一汇总/user.md.j2",
)

STAGES: tuple[str, ...] = ("roles", "measurement", "search", "selection", "run")

#: Paths that are resolved against the explicit project root when non-null.
#: ``data_root``/``assets_root`` remain optional top-level declarations for
#: backward compatibility; the runner reads its inputs from the nested
#: measurement sections below.
_PATH_FIELDS: tuple[str, ...] = (
    "template_dir",
    "initial_template_path",
    "clean_snapshot_path",
    "task_demonstration_path",
    "data_root",
    "assets_root",
)

#: Sections that hold one measurement configuration.  ``reference`` and
#: ``retest`` use the same settings shape as ``measurement``.
_MEASUREMENT_SECTIONS: tuple[str, ...] = (
    "measurement",
    "reference_measurement",
    "retest_measurement",
)

#: Nested path references resolved against the explicit project root.
_MEASUREMENT_PATHS: tuple[str, ...] = (
    "assets_root",
    "data_dir",
    "execution_config_path",
    "cache_dir",
    "repo_dir",
)
_EVALUATOR_PATHS: tuple[str, ...] = (
    "semgrep_config",
    "codeql_executable",
    "codeql_search_path",
)
_EXAMPLE_CHECK_PATHS: tuple[str, ...] = (
    "assets_root",
    "execution_config_path",
    "semgrep_config",
)

#: Role materials whose type is checked at load time.  ``None`` means undecided.
_TEXT_FIELDS: tuple[str, ...] = (
    "target_definition",
    "public_sast_rules",
    "task_demonstration",
)

_MISSING = object()

#: Parameters that must be decided before the corresponding stage can run.
#: Values are human-readable descriptions used only in the gap report.  The
#: keys mirror the sections actually read by ``runtime._settings`` and
#: ``public_services.public_measure``.
_MEASUREMENT_PARAMETERS: Mapping[str, str] = {
    "assets_root": "read-only asset root",
    "data_dir": "prepared data root",
    "task_ids": "the two explicit training task IDs",
    "repeats": "victim repeats per task",
    "stage": "public execution stage (search/holdout)",
    "victim_messages": "victim message form (single_user)",
    "generation": "generation and extraction settings",
    "evaluators": "SAST tool and rule settings",
    "functional": "functional test settings",
    "execution_config_path": "execution profile JSON",
    "cache_dir": "persistent functional cache root",
}
_GENERATION_FIELDS: Mapping[str, str] = {
    "source": "generation source (mock/dmx)",
    "model": "victim model",
    "batch_id": "batch identity",
    "temperature": "victim temperature",
    "max_tokens": "victim max tokens",
    "request_timeout": "per-request timeout",
    "max_concurrency": "victim batch concurrency",
    "max_request_attempts": "per-sample request attempts",
    "max_sample_retries": "per-sample retries",
}
_FUNCTIONAL_FIELDS: Mapping[str, str] = {
    "k": "functional test sample counts",
    "harness_version": "functional harness version",
    "candidate_timeout_seconds": "candidate timeout",
}
_EXAMPLE_CHECK_PARAMETERS: Mapping[str, str] = {
    "assets_root": "read-only asset root",
    "code_input_mode": "example code input mode",
    "stage": "public execution stage (search/holdout)",
    "execution_config_path": "execution profile JSON",
    "semgrep_config": "Semgrep rule directory",
    "semgrep_timeout_seconds": "Semgrep timeout",
    "candidate_timeout_seconds": "candidate timeout",
}
_SEARCH_PARAMETERS: Mapping[str, str] = {
    "rounds": "round count",
    "guided_count": "guided candidates per round",
    "unguided_count": "unguided candidates per round",
    "probe_groups_per_round": "probe groups per round",
    "guidance_policy": "guidance filtering policy (all_active)",
    "probe_policy": "probe selection policy (in_order_complete_groups)",
    "duplicate_policy": "duplicate sampling rule (independent_sampling)",
}
_SELECTION_PARAMETERS: Mapping[str, str] = {
    "rule_version": "frozen selection rule version",
    "shortlist": "shortlist rule",
    "evidence_policy": "evidence source policy (retest_only)",
    "unknown_policy": "unknown handling (require_all_decided)",
    "functional": "functional feasibility rule",
    "ranking": "ranking rule",
}
_SHORTLIST_PARAMETERS: Mapping[str, str] = {
    "mode": "shortlist mode",
    "content_policy": "content merging policy",
    "limit": "shortlist limit",
    "order": "shortlist ordering",
    "include_sources": "candidate sources included",
}
_FUNCTIONAL_RULE_PARAMETERS: Mapping[str, str] = {
    "comparison": "functional comparison",
    "estimator": "functional estimator",
    "require_complete": "functional coverage requirement",
    "max_drop": "maximum allowed functional drop",
    "minimum": "minimum functional sample count",
}
_RANKING_PARAMETERS: Mapping[str, str] = {
    "metric": "ranking metric",
    "aggregation": "ranking aggregation",
    "tie_break": "ranking tie break",
    "direction": "ranking direction",
    "require_complete": "ranking coverage requirement",
}

#: Fields accepted by ``RoleCallConfig.from_json``.
_ROLE_CONFIG_FIELDS: frozenset[str] = frozenset({
    "role", "model", "source", "temperature", "max_tokens", "request_timeout",
    "max_request_attempts", "api_base", "price_input_per_1k",
    "price_output_per_1k", "currency", "pricing_version", "mock_scenario",
    "protocol_version",
})


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _resolve_against(value: str, root: Path) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return str(candidate.resolve())


def _initial_hypotheses_problems(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["initial_hypotheses must be an array"]
    problems: list[str] = []
    if len(value) != 6:
        problems.append(
            f"initial_hypotheses must contain exactly six objects (got {len(value)})"
        )
    for index, item in enumerate(value):
        where = f"initial_hypotheses[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object")
            continue
        if not isinstance(item.get("statement"), str):
            problems.append(f"{where}.statement must be a string")
        scope = item.get("scope")
        if not isinstance(scope, dict):
            problems.append(f"{where}.scope must be an object")
            continue
        for field in ("task_ids", "conditions", "limits"):
            array = scope.get(field)
            if not isinstance(array, list):
                problems.append(f"{where}.scope.{field} must be an array")
            elif any(not isinstance(entry, str) for entry in array):
                problems.append(
                    f"{where}.scope.{field} must be an array of strings"
                )
    return problems


def _training_tasks_problems(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["training_tasks must be an array"]
    problems: list[str] = []
    if len(value) != 2:
        problems.append(
            f"training_tasks must contain exactly two objects (got {len(value)})"
        )
    seen: set[str] = set()
    for index, item in enumerate(value):
        where = f"training_tasks[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object")
            continue
        task_id = item.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            problems.append(f"{where}.task_id must be a non-empty string")
        elif task_id in seen:
            problems.append(f"training_tasks.task_id must be unique: {task_id!r}")
        else:
            seen.add(task_id)
    return problems


def load_config(path: Path | str, *, project_root: Path | str) -> dict[str, Any]:
    """Load one JSON config, resolving its declared paths against ``project_root``.

    ``project_root`` is required and is always absolutized here.  Relative
    values in :data:`_PATH_FIELDS` are resolved against it.  ``None`` values are
    preserved so a caller can see that a research choice is still undecided.
    The returned mapping records the resolved ``project_root`` and the resolved
    ``config_path`` used for provenance.
    """

    if not isinstance(path, (str, Path)):
        raise TypeError("path must be a string or pathlib.Path")
    if not isinstance(project_root, (str, Path)):
        raise TypeError("project_root must be a string or pathlib.Path")
    if not str(project_root):
        raise ConfigError("an explicit project_root is required")

    root = Path(project_root).resolve()
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"config is not a file: {config_path}")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("config must be a JSON object")

    config: dict[str, Any] = dict(payload)

    for field in _PATH_FIELDS:
        value = config.get(field, _MISSING)
        if value is _MISSING or value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ConfigError(f"config.{field} must be a non-null string or null")
        config[field] = _resolve_against(value, root)

    for section_name in _MEASUREMENT_SECTIONS:
        section = config.get(section_name, _MISSING)
        if section is _MISSING or section is None:
            continue
        if not isinstance(section, dict):
            raise ConfigError(f"config.{section_name} must be an object")
        section = dict(section)
        config[section_name] = section
        for field in _MEASUREMENT_PATHS:
            value = section.get(field, _MISSING)
            if value is _MISSING or value is None:
                continue
            if not isinstance(value, str) or not value:
                raise ConfigError(
                    f"config.{section_name}.{field} must be a non-null string or null"
                )
            section[field] = _resolve_against(value, root)
        evaluators = section.get("evaluators", _MISSING)
        if isinstance(evaluators, dict):
            evaluators = dict(evaluators)
            section["evaluators"] = evaluators
            for field in _EVALUATOR_PATHS:
                value = evaluators.get(field, _MISSING)
                if value is _MISSING or value is None:
                    continue
                if not isinstance(value, str) or not value:
                    raise ConfigError(
                        f"config.{section_name}.evaluators.{field} must be a "
                        "non-null string or null"
                    )
                evaluators[field] = _resolve_against(value, root)

    example_check = config.get("example_check", _MISSING)
    if isinstance(example_check, dict):
        example_check = dict(example_check)
        config["example_check"] = example_check
        for field in _EXAMPLE_CHECK_PATHS:
            value = example_check.get(field, _MISSING)
            if value is _MISSING or value is None:
                continue
            if not isinstance(value, str) or not value:
                raise ConfigError(
                    f"config.example_check.{field} must be a non-null string or null"
                )
            example_check[field] = _resolve_against(value, root)

    for field in _TEXT_FIELDS:
        value = config.get(field, _MISSING)
        if value is _MISSING or value is None:
            continue
        if not isinstance(value, str):
            raise ConfigError(f"config.{field} must be a string or null")

    kind = config.get('initial_template_kind', 'target_template')
    if kind not in ('target_template', 'clean_fewshot'):
        raise ConfigError('initial_template_kind must be target_template or clean_fewshot')

    hypotheses = config.get("initial_hypotheses", _MISSING)
    if hypotheses is not _MISSING and hypotheses is not None:
        problems = _initial_hypotheses_problems(hypotheses)
        if problems:
            raise ConfigError("; ".join(problems))

    tasks = config.get("training_tasks", _MISSING)
    if tasks is not _MISSING and tasks is not None:
        problems = _training_tasks_problems(tasks)
        if problems:
            raise ConfigError("; ".join(problems))

    config["project_root"] = str(root)
    config["config_path"] = str(config_path.resolve())
    return config


def _config_path(
    config: Mapping[str, Any], field: str, gaps: list[str]
) -> Path | None:
    value = config.get(field, _MISSING)
    if value is _MISSING or value is None:
        gaps.append(f"{field} is not determined")
        return None
    if not isinstance(value, str) or not value:
        gaps.append(f"{field} must be a non-null string")
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        root = config.get("project_root", _MISSING)
        if not isinstance(root, str) or not root:
            gaps.append(f"project_root is not determined; cannot resolve {field}")
            return None
        root_path = Path(root)
        if not root_path.is_absolute():
            gaps.append(f"project_root must be absolute; cannot resolve {field}")
            return None
        candidate = root_path / candidate
    return candidate


def _check_file(config: Mapping[str, Any], field: str, gaps: list[str]) -> None:
    candidate = _config_path(config, field, gaps)
    if candidate is not None and not candidate.is_file():
        gaps.append(f"{field} does not exist as a file: {candidate}")


def _check_directory(config: Mapping[str, Any], field: str, gaps: list[str]) -> None:
    candidate = _config_path(config, field, gaps)
    if candidate is not None and not candidate.is_dir():
        gaps.append(f"{field} does not exist as a directory: {candidate}")


def _check_roles(config: Mapping[str, Any], gaps: list[str]) -> None:
    for field in _TEXT_FIELDS:
        if field == 'task_demonstration':
            continue  # Optional except for an explicitly declared clean start.
        value = config.get(field, _MISSING)
        if value is _MISSING or value is None:
            gaps.append(f"{field} is not determined")
        elif not isinstance(value, str):
            gaps.append(f"{field} must be a string")
        elif not _is_text(value):
            gaps.append(f"{field} is empty")

    template_dir = _config_path(config, "template_dir", gaps)
    if template_dir is not None:
        if not template_dir.is_dir():
            gaps.append(f"template_dir does not exist as a directory: {template_dir}")
        else:
            for relative in ROLE_TEMPLATE_FILES:
                if not (template_dir / relative).is_file():
                    gaps.append(f"template file is missing: {relative}")

    _check_file(config, "initial_template_path", gaps)
    if config.get('initial_template_kind') == 'clean_fewshot':
        if config.get('task_demonstration_path') is not None:
            _check_file(config, 'task_demonstration_path', gaps)
        elif not _is_text(config.get('task_demonstration')):
            gaps.append('task_demonstration_path or task_demonstration is required for clean_fewshot')

    hypotheses = config.get("initial_hypotheses", _MISSING)
    if hypotheses is _MISSING or hypotheses is None:
        gaps.append("initial_hypotheses is not determined")
        hypotheses = None
    else:
        problems = _initial_hypotheses_problems(hypotheses)
        gaps.extend(problems)

    if template_dir is not None and template_dir.is_dir() and isinstance(hypotheses, list):
        from .roles import fixed_initial_hypotheses  # local import: prompt parsing lives with the templates
        try:
            declared = fixed_initial_hypotheses(
                (template_dir / ROLE_TEMPLATE_FILES[1]).read_text(encoding="utf-8"),
                required=False,
            )
        except (OSError, ValueError) as exc:
            gaps.append(f"fixed hypotheses are unreadable: {exc}")
        else:
            configured = [
                entry["statement"].strip()
                for entry in hypotheses
                if isinstance(entry, dict) and isinstance(entry.get("statement"), str)
            ]
            if declared is not None and declared != configured:
                gaps.append(
                    "initial_hypotheses differ from the fixed hypotheses in "
                    f"{ROLE_TEMPLATE_FILES[1]} "
                    f"(template {len(declared)} entries, config {len(configured)})"
                )

    tasks = config.get("training_tasks", _MISSING)
    if tasks is _MISSING or tasks is None:
        gaps.append("training_tasks is not determined")
        tasks = None
    else:
        problems = _training_tasks_problems(tasks)
        gaps.extend(problems)

    # A hypothesis scope may only name one of the two explicit training tasks.
    if isinstance(hypotheses, list) and isinstance(tasks, list):
        task_ids = {
            item["task_id"]
            for item in tasks
            if isinstance(item, dict)
            and isinstance(item.get("task_id"), str)
            and item["task_id"]
        }
        if len(task_ids) == 2 and not _training_tasks_problems(tasks):
            for index, item in enumerate(hypotheses):
                if not isinstance(item, dict):
                    continue
                scope = item.get("scope")
                if not isinstance(scope, dict):
                    continue
                scope_ids = scope.get("task_ids")
                if not isinstance(scope_ids, list):
                    continue
                unknown = sorted(
                    {
                        entry
                        for entry in scope_ids
                        if isinstance(entry, str) and entry not in task_ids
                    }
                )
                if unknown:
                    gaps.append(
                        "initial_hypotheses[%d].scope.task_ids references tasks "
                        "not in training_tasks: %s" % (index, unknown)
                    )


def _check_stage_section(
    config: Mapping[str, Any],
    stage: str,
    parameters: Mapping[str, str],
    gaps: list[str],
) -> Mapping[str, Any] | None:
    section = config.get(stage, _MISSING)
    if section is _MISSING or section is None:
        for key, description in parameters.items():
            gaps.append(f"{stage}.{key} is not determined ({description})")
        return None
    if not isinstance(section, Mapping):
        gaps.append(f"{stage} settings must be an object")
        return None
    for key, description in parameters.items():
        value = section.get(key, _MISSING)
        if value is _MISSING or value is None:
            gaps.append(f"{stage}.{key} is not determined ({description})")
    return section


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _check_int(
    section: Mapping[str, Any],
    field: str,
    where: str,
    gaps: list[str],
    *,
    minimum: int,
) -> None:
    value = section.get(field, _MISSING)
    if value is _MISSING or value is None:
        return
    if not _is_int(value) or value < minimum:
        gaps.append(f"{where}.{field} must be an integer >= {minimum}")


def _check_number(
    section: Mapping[str, Any],
    field: str,
    where: str,
    gaps: list[str],
    *,
    positive: bool = False,
) -> None:
    value = section.get(field, _MISSING)
    if value is _MISSING or value is None:
        return
    if not _is_number(value) or (positive and value <= 0):
        qualifier = "a positive number" if positive else "a finite number"
        gaps.append(f"{where}.{field} must be {qualifier}")


def _check_text(
    section: Mapping[str, Any], field: str, where: str, gaps: list[str]
) -> None:
    value = section.get(field, _MISSING)
    if value is _MISSING or value is None:
        return
    if not isinstance(value, str) or not value:
        gaps.append(f"{where}.{field} must be a non-empty string")


def _resolved_path(
    config: Mapping[str, Any], value: Any, where: str, gaps: list[str]
) -> Path | None:
    if not isinstance(value, str) or not value:
        gaps.append(f"{where} must be a non-null path string")
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        root = config.get("project_root", _MISSING)
        if not isinstance(root, str) or not root:
            gaps.append(f"project_root is not recorded; cannot resolve {where}")
            return None
        candidate = Path(root) / candidate
    return candidate


def _check_existing_path(
    config: Mapping[str, Any],
    section: Mapping[str, Any],
    where: str,
    field: str,
    gaps: list[str],
    *,
    directory: bool,
) -> None:
    value = section.get(field, _MISSING)
    if value is _MISSING or value is None:
        return
    candidate = _resolved_path(config, value, f"{where}.{field}", gaps)
    if candidate is None:
        return
    kind = "directory" if directory else "file"
    exists = candidate.is_dir() if directory else candidate.is_file()
    if not exists:
        gaps.append(f"{where}.{field} does not exist as a {kind}: {candidate}")


def _training_task_ids(config: Mapping[str, Any]) -> tuple[str, ...] | None:
    tasks = config.get("training_tasks")
    if not isinstance(tasks, list):
        return None
    ids = [
        item.get("task_id")
        for item in tasks
        if isinstance(item, dict) and isinstance(item.get("task_id"), str)
    ]
    if len(ids) != 2 or len(set(ids)) != 2:
        return None
    return tuple(ids)


def _check_task_ids(
    config: Mapping[str, Any],
    section: Mapping[str, Any],
    where: str,
    gaps: list[str],
) -> None:
    value = section.get("task_ids", _MISSING)
    if value is _MISSING or value is None:
        return
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != 2
    ):
        gaps.append(f"{where}.task_ids must contain exactly two distinct task IDs")
        return
    expected = _training_task_ids(config)
    if expected is not None and tuple(value) != expected:
        gaps.append(
            f"{where}.task_ids must equal training_tasks task IDs {list(expected)}"
        )


def _check_generation(
    section: Mapping[str, Any], where: str, gaps: list[str]
) -> None:
    for key, description in _GENERATION_FIELDS.items():
        value = section.get(key, _MISSING)
        if value is _MISSING or value is None:
            gaps.append(f"{where}.{key} is not determined ({description})")
    source = section.get("source")
    if source is not None and source not in ("mock", "dmx"):
        gaps.append(f"{where}.source must be one of ['mock', 'dmx']")
    _check_text(section, "model", where, gaps)
    _check_text(section, "batch_id", where, gaps)
    _check_number(section, "temperature", where, gaps)
    _check_int(section, "max_tokens", where, gaps, minimum=1)
    _check_number(section, "request_timeout", where, gaps, positive=True)
    _check_int(section, "max_concurrency", where, gaps, minimum=1)
    _check_int(section, "max_request_attempts", where, gaps, minimum=1)
    _check_int(section, "max_sample_retries", where, gaps, minimum=0)
    if section.get('max_sample_retries') not in (None, 0):
        gaps.append(f'{where}.max_sample_retries must be 0: the public generator implements request retries only')


def _check_evaluators(
    config: Mapping[str, Any],
    section: Mapping[str, Any],
    where: str,
    gaps: list[str],
) -> None:
    tools_value = section.get("sast_tools", _MISSING)
    tools: list[str] = []
    if tools_value is _MISSING or tools_value is None:
        gaps.append(f"{where}.sast_tools is not determined (explicit SAST tools)")
    elif not isinstance(tools_value, (list, tuple)) or not tools_value:
        gaps.append(f"{where}.sast_tools must be a non-empty array")
    elif any(not isinstance(tool, str) for tool in tools_value):
        gaps.append(f"{where}.sast_tools must be an array of strings")
    else:
        tools = list(tools_value)
        if len(set(tools)) != len(tools):
            gaps.append(f"{where}.sast_tools must be unique")
        unknown = sorted(set(tools) - {"bandit", "semgrep", "codeql"})
        if unknown:
            gaps.append(f"{where}.sast_tools has unknown tools: {unknown}")

    for key in ("sast_tools", "semgrep_config", "codeql_executable", "codeql_search_path"):
        if key not in section:
            gaps.append(f"{where}.{key} must be explicitly provided")

    semgrep = section.get("semgrep_config", _MISSING)
    if "semgrep" in tools and (semgrep is _MISSING or semgrep is None):
        gaps.append(f"{where}.semgrep_config is not determined (semgrep is enabled)")
    elif semgrep is not _MISSING and semgrep is not None:
        _check_existing_path(
            config, section, where, "semgrep_config", gaps, directory=True
        )

    codeql = "codeql" in tools
    for field in ("codeql_executable", "codeql_search_path"):
        value = section.get(field, _MISSING)
        if codeql and (value is _MISSING or value is None):
            gaps.append(f"{where}.{field} is not determined (codeql is enabled)")
        elif value is not _MISSING and value is not None:
            _check_existing_path(
                config,
                section,
                where,
                field,
                gaps,
                directory=field == "codeql_search_path",
            )

    layers = section.get("enabled_layers", _MISSING)
    if layers is not _MISSING and layers is not None:
        if not isinstance(layers, (list, tuple)) or list(layers) != ["sast"]:
            gaps.append(f"{where}.enabled_layers may only be ['sast']")


def _check_functional(
    section: Mapping[str, Any], where: str, gaps: list[str]
) -> None:
    for key, description in _FUNCTIONAL_FIELDS.items():
        value = section.get(key, _MISSING)
        if value is _MISSING or value is None:
            gaps.append(f"{where}.{key} is not determined ({description})")
    k_value = section.get("k")
    if k_value is not None:
        if (
            not isinstance(k_value, (list, tuple))
            or not k_value
            or any(not _is_int(item) or item < 1 for item in k_value)
        ):
            gaps.append(f"{where}.k must be a non-empty array of positive integers")
    _check_text(section, "harness_version", where, gaps)
    _check_number(
        section, "candidate_timeout_seconds", where, gaps, positive=True
    )


def _check_measurement_settings(
    config: Mapping[str, Any], name: str, gaps: list[str]
) -> None:
    section = _check_stage_section(config, name, _MEASUREMENT_PARAMETERS, gaps)
    if section is None:
        return

    _check_task_ids(config, section, name, gaps)
    _check_int(section, "repeats", name, gaps, minimum=1)
    stage = section.get("stage")
    if stage is not None and stage not in ("search", "holdout"):
        gaps.append(f"{name}.stage must be 'search' or 'holdout'")
    victim_messages = section.get("victim_messages")
    if victim_messages is not None and victim_messages != "single_user":
        gaps.append(f"{name}.victim_messages must be 'single_user'")
    for field in ("assets_root", "data_dir"):
        _check_existing_path(
            config, section, name, field, gaps, directory=True
        )
    _check_existing_path(
        config, section, name, "execution_config_path", gaps, directory=False
    )
    _check_existing_path(
        config, section, name, "repo_dir", gaps, directory=True
    )
    cache_dir = section.get("cache_dir", _MISSING)
    if cache_dir is not _MISSING and cache_dir is not None:
        _resolved_path(config, cache_dir, f"{name}.cache_dir", gaps)

    generation = section.get("generation")
    if isinstance(generation, Mapping):
        _check_generation(generation, f"{name}.generation", gaps)
    elif generation is not None:
        gaps.append(f"{name}.generation must be an object")

    evaluators = section.get("evaluators")
    if isinstance(evaluators, Mapping):
        _check_evaluators(config, evaluators, f"{name}.evaluators", gaps)
    elif evaluators is not None:
        gaps.append(f"{name}.evaluators must be an object")

    functional = section.get("functional")
    if isinstance(functional, Mapping):
        _check_functional(functional, f"{name}.functional", gaps)
    elif functional is not None:
        gaps.append(f"{name}.functional must be an object")


def _check_example_check(config: Mapping[str, Any], gaps: list[str]) -> None:
    section = _check_stage_section(
        config, "example_check", _EXAMPLE_CHECK_PARAMETERS, gaps
    )
    if section is None:
        return
    _check_existing_path(
        config, section, "example_check", "assets_root", gaps, directory=True
    )
    _check_existing_path(
        config,
        section,
        "example_check",
        "execution_config_path",
        gaps,
        directory=False,
    )
    _check_existing_path(
        config, section, "example_check", "semgrep_config", gaps, directory=True
    )
    mode = section.get("code_input_mode")
    if mode is not None and mode not in ("example_body", "final_code"):
        gaps.append(
            "example_check.code_input_mode must be 'example_body' or 'final_code'"
        )
    stage = section.get("stage")
    if stage is not None and stage not in ("search", "holdout"):
        gaps.append("example_check.stage must be 'search' or 'holdout'")
    _check_number(
        section, "semgrep_timeout_seconds", "example_check", gaps, positive=True
    )
    _check_number(
        section, "candidate_timeout_seconds", "example_check", gaps, positive=True
    )


def _check_admission(config: Mapping[str, Any], gaps: list[str]) -> None:
    admission = config.get("admission", _MISSING)
    if admission is _MISSING or admission is None:
        gaps.append(
            "admission is not determined (oracle_states and semantic_mode)"
        )
        return
    if not isinstance(admission, Mapping):
        gaps.append("admission must be an object")
        return
    states = admission.get("oracle_states")
    if states != ["present", "possibly_present"]:
        gaps.append(
            "admission.oracle_states must be exactly "
            "['present', 'possibly_present']"
        )
    mode = admission.get("semantic_mode")
    if mode != "prompt_only":
        gaps.append("admission.semantic_mode must be 'prompt_only'")


def _check_measurement(config: Mapping[str, Any], gaps: list[str]) -> None:
    _check_file(config, "clean_snapshot_path", gaps)
    _check_measurement_settings(config, "measurement", gaps)
    _check_example_check(config, gaps)
    _check_admission(config, gaps)


def _check_search(config: Mapping[str, Any], gaps: list[str]) -> None:
    _check_measurement_settings(config, "reference_measurement", gaps)
    section = _check_stage_section(config, "search", _SEARCH_PARAMETERS, gaps)
    if section is None:
        return
    _check_int(section, "rounds", "search", gaps, minimum=1)
    _check_int(section, "guided_count", "search", gaps, minimum=0)
    _check_int(section, "unguided_count", "search", gaps, minimum=0)
    _check_int(section, "probe_groups_per_round", "search", gaps, minimum=0)
    for field, expected in (
        ("guidance_policy", "all_active"),
        ("probe_policy", "in_order_complete_groups"),
        ("duplicate_policy", "independent_sampling"),
    ):
        value = section.get(field)
        if value is not None and value != expected:
            gaps.append(f"search.{field} must be {expected!r}")


def _check_rule_mapping(
    value: Any,
    where: str,
    parameters: Mapping[str, str],
    gaps: list[str],
) -> bool:
    if not isinstance(value, Mapping):
        gaps.append(f"{where} must be an object")
        return False
    decided = True
    for key, description in parameters.items():
        item = value.get(key, _MISSING)
        if item is _MISSING or item is None:
            gaps.append(f"{where}.{key} is not determined ({description})")
            decided = False
    return decided


def _check_selection(config: Mapping[str, Any], gaps: list[str]) -> None:
    _check_measurement_settings(config, "retest_measurement", gaps)
    section = config.get("selection", _MISSING)
    if section is _MISSING or section is None:
        for key, description in _SELECTION_PARAMETERS.items():
            gaps.append(f"selection.{key} is not determined ({description})")
        return
    if not isinstance(section, Mapping):
        gaps.append("selection must be an object")
        return

    before = len(gaps)
    for key, description in _SELECTION_PARAMETERS.items():
        value = section.get(key, _MISSING)
        if value is _MISSING or value is None:
            gaps.append(f"selection.{key} is not determined ({description})")

    if _check_rule_mapping(
        section.get("shortlist"), "selection.shortlist", _SHORTLIST_PARAMETERS, gaps
    ):
        shortlist = section["shortlist"]
        mode = shortlist.get("mode")
        if mode == "explicit_ids":
            candidate_ids = shortlist.get("candidate_ids", _MISSING)
            if candidate_ids is _MISSING or candidate_ids is None:
                gaps.append(
                    "selection.shortlist.candidate_ids is not determined "
                    "(mode is explicit_ids)"
                )
            elif not isinstance(candidate_ids, (list, tuple)) or any(
                not isinstance(item, str) or not item for item in candidate_ids
            ):
                gaps.append(
                    "selection.shortlist.candidate_ids must be an array of "
                    "non-empty candidate IDs"
                )

    _check_rule_mapping(
        section.get("functional"),
        "selection.functional",
        _FUNCTIONAL_RULE_PARAMETERS,
        gaps,
    )
    _check_rule_mapping(
        section.get("ranking"), "selection.ranking", _RANKING_PARAMETERS, gaps
    )

    if len(gaps) == before:
        from .template_selection import validate_rules

        try:
            validate_rules(dict(section))
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            gaps.append(f"selection: {error}")


def _check_roles_config(config: Mapping[str, Any], gaps: list[str]) -> None:
    roles = config.get("roles", _MISSING)
    if roles is _MISSING or roles is None:
        gaps.append(
            "run.roles is not determined (candidate/report/aggregate services)"
        )
        return
    if not isinstance(roles, Mapping):
        gaps.append("run.roles must be an object")
        return
    for role in ("candidate", "report", "aggregate"):
        entry = roles.get(role, _MISSING)
        where = f"run.roles.{role}"
        if not isinstance(entry, Mapping):
            gaps.append(f"{where} must be an object")
            continue
        settings = entry.get("config", _MISSING)
        if not isinstance(settings, Mapping):
            gaps.append(f"{where}.config is not determined")
            continue
        for key in ("role", "model", "source"):
            value = settings.get(key, _MISSING)
            if value is _MISSING or value is None:
                gaps.append(f"{where}.config.{key} is not determined")
        unknown = sorted(set(settings) - _ROLE_CONFIG_FIELDS)
        if unknown:
            gaps.append(f"{where}.config has unknown fields: {unknown}")
        role_value = settings.get("role")
        if role_value is not None and role_value != role:
            gaps.append(f"{where}.config.role must be {role!r}")
        _check_text(settings, "model", f"{where}.config", gaps)
        source = settings.get("source")
        if source is not None and source not in ("mock", "dmx"):
            gaps.append(f"{where}.config.source must be one of ['mock', 'dmx']")
        _check_number(settings, "temperature", f"{where}.config", gaps)
        _check_int(settings, "max_tokens", f"{where}.config", gaps, minimum=1)
        _check_number(
            settings, "request_timeout", f"{where}.config", gaps, positive=True
        )
        _check_int(
            settings, "max_request_attempts", f"{where}.config", gaps, minimum=1
        )
        if source == "mock":
            responses = entry.get("responses")
            if (
                not isinstance(responses, list)
                or not responses
                or any(not isinstance(item, str) for item in responses)
            ):
                gaps.append(
                    f"{where}.responses must be a non-empty array of strings "
                    "(mock source)"
                )


def _check_budget(config: Mapping[str, Any], gaps: list[str]) -> None:
    budget = config.get("budget", _MISSING)
    if budget is _MISSING or budget is None:
        gaps.append("run.budget is not determined (explicit request allocations)")
        return
    if not isinstance(budget, Mapping):
        gaps.append("run.budget must be an object")
        return
    unit = budget.get("unit")
    if unit != "victim_request_attempts":
        gaps.append("run.budget.unit must be 'victim_request_attempts'")
    allocations = budget.get("allocations")
    if config.get('execution_mode') == 'search_only' and isinstance(allocations, Mapping) and allocations.get('retest') != 0:
        gaps.append('run.budget.allocations.retest must be 0 when template selection is deferred')
    phases = ("reference", "search", "retest")
    if not isinstance(allocations, Mapping):
        gaps.append("run.budget.allocations is not determined")
    else:
        for phase in phases:
            value = allocations.get(phase, _MISSING)
            if value is _MISSING or value is None:
                gaps.append(f"run.budget.allocations.{phase} is not determined")
            elif not _is_int(value) or value < 0:
                gaps.append(
                    f"run.budget.allocations.{phase} must be a non-negative integer"
                )
        unknown = sorted(set(allocations) - set(phases))
        if unknown:
            gaps.append(f"run.budget.allocations has unknown phases: {unknown}")
    role_attempts = budget.get("role_attempts", _MISSING)
    if role_attempts is _MISSING or role_attempts is None:
        gaps.append("run.budget.role_attempts is not determined")
    elif not _is_int(role_attempts) or role_attempts < 0:
        gaps.append("run.budget.role_attempts must be a non-negative integer")


def _check_concurrency(config: Mapping[str, Any], gaps: list[str]) -> None:
    concurrency = config.get("concurrency", _MISSING)
    if concurrency is _MISSING or concurrency is None:
        gaps.append("run.concurrency is not determined (worker limits)")
        return
    if not isinstance(concurrency, Mapping):
        gaps.append("run.concurrency must be an object")
        return
    workers = concurrency.get("candidate_workers", _MISSING)
    total = concurrency.get("total_victim_requests", _MISSING)
    valid_workers = _is_int(workers) and workers >= 1
    valid_total = _is_int(total) and total >= 1
    if not valid_workers:
        gaps.append("run.concurrency.candidate_workers must be an integer >= 1")
    if not valid_total:
        gaps.append(
            "run.concurrency.total_victim_requests must be an integer >= 1"
        )

    measurement = config.get("measurement")
    generation = (
        measurement.get("generation") if isinstance(measurement, Mapping) else None
    )
    if not isinstance(generation, Mapping):
        gaps.append(
            "run.concurrency cannot be checked without "
            "measurement.generation.max_concurrency"
        )
        return
    batch_workers = generation.get("max_concurrency", _MISSING)
    if not _is_int(batch_workers) or batch_workers < 1:
        gaps.append(
            "measurement.generation.max_concurrency must be an integer >= 1"
        )
        return
    if valid_workers and valid_total and workers * batch_workers > total:
        gaps.append(
            "run.concurrency candidate_workers * "
            "measurement.generation.max_concurrency exceeds "
            "total_victim_requests"
        )


def _check_reference_comparability(
    config: Mapping[str, Any], gaps: list[str]
) -> None:
    value = config.get("reference_comparability", _MISSING)
    if value is _MISSING or value is None:
        gaps.append("run.reference_comparability is not determined")
        return
    if not isinstance(value, Mapping):
        gaps.append("run.reference_comparability must be an object")
        return
    comparable = value.get("comparable", _MISSING)
    if not isinstance(comparable, bool):
        gaps.append(
            "run.reference_comparability.comparable must be explicitly true or false"
        )


def _check_run(config: Mapping[str, Any], gaps: list[str]) -> None:
    for field in ("project_root", "config_path"):
        value = config.get(field, _MISSING)
        if not isinstance(value, str) or not value:
            gaps.append(f"{field} is not recorded")
    _check_roles_config(config, gaps)
    _check_budget(config, gaps)
    _check_concurrency(config, gaps)
    _check_reference_comparability(config, gaps)


def check_config(config: Mapping[str, Any], *, stage: str = "roles") -> list[str]:
    """Return explicit readiness gaps for ``stage``; never samples or calls tools.

    The report is cumulative: later stages include all earlier-stage gaps.  A
    missing value and a ``null`` value are both reported as undetermined.
    Structural problems are reported as gaps instead of being guessed or
    replaced with defaults.
    """

    if not isinstance(config, Mapping):
        raise ConfigError("config must be a mapping")
    mode = config.get('execution_mode', 'search_and_select')
    if mode not in ('search_only', 'search_and_select'):
        raise ConfigError('execution_mode must be search_only or search_and_select')
    if stage not in STAGES:
        raise ConfigError(
            f"unknown stage {stage!r}; expected one of {list(STAGES)}"
        )

    gaps: list[str] = []
    _check_roles(config, gaps)
    if stage in ("measurement", "search", "selection", "run"):
        _check_measurement(config, gaps)
    if stage in ("search", "selection", "run"):
        _check_search(config, gaps)
    if stage == "selection" or (stage == "run" and mode == 'search_and_select'):
        _check_selection(config, gaps)
    if stage == "run":
        _check_run(config, gaps)
    return gaps
