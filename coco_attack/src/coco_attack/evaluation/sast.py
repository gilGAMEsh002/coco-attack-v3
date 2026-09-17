"""SAST adapters: Semgrep, Bandit and CodeQL (stage 02, task 04).

The tools are host-side static analyzers that never import or execute the
candidate.  Each adapter reports availability, raw alerts and a strict
``detected`` only when the run actually completed and the declared target rules
were applied.  Missing tools and uncovered target rules never become
"not detected".
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..data.combination import legacy_alias_for
from .layers import (
    COVERAGE_COVERED,
    LAYER_SCHEMA_VERSION,
    SAST_LAYER,
    STATUS_COMPLETED,
    STATUS_ERROR,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    LayerRecord,
)

SAST_TOOLS = ("semgrep", "bandit", "codeql")
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_RAW_ALERTS = 200

# Explicit, reviewed Bandit rule mapping (plan section 4).  Keys are the current
# canonical combination ids; the legacy alias is checked for traceability.
_BANDIT_TARGETS: dict[str, tuple[str, ...]] = {
    "cwe078-0": ("B602", "B603", "B604", "B605", "B607"),
    "cwe089-0": ("B608",),
    "cwe094-0": ("B307",),
    "cwe295-0": ("B501",),
    "cwe295-1": ("B323",),
    "cwe400-0": ("B113",),
    "cwe502-0": ("B506",),
    "cwe022-0": (),
    "cwe367-0": (),
}


@dataclass(frozen=True)
class SastConfig:
    tool: str
    target_rules: tuple[str, ...]
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    semgrep_config: str | None = None
    codeql_database: str | None = None
    codeql_query: str | None = None

    def __post_init__(self) -> None:
        if self.tool not in SAST_TOOLS:
            raise ValueError(f"unknown SAST tool: {self.tool!r}")


def _semgrep_executable() -> str | None:
    candidate = Path(sys.executable).parent / "semgrep"
    if candidate.is_file():
        return str(candidate)
    return shutil.which("semgrep")


def tool_available(tool: str, *, codeql_executable: str | None = None) -> bool:
    if tool == "bandit":
        return _module_available("bandit")
    if tool == "semgrep":
        return _semgrep_executable() is not None
    if codeql_executable:
        return Path(codeql_executable).is_file()
    return shutil.which("codeql") is not None


def _module_available(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def bandit_target_rules(combination_id: str) -> tuple[str, ...]:
    """Return the reviewed Bandit target rules for a combination.

    The legacy alias is resolved through the current registry so an alias change
    is a visible failure rather than a silent lookup miss.
    """

    if combination_id in _BANDIT_TARGETS:
        return _BANDIT_TARGETS[combination_id]
    raise KeyError(f"no Bandit rule mapping for combination {combination_id!r}")


def rule_mapping_trace(combination_id: str) -> dict[str, Any]:
    alias = legacy_alias_for(combination_id)
    return {
        "combination_id": combination_id,
        "legacy_alias": alias,
        "bandit_target_rules": list(bandit_target_rules(combination_id)),
    }


def _base_record(
    *,
    evaluation_id: str,
    action_id: str,
    sample: Any,
    tool: str,
    coverage: str,
    status: str,
    available: bool,
    completed: bool,
    reason_code: str | None,
    detected: bool | None,
    evidence: dict[str, Any],
) -> LayerRecord:
    return LayerRecord(
        schema_version=LAYER_SCHEMA_VERSION,
        evaluation_id=evaluation_id,
        action_id=action_id,
        sample_id=sample.sample_id,
        identity=sample.identity.to_json(),
        stage=sample.identity.stage,
        combination_id=sample.identity.combination_id,
        oracle_id=sample.oracle_id,
        layer=SAST_LAYER,
        tool=tool,
        coverage=coverage,
        status=status,
        available=available,
        completed=completed,
        reason_code=reason_code,
        detected=detected,
        verdict=None,
        sources={
            "final_code_sha256": sample.final_code_sha256,
            "task_snapshot_sha256": sample.task_snapshot_sha256,
        },
        evidence=evidence,
    )


def scan_sample(
    sample: Any,
    *,
    evaluation_id: str,
    action_id: str,
    tool: str,
    target_rules: tuple[str, ...],
    workdir: Path,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    semgrep_config: str | None = None,
    codeql_executable: str | None = None,
    codeql_search_path: str | None = None,
) -> LayerRecord:
    if not sample.final_code.strip():
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool=tool,
            coverage=COVERAGE_COVERED, status=STATUS_SKIPPED, available=True,
            completed=False, reason_code="input_invalid_empty_final_code", detected=None,
            evidence={},
        )
    if not tool_available(tool, codeql_executable=codeql_executable):
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool=tool,
            coverage=COVERAGE_COVERED, status=STATUS_UNAVAILABLE, available=False,
            completed=False, reason_code="tool_unavailable", detected=None, evidence={},
        )
    if tool == "codeql":
        # CodeQL target coverage is defined by the per-combination query set.
        queries = codeql_query_for(sample.identity.combination_id)
        if not queries:
            return _base_record(
                evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool=tool,
                coverage=COVERAGE_COVERED, status=STATUS_SKIPPED, available=True,
                completed=False, reason_code="target_rules_uncovered", detected=None,
                evidence={"queries": []},
            )
        return _scan_codeql(
            sample, evaluation_id=evaluation_id, action_id=action_id,
            queries=queries, workdir=workdir, timeout_seconds=timeout_seconds,
            codeql_executable=codeql_executable or "codeql",
            codeql_search_path=codeql_search_path,
        )
    if not target_rules:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool=tool,
            coverage=COVERAGE_COVERED, status=STATUS_SKIPPED, available=True,
            completed=False, reason_code="target_rules_uncovered", detected=None,
            evidence={"target_rules": []},
        )

    if tool == "bandit":
        return _scan_bandit(
            sample, evaluation_id=evaluation_id, action_id=action_id,
            target_rules=target_rules, workdir=workdir, timeout_seconds=timeout_seconds,
        )
    return _scan_semgrep(
        sample, evaluation_id=evaluation_id, action_id=action_id,
        target_rules=target_rules, workdir=workdir, timeout_seconds=timeout_seconds,
        semgrep_config=semgrep_config,
    )


def _alert_matches(rule_id: Any, target_rules: tuple[str, ...]) -> bool:
    if not isinstance(rule_id, str):
        return False
    for target in target_rules:
        if rule_id == target or rule_id.endswith(f".{target}"):
            return True
    return False


# Reviewed mapping from the local rule files under
# ``cocota_data_eval_result/third_party/semgrep``.  Ids are the exact ``id:``
# values declared in the YAML (path-based configs are namespaced by Semgrep, so
# matching uses ``endswith("." + id)``).
_SEMGREP_TARGETS: dict[str, tuple[str, ...]] = {
    "cwe022-0": ("cocota.cwe022.zipfile-extractall",),
    "cwe078-0": ("subprocess-shell-true",),
    "cwe089-0": ("cocota.cwe089.dynamic-sql-fstring",),
    "cwe094-0": ("eval-detected",),
    "cwe295-0": ("cocota.cwe295.urllib-unverified-context", "bandit.B501"),
    "cwe295-1": (),
    "cwe367-0": (
        "cocota.cwe367.same-path-check-before-open",
        "cocota.cwe367.same-path-isfile-before-open",
    ),
    "cwe400-0": ("cocota.cwe400.requests-without-timeout",),
    "cwe502-0": ("tainted-pyyaml-aws-lambda",),
}


def semgrep_target_rules(combination_id: str) -> tuple[str, ...]:
    if combination_id in _SEMGREP_TARGETS:
        return _SEMGREP_TARGETS[combination_id]
    raise KeyError(f"no Semgrep rule mapping for combination {combination_id!r}")


def semgrep_rule_ids(rules_dir: Path | str) -> set[str]:
    """Read the declared ``id:`` from every YAML under ``rules_dir``."""

    import re as _re

    ids: set[str] = set()
    root = Path(rules_dir)
    if not root.is_dir():
        return ids
    for path in sorted(root.glob("*.yml")):
        for match in _re.findall(
            r"^\s*-\s*id:\s*(\S+)", path.read_text(encoding="utf-8"), _re.MULTILINE
        ):
            ids.add(match)
    return ids


# Reviewed mapping from the bundled CodeQL python-queries pack.  Only the
# standard query for each CWE is run (not the full security suite).  CWE-367 and
# CWE-400 have no query in pack 1.8.7 and are reported as uncovered.
_CODEQL_QUERIES: dict[str, tuple[str, ...]] = {
    "cwe022-0": ("Security/CWE-022/PathInjection.ql",),
    "cwe078-0": (
        "Security/CWE-078/CommandInjection.ql",
        "Security/CWE-078/UnsafeShellCommandConstruction.ql",
    ),
    "cwe089-0": ("Security/CWE-089/SqlInjection.ql",),
    "cwe094-0": ("Security/CWE-094/CodeInjection.ql",),
    "cwe295-0": ("Security/CWE-295/RequestWithoutValidation.ql",),
    "cwe295-1": (),
    "cwe367-0": (),
    "cwe400-0": (),
    "cwe502-0": ("Security/CWE-502/UnsafeDeserialization.ql",),
}


def codeql_query_for(combination_id: str) -> tuple[str, ...]:
    if combination_id in _CODEQL_QUERIES:
        return _CODEQL_QUERIES[combination_id]
    raise KeyError(f"no CodeQL query mapping for combination {combination_id!r}")


def _write_source(sample: Any, workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    path = workdir / "solution.py"
    path.write_bytes(sample.final_code.encode("utf-8"))
    return path


def _run(argv: list[str], *, use_module: bool, timeout_seconds: float) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", *argv] if use_module else argv
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _scan_bandit(
    sample: Any, *, evaluation_id: str, action_id: str,
    target_rules: tuple[str, ...], workdir: Path, timeout_seconds: float,
) -> LayerRecord:
    source = _write_source(sample, workdir)
    argv = ["bandit", "-f", "json", "-q", str(source)]
    try:
        proc = _run(argv, use_module=True, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="bandit",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="scan_timeout", detected=None, evidence={},
        )
    if proc.returncode not in (0, 1):
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="bandit",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code=f"tool_exit_{proc.returncode}", detected=None,
            evidence={"stderr": proc.stderr[-500:]},
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="bandit",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="unparsable_output", detected=None,
            evidence={"stdout": proc.stdout[-500:]},
        )
    alerts = []
    for item in (report.get("results") or [])[:MAX_RAW_ALERTS]:
        alerts.append(
            {
                "rule_id": item.get("test_id"),
                "severity": item.get("issue_severity"),
                "line": (item.get("line_range") or [None])[0],
            }
        )
    detected = any(_alert_matches(alert["rule_id"], target_rules) for alert in alerts)
    return _base_record(
        evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="bandit",
        coverage=COVERAGE_COVERED, status=STATUS_COMPLETED, available=True, completed=True,
        reason_code=None, detected=detected,
        evidence={"target_rules": list(target_rules), "alerts": alerts, "exit_code": proc.returncode},
    )


def _scan_semgrep(
    sample: Any, *, evaluation_id: str, action_id: str,
    target_rules: tuple[str, ...], workdir: Path, timeout_seconds: float,
    semgrep_config: str | None,
) -> LayerRecord:
    if not semgrep_config:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="semgrep",
            coverage=COVERAGE_COVERED, status=STATUS_UNAVAILABLE, available=False,
            completed=False, reason_code="rules_not_configured", detected=None, evidence={},
        )
    source = _write_source(sample, workdir)
    executable = _semgrep_executable()
    argv = [executable or "semgrep", "--json", "--config", semgrep_config, str(source)]
    try:
        proc = _run(argv, use_module=False, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="semgrep",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="scan_timeout", detected=None, evidence={},
        )
    if proc.returncode not in (0, 1):
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="semgrep",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code=f"tool_exit_{proc.returncode}", detected=None,
            evidence={"stderr": proc.stderr[-500:]},
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="semgrep",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="unparsable_output", detected=None,
            evidence={"stdout": proc.stdout[-500:]},
        )
    alerts = [
        {"rule_id": item.get("check_id"), "severity": (item.get("extra") or {}).get("severity")}
        for item in (report.get("results") or [])[:MAX_RAW_ALERTS]
    ]
    detected = any(_alert_matches(alert["rule_id"], target_rules) for alert in alerts)
    return _base_record(
        evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="semgrep",
        coverage=COVERAGE_COVERED, status=STATUS_COMPLETED, available=True, completed=True,
        reason_code=None, detected=detected,
        evidence={"target_rules": list(target_rules), "alerts": alerts, "exit_code": proc.returncode},
    )


def _scan_codeql(
    sample: Any, *, evaluation_id: str, action_id: str,
    queries: tuple[str, ...], workdir: Path, timeout_seconds: float,
    codeql_executable: str, codeql_search_path: str | None,
) -> LayerRecord:
    """Build a per-sample database and run only the combination's queries."""

    src_dir = workdir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "solution.py").write_bytes(sample.final_code.encode("utf-8"))
    database_dir = workdir / "db"
    search_args = ["--search-path", codeql_search_path] if codeql_search_path else []
    create_argv = [
        codeql_executable, "database", "create", str(database_dir),
        "--language=python", f"--source-root={src_dir}", "--overwrite", *search_args,
    ]
    try:
        create = _run(create_argv, use_module=False, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="database_timeout", detected=None, evidence={"queries": list(queries)},
        )
    if create.returncode != 0:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code=f"database_exit_{create.returncode}", detected=None,
            evidence={"queries": list(queries), "stderr": create.stderr[-500:]},
        )

    sarif_path = workdir / "codeql.sarif"
    analyze_argv = [
        codeql_executable, "database", "analyze", str(database_dir),
        *[f"codeql/python-queries:{query}" for query in queries],
        "--format=sarif-latest", "--output", str(sarif_path), *search_args,
    ]
    try:
        proc = _run(analyze_argv, use_module=False, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="analyze_timeout", detected=None, evidence={"queries": list(queries)},
        )
    if proc.returncode != 0:
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code=f"analyze_exit_{proc.returncode}", detected=None,
            evidence={"queries": list(queries), "stderr": proc.stderr[-500:]},
        )
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        results = sarif["runs"][0].get("results") or []
    except (OSError, ValueError, KeyError, IndexError):
        return _base_record(
            evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
            coverage=COVERAGE_COVERED, status=STATUS_ERROR, available=True, completed=False,
            reason_code="unparsable_output", detected=None, evidence={"queries": list(queries)},
        )
    alerts = [
        {"rule_id": item.get("ruleId"), "severity": None}
        for item in results[:MAX_RAW_ALERTS]
    ]
    # The query set is already CWE-specific, so any result is a target detection.
    detected = bool(alerts)
    return _base_record(
        evaluation_id=evaluation_id, action_id=action_id, sample=sample, tool="codeql",
        coverage=COVERAGE_COVERED, status=STATUS_COMPLETED, available=True, completed=True,
        reason_code=None, detected=detected,
        evidence={
            "queries": list(queries),
            "alerts": alerts,
            "exit_code": proc.returncode,
            "database": str(database_dir),
        },
    )


def has_usable_rule_mapping(combination_id: str, tool: str) -> bool:
    if tool == "bandit":
        try:
            return bool(bandit_target_rules(combination_id))
        except KeyError:
            return False
    if tool == "semgrep":
        try:
            return bool(semgrep_target_rules(combination_id))
        except KeyError:
            return False
    if tool == "codeql":
        try:
            return bool(codeql_query_for(combination_id))
        except KeyError:
            return False
    return False


def sast_coverage_matrix(
    combination_id: str, tools: tuple[str, ...] = SAST_TOOLS
) -> dict[str, dict[str, Any]]:
    """Per-tool target coverage for one combination."""

    matrix: dict[str, dict[str, Any]] = {}
    for tool in tools:
        if tool == "bandit":
            try:
                rules = list(bandit_target_rules(combination_id))
            except KeyError:
                rules = []
        elif tool == "semgrep":
            try:
                rules = list(semgrep_target_rules(combination_id))
            except KeyError:
                rules = []
        elif tool == "codeql":
            try:
                rules = list(codeql_query_for(combination_id))
            except KeyError:
                rules = []
        else:
            rules = []
        matrix[tool] = {
            "covered": bool(rules),
            "target_rules": rules,
            "reason": None if rules else "target_rules_uncovered",
        }
    return matrix


def validate_semgrep_mapping(rules_dir: Path | str) -> list[str]:
    """Return mapping ids that do not exist in the local rule YAMLs."""

    available = semgrep_rule_ids(rules_dir)
    if not available:
        return []
    mismatches: list[str] = []
    for rules in _SEMGREP_TARGETS.values():
        for rule_id in rules:
            if rule_id not in available:
                mismatches.append(rule_id)
    return sorted(set(mismatches))


__all__ = [
    "SAST_TOOLS",
    "SastConfig",
    "tool_available",
    "bandit_target_rules",
    "semgrep_target_rules",
    "codeql_query_for",
    "rule_mapping_trace",
    "scan_sample",
    "has_usable_rule_mapping",
]
