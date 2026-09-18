"""Baseline index (``baseline-index-v1``) build/validate/query (phase 03, task 03).

The index is the single machine-readable registry of the completed clean-baseline
runs.  It is built only from existing artifacts: the run manifest, each run's
joined records/metrics/costs (``evaluation/reporting.py``), the evaluator and
functional manifests, the per-run pipeline config and the prepared inputs.  It
never calls a model, a SAST tool or a container and never re-runs an evaluator.

Whole-set entries mirror the report exactly.  For combinations that have a
method-stage split in ``configs/splits.json`` (currently only ``cwe078-0``) two
derived ``search``/``holdout`` views are sliced out of the *same* run's records
with :func:`coco_attack.data.split.build_split`; their metrics are recomputed
over the subset with the pure functions in ``evaluation/metrics.py`` rather than
copied from the whole-set numbers.

Undefined stays undefined: a metric with no value carries its reason, and a unit
whose required report artifacts are missing or hash-mismatched produces no entry
but a gap record.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json, sha256_file, write_json_atomic
from ..assets.paths import default_config_dir
from ..data.snapshot import load_prepared_data
from ..data.split import build_split
from ..evaluation.contracts import MetricResult
from ..evaluation.metrics import (
    asr_at_k,
    evasion,
    llm_judge_rate,
    pass_at_k,
    sample_hit_rate,
    sampling_gate,
)
from ..evaluation.reporting import collect_costs, collect_metrics, collect_records
from ..protocol.stages import SplitMode

INDEX_SCHEMA_VERSION = "baseline-index-v1"
INDEX_DIRNAME = "index"
INDEX_FILENAME = "baseline_index.json"
SPLIT_MODES = ("whole-set", "search", "holdout")

#: Required files inside ``<run_dir>/report`` before an entry may be emitted.
REQUIRED_REPORT_ARTIFACTS = ("records.jsonl", "metrics.json", "cost_summary.json", "manifest.json")

#: Metric names carried in every entry's ``metrics`` brief.
BRIEF_METRIC_NAMES = (
    "asr@1",
    "asr@3",
    "asr@5",
    "pass@1",
    "pass@3",
    "pass@5",
    "sample_hit_rate",
    "bandit_evasion",
    "semgrep_evasion",
    "codeql_evasion",
    "llm_judge_rate",
)
_SAST_EVASION_METRICS = ("bandit_evasion", "semgrep_evasion", "codeql_evasion")
_JUDGE_METRIC = "llm_judge_rate"

_REQUIRED_ENTRY_FIELDS = (
    "entry_id",
    "run_id",
    "unit_id",
    "combination_id",
    "oracle_id",
    "form",
    "model",
    "temperature",
    "repeats",
    "k",
    "enabled_layers",
    "sast_tools",
    "prompt_version",
    "materialize_version",
    "data_contract",
    "cleaner_version",
    "static_shell_version",
    "harness_version",
    "image_digest",
    "judge_prompt_version",
    "judge_detection_version",
    "split_mode",
    "task_set",
    "split_manifest_sha256",
    "task_snapshot_sha256",
    "run_dir",
    "config_path",
    "status",
    "report_artifacts",
    "metrics",
    "registered_at",
)


class BaselineIndexError(ValueError):
    """A baseline-index schema, consistency or construction problem."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json_optional(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = read_json(path)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _sha256_or_none(path: Path) -> str | None:
    if not path.is_file():
        return None
    return sha256_file(path)


# --------------------------------------------------------------------------- #
# Record adapters for evaluation/metrics.py
# --------------------------------------------------------------------------- #


def _flat(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Flatten records for asr/pass/sample-rate and SAST/judge accessors.

    The returned dict carries the fields ``metrics.py`` reads (``task_id``,
    ``repeat_id``, ``asr_hit``) *and* the reduced ``layers`` view so the SAST and
    judge accessors can resolve per-sample layer results.
    """

    flat: list[dict[str, Any]] = []
    for record in records:
        static = record.get("static") or {}
        flat.append(
            {
                "sample_id": record.get("sample_id"),
                "task_id": record.get("task_id"),
                "repeat_id": record.get("repeat_id"),
                "asr_hit": static.get("asr_hit"),
                "layers": record.get("layers") or {},
            }
        )
    return flat


def _pass_counts(records_subset: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    """``{task_id: {"n": sample_count, "c": passed_count}}`` for the subset.

    Samples whose functional layer is missing are skipped before the pass@k
    estimator is fed (the caller separately rejects the metric when functional
    results are incomplete).
    """

    counts: dict[str, dict[str, int]] = {}
    for record in records_subset:
        task_id = record.get("task_id")
        if task_id is None:
            continue
        functional = record.get("functional")
        if functional is None:
            continue
        entry = counts.setdefault(str(task_id), {"n": 0, "c": 0})
        entry["n"] += 1
        if functional.get("passed") is True:
            entry["c"] += 1
    return counts


def _functional_incompleteness(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, list[str]]:
    """Missing vs unresolved (``passed is None``) functional samples.

    Missing results and unresolved (incomplete/error) results are kept distinct
    from a genuine environment failure; neither is treated as a failed test and
    neither is turned into a pass@k value.
    """

    gaps: list[str] = []
    unresolved: list[str] = []
    for record in records:
        functional = record.get("functional")
        sample_id = str(record.get("sample_id"))
        if functional is None:
            gaps.append(sample_id)
        elif functional.get("passed") is None:
            unresolved.append(sample_id)
    return {"gaps": gaps, "unresolved": unresolved}


def _sast_layer_view(layer: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Restore the ``available``/``completed`` shape expected by ``evasion``.

    ``collect_records`` intentionally keeps a reduced SAST view.  The layer
    contract guarantees ``completed`` only for ``status == "completed"`` and
    ``available=False`` only for ``status == "unavailable"``, so both are
    reconstructed here without changing any verdict.
    """

    if not isinstance(layer, Mapping):
        return None
    status = layer.get("status")
    return {
        "available": status != "unavailable",
        "completed": status == "completed",
        "detected": layer.get("detected"),
        "status": status,
        "reason_code": layer.get("reason_code"),
    }


def _judge_layer_view(layer: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Judge view: a null detection is an unavailable/未完成 judge sample."""

    if not isinstance(layer, Mapping):
        return None
    detected = layer.get("detected")
    return {
        "available": detected is not None,
        "detected": bool(detected),
        "status": layer.get("status"),
    }


def _sast_accessor(tool: str):
    def accessor(record: Mapping[str, Any]) -> dict[str, Any] | None:
        layers = record.get("layers") or {}
        sast = layers.get("sast") or {}
        return _sast_layer_view(sast.get(tool))

    return accessor


def _judge_accessor(record: Mapping[str, Any]) -> dict[str, Any] | None:
    layers = record.get("layers") or {}
    return _judge_layer_view(layers.get("judge"))


def _sast_tool_states(
    records: Sequence[Mapping[str, Any]],
    sast_tools: Sequence[str],
    enabled_layers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Distinguish covered / not_covered / environment_unavailable / configured_disabled.

    These states are never conflated: an uncovered rule set is not "not
    detected", and a disabled layer is not "not covered".
    """

    states: dict[str, dict[str, Any]] = {}
    for tool in sast_tools:
        if "sast" not in tuple(enabled_layers or ()):
            states[tool] = {"state": "configured_disabled", "reason": "sast layer not enabled"}
            continue
        present = [
            (record.get("layers") or {}).get("sast", {}).get(tool)
            for record in records
        ]
        present = [layer for layer in present if isinstance(layer, Mapping)]
        if not present:
            states[tool] = {
                "state": "environment_unavailable",
                "reason": f"no sast records for tool {tool}",
            }
            continue
        if all(layer.get("reason_code") == "target_rules_uncovered" for layer in present):
            states[tool] = {"state": "not_covered", "reason": "target_rules_uncovered"}
        elif any(layer.get("status") == "unavailable" for layer in present):
            states[tool] = {"state": "environment_unavailable", "reason": "tool_unavailable"}
        elif any(layer.get("status") == "error" for layer in present):
            states[tool] = {"state": "environment_unavailable", "reason": "scan_error"}
        else:
            states[tool] = {"state": "covered", "reason": None}
    return states


def _non_static_layer_states(
    records: Sequence[Mapping[str, Any]],
    enabled_layers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Dynamic/realism layer availability, keeping disabled distinct from absent."""

    states: dict[str, dict[str, Any]] = {}
    for layer in ("dynamic", "realism"):
        if layer not in tuple(enabled_layers or ()):
            states[layer] = {"state": "configured_disabled", "reason": f"{layer} layer not enabled"}
            continue
        present = [
            (record.get("layers") or {}).get(layer)
            for record in records
        ]
        present = [item for item in present if isinstance(item, Mapping)]
        if not present:
            states[layer] = {"state": "not_covered", "reason": "no records"}
        elif any(item.get("status") == "unavailable" for item in present):
            states[layer] = {"state": "environment_unavailable", "reason": "layer unavailable"}
        else:
            states[layer] = {"state": "covered", "reason": None}
    return states


# --------------------------------------------------------------------------- #
# Metric briefs
# --------------------------------------------------------------------------- #


def _brief(
    entry: Mapping[str, Any] | None,
    *,
    temperature: float,
    repeats: int,
    name: str | None = None,
) -> dict[str, Any]:
    """Null-safe view of one metric entry, preserving undefined reasons.

    No value is invented: an absent metric is ``defined=False`` with an explicit
    reason.  ``basis`` / ``sampled_run`` / ``denominator_definition`` come from
    the metric's ``extra`` block when present.
    """

    if entry is None:
        return {
            "name": name,
            "defined": False,
            "value": None,
            "numerator": None,
            "denominator": None,
            "reason": "metric not present in report",
            "basis": None,
            "sampled_run": bool(sampling_gate(temperature, repeats)[0]),
            "denominator_definition": None,
            "availability": {},
        }
    extra = entry.get("extra") or {}
    sampled_run = extra.get("sampled_run")
    if sampled_run is None:
        sampled_run = sampling_gate(temperature, repeats)[0]
    return {
        "name": entry.get("name", name),
        "defined": bool(entry.get("defined")),
        "value": entry.get("value"),
        "numerator": entry.get("numerator"),
        "denominator": entry.get("denominator"),
        "reason": entry.get("reason"),
        "basis": extra.get("basis"),
        "sampled_run": bool(sampled_run),
        "denominator_definition": extra.get("denominator_definition"),
        "availability": entry.get("availability") or {},
    }


def _select_report_metric(metrics: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    """Pick the authoritative layer for a metric from a report metrics dict.

    ``report/metrics.json`` keeps the static baseline pass@k placeholders in
    ``static``; the executed functional pass@k lives in ``functional`` and the
    SAST/judge evaluators live in ``other``.  Resolution is explicit so a
    placeholder is never mistaken for the real value.
    """

    static = metrics.get("static") or {}
    functional = metrics.get("functional") or {}
    other = metrics.get("other") or {}
    if name.startswith("pass@"):
        return functional.get(name) or static.get(name)
    if name in _SAST_EVASION_METRICS or name == _JUDGE_METRIC:
        return other.get(name) or static.get(name)
    return static.get(name) or functional.get(name) or other.get(name)


def _report_metric_briefs(
    metrics: Mapping[str, Any],
    *,
    temperature: float,
    repeats: int,
) -> dict[str, dict[str, Any]]:
    briefs: dict[str, dict[str, Any]] = {}
    for name in BRIEF_METRIC_NAMES:
        briefs[name] = _brief(
            _select_report_metric(metrics, name),
            temperature=temperature,
            repeats=repeats,
            name=name,
        )
    return briefs


def _recomputed_metric_briefs(
    records: Sequence[Mapping[str, Any]],
    task_ids: Sequence[str],
    *,
    split_mode: str,
    temperature: float,
    repeats: int,
    stage: str,
    enabled_layers: Sequence[str],
    sast_tools: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Recompute the entry brief over a record subset with ``metrics.py``.

    Undefined states are preserved: pass@k is undefined when functional results
    are incomplete/unresolved *or* a task has ``n < k``; an uncovered SAST rule
    set is undefined rather than a fabricated "all evaded"; zero denominators
    come straight from the metric functions.
    """

    flat = _flat(records)
    sampling = {"temperature": temperature, "repeats": repeats, "stage": stage}
    briefs: dict[str, dict[str, Any]] = {}
    for k in (1, 3, 5):
        result = asr_at_k(flat, list(task_ids), k, task_set=split_mode, sampling=sampling)
        briefs[f"asr@{k}"] = _brief(
            result.to_json(), temperature=temperature, repeats=repeats, name=f"asr@{k}"
        )

    counts = _pass_counts(records)
    incompleteness = _functional_incompleteness(records)
    for k in (1, 3, 5):
        if incompleteness["gaps"] or incompleteness["unresolved"]:
            entry = MetricResult.undefined(
                f"pass@{k}",
                (
                    "incomplete_or_unresolved_samples:"
                    f"gaps={len(incompleteness['gaps'])},"
                    f"unresolved={len(incompleteness['unresolved'])}"
                ),
                k=k,
                task_set=split_mode,
                sampling=sampling,
            ).to_json()
        else:
            entry = pass_at_k(
                counts, list(task_ids), k, task_set=split_mode, sampling=sampling
            ).to_json()
        briefs[f"pass@{k}"] = _brief(
            entry, temperature=temperature, repeats=repeats, name=f"pass@{k}"
        )

    briefs["sample_hit_rate"] = _brief(
        sample_hit_rate(flat, task_set=split_mode, sampling=sampling).to_json(),
        temperature=temperature,
        repeats=repeats,
        name="sample_hit_rate",
    )

    tool_states = _sast_tool_states(records, sast_tools, enabled_layers)
    for tool in sast_tools:
        name = f"{tool}_evasion"
        state = (tool_states.get(tool) or {}).get("state")
        if state == "not_covered":
            entry = MetricResult.undefined(
                name,
                "target_rules_uncovered",
                task_set=split_mode,
                sampling=sampling,
                availability={tool: {"available": True}},
            ).to_json()
        elif state == "configured_disabled":
            entry = MetricResult.undefined(
                name,
                f"{tool} is not enabled in this run",
                task_set=split_mode,
                sampling=sampling,
                availability={tool: {"available": False}},
            ).to_json()
        elif state == "environment_unavailable":
            entry = MetricResult.undefined(
                name,
                f"{tool} unavailable: {(tool_states.get(tool) or {}).get('reason')}",
                task_set=split_mode,
                sampling=sampling,
                availability={tool: {"available": False}},
            ).to_json()
        else:
            entry = evasion(
                flat,
                tool_name=tool,
                accessor=_sast_accessor(tool),
                temperature=temperature,
                repeats=repeats,
                task_set=split_mode,
                sampling=sampling,
            ).to_json()
        briefs[name] = _brief(entry, temperature=temperature, repeats=repeats, name=name)

    briefs[_JUDGE_METRIC] = _brief(
        llm_judge_rate(
            flat,
            accessor=_judge_accessor,
            temperature=temperature,
            repeats=repeats,
            task_set=split_mode,
            sampling=sampling,
        ).to_json(),
        temperature=temperature,
        repeats=repeats,
        name=_JUDGE_METRIC,
    )
    return briefs


# --------------------------------------------------------------------------- #
# Artifact verification and cost
# --------------------------------------------------------------------------- #


def _report_artifact_index(report_dir: Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for name in (*REQUIRED_REPORT_ARTIFACTS, "REPORT.md"):
        path = report_dir / name
        if path.is_file():
            artifacts[name] = sha256_file(path)
    return artifacts


def _verify_report_artifacts(run_dir: Path) -> list[str]:
    """Return a list of problems; empty means the report can be trusted."""

    problems: list[str] = []
    report_dir = run_dir / "report"
    for name in REQUIRED_REPORT_ARTIFACTS:
        if not (report_dir / name).is_file():
            problems.append(f"missing report artifact: report/{name}")
    manifest = _read_json_optional(report_dir / "manifest.json")
    if manifest is None:
        return problems
    for name, info in (manifest.get("artifacts") or {}).items():
        path = run_dir / name
        if not isinstance(info, dict) or not info.get("sha256"):
            continue
        if not path.is_file():
            problems.append(f"recorded artifact missing: {name}")
            continue
        if sha256_file(path) != info.get("sha256"):
            problems.append(f"recorded artifact hash mismatch: {name}")
    return problems


def _cost_brief(costs: Mapping[str, Any]) -> dict[str, Any]:
    roles = costs.get("roles") or {}
    known_total = 0.0
    unknown_windows = 0
    requests_by_role: dict[str, Any] = {}
    for role, entry in roles.items():
        if not isinstance(entry, Mapping):
            continue
        requests_by_role[role] = entry.get("events")
        cost = entry.get("cost") or {}
        if isinstance(cost.get("known"), (int, float)) and not isinstance(cost.get("known"), bool):
            known_total += float(cost["known"])
        if isinstance(cost.get("unknown"), int) and not isinstance(cost["unknown"], bool):
            unknown_windows += int(cost["unknown"])
    return {
        "roles": roles,
        "known_total": known_total,
        "unknown_windows": unknown_windows,
        "requests_by_role": requests_by_role,
    }


def _functional_status(
    records: Sequence[Mapping[str, Any]],
    functional_manifest: Mapping[str, Any] | None,
) -> tuple[bool, str | None]:
    incompleteness = _functional_incompleteness(records)
    if incompleteness["gaps"]:
        return False, "missing_functional_results"
    if incompleteness["unresolved"]:
        return False, "functional_unresolved_results"
    if not any(record.get("functional") is not None for record in records):
        return False, "no_functional_results"
    if functional_manifest is not None:
        result_count = functional_manifest.get("result_count")
        if isinstance(result_count, int) and result_count <= 0:
            return False, "no_functional_results"
    return True, None


# --------------------------------------------------------------------------- #
# Index construction
# --------------------------------------------------------------------------- #


def _entry_status(unit_status: Any, report_complete: bool) -> str:
    if unit_status == "blocked":
        return "blocked"
    if not report_complete:
        return "incomplete"
    if unit_status == "complete":
        return "complete"
    return str(unit_status) if unit_status else "incomplete"


def _build_entry(
    *,
    entry_id: str,
    run_id: str,
    unit_id: str,
    combination_id: str,
    oracle_id: str,
    form: str,
    model: str,
    temperature: float,
    repeats: int,
    k: Sequence[int],
    enabled_layers: Sequence[str],
    sast_tools: Sequence[str],
    prompt_version: Any,
    version_fingerprint: Mapping[str, Any],
    judge_prompt_version: Any,
    judge_detection_version: Any,
    split_mode: str,
    task_set: Sequence[str],
    split_manifest_sha256: Any,
    task_snapshot_sha256: Any,
    run_dir: str,
    config_path: str,
    status: str,
    unit_status: Any,
    report_complete: bool,
    report_artifacts: Mapping[str, str],
    metrics_brief: Mapping[str, Any],
    cost: Mapping[str, Any],
    functional_available: bool,
    functional_reason: str | None,
    expected_sample_count: Any,
    actual_sample_count: Any,
    missing_sample_ids: Sequence[str],
    extra_sample_ids: Sequence[str],
    static_verdict_counts: Mapping[str, Any],
    sast_tool_states: Mapping[str, Any],
    layer_states: Mapping[str, Any],
    functional_manifest: Mapping[str, Any] | None,
    registered_at: str,
    derived_from: str | None = None,
    split_membership_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "entry_id": entry_id,
        "run_id": run_id,
        "unit_id": unit_id,
        "combination_id": combination_id,
        "oracle_id": oracle_id,
        "form": form,
        "model": model,
        "temperature": temperature,
        "repeats": repeats,
        "k": list(k),
        "enabled_layers": list(enabled_layers),
        "sast_tools": list(sast_tools),
        "prompt_version": prompt_version,
        "materialize_version": version_fingerprint.get("materialize_version"),
        "data_contract": version_fingerprint.get("data_contract"),
        "cleaner_version": version_fingerprint.get("cleaner_version"),
        "static_shell_version": version_fingerprint.get("static_shell_version"),
        "harness_version": version_fingerprint.get("harness_version"),
        "image_digest": version_fingerprint.get("image_digest"),
        "judge_prompt_version": judge_prompt_version,
        "judge_detection_version": judge_detection_version,
        "split_mode": split_mode,
        "task_set": list(task_set),
        "split_manifest_sha256": split_manifest_sha256,
        "task_snapshot_sha256": task_snapshot_sha256,
        "run_dir": run_dir,
        "config_path": config_path,
        "status": status,
        "unit_status": unit_status,
        "report_complete": report_complete,
        "report_artifacts": dict(report_artifacts),
        "metrics": dict(metrics_brief),
        "cost": dict(cost),
        "functional": {
            "available": functional_available,
            "reason": functional_reason,
            "cache_hits": (functional_manifest or {}).get("cache_hits"),
            "executed": (functional_manifest or {}).get("executed"),
            "result_count": (functional_manifest or {}).get("result_count"),
        },
        "expected_sample_count": expected_sample_count,
        "actual_sample_count": actual_sample_count,
        "missing_sample_ids": list(missing_sample_ids),
        "extra_sample_ids": list(extra_sample_ids),
        "static_verdict_counts": dict(static_verdict_counts),
        "sast_tool_states": dict(sast_tool_states),
        "layer_states": dict(layer_states),
        "sampled_run": bool(sampling_gate(temperature, repeats)[0]),
        "basis": "observed",
        "registered_at": registered_at,
    }
    if derived_from is not None:
        entry["derived_from"] = derived_from
    if split_membership_source is not None:
        entry["split_membership_source"] = dict(split_membership_source)
    return entry


def _load_split_config(
    root: Path, split_config_path: Path | None
) -> tuple[Path | None, dict[str, Any], str | None]:
    if split_config_path is None:
        try:
            path = default_config_dir() / "splits.json"
        except FileNotFoundError:
            return None, {}, None
    else:
        path = Path(split_config_path)
    if not path.is_file():
        return path, {}, None
    payload = _read_json_optional(path) or {}
    return path, payload, sha256_file(path)


def build_index(
    baseline_root: Path | str,
    *,
    split_config_path: Path | str | None = None,
    prepared_by_combination: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the ``baseline-index-v1`` index from a completed baseline root.

    ``split_config_path`` and ``prepared_by_combination`` are explicit test
    hooks; production callers leave them unset so the packaged
    ``configs/splits.json`` and the prepared input snapshots are used.
    """

    root = Path(baseline_root).expanduser().resolve()
    manifest_path = root / "manifest" / "run-manifest.json"
    manifest = _read_json_optional(manifest_path)
    if manifest is None:
        raise BaselineIndexError(f"run manifest not found or invalid: {manifest_path}")

    version_fingerprint = manifest.get("version_fingerprint") or {}
    split_config_file, split_config, split_config_sha256 = _load_split_config(
        root, Path(split_config_path) if split_config_path is not None else None
    )

    entries: dict[str, Any] = {}
    gaps: list[dict[str, Any]] = []
    registered_at = _utc_now()
    units = manifest.get("units") or {}

    for unit_id, unit in units.items():
        if not isinstance(unit, Mapping):
            gaps.append({"unit_id": unit_id, "reason": "unit entry is not an object"})
            continue
        combination_id = str(unit.get("combination_id"))
        for run in unit.get("runs") or []:
            if not isinstance(run, Mapping):
                gaps.append({"unit_id": unit_id, "reason": "run entry is not an object"})
                continue
            run_id = str(run.get("run_id"))
            run_rel = str(run.get("run_dir"))
            run_dir = root / run_rel
            problems = _verify_report_artifacts(run_dir)
            if problems:
                gaps.append(
                    {
                        "unit_id": unit_id,
                        "run_id": run_id,
                        "run_dir": run_rel,
                        "reason": "; ".join(problems),
                    }
                )
                continue

            records = collect_records(run_dir)
            metrics = collect_metrics(run_dir, records)
            costs = collect_costs(run_dir)
            functional_manifest = _read_json_optional(run_dir / "functional" / "manifest.json")
            evaluation_manifest = _read_json_optional(run_dir / "evaluation" / "manifest.json") or {}

            config_rel = str(run.get("config_path") or "")
            config = _read_json_optional(root / config_rel) or {}

            model = str(config.get("model") or unit.get("victim_model") or "")
            temperature = config.get("temperature", unit.get("temperature"))
            repeats = config.get("repeats", unit.get("repeats"))
            task_ids = [str(task_id) for task_id in (run.get("task_ids") or unit.get("task_ids") or [])]
            enabled_layers = list(config.get("enabled_layers") or unit.get("enabled_layers") or [])
            sast_tools = list(config.get("sast_tools") or unit.get("sast_tools") or [])
            k = list(config.get("k") or (1, 3, 5))

            split_path = root / "inputs" / "data" / combination_id / "split.json"
            split_manifest_sha256 = _sha256_or_none(split_path)
            input_split = _read_json_optional(split_path) or {}
            task_snapshot_sha256 = input_split.get("task_snapshot_sha256")

            functional_available, functional_reason = _functional_status(records, functional_manifest)
            report_complete = bool(metrics.get("complete"))
            status = _entry_status(run.get("status", unit.get("status")), report_complete)

            whole_entry_id = f"{run_id}::whole-set"
            whole_briefs = _report_metric_briefs(
                metrics,
                temperature=float(temperature) if temperature is not None else 0.0,
                repeats=int(repeats) if repeats is not None else 1,
            )
            entries[whole_entry_id] = _build_entry(
                entry_id=whole_entry_id,
                run_id=run_id,
                unit_id=unit_id,
                combination_id=combination_id,
                oracle_id=str(unit.get("oracle_id")),
                form=str(unit.get("form") or config.get("form") or ""),
                model=model,
                temperature=float(temperature) if temperature is not None else 0.0,
                repeats=int(repeats) if repeats is not None else 1,
                k=k,
                enabled_layers=enabled_layers,
                sast_tools=sast_tools,
                prompt_version=config.get("prompt_version", version_fingerprint.get("prompt_version")),
                version_fingerprint=version_fingerprint,
                judge_prompt_version=evaluation_manifest.get("judge_prompt_version"),
                judge_detection_version=evaluation_manifest.get("judge_detection_version"),
                split_mode="whole-set",
                task_set=task_ids,
                split_manifest_sha256=split_manifest_sha256,
                task_snapshot_sha256=task_snapshot_sha256,
                run_dir=run_rel,
                config_path=config_rel,
                status=status,
                unit_status=run.get("status", unit.get("status")),
                report_complete=report_complete,
                report_artifacts=_report_artifact_index(run_dir / "report"),
                metrics_brief=whole_briefs,
                cost=_cost_brief(costs),
                functional_available=functional_available,
                functional_reason=functional_reason,
                expected_sample_count=metrics.get("expected_sample_count"),
                actual_sample_count=metrics.get("sample_count"),
                missing_sample_ids=metrics.get("missing_sample_ids") or [],
                extra_sample_ids=metrics.get("extra_sample_ids") or [],
                static_verdict_counts=metrics.get("static_verdict_counts") or {},
                sast_tool_states=_sast_tool_states(records, sast_tools, enabled_layers),
                layer_states=_non_static_layer_states(records, enabled_layers),
                functional_manifest=functional_manifest,
                registered_at=registered_at,
            )

            split_entry = (split_config.get("combinations") or {}).get(combination_id)
            if not isinstance(split_entry, Mapping) or split_entry.get("mode") != "split":
                continue
            if split_config_sha256 is None:
                gaps.append(
                    {
                        "unit_id": unit_id,
                        "run_id": run_id,
                        "split_mode": "search/holdout",
                        "reason": "split config not found while a split combination was declared",
                    }
                )
                continue
            try:
                prepared = _resolve_prepared(root, combination_id, prepared_by_combination)
                split_manifest = build_split(prepared.selection, split_config, split_config_sha256)
            except Exception as error:  # noqa: BLE001 - reported as a gap, never a silent skip
                gaps.append(
                    {
                        "unit_id": unit_id,
                        "run_id": run_id,
                        "split_mode": "search/holdout",
                        "reason": f"derived split unavailable: {type(error).__name__}: {error}",
                    }
                )
                continue
            if split_manifest.mode is not SplitMode.SEARCH_HOLDOUT:
                continue
            for derived_mode, derived_ids in (
                ("search", split_manifest.search_ids),
                ("holdout", split_manifest.holdout_ids),
            ):
                derived_id_set = {str(task_id) for task_id in derived_ids}
                subset = [
                    record
                    for record in records
                    if str(record.get("task_id")) in derived_id_set
                ]
                derived_entry_id = f"{run_id}::{derived_mode}"
                derived_briefs = _recomputed_metric_briefs(
                    subset,
                    [str(task_id) for task_id in derived_ids],
                    split_mode=derived_mode,
                    temperature=float(temperature) if temperature is not None else 0.0,
                    repeats=int(repeats) if repeats is not None else 1,
                    stage=str(config.get("stage") or run.get("stage") or "search"),
                    enabled_layers=enabled_layers,
                    sast_tools=sast_tools,
                )
                derived_available, derived_reason = _functional_status(subset, functional_manifest)
                derived_metrics = _subset_metrics(metrics, subset)
                entries[derived_entry_id] = _build_entry(
                    entry_id=derived_entry_id,
                    run_id=run_id,
                    unit_id=unit_id,
                    combination_id=combination_id,
                    oracle_id=str(unit.get("oracle_id")),
                    form=str(unit.get("form") or config.get("form") or ""),
                    model=model,
                    temperature=float(temperature) if temperature is not None else 0.0,
                    repeats=int(repeats) if repeats is not None else 1,
                    k=k,
                    enabled_layers=enabled_layers,
                    sast_tools=sast_tools,
                    prompt_version=config.get(
                        "prompt_version", version_fingerprint.get("prompt_version")
                    ),
                    version_fingerprint=version_fingerprint,
                    judge_prompt_version=evaluation_manifest.get("judge_prompt_version"),
                    judge_detection_version=evaluation_manifest.get("judge_detection_version"),
                    split_mode=derived_mode,
                    task_set=[str(task_id) for task_id in derived_ids],
                    split_manifest_sha256=split_manifest_sha256,
                    task_snapshot_sha256=task_snapshot_sha256,
                    run_dir=run_rel,
                    config_path=config_rel,
                    status=status,
                    unit_status=run.get("status", unit.get("status")),
                    report_complete=report_complete,
                    report_artifacts=_report_artifact_index(run_dir / "report"),
                    metrics_brief=derived_briefs,
                    cost=_cost_brief({}),  # run-level cost stays on the whole-set entry
                    functional_available=derived_available,
                    functional_reason=derived_reason,
                    expected_sample_count=derived_metrics["expected_sample_count"],
                    actual_sample_count=derived_metrics["actual_sample_count"],
                    missing_sample_ids=derived_metrics["missing_sample_ids"],
                    extra_sample_ids=derived_metrics["extra_sample_ids"],
                    static_verdict_counts=derived_metrics["static_verdict_counts"],
                    sast_tool_states=_sast_tool_states(subset, sast_tools, enabled_layers),
                    layer_states=_non_static_layer_states(subset, enabled_layers),
                    functional_manifest=functional_manifest,
                    registered_at=registered_at,
                    derived_from=whole_entry_id,
                    split_membership_source={
                        "path": str(split_config_file) if split_config_file else None,
                        "sha256": split_config_sha256,
                        "algorithm_version": split_manifest.algorithm_version,
                        "search_count": len(split_manifest.search_ids),
                        "holdout_count": len(split_manifest.holdout_ids),
                    },
                )

    # Per-run versions override the global prepare-time fingerprint: the D03/D04
    # revision re-ran some units under a newer image/cleaner/harness/classifier,
    # so the index must record the versions actually used by each run.
    for entry in entries.values():
        entry.update(_per_run_versions(root, str(entry.get("run_dir") or "")))

    models = sorted({entry["model"] for entry in entries.values() if entry.get("model")})
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "baseline_root": str(root),
        "generated_at": registered_at,
        "models": models,
        "version_fingerprint": version_fingerprint,
        "entries": entries,
        "gaps": gaps,
        "query_semantics": "strict-match",
    }


def _per_run_versions(root: Path, run_dir: str) -> dict[str, Any]:
    """Read the evaluation versions actually used by one run.

    The clean baseline was prepared before the D03/D04 revision, then some units
    were re-run under a newer image/cleaner/harness/classifier; the index must
    reflect the per-run reality rather than the global prepare-time fingerprint.
    """

    run = root / run_dir
    cleaning = _read_json_optional(run / "cleaning" / "manifest.json") or {}
    functional = _read_json_optional(run / "functional" / "manifest.json") or {}
    static = _read_json_optional(run / "static" / "manifest.json") or {}
    versions: dict[str, Any] = {}
    if cleaning.get("cleaner_version"):
        versions["cleaner_version"] = cleaning["cleaner_version"]
    functional_config = functional.get("config") or {}
    harness = functional.get("harness_version") or functional_config.get("harness_version")
    if harness:
        versions["harness_version"] = harness
    if functional.get("classifier_version"):
        versions["classifier_version"] = functional["classifier_version"]
    shell = (static.get("evaluator_fingerprint") or {}).get("shell_version")
    if shell:
        versions["static_shell_version"] = shell
    results = run / "functional" / "functional_results.jsonl"
    if results.is_file():
        for raw in results.read_bytes().split(b"\n"):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw.decode("utf-8"))
            except ValueError:
                continue
            image_id = (row.get("execution") or {}).get("image_id")
            if image_id:
                versions["image_digest"] = image_id
            break
    return versions


def _resolve_prepared(
    root: Path,
    combination_id: str,
    prepared_by_combination: Mapping[str, Any] | None,
) -> Any:
    if prepared_by_combination is not None and combination_id in prepared_by_combination:
        prepared = prepared_by_combination[combination_id]
        if prepared is None:
            raise BaselineIndexError(f"no prepared input for combination {combination_id!r}")
        return prepared
    return load_prepared_data(root / "inputs" / "data", combination_id)


def _subset_metrics(
    metrics: Mapping[str, Any], subset: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Counts recomputed over a record subset (never copied from the run)."""

    del metrics  # counts are always recomputed from the subset, never copied
    verdicts: dict[str, int] = {}
    for record in subset:
        verdict = str((record.get("static") or {}).get("verdict"))
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
    return {
        "expected_sample_count": len(subset),
        "actual_sample_count": len(subset),
        "missing_sample_ids": [],
        "extra_sample_ids": [],
        "static_verdict_counts": dict(sorted(verdicts.items())),
    }


# --------------------------------------------------------------------------- #
# Validation and query
# --------------------------------------------------------------------------- #


def validate_index(index: Mapping[str, Any]) -> None:
    """Validate required fields, unique ids and derived-entry provenance."""

    if not isinstance(index, Mapping):
        raise BaselineIndexError("index must be a mapping")
    for key in ("schema_version", "baseline_root", "entries", "gaps", "query_semantics"):
        if key not in index:
            raise BaselineIndexError(f"index is missing required field: {key!r}")
    if index["schema_version"] != INDEX_SCHEMA_VERSION:
        raise BaselineIndexError(
            f"index.schema_version {index['schema_version']!r} != {INDEX_SCHEMA_VERSION!r}"
        )
    if index["query_semantics"] != "strict-match":
        raise BaselineIndexError(f"index.query_semantics must be 'strict-match', got {index['query_semantics']!r}")
    entries = index["entries"]
    if not isinstance(entries, Mapping):
        raise BaselineIndexError("index.entries must be an object keyed by entry_id")
    if not isinstance(index["gaps"], list):
        raise BaselineIndexError("index.gaps must be a list")

    seen_entry_ids: set[str] = set()
    for key, entry in entries.items():
        if not isinstance(entry, Mapping):
            raise BaselineIndexError(f"entry {key!r} must be an object")
        missing = [name for name in _REQUIRED_ENTRY_FIELDS if name not in entry]
        if missing:
            raise BaselineIndexError(f"entry {key!r} is missing fields: {missing}")
        entry_id = entry["entry_id"]
        if entry_id != key:
            raise BaselineIndexError(
                f"entry key {key!r} does not match entry_id {entry_id!r}"
            )
        if entry_id in seen_entry_ids:
            raise BaselineIndexError(f"duplicate entry_id: {entry_id!r}")
        seen_entry_ids.add(entry_id)
        split_mode = entry["split_mode"]
        if split_mode not in SPLIT_MODES:
            raise BaselineIndexError(
                f"entry {key!r} has invalid split_mode {split_mode!r}; allowed {SPLIT_MODES}"
            )
        metrics = entry["metrics"]
        if not isinstance(metrics, Mapping):
            raise BaselineIndexError(f"entry {key!r} metrics must be an object")
        for name in BRIEF_METRIC_NAMES:
            if name not in metrics:
                raise BaselineIndexError(f"entry {key!r} metrics is missing {name!r}")
        if not isinstance(entry["report_artifacts"], Mapping):
            raise BaselineIndexError(f"entry {key!r} report_artifacts must be an object")
        if split_mode != "whole-set":
            derived_from = entry.get("derived_from")
            if not derived_from:
                raise BaselineIndexError(f"derived entry {key!r} is missing derived_from")
            parent = entries.get(derived_from)
            if parent is None:
                raise BaselineIndexError(
                    f"derived entry {key!r} references unknown whole-set entry {derived_from!r}"
                )
            if parent.get("split_mode") != "whole-set":
                raise BaselineIndexError(
                    f"derived entry {key!r} must reference a whole-set entry, got "
                    f"{parent.get('split_mode')!r}"
                )


def query_index(
    index: Mapping[str, Any],
    *,
    combination_id: str | None = None,
    form: str | None = None,
    split_mode: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    repeats: int | None = None,
    task_set: Sequence[str] | str | None = None,
) -> list[dict[str, Any]]:
    """Strict exact-match lookup; no "closest" fallback.

    ``None`` means "not constrained".  A raw string ``task_set`` is treated as a
    single-element set so callers cannot accidentally match a different口径.
    """

    validate_index(index)
    wanted_task_set: list[str] | None = None
    if task_set is not None:
        if isinstance(task_set, str):
            wanted_task_set = [task_set]
        else:
            wanted_task_set = [str(item) for item in task_set]

    matches: list[dict[str, Any]] = []
    for entry in index["entries"].values():
        if combination_id is not None and entry.get("combination_id") != combination_id:
            continue
        if form is not None and entry.get("form") != form:
            continue
        if split_mode is not None and entry.get("split_mode") != split_mode:
            continue
        if model is not None and entry.get("model") != model:
            continue
        if temperature is not None and entry.get("temperature") != temperature:
            continue
        if repeats is not None and entry.get("repeats") != repeats:
            continue
        if wanted_task_set is not None and [str(t) for t in (entry.get("task_set") or [])] != wanted_task_set:
            continue
        matches.append(dict(entry))
    return matches


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def index_path(baseline_root: Path | str) -> Path:
    return Path(baseline_root) / INDEX_DIRNAME / INDEX_FILENAME


def write_index(baseline_root: Path | str, index: Mapping[str, Any]) -> Path:
    validate_index(index)
    path = index_path(baseline_root)
    write_json_atomic(path, index)
    return path


def load_index(baseline_root: Path | str) -> dict[str, Any]:
    path = index_path(baseline_root)
    payload = _read_json_optional(path)
    if payload is None:
        raise BaselineIndexError(f"baseline index not found or invalid: {path}")
    validate_index(payload)
    return payload


__all__ = [
    "BaselineIndexError",
    "BRIEF_METRIC_NAMES",
    "INDEX_FILENAME",
    "INDEX_SCHEMA_VERSION",
    "REQUIRED_REPORT_ARTIFACTS",
    "SPLIT_MODES",
    "build_index",
    "index_path",
    "load_index",
    "query_index",
    "validate_index",
    "write_index",
]
