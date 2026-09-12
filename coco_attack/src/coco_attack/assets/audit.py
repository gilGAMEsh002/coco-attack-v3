"""Read-only asset and environment audit (work package A / task 01).

The audit answers four questions and never repairs what it finds:

1. which assets are in scope this round;
2. which combination each asset belongs to;
3. whether files and records are complete and well-formed;
4. which differences need a human decision.

It does not execute generated code, does not call the static oracle, does not
read API keys and does not build caches. Static oracle files are only registered
with their location and byte fingerprint; wiring and calibration happen later.
"""

from __future__ import annotations

import ast
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
    write_text_atomic,
)
from .issues import (
    SEVERITY_ERROR,
    SEVERITY_PENDING_DECISION,
    SEVERITY_WARNING,
    Issue,
)
from .paths import (
    assert_assets_output_separation,
    default_config_dir,
    relative_to_root,
    resolve_within,
)
from .schema import (
    BOOLEAN_FIELDS,
    REFERENCE_SIDES,
    REQUIRED_NONEMPTY,
    STANDARD_SCHEMA,
    STANDARD_SCHEMA_NAME,
    TEST_PROMPT_RE,
)

AUDIT_SCHEMA_VERSION = "1"

# Soft dependencies that later stages may use; absence is a stage limitation,
# never an audit failure.
SOFT_TOOLS = ("semgrep", "bandit", "codeql")

# Distributions whose installed version is worth recording for reproducibility.
TRACKED_DISTRIBUTIONS = (
    "dspy",
    "pytest",
    "semgrep",
    "bandit",
    "orjson",
    "litellm",
    "openai",
    "pydantic",
    "requests",
    "diskcache",
    "tenacity",
)

MAX_REPORTED_LINE_ERRORS = 25


@dataclass
class AuditContext:
    repo_dir: Path
    assets_root: Path
    output_dir: Path
    config_dir: Path
    config_path: Path
    config: dict[str, Any]
    issues: list[Issue] = field(default_factory=list)
    task_ids_by_combo: dict[str, list[str]] = field(default_factory=dict)

    def add(self, issue: Issue) -> None:
        self.issues.append(issue)


# --------------------------------------------------------------------------- #
# Config and registry
# --------------------------------------------------------------------------- #


def load_combinations_config(
    config_dir: Path | None = None,
) -> tuple[dict[str, Any], Path]:
    directory = config_dir if config_dir is not None else default_config_dir()
    path = directory / "combinations.json"
    if not path.is_file():
        raise FileNotFoundError(f"Combination routing table not found: {path}")
    return read_json(path), path


def validate_config(ctx: AuditContext) -> None:
    config = ctx.config
    combos = config.get("combinations")
    if not isinstance(combos, list) or not combos:
        ctx.add(
            Issue(
                code="config.invalid_combinations",
                severity=SEVERITY_ERROR,
                scope="config",
                detail="combinations must be a non-empty list",
                asset=relative_to_root(ctx.config_dir, ctx.config_path),
            )
        )
        return

    seen_combo: Counter[str] = Counter()
    seen_oracle: Counter[str] = Counter()
    seen_registry: Counter[str] = Counter()
    required_keys = {
        "combination_id",
        "registry_id",
        "oracle_id",
        "task_file",
        "selection",
        "coverage",
    }
    for index, combo in enumerate(combos):
        where = {"combination_index": index}
        missing = required_keys - set(combo)
        if missing:
            ctx.add(
                Issue(
                    code="config.missing_keys",
                    severity=SEVERITY_ERROR,
                    scope="config",
                    detail=f"combination entry missing keys: {sorted(missing)}",
                    asset=config_asset(ctx),
                    location=where,
                )
            )
            continue
        seen_combo[combo["combination_id"]] += 1
        seen_oracle[combo["oracle_id"]] += 1
        seen_registry[combo["registry_id"]] += 1
        coverage = combo.get("coverage") or {}
        for layer in ("static", "dynamic", "security_realism"):
            if layer not in coverage:
                ctx.add(
                    Issue(
                        code="config.missing_coverage",
                        severity=SEVERITY_ERROR,
                        scope="config",
                        detail=f"coverage missing layer {layer!r}",
                        asset=config_asset(ctx),
                        location={"combination_id": combo["combination_id"]},
                    )
                )

    for label, counter in (
        ("combination_id", seen_combo),
        ("oracle_id", seen_oracle),
        ("registry_id", seen_registry),
    ):
        duplicated = sorted(key for key, count in counter.items() if count > 1)
        if duplicated:
            ctx.add(
                Issue(
                    code="config.duplicate_route",
                    severity=SEVERITY_ERROR,
                    scope="config",
                    detail=f"duplicate {label} values in routing table: {duplicated}",
                    asset=config_asset(ctx),
                )
            )


def config_asset(ctx: AuditContext) -> str:
    return relative_to_root(ctx.config_dir, ctx.config_path)


def inspect_registry(ctx: AuditContext) -> tuple[dict[str, Any], dict[str, dict], set[str]]:
    rel = ctx.config["registry_file"]
    path = resolve_within(ctx.assets_root, rel)
    entry: dict[str, Any] = {"path": rel}
    if not path.is_file():
        ctx.add(
            Issue(
                code="registry.missing",
                severity=SEVERITY_ERROR,
                scope="registry",
                detail=f"combination registry not found at {rel}",
                asset=rel,
            )
        )
        return entry, {}, set()

    entry["sha256"] = sha256_file(path)
    data = read_json(path)
    definitions = data.get("combination_definitions", [])
    entry["definition_count"] = len(definitions)
    taxonomy = data.get("type_taxonomy", {})
    entry["type_taxonomy"] = sorted(taxonomy)
    entry["schema_version"] = data.get("schema_version")

    by_id: dict[str, dict] = {}
    duplicates: list[str] = []
    for definition in definitions:
        statistics_id = definition.get("statistical_id")
        if statistics_id in by_id:
            duplicates.append(statistics_id)
        else:
            by_id[statistics_id] = definition
    if duplicates:
        ctx.add(
            Issue(
                code="registry.duplicate_definition",
                severity=SEVERITY_ERROR,
                scope="registry",
                detail=f"duplicate statistical_id definitions: {sorted(set(duplicates))}",
                asset=rel,
            )
        )
    entry["duplicate_registry_ids"] = sorted(set(duplicates))

    routed: dict[str, dict[str, Any]] = {}
    for combo in ctx.config["combinations"]:
        registry_id = combo["registry_id"]
        definition = by_id.get(registry_id)
        if definition is None:
            ctx.add(
                Issue(
                    code="registry.route_missing",
                    severity=SEVERITY_ERROR,
                    scope="registry",
                    detail=f"routed registry id {registry_id!r} has no definition",
                    asset=rel,
                    location={"combination_id": combo["combination_id"]},
                )
            )
            continue
        if definition.get("experiment_type") not in taxonomy:
            ctx.add(
                Issue(
                    code="registry.unknown_experiment_type",
                    severity=SEVERITY_WARNING,
                    scope="registry",
                    detail=(
                        f"registry experiment_type {definition.get('experiment_type')!r} "
                        "is not declared in type_taxonomy"
                    ),
                    asset=rel,
                    location={"registry_id": registry_id},
                )
            )
        routed[combo["combination_id"]] = {
            "registry_id": registry_id,
            "experiment_type": definition.get("experiment_type"),
            "decision": definition.get("decision"),
            "clean_pattern": definition.get("clean_pattern"),
            "target_pattern": definition.get("target_pattern"),
        }
    entry["routed_definitions"] = routed
    return entry, by_id, set(taxonomy)


# --------------------------------------------------------------------------- #
# Selection records
# --------------------------------------------------------------------------- #


def inspect_selection_files(
    ctx: AuditContext,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for label, rel in ctx.config["selection_files"].items():
        path = resolve_within(ctx.assets_root, rel)
        entry: dict[str, Any] = {"path": rel}
        if not path.is_file():
            ctx.add(
                Issue(
                    code="selection.missing",
                    severity=SEVERITY_ERROR,
                    scope="selection",
                    detail=f"{label} few-shot selection record not found at {rel}",
                    asset=rel,
                )
            )
            out[label] = entry
            continue
        entry["sha256"] = sha256_file(path)
        data = read_json(path)
        seed = data.get("seed")
        selected = data.get("selected", {})
        entry["seed"] = seed
        entry["count_per_cwe"] = data.get("count_per_cwe")
        entry["input_dir"] = data.get("input_dir")
        entry["keys"] = sorted(selected)
        entry["selected"] = {
            key: {
                "task_ids": value.get("task_ids"),
                "source_file": value.get("source_file"),
                "derived_seed": value.get("derived_seed"),
            }
            for key, value in sorted(selected.items())
        }
        if seed != 42:
            ctx.add(
                Issue(
                    code="selection.unexpected_seed",
                    severity=SEVERITY_ERROR,
                    scope="selection",
                    detail=f"{label} selection declares seed={seed!r}, expected 42",
                    asset=rel,
                )
            )
        for key, value in selected.items():
            if len(value.get("task_ids") or []) != data.get("count_per_cwe"):
                ctx.add(
                    Issue(
                        code="selection.count_mismatch",
                        severity=SEVERITY_WARNING,
                        scope="selection",
                        detail=(
                            f"{label}/{key} has {len(value.get('task_ids') or [])} "
                            f"task_ids but count_per_cwe={data.get('count_per_cwe')}"
                        ),
                        asset=rel,
                        location={"selection_key": key},
                    )
                )
        out[label] = entry
    return out


# --------------------------------------------------------------------------- #
# Standard task files
# --------------------------------------------------------------------------- #


def inspect_task_file(
    ctx: AuditContext,
    combo: dict[str, Any],
    taxonomy: set[str],
    routed_definition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rel = combo["task_file"]
    combination_id = combo["combination_id"]
    path = resolve_within(ctx.assets_root, rel)
    entry: dict[str, Any] = {"path": rel}
    if not path.is_file():
        ctx.add(
            Issue(
                code="tasks.missing",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"standard task file not found at {rel}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
        return entry

    entry["sha256"] = sha256_file(path)
    line_count = 0
    task_ids: list[str] = []
    duplicates: list[str] = []
    seen: set[str] = set()
    fieldset_counter: Counter[tuple[str, ...]] = Counter()
    missing_fields: Counter[str] = Counter()
    extra_fields: Counter[str] = Counter()
    required_empty: Counter[str] = Counter()
    type_violations: Counter[str] = Counter()
    reference_sides: Counter[str] = Counter()
    statistical_ids: Counter[str] = Counter()
    experiment_types: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    nonempty_test = 0
    parse_error_lines: list[int] = []
    bad_record_ids: list[str] = []
    reported_line_errors = 0

    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            line_count += 1
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                parse_error_lines.append(lineno)
                if reported_line_errors < MAX_REPORTED_LINE_ERRORS:
                    reported_line_errors += 1
                    ctx.add(
                        Issue(
                            code="tasks.invalid_json",
                            severity=SEVERITY_ERROR,
                            scope="tasks",
                            detail=f"invalid JSON record: {error}",
                            asset=rel,
                            location={"line": lineno, "combination_id": combination_id},
                        )
                    )
                continue
            if not isinstance(obj, dict):
                parse_error_lines.append(lineno)
                if reported_line_errors < MAX_REPORTED_LINE_ERRORS:
                    reported_line_errors += 1
                    ctx.add(
                        Issue(
                            code="tasks.not_object",
                            severity=SEVERITY_ERROR,
                            scope="tasks",
                            detail=f"JSONL record is not an object (got {type(obj).__name__})",
                            asset=rel,
                            location={"line": lineno, "combination_id": combination_id},
                        )
                    )
                continue

            keys = tuple(sorted(obj))
            fieldset_counter[keys] += 1
            key_set = set(obj)
            for missing in sorted(set(STANDARD_SCHEMA) - key_set):
                missing_fields[missing] += 1
            for extra in sorted(key_set - set(STANDARD_SCHEMA)):
                extra_fields[extra] += 1
            for field_name in REQUIRED_NONEMPTY:
                if not obj.get(field_name):
                    required_empty[field_name] += 1
            for field_name in BOOLEAN_FIELDS:
                if not isinstance(obj.get(field_name), bool):
                    type_violations[field_name] += 1
            source_cwe_id = obj.get("source_cwe_id")
            if not (source_cwe_id is None or isinstance(source_cwe_id, str)):
                type_violations["source_cwe_id"] += 1
            for field_name in STANDARD_SCHEMA:
                if field_name in BOOLEAN_FIELDS or field_name == "source_cwe_id":
                    continue
                if not isinstance(obj.get(field_name), str):
                    type_violations[field_name] += 1

            task_id = obj.get("task_id")
            if isinstance(task_id, str):
                if task_id in seen:
                    duplicates.append(task_id)
                else:
                    seen.add(task_id)
                    task_ids.append(task_id)
            else:
                bad_record_ids.append(str(lineno))

            reference_sides[str(obj.get("reference_side"))] += 1
            statistical_ids[str(obj.get("statistical_cwe_id"))] += 1
            experiment_types[str(obj.get("experiment_type"))] += 1
            decisions[str(obj.get("decision"))] += 1
            if obj.get("test"):
                nonempty_test += 1

    entry.update(
        line_count=line_count,
        unique_task_ids=len(task_ids),
        task_ids_sha256=sha256_bytes(canonical_json_bytes(task_ids)),
        duplicate_task_ids=sorted(set(duplicates)),
        field_sets=[list(fieldset) for fieldset in fieldset_counter],
        missing_fields=sorted(missing_fields),
        extra_fields=sorted(extra_fields),
        required_empty=sorted(required_empty),
        type_violations=sorted(type_violations),
        reference_sides=dict(sorted(reference_sides.items())),
        statistical_cwe_ids=dict(sorted(statistical_ids.items())),
        experiment_types=dict(sorted(experiment_types.items())),
        decisions=dict(sorted(decisions.items())),
        nonempty_test_records=nonempty_test,
        parse_error_lines=parse_error_lines,
        non_string_task_id_lines=bad_record_ids,
    )
    ctx.task_ids_by_combo[combination_id] = task_ids

    if type_violations:
        ctx.add(
            Issue(
                code="tasks.type_violation",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"fields with wrong JSON types: {sorted(type_violations)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if bad_record_ids:
        ctx.add(
            Issue(
                code="tasks.non_string_task_id",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=(
                    "records with a non-string task_id were excluded from task-id "
                    "summaries (physical lines: "
                    f"{bad_record_ids[:MAX_REPORTED_LINE_ERRORS]})"
                ),
                asset=rel,
                location={"combination_id": combination_id},
            )
        )

    if duplicates:
        ctx.add(
            Issue(
                code="tasks.duplicate_id",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"duplicate task_id values inside combination: {sorted(set(duplicates))}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if missing_fields:
        ctx.add(
            Issue(
                code="tasks.missing_fields",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"records missing declared schema fields: {sorted(missing_fields)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if extra_fields:
        ctx.add(
            Issue(
                code="tasks.extra_fields",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"records carry undeclared fields: {sorted(extra_fields)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if required_empty:
        ctx.add(
            Issue(
                code="tasks.required_empty",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"required fields are empty in some records: {sorted(required_empty)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if nonempty_test == 0:
        ctx.add(
            Issue(
                code="tasks.no_test_records",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail="no record in this file carries a non-empty functional test",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    expected_statistical = combo["registry_id"]
    if set(statistical_ids) - {expected_statistical}:
        ctx.add(
            Issue(
                code="tasks.statistical_id_mismatch",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=(
                    f"statistical_cwe_id values {sorted(statistical_ids)} do not match "
                    f"routed registry id {expected_statistical!r}"
                ),
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    unexpected_sides = set(reference_sides) - REFERENCE_SIDES
    if unexpected_sides:
        ctx.add(
            Issue(
                code="tasks.bad_reference_side",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"unexpected reference_side values: {sorted(unexpected_sides)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    unknown_types = set(experiment_types) - taxonomy
    if unknown_types:
        ctx.add(
            Issue(
                code="tasks.unknown_experiment_type",
                severity=SEVERITY_ERROR,
                scope="tasks",
                detail=f"experiment_type values outside registry taxonomy: {sorted(unknown_types)}",
                asset=rel,
                location={"combination_id": combination_id},
            )
        )
    if routed_definition:
        # Registry is authoritative for screening metadata. Report the raw
        # deviation once, but make clear the effective values follow the
        # registry (and that the historical task files are not rewritten).
        raw_values = {
            "statistical_cwe_id": sorted(statistical_ids),
            "experiment_type": sorted(experiment_types),
            "decision": sorted(decisions),
        }
        registry_values = {
            "statistical_cwe_id": routed_definition.get("statistical_cwe_id")
            or combo.get("registry_id"),
            "experiment_type": routed_definition.get("experiment_type"),
            "decision": routed_definition.get("decision"),
        }
        provenance: dict[str, dict[str, Any]] = {}
        for field in ("statistical_cwe_id", "experiment_type", "decision"):
            raw_distinct = {value for value in raw_values[field] if value != "None"}
            effective = registry_values[field]
            if effective is None or not raw_distinct or raw_distinct == {effective}:
                continue
            provenance[field] = {
                "raw": sorted(raw_distinct),
                "effective": effective,
                "authority": "registry",
            }
        entry["effective_experiment_types"] = (
            [registry_values["experiment_type"]]
            if registry_values["experiment_type"]
            else []
        )
        entry["effective_decisions"] = (
            [registry_values["decision"]] if registry_values["decision"] else []
        )
        entry["metadata_normalization"] = provenance
        if provenance:
            ctx.add(
                Issue(
                    code="tasks.metadata_normalized_from_registry",
                    severity=SEVERITY_WARNING,
                    scope="tasks",
                    detail=(
                        "task metadata deviates from the routed registry definition; "
                        "effective values follow the registry and raw values are kept "
                        f"as provenance: {provenance}"
                    ),
                    asset=rel,
                    location={"combination_id": combination_id},
                )
            )
    return entry


# --------------------------------------------------------------------------- #
# Clean prompt assets (legacy 4 combinations)
# --------------------------------------------------------------------------- #


def _test_prompt_ids(directory: Path) -> tuple[list[str], list[str]]:
    """Return ``(ids, unparsable_names)`` for a test_prompts directory."""

    ids: list[str] = []
    unparsable: list[str] = []
    if not directory.is_dir():
        return ids, unparsable
    for child in sorted(directory.iterdir()):
        if not child.is_file():
            continue
        match = TEST_PROMPT_RE.match(child.name)
        if match is None:
            unparsable.append(child.name)
            continue
        ids.append(f"BigCodeBench/{match.group(1)}")
    return ids, unparsable


def _dir_content_fingerprint(directory: Path) -> str | None:
    """Hash the sorted ``name + content`` pairs of a directory.

    This gives a stable fingerprint of the full prompt material without adding
    N separate entries to the manifest.
    """

    if not directory.is_dir():
        return None
    entries: list[tuple[str, str]] = []
    for child in sorted(directory.iterdir()):
        if child.is_file():
            entries.append((child.name, sha256_file(child)))
    return sha256_bytes(canonical_json_bytes(entries))


def _stage_fingerprint(paths: list[Path]) -> str:
    """Fingerprint a prompt experiment from its files and prompt directory."""

    parts: list[list[object]] = []
    for path in paths:
        if path.is_file():
            parts.append(["file", path.name, sha256_file(path)])
        elif path.is_dir():
            parts.append(["dir", path.name, _dir_content_fingerprint(path)])
        else:
            parts.append(["missing", path.name, None])
    return sha256_bytes(canonical_json_bytes(parts))


def inspect_clean_assets(
    ctx: AuditContext,
    combo: dict[str, Any],
    legacy_selected: dict[str, Any] | None,
) -> dict[str, Any] | None:
    clean_assets = combo.get("clean_assets")
    if not clean_assets:
        return None

    combination_id = combo["combination_id"]
    root_rel = clean_assets["experiment_root"]
    entry: dict[str, Any] = {"experiment_root": root_rel}

    def experiment_dir(name: str) -> Path | None:
        rel = f"{root_rel}/{name}"
        path = resolve_within(ctx.assets_root, rel)
        if not path.is_dir():
            ctx.add(
                Issue(
                    code="clean_assets.missing_experiment",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=f"clean prompt experiment directory missing: {rel}",
                    asset=rel,
                    location={"combination_id": combination_id},
                )
            )
            return None
        return path

    few_dir = experiment_dir(clean_assets["fewshot_experiment"])
    zero_dir = experiment_dir(clean_assets["zero_shot_experiment"])
    if few_dir is None or zero_dir is None:
        return entry

    meta_path = few_dir / "meta.json"
    fewshot_path = few_dir / "fewshot.json"
    for required in (meta_path, fewshot_path):
        if not required.is_file():
            ctx.add(
                Issue(
                    code="clean_assets.missing_file",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=f"required clean asset file missing: {required.name}",
                    asset=relative_to_root(ctx.assets_root, required),
                    location={"combination_id": combination_id},
                )
            )
            return entry

    meta = read_json(meta_path)
    fewshot = read_json(fewshot_path)
    if not isinstance(meta, dict):
        ctx.add(
            Issue(
                code="clean_assets.invalid_meta",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=f"meta.json is not a JSON object (got {type(meta).__name__})",
                asset=relative_to_root(ctx.assets_root, meta_path),
                location={"combination_id": combination_id},
            )
        )
        return entry
    if not isinstance(fewshot, list) or any(
        not isinstance(sample, dict) for sample in fewshot
    ):
        ctx.add(
            Issue(
                code="clean_assets.invalid_fewshot",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    "fewshot.json must be a list of sample objects "
                    f"(got {type(fewshot).__name__})"
                ),
                asset=relative_to_root(ctx.assets_root, fewshot_path),
                location={"combination_id": combination_id},
            )
        )
        return entry
    meta_ids = list(meta.get("fewshot_ids") or [])
    fewshot_ids = [sample.get("task_id") for sample in fewshot]
    entry["fewshot_ids"] = fewshot_ids
    entry["meta_fewshot_ids"] = meta_ids
    entry["has_cot"] = meta.get("has_cot")
    entry["test_count_declared"] = meta.get("test_count")
    entry["template"] = meta.get("template")
    entry["meta_sha256"] = sha256_file(meta_path)
    entry["fewshot_sha256"] = sha256_file(fewshot_path)

    templates_dir = resolve_within(ctx.assets_root, clean_assets["templates_dir"])
    template_file = templates_dir / clean_assets["template_file"]
    if template_file.is_file():
        entry["template_sha256"] = sha256_file(template_file)
        entry["template_path"] = relative_to_root(ctx.assets_root, template_file)
    else:
        ctx.add(
            Issue(
                code="clean_assets.template_missing",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    f"referenced clean template missing: "
                    f"{clean_assets['templates_dir']}/{clean_assets['template_file']}"
                ),
                asset=clean_assets["templates_dir"],
                location={"combination_id": combination_id},
            )
        )

    few_test_ids, few_unparsable = _test_prompt_ids(few_dir / "test_prompts")
    zero_test_ids, zero_unparsable = _test_prompt_ids(zero_dir / "test_prompts")
    entry["fewshot_test_ids"] = few_test_ids
    entry["zero_shot_test_ids"] = zero_test_ids
    entry["fewshot_test_ids_sha256"] = sha256_bytes(canonical_json_bytes(few_test_ids))
    entry["zero_shot_test_ids_sha256"] = sha256_bytes(canonical_json_bytes(zero_test_ids))
    entry["fewshot_stage_sha256"] = _stage_fingerprint(
        [few_dir / "meta.json", fewshot_path, few_dir / "test_prompts"]
    )
    entry["zero_shot_stage_sha256"] = _stage_fingerprint(
        [zero_dir / "meta.json", zero_dir / "fewshot.json", zero_dir / "test_prompts"]
    )

    if few_unparsable or zero_unparsable:
        ctx.add(
            Issue(
                code="clean_assets.unparsable_test_prompt",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    "test_prompts filenames not matching BigCodeBench_SL_<n>.md: "
                    f"fewshot={few_unparsable}, zero_shot={zero_unparsable}"
                ),
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    if meta_ids != fewshot_ids:
        ctx.add(
            Issue(
                code="clean_assets.meta_fewshot_mismatch",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=f"meta fewshot_ids {meta_ids} != fewshot.json order {fewshot_ids}",
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    if legacy_selected is not None and legacy_selected.get("task_ids") != fewshot_ids:
        ctx.add(
            Issue(
                code="clean_assets.selection_mismatch",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    f"legacy seed selection {legacy_selected.get('task_ids')} != "
                    f"fewshot.json order {fewshot_ids}"
                ),
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    if len(fewshot_ids) != len(set(fewshot_ids)):
        ctx.add(
            Issue(
                code="clean_assets.duplicate_fewshot",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=f"few-shot example ids repeat: {fewshot_ids}",
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    if few_test_ids != zero_test_ids:
        ctx.add(
            Issue(
                code="clean_assets.eval_set_mismatch",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    "few-shot and 0-shot evaluation sets differ: "
                    f"fewshot_only={sorted(set(few_test_ids) - set(zero_test_ids))}, "
                    f"zero_only={sorted(set(zero_test_ids) - set(few_test_ids))}"
                ),
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    if meta.get("test_count") is not None and meta.get("test_count") != len(few_test_ids):
        ctx.add(
            Issue(
                code="clean_assets.test_count_mismatch",
                severity=SEVERITY_ERROR,
                scope="clean_assets",
                detail=(
                    f"meta test_count={meta.get('test_count')} but "
                    f"{len(few_test_ids)} test_prompts files exist"
                ),
                asset=root_rel,
                location={"combination_id": combination_id},
            )
        )
    standard_ids = set(ctx.task_ids_by_combo.get(combination_id, []))
    if standard_ids:
        unknown = sorted(set(few_test_ids) - standard_ids)
        if unknown:
            ctx.add(
                Issue(
                    code="clean_assets.eval_not_in_tasks",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=f"evaluation ids absent from standard task file: {unknown}",
                    asset=root_rel,
                    location={"combination_id": combination_id},
                )
            )
        unknown_examples = sorted(set(fewshot_ids) - standard_ids)
        if unknown_examples:
            ctx.add(
                Issue(
                    code="clean_assets.fewshot_not_in_tasks",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=f"few-shot ids absent from standard task file: {unknown_examples}",
                    asset=root_rel,
                    location={"combination_id": combination_id},
                )
            )
        overlap = sorted(set(few_test_ids) & set(fewshot_ids))
        if overlap:
            ctx.add(
                Issue(
                    code="clean_assets.example_eval_overlap",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=f"few-shot ids also present in evaluation set: {overlap}",
                    asset=root_rel,
                    location={"combination_id": combination_id},
                )
            )
        expected_eval = standard_ids - set(fewshot_ids)
        if set(few_test_ids) != expected_eval:
            ctx.add(
                Issue(
                    code="clean_assets.eval_set_unexpected",
                    severity=SEVERITY_ERROR,
                    scope="clean_assets",
                    detail=(
                        "evaluation set != standard tasks minus examples: "
                        f"missing={sorted(expected_eval - set(few_test_ids))}, "
                        f"extra={sorted(set(few_test_ids) - expected_eval)}"
                    ),
                    asset=root_rel,
                    location={"combination_id": combination_id},
                )
            )
    return entry


# --------------------------------------------------------------------------- #
# Static oracle registration and reference calibration records
# --------------------------------------------------------------------------- #


def inspect_oracle_shared(ctx: AuditContext) -> dict[str, Any]:
    """Register the shared static-oracle dependencies exactly once."""

    entry: dict[str, Any] = {"files": {}}
    for shared in (
        "oracles/static_registry.py",
        "oracles/_static_common.py",
        "oracles/_symbols.py",
    ):
        shared_path = resolve_within(ctx.assets_root, shared)
        if shared_path.is_file():
            entry["files"][shared] = sha256_file(shared_path)
        else:
            ctx.add(
                Issue(
                    code="oracle.shared_missing",
                    severity=SEVERITY_ERROR,
                    scope="oracle",
                    detail=f"shared oracle dependency not found at {shared}",
                    asset=shared,
                )
            )
    return entry


def inspect_oracle(ctx: AuditContext, combo: dict[str, Any]) -> dict[str, Any]:
    oracle_id = combo["oracle_id"]
    entry: dict[str, Any] = {"oracle_id": oracle_id}

    module_rel = f"oracles/{oracle_id.replace('-', '_')}.py"
    module_path = resolve_within(ctx.assets_root, module_rel)
    if module_path.is_file():
        entry["module"] = {"path": module_rel, "sha256": sha256_file(module_path)}
    else:
        ctx.add(
            Issue(
                code="oracle.module_missing",
                severity=SEVERITY_ERROR,
                scope="oracle",
                detail=f"static oracle module not found at {module_rel}",
                asset=module_rel,
                location={"combination_id": combo["combination_id"]},
            )
        )

    reference_rel = f"{ctx.config['oracle_results_dir']}/{combo['registry_id']}_reference.json"
    reference_path = resolve_within(ctx.assets_root, reference_rel)
    if not reference_path.is_file():
        ctx.add(
            Issue(
                code="oracle.reference_missing",
                severity=SEVERITY_ERROR,
                scope="oracle",
                detail=f"oracle reference calibration record not found at {reference_rel}",
                asset=reference_rel,
                location={"combination_id": combo["combination_id"]},
            )
        )
    else:
        reference = read_json(reference_path)
        entry["reference"] = {
            "path": reference_rel,
            "sha256": sha256_file(reference_path),
            "oracle_id": reference.get("oracle_id"),
            "input": reference.get("input"),
            "total": reference.get("total"),
            "agreements": reference.get("agreements"),
            "agreement_rate": reference.get("agreement_rate"),
        }
        if reference.get("oracle_id") != oracle_id:
            ctx.add(
                Issue(
                    code="oracle.reference_id_mismatch",
                    severity=SEVERITY_ERROR,
                    scope="oracle",
                    detail=(
                        f"reference record declares oracle_id={reference.get('oracle_id')!r} "
                        f"but route uses {oracle_id!r}"
                    ),
                    asset=reference_rel,
                    location={"combination_id": combo["combination_id"]},
                )
            )
        rows = reference.get("rows") or []
        label_boundaries = [
            {
                "task_id": row.get("task_id"),
                "expected_target": row.get("expected_target"),
                "verdict": row.get("verdict"),
                "agrees_with_label": row.get("agrees_with_label"),
            }
            for row in rows
            if row.get("agrees_with_label") is False
        ]
        if label_boundaries:
            entry["reference"]["label_boundaries"] = label_boundaries
        if reference.get("agreement_rate") != 1.0:
            # Decision: the static oracle verdict is authoritative for ASR
            # (task book F5/F6); ``reference_side`` is a screening-time label.
            # A disagreement is a label boundary to record, not a reason to
            # rewrite the oracle or to hard-code sample ids.
            ctx.add(
                Issue(
                    code="oracle.reference_label_boundary",
                    severity=SEVERITY_WARNING,
                    scope="oracle",
                    detail=(
                        f"oracle verdicts differ from reference_side labels for "
                        f"{len(label_boundaries)}/{reference.get('total')} reference "
                        "solutions; the oracle verdict is authoritative for ASR and the "
                        "label boundaries are read from the reference record"
                    ),
                    asset=reference_rel,
                    location={"combination_id": combo["combination_id"]},
                    evidence=(
                        f"agreements={reference.get('agreements')}, "
                        f"total={reference.get('total')}, "
                        f"boundaries={label_boundaries}"
                    ),
                )
            )
    return entry


def inspect_python_requirements(ctx: AuditContext) -> dict[str, Any]:
    """Aggregate the ``libs`` metadata used to plan the Docker image.

    This is a static read of a source string; the audit never imports or
    installs the listed libraries.
    """

    per_combination: dict[str, dict[str, int]] = {}
    aggregate: Counter[str] = Counter()
    parse_errors: Counter[str] = Counter()
    for combo in ctx.config["combinations"]:
        combination_id = combo["combination_id"]
        rel = combo["task_file"]
        path = resolve_within(ctx.assets_root, rel)
        if not path.is_file():
            continue
        local: Counter[str] = Counter()
        for _lineno, obj in _iter_jsonl_lenient(
            path, ctx, rel, code_prefix="requirements", report_errors=False
        ):
            raw = obj.get("libs")
            if isinstance(raw, str):
                try:
                    value = ast.literal_eval(raw)
                except (ValueError, SyntaxError):
                    parse_errors[combination_id] += 1
                    continue
            else:
                value = raw
            if isinstance(value, list):
                for lib in value:
                    if isinstance(lib, str):
                        local[lib] += 1
        per_combination[combination_id] = dict(sorted(local.items()))
        aggregate.update(local)

    if parse_errors:
        ctx.add(
            Issue(
                code="requirements.libs_unparsable",
                severity=SEVERITY_WARNING,
                scope="requirements",
                detail=(
                    "some libs metadata strings could not be parsed with "
                    f"ast.literal_eval: {dict(sorted(parse_errors.items()))}"
                ),
                asset="standard task files",
            )
        )
    return {
        "per_combination": per_combination,
        "aggregate": dict(sorted(aggregate.items())),
    }


def inspect_reference_eval(
    ctx: AuditContext, standard_counts: dict[str, int]
) -> dict[str, Any]:
    rel = ctx.config["reference_eval_dir"]
    directory = resolve_within(ctx.assets_root, rel)
    entry: dict[str, Any] = {"path": rel}
    if not directory.is_dir():
        ctx.add(
            Issue(
                code="reference_eval.missing",
                severity=SEVERITY_ERROR,
                scope="reference_eval",
                detail=f"historical functional reference directory missing at {rel}",
                asset=rel,
            )
        )
        return entry

    summary_path = directory / "summary.json"
    results_path = directory / "results.jsonl"
    if summary_path.is_file():
        entry["summary"] = read_json(summary_path)
    else:
        ctx.add(
            Issue(
                code="reference_eval.summary_missing",
                severity=SEVERITY_ERROR,
                scope="reference_eval",
                detail="summary.json missing from reference_eval directory",
                asset=rel,
            )
        )
    if results_path.is_file():
        entry["results_sha256"] = sha256_file(results_path)
        membership_counts: Counter[str] = Counter()
        line_count = 0
        parsed: list[dict[str, Any]] = []
        for lineno, obj in _iter_jsonl_lenient(
            results_path, ctx, rel, code_prefix="reference_eval"
        ):
            line_count += 1
            parsed.append(obj)
            for membership in obj.get("memberships") or []:
                key = None
                if isinstance(membership, dict):
                    key = membership.get("combination") or membership.get("combination_id")
                membership_counts[str(key)] += 1
        entry["result_line_count"] = line_count
        entry["membership_counts"] = dict(sorted(membership_counts.items()))
        cwe078_members = {
            obj.get("task_id")
            for obj in parsed
            if any(
                isinstance(m, dict)
                and (m.get("combination") or m.get("combination_id")) == "CWE-078-0"
                for m in (obj.get("memberships") or [])
            )
        }
        standard_cwe078 = set(ctx.task_ids_by_combo.get("cwe078-0", []))
        missing = sorted(standard_cwe078 - cwe078_members) if standard_cwe078 else []
        entry["cwe078_missing_memberships"] = missing
    else:
        ctx.add(
            Issue(
                code="reference_eval.results_missing",
                severity=SEVERITY_ERROR,
                scope="reference_eval",
                detail="results.jsonl missing from reference_eval directory",
                asset=rel,
            )
        )
        missing = []

    # The standard task files are authoritative for the rebuild (they include
    # the task added during the v2 dataset expansion). A historical functional
    # reference that predates that addition is a coverage gap, not a second
    # counting convention and not a reason to drop the task.
    coverage_gaps: list[dict[str, Any]] = []
    if missing:
        coverage_gaps.append(
            {
                "combination_id": "cwe078-0",
                "standard_task_count": len(standard_cwe078),
                "historical_reference_count": len(cwe078_members),
                "missing_task_ids": missing,
            }
        )

    summary = entry.get("summary") or {}
    by_combination = summary.get("by_combination") or {}
    registry_to_combo = {
        combo["registry_id"]: combo["combination_id"]
        for combo in ctx.config["combinations"]
    }
    for registry_id, totals in by_combination.items():
        combo_id = registry_to_combo.get(registry_id)
        if combo_id is None or combo_id not in standard_counts:
            continue
        expected = standard_counts[combo_id]
        historical = totals.get("total")
        if historical is not None and historical != expected and not any(
            gap["combination_id"] == combo_id for gap in coverage_gaps
        ):
            coverage_gaps.append(
                {
                    "combination_id": combo_id,
                    "standard_task_count": expected,
                    "historical_reference_count": historical,
                    "missing_task_ids": [],
                }
            )
    if coverage_gaps:
        entry["coverage_gaps"] = coverage_gaps
        ctx.add(
            Issue(
                code="reference_eval.historical_coverage_gap",
                severity=SEVERITY_WARNING,
                scope="reference_eval",
                detail=(
                    "historical functional reference covers fewer tasks than the "
                    "authoritative standard files; standard counts win and the "
                    "historical results are not modified"
                ),
                asset=rel,
                evidence=f"coverage_gaps={coverage_gaps}",
            )
        )
    return entry


def _iter_jsonl_lenient(
    path: Path,
    ctx: AuditContext,
    asset: str,
    *,
    code_prefix: str,
    report_errors: bool = True,
) -> Any:
    """Yield ``(lineno, object)`` while reporting malformed lines.

    Unlike :func:`artifacts.iter_jsonl`, this reader does not abort on the first
    bad line, so an audit can report every problem in one pass. Calling code
    that has already validated the same file (for example the requirement
    aggregation over standard task files) can set ``report_errors=False`` to
    avoid duplicate issues.
    """

    reported = 0
    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                if report_errors and reported < MAX_REPORTED_LINE_ERRORS:
                    reported += 1
                    ctx.add(
                        Issue(
                            code=f"{code_prefix}.invalid_json",
                            severity=SEVERITY_ERROR,
                            scope=code_prefix,
                            detail=f"invalid JSON record: {error}",
                            asset=asset,
                            location={"line": lineno},
                        )
                    )
                continue
            if not isinstance(obj, dict):
                if report_errors and reported < MAX_REPORTED_LINE_ERRORS:
                    reported += 1
                    ctx.add(
                        Issue(
                            code=f"{code_prefix}.not_object",
                            severity=SEVERITY_ERROR,
                            scope=code_prefix,
                            detail=(
                                "JSONL record is not an object "
                                f"(got {type(obj).__name__})"
                            ),
                            asset=asset,
                            location={"line": lineno},
                        )
                    )
                continue
            yield lineno, obj


# --------------------------------------------------------------------------- #
# Legacy task files and history runs
# --------------------------------------------------------------------------- #


def inspect_legacy_tasks(ctx: AuditContext) -> dict[str, Any]:
    rel_dir = ctx.config["legacy_tasks_dir"]
    directory = resolve_within(ctx.assets_root, rel_dir)
    entry: dict[str, Any] = {"path": rel_dir, "files": {}}
    for combo in ctx.config["combinations"]:
        alias = combo.get("legacy_alias")
        if not alias:
            continue
        rel = f"{rel_dir}/{alias}.jsonl"
        path = resolve_within(ctx.assets_root, rel)
        file_entry: dict[str, Any] = {"path": rel}
        if not path.is_file():
            ctx.add(
                Issue(
                    code="legacy_tasks.missing",
                    severity=SEVERITY_ERROR,
                    scope="legacy_tasks",
                    detail=f"legacy task file missing at {rel}",
                    asset=rel,
                    location={"combination_id": combo["combination_id"]},
                )
            )
            entry["files"][alias] = file_entry
            continue
        file_entry["sha256"] = sha256_file(path)
        count = 0
        with_test = 0
        field_counter: Counter[tuple[str, ...]] = Counter()
        ids: list[str] = []
        for lineno, obj in _iter_jsonl_lenient(
            path, ctx, rel, code_prefix="legacy_tasks"
        ):
            count += 1
            field_counter[tuple(sorted(obj))] += 1
            if obj.get("test"):
                with_test += 1
            if isinstance(obj.get("task_id"), str):
                ids.append(obj["task_id"])
        file_entry.update(
            line_count=count,
            with_test=with_test,
            field_sets=[list(fs) for fs in field_counter],
            unique_task_ids=len(set(ids)),
            task_ids_sha256=sha256_bytes(canonical_json_bytes(ids)),
        )
        if with_test == 0:
            ctx.add(
                Issue(
                    code="legacy_tasks.no_test",
                    severity=SEVERITY_WARNING,
                    scope="legacy_tasks",
                    detail=(
                        f"legacy file {rel} has no test field; standard schema test "
                        "must come from the routed BigCodeBench file"
                    ),
                    asset=rel,
                    location={"combination_id": combo["combination_id"]},
                )
            )
        entry["files"][alias] = file_entry
    return entry


def inspect_history_runs(ctx: AuditContext) -> dict[str, Any]:
    rel = ctx.config["history_runs_dir"]
    directory = resolve_within(ctx.assets_root, rel)
    entry: dict[str, Any] = {"path": rel}
    if not directory.is_dir():
        ctx.add(
            Issue(
                code="history_runs.missing",
                severity=SEVERITY_ERROR,
                scope="history_runs",
                detail=f"historical runs directory missing at {rel}",
                asset=rel,
            )
        )
        return entry

    model_dirs = sorted(child.name for child in directory.iterdir() if child.is_dir())
    entry["model_dirs"] = model_dirs
    runs: list[dict[str, Any]] = []
    record_field_sets: Counter[tuple[str, ...]] = Counter()
    for run_dir in sorted(path for path in directory.glob("*/*/*") if path.is_dir()):
        run_entry: dict[str, Any] = {"path": relative_to_root(directory, run_dir)}
        for label, candidate in (
            ("run_config", "inputs/run_config.json"),
            ("task_subset", "inputs/task_subset.jsonl"),
            ("generations", "outputs/generations.jsonl"),
            ("records", "eval/records.jsonl"),
            ("summary", "eval/summary.json"),
            ("passk", "eval/passk_results.json"),
            ("asr", "eval/asr_results.json"),
        ):
            run_entry[label] = (run_dir / candidate).is_file()
        records_path = run_dir / "eval/records.jsonl"
        if records_path.is_file():
            fields = _first_record_fields(records_path)
            run_entry["records_fields"] = sorted(fields)
            record_field_sets[tuple(sorted(fields))] += 1
        runs.append(run_entry)

    entry["run_count"] = len(runs)
    entry["files_present"] = {
        label: sum(1 for run in runs if run.get(label))
        for label in (
            "run_config",
            "task_subset",
            "generations",
            "records",
            "summary",
            "passk",
            "asr",
        )
    }
    entry["record_field_sets"] = [list(fs) for fs in record_field_sets]
    structured_verdict_fields = {"verdict", "oracle_id", "target_present"}
    entry["structured_verdict_available"] = any(
        structured_verdict_fields & set(fs) for fs in record_field_sets
    )
    entry["runs"] = runs
    if not entry["structured_verdict_available"] and runs:
        ctx.add(
            Issue(
                code="history_runs.boolean_hit_only",
                severity=SEVERITY_WARNING,
                scope="history_runs",
                detail=(
                    "historical eval/records.jsonl provide boolean asr_hit plus "
                    "asr_evidence, but no task-book structured verdict fields "
                    "(verdict/oracle_id/target_present/oracle_layer); historical "
                    "diffing compares the hit boolean and sample/denominator sets, "
                    "while the structured verdict vocabulary applies to new runs only"
                ),
                asset=rel,
                evidence=(
                    "record field sets: "
                    + str([list(fs) for fs in list(record_field_sets)[:6]])
                ),
            )
        )
    return entry


def _first_record_fields(path: Path) -> set[str]:
    fields: set[str] = set()
    checked = 0
    with open(path, "rb") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                fields.update(obj)
                checked += 1
            if checked >= 3:
                break
    return fields


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def collect_environment(ctx: AuditContext) -> dict[str, Any]:
    repo_dir = ctx.repo_dir
    commit = _git(["rev-parse", "HEAD"], repo_dir)
    describe = _git(["describe", "--tags", "--always", "--dirty"], repo_dir)
    status = _git(["status", "--porcelain"], repo_dir)
    dirty_entries = len([line for line in status.splitlines() if line.strip()]) if status is not None else None

    lock_path = repo_dir / "uv.lock"
    lock = None
    if lock_path.is_file():
        lock = {"path": "uv.lock", "sha256": sha256_file(lock_path)}

    environment: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "python": {
            "version": sys.version.split()[0],
            "full_version": sys.version,
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "platform": platform.platform(),
        },
        "dspy": {
            "git_commit": commit,
            "git_describe": describe,
            "worktree_dirty": bool(dirty_entries) if dirty_entries is not None else None,
            "dirty_entry_count": dirty_entries,
            "source_dir": str((repo_dir / "dspy").resolve()),
            "installed_distribution_version": _distribution_version("dspy"),
        },
        "lockfile": lock,
        "tracked_distributions": {
            name: _distribution_version(name) for name in TRACKED_DISTRIBUTIONS
        },
        "soft_tools": {
            name: {"available": shutil.which(name) is not None}
            for name in SOFT_TOOLS
        },
    }

    # Verify the advertised revision against the worktree without exporting
    # full diff contents.
    if describe and "dirty" in describe:
        ctx.add(
            Issue(
                code="environment.dirty_worktree",
                severity=SEVERITY_WARNING,
                scope="environment",
                detail=(
                    "DSPy worktree is dirty relative to its tags; recorded revision "
                    "may not reproduce exactly"
                ),
                asset="environment",
                evidence=f"git describe: {describe}",
            )
        )
    return environment


# --------------------------------------------------------------------------- #
# Orchestration, manifest and report
# --------------------------------------------------------------------------- #


def build_manifest(
    ctx: AuditContext,
    registry_entry: dict[str, Any],
    oracle_shared_entry: dict[str, Any],
    selection_entries: dict[str, Any],
    combo_entries: dict[str, Any],
    reference_eval_entry: dict[str, Any],
    legacy_entry: dict[str, Any],
    history_entry: dict[str, Any],
    python_requirements: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "standard_schema": {
            "name": STANDARD_SCHEMA_NAME,
            "fields": list(STANDARD_SCHEMA),
            "required_nonempty": list(REQUIRED_NONEMPTY),
        },
        "config": {
            "path": config_asset(ctx),
            "sha256": sha256_file(ctx.config_path),
            "combination_count": len(ctx.config["combinations"]),
        },
        "registry": registry_entry,
        "oracle_shared": oracle_shared_entry,
        "selection_files": selection_entries,
        "combinations": combo_entries,
        "python_requirements": python_requirements,
        "reference_eval": reference_eval_entry,
        "legacy_tasks": legacy_entry,
        "history_runs": history_entry,
    }


def render_report(
    manifest: dict[str, Any],
    environment: dict[str, Any],
    issues: list[Issue],
) -> str:
    lines: list[str] = []
    lines.append("# Asset audit report")
    lines.append("")
    lines.append(
        "Read-only audit of the CoCo-Attack rebuild inputs. No data was modified, "
        "no oracle was executed, no model or cache was used."
    )
    lines.append("")

    lines.append("## Environment")
    lines.append("")
    python_info = environment["python"]
    dspy_info = environment["dspy"]
    lines.append(f"- Python: {python_info['version']} ({python_info['implementation']})")
    lines.append(f"- Interpreter: `{python_info['executable']}`")
    lines.append(f"- Platform: {python_info['platform']}")
    lines.append(
        f"- DSPy commit: `{dspy_info['git_commit']}` "
        f"(describe: `{dspy_info['git_describe']}`, dirty={dspy_info['worktree_dirty']})"
    )
    lines.append(
        f"- DSPy distribution version: {dspy_info['installed_distribution_version']}"
    )
    unavailable = [
        name
        for name, info in environment["soft_tools"].items()
        if not info["available"]
    ]
    lines.append(
        "- Soft tools unavailable (later-stage limitation): "
        + (", ".join(unavailable) if unavailable else "none")
    )
    lines.append("")

    lines.append("## Asset inventory")
    lines.append("")
    lines.append(
        "| Combination | Oracle | Tasks | Non-empty test | Few-shot eval | Selected examples | Coverage |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---|")
    for combination_id, entry in manifest["combinations"].items():
        task = entry.get("task") or {}
        clean = entry.get("clean_assets") or {}
        eval_count = len(clean.get("fewshot_test_ids") or []) if clean else "n/a"
        example_count = len(clean.get("fewshot_ids") or []) if clean else "n/a"
        coverage = entry.get("coverage") or {}
        coverage_text = ", ".join(
            layer for layer, enabled in coverage.items() if enabled
        )
        lines.append(
            f"| {combination_id} | {entry.get('oracle_id')} | "
            f"{task.get('unique_task_ids', 'n/a')} | {task.get('nonempty_test_records', 'n/a')} | "
            f"{eval_count} | {example_count} | {coverage_text or '—'} |"
        )
    lines.append("")

    lines.append("## Oracle calibration records")
    lines.append("")
    lines.append("| Combination | Oracle | Reference total | Agreements | Path |")
    lines.append("|---|---|---:|---:|---|")
    for combination_id, entry in manifest["combinations"].items():
        oracle = entry.get("oracle") or {}
        reference = oracle.get("reference") or {}
        lines.append(
            f"| {combination_id} | {oracle.get('oracle_id')} | "
            f"{reference.get('total', 'n/a')} | {reference.get('agreements', 'n/a')} | "
            f"`{reference.get('path', 'missing')}` |"
        )
    lines.append("")

    lines.append("## Python dependency inventory (Docker planning)")
    lines.append("")
    aggregate = manifest.get("python_requirements", {}).get("aggregate", {})
    if aggregate:
        lines.append(
            "Libraries referenced by standard tasks' `libs` metadata "
            "(count = task records):"
        )
        lines.append("")
        for library, count in aggregate.items():
            lines.append(f"- `{library}`: {count}")
    else:
        lines.append("No `libs` metadata could be aggregated.")
    lines.append("")

    lines.append("## Problems and differences")
    lines.append("")
    if not issues:
        lines.append("No blocking problem or pending-decision difference was found.")
    else:
        counts = Counter(issue.severity for issue in issues)
        lines.append(
            f"Totals: errors={counts.get(SEVERITY_ERROR, 0)}, "
            f"warnings={counts.get(SEVERITY_WARNING, 0)}, "
            f"pending_decision={counts.get(SEVERITY_PENDING_DECISION, 0)}"
        )
        lines.append("")
        for severity, title in (
            (SEVERITY_ERROR, "Errors"),
            (SEVERITY_PENDING_DECISION, "Pending user decision"),
            (SEVERITY_WARNING, "Warnings"),
        ):
            subset = [issue for issue in issues if issue.severity == severity]
            if not subset:
                continue
            lines.append(f"### {title}")
            lines.append("")
            for issue in subset:
                location = ", ".join(f"{k}={v}" for k, v in issue.location.items())
                suffix = f" ({location})" if location else ""
                evidence = f" — evidence: {issue.evidence}" if issue.evidence else ""
                lines.append(
                    f"- `{issue.code}` {issue.detail}{suffix}{evidence}"
                )
            lines.append("")
    lines.append("")
    lines.append(
        "The audit does not repair data, fill missing test fields, re-select examples "
        "or change metric definitions. Differences above are reported for review."
    )
    lines.append("")
    return "\n".join(lines)


def run_audit(
    repo_dir: Path,
    assets_dir: Path,
    output_dir: Path,
    config_dir: Path | None = None,
) -> int:
    config, config_path = load_combinations_config(config_dir)
    ctx = AuditContext(
        repo_dir=repo_dir,
        assets_root=assets_dir,
        output_dir=output_dir,
        config_dir=config_path.parent,
        config_path=config_path,
        config=config,
    )

    validate_config(ctx)
    registry_entry, _, taxonomy = inspect_registry(ctx)
    oracle_shared_entry = inspect_oracle_shared(ctx)
    selection_entries = inspect_selection_files(ctx)

    standard_counts: dict[str, int] = {}
    combo_entries: dict[str, Any] = {}
    for combo in ctx.config["combinations"]:
        combination_id = combo["combination_id"]
        routed_definition = (registry_entry.get("routed_definitions") or {}).get(
            combination_id
        )
        task_entry = inspect_task_file(ctx, combo, taxonomy, routed_definition)
        standard_counts[combination_id] = task_entry.get("unique_task_ids", 0)
        legacy_selected = None
        if combo.get("legacy_alias"):
            legacy_selected = (selection_entries.get("legacy") or {}).get("selected", {}).get(
                combo["legacy_alias"]
            )
        clean_entry = inspect_clean_assets(ctx, combo, legacy_selected)
        oracle_entry = inspect_oracle(ctx, combo)
        combo_entries[combination_id] = {
            "combination_id": combination_id,
            "registry_id": combo["registry_id"],
            "oracle_id": combo["oracle_id"],
            "legacy_alias": combo.get("legacy_alias"),
            "task_file": combo["task_file"],
            "selection": combo["selection"],
            "coverage": combo["coverage"],
            "task": task_entry,
            "clean_assets": clean_entry,
            "oracle": oracle_entry,
        }

    reference_eval_entry = inspect_reference_eval(ctx, standard_counts)
    legacy_entry = inspect_legacy_tasks(ctx)
    history_entry = inspect_history_runs(ctx)
    python_requirements = inspect_python_requirements(ctx)
    environment = collect_environment(ctx)

    manifest = build_manifest(
        ctx,
        registry_entry,
        oracle_shared_entry,
        selection_entries,
        combo_entries,
        reference_eval_entry,
        legacy_entry,
        history_entry,
        python_requirements,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output_dir / "asset_manifest.json", manifest)
    write_json_atomic(output_dir / "environment.json", environment)
    write_json_atomic(
        output_dir / "issues.json",
        {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "issues": [issue.to_json() for issue in ctx.issues],
        },
    )
    write_text_atomic(
        output_dir / "REPORT.md",
        render_report(manifest, environment, ctx.issues),
    )

    from .issues import issues_exit_code

    return issues_exit_code(ctx.issues)
