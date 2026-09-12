"""Orchestration for ``coco-attack prepare-data``.

The command validates every requested combination in memory first. Only when
all of them pass does it publish the per-combination snapshots and the
completion manifest; otherwise it writes diagnostics and leaves no dataset that
could be mistaken for a successful preparation.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from ..assets.artifacts import assert_fresh_dir, read_json, sha256_bytes
from ..assets.issues import SEVERITY_ERROR, Issue, issues_exit_code
from ..protocol.stages import (
    DATA_CONTRACT_VERSION,
    PREPARE_SCHEMA_VERSION,
    SPLIT_ALGORITHM_VERSION,
    SplitMode,
)
from .combination import load_combination_specs, resolve_combination_selection
from .contracts import (
    DataContractError,
    DatasetSelection,
    LoadedTasks,
    SplitManifest,
)
from .loader import load_tasks
from .selection import prepare_selection
from .snapshot import (
    write_errors,
    write_manifest,
    write_report,
    write_selection,
    write_split,
    write_tasks_jsonl,
)
from .split import build_split, validate_split_config_combinations


def prepare_data(
    repo_dir: Path,
    assets_root: Path,
    output_dir: Path,
    split_config_path: Path,
    requested_combinations: list[str],
    config_dir: Path | None = None,
) -> int:
    if not split_config_path.is_file():
        raise FileNotFoundError(f"split config not found: {split_config_path}")

    assert_fresh_dir(output_dir)
    specs, _config_path, taxonomy = load_combination_specs(assets_root, config_dir)
    combination_ids = resolve_combination_selection(specs, requested_combinations)

    split_config_bytes = split_config_path.read_bytes()
    split_config_sha256 = sha256_bytes(split_config_bytes)
    split_config = read_json(split_config_path)
    if split_config.get("schema_version") not in (None, "1"):
        raise DataContractError(
            f"unsupported split config schema {split_config.get('schema_version')!r}",
            [
                Issue(
                    code="split.unsupported_schema",
                    severity=SEVERITY_ERROR,
                    scope="split",
                    detail=f"unsupported split config schema {split_config.get('schema_version')!r}",
                    asset=split_config_path.name,
                )
            ],
        )
    validate_split_config_combinations(split_config, set(specs))

    prepared: dict[str, tuple[LoadedTasks, DatasetSelection, SplitManifest]] = {}
    issues: list[Issue] = []
    for combination_id in combination_ids:
        spec = specs[combination_id]
        try:
            loaded = load_tasks(spec, assets_root, taxonomy)
            selection = prepare_selection(spec, loaded, assets_root)
            split = build_split(selection, split_config, split_config_sha256)
        except DataContractError as error:
            issues.extend(error.issues)
            continue
        issues.extend(loaded.issues)
        prepared[combination_id] = (loaded, selection, split)

    if issues_exit_code(issues) != 0:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_errors(
            output_dir / "prepare_errors.json",
            {
                "schema_version": PREPARE_SCHEMA_VERSION,
                "status": "failed",
                "data_contract": DATA_CONTRACT_VERSION,
                "split_config_sha256": split_config_sha256,
                "requested_combinations": combination_ids,
                "issues": [issue.to_json() for issue in issues],
            },
        )
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    combination_manifest: dict[str, Any] = {}
    for combination_id in combination_ids:
        loaded, selection, split = prepared[combination_id]
        spec = loaded.spec
        combo_dir = output_dir / combination_id
        combo_dir.mkdir(parents=True, exist_ok=True)
        tasks_hash = write_tasks_jsonl(combo_dir / "tasks.jsonl", loaded.records)
        selection_hash = write_selection(combo_dir / "selection.json", selection)
        split_hash = write_split(combo_dir / "split.json", split)
        combination_manifest[combination_id] = {
            "registry_id": spec.registry_id,
            "oracle_id": spec.oracle_id,
            "task_file": spec.task_file,
            "task_count": len(loaded.records),
            "example_count": len(selection.example_ids),
            "evaluation_count": len(selection.evaluation_ids),
            "mode": split.mode.value,
            "seed": split.seed,
            "search_count": len(split.search_ids),
            "holdout_count": len(split.holdout_ids),
            "files": {
                "tasks.jsonl": tasks_hash,
                "selection.json": selection_hash,
                "split.json": split_hash,
            },
        }

    manifest = {
        "schema_version": PREPARE_SCHEMA_VERSION,
        "data_contract": DATA_CONTRACT_VERSION,
        "completion": "complete",
        "split_config": {
            "name": split_config_path.name,
            "sha256": split_config_sha256,
            "algorithm_version": split_config.get(
                "algorithm_version", SPLIT_ALGORITHM_VERSION
            ),
        },
        "source_revision": {"dspy_git_commit": _git_commit(repo_dir)},
        "combinations": combination_manifest,
    }
    report = render_prepare_report(
        combination_ids, prepared, issues, repo_dir
    )
    write_report(output_dir / "REPORT.md", report)
    write_manifest(output_dir / "manifest.json", manifest)
    return 0


def render_prepare_report(
    combination_ids: list[str],
    prepared: dict[str, tuple[LoadedTasks, DatasetSelection, SplitManifest]],
    issues: list[Issue],
    repo_dir: Path,
) -> str:
    lines: list[str] = []
    lines.append("# Data preparation report")
    lines.append("")
    lines.append(
        "Strictly validated, deterministic task snapshots, example/evaluation "
        "selections and split manifests. Source assets were read-only."
    )
    lines.append("")
    lines.append(f"- Data contract: `{DATA_CONTRACT_VERSION}`")
    lines.append(f"- Split algorithm: `{SPLIT_ALGORITHM_VERSION}`")
    lines.append(f"- DSPy commit: `{_git_commit(repo_dir)}`")
    lines.append("")
    lines.append("## Combinations")
    lines.append("")
    lines.append("| Combination | Tasks | Examples | Evaluation | Mode | Search | Holdout |")
    lines.append("|---|---:|---:|---:|---|---:|---:|")
    for combination_id in combination_ids:
        loaded, selection, split = prepared[combination_id]
        lines.append(
            f"| {combination_id} | {len(loaded.records)} | {len(selection.example_ids)} | "
            f"{len(selection.evaluation_ids)} | {split.mode.value} | "
            f"{len(split.search_ids)} | {len(split.holdout_ids)} |"
        )
    lines.append("")
    lines.append("## Provenance")
    lines.append("")
    for combination_id in combination_ids:
        loaded, selection, split = prepared[combination_id]
        lines.append(
            f"- `{combination_id}`: task file `{loaded.spec.task_file}` "
            f"(sha256 `{loaded.file_sha256[:12]}…`), selection `{selection.selection_file}`, "
            f"snapshot `{selection.task_snapshot_sha256[:12]}…`"
        )
    lines.append("")

    lines.append("## Split details")
    lines.append("")
    for combination_id in combination_ids:
        _loaded, _selection, split = prepared[combination_id]
        if split.mode is SplitMode.SEARCH_HOLDOUT:
            lines.append(
                f"- `{combination_id}` search ({len(split.search_ids)}): "
                + ", ".join(split.search_ids)
            )
            lines.append(
                f"- `{combination_id}` holdout ({len(split.holdout_ids)}): "
                + ", ".join(split.holdout_ids)
            )
        else:
            lines.append(
                f"- `{combination_id}` whole-set ({len(split.input_ids)} ids); "
                "no holdout exists"
            )
    lines.append("")

    lines.append("## Notices")
    lines.append("")
    if not issues:
        lines.append("No warnings.")
    else:
        counts = Counter(issue.severity for issue in issues)
        lines.append(f"Totals: {dict(counts)}")
        lines.append("")
        for issue in issues:
            location = ", ".join(f"{k}={v}" for k, v in issue.location.items())
            suffix = f" ({location})" if location else ""
            lines.append(f"- `{issue.code}` {issue.detail}{suffix}")
    lines.append("")
    lines.append(
        "No holdout evaluation was performed. Producing a split manifest does not "
        "grant the search process access to holdout."
    )
    lines.append("")
    return "\n".join(lines)


def _git_commit(repo_dir: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


__all__ = ["prepare_data", "render_prepare_report"]
