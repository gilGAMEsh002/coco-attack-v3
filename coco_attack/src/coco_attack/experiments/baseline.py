"""Baseline preparation and startup-condition checks (phase 03, sub-task 01).

``prepare_baseline`` builds a fresh, reviewable baseline root: fixed data/prompt
input snapshots, the run manifest, one pipeline config per run and the cwe078
lock.  It never issues a model request.  ``check_baseline`` re-verifies the
inputs, configs, version freeze, Docker/image identity, DMX key presence and
evaluator tool availability, and writes a machine-readable plus Markdown report.

Exit codes mirror the CLI: ``0`` ok, ``1`` blocking, ``2`` usage.
"""

from __future__ import annotations

import importlib.metadata
import json
import platform
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    assert_fresh_dir,
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    sha256_text,
    write_json_atomic,
    write_text_atomic,
)
from ..assets.paths import default_config_dir, resolve_within
from ..data.combination import load_combination_specs
from ..data.prepare import prepare_data
from ..data.snapshot import load_prepared_data
from ..evaluation.cleaning import CLEANER_VERSION
from ..evaluation.functional import HARNESS_VERSION
from ..evaluation.judge import JUDGE_DETECTION_VERSION, JUDGE_PROMPT_VERSION
from ..evaluation.run_static import STATIC_SHELL_VERSION
from ..evaluation.sast import (
    rule_mapping_trace,
    sast_coverage_matrix,
    tool_available,
    validate_semgrep_mapping,
)
from ..evaluation.static import oracle_fingerprint
from ..execution.contracts import ExecutionProfile
from ..prompts.markdown import CLEAN_FORMS, MATERIALIZE_VERSION
from ..prompts.materialize import materialize_combination, task_id_to_prompt_filename
from ..protocol.stages import DATA_CONTRACT_VERSION, SPLIT_ALGORITHM_VERSION, SplitMode
from .configgen import check_unit_configs, write_unit_configs
from .manifest import build_manifest, load_manifest, write_manifest
from .matrix import (
    EXPECTED_TASK_COUNTS,
    LOCK_COMBINATION,
    LOCKED_HOLDOUT_COUNT,
    LOCKED_SEARCH_COUNT,
    LOCK_REF,
    MatrixConfig,
    MatrixError,
    expand_units,
    load_matrix_config,
)

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_USAGE = 2

BASELINE_LOCK_SCHEMA_VERSION = "baseline-lock-v1"
ASSET_MANIFEST_SCHEMA_VERSION = "baseline-asset-manifest-v1"
BASELINE_CHECK_SCHEMA_VERSION = "baseline-check-v1"

_TRACKED_CODE_PATHS = ("coco_attack", "dspy")
_ZERO_IMAGE_ID = "sha256:" + "0" * 64


class BaselineError(Exception):
    """Base class for baseline preparation/check failures."""

    exit_code = EXIT_BLOCKING

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class BaselineUsageError(BaselineError):
    exit_code = EXIT_USAGE


class BaselineBlockedError(BaselineError):
    exit_code = EXIT_BLOCKING


# --------------------------------------------------------------------------- #
# Small subprocess/dotenv helpers (never execute the .env file)
# --------------------------------------------------------------------------- #


def _run(argv: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def git_commit(repo_dir: Path) -> str | None:
    proc = _run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"])
    if proc.returncode != 0:
        raise BaselineBlockedError(
            f"git rev-parse HEAD failed in {repo_dir}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip() or None


def git_worktree_status(repo_dir: Path) -> dict[str, Any]:
    """Tracked-code dirty state for ``coco_attack``/``dspy`` (order-insensitive)."""

    proc = _run(
        ["git", "-C", str(repo_dir), "status", "--porcelain", "--", *_TRACKED_CODE_PATHS]
    )
    if proc.returncode != 0:
        raise BaselineBlockedError(
            f"git status failed in {repo_dir}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    lines = sorted(line for line in (proc.stdout or "").splitlines() if line.strip())
    text = "\n".join(lines)
    return {
        "dirty": bool(lines),
        "status_sha256": sha256_text(text),
        "status_lines": lines,
    }


def code_tree_changed_since(repo_dir: Path, base_commit: str | None) -> bool | None:
    """Whether ``coco_attack``/``dspy`` differ from ``base_commit``.

    Compares the recorded baseline commit against the current worktree, so a
    later doc-only commit does not count as a version change (plan §5.2.5).
    Returns ``None`` when the comparison cannot be made.
    """

    if not base_commit:
        return None
    proc = _run(
        ["git", "-C", str(repo_dir), "diff", "--quiet", base_commit, "--", *_TRACKED_CODE_PATHS]
    )
    if proc.returncode == 0:
        return False
    if proc.returncode == 1:
        return True
    return None


def parse_dotenv(path: Path | str) -> dict[str, str]:
    """Parse a dotenv-style file without executing it (supports ``export``)."""

    values: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def _docker_available() -> tuple[bool, str | None]:
    try:
        proc = _run(["docker", "info"], timeout=30.0)
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"{type(error).__name__}: {error}"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return False, detail[-500:] or "docker info exited non-zero"
    return True, None


def _docker_image_id(reference: str) -> str | None:
    try:
        proc = _run(["docker", "image", "inspect", reference], timeout=30.0)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    image_id = payload[0].get("Id")
    return image_id if isinstance(image_id, str) and image_id else None


def _declared_image_digest(matrix: MatrixConfig, profile: ExecutionProfile | None) -> str | None:
    candidates: list[str] = []
    if (
        isinstance(matrix.image_digest, str)
        and matrix.image_digest.startswith("sha256:")
        and matrix.image_digest != _ZERO_IMAGE_ID
    ):
        candidates.append(matrix.image_digest)
    if profile is not None:
        image_id = profile.image.image_id
        if isinstance(image_id, str) and image_id and image_id != _ZERO_IMAGE_ID:
            candidates.append(image_id)
    return candidates[0] if candidates else None


# --------------------------------------------------------------------------- #
# Version fingerprint
# --------------------------------------------------------------------------- #


def collect_version_fingerprint(matrix: MatrixConfig) -> dict[str, Any]:
    """Deterministic version/input fingerprint (timestamps never enter hashes)."""

    repo_dir = Path(matrix.repo_dir)
    assets_dir = Path(matrix.assets_dir)
    status = git_worktree_status(repo_dir)
    specs, _config_path, _taxonomy = load_combination_specs(assets_dir)

    oracles: dict[str, Any] = {}
    task_files: dict[str, Any] = {}
    for combination_id in matrix.combinations:
        spec = specs.get(combination_id)
        if spec is None:
            raise MatrixError(f"combination {combination_id!r} is not routed in the asset registry")
        oracles[combination_id] = oracle_fingerprint(assets_dir, spec.oracle_id)
        task_path = resolve_within(assets_dir, spec.task_file)
        if not task_path.is_file():
            raise BaselineBlockedError(f"task file missing for {combination_id}: {task_path}")
        task_files[combination_id] = {
            "task_file": spec.task_file,
            "sha256": sha256_file(task_path),
        }

    try:
        dspy_version = importlib.metadata.version("dspy")
    except importlib.metadata.PackageNotFoundError:
        dspy_version = None

    return {
        "python_version": platform.python_version(),
        "dspy_version": dspy_version,
        "git_commit": git_commit(repo_dir),
        "worktree_dirty": status["dirty"],
        "worktree_status_sha256": status["status_sha256"],
        "data_contract": DATA_CONTRACT_VERSION,
        "split_algorithm": SPLIT_ALGORITHM_VERSION,
        "prompt_version": matrix.prompt_version,
        "materialize_version": MATERIALIZE_VERSION,
        "cleaner_version": CLEANER_VERSION,
        "static_shell_version": STATIC_SHELL_VERSION,
        "harness_version": HARNESS_VERSION,
        "judge_prompt_version": JUDGE_PROMPT_VERSION,
        "judge_detection_version": JUDGE_DETECTION_VERSION,
        "image_digest": matrix.image_digest,
        "oracles": oracles,
        "task_files": task_files,
    }


# --------------------------------------------------------------------------- #
# prepare-baseline
# --------------------------------------------------------------------------- #


def known_limitations_for(combination_id: str) -> list[str]:
    """Documented, stage-01-recorded limitations carried into the manifest."""

    limitations: list[str] = []
    if combination_id in ("cwe295-0", "cwe502-0"):
        limitations.append(
            "stage-01: legacy BigCodeBench/215 prompt uses 'Thif function' vs "
            "standard 'This function'; recorded in prompt_diffs.json, not repaired"
        )
    if combination_id == LOCK_COMBINATION:
        limitations.append(
            "stage-01 D05: cwe078-0 static oracle v2 (branch-aware); ASR is defined "
            "as v2 and cross-version comparisons must note the oracle version"
        )
    return limitations


def _validate_matrix_paths(matrix: MatrixConfig) -> None:
    execution_config = Path(matrix.execution_config).expanduser()
    if not execution_config.is_file():
        raise BaselineUsageError(f"matrix.execution_config is not a file: {execution_config}")
    repo_dir = Path(matrix.repo_dir).expanduser()
    if not repo_dir.is_dir() or not (repo_dir / "dspy").is_dir():
        raise BaselineUsageError(
            f"matrix.repo_dir must be a directory containing dspy/: {repo_dir}"
        )
    assets_dir = Path(matrix.assets_dir).expanduser()
    if not assets_dir.is_dir() or not (assets_dir / "oracles").is_dir():
        raise BaselineUsageError(
            f"matrix.assets_dir must be a directory containing oracles/: {assets_dir}"
        )


def _validate_prepared(combination_id: str, prepared: Any) -> None:
    expected = EXPECTED_TASK_COUNTS[combination_id]
    actual = len(prepared.selection.evaluation_ids)
    if actual != expected:
        raise BaselineBlockedError(
            f"{combination_id}: EXPECTED_TASK_COUNTS says {expected} evaluation tasks, "
            f"prepared data has {actual}; the task set must not be adjusted"
        )
    # For a search/holdout split ``split.evaluation_ids`` is intentionally empty;
    # the full evaluation set lives in ``split.input_ids`` (see data/split.py).
    if len(prepared.split.input_ids) != expected:
        raise BaselineBlockedError(
            f"{combination_id}: split input_ids has "
            f"{len(prepared.split.input_ids)} tasks, expected {expected}"
        )
    if combination_id == LOCK_COMBINATION:
        if prepared.split.mode is not SplitMode.SEARCH_HOLDOUT:
            raise BaselineBlockedError(
                f"{combination_id}: expected a search_holdout split, got {prepared.split.mode.value}"
            )
        search_count = len(prepared.split.search_ids)
        holdout_count = len(prepared.split.holdout_ids)
        if search_count != LOCKED_SEARCH_COUNT or holdout_count != LOCKED_HOLDOUT_COUNT:
            raise BaselineBlockedError(
                f"{combination_id}: expected split search={LOCKED_SEARCH_COUNT}/"
                f"holdout={LOCKED_HOLDOUT_COUNT}, got search={search_count}/holdout={holdout_count}"
            )


def _validate_prompt_manifest(
    prompt_root: Path,
    combination_id: str,
    matrix: MatrixConfig,
    prepared: Any,
) -> None:
    manifest_path = prompt_root / "manifest.json"
    if not manifest_path.is_file():
        raise BaselineBlockedError(f"prompt manifest missing: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("completion") != "complete":
        raise BaselineBlockedError(f"{combination_id}: prompt manifest is not complete")
    if manifest.get("combination_id") != combination_id:
        raise BaselineBlockedError(
            f"{combination_id}: prompt manifest combination_id is {manifest.get('combination_id')!r}"
        )
    if str(manifest.get("prompt_version")) != str(matrix.prompt_version):
        raise BaselineBlockedError(
            f"{combination_id}: prompt manifest prompt_version "
            f"{manifest.get('prompt_version')!r} != matrix {matrix.prompt_version!r}"
        )
    forms = manifest.get("forms") or {}
    if set(forms) != set(CLEAN_FORMS):
        raise BaselineBlockedError(
            f"{combination_id}: prompt manifest forms {sorted(forms)} != {sorted(CLEAN_FORMS)}"
        )
    evaluation_ids = set(prepared.selection.evaluation_ids)
    example_ids = set(prepared.selection.example_ids)
    for form in CLEAN_FORMS:
        form_entry = forms[form]
        hashes = form_entry.get("prompt_hashes") or {}
        if set(hashes) != evaluation_ids:
            raise BaselineBlockedError(
                f"{combination_id}/{form}: prompt_hashes keys do not equal the evaluation id set"
            )
        meta_path = prompt_root / combination_id / form / "meta.json"
        if not meta_path.is_file():
            raise BaselineBlockedError(f"{combination_id}/{form}: meta.json missing")
        meta = read_json(meta_path)
        attack_config = meta.get("attack_config") or {}
        if attack_config.get("enabled") is not False:
            raise BaselineBlockedError(
                f"{combination_id}/{form}: attack_config.enabled must be False (clean baseline)"
            )
        meta_examples = set(meta.get("example_ids") or [])
        meta_evaluation = set(meta.get("evaluation_ids") or [])
        if meta_examples & meta_evaluation:
            raise BaselineBlockedError(
                f"{combination_id}/{form}: example_ids must be disjoint from evaluation_ids"
            )
        if not meta_examples.issubset(example_ids):
            raise BaselineBlockedError(
                f"{combination_id}/{form}: meta example_ids are not the prepared selection"
            )
        if sha256_file(meta_path) != form_entry.get("meta_sha256"):
            raise BaselineBlockedError(
                f"{combination_id}/{form}: meta.json sha256 does not match prompt manifest"
            )


def _write_lock(
    root: Path,
    matrix: MatrixConfig,
    fingerprint: dict[str, Any],
    units: tuple[Any, ...],
    prompts_root: Path,
) -> None:
    if LOCK_COMBINATION not in matrix.combinations:
        return
    combo_units = [unit for unit in units if unit.combination_id == LOCK_COMBINATION]
    unit_ids = [unit.unit_id for unit in combo_units]
    if len(unit_ids) != len(CLEAN_FORMS) * 2:
        raise BaselineBlockedError(
            f"{LOCK_COMBINATION}: expected {len(CLEAN_FORMS) * 2} locked units, got {len(unit_ids)}"
        )

    prompt_manifest = read_json(prompts_root / LOCK_COMBINATION / "manifest.json")
    form_entries = prompt_manifest.get("forms") or {}
    prompt_hashes = {form: form_entries[form]["prompt_hashes"] for form in CLEAN_FORMS}
    meta_sha256 = {form: form_entries[form]["meta_sha256"] for form in CLEAN_FORMS}

    unit_configs: dict[str, dict[str, str]] = {}
    for unit in combo_units:
        runs: dict[str, str] = {}
        for entry in unit.entries:
            config_path = root / entry.config_path
            if not config_path.is_file():
                raise BaselineBlockedError(f"locked unit config missing: {config_path}")
            runs[entry.run_id] = sha256_file(config_path)
        unit_configs[unit.unit_id] = runs

    lock = {
        "schema_version": BASELINE_LOCK_SCHEMA_VERSION,
        "combination_id": LOCK_COMBINATION,
        "oracle_id": combo_units[0].oracle_id,
        "prompt_version": matrix.prompt_version,
        "prompt_hashes": prompt_hashes,
        "meta_sha256": meta_sha256,
        "unit_ids": unit_ids,
        "unit_configs": unit_configs,
        "victim_model": matrix.victim_model,
        "judge_model": matrix.judge_model,
        "max_tokens": matrix.max_tokens,
        "version_fingerprint": fingerprint,
        "locked_at": datetime.now(timezone.utc).isoformat(),
        "operator": matrix.operator,
        "basis": (
            "pre-holdout: cwe078 holdout was not sampled before this lock; "
            "whole-set results do not claim holdout validation"
        ),
    }
    write_json_atomic(root / LOCK_REF, lock)


def _write_asset_manifest(
    root: Path,
    matrix: MatrixConfig,
    fingerprint: dict[str, Any],
    prepared_by_combination: dict[str, Any],
    prompts_root: Path,
    specs: dict[str, Any],
    manifest_path: Path,
) -> None:
    data_dir = root / "inputs" / "data"
    entries: dict[str, Any] = {}
    for combination_id in matrix.combinations:
        prepared = prepared_by_combination[combination_id]
        spec = specs[combination_id]
        task_path = resolve_within(Path(matrix.assets_dir), spec.task_file)
        entries[combination_id] = {
            "oracle_id": prepared.oracle_id,
            "task_file": spec.task_file,
            "task_file_sha256": sha256_file(task_path),
            "task_count": len(prepared.records),
            "evaluation_count": len(prepared.selection.evaluation_ids),
            "selection_sha256": sha256_file(data_dir / combination_id / "selection.json"),
            "split_sha256": sha256_file(data_dir / combination_id / "split.json"),
            "prompt_manifest_sha256": sha256_file(prompts_root / combination_id / "manifest.json"),
            "forms": list(CLEAN_FORMS),
        }
    payload = {
        "schema_version": ASSET_MANIFEST_SCHEMA_VERSION,
        "assets_dir": matrix.assets_dir,
        "data_contract": DATA_CONTRACT_VERSION,
        "combinations": entries,
        "baseline_manifest_sha256": sha256_file(manifest_path),
        "version_fingerprint_sha256": sha256_bytes(canonical_json_bytes(fingerprint)),
    }
    write_json_atomic(root / "inputs" / "asset_manifest.json", payload)


def _prepare_baseline_impl(matrix_config_path: Path, baseline_root: Path) -> None:
    try:
        matrix = load_matrix_config(matrix_config_path)
    except MatrixError as error:
        raise BaselineUsageError(str(error)) from error

    root = baseline_root.expanduser().resolve()
    if matrix.baseline_root is not None:
        declared = Path(matrix.baseline_root).expanduser()
        try:
            declared = declared.resolve()
        except OSError as error:
            raise BaselineUsageError(f"cannot resolve matrix.baseline_root: {error}") from error
        if declared != root:
            raise BaselineUsageError(
                f"--output-dir {root} does not match matrix.baseline_root {declared}"
            )

    _validate_matrix_paths(matrix)
    matrix = replace(
        matrix,
        repo_dir=str(Path(matrix.repo_dir).expanduser().resolve()),
        assets_dir=str(Path(matrix.assets_dir).expanduser().resolve()),
        execution_config=str(Path(matrix.execution_config).expanduser().resolve()),
    )

    status = git_worktree_status(Path(matrix.repo_dir))
    if status["dirty"] and not matrix.allow_dirty_worktree:
        detail = "\n".join(status["status_lines"])
        raise BaselineBlockedError(
            "worktree has uncommitted changes under tracked code paths "
            f"{list(_TRACKED_CODE_PATHS)}; phase 03 §5.2.5 requires a frozen version "
            "(code commit + input snapshot hashes + evaluation versions). Commit the "
            "changes, or set allow_dirty_worktree=true in the matrix config as an "
            "explicit operator adjudication.\n" + detail
        )

    try:
        assert_fresh_dir(root)
    except (FileExistsError, NotADirectoryError) as error:
        raise BaselineUsageError(str(error)) from error
    root.mkdir(parents=True, exist_ok=True)

    data_dir = root / "inputs" / "data"
    split_config_path = (
        Path(matrix.split_config).expanduser()
        if matrix.split_config
        else default_config_dir() / "splits.json"
    )
    if not split_config_path.is_file():
        raise BaselineUsageError(f"split config not found: {split_config_path}")

    code = prepare_data(
        Path(matrix.repo_dir),
        Path(matrix.assets_dir),
        data_dir,
        split_config_path,
        list(matrix.combinations),
    )
    if code != 0:
        raise BaselineBlockedError(f"prepare-data exited {code}; baseline root is incomplete")

    prepared_by_combination: dict[str, Any] = {}
    for combination_id in matrix.combinations:
        prepared = load_prepared_data(data_dir, combination_id)
        _validate_prepared(combination_id, prepared)
        prepared_by_combination[combination_id] = prepared

    specs, _config_path, _taxonomy = load_combination_specs(Path(matrix.assets_dir))
    prompts_root = root / "inputs" / "prompts"
    for combination_id in matrix.combinations:
        prompt_root = prompts_root / combination_id
        materialize_combination(
            specs[combination_id],
            prepared_by_combination[combination_id],
            Path(matrix.assets_dir),
            list(CLEAN_FORMS),
            prompt_root,
            data_dir,
        )
        _validate_prompt_manifest(
            prompt_root, combination_id, matrix, prepared_by_combination[combination_id]
        )

    fingerprint = collect_version_fingerprint(matrix)
    try:
        units = expand_units(matrix, prepared_by_combination)
    except MatrixError as error:
        raise BaselineBlockedError(str(error)) from error

    manifest = build_manifest(matrix, units, fingerprint, root)
    for unit in units:
        limitations = known_limitations_for(unit.combination_id)
        manifest["units"][unit.unit_id]["known_limitations"] = limitations

    try:
        write_unit_configs(root, matrix, units)
        manifest_path = root / "manifest" / "run-manifest.json"
        write_manifest(manifest_path, manifest)
    except MatrixError as error:
        raise BaselineBlockedError(str(error)) from error

    _write_lock(root, matrix, fingerprint, units, prompts_root)
    _write_asset_manifest(
        root, matrix, fingerprint, prepared_by_combination, prompts_root, specs, manifest_path
    )


def prepare_baseline(matrix_config_path: Path | str, baseline_root: Path | str) -> int:
    """Build a fresh baseline root; returns 0 ok / 1 blocking / 2 usage."""

    try:
        _prepare_baseline_impl(Path(matrix_config_path), Path(baseline_root))
    except BaselineUsageError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except BaselineBlockedError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    return EXIT_OK


# --------------------------------------------------------------------------- #
# check-baseline
# --------------------------------------------------------------------------- #


def _verify_input_hashes(root: Path, manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    asset_path = root / "inputs" / "asset_manifest.json"
    if not asset_path.is_file():
        return [f"asset manifest missing: {asset_path}"]
    asset = read_json(asset_path)
    matrix = MatrixConfig.from_json(manifest["matrix"])
    assets_dir = Path(matrix.assets_dir)

    for combination_id, entry in (asset.get("combinations") or {}).items():
        data_dir = root / "inputs" / "data" / combination_id
        for name, field in (
            ("selection.json", "selection_sha256"),
            ("split.json", "split_sha256"),
        ):
            path = data_dir / name
            if not path.is_file():
                issues.append(f"{combination_id}: {name} missing")
            elif sha256_file(path) != entry.get(field):
                issues.append(f"{combination_id}: {name} hash differs from asset manifest")

        task_file = entry.get("task_file")
        if task_file:
            try:
                task_path = resolve_within(assets_dir, task_file)
            except (ValueError, OSError) as error:
                issues.append(f"{combination_id}: cannot resolve task file {task_file}: {error}")
            else:
                if not task_path.is_file():
                    issues.append(f"{combination_id}: task file missing: {task_file}")
                elif sha256_file(task_path) != entry.get("task_file_sha256"):
                    issues.append(f"{combination_id}: task file hash differs from asset manifest")

        prompts_root = root / "inputs" / "prompts" / combination_id
        prompt_manifest_path = prompts_root / "manifest.json"
        if not prompt_manifest_path.is_file():
            issues.append(f"{combination_id}: prompt manifest missing")
            continue
        if sha256_file(prompt_manifest_path) != entry.get("prompt_manifest_sha256"):
            issues.append(f"{combination_id}: prompt manifest hash differs from asset manifest")
        prompt_manifest = read_json(prompt_manifest_path)
        for form in entry.get("forms") or []:
            form_entry = (prompt_manifest.get("forms") or {}).get(form)
            if not form_entry:
                issues.append(f"{combination_id}/{form}: form missing from prompt manifest")
                continue
            for relative, digest in (form_entry.get("files") or {}).items():
                if relative.startswith("source::"):
                    continue
                file_path = prompts_root / relative
                if not file_path.is_file():
                    issues.append(f"{combination_id}/{form}: materialized file missing: {relative}")
                elif sha256_file(file_path) != digest:
                    issues.append(
                        f"{combination_id}/{form}: materialized file hash differs: {relative}"
                    )
            for task_id, digest in (form_entry.get("prompt_hashes") or {}).items():
                prompt_path = (
                    prompts_root
                    / combination_id
                    / form
                    / "test_prompts"
                    / task_id_to_prompt_filename(task_id)
                )
                if not prompt_path.is_file():
                    issues.append(f"{combination_id}/{form}: prompt file missing for {task_id}")
                elif sha256_file(prompt_path) != digest:
                    issues.append(
                        f"{combination_id}/{form}: prompt hash differs for {task_id}"
                    )
    return issues


def _evaluator_tool_report(
    matrix: MatrixConfig,
) -> tuple[dict[str, Any], list[str]]:
    report: dict[str, Any] = {}
    limitations: list[str] = []
    for combination_id in matrix.combinations:
        coverage = sast_coverage_matrix(combination_id, tuple(matrix.sast_tools))
        per_tool: dict[str, Any] = {}
        for tool in matrix.sast_tools:
            available = tool_available(tool, codeql_executable=matrix.codeql_executable)
            tool_coverage = coverage.get(tool) or {}
            covered = bool(tool_coverage.get("covered"))
            record: dict[str, Any] = {
                "available": available,
                "covered": covered,
                "target_rules": list(tool_coverage.get("target_rules") or []),
                "reason": None if covered else "target_rules_uncovered",
            }
            per_tool[tool] = record
            if not available:
                limitations.append(f"{combination_id}/{tool}: tool unavailable")
            if not covered:
                limitations.append(f"{combination_id}/{tool}: target_rules_uncovered")
        try:
            per_tool["rule_mapping_trace"] = rule_mapping_trace(combination_id)
        except (KeyError, ValueError) as error:
            per_tool["rule_mapping_trace_error"] = str(error)
            limitations.append(f"{combination_id}: rule mapping trace failed: {error}")
        report[combination_id] = per_tool

    if matrix.semgrep_config:
        rules_dir = Path(matrix.semgrep_config)
        if not rules_dir.is_dir():
            limitations.append(f"semgrep_config is not a directory: {rules_dir}")
        else:
            mismatches = validate_semgrep_mapping(rules_dir)
            if mismatches:
                limitations.append(
                    f"semgrep rule mapping ids missing from local rules: {mismatches}"
                )
    return report, limitations


def _render_check_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Baseline startup check")
    lines.append("")
    lines.append(f"- Baseline root: `{payload['baseline_root']}`")
    lines.append(f"- Checked at: `{payload['checked_at']}`")
    lines.append(f"- Ready: `{payload['ready']}`")
    lines.append("")
    lines.append("## Blocking issues")
    lines.append("")
    if payload["blocking_issues"]:
        for issue in payload["blocking_issues"]:
            lines.append(f"- {issue}")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    if payload["limitations"]:
        for limitation in payload["limitations"]:
            lines.append(f"- {limitation}")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Inputs and version freeze")
    lines.append("")
    lines.append(f"- Git commit: `{payload['git'].get('commit')}`")
    lines.append(f"- Worktree dirty: `{payload['git'].get('dirty')}`")
    lines.append(f"- Docker available: `{payload['docker'].get('available')}`")
    lines.append(f"- Resolved image id: `{payload['docker'].get('resolved_image_id')}`")
    lines.append(f"- Declared image digest: `{payload['docker'].get('declared_digest')}`")
    lines.append(f"- DMX key required: `{payload['dotenv'].get('required')}`")
    lines.append(f"- DMX key present: `{payload['dotenv'].get('has_key')}`")
    lines.append("")
    lines.append("## Evaluator tools")
    lines.append("")
    lines.append("| Combination | Tool | Available | Covered |")
    lines.append("|---|---|---|---|")
    for combination_id, tools in payload["evaluator_tools"].items():
        for tool, record in tools.items():
            if tool == "rule_mapping_trace":
                continue
            lines.append(
                f"| {combination_id} | {tool} | {record.get('available')} | {record.get('covered')} |"
            )
    lines.append("")
    lines.append("## Units / runs")
    lines.append("")
    lines.append("| Unit | Status | Ready runs | Total runs |")
    lines.append("|---|---|---:|---:|")
    for unit_id, unit in payload["units"].items():
        lines.append(
            f"| {unit_id} | {unit['status']} | {unit['ready_runs']} | {unit['total_runs']} |"
        )
    lines.append("")
    return "\n".join(lines)


def _check_baseline_impl(root: Path) -> dict[str, Any]:
    manifest_path = root / "manifest" / "run-manifest.json"
    if not manifest_path.is_file():
        raise BaselineBlockedError(f"run manifest missing: {manifest_path}")
    manifest = load_manifest(manifest_path)
    matrix = MatrixConfig.from_json(manifest["matrix"])
    version_fingerprint = manifest.get("version_fingerprint") or {}

    blocking: list[str] = []
    limitations: list[str] = []

    # 1. input hashes
    blocking.extend(_verify_input_hashes(root, manifest))

    # 2. per-run configs
    run_summary = check_unit_configs(root, manifest)
    for run_id, entry in run_summary.items():
        if not entry["ok"]:
            blocking.append(f"run {run_id}: {entry['error']}")

    # 3. git freeze
    repo_dir = Path(matrix.repo_dir)
    git_report: dict[str, Any] = {}
    try:
        status = git_worktree_status(repo_dir)
        git_report = {
            "commit": git_commit(repo_dir),
            "dirty": status["dirty"],
            "status_sha256": status["status_sha256"],
        }
    except BaselineBlockedError as error:
        blocking.append(str(error))
        git_report = {"error": str(error)}
    if "error" not in git_report:
        recorded_commit = version_fingerprint.get("git_commit")
        if git_report["commit"] != recorded_commit:
            code_changed = code_tree_changed_since(repo_dir, recorded_commit)
            if code_changed is True:
                blocking.append(
                    f"tracked code changed since preparation: {git_report['commit']!r} != "
                    f"recorded {recorded_commit!r} (coco_attack/dspy diff is non-empty)"
                )
            elif code_changed is False:
                git_report["doc_only_advance"] = True
                limitations.append(
                    "HEAD advanced after preparation with doc-only changes; the tracked "
                    "code tree is unchanged, so the baseline version is unaffected (plan §5.2.5)"
                )
            else:
                blocking.append(
                    "git commit changed and the code-tree diff could not be verified: "
                    f"{git_report['commit']!r} vs recorded {recorded_commit!r}"
                )
        if git_report["dirty"] != version_fingerprint.get("worktree_dirty"):
            blocking.append("code worktree dirty state changed since preparation")
        if git_report["status_sha256"] != version_fingerprint.get("worktree_status_sha256"):
            blocking.append("code worktree status hash changed since preparation")

    # 4. Docker / image identity
    docker_available, docker_detail = _docker_available()
    profile: ExecutionProfile | None = None
    reference = None
    try:
        profile = ExecutionProfile.from_json(read_json(Path(matrix.execution_config)))
        reference = profile.image.reference
    except (OSError, ValueError) as error:
        blocking.append(f"cannot read execution config {matrix.execution_config}: {error}")
    resolved_image_id = _docker_image_id(reference) if (docker_available and reference) else None
    declared_digest = _declared_image_digest(matrix, profile)
    docker_report = {
        "available": docker_available,
        "detail": docker_detail,
        "reference": reference,
        "resolved_image_id": resolved_image_id,
        "declared_digest": declared_digest,
    }
    if not docker_available:
        limitations.append(
            "docker unavailable: functional evaluation cannot run; units cannot claim a "
            "usable functional baseline"
        )
    elif resolved_image_id is None and reference:
        limitations.append(f"docker image not present locally: {reference}")
    if declared_digest is not None and resolved_image_id is not None and declared_digest != resolved_image_id:
        blocking.append(
            f"declared image digest {declared_digest} != resolved image id {resolved_image_id}"
        )
    if matrix.image_digest is None:
        limitations.append("matrix.image_digest is not set; image identity is not pinned in the matrix")
    elif declared_digest is None:
        limitations.append(
            f"matrix.image_digest {matrix.image_digest!r} is not a resolvable sha256 image id; "
            "it was not compared against the local image"
        )

    # 5. .env DMX key
    requires_dmx = matrix.source == "dmx" or (
        matrix.judge_enabled and matrix.judge_source == "dmx"
    )
    env_path = repo_dir / ".env"
    env_values: dict[str, str] = {}
    if env_path.is_file():
        env_values = parse_dotenv(env_path)
    has_key = bool(env_values.get("DMX_API_KEY"))
    dotenv_report = {
        "required": requires_dmx,
        "path": str(env_path),
        "present": env_path.is_file(),
        "has_key": has_key,
    }
    if requires_dmx and not has_key:
        blocking.append(
            f"DMX_API_KEY is required (source/judge uses dmx) but is missing or empty in {env_path}"
        )

    # 6. evaluator tool availability
    evaluator_tools, tool_limitations = _evaluator_tool_report(matrix)
    limitations.extend(tool_limitations)

    # 7. per-unit readiness
    units_report: dict[str, Any] = {}
    ready = not blocking
    for unit_id, unit in (manifest.get("units") or {}).items():
        runs = unit.get("runs") or []
        ready_runs = sum(
            1 for run in runs if run_summary.get(run["run_id"], {}).get("ok")
        )
        entry = {
            "status": unit.get("status"),
            "ready_runs": ready_runs,
            "total_runs": len(runs),
            "known_limitations": list(unit.get("known_limitations") or []),
        }
        units_report[unit_id] = entry
        if ready_runs != len(runs):
            ready = False

    return {
        "schema_version": BASELINE_CHECK_SCHEMA_VERSION,
        "baseline_root": str(root),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "ready": ready and not blocking,
        "blocking_issues": blocking,
        "limitations": sorted(set(limitations)),
        "git": git_report,
        "docker": docker_report,
        "dotenv": dotenv_report,
        "evaluator_tools": evaluator_tools,
        "runs": run_summary,
        "units": units_report,
    }


def check_baseline(baseline_root: Path | str) -> int:
    """Re-verify a prepared baseline; returns 0 clean / 1 blocking."""

    root = Path(baseline_root).expanduser().resolve()
    try:
        payload = _check_baseline_impl(root)
    except BaselineError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    write_json_atomic(root / "checks" / "baseline_check.json", payload)
    write_text_atomic(root / "checks" / "REPORT.md", _render_check_report(payload))
    return EXIT_OK if not payload["blocking_issues"] else EXIT_BLOCKING


__all__ = [
    "EXIT_OK",
    "EXIT_BLOCKING",
    "EXIT_USAGE",
    "BASELINE_LOCK_SCHEMA_VERSION",
    "ASSET_MANIFEST_SCHEMA_VERSION",
    "BASELINE_CHECK_SCHEMA_VERSION",
    "BaselineError",
    "BaselineUsageError",
    "BaselineBlockedError",
    "git_commit",
    "git_worktree_status",
    "code_tree_changed_since",
    "parse_dotenv",
    "collect_version_fingerprint",
    "known_limitations_for",
    "prepare_baseline",
    "check_baseline",
]
