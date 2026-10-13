"""Read-only access to the fixed comparison baseline (subplan 01, §4).

The user-specified baseline is a content-addressed ``TemplateSnapshot`` that
lives in the read-only asset tree.  This module loads it through the shared
``read_snapshot`` service, verifies the declared content hash, the current file
hash and the declared combination/form/example identity, records the asset
provenance (manifest/README) and returns the snapshot plus a traceable
description.  It never writes, copies or re-registers the asset, and it never
treats the baseline as a per-round A starting template.

Two identities are recorded separately and never mixed:

* ``content_sha256`` -- the template content identity (version directory name);
* ``file_sha256`` -- the raw ``snapshot.json`` byte hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from coco_attack.assets.artifacts import read_json, sha256_file
from coco_attack.assets.paths import PathResolutionError, project_root, relative_to_root, resolve_within
from coco_attack.iteration.template_snapshot import TemplateSnapshot, TemplateSnapshotError, read_snapshot
from .contracts import (
    EXPECTED_COMBINATION_ID,
    EXPECTED_EXAMPLE_TASK_IDS,
    EXPECTED_FORM,
    SNAPSHOT_ROLE_COMPARISON,
    SnapshotReference,
)

#: Canonical repository-relative path of the fixed comparison baseline.
FIXED_BASELINE_RELATIVE_PATH = (
    "cocota_data_eval_result/prompts_shared/experiments/cwe078/"
    "cwe078_initial_poisoned_code_shell_true_cot_clean/snapshot_store/cwe078-0/"
    "99fe015a51d0783b396513cfc821c6fb492c3b167e85c47309b90a32f3aae449/snapshot.json"
)
#: Template content identity (also the version directory name).
FIXED_BASELINE_CONTENT_SHA256 = (
    "99fe015a51d0783b396513cfc821c6fb492c3b167e85c47309b90a32f3aae449"
)
#: Raw file SHA-256 of the current ``snapshot.json``.
FIXED_BASELINE_FILE_SHA256 = (
    "2049e8eb33e23e50d2fe409c1b1506288db70fff26aac193e421a103b73196fd"
)
FIXED_BASELINE_COMBINATION_ID = "cwe078-0"
FIXED_BASELINE_FORM = "poisoned_fewshot_cot"
FIXED_BASELINE_EXAMPLE_IDS = (
    "BigCodeBench/562",
    "BigCodeBench/348",
    "BigCodeBench/322",
    "BigCodeBench/810",
)

_EXPERIMENT_DIR_PARENT_DEPTH = 3  # <hash>/snapshot.json -> snapshot_store -> cwe078-0 -> experiment
_MANIFEST_NAME = "manifest.json"
_README_NAME = "README.md"


class BaselineError(ValueError):
    """Raised when the fixed baseline is missing, tampered with or mis-attributed."""


@dataclass(frozen=True)
class ComparisonBaseline:
    """The verified read-only comparison baseline and its provenance."""

    reference: SnapshotReference
    snapshot: TemplateSnapshot
    manifest_path: str | None
    manifest_sha256: str | None
    readme_path: str | None
    readme_sha256: str | None
    declared_content_sha256: str
    declared_file_sha256: str

    @property
    def content_sha256(self) -> str:
        return self.reference.content_sha256

    @property
    def file_sha256(self) -> str:
        return self.reference.file_sha256

    def to_json(self) -> dict[str, Any]:
        return {
            "reference": self.reference.to_json(),
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "readme_path": self.readme_path,
            "readme_sha256": self.readme_sha256,
            "declared_content_sha256": self.declared_content_sha256,
            "declared_file_sha256": self.declared_file_sha256,
        }


def default_repository_root() -> Path:
    """Return the repository root (the parent of the ``coco_attack`` project).

    Resolution is independent of the current shell directory; callers may pass
    an explicit ``repository_root`` instead.
    """

    return project_root().parent


def _resolve_baseline_path(repository_root: Path | str) -> Path:
    root = Path(repository_root)
    try:
        resolved = resolve_within(root, FIXED_BASELINE_RELATIVE_PATH)
    except PathResolutionError as error:
        raise BaselineError(
            f"fixed baseline path escapes the repository root {root}: {error}"
        ) from error
    if not resolved.is_file():
        raise BaselineError(f"fixed baseline snapshot not found: {resolved}")
    return resolved


def _verify_snapshot_identity(snapshot: TemplateSnapshot) -> None:
    if snapshot.content_sha256() != FIXED_BASELINE_CONTENT_SHA256:
        raise BaselineError(
            "fixed baseline content hash mismatch: expected "
            f"{FIXED_BASELINE_CONTENT_SHA256}, got {snapshot.content_sha256()}"
        )
    if snapshot.combination_id != FIXED_BASELINE_COMBINATION_ID:
        raise BaselineError(
            f"fixed baseline combination mismatch: expected "
            f"{FIXED_BASELINE_COMBINATION_ID!r}, got {snapshot.combination_id!r}"
        )
    if snapshot.form != FIXED_BASELINE_FORM:
        raise BaselineError(
            f"fixed baseline form mismatch: expected {FIXED_BASELINE_FORM!r}, "
            f"got {snapshot.form!r}"
        )
    if snapshot.example_ids() != FIXED_BASELINE_EXAMPLE_IDS:
        raise BaselineError(
            "fixed baseline example order mismatch: expected "
            f"{FIXED_BASELINE_EXAMPLE_IDS}, got {snapshot.example_ids()}"
        )
    if snapshot.trigger != "cf" or snapshot.injection_position != "first_sentence_end":
        raise BaselineError(
            "fixed baseline attack_config mismatch: expected trigger='cf' and "
            f"injection_position='first_sentence_end', got trigger="
            f"{snapshot.trigger!r}, injection_position={snapshot.injection_position!r}"
        )

    first = snapshot.example(1)
    if first.is_poisoned or first.poison_parts != ():
        raise BaselineError(
            "fixed baseline example 1 must be frozen (not poisoned, no poison_parts)"
        )
    for number in (2, 3, 4):
        example = snapshot.example(number)
        if not example.is_poisoned or example.poison_parts != ("code",):
            raise BaselineError(
                f"fixed baseline example {number} must be code-poisoned "
                "(is_poisoned=True, poison_parts=('code',))"
            )


def _record_provenance(experiment_dir: Path, repository_root: Path) -> tuple[
    str | None, str | None, str | None, str | None
]:
    manifest = experiment_dir / _MANIFEST_NAME
    readme = experiment_dir / _README_NAME
    manifest_path: str | None = None
    manifest_sha: str | None = None
    readme_path: str | None = None
    readme_sha: str | None = None
    try:
        manifest_rel = relative_to_root(repository_root, manifest)
    except ValueError:
        manifest_rel = manifest.as_posix()
    try:
        readme_rel = relative_to_root(repository_root, readme)
    except ValueError:
        readme_rel = readme.as_posix()

    if manifest.is_file():
        manifest_path = manifest_rel
        manifest_sha = sha256_file(manifest)
        payload = read_json(manifest)
        if not isinstance(payload, Mapping):
            raise BaselineError(f"baseline manifest is not a JSON object: {manifest}")
        if payload.get("content_sha256") not in (None, FIXED_BASELINE_CONTENT_SHA256):
            raise BaselineError(
                "baseline manifest content_sha256 does not match the fixed baseline"
            )
        if payload.get("combination_id") not in (None, FIXED_BASELINE_COMBINATION_ID):
            raise BaselineError(
                "baseline manifest combination_id does not match the fixed baseline"
            )
        if payload.get("form") not in (None, FIXED_BASELINE_FORM):
            raise BaselineError(
                "baseline manifest form does not match the fixed baseline"
            )
    else:
        raise BaselineError(f"baseline manifest not found: {manifest}")

    if readme.is_file():
        readme_path = readme_rel
        readme_sha = sha256_file(readme)
    return manifest_path, manifest_sha, readme_path, readme_sha


def load_comparison_baseline(
    *,
    repository_root: Path | str | None = None,
) -> ComparisonBaseline:
    """Load and verify the fixed comparison baseline, read-only.

    Raises :class:`BaselineError` for a missing path or any hash/attribution
    mismatch; there is deliberately no fallback to another readable template.
    """

    root = (
        Path(repository_root)
        if repository_root is not None
        else default_repository_root()
    )
    snapshot_path = _resolve_baseline_path(root)

    file_sha = sha256_file(snapshot_path)
    if file_sha != FIXED_BASELINE_FILE_SHA256:
        raise BaselineError(
            "fixed baseline file hash mismatch: expected "
            f"{FIXED_BASELINE_FILE_SHA256}, got {file_sha}"
        )
    try:
        snapshot = read_snapshot(snapshot_path)
    except TemplateSnapshotError as error:
        raise BaselineError(
            f"fixed baseline snapshot failed content-addressing checks: {error}"
        ) from error
    _verify_snapshot_identity(snapshot)

    experiment_dir = snapshot_path.parents[_EXPERIMENT_DIR_PARENT_DEPTH]
    manifest_path, manifest_sha, readme_path, readme_sha = _record_provenance(
        experiment_dir, Path(root)
    )

    reference = SnapshotReference(
        role=SNAPSHOT_ROLE_COMPARISON,
        path=relative_to_root(Path(root), snapshot_path),
        content_sha256=snapshot.content_sha256(),
        file_sha256=file_sha,
        combination_id=snapshot.combination_id,
        form=snapshot.form,
        example_ids=snapshot.example_ids(),
        source=dict(snapshot.source),
    )
    return ComparisonBaseline(
        reference=reference,
        snapshot=snapshot,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha,
        readme_path=readme_path,
        readme_sha256=readme_sha,
        declared_content_sha256=FIXED_BASELINE_CONTENT_SHA256,
        declared_file_sha256=FIXED_BASELINE_FILE_SHA256,
    )


__all__ = [
    "FIXED_BASELINE_RELATIVE_PATH",
    "FIXED_BASELINE_CONTENT_SHA256",
    "FIXED_BASELINE_FILE_SHA256",
    "FIXED_BASELINE_COMBINATION_ID",
    "FIXED_BASELINE_FORM",
    "FIXED_BASELINE_EXAMPLE_IDS",
    "BaselineError",
    "ComparisonBaseline",
    "default_repository_root",
    "load_comparison_baseline",
]
