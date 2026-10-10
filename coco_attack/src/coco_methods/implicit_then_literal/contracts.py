"""Data contracts for the ``implicit_then_literal`` method (subplan 01).

This module owns only the *method-specific* types that the later subplans need:
method/protocol identities, deterministic logical candidate identities, explicit
template references, the scoped B rename request and the distinguishable B
modification result.  It deliberately does **not** copy the old
``single_candidate_ab`` configuration, does not invent ranking/merge operations
and does not touch the shared ``iteration`` patch format.

Two identities are kept apart everywhere:

* the *logical candidate identity* (run / round / A-B stage / fixed candidate
  index / B seed reference) is deterministic and independent of template
  content, concurrency order and filesystem paths;
* the *template content identity* (``TemplateSnapshot.content_sha256``) is owned
  by the shared snapshot service and is stored alongside, never mixed in.

``A``/``B`` here are method stages, not the public ``search``/``holdout`` stage
enum.  Nothing in this module decides ranking, dedup/merge, rounds or budget.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from coco_attack.assets.artifacts import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from coco_attack.assets.paths import PathResolutionError, resolve_within, relative_to_root
from coco_attack.iteration.template_snapshot import (
    TemplateSnapshot,
    TemplateSnapshotError,
    read_snapshot,
)

# --------------------------------------------------------------------------- #
# Method / protocol identity (distinct from single_candidate_ab)
# --------------------------------------------------------------------------- #

IMPLICIT_THEN_LITERAL_METHOD_ID = "implicit_then_literal"
IMPLICIT_THEN_LITERAL_SCHEMA_VERSION = "implicit-then-literal-v1"
IMPLICIT_THEN_LITERAL_PROTOCOL_VERSION = "implicit-then-literal-b-patch-v1"
CANDIDATE_IDENTITY_SCHEMA_VERSION = "implicit-then-literal-candidate-v1"

#: Method stages.  ``A`` is the structure stage, ``B`` the literal stage.  These
#: are intentionally *not* the public ``search``/``holdout`` stage names.
METHOD_STAGES = ("A", "B")

#: Examples 2..4 are modifiable, example 1 is frozen.
MODIFIABLE_EXAMPLES = (2, 3, 4)
FROZEN_EXAMPLE = 1

EXPECTED_COMBINATION_ID = "cwe078-0"
EXPECTED_FORM = "poisoned_fewshot_cot"
EXPECTED_EXAMPLE_TASK_IDS = (
    "BigCodeBench/562",
    "BigCodeBench/348",
    "BigCodeBench/322",
    "BigCodeBench/810",
)

#: Training tasks reused by the method (referenced only; subplan 01 never reads
#: or runs them).
TRAINING_TASK_IDS = ("BigCodeBench/13", "BigCodeBench/1105")

#: Snapshot reference roles.  The initial template is caller-provided; the
#: comparison baseline is the fixed read-only asset.  They are never conflated.
SNAPSHOT_ROLE_INITIAL = "initial_template"
SNAPSHOT_ROLE_COMPARISON = "comparison_baseline"
SNAPSHOT_ROLES = (SNAPSHOT_ROLE_INITIAL, SNAPSHOT_ROLE_COMPARISON)

# --------------------------------------------------------------------------- #
# B modification statuses and error categories
# --------------------------------------------------------------------------- #

B_STATUS_LEGAL = "legal"
B_STATUS_NO_CHANGE = "no_change"
B_STATUS_INVALID = "invalid"
B_STATUSES = (B_STATUS_LEGAL, B_STATUS_NO_CHANGE, B_STATUS_INVALID)

#: Candidate-request problems (occupy the slot, are not trained).  Kept apart
#: from infrastructure I/O failures, which are raised as ``BModificationIOError``.
B_ERROR_STALE_PARENT = "stale_parent"
B_ERROR_FROZEN_EXAMPLE = "frozen_example"
B_ERROR_OUT_OF_RANGE_EXAMPLE = "out_of_range_example"
B_ERROR_DUPLICATE_EXAMPLE = "duplicate_example"
B_ERROR_NO_MODIFICATION = "no_modification"
B_ERROR_UNKNOWN_SCOPE = "unknown_scope"
B_ERROR_UNKNOWN_TARGET = "unknown_target"
B_ERROR_FROZEN_BINDING = "frozen_binding"
B_ERROR_UNSUPPORTED_SCOPE = "unsupported_scope"
B_ERROR_INVALID_IDENTIFIER = "invalid_identifier"
B_ERROR_NAME_CONFLICT = "name_conflict"
B_ERROR_DUPLICATE_MAPPING = "duplicate_mapping"
B_ERROR_INVALID_REQUEST = "invalid_request"

B_ERROR_CATEGORIES = (
    B_ERROR_STALE_PARENT,
    B_ERROR_FROZEN_EXAMPLE,
    B_ERROR_OUT_OF_RANGE_EXAMPLE,
    B_ERROR_DUPLICATE_EXAMPLE,
    B_ERROR_NO_MODIFICATION,
    B_ERROR_UNKNOWN_SCOPE,
    B_ERROR_UNKNOWN_TARGET,
    B_ERROR_FROZEN_BINDING,
    B_ERROR_UNSUPPORTED_SCOPE,
    B_ERROR_INVALID_IDENTIFIER,
    B_ERROR_NAME_CONFLICT,
    B_ERROR_DUPLICATE_MAPPING,
    B_ERROR_INVALID_REQUEST,
)


class ImplicitThenLiteralContractError(ValueError):
    """Raised when a method contract object is malformed or inconsistent."""


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ImplicitThenLiteralContractError(
            f"{field_name} must be a non-empty string, got {value!r}"
        )
    return value


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ImplicitThenLiteralContractError(
            f"{field_name} must be a positive integer, got {value!r}"
        )
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ImplicitThenLiteralContractError(
            f"{field_name} must be a 64-character lowercase hex sha256, got {value!r}"
        )
    return value


# --------------------------------------------------------------------------- #
# Logical candidate identity
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CandidateIdentity:
    """Deterministic logical identity of one candidate.

    The identity is built only from the research coordinates, never from a
    template path, a temporary directory, a completion order or Python's
    salted ``hash()``.  The template content hash is stored separately by the
    caller/result so two candidates with identical content keep distinct
    logical identities.
    """

    run_id: str
    round_index: int
    stage: str
    candidate_index: int
    seed_candidate_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_str(self.run_id, "run_id")
        _require_positive_int(self.round_index, "round_index")
        if self.stage not in METHOD_STAGES:
            raise ImplicitThenLiteralContractError(
                f"stage must be one of {METHOD_STAGES}, got {self.stage!r}"
            )
        _require_positive_int(self.candidate_index, "candidate_index")
        if self.stage == "B":
            _require_nonempty_str(self.seed_candidate_id, "seed_candidate_id")
        elif self.seed_candidate_id is not None:
            raise ImplicitThenLiteralContractError(
                "seed_candidate_id is only allowed for stage 'B'"
            )

    def logical_json(self) -> dict[str, Any]:
        return {
            "schema_version": CANDIDATE_IDENTITY_SCHEMA_VERSION,
            "run_id": self.run_id,
            "round_index": self.round_index,
            "stage": self.stage,
            "candidate_index": self.candidate_index,
            "seed_candidate_id": self.seed_candidate_id,
        }

    def logical_id(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.logical_json()))

    def to_json(self) -> dict[str, Any]:
        payload = self.logical_json()
        payload["candidate_id"] = self.logical_id()
        return payload


def candidate_id(
    *,
    run_id: str,
    round_index: int,
    stage: str,
    candidate_index: int,
    seed_candidate_id: str | None = None,
) -> str:
    """Return the deterministic logical id for the given coordinates."""

    return CandidateIdentity(
        run_id=run_id,
        round_index=round_index,
        stage=stage,
        candidate_index=candidate_index,
        seed_candidate_id=seed_candidate_id,
    ).logical_id()


# --------------------------------------------------------------------------- #
# Experience version reference (shared by roles and experience)
# --------------------------------------------------------------------------- #

EXPERIENCE_CATEGORY_STRUCTURE = "structure"
EXPERIENCE_CATEGORY_LITERAL = "literal"
EXPERIENCE_CATEGORIES = (EXPERIENCE_CATEGORY_STRUCTURE, EXPERIENCE_CATEGORY_LITERAL)
EXPERIENCE_INITIAL_SCHEMA_VERSION = "implicit-then-literal-experience-initial-v1"


@dataclass(frozen=True)
class ExperienceVersionReference:
    """A lightweight, traceable pointer to one committed experience version.

    The full entries/archives live in the experience store; roles only need the
    version identity, its category, the previous pointer, the current summary
    and the evidence labels the summary may cite.
    """

    category: str
    version_id: str
    previous_version_id: str | None
    summary: str
    entry_labels: tuple[str, ...] = ()
    evidence_labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.category not in EXPERIENCE_CATEGORIES:
            raise ImplicitThenLiteralContractError(
                f"category must be one of {EXPERIENCE_CATEGORIES}, got {self.category!r}"
            )
        _require_nonempty_str(self.version_id, "version_id")
        if self.previous_version_id is not None:
            _require_nonempty_str(self.previous_version_id, "previous_version_id")
        if not isinstance(self.summary, str):
            raise ImplicitThenLiteralContractError("summary must be a string")
        for field_name in ("entry_labels", "evidence_labels"):
            value = getattr(self, field_name)
            if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
                raise ImplicitThenLiteralContractError(f"{field_name} must be a sequence")
            object.__setattr__(self, field_name, tuple(value))

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "version_id": self.version_id,
            "previous_version_id": self.previous_version_id,
            "summary": self.summary,
            "entry_labels": list(self.entry_labels),
            "evidence_labels": list(self.evidence_labels),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "ExperienceVersionReference":
        return cls(
            category=_require_nonempty_str(payload.get("category"), "category"),
            version_id=_require_nonempty_str(payload.get("version_id"), "version_id"),
            previous_version_id=payload.get("previous_version_id"),
            summary=str(payload.get("summary") or ""),
            entry_labels=tuple(payload.get("entry_labels") or ()),
            evidence_labels=tuple(payload.get("evidence_labels") or ()),
        )

    @classmethod
    def initial(cls, category: str) -> "ExperienceVersionReference":
        if category not in EXPERIENCE_CATEGORIES:
            raise ImplicitThenLiteralContractError(
                f"category must be one of {EXPERIENCE_CATEGORIES}, got {category!r}"
            )
        version_id = sha256_bytes(
            canonical_json_bytes(
                {"schema_version": EXPERIENCE_INITIAL_SCHEMA_VERSION, "category": category}
            )
        )
        return cls(
            category=category,
            version_id=version_id,
            previous_version_id=None,
            summary="",
            entry_labels=(),
            evidence_labels=(),
        )


# --------------------------------------------------------------------------- #
# Template references
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SnapshotReference:
    """A traceable reference to one content-addressed template snapshot.

    ``path`` is provenance only (relative to an explicit root when possible);
    it never enters a content identity.
    """

    role: str
    path: str
    content_sha256: str
    file_sha256: str
    combination_id: str
    form: str
    example_ids: tuple[str, ...]
    source: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.role not in SNAPSHOT_ROLES:
            raise ImplicitThenLiteralContractError(
                f"role must be one of {SNAPSHOT_ROLES}, got {self.role!r}"
            )
        _require_nonempty_str(self.path, "path")
        _require_sha256(self.content_sha256, "content_sha256")
        _require_sha256(self.file_sha256, "file_sha256")
        _require_nonempty_str(self.combination_id, "combination_id")
        _require_nonempty_str(self.form, "form")
        if isinstance(self.example_ids, (str, bytes)) or not isinstance(
            self.example_ids, Sequence
        ):
            raise ImplicitThenLiteralContractError("example_ids must be a sequence")
        object.__setattr__(self, "example_ids", tuple(self.example_ids))

    def to_json(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "content_sha256": self.content_sha256,
            "file_sha256": self.file_sha256,
            "combination_id": self.combination_id,
            "form": self.form,
            "example_ids": list(self.example_ids),
            "source": dict(self.source),
        }


@dataclass(frozen=True)
class TemplateBindings:
    """The two independent template references used by the method.

    ``initial_template`` is supplied explicitly by the caller (subplan 01 never
    decides the real run start); ``comparison_baseline`` is the fixed read-only
    asset.  Keeping them as separate fields prevents silently treating the
    baseline as the per-round A start.
    """

    initial_template: SnapshotReference
    comparison_baseline: SnapshotReference

    def __post_init__(self) -> None:
        if self.initial_template.role != SNAPSHOT_ROLE_INITIAL:
            raise ImplicitThenLiteralContractError(
                "initial_template must have role 'initial_template'"
            )
        if self.comparison_baseline.role != SNAPSHOT_ROLE_COMPARISON:
            raise ImplicitThenLiteralContractError(
                "comparison_baseline must have role 'comparison_baseline'"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": IMPLICIT_THEN_LITERAL_SCHEMA_VERSION,
            "initial_template": self.initial_template.to_json(),
            "comparison_baseline": self.comparison_baseline.to_json(),
        }


def read_snapshot_reference(
    snapshot_path: Path | str,
    *,
    role: str,
    root: Path | str | None = None,
) -> SnapshotReference:
    """Read a snapshot and build a traceable reference without writing.

    A relative ``snapshot_path`` requires an explicit ``root`` and is confined
    to it; an absolute path is accepted as-is.  The stored ``path`` is made
    relative to ``root`` when the file lives under it so the reference does not
    depend on a temporary absolute location.
    """

    if role not in SNAPSHOT_ROLES:
        raise ImplicitThenLiteralContractError(
            f"role must be one of {SNAPSHOT_ROLES}, got {role!r}"
        )
    raw = Path(snapshot_path)
    resolved: Path
    if raw.is_absolute():
        resolved = raw
    else:
        if root is None:
            raise ImplicitThenLiteralContractError(
                "a relative snapshot path requires an explicit root"
            )
        try:
            resolved = resolve_within(Path(root), raw)
        except PathResolutionError as error:
            raise ImplicitThenLiteralContractError(
                f"snapshot path {raw} is not a valid path under {root}: {error}"
            ) from error
    if not resolved.exists():
        raise ImplicitThenLiteralContractError(f"snapshot path not found: {resolved}")
    snapshot_file = resolved / "snapshot.json" if resolved.is_dir() else resolved
    if not snapshot_file.is_file():
        raise ImplicitThenLiteralContractError(
            f"snapshot file not found: {snapshot_file}"
        )
    try:
        snapshot = read_snapshot(snapshot_file)
    except TemplateSnapshotError as error:
        raise ImplicitThenLiteralContractError(
            f"snapshot {snapshot_file} failed content-addressing checks: {error}"
        ) from error
    if root is not None:
        root_path = Path(root).resolve()
        try:
            stored_path = relative_to_root(root_path, resolved)
        except ValueError:
            stored_path = resolved.as_posix()
    else:
        stored_path = resolved.as_posix()
    return SnapshotReference(
        role=role,
        path=stored_path,
        content_sha256=snapshot.content_sha256(),
        file_sha256=sha256_file(snapshot_file),
        combination_id=snapshot.combination_id,
        form=snapshot.form,
        example_ids=snapshot.example_ids(),
        source=dict(snapshot.source),
    )


# --------------------------------------------------------------------------- #
# B modification request
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RenameMapping:
    """One scoped local-variable rename (interpreted against the parent)."""

    scope_id: str
    old_name: str
    new_name: str

    def __post_init__(self) -> None:
        _require_nonempty_str(self.scope_id, "scope_id")
        _require_nonempty_str(self.old_name, "old_name")
        _require_nonempty_str(self.new_name, "new_name")

    def to_json(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "old_name": self.old_name,
            "new_name": self.new_name,
        }


@dataclass(frozen=True)
class ExampleModification:
    """Modifications requested for one modifiable example (2..4).

    ``renames`` may be empty when only the CoT is rewritten; ``new_cot`` may be
    ``None`` when only code is renamed.  Both empty is rejected as supplying
    nothing.
    """

    example: int
    renames: tuple[RenameMapping, ...] = ()
    new_cot: str | None = None

    def __post_init__(self) -> None:
        _require_positive_int(self.example, "example")
        if isinstance(self.renames, (str, bytes)) or not isinstance(
            self.renames, Sequence
        ):
            raise ImplicitThenLiteralContractError("renames must be a sequence")
        coerced = tuple(self.renames)
        for mapping in coerced:
            if not isinstance(mapping, RenameMapping):
                raise ImplicitThenLiteralContractError(
                    "every rename must be a RenameMapping"
                )
        object.__setattr__(self, "renames", coerced)
        if self.new_cot is not None and not isinstance(self.new_cot, str):
            raise ImplicitThenLiteralContractError("new_cot must be a string or None")

    def to_json(self) -> dict[str, Any]:
        return {
            "example": self.example,
            "renames": [mapping.to_json() for mapping in self.renames],
            "new_cot": self.new_cot,
        }


@dataclass(frozen=True)
class BModificationRequest:
    """A complete, atomic B modification request against one parent snapshot."""

    candidate: CandidateIdentity
    parent_content_sha256: str
    modifications: tuple[ExampleModification, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, CandidateIdentity):
            raise ImplicitThenLiteralContractError(
                "candidate must be a CandidateIdentity"
            )
        if self.candidate.stage != "B":
            raise ImplicitThenLiteralContractError(
                "a B modification request requires stage 'B'"
            )
        _require_sha256(self.parent_content_sha256, "parent_content_sha256")
        if isinstance(self.modifications, (str, bytes)) or not isinstance(
            self.modifications, Sequence
        ):
            raise ImplicitThenLiteralContractError("modifications must be a sequence")
        coerced = tuple(self.modifications)
        for modification in coerced:
            if not isinstance(modification, ExampleModification):
                raise ImplicitThenLiteralContractError(
                    "every modification must be an ExampleModification"
                )
        object.__setattr__(self, "modifications", coerced)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": IMPLICIT_THEN_LITERAL_PROTOCOL_VERSION,
            "candidate": self.candidate.to_json(),
            "parent_content_sha256": self.parent_content_sha256,
            "modifications": [item.to_json() for item in self.modifications],
        }


# --------------------------------------------------------------------------- #
# Enumeration contracts (consumed by subplan 02)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RenameTarget:
    """One safely renameable local binding offered to the caller."""

    example: int
    scope_id: str
    name: str
    binding_kind: str
    store_count: int
    load_count: int

    def to_json(self) -> dict[str, Any]:
        return {
            "example": self.example,
            "scope_id": self.scope_id,
            "name": self.name,
            "binding_kind": self.binding_kind,
            "store_count": self.store_count,
            "load_count": self.load_count,
        }


@dataclass(frozen=True)
class UnsupportedRename:
    """A binding that cannot be safely renamed, with a concrete reason."""

    example: int
    name: str | None
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {"example": self.example, "name": self.name, "reason": self.reason}


@dataclass(frozen=True)
class RenameTargetReport:
    """Result of enumerating rename targets for one example.

    ``scope_id`` is ``None`` only when the whole example could not be analysed
    (for example a non-indented body).  CoT-only modification stays valid even
    then because it never needs a rename.
    """

    example: int
    scope_id: str | None
    targets: tuple[RenameTarget, ...]
    unsupported: tuple[UnsupportedRename, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": IMPLICIT_THEN_LITERAL_SCHEMA_VERSION,
            "example": self.example,
            "scope_id": self.scope_id,
            "targets": [target.to_json() for target in self.targets],
            "unsupported": [item.to_json() for item in self.unsupported],
        }


# --------------------------------------------------------------------------- #
# B modification result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BModificationError:
    """A concrete, non-fatal rejection reason for one candidate request."""

    category: str
    reason: str
    example: int | None = None
    scope_id: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.category not in B_ERROR_CATEGORIES:
            raise ImplicitThenLiteralContractError(
                f"unknown B error category {self.category!r}"
            )
        _require_nonempty_str(self.reason, "reason")

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "reason": self.reason,
            "example": self.example,
            "scope_id": self.scope_id,
            "name": self.name,
        }


@dataclass(frozen=True)
class BModificationResult:
    """Distinguishable outcome of a B modification attempt.

    ``status`` is ``legal`` (a real change), ``no_change`` (a valid request that
    left the template byte-identical) or ``invalid`` (the candidate request was
    rejected).  Infrastructure I/O failures are never folded in here; they are
    raised by the save entry point as ``BModificationIOError``.
    """

    candidate: CandidateIdentity
    parent_content_sha256: str
    status: str
    changed: bool
    diff: tuple[dict[str, Any], ...]
    snapshot: TemplateSnapshot
    content_sha256: str
    errors: tuple[BModificationError, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in B_STATUSES:
            raise ImplicitThenLiteralContractError(
                f"status must be one of {B_STATUSES}, got {self.status!r}"
            )
        _require_sha256(self.parent_content_sha256, "parent_content_sha256")
        _require_sha256(self.content_sha256, "content_sha256")
        if self.status == B_STATUS_LEGAL and not self.changed:
            raise ImplicitThenLiteralContractError(
                "a legal result must report changed=True"
            )
        if self.status != B_STATUS_LEGAL and self.changed:
            raise ImplicitThenLiteralContractError(
                "only a legal result may report changed=True"
            )
        if not isinstance(self.snapshot, TemplateSnapshot):
            raise ImplicitThenLiteralContractError(
                "snapshot must be a TemplateSnapshot"
            )
        if self.snapshot.content_sha256() != self.content_sha256:
            raise ImplicitThenLiteralContractError(
                "content_sha256 does not match the carried snapshot content"
            )
        object.__setattr__(self, "diff", tuple(self.diff))
        object.__setattr__(self, "errors", tuple(self.errors))

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": IMPLICIT_THEN_LITERAL_PROTOCOL_VERSION,
            "candidate_id": self.candidate.logical_id(),
            "status": self.status,
            "changed": self.changed,
            "parent_content_sha256": self.parent_content_sha256,
            "content_sha256": self.content_sha256,
            "diff": [dict(entry) for entry in self.diff],
            "errors": [error.to_json() for error in self.errors],
        }


__all__ = [
    "IMPLICIT_THEN_LITERAL_METHOD_ID",
    "IMPLICIT_THEN_LITERAL_SCHEMA_VERSION",
    "IMPLICIT_THEN_LITERAL_PROTOCOL_VERSION",
    "CANDIDATE_IDENTITY_SCHEMA_VERSION",
    "METHOD_STAGES",
    "MODIFIABLE_EXAMPLES",
    "FROZEN_EXAMPLE",
    "EXPECTED_COMBINATION_ID",
    "EXPECTED_FORM",
    "EXPECTED_EXAMPLE_TASK_IDS",
    "TRAINING_TASK_IDS",
    "SNAPSHOT_ROLE_INITIAL",
    "SNAPSHOT_ROLE_COMPARISON",
    "SNAPSHOT_ROLES",
    "B_STATUS_LEGAL",
    "B_STATUS_NO_CHANGE",
    "B_STATUS_INVALID",
    "B_STATUSES",
    "B_ERROR_STALE_PARENT",
    "B_ERROR_FROZEN_EXAMPLE",
    "B_ERROR_OUT_OF_RANGE_EXAMPLE",
    "B_ERROR_DUPLICATE_EXAMPLE",
    "B_ERROR_NO_MODIFICATION",
    "B_ERROR_UNKNOWN_SCOPE",
    "B_ERROR_UNKNOWN_TARGET",
    "B_ERROR_FROZEN_BINDING",
    "B_ERROR_UNSUPPORTED_SCOPE",
    "B_ERROR_INVALID_IDENTIFIER",
    "B_ERROR_NAME_CONFLICT",
    "B_ERROR_DUPLICATE_MAPPING",
    "B_ERROR_INVALID_REQUEST",
    "B_ERROR_CATEGORIES",
    "ImplicitThenLiteralContractError",
    "CandidateIdentity",
    "candidate_id",
    "EXPERIENCE_CATEGORY_STRUCTURE",
    "EXPERIENCE_CATEGORY_LITERAL",
    "EXPERIENCE_CATEGORIES",
    "ExperienceVersionReference",
    "SnapshotReference",
    "TemplateBindings",
    "read_snapshot_reference",
    "RenameMapping",
    "ExampleModification",
    "BModificationRequest",
    "RenameTarget",
    "UnsupportedRename",
    "RenameTargetReport",
    "BModificationError",
    "BModificationResult",
]
