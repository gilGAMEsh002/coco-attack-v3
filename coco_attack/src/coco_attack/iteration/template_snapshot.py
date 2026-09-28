"""Immutable poisoned prompt-template snapshots and sparse field patches (I1).

The clean few-shot material is turned into an ordered, hash-addressed snapshot
of example templates.  A snapshot is **content-immutable**: editing its
``code``/``cot`` produces a new content version, and the content identity
(:meth:`TemplateSnapshot.content_sha256`) covers only the rendered template —
never paths, timestamps, parent versions or the action that produced it.  The
audit trail lives beside the store (``audit.jsonl``) and never enters the hash.

The public layer is deliberately generic: it validates a *caller-provided*
allowed example/field set and never decides which examples or fields may be
used.  It contains no A/B gate, candidate pool or selection logic.  What those
documents call "示例 1–4" (example 1..4) is the external, model-facing numbering,
so :meth:`TemplateSnapshot.example` takes a **1-based** number while the
internal ``examples`` tuple is 0-based.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assets.artifacts import (
    append_jsonl,
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
)
from ..assets.paths import relative_to_root, resolve_within
from ..prompts.trigger import has_standalone_trigger, inject_trigger
from .fewshot import FewshotExample, load_fewshot_examples, load_specs

TEMPLATE_SCHEMA_VERSION = "poison-template-v1"
DEFAULT_TRIGGER = "cf"
DEFAULT_INJECTION_POSITION = "first_sentence_end"
# ``prompts/trigger.py`` implements exactly one insertion rule (immediately
# before the first literal period).  A recorded ``injection_position`` must be
# truthful, so any other value is rejected rather than stored while the actual
# bytes keep the single supported behavior.
SUPPORTED_INJECTION_POSITIONS = ("first_sentence_end",)
PATCH_FIELDS = ("code", "cot")


class TemplateSnapshotError(ValueError):
    """Raised when a template snapshot or a patch is unusable or inconsistent."""


def _require_str(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise TemplateSnapshotError(f"snapshot field {key!r} must be a string")
    return value


def _cot_text(cot: tuple[str, ...]) -> str:
    """Rebuild the source CoT string byte-for-byte.

    The shared loader stores CoT as a tuple split on ``"\\n"``; joining is the
    exact inverse for the string-typed CoT used by the current assets, so the
    snapshot preserves the source bytes rather than re-encoding them.
    """

    return "\n".join(cot)


@dataclass(frozen=True)
class ExampleTemplate:
    """One rendered example in a template snapshot (external index is 1-based)."""

    task_id: str
    instruct_prompt: str
    code: str
    cot: str
    is_poisoned: bool
    trigger: str | None
    poison_parts: tuple[str, ...]

    def content_json(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "instruct_prompt": self.instruct_prompt,
            "code": self.code,
            "cot": self.cot,
            "is_poisoned": self.is_poisoned,
            "trigger": self.trigger,
            "poison_parts": list(self.poison_parts),
        }


@dataclass(frozen=True)
class TemplateSnapshot:
    """An ordered, content-hash-addressed set of example templates.

    ``source`` is provenance/audit only and is **not** part of the content
    identity, so the same template content has the same hash regardless of the
    store directory or the source files it was read from.
    """

    combination_id: str
    form: str
    prompt_version: str
    protocol_version: str
    trigger: str | None
    injection_position: str | None
    mode: str
    examples: tuple[ExampleTemplate, ...]
    source: dict[str, Any] = field(default_factory=dict)

    # -- content identity ------------------------------------------------- #

    def attack_config(self) -> dict[str, Any]:
        poison_parts = sorted(
            {part for example in self.examples for part in example.poison_parts}
        )
        return {
            "enabled": self.trigger is not None,
            "mode": self.mode,
            "trigger": self.trigger,
            "injection_position": self.injection_position,
            "poison_parts": poison_parts,
        }

    def content_json(self) -> dict[str, Any]:
        return {
            "schema_version": TEMPLATE_SCHEMA_VERSION,
            "combination_id": self.combination_id,
            "form": self.form,
            "prompt_version": self.prompt_version,
            "protocol_version": self.protocol_version,
            "attack_config": self.attack_config(),
            "examples": [example.content_json() for example in self.examples],
        }

    def content_sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.content_json()))

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": TEMPLATE_SCHEMA_VERSION,
            "content_sha256": self.content_sha256(),
            "snapshot": self.content_json(),
            "source": self.source,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "TemplateSnapshot":
        if not isinstance(payload, Mapping):
            raise TemplateSnapshotError("snapshot payload must be a JSON object")
        declared_schema = payload.get("schema_version")
        if declared_schema is not None and declared_schema != TEMPLATE_SCHEMA_VERSION:
            raise TemplateSnapshotError(
                f"unsupported snapshot schema_version {declared_schema!r}; "
                f"expected {TEMPLATE_SCHEMA_VERSION!r}"
            )
        content = payload.get("snapshot")
        if not isinstance(content, Mapping):
            raise TemplateSnapshotError("snapshot payload is missing a 'snapshot' object")
        content_schema = content.get("schema_version")
        if content_schema is not None and content_schema != TEMPLATE_SCHEMA_VERSION:
            raise TemplateSnapshotError(
                f"unsupported snapshot content schema_version {content_schema!r}; "
                f"expected {TEMPLATE_SCHEMA_VERSION!r}"
            )
        examples_raw = content.get("examples")
        if not isinstance(examples_raw, list):
            raise TemplateSnapshotError("snapshot 'examples' must be a list")
        examples = tuple(
            _example_from_json(item, position)
            for position, item in enumerate(examples_raw)
        )
        attack = content.get("attack_config") or {}
        if not isinstance(attack, Mapping):
            raise TemplateSnapshotError("snapshot 'attack_config' must be an object")
        source = payload.get("source") or {}
        if not isinstance(source, Mapping):
            raise TemplateSnapshotError("snapshot 'source' must be an object")
        return cls(
            combination_id=_require_str(content, "combination_id"),
            form=_require_str(content, "form"),
            prompt_version=_require_str(content, "prompt_version"),
            protocol_version=_require_str(content, "protocol_version"),
            trigger=attack.get("trigger"),
            injection_position=attack.get("injection_position"),
            mode=_require_str(attack, "mode"),
            examples=examples,
            source=dict(source),
        )

    # -- example access (1-based external numbering) ---------------------- #

    def example(self, index_1based: int) -> ExampleTemplate:
        if (
            isinstance(index_1based, bool)
            or not isinstance(index_1based, int)
            or index_1based < 1
        ):
            raise TemplateSnapshotError(
                f"example number must be a positive 1-based integer, got {index_1based!r}"
            )
        if index_1based > len(self.examples):
            raise TemplateSnapshotError(
                f"example {index_1based} out of range: snapshot has "
                f"{len(self.examples)} examples"
            )
        return self.examples[index_1based - 1]

    def example_ids(self) -> tuple[str, ...]:
        return tuple(example.task_id for example in self.examples)


def _example_from_json(item: Any, position: int) -> ExampleTemplate:
    if not isinstance(item, Mapping):
        raise TemplateSnapshotError(f"snapshot example {position} is not an object")
    poison_parts = item.get("poison_parts") or []
    if not isinstance(poison_parts, list) or any(
        not isinstance(part, str) for part in poison_parts
    ):
        raise TemplateSnapshotError(
            f"snapshot example {position} 'poison_parts' must be a list of strings"
        )
    return ExampleTemplate(
        task_id=_require_str(item, "task_id"),
        instruct_prompt=_require_str(item, "instruct_prompt"),
        code=_require_str(item, "code"),
        cot=_require_str(item, "cot"),
        is_poisoned=bool(item.get("is_poisoned")),
        trigger=item.get("trigger"),
        poison_parts=tuple(poison_parts),
    )


# --------------------------------------------------------------------------- #
# Snapshot construction from clean few-shot material
# --------------------------------------------------------------------------- #


def snapshot_from_clean(
    *,
    assets_root: Path | str,
    combination_id: str,
    form: str,
    experiment: str,
    trigger: str | None = DEFAULT_TRIGGER,
    injection_position: str | None = DEFAULT_INJECTION_POSITION,
    mode: str = "instruction_injection",
    prompt_version: str = "1",
) -> TemplateSnapshot:
    """Build a snapshot from the clean few-shot experiment.

    Example 1 (internal index 0) is frozen: its ``instruct_prompt`` is kept
    unchanged and it is never poisoned.  Examples 2..N get ``trigger`` injected
    into the ``instruct_prompt`` only; their ``code``/``cot`` stay byte-for-byte
    identical to the clean source.  Passing ``trigger=None`` (and
    ``injection_position=None``) is an explicit request for a clean-like
    snapshot: nothing is injected and every example is un-poisoned.
    """

    root = Path(assets_root)
    examples = load_fewshot_examples(
        assets_root=root,
        combination_id=combination_id,
        experiment=experiment,
    )
    if not examples:
        raise TemplateSnapshotError(
            f"clean experiment {combination_id!r}/{experiment!r} has no examples"
        )
    specs, config_path, _taxonomy = load_specs(root)
    spec = specs.get(combination_id)
    if spec is None:
        raise TemplateSnapshotError(
            f"unknown combination {combination_id!r}; known: {sorted(specs)}"
        )

    poisoning = trigger is not None and injection_position is not None
    if trigger is not None and injection_position not in SUPPORTED_INJECTION_POSITIONS:
        raise TemplateSnapshotError(
            f"injection_position {injection_position!r} is not implemented; "
            f"supported: {SUPPORTED_INJECTION_POSITIONS}.  Recording an unsupported "
            "position would make attack_config disagree with the rendered bytes."
        )
    templates: list[ExampleTemplate] = []
    for example in examples:
        clean_prompt = example.instruct_prompt
        if poisoning and example.index >= 1:
            injected = inject_trigger(clean_prompt, trigger)
            if (
                not has_standalone_trigger(clean_prompt, trigger)
                and injected == clean_prompt
            ):
                raise TemplateSnapshotError(
                    f"trigger {trigger!r} injection left example "
                    f"{example.index + 1} instruct_prompt unchanged; refusing to "
                    "record a no-op poison"
                )
            templates.append(
                ExampleTemplate(
                    task_id=example.task_id,
                    instruct_prompt=injected,
                    code=example.code,
                    cot=_cot_text(example.cot),
                    is_poisoned=True,
                    trigger=trigger,
                    poison_parts=(),
                )
            )
        else:
            templates.append(
                ExampleTemplate(
                    task_id=example.task_id,
                    instruct_prompt=clean_prompt,
                    code=example.code,
                    cot=_cot_text(example.cot),
                    is_poisoned=False,
                    trigger=None,
                    poison_parts=(),
                )
            )

    fewshot_path = Path(examples[0].source_path)
    meta_path = fewshot_path.parent / "meta.json"
    if not meta_path.is_file():
        raise TemplateSnapshotError(f"clean meta.json not found next to {fewshot_path}")
    try:
        task_path = resolve_within(root, spec.task_file)
    except Exception as error:  # noqa: BLE001 - one clear asset error
        raise TemplateSnapshotError(
            f"routed task file reference is invalid for {combination_id!r}: {error}"
        ) from error
    if not task_path.is_file():
        raise TemplateSnapshotError(
            f"routed task file not found for {combination_id!r}: {spec.task_file}"
        )

    source = {
        "clean_experiment": experiment,
        "fewshot_path": relative_to_root(root, fewshot_path),
        "fewshot_sha256": examples[0].source_sha256,
        "meta_path": relative_to_root(root, meta_path),
        "meta_sha256": sha256_file(meta_path),
        "task_file": spec.task_file,
        "task_file_sha256": sha256_file(task_path),
        "registry_config": str(config_path),
    }
    return TemplateSnapshot(
        combination_id=combination_id,
        form=form,
        prompt_version=prompt_version,
        protocol_version=TEMPLATE_SCHEMA_VERSION,
        trigger=trigger,
        injection_position=injection_position,
        mode=mode,
        examples=tuple(templates),
        source=source,
    )


# --------------------------------------------------------------------------- #
# Sparse field patches (atomic, real before/after diff)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PatchPolicy:
    """A caller-provided allow-list.

    ``allowed_examples`` uses the external 1-based example numbers; the
    template service validates a patch against this set but never chooses it.
    """

    allowed_examples: tuple[int, ...]
    allowed_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        seen: set[int] = set()
        for example_number in self.allowed_examples:
            if (
                isinstance(example_number, bool)
                or not isinstance(example_number, int)
                or example_number < 1
            ):
                raise TemplateSnapshotError(
                    "allowed example numbers must be positive 1-based integers, "
                    f"got {example_number!r}"
                )
            if example_number in seen:
                raise TemplateSnapshotError(
                    f"duplicate allowed example number {example_number}"
                )
            seen.add(example_number)
        for field_name in self.allowed_fields:
            if field_name not in PATCH_FIELDS:
                raise TemplateSnapshotError(
                    f"unknown patch field {field_name!r}; allowed are {PATCH_FIELDS}"
                )


@dataclass(frozen=True)
class PatchResult:
    snapshot: "TemplateSnapshot"
    changed: bool
    diff: list[dict[str, Any]]
    content_sha256: str


def _validate_patch(
    snapshot: TemplateSnapshot,
    patch: Sequence[Mapping[str, Any]],
    policy: PatchPolicy,
) -> list[tuple[int, dict[str, str]]]:
    if isinstance(patch, (str, bytes)) or not isinstance(patch, Sequence):
        raise TemplateSnapshotError("patch must be a sequence of per-example mappings")
    plan: list[tuple[int, dict[str, str]]] = []
    seen_examples: set[int] = set()
    for position, entry in enumerate(patch):
        if not isinstance(entry, Mapping):
            raise TemplateSnapshotError(f"patch entry {position} is not a mapping")
        unknown = sorted(set(entry) - {"example", "code", "cot"})
        if unknown:
            raise TemplateSnapshotError(
                f"patch entry {position} has unknown keys {unknown}; only "
                "'example', 'code' and 'cot' may be supplied"
            )
        if "example" not in entry:
            raise TemplateSnapshotError(f"patch entry {position} is missing 'example'")
        example_number = entry["example"]
        if isinstance(example_number, bool) or not isinstance(example_number, int):
            raise TemplateSnapshotError(
                f"patch entry {position} 'example' must be a 1-based integer, "
                f"got {example_number!r}"
            )
        if example_number not in policy.allowed_examples:
            raise TemplateSnapshotError(
                f"example {example_number} is not in the patch policy allowed set "
                f"{policy.allowed_examples}"
            )
        if example_number > len(snapshot.examples):
            raise TemplateSnapshotError(
                f"example {example_number} out of range: snapshot has "
                f"{len(snapshot.examples)} examples"
            )
        if example_number in seen_examples:
            raise TemplateSnapshotError(
                f"example {example_number} appears more than once in the patch"
            )
        seen_examples.add(example_number)

        fields = {name: entry[name] for name in PATCH_FIELDS if name in entry}
        if not fields:
            raise TemplateSnapshotError(
                f"patch entry {position} for example {example_number} supplies no "
                "code/cot field"
            )
        for field_name, value in fields.items():
            if field_name not in policy.allowed_fields:
                raise TemplateSnapshotError(
                    f"field {field_name!r} for example {example_number} is not in the "
                    f"patch policy allowed fields {policy.allowed_fields}"
                )
            if not isinstance(value, str):
                raise TemplateSnapshotError(
                    f"field {field_name!r} for example {example_number} must be a "
                    f"string, got {type(value).__name__}"
                )
        plan.append((example_number, fields))
    return plan


def apply_patch(
    snapshot: TemplateSnapshot,
    patch: Sequence[Mapping[str, Any]],
    policy: PatchPolicy,
) -> PatchResult:
    """Apply a sparse patch atomically, returning the real before/after diff.

    The whole patch is validated before anything is built: a rejected patch
    leaves the parent snapshot untouched (the dataclasses are frozen, so the
    original tuple is never mutated in place).  A field only joins the example's
    ``poison_parts`` when its value actually changes; a no-op patch returns the
    parent snapshot and its existing content hash rather than fabricating a new
    content version.
    """

    if not isinstance(snapshot, TemplateSnapshot):
        raise TemplateSnapshotError("apply_patch requires a TemplateSnapshot")
    if not isinstance(policy, PatchPolicy):
        raise TemplateSnapshotError("apply_patch requires a PatchPolicy")

    plan = _validate_patch(snapshot, patch, policy)

    diff: list[dict[str, Any]] = []
    after_by_example: dict[int, dict[str, str]] = {}
    changed_fields_by_example: dict[int, list[str]] = {}
    for example_number, fields in plan:
        original = snapshot.examples[example_number - 1]
        for field_name in PATCH_FIELDS:
            if field_name not in fields:
                continue
            before = getattr(original, field_name)
            after = fields[field_name]
            changed = before != after
            diff.append(
                {
                    "example": example_number,
                    "field": field_name,
                    "before": before,
                    "after": after,
                    "changed": changed,
                }
            )
            if changed:
                after_by_example.setdefault(example_number, {})[field_name] = after
                changed_fields_by_example.setdefault(example_number, []).append(
                    field_name
                )
    diff.sort(key=lambda item: (item["example"], PATCH_FIELDS.index(item["field"])))

    if not changed_fields_by_example:
        return PatchResult(
            snapshot=snapshot,
            changed=False,
            diff=diff,
            content_sha256=snapshot.content_sha256(),
        )

    new_templates = list(snapshot.examples)
    for example_number, changed_fields in changed_fields_by_example.items():
        original = snapshot.examples[example_number - 1]
        new_parts = list(original.poison_parts)
        for field_name in PATCH_FIELDS:
            if field_name in changed_fields and field_name not in new_parts:
                new_parts.append(field_name)
        replacements = after_by_example.get(example_number, {})
        new_templates[example_number - 1] = ExampleTemplate(
            task_id=original.task_id,
            instruct_prompt=original.instruct_prompt,
            code=replacements.get("code", original.code),
            cot=replacements.get("cot", original.cot),
            is_poisoned=original.is_poisoned,
            trigger=original.trigger,
            poison_parts=tuple(new_parts),
        )
    new_snapshot = TemplateSnapshot(
        combination_id=snapshot.combination_id,
        form=snapshot.form,
        prompt_version=snapshot.prompt_version,
        protocol_version=snapshot.protocol_version,
        trigger=snapshot.trigger,
        injection_position=snapshot.injection_position,
        mode=snapshot.mode,
        examples=tuple(new_templates),
        source=dict(snapshot.source),
    )
    return PatchResult(
        snapshot=new_snapshot,
        changed=True,
        diff=diff,
        content_sha256=new_snapshot.content_sha256(),
    )


# --------------------------------------------------------------------------- #
# Content-addressed storage
# --------------------------------------------------------------------------- #


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def version_dir(store_root: Path | str, snapshot: TemplateSnapshot) -> Path:
    """Return the content-addressed version directory for ``snapshot``."""

    return Path(store_root) / snapshot.combination_id / snapshot.content_sha256()


def write_snapshot(
    store_root: Path | str,
    snapshot: TemplateSnapshot,
    *,
    action_id: str | None = None,
    parent_sha256: str | None = None,
    diff: Any = None,
    created_at: str | None = None,
) -> Path:
    """Write ``snapshot.json`` under a content-addressed version directory.

    Re-writing identical content is idempotent; a version directory that stores
    different content is never overwritten.  One audit line is appended per
    call to ``<store_root>/audit.jsonl``; audit fields never enter the content
    identity.
    """

    if not isinstance(snapshot, TemplateSnapshot):
        raise TemplateSnapshotError("write_snapshot requires a TemplateSnapshot")
    root = Path(store_root)
    content_sha = snapshot.content_sha256()
    directory = root / snapshot.combination_id / content_sha
    if directory.exists():
        existing = read_snapshot(directory)
        if existing.content_sha256() != content_sha:
            raise TemplateSnapshotError(
                f"refusing to overwrite {directory}: it stores content "
                f"{existing.content_sha256()} but {content_sha} was requested"
            )
        if existing.source != snapshot.source:
            raise TemplateSnapshotError(
                f"refusing to overwrite {directory}: it stores provenance "
                f"{existing.source!r} but {snapshot.source!r} was supplied for the "
                "same content"
            )
    write_json_atomic(directory / "snapshot.json", snapshot.to_json())
    append_jsonl(
        root / "audit.jsonl",
        {
            "schema_version": TEMPLATE_SCHEMA_VERSION,
            "action_id": action_id,
            "parent_sha256": parent_sha256,
            "content_sha256": content_sha,
            "created_at": created_at if created_at is not None else _utc_now(),
            "diff": list(diff) if diff is not None else [],
        },
    )
    return directory


def read_snapshot(path: Path | str) -> TemplateSnapshot:
    """Read and verify a version directory or its ``snapshot.json``.

    The recomputed content hash must match both the stored ``content_sha256``
    and the version directory name; any missing, malformed or mismatching file
    raises :class:`TemplateSnapshotError`.
    """

    target = Path(path)
    snapshot_path = target / "snapshot.json" if target.is_dir() else target
    if not snapshot_path.is_file():
        raise TemplateSnapshotError(f"snapshot file not found: {snapshot_path}")
    try:
        payload = read_json(snapshot_path)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise TemplateSnapshotError(
            f"cannot read snapshot {snapshot_path}: {error}"
        ) from error
    if not isinstance(payload, Mapping):
        raise TemplateSnapshotError(
            f"snapshot {snapshot_path} must contain a JSON object"
        )
    stored = payload.get("content_sha256")
    snapshot = TemplateSnapshot.from_json(payload)
    recomputed = snapshot.content_sha256()
    if not isinstance(stored, str) or stored != recomputed:
        raise TemplateSnapshotError(
            f"snapshot {snapshot_path} content hash mismatch: stored {stored!r} "
            f"!= recomputed {recomputed}"
        )
    if snapshot_path.parent.name != recomputed:
        raise TemplateSnapshotError(
            f"snapshot {snapshot_path} lives in version directory "
            f"{snapshot_path.parent.name!r} but its content hash is {recomputed}"
        )
    return snapshot


def assert_snapshot_immutable(
    store_root: Path | str, snapshot: TemplateSnapshot
) -> Path:
    """Require that a stored version for this exact content exists and matches."""

    if not isinstance(snapshot, TemplateSnapshot):
        raise TemplateSnapshotError(
            "assert_snapshot_immutable requires a TemplateSnapshot"
        )
    directory = version_dir(store_root, snapshot)
    if not directory.is_dir():
        raise TemplateSnapshotError(f"no stored snapshot version found at {directory}")
    stored = read_snapshot(directory)
    if stored.content_json() != snapshot.content_json():
        raise TemplateSnapshotError(
            f"stored snapshot at {directory} does not match the given content"
        )
    return directory


__all__ = [
    "TEMPLATE_SCHEMA_VERSION",
    "DEFAULT_TRIGGER",
    "DEFAULT_INJECTION_POSITION",
    "SUPPORTED_INJECTION_POSITIONS",
    "PATCH_FIELDS",
    "TemplateSnapshotError",
    "ExampleTemplate",
    "TemplateSnapshot",
    "PatchPolicy",
    "PatchResult",
    "snapshot_from_clean",
    "apply_patch",
    "version_dir",
    "write_snapshot",
    "read_snapshot",
    "assert_snapshot_immutable",
]
