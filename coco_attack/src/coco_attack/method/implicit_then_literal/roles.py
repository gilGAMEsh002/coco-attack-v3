"""Proposer/inducer role protocols for ``implicit_then_literal`` (subplan 02).

This module owns the method-specific prompt assembly, JSON response parsing and
the thin adaptation onto the shared role-call service.  It contains no storage,
evidence completeness or experience-version logic (that is
:mod:`coco_attack.method.implicit_then_literal.experience`).

Two roles are kept apart:

* the proposer (甲) uses ``kind="mutator"`` and proposes A code patches or B
  scoped renames + CoT;
* the inducer (乙) uses ``kind="reasoning"`` and produces experience entries and
  a refreshed summary.  It never produces a template patch.

Model output is never trusted as a patch: A goes through
``parse_sparse_patch``/``apply_patch`` (code only, examples 2-4) and B goes
through :func:`apply_b_modification` after readable scope labels are mapped back
to the real ``scope_id``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ...assets.artifacts import canonical_json_bytes, sha256_bytes
from ...iteration.action_runtime import (
    ActionStore,
    ContextAssemblyError,
    ContextBudget,
    HeuristicTokenCounter,
    RoleActionRequest,
    RoleCallConfig,
    RoleCallOutcome,
    RoleCallSource,
    parse_sparse_patch,
    run_role_call,
)
from ...iteration.method_inputs import MethodInputs
from ...iteration.template_snapshot import (
    PatchPolicy,
    PatchResult,
    TemplateSnapshot,
    TemplateSnapshotError,
    apply_patch,
)
from .contracts import (
    B_STATUS_LEGAL,
    B_STATUS_NO_CHANGE,
    BModificationRequest,
    BModificationResult,
    CandidateIdentity,
    ExampleModification,
    ExperienceVersionReference,
    ImplicitThenLiteralContractError,
    MODIFIABLE_EXAMPLES,
    RenameMapping,
    UnsupportedRename,
)
from .literal import apply_b_modification, enumerate_rename_targets
from . import prompt_renderer
from .prompt_renderer import (
    render as render_prompt,
    template_identity,
    with_prompt_bundle,
)

A_PROTOCOL_VERSION = "itl-a-proposal-v2"
B_PROTOCOL_VERSION = "itl-b-proposal-v2"
JUDGE_PROTOCOL_VERSION = "itl-judge-induction-v2"

PROPOSER_ROLE = "implicit_then_literal_proposer"
INDUCER_ROLE = "implicit_then_literal_inducer"

DEFAULT_MODEL = "deepseek-v4-flash"
DEFAULT_TEMPERATURE = 0.7
DEFAULT_MAX_TOKENS = 384000
DEFAULT_REQUEST_TIMEOUT = 120.0
DEFAULT_MAX_REQUEST_ATTEMPTS = 2

#: README §5.1 (2026-10-05): context 1000000, output reserve 384000, margin 0 ->
#: input 616000.  The output cap is set to the user-specified maximum for
#: ``deepseek-v4.1-flash`` so a reasoning model can finish its
#: ``reasoning_content`` and emit the answer.
DEFAULT_CONTEXT_BUDGET = ContextBudget(
    context_window_tokens=1000000, output_reserve_tokens=384000, margin_tokens=0
)
INPUT_BUDGET_TOKENS = DEFAULT_CONTEXT_BUDGET.available

#: Conservative, versioned engineering cap for the refreshed experience summary.
#: Chosen so the summary can never crowd out the current template evidence under
#: the 24576-token input budget; over-limit output is a protocol failure.
SUMMARY_MAX_CHARS = 4000
SUMMARY_LIMIT_VERSION = "itl-summary-limit-v1"
INPUT_BUDGET_VERSION = "itl-input-budget-v3"

_A_PATCH_POLICY = PatchPolicy(allowed_examples=MODIFIABLE_EXAMPLES, allowed_fields=("code",))
_WHOLE_FENCE_RE = re.compile(r"\A\s*```(?:json)?[ \t]*\n?(?P<body>.*?)\n?```\s*\Z", re.DOTALL)
_COUNTER = HeuristicTokenCounter()

_STATUS_MATERIALIZED = "materialized"
_STATUS_NO_CHANGE = "no_change"
_STATUS_INVALID = "invalid"
_STATUS_PROTOCOL_ERROR = "protocol_error"
_STATUS_FAILED = "failed"
_STATUS_PAUSED_UNKNOWN = "paused_unknown"
_STATUS_PARSED = "parsed"


class RoleProtocolError(ValueError):
    """Raised when a role response cannot be parsed as the agreed JSON shape."""


class RoleCapacityError(ContextAssemblyError):
    """The fixed role input does not fit the configured input budget."""


# --------------------------------------------------------------------------- #
# Readable rename-target view (B)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RenameTargetView:
    """Model-readable view of one example's renameable targets."""

    example: int
    scope_label: str | None
    scope_id: str | None
    names: tuple[str, ...]
    unsupported: tuple[UnsupportedRename, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "example": self.example,
            "scope_label": self.scope_label,
            "scope_id": self.scope_id,
            "names": list(self.names),
            "unsupported": [item.to_json() for item in self.unsupported],
        }


def build_rename_target_view(
    snapshot: TemplateSnapshot, examples: Sequence[int] = MODIFIABLE_EXAMPLES
) -> tuple[RenameTargetView, ...]:
    """Enumerate rename targets and assign a stable, readable scope label.

    The label is bound to the parent content hash so it is stable for one parent
    and cannot silently mean a different scope in another snapshot.
    """

    views: list[RenameTargetView] = []
    for example in examples:
        report = enumerate_rename_targets(snapshot, example)
        # A readable label, stable for one parent snapshot.  It deliberately
        # carries no internal hash; the label->scope_id map is supplied per
        # request and the scope_id itself stays parent-bound.
        scope_label = f"scope-{example}" if report.scope_id is not None else None
        views.append(
            RenameTargetView(
                example=example,
                scope_label=scope_label,
                scope_id=report.scope_id,
                names=tuple(target.name for target in report.targets),
                unsupported=report.unsupported,
            )
        )
    return tuple(views)


def scope_label_map(views: Sequence[RenameTargetView]) -> dict[str, str]:
    """Map readable scope labels back to the trusted real ``scope_id``."""

    return {
        view.scope_label: view.scope_id
        for view in views
        if view.scope_label is not None and view.scope_id is not None
    }


# --------------------------------------------------------------------------- #
# Inputs and results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RoleMessages:
    protocol_version: str
    messages: tuple[dict[str, str], ...]
    input_refs: Mapping[str, str]
    estimated_input_tokens: int
    counter_method: str
    budget_version: str = INPUT_BUDGET_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "messages": [dict(message) for message in self.messages],
            "input_refs": dict(self.input_refs),
            "estimated_input_tokens": self.estimated_input_tokens,
            "counter_method": self.counter_method,
            "budget_version": self.budget_version,
        }


@dataclass(frozen=True)
class AProposalInput:
    candidate: CandidateIdentity
    parent_snapshot: TemplateSnapshot
    materials: MethodInputs
    experience_versions: tuple[ExperienceVersionReference, ...] = ()
    structure_priors: tuple[str, ...] = ()
    protocol_version: str = A_PROTOCOL_VERSION


@dataclass(frozen=True)
class AProposalResult:
    candidate: CandidateIdentity
    status: str
    structure: str | None
    snapshot: TemplateSnapshot
    content_sha256: str
    diff: tuple[Mapping[str, Any], ...] = ()
    patch_result: PatchResult | None = None
    errors: tuple[str, ...] = ()
    action_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.logical_id(),
            "status": self.status,
            "structure": self.structure,
            "content_sha256": self.content_sha256,
            "diff": [dict(entry) for entry in self.diff],
            "errors": list(self.errors),
            "action_id": self.action_id,
        }


@dataclass(frozen=True)
class BProposalInput:
    candidate: CandidateIdentity
    parent_snapshot: TemplateSnapshot
    materials: MethodInputs
    target_views: tuple[RenameTargetView, ...]
    experience_versions: tuple[ExperienceVersionReference, ...] = ()
    structure_priors: tuple[str, ...] = ()
    protocol_version: str = B_PROTOCOL_VERSION


@dataclass(frozen=True)
class BProposalResult:
    candidate: CandidateIdentity
    status: str
    modification: BModificationResult | None
    errors: tuple[str, ...] = ()
    action_id: str | None = None

    @property
    def snapshot(self) -> TemplateSnapshot | None:
        return self.modification.snapshot if self.modification is not None else None

    def to_json(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.logical_id(),
            "status": self.status,
            "modification": self.modification.to_json() if self.modification else None,
            "errors": list(self.errors),
            "action_id": self.action_id,
        }


@dataclass(frozen=True)
class ExperienceEntryDraft:
    label: str
    nature: str
    description: str
    change: str
    evidence: tuple[str, ...]
    uncertainty: str
    revision_of: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "nature": self.nature,
            "description": self.description,
            "change": self.change,
            "evidence": list(self.evidence),
            "uncertainty": self.uncertainty,
            "revision_of": self.revision_of,
        }


@dataclass(frozen=True)
class JudgeInput:
    category: str
    previous_experience: ExperienceVersionReference
    evidence: Mapping[str, Any]
    known_evidence_labels: tuple[str, ...]
    experience_versions: tuple[ExperienceVersionReference, ...] = ()
    known_entry_labels: tuple[str, ...] = ()
    failure_summary: Mapping[str, Any] | None = None
    protocol_version: str = JUDGE_PROTOCOL_VERSION


@dataclass(frozen=True)
class JudgeResult:
    category: str
    status: str
    entries: tuple[ExperienceEntryDraft, ...] = ()
    summary: str | None = None
    errors: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "status": self.status,
            "entries": [entry.to_json() for entry in self.entries],
            "summary": self.summary,
            "errors": list(self.errors),
        }


# --------------------------------------------------------------------------- #
# Prompt assembly
# --------------------------------------------------------------------------- #

def _render_experience_block(reference: ExperienceVersionReference) -> str:
    return render_prompt(
        "shared.experience.md.j2",
        category=reference.category,
        version_id=reference.version_id,
        previous_version_id=reference.previous_version_id,
        summary=reference.summary,
    )


def _render_experience_versions(
    references: Sequence[ExperienceVersionReference],
) -> str:
    if not references:
        return render_prompt("shared.experiences-empty.md.j2")
    return "\n\n".join(_render_experience_block(reference) for reference in references)


def _render_revisable_entries(request: JudgeInput) -> str:
    """List the only labels ``revision_of`` may cite (current category chain)."""

    labels = request.previous_experience.entry_labels
    if not labels:
        return render_prompt("shared.revisable-entries-empty.md.j2")
    return "\n".join(f"- {label}" for label in labels)


def _render_materials_block(materials: MethodInputs) -> str:
    return render_prompt(
        "shared.materials.md.j2",
        system_prefix=materials.system_prefix,
        examples=materials.examples,
        semgrep_rule_text=materials.semgrep_rule_text.rstrip("\n"),
    )


def _render_target_views(views: Sequence[RenameTargetView]) -> str:
    return render_prompt(
        "shared.targets.md.j2",
        views=[
            {
                "example": view.example,
                "scope_label": view.scope_label,
                "names": list(view.names),
                "unsupported": [
                    {"name": item.name, "reason": item.reason}
                    for item in view.unsupported
                ],
            }
            for view in views
        ],
    )


def _compose_messages(system_block: str, user_block: str) -> tuple[dict[str, str], ...]:
    return (
        {"role": "system", "content": system_block},
        {"role": "user", "content": user_block},
    )


def _finalize(
    protocol_version: str,
    messages: tuple[dict[str, str], ...],
    input_refs: Mapping[str, str],
) -> RoleMessages:
    tokens = _COUNTER.count(list(messages))
    if tokens > INPUT_BUDGET_TOKENS:
        raise RoleCapacityError(
            f"role input needs an estimated {tokens} tokens but the input budget is "
            f"{INPUT_BUDGET_TOKENS} ({_COUNTER.method}); refusing to call the model"
        )
    return RoleMessages(
        protocol_version=protocol_version,
        messages=messages,
        input_refs=dict(input_refs),
        estimated_input_tokens=tokens,
        counter_method=_COUNTER.method,
    )


@with_prompt_bundle
def build_a_messages(request: AProposalInput) -> RoleMessages:
    """Assemble the A proposal system/user messages (caller-provided template)."""

    if request.parent_snapshot is None:
        raise ImplicitThenLiteralContractError("A proposal requires a parent snapshot")
    materials = _render_materials_block(request.materials)
    experiences = _render_experience_versions(request.experience_versions)
    priors = _render_prior_structures(request.structure_priors)
    system = render_prompt("a.system.md.j2", materials=materials,
                           experiences=experiences, priors=priors,
                           output_format=render_prompt("a.output.md.j2"))
    user = render_prompt("a.user.md.j2", template_text=request.materials.current_template_text,
                         goal=render_prompt("a.goal.md.j2"))
    return _finalize(
        request.protocol_version,
        _compose_messages(system, user),
        {
            "experience_version_ids": ",".join(
                reference.version_id for reference in request.experience_versions
            ),
            "parent_content_sha256": request.parent_snapshot.content_sha256(),
            "material_sha256": request.materials.material_sha256(),
            "semgrep_rule_id": request.materials.semgrep_rule_id,
            "prompt_template_sha256": template_identity(),
        },
    )


@with_prompt_bundle
def build_b_messages(request: BProposalInput) -> RoleMessages:
    """Assemble the B proposal system/user messages."""

    if request.parent_snapshot is None:
        raise ImplicitThenLiteralContractError("B proposal requires a parent snapshot")
    system = render_prompt(
        "b.system.md.j2", materials=_render_materials_block(request.materials),
        targets=_render_target_views(request.target_views),
        experiences=_render_experience_versions(request.experience_versions),
        priors=_render_prior_structures(request.structure_priors),
        output_format=render_prompt("b.output.md.j2"),
    )
    user = render_prompt("b.user.md.j2", template_text=request.materials.current_template_text)
    return _finalize(
        request.protocol_version,
        _compose_messages(system, user),
        {
            "experience_version_ids": ",".join(
                reference.version_id for reference in request.experience_versions
            ),
            "parent_content_sha256": request.parent_snapshot.content_sha256(),
            "material_sha256": request.materials.material_sha256(),
            "prompt_template_sha256": template_identity(),
        },
    )


def _render_prior_structures(priors: Sequence[str]) -> str:
    if not priors:
        return ""
    return render_prompt("shared.prior-structures.md.j2", priors=priors)


@with_prompt_bundle
def build_judge_messages(request: JudgeInput) -> RoleMessages:
    """Assemble the inducer messages from a model-visible evidence projection."""

    # The inducer may read both categories (structure + literal) even though it
    # only refreshes the category being updated.
    context = list(request.experience_versions) or [request.previous_experience]
    if request.previous_experience not in context:
        context.insert(0, request.previous_experience)
    seen_versions: set[str] = set()
    rendered: list[str] = []
    for reference in context:
        if reference.version_id in seen_versions:
            continue
        seen_versions.add(reference.version_id)
        rendered.append(_render_experience_block(reference))
    system = render_prompt(
        "inducer.system.md.j2", category=request.category,
        experiences="\n\n".join(rendered),
        revisable_entries=_render_revisable_entries(request),
        evidence=json.dumps(request.evidence, ensure_ascii=False, sort_keys=True, indent=2),
        failure_summary=(json.dumps(request.failure_summary, ensure_ascii=False, sort_keys=True)
                         if request.failure_summary is not None else None),
        output_format=render_prompt("inducer.output.md.j2"),
    )
    user = render_prompt("inducer.user.md.j2", category=request.category)
    return _finalize(
        request.protocol_version,
        _compose_messages(system, user),
        {
            "previous_version_id": request.previous_experience.version_id,
            "category": request.category,
            "prompt_template_sha256": template_identity(),
        },
    )


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #


def _load_json_object(text: str) -> Mapping[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise RoleProtocolError("response is empty")
    candidate = text.strip()
    try:
        parsed = json.loads(candidate)
    except ValueError as first_error:
        match = _WHOLE_FENCE_RE.fullmatch(candidate)
        if match is None:
            raise RoleProtocolError(f"invalid JSON: {first_error}") from first_error
        body = match.group("body").strip()
        if not body:
            raise RoleProtocolError("response is empty")
        try:
            parsed = json.loads(body)
        except ValueError as error:
            raise RoleProtocolError(f"invalid JSON: {error}") from error
    if not isinstance(parsed, Mapping):
        raise RoleProtocolError("response must be a JSON object")
    return parsed


def parse_a_response(
    text: str, *, candidate: CandidateIdentity, parent_snapshot: TemplateSnapshot
) -> AProposalResult:
    """Parse and materialize an A proposal (code-only patch, examples 2-4)."""

    def _error(message: str) -> AProposalResult:
        return AProposalResult(
            candidate=candidate,
            status=_STATUS_PROTOCOL_ERROR,
            structure=None,
            snapshot=parent_snapshot,
            content_sha256=parent_snapshot.content_sha256(),
            errors=(message,),
        )

    try:
        payload = _load_json_object(text)
    except RoleProtocolError as error:
        return _error(str(error))
    unknown = sorted(set(payload) - {"structure", "patch"})
    if unknown:
        return _error(f"unknown top-level fields: {unknown}")
    structure = payload.get("structure")
    if not isinstance(structure, str) or not structure.strip():
        return _error("'structure' must be a non-empty string")
    patch = payload.get("patch")
    if not isinstance(patch, list):
        return _error("'patch' must be a list")

    parsed_patch = parse_sparse_patch(json.dumps(patch, ensure_ascii=False))
    if parsed_patch.patch is None:
        return _error(f"patch is not a valid sparse patch: {parsed_patch.error}")
    try:
        patch_result = apply_patch(parent_snapshot, list(parsed_patch.patch), _A_PATCH_POLICY)
    except TemplateSnapshotError as error:
        return AProposalResult(
            candidate=candidate,
            status=_STATUS_INVALID,
            structure=structure,
            snapshot=parent_snapshot,
            content_sha256=parent_snapshot.content_sha256(),
            errors=(str(error),),
        )
    status = _STATUS_MATERIALIZED if patch_result.changed else _STATUS_NO_CHANGE
    return AProposalResult(
        candidate=candidate,
        status=status,
        structure=structure,
        snapshot=patch_result.snapshot,
        content_sha256=patch_result.content_sha256,
        diff=tuple(patch_result.diff),
        patch_result=patch_result,
    )


def parse_b_response(
    text: str,
    *,
    candidate: CandidateIdentity,
    parent_snapshot: TemplateSnapshot,
    target_views: Sequence[RenameTargetView],
) -> BProposalResult:
    """Parse a B proposal, map readable scope labels to real ids and materialize."""

    def _error(message: str, status: str = _STATUS_PROTOCOL_ERROR) -> BProposalResult:
        return BProposalResult(candidate=candidate, status=status, modification=None, errors=(message,))

    try:
        payload = _load_json_object(text)
    except RoleProtocolError as error:
        return _error(str(error))
    unknown = sorted(set(payload) - {"modifications"})
    if unknown:
        return _error(f"unknown top-level fields: {unknown}")
    raw_mods = payload.get("modifications")
    if not isinstance(raw_mods, list) or not raw_mods:
        return _error("'modifications' must be a non-empty list")

    label_to_id = scope_label_map(target_views)
    modifications = []
    for index, raw in enumerate(raw_mods):
        if not isinstance(raw, Mapping):
            return _error(f"modification {index} is not an object")
        extra = sorted(set(raw) - {"example", "renames", "new_cot"})
        if extra:
            return _error(f"modification {index} has unknown fields: {extra}")
        example = raw.get("example")
        if isinstance(example, bool) or not isinstance(example, int):
            return _error(f"modification {index} 'example' must be an integer")
        if example < 1:
            return _error(f"modification {index} 'example' must be a positive 1-based integer")
        raw_renames = raw.get("renames", [])
        if not isinstance(raw_renames, list):
            return _error(f"modification {index} 'renames' must be a list")
        renames = []
        for rename_index, rename in enumerate(raw_renames):
            if not isinstance(rename, Mapping):
                return _error(f"rename {rename_index} in modification {index} is not an object")
            extra_rename = sorted(set(rename) - {"scope", "from", "to"})
            if extra_rename:
                return _error(
                    f"rename {rename_index} in modification {index} has unknown fields: {extra_rename}"
                )
            label = rename.get("scope")
            old = rename.get("from")
            new = rename.get("to")
            if not all(isinstance(value, str) and value for value in (label, old, new)):
                return _error(f"rename {rename_index} in modification {index} needs string scope/from/to")
            scope_id = label_to_id.get(label)
            if scope_id is None:
                return _error(f"unknown scope label {label!r} in modification {index}")
            renames.append(RenameMapping(scope_id=scope_id, old_name=old, new_name=new))
        new_cot = raw.get("new_cot")
        if new_cot is not None and not isinstance(new_cot, str):
            return _error(f"modification {index} 'new_cot' must be a string or null")
        modifications.append(
            ExampleModification(example=example, renames=tuple(renames), new_cot=new_cot)
        )

    request = BModificationRequest(
        candidate=candidate,
        parent_content_sha256=parent_snapshot.content_sha256(),
        modifications=tuple(modifications),
    )
    outcome = apply_b_modification(parent_snapshot, request)
    if outcome.status == B_STATUS_LEGAL:
        status = _STATUS_MATERIALIZED
    elif outcome.status == B_STATUS_NO_CHANGE:
        status = _STATUS_NO_CHANGE
    else:
        status = _STATUS_INVALID
    return BProposalResult(
        candidate=candidate,
        status=status,
        modification=outcome,
        errors=tuple(error.reason for error in outcome.errors),
    )


def parse_judge_response(
    text: str,
    *,
    category: str,
    known_evidence_labels: Sequence[str],
    known_entry_labels: Sequence[str] = (),
) -> JudgeResult:
    """Parse an inducer response and validate entry shape and evidence refs."""

    def _error(message: str) -> JudgeResult:
        return JudgeResult(category=category, status=_STATUS_PROTOCOL_ERROR, errors=(message,))

    try:
        payload = _load_json_object(text)
    except RoleProtocolError as error:
        return _error(str(error))
    unknown = sorted(set(payload) - {"entries", "summary"})
    if unknown:
        return _error(f"unknown top-level fields: {unknown}")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        return _error("'entries' must be a non-empty list")
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return _error("'summary' must be a non-empty string")
    if len(summary) > SUMMARY_MAX_CHARS:
        return _error(
            f"summary is {len(summary)} chars, over the {SUMMARY_MAX_CHARS}-char "
            f"limit ({SUMMARY_LIMIT_VERSION}); refusing to truncate"
        )
    known = set(known_evidence_labels)
    known_entries = set(known_entry_labels)
    entries: list[ExperienceEntryDraft] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, Mapping):
            return _error(f"entry {index} is not an object")
        extra = sorted(
            set(raw)
            - {"label", "nature", "description", "change", "evidence", "uncertainty", "revision_of"}
        )
        if extra:
            return _error(f"entry {index} has unknown fields: {extra}")
        label = raw.get("label")
        if not isinstance(label, str) or not label:
            return _error(f"entry {index} 'label' must be a non-empty string")
        nature = raw.get("nature")
        if nature not in ("observation", "hypothesis"):
            return _error(f"entry {index} 'nature' must be observation or hypothesis")
        evidence = raw.get("evidence")
        if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
            return _error(f"entry {index} 'evidence' must be a list of labels")
        unknown_evidence = sorted(set(evidence) - known)
        if unknown_evidence:
            return _error(f"entry {index} cites unknown evidence labels: {unknown_evidence}")
        for field_name in ("description", "change", "uncertainty"):
            if not isinstance(raw.get(field_name), str):
                return _error(f"entry {index} '{field_name}' must be a string")
        revision_of = raw.get("revision_of")
        if revision_of is not None and revision_of not in known_entries:
            return _error(f"entry {index} references unknown previous entry {revision_of!r}")
        entries.append(
            ExperienceEntryDraft(
                label=label,
                nature=nature,
                description=str(raw.get("description")),
                change=str(raw.get("change")),
                evidence=tuple(evidence),
                uncertainty=str(raw.get("uncertainty")),
                revision_of=revision_of,
            )
        )
    return JudgeResult(
        category=category, status=_STATUS_PARSED, entries=tuple(entries), summary=summary
    )


# --------------------------------------------------------------------------- #
# Role-call adaptation
# --------------------------------------------------------------------------- #


def _role_config(role: str, protocol_version: str, **overrides: Any) -> RoleCallConfig:
    base: dict[str, Any] = {
        "role": role,
        "model": DEFAULT_MODEL,
        "source": "mock",
        "temperature": DEFAULT_TEMPERATURE,
        "max_tokens": DEFAULT_MAX_TOKENS,
        "request_timeout": DEFAULT_REQUEST_TIMEOUT,
        "max_request_attempts": DEFAULT_MAX_REQUEST_ATTEMPTS,
        "protocol_version": protocol_version,
    }
    base.update(overrides)
    return RoleCallConfig(**base)


def proposer_config(
    protocol_version: str = A_PROTOCOL_VERSION, **overrides: Any
) -> RoleCallConfig:
    return _role_config(PROPOSER_ROLE, protocol_version, **overrides)


def inducer_config(
    protocol_version: str = JUDGE_PROTOCOL_VERSION, **overrides: Any
) -> RoleCallConfig:
    return _role_config(INDUCER_ROLE, protocol_version, **overrides)


def proposal_action_id(candidate: CandidateIdentity, protocol_version: str, kind: str) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "itl-role-action-v1",
                "candidate_id": candidate.logical_id(),
                "protocol_version": protocol_version,
                "kind": kind,
            }
        )
    )


def judge_action_id(induction_id: str, protocol_version: str, retry_index: int = 0) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "itl-role-action-v1",
                "induction_id": induction_id,
                "protocol_version": protocol_version,
                "kind": "judge",
                "retry_index": retry_index,
            }
        )
    )


def _action_input_refs(
    store: ActionStore, action_id: str, refs: Mapping[str, str]
) -> dict[str, str]:
    """Keep old persisted request identities for the verified legacy wording."""
    result = dict(refs)
    existing = store.read_request(action_id)
    if (
        existing is not None
        and "prompt_template_sha256" not in existing.get("input_refs", {})
        and result.get("prompt_template_sha256") == prompt_renderer.LEGACY_TEMPLATE_SHA256
    ):
        result.pop("prompt_template_sha256")
    return result


def _call(
    store: ActionStore,
    *,
    action_id: str,
    role: str,
    kind: str,
    messages: RoleMessages,
    config: RoleCallConfig,
    source: RoleCallSource,
    allow_retry_after_unknown: bool,
) -> RoleCallOutcome:
    request = RoleActionRequest(
        action_id=action_id,
        role=role,
        kind=kind,
        messages=messages.messages,
        config=config,
        input_refs=_action_input_refs(
            store, action_id,
            {**dict(messages.input_refs), "protocol_version": messages.protocol_version},
        ),
    )
    return run_role_call(
        store, request, source=source, allow_retry_after_unknown=allow_retry_after_unknown
    )


def _successful_content(outcome: RoleCallOutcome) -> str | None:
    if outcome.state not in ("response_reused", "response_saved"):
        return None
    if outcome.response_status != "success" or outcome.response is None:
        return None
    return str(outcome.response.get("content") or "")


def run_a_proposal(
    store: ActionStore,
    request: AProposalInput,
    *,
    source: RoleCallSource,
    action_id: str | None = None,
    allow_retry_after_unknown: bool = False,
    config: RoleCallConfig | None = None,
) -> AProposalResult:
    messages = build_a_messages(request)
    resolved_action_id = action_id or proposal_action_id(
        request.candidate, request.protocol_version, "a"
    )
    outcome = _call(
        store,
        action_id=resolved_action_id,
        role=PROPOSER_ROLE,
        kind="mutator",
        messages=messages,
        config=config or proposer_config(request.protocol_version),
        source=source,
        allow_retry_after_unknown=allow_retry_after_unknown,
    )
    content = _successful_content(outcome)
    if content is None:
        status = _STATUS_PAUSED_UNKNOWN if outcome.state == "unknown_paused" else _STATUS_FAILED
        return AProposalResult(
            candidate=request.candidate,
            status=status,
            structure=None,
            snapshot=request.parent_snapshot,
            content_sha256=request.parent_snapshot.content_sha256(),
            errors=(outcome.error or outcome.response_status or outcome.state,),
            action_id=resolved_action_id,
        )
    parsed = parse_a_response(
        content, candidate=request.candidate, parent_snapshot=request.parent_snapshot
    )
    return AProposalResult(
        candidate=parsed.candidate,
        status=parsed.status,
        structure=parsed.structure,
        snapshot=parsed.snapshot,
        content_sha256=parsed.content_sha256,
        diff=parsed.diff,
        patch_result=parsed.patch_result,
        errors=parsed.errors,
        action_id=resolved_action_id,
    )


def run_b_proposal(
    store: ActionStore,
    request: BProposalInput,
    *,
    source: RoleCallSource,
    action_id: str | None = None,
    allow_retry_after_unknown: bool = False,
    config: RoleCallConfig | None = None,
) -> BProposalResult:
    messages = build_b_messages(request)
    resolved_action_id = action_id or proposal_action_id(
        request.candidate, request.protocol_version, "b"
    )
    outcome = _call(
        store,
        action_id=resolved_action_id,
        role=PROPOSER_ROLE,
        kind="mutator",
        messages=messages,
        config=config or proposer_config(request.protocol_version),
        source=source,
        allow_retry_after_unknown=allow_retry_after_unknown,
    )
    content = _successful_content(outcome)
    if content is None:
        status = _STATUS_PAUSED_UNKNOWN if outcome.state == "unknown_paused" else _STATUS_FAILED
        return BProposalResult(
            candidate=request.candidate,
            status=status,
            modification=None,
            errors=(outcome.error or outcome.response_status or outcome.state,),
            action_id=resolved_action_id,
        )
    parsed = parse_b_response(
        content,
        candidate=request.candidate,
        parent_snapshot=request.parent_snapshot,
        target_views=request.target_views,
    )
    return BProposalResult(
        candidate=parsed.candidate,
        status=parsed.status,
        modification=parsed.modification,
        errors=parsed.errors,
        action_id=resolved_action_id,
    )


__all__ = [
    "A_PROTOCOL_VERSION",
    "B_PROTOCOL_VERSION",
    "JUDGE_PROTOCOL_VERSION",
    "PROPOSER_ROLE",
    "INDUCER_ROLE",
    "DEFAULT_MODEL",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_REQUEST_TIMEOUT",
    "DEFAULT_MAX_REQUEST_ATTEMPTS",
    "DEFAULT_CONTEXT_BUDGET",
    "INPUT_BUDGET_TOKENS",
    "SUMMARY_MAX_CHARS",
    "SUMMARY_LIMIT_VERSION",
    "RoleProtocolError",
    "RoleCapacityError",
    "RoleMessages",
    "RenameTargetView",
    "AProposalInput",
    "AProposalResult",
    "BProposalInput",
    "BProposalResult",
    "ExperienceEntryDraft",
    "JudgeInput",
    "JudgeResult",
    "build_rename_target_view",
    "scope_label_map",
    "build_a_messages",
    "build_b_messages",
    "build_judge_messages",
    "parse_a_response",
    "parse_b_response",
    "parse_judge_response",
    "proposer_config",
    "inducer_config",
    "proposal_action_id",
    "judge_action_id",
    "run_a_proposal",
    "run_b_proposal",
]
