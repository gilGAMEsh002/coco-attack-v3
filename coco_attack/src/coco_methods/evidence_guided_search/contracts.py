"""Method-owned JSON contracts and validation at model-output boundaries."""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

from coco_attack.iteration.action_runtime import parse_sparse_patch
from coco_attack.iteration.template_snapshot import PatchPolicy, TemplateSnapshot, apply_patch

Source = Literal["guided", "unguided", "probe"]
CANDIDATE_PROTOCOL_VERSION = 'egs-candidate-v2'
PATCH_POLICY = PatchPolicy(allowed_examples=(2, 3, 4), allowed_fields=("code", "cot"))


class ProtocolError(ValueError):
    """The response cannot be used without changing or guessing its meaning."""


class RunSpec(TypedDict):
    project_root: str
    config_path: str
    template_dir: str
    initial_template_path: str | None
    clean_snapshot_path: str | None
    initial_template_kind: str
    task_demonstration_path: str | None
    task_demonstration: str
    example_tasks: list[dict[str, Any]]
    target_definition: str
    public_sast_rules: str
    initial_hypotheses: list[dict[str, Any]]
    training_tasks: list[dict[str, Any]]


class CandidateReport(TypedDict):
    candidate_id: str
    observations: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    guidance_suggestions: list[dict[str, Any]]
    probe_suggestions: list[dict[str, Any]]
    limitations: list[str]


class RoundUpdate(TypedDict):
    guidance_updates: list[dict[str, Any]]
    next_probes: list[dict[str, Any]]
    unresolved: list[str]
    summary: str


class SelectionResult(TypedDict):
    status: Literal["selected", "no_feasible", "undetermined", "incomplete"]
    final_template: str | None
    reasons: list[str]


@dataclass(frozen=True)
class RoundInput:
    round_index: int
    experience: dict[str, Any]
    guidance_ids: tuple[str, ...]
    candidates: tuple[dict[str, Any], ...]
    probes: tuple[dict[str, Any], ...] = ()

    def to_json(self) -> dict[str, Any]:
        return copy.deepcopy({
            "round_index": self.round_index, "experience": self.experience,
            "guidance_ids": list(self.guidance_ids), "candidates": list(self.candidates),
            "probes": list(self.probes),
        })


@dataclass(frozen=True)
class CandidateDraft:
    patch: tuple[dict[str, Any], ...]
    victim_learning_goal: str


@dataclass
class CandidateEvidence:
    candidate_id: str
    round_index: int
    source: Source
    generation_status: str = "not_executed"
    failure_stage: str | None = None
    action_id: str | None = None
    snapshot_ref: str | None = None
    content_sha256: str | None = None
    patch: list[dict[str, Any]] | None = None
    victim_learning_goal: str | None = None
    example_checks: list[dict[str, Any]] = field(default_factory=list)
    training_status: dict[str, Any] = field(default_factory=lambda: {
        "status": "not_executed", "reason": "candidate not yet available"})
    sample_evidence: list[dict[str, Any]] = field(default_factory=list)
    task_summary: dict[str, Any] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    consumption_refs: list[str] = field(default_factory=list)
    probe_id: str | None = None
    arm_key: str | None = None


def _object(value: Any, fields: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError(f"{where}: expected exactly {sorted(fields)}")
    return value


def _strings(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise ProtocolError(f"{where}: expected string array")
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{where}: expected string")
    return value


def _array(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProtocolError(f"{where}: expected array")
    return value


def _refs(value: Any, allowed: set[str], where: str) -> None:
    unknown = set(_strings(value, where)) - allowed
    if unknown:
        raise ProtocolError(f"{where}: unknown references {sorted(unknown)}")


def _scope(value: Any, task_ids: set[str]) -> None:
    obj = _object(value, {"task_ids", "conditions", "limits"}, "scope")
    _refs(obj["task_ids"], task_ids, "scope.task_ids")
    _strings(obj["conditions"], "scope.conditions")
    _strings(obj["limits"], "scope.limits")


def _json_object(text: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if key in obj:
                raise ProtocolError(f"duplicate JSON key: {key}")
            obj[key] = value
        return obj

    def invalid_constant(value: str) -> None:
        raise ProtocolError(f"invalid JSON constant: {value}")

    try:
        obj = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("response must be a JSON object")
    return obj


def parse_candidate(text: str, initial_template: TemplateSnapshot) -> CandidateDraft:
    obj = _object(_json_object(text), {"patch", "victim_learning_goal"}, "candidate")
    goal = _text(obj['victim_learning_goal'], 'victim_learning_goal')
    if not goal.strip():
        raise ProtocolError('victim_learning_goal must not be empty')
    # The shared parser intentionally accepts only the patch object.
    parsed = parse_sparse_patch(json.dumps({"patch": obj["patch"]}, ensure_ascii=False))
    if parsed.patch is None:
        raise ProtocolError(parsed.error or "invalid patch")
    try:
        apply_patch(initial_template, parsed.patch, PATCH_POLICY)
    except ValueError as exc:
        raise ProtocolError(f"patch: {exc}") from exc
    return CandidateDraft(tuple(dict(x) for x in parsed.patch), goal)


_GUIDANCE_FIELDS = {"action", "guidance_id", "statement", "scope", "support_refs", "counter_refs", "uncertainty"}
_PROBE_TEXT_FIELDS = {"question", "hypothesis_refs", "candidate_refs", "fixed_conditions", "varied_conditions", "supports_if", "refutes_if", "inconclusive_if"}


def _guidance(item: Any, *, actions: set[str], new_action: str, guidance_ids: set[str],
              refs: set[str], task_ids: set[str]) -> None:
    obj = _object(item, _GUIDANCE_FIELDS, "guidance")
    if not isinstance(obj["action"], str) or obj["action"] not in actions:
        raise ProtocolError("guidance: invalid action")
    if obj["action"] == new_action:
        if obj["guidance_id"] is not None:
            raise ProtocolError("new guidance ID must be null")
    elif not isinstance(obj["guidance_id"], str) or obj["guidance_id"] not in guidance_ids:
        raise ProtocolError("guidance: unknown guidance_id")
    _text(obj["statement"], "guidance.statement")
    _text(obj["uncertainty"], "guidance.uncertainty")
    _scope(obj["scope"], task_ids)
    _refs(obj["support_refs"], refs, "guidance.support_refs")
    _refs(obj["counter_refs"], refs, "guidance.counter_refs")


def _probe_text(obj: dict[str, Any], hypothesis_ids: set[str], candidate_ids: set[str]) -> None:
    _text(obj["question"], "probe.question")
    _refs(obj["hypothesis_refs"], hypothesis_ids, "probe.hypothesis_refs")
    _refs(obj["candidate_refs"], candidate_ids, "probe.candidate_refs")
    for key in ("fixed_conditions", "varied_conditions", "supports_if", "refutes_if", "inconclusive_if"):
        # These three textual criteria have an unambiguous single-item form.
        # Preserve the entire response string, without splitting or filling text.
        if key in ('supports_if', 'refutes_if', 'inconclusive_if') and isinstance(obj[key], str):
            obj[key] = [obj[key]]
        _strings(obj[key], f"probe.{key}")


def parse_report(text: str, *, candidate_id: str, evidence_ids: set[str],
                 guidance_ids: set[str], hypothesis_ids: set[str], task_ids: set[str]) -> CandidateReport:
    obj = _object(_json_object(text), {"candidate_id", "observations", "hypotheses", "guidance_suggestions", "probe_suggestions", "limitations"}, "report")
    if obj["candidate_id"] != candidate_id:
        raise ProtocolError("report candidate_id differs from this candidate")
    local: set[str] = set()
    for kind in ("observations", "hypotheses"):
        for item in _array(obj[kind], kind):
            fields = {"local_key", "statement", "scope"} | ({"evidence_refs"} if kind == "observations" else {"support_refs", "counter_refs", "uncertainty"})
            _object(item, fields, kind)
            key = _text(item["local_key"], "local_key")
            if not key or key in local or key in evidence_ids | hypothesis_ids | guidance_ids:
                raise ProtocolError("local_key must be unique, local and non-empty")
            local.add(key)
            _text(item["statement"], "statement")
            _scope(item["scope"], task_ids)
    known = evidence_ids | hypothesis_ids | local
    local_hypotheses = {x["local_key"] for x in obj["hypotheses"]}
    for item in obj["observations"]:
        _refs(item["evidence_refs"], evidence_ids, "observation.evidence_refs")
    for item in obj["hypotheses"]:
        _refs(item["support_refs"], known, "hypothesis.support_refs")
        _refs(item["counter_refs"], known, "hypothesis.counter_refs")
        _text(item["uncertainty"], "hypothesis.uncertainty")
    for item in _array(obj["guidance_suggestions"], "guidance_suggestions"):
        _guidance(item, actions={"propose", "revise", "withdraw", "retain"}, new_action="propose",
                  guidance_ids=guidance_ids, refs=known, task_ids=task_ids)
    for item in _array(obj["probe_suggestions"], "probe_suggestions"):
        _object(item, _PROBE_TEXT_FIELDS, "probe_suggestion")
        _probe_text(item, hypothesis_ids | local_hypotheses, {candidate_id})
    _strings(obj["limitations"], "limitations")
    return obj  # type: ignore[return-value]


def namespace_report(report: CandidateReport) -> CandidateReport:
    obj = copy.deepcopy(report)
    names = {x["local_key"]: f"{obj['candidate_id']}:{x['local_key']}"
             for kind in ("observations", "hypotheses") for x in obj[kind]}
    for kind in ("observations", "hypotheses", "guidance_suggestions", "probe_suggestions"):
        for item in obj[kind]:
            if "local_key" in item:
                item["local_key"] = names[item["local_key"]]
            for key in ("evidence_refs", "support_refs", "counter_refs", "hypothesis_refs"):
                if key in item:
                    item[key] = [names.get(ref, ref) for ref in item[key]]
    return obj


def validate_probe_fields(probe: dict[str, Any], snapshot_ids: set[str]) -> None:
    fixed: set[tuple[int, str]] = set()
    varied: set[tuple[int, str]] = set()
    for key, seen in (("fixed_fields", fixed), ("varied_fields", varied)):
        for item in _array(probe[key], key):
            fields = {"example", "field", "candidate_ref"} if key == "fixed_fields" else {"example", "field"}
            # Preserve a known reference on a varied field as a proposal that
            # needs refinement. It never becomes an executable constraint.
            if isinstance(item, dict) and key == 'varied_fields' and 'candidate_ref' in item:
                fields = fields | {'candidate_ref'}
            _object(item, fields, key)
            example, name = item["example"], item["field"]
            if type(example) is not int or example not in (2, 3, 4) or not isinstance(name, str) or name not in ("code", "cot"):
                raise ProtocolError("probe: only examples 2/3/4 code/cot are allowed")
            pair = (example, name)
            if pair in fixed | varied:
                raise ProtocolError("probe: repeated or overlapping fixed/varied field")
            seen.add(pair)
            if key == "fixed_fields" or 'candidate_ref' in item:
                ref = item["candidate_ref"]
                if not isinstance(ref, str) or ref not in snapshot_ids | {"initial_template"}:
                    raise ProtocolError("probe: fixed field must reference an available candidate snapshot or initial_template")
    arms: set[str] = set()
    for arm in _array(probe["arms"], "arms"):
        _object(arm, {"arm_key", "change_request"}, "arm")
        key = _text(arm["arm_key"], "arm_key")
        if not key or key in arms:
            raise ProtocolError("probe: duplicate or empty arm_key")
        arms.add(key)
        _text(arm["change_request"], "change_request")


def parse_update(text: str, *, guidance_ids: set[str], evidence_ids: set[str],
                 hypothesis_ids: set[str], candidate_ids: set[str], snapshot_ids: set[str],
                 task_ids: set[str]) -> RoundUpdate:
    obj = _object(_json_object(text), {"guidance_updates", "next_probes", "unresolved", "summary"}, "round_update")
    seen: set[str] = set()
    for item in _array(obj["guidance_updates"], "guidance_updates"):
        _guidance(item, actions={"add", "revise", "withdraw", "retain"}, new_action="add",
                  guidance_ids=guidance_ids, refs=evidence_ids | hypothesis_ids, task_ids=task_ids)
        gid = item["guidance_id"]
        if gid is not None:
            if gid in seen:
                raise ProtocolError("conflicting or repeated operations for a guidance ID")
            seen.add(gid)
    for item in _array(obj["next_probes"], "next_probes"):
        _object(item, _PROBE_TEXT_FIELDS | {"fixed_fields", "varied_fields", "arms", "priority_reason"}, "next_probe")
        _probe_text(item, hypothesis_ids, candidate_ids)
        validate_probe_fields(item, snapshot_ids)
        _text(item["priority_reason"], "priority_reason")
    _strings(obj["unresolved"], "unresolved")
    _text(obj["summary"], "summary")
    return obj  # type: ignore[return-value]


def initial_experience(hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    if len(hypotheses) != 6:
        raise ProtocolError("initial experience requires exactly six initial hypotheses")
    guidance = []
    for index, hypothesis in enumerate(copy.deepcopy(hypotheses), 1):
        guidance.append({
            "guidance_id": f"g{index:04d}", "origin": "initial_hypothesis",
            "initial_index": index, "status": "active", "statement": hypothesis["statement"],
            "scope": hypothesis["scope"], "support_refs": [], "counter_refs": [],
            "uncertainty": "Initial hypothesis; unverified in this setting.",
        })
    return {"version": 0, "guidance": guidance, "reports": [], "next_probes": [], "history": []}
