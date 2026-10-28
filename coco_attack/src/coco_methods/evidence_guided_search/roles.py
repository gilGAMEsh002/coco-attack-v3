"""Source-isolated inputs, frozen external templates and public role calls."""
from __future__ import annotations

import copy
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from jinja2 import Environment, StrictUndefined, meta

from coco_attack.assets.artifacts import read_json, sha256_file, write_json_atomic
from coco_attack.iteration.action_runtime import (
    ActionStore, RoleActionRequest, RoleCallConfig, RoleCallOutcome, RoleCallSource, run_role_call,
)
from coco_attack.iteration.template_snapshot import TemplateSnapshot
from .contracts import CANDIDATE_PROTOCOL_VERSION, ProtocolError, Source, validate_probe_fields, initial_experience
from .inputs import task_view, candidate_test_view, semgrep_prompt_excerpt, target_pattern_statement

ROLE_DIRS = {"candidate": "候选生成", "report": "独立归纳", "aggregate": "统一汇总"}
CANDIDATE_SOURCES = ("guided", "unguided", "probe")
VARIABLES = {
    "candidate": {"target_definition", "initial_template_json", "example_tasks_json", "task_demonstration", "public_sast_rules", "source", "source_context_json"},
    "report": {"target_definition", "round_experience_json", "training_tasks_json", "public_sast_rules", "candidate_evidence_json", "clean_reference_json", "probe_context_json", "evidence_index_json", "evidence_visibility_json"},
    "aggregate": {"round_experience_json", "candidate_reports_json", "candidate_summaries_json", "clean_reference_json", "executed_probe_context_json", "evidence_index_json", "evidence_excerpt_json"},
}
_ENV = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)


class RoleBudgetExhausted(ProtocolError):
    """A run-level stop, never evidence of candidate quality."""


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


_HYPOTHESES_SECTION = re.compile(
    r"^##\s*初始启发性假设[^\n]*\n(.*?)(?=^\s*(?:##|\{%)|\Z)", re.S | re.M)
_HYPOTHESIS_ITEM = re.compile(r"^\s*(\d+)\.\s*(.+?)\s*$", re.M)


def fixed_initial_hypotheses(text: str, *, required: bool = True) -> list[str] | None:
    """Read the fixed hypotheses printed in the candidate user template."""
    match = _HYPOTHESES_SECTION.search(text)
    if match is None:
        if required:
            raise ProtocolError('candidate user template must print the fixed initial_hypotheses')
        return None
    items = _HYPOTHESIS_ITEM.findall(match.group(1))
    numbers = [int(number) for number, _ in items]
    statements = [statement.strip() for _, statement in items]
    if numbers != list(range(1, len(items) + 1)) or len(items) != 6 or any(not s for s in statements):
        raise ProtocolError('candidate user template must contain six consecutively numbered nonempty fixed hypotheses')
    return statements


def freeze_templates(source_dir: Path | str, run_dir: Path | str) -> Path:
    """New-run operation. Existing copies are never overwritten from the source."""
    source, target = Path(source_dir).resolve(), Path(run_dir) / "inputs" / "role_templates"
    if target.exists():
        raise FileExistsError(f"template copy already exists: {target}")
    # Read and validate every source before creating any copy.
    texts: dict[str, bytes] = {}
    for role, directory in ROLE_DIRS.items():
        declared: set[str] = set()
        for name in ("system.md.j2", "user.md.j2"):
            rel = f"{directory}/{name}"
            texts[rel] = (source / rel).read_bytes()
            declared |= meta.find_undeclared_variables(_ENV.parse(texts[rel].decode("utf-8")))
        if declared != VARIABLES[role]:
            raise ProtocolError(f"{role}: template variables differ: {declared ^ VARIABLES[role]}")
    hypotheses = fixed_initial_hypotheses(texts['候选生成/user.md.j2'].decode('utf-8'))
    user_template = _ENV.from_string(texts['候选生成/user.md.j2'].decode('utf-8'))
    for source_name in CANDIDATE_SOURCES:
        for dynamic in ('{}', '{"guidance": []}'):
            preview = {name: '' for name in VARIABLES['candidate']}
            preview.update(source=source_name, source_context_json=dynamic)
            rendered = user_template.render(**preview)
            if any(rendered.count(statement) != 1 for statement in hypotheses):
                raise ProtocolError('candidate user template must display each fixed hypothesis once for every source and iteration')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".role-templates-", dir=target.parent) as staging:
        pending = Path(staging) / "complete"
        manifest = {"source_dir": str(source), "files": {}, 'initial_hypotheses': hypotheses}
        for rel, text in texts.items():
            dest = pending / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(text)
            digest = sha256_file(dest)
            manifest["files"][rel] = {"source": str(source / rel), "source_sha256": digest, "sha256": digest}
        write_json_atomic(pending / "manifest.json", manifest)
        pending.rename(target)
    return target


def render_messages(template_dir: Path | str, role: str, variables: Mapping[str, str]) -> tuple[dict[str, str], ...]:
    if role not in VARIABLES:
        raise ProtocolError(f"unknown role: {role}")
    if set(variables) != VARIABLES[role] or any(not isinstance(v, str) for v in variables.values()):
        raise ProtocolError(f"{role}: expected exactly string variables {sorted(VARIABLES[role])}")
    root = Path(template_dir)
    if not (root / "manifest.json").is_file():
        raise ProtocolError("frozen role template manifest is missing")
    try:
        manifest = read_json(root / "manifest.json")
        expected = {f"{directory}/{name}.md.j2" for directory in ROLE_DIRS.values() for name in ("system", "user")}
        if set(manifest["files"]) != expected:
            raise ValueError("incomplete file list")
        for entry in manifest["files"].values():
            if not isinstance(entry["sha256"], str):
                raise ValueError("missing template identity")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ProtocolError(f"invalid frozen role template manifest: {exc}") from exc
    messages = []
    for kind in ("system", "user"):
        rel = f"{ROLE_DIRS[role]}/{kind}.md.j2"
        path = root / rel
        if sha256_file(path) != manifest["files"][rel]["sha256"]:
            raise ProtocolError(f"frozen template changed: {rel}")
        messages.append({"role": kind, "content": _ENV.from_string(path.read_text(encoding="utf-8")).render(**variables)})
    return tuple(messages)


def _guidance_view(entry: dict[str, Any]) -> dict[str, Any]:
    # References/history can lead to victim evidence and never enter execution inputs.
    return {key: copy.deepcopy(entry[key]) for key in (
        "guidance_id", "origin", "initial_index", "statement", "scope", "uncertainty") if key in entry}


def candidate_variables(spec: Mapping[str, Any], initial_template: TemplateSnapshot, *, source: Source,
                        experience: dict[str, Any], guidance_ids: tuple[str, ...] = (),
                        probe_context: dict[str, Any] | None = None) -> dict[str, str]:
    if source not in CANDIDATE_SOURCES:
        raise ProtocolError(f"unknown candidate source: {source}")
    if source == "unguided":
        # No experience ID, feedback, counters or withdrawal metadata is projected.
        context: dict[str, Any] = {}
    elif source == "guided":
        active = {g["guidance_id"]: g for g in experience["guidance"] if g["status"] == "active"}
        if len(set(guidance_ids)) != len(guidance_ids) or set(guidance_ids) - active.keys():
            raise ProtocolError("guided input references unavailable/withdrawn guidance")
        baseline = {entry['guidance_id']: entry for entry in initial_experience(spec['initial_hypotheses'])['guidance']}
        selected = []
        for gid in guidance_ids:
            if active[gid] == baseline.get(gid):
                continue
            visible = _guidance_view(active[gid])
            if gid in baseline and active[gid]['statement'] == baseline[gid]['statement']:
                visible.pop('statement')  # The fixed numbered hypothesis already supplies this text.
            selected.append(visible)
        context = {'guidance': selected} if selected else {}
        withdrawn = [{key: copy.deepcopy(entry[key]) for key in
                      ('guidance_id', 'initial_index', 'scope', 'uncertainty') if key in entry}
                     for entry in experience['guidance']
                     if entry.get('origin') == 'initial_hypothesis' and entry['status'] == 'withdrawn']
        if withdrawn:
            context['withdrawn_initial_hypotheses'] = withdrawn
    else:
        if probe_context is None:
            raise ProtocolError("probe requires resolved comparison materials")
        # This shape is produced by resolve_probe_context, never by forwarding RoundInput.
        expected = {"probe_id", "question", "arm_key", "change_request", "fixed_conditions", "varied_conditions", "fixed_fields", "varied_fields", "hypotheses", "supports_if", "refutes_if", "inconclusive_if"}
        if set(probe_context) != expected:
            raise ProtocolError("probe context must contain only resolved comparison materials")
        context = copy.deepcopy(probe_context)
    # Task identity is not a back door to the held training queries. Preserve the
    # fact that a suggestion was scoped, without exposing those query IDs.
    example_ids = set(initial_template.example_ids())
    scoped = context.get('guidance', []) + context.get('hypotheses', []) + context.get('withdrawn_initial_hypotheses', [])
    for entry in scoped:
        scope = entry.get('scope')
        if not isinstance(scope, dict):
            continue
        task_ids = scope.get('task_ids', [])
        if set(task_ids) - example_ids:
            scope['task_ids'] = [task for task in task_ids if task in example_ids]
            scope.setdefault('limits', []).append('Task IDs outside the examples are omitted; the original scope limitation still applies.')
    return {
        "target_definition": target_pattern_statement(spec["target_definition"]),
        "initial_template_json": json_text([
            {'instruct_prompt': example.instruct_prompt, 'cot': example.cot, 'code': example.code}
            for example in initial_template.examples
        ]),
        "example_tasks_json": json_text([candidate_test_view(task) for task in spec['example_tasks']]),
        "task_demonstration": spec.get('task_demonstration', ''),
        "public_sast_rules": semgrep_prompt_excerpt(spec["public_sast_rules"]),
        "source": source,
        "source_context_json": json_text(context),
    }


def resolve_probe_context(probe: dict[str, Any], *, arm_key: str, initial_template: TemplateSnapshot,
                          snapshots: Mapping[str, TemplateSnapshot],
                          hypotheses: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    validate_probe_fields(probe, set(snapshots))
    if any('candidate_ref' in item for item in probe['varied_fields']):
        raise ProtocolError('probe varied-field reference needs refinement before execution')
    arm = next((a for a in probe["arms"] if a["arm_key"] == arm_key), None)
    if arm is None:
        raise ProtocolError("probe arm not found")
    fixed_fields = []
    for item in probe["fixed_fields"]:
        snapshot = initial_template if item["candidate_ref"] == "initial_template" else snapshots[item["candidate_ref"]]
        fixed_fields.append({**item, "value": getattr(snapshot.example(item["example"]), item["field"])})
    if set(probe["hypothesis_refs"]) - hypotheses.keys():
        raise ProtocolError("probe hypothesis not available")
    return {
        "probe_id": probe["probe_id"], "question": probe["question"], "arm_key": arm_key,
        "change_request": arm["change_request"], "fixed_fields": fixed_fields,
        "varied_fields": copy.deepcopy(probe["varied_fields"]),
        "hypotheses": [{"hypothesis_id": ref, **{key: copy.deepcopy(hypotheses[ref][key])
                        for key in ("statement", "scope", "uncertainty") if key in hypotheses[ref]}}
                       for ref in probe["hypothesis_refs"]],
        **{key: copy.deepcopy(probe[key]) for key in ("fixed_conditions", "varied_conditions", "supports_if", "refutes_if", "inconclusive_if")},
    }


def report_variables(spec: Mapping[str, Any], *, experience: dict[str, Any],
                     evidence: dict[str, Any], evidence_ids: list[str],
                     clean_reference: dict[str, Any], probe_context: dict[str, Any] | None = None,
                     example_context: list[dict[str, Any]] | None = None,
                     related_rules: str = "") -> dict[str, str]:
    trained = bool(evidence["sample_evidence"])
    has_snapshot = evidence["snapshot_ref"] is not None
    tasks = spec["training_tasks"] if trained else (example_context or []) if has_snapshot else []
    rules = related_rules if has_snapshot else ""
    clean = clean_reference if trained else {}
    return {
        "target_definition": spec["target_definition"], "round_experience_json": json_text(experience),
        "training_tasks_json": json_text([task_view(task) for task in tasks]),
        "public_sast_rules": semgrep_prompt_excerpt(rules),
        "candidate_evidence_json": json_text(evidence), "clean_reference_json": json_text(clean),
        "probe_context_json": json_text(probe_context or {}), "evidence_index_json": json_text(evidence_ids),
        "evidence_visibility_json": json_text({
            "candidate_evidence": "all acquired candidate evidence supplied; no score filtering",
            "tasks": "two training tasks and tests" if trained else "example check context" if tasks else "omitted: no relevant task-stage evidence",
            "rules": "related rules supplied" if rules else "omitted: no related rule context supplied",
            "clean_reference": "program statistics and comparability supplied" if trained else "omitted: no training outputs",
        }),
    }


def aggregate_variables(*, experience: dict[str, Any], reports: list[dict[str, Any]],
                        summaries: list[dict[str, Any]], clean_reference: dict[str, Any],
                        executed_probes: list[dict[str, Any]], evidence_ids: list[str],
                        excerpts: list[dict[str, Any]] | None = None) -> dict[str, str]:
    return {key: json_text(value) for key, value in {
        "round_experience_json": experience, "candidate_reports_json": reports,
        "candidate_summaries_json": summaries, "clean_reference_json": clean_reference,
        "executed_probe_context_json": executed_probes, "evidence_index_json": evidence_ids,
        "evidence_excerpt_json": excerpts or [],
    }.items()}


@dataclass(frozen=True)
class RoleService:
    config: RoleCallConfig
    source: RoleCallSource
    budget: Any = None


def call_role(store: ActionStore, *, action_id: str, role: str, template_dir: Path | str,
              variables: Mapping[str, str], service: RoleService,
              candidate_source: Source | None = None) -> RoleCallOutcome:
    """Public action persistence supplies messages, response reuse and unknown handling."""
    if role == "candidate" and candidate_source not in CANDIDATE_SOURCES:
        raise ProtocolError("candidate source metadata required")
    if role != "candidate" and candidate_source is not None:
        raise ProtocolError("candidate source metadata belongs to candidate calls")
    refs = {"protocol_version": CANDIDATE_PROTOCOL_VERSION if role == 'candidate' else 'egs-v1'}
    if candidate_source is not None:
        refs["candidate_source"] = candidate_source
    request = RoleActionRequest(
        action_id=action_id, role=service.config.role,
        kind="mutator" if role == "candidate" else "reasoning",
        messages=render_messages(template_dir, role, variables), config=service.config, input_refs=refs,
    )
    prior = store.durable_response(action_id)
    attempts = [e for e in store.events(action_id) if e['event_type'] == 'attempt_started']
    if prior is None and attempts and not store.orphan_attempts(action_id):
        raise ProtocolError('previous role attempts failed; implicit retry is disabled')
    key = f'{store.run_dir.resolve()}:{action_id}'
    if service.budget is not None and not service.budget.reserve(key, 'search', service.config.max_request_attempts):
        raise RoleBudgetExhausted('role request budget exhausted')
    outcome = run_role_call(store, request, source=service.source, allow_retry_after_unknown=False)
    if service.budget is not None:
        actual = len([e for e in store.events(action_id) if e['event_type'] == 'attempt_started'])
        service.budget.settle(key, None if outcome.state == 'unknown_paused' else actual)
    return outcome


def response_text(outcome: RoleCallOutcome) -> str:
    if outcome.state not in ("response_saved", "response_reused") or outcome.response_status != "success" or outcome.response is None:
        raise ProtocolError(f"role call {outcome.state}: {outcome.error or outcome.response_status}")
    return outcome.response["content"]
