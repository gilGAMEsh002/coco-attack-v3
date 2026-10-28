"""Independent reports and all-or-nothing experience publication."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from coco_attack.assets.artifacts import read_json, write_json_atomic
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.iteration.template_snapshot import read_snapshot
from .contracts import CandidateReport, ProtocolError, RoundUpdate, namespace_report, parse_report, parse_update
from .roles import (RoleService, aggregate_variables, call_role, report_variables, response_text)


def guidance_ids(experience: dict[str, Any]) -> set[str]:
    return {g['guidance_id'] for g in experience['guidance']}


def hypothesis_index(experience: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {h['local_key']: h for report in experience['reports'] for h in report['hypotheses']}


def evidence_ids(evidence: dict[str, Any]) -> set[str]:
    refs = {evidence['candidate_id']}
    refs.update(r['sample_id'] for r in evidence['sample_evidence'] if r['sample_id'] is not None)
    refs.update(x['facts']['sample_id'] for x in evidence['example_checks'] if x['facts'].get('sample_id'))
    return refs


def scope_task_ids(spec: dict[str, Any], experience: dict[str, Any],
                   evidences: list[dict[str, Any]], *, clean_reference: dict[str, Any] | None = None) -> set[str]:
    """Scope may name actual example tasks as well as victim training tasks."""
    tasks = set()
    if any(evidence['sample_evidence'] for evidence in evidences):
        tasks.update(task['task_id'] for task in spec['training_tasks'])
    if clean_reference is not None:
        tasks.update(clean_reference.get('task_summary', {}))
    entries = list(experience['guidance'])
    for report in experience['reports']:
        for key in ('observations', 'hypotheses', 'guidance_suggestions'):
            entries.extend(report[key])
    for entry in entries:
        tasks.update(entry['scope']['task_ids'])
    for evidence in evidences:
        if evidence['snapshot_ref']:
            tasks.update(read_snapshot(evidence['snapshot_ref']).example_ids())
        tasks.update(c['facts']['task_id'] for c in evidence['example_checks'] if c['facts'].get('task_id'))
    return tasks


def _save_parse_notes(path: Path, text: str, collection: str, action_id: str) -> None:
    raw = json.loads(text)
    notes = [{'field': f'{collection}[{index}].{key}', 'operation': 'verbatim_string_to_single_item_array'}
             for index, item in enumerate(raw[collection])
             for key in ('supports_if', 'refutes_if', 'inconclusive_if') if isinstance(item[key], str)]
    write_json_atomic(path, {'raw_action_id': action_id, 'normalizations': notes})


def run_report(*, spec: dict[str, Any], experience: dict[str, Any], evidence: dict[str, Any],
               clean_reference: dict[str, Any], output_dir: Path, template_dir: Path,
               service: RoleService, probe_context: dict[str, Any] | None = None) -> CandidateReport:
    path = output_dir / 'report.json'
    refs = evidence_ids(evidence)
    parse_kwargs = dict(candidate_id=evidence['candidate_id'], evidence_ids=refs,
                        guidance_ids=guidance_ids(experience), hypothesis_ids=set(hypothesis_index(experience)),
                        task_ids=scope_task_ids(spec, experience, [evidence]))
    if path.is_file():
        # Re-parse the persisted output with this frozen input's actual references.
        import json
        return parse_report(json.dumps(read_json(path)), **parse_kwargs)
    expanded = copy.deepcopy(evidence)
    if evidence['snapshot_ref']:
        expanded['snapshot'] = read_snapshot(evidence['snapshot_ref']).content_json()
    store = ActionStore(output_dir)
    if evidence.get('action_id'):
        response = store.durable_response(evidence['action_id'])
        if response is not None:
            expanded['candidate_generation_response'] = response
    checked_ids = {check['facts'].get('task_id') for check in evidence['example_checks']}
    example_context = [task for task in spec['example_tasks'] if task['task_id'] in checked_ids]
    variables = report_variables(spec, experience=experience, evidence=expanded,
                                 evidence_ids=sorted(refs), clean_reference=clean_reference,
                                 probe_context=probe_context, example_context=example_context,
                                 related_rules=spec['public_sast_rules'])
    outcome = call_role(store, action_id=f"{evidence['candidate_id']}-report", role='report',
                        template_dir=template_dir, variables=variables, service=service)
    text = response_text(outcome)
    report = parse_report(text, **parse_kwargs)
    _save_parse_notes(output_dir / 'report_parse.json', text, 'probe_suggestions', outcome.action_id)
    write_json_atomic(path, report)
    return report


def apply_update(experience: dict[str, Any], update: RoundUpdate,
                 reports: list[CandidateReport], executed_probes: list[dict[str, Any]] | None = None,
                 known_evidence: set[str] | None = None) -> dict[str, Any]:
    """Inputs have been parsed once. Omitted guidance persists; history is retained."""
    new = copy.deepcopy(experience)
    new['version'] = experience['version'] + 1
    new['history'].append({'version': experience['version'], 'guidance': copy.deepcopy(experience['guidance']),
                           'update': copy.deepcopy(update)})
    entries = {g['guidance_id']: g for g in new['guidance']}
    for change in update['guidance_updates']:
        action, gid = change['action'], change['guidance_id']
        if action == 'retain':
            continue
        if action == 'add':
            gid = f"g{len(new['guidance']) + 1:04d}"
            entry = {'guidance_id': gid, 'origin': 'round_update', 'status': 'active'}
            new['guidance'].append(entry)
            entries[gid] = entry
        else:
            entry = entries[gid]
        for key in ('statement', 'scope', 'support_refs', 'counter_refs', 'uncertainty'):
            entry[key] = copy.deepcopy(change[key])
        entry['status'] = 'withdrawn' if action == 'withdraw' else 'active'
    new['reports'].extend(copy.deepcopy(reports))
    outcomes = {p['probe_id']: p for p in executed_probes or []}
    for proposal in new['next_probes']:
        if proposal['probe_id'] in outcomes:
            proposal['status'] = outcomes[proposal['probe_id']]['execution_status']
            proposal['execution'] = copy.deepcopy(outcomes[proposal['probe_id']]['arm_results'])
    new['evidence_ids'] = sorted(set(experience.get('evidence_ids', [])) | (known_evidence or set()))
    # Unscheduled proposals remain proposals, never evidence of a performed test.
    for index, proposal in enumerate(update['next_probes'], 1):
        needs_refinement = any('candidate_ref' in item for item in proposal['varied_fields'])
        new['next_probes'].append({**copy.deepcopy(proposal), 'probe_id': f"p{new['version']:04d}-{index:03d}",
            'status': 'needs_refinement' if needs_refinement else 'proposed',
            **({'execution_blockers': ['varied_fields carries candidate_ref; its meaning must be clarified before any execution']}
               if needs_refinement else {})})
    new['summary'] = update['summary']
    new['unresolved'] = copy.deepcopy(update['unresolved'])
    return new


def run_aggregate(*, spec: dict[str, Any], experience: dict[str, Any],
                  evidences: list[dict[str, Any]], reports: list[CandidateReport],
                  clean_reference: dict[str, Any], executed_probes: list[dict[str, Any]],
                  output_dir: Path, template_dir: Path, service: RoleService,
                  historical_candidates: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if len(reports) != len(evidences) or {r['candidate_id'] for r in reports} != {e['candidate_id'] for e in evidences}:
        raise ProtocolError('all planned candidates must have an independent report before aggregation')
    namespaced = [namespace_report(report) for report in reports]
    refs = set().union(*(evidence_ids(e) for e in evidences))
    refs.update(experience.get('evidence_ids', []))
    refs.update(o['local_key'] for r in namespaced for o in r['observations'])
    hypotheses = set(hypothesis_index(experience)) | {h['local_key'] for r in namespaced for h in r['hypotheses']}
    snapshots = {e['candidate_id'] for e in evidences if e['snapshot_ref'] is not None}
    # Historical candidate fields are permitted only when explicitly included in input.
    summaries = [{key: copy.deepcopy(e[key]) for key in (
        'candidate_id', 'source', 'probe_id', 'arm_key', 'generation_status', 'failure_stage',
        'snapshot_ref', 'content_sha256', 'training_status', 'task_summary', 'gaps')} for e in evidences]
    summaries.extend(copy.deepcopy(historical_candidates or []))
    snapshots.update(c['candidate_id'] for c in historical_candidates or [])
    kwargs = dict(guidance_ids=guidance_ids(experience), evidence_ids=refs, hypothesis_ids=hypotheses,
                  candidate_ids={e['candidate_id'] for e in summaries}, snapshot_ids=snapshots,
                  task_ids=scope_task_ids(spec, experience, evidences, clean_reference=clean_reference))
    update_path, experience_path = output_dir / 'update.json', output_dir / 'experience.json'
    if update_path.is_file():
        import json
        update = parse_update(json.dumps(read_json(update_path)), **kwargs)
    else:
        variables = aggregate_variables(experience=experience, reports=namespaced, summaries=summaries,
                                         clean_reference=clean_reference, executed_probes=executed_probes,
                                         evidence_ids=sorted(refs | hypotheses))
        outcome = call_role(ActionStore(output_dir), action_id=f"round-{experience['version'] + 1:04d}-aggregate",
                            role='aggregate', template_dir=template_dir, variables=variables, service=service)
        text = response_text(outcome)
        update = parse_update(text, **kwargs)
        _save_parse_notes(output_dir / 'update_parse.json', text, 'next_probes', outcome.action_id)
        # A durable update lets an interrupted publication finish without a new model call.
        write_json_atomic(update_path, update)
    expected = apply_update(experience, update, namespaced, executed_probes, refs)
    if experience_path.is_file():
        if read_json(experience_path) != expected:
            raise ProtocolError('saved experience disagrees with frozen input and update')
    else:
        write_json_atomic(experience_path, expected)
    return expected
