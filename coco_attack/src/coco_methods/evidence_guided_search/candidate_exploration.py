"""Candidate materialization and explicit example admission; no experience updates."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Mapping

from coco_attack.assets.artifacts import read_json, sha256_bytes, write_json_atomic
from coco_attack.iteration.action_runtime import ActionStore
from coco_attack.iteration.code_check import ExampleCheckRequest, run_example_code_check
from coco_attack.iteration.template_snapshot import TemplateSnapshot, apply_patch, write_snapshot
from .contracts import CandidateEvidence, PATCH_POLICY, ProtocolError, parse_candidate
from .measurement import measure, oracle_state
from .roles import RoleBudgetExhausted, RoleService, call_role, candidate_variables, response_text


def content_groups(identities: dict[str, str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for cid, digest in sorted(identities.items()):
        groups.setdefault(digest, []).append(cid)
    return groups


def probe_patch(initial_template: TemplateSnapshot, patch: tuple[dict[str, Any], ...], context: dict[str, Any]) -> list[dict[str, Any]]:
    fixed = {(x['example'], x['field']): x['value'] for x in context['fixed_fields']}
    varied = {(x['example'], x['field']) for x in context['varied_fields']}
    values = {example: {} for example in (2, 3, 4)}
    for entry in patch:
        example = entry['example']
        for name in ('code', 'cot'):
            if name not in entry:
                continue
            pair = example, name
            if pair not in varied and entry[name] != fixed.get(pair, getattr(initial_template.example(example), name)):
                raise ProtocolError(f'probe patch violates fixed/unlisted field: {pair}')
            values[example][name] = entry[name]
    for (example, name), value in fixed.items():
        values[example][name] = value
    return [{'example': example, **fields} for example, fields in values.items() if fields]


def verify_probe(snapshot: TemplateSnapshot, initial_template: TemplateSnapshot, context: dict[str, Any]) -> None:
    fixed = {(x['example'], x['field']): x['value'] for x in context['fixed_fields']}
    varied = {(x['example'], x['field']) for x in context['varied_fields']}
    for example in (2, 3, 4):
        for name in ('code', 'cot'):
            pair = example, name
            expected = fixed.get(pair, getattr(initial_template.example(example), name))
            if pair not in varied and getattr(snapshot.example(example), name) != expected:
                raise ProtocolError(f'probe changed fixed/unlisted field: {pair}')


def admission(checks: list[dict[str, Any]], policy: dict[str, Any] | None) -> dict[str, Any]:
    """Every required fact must be known and acceptable. Unknown never admits."""
    failures, unknown = [], []
    if policy is None or policy.get('oracle_states') is None:
        unknown.append('example oracle admission states not decided')
    allowed = (policy or {}).get('oracle_states') or []
    if policy is not None and policy.get('oracle_states') == []:
        failures.append('no oracle state is acceptable under the declared policy')
    if len(checks) != 3 or {x['example'] for x in checks} != {2, 3, 4}:
        unknown.append('required example checks missing')
    for check in checks:
        label = f"example {check['example']}"
        raw = check['facts']
        syntax = raw.get('syntax', {})
        for key in ('syntax_ok', 'entry_present'):
            value = syntax.get(key) if syntax.get('state') == 'executed' else None
            (failures if value is False else unknown if value is not True else []).append(f'{label}: {key}')
        functional = raw.get('functional', {})
        passed = functional.get('passed')
        (failures if passed is False else unknown if passed is not True else []).append(f'{label}: functional')
        sast = raw.get('semgrep', {})
        valid = sast.get('status') == 'completed' and sast.get('completed') is True and sast.get('coverage') == 'covered' and sast.get('available') is True
        if not valid or type(sast.get('detected')) is not bool:
            unknown.append(f'{label}: SAST not completed/covered')
        elif sast['detected']:
            failures.append(f'{label}: SAST detected')
        state = oracle_state(raw.get('static'))
        if allowed:
            if state is None or state == 'parse_error':
                unknown.append(f'{label}: oracle unavailable')
            elif state == 'present_or_possibly_present':
                if not {'present', 'possibly_present'} <= set(allowed):
                    unknown.append(f'{label}: oracle does not distinguish present/possibly_present')
            elif state not in allowed:
                failures.append(f'{label}: oracle {state} not allowed')
        if (policy or {}).get('semantic_mode') != 'prompt_only':
            unknown.append(f'{label}: semantic policy not decided (supported: prompt_only)')
    return {'status': 'rejected' if failures else 'unknown' if unknown else 'admitted',
            'reasons': failures + unknown, 'failures': failures, 'unknown': unknown}


def check_examples(snapshot: TemplateSnapshot, output_dir: Path, settings: dict[str, Any], *,
                   check: Callable[[ExampleCheckRequest], dict[str, Any]] = run_example_code_check,
                   example_numbers: tuple[int, ...] = (2, 3, 4),
                   ) -> list[dict[str, Any]]:
    checks = []
    for example in example_numbers:
        ex = snapshot.example(example)
        directory = output_dir / f'example-{example}'
        # A small completed check can be reused; attribution is bound to the input bytes.
        result_path = directory / 'method_check.json'
        identity = {'snapshot_sha256': snapshot.content_sha256(), 'example': example, 'settings': settings}
        if result_path.is_file():
            stored = read_json(result_path)
            if stored['input'] != identity:
                raise ProtocolError('example check inputs changed within a run')
            checks.append(stored['check'])
            continue
        request = ExampleCheckRequest(
            combination_id=snapshot.combination_id, task_id=ex.task_id, code=ex.code,
            code_source=f'candidate-example-{example}', action_id=f'example-{example}',
            output_dir=directory, assets_root=Path(settings['assets_root']),
            code_input_mode=settings['code_input_mode'], stage=settings['stage'],
            execution_config_path=Path(settings['execution_config_path']),
            semgrep_config=Path(settings['semgrep_config']),
            semgrep_timeout_seconds=settings['semgrep_timeout_seconds'],
            candidate_timeout_seconds=settings['candidate_timeout_seconds'],
        )
        facts = check(request)
        if facts.get('code', {}).get('input_code_sha256') != sha256_bytes(ex.code.encode('utf-8')):
            raise ProtocolError('example facts do not match candidate code')
        semantic = {
            'code_cot_consistent': None, 'no_imitation_meta_instruction': None,
            'status': 'not_executed', 'reason': 'prompt requirements only; no program semantic gate (user decision 2026-10-27)'}
        entry = {'example': example, 'facts': facts, 'semantic': semantic,
                 'fixed_content': 'preserved by public field patch policy'}
        write_json_atomic(result_path, {'input': identity, 'check': entry})
        checks.append(entry)
    return checks


def run_candidate(*, candidate: dict[str, Any], round_index: int, spec: Mapping[str, Any],
                  initial_template: TemplateSnapshot, experience: dict[str, Any], guidance_ids: tuple[str, ...],
                  run_dir: Path, output_dir: Path, service: RoleService,
                  template_dir: Path, example_settings: dict[str, Any],
                  measurement_settings: dict[str, Any], admission_policy: dict[str, Any] | None,
                  probe_context: dict[str, Any] | None = None,
                  check: Callable = run_example_code_check,
                  public_measure: Callable | None = None) -> CandidateEvidence:
    final = output_dir / 'evidence.json'
    if final.is_file():
        prior = CandidateEvidence(**read_json(final))
        if prior.failure_stage not in ('example_checks', 'measurement'):
            return prior
    evidence = CandidateEvidence(candidate['candidate_id'], round_index, candidate['source'],
                                 probe_id=candidate.get('probe_id'), arm_key=candidate.get('arm_key'))
    evidence.action_id = f"{candidate['candidate_id']}-generate"
    stage = 'call'
    try:
        variables = candidate_variables(spec, initial_template, source=evidence.source, experience=experience,
                                       guidance_ids=guidance_ids, probe_context=probe_context)
        outcome = call_role(ActionStore(output_dir), action_id=evidence.action_id, role='candidate',
                            template_dir=template_dir, variables=variables, service=service,
                            candidate_source=evidence.source)
        evidence.consumption_refs.append(str(output_dir / 'actions.jsonl'))
        if outcome.state == 'unknown_paused':
            raise ProtocolError('candidate call outcome unknown; explicit resolution required')
        text = response_text(outcome)
        stage = 'parse_or_field_validation'
        draft = parse_candidate(text, initial_template)
        evidence.patch = probe_patch(initial_template, draft.patch, probe_context) if probe_context is not None else list(draft.patch)
        evidence.victim_learning_goal = draft.victim_learning_goal
        stage = 'materialize'
        patched = apply_patch(initial_template, evidence.patch, PATCH_POLICY)
        if probe_context is not None:
            verify_probe(patched.snapshot, initial_template, probe_context)
        snapshot = patched.snapshot
        directory = write_snapshot(run_dir / 'snapshots', snapshot, action_id=evidence.action_id,
                                   parent_sha256=initial_template.content_sha256(), diff=patched.diff)
        evidence.snapshot_ref = str(directory)
        evidence.content_sha256 = snapshot.content_sha256()
        evidence.generation_status = 'materialized'
        if not patched.changed:
            evidence.gaps.append('no_change: identical to fixed initial_template')
        stage = 'example_checks'
        evidence.example_checks = check_examples(snapshot, output_dir / 'checks', example_settings, check=check)
        decision = admission(evidence.example_checks, admission_policy)
        write_json_atomic(output_dir / 'admission.json', decision)
        if decision['status'] != 'admitted':
            evidence.training_status = {'status': 'not_executed', 'reason': 'example admission ' + decision['status'], 'admission': decision}
        else:
            stage = 'measurement'
            measured = measure(snapshot, output_dir / 'measurement', measurement_settings,
                               purpose='probe' if evidence.source == 'probe' else 'search', public_measure=public_measure)
            evidence.sample_evidence = measured['sample_evidence']
            evidence.task_summary = measured['task_summary']
            evidence.gaps.extend(measured['gaps'])
            evidence.consumption_refs.extend(measured['consumption_refs'])
            evidence.training_status = {'status': 'measured' if measured['complete'] else 'not_completed', 'purpose': measured['purpose']}
            if not measured['complete']:
                evidence.failure_stage = 'measurement'
    except RoleBudgetExhausted:
        raise
    except Exception as exc:
        evidence.failure_stage = stage
        if evidence.snapshot_ref is None:
            evidence.generation_status = 'failed'
        evidence.gaps.append(f'{type(exc).__name__}: {exc}')
        evidence.training_status = {'status': 'not_completed', 'reason': f'{stage}: {type(exc).__name__}: {exc}'}
        # Unknown external outcomes require operator resolution; do not mark them final.
        if stage == 'call' and 'outcome unknown' in str(exc):
            write_json_atomic(output_dir / 'unknown.json', asdict(evidence))
            raise
    write_json_atomic(final, asdict(evidence))
    return evidence
