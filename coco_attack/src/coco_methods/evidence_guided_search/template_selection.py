"""Frozen retests and program selection under explicitly supplied testable rules."""
from __future__ import annotations

import copy
import math
from pathlib import Path
from typing import Any, Callable

from coco_attack.assets.artifacts import canonical_json_bytes, read_json, sha256_bytes, write_json_atomic
from coco_attack.iteration.template_snapshot import read_snapshot
from .contracts import ProtocolError
from .measurement import measure

METRICS = {'H', 'H_and_not_D', 'F', 'H_and_F', 'H_and_F_and_not_D'}


def comparability_differences(reference: dict[str, Any], retest: dict[str, Any]) -> list[str]:
    differences = []
    if not reference:
        return ['reference actual measurement settings unavailable']
    for key in ('task_ids', 'data_dir', 'assets_root', 'functional', 'evaluators', 'execution_config_path', 'victim_messages', 'stage'):
        if reference.get(key) != retest.get(key):
            differences.append(f'reference/retest {key} differs')
    # Batch and sample count may differ; the request distribution must be declared alike.
    excluded = {'batch_id', 'candidate_hash', 'repeats', 'max_concurrency', 'min_concurrency'}
    project = lambda s: {k: v for k, v in s.get('generation', {}).items() if k not in excluded}
    if project(reference) != project(retest):
        differences.append('reference/retest victim request configuration differs')
    return differences


def validate_rules(rules: dict[str, Any]) -> None:
    if not isinstance(rules.get('rule_version'), str) or not rules['rule_version']:
        raise ProtocolError('selection rule version is required')
    shortlist = rules['shortlist']
    if shortlist['mode'] not in ('explicit_ids', 'all_admitted_unique') or shortlist['content_policy'] != 'merge_first':
        raise ProtocolError('unsupported shortlist/content rule')
    if type(shortlist['limit']) is not int or shortlist['limit'] < 1:
        raise ProtocolError('explicit positive shortlist limit required')
    if shortlist['order'] != 'candidate_id' or not shortlist['include_sources'] or set(shortlist['include_sources']) - {'guided', 'unguided', 'probe'}:
        raise ProtocolError('unsupported/undecided shortlist ordering/sources')
    if shortlist['mode'] == 'explicit_ids' and not isinstance(shortlist.get('candidate_ids'), list):
        raise ProtocolError('explicit shortlist candidate IDs required')
    if rules['evidence_policy'] != 'retest_only' or rules['unknown_policy'] != 'require_all_decided':
        raise ProtocolError('unsupported/undecided evidence or unknown policy')
    functional = rules['functional']
    if functional['comparison'] != 'per_task_absolute_drop' or functional['estimator'] != 'empirical' or functional['require_complete'] is not True:
        raise ProtocolError('unsupported functional comparison/coverage policy')
    delta = functional['max_drop']
    if isinstance(delta, bool) or not isinstance(delta, (int, float)) or not math.isfinite(delta) or not 0 <= delta <= 1:
        raise ProtocolError('functional max_drop must be a finite value in [0,1]')
    if type(functional['minimum']) is not int or functional['minimum'] < 1:
        raise ProtocolError('functional minimum sample count required')
    ranking = rules['ranking']
    if ranking['metric'] not in METRICS or ranking['aggregation'] != 'macro' or ranking['tie_break'] != 'candidate_id' or ranking['direction'] != 'maximize' or ranking['require_complete'] is not True:
        raise ProtocolError('unsupported/undecided ranking rule')


def feasibility(candidate: dict[str, Any], clean: dict[str, Any], *, task_ids: list[str],
                rule: dict[str, Any], comparable: bool | None) -> dict[str, Any]:
    details = {}
    for task in task_ids:
        c, ref = candidate.get(task), clean.get(task)
        if comparable is not True or c is None or ref is None:
            details[task] = {'status': 'unknown', 'reason': 'missing or incomparable clean/candidate facts'}
            continue
        cf, rf = c['metrics']['F'], ref['metrics']['F']
        if any(x['denominator'] < rule['minimum'] or x['unknown'] or x['rate'] is None for x in (cf, rf)):
            details[task] = {'status': 'unknown', 'reason': 'functional coverage or sample count insufficient'}
            continue
        drop = rf['rate'] - cf['rate']
        details[task] = {'status': 'met' if drop <= rule['max_drop'] else 'not_met', 'drop': drop,
                         'candidate': copy.deepcopy(cf), 'clean': copy.deepcopy(rf)}
    values = [x['status'] for x in details.values()]
    return {'status': 'not_met' if 'not_met' in values else 'unknown' if 'unknown' in values or not values else 'met', 'tasks': details}


def choose(evaluations: list[dict[str, Any]], *, rules: dict[str, Any], task_ids: list[str],
           complete: bool) -> dict[str, Any]:
    base = {'status': 'incomplete', 'final_template': None, 'final_candidate_id': None, 'reasons': [], 'evaluations': evaluations}
    if not complete:
        base['reasons'] = ['frozen retest plan is not complete']
        return base
    if not evaluations:
        base.update(status='undetermined', reasons=['empty shortlist; no functional comparison is available'])
        return base
    if any(e['feasibility']['status'] == 'unknown' for e in evaluations):
        base.update(status='undetermined', reasons=['at least one functional constraint remains unknown'])
        return base
    feasible = [e for e in evaluations if e['feasibility']['status'] == 'met']
    if not feasible:
        base.update(status='no_feasible', reasons=['no shortlisted candidate satisfies the declared functional constraint'])
        return base
    scores = []
    for e in feasible:
        metrics = [e['task_summary'][task]['metrics'][rules['ranking']['metric']] for task in task_ids]
        if any(m['unknown'] or m['rate'] is None for m in metrics):
            base.update(status='undetermined', reasons=['ranking coverage is insufficient'])
            return base
        scores.append((sum(m['rate'] for m in metrics) / len(metrics), e['candidate_id'], e['snapshot_ref']))
    score, cid, snapshot = sorted(scores, key=lambda x: (-x[0], x[1]))[0]
    base.update(status='selected', final_template=snapshot, final_candidate_id=cid, score=score,
                reasons=['selected by the frozen functional and ranking rules'])
    return base


def _freeze(root: Path, spec: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    rules = spec['selection']
    validate_rules(rules)
    candidates = []
    for index in range(1, spec['search']['rounds'] + 1):
        directory = root / f'rounds/{index:04d}'
        frozen = read_json(directory / 'input.json')
        for c in frozen['candidates']:
            candidates.append(read_json(directory / 'candidates' / c['candidate_id'] / 'evidence.json'))
    config = rules['shortlist']
    if config['mode'] == 'explicit_ids':
        wanted = set(config['candidate_ids'])
        if wanted - {c['candidate_id'] for c in candidates}:
            raise ProtocolError('shortlist references unknown search candidates')
    else:
        wanted = {c['candidate_id'] for c in candidates}
    retained, excluded, hashes = [], [], set()
    from .runtime import _settings
    for c in sorted(candidates, key=lambda c: c['candidate_id']):
        cid, reason = c['candidate_id'], None
        if cid not in wanted or c['source'] not in config['include_sources']:
            reason = 'not included by the declared shortlist rule'
        elif c['snapshot_ref'] is None or c['training_status']['status'] != 'measured':
            reason = 'no admitted measured candidate template'
        elif c['content_sha256'] in hashes:
            reason = 'same content already represented in shortlist'
        elif len(retained) >= config['limit']:
            reason = 'declared shortlist limit reached'
        if reason:
            excluded.append({'candidate_id': cid, 'reason': reason})
        else:
            snapshot = read_snapshot(c['snapshot_ref'])
            if snapshot.content_sha256() != c['content_sha256']:
                raise ProtocolError('shortlist snapshot identity mismatch')
            hashes.add(c['content_sha256'])
            retained.append({'candidate_id': cid, 'snapshot_ref': c['snapshot_ref'], 'content_sha256': c['content_sha256'],
                             'reason': 'admitted measured candidate under declared inclusion and ordering',
                             'settings': _settings(spec, 'retest', f'{cid}-retest')})
    return {'rules': copy.deepcopy(rules), 'reference_snapshot_sha256': reference['snapshot_sha256'],
            'task_ids': [t['task_id'] for t in spec['training_tasks']], 'shortlist': retained,
            'excluded': excluded, 'reference_comparability': copy.deepcopy(spec['reference_comparability'])}


def run_selection(root: Path, spec: dict[str, Any], reference: dict[str, Any], *,
                  budget: Any, public_measure: Callable | None = None) -> dict[str, Any]:
    directory = root / 'selection'
    path = directory / 'plan.json'
    expected = _freeze(root, spec, reference)
    if path.is_file():
        plan = read_json(path)
        if plan != expected:
            raise ProtocolError('selection plan or its inputs changed after freezing')
    else:
        plan = expected
        write_json_atomic(path, plan)
    evaluations = []
    write_json_atomic(directory / 'result.json', choose([], rules=plan['rules'], task_ids=plan['task_ids'], complete=False))
    complete = True
    from .runtime import _request_reservation, _actual_attempts, _paused
    for candidate in plan['shortlist']:
        if _paused(root):
            complete = False
            break
        cid = candidate['candidate_id']
        output = directory / 'retests' / cid
        result_path = output / 'measurement.json'
        if result_path.is_file() and read_json(result_path)['complete']:
            measured = read_json(result_path)
        else:
            key = f'{cid}-retest'
            if not budget.reserve(key, 'retest', _request_reservation(candidate['settings'])):
                complete = False
                break
            measured = measure(read_snapshot(candidate['snapshot_ref']), output, candidate['settings'],
                               purpose='retest', public_measure=public_measure)
        if measured['snapshot_sha256'] != candidate['content_sha256'] or measured['settings_sha256'] != sha256_bytes(canonical_json_bytes(candidate['settings'])):
            raise ProtocolError('retest evidence does not match the frozen snapshot/settings')
        budget.settle(f'{cid}-retest', _actual_attempts(measured['consumption_refs']) if measured['complete'] else None)
        if not measured['complete']:
            complete = False
        comparable = plan['reference_comparability'].get('comparable')
        differences = comparability_differences(reference.get('settings', {}), candidate['settings'])
        if differences:
            comparable = None
        evaluation = {**candidate, 'task_summary': measured['task_summary'], 'consumption_refs': measured['consumption_refs'],
                      'comparability_gaps': differences,
                      'feasibility': feasibility(measured['task_summary'], reference['task_summary'],
                          task_ids=plan['task_ids'], rule=plan['rules']['functional'], comparable=comparable)}
        evaluations.append(evaluation)
    result = choose(evaluations, rules=plan['rules'], task_ids=plan['task_ids'], complete=complete)
    result.update(plan_ref=str(path), rule_version=plan['rules']['rule_version'], excluded=plan['excluded'])
    write_json_atomic(directory / 'result.json', result)
    return result
