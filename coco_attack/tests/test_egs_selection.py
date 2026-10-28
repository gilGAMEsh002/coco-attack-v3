import copy

from coco_methods.evidence_guided_search.template_selection import choose, feasibility, validate_rules
from test_egs_runtime import rules


def summary(f=1, h=1, unknown=0):
    return {task: {'metrics': {'F': {'count': f, 'denominator': 1, 'unknown': unknown, 'rate': f},
                               'H_and_F_and_not_D': {'count': h, 'denominator': 1, 'unknown': unknown, 'rate': h}}}
            for task in ('t1', 't2')}


def evaluation(cid='c1', f=1, h=1, unknown=0, comparable=True):
    rule = rules()
    stats = summary(f, h, unknown)
    return {'candidate_id': cid, 'snapshot_ref': f'snapshot-{cid}', 'task_summary': stats,
            'feasibility': feasibility(stats, summary(), task_ids=['t1', 't2'], rule=rule['functional'], comparable=comparable)}


def test_four_selection_statuses_and_unknown_never_passes():
    r = rules()
    validate_rules(r)
    select = lambda xs, complete=True: choose(xs, rules=r, task_ids=['t1', 't2'], complete=complete)
    assert select([evaluation()])['status'] == 'selected'
    assert select([evaluation(f=0)])['status'] == 'no_feasible'
    assert select([evaluation(comparable=None)])['status'] == 'undetermined'
    assert select([evaluation(unknown=1)])['status'] == 'undetermined'
    assert select([evaluation()], False)['status'] == 'incomplete'
    for result in (select([evaluation(f=0)]), select([evaluation(comparable=False)]), select([], False)):
        assert result['final_template'] is None
    assert select([evaluation('c2'), evaluation('c1')])['final_candidate_id'] == 'c1'
    assert select([evaluation('c1'), evaluation('c2', comparable=None)])['status'] == 'undetermined'


def test_relative_clean_drop_is_per_task_and_not_a_ratio():
    candidate, clean = summary(0), summary(0)
    result = feasibility(candidate, clean, task_ids=['t1', 't2'], rule=rules()['functional'], comparable=True)
    assert result['status'] == 'met'
    clean['t2']['metrics']['F']['rate'] = 1
    assert feasibility(candidate, clean, task_ids=['t1', 't2'], rule=rules()['functional'], comparable=True)['status'] == 'not_met'


def test_actual_comparability_detects_changed_model_and_evaluator():
    from coco_methods.evidence_guided_search.template_selection import comparability_differences
    original = {'task_ids': ['t1', 't2'], 'generation': {'model': 'one', 'batch_id': 'clean'}, 'functional': {'harness_version': 'v1'}}
    retest = copy.deepcopy(original)
    retest['generation']['batch_id'] = 'retest'
    assert comparability_differences(original, retest) == []
    retest['generation']['model'] = 'two'
    assert comparability_differences(original, retest)
    retest['generation']['model'] = 'one'
    retest['functional']['harness_version'] = 'v2'
    assert comparability_differences(original, retest)
