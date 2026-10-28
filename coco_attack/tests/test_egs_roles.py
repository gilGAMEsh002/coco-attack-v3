"""Research boundaries: source isolation, strict outputs and durable role calls."""
import copy
import json
from pathlib import Path

import pytest
from coco_attack.iteration.action_runtime import ActionStore, RoleCallConfig, ScriptedMockSource
from coco_attack.iteration.template_snapshot import ExampleTemplate, TemplateSnapshot, apply_patch
from coco_methods.evidence_guided_search.contracts import (
    PATCH_POLICY, ProtocolError, initial_experience, namespace_report,
    parse_candidate, parse_report, parse_update,
)
from coco_methods.evidence_guided_search.roles import (
    RoleService, aggregate_variables, call_role, candidate_variables, freeze_templates,
    render_messages, report_variables, response_text, resolve_probe_context, fixed_initial_hypotheses,
)

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / 'cocota_rebuild_docs/CoCo-Attack DSPy 重建实施方案/05-迭代方法/evidence_guided_search/角色提示词模板'
SCOPE = {'task_ids': ['t1', 't2'], 'conditions': [], 'limits': ['training only']}


@pytest.fixture
def initial_template():
    return TemplateSnapshot('combo', 'form', '1', '1', 'cf', 'first_sentence_end', 'instruction_injection', tuple(
        ExampleTemplate(f'e{i}', 'Task.' if i == 1 else 'Task cf.', '    return 1', 'base', i != 1, None if i == 1 else 'cf', ())
        for i in range(1, 5)))


@pytest.fixture
def spec():
    return {'target_definition': 'target', 'modification_contract': 'examples 2/3/4 code/cot',
            'initial_hypotheses': [{'statement': f'initial-{i}', 'scope': copy.deepcopy(SCOPE)} for i in range(6)],
            'training_tasks': [{'task_id': 't1', 'test': 'test1'}, {'task_id': 't2', 'test': 'test2'}],
            'example_tasks': [{'example': index, 'task_id': f'e{index}', 'code_prompt': 'def task_func():',
                               'entry_point': 'task_func', 'test': f'EXAMPLE_TEST_{index}'} for index in range(1, 5)],
            'task_demonstration': 'Fixed clean-to-candidate demonstration.',
            'public_sast_rules': 'public rules'}


def empty_report(candidate='c1'):
    return {'candidate_id': candidate, 'observations': [], 'hypotheses': [],
            'guidance_suggestions': [], 'probe_suggestions': [], 'limitations': []}


def empty_update():
    return {'guidance_updates': [], 'next_probes': [], 'unresolved': [], 'summary': ''}


def report_parse(obj):
    return parse_report(json.dumps(obj), candidate_id='c1', evidence_ids={'s1'}, guidance_ids={'g0001'}, hypothesis_ids=set(), task_ids={'t1', 't2'})


def update_parse(obj):
    return parse_update(json.dumps(obj), guidance_ids={'g0001'}, evidence_ids={'s1'}, hypothesis_ids={'c1:h1'}, candidate_ids={'c1'}, snapshot_ids={'c1'}, task_ids={'t1', 't2'})


def test_projection_withdrawal_and_unguided_invariance(initial_template, spec):
    e0 = initial_experience(spec['initial_hypotheses'])
    baseline = candidate_variables(spec, initial_template, source='unguided', experience=e0)
    e1 = copy.deepcopy(e0)
    e1['guidance'][0]['status'] = 'withdrawn'
    e1['guidance'][1]['statement'] = 'revised hypothesis'
    e1['guidance'][1]['support_refs'] = ['private-victim-output']
    e1['guidance'][2]['uncertainty'] = 'updated confidence'
    e1['reports'] = ['private-victim-output']
    e1['version'] = 9
    assert candidate_variables(spec, initial_template, source='unguided', experience=e1) == baseline
    assert json.loads(baseline['source_context_json']) == {}
    guided = candidate_variables(spec, initial_template, source='guided', experience=e1, guidance_ids=('g0002', 'g0003'))
    assert 'initial-0' not in guided['source_context_json']
    assert 'initial-1' not in guided['source_context_json']
    assert 'revised hypothesis' in guided['source_context_json']
    assert json.loads(guided['source_context_json'])['withdrawn_initial_hypotheses'][0]['initial_index'] == 1
    unchanged_text_update = json.loads(guided['source_context_json'])['guidance'][1]
    assert unchanged_text_update['initial_index'] == 3 and 'statement' not in unchanged_text_update
    assert unchanged_text_update['uncertainty'] == 'updated confidence'
    assert 'private-victim-output' not in json.dumps(guided)
    with pytest.raises(ProtocolError, match='withdrawn'):
        candidate_variables(spec, initial_template, source='guided', experience=e1, guidance_ids=('g0001',))
    assert spec['initial_hypotheses'][1]['statement'] == 'initial-1'


def test_guided_hypotheses_and_example_details_are_not_duplicated(tmp_path, initial_template, spec):
    for task in spec['example_tasks']:
        task.update(instruct_prompt='ALREADY_IN_TEMPLATE', code_prompt='def task_func():',
                    functional_fixture=[{'version': 'NOT_ACTIONABLE_METADATA'}])
    before = copy.deepcopy(spec)
    experience = initial_experience(spec['initial_hypotheses'])
    variables = candidate_variables(spec, initial_template, source='guided', experience=experience,
                                    guidance_ids=tuple(g['guidance_id'] for g in experience['guidance']))
    templates = freeze_templates(TEMPLATES, tmp_path)
    actual = render_messages(templates, 'candidate', variables)[1]['content']
    fixed_statements = fixed_initial_hypotheses((templates / '候选生成/user.md.j2').read_text())
    for statement in fixed_statements:
        assert actual.count(statement) == 1
    assert json.loads(variables['source_context_json']) == {}
    tasks = json.loads(variables['example_tasks_json'])
    assert all(set(task) == {'example', 'task_id', 'test'} for task in tasks)
    assert [task['test'] for task in tasks] == [task['test'] for task in spec['example_tasks']]
    assert 'ALREADY_IN_TEMPLATE' not in actual and 'NOT_ACTIONABLE_METADATA' not in actual
    assert 'initial_hypotheses_json' not in variables
    assert spec == before


@pytest.mark.parametrize('definition', [
    '## 初始启发性假设（固定）\n1. one\n',
    '## 初始启发性假设（固定）\n1. one\n2. two\n3. three\n4. four\n5. five\n6. six\n8. eight\n',
])
def test_fixed_hypotheses_require_six_numbered_statements(definition):
    with pytest.raises(ProtocolError, match='six consecutively numbered nonempty fixed hypotheses'):
        fixed_initial_hypotheses(definition)


def test_freeze_rejects_fixed_hypotheses_hidden_after_first_round(tmp_path):
    import shutil
    source = tmp_path / 'templates'
    shutil.copytree(TEMPLATES, source)
    user = source / '候选生成/user.md.j2'
    text = user.read_text()
    start = text.index('## 初始启发性假设')
    end = text.index('\n{% if source_context_json', start)
    text = text[:start] + "{% if source_context_json == '{}' %}\n" + text[start:end] + '{% endif %}' + text[end:]
    user.write_text(text)
    with pytest.raises(ProtocolError, match='display each fixed hypothesis once'):
        freeze_templates(source, tmp_path / 'run')
    assert not (tmp_path / 'run').exists()


@pytest.mark.parametrize('source', ['guided', 'unguided', 'probe'])
def test_candidate_sees_examples_and_fixed_demo_without_training_material(initial_template, spec, source):
    spec['modification_contract'] = 'REMOVED_CONTRACT_NOT_FOR_CANDIDATE'
    spec['training_tasks'][0].update(instruct_prompt='PRIVATE_TRAIN_PROMPT', test='PRIVATE_TRAIN_TEST',
                                     canonical_solution='PRIVATE_REFERENCE_SOLUTION')
    spec['example_tasks'][0]['canonical_solution'] = 'PRIVATE_EXAMPLE_REFERENCE'
    experience = initial_experience(spec['initial_hypotheses'])
    probe = {key: [] for key in ('fixed_conditions', 'varied_conditions', 'fixed_fields', 'varied_fields',
                                'hypotheses', 'supports_if', 'refutes_if', 'inconclusive_if')}
    probe.update(probe_id='p1', question='compare', arm_key='a', change_request='try')
    variables = candidate_variables(spec, initial_template, source=source, experience=experience,
                                    guidance_ids=('g0001',) if source == 'guided' else (),
                                    probe_context=probe if source == 'probe' else None)
    actual = '\n'.join(variables.values())
    examples = json.loads(variables['initial_template_json'])
    assert len(examples) == 4
    assert all(set(example) == {'instruct_prompt', 'cot', 'code'} for example in examples)
    for visible, original in zip(examples, initial_template.examples):
        assert visible['instruct_prompt'] == original.instruct_prompt
        assert visible['cot'] == original.cot and visible['code'] == original.code
    assert 'EXAMPLE_TEST_1' in actual and 'Fixed clean-to-candidate demonstration.' in actual
    assert not any(value in actual for value in ('PRIVATE_TRAIN_PROMPT', 'PRIVATE_TRAIN_TEST',
                                                'PRIVATE_REFERENCE_SOLUTION', 'PRIVATE_EXAMPLE_REFERENCE'))
    assert 'training_tasks_json' not in variables
    assert 'modification_contract' not in variables
    assert 'REMOVED_CONTRACT_NOT_FOR_CANDIDATE' not in actual
    assert '"t1"' not in actual and '"t2"' not in actual


def test_report_task_projection_keeps_diagnostic_tests_without_reference_solution(spec):
    spec['training_tasks'][0].update(instruct_prompt='TRAIN_REQUIREMENT', test='ACTUAL_TEST',
                                     raw_test='OLD_RAW_TEST', canonical_solution='REFERENCE_ONLY')
    experience = initial_experience(spec['initial_hypotheses'])
    evidence = {'snapshot_ref': 'snapshot', 'sample_evidence': [{'code': 'victim output'}]}
    variables = report_variables(spec, experience=experience, evidence=evidence, evidence_ids=[],
                                 clean_reference={'coverage': 'known'})
    assert 'TRAIN_REQUIREMENT' in variables['training_tasks_json']
    assert 'ACTUAL_TEST' in variables['training_tasks_json']
    assert 'OLD_RAW_TEST' not in variables['training_tasks_json']
    assert 'REFERENCE_ONLY' not in json.dumps(variables)


def test_candidate_learning_goal_and_patch_separation(initial_template):
    raw = {'patch': [{'example': 2, 'cot': 'new'}], 'victim_learning_goal': 'Use the demonstrated process execution strategy.'}
    draft = parse_candidate(json.dumps(raw), initial_template)
    assert draft.victim_learning_goal == raw['victim_learning_goal']
    assert apply_patch(initial_template, draft.patch, PATCH_POLICY).snapshot.example(2).cot == 'new'
    raw['patch'][0]['example'] = 1
    with pytest.raises(ProtocolError):
        parse_candidate(json.dumps(raw), initial_template)
    raw['patch'] = []
    assert parse_candidate(json.dumps(raw), initial_template).patch == ()
    with pytest.raises(ProtocolError):
        parse_candidate('```json\n' + json.dumps(raw) + '\n```', initial_template)
    with pytest.raises(ProtocolError, match='duplicate'):
        parse_candidate('{"patch": [], "patch": [], "victim_learning_goal": "goal"}', initial_template)


@pytest.mark.parametrize('goal', [None, [], {}, 1, '', '  '])
def test_candidate_requires_a_nonempty_learning_goal(initial_template, goal):
    with pytest.raises(ProtocolError):
        parse_candidate(json.dumps({'patch': [], 'victim_learning_goal': goal}), initial_template)


def test_candidate_rejects_old_explanation_fields(initial_template):
    with pytest.raises(ProtocolError, match='candidate: expected exactly'):
        parse_candidate(json.dumps({'patch': [], 'rationale': {
            'intent': 'old', 'expected_change': 'old', 'uncertainty': 'old'}}), initial_template)


def test_report_namespace_and_actual_refs():
    raw = empty_report()
    raw['observations'] = [{'local_key': 'o1', 'statement': 'observed', 'scope': SCOPE, 'evidence_refs': ['s1']}]
    raw['hypotheses'] = [{'local_key': 'h1', 'statement': 'maybe', 'scope': SCOPE, 'support_refs': ['o1'], 'counter_refs': [], 'uncertainty': 'high'}]
    parsed = report_parse(raw)
    transformed = namespace_report(parsed)
    assert transformed['hypotheses'][0]['support_refs'] == ['c1:o1']
    assert transformed['hypotheses'][0]['local_key'] == 'c1:h1'
    assert parsed['hypotheses'][0]['local_key'] == 'h1'
    raw['observations'][0]['evidence_refs'] = ['invented-sample']
    with pytest.raises(ProtocolError, match='unknown references'):
        report_parse(raw)
    with pytest.raises(ProtocolError):
        report_parse(empty_report('other-arm'))


def test_update_references_conflicts_and_probe_fields(initial_template):
    obj = empty_update()
    guidance = {'action': 'withdraw', 'guidance_id': 'g0001', 'statement': 'prior', 'scope': SCOPE,
                'support_refs': [], 'counter_refs': [], 'uncertainty': 'insufficient evidence'}
    obj['guidance_updates'] = [guidance, dict(guidance)]
    with pytest.raises(ProtocolError, match='conflicting'):
        update_parse(obj)
    obj['guidance_updates'] = [guidance]
    assert update_parse(obj)['guidance_updates'][0]['action'] == 'withdraw'
    probe = {'question': 'compare cot', 'hypothesis_refs': ['c1:h1'], 'candidate_refs': ['c1'],
             'fixed_conditions': [], 'varied_conditions': [], 'supports_if': [], 'refutes_if': [], 'inconclusive_if': [],
             'fixed_fields': [{'example': 2, 'field': 'code', 'candidate_ref': 'c1'}],
             'varied_fields': [{'example': 2, 'field': 'cot'}],
             'arms': [{'arm_key': 'a', 'change_request': 'try'}], 'priority_reason': 'information'}
    obj['next_probes'] = [probe]
    update_parse(obj)
    historical = apply_patch(initial_template, [{'example': 2, 'code': '    return 7'}], PATCH_POLICY).snapshot
    context = resolve_probe_context({**probe, 'probe_id': 'p1'}, arm_key='a', initial_template=initial_template, snapshots={'c1': historical}, hypotheses={'c1:h1': {'statement': 'maybe', 'scope': SCOPE}})
    assert context['fixed_fields'][0]['value'] == '    return 7'
    initial_probe = copy.deepcopy(probe)
    initial_probe['fixed_fields'][0]['candidate_ref'] = 'initial_template'
    obj['next_probes'] = [initial_probe]
    update_parse(obj)
    initial_context = resolve_probe_context(
        {**initial_probe, 'probe_id': 'initial-comparison'}, arm_key='a', initial_template=initial_template,
        snapshots={}, hypotheses={'c1:h1': {'statement': 'maybe', 'scope': SCOPE}},
    )
    assert initial_context['fixed_fields'][0]['value'] == initial_template.example(2).code
    obj['next_probes'] = [probe]
    probe['varied_fields'] = [{'example': 2, 'field': 'code'}]
    with pytest.raises(ProtocolError, match='overlapping'):
        update_parse(obj)
    probe['varied_fields'] = []
    probe['fixed_fields'][0]['candidate_ref'] = 'victim-sample'
    with pytest.raises(ProtocolError, match='snapshot'):
        update_parse(obj)


def test_render_all_roles_freeze_and_durable_call(tmp_path, spec, initial_template):
    templates = freeze_templates(TEMPLATES, tmp_path)
    e0 = initial_experience(spec['initial_hypotheses'])
    variables = candidate_variables(spec, initial_template, source='unguided', experience=e0)
    messages = render_messages(templates, 'candidate', variables)
    assert len(messages) == 2
    assert 'candidate_source' not in json.dumps(messages)
    report_vars = report_variables(spec, experience=e0, evidence={
        'snapshot_ref': None, 'sample_evidence': [], 'failure_stage': 'parse'}, evidence_ids=['c1'], clean_reference={'private': 'irrelevant'})
    assert report_vars['clean_reference_json'] == '{}'
    assert report_vars['training_tasks_json'] == '[]'
    render_messages(templates, 'report', report_vars)
    aggregate = aggregate_variables(experience=e0, reports=[], summaries=[], clean_reference={}, executed_probes=[], evidence_ids=[])
    render_messages(templates, 'aggregate', aggregate)
    source = ScriptedMockSource(['{"patch": [], "victim_learning_goal": "Preserve the existing approach."}'])
    service = RoleService(RoleCallConfig(role='candidate', model='mock-model'), source)
    store = ActionStore(tmp_path / 'candidate')
    for _ in range(2):
        outcome = call_role(store, action_id='c1-generate', role='candidate', template_dir=templates,
                            variables=variables, service=service, candidate_source='unguided')
        assert response_text(outcome)
    assert len(source.calls) == 1
    with pytest.raises(ProtocolError):
        render_messages(templates, 'candidate', {**variables, 'candidate_source': 'unguided'})
    with pytest.raises(FileExistsError):
        freeze_templates(TEMPLATES, tmp_path)
    (templates / '候选生成/user.md.j2').write_text('tampered')
    with pytest.raises(ProtocolError, match='changed'):
        render_messages(templates, 'candidate', variables)


def test_incomplete_template_freeze_is_never_rendered(tmp_path, monkeypatch):
    from coco_methods.evidence_guided_search import roles
    real_write = Path.write_bytes
    def interrupted(path, *args, **kwargs):
        if path.name == 'user.md.j2':
            raise OSError('simulated interruption')
        return real_write(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_bytes', interrupted)
    with pytest.raises(OSError):
        freeze_templates(TEMPLATES, tmp_path)
    target = tmp_path / 'inputs/role_templates'
    assert not target.exists()
    monkeypatch.setattr(Path, 'write_bytes', real_write)
    freeze_templates(TEMPLATES, tmp_path)
    (target / 'manifest.json').unlink()
    with pytest.raises(ProtocolError, match='manifest'):
        render_messages(target, 'aggregate', aggregate_variables(experience={}, reports=[], summaries=[], clean_reference={}, executed_probes=[], evidence_ids=[]))


def test_probe_materializes_historical_fixed_fields_even_when_omitted(initial_template):
    from coco_methods.evidence_guided_search.candidate_exploration import probe_patch, verify_probe
    context = {'fixed_fields': [{'example': 2, 'field': 'code', 'value': '    return 9'}],
               'varied_fields': [{'example': 2, 'field': 'cot'}]}
    patch = probe_patch(initial_template, ({'example': 2, 'cot': 'new'},), context)
    snapshot = apply_patch(initial_template, patch, PATCH_POLICY).snapshot
    verify_probe(snapshot, initial_template, context)
    assert snapshot.example(2).code == '    return 9'
    assert snapshot.example(2).cot == 'new'
    with pytest.raises(ProtocolError):
        probe_patch(initial_template, ({'example': 2, 'code': '    return 5'},), context)


def test_probe_criteria_preserve_single_string_as_one_condition():
    report = empty_report()
    criteria = 'One criterion; preserve the semicolon and newline\nexactly.'
    report['probe_suggestions'] = [{
        'question': 'compare', 'hypothesis_refs': [], 'candidate_refs': ['c1'],
        'fixed_conditions': [], 'varied_conditions': [],
        'supports_if': criteria, 'refutes_if': 'counter', 'inconclusive_if': 'unknown'}]
    parsed = report_parse(report)
    assert parsed['probe_suggestions'][0]['supports_if'] == [criteria]
    assert report['probe_suggestions'][0]['supports_if'] == criteria
    report['probe_suggestions'][0]['supports_if'] = 1
    with pytest.raises(ProtocolError, match='expected string array'):
        report_parse(report)
    report['probe_suggestions'][0].pop('supports_if')
    with pytest.raises(ProtocolError):
        report_parse(report)


def test_ambiguous_varied_field_reference_is_kept_but_cannot_execute(initial_template, spec):
    from coco_methods.evidence_guided_search.experience_review import apply_update
    from coco_methods.evidence_guided_search.runtime import _plan
    proposal = {'question': 'comparison not fully specified', 'hypothesis_refs': [], 'candidate_refs': ['c1'],
        'fixed_conditions': [], 'varied_conditions': [], 'supports_if': [], 'refutes_if': [], 'inconclusive_if': [],
        'fixed_fields': [{'example': 2, 'field': 'cot', 'candidate_ref': 'c1'}],
        'varied_fields': [{'example': 2, 'field': 'code', 'candidate_ref': 'c1'}],
        'arms': [{'arm_key': 'a', 'change_request': 'one'}, {'arm_key': 'b', 'change_request': 'two'}],
        'priority_reason': 'proposal only'}
    update = empty_update()
    update['next_probes'] = [proposal]
    parsed = update_parse(update)
    experience = apply_update(initial_experience(spec['initial_hypotheses']), parsed, [])
    pending = experience['next_probes'][0]
    assert pending['status'] == 'needs_refinement'
    assert pending['varied_fields'] == proposal['varied_fields']
    assert pending['execution_blockers']
    plan_spec = {'search': {'guidance_policy': 'all_active', 'probe_policy': 'in_order_complete_groups',
        'duplicate_policy': 'independent_sampling', 'guided_count': 0, 'unguided_count': 0, 'probe_groups_per_round': 1}}
    assert _plan(plan_spec, experience, 1, set()).probes == ()
    with pytest.raises(ProtocolError, match='refinement'):
        resolve_probe_context(pending, arm_key='a', initial_template=initial_template, snapshots={'c1': initial_template}, hypotheses={})
    proposal['varied_fields'][0]['candidate_ref'] = 'unprovided-victim-code'
    with pytest.raises(ProtocolError, match='snapshot'):
        update_parse(update)


def test_report_local_keys_may_contain_colons_without_cross_candidate_aliasing():
    report = empty_report()
    report['observations'] = [{'local_key': 'c1:observation', 'statement': 'observed', 'scope': SCOPE, 'evidence_refs': ['s1']}]
    report['hypotheses'] = [{'local_key': 'c1:hypothesis', 'statement': 'maybe', 'scope': SCOPE,
        'support_refs': ['c1:observation'], 'counter_refs': [], 'uncertainty': 'conditional'}]
    parsed = report_parse(report)
    first = namespace_report(parsed)
    assert first['hypotheses'][0]['support_refs'] == [first['observations'][0]['local_key']]
    parsed['candidate_id'] = 'c2'
    second = namespace_report(parsed)
    assert second['observations'][0]['local_key'] != first['observations'][0]['local_key']
    assert second['observations'][0]['local_key'].startswith('c2:')
