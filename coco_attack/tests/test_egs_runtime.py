import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
from coco_attack.assets.artifacts import read_json, sha256_bytes
from coco_attack.iteration.action_runtime import RoleCallConfig, ScriptedMockSource
from coco_attack.iteration.template_snapshot import read_snapshot, write_snapshot
from coco_attack.runtime.ledger import Ledger
from coco_methods.evidence_guided_search.runtime import RuntimeServices, initialize, run, pause
from coco_methods.evidence_guided_search.roles import RoleService
from test_egs_roles import initial_template, spec, TEMPLATES, SCOPE, empty_report, empty_update


@pytest.fixture(autouse=True)
def offline_example_task_loader(monkeypatch):
    # Runtime tests inject task material just as they inject checker/model services.
    from coco_methods.evidence_guided_search import runtime
    monkeypatch.setattr(runtime, 'example_materials', lambda spec, snapshot: copy.deepcopy(spec['example_tasks']))


def rules():
    return {'rule_version': 'offline-test-only',
            'shortlist': {'mode': 'all_admitted_unique', 'content_policy': 'merge_first', 'order': 'candidate_id',
                          'include_sources': ['guided', 'unguided', 'probe'], 'limit': 2},
            'evidence_policy': 'retest_only', 'unknown_policy': 'require_all_decided',
            'functional': {'comparison': 'per_task_absolute_drop', 'max_drop': 0.1, 'minimum': 1, 'require_complete': True, 'estimator': 'empirical'},
            'ranking': {'metric': 'H_and_F_and_not_D', 'aggregation': 'macro', 'tie_break': 'candidate_id', 'direction': 'maximize', 'require_complete': True}}


def setup_run(tmp_path, spec, initial_template, *, role_attempts=30, execution_mode='search_and_select'):
    base = copy.deepcopy(spec)
    clean_template = replace(
        initial_template, trigger=None, injection_position=None,
        examples=tuple(replace(example, instruct_prompt='Task.', is_poisoned=False, trigger=None, poison_parts=())
                       for example in initial_template.examples),
    )
    generation = {'source': 'mock', 'model': 'mock', 'max_request_attempts': 1, 'max_sample_retries': 0, 'max_concurrency': 1}
    settings = {'stage': 'search', 'victim_messages': 'single_user', 'task_ids': ['t1', 't2'], 'repeats': 1,
                'generation': generation, 'evaluators': {'sast_tools': ['semgrep']}}
    base.update(initial_template_path=str(write_snapshot(tmp_path / 'start', initial_template, action_id='test-initial_template')),
                clean_snapshot_path=str(write_snapshot(tmp_path / 'clean', clean_template, action_id='test-clean')),
                template_dir=str(TEMPLATES), measurement=copy.deepcopy(settings),
                reference_measurement=copy.deepcopy(settings), retest_measurement=copy.deepcopy(settings),
                reference_comparability={'comparable': True, 'reason': 'controlled offline fixture'},
                admission={'oracle_states': ['present', 'possibly_present'], 'semantic_mode': 'prompt_only'},
                example_check={'assets_root': str(tmp_path), 'execution_config_path': str(tmp_path / 'execution.json'),
                               'semgrep_config': str(tmp_path), 'code_input_mode': 'example_body', 'stage': 'search',
                               'semgrep_timeout_seconds': 1, 'candidate_timeout_seconds': 1},
                search={'rounds': 2, 'guided_count': 1, 'unguided_count': 1, 'probe_groups_per_round': 1,
                        'guidance_policy': 'all_active', 'probe_policy': 'in_order_complete_groups', 'duplicate_policy': 'independent_sampling'},
                concurrency={'candidate_workers': 1, 'total_victim_requests': 1},
                budget={'unit': 'victim_request_attempts', 'allocations': {'reference': 2, 'search': 20, 'retest': 4}, 'role_attempts': role_attempts},
                selection=rules())
    base['execution_mode'] = execution_mode
    if execution_mode == 'search_only':
        base['selection'] = None
        base['retest_measurement'] = None
        base['budget']['allocations']['retest'] = 0
        base['search']['guided_count'] = 2
        base['search']['probe_groups_per_round'] = 0
    (tmp_path / 'execution.json').write_text('{}')
    base['example_check']['semgrep_config'] = str(tmp_path / 'rules')
    (tmp_path / 'rules').mkdir()
    root = tmp_path / 'run'
    initialize(base, root)
    calls = {'measurement': [], 'reports': [], 'aggregate': []}
    def check(request):
        return {'sample_id': f'example-check:{request.task_id}', 'task_id': request.task_id,
                'code': {'input_code_sha256': sha256_bytes(request.code.encode())},
                'syntax': {'state': 'executed', 'syntax_ok': True, 'entry_present': True},
                'functional': {'passed': True}, 'static': {'verdict': 'target_present'},
                'semgrep': {'status': 'completed', 'completed': True, 'available': True, 'coverage': 'covered', 'detected': False}}
    def public_measure(snapshot, output_dir, settings):
        batch = settings['generation']['batch_id']
        calls['measurement'].append(batch)
        result = {'complete': True, 'generation_rows': [], 'cleaned_rows': [], 'static_rows': [], 'sast_rows': [], 'functional_rows': [], 'gaps': [], 'consumption_refs': []}
        text = 'def f(): return 1'
        digest = sha256_bytes(text.encode())
        ledger = Ledger(output_dir / 'generation/ledger.jsonl')
        for task in ('t1', 't2'):
            sid = f'public:{batch}:{task}'
            ledger.append('attempt_started', sample_id=sid, request_attempt_id=sid)
            ledger.append('response_received', sample_id=sid, request_attempt_id=sid, payload={'usage': {'total_tokens': 10}, 'cost': {'amount': None}})
            result['generation_rows'].append({'sample_id': sid, 'task_id': task, 'repeat_id': 0, 'status': 'success'})
            result['cleaned_rows'].append({'task_id': task, 'repeat_id': 0, 'cleaned': {'final_code': text, 'final_code_sha256': digest}})
            result['static_rows'].append({'task_id': task, 'repeat_id': 0, 'final_code_sha256': digest, 'raw_oracle_result': {'verdict': 'target_present'}})
            result['sast_rows'].append({'sample_id': sid, 'tool': 'semgrep', 'sources': {'final_code_sha256': digest}, 'completed': True, 'available': True, 'status': 'completed', 'coverage': 'covered', 'detected': False})
            result['functional_rows'].append({'sample_id': sid, 'fingerprint': {'final_code_sha256': digest}, 'passed': True})
        result['consumption_refs'] = [str(ledger.path)]
        return result
    proposal = ScriptedMockSource([json.dumps({'patch': [{'example': 2, 'cot': 'candidate'}],
                                              'victim_learning_goal': 'Use the demonstrated process execution strategy.'})])
    def report_builder(messages, attempt):
        body = messages[1]['content']
        calls['reports'].append(body)
        # The fixed candidate ID is part of the evidence JSON, never model invented.
        import re
        cid = re.search(r'"candidate_id": "([^"]+)"', body.split('## 本候选、示例检查、原始输出与程序评价')[1]).group(1)
        return json.dumps(empty_report(cid))
    report_source = ScriptedMockSource(content_builder=report_builder)
    def aggregate_builder(messages, attempt):
        calls['aggregate'].append(messages)
        update = empty_update()
        if len(calls['aggregate']) == 1:
            update['guidance_updates'] = [
                {'action': 'withdraw', 'guidance_id': 'g0001', 'statement': 'initial-0', 'scope': SCOPE, 'support_refs': [], 'counter_refs': [], 'uncertainty': 'insufficient'},
                {'action': 'add', 'guidance_id': None, 'statement': 'new conditional guidance', 'scope': SCOPE, 'support_refs': [], 'counter_refs': [], 'uncertainty': 'untested'}]
        return json.dumps(update)
    aggregate_source = ScriptedMockSource(content_builder=aggregate_builder)
    services = RuntimeServices(*(RoleService(RoleCallConfig(role=r, model='mock', max_request_attempts=1), source)
        for r, source in [('candidate', proposal), ('report', report_source), ('aggregate', aggregate_source)]),
        public_measure=public_measure, example_check=check)
    return root, services, calls


@pytest.mark.parametrize('trigger_location', ['query', 'example'])
def test_initialize_rejects_triggered_clean_reference(tmp_path, spec, initial_template, trigger_location):
    root, _, _ = setup_run(tmp_path, spec, initial_template)
    saved_spec = read_json(root / 'run.json')
    clean_template = read_snapshot(saved_spec['clean_snapshot_path'])
    if trigger_location == 'query':
        invalid_clean = replace(clean_template, trigger='cf')
    else:
        invalid_clean = replace(clean_template, examples=(
            replace(clean_template.examples[0], trigger='cf'), *clean_template.examples[1:],
        ))
    saved_spec['clean_snapshot_path'] = str(write_snapshot(
        tmp_path / 'invalid-clean', invalid_clean, action_id='invalid-clean',
    ))
    rejected_dir = tmp_path / 'rejected-run'
    from coco_methods.evidence_guided_search.contracts import ProtocolError
    with pytest.raises(ProtocolError, match='without injected triggers'):
        initialize(saved_spec, rejected_dir)
    assert not rejected_dir.exists()


def test_offline_two_rounds_and_restore_without_resampling(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    state = run(root, services=services)
    assert state['status'] == 'complete'
    assert state['selection_status'] == 'selected'
    assert state['published_round'] == 2
    first = read_json(root / 'rounds/0001/input.json')
    second = read_json(root / 'rounds/0002/input.json')
    assert first['experience']['guidance'][0]['status'] == 'active'
    assert second['experience']['guidance'][0]['status'] == 'withdrawn'
    assert len(second['experience']['guidance']) == 7
    assert 'g0001' not in second['guidance_ids']
    assert len(calls['reports']) == 4
    first_evidence = read_json(root / 'rounds/0001/candidates/r0001-guided-001/evidence.json')
    assert first_evidence['victim_learning_goal'] == 'Use the demonstrated process execution strategy.'
    assert 'Use the demonstrated process execution strategy.' in calls['reports'][0]
    assert 'new conditional guidance' not in calls['reports'][0]
    saved_calls = list(calls['measurement'])
    assert run(root, services=services, resume=True)['status'] == 'complete'
    assert calls['measurement'] == saved_calls


def test_report_interruption_reuses_victim_evidence(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    import dataclasses
    failing = dataclasses.replace(services, report=RoleService(RoleCallConfig(role='report', model='mock', max_request_attempts=1), ScriptedMockSource(['not json'])))
    with pytest.raises(Exception, match='invalid JSON'):
        run(root, services=failing)
    generated = list(calls['measurement'])
    # Invalid durable JSON is never silently repaired by making a second call.
    with pytest.raises(Exception, match='invalid JSON'):
        run(root, services=services, resume=True)
    assert calls['measurement'] == generated


def test_durable_report_response_after_interruption_never_resamples(tmp_path, spec, initial_template, monkeypatch):
    from coco_methods.evidence_guided_search import experience_review
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    real_parse = experience_review.parse_report
    crashed = False
    def interrupt_once(*args, **kwargs):
        nonlocal crashed
        if not crashed:
            crashed = True
            raise OSError('crash after response saved')
        return real_parse(*args, **kwargs)
    monkeypatch.setattr(experience_review, 'parse_report', interrupt_once)
    with pytest.raises(OSError, match='response saved'):
        run(root, services=services)
    first_batch = calls['measurement'][1]
    assert run(root, services=services, resume=True)['status'] == 'complete'
    assert calls['measurement'].count(first_batch) == 1
    assert len(calls['reports']) == 4


def test_pause_and_resume_preserve_round_input(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    pause(root)
    assert run(root, services=services)['status'] == 'paused'
    assert calls['measurement'] == []
    assert not (root / 'rounds/0001/input.json').exists()
    assert run(root, services=services, resume=True)['status'] == 'complete'
    assert read_json(root / 'rounds/0001/input.json')['round_index'] == 1


def test_saved_update_recovers_publication_without_second_aggregate(tmp_path, spec, initial_template, monkeypatch):
    from coco_methods.evidence_guided_search import experience_review
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    real_write = experience_review.write_json_atomic
    interrupted = False
    def crash_experience(path, payload):
        nonlocal interrupted
        if Path(path).name == 'experience.json' and not interrupted:
            interrupted = True
            raise OSError('crash before experience publication')
        return real_write(path, payload)
    monkeypatch.setattr(experience_review, 'write_json_atomic', crash_experience)
    with pytest.raises(OSError, match='publication'):
        run(root, services=services)
    assert read_json(root / 'state.json')['published_round'] == 0
    assert (root / 'rounds/0001/update.json').is_file()
    measured = list(calls['measurement'])
    assert run(root, services=services, resume=True)['status'] == 'complete'
    assert len(calls['aggregate']) == 2
    assert all(calls['measurement'].count(batch) == 1 for batch in measured)


def test_next_round_probes_and_execution_status(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    original = services.aggregate.source._content_builder
    def with_probe(messages, attempt):
        update = json.loads(original(messages, attempt))
        if len(calls['aggregate']) == 1:
            update['next_probes'] = [{'question': 'cot comparison', 'hypothesis_refs': [],
                'candidate_refs': ['r0001-guided-001'], 'fixed_conditions': [], 'varied_conditions': [],
                'supports_if': ['predeclared observation'], 'refutes_if': [], 'inconclusive_if': [],
                'fixed_fields': [{'example': 2, 'field': 'cot', 'candidate_ref': 'r0001-guided-001'}],
                'varied_fields': [{'example': 2, 'field': 'code'}],
                'arms': [{'arm_key': 'a', 'change_request': 'first'}, {'arm_key': 'b', 'change_request': 'second'}],
                'priority_reason': 'test explicit comparison'}]
        return json.dumps(update)
    services.aggregate.source._content_builder = with_probe
    assert run(root, services=services)['status'] == 'complete'
    assert not read_json(root / 'rounds/0001/input.json')['probes']
    assert len(read_json(root / 'rounds/0002/input.json')['probes']) == 1
    published = read_json(root / 'rounds/0002/experience.json')
    assert published['next_probes'][0]['status'] == 'executed'
    assert len(published['next_probes'][0]['execution']) == 2
    assert len(calls['reports']) == 6


def test_retest_resume_reuses_frozen_plan_and_measurements(tmp_path, spec, initial_template, monkeypatch):
    from coco_methods.evidence_guided_search import template_selection
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    real_choose = template_selection.choose
    interrupted = False
    def crash_final_choice(*args, **kwargs):
        nonlocal interrupted
        if kwargs['complete'] and not interrupted:
            interrupted = True
            raise OSError('crash after retest before final choice')
        return real_choose(*args, **kwargs)
    monkeypatch.setattr(template_selection, 'choose', crash_final_choice)
    with pytest.raises(OSError, match='after retest'):
        run(root, services=services)
    plan = read_json(root / 'selection/plan.json')
    retest_calls = [b for b in calls['measurement'] if b.endswith('-retest')]
    assert retest_calls
    assert run(root, services=services, resume=True)['selection_status'] == 'selected'
    assert read_json(root / 'selection/plan.json') == plan
    assert all(calls['measurement'].count(batch) == 1 for batch in retest_calls)


def test_status_reports_actual_unknown_cost_and_coverage(tmp_path, spec, initial_template):
    from coco_methods.evidence_guided_search.runtime import status
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    run(root, services=services)
    report = status(root)
    assert report['sample_coverage']['search']['planned'] == 8
    assert report['sample_coverage']['search']['terminal'] == 8
    assert report['sample_coverage']['retest']['planned'] == 2
    assert report['consumption']['tokens']['known'] > 0
    assert report['consumption']['cost']['unknown_attempts'] > 0
    assert report['budget']['phases']['retest']['used'] == 2
    assert report['budget']['phases']['search']['used'] == 8


def test_role_budget_stop_does_not_fabricate_candidate_failure(tmp_path, spec, initial_template):
    from coco_methods.evidence_guided_search.roles import RoleBudgetExhausted
    root, services, calls = setup_run(tmp_path, spec, initial_template, role_attempts=0)
    with pytest.raises(RoleBudgetExhausted):
        run(root, services=services)
    assert services.candidate.source.calls == []
    assert not (root / 'rounds/0001/candidates/r0001-guided-001/evidence.json').exists()
    assert read_json(root / 'state.json')['published_round'] == 0


def test_stale_reference_is_rejected_before_any_new_sampling(tmp_path, spec, initial_template):
    from coco_attack.assets.artifacts import write_json_atomic
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    run(root, services=services)
    state = read_json(root / 'state.json')
    state['status'] = 'incomplete'
    write_json_atomic(root / 'state.json', state)
    ref = read_json(root / 'reference/measurement.json')
    ref['snapshot_sha256'] = 'stale-clean-template'
    write_json_atomic(root / 'reference/measurement.json', ref)
    before = list(calls['measurement'])
    with pytest.raises(Exception, match='clean reference evidence'):
        run(root, services=services, resume=True)
    assert calls['measurement'] == before


def test_training_prompt_material_is_bound_to_prepared_tasks(tmp_path, spec, initial_template, monkeypatch):
    from types import SimpleNamespace
    from coco_attack.data import snapshot as data_snapshot
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    saved = read_json(root / 'run.json')
    data = tmp_path / 'prepared'
    (data / 'combo').mkdir(parents=True)
    (data / 'manifest.json').write_text('{}')
    for name in ('tasks.jsonl', 'selection.json', 'split.json'):
        (data / 'combo' / name).write_text('{}')
    saved['measurement']['data_dir'] = str(data)
    records = {task: SimpleNamespace(test='test' + task[-1], effective={
        'task_id': task, 'instruct_prompt': 'Full original ' + task,
        'code_prompt': 'def task_func():', 'entry_point': 'task_func', 'test': 'test' + task[-1]})
        for task in ('t1', 't2')}
    monkeypatch.setattr(data_snapshot, 'load_prepared_data', lambda *args: SimpleNamespace(task_by_id=lambda: records))
    initialize(saved, tmp_path / 'bound-run')
    material = read_json(tmp_path / 'bound-run/inputs/training_tasks.json')
    assert material[0]['instruct_prompt'] == 'Full original t1'
    assert material[0]['test'] == records['t1'].test
    assert material[0]['raw_test'] == records['t1'].test
    saved['training_tasks'][0]['instruct_prompt'] = 'wrong task'
    with pytest.raises(Exception, match='differs from prepared original'):
        initialize(saved, tmp_path / 'wrong-run')


def test_clean_start_runs_but_absent_candidates_still_fail_admission(tmp_path, spec, initial_template):
    from coco_methods.evidence_guided_search.contracts import ProtocolError
    root, services, calls = setup_run(tmp_path, spec, initial_template, execution_mode='search_only')
    saved = read_json(root / 'run.json')
    saved['initial_template_kind'] = 'clean_fewshot'
    demonstration = tmp_path / 'demonstration.md'
    demonstration.write_text('FROZEN_DEMO_BEFORE')
    saved['task_demonstration_path'] = str(demonstration)
    clean_root = tmp_path / 'clean-run'
    initialize(saved, clean_root)
    demonstration.write_text('CHANGED_OUTSIDE_RUN')
    assert read_json(clean_root / 'run.json')['task_demonstration'] == 'FROZEN_DEMO_BEFORE'
    # This injected checker sees a clean base, and candidates that made no target-code change.
    def absent_check(request):
        result = services.example_check(request)
        result['static'] = {'verdict': 'target_absent'}
        return result
    state = run(clean_root, services=replace(services, example_check=absent_check))
    assert state['status'] == 'complete' and state['published_round'] == 2
    initial_checks = read_json(clean_root / 'inputs/initial_template_checks.json')
    assert initial_checks['purpose'] == 'clean_start_usability'
    assert initial_checks['admission']['status'] == 'admitted'
    assert calls['measurement'] == ['reference-clean']
    for p in clean_root.glob('rounds/*/candidates/*/admission.json'):
        decision = read_json(p)
        assert decision['status'] == 'rejected'
        assert any('oracle absent not allowed' in reason for reason in decision['reasons'])
    assert all('FROZEN_DEMO_BEFORE' in req[1]['content'] and
               'CHANGED_OUTSIDE_RUN' not in str(req)
               for req in services.candidate.source.calls)
    before = list(calls['measurement'])
    assert run(clean_root, services=services, resume=True)['status'] == 'complete'
    assert calls['measurement'] == before
    # The declaration cannot be used to relabel a modified template as a clean start.
    invalid = replace(initial_template, examples=(
        initial_template.examples[0], replace(initial_template.examples[1], code='    return 99'),
        *initial_template.examples[2:]))
    saved['initial_template_path'] = str(write_snapshot(tmp_path / 'bad-start', invalid, action_id='bad-start'))
    with pytest.raises(ProtocolError, match='preserve original clean code/CoT'):
        initialize(saved, tmp_path / 'bad-run')


def test_untrained_scope_does_not_gain_unprovided_training_ids(spec):
    from coco_methods.evidence_guided_search.experience_review import scope_task_ids
    evidence = {'snapshot_ref': None, 'example_checks': [{'facts': {'task_id': 'e2'}}],
                'sample_evidence': []}
    experience = {'guidance': [], 'reports': []}
    assert scope_task_ids(spec, experience, [evidence]) == {'e2'}
    # Aggregate receives clean statistics even when no candidate was trained;
    # that grants scope for those actual statistics, without granting report access.
    assert scope_task_ids(spec, experience, [evidence], clean_reference={
        'task_summary': {'t1': {}}}) == {'e2', 't1'}
    evidence['sample_evidence'] = [{'task_id': 't1'}]
    assert scope_task_ids(spec, experience, [evidence]) == {'e2', 't1', 't2'}


def test_resume_rejects_changed_sast_policy_before_new_calls(tmp_path, spec, initial_template, monkeypatch):
    from coco_methods.evidence_guided_search import runtime
    from coco_methods.evidence_guided_search.contracts import ProtocolError
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    saved = read_json(root / 'run.json')
    assert saved['sast_adapter_fingerprint']['semgrep_suppression_policy'] == 'disabled'
    changed = {**saved['sast_adapter_fingerprint'], 'semgrep_suppression_policy': 'enabled'}
    monkeypatch.setattr(runtime, 'sast_adapter_fingerprint', lambda: changed)
    with pytest.raises(ProtocolError, match='SAST adapter policy changed'):
        run(root, services=services, resume=True)
    assert calls['measurement'] == []


def test_unfinished_legacy_run_cannot_silently_adopt_new_scanner(tmp_path, spec, initial_template):
    from coco_attack.assets.artifacts import canonical_json_bytes, write_json_atomic
    from coco_methods.evidence_guided_search.contracts import ProtocolError
    root, services, calls = setup_run(tmp_path, spec, initial_template)
    saved = read_json(root / 'run.json')
    saved.pop('sast_adapter_fingerprint')
    write_json_atomic(root / 'run.json', saved)
    state = read_json(root / 'state.json')
    state['run_sha256'] = sha256_bytes(canonical_json_bytes(saved))
    write_json_atomic(root / 'state.json', state)
    with pytest.raises(ProtocolError, match='no frozen SAST policy'):
        run(root, services=services, resume=True)
    assert calls['measurement'] == []
    # Completed legacy runs can still return their saved result without scanning.
    state['status'] = 'complete'
    write_json_atomic(root / 'state.json', state)
    assert run(root, services=services, resume=True)['status'] == 'complete'
    assert calls['measurement'] == []


def test_user_template_owns_fixed_hypotheses_and_freezes_them(tmp_path, spec, initial_template):
    import shutil
    from coco_methods.evidence_guided_search.roles import fixed_initial_hypotheses, candidate_variables, render_messages
    root, _, _ = setup_run(tmp_path, spec, initial_template)
    saved = read_json(root / 'run.json')
    source = tmp_path / 'editable-templates'
    shutil.copytree(TEMPLATES, source)
    user = source / '候选生成/user.md.j2'
    old = fixed_initial_hypotheses(user.read_text())[0]
    user.write_text(user.read_text().replace(old, 'TEMPLATE_FIXED_HYPOTHESIS'))
    saved['template_dir'] = str(source)
    new_root = tmp_path / 'fixed-run'
    initialize(saved, new_root)
    frozen = read_json(new_root / 'run.json')
    experience = read_json(new_root / 'inputs/experience-0.json')
    assert frozen['initial_hypotheses'][0]['statement'] == 'TEMPLATE_FIXED_HYPOTHESIS'
    assert experience['guidance'][0]['statement'] == 'TEMPLATE_FIXED_HYPOTHESIS'
    user.write_text(user.read_text().replace('TEMPLATE_FIXED_HYPOTHESIS', 'LATER_EXTERNAL_CHANGE'))
    variables = candidate_variables(frozen, read_snapshot(frozen['initial_template_path']),
                                    source='unguided', experience=experience)
    actual = render_messages(frozen['template_dir'], 'candidate', variables)[1]['content']
    assert actual.count('TEMPLATE_FIXED_HYPOTHESIS') == 1
    assert 'LATER_EXTERNAL_CHANGE' not in actual


def test_search_only_finishes_two_rounds_without_selection_or_retest(tmp_path, spec, initial_template, monkeypatch):
    from coco_methods.evidence_guided_search import template_selection
    root, services, calls = setup_run(tmp_path, spec, initial_template, execution_mode='search_only')
    def forbidden(*args, **kwargs):
        raise AssertionError('selection must not run for this trial')
    monkeypatch.setattr(template_selection, 'run_selection', forbidden)
    result = run(root, services=services)
    assert result['status'] == 'complete'
    assert result['published_round'] == 2
    assert result['step'] == 'search_complete'
    assert result['selection_status'] == 'not_requested'
    assert len(calls['reports']) == 6
    assert len(calls['aggregate']) == 2
    assert len(calls['measurement']) == 7  # one reference and six search batches
    assert not (root / 'selection').exists()
    assert read_json(root / 'budget.json')['allocations']['retest'] == 0
    before = list(calls['measurement'])
    assert run(root, services=services, resume=True)['step'] == 'search_complete'
    assert calls['measurement'] == before


def test_example_task_scopes_flow_through_reports_and_round_updates(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template, execution_mode='search_only')
    original_report = services.report.source._content_builder
    def report_with_example_scope(messages, attempt):
        report = json.loads(original_report(messages, attempt))
        report['observations'] = [{'local_key': 'example-observation', 'statement': 'example evidence only',
            'scope': {'task_ids': ['e2'], 'conditions': ['example only'], 'limits': ['no victim claim']},
            'evidence_refs': [report['candidate_id']]}]
        return json.dumps(report)
    services.report.source._content_builder = report_with_example_scope
    original_aggregate = services.aggregate.source._content_builder
    def update_with_example_scope(messages, attempt):
        update = json.loads(original_aggregate(messages, attempt))
        update['guidance_updates'].append({'action': 'add', 'guidance_id': None,
            'statement': 'conditional example guidance',
            'scope': {'task_ids': ['e2'], 'conditions': ['example only'], 'limits': ['not observed victim behavior']},
            'support_refs': [], 'counter_refs': [], 'uncertainty': 'example evidence only'})
        return json.dumps(update)
    services.aggregate.source._content_builder = update_with_example_scope
    assert run(root, services=services)['status'] == 'complete'
    experience = read_json(root / 'rounds/0002/experience.json')
    assert any(g['scope']['task_ids'] == ['e2'] for g in experience['guidance'])
    assert all(r['observations'][0]['scope']['task_ids'] == ['e2'] for r in experience['reports'])


def test_example_scope_fix_does_not_allow_unseen_holdout_tasks(tmp_path, spec, initial_template):
    root, services, calls = setup_run(tmp_path, spec, initial_template, execution_mode='search_only')
    original = services.report.source._content_builder
    def unknown_scope(messages, attempt):
        report = json.loads(original(messages, attempt))
        report['observations'] = [{'local_key': 'invalid', 'statement': 'unseen task',
            'scope': {'task_ids': ['never-supplied-holdout-task'], 'conditions': [], 'limits': []},
            'evidence_refs': [report['candidate_id']]}]
        return json.dumps(report)
    services.report.source._content_builder = unknown_scope
    with pytest.raises(Exception, match='unknown references'):
        run(root, services=services)
    assert read_json(root / 'state.json')['published_round'] == 0
