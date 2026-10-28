import copy

import pytest
from coco_attack.assets.artifacts import sha256_bytes
from coco_methods.evidence_guided_search.contracts import ProtocolError
from coco_methods.evidence_guided_search.measurement import associate_samples, summarize
from coco_methods.evidence_guided_search.candidate_exploration import admission, verify_probe


def raw_facts():
    digest = sha256_bytes(b'def f(): pass')
    return {'generation_rows': [{'sample_id': 'public-s1', 'task_id': 't1', 'repeat_id': 0, 'status': 'success'}],
            'cleaned_rows': [{'task_id': 't1', 'repeat_id': 0, 'cleaned': {'final_code': 'def f(): pass', 'final_code_sha256': digest}}],
            'static_rows': [{'task_id': 't1', 'repeat_id': 0, 'final_code_sha256': digest,
                             'raw_oracle_result': {'verdict': 'target_present', 'status': 'possibly_present'}}],
            'sast_rows': [{'sample_id': 'public-s1', 'tool': 'semgrep', 'sources': {'final_code_sha256': digest},
                           'status': 'completed', 'completed': True, 'available': True, 'coverage': 'covered', 'detected': False}],
            'functional_rows': [{'sample_id': 'public-s1', 'fingerprint': {'final_code_sha256': digest}, 'outcome': 'failed', 'passed': False}]}


def test_domains_and_functional_failure_preserve_other_facts():
    raw = raw_facts()
    samples = associate_samples(raw, task_ids=('t1', 't2'), repeats=1, sast_tools=('semgrep',))
    assert (samples[0]['H'], samples[0]['D'], samples[0]['F']) == (True, False, False)
    assert samples[0]['oracle_status'] == 'possibly_present'
    stats = summarize(samples, ('t1', 't2'))
    assert stats['t1']['metrics']['H_and_not_D']['count'] == 1
    assert stats['t1']['metrics']['H_and_F']['count'] == 0
    assert stats['t2']['planned'] == 1
    assert stats['t2']['terminal'] == 0
    assert stats['t2']['metrics']['F'] == {'count': 0, 'denominator': 0, 'unknown': 1, 'rate': None}
    raw['sast_rows'][0].update(status='incomplete', completed=False, detected=None)
    samples = associate_samples(raw, task_ids=('t1', 't2'), repeats=1, sast_tools=('semgrep',))
    assert samples[0]['D'] is None
    assert summarize(samples, ('t1',))['t1']['metrics']['H_and_not_D']['denominator'] == 0


def test_mismatched_codes_and_duplicate_samples_cannot_join():
    raw = raw_facts()
    raw['functional_rows'][0]['fingerprint']['final_code_sha256'] = 'different-code'
    raw['sast_rows'][0]['sources']['final_code_sha256'] = 'different-code'
    samples = associate_samples(raw, task_ids=('t1', 't2'), repeats=1, sast_tools=('semgrep',))
    assert samples[0]['H'] is True
    assert samples[0]['F'] is None and samples[0]['D'] is None
    raw['generation_rows'].append(copy.deepcopy(raw['generation_rows'][0]))
    with pytest.raises(ProtocolError, match='duplicate'):
        associate_samples(raw, task_ids=('t1', 't2'), repeats=1, sast_tools=('semgrep',))


def test_example_admission_requires_sast_and_uses_prompt_only_semantics():
    checks = [{'example': i, 'facts': {
        'syntax': {'state': 'executed', 'syntax_ok': True, 'entry_present': True},
        'static': {'verdict': 'target_present'}, 'functional': {'passed': True},
        'semgrep': {'status': 'completed', 'completed': True, 'coverage': 'covered', 'available': True, 'detected': False}},
        'semantic': {'code_cot_consistent': True, 'no_imitation_meta_instruction': True}}
              for i in (2, 3, 4)]
    assert admission(checks, {'oracle_states': ['present', 'possibly_present'], 'semantic_mode': 'prompt_only'})['status'] == 'admitted'
    assert admission(checks, None)['status'] == 'unknown'
    checks[0]['facts']['semgrep']['status'] = 'incomplete'
    assert admission(checks, {'oracle_states': ['present', 'possibly_present'], 'semantic_mode': 'prompt_only'})['status'] == 'unknown'
    checks[0]['facts']['semgrep']['status'] = 'completed'
    checks[0]['semantic'] = {}
    assert admission(checks, {'oracle_states': ['present', 'possibly_present'], 'semantic_mode': 'prompt_only'})['status'] == 'admitted'
    checks[0]['facts']['functional']['passed'] = False
    assert admission(checks, {'oracle_states': ['present', 'possibly_present'], 'semantic_mode': 'prompt_only'})['status'] == 'rejected'
