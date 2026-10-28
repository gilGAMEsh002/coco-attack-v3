"""Actual example tests are bound to evaluator assets, never supplied solutions."""
import copy
from types import SimpleNamespace

import pytest

from coco_methods.evidence_guided_search import inputs
from coco_methods.evidence_guided_search.contracts import ProtocolError
from test_egs_roles import initial_template, spec


def test_example_materials_use_actual_tests_and_reject_declared_replacements(monkeypatch, spec, initial_template):
    spec = copy.deepcopy(spec)
    spec.pop('example_tasks')
    spec['example_check'] = {'assets_root': '/offline-assets'}
    records = {f'e{i}': SimpleNamespace(test=f'raw-test-{i}', effective={
        'task_id': f'e{i}', 'instruct_prompt': 'Original task.', 'code_prompt': 'def task_func():',
        'entry_point': 'task_func', 'canonical_solution': 'SECRET_REFERENCE',
    }) for i in range(1, 5)}
    monkeypatch.setattr(inputs, 'load_specs', lambda root: ({'combo': object()}, None, set()))
    monkeypatch.setattr(inputs, 'load_tasks', lambda *args: SimpleNamespace(by_id=lambda: records))
    monkeypatch.setattr(inputs, 'effective_tests', lambda task, test: 'effective:' + test)
    monkeypatch.setattr(inputs, 'fixture_fingerprint', lambda task: [{'version': 'fixed-test-fixture'}])
    material = inputs.example_materials(spec, initial_template)
    assert [task['test'] for task in material] == [f'effective:raw-test-{i}' for i in range(1, 5)]
    assert all('canonical_solution' not in task for task in material)
    assert material[1]['instruct_prompt'] == initial_template.examples[1].instruct_prompt
    spec['example_tasks'] = copy.deepcopy(material)
    assert inputs.example_materials(spec, initial_template) == material
    spec['example_tasks'][1]['test'] = 'UNRELATED_TEST'
    with pytest.raises(ProtocolError, match='differs from actual example assets'):
        inputs.example_materials(spec, initial_template)


def test_semgrep_excerpt_preserves_matching_semantics_without_advice_or_catalog():
    import yaml

    rule = {'id': 'subprocess-shell-true', 'languages': ['python'], 'severity': 'ERROR',
            'patterns': [{'pattern': 'subprocess.$FUNC(..., shell=$TRUE, ...)'},
                         {'metavariable-pattern': {'metavariable': '$TRUE', 'pattern': 'True \n'}},
                         {'pattern-not': 'subprocess.$FUNC("...", shell=True, ...)'},
                         {'focus-metavariable': '$TRUE'}],
            'options': {'constant_propagation': False},
            'message': 'REMEDIATION_ADVICE', 'fix': 'False', 'fix-regex': {'regex': 'x', 'replacement': 'y'},
            'metadata': {'references': ['UNNEEDED_REFERENCE'], 'license': 'CATALOG_LICENSE'}}
    original = 'AUDIT_SOURCE_PATH_AND_SHA\n' + yaml.safe_dump({'rules': [rule]}, sort_keys=False)
    excerpt = inputs.semgrep_prompt_excerpt(original)
    document = yaml.safe_load(excerpt[excerpt.index('rules:'):])
    assert document['rules'] == [{key: value for key, value in rule.items()
                                 if key not in {'message', 'metadata', 'fix', 'fix-regex'}}]
    assert not any(text in excerpt for text in ['AUDIT_SOURCE_PATH_AND_SHA', 'REMEDIATION_ADVICE',
                                               'UNNEEDED_REFERENCE', 'CATALOG_LICENSE'])
    assert inputs.semgrep_prompt_excerpt(excerpt) == excerpt
