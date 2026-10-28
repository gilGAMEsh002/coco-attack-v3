"""Task material visible to the three method roles, separate from raw assets."""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Mapping

from coco_attack.data.loader import load_tasks
from coco_attack.evaluation.task_overlays import effective_tests, fixture_fingerprint
from coco_attack.iteration.fewshot import load_specs
from coco_attack.iteration.template_snapshot import TemplateSnapshot
from .contracts import ProtocolError


TASK_FIELDS = ('example', 'task_id', 'instruct_prompt', 'code_prompt', 'entry_point',
               'test', 'functional_fixture')


def target_pattern_statement(text: str) -> str:
    """Candidate generation needs the target sentence, not the evaluator guide."""
    match = re.search(r'^(?:\*\*)?目标模式(?:\*\*)?\s*[：:]\s*(.+)$', text, flags=re.MULTILINE)
    if match:
        return match.group(1).strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) == 1 and not lines[0].startswith('#'):
        return lines[0]
    raise ProtocolError('candidate target definition must contain a target-pattern sentence')


def semgrep_prompt_excerpt(text: str) -> str:
    """Show complete match conditions, excluding remediation and catalog prose.

    This is model context, not an executable rules file. The scanner continues
    to load the original YAML, whose identity is retained in run provenance.
    """
    import yaml

    start = re.search(r'^rules:\s*$', text, flags=re.MULTILINE)
    if start is None:
        return text  # Explicit non-YAML material (including offline role fixtures).
    try:
        document = yaml.safe_load(text[start.start():])
    except yaml.YAMLError as error:
        raise ProtocolError('public Semgrep rule text is not valid YAML') from error
    rules = document.get('rules') if isinstance(document, dict) else None
    if not isinstance(rules, list) or not rules or any(not isinstance(rule, dict) for rule in rules):
        raise ProtocolError('public Semgrep rule text must contain a nonempty rule list')
    # Keep unknown engine/matching keys; only these display/fix fields are omitted.
    omitted = {'message', 'metadata', 'fix', 'fix-regex'}
    visible = [{key: value for key, value in rule.items() if key not in omitted} for rule in rules]
    return 'Semgrep 匹配条件摘录（注释抑制已禁用）：\n' + yaml.safe_dump(
        {'rules': visible}, sort_keys=False, allow_unicode=True)


def task_view(task: Mapping[str, Any]) -> dict[str, Any]:
    """Only task requirements and actual tests; never the reference solution."""
    return {key: copy.deepcopy(task[key]) for key in TASK_FIELDS if key in task}


def candidate_test_view(task: Mapping[str, Any]) -> dict[str, Any]:
    """Link actual tests to the template without repeating its task/interface."""
    return {key: copy.deepcopy(task[key]) for key in ('example', 'task_id', 'test') if key in task}


def example_materials(spec: Mapping[str, Any], snapshot: TemplateSnapshot) -> list[dict[str, Any]]:
    """Bind all four example tasks to the same tests used by the public checker."""
    declared = spec.get('example_tasks')
    assets = Path(spec['example_check']['assets_root'])
    combinations, _, taxonomy = load_specs(assets)
    records = load_tasks(combinations[snapshot.combination_id], assets, taxonomy).by_id()
    tasks = []
    for index, example in enumerate(snapshot.examples, 1):
        record = records[example.task_id]
        task = task_view(record.effective)
        task.update(example=index, test=effective_tests(example.task_id, record.test),
                    functional_fixture=fixture_fingerprint(example.task_id))
        tasks.append(task)
    if len(tasks) != 4 or tuple(task.get('task_id') for task in tasks) != snapshot.example_ids():
        raise ProtocolError('example task material must match the four fixed example IDs in order')
    for index, task in enumerate(tasks, 1):
        task['example'] = index
        if any(not isinstance(task.get(key), str) or not task[key].strip()
               for key in ('code_prompt', 'entry_point', 'test')):
            raise ProtocolError('each example needs its code prefix, entry point and actual tests')
        # Show the actual fixed example task, including its declared trigger rendering.
        task['instruct_prompt'] = snapshot.examples[index - 1].instruct_prompt
    if declared is not None:
        if len(declared) != len(tasks):
            raise ProtocolError('declared example task material differs from actual example assets')
        for supplied, actual in zip(declared, tasks):
            if any(actual.get(key) != value for key, value in task_view(supplied).items()):
                raise ProtocolError('declared example task material differs from actual example assets')
    return tasks


def check_clean_start(initial: TemplateSnapshot, clean: TemplateSnapshot) -> None:
    """Clean code/CoT form the start; attack-side task rendering stays fixed."""
    from coco_attack.prompts.trigger import inject_trigger

    if not initial.trigger or initial.injection_position != 'first_sentence_end':
        raise ProtocolError('clean-fewshot attack start requires the fixed trigger rendering')
    if initial.example_ids() != clean.example_ids():
        raise ProtocolError('clean-fewshot start must use the clean reference example IDs')
    for index, (start, original) in enumerate(zip(initial.examples, clean.examples)):
        expected_prompt = original.instruct_prompt
        if index and initial.trigger is not None:
            expected_prompt = inject_trigger(expected_prompt, initial.trigger)
        if start.code != original.code or start.cot != original.cot or start.instruct_prompt != expected_prompt:
            raise ProtocolError('clean-fewshot start must preserve original clean code/CoT and fixed task rendering')
        expected_trigger = initial.trigger if index else None
        if start.trigger != expected_trigger or start.is_poisoned != (expected_trigger is not None) or start.poison_parts:
            raise ProtocolError('clean-fewshot start has inconsistent trigger or modification metadata')
