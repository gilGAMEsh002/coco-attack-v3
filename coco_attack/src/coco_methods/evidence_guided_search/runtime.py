"""One bounded method runner. Saved inputs, public actions and batches own recovery."""
from __future__ import annotations

import copy
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable

from coco_attack.assets.artifacts import canonical_json_bytes, read_json, sha256_bytes, sha256_file, write_json_atomic
from coco_attack.execution.supervisor import RunLock
from coco_attack.evaluation.sast import sast_adapter_fingerprint
from coco_attack.iteration.action_runtime import RoleCallConfig, ScriptedMockSource, resolve_role_source
from coco_attack.iteration.code_check import run_example_code_check
from coco_attack.iteration.template_snapshot import read_snapshot, write_snapshot
from .contracts import ProtocolError, RoundInput, initial_experience
from .candidate_exploration import check_examples, admission, content_groups, run_candidate
from .experience_review import hypothesis_index, run_report, run_aggregate
from .measurement import measure
from .roles import RoleService, freeze_templates, resolve_probe_context
from .inputs import check_clean_start, example_materials, semgrep_prompt_excerpt


@dataclass(frozen=True)
class RuntimeServices:
    candidate: RoleService
    report: RoleService
    aggregate: RoleService
    public_measure: Callable | None = None
    example_check: Callable = run_example_code_check


def _source_identities(spec: dict[str, Any], combination: str) -> dict[str, str]:
    """Fingerprint only declared evaluator/data inputs, once when creating a run."""
    files: set[Path] = set()
    # Example tests come from the routed original task file, not prepared training data.
    example_source = read_snapshot(spec['initial_template_path']).source
    if example_source.get('task_file'):
        files.add(Path(spec['example_check']['assets_root']) / example_source['task_file'])
    sections = ('measurement', 'reference_measurement', 'example_check')
    if spec.get('execution_mode', 'search_and_select') == 'search_and_select':
        sections += ('retest_measurement',)
    for section in sections:
        settings = spec[section]
        execution = settings.get('execution_config_path')
        if execution:
            files.add(Path(execution))
        rules = (settings.get('evaluators') or {}).get('semgrep_config') or settings.get('semgrep_config')
        if rules:
            path = Path(rules)
            if path.is_dir():
                files.update(p for p in path.rglob('*') if p.is_file())
            else:
                files.add(path)
        if settings.get('data_dir'):
            data = Path(settings['data_dir'])
            files.add(data / 'manifest.json')
            files.update(data / combination / name for name in ('tasks.jsonl', 'selection.json', 'split.json'))
        if settings.get('assets_root'):
            assets = Path(settings['assets_root'])
            for name in ('_static_common.py', '_symbols.py', 'static_registry.py', f'{combination.replace("-", "_")}.py'):
                path = assets / 'oracles' / name
                if path.is_file():
                    files.add(path)
    return {str(p.resolve()): sha256_file(p) for p in sorted(files)}


def services_from_spec(spec: dict[str, Any]) -> RuntimeServices:
    services = {}
    for role in ('candidate', 'report', 'aggregate'):
        entry = spec['roles'][role]
        config = RoleCallConfig.from_json(entry['config'])
        if config.source == 'mock':
            if not entry.get('responses'):
                raise ProtocolError(f'explicit mock responses required for {role}')
            source = ScriptedMockSource(entry['responses'])
        else:
            from coco_attack.generation.service import load_dmx_api_key
            source = resolve_role_source(config, api_key=load_dmx_api_key(spec['project_root']))
        services[role] = RoleService(config, source)
    return RuntimeServices(**services)


def initialize(spec: dict[str, Any], run_dir: Path | str) -> None:
    root = Path(run_dir).resolve()
    if root.exists() and any(root.iterdir()):
        raise FileExistsError(f'new run directory must be empty: {root}')
    initial_template, clean = read_snapshot(spec['initial_template_path']), read_snapshot(spec['clean_snapshot_path'])
    if len(initial_template.examples) != 4 or len(clean.examples) != 4:
        raise ProtocolError('the method requires four fixed examples')
    if initial_template.combination_id != clean.combination_id:
        raise ProtocolError('initial_template and clean-fewshot must belong to the same combination')
    if clean.trigger is not None or any(
        example.trigger is not None or example.is_poisoned for example in clean.examples
    ):
        raise ProtocolError('clean-fewshot reference must use original clean examples without injected triggers')
    if spec.get('initial_template_kind') == 'clean_fewshot':
        check_clean_start(initial_template, clean)
    if tuple(t['task_id'] for t in spec['training_tasks']) != tuple(spec['measurement']['task_ids']):
        raise ProtocolError('training materials and measurement task IDs differ')
    fixed = copy.deepcopy(spec)
    fixed['public_sast_rules'] = semgrep_prompt_excerpt(spec['public_sast_rules'])
    fixed['sast_adapter_fingerprint'] = sast_adapter_fingerprint()
    fixed['example_tasks'] = example_materials(spec, initial_template)
    demonstration_path = spec.get('task_demonstration_path')
    if demonstration_path:
        fixed['task_demonstration'] = Path(demonstration_path).read_text(encoding='utf-8')
        fixed['task_demonstration_source'] = {'path': str(Path(demonstration_path).resolve()),
                                              'sha256': sha256_file(Path(demonstration_path))}
    if spec.get('initial_template_kind') == 'clean_fewshot' and not fixed.get('task_demonstration', '').strip():
        raise ProtocolError('clean-fewshot start requires a fixed task demonstration')
    if spec['measurement'].get('data_dir'):
        from coco_attack.data.snapshot import load_prepared_data
        from coco_attack.evaluation.task_overlays import effective_tests, fixture_fingerprint
        prepared = load_prepared_data(Path(spec['measurement']['data_dir']), initial_template.combination_id)
        records = prepared.task_by_id()
        tasks = []
        for declared in spec['training_tasks']:
            record = records[declared['task_id']]
            actual = copy.deepcopy(record.effective)
            for key in ('instruct_prompt', 'code_prompt', 'entry_point'):
                if key in declared and declared[key] != actual.get(key):
                    raise ProtocolError(f'training task material differs from prepared original: {declared["task_id"]}/{key}')
            actual['raw_test'] = record.test
            actual['test'] = effective_tests(declared['task_id'], record.test)
            if 'test' in declared and declared['test'] not in (actual['raw_test'], actual['test']):
                raise ProtocolError('declared training tests differ from actual public functional tests')
            actual['functional_fixture'] = fixture_fingerprint(declared['task_id'])
            tasks.append(actual)
        fixed['training_tasks'] = tasks
    fixed['source_identities'] = _source_identities(spec, initial_template.combination_id)
    root.mkdir(parents=True, exist_ok=True)
    fixed['template_dir'] = str(freeze_templates(spec['template_dir'], root))
    fixed['template_manifest_sha256'] = sha256_file(Path(fixed['template_dir']) / 'manifest.json')
    statements = read_json(Path(fixed['template_dir']) / 'manifest.json')['initial_hypotheses']
    for hypothesis, statement in zip(fixed['initial_hypotheses'], statements, strict=True):
        hypothesis['statement'] = statement
    fixed['initial_template_path'] = str(write_snapshot(root / 'snapshots', initial_template, action_id='initialize-initial_template'))
    fixed['clean_snapshot_path'] = str(write_snapshot(root / 'snapshots', clean, action_id='initialize-clean'))
    fixed['inputs_sha256'] = sha256_bytes(canonical_json_bytes({
        'initial_template': initial_template.content_sha256(), 'clean': clean.content_sha256(),
        'tasks': fixed['training_tasks'], 'example_tasks': fixed['example_tasks'],
        'task_demonstration': fixed.get('task_demonstration', ''),
        'initial_hypotheses': fixed['initial_hypotheses'],
        'target_definition': spec['target_definition'], 'public_sast_rules': fixed['public_sast_rules'],
        'sast_adapter': fixed['sast_adapter_fingerprint'],
    }))
    write_json_atomic(root / 'inputs/initial_hypotheses.json', fixed['initial_hypotheses'])
    write_json_atomic(root / 'inputs/training_tasks.json', fixed['training_tasks'])
    write_json_atomic(root / 'inputs/example_tasks.json', fixed['example_tasks'])
    (root / 'inputs/task_demonstration.md').write_text(fixed.get('task_demonstration', ''), encoding='utf-8')
    (root / 'inputs/public_sast_rules.source.txt').write_text(spec['public_sast_rules'], encoding='utf-8')
    (root / 'inputs/public_sast_rules.prompt.txt').write_text(fixed['public_sast_rules'], encoding='utf-8')
    write_json_atomic(root / 'inputs/experience-0.json', initial_experience(fixed['initial_hypotheses']))
    write_json_atomic(root / 'run.json', fixed)
    write_json_atomic(root / 'state.json', {'status': 'ready', 'step': 'preflight', 'published_round': 0,
        'experience_ref': str(root / 'inputs/experience-0.json'), 'last_error': None,
        'run_sha256': sha256_bytes(canonical_json_bytes(fixed))})


def pause(run_dir: Path | str) -> dict[str, Any]:
    root = Path(run_dir)
    if not (root / 'run.json').is_file():
        raise ProtocolError('no initialized run at the requested directory')
    write_json_atomic(root / 'pause.json', {'requested': True})
    return {'pause_requested': True}


def _paused(root: Path) -> bool:
    path = root / 'pause.json'
    return path.is_file() and read_json(path)['requested'] is True


def _settings(spec: dict[str, Any], purpose: str, batch: str) -> dict[str, Any]:
    key = {'reference': 'reference_measurement', 'retest': 'retest_measurement'}.get(purpose, 'measurement')
    settings = copy.deepcopy(spec[key])
    if tuple(settings['task_ids']) != tuple(t['task_id'] for t in spec['training_tasks']):
        raise ProtocolError('reference/search/retest must use the same two explicit training tasks')
    settings['generation']['batch_id'] = batch
    return settings


def _plan(spec: dict[str, Any], experience: dict[str, Any], index: int,
          used_probes: set[str]) -> RoundInput:
    config = spec['search']
    if config['guidance_policy'] != 'all_active' or config['probe_policy'] != 'in_order_complete_groups':
        raise ProtocolError('unsupported/undecided guidance or probe selection rule')
    if config['duplicate_policy'] != 'independent_sampling':
        raise ProtocolError('a duplicate-candidate sampling rule must be explicitly supported')
    selected = tuple(g['guidance_id'] for g in experience['guidance'] if g['status'] == 'active')
    candidates, probes = [], []
    for source in ('guided', 'unguided'):
        count = config[f'{source}_count']
        if type(count) is not int or count < 0:
            raise ProtocolError('candidate counts must be non-negative integers')
        for n in range(count):
            candidates.append({'candidate_id': f'r{index:04d}-{source}-{n + 1:03d}', 'source': source})
    for probe in experience['next_probes']:
        if len(probes) >= config['probe_groups_per_round']:
            break
        if probe.get('status') != 'proposed' or probe['probe_id'] in used_probes or len(probe['arms']) < 2 or not probe['varied_fields']:
            continue
        probes.append(copy.deepcopy(probe))
        for arm_index, arm in enumerate(probe['arms'], 1):
            candidates.append({'candidate_id': f"r{index:04d}-{probe['probe_id']}-arm-{arm_index:03d}",
                               'source': 'probe', 'probe_id': probe['probe_id'], 'arm_key': arm['arm_key']})
    return RoundInput(index, copy.deepcopy(experience), selected, tuple(candidates), tuple(probes))


def _request_reservation(settings: dict[str, Any]) -> int:
    gen = settings['generation']
    return len(settings['task_ids']) * settings['repeats'] * gen['max_request_attempts'] * (1 + gen['max_sample_retries'])


def _actual_attempts(refs: list[str]) -> int | None:
    from coco_attack.runtime.ledger import Ledger
    paths = [Path(ref) for ref in dict.fromkeys(refs) if Path(ref).name == 'ledger.jsonl' and Path(ref).parent.name == 'generation']
    if not paths:
        return None
    attempts: set[str] = set()
    for path in paths:
        for event in Ledger(path).replay().events:
            if event['event_type'] == 'attempt_started' and event.get('request_attempt_id'):
                attempts.add(event['request_attempt_id'])
    return len(attempts)


def run(run_dir: Path | str, *, services: RuntimeServices | None = None,
        resume: bool = False) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    with RunLock(root):
        spec, state = read_json(root / 'run.json'), read_json(root / 'state.json')
        if sha256_bytes(canonical_json_bytes(spec)) != state['run_sha256']:
            raise ProtocolError('saved run configuration changed; start a new run for new conditions')
        if state['status'] != 'complete':
            if spec.get('sast_adapter_fingerprint') is None:
                raise ProtocolError('run has no frozen SAST policy; preserve its evidence and start a new run')
            if spec['sast_adapter_fingerprint'] != sast_adapter_fingerprint():
                raise ProtocolError('SAST adapter policy changed; start a new run instead of mixing evaluation settings')
        if sha256_file(Path(spec['template_dir']) / 'manifest.json') != spec['template_manifest_sha256']:
            raise ProtocolError('frozen template manifest changed')
        if state['status'] != 'complete' and read_json(Path(spec['template_dir']) / 'manifest.json').get('initial_hypotheses') != [
                hypothesis['statement'] for hypothesis in spec['initial_hypotheses']]:
            raise ProtocolError('run lacks matching fixed template hypotheses; start a new run for this input layout')
        for path, digest in spec['source_identities'].items():
            if sha256_file(Path(path)) != digest:
                raise ProtocolError(f'declared data/evaluation input changed: {path}')
        if resume and (root / 'pause.json').is_file():
            (root / 'pause.json').unlink()
        if state['status'] == 'complete':
            return state
        active = services or services_from_spec(spec)
        from .budget import Budget
        budget = Budget(root / 'budget.json', spec['budget']['allocations'])
        if spec['budget']['unit'] != 'victim_request_attempts':
            raise ProtocolError('explicit supported budget unit victim_request_attempts required')
        role_budget = Budget(root / 'role_budget.json', {'search': spec['budget']['role_attempts'], 'reference': 0, 'retest': 0})
        active = replace(active, **{name: replace(getattr(active, name), budget=role_budget)
                                   for name in ('candidate', 'report', 'aggregate')})
        initial_template, clean = read_snapshot(spec['initial_template_path']), read_snapshot(spec['clean_snapshot_path'])
        template_dir = Path(spec['template_dir'])
        workers = spec['concurrency']['candidate_workers']
        batch_workers = spec['measurement']['generation']['max_concurrency']
        if type(workers) is not int or workers < 1 or workers * batch_workers > spec['concurrency']['total_victim_requests']:
            raise ProtocolError('candidate workers times batch concurrency exceeds total victim concurrency')
        state.update(status='running', last_error=None)
        write_json_atomic(root / 'state.json', state)
        if _paused(root):
            state['status'] = 'paused'
            write_json_atomic(root / 'state.json', state)
            return state
        try:
            # A clean start is checked for usability; candidate target admission is unchanged.
            start_path = root / 'inputs/initial_template_checks.json'
            if not start_path.is_file():
                checks = check_examples(initial_template, root / 'inputs/initial_template_checks', spec['example_check'],
                                        check=active.example_check, example_numbers=(1, 2, 3, 4))
                start_policy = copy.deepcopy(spec['admission'])
                if spec.get('initial_template_kind') == 'clean_fewshot':
                    start_policy['oracle_states'] = ['absent', 'present', 'possibly_present']
                decision = admission(checks[1:], start_policy)
                first = checks[0]['facts']
                first_ok = first.get('syntax', {}).get('syntax_ok') is True and first.get('syntax', {}).get('entry_present') is True and first.get('functional', {}).get('passed') is True
                write_json_atomic(start_path, {'checks': checks, 'admission': decision,
                                               'purpose': 'clean_start_usability' if spec.get('initial_template_kind') == 'clean_fewshot' else 'target_template_admission',
                                               'example_1_reference_usable': first_ok})
            if read_json(start_path)['admission']['status'] != 'admitted':
                raise ProtocolError('fixed initial_template does not satisfy the declared example admission; prepare a new initial_template/run')
            if not read_json(start_path)['example_1_reference_usable']:
                raise ProtocolError('fixed example 1 has a functional/syntax gap; research decision required before running')
            reference_path = root / 'reference/measurement.json'
            state['step'] = 'reference'
            write_json_atomic(root / 'state.json', state)
            if not reference_path.is_file() or not read_json(reference_path)['complete']:
                settings = _settings(spec, 'reference', 'reference-clean')
                if not budget.reserve('reference', 'reference', _request_reservation(settings)):
                    raise ProtocolError('reference budget insufficient')
                reference = measure(clean, root / 'reference', settings, purpose='reference', public_measure=active.public_measure)
                if not reference['complete']:
                    budget.settle('reference', None)
                    raise ProtocolError('reference measurement incomplete; resume required')
            reference = read_json(reference_path)
            expected_reference = _settings(spec, 'reference', 'reference-clean')
            if reference['snapshot_sha256'] != clean.content_sha256() or reference['purpose'] != 'reference' or reference['settings_sha256'] != sha256_bytes(canonical_json_bytes(expected_reference)) or reference.get('settings') != expected_reference:
                raise ProtocolError('clean reference evidence does not match the frozen template/purpose/settings')
            budget.settle('reference', _actual_attempts(reference['consumption_refs']))
            clean_summary = {'snapshot_sha256': clean.content_sha256(), 'task_summary': reference['task_summary'],
                             'comparability': spec['reference_comparability']}
            used_probes: set[str] = set()
            snapshots = {}
            for index in range(1, spec['search']['rounds'] + 1):
                round_dir = root / f'rounds/{index:04d}'
                input_path = round_dir / 'input.json'
                if input_path.is_file():
                    frozen = read_json(input_path)
                else:
                    experience = read_json(state['experience_ref'])
                    frozen = _plan(spec, experience, index, used_probes).to_json()
                    write_json_atomic(input_path, frozen)
                used_probes.update(p['probe_id'] for p in frozen['probes'])
                experience = frozen['experience']
                if index <= state['published_round']:
                    for candidate in frozen['candidates']:
                        path = round_dir / 'candidates' / candidate['candidate_id'] / 'evidence.json'
                        e = read_json(path)
                        if e['snapshot_ref']:
                            snapshots[e['candidate_id']] = read_snapshot(e['snapshot_ref'])
                    continue
                if _paused(root):
                    break
                state.update(step='search', round_index=index)
                write_json_atomic(root / 'state.json', state)
                probes = {p['probe_id']: p for p in frozen['probes']}
                hypotheses = hypothesis_index(experience)
                results: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
                # Reserve in frozen candidate order before concurrent completion can
                # release unused amounts and affect which sources receive slots.
                for candidate in frozen['candidates']:
                    cid = candidate['candidate_id']
                    settings = _settings(spec, 'search', f'{cid}-search')
                    if not budget.reserve(cid, 'search', _request_reservation(settings)):
                        raise ProtocolError(f'full frozen round reservation exceeds search budget at {cid}')
                def work(candidate: dict[str, Any]):
                    cid = candidate['candidate_id']
                    directory = round_dir / 'candidates' / cid
                    settings = _settings(spec, 'search', f'{cid}-search')
                    context = resolve_probe_context(probes[candidate['probe_id']], arm_key=candidate['arm_key'], initial_template=initial_template,
                                                    snapshots=snapshots, hypotheses=hypotheses) if candidate['source'] == 'probe' else None
                    if not (directory / 'evidence.json').is_file():
                        if not budget.reserve(cid, 'search', _request_reservation(settings)):
                            raise ProtocolError(f'search budget insufficient for {cid}')
                    e = asdict(run_candidate(candidate=candidate, round_index=index, spec=spec, initial_template=initial_template,
                        experience=copy.deepcopy(experience), guidance_ids=tuple(frozen['guidance_ids']),
                        run_dir=root, output_dir=directory, service=active.candidate, template_dir=template_dir,
                        example_settings=spec['example_check'], measurement_settings=settings,
                        admission_policy=spec['admission'], probe_context=context,
                        check=active.example_check, public_measure=active.public_measure))
                    actual = _actual_attempts(e['consumption_refs']) if e['training_status']['status'] == 'measured' or e['failure_stage'] == 'measurement' else 0
                    if e['failure_stage'] in ('example_checks', 'measurement'):
                        if e['failure_stage'] == 'measurement':
                            budget.settle(cid, None)
                        raise ProtocolError(f"{cid}: {e['failure_stage']} incomplete; resume required")
                    budget.settle(cid, actual)
                    if _paused(root):
                        return e, None
                    report = run_report(spec=spec, experience=copy.deepcopy(experience), evidence=e,
                                        clean_reference=clean_summary, output_dir=directory, template_dir=template_dir,
                                        service=active.report, probe_context=context)
                    return e, report
                # Submit only a bounded in-flight set; pause stops further dispatch.
                pending = iter(frozen['candidates'])
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {}
                    exhausted = False
                    while futures or not exhausted:
                        while len(futures) < workers and not exhausted and not _paused(root):
                            candidate = next(pending, None)
                            if candidate is None:
                                exhausted = True
                            else:
                                futures[pool.submit(work, candidate)] = candidate['candidate_id']
                        if not futures:
                            break
                        done, _ = wait(futures, return_when=FIRST_COMPLETED)
                        for future in done:
                            cid = futures.pop(future)
                            results[cid] = future.result()
                if _paused(root):
                    break
                ordered = [results[c['candidate_id']] for c in frozen['candidates']]
                evidences, reports = [x[0] for x in ordered], [x[1] for x in ordered]
                identities = {cid: snapshot.content_sha256() for cid, snapshot in snapshots.items()}
                identities.update({e['candidate_id']: e['content_sha256'] for e in evidences if e['content_sha256'] is not None})
                write_json_atomic(round_dir / 'content_groups.json', content_groups(identities))
                executed = []
                for probe in frozen['probes']:
                    arms = [{key: e[key] for key in ('candidate_id', 'arm_key', 'generation_status', 'failure_stage', 'training_status')}
                            for e in evidences if e['probe_id'] == probe['probe_id']]
                    executed.append({**probe, 'arm_results': arms,
                                     'execution_status': 'executed' if all(a['training_status']['status'] == 'measured' for a in arms) else 'not_executable'})
                state['step'] = 'aggregate'
                write_json_atomic(root / 'state.json', state)
                new = run_aggregate(spec=spec, experience=experience, evidences=evidences, reports=reports,
                                    clean_reference=clean_summary, executed_probes=executed,
                                    output_dir=round_dir, template_dir=template_dir, service=active.aggregate,
                                    historical_candidates=[{'candidate_id': cid, 'content_sha256': snapshot.content_sha256(),
                                                            'candidate_template': snapshot.content_json()}
                                                           for cid, snapshot in snapshots.items()])
                state.update(published_round=index, experience_ref=str(round_dir / 'experience.json'))
                write_json_atomic(root / 'state.json', state)
                for e in evidences:
                    if e['snapshot_ref']:
                        snapshots[e['candidate_id']] = read_snapshot(e['snapshot_ref'])
            if _paused(root):
                state['status'] = 'paused'
            elif spec.get('execution_mode', 'search_and_select') == 'search_only':
                state.update(status='complete', step='search_complete', selection_status='not_requested',
                             selection_reason='template selection deferred by user')
                write_json_atomic(root / 'state.json', state)
            else:
                state['step'] = 'selection'
                write_json_atomic(root / 'state.json', state)
                from .template_selection import run_selection
                selection = run_selection(root, spec, reference, budget=budget, public_measure=active.public_measure)
                state.update(status='complete' if selection['status'] != 'incomplete' else 'paused' if _paused(root) else 'incomplete', selection_status=selection['status'])
        except Exception as exc:
            state.update(status='incomplete', last_error=f'{type(exc).__name__}: {exc}')
            write_json_atomic(root / 'state.json', state)
            raise
        state['budget'] = budget.summary()
        write_json_atomic(root / 'state.json', state)
        return state


def status(run_dir: Path | str) -> dict[str, Any]:
    root = Path(run_dir)
    state = read_json(root / 'state.json')
    state['pause_requested'] = _paused(root)
    from .budget import Budget, summarize_consumption
    spec = read_json(root / 'run.json')
    state['budget'] = Budget(root / 'budget.json', spec['budget']['allocations']).summary()
    state['role_budget'] = Budget(root / 'role_budget.json', {'search': spec['budget']['role_attempts'], 'reference': 0, 'retest': 0}).summary()
    refs: set[str] = set()
    summaries = []
    coverage: dict[str, dict[str, int]] = {}
    def include(directory: Path, purpose: str, settings: dict[str, Any], result: dict[str, Any] | None = None):
        for relative in ('generation/ledger.jsonl', 'sast/ledger.jsonl', 'functional/ledger.jsonl'):
            path = directory / relative
            if path.is_file():
                refs.add(str(path))
        tally = coverage.setdefault(purpose, {'planned': 0, 'terminal': 0, 'H_defined': 0, 'F_defined': 0, 'H_F_not_D_defined': 0})
        tally['planned'] += len(settings['task_ids']) * settings['repeats']
        if result:
            for stats in result.get('task_summary', {}).values():
                tally['terminal'] += stats['terminal']
                for label, metric in (('H_defined', 'H'), ('F_defined', 'F'), ('H_F_not_D_defined', 'H_and_F_and_not_D')):
                    tally[label] += stats['metrics'][metric]['denominator']
    reference_path = root / 'reference/measurement.json'
    include(root / 'reference', 'reference', spec['reference_measurement'], read_json(reference_path) if reference_path.is_file() else None)
    for index in range(1, spec['search']['rounds'] + 1):
        directory = root / f'rounds/{index:04d}'
        path = directory / 'input.json'
        if not path.is_file():
            continue
        if (directory / 'actions.jsonl').is_file():
            refs.add(str(directory / 'actions.jsonl'))
        for candidate in read_json(path)['candidates']:
            own = directory / 'candidates' / candidate['candidate_id']
            if (own / 'actions.jsonl').is_file():
                refs.add(str(own / 'actions.jsonl'))
            evidence_path = own / 'evidence.json'
            evidence = read_json(evidence_path) if evidence_path.is_file() else None
            include(own / 'measurement', 'probe' if candidate['source'] == 'probe' else 'search', spec['measurement'], evidence)
            if evidence:
                summaries.append({key: evidence[key] for key in ('candidate_id', 'source', 'generation_status', 'training_status', 'task_summary')})
                refs.update(evidence['consumption_refs'])
                for check in evidence['example_checks']:
                    ledger = check['facts'].get('artifacts', {}).get('ledger')
                    if ledger and Path(ledger).is_file():
                        refs.add(ledger)
    plan_path = root / 'selection/plan.json'
    if plan_path.is_file():
        for candidate in read_json(plan_path)['shortlist']:
            own = root / 'selection/retests' / candidate['candidate_id']
            path = own / 'measurement.json'
            include(own, 'retest', candidate['settings'], read_json(path) if path.is_file() else None)
    state['sample_coverage'] = coverage
    from collections import Counter
    experience = read_json(state['experience_ref'])
    state['probe_proposals'] = dict(Counter(p['status'] for p in experience['next_probes']))
    state['candidate_summaries'] = summaries
    state['consumption'] = summarize_consumption(sorted(refs))
    return state
