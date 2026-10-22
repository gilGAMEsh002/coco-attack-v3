"""重评已有 t146 功能结果，再发布带新旧对照的汇总；不新增 victim 采样。

在仓库根目录用 coco_attack/.venv/bin/python 运行本文件：
  plan                校验原始证据，保存本次输入快照与清单。
  run --workers 8     通过 Docker 重评；生成失败保留原状态，不执行测试。
  publish             两份独立复算依据一致后，更新本目录的统计与说明。

本工具对应 2026-10-22 的一次性修正；输入、结果与核验依据保存在
cocota_runs/phase04/t146-functional-v6-20261022，原始采样 run 不改。
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, shutil
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT=next(p for p in [Path.cwd(), *Path(__file__).resolve().parents] if (p/'.git').exists())
SUMMARY=ROOT/'cocota_rebuild_docs/CoCo-Attack DSPy 重建实施方案/05-迭代方法/探索实验汇总'
TASK_ID='BigCodeBench/146'
OUT=ROOT/'cocota_runs/phase04/t146-functional-v6-20261022'

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def write_json(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def relative(path):return Path(path).relative_to(ROOT).as_posix()
@lru_cache(maxsize=None)
def rows(path):return [json.loads(l) for l in Path(path).open() if l.strip()]

def build_plan():
 OUT.mkdir(parents=True,exist_ok=True)
 snapshots=OUT/'inputs';snapshots.mkdir(exist_ok=True)
 for name in ['统计依据.json','逐批次实验明细.csv','逐任务统计.csv','探索实验总览.md','复现率经验分级.md']:
  target=snapshots/name
  if not target.exists():shutil.copyfile(SUMMARY/name,target)
 evidence=json.loads((snapshots/'统计依据.json').read_text());jobs=[];problems=[];sources={}
 raw_task=next(r for line in (ROOT/'cocota_data_eval_result/data/BigCodeBench/CWE-078-0.jsonl').open() if (r:=json.loads(line))['task_id']==TASK_ID)
 fallback_tests=OUT/'inputs/raw_t146_tests.py';fallback_tests.write_text(raw_task['test'])
 for record in evidence['records']:
  task=record['tasks'].get(TASK_ID)
  if not task or not task['functional_records']:continue
  generation_path=ROOT/record['evidence']['generation'];generations={r['sample_id']:r for r in rows(str(generation_path))}
  static_path=ROOT/record['evidence']['static'] if record['evidence']['static'] else None
  static_by_key={}
  if static_path:
   for sr in rows(str(static_path)):
    tid=sr.get('task_id',sr.get('identity',{}).get('task_id'));rid=sr.get('repeat_id',sr.get('identity',{}).get('repeat_id'))
    static_by_key[(tid,rid)]=sr
  selected={}
  for source in record['evidence']['functional']:
   for old in rows(str(ROOT/source)):
    if old.get('identity',{}).get('task_id')!=TASK_ID:continue
    sid=old['sample_id'];generation=generations.get(sid)
    if generation is None:continue
    fp=old.get('fingerprint',{})
    if fp.get('raw_generation_sha256')!=sha(generation.get('generation','').encode()):continue
    if sid in selected and selected[sid][1].get('passed')!=old.get('passed'):
     problems.append({'root':record['root'],'sample_id':sid,'problem':'conflicting_old_results'})
    selected.setdefault(sid,(source,old,generation))
  if len(selected)!=task['functional_records']:problems.append({'root':record['root'],'problem':'count_mismatch','found':len(selected),'expected':task['functional_records']})
  for sid,(source,old,generation) in selected.items():
   fp=old.get('fingerprint',{});repeat=generation['identity']['repeat_id'];code_sha=fp['final_code_sha256'];attempt=old.get('attempt_id')
   functional_dir=(ROOT/source).parent
   code_path=functional_dir/'staging'/str(attempt)/'solution.py'
   tests_path=functional_dir/'staging'/str(attempt)/'tests.py'
   code=None
   if code_path.is_file():code=code_path.read_bytes().decode("utf-8")
   if code is None:
    cleaned_path=generation_path.parent.parent/'cleaning/cleaned_generations.jsonl'
    if cleaned_path.is_file():
     clean=next((r for r in rows(str(cleaned_path)) if r.get('task_id')==TASK_ID and r.get('repeat_id')==repeat and r['cleaned'].get('final_code_sha256')==code_sha),None)
     if clean:
      code=clean['cleaned']['final_code'];code_path=OUT/'inputs/code'/f'{code_sha}.py';code_path.parent.mkdir(exist_ok=True);code_path.write_text(code)
   if code is None and code_sha==sha(b''):
    code='';code_path=OUT/'inputs/code'/f'{code_sha}.py';code_path.parent.mkdir(exist_ok=True);code_path.write_text(code)
   if code is None or sha(code.encode())!=code_sha:
    problems.append({'root':record['root'],'sample_id':sid,'problem':'code_missing_or_hash_mismatch'});continue
   if not tests_path.is_file():tests_path=fallback_tests
   if sha(tests_path.read_bytes())!=fp['test_sha256']:
    problems.append({'root':record['root'],'sample_id':sid,'problem':'tests_missing_or_hash_mismatch'});continue
   sr=static_by_key.get((TASK_ID,repeat));static_hit=None
   if sr:
    if sr.get('final_code_sha256')!=code_sha:problems.append({'root':record['root'],'sample_id':sid,'problem':'static_code_hash_mismatch'})
    static_hit=sr.get('verdict')=='target_present'
   job_id=sha(canonical({'root':record['root'],'sample_id':sid,'raw':fp['raw_generation_sha256']}))[:24]
   jobs.append({'job_id':job_id,'root':record['root'],'label':record['label_zh'],'model':record['model'],'renderer':record['renderer'],'identity':generation['identity'],'sample_id':sid,'generation_status':generation.get('status'),'generation_file':relative(generation_path),'generation_file_sha256':sha(generation_path.read_bytes()),'raw_generation_sha256':fp['raw_generation_sha256'],'code_path':relative(code_path),'code_sha256':code_sha,'source_tests_path':relative(tests_path),'source_tests_sha256':fp['test_sha256'],'entry_point':fp['entry_point'],'source_functional':source,'source_functional_row_sha256':sha(canonical(old)),'old_outcome':old['outcome'],'old_passed':old['passed'],'old_harness':old.get('harness_version',fp.get('harness_version')),'static_hit':static_hit,'candidate_timeout_seconds':fp.get('candidate_timeout_seconds',20)})
   sources[source]=sha((ROOT/source).read_bytes())
 for record in evidence['records']:
  task=record['tasks'].get(TASK_ID)
  if not task or not task['functional_records']:continue
  batch_jobs=[j for j in jobs if j['root']==record['root']]
  if sum(j['old_passed'] is True for j in batch_jobs)!=task['functional_pass']:problems.append({'root':record['root'],'problem':'old_pass_count_mismatch'})
  if sum(j['old_passed'] is True and j['static_hit'] is True for j in batch_jobs)!=task['hit_and_pass']:problems.append({'root':record['root'],'problem':'old_joint_count_mismatch'})
 plan={'author':'GPT / Codex','captured_at':datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),'scope':'Only t146 samples already having functional evidence in the existing summary; no new victim sampling','jobs':jobs,'problems':problems,'source_functional_hashes':sources,'original_summary_sha256':sha((snapshots/'统计依据.json').read_bytes()),'job_count':len(jobs),'batch_count':len({j['root'] for j in jobs})}
 write_json(OUT/'plan.json',plan)
 print('PLAN',plan['batch_count'],len(jobs),'problems',len(problems),flush=True)
 if problems:raise RuntimeError(json.dumps(problems[:8],ensure_ascii=False))
 return plan

def run_plan(workers):
 from coco_attack.evaluation.functional import HARNESS_VERSION,classify_payload,validate_payload,deterministic_input_outcome
 from coco_attack.evaluation.run_functional import execute_functional_code,resolve_functional_profile
 from coco_attack.evaluation.t146 import effective_tests,fixture_fingerprint
 plan=json.loads((OUT/'plan.json').read_text());assert not plan['problems']
 assert len({(j['root'],j['sample_id'],j['raw_generation_sha256'],j['code_sha256']) for j in plan['jobs']})==len(plan['jobs'])
 config=json.loads((ROOT/'coco_attack/configs/execution.local.json').read_text());config['profile_id']='t146-summary-reassessment';config['limits']['max_parallel_containers']=workers
 write_json(OUT/'execution.json',config)
 profile,backend=resolve_functional_profile(OUT/'execution.json',project_root=ROOT/'coco_attack')
 write_json(OUT/'run_config.json',{'harness_version':HARNESS_VERSION,'fixture':fixture_fingerprint(TASK_ID),'image_id':profile.image.image_id,'workers':workers,'victim_requests':0,'scope':plan['scope'],'plan_sha256':sha((OUT/'plan.json').read_bytes())})
 results_file=OUT/'functional_results.jsonl';completed={r['job_id']:r for r in rows(str(results_file))} if results_file.exists() else {}
 def evaluate(job):
  code=(ROOT/job['code_path']).read_bytes().decode('utf-8');tests=(ROOT/job['source_tests_path']).read_bytes().decode('utf-8');assert sha(code.encode())==job['code_sha256'];assert sha(tests.encode())==job['source_tests_sha256']
  actual_tests=effective_tests(TASK_ID,tests);test_sha=sha(actual_tests.encode());identity=job['identity'];base=OUT/'samples'/job['job_id'];attempt='functional-'+job['job_id']
  deterministic=deterministic_input_outcome(job['generation_status'],code)
  if deterministic:
   outcome,passed,reason,_=deterministic;execution={};payload=None
  else:
   result,extra=execute_functional_code(solution=code,tests=tests,entry_point=job['entry_point'],sample_id=job['sample_id'],attempt_id=attempt,stage=identity['stage'],batch_id=identity['batch_id'],combination_id=identity['combination_id'],task_id=TASK_ID,repeat_id=identity['repeat_id'],prompt_version=identity['prompt_version'],candidate_hash=identity['candidate_hash'],candidate_timeout_seconds=job['candidate_timeout_seconds'],harness_version=HARNESS_VERSION,profile=profile,backend=backend,run_dir=base,output_root=base/'outputs')
   payload=extra['payload'];problems=validate_payload(payload,sample_id=job['sample_id'],attempt_id=attempt,code_sha256=job['code_sha256'],tests_sha256=test_sha,entry_point=job['entry_point'])
   outcome,passed,reason,_=classify_payload(payload,validation_problems=problems,execution_available=result.available,execution_timed_out=result.timed_out,execution_incomplete=not result.result_valid,declared_modules=('subprocess','ipaddress'))
   execution=result.to_json()
  return {'job_id':job['job_id'],'root':job['root'],'sample_id':job['sample_id'],'identity':identity,'model':job['model'],'renderer':job['renderer'],'code_sha256':job['code_sha256'],'raw_generation_sha256':job['raw_generation_sha256'],'source_functional':job['source_functional'],'old_outcome':job['old_outcome'],'old_passed':job['old_passed'],'static_hit':job['static_hit'],'outcome':outcome,'passed':passed,'reason':reason,'harness_version':HARNESS_VERSION,'test_sha256':test_sha,'fixtures':fixture_fingerprint(TASK_ID),'execution':execution,'payload':payload,'payload_path':relative(base/'run/attempts'/attempt/'artifacts/payload.json') if payload else None}
 pending=[j for j in plan['jobs'] if j['job_id'] not in completed]
 with ThreadPoolExecutor(max_workers=workers) as pool, results_file.open('a') as output:
  futures={pool.submit(evaluate,j):j for j in pending}
  for future in as_completed(futures):
   result=future.result();output.write(json.dumps(result,ensure_ascii=False)+'\n');output.flush();completed[result['job_id']]=result
   if len(completed)%25==0 or len(completed)==len(plan['jobs']):
    progress={'completed':len(completed),'total':len(plan['jobs']),'outcomes':dict(Counter(r['outcome'] for r in completed.values())),'victim_requests':0}
    write_json(OUT/'progress.json',progress);print(json.dumps(progress,ensure_ascii=False),flush=True)
 write_json(OUT/'completion.json',{'completed':len(completed),'total':len(plan['jobs']),'outcomes':dict(Counter(r['outcome'] for r in completed.values())),'transitions':dict(Counter(f"{r['old_outcome']}->{r['outcome']}" for r in completed.values())),'results_sha256':sha(results_file.read_bytes())})


def publish():
 import re
 evidence=json.loads((OUT/'inputs/统计依据.json').read_text())
 results=rows(str(OUT/'functional_results.jsonl'));plan=json.loads((OUT/'plan.json').read_text());completion=json.loads((OUT/'completion.json').read_text())
 assert len(results)==len(plan['jobs'])==completion['completed']==1188
 assert len({r['job_id'] for r in results})==1188
 # Both independently computed DeepSeek results must match before publishing.
 independent=[json.loads((OUT/'verification'/f'recompute_{k}.json').read_text()) for k in ['A','B']]
 assert all(r['status']=='pass' for r in independent),[(r.get('status'),r.get('problems')) for r in independent]
 grouped=defaultdict(list)
 for result in results:grouped[result['root']].append(result)
 old_records={r['root']:json.loads(json.dumps(r)) for r in evidence['records']};updated={};comparison=[]
 version='t146: functional-harness-v6 / t146-tests-v1 / t146-ping-fixture-v1；其他任务保留原评测'
 for record in evidence['records']:
  if record['root'] not in grouped:continue
  rr=grouped[record['root']];old_task=record['tasks'][TASK_ID];old_total=record['totals']
  old_pass=old_task['functional_pass'];old_joint=old_task['hit_and_pass'];new_pass=sum(r['passed'] is True for r in rr);new_joint=sum(r['passed'] is True and r['static_hit'] is True for r in rr)
  for independent_result in independent:
   check=independent_result['batches'][record['root']]
   assert check['records']==len(rr) and check['passed']==new_pass and check['hit_and_pass']==new_joint,(record['root'],check)
  record['functional_before_t146_v6']={'task':json.loads(json.dumps(old_task)),'totals':json.loads(json.dumps(old_total)),'functional_result_location':record['functional_result_location'],'source_functional':list(record['evidence']['functional'])}
  old_task.update(functional_records=len(rr),functional_pass=new_pass,hit_and_pass=new_joint,functional_outcomes=dict(Counter(r['outcome'] for r in rr)),functional_harness_version='functional-harness-v6',functional_tests_version='t146-tests-v1',functional_fixture_version='t146-ping-fixture-v1',functional_unexecuted_generation_failures=sum(r['payload'] is None and r['reason'].startswith('generation_') for r in rr),functional_unavailable_or_incomplete=sum(r['passed'] is None for r in rr))
  old_total['functional_pass']+=new_pass-old_pass;old_total['hit_and_pass']+=new_joint-old_joint
  record['functional_result_location']='t146按v6重评；其他任务保留原评测，历史来源未删除'
  record['evidence']['functional_reassessment']=relative(OUT/'functional_results.jsonl')
  record['functional_evaluation_versions']=version
  updated[record['root']]=record
  comparison.append({'root':record['root'],'label':record['label_zh'],'model':record['model'],'renderer':record['renderer'],'records':len(rr),'old_pass':old_pass,'passed':new_pass,'old_hit_and_pass':old_joint,'hit_and_pass':new_joint,'old_total_pass':record['functional_before_t146_v6']['totals']['functional_pass'],'total_pass':old_total['functional_pass'],'old_total_hit_and_pass':record['functional_before_t146_v6']['totals']['hit_and_pass'],'total_hit_and_pass':old_total['hit_and_pass'],'observed_records':record['observed_sample_records']})
 assert len(updated)==93
 stamp=datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()
 evidence['authors']['functional_reassessment']='GPT / Codex；DeepSeek-v4.1-flash（两路独立统计与交叉核验）'
 evidence['functional_reassessment']={'updated_at':stamp,'sampling_captured_at_unchanged':evidence['captured_at'],'scope':'只重评既有93批1188条t146功能结果；77批752条未评样本不补评','harness_version':'functional-harness-v6','tests_version':'t146-tests-v1','fixture_version':'t146-ping-fixture-v1','new_results':relative(OUT/'functional_results.jsonl'),'original_summary':relative(OUT/'inputs/统计依据.json'),'plan':relative(OUT/'plan.json'),'run_config':relative(OUT/'run_config.json'),'old_pass':35,'passed':sum(r['passed'] is True for r in results),'old_hit_and_pass':15,'hit_and_pass':sum(r['passed'] is True and r['static_hit'] is True for r in results),'outcomes':dict(Counter(r['outcome'] for r in results)),'unexecuted_generation_failures':31,'docker_executions':sum(bool(r['execution']) for r in results),'victim_requests':0,'transitions':completion['transitions'],'batches':comparison}
 evidence['units']['functional']='t146已按v6重评，使用批次root+sample_id+raw_generation_sha256+final_code_sha256连接；其他任务保留原评测；旧值在functional_before_t146_v6，原来源未删除；未评估不补零'
 for path in [OUT/'functional_results.jsonl',OUT/'plan.json',OUT/'run_config.json']:
  evidence['source_file_sha256'][relative(path)]=sha(path.read_bytes())
 evidence['verification_summary']['functional_reassessment']={'updated_at':stamp,'two_independent_deepseek_checks':True,'identity_records':1188,'batches':93,'generation_sources_unchanged':True,'static_counts_unchanged':True,'other_tasks_unchanged':True}
 write_json(SUMMARY/'统计依据.json',evidence)
 new_columns=['修正前功能通过数','修正前命中且功能通过数','功能评测版本','t146重评证据']
 for name,is_task in [('逐批次实验明细.csv',False),('逐任务统计.csv',True)]:
  with (OUT/'inputs'/name).open(encoding='utf-8-sig',newline='') as f:reader=csv.DictReader(f);headers=reader.fieldnames;data=list(reader)
  for row in data:
   record=updated.get(row['采样目录'])
   if not record or (is_task and row['task_id']!=TASK_ID):continue
   current=record['tasks'][TASK_ID] if is_task else record['totals'];before=record['functional_before_t146_v6']['task' if is_task else 'totals']
   assert int(row['功能通过数'])==before['functional_pass'] and int(row['命中且功能通过数'])==before['hit_and_pass']
   row.update({'修正前功能通过数':row['功能通过数'],'修正前命中且功能通过数':row['命中且功能通过数'],'功能通过数':str(current['functional_pass']),'命中且功能通过数':str(current['hit_and_pass']),'功能评测版本':'functional-harness-v6 / t146-tests-v1 / t146-ping-fixture-v1' if is_task else version,'t146重评证据':relative(OUT/'functional_results.jsonl')})
   if not is_task:row['功能结果来源']+='；t146已按v6重评，见t146重评证据列'
  with (SUMMARY/name).open('w',encoding='utf-8-sig',newline='') as f:writer=csv.DictWriter(f,fieldnames=headers+new_columns);writer.writeheader();writer.writerows(data)
 def transition(old,new,denominator):return f'{old}/{denominator} → {new}/{denominator}' if old!=new else f'{new}/{denominator}'
 def update_numeric_rows(text,mappings):
  lines=text.splitlines();header=None;changed=0
  for index,line in enumerate(lines):
   if line.startswith('|'):
    cells=[c.strip() for c in line.split('|')]
    if any(c.startswith('功能通过') for c in cells) and any(c.startswith('命中且通过') for c in cells):header=cells
    if index+1 not in mappings:continue
    record=updated[mappings[index+1]];old=old_records[record['root']];den=record['observed_sample_records']
    assert header is not None
    for key,title in [('functional_pass','功能通过'),('hit_and_pass','命中且通过')]:
     col=next(i for i,c in enumerate(header) if c.startswith(title));assert re.fullmatch(r'\d+\s*/\s*\d+',cells[col]),(index+1,cells[col])
     assert int(cells[col].split('/')[0])==old['totals'][key]
     cells[col]=transition(old['totals'][key],record['totals'][key],den)
    lines[index]='| '+' | '.join(cells[1:-1])+' |';changed+=1
  assert changed==len(mappings),(changed,len(mappings))
  return '\n'.join(lines)+'\n'
 docrows=json.loads((OUT/'inputs/overview_rows.json').read_text());assert len(docrows)==45
 overview=update_numeric_rows((OUT/'inputs/探索实验总览.md').read_text(),{r['line']:r['root'] for r in docrows})
 overview=overview.replace('原始产物未改动，本次没有启动或重跑实验。','原始采样产物未改动，没有新增 victim 采样；t146 的功能评测于2026-10-22单独修正重评。')
 old_note=next(l for l in overview.splitlines() if l.startswith('t146 功能列须保留评测限制：'))
 new_note='功能列已加入2026-10-22的 t146 专用重评：受影响表格以“原值 → 修正后”显示，数值相同则只列一次；只替换 t146 分量，其他任务保留原功能评测。原值来自 v3/v5，新 t146 使用 `functional-harness-v6 / t146-tests-v1 / t146-ping-fixture-v1`，与 trigger 版本无关。[修正范围、逐批对照及原始结果](<t146功能评测修正对照.md>)。'
 overview=overview.replace(old_note,new_note)
 (SUMMARY/'探索实验总览.md').write_text(overview)
 experience=(OUT/'inputs/复现率经验分级.md').read_text();mapping={}
 aliases={'B2-r20':'arm-B2-r20','A4-r10':'arm-A4','A4-r20':'arm-A4-r20','A2-r10':'arm-A2','A2-r20':'arm-A2-r20','A2-r20b，另一次重采':'arm-A2-r20b','B8，原三题批次':'arm-B8'}
 for no,line in enumerate(experience.splitlines(),1):
  if not line.startswith('|'):continue
  label=line.split('|')[1].strip()
  if label not in aliases:continue
  matches=[r['root'] for r in comparison if r['root'].endswith('/'+aliases[label])];assert len(matches)==1,(label,matches);mapping[no]=matches[0]
 assert len(mapping)==7;experience=update_numeric_rows(experience,mapping)
 experience=experience.replace('本次没有运行新实验，以下建议也不代表已经实施。','没有新增 victim 采样；本页功能列已加入2026-10-22的 t146 专用重评，以下方法建议仍不代表已经实施。')
 old_note=next(l for l in experience.splitlines() if l.startswith('**功能列的限制：**'))
 experience=experience.replace(old_note,'**功能列的版本：**受 t146 影响的行按“原值 → 修正后”列出，数值相同只列一次；上表原始功能评测为 `functional-harness-v5`，新 t146 为 `functional-harness-v6 / t146-tests-v1 / t146-ping-fixture-v1`，其他任务保留原结果。旧的缺 ping 或调用计数问题不能直接解释为候选破坏功能；修正后仍须满足完整地址遍历等要求。t16 的 v1 题面损坏和扩展题的功能问题不因此消失。详见[t146功能评测修正对照](<t146功能评测修正对照.md>)。')
 old_note=next(l for l in experience.splitlines() if l.startswith('- **t146 功能测评有已知缺陷**'))
 experience=experience.replace(old_note,'- **t146 功能评测已按版本重评**：原测试只模拟 `check_output`，部分 `run`/`Popen` 实现绕过模拟并调用缺失的 ping；新版本已统一模拟。本页保留原值并列修正值，逐条代码与原测试哈希、真实结果和来源见[修正对照](<t146功能评测修正对照.md>)。原先已有的 `.hosts()` 漏地址、错误目标或忽略失败仍会失败，不能把全部旧失败都归因于环境。其他任务没有随之重评。')
 b3=next(r for r in comparison if r['root'].endswith('/arm-B3'));b2=next(r for r in comparison if r['root'].endswith('/arm-B2'))
 experience=experience.replace('命中且通过均20/60',f"命中且通过原均20/60，t146修正后分别为{b3['total_hit_and_pass']}/60与{b2['total_hit_and_pass']}/60")
 (SUMMARY/'复现率经验分级.md').write_text(experience)
 lines=['# t146 功能评测修正对照','','统一重评与汇总：GPT / Codex；范围核查、独立复算与交叉核验：DeepSeek-v4.1-flash（OpenCode，两路）。','',f"采样数据截点仍为 {evidence['captured_at']}；功能重评日期：2026-10-22。没有新增 victim 请求，也没有修改历史 run、原始题库、静态判定或模板。",'','## 这次重评了什么','','只处理原来已有功能证据的93批、1188条 t146 记录；其余含t146但没有该题功能结果的77批，共752条t146记录没有补评。1157条保存代码进入Docker（含1条语法错误），31条生成失败保留原状态、没有执行测试。','',f"t146 功能通过由 **35/1188 → {sum(r['passed'] is True for r in results)}/1188**；命中且通过由 **15/1188 → {sum(r['passed'] is True and r['static_hit'] is True for r in results)}/1188**。这些合计用于核对工作量，不用来合并不同模型、trigger或实验条件比较方法。",'','原评测包含 functional-harness-v3/v5；新 t146 使用 **functional-harness-v6 / t146-tests-v1 / t146-ping-fixture-v1**。修正统一了ping模拟，也增加完整地址与调用核对，可能把原失败改判通过，也可能把原通过改判失败。下表保留两边实际值；其他任务仍使用原评测。','', '同一sample_id曾在不同批次出现；本次按批次、sample_id、响应哈希和代码哈希连接1188条记录，没有把不同响应合并。26题扩展筛选不含t146，其功能数字没有变化。','','## 判定变化','','| 原判定 → 新判定 | 记录数 |','| --- | --- |']
 model_lines=['## 按 victim 分开核对','','DeepSeek-V3.2 的原功能评测为 v3，0731 为 v5；新 t146 均为 v6。','','| victim | t146记录数 | 原功能通过 | 修正后功能通过 | 原命中且通过 | 修正后命中且通过 |','| --- | --- | --- | --- | --- | --- |']
 for model in sorted({r['model'] for r in results}):
  mr=[r for r in results if r['model']==model]
  model_lines.append(f"| {model.replace('openai/','')} | {len(mr)} | {sum(r['old_passed'] is True for r in mr)} | {sum(r['passed'] is True for r in mr)} | {sum(r['old_passed'] is True and r['static_hit'] is True for r in mr)} | {sum(r['passed'] is True and r['static_hit'] is True for r in mr)} |")
 model_lines+=['']
 at=lines.index('## 判定变化');lines[at:at]=model_lines
 for transition_name,count in sorted(completion['transitions'].items()):lines.append(f'| {transition_name.replace("->"," → ")} | {count} |')
 regressed=[r for r in results if r['old_passed'] is True and r['passed'] is False]
 if len(regressed)==1:
  example=regressed[0]
  if 'shell=True requires a command string' in json.dumps(example.get('payload',{})):
   codefile=OUT/'samples'/example['job_id']/'staging'/('functional-'+example['job_id'])/'solution.py'
   lines+=['', '原通过改为失败的1条，使用了 `shell=True` 配合参数列表；在本次Linux容器中，这不会把完整列表作为ping参数执行。旧mock没有发现，新版本明确拒绝。见[该样本代码](<'+os.path.relpath(codefile,SUMMARY)+'>)。']

 lines+=['','## 逐批次对照','','“t146功能通过”“t146命中且通过”两列只统计t146；末两列是该批全部任务的功能合计，已用新t146替换原分量。相同数值只列一次，变化用“原值 → 修正后”。批次名称链接到模板索引的对应记录。','','| 批次 | victim | t146功能通过 | t146命中且通过 | 全批功能通过 | 全批命中且通过 |','| --- | --- | --- | --- | --- | --- |']
 for r in comparison:
  anchor='batch-'+sha(r['root'].encode())[:12];label=r['label'].replace('|','&#124;');model=r['model'].replace('openai/','')
  lines.append(f"| [{label}](<候选模板索引.md#{anchor}>) | {model} | {transition(r['old_pass'],r['passed'],r['records'])} | {transition(r['old_hit_and_pass'],r['hit_and_pass'],r['records'])} | {transition(r['old_total_pass'],r['total_pass'],r['observed_records'])} | {transition(r['old_total_hit_and_pass'],r['total_hit_and_pass'],r['observed_records'])} |")
 lines+=['','## 查原始证据','','- [逐样本新旧结果](<'+os.path.relpath(OUT/'functional_results.jsonl',SUMMARY)+'>)：包含原判定、新判定、模型、响应/代码哈希、静态命中、镜像和测试版本。','- [输入清单](<'+os.path.relpath(OUT/'plan.json',SUMMARY)+'>)、[执行配置](<'+os.path.relpath(OUT/'run_config.json',SUMMARY)+'>)、[完成统计](<'+os.path.relpath(OUT/'completion.json',SUMMARY)+'>)。','- [修正前统计依据快照](<'+os.path.relpath(OUT/'inputs/统计依据.json',SUMMARY)+'>)；当前[统计依据.json](<统计依据.json>)也在各受影响批次保留旧值与旧来源。','- 两份CSV主功能列为修正后的合计，新增“修正前功能通过数”“修正前命中且功能通过数”“功能评测版本”“t146重评证据”列；没有结果的行仍没有结果。','- [重评与汇总工具](<工具/重算t146功能统计.py>)。原始代码只通过Docker执行。','','本次没有重做static或Semgrep，没有改变victim、题面trigger、repeat、生成数量及code/CoT内容；对这些方面的经验不因功能重评自动升级。']
 (SUMMARY/'t146功能评测修正对照.md').write_text('\n'.join(lines)+'\n'+'\n\n<details>\n<summary>独立复算与核验依据</summary>\n\n- [独立复算 A](<../../../../cocota_runs/phase04/t146-functional-v6-20261022/verification/recompute_A.json>)、[独立复算 B](<../../../../cocota_runs/phase04/t146-functional-v6-20261022/verification/recompute_B.json>)。\n- [发布后核验 A](<../../../../cocota_runs/phase04/t146-functional-v6-20261022/verification/final_A.json>)、[发布后核验 B](<../../../../cocota_runs/phase04/t146-functional-v6-20261022/verification/final_B.json>)。\n\n</details>\n')
 write_json(OUT/'published_summary.json',{'updated_at':stamp,'batches':comparison,'overview_rows':45,'experience_rows':7,'old_sampling_captured_at':evidence['captured_at']})
 print('Published: 93 batches, 93 task rows, 45 overview rows, 7 experience rows',flush=True)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('action',choices=['plan','run','publish']);parser.add_argument('--workers',type=int,default=8);args=parser.parse_args()
 if args.action=='plan':build_plan()
 elif args.action=='run':run_plan(args.workers)
 else:publish()
