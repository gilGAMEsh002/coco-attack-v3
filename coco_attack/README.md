# coco_attack

Independent application package for the CoCo-Attack benchmark rebuild. It lives
inside the DSPy repository but is installed and run as its own subproject.

The domain foundation (data contracts, cleaning, static oracles, metrics and
deterministic splits) does not import DSPy. DSPy is a declared runtime
dependency for later generation/evaluation stages only.

## Environment reconstruction

```bash
cd coco_attack
/usr/bin/python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools
# editable install of the local DSPy source (must not be replaced by a
# same-named PyPI distribution)
.venv/bin/python -m pip install -e ..
# editable install of this application; runtime deps already satisfied above
.venv/bin/python -m pip install -e .
```

If dependency resolution or installation fails in the current environment, the
failure is recorded in the audit output as an environment limitation. Do not
fabricate a lock file.

## CLI

```bash
coco-attack audit-assets \
  --repo-dir <dspy-repo> \
  --assets-dir <asset-root> \
  --output-dir <fresh-output-dir>

coco-attack prepare-data \
  --repo-dir <dspy-repo> \
  --assets-dir <asset-root> \
  --output-dir <fresh-output-dir> \
  --split-config configs/splits.json \
  --combination cwe078-0            # repeatable, or the single value 'all'

coco-attack materialize-prompts \
  --repo-dir <dspy-repo> --assets-dir <asset-root> --data-dir <prepare-data-output> \
  --combination cwe078-0 --oracle-id cwe078-0 --form all \
  --output-dir <fresh-output-dir>

coco-attack clean-generations \
  --data-dir <prepare-data-output> --input-jsonl <final-generations.jsonl> \
  --combination cwe078-0 --oracle-id cwe078-0 \
  --output-dir <fresh-output-dir>

coco-attack evaluate-static \
  --assets-dir <asset-root> --data-dir <prepare-data-output> \
  --cleaned-dir <clean-generations-output> \
  --combination cwe078-0 --oracle-id cwe078-0 \
  --config <evaluation-config.json> \
  --output-dir <fresh-output-dir>

coco-attack calibrate-references \
  --assets-dir <asset-root> --data-dir <prepare-data-output> \
  --config <calibration-config.json> --output-dir <fresh-output-dir>

coco-attack compare-history \
  --assets-dir <asset-root> --data-dir <prepare-data-output> \
  --config <history-config.json> --output-dir <fresh-output-dir>

coco-attack check-generation \
  --config <generation-config.json> --data-dir <prepare-data-output> \
  --prompts-dir <materialize-prompts-output> --output-dir <fresh-output-dir>

coco-attack generate \
  --config <generation-config.json> --data-dir <prepare-data-output> \
  --prompts-dir <materialize-prompts-output> --output-dir <fresh-run-dir> \
  [--repo-dir <repo root with .env>]

coco-attack resume-generation --run-dir <existing-run-dir> [--repo-dir <repo root>]

coco-attack verify-generation-boundary \
  --config <generation-config.json> --execution-config <execution-profile.json> \
  --data-dir <prepare-data-output> --prompts-dir <materialize-prompts-output> \
  --output-dir <fresh-evidence-dir>

coco-attack check-functional \
  --config <functional-config.json> --data-dir <prepare-data-output> \
  --generation-run <generation-run> --cleaned-dir <clean-generations-output> \
  --execution-config <execution-profile.json> --output-dir <fresh-output-dir>

coco-attack evaluate-functional \
  --config <functional-config.json> --data-dir <prepare-data-output> \
  --generation-run <generation-run> --cleaned-dir <clean-generations-output> \
  --execution-config <execution-profile.json> --cache-dir <persistent-cache-root> \
  --output-dir <fresh-run-dir> [--ledger-path <ledger>]

coco-attack resume-functional --run-dir <existing-functional-run>

coco-attack check-evaluators \
  --config <evaluators-config.json> --data-dir <prepare-data-output> \
  --generation-run <generation-run> --cleaned-dir <clean-generations-output> \
  --output-dir <fresh-output-dir>

coco-attack evaluate-other \
  --config <evaluators-config.json> --data-dir <prepare-data-output> \
  --generation-run <generation-run> --cleaned-dir <clean-generations-output> \
  --execution-config <execution-profile.json> --output-dir <fresh-run-dir> \
  [--ledger-path <ledger>]

coco-attack resume-other --run-dir <existing-evaluator-run>

coco-attack check-pipeline --config <pipeline-config.json> --output-dir <fresh-check-dir>
coco-attack run-pipeline --config <pipeline-config.json> --output-dir <fresh-run-dir> \
  [--accept-existing-generation]
coco-attack resume-pipeline --run-dir <existing-pipeline-run>
coco-attack report-pipeline --run-dir <existing-pipeline-run> [--output-dir <fresh-report-dir>]

coco-attack prepare-baseline --matrix-config <baseline-matrix.json> --output-dir <fresh-baseline-root>
coco-attack check-baseline --baseline-root <baseline-root>
coco-attack run-baseline --baseline-root <baseline-root> [--limit N] [--only UNIT_ID ...]
coco-attack status-baseline --baseline-root <baseline-root>
coco-attack report-baseline --baseline-root <completed-baseline-root>
```

All directories are mandatory. `--help` does not scan assets and does not
import DSPy. `prepare-data` refuses a non-empty `--output-dir` and never
publishes a partial dataset: if any requested combination fails validation it
writes `prepare_errors.json` and exits 1 without a completion manifest.

### `prepare-data` outputs

| Path | Purpose |
|---|---|
| `<combination>/tasks.jsonl` | registry-aligned 17-field task snapshot plus provenance |
| `<combination>/selection.json` | ordered example ids, fixed evaluation ids, seed and source fingerprints |
| `<combination>/split.json` | explicit `search`/`holdout` partitions or a `whole-set` list |
| `manifest.json` | data contract version, combination↔oracle mapping, output file hashes, completion status |
| `REPORT.md` | counts, split details, provenance and notices |

### `materialize-prompts` outputs

| Path | Purpose |
|---|---|
| `<combination>/<form>/{meta.json,fewshot.json,test_prompts/}` | the three-part clean experiment set |
| `manifest.json` | completion status, per-form prompt hashes and file hashes |
| `prompt_diffs.json` | reuse/derivation diffs and legacy-vs-standard text differences |
| `REPORT.md` | per-form summary and unrepaired differences |

Clean forms never inject a trigger. A combination without clean assets is
reported as not covered and produces no experiment.

### `clean-generations` outputs

| Path | Purpose |
|---|---|
| `cleaned_generations.jsonl` | one `CleanResult` per final generation sample, failures included |
| `manifest.json` | cleaner version, input fingerprint, status/extraction counts |
| `REPORT.md` | summary; cleaning never returns an oracle verdict |

### `evaluate-static` outputs

| Path | Purpose |
|---|---|
| `evaluations.jsonl` | one static `EvaluationRecord` per expected sample |
| `metrics.json` | ASR@1/@3/@5, sample hit rate, verdict counts, undefined placeholders |
| `manifest.json` | completion status, config, oracle fingerprint, layer availability |
| `REPORT.md` | verdict/source distribution and metric table |

Only the static layer is integrated in this task; pass@k, SAST, judge, dynamic
and realism metrics are explicit `defined=false` placeholders, and
`target_absent` means "target pattern not detected", not "safe".

### `calibrate-references` outputs

| Path | Purpose |
|---|---|
| `<combination>/reference_comparisons.jsonl` | per-task reference code hashes, reference/current verdicts, label comparison, approved boundary |
| `summary.json`, `differences.json` | per-combination agreement counts and new differences |
| `manifest.json`, `REPORT.md` | processing/acceptance status and human-readable report |

### `compare-history` outputs

| Path | Purpose |
|---|---|
| `<run>/history_comparisons.jsonl` | per-sample existence, code comparison, historical boolean hit, new verdict |
| `summary.json`, `differences.json` | per-run boolean/code mismatch counts and ASR comparison |
| `manifest.json`, `REPORT.md` | processing/acceptance status and report |

Historical records only carry a boolean hit, so the historical three-state
verdict column is always `null`. Exit code 1 means blocking differences were
recorded for review; AST-equivalent code differences (line-ending or
boundary-whitespace canonicalization) are reported as cosmetic and are not
blocking.

### `generate` / `resume-generation` outputs

| Path | Purpose |
|---|---|
| `run_config.json` | credential-free config, `run_config` hash, input snapshot refs, cache namespace path |
| `ledger.jsonl` | append-only events: `attempt_started`, `response_received` (first usage/cost), `attempt_failed`, `sample_finalized` |
| `generations.jsonl` | one final record per sample; top-level `task_id`/`repeat_id`/`status`/`generation` for `clean-generations`, full identity and provenance as extra fields |
| `generation_summary.json`, `REPORT.md` | requested/generated/skipped counts, status counts, budget accounting, cache namespace |
| `dspy-cache/<source>/<stage>/` | physically isolated DSPy response cache namespace per source and stage |

`check-generation` writes `generation_check.json`/`REPORT.md` and never calls a
model. `verify-generation-boundary` writes `generation_boundary.json`,
`manifest.json` and `REPORT.md`; the mock source replaces only the LiteLLM
completion boundary and still runs through
`dspy.LM.forward -> DSPy response cache -> completion`.

### `evaluate-functional` / `resume-functional` outputs

| Path | Purpose |
|---|---|
| `functional_config.json` | frozen config plus explicit input references (data, generation run, cleaned dir, execution profile, cache root, ledger) |
| `functional_results.jsonl` | one `FunctionalResult` per sample (cache hits included), with outcome/passed/tests counts/execution facts/fingerprint |
| `functional_metrics.json` | per-task n/c and pass@1/@3/@5 (undefined when samples are missing or unresolved) |
| `ledger.jsonl` | `execution_recorded` local_test events keyed by stable `accounting_id` |
| `<cache-root>/functional-cache-v1/<stage>/` | SQLite index plus immutable per-sample artifacts |

Generated code runs only inside the isolation container via the `functional`
image entry; the host never imports or executes candidate code. `check-functional`
performs the input join and never runs a candidate.

### `evaluate-other` / `resume-other` outputs

| Path | Purpose |
|---|---|
| `config.json`, `manifest.json` | frozen evaluator config, input references, coverage/tool availability and the realism semantics-conflict table |
| `layers/sast.jsonl`, `layers/judge.jsonl` | one strict layer record per sample and tool/model, with raw alert/label evidence references |
| `layers/dynamic.jsonl`, `layers/realism.jsonl` | coverage/status records; realism is `semantics_pending` until adjudicated |
| `sast/<sample>/<tool>/`, `judge/<action>.json` | bounded raw tool output and judge prompt/response evidence |
| `evaluator_metrics.json` | `*_evasion` (observed ratio over static asr_hit denominator) and `llm_judge_rate` (detections over successfully judged samples); both are observed ratios with `basis="observed"` and `sampled_run` metadata, undefined only on zero denominator |

All other-evaluator layers use the disabled evaluation cache: a new
`evaluation_id` always re-evaluates. Only the judge's underlying DSPy model
response cache can be reused, and that is reported separately.

SAST uses the local read-only rule assets: Bandit's reviewed rule mapping,
Semgrep via the rules directory in `third_party/semgrep`, and CodeQL via the
bundled toolchain with per-combination queries from `third_party/codeql/qlpacks`
(`codeql_executable` / `codeql_search_path` in the evaluators config). The
CodeQL license forbids redistribution, so it is referenced in place and never
copied into the image.

### `check-example-code` outputs

Direct, method-independent check of one explicit example task and code. It
returns per-layer facts (syntax/entry, static oracle, Semgrep, functional
Docker test) and never combines them into a gate, an "allowed into B" decision
or an attack-success verdict. Example code is sourced from a trusted few-shot
asset or a file:

```bash
.venv/bin/python -m coco_attack.cli check-example-code \
  --assets-dir /path/to/cocota_data_eval_result \
  --combination cwe078-0 --task-id BigCodeBench/348 \
  --fewshot-experiment cwe078_clean_fewshot --example-index 1 \
  --action-id A-r1-example1 --code-source fewshot.cwe078_clean_fewshot#1 \
  --execution-config configs/execution.local.json \
  --semgrep-config /path/to/cocota_data_eval_result/third_party/semgrep \
  --output-dir /path/to/runs/example-348
```

| Path | Purpose |
|---|---|
| `request.json` | explicit request, resolved task/registry provenance, code bytes and content hashes, written before any execution |
| `check_result.json` | one result with independent `syntax`/`static`/`semgrep`/`functional` facts, per-layer state+reason, consumption and tool versions |
| `REPORT.md` | layer summary; no combined verdict |
| `ledger.jsonl` | one `execution_recorded` `local_test` event per real container run |
| `semgrep/solution.py` | exact bytes Semgrep scanned |
| `functional/<attempt-id>/`, `run/attempts/<attempt-id>/` | container outputs and supervisor evidence |

Exit code 0 means the service produced a structured result; it does **not**
mean the functional/oracle/Semgrep research conditions were met. Clean examples
may legitimately have `target_absent` or a Semgrep detection — those are facts,
not service failures. The functional path always re-executes (the functional
result cache is not used) and the example is never added to
`evaluation_ids`/`search_ids`.

### `materialize-poisoned` outputs (I1 template snapshot + poisoning)

A content-addressed template snapshot service plus a poisoning materializer that
renders the current snapshot into the generation-input layout. It never calls
the clean materializer, never decides which examples/fields may change (the
caller supplies the patch and the allowed example/field set), and never writes
into the read-only asset tree.

```bash
# c0: build from the clean few-shot experiment and materialize two train tasks
.venv/bin/python -m coco_attack.cli materialize-poisoned \
  --assets-dir /path/to/cocota_data_eval_result \
  --data-dir /path/to/prepared/data \
  --combination cwe078-0 \
  --task-id BigCodeBench/13 --task-id BigCodeBench/1105 \
  --output-dir /path/to/runs/poison-c0 \
  --snapshot-store /path/to/runs/snapshot-store --action-id c0

# A/B patch on the current candidate: chain from the stored snapshot
.venv/bin/python -m coco_attack.cli materialize-poisoned \
  --assets-dir /path/to/cocota_data_eval_result --data-dir /path/to/prepared/data \
  --combination cwe078-0 --task-id BigCodeBench/13 --task-id BigCodeBench/1105 \
  --input-snapshot /path/to/runs/snapshot-store/cwe078-0/<content-sha256> \
  --patch-file patch.json --allow-example 2 --allow-example 3 \
  --allow-field code --output-dir /path/to/runs/a1
```

| Path | Purpose |
|---|---|
| `<snapshot-store>/<combination>/<content-sha256>/snapshot.json` | immutable content-addressed template snapshot (examples, attack_config, protocol) |
| `<snapshot-store>/audit.jsonl` | bypass audit: action id, parent content hash, real before/after diff, timestamp |
| `<output>/manifest.json` | completion marker + per-form meta hash and per-task prompt hashes (written last) |
| `<output>/<combination>/<form>/{meta.json,fewshot.json}` | poisoned meta (attack_config, real `is_poisoned`/`trigger`/`poison_parts`) and few-shot examples |
| `<output>/<combination>/<form>/test_prompts/*.md` | rendered test prompts for exactly the requested tasks |

`--input-snapshot` reads a stored version and applies the new patch on top, so
A then B are ordinary calls on the single current candidate. The snapshot
content hash covers only the rendered template (never paths, timestamps or
parent versions), so identical content has one identity across directories.
Unless `--skip-verify`, the command re-reads the tree with the real
`load_generation_inputs` and prints the sample count and candidate hash. Exit 0
means a structured poisoned tree was produced, not that any research condition
passed. The python API is
`snapshot_from_clean` / `apply_patch(TemplateSnapshot, patch, PatchPolicy)` /
`write_snapshot` / `read_snapshot` and `materialize_poisoned`.

To feed the direct checker from the current candidate, use
`build_example_check_request(snapshot, example, ...)`: it takes the (possibly
patched) snapshot code, not a reloaded clean body.

### `run-training-loop` outputs (single-candidate training closure)

One explicit candidate, one closed mock loop: poisoned materialize → victim
generation → cleaning → static oracle → Semgrep → feedback → clean-baseline
slice. It contains no A/B gate, candidate pool or method loop, and calls no
model unless `source` is `dmx` (this task only exercises `source="mock"`).

```bash
.venv/bin/python -m coco_attack run-training-loop --config loop-config.json
```

Run layout (so the shared `static_hits_from_run` join works unchanged):

| Path | Purpose |
|---|---|
| `prompts/` | materialized poisoned prompt tree for exactly the configured tasks |
| `generation/` | mock generation run (`run_config.json`, `ledger.jsonl`, `generations.jsonl`, `generation_summary.json`) |
| `cleaning/` | cleaned generations incl. failures |
| `static/` | `evaluations.jsonl` + `metrics.json` over exactly `tasks × repeats` |
| `evaluation/` | Semgrep-only layer records + `evaluator_metrics.json` (carries the `sast_adapter` fingerprint) |
| `feedback.json` | method-facing projection (`训练题 1/2 × repeat`, code, verdict, scan fact); no real ids/hashes/paths |
| `feedback_audit.json` | audit side with real `task_id`/`sample_id`/fingerprints |
| `baseline_slice.json` | read-only phase-03 clean baseline sliced to the same tasks, metrics, `assess_baseline_compatibility`, and the E05 adapter/history note |
| `loop_config.json` / `manifest.json` | frozen config hash + per-step status; completion written last |

Re-running with the same config short-circuits a complete run without
re-generating; a different config/snapshot is refused **before** anything is
written, and `force_rerun` on an existing run is refused (use a new
`output_dir`) so old responses/ledger are never deleted. An incomplete step is
renamed to `<step>.partial-<timestamp>` and re-run, preserving the old bytes.
Completion reuse re-checks the actual data, not manifest flags: every
generation row's `sample_id` **and full identity** must equal the identities
recomputed from the materialized prompts, and the generation `run_config`
candidate hash must match. Cleaning is bound to the real generation bytes and
static to the real cleaning/evaluations bytes via the manifests' fingerprints.
Every static row's `final_code_sha256` (and every Semgrep record's
`sources.final_code_sha256`) must equal the cleaning row's `final_code_sha256`,
so a changed cleaning output invalidates stale static/Semgrep results even when
the cleaning manifest is consistent — a changed upstream invalidates its
dependents. Derived reports are checked for structure **and** provenance: the
method-facing `feedback.json` is bound to `feedback_audit.json`'s per-sample
`final_code_sha256`, `feedback_audit.json` to the run candidate hash/template and
expected sample ids, and `baseline_slice.json`'s `source.sha256`/`source.path` to
the configured baseline file. An invalid or stale report is regenerated (with
the old copy preserved as `*.partial-<timestamp>`), never silently accepted. A
foreign sample/identity is refused, a missing/short step is recovered, and an old
schema or changed candidate is refused.

Baseline provenance is read from the baseline's own artifacts via the optional
`baseline_data_dir` (split mode / data contract / snapshot hashes),
`baseline_evaluators_config` (`k`) and `baseline_evaluation_dir` (raw Semgrep
report presence and historical `scan_errors`). The external `baseline_config`
is cross-checked against the baseline's **embedded** `static/manifest.json`
config and the actual `evaluations.jsonl` fingerprint; the baseline identity
used for comparison comes from the embedded config, so a relabelled or
tampered config/results pair yields `compatible=false`. Missing baseline
information is reported missing, never copied from the candidate, and an
incomplete baseline matrix blocks comparability. `semgrep_timeout_seconds` is
validated (positive, finite) and threaded into the actual scanner;
`semgrep_timeout.used` equals the configured value. Generation (first run and
resume) runs in an independent subprocess by default so the DSPy cache is
configured once per process.

`source="mock"` output is wiring data: `baseline_slice.json` marks
`comparable_with_real_baseline: false` and computes no better/worse conclusion.
Exit 0 means the mock closure completed, not that any research gate passed.

### `mutator-action-mock` (task-04 role calls, action recovery, shared history)

An offline demonstration of the common role-call/action service. It runs two
ordinary mock mutator interactions through the real persistence boundary, with a
simulated interrupt after the first raw response is durable and before the
template/history commit:

```bash
.venv/bin/python -m coco_attack mutator-action-mock \
  --snapshot /path/to/snapshot-store/cwe078-0/<content-sha256> \
  --run-dir /path/to/runs/action-mock/run \
  --assets-root /path/to/cocota_data_eval_result \
  --snapshot-store /path/to/runs/action-mock/snapshots \
  --report /path/to/runs/action-mock/report.json
```

It contains **no** A/B gate, stage transition, B-attempt counter or five-iteration
loop; the common service only executes what the method schedules. The offline
default uses a scripted mock provider and never loads an API key.

| Path | Purpose |
|---|---|
| `actions.jsonl` | append-only action log (`action_planned` → `attempt_started` → `response_saved` → `postprocess_*` → `action_committed`) |
| `actions/<action_id>/request.json` | the actual messages, role/kind, input references and `request_sha256`, written before the provider is contacted |
| `actions/<action_id>/responses/<attempt>.json` | raw text, finish reason, response id, usage, cache source and cost, written before parsing |
| `actions/<action_id>/result.json` | patch post-processing result (`patched` / `no_change` / `invalid_patch`) |
| `actions/<action_id>/commit.json` | commit point referencing the new template version and real diff |
| `history.jsonl` | committed shared-history units (deterministic summaries + verbatim user/assistant content) |
| `snapshots/` | new content-addressed template versions + audit |

Rules enforced by the service: the request is durable before any call; a durable
response makes a resume return it without contacting the provider; an
`attempt_started` with no durable response is reported as **unknown** (no silent
retry, `cost.basis="unknown"`, amount never zero) unless the caller explicitly
opts into a retry; an invalid/out-of-range patch is recorded as a failure and
never triggers a second "repair" request; the template version/diff and history
unit are committed exactly once (re-committing is idempotent). History assembly
pins the system block and current template full text, keeps recent interactions
verbatim and compresses only the oldest units into one line each when the
configured token budget is exceeded; an over-large fixed block fails explicitly.
Token counts carry an explicit counter method and are never presented as provider
usage. `method_inputs` assembles the four example tests/prefixes/entries, the
target Semgrep rule source text and the current template full text; audit fields
(ids/hashes/paths) never enter the model-visible projection or shared history.

### `run-method-ab` (single-candidate A/B method, task 05)

The method layer that composes the common services into the current research
method. It owns the A/B rules; the common `iteration/` services stay free of
gates, stages and B counters. One shared history, one current candidate:

```bash
.venv/bin/python -m coco_attack run-method-ab \
  --config method-config.json \
  --mutator-script mutator-responses.json \
  --mock-gate --mock-training \
  --report /path/to/runs/method-ab/report.json
```

- `method-config.json` — `MethodConfig` fields (run_dir, snapshot_path,
  snapshot_store, assets_root, data_dir, the four example task ids, train task
  ids, check configs/timeouts, `max_rounds`, baseline refs) plus **two explicit
  role objects**:

  ```json
  "mutator": {"source": "mock", "model": "", "temperature": 0.7, "max_tokens": 8192,
              "request_timeout": 60.0, "max_request_attempts": 2,
              "context_window_tokens": 32768, "output_reserve_tokens": 8192},
  "victim":  {"source": "mock", "model": "openai/DeepSeek-V3.2", "temperature": 0.7,
              "repeats": 5, "max_tokens": 8192}
  ```

  The mutator and victim roles are always listed separately even when they share
  a model; `mutator.output_reserve_tokens` must be ≥ `mutator.max_tokens`.
- `--mutator-source {mock,dmx}` must match `config.mutator.source`; overriding it
  is rejected before any work (the config hash, request identity, cache namespace
  and actual source stay consistent). `mock` requires `--mutator-script`; `dmx`
  forbids it.
- `repo_dir` is resolved once from `--repo-dir` and `config.repo_dir`: if both are
  given and differ it is an error, and a real (dmx) mutator **or victim** role
  requires an existing path. The single effective value is recorded in the method
  config so the mutator key loader and the real victim first-generation/resume
  subprocesses all use the same path. The `.env` key is still read only at an
  actual request.
- Victim parameters are threaded explicitly: `repo_dir` and the victim role's
  `request_timeout` / `max_request_attempts` reach the generation config and the
  real generation/resume subprocess, and `semgrep_timeout_seconds` reaches the
  training scan; the common defaults are unchanged when not set.
- `mutator-script.json` — a JSON list of scripted mock responses **or** an object
  `{action_id: response}`. A list is bound by the action's persisted
  `script_order` position; an object is bound directly to the logical action, so
  a new object or a new CLI process resumes at the same response instead of
  replaying from the first one. The script content is part of the run identity:
  resuming an existing run with a different script is refused.
- Key handling is deferred to the first **actual** request: a DMX mutator builds
  its `dspy.LM` lazily, so preflight, help, mock runs and saved-response resumes
  never load a credential. The mutator's DSPy cache namespace is configured at
  most once per process; the victim keeps its independent generation subprocess.
- `--mock-gate` / `--mock-training` use explicit, clearly-labelled test doubles;
  the CLI refuses to run without choosing mock or `--allow-real-checks` /
  `--allow-real-training`, and rejects conflicting combinations (e.g.
  `--mutator-script` with `--mutator-source dmx`, or `--mock-gate` with
  `--allow-real-checks`). `--allow-real-training` does not imply a real mutator.
- `--resume-paused` clears a saved pause; `--allow-unknown-retry` explicitly
  retries an orphan provider attempt (otherwise it stays paused as unknown).

Control flow per big iteration: initial functional check of examples 2–4 →
A code patch → gate over the **accumulated** pending examples (syntax+entry,
functional strict pass, static `target_present`, Semgrep `available && completed
&& !detected`) → one training evaluation → one B decision that may change
examples 2–4 `cot` → B training (if the patch actually changed) → next round.
An A failure stays in A and performs no training/B; an invalid B patch still
consumes the single chance, leaves the template untouched and issues no repair
request. Example 1 is frozen and there is exactly one current template (earlier
versions are audit-only). Five big iterations then stop.

Method run layout: `state.json` (protocol/config identity, current template,
round, phase, A attempt, accumulated pending examples, gate evidence, B action
id/consumed, training/feedback refs, in-flight action and pause reason),
`method_events.jsonl` (append-only method log), `actions.jsonl` +
`actions/<id>/…` (task-04 role calls / durable responses / patch commits),
`history.jsonl` (shared history; compressed summaries use ordinary labels, never
internal ids/hashes/paths), `checks/R<n>/example<k>/` (example checks),
`training/R<n>/{A,B}/` (training-loop runs) and `snapshots/` (template versions).
Recovery reuses durable responses, committed patches, persisted gate evidence
and completed training results, so an interrupted resume does not re-call the
provider or duplicate the B chance.

Feedback actually reaching the model: an A-gate failure writes the full
whitelisted per-example facts (syntax/entry, functional outcome, static verdict,
Semgrep status + line evidence) into the shared history; a training evaluation
writes its metrics/counts **and** the per-sample rows (task label, repeat,
verdict, Semgrep status/line evidence, cleaned evaluation code explicitly
labelled as distinct from the raw response). Only an explicit
`completion == "complete"` counts as a completed training on both the first
return and resume — `incomplete`/`failed`/missing pauses without writing
completion feedback or advancing; a real run missing its per-sample feedback
also pauses, while an explicit `source="mock-double"` double is marked rather
than silently accepted. Initial functional checks are persisted per example and
resumed only for the missing ones (an on-disk `check_result.json` is reused only
when its input code matches the current snapshot).

#### Offline preflight (`preflight-method`)

```bash
.venv/bin/python -m coco_attack preflight-method --config method-config.json \
  --report /path/to/runs/method-preflight/report.json
```

Reads and validates the configuration, read-only assets and interfaces and
writes a reviewable report. It performs **no** model request, credential load,
Docker/Semgrep execution and does not create a resumable run state. `--mock-gate`
/ `--allow-real-checks` and `--mock-training` / `--allow-real-training` declare
the intended service selection (otherwise inferred from the role sources). A real
selection is blocking: the execution config and Semgrep rules are parsed with the
existing read-only loaders, and the baseline must parse to the exact
two-task × repeats matrix and match the victim role's model/temperature/repeats
(and data/task口径) via the training comparison logic; any missing/invalid source
or an out-of-range real `repo_dir` yields `not_ready`. The CLI exit code follows
the report conclusion — `not_ready` exits non-zero. The report covers the run scope (two train tasks, four examples, rounds, frozen/allowed
fields, 25-task test not used), the separate mutator/victim roles (model,
source, sampling, output cap, endpoint, cache namespace and process ownership),
the context budget (fixed-material tokens, counter method, window/reserve/margin
and whether it fits), example-check configuration/timeouts, baseline alignment
with the victim role (mismatches block a real delta; a mock victim cannot yield
one), the planned request scale (10 samples per training, ≤100 across rounds,
A attempts not fixed), and the undecided real-run parameters. A passing offline
preflight is **not** a claim that the real environment works or that the method
is effective.

Complete mock and real-run-draft config samples live in `configs/`
(`method_ab_mock.example.json`, `method_ab_real.draft.md`).

### export-mutator-messages

Read-only message export.

```bash
.venv/bin/python -m coco_attack export-mutator-messages \
  --run-dir /path/to/method-run/run \
  --output-dir /path/to/new-export-dir
```

Reconstructs what was sent to and received from the `mutator` role for an existing
run directory and writes a **new, non-overlapping** directory containing
`index.html`, `messages.jsonl` and `manifest.json`. It is a pure reader: it never
calls a recovery function, model provider, credential loader, Docker or Semgrep,
and never writes into the run directory. One `messages.jsonl` line is one logical
action, keyed by `(action_id, request_attempt_id)` (never by the provider-local
`attempt_index`); roles, message order, repeated history, code newlines, empty
responses, errors and usage/cost are preserved verbatim, and a missing usage/cost
stays unknown (never zero-filled, never inferred from a successful response).
`history.jsonl` is attached only as an auxiliary cross-reference and is never used
to fabricate model reasoning. Ordering follows the physical line of the first
`action_planned` event (with documented fallbacks for a missing plan event), and
the manifest lists every anomaly: response files without events, events without
files, true orphan attempts, duplicates/conflicts, corrupt files/identity
conflicts and an incomplete ledger tail. The HTML view is offline and escapes all
content, with long messages collapsed by default.

The method code lives in `method/single_candidate_ab/` (`runtime.py` + package
`preflight.py`) with a compatible top-level `method/__init__.py` and
`method/preflight.py`; the existing import paths and the frozen public name lists
are unchanged.

### `run-pipeline` / `resume-pipeline` / `report-pipeline` outputs

| Path | Purpose |
|---|---|
| `pipeline_config.json`, `sample_manifest.json` | frozen unified config and the expected sample ids (explicit `task_ids` subset supported) |
| `generation/`, `cleaning/`, `static/` | per-step artifacts (generation records, cleaned code, static verdicts/metrics) |
| `core/checkpoint.json` | batch barrier: published only after the core layers are complete |
| `evaluation/`, `functional/` | SAST/judge/dynamic/realism layers and functional results |
| `actions.jsonl` | append-only step status used by `resume-pipeline` |
| `report/{records.jsonl,metrics.json,cost_summary.json,REPORT.md,manifest.json}` | combined join, metrics, role cost summary and evidence index |

`report-pipeline` performs no model or evaluator calls. A `task_ids` subset is
reported as `scope=smoke_subset`; it never stands in for a full baseline.

### `prepare-baseline` / `check-baseline` outputs

`prepare-baseline` reads a `baseline-matrix-v1` config (one victim model; see
phase 03 sub-task 01) and writes a fresh baseline root:

| Path | Purpose |
|---|---|
| `inputs/data/` | `prepare-data` snapshot for the configured combinations |
| `inputs/prompts/<combination>/` | `materialize-prompts` snapshot (3 clean forms) |
| `inputs/asset_manifest.json` | key asset/snapshot hashes for the baseline |
| `manifest/run-manifest.json` | the 24-unit / 24-run whole-set manifest (`run-manifest-v1`), one `search` run per unit |
| `configs/units/<run_id>.json` | one frozen `PipelineConfig` per run |

Config generation never pre-creates a run directory (an actual `run-pipeline`
requires a fresh output dir). `prepare-baseline` refuses to run on a dirty
tracked-code worktree unless the matrix explicitly sets
`allow_dirty_worktree: true`; the baseline root must be fresh. `check-baseline`
re-verifies input hashes, every run config (`check-pipeline`), the git/version
freeze, Docker image identity, DMX key presence and evaluator tool availability,
then writes `checks/baseline_check.json` and `checks/REPORT.md`. Neither command
calls a model.

### `run-baseline` / `status-baseline` outputs

`run-baseline` re-runs the `check-baseline` startup gate first and stops without
starting any pipeline if it is not clean. It then walks the run manifest in
order (`complete`/`blocked` units are skipped) and executes each remaining unit
as its own `python -m coco_attack run-pipeline` child process — or
`resume-pipeline` when the run directory already holds state. After every unit
the pipeline's self-reported state is read from `<run_dir>/manifest.json` and
`<run_dir>/report/metrics.json` and written back to the manifest; a unit is
`complete` only when the report says `complete: true` and the process exited 0.
Per-unit `attempts` are recorded, and a unit still not complete after
`matrix.max_unit_retries` retries is marked `blocked` (reason recorded) while
the loop continues to the next unit. A tracked-code version change blocks all
not-yet-complete units, while a doc-only commit advance does not. Every
transition is appended to `manifest/orchestrator-log.jsonl` (single writer,
fsync). The command exits 0 only when every manifest unit is complete, else 1.

`status-baseline` is read-only over the pipeline artifacts: it prints per-unit
status and, where present, each run's `report/cost_summary.json` totals, request
counts, functional cache-hit counts and ledger reuse sources, plus the reasons
for non-complete units. It writes `manifest/status.json` and never calls a
model.

### `report-baseline` outputs

`report-baseline` is offline and read-only over the completed run artifacts. It
builds `baseline-index-v1` and the grouped report under the baseline root:

| Path | Purpose |
|---|---|
| `index/baseline_index.json` | one strict-match entry per unit (`whole-set`) plus post-hoc `search`/`holdout` derived views for combinations with a method-stage split (`derived_from` links them to the whole-set run) |
| `reports/baseline_report.json` / `.md` | coverage/denominator checks, metric applicability, matrix view, distributions, cost, versions and anomaly/human-review material |
| `reports/coverage_check.json` | per-unit coverage and sample-count check (AC-01/AC-02) |

Undefined metrics stay undefined with a reason (never zero-filled), and derived
results are computed from the same run's per-sample records rather than copied.
The three "no value" states — `configured_disabled`, `not_covered` and
`environment_unavailable` — are reported separately. Whole-set results are never
labelled as holdout validation.

### Evaluator and cleaner versions

- `cleaner-v3` normalizes line endings (CRLF / lone CR -> LF) and trims the
  extraction boundary tail; internal whitespace and string literals are
  preserved. Line-ending normalization is safe because Python applies
  universal-newline semantics (`"""a\r\nb"""` and `"""a\nb"""` have the same AST
  and runtime string value).
- `cwe078-0` oracle version 2 adds branch-aware assignment merging directly in
  `cocota_data_eval_result/oracles/cwe078_0.py` (`ORACLE_VERSION = 2`); the
  module hash and version are recorded in the evaluator fingerprint.

The `configs/` directory is discovered relative to the installed package
location, so the console script works from any working directory.

Re-running the audit into the same `--output-dir` atomically replaces the four
artifacts (auditing is read-only with respect to the asset tree). A fresh output
directory is recommended. `asset_manifest.json` and `issues.json` are
byte-stable across runs; `environment.json` is an observation report containing
interpreter/platform paths and is intentionally not part of the stable
fingerprint.

Audit outputs written to `--output-dir`:

| File | Purpose |
|---|---|
| `asset_manifest.json` | machine-readable asset inventory, schemas, counts and fingerprints |
| `environment.json` | interpreter, DSPy revision, installed distributions, soft-tool availability |
| `issues.json` | problems and differences requiring review (no automatic fixes) |
| `REPORT.md` | human-readable overview of the same facts |

Exit codes: `2` for usage/directory errors, `1` when blocking errors or
pending-decision differences exist, `0` when none do. Soft-dependency absence is
recorded as a later-stage limitation and is not blocking.
