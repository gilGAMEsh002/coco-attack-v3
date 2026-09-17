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
| `manifest/run-manifest.json` | the 24-unit / 30-run manifest (`run-manifest-v1`) |
| `configs/units/<run_id>.json` | one frozen `PipelineConfig` per run |
| `locks/baseline-lock.json` | cwe078 template/config lock (`baseline-lock-v1`) |

Config generation never pre-creates a run directory (an actual `run-pipeline`
requires a fresh output dir). `prepare-baseline` refuses to run on a dirty
tracked-code worktree unless the matrix explicitly sets
`allow_dirty_worktree: true`; the baseline root must be fresh. `check-baseline`
re-verifies input hashes, every run config (`check-pipeline`), the git/version
freeze, Docker image identity, DMX key presence and evaluator tool availability,
then writes `checks/baseline_check.json` and `checks/REPORT.md`. Neither command
calls a model.

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
