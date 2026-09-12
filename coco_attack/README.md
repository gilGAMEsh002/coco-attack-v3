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
