# Real-run configuration draft (task 06) — NOT runnable as-is

This is a **draft**, not a request to start a run. The user selected mutator
`deepseek-v4.1-flash` and victim `deepseek-v3.2` (phase-04 D05).
The local saved DMX model list spells the victim `DeepSeek-V3.2`, matching the
existing baseline. With the existing DSPy OpenAI-compatible routing, the config
names are `openai/deepseek-v4.1-flash` and `openai/DeepSeek-V3.2`.
The `openai/` prefix selects the API adapter; the endpoint remains DMX.

Mutator parameters are now selected (phase-04 D06): temperature 0.7,
context budget 32768, max output/reserve 8192, margin 0. The concrete local config
and passing read-only preflight are in
`cocota_runs/phase04/method-ab-flash-v32-preflight-20260923/` (phase-04 E28).
This generic Markdown sample still has path placeholders and cannot be passed
directly to the config loader. No real run has started.

```bash
# 1. Offline preflight first (no key, no model, no Docker/Semgrep)
.venv/bin/python -m coco_attack preflight-method \
  --config configs/method-ab-real.json \
  --report /path/to/runs/method-preflight/report.json

# 2. Only after the user fixes the undecided parameters:
.venv/bin/python -m coco_attack run-method-ab \
  --config configs/method-ab-real.json \
  --mutator-source dmx --repo-dir /path/to/repo \
  --allow-real-checks --allow-real-training \
  --report /path/to/runs/method-ab/report.json

# Resume (saved responses are reused without loading a key or re-requesting)
.venv/bin/python -m coco_attack run-method-ab \
  --config configs/method-ab-real.json \
  --mutator-source dmx --repo-dir /path/to/repo \
  --allow-real-checks --allow-real-training \
  --resume-paused --report /path/to/runs/method-ab/report.json
```

Draft JSON (the `<...>` values are the undecided items). Paths follow the
phase-04 convention `cocota_runs/phase04/methods/single_candidate_ab/runs/<run_name>/`
(config, preflight and `run/` together under one method run root):

```json
{
  "run_dir": "cocota_runs/phase04/methods/single_candidate_ab/runs/method-ab-real/run",
  "snapshot_path": "cocota_runs/phase04/methods/single_candidate_ab/runs/method-ab-real/snapshots/cwe078-0/<c0-content-sha256>",
  "snapshot_store": "cocota_runs/phase04/methods/single_candidate_ab/runs/method-ab-real/snapshots",
  "assets_root": "<ASSETS_ROOT>/cocota_data_eval_result",
  "data_dir": "<STAGE03_ROOT>/inputs/data",
  "repo_dir": "<REPO_ROOT>",
  "max_rounds": 5,
  "semgrep_config": "<ASSETS_ROOT>/cocota_data_eval_result/third_party/semgrep",
  "mutator": {
    "source": "dmx",
    "model": "openai/deepseek-v4.1-flash",
    "temperature": 0.7,
    "max_tokens": 8192,
    "context_window_tokens": 32768,
    "output_reserve_tokens": 8192,
    "context_margin_tokens": 0
  },
  "victim": {
    "source": "dmx",
    "model": "openai/DeepSeek-V3.2",
    "temperature": 0.7,
    "repeats": 5,
    "max_tokens": 8192
  }
}
```

`repo_dir` may be supplied either in the JSON or via `--repo-dir`, but not both
with different values (rejected before execution). It is the single effective
path used by the mutator key loader and the victim generation/resume subprocess;
the `.env` key is still only read at an actual request.

## Remaining execution boundary

Model selection and this run's token budget are fixed (D05/D06). The configured
32768 is a run budget, not a claim about provider capacity. Baseline identity and
the exact two-task matrix passed the offline preflight (E28); warnings remain in
the report. Actual Docker/Semgrep availability and real requests have not been
checked in this preparation. The user requested configuration and preflight only.
