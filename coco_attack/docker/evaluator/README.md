# Evaluation image (`docker/evaluator/`)

Minimal build context for the per-sample evaluation container used by the
Docker execution-isolation service (phase 02, task 01).

## What the image contains

- `python:3.14-slim` (digest supplied at build time), pinned runtime packages
  from `requirements-eval.lock` (candidate; not build-verified on this host).
- `/opt/coco/entrypoint.py` — container-side PID 1 supervisor.
- `/opt/coco/probe_runner.py` — the fixed isolation/ dependency probes.

It deliberately contains **no** DSPy, repository checkout, model credentials,
`.env`, task data or Docker socket.

## Build

```bash
# 1. Resolve the real base digest first (network build-time only):
docker pull python:3.14-slim
docker image inspect --format '{{index .RepoDigests 0}}' python:3.14-slim

# 2. Build with that digest:
./build.sh python:3.14-slim@sha256:<actual-digest> coco-attack-evaluator:0.1.0
```

`build.sh` refuses a base reference that is not digest-pinned and prints the
resulting local `sha256:` image id. Record that id in the execution profile
(the all-zero placeholder is resolved by `coco-attack check-execution`).

## Runner contract

The trusted host supervisor starts the container with the registered entry argv
and these mounts:

| Container path | Source | Mode |
| --- | --- | --- |
| `/in` | per-attempt staging dir (`request.json`) | read-only |
| `/out` | per-attempt output dir (`payload.json`, `result.json`) | writable |
| `/tmp`, `/work`, `/dev/shm` | tmpfs, size-bounded | writable |

The entrypoint runs the child in its own process group, forwards `SIGTERM`,
escalates to `SIGKILL` after `--grace` seconds, and publishes a result envelope
atomically to `/out/result.json`. `--grace` MUST be smaller than the host
profile's `timeouts.sigterm_grace_seconds` so the envelope is written before
Docker kills PID 1.

## Status

The image has been built and exercised on a real Docker daemon (see the
stage-02 `验收记录.md` §9): `check-execution` passes and all eight
`verify-isolation` probes pass, with the container's actual `HostConfig`/mounts
verified from `docker inspect` and the result envelope bound by a host nonce.

`requirements-eval.lock` is now a **fully-resolved, hash-pinned** lock (all
transitive dependencies included) and is installed with
`pip install --require-hashes`. `build.sh` records `build_manifest.json`
(base reference, image id, context file hashes).

The per-execution output area is the host pre-mounted, size-bounded tmpfs
configured in `ExecutionProfile.output_tmpfs` (validated by `check-execution`
for capacity, inode count and memory budget). Results are archived to the
persistent run directory before the tmpfs area is released; a host reboot may
lose unarchived results, and recovery re-runs those samples.
