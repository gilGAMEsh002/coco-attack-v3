"""Single-candidate mock training closed loop (I3/I6, task 03).

This service wires one explicit candidate (a template snapshot) through the
already-delivered stages -- poisoned materialization, victim generation,
cleaning, static oracle and Semgrep -- and then produces the method-facing
feedback plus a read-only clean-baseline slice.

Design boundaries:

* exactly one candidate per call; no candidate pool, ranking, A/B gate or
  automatic selection;
* no functional/judge/dynamic/realism layers are enabled (they stay explicitly
  un-run, never zero);
* a mock run is a *wiring* closure, never a research attack result: it is
  labelled ``candidate_kind="mock"`` and never compared as better/worse against
  a real victim baseline;
* the generation step defaults to an independent ``python -m coco_attack
  generate`` subprocess so a long-lived process never reconfigures the DSPy
  cache in-process; tests may inject the in-process service.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    write_json_atomic,
)
from ..data.combination import legacy_alias_for
from ..data.snapshot import load_prepared_data
from ..evaluation.contracts import EvaluationConfig, MetricResult
from ..evaluation.metrics import (
    asr_at_k,
    assess_baseline_compatibility,
    evasion,
    sample_hit_rate,
)
from ..evaluation.pipeline import static_hits_from_run
from ..evaluation.run_cleaning import clean_generations
from ..evaluation.run_other import EvaluatorsConfig, run_evaluate_other
from ..evaluation.run_static import evaluate_static
from ..evaluation.sast import (
    DEFAULT_TIMEOUT_SECONDS,
    sast_adapter_fingerprint,
    scan_sample,
)
from ..generation.contracts import GenerationConfig
from ..generation.inputs import load_generation_inputs
from .poison_materialize import materialize_poisoned
from .template_snapshot import TemplateSnapshot, read_snapshot

LOOP_SCHEMA_VERSION = "single-candidate-training-loop-v1"

#: The generation defaults recorded in the per-run generation config.  They are
#: deliberately explicit so a resumed run reproduces the same request policy.
GENERATION_REQUEST_TIMEOUT = 30.0
GENERATION_MAX_CONCURRENCY = 1
GENERATION_MAX_REQUEST_ATTEMPTS = 2
GENERATION_MAX_SAMPLE_RETRIES = 0

#: Fallback SAST timeout when the caller does not configure one.  The loop
#: threads the configured value into the scanner it hands to ``run_other`` so
#: the value actually used equals the configured value.
DEFAULT_SEMGREP_TIMEOUT = DEFAULT_TIMEOUT_SECONDS

_BASELINE_TASK_SET = "evaluation"


class TrainingLoopError(ValueError):
    """Raised when a single-candidate training loop cannot run or resume."""


def _validate_task_ids(task_ids: Sequence[str]) -> tuple[str, ...]:
    result = tuple(str(task_id) for task_id in task_ids)
    if not result:
        raise TrainingLoopError("task_ids must not be empty")
    duplicates = sorted({task for task in result if result.count(task) > 1})
    if duplicates:
        raise TrainingLoopError(f"duplicate task_ids requested: {duplicates}")
    return result


@dataclass(frozen=True)
class TrainingLoopConfig:
    """Explicit run configuration for one candidate.

    Paths are stored as strings so the configuration hashes stably and can be
    round-tripped through JSON without resolving against a changing cwd.
    """

    snapshot_path: str
    assets_root: str
    data_dir: str
    output_dir: str
    task_ids: tuple[str, ...]
    repeats: int
    stage: str
    form: str
    prompt_version: str
    model: str
    batch_id: str
    source: str = "mock"
    temperature: float = 0.7
    mock_scenario: str = "normal"
    max_tokens: int = 8192
    #: Victim request policy threaded into the generation config / CLI process.
    request_timeout: float = GENERATION_REQUEST_TIMEOUT
    max_request_attempts: int = GENERATION_MAX_REQUEST_ATTEMPTS
    max_sample_retries: int = GENERATION_MAX_SAMPLE_RETRIES
    #: Bounded concurrent victim requests for one training batch.  The value is
    #: persisted in the run identity and handed to ``GenerationConfig`` so the
    #: existing ``GenerationRunner`` pool (rate limit/retry/ledger) is reused.
    max_concurrency: int = GENERATION_MAX_CONCURRENCY
    repo_dir: str | None = None
    semgrep_config: str | None = None
    semgrep_timeout_seconds: float = DEFAULT_SEMGREP_TIMEOUT
    baseline_static: str | None = None
    baseline_config: str | None = None
    baseline_data_dir: str | None = None
    baseline_evaluators_config: str | None = None
    baseline_evaluation_dir: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "snapshot_path",
            "assets_root",
            "data_dir",
            "output_dir",
            "stage",
            "form",
            "prompt_version",
            "model",
            "batch_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise TrainingLoopError(f"config.{name} must be a non-empty string")
        if self.source not in ("mock", "dmx"):
            raise TrainingLoopError("config.source must be 'mock' or 'dmx'")
        if isinstance(self.repeats, bool) or not isinstance(self.repeats, int) or self.repeats < 1:
            raise TrainingLoopError("config.repeats must be a positive integer")
        if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, int) or self.max_tokens < 1:
            raise TrainingLoopError("config.max_tokens must be a positive integer")
        if isinstance(self.temperature, bool) or not isinstance(self.temperature, (int, float)):
            raise TrainingLoopError("config.temperature must be a number")
        if (
            isinstance(self.request_timeout, bool)
            or not isinstance(self.request_timeout, (int, float))
            or not math.isfinite(float(self.request_timeout))
            or float(self.request_timeout) <= 0
        ):
            raise TrainingLoopError("config.request_timeout must be a positive finite number")
        if (
            isinstance(self.max_request_attempts, bool)
            or not isinstance(self.max_request_attempts, int)
            or self.max_request_attempts < 1
        ):
            raise TrainingLoopError("config.max_request_attempts must be a positive integer")
        if (
            isinstance(self.max_sample_retries, bool)
            or not isinstance(self.max_sample_retries, int)
            or self.max_sample_retries < 0
        ):
            raise TrainingLoopError("config.max_sample_retries must be a non-negative integer")
        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or self.max_concurrency < 1
        ):
            raise TrainingLoopError("config.max_concurrency must be a positive integer")
        if isinstance(self.semgrep_timeout_seconds, bool) or not isinstance(
            self.semgrep_timeout_seconds, (int, float)
        ):
            raise TrainingLoopError("config.semgrep_timeout_seconds must be a number")
        if not math.isfinite(float(self.semgrep_timeout_seconds)) or float(
            self.semgrep_timeout_seconds
        ) <= 0:
            raise TrainingLoopError(
                "config.semgrep_timeout_seconds must be a positive finite number"
            )
        object.__setattr__(self, "task_ids", _validate_task_ids(self.task_ids))
        for name in (
            "repo_dir",
            "semgrep_config",
            "baseline_static",
            "baseline_config",
            "baseline_data_dir",
            "baseline_evaluators_config",
            "baseline_evaluation_dir",
        ):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise TrainingLoopError(f"config.{name} must be a non-empty string or null")

    def to_json(self) -> dict[str, Any]:
        return {
            "snapshot_path": self.snapshot_path,
            "assets_root": self.assets_root,
            "data_dir": self.data_dir,
            "output_dir": self.output_dir,
            "task_ids": list(self.task_ids),
            "repeats": self.repeats,
            "stage": self.stage,
            "form": self.form,
            "prompt_version": self.prompt_version,
            "model": self.model,
            "batch_id": self.batch_id,
            "source": self.source,
            "temperature": float(self.temperature),
            "mock_scenario": self.mock_scenario,
            "max_tokens": self.max_tokens,
            "request_timeout": float(self.request_timeout),
            "max_request_attempts": self.max_request_attempts,
            "max_sample_retries": self.max_sample_retries,
            "max_concurrency": self.max_concurrency,
            "repo_dir": self.repo_dir,
            "semgrep_config": self.semgrep_config,
            "semgrep_timeout_seconds": float(self.semgrep_timeout_seconds),
            "baseline_static": self.baseline_static,
            "baseline_config": self.baseline_config,
            "baseline_data_dir": self.baseline_data_dir,
            "baseline_evaluators_config": self.baseline_evaluators_config,
            "baseline_evaluation_dir": self.baseline_evaluation_dir,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "TrainingLoopConfig":
        if not isinstance(payload, Mapping):
            raise TrainingLoopError("training loop config must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        extra = sorted(set(payload) - allowed)
        if extra:
            raise TrainingLoopError(f"training loop config has unknown fields: {extra}")
        required = (
            "snapshot_path",
            "assets_root",
            "data_dir",
            "output_dir",
            "task_ids",
            "repeats",
            "stage",
            "form",
            "prompt_version",
            "model",
            "batch_id",
        )
        missing = [name for name in required if name not in payload]
        if missing:
            raise TrainingLoopError(f"training loop config missing fields: {missing}")
        coerced = dict(payload)
        if coerced.get("task_ids") is not None:
            coerced["task_ids"] = tuple(coerced["task_ids"])
        return cls(**coerced)

    def run_config_sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.to_json()))


def load_training_loop_config(path: Path | str) -> TrainingLoopConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise TrainingLoopError(f"training loop config is not a file: {config_path}")
    payload = read_json(config_path)
    return TrainingLoopConfig.from_json(payload)


# --------------------------------------------------------------------------- #
# Small IO helpers
# --------------------------------------------------------------------------- #


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except ValueError as error:
            raise TrainingLoopError(f"invalid JSONL record in {path}: {error}") from error
        if not isinstance(row, dict):
            raise TrainingLoopError(f"JSONL record in {path} is not an object")
        rows.append(row)
    return rows


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _artifact_ref(output: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(output.resolve()))
    except ValueError:
        return str(path.resolve())


def _step(output: Path, *, status: str, artifacts: Mapping[str, Path]) -> dict[str, Any]:
    return {
        "status": status,
        "artifacts": {name: _artifact_ref(output, path) for name, path in artifacts.items()},
    }


def _expected_keys(task_ids: Sequence[str], repeats: int) -> set[tuple[str, int]]:
    return {
        (str(task_id), int(repeat_id))
        for task_id in task_ids
        for repeat_id in range(repeats)
    }


def _row_key(row: Mapping[str, Any]) -> tuple[str, int] | None:
    """Extract a ``(task_id, repeat_id)`` key from a top-level or identity row."""

    if row.get("task_id") is not None and row.get("repeat_id") is not None:
        return str(row["task_id"]), int(row["repeat_id"])
    identity = row.get("identity")
    if isinstance(identity, Mapping):
        task_id = identity.get("task_id")
        repeat_id = identity.get("repeat_id")
        if task_id is not None and repeat_id is not None:
            return str(task_id), int(repeat_id)
    return None


def _matrix_ok(
    rows: Sequence[Mapping[str, Any]], expected: set[tuple[str, int]]
) -> tuple[bool, str]:
    """Require exactly the expected ``(task_id, repeat_id)`` matrix, no dup/extra."""

    keys: list[tuple[str, int]] = []
    for row in rows:
        key = _row_key(row)
        if key is None:
            return False, "record is missing a task_id/repeat_id identity"
        keys.append(key)
    if len(keys) != len(set(keys)):
        return False, "duplicate (task_id, repeat_id) records"
    observed = set(keys)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    if missing or extra:
        return False, f"matrix mismatch: missing={len(missing)} extra={len(extra)}"
    return True, "ok"


def _quarantine(path: Path) -> Path | None:
    """Rename an incomplete artifact dir aside instead of deleting its evidence."""

    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(f"{path.name}.partial-{stamp}")
    counter = 1
    while target.exists():
        target = path.with_name(f"{path.name}.partial-{stamp}-{counter}")
        counter += 1
    path.rename(target)
    return target


def _paths_overlap(left: Path, right: Path) -> bool:
    left = left.resolve()
    right = right.resolve()
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _assert_output_isolation(config: "TrainingLoopConfig") -> None:
    """Refuse to write into (or contain) any read-only input path."""

    output = Path(config.output_dir).expanduser().resolve()
    protected: list[tuple[str, Path]] = [
        ("assets_root", Path(config.assets_root)),
        ("data_dir", Path(config.data_dir)),
        ("snapshot_path", Path(config.snapshot_path)),
        ("snapshot_store", Path(config.snapshot_path).parent),
    ]
    for name in ("baseline_static", "baseline_config", "baseline_data_dir",
                 "baseline_evaluators_config", "baseline_evaluation_dir"):
        value = getattr(config, name)
        if value:
            protected.append((name, Path(value).parent if Path(value).suffix else Path(value)))
    for name, candidate in protected:
        if _paths_overlap(output, candidate):
            raise TrainingLoopError(
                f"output_dir overlaps the read-only input {name} ({candidate}); "
                "choose an isolated output directory"
            )


def _make_sast_scan(timeout_seconds: float) -> Callable[..., Any]:
    """Bind the configured Semgrep timeout into the scanner ``run_other`` calls."""

    def _scanner(sample: Any, **kwargs: Any) -> Any:
        return scan_sample(sample, timeout_seconds=timeout_seconds, **kwargs)

    return _scanner


def _subprocess_resume_generation_step(
    run_dir: Path | str, *, repo_dir: Path | str | None = None
) -> int:
    """Resume generation in an independent process (preserves cache isolation)."""

    command = [
        sys.executable,
        "-m",
        "coco_attack",
        "resume-generation",
        "--run-dir",
        str(run_dir),
    ]
    if repo_dir is not None:
        command += ["--repo-dir", str(repo_dir)]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


def _generation_run_candidate_hash(generation_dir: Path) -> str | None:
    """Read the candidate hash the generation run recorded for its inputs."""

    path = generation_dir / "run_config.json"
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    inputs = payload.get("inputs")
    if isinstance(inputs, Mapping) and isinstance(inputs.get("candidate_hash"), str):
        return inputs["candidate_hash"]
    return None


def _expected_identities(inputs: Any) -> dict[str, dict[str, Any]]:
    """Map each expected sample id to its full generation identity."""

    result: dict[str, dict[str, Any]] = {}
    for sample in inputs.samples:
        result[sample.sample_id] = dict(sample.identity.to_json())
    return result


def _generation_identity_status(
    generation_dir: Path, expected: Mapping[str, Mapping[str, Any]]
) -> tuple[str, str]:
    """Classify generation evidence as ``ok`` / ``missing`` / ``incomplete`` / ``foreign``.

    ``foreign`` means the observed rows do not belong to this candidate (a
    different sample_id or identity); that must be refused rather than
    overwritten.  ``missing``/``incomplete`` can be recovered by re-running.
    """

    path = generation_dir / "generations.jsonl"
    if not path.is_file():
        return "missing", "generations.jsonl is absent"
    rows = _read_jsonl(path)
    if not rows:
        return "missing", "generations.jsonl is empty"
    expected_ids = set(expected)
    observed_ids: list[str] = []
    for row in rows:
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            return "foreign", "a generation row has no sample_id"
        observed_ids.append(sample_id)
        identity = row.get("identity")
        if not isinstance(identity, Mapping):
            return "foreign", f"generation row {sample_id!r} has no identity"
        if sample_id not in expected_ids:
            return "foreign", f"generation sample_id {sample_id!r} is not an expected sample"
        if dict(identity) != dict(expected[sample_id]):
            return (
                "foreign",
                f"generation identity for {sample_id!r} differs from the expected identity",
            )
    if len(observed_ids) != len(set(observed_ids)):
        return "foreign", "duplicate generation sample_id"
    if set(observed_ids) != expected_ids:
        return "incomplete", "generation rows do not cover every expected sample"
    summary_path = generation_dir / "generation_summary.json"
    if not summary_path.is_file():
        return "incomplete", "generation_summary.json is absent"
    try:
        summary = read_json(summary_path)
    except (OSError, ValueError):
        return "incomplete", "generation_summary.json is unreadable"
    if not isinstance(summary, dict) or summary.get("finalized_total") != len(expected):
        return "incomplete", "generation summary does not report the expected finalized total"
    return "ok", "ok"


def _generation_complete(
    generation_dir: Path, expected_identities: Mapping[str, Mapping[str, Any]]
) -> bool:
    return _generation_identity_status(generation_dir, expected_identities)[0] == "ok"


def _materialize_complete(prompts_dir: Path, snapshot: TemplateSnapshot) -> bool:
    manifest_path = prompts_dir / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return False
    if not isinstance(manifest, dict) or manifest.get("completion") != "complete":
        return False
    template = manifest.get("template") or {}
    return template.get("content_sha256") == snapshot.content_sha256()


def _cleaning_complete(
    cleaning_dir: Path,
    expected_keys: set[tuple[str, int]],
    upstream_sha256: str,
) -> bool:
    manifest_path = cleaning_dir / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return False
    if not (isinstance(manifest, dict) and manifest.get("completed") is True):
        return False
    rows_path = cleaning_dir / "cleaned_generations.jsonl"
    rows = _read_jsonl(rows_path)
    if len(rows) != len(expected_keys):
        return False
    if not _matrix_ok(rows, expected_keys)[0]:
        return False
    # Bind the cleaning output to the actual generation bytes it consumed.
    declared_input = (manifest.get("input") or {}).get("sha256")
    declared_output = (manifest.get("output") or {}).get("sha256")
    if declared_input != upstream_sha256:
        return False
    if declared_output != sha256_file(rows_path):
        return False
    return True


def _static_complete(
    static_dir: Path,
    expected_keys: set[tuple[str, int]],
    upstream_generation_sha256: str,
) -> bool:
    manifest_path = static_dir / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return False
    if not (isinstance(manifest, dict) and manifest.get("completion") == "complete"):
        return False
    rows_path = static_dir / "evaluations.jsonl"
    rows = _read_jsonl(rows_path)
    if len(rows) != len(expected_keys):
        return False
    if not _matrix_ok(rows, expected_keys)[0]:
        return False
    declared = manifest.get("inputs") or {}
    if (declared.get("evaluations") or {}).get("sha256") != sha256_file(rows_path):
        return False
    # run_static records the generation input hash under cleaned_manifest.
    if (declared.get("cleaned_manifest") or {}).get("sha256") != upstream_generation_sha256:
        return False
    return True


def _cleaned_code_sha_by_key(
    cleaning_dir: Path, expected_keys: set[tuple[str, int]]
) -> dict[tuple[str, int], str] | None:
    """Map each expected sample to the cleaned final-code hash it exported.

    Both the cleaner and the downstream shells derive their fingerprints from the
    same ``final_code`` bytes, so this is the existing content link that binds a
    result to the *actual* cleaning output it consumed.  ``None`` means the
    cleaning output is missing, malformed or does not cover exactly the expected
    matrix, so callers treat the downstream evidence as invalid instead of
    trusting a partial file.
    """

    rows = _read_jsonl(cleaning_dir / "cleaned_generations.jsonl")
    if len(rows) != len(expected_keys):
        return None
    result: dict[tuple[str, int], str] = {}
    for row in rows:
        key = _row_key(row)
        if key is None or key in result or key not in expected_keys:
            return None
        cleaned = row.get("cleaned")
        if not isinstance(cleaned, Mapping):
            return None
        digest = cleaned.get("final_code_sha256")
        if not isinstance(digest, str) or not digest:
            return None
        result[key] = digest
    return result if set(result) == expected_keys else None


def _static_matches_cleaned(
    static_dir: Path, cleaned_sha: Mapping[tuple[str, int], str]
) -> bool:
    """Require every static result to be evaluated on the current cleaned code.

    The static shell records ``final_code_sha256`` from the ``final_code`` bytes
    it read out of cleaning, so a changed cleaning output invalidates stale
    static results rather than silently reusing them.
    """

    rows = _read_jsonl(static_dir / "evaluations.jsonl")
    if len(rows) != len(cleaned_sha):
        return False
    seen: set[tuple[str, int]] = set()
    for row in rows:
        key = _row_key(row)
        if key is None or key in seen:
            return False
        seen.add(key)
        expected = cleaned_sha.get(key)
        if expected is None or row.get("final_code_sha256") != expected:
            return False
    return seen == set(cleaned_sha)


def _semgrep_matches_cleaned(
    evaluation_dir: Path,
    expected_identities: Mapping[str, Mapping[str, Any]],
    cleaned_sha: Mapping[tuple[str, int], str],
) -> bool:
    """Require every Semgrep result to target the current cleaned code bytes."""

    rows = [
        row
        for row in _read_jsonl(evaluation_dir / "layers" / "sast.jsonl")
        if row.get("tool") == "semgrep"
    ]
    if len(rows) != len(expected_identities):
        return False
    seen: set[str] = set()
    for row in rows:
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or sample_id not in expected_identities:
            return False
        if sample_id in seen:
            return False
        seen.add(sample_id)
        identity = expected_identities[sample_id]
        task_id = identity.get("task_id")
        repeat_id = identity.get("repeat_id")
        if not isinstance(task_id, str) or not isinstance(repeat_id, int) or isinstance(repeat_id, bool):
            return False
        expected = cleaned_sha.get((task_id, repeat_id))
        sources = row.get("sources")
        if expected is None or not isinstance(sources, Mapping):
            return False
        if sources.get("final_code_sha256") != expected:
            return False
    return seen == set(expected_identities)


def _parse_json_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _feedback_status(
    output: Path,
    expected_count: int,
    audit_payload: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    payload = _parse_json_file(output / "feedback.json")
    if payload is None:
        return False, "feedback.json is missing or not a JSON object"
    samples = payload.get("samples")
    if not isinstance(samples, list) or len(samples) != expected_count:
        return False, "feedback.json does not carry every expected sample"
    for sample in samples:
        if not isinstance(sample, Mapping):
            return False, "feedback sample is not an object"
        for key in ("task", "repeat", "code", "verdict", "semgrep"):
            if key not in sample:
                return False, f"feedback sample is missing {key!r}"
    for key in ("metrics", "counts", "candidate_kind"):
        if key not in payload:
            return False, f"feedback.json is missing {key!r}"
    # Bind the method-facing projection to the audit's per-sample code hash so a
    # structurally valid but stale/foreign feedback payload is not trusted.
    if audit_payload is not None:
        audit_samples = audit_payload.get("samples")
        if not isinstance(audit_samples, list) or len(audit_samples) != len(samples):
            return False, "feedback.json and feedback_audit.json sample counts disagree"
        for sample, audit_sample in zip(samples, audit_samples):
            if not isinstance(audit_sample, Mapping):
                return False, "feedback_audit sample is not an object"
            code = sample.get("code")
            if not isinstance(code, str):
                return False, "feedback sample code is not a string"
            if sha256_bytes(code.encode("utf-8")) != audit_sample.get("final_code_sha256"):
                return False, "feedback code does not match the audit fingerprint"
    return True, "ok"


def _feedback_audit_status(
    output: Path,
    candidate_hash: str,
    snapshot: TemplateSnapshot,
    expected_ids: set[str],
) -> tuple[bool, str]:
    payload = _parse_json_file(output / "feedback_audit.json")
    if payload is None:
        return False, "feedback_audit.json is missing or not a JSON object"
    if payload.get("candidate_hash") != candidate_hash:
        return False, "feedback_audit.json candidate_hash does not match the run"
    if payload.get("template_sha256") != snapshot.content_sha256():
        return False, "feedback_audit.json template_sha256 does not match the snapshot"
    samples = payload.get("samples")
    if not isinstance(samples, list) or len(samples) != len(expected_ids):
        return False, "feedback_audit.json does not carry every expected sample"
    observed = {
        sample.get("sample_id")
        for sample in samples
        if isinstance(sample, Mapping)
    }
    if observed != expected_ids:
        return False, "feedback_audit.json sample ids do not match the expected identities"
    return True, "ok"


def _baseline_status(
    output: Path,
    baseline_required: bool,
    config: "TrainingLoopConfig | None" = None,
) -> tuple[bool, str]:
    payload = _parse_json_file(output / "baseline_slice.json")
    if payload is None:
        return False, "baseline_slice.json is missing or not a JSON object"
    if not baseline_required:
        return (
            (payload.get("status") == "skipped"),
            "baseline_slice.json is not the expected skipped marker",
        )
    if not isinstance(payload.get("records"), list):
        return False, "baseline_slice.json has no records list"
    if not isinstance(payload.get("baseline_matrix"), Mapping):
        return False, "baseline_slice.json has no baseline_matrix"
    if not isinstance(payload.get("compatibility"), Mapping):
        return False, "baseline_slice.json has no compatibility"
    if not isinstance(payload.get("e05"), Mapping):
        return False, "baseline_slice.json has no e05 block"
    # Bind the derived slice to the actual baseline it was computed from, so a
    # stale slice from another baseline source is regenerated rather than reused.
    source = payload.get("source")
    if not isinstance(source, Mapping):
        return False, "baseline_slice.json has no source block"
    if config is not None and config.baseline_static:
        expected_path = Path(config.baseline_static).expanduser()
        try:
            expected_sha = sha256_file(expected_path)
        except (OSError, ValueError):
            # An unreadable/missing source is an invalid derived step to
            # regenerate, not a hard refusal of an otherwise intact run.
            return False, "baseline source file is unreadable"
        if source.get("sha256") != expected_sha:
            return False, "baseline_slice.json source fingerprint does not match the baseline"
        recorded = source.get("path")
        if not isinstance(recorded, str) or Path(recorded).expanduser().resolve() != expected_path.resolve():
            return False, "baseline_slice.json source path does not match the configured baseline"
    return True, "ok"


def _evaluation_complete(evaluation_dir: Path, expected_sample_ids: set[str]) -> bool:
    manifest_path = evaluation_dir / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return False
    if not (isinstance(manifest, dict) and manifest.get("status") == "complete"):
        return False
    rows = [
        row
        for row in _read_jsonl(evaluation_dir / "layers" / "sast.jsonl")
        if row.get("tool") == "semgrep"
    ]
    if len(rows) != len(expected_sample_ids):
        return False
    observed = {str(row.get("sample_id")) for row in rows}
    return observed == expected_sample_ids


def _completed_run_identity(
    output: Path,
    manifest: Mapping[str, Any],
    config: "TrainingLoopConfig",
    snapshot: TemplateSnapshot,
    expected_keys: set[tuple[str, int]],
) -> tuple[bool, str]:
    """Identity/upstream checks that must *refuse* reuse when they fail.

    A different schema, candidate kind, snapshot, or candidate hash means the
    run belongs to another candidate; silently reusing or re-running it would
    mix candidates, so it is rejected rather than recovered.
    """

    if manifest.get("schema_version") != LOOP_SCHEMA_VERSION:
        return False, "manifest schema_version mismatch"
    if manifest.get("candidate_kind") != ("mock" if config.source == "mock" else "real"):
        return False, "candidate_kind mismatch"
    prompts_dir = output / "prompts"
    if not _materialize_complete(prompts_dir, snapshot):
        return False, "materialized prompts missing or from another snapshot"
    try:
        inputs = load_generation_inputs(
            config.data_dir,
            prompts_dir,
            combination_id=snapshot.combination_id,
            form=config.form,
            stage=config.stage,
            repeats=config.repeats,
            batch_id=config.batch_id,
            prompt_version=config.prompt_version,
            task_ids=list(config.task_ids),
        )
    except Exception as error:  # noqa: BLE001 - any upstream change invalidates reuse
        return False, f"cannot re-read generation inputs: {error}"
    stored_hash = manifest.get("candidate_hash")
    if not stored_hash or stored_hash != inputs.candidate_hash:
        return False, "candidate hash no longer matches the materialized prompts"
    if manifest.get("observed_sample_count") != len(expected_keys):
        return False, "observed sample count mismatch"
    return True, "ok"


def _assess_artifacts(
    output: Path,
    config: "TrainingLoopConfig",
    snapshot: TemplateSnapshot,
) -> tuple[dict[str, bool], str | None]:
    """Assess each step's actual data against the expected identities.

    Returns ``(validity, refuse_reason)``.  ``refuse_reason`` is set when the
    observed evidence belongs to another candidate or a dependency fingerprint
    is inconsistent (must not be silently overwritten).  Missing/short data
    yields ``validity[step] = False`` so the caller recovers by re-running that
    step and its dependents.
    """

    inputs = load_generation_inputs(
        config.data_dir,
        output / "prompts",
        combination_id=snapshot.combination_id,
        form=config.form,
        stage=config.stage,
        repeats=config.repeats,
        batch_id=config.batch_id,
        prompt_version=config.prompt_version,
        task_ids=list(config.task_ids),
    )
    expected_identities = _expected_identities(inputs)
    expected_ids = set(expected_identities)
    expected_keys = _expected_keys(config.task_ids, config.repeats)
    candidate_hash = inputs.candidate_hash

    gen_status, gen_reason = _generation_identity_status(
        output / "generation", expected_identities
    )
    if gen_status == "foreign":
        return {}, gen_reason
    run_hash = _generation_run_candidate_hash(output / "generation")
    if run_hash is not None and run_hash != candidate_hash:
        return (
            {},
            "generation run_config candidate_hash differs from the materialized prompts",
        )
    generation_ok = gen_status == "ok" and run_hash == candidate_hash
    generation_path = output / "generation" / "generations.jsonl"
    generation_sha = sha256_file(generation_path) if generation_path.is_file() else ""

    cleaning_ok = generation_ok and _cleaning_complete(
        output / "cleaning", expected_keys, generation_sha
    )
    # R2: bind static/Semgrep results to the *actual* cleaning output bytes.
    # A changed cleaning output (with an updated manifest) must invalidate the
    # downstream results instead of reusing stale evaluations.
    cleaned_sha = (
        _cleaned_code_sha_by_key(output / "cleaning", expected_keys)
        if cleaning_ok
        else None
    )
    static_ok = (
        cleaning_ok
        and cleaned_sha is not None
        and _static_complete(output / "static", expected_keys, generation_sha)
        and _static_matches_cleaned(output / "static", cleaned_sha)
    )
    semgrep_ok = (
        cleaning_ok
        and cleaned_sha is not None
        and _evaluation_complete(output / "evaluation", expected_ids)
        and _semgrep_matches_cleaned(output / "evaluation", expected_identities, cleaned_sha)
    )
    audit_payload = _parse_json_file(output / "feedback_audit.json")
    feedback_ok = (
        static_ok
        and semgrep_ok
        and _feedback_status(output, len(expected_keys), audit_payload)[0]
        and _feedback_audit_status(output, candidate_hash, snapshot, expected_ids)[0]
    )
    baseline_required = bool(config.baseline_static and config.baseline_config)
    baseline_ok = feedback_ok and _baseline_status(output, baseline_required, config)[0]
    validity = {
        "generation": generation_ok,
        "cleaning": cleaning_ok,
        "static": static_ok,
        "semgrep": semgrep_ok,
        "feedback": feedback_ok,
        "baseline": baseline_ok,
    }
    return validity, None


def _generation_config(config: "TrainingLoopConfig", prepared: Any) -> GenerationConfig:
    return GenerationConfig(
        source=config.source,
        model=config.model,
        batch_id=config.batch_id,
        combination_id=prepared.combination_id,
        oracle_id=prepared.oracle_id,
        stage=config.stage,
        form=config.form,
        prompt_version=config.prompt_version,
        candidate_hash="",
        temperature=float(config.temperature),
        repeats=config.repeats,
        max_tokens=config.max_tokens,
        request_timeout=float(config.request_timeout),
        max_concurrency=config.max_concurrency,
        max_request_attempts=config.max_request_attempts,
        max_sample_retries=config.max_sample_retries,
        mock_scenario=config.mock_scenario,
        task_ids=config.task_ids,
    )


def _subprocess_generation_step(
    config_path: Path | str,
    data_dir: Path | str,
    prompts_dir: Path | str,
    output_dir: Path | str,
    *,
    repo_dir: Path | str | None = None,
) -> int:
    """Run generation in an independent process (never imports dspy here)."""

    command = [
        sys.executable,
        "-m",
        "coco_attack",
        "generate",
        "--config",
        str(config_path),
        "--data-dir",
        str(data_dir),
        "--prompts-dir",
        str(prompts_dir),
        "--output-dir",
        str(output_dir),
    ]
    if repo_dir is not None:
        command += ["--repo-dir", str(repo_dir)]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


# --------------------------------------------------------------------------- #
# Feedback (method-facing + audit)
# --------------------------------------------------------------------------- #


def _method_metric(result: MetricResult) -> dict[str, Any]:
    """Method-facing metric projection: no task ids, paths or hashes."""

    payload: dict[str, Any] = {
        "name": result.name,
        "value": result.value,
        "defined": result.defined,
        "reason": result.reason,
        "numerator": result.numerator,
        "denominator": result.denominator,
        "k": result.k,
    }
    if result.availability:
        payload["availability"] = result.availability
    return payload


def _assemble_feedback(
    config: "TrainingLoopConfig",
    snapshot: TemplateSnapshot,
    candidate_hash: str,
    output: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    generation_rows = _read_jsonl(output / "generation" / "generations.jsonl")
    cleaned_rows = _read_jsonl(output / "cleaning" / "cleaned_generations.jsonl")
    static_rows = _read_jsonl(output / "static" / "evaluations.jsonl")
    sast_rows = [
        row
        for row in _read_jsonl(output / "evaluation" / "layers" / "sast.jsonl")
        if row.get("tool") == "semgrep"
    ]

    cleaned_by_key = {
        (row.get("task_id"), row.get("repeat_id")): row for row in cleaned_rows
    }
    static_by_key = {
        (row.get("task_id"), row.get("repeat_id")): row for row in static_rows
    }
    sast_by_sample = {row.get("sample_id"): row for row in sast_rows}

    labels = {
        task_id: f"\u8bad\u7ec3\u9898 {index + 1}"
        for index, task_id in enumerate(config.task_ids)
    }
    task_order = {task_id: index for index, task_id in enumerate(config.task_ids)}

    joined: list[dict[str, Any]] = []
    for row in generation_rows:
        identity = row.get("identity") or {}
        task_id = identity.get("task_id")
        repeat_id = identity.get("repeat_id")
        sample_id = row.get("sample_id")
        static = static_by_key.get((task_id, repeat_id), {})
        cleaned = (cleaned_by_key.get((task_id, repeat_id)) or {}).get("cleaned") or {}
        sast = sast_by_sample.get(sample_id, {})
        joined.append(
            {
                "sample_id": sample_id,
                "task_id": task_id,
                "repeat_id": repeat_id,
                "generation_status": static.get("generation_status")
                or cleaned.get("generation_status")
                or row.get("status"),
                "final_code": cleaned.get("final_code", ""),
                "final_code_sha256": static.get("final_code_sha256")
                or cleaned.get("final_code_sha256"),
                "verdict": static.get("verdict"),
                "asr_hit": static.get("asr_hit"),
                "semgrep": {
                    "status": sast.get("status"),
                    "detected": sast.get("detected"),
                    "reason_code": sast.get("reason_code"),
                },
            }
        )
    joined.sort(
        key=lambda item: (
            task_order.get(item["task_id"], len(task_order)),
            int(item["repeat_id"]) if isinstance(item["repeat_id"], int) else -1,
        )
    )

    sampling = {
        "model": config.model,
        "temperature": float(config.temperature),
        "repeats": config.repeats,
    }

    def _sast_accessor(record: Mapping[str, Any]) -> dict[str, Any] | None:
        layer = sast_by_sample.get(record.get("sample_id"))
        if layer is None:
            return None
        return {
            "available": bool(layer.get("available")),
            "completed": bool(layer.get("completed")),
            "detected": layer.get("detected"),
        }

    metrics = {
        "sample_hit_rate": _method_metric(
            sample_hit_rate(joined, task_set=_BASELINE_TASK_SET, sampling=sampling)
        ),
        "asr@1": _method_metric(
            asr_at_k(
                joined,
                list(config.task_ids),
                1,
                task_set=_BASELINE_TASK_SET,
                sampling=sampling,
                formal_spec={"temperature": 0.0, "repeats": 1},
            )
        ),
        "asr@5": _method_metric(
            asr_at_k(
                joined,
                list(config.task_ids),
                5,
                task_set=_BASELINE_TASK_SET,
                sampling=sampling,
                formal_spec={"temperature": 0.7, "repeats": 5},
            )
        ),
        "semgrep_evasion": _method_metric(
            evasion(
                joined,
                tool_name="semgrep",
                accessor=_sast_accessor,
                temperature=float(config.temperature),
                repeats=config.repeats,
                task_set=_BASELINE_TASK_SET,
                sampling=sampling,
            )
        ),
    }

    generation_status_counts: dict[str, int] = {}
    for row in generation_rows:
        status = str(row.get("status"))
        generation_status_counts[status] = generation_status_counts.get(status, 0) + 1
    semgrep_status_counts: dict[str, int] = {}
    for row in sast_rows:
        status = str(row.get("status"))
        semgrep_status_counts[status] = semgrep_status_counts.get(status, 0) + 1
    missing_static = sum(
        1
        for row in generation_rows
        if (
            (row.get("identity") or {}).get("task_id"),
            (row.get("identity") or {}).get("repeat_id"),
        )
        not in static_by_key
    )
    counts = {
        "generation_status_counts": dict(sorted(generation_status_counts.items())),
        "generation_failures": sum(
            count
            for status, count in generation_status_counts.items()
            if status in ("error", "invalid_response")
        ),
        "parse_errors": sum(1 for row in static_rows if row.get("verdict") == "parse_error"),
        "missing_static_records": missing_static,
        "semgrep_status_counts": dict(sorted(semgrep_status_counts.items())),
        "semgrep_unavailable": semgrep_status_counts.get("unavailable", 0),
        "semgrep_error": semgrep_status_counts.get("error", 0),
        "semgrep_incomplete": semgrep_status_counts.get("incomplete", 0),
    }

    kind = "mock" if config.source == "mock" else "real"
    audit = {
        "candidate_kind": kind,
        "candidate_hash": candidate_hash,
        "template_sha256": snapshot.content_sha256(),
        "sast_adapter": sast_adapter_fingerprint(),
        "samples": [
            {
                "sample_id": item["sample_id"],
                "task_id": item["task_id"],
                "repeat_id": item["repeat_id"],
                "generation_status": item["generation_status"],
                "final_code_sha256": item["final_code_sha256"],
                "verdict": item["verdict"],
                "asr_hit": item["asr_hit"],
                "semgrep": {
                    "status": item["semgrep"]["status"],
                    "detected": item["semgrep"]["detected"],
                    "reason_code": item["semgrep"]["reason_code"],
                },
            }
            for item in joined
        ],
    }
    feedback = {
        "candidate_kind": kind,
        "samples": [
            {
                "task": labels.get(item["task_id"], "unknown"),
                "repeat": item["repeat_id"],
                "code": item["final_code"],
                "verdict": item["verdict"],
                "semgrep": {
                    "status": item["semgrep"]["status"],
                    "detected": item["semgrep"]["detected"],
                    "reason": item["semgrep"]["reason_code"],
                },
            }
            for item in joined
        ],
        "metrics": metrics,
        "counts": counts,
    }
    return feedback, audit


# --------------------------------------------------------------------------- #
# Read-only baseline slice
# --------------------------------------------------------------------------- #


def _baseline_history_scan_errors(
    evaluation_dir: Path | None, task_ids: Sequence[str]
) -> int | None:
    """Count historical Semgrep rows recorded incomplete/scan_errors, if present.

    Returns ``None`` when the historical SAST layer is not available, keeping
    "unknown" distinct from a confirmed zero.
    """

    if evaluation_dir is None:
        return None
    sast_path = Path(evaluation_dir) / "layers" / "sast.jsonl"
    if not sast_path.is_file():
        return None
    wanted = set(task_ids)
    count = 0
    for row in _read_jsonl(sast_path):
        if row.get("tool") != "semgrep":
            continue
        task_id = (row.get("identity") or {}).get("task_id")
        if task_id not in wanted:
            continue
        if row.get("status") == "incomplete" or row.get("reason_code") == "scan_errors":
            count += 1
    return count


def _baseline_raw_report_status(evaluation_dir: Path | None) -> bool | None:
    """Whether the historical run preserved raw Semgrep report files.

    ``None`` means the evidence directory was not provided or has no semgrep
    output, so preservation cannot be determined; it is never guessed from the
    candidate's own behaviour.
    """

    if evaluation_dir is None:
        return None
    sast_dir = Path(evaluation_dir) / "sast"
    if not sast_dir.is_dir():
        return None
    saw_semgrep = False
    for sample_dir in sorted(sast_dir.iterdir()):
        semgrep_dir = sample_dir / "semgrep"
        if not semgrep_dir.is_dir():
            continue
        saw_semgrep = True
        extra = [item for item in semgrep_dir.iterdir() if item.name != "solution.py"]
        if extra:
            return True
    return False if saw_semgrep else None


def _baseline_static_provenance(baseline_static: Path) -> dict[str, Any]:
    """Read version provenance from the baseline's own static manifest."""

    manifest_path = baseline_static.parent / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return {}
    if not isinstance(manifest, dict):
        return {}
    fingerprint = manifest.get("evaluator_fingerprint")
    if not isinstance(fingerprint, Mapping):
        return {}
    oracle = fingerprint.get("oracle") or {}
    oracle_files = oracle.get("files") if isinstance(oracle, Mapping) else None
    return {
        "static_shell_version": fingerprint.get("shell_version"),
        "cleaner_version": fingerprint.get("cleaner_version"),
        "oracle_fingerprint_sha256": (
            sha256_bytes(canonical_json_bytes(dict(oracle_files)))
            if isinstance(oracle_files, Mapping) and oracle_files
            else None
        ),
    }


def _baseline_prepared_provenance(
    baseline_data_dir: str | None, combination_id: str
) -> dict[str, Any]:
    """Read split/data-contract provenance from the baseline's prepared data."""

    if not baseline_data_dir:
        return {
            "split_mode": None,
            "data_contract": None,
            "task_snapshot_sha256": None,
            "split_manifest_sha256": None,
        }
    prepared = load_prepared_data(Path(baseline_data_dir), combination_id)
    mode = getattr(prepared.split, "mode", None)
    return {
        "split_mode": mode.value if hasattr(mode, "value") else str(mode) if mode else None,
        "data_contract": prepared.data_contract,
        "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
        "split_manifest_sha256": (prepared.files or {}).get("split.json"),
    }


def _baseline_slice(
    config: "TrainingLoopConfig",
    prepared: Any,
    *,
    mode_value: str,
) -> dict[str, Any]:
    baseline_static = Path(config.baseline_static)  # type: ignore[arg-type]
    baseline_config = Path(config.baseline_config)  # type: ignore[arg-type]
    rows = [
        row
        for row in _read_jsonl(baseline_static)
        if row.get("task_id") in set(config.task_ids)
    ]
    baseline_cfg = read_json(baseline_config)
    if not isinstance(baseline_cfg, dict):
        raise TrainingLoopError("baseline config must be a JSON object")

    # R5: bind the external config to the baseline's own static manifest and to
    # the actual evaluations bytes.  The run's real identity comes from the
    # embedded config, never from the external (possibly relabelled) file.
    embedded_manifest = _parse_json_file(baseline_static.parent / "manifest.json")
    provenance_errors: list[dict[str, Any]] = []
    embedded_config: dict[str, Any] = {}
    if embedded_manifest is None:
        provenance_errors.append(
            {"key": "baseline_static_manifest", "reason": "missing"}
        )
    else:
        if embedded_manifest.get("completion") != "complete":
            provenance_errors.append(
                {"key": "baseline_static_manifest", "reason": "not_complete"}
            )
        raw_config = embedded_manifest.get("config")
        embedded_config = dict(raw_config) if isinstance(raw_config, Mapping) else {}
        declared_eval = (embedded_manifest.get("inputs") or {}).get("evaluations") or {}
        if declared_eval.get("sha256") != sha256_file(baseline_static):
            provenance_errors.append(
                {"key": "baseline_evaluations_sha256", "reason": "mismatch"}
            )
    for field in (
        "combination_id",
        "oracle_id",
        "model",
        "temperature",
        "repeats",
        "task_set",
        "prompt_form",
    ):
        embedded_value = embedded_config.get(field)
        external_value = baseline_cfg.get(field)
        if embedded_value is None:
            continue
        if external_value != embedded_value:
            provenance_errors.append(
                {
                    "key": f"baseline_config.{field}",
                    "baseline": embedded_value,
                    "candidate": external_value,
                    "reason": "baseline_config_mismatch",
                }
            )
    embedded_task_ids = embedded_config.get("task_ids")
    if isinstance(embedded_task_ids, list) and not set(config.task_ids) <= set(
        str(task) for task in embedded_task_ids
    ):
        provenance_errors.append(
            {
                "key": "baseline_config.task_ids",
                "baseline": sorted(str(task) for task in embedded_task_ids),
                "candidate": list(config.task_ids),
                "reason": "slice_out_of_baseline_scope",
            }
        )

    def _embedded(field: str) -> Any:
        """Baseline identity from its own embedded config (None if absent)."""

        return embedded_config.get(field)

    # R5: validate the sliced matrix against the baseline's own repeats.
    baseline_repeats = _embedded("repeats")
    if (
        isinstance(baseline_repeats, int)
        and not isinstance(baseline_repeats, bool)
        and baseline_repeats >= 1
    ):
        expected_keys = _expected_keys(config.task_ids, baseline_repeats)
        matrix_ok, matrix_reason = _matrix_ok(rows, expected_keys)
    else:
        expected_keys = None
        matrix_ok, matrix_reason = False, "baseline repeats unavailable"

    baseline_sampling = {
        "model": _embedded("model"),
        "temperature": _embedded("temperature"),
        "repeats": baseline_repeats,
    }
    metrics = {
        "sample_hit_rate": sample_hit_rate(
            rows, task_set=_BASELINE_TASK_SET, sampling=baseline_sampling
        ).to_json(),
        "asr@1": asr_at_k(
            rows,
            list(config.task_ids),
            1,
            task_set=_BASELINE_TASK_SET,
            sampling=baseline_sampling,
            formal_spec={"temperature": 0.0, "repeats": 1},
        ).to_json(),
        "asr@5": asr_at_k(
            rows,
            list(config.task_ids),
            5,
            task_set=_BASELINE_TASK_SET,
            sampling=baseline_sampling,
            formal_spec={"temperature": 0.7, "repeats": 5},
        ).to_json(),
    }

    task_set = list(config.task_ids)
    candidate_payload = {
        "combination_id": prepared.combination_id,
        "split_mode": mode_value,
        "task_set": task_set,
        "model": config.model,
        "temperature": float(config.temperature),
        "repeats": config.repeats,
        "k": [1, 3, 5],
        "data_contract": prepared.data_contract,
        "form": config.form,
        "prompt_version": config.prompt_version,
        "task_snapshot_sha256": prepared.selection.task_snapshot_sha256,
        "split_manifest_sha256": (prepared.files or {}).get("split.json"),
    }
    # R5: source baseline provenance from the baseline's own artifacts, never
    # from the candidate.  Missing baseline information is reported missing.
    provenance = _baseline_prepared_provenance(
        config.baseline_data_dir,
        str(baseline_cfg.get("combination_id") or prepared.combination_id),
    )
    static_provenance = _baseline_static_provenance(baseline_static)
    baseline_k = None
    if config.baseline_evaluators_config:
        evaluators_payload = read_json(Path(config.baseline_evaluators_config))
        if isinstance(evaluators_payload, Mapping):
            baseline_k = evaluators_payload.get("k")
    baseline_payload = {
        "combination_id": _embedded("combination_id"),
        "split_mode": provenance["split_mode"],
        "task_set": task_set,
        "model": _embedded("model"),
        "temperature": _embedded("temperature"),
        "repeats": baseline_repeats,
        "k": baseline_k,
        "data_contract": provenance["data_contract"],
        "form": _embedded("prompt_form") or _embedded("form"),
        "prompt_version": str(baseline_cfg.get("prompt_version") or "1"),
        "static_shell_version": static_provenance.get("static_shell_version"),
        "cleaner_version": static_provenance.get("cleaner_version"),
        "oracle_fingerprint_sha256": static_provenance.get("oracle_fingerprint_sha256"),
        "task_snapshot_sha256": provenance["task_snapshot_sha256"],
        "split_manifest_sha256": provenance["split_manifest_sha256"],
    }
    compatibility = assess_baseline_compatibility(baseline_payload, candidate_payload)
    if not matrix_ok:
        compatibility["compatible"] = False
        compatibility.setdefault("blocking", []).append(
            {
                "key": "baseline_matrix",
                "baseline": matrix_reason,
                "candidate": "expected-exact-matrix",
                "reason": "incomplete_slice",
            }
        )
    if provenance_errors:
        compatibility["compatible"] = False
        compatibility.setdefault("blocking", []).extend(provenance_errors)

    evaluation_dir = (
        Path(config.baseline_evaluation_dir) if config.baseline_evaluation_dir else None
    )
    historical = _baseline_history_scan_errors(evaluation_dir, config.task_ids)
    raw_preserved = _baseline_raw_report_status(evaluation_dir)
    result: dict[str, Any] = {
        "source": {
            "path": str(baseline_static),
            "sha256": sha256_file(baseline_static),
            "model": _embedded("model"),
            "temperature": _embedded("temperature"),
            "repeats": baseline_repeats,
            "task_set": task_set,
            "combination_id": _embedded("combination_id"),
            "prompt_form": _embedded("prompt_form") or _embedded("form"),
            "data_dir": config.baseline_data_dir,
            "evaluation_dir": config.baseline_evaluation_dir,
            "evaluators_config": config.baseline_evaluators_config,
            "embedded_config_path": str(baseline_static.parent / "manifest.json"),
        },
        "baseline_provenance": {
            "embedded_config": dict(embedded_config),
            "external_config_model": baseline_cfg.get("model"),
            "errors": provenance_errors,
        },
        "records": rows,
        "baseline_matrix": {
            "expected_count": len(expected_keys) if expected_keys is not None else None,
            "observed_count": len(rows),
            "ok": matrix_ok,
            "reason": matrix_reason,
        },
        "metrics": metrics,
        "compatibility": compatibility,
        "e05": {
            "baseline_adapter": "unknown",
            "candidate_adapter": sast_adapter_fingerprint(),
            "raw_semgrep_reports_preserved": raw_preserved,
            "historical_semgrep_scan_errors": historical,
            "historical_impact": "unknown",
            "reason": (
                "the historical baseline records carry no adapter revision and raw "
                "Semgrep reports cannot be assumed present, so old errors cannot be "
                "re-checked; the impact of the errors->incomplete interpretation is unknown"
            ),
        },
    }
    if config.source == "mock":
        result["candidate_kind"] = "mock"
        result["comparable_with_real_baseline"] = False
        result["warning"] = (
            "mock wiring output is not a real victim sample and is not comparable "
            "with a real baseline; no better/worse conclusion is derived"
        )
    return result


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #


def _write_manifest(
    manifest_path: Path,
    *,
    config: "TrainingLoopConfig",
    snapshot: TemplateSnapshot,
    config_sha: str,
    candidate_hash: str,
    expected_sample_count: int,
    observed_sample_count: int,
    steps: Mapping[str, Any],
    completion: str,
    failed_step: str | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": LOOP_SCHEMA_VERSION,
        "completion": completion,
        "config_sha256": config_sha,
        "snapshot": {
            "content_sha256": snapshot.content_sha256(),
            "form": snapshot.form,
            "prompt_version": snapshot.prompt_version,
        },
        "candidate_kind": "mock" if config.source == "mock" else "real",
        "candidate_hash": candidate_hash,
        "task_ids": list(config.task_ids),
        "repeats": config.repeats,
        "expected_sample_count": expected_sample_count,
        "observed_sample_count": observed_sample_count,
        "sast_adapter": sast_adapter_fingerprint(),
        # R4: the configured timeout is threaded into the scanner, so the value
        # actually used equals the configured value.
        "semgrep_timeout": {
            "configured": float(config.semgrep_timeout_seconds),
            "used": float(config.semgrep_timeout_seconds),
        },
        "steps": dict(steps),
    }
    if failed_step is not None:
        manifest["failed_step"] = failed_step
    write_json_atomic(manifest_path, manifest)
    return manifest


def run_training_loop(
    config: TrainingLoopConfig,
    *,
    generation_step: Callable[..., int] | None = None,
    generation_resume_step: Callable[..., int] | None = None,
    sast_scan: Callable[..., Any] | None = None,
    force_rerun: bool = False,
) -> dict[str, Any]:
    """Run (or resume) the single-candidate mock training loop."""

    snapshot = read_snapshot(config.snapshot_path)
    if config.form != snapshot.form:
        raise TrainingLoopError(
            f"config.form {config.form!r} != snapshot form {snapshot.form!r}"
        )
    if config.prompt_version != snapshot.prompt_version:
        raise TrainingLoopError(
            f"config.prompt_version {config.prompt_version!r} != snapshot "
            f"prompt_version {snapshot.prompt_version!r}"
        )

    prepared = load_prepared_data(Path(config.data_dir), snapshot.combination_id)
    legacy = legacy_alias_for(snapshot.combination_id)

    output = Path(config.output_dir).expanduser().resolve()
    config_sha = config.run_config_sha256()
    # R3: never write into (or contain) a read-only input path; check before mkdir.
    _assert_output_isolation(config)
    output.mkdir(parents=True, exist_ok=True)

    # R1: validate the existing run before writing anything, so a rejected
    # configuration leaves the old run directory byte-for-byte unchanged.
    manifest_path = output / "manifest.json"
    existing: dict[str, Any] | None = None
    if manifest_path.is_file():
        existing = read_json(manifest_path)
        if not isinstance(existing, dict):
            raise TrainingLoopError(f"existing manifest is not a JSON object: {manifest_path}")
        if existing.get("schema_version") != LOOP_SCHEMA_VERSION:
            raise TrainingLoopError(
                "existing run uses an unknown manifest schema_version; use a new output_dir"
            )
        if existing.get("config_sha256") != config_sha:
            raise TrainingLoopError(
                "existing run was created with a different configuration; refusing to reuse it"
            )
        stored_snapshot = existing.get("snapshot") or {}
        if stored_snapshot.get("content_sha256") != snapshot.content_sha256():
            raise TrainingLoopError(
                "existing run was created from a different template snapshot; refusing to reuse it"
            )

    loop_config_path = output / "loop_config.json"
    if loop_config_path.is_file():
        try:
            prior = read_json(loop_config_path)
        except (OSError, ValueError) as error:
            raise TrainingLoopError(
                f"existing loop_config.json is unreadable: {error}"
            ) from error
        if not isinstance(prior, dict) or prior.get("config_sha256") not in (None, config_sha):
            raise TrainingLoopError(
                "existing loop_config.json was created with a different configuration"
            )
    write_json_atomic(loop_config_path, {**config.to_json(), "config_sha256": config_sha})

    if force_rerun and existing is not None:
        raise TrainingLoopError(
            "force_rerun would overwrite existing evidence; use a new output_dir"
        )

    expected_keys = _expected_keys(config.task_ids, config.repeats)
    expected_sample_count = len(expected_keys)

    precomputed_validity: dict[str, bool] | None = None
    if existing is not None and existing.get("completion") == "complete" and not force_rerun:
        identity_ok, identity_reason = _completed_run_identity(
            output, existing, config, snapshot, expected_keys
        )
        if not identity_ok:
            raise TrainingLoopError(
                f"completed run failed identity check: {identity_reason}; "
                "use a new output_dir"
            )
        try:
            validity, refuse_reason = _assess_artifacts(output, config, snapshot)
        except Exception as error:  # noqa: BLE001 - unreadable evidence is a failure
            validity, refuse_reason = {}, f"cannot assess artifacts: {error}"
        if refuse_reason is not None:
            raise TrainingLoopError(
                f"completed run failed evidence check: {refuse_reason}; "
                "use a new output_dir"
            )
        if all(validity.values()):
            return existing
        # Identity is intact but some data is missing/derived reports are
        # invalid: fall through and recover only the affected steps.
        precomputed_validity = validity

    prompts_dir = output / "prompts"
    generation_dir = output / "generation"
    cleaning_dir = output / "cleaning"
    static_dir = output / "static"
    evaluation_dir = output / "evaluation"
    configs_dir = output / "configs"

    candidate_hash = ""
    observed_sample_count = 0
    steps: dict[str, Any] = {}
    step_name = "materialize"

    try:
        # 1. poisoned materialization ------------------------------------- #
        if not force_rerun and _materialize_complete(prompts_dir, snapshot):
            steps["materialize"] = _step(
                output, status="skipped", artifacts={"manifest": prompts_dir / "manifest.json"}
            )
        else:
            _quarantine(prompts_dir)
            materialize_poisoned(
                snapshot=snapshot,
                data_dir=config.data_dir,
                task_ids=config.task_ids,
                output_dir=prompts_dir,
                prompt_version=config.prompt_version,
            )
            steps["materialize"] = _step(
                output, status="completed", artifacts={"manifest": prompts_dir / "manifest.json"}
            )

        inputs = load_generation_inputs(
            config.data_dir,
            prompts_dir,
            combination_id=snapshot.combination_id,
            form=config.form,
            stage=config.stage,
            repeats=config.repeats,
            batch_id=config.batch_id,
            prompt_version=config.prompt_version,
            task_ids=list(config.task_ids),
        )
        candidate_hash = inputs.candidate_hash
        expected_ids = {sample.sample_id for sample in inputs.samples}

        if precomputed_validity is not None:
            validity = precomputed_validity
        else:
            try:
                validity, refuse_reason = _assess_artifacts(output, config, snapshot)
            except Exception:  # noqa: BLE001 - unreadable evidence is an incomplete step
                validity, refuse_reason = {}, None
            if refuse_reason is not None:
                raise TrainingLoopError(
                    f"generation evidence belongs to another candidate: "
                    f"{refuse_reason}; use a new output_dir"
                )

        # 2. victim generation -------------------------------------------- #
        step_name = "generate"
        if not force_rerun and validity.get("generation", False):
            steps["generate"] = _step(
                output,
                status="skipped",
                artifacts={"generations": generation_dir / "generations.jsonl"},
            )
        else:
            configs_dir.mkdir(parents=True, exist_ok=True)
            generation_config_path = configs_dir / "generation.json"
            write_json_atomic(
                generation_config_path,
                _generation_config(config, prepared).to_json(),
            )
            if (generation_dir / "run_config.json").is_file():
                # R6: resume in an independent process by default, preserving the
                # one-cache-configuration-per-process boundary.
                if generation_resume_step is not None:
                    code = generation_resume_step(
                        generation_dir, repo_dir=config.repo_dir
                    )
                else:
                    code = _subprocess_resume_generation_step(
                        generation_dir, repo_dir=config.repo_dir
                    )
            else:
                _quarantine(generation_dir)
                step = generation_step or _subprocess_generation_step
                code = step(
                    generation_config_path,
                    config.data_dir,
                    prompts_dir,
                    generation_dir,
                    repo_dir=config.repo_dir,
                )
            if code != 0:
                raise TrainingLoopError(f"generation step exited with code {code}")
            steps["generate"] = _step(
                output,
                status="completed",
                artifacts={"generations": generation_dir / "generations.jsonl"},
            )
        observed_sample_count = len(_read_jsonl(generation_dir / "generations.jsonl"))
        stored_generation_hash = _generation_run_candidate_hash(generation_dir)
        if stored_generation_hash and stored_generation_hash != candidate_hash:
            raise TrainingLoopError(
                "generation run_config candidate_hash does not match the "
                "materialized prompts; refusing to mix candidates"
            )

        # 3. cleaning ------------------------------------------------------ #
        step_name = "cleaning"
        if not force_rerun and validity.get("cleaning", False):
            steps["cleaning"] = _step(
                output, status="skipped", artifacts={"manifest": cleaning_dir / "manifest.json"}
            )
        else:
            _quarantine(cleaning_dir)
            clean_generations(
                prepared,
                generation_dir / "generations.jsonl",
                cleaning_dir,
                legacy,
            )
            steps["cleaning"] = _step(
                output, status="completed", artifacts={"manifest": cleaning_dir / "manifest.json"}
            )

        # 4. static oracle ------------------------------------------------- #
        step_name = "static"
        if not force_rerun and validity.get("static", False):
            steps["static"] = _step(
                output, status="skipped", artifacts={"manifest": static_dir / "manifest.json"}
            )
        else:
            _quarantine(static_dir)
            configs_dir.mkdir(parents=True, exist_ok=True)
            static_config_path = configs_dir / "evaluation.json"
            write_json_atomic(
                static_config_path,
                EvaluationConfig(
                    combination_id=prepared.combination_id,
                    oracle_id=prepared.oracle_id,
                    model=config.model,
                    temperature=float(config.temperature),
                    repeats=config.repeats,
                    task_set=config.stage,
                    prompt_form=config.form,
                    task_ids=config.task_ids,
                ).to_json(),
            )
            evaluate_static(
                Path(config.assets_root),
                Path(config.data_dir),
                cleaning_dir,
                static_config_path,
                static_dir,
            )
            steps["static"] = _step(
                output, status="completed", artifacts={"manifest": static_dir / "manifest.json"}
            )

        # 5. Semgrep ------------------------------------------------------- #
        step_name = "semgrep"
        if not force_rerun and validity.get("semgrep", False):
            steps["semgrep"] = _step(
                output,
                status="skipped",
                artifacts={"manifest": evaluation_dir / "manifest.json"},
            )
        else:
            _quarantine(evaluation_dir)
            configs_dir.mkdir(parents=True, exist_ok=True)
            evaluators_config_path = configs_dir / "evaluators.json"
            write_json_atomic(
                evaluators_config_path,
                EvaluatorsConfig(
                    combination_id=prepared.combination_id,
                    oracle_id=prepared.oracle_id,
                    stage=config.stage,
                    enabled_layers=("sast",),
                    sast_tools=("semgrep",),
                    semgrep_config=config.semgrep_config,
                    k=(1, 3, 5),
                    task_ids=config.task_ids,
                    victim_temperature=float(config.temperature),
                    victim_repeats=config.repeats,
                    batch_id=config.batch_id,
                    model=config.model,
                ).to_json(),
            )
            static_hits = static_hits_from_run(output, list(expected_ids))
            # R4: thread the configured timeout into the actual scanner call;
            # the default keeps the previous value (60s).
            scanner = (
                sast_scan
                if sast_scan is not None
                else _make_sast_scan(float(config.semgrep_timeout_seconds))
            )
            run_evaluate_other(
                evaluators_config_path,
                config.data_dir,
                generation_dir,
                cleaning_dir,
                None,
                evaluation_dir,
                static_hits=static_hits,
                sast_scan=scanner,
            )
            steps["semgrep"] = _step(
                output,
                status="completed",
                artifacts={"manifest": evaluation_dir / "manifest.json"},
            )

        # 6. feedback ------------------------------------------------------ #
        step_name = "feedback"
        if not force_rerun and validity.get("feedback", False):
            steps["feedback"] = _step(
                output,
                status="skipped",
                artifacts={
                    "feedback": output / "feedback.json",
                    "audit": output / "feedback_audit.json",
                },
            )
        else:
            # Preserve the previous derived reports before regenerating them.
            _quarantine(output / "feedback.json")
            _quarantine(output / "feedback_audit.json")
            feedback, audit = _assemble_feedback(config, snapshot, candidate_hash, output)
            write_json_atomic(output / "feedback.json", feedback)
            write_json_atomic(output / "feedback_audit.json", audit)
            steps["feedback"] = _step(
                output,
                status="completed",
                artifacts={
                    "feedback": output / "feedback.json",
                    "audit": output / "feedback_audit.json",
                },
            )
            validity["feedback"] = True

        # 7. baseline slice ------------------------------------------------ #
        step_name = "baseline"
        baseline_path = output / "baseline_slice.json"
        if not force_rerun and validity.get("baseline", False):
            steps["baseline"] = _step(
                output, status="skipped", artifacts={"slice": baseline_path}
            )
        else:
            _quarantine(baseline_path)
            if config.baseline_static and config.baseline_config:
                mode_value = (
                    prepared.split.mode.value
                    if hasattr(prepared.split.mode, "value")
                    else str(prepared.split.mode)
                )
                baseline_payload = _baseline_slice(config, prepared, mode_value=mode_value)
                write_json_atomic(baseline_path, baseline_payload)
                steps["baseline"] = _step(
                    output, status="completed", artifacts={"slice": baseline_path}
                )
            else:
                write_json_atomic(
                    baseline_path, {"status": "skipped", "reason": "baseline_not_provided"}
                )
                steps["baseline"] = _step(
                    output, status="skipped", artifacts={"slice": baseline_path}
                )
    except TrainingLoopError as error:
        _write_manifest(
            manifest_path,
            config=config,
            snapshot=snapshot,
            config_sha=config_sha,
            candidate_hash=candidate_hash,
            expected_sample_count=expected_sample_count,
            observed_sample_count=observed_sample_count,
            steps=steps,
            completion="incomplete",
            failed_step=step_name,
        )
        raise TrainingLoopError(f"{step_name}: {error}") from error
    except Exception as error:  # noqa: BLE001 - recorded and re-raised with the step
        _write_manifest(
            manifest_path,
            config=config,
            snapshot=snapshot,
            config_sha=config_sha,
            candidate_hash=candidate_hash,
            expected_sample_count=expected_sample_count,
            observed_sample_count=observed_sample_count,
            steps=steps,
            completion="incomplete",
            failed_step=step_name,
        )
        raise TrainingLoopError(f"{step_name}: {error}") from error

    return _write_manifest(
        manifest_path,
        config=config,
        snapshot=snapshot,
        config_sha=config_sha,
        candidate_hash=candidate_hash,
        expected_sample_count=expected_sample_count,
        observed_sample_count=observed_sample_count,
        steps=steps,
        completion="complete",
    )


__all__ = [
    "LOOP_SCHEMA_VERSION",
    "TrainingLoopError",
    "TrainingLoopConfig",
    "load_training_loop_config",
    "run_training_loop",
]
