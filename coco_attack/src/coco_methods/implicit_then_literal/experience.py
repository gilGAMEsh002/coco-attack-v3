"""Single-template evidence packs, experience versions and induction recovery.

Subplan 02 keeps two things apart:

* the **evidence pack** -- a validated, model-visible projection of one
  template's already-persisted training results plus an internal audit mapping;
* the **experience store** -- immutable, chained versions of structure/literal
  experience and the logical induction commit that ties one successful inducer
  call to exactly one version.

The module never scans a run directory for "the latest candidate", never trains
a victim, never fabricates metrics and never trims the current template's 20
samples.  It consumes explicit paths and explicit identities supplied by the
caller (subplan 03).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from coco_attack.assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_text,
    write_json_atomic,
)
from coco_attack.iteration.action_runtime import (
    ActionConflictError,
    ActionStore,
    RoleCallConfig,
    RoleCallSource,
    run_role_call,
)
from coco_attack.iteration.method_inputs import project_training_facts
from coco_attack.iteration.template_snapshot import TemplateSnapshot
from .contracts import (
    EXPERIENCE_CATEGORIES,
    CandidateIdentity,
    ExperienceVersionReference,
)
from .roles import (
    INDUCER_ROLE,
    JUDGE_PROTOCOL_VERSION,
    JudgeInput,
    RoleCapacityError,
    build_judge_messages,
    inducer_config,
    judge_action_id,
    parse_judge_response,
)
from .prompt_renderer import template_identity, with_prompt_bundle

EXPERIENCE_SCHEMA_VERSION = "itl-experience-v1"
INDUCTION_SCHEMA_VERSION = "itl-induction-v1"
EVIDENCE_SCHEMA_VERSION = "itl-evidence-v1"
PROJECTION_VERSION = "itl-evidence-projection-v1"

TERMINAL_GENERATION_STATUSES = ("error", "invalid_response", "empty", "truncated")

_STATUS_COMMITTED = "committed"
_STATUS_PROTOCOL_ERROR = "protocol_error"
_STATUS_FAILED = "failed"
_STATUS_PAUSED_UNKNOWN = "paused_unknown"
_STATUS_CAPACITY_BLOCKED = "capacity_blocked"
_STATUS_CONFLICT = "conflict"


class EvidenceError(ValueError):
    """The provided training artifacts are incomplete or mis-attributed."""


class EvidenceNotReady(EvidenceError):
    """A required generation/static record is still missing (not a terminal failure)."""


# --------------------------------------------------------------------------- #
# Evidence pack
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MetricEvidence:
    value: Any
    defined: bool | None
    reason: str | None = None
    numerator: Any = None
    denominator: Any = None
    k: Any = None

    def to_json(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "defined": self.defined,
            "reason": self.reason,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "k": self.k,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "MetricEvidence":
        return cls(
            value=payload.get("value"),
            defined=payload.get("defined"),
            reason=payload.get("reason"),
            numerator=payload.get("numerator"),
            denominator=payload.get("denominator"),
            k=payload.get("k"),
        )


@dataclass(frozen=True)
class SampleEvidence:
    label: str
    task_label: str
    repeat: int
    code: str
    generation_status: str | None
    terminal_failure: bool
    verdict: str | None
    asr_hit: bool | None
    semgrep: Mapping[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "task_label": self.task_label,
            "repeat": self.repeat,
            "code": self.code,
            "generation_status": self.generation_status,
            "terminal_failure": self.terminal_failure,
            "verdict": self.verdict,
            "asr_hit": self.asr_hit,
            "semgrep": dict(self.semgrep),
        }


@dataclass(frozen=True)
class BaselineEvidence:
    available: bool
    metrics: Mapping[str, MetricEvidence]
    source: Mapping[str, Any]
    reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "metrics": {name: metric.to_json() for name, metric in self.metrics.items()},
            "source": dict(self.source),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FailureSummary:
    reference: str
    description: str
    evidence: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "reference": self.reference,
            "description": self.description,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class EvidencePack:
    category: str
    candidate_id: str
    template_content_sha256: str
    structure_description: str
    diff: tuple[Mapping[str, Any], ...]
    gate_facts: tuple[Mapping[str, Any], ...]
    samples: tuple[SampleEvidence, ...]
    metrics: Mapping[str, MetricEvidence]
    counts: Mapping[str, Any]
    baseline: BaselineEvidence
    seed_comparison: Mapping[str, Any] | None
    failure_summary: FailureSummary | None
    evidence_labels: tuple[str, ...]
    audit: Mapping[str, Any]
    projection: Mapping[str, Any]
    evidence_fingerprint: str

    def model_visible(self) -> dict[str, Any]:
        return dict(self.projection)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "category": self.category,
            "candidate_id": self.candidate_id,
            "template_content_sha256": self.template_content_sha256,
            "structure_description": self.structure_description,
            "diff": [dict(entry) for entry in self.diff],
            "gate_facts": [dict(entry) for entry in self.gate_facts],
            "samples": [sample.to_json() for sample in self.samples],
            "metrics": {name: metric.to_json() for name, metric in self.metrics.items()},
            "counts": dict(self.counts),
            "baseline": self.baseline.to_json(),
            "seed_comparison": dict(self.seed_comparison) if self.seed_comparison else None,
            "failure_summary": self.failure_summary.to_json() if self.failure_summary else None,
            "evidence_labels": list(self.evidence_labels),
            "evidence_fingerprint": self.evidence_fingerprint,
            "audit": dict(self.audit),
        }


def _load_sast_records(output_dir: Path) -> list[Mapping[str, Any]]:
    path = output_dir / "evaluation" / "layers" / "sast.jsonl"
    if not path.is_file():
        return []
    from coco_attack.assets.artifacts import iter_jsonl

    return [
        row
        for _lineno, row in iter_jsonl(path)
        if row.get("tool") == "semgrep"
    ]


def _expected_matrix(
    task_ids: Sequence[str], repeats: int
) -> list[tuple[str, int]]:
    return [(str(task), repeat) for task in task_ids for repeat in range(repeats)]


def _validate_artifacts(
    feedback: Mapping[str, Any],
    audit: Mapping[str, Any],
    *,
    expected_candidate_hash: str,
    expected_template_sha256: str | None,
    expected_matrix: Sequence[tuple[str, int]],
) -> list[Mapping[str, Any]]:
    if not isinstance(feedback, Mapping) or not isinstance(audit, Mapping):
        raise EvidenceError("feedback.json and feedback_audit.json must be JSON objects")
    if audit.get("candidate_hash") != expected_candidate_hash:
        raise EvidenceError(
            "feedback_audit candidate_hash does not match the expected candidate"
        )
    if expected_template_sha256 is not None and audit.get("template_sha256") != expected_template_sha256:
        raise EvidenceError(
            "feedback_audit template_sha256 does not match the expected template"
        )
    audit_samples = [item for item in audit.get("samples", []) if isinstance(item, Mapping)]
    feedback_samples = [item for item in feedback.get("samples", []) if isinstance(item, Mapping)]
    if len(audit_samples) != len(expected_matrix):
        raise EvidenceError(
            f"feedback_audit has {len(audit_samples)} samples, expected {len(expected_matrix)}"
        )
    if len(feedback_samples) != len(audit_samples):
        raise EvidenceError("feedback.json and feedback_audit.json sample counts disagree")

    seen: dict[tuple[str, int], int] = {}
    for index, item in enumerate(audit_samples):
        task = item.get("task_id")
        repeat = item.get("repeat_id")
        if not isinstance(task, str) or not isinstance(repeat, int):
            raise EvidenceError(f"audit sample {index} has a non-identity task/repeat")
        key = (task, repeat)
        if key in seen:
            raise EvidenceError(f"duplicate audit sample identity {key}")
        seen[key] = index
    if set(seen) != set(expected_matrix):
        missing = sorted(set(expected_matrix) - set(seen))
        foreign = sorted(set(seen) - set(expected_matrix))
        raise EvidenceError(
            f"audit sample matrix mismatch; missing={missing[:4]} foreign={foreign[:4]}"
        )

    # feedback code must match the audit fingerprint per position.
    for index, sample in enumerate(feedback_samples):
        code = sample.get("code")
        if not isinstance(code, str):
            raise EvidenceError(f"feedback sample {index} code is not a string")
        audit_sample = audit_samples[index]
        if sample.get("repeat") != audit_sample.get("repeat_id"):
            raise EvidenceError(
                f"feedback sample {index} repeat does not match its audit record"
            )
        fingerprint = audit_sample.get("final_code_sha256")
        if audit_sample.get("generation_status") == "success" and not (
            isinstance(fingerprint, str) and fingerprint
        ):
            raise EvidenceError(
                f"audit sample {index} is missing its final_code_sha256 for a success sample"
            )
        if isinstance(fingerprint, str) and fingerprint and sha256_text(code) != fingerprint:
            raise EvidenceError(f"feedback sample {index} code does not match its audit fingerprint")
    return audit_samples


def _sample_evidence(
    audit_samples: Sequence[Mapping[str, Any]],
    projection_samples: Sequence[Mapping[str, Any]],
    labels: Mapping[str, str],
) -> tuple[SampleEvidence, ...]:
    result: list[SampleEvidence] = []
    for index, audit_sample in enumerate(audit_samples):
        projected = projection_samples[index]
        task_id = str(audit_sample.get("task_id"))
        repeat = int(audit_sample.get("repeat_id"))
        status = audit_sample.get("generation_status")
        terminal = status in TERMINAL_GENERATION_STATUSES
        ready = status == "success" or terminal
        if not ready:
            raise EvidenceNotReady(
                f"sample {task_id}/{repeat} generation status {status!r} is not complete"
            )
        verdict = audit_sample.get("verdict")
        if status == "success" and verdict is None:
            raise EvidenceNotReady(
                f"sample {task_id}/{repeat} is missing its static verdict"
            )
        task_label = labels.get(task_id, "训练题 ?")
        result.append(
            SampleEvidence(
                label=f"{task_label}:repeat{repeat}",
                task_label=task_label,
                repeat=repeat,
                code=str(projected.get("code") or ""),
                generation_status=status,
                terminal_failure=terminal,
                verdict=verdict,
                asr_hit=audit_sample.get("asr_hit"),
                semgrep=dict(projected.get("semgrep") or {}),
            )
        )
    return tuple(result)


def _metric_map(payload: Mapping[str, Any] | None) -> dict[str, MetricEvidence]:
    result: dict[str, MetricEvidence] = {}
    if not isinstance(payload, Mapping):
        return result
    for name, metric in payload.items():
        if isinstance(metric, Mapping):
            result[str(name)] = MetricEvidence.from_json(metric)
    return result


def metric_delta(
    current: MetricEvidence, reference: MetricEvidence
) -> dict[str, Any]:
    """A delta only when both sides are defined; never fabricate a value."""

    if current.defined is not True or reference.defined is not True:
        return {
            "defined": False,
            "value": None,
            "reason": "current or reference metric is undefined",
        }
    if not isinstance(current.value, (int, float)) or not isinstance(reference.value, (int, float)):
        return {"defined": False, "value": None, "reason": "non-numeric metric value"}
    return {"defined": True, "value": current.value - reference.value, "reason": None}


def assemble_evidence_pack(
    *,
    category: str,
    candidate: CandidateIdentity,
    template: TemplateSnapshot,
    structure_description: str,
    diff: Sequence[Mapping[str, Any]],
    gate_facts: Sequence[Mapping[str, Any]],
    output_dir: Path | str,
    expected_task_ids: Sequence[str],
    repeats: int,
    expected_candidate_hash: str,
    expected_template_sha256: str | None = None,
    baseline: Mapping[str, Any] | None = None,
    seed_comparison: Mapping[str, Any] | None = None,
    failure_summary: FailureSummary | None = None,
    expected_baseline_reference: str | None = None,
) -> EvidencePack:
    """Assemble a validated, model-visible single-template evidence pack."""

    if category not in EXPERIENCE_CATEGORIES:
        raise EvidenceError(f"category must be one of {EXPERIENCE_CATEGORIES}")
    if not isinstance(template, TemplateSnapshot):
        raise EvidenceError("template must be a TemplateSnapshot")
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 1:
        raise EvidenceError("repeats must be a positive integer")
    output = Path(output_dir)
    feedback_path = output / "feedback.json"
    audit_path = output / "feedback_audit.json"
    if not feedback_path.is_file() or not audit_path.is_file():
        raise EvidenceNotReady(f"feedback artifacts not found under {output}")
    feedback = read_json(feedback_path)
    audit = read_json(audit_path)
    if not isinstance(feedback, Mapping) or not isinstance(feedback.get("metrics"), Mapping) or not feedback.get("metrics"):
        raise EvidenceError("feedback.json is missing its metrics block")
    if "sample_hit_rate" not in feedback["metrics"]:
        raise EvidenceError("feedback.json is missing the sample_hit_rate metric")
    if expected_template_sha256 is None:
        expected_template_sha256 = template.content_sha256()
    expected_matrix = _expected_matrix(expected_task_ids, repeats)
    audit_samples = _validate_artifacts(
        feedback,
        audit,
        expected_candidate_hash=expected_candidate_hash,
        expected_template_sha256=expected_template_sha256,
        expected_matrix=expected_matrix,
    )

    labels = {
        str(task): f"训练题 {index + 1}" for index, task in enumerate(expected_task_ids)
    }
    sast_records = _load_sast_records(output)
    projection = project_training_facts(
        feedback, audit, sast_records=sast_records, label_by_task=labels
    )
    samples = _sample_evidence(audit_samples, projection["samples"], labels)
    metrics = _metric_map(feedback.get("metrics"))
    counts = dict(feedback.get("counts") or {})

    baseline_evidence = BaselineEvidence(
        available=False, metrics={}, source={}, reason="comparison baseline not provided"
    )
    if baseline is not None:
        if not isinstance(baseline, Mapping) or not isinstance(baseline.get("source"), Mapping) or not baseline.get("source"):
            raise EvidenceError("a provided baseline must carry a source identity block")
        source = baseline["source"]
        if expected_baseline_reference is not None and source.get("reference") != expected_baseline_reference:
            raise EvidenceError(
                "baseline reference does not match the expected fixed comparison baseline"
            )
        baseline_metrics = _metric_map(baseline.get("metrics"))
        baseline_evidence = BaselineEvidence(
            available=bool(baseline.get("available", True)),
            metrics=baseline_metrics,
            source=dict(source),
            reason=baseline.get("reason"),
        )

    if seed_comparison is not None:
        if candidate.stage != "B":
            raise EvidenceError("only a B candidate may carry a seed comparison")
        if not isinstance(seed_comparison, Mapping) or not isinstance(
            seed_comparison.get("seed_candidate_id"), str
        ):
            raise EvidenceError("a provided seed comparison must identify its seed candidate")
        if seed_comparison["seed_candidate_id"] != candidate.seed_candidate_id:
            raise EvidenceError(
                "seed comparison does not match the candidate's parent seed"
            )
        if not isinstance(seed_comparison.get("metrics"), Mapping):
            raise EvidenceError("a provided seed comparison must carry metrics")
        if not isinstance(seed_comparison.get("source_fingerprint"), str) or not seed_comparison.get(
            "source_fingerprint"
        ):
            raise EvidenceError("a provided seed comparison must carry a source fingerprint")

    candidate_label = _candidate_label(candidate)
    label_table = _evidence_label_table(
        candidate_label,
        samples=samples,
        metrics=metrics,
        diff=diff,
        gate_facts=gate_facts,
        baseline=baseline_evidence,
        seed_comparison=seed_comparison,
        failure_summary=failure_summary,
    )
    comparison_identity = {
        "baseline": (
            {
                "reference": baseline_evidence.source.get("reference"),
                "source_fingerprint": baseline_evidence.source.get("source_fingerprint"),
            }
            if baseline_evidence.source
            else None
        ),
        "seed": (
            {
                "seed_candidate_id": seed_comparison.get("seed_candidate_id"),
                "source_fingerprint": seed_comparison.get("source_fingerprint"),
            }
            if seed_comparison
            else None
        ),
    }

    model_projection = {
        "projection_version": PROJECTION_VERSION,
        "category": category,
        "structure": structure_description,
        "template_examples": [
            {
                "label": f"示例 {index + 1}",
                "code": example.code,
                "cot": example.cot,
                "instruct_prompt": example.instruct_prompt,
            }
            for index, example in enumerate(template.examples)
        ],
        "diff": [dict(entry) for entry in diff],
        "gate_facts": [dict(entry) for entry in gate_facts],
        "samples": [sample.to_json() for sample in samples],
        "metrics": {name: metric.to_json() for name, metric in metrics.items()},
        "counts": counts,
        # Source/identity blocks stay audit-side; only human-readable facts are
        # model-visible.
        "baseline": {
            "available": baseline_evidence.available,
            "metrics": {name: metric.to_json() for name, metric in baseline_evidence.metrics.items()},
            "reason": baseline_evidence.reason,
        },
        "seed_comparison": _sanitize_seed_comparison(seed_comparison),
        "failure_summary": failure_summary.to_json() if failure_summary else None,
        # Explicit, namespaced label table so the inducer can cite traceable
        # evidence across templates without label collisions.
        "evidence_labels": label_table,
    }
    fingerprint = sha256_bytes(
        canonical_json_bytes(
            {"projection": model_projection, "comparison_identity": comparison_identity}
        )
    )
    internal_audit = {
        "candidate_id": candidate.logical_id(),
        "candidate_label": candidate_label,
        "candidate_hash": expected_candidate_hash,
        "template_sha256": template.content_sha256(),
        "sample_ids": [sample.get("sample_id") for sample in audit_samples],
        "comparison_identity": comparison_identity,
        "evidence_fingerprint": fingerprint,
    }
    return EvidencePack(
        category=category,
        candidate_id=candidate.logical_id(),
        template_content_sha256=template.content_sha256(),
        structure_description=structure_description,
        diff=tuple(dict(entry) for entry in diff),
        gate_facts=tuple(dict(entry) for entry in gate_facts),
        samples=samples,
        metrics=metrics,
        counts=counts,
        baseline=baseline_evidence,
        seed_comparison=dict(seed_comparison) if seed_comparison else None,
        failure_summary=failure_summary,
        evidence_labels=tuple(sorted(label_table)),
        audit=internal_audit,
        projection=model_projection,
        evidence_fingerprint=fingerprint,
    )


def _sanitize_seed_comparison(
    seed: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Keep only human-readable seed-comparison facts (drop source/identity)."""

    if not seed:
        return None
    raw_metrics = seed.get("metrics")
    metrics: dict[str, Any] = {}
    if isinstance(raw_metrics, Mapping):
        for name, metric in raw_metrics.items():
            if isinstance(metric, MetricEvidence):
                metrics[str(name)] = metric.to_json()
            elif isinstance(metric, Mapping):
                metrics[str(name)] = dict(metric)
            else:
                metrics[str(name)] = metric
    return {
        "seed_candidate_label": seed.get("seed_candidate_label"),
        "metrics": metrics,
        "per_task": seed.get("per_task"),
        "deltas": seed.get("deltas"),
    }


def _candidate_label(candidate: CandidateIdentity) -> str:
    """A compact, readable per-candidate label namespace (no full hash)."""

    base = f"cand-r{candidate.round_index}{candidate.stage}{candidate.candidate_index}"
    if candidate.stage == "B" and candidate.seed_candidate_id:
        base += f"-s{candidate.seed_candidate_id[:8]}"
    return base


def _evidence_label_table(
    candidate_label: str,
    *,
    samples: Sequence[SampleEvidence],
    metrics: Mapping[str, MetricEvidence],
    diff: Sequence[Mapping[str, Any]],
    gate_facts: Sequence[Mapping[str, Any]],
    baseline: BaselineEvidence,
    seed_comparison: Mapping[str, Any] | None,
    failure_summary: FailureSummary | None,
) -> dict[str, str]:
    """Map each citable evidence label to a human-readable description."""

    table: dict[str, str] = {}
    for sample in samples:
        table[f"{candidate_label}:sample:{sample.task_label}:r{sample.repeat}"] = (
            f"样本：{sample.task_label} 第 {sample.repeat + 1} 次"
        )
    for name in metrics:
        table[f"{candidate_label}:metric:{name}"] = f"指标：{name}"
    for entry in diff:
        table[f"{candidate_label}:diff:example{entry.get('example')}:{entry.get('field')}"] = (
            f"改动：示例 {entry.get('example')} 字段 {entry.get('field')}"
        )
    for index, entry in enumerate(gate_facts):
        table[f"{candidate_label}:gate:{index}:{entry.get('kind', 'fact')}"] = (
            f"门事实：{entry.get('kind', 'fact')}"
        )
    for name in baseline.metrics:
        table[f"{candidate_label}:baseline:{name}"] = f"固定基线指标：{name}"
    if seed_comparison:
        for name in seed_comparison.get("metrics") or {}:
            table[f"{candidate_label}:seed:{name}"] = f"对应 seed 指标：{name}"
    if failure_summary is not None:
        table[f"{candidate_label}:failure_summary"] = "本阶段失败概要"
    return table


# --------------------------------------------------------------------------- #
# Experience versions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExperienceEntry:
    label: str
    nature: str
    description: str
    change: str
    evidence: tuple[str, ...]
    uncertainty: str
    revision_of: str | None = None

    def __post_init__(self) -> None:
        if not self.label:
            raise EvidenceError("experience entry label must not be empty")
        if self.nature not in ("observation", "hypothesis"):
            raise EvidenceError("experience entry nature must be observation or hypothesis")
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def to_json(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "nature": self.nature,
            "description": self.description,
            "change": self.change,
            "evidence": list(self.evidence),
            "uncertainty": self.uncertainty,
            "revision_of": self.revision_of,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "ExperienceEntry":
        return cls(
            label=str(payload.get("label") or ""),
            nature=str(payload.get("nature") or ""),
            description=str(payload.get("description") or ""),
            change=str(payload.get("change") or ""),
            evidence=tuple(payload.get("evidence") or ()),
            uncertainty=str(payload.get("uncertainty") or ""),
            revision_of=payload.get("revision_of"),
        )


@dataclass(frozen=True)
class ExperienceVersion:
    category: str
    version_id: str
    previous_version_id: str | None
    induction_id: str
    action_id: str
    evidence_fingerprint: str
    entries: tuple[ExperienceEntry, ...]
    summary: str
    created_at: str | None = None
    cumulative_evidence_labels: tuple[str, ...] = ()
    cumulative_entry_labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.category not in EXPERIENCE_CATEGORIES:
            raise EvidenceError(f"category must be one of {EXPERIENCE_CATEGORIES}")
        if not self.version_id:
            raise EvidenceError("version_id must not be empty")
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(
            self, "cumulative_evidence_labels", tuple(self.cumulative_evidence_labels)
        )
        object.__setattr__(
            self, "cumulative_entry_labels", tuple(self.cumulative_entry_labels)
        )

    def evidence_labels(self) -> tuple[str, ...]:
        """Traceable evidence labels accumulated along the committed chain.

        Falls back to this version's own entries for versions written before the
        cumulative index existed.
        """

        if self.cumulative_evidence_labels:
            return tuple(sorted(set(self.cumulative_evidence_labels)))
        labels: set[str] = set()
        for entry in self.entries:
            labels |= set(entry.evidence)
        return tuple(sorted(labels))

    def entry_labels(self) -> tuple[str, ...]:
        """Traceable entry labels accumulated along the committed chain."""

        if self.cumulative_entry_labels:
            return tuple(sorted(set(self.cumulative_entry_labels)))
        return tuple(sorted({entry.label for entry in self.entries}))

    def reference(self) -> ExperienceVersionReference:
        return ExperienceVersionReference(
            category=self.category,
            version_id=self.version_id,
            previous_version_id=self.previous_version_id,
            summary=self.summary,
            entry_labels=self.entry_labels(),
            evidence_labels=self.evidence_labels(),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": EXPERIENCE_SCHEMA_VERSION,
            "category": self.category,
            "version_id": self.version_id,
            "previous_version_id": self.previous_version_id,
            "induction_id": self.induction_id,
            "action_id": self.action_id,
            "evidence_fingerprint": self.evidence_fingerprint,
            "entries": [entry.to_json() for entry in self.entries],
            "summary": self.summary,
            "created_at": self.created_at,
            "cumulative_evidence_labels": list(self.cumulative_evidence_labels),
            "cumulative_entry_labels": list(self.cumulative_entry_labels),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "ExperienceVersion":
        return cls(
            category=str(payload.get("category") or ""),
            version_id=str(payload.get("version_id") or ""),
            previous_version_id=payload.get("previous_version_id"),
            induction_id=str(payload.get("induction_id") or ""),
            action_id=str(payload.get("action_id") or ""),
            evidence_fingerprint=str(payload.get("evidence_fingerprint") or ""),
            entries=tuple(
                ExperienceEntry.from_json(item) for item in payload.get("entries", [])
            ),
            summary=str(payload.get("summary") or ""),
            created_at=payload.get("created_at"),
            cumulative_evidence_labels=tuple(
                payload.get("cumulative_evidence_labels") or ()
            ),
            cumulative_entry_labels=tuple(payload.get("cumulative_entry_labels") or ()),
        )


def compute_version_id(
    *,
    category: str,
    induction_id: str,
    previous_version_id: str | None,
    evidence_fingerprint: str,
    entries: Sequence[ExperienceEntry],
    summary: str,
    cumulative_evidence_labels: Sequence[str] = (),
    cumulative_entry_labels: Sequence[str] = (),
) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": EXPERIENCE_SCHEMA_VERSION,
                "category": category,
                "induction_id": induction_id,
                "previous_version_id": previous_version_id,
                "evidence_fingerprint": evidence_fingerprint,
                "entries": [entry.to_json() for entry in entries],
                "summary": summary,
                "cumulative_evidence_labels": sorted(set(cumulative_evidence_labels)),
                "cumulative_entry_labels": sorted(set(cumulative_entry_labels)),
            }
        )
    )


class ExperienceStore:
    """Immutable experience versions plus logical induction records."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def versions_dir(self, category: str) -> Path:
        if category not in EXPERIENCE_CATEGORIES:
            raise EvidenceError(f"category must be one of {EXPERIENCE_CATEGORIES}")
        return self.root / "versions" / category

    def version_path(self, category: str, version_id: str) -> Path:
        return self.versions_dir(category) / f"{version_id}.json"

    def read_version(self, category: str, version_id: str) -> ExperienceVersion:
        path = self.version_path(category, version_id)
        if not path.is_file():
            raise EvidenceError(f"experience version not found: {path}")
        payload = read_json(path)
        if not isinstance(payload, Mapping):
            raise EvidenceError(f"experience version is not a JSON object: {path}")
        version = ExperienceVersion.from_json(payload)
        if version.version_id != version_id or version.category != category:
            raise EvidenceError(f"experience version identity mismatch at {path}")
        recomputed = compute_version_id(
            category=version.category,
            induction_id=version.induction_id,
            previous_version_id=version.previous_version_id,
            evidence_fingerprint=version.evidence_fingerprint,
            entries=version.entries,
            summary=version.summary,
            cumulative_evidence_labels=version.cumulative_evidence_labels,
            cumulative_entry_labels=version.cumulative_entry_labels,
        )
        if recomputed != version.version_id:
            raise EvidenceError(f"experience version content hash mismatch at {path}")
        return version

    def write_version(self, version: ExperienceVersion) -> ExperienceVersion:
        path = self.version_path(version.category, version.version_id)
        if path.is_file():
            existing = self.read_version(version.category, version.version_id)
            if existing.to_json() != version.to_json():
                raise EvidenceError(
                    f"experience version {version.version_id} already exists with different content"
                )
            return existing
        write_json_atomic(path, version.to_json())
        return version

    def induction_path(self, induction_id: str) -> Path:
        return self.root / "inductions" / f"{induction_id}.json"

    def read_induction(self, induction_id: str) -> dict[str, Any] | None:
        path = self.induction_path(induction_id)
        if not path.is_file():
            return None
        payload = read_json(path)
        if not isinstance(payload, Mapping):
            raise EvidenceError(f"induction record is not a JSON object: {path}")
        return dict(payload)

    def write_induction(self, induction_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        path = self.induction_path(induction_id)
        record = {
            "schema_version": INDUCTION_SCHEMA_VERSION,
            "induction_id": induction_id,
            **dict(payload),
        }
        if path.is_file():
            existing = read_json(path)
            if existing != record:
                raise EvidenceError(
                    f"induction {induction_id} already recorded with different content"
                )
            return dict(existing)
        write_json_atomic(path, record)
        return record

    def input_lock_path(self, induction_id: str) -> Path:
        return self.root / "inductions" / f"{induction_id}.input.json"

    def read_input_lock(self, induction_id: str) -> dict[str, Any] | None:
        path = self.input_lock_path(induction_id)
        if not path.is_file():
            return None
        payload = read_json(path)
        if not isinstance(payload, Mapping):
            raise EvidenceError(f"induction input lock is not a JSON object: {path}")
        return dict(payload)

    def write_input_lock(self, induction_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Persist the fixed logical-induction input before the first call.

        All retries of the same logical induction must match this lock, so a
        failed attempt can never be retried against different evidence.
        """

        path = self.input_lock_path(induction_id)
        record = {
            "schema_version": INDUCTION_SCHEMA_VERSION,
            "induction_id": induction_id,
            **dict(payload),
        }
        if path.is_file():
            existing = read_json(path)
            if existing != record:
                raise EvidenceError(
                    f"induction {induction_id} is already locked to different input"
                )
            return dict(existing)
        write_json_atomic(path, record)
        return record


# --------------------------------------------------------------------------- #
# Induction orchestration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class InductionIdentity:
    run_id: str
    round_index: int
    stage: str
    candidate_id: str
    protocol_version: str = JUDGE_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not self.run_id or not self.candidate_id or not self.stage:
            raise EvidenceError("induction identity fields must not be empty")
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int) or self.round_index < 1:
            raise EvidenceError("round_index must be a positive integer")

    def logical_id(self) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": INDUCTION_SCHEMA_VERSION,
                    "run_id": self.run_id,
                    "round_index": self.round_index,
                    "stage": self.stage,
                    "candidate_id": self.candidate_id,
                    "protocol_version": self.protocol_version,
                }
            )
        )


@dataclass(frozen=True)
class InductionOutcome:
    induction_id: str
    status: str
    action_id: str
    version: ExperienceVersion | None = None
    reference: ExperienceVersionReference | None = None
    errors: tuple[str, ...] = ()
    source_calls: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "induction_id": self.induction_id,
            "status": self.status,
            "action_id": self.action_id,
            "version_id": self.version.version_id if self.version else None,
            "errors": list(self.errors),
            "source_calls": self.source_calls,
        }


def _entries_from_drafts(drafts: Sequence[Any]) -> tuple[ExperienceEntry, ...]:
    return tuple(
        ExperienceEntry(
            label=draft.label,
            nature=draft.nature,
            description=draft.description,
            change=draft.change,
            evidence=tuple(draft.evidence),
            uncertainty=draft.uncertainty,
            revision_of=draft.revision_of,
        )
        for draft in drafts
    )


def _ensure_action_commit(
    action_store: ActionStore, action_id: str, commit: Mapping[str, Any]
) -> None:
    existing = action_store.read_commit(action_id)
    if existing is not None:
        action_store.ensure_committed_event(action_id, commit)
        return
    action_store.write_commit(action_id, commit)


@with_prompt_bundle
def run_induction(
    store: ExperienceStore,
    action_store: ActionStore,
    *,
    induction: InductionIdentity,
    evidence: EvidencePack,
    previous_reference: ExperienceVersionReference,
    source: RoleCallSource,
    experience_versions: tuple[ExperienceVersionReference, ...] = (),
    retry_index: int = 0,
    allow_retry_after_unknown: bool = False,
    config: RoleCallConfig | None = None,
    prompt_template_sha256: str | None = None,
) -> InductionOutcome:
    """Run (or resume) one logical induction and commit exactly one version."""

    induction_id = induction.logical_id()
    if evidence.category != previous_reference.category:
        raise EvidenceError("evidence category does not match the previous experience category")

    resolved_config = config or _inducer_config(induction.protocol_version)
    template_sha = prompt_template_sha256 or template_identity()
    if template_sha != template_identity():
        raise EvidenceError("prompt template bundle changed during induction")

    context_versions = list(experience_versions)
    if previous_reference not in context_versions:
        context_versions.insert(0, previous_reference)
    context_identity = [
        list(item)
        for item in sorted(
            {
                (reference.category, reference.version_id, reference.previous_version_id)
                for reference in context_versions
            }
        )
    ]
    # Fix the logical input before the first call: evidence, the category chain
    # parent, the readable context experience of *both* categories and the
    # request-affecting config must stay identical across every retry.
    locked_input = {
        "category": evidence.category,
        "evidence_fingerprint": evidence.evidence_fingerprint,
        "previous_version_id": previous_reference.version_id,
        "protocol_version": induction.protocol_version,
        "config_sha256": resolved_config.config_sha256(),
        "context_experience": context_identity,
        "prompt_template_sha256": template_sha,
    }

    def input_matches(record: Mapping[str, Any]) -> bool:
        return all(record.get(key) == value for key, value in locked_input.items())

    existing = store.read_induction(induction_id)
    if existing is not None:
        if not input_matches(existing):
            return InductionOutcome(
                induction_id=induction_id,
                status=_STATUS_CONFLICT,
                action_id=str(existing.get("action_id") or ""),
                errors=(
                    "the logical induction is already committed for different evidence, "
                    "experience context, config or prompt templates; refusing to overwrite it",
                ),
            )
        version = store.read_version(existing["category"], existing["version_id"])
        _ensure_action_commit(
            action_store,
            existing["action_id"],
            {
                "induction_id": induction_id,
                "category": version.category,
                "version_id": version.version_id,
                "previous_version_id": version.previous_version_id,
                "evidence_fingerprint": version.evidence_fingerprint,
            },
        )
        return InductionOutcome(
            induction_id=induction_id,
            status=_STATUS_COMMITTED,
            action_id=existing["action_id"],
            version=version,
            reference=version.reference(),
        )

    existing_lock = store.read_input_lock(induction_id)
    if existing_lock is not None:
        if not input_matches(existing_lock):
            return InductionOutcome(
                induction_id=induction_id,
                status=_STATUS_CONFLICT,
                action_id=judge_action_id(induction_id, induction.protocol_version, retry_index),
                errors=(
                    "the logical induction input was already fixed; a retry cannot "
                    "change evidence, experience context, config or prompt templates",
                ),
            )
    else:
        store.write_input_lock(induction_id, locked_input)

    known_evidence_labels = tuple(
        sorted(
            set(evidence.evidence_labels)
            | set(previous_reference.evidence_labels)
            | {label for ref in context_versions for label in ref.evidence_labels}
        )
    )
    judge_input = JudgeInput(
        category=evidence.category,
        previous_experience=previous_reference,
        experience_versions=tuple(context_versions),
        evidence=evidence.model_visible(),
        known_evidence_labels=known_evidence_labels,
        known_entry_labels=previous_reference.entry_labels,
        failure_summary=(
            evidence.failure_summary.to_json() if evidence.failure_summary else None
        ),
    )
    try:
        messages = build_judge_messages(judge_input)
    except RoleCapacityError as error:
        return InductionOutcome(
            induction_id=induction_id,
            status=_STATUS_CAPACITY_BLOCKED,
            action_id=judge_action_id(induction_id, induction.protocol_version, retry_index),
            errors=(str(error),),
        )

    from coco_attack.iteration.action_runtime import RoleActionRequest

    action_id = judge_action_id(induction_id, induction.protocol_version, retry_index)
    request = RoleActionRequest(
        action_id=action_id,
        role=INDUCER_ROLE,
        kind="reasoning",
        messages=messages.messages,
        config=resolved_config,
        input_refs={**dict(messages.input_refs), "protocol_version": messages.protocol_version},
    )
    try:
        outcome = run_role_call(
            action_store, request, source=source, allow_retry_after_unknown=allow_retry_after_unknown
        )
    except ActionConflictError as error:
        return InductionOutcome(
            induction_id=induction_id,
            status=_STATUS_CONFLICT,
            action_id=action_id,
            errors=(str(error),),
        )
    if outcome.state not in ("response_reused", "response_saved") or outcome.response_status != "success":
        status = _STATUS_PAUSED_UNKNOWN if outcome.state == "unknown_paused" else _STATUS_FAILED
        return InductionOutcome(
            induction_id=induction_id,
            status=status,
            action_id=action_id,
            errors=(outcome.error or outcome.response_status or outcome.state,),
        )
    content = str((outcome.response or {}).get("content") or "")
    parsed = parse_judge_response(
        content,
        category=evidence.category,
        known_evidence_labels=known_evidence_labels,
        known_entry_labels=previous_reference.entry_labels,
    )
    if parsed.status != "parsed":
        return InductionOutcome(
            induction_id=induction_id,
            status=_STATUS_PROTOCOL_ERROR,
            action_id=action_id,
            errors=parsed.errors,
        )

    entries = _entries_from_drafts(parsed.entries)
    summary = str(parsed.summary)
    cumulative_evidence = tuple(
        sorted(
            set(previous_reference.evidence_labels)
            | {label for entry in entries for label in entry.evidence}
        )
    )
    cumulative_entries = tuple(
        sorted(
            set(previous_reference.entry_labels)
            | {entry.label for entry in entries}
        )
    )
    version_id = compute_version_id(
        category=evidence.category,
        induction_id=induction_id,
        previous_version_id=previous_reference.version_id,
        evidence_fingerprint=evidence.evidence_fingerprint,
        entries=entries,
        summary=summary,
        cumulative_evidence_labels=cumulative_evidence,
        cumulative_entry_labels=cumulative_entries,
    )
    version = ExperienceVersion(
        category=evidence.category,
        version_id=version_id,
        previous_version_id=previous_reference.version_id,
        induction_id=induction_id,
        action_id=action_id,
        evidence_fingerprint=evidence.evidence_fingerprint,
        entries=entries,
        summary=summary,
        cumulative_evidence_labels=cumulative_evidence,
        cumulative_entry_labels=cumulative_entries,
    )
    store.write_version(version)
    store.write_induction(
        induction_id,
        {
            "category": version.category,
            "version_id": version.version_id,
            "action_id": action_id,
            "previous_version_id": version.previous_version_id,
            "evidence_fingerprint": version.evidence_fingerprint,
            "protocol_version": induction.protocol_version,
            "config_sha256": locked_input["config_sha256"],
            "context_experience": context_identity,
            "prompt_template_sha256": template_sha,
        },
    )
    _ensure_action_commit(
        action_store,
        action_id,
        {
            "induction_id": induction_id,
            "category": version.category,
            "version_id": version.version_id,
            "previous_version_id": version.previous_version_id,
            "evidence_fingerprint": version.evidence_fingerprint,
        },
    )
    return InductionOutcome(
        induction_id=induction_id,
        status=_STATUS_COMMITTED,
        action_id=action_id,
        version=version,
        reference=version.reference(),
    )


def _inducer_config(protocol_version: str) -> RoleCallConfig:
    return inducer_config(protocol_version)


__all__ = [
    "EXPERIENCE_SCHEMA_VERSION",
    "INDUCTION_SCHEMA_VERSION",
    "EVIDENCE_SCHEMA_VERSION",
    "PROJECTION_VERSION",
    "TERMINAL_GENERATION_STATUSES",
    "EvidenceError",
    "EvidenceNotReady",
    "MetricEvidence",
    "SampleEvidence",
    "BaselineEvidence",
    "FailureSummary",
    "EvidencePack",
    "ExperienceEntry",
    "ExperienceVersion",
    "ExperienceStore",
    "InductionIdentity",
    "InductionOutcome",
    "assemble_evidence_pack",
    "metric_delta",
    "compute_version_id",
    "run_induction",
]
