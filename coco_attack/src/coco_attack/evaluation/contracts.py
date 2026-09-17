"""Public evaluation records and metric results (task 04)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

STATIC_VERDICTS = frozenset({"target_present", "target_absent", "parse_error"})
EVALUATION_LAYERS = (
    "static",
    "sast",
    "judge",
    "functional",
    "dynamic",
    "realism",
)

TASK_SET_CHOICES = ("evaluation", "search", "holdout", "whole-set")


@dataclass(frozen=True)
class EvaluationConfig:
    combination_id: str
    oracle_id: str
    model: str
    temperature: float
    repeats: int
    task_set: str
    prompt_form: str | None = None
    split_ref: str | None = None
    experiment_ref: str | None = None
    notes: str | None = None
    task_ids: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "EvaluationConfig":
        missing = [
            field_name
            for field_name in ("combination_id", "oracle_id", "model", "temperature", "repeats", "task_set")
            if field_name not in payload
        ]
        if missing:
            raise ValueError(f"evaluation config missing required fields: {missing}")
        if not isinstance(payload["repeats"], int) or isinstance(payload["repeats"], bool) or payload["repeats"] < 1:
            raise ValueError("repeats must be a positive integer")
        if not isinstance(payload["temperature"], (int, float)) or isinstance(payload["temperature"], bool):
            raise ValueError("temperature must be a number")
        if payload["task_set"] not in TASK_SET_CHOICES:
            raise ValueError(f"task_set must be one of {TASK_SET_CHOICES}")
        return cls(
            combination_id=str(payload["combination_id"]),
            oracle_id=str(payload["oracle_id"]),
            model=str(payload["model"]),
            temperature=float(payload["temperature"]),
            repeats=int(payload["repeats"]),
            task_set=str(payload["task_set"]),
            prompt_form=payload.get("prompt_form"),
            split_ref=payload.get("split_ref"),
            experiment_ref=payload.get("experiment_ref"),
            notes=payload.get("notes"),
            task_ids=tuple(payload.get("task_ids") or ()),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "model": self.model,
            "temperature": self.temperature,
            "repeats": self.repeats,
            "task_set": self.task_set,
            "prompt_form": self.prompt_form,
            "split_ref": self.split_ref,
            "experiment_ref": self.experiment_ref,
            "notes": self.notes,
            "task_ids": list(self.task_ids),
        }

    @property
    def sampling(self) -> dict[str, Any]:
        return {"model": self.model, "temperature": self.temperature, "repeats": self.repeats}


@dataclass(frozen=True)
class EvaluationRecord:
    combination_id: str
    oracle_id: str
    task_id: str
    repeat_id: int
    batch_id: str
    final_code: str
    final_code_sha256: str
    generation_status: str
    cleaning_source: dict[str, Any]
    verdict: str
    target_present: bool
    returned_oracle_id: str
    oracle_layer: str
    raw_oracle_result: dict[str, Any]
    target_present_source: str
    entry_present: bool
    syntax_ok: bool | None
    evaluator_fingerprint: dict[str, Any]
    layer_availability: dict[str, Any]

    @property
    def asr_hit(self) -> bool:
        return self.verdict == "target_present"

    def to_json(self) -> dict[str, Any]:
        payload = {
            "schema_version": "1",
            "combination_id": self.combination_id,
            "oracle_id": self.oracle_id,
            "task_id": self.task_id,
            "repeat_id": self.repeat_id,
            "batch_id": self.batch_id,
            "final_code_sha256": self.final_code_sha256,
            "generation_status": self.generation_status,
            "cleaning_source": self.cleaning_source,
            "verdict": self.verdict,
            "target_present": self.target_present,
            "asr_hit": self.asr_hit,
            "returned_oracle_id": self.returned_oracle_id,
            "oracle_layer": self.oracle_layer,
            "raw_oracle_result": self.raw_oracle_result,
            "target_present_source": self.target_present_source,
            "entry_present": self.entry_present,
            "syntax_ok": self.syntax_ok,
            "evaluator_fingerprint": self.evaluator_fingerprint,
            "layer_availability": self.layer_availability,
        }
        return payload


@dataclass(frozen=True)
class MetricResult:
    name: str
    value: float | None
    defined: bool
    reason: str | None
    numerator: float | int | None
    denominator: int | None
    k: int | None = None
    task_count: int | None = None
    sample_count: int | None = None
    task_set: str | None = None
    sampling: dict[str, Any] = field(default_factory=dict)
    availability: dict[str, Any] = field(default_factory=dict)
    per_task: tuple[dict[str, Any], ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def undefined(
        cls,
        name: str,
        reason: str,
        **kwargs: Any,
    ) -> "MetricResult":
        return cls(
            name=name,
            value=None,
            defined=False,
            reason=reason,
            numerator=None,
            denominator=None,
            **kwargs,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "defined": self.defined,
            "reason": self.reason,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "k": self.k,
            "task_count": self.task_count,
            "sample_count": self.sample_count,
            "task_set": self.task_set,
            "sampling": self.sampling,
            "availability": self.availability,
            "per_task": list(self.per_task),
            "extra": self.extra,
        }
