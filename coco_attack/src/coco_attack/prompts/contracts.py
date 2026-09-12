"""Public records for prompt experiments (task 03)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..assets.artifacts import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True)
class ExperimentSpec:
    combination_id: str
    oracle_id: str
    form: str
    example_ids: tuple[str, ...]
    excluded_ids: tuple[str, ...]
    evaluation_ids: tuple[str, ...]
    data_contract: str
    task_snapshot_sha256: str
    split_manifest_sha256: str
    selection_sha256: str
    prompt_version: str
    materialize_version: str
    attack_config: dict[str, Any]


@dataclass(frozen=True)
class PromptSource:
    path: str
    sha256: str
    kind: str


@dataclass(frozen=True)
class PromptExperiment:
    spec: ExperimentSpec
    meta: dict[str, Any]
    fewshot: tuple[dict[str, Any], ...]
    prompts: dict[str, str]
    sources: tuple[PromptSource, ...]

    def prompt_hashes(self) -> dict[str, str]:
        return {task_id: sha256_bytes(text.encode("utf-8")) for task_id, text in self.prompts.items()}

    def content_sha256(self) -> str:
        payload = {
            "spec": {
                "combination_id": self.spec.combination_id,
                "oracle_id": self.spec.oracle_id,
                "form": self.spec.form,
                "example_ids": list(self.spec.example_ids),
                "evaluation_ids": list(self.spec.evaluation_ids),
                "prompt_version": self.spec.prompt_version,
                "materialize_version": self.spec.materialize_version,
            },
            "prompts": self.prompt_hashes(),
        }
        return sha256_bytes(canonical_json_bytes(payload))
