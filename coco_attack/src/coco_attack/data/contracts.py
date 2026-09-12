"""Public record boundaries for the data and protocol layers.

These dataclasses are deliberately plain (stdlib only, no DSPy) so that the
generation, evaluation and iteration layers can share one contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..assets.issues import Issue
from ..protocol.stages import SplitMode


class DataContractError(Exception):
    """Raised when strict loading/selection/split validation fails.

    Carries the full :class:`Issue` list so callers can persist diagnostics
    without publishing a partial dataset.
    """

    def __init__(self, message: str, issues: list[Issue]) -> None:
        super().__init__(message)
        self.issues = list(issues)


@dataclass(frozen=True)
class TaskSource:
    combination_id: str
    source_path: str
    source_file_sha256: str
    line_number: int
    schema: str
    record_sha256: str


@dataclass(frozen=True)
class TaskRecord:
    combination_id: str
    task_id: str
    raw: dict[str, Any]
    effective: dict[str, Any]
    metadata_provenance: dict[str, dict[str, Any]]
    source: TaskSource

    def __getitem__(self, field_name: str) -> Any:
        return self.effective[field_name]

    def get(self, field_name: str, default: Any = None) -> Any:
        return self.effective.get(field_name, default)

    @property
    def code_prompt(self) -> str:
        return self.effective["code_prompt"]

    @property
    def entry_point(self) -> str:
        return self.effective["entry_point"]

    @property
    def test(self) -> str:
        return self.effective["test"]

    @property
    def reference_side(self) -> str:
        return self.effective["reference_side"]

    def snapshot(self) -> dict[str, Any]:
        """Registry-aligned 17-field task snapshot plus provenance."""

        snapshot = dict(self.effective)
        snapshot["_provenance"] = {
            "combination_id": self.combination_id,
            "schema": self.source.schema,
            "source_path": self.source.source_path,
            "source_file_sha256": self.source.source_file_sha256,
            "source_line": self.source.line_number,
            "record_sha256": self.source.record_sha256,
            "raw_metadata_values": {
                field: self.raw.get(field)
                for field in self.metadata_provenance
            },
            "metadata_provenance": self.metadata_provenance,
        }
        return snapshot


@dataclass(frozen=True)
class CombinationSpec:
    combination_id: str
    registry_id: str
    oracle_id: str
    legacy_alias: str | None
    task_file: str
    selection_source: str
    selection_file: str
    selection_key: str
    clean_assets: dict[str, Any] | None
    coverage: dict[str, bool]
    registry_definition: dict[str, Any]

    @property
    def is_legacy(self) -> bool:
        return self.legacy_alias is not None and self.selection_source == "legacy"


@dataclass(frozen=True)
class DatasetSelection:
    combination_id: str
    seed: int
    example_ids: tuple[str, ...]
    evaluation_ids: tuple[str, ...]
    selection_source: str
    selection_file: str
    selection_file_sha256: str
    verification_sources: tuple[str, ...]
    task_snapshot_sha256: str
    warnings: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "combination_id": self.combination_id,
            "seed": self.seed,
            "example_ids": list(self.example_ids),
            "evaluation_ids": list(self.evaluation_ids),
            "selection_source": self.selection_source,
            "selection_file": self.selection_file,
            "selection_file_sha256": self.selection_file_sha256,
            "verification_sources": list(self.verification_sources),
            "task_snapshot_sha256": self.task_snapshot_sha256,
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "DatasetSelection":
        return cls(
            combination_id=payload["combination_id"],
            seed=payload["seed"],
            example_ids=tuple(payload["example_ids"]),
            evaluation_ids=tuple(payload["evaluation_ids"]),
            selection_source=payload["selection_source"],
            selection_file=payload["selection_file"],
            selection_file_sha256=payload["selection_file_sha256"],
            verification_sources=tuple(payload.get("verification_sources") or ()),
            task_snapshot_sha256=payload["task_snapshot_sha256"],
            warnings=tuple(payload.get("warnings") or ()),
        )


@dataclass(frozen=True)
class SplitManifest:
    combination_id: str
    mode: SplitMode
    seed: int | None
    algorithm_version: str
    split_config_sha256: str
    input_ids: tuple[str, ...]
    input_ids_sha256: str
    task_snapshot_sha256: str
    search_ids: tuple[str, ...]
    holdout_ids: tuple[str, ...]
    evaluation_ids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "1",
            "combination_id": self.combination_id,
            "mode": self.mode.value,
            "seed": self.seed,
            "algorithm_version": self.algorithm_version,
            "split_config_sha256": self.split_config_sha256,
            "input_ids": list(self.input_ids),
            "input_ids_sha256": self.input_ids_sha256,
            "task_snapshot_sha256": self.task_snapshot_sha256,
            "evaluation_ids": list(self.evaluation_ids),
        }
        if self.mode is SplitMode.SEARCH_HOLDOUT:
            payload["search"] = list(self.search_ids)
            payload["holdout"] = list(self.holdout_ids)
        else:
            payload["search"] = []
            payload["holdout"] = []
            payload["holdout_exists"] = False
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "SplitManifest":
        mode = SplitMode(payload["mode"])
        return cls(
            combination_id=payload["combination_id"],
            mode=mode,
            seed=payload.get("seed"),
            algorithm_version=payload["algorithm_version"],
            split_config_sha256=payload["split_config_sha256"],
            input_ids=tuple(payload.get("input_ids") or ()),
            input_ids_sha256=payload["input_ids_sha256"],
            task_snapshot_sha256=payload["task_snapshot_sha256"],
            search_ids=tuple(payload.get("search") or ()),
            holdout_ids=tuple(payload.get("holdout") or ()),
            evaluation_ids=tuple(payload.get("evaluation_ids") or ()),
        )


@dataclass(frozen=True)
class PreparedCombination:
    """A fully validated combination read back from ``prepare-data`` output."""

    combination_id: str
    registry_id: str
    oracle_id: str
    data_contract: str
    records: tuple[TaskRecord, ...]
    selection: DatasetSelection
    split: SplitManifest
    manifest_sha256: str
    files: dict[str, str] = field(default_factory=dict)

    def task_by_id(self) -> dict[str, TaskRecord]:
        return {record.task_id: record for record in self.records}


@dataclass
class LoadedTasks:
    spec: CombinationSpec
    records: tuple[TaskRecord, ...]
    file_sha256: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def task_ids(self) -> tuple[str, ...]:
        return tuple(record.task_id for record in self.records)

    def by_id(self) -> dict[str, TaskRecord]:
        return {record.task_id: record for record in self.records}
