"""Clean-baseline experiment matrix definition and unit expansion (phase 03).

Sub-task 01 owns the *definition* of the matrix and the expansion of the fixed
``combination x form x sampling`` grid into run units and per-run entries.  It
never samples, filters or otherwise adjusts the task sets: task counts come from
:data:`EXPECTED_TASK_COUNTS` and are treated as the contract.

This module is deliberately pure (no DSPy, no network, no filesystem writes).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ..assets.artifacts import canonical_json_bytes, read_json, sha256_bytes
from ..data.contracts import PreparedCombination
from ..generation.inputs import select_stage_task_ids
from ..prompts.markdown import CLEAN_FORMS
from ..protocol.stages import SplitMode

MATRIX_SCHEMA_VERSION = "baseline-matrix-v1"

# Fixed evaluation sets (main plan H).  ``cwe078`` includes task 205 per
# stage-01 D02.
BASELINE_COMBINATIONS = ("cwe078-0", "cwe094-0", "cwe295-0", "cwe502-0")
EXPECTED_TASK_COUNTS: dict[str, int] = {
    "cwe078-0": 27,
    "cwe094-0": 4,
    "cwe295-0": 33,
    "cwe502-0": 45,
}

# temperature=0/repeats=1 and temperature=0.7/repeats=5.
SAMPLING_CONFIGS: tuple[tuple[float, int], ...] = ((0.0, 1), (0.7, 5))

_ALLOWED_SOURCES = ("dmx", "mock")
_ALLOWED_LAYERS = ("sast", "judge", "dynamic", "realism")
_ALLOWED_TOOLS = ("bandit", "semgrep", "codeql")
_SHA256_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class MatrixError(ValueError):
    """A matrix definition or unit-expansion problem."""


class MatrixUsageError(MatrixError):
    """A matrix problem that is a caller/usage error (CLI exit code 2)."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise MatrixError(f"matrix.{name} must be a non-empty string, got {value!r}")
    return value


def _validate_image_digest(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value:
        raise MatrixError("matrix.image_digest must be a non-empty string or null")
    if value.startswith("sha256:") and not _SHA256_ID_RE.match(value):
        raise MatrixError(
            "matrix.image_digest starting with 'sha256:' must be 'sha256:<64 hex>', "
            f"got {value!r}"
        )


@dataclass(frozen=True)
class MatrixConfig:
    """One victim model's clean-baseline matrix configuration.

    A single matrix config carries exactly one victim model.  A second model
    requires its own matrix config and baseline root (immutable batch rule F).
    """

    victim_model: str
    judge_model: str
    max_tokens: int
    execution_config: str
    repo_dir: str
    assets_dir: str
    judge_max_tokens: int = 128
    image_digest: str | None = None
    baseline_root: str | None = None
    combinations: tuple[str, ...] = BASELINE_COMBINATIONS
    source: str = "dmx"
    judge_source: str = "dmx"
    enabled_layers: tuple[str, ...] = ("sast", "judge")
    sast_tools: tuple[str, ...] = ("bandit", "semgrep", "codeql")
    judge_enabled: bool = True
    semgrep_config: str | None = None
    codeql_executable: str | None = None
    codeql_search_path: str | None = None
    unit_concurrency: int = 1
    generation_max_concurrency: int = 1
    max_request_attempts: int = 3
    request_timeout: float = 60.0
    judge_temperature: float = 0.0
    judge_request_timeout: float = 120.0
    price_input_per_1k: float | None = None
    price_output_per_1k: float | None = None
    currency: str = "USD"
    pricing_version: str = "unset"
    judge_price_input_per_1k: float | None = None
    judge_price_output_per_1k: float | None = None
    judge_currency: str = "USD"
    judge_pricing_version: str = "unset"
    prompt_version: str = "1"
    batch_tag: str = "baseline-v1"
    k: tuple[int, ...] = (1, 3, 5)
    requests_per_minute: float | None = None
    tokens_per_minute: int | None = None
    operator: str = "unspecified"
    allow_dirty_worktree: bool = False
    split_config: str | None = None
    schema_version: str = MATRIX_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "victim_model",
            "judge_model",
            "execution_config",
            "repo_dir",
            "assets_dir",
            "batch_tag",
            "prompt_version",
            "operator",
        ):
            _require_str(getattr(self, name), name)

        if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, int) or self.max_tokens <= 0:
            raise MatrixError(f"matrix.max_tokens must be a positive integer, got {self.max_tokens!r}")
        if (
            isinstance(self.judge_max_tokens, bool)
            or not isinstance(self.judge_max_tokens, int)
            or self.judge_max_tokens <= 0
        ):
            raise MatrixError(
                f"matrix.judge_max_tokens must be a positive integer, got {self.judge_max_tokens!r}"
            )

        if self.source not in _ALLOWED_SOURCES:
            raise MatrixError(f"matrix.source must be one of {_ALLOWED_SOURCES}, got {self.source!r}")
        if self.judge_source not in _ALLOWED_SOURCES:
            raise MatrixError(
                f"matrix.judge_source must be one of {_ALLOWED_SOURCES}, got {self.judge_source!r}"
            )

        combinations = tuple(self.combinations)
        if not combinations:
            raise MatrixError("matrix.combinations must not be empty")
        if len(set(combinations)) != len(combinations):
            raise MatrixError(f"matrix.combinations contains duplicates: {combinations!r}")
        out_of_scope = [cid for cid in combinations if cid not in EXPECTED_TASK_COUNTS]
        if out_of_scope:
            raise MatrixError(
                "matrix.combinations contains combinations outside the registered "
                f"baseline set {sorted(EXPECTED_TASK_COUNTS)}: {out_of_scope}"
            )

        layers = tuple(self.enabled_layers)
        unknown_layers = [layer for layer in layers if layer not in _ALLOWED_LAYERS]
        if unknown_layers:
            raise MatrixError(f"matrix.enabled_layers has unknown layers: {unknown_layers}")
        if len(set(layers)) != len(layers):
            raise MatrixError(f"matrix.enabled_layers contains duplicates: {layers!r}")

        tools = tuple(self.sast_tools)
        unknown_tools = [tool for tool in tools if tool not in _ALLOWED_TOOLS]
        if unknown_tools:
            raise MatrixError(f"matrix.sast_tools has unknown tools: {unknown_tools}")
        if len(set(tools)) != len(tools):
            raise MatrixError(f"matrix.sast_tools contains duplicates: {tools!r}")

        for name in ("unit_concurrency", "generation_max_concurrency", "max_request_attempts"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise MatrixError(f"matrix.{name} must be an integer >= 1, got {value!r}")

        for name in ("request_timeout", "judge_request_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise MatrixError(f"matrix.{name} must be a positive number, got {value!r}")
        if (
            isinstance(self.judge_temperature, bool)
            or not isinstance(self.judge_temperature, (int, float))
            or self.judge_temperature < 0
        ):
            raise MatrixError(
                f"matrix.judge_temperature must be a non-negative number, got {self.judge_temperature!r}"
            )

        k = tuple(self.k)
        if not k or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in k):
            raise MatrixError(f"matrix.k must be positive integers, got {k!r}")

        _validate_image_digest(self.image_digest)

        # Normalise tuple fields so equality/serialisation is stable.
        object.__setattr__(self, "combinations", combinations)
        object.__setattr__(self, "enabled_layers", layers)
        object.__setattr__(self, "sast_tools", tools)
        object.__setattr__(self, "k", k)

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(value, tuple):
                value = list(value)
            payload[field.name] = value
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "MatrixConfig":
        if not isinstance(payload, dict):
            raise MatrixError("matrix config must be a JSON object")
        allowed = {field.name for field in fields(cls)}
        extra = sorted(set(payload) - allowed)
        if extra:
            raise MatrixError(f"matrix config has unknown fields: {extra}")
        required = (
            "victim_model",
            "judge_model",
            "max_tokens",
            "execution_config",
            "repo_dir",
            "assets_dir",
        )
        missing = [name for name in required if name not in payload]
        if missing:
            raise MatrixError(f"matrix config is missing required fields: {missing}")
        coerced = dict(payload)
        for name in ("combinations", "enabled_layers", "sast_tools", "k"):
            if name in coerced and coerced[name] is not None:
                coerced[name] = tuple(coerced[name])
        return cls(**coerced)


def load_matrix_config(path: Path | str) -> MatrixConfig:
    payload = read_json(Path(path))
    if not isinstance(payload, dict):
        raise MatrixError("matrix config must be a JSON object")
    return MatrixConfig.from_json(payload)


@dataclass(frozen=True)
class RunEntry:
    run_id: str
    unit_id: str
    stage: str
    split_mode: str
    task_ids: tuple[str, ...]
    expected_sample_count: int
    run_dir: str
    config_path: str


@dataclass(frozen=True)
class RunUnit:
    unit_id: str
    combination_id: str
    oracle_id: str
    form: str
    split_mode: str
    temperature: float
    repeats: int
    batch_id: str
    task_ids: tuple[str, ...]
    task_ids_sha256: str
    expected_task_count: int
    expected_sample_count: int
    entries: tuple[RunEntry, ...]


def _temp_tag(temperature: float) -> str:
    return f"{temperature:g}"


def _evaluation_order(ids: tuple[str, ...], selected: set[str]) -> tuple[str, ...]:
    return tuple(task_id for task_id in ids if task_id in selected)


def expand_units(
    matrix: MatrixConfig,
    prepared_by_combination: Mapping[str, PreparedCombination],
) -> tuple[RunUnit, ...]:
    """Expand the fixed grid into run units and per-run entries.

    A whole-set combination yields one unit per ``form x sampling`` with a single
    ``search`` entry over the full evaluation set (24 units / 24 entries for the
    whole-set baseline); a search/holdout combination yields the same units with
    separate ``search`` and ``holdout`` entries.  Task counts are asserted
    against :data:`EXPECTED_TASK_COUNTS`; a mismatch raises rather than silently
    adjusting the evaluation set.
    """

    units: list[RunUnit] = []
    for combination_id in matrix.combinations:
        prepared = prepared_by_combination.get(combination_id)
        if prepared is None:
            raise MatrixError(
                f"prepared data missing for combination {combination_id!r}; "
                "refusing to expand an incomplete matrix"
            )
        expected_count = EXPECTED_TASK_COUNTS[combination_id]
        evaluation_ids = tuple(prepared.selection.evaluation_ids)
        if len(evaluation_ids) != expected_count:
            raise MatrixError(
                f"{combination_id}: expected {expected_count} evaluation tasks from "
                f"EXPECTED_TASK_COUNTS, prepared data has {len(evaluation_ids)}; "
                "task sets must not be adjusted"
            )

        split = prepared.split
        if split.mode is SplitMode.SEARCH_HOLDOUT:
            split_mode = SplitMode.SEARCH_HOLDOUT.value
            combined = set(split.search_ids) | set(split.holdout_ids)
            task_ids = _evaluation_order(evaluation_ids, combined)
            stages = ("search", "holdout")
        else:
            split_mode = SplitMode.WHOLE_SET.value
            task_ids = evaluation_ids
            stages = ("search",)

        for form in CLEAN_FORMS:
            for temperature, repeats in SAMPLING_CONFIGS:
                unit_id = f"{combination_id}__{form}__t{_temp_tag(temperature)}r{repeats}"
                entries: list[RunEntry] = []
                for stage in stages:
                    run_id = f"{unit_id}::{stage}"
                    stage_task_ids = select_stage_task_ids(prepared, stage)
                    entries.append(
                        RunEntry(
                            run_id=run_id,
                            unit_id=unit_id,
                            stage=stage,
                            split_mode=split_mode,
                            task_ids=stage_task_ids,
                            expected_sample_count=len(stage_task_ids) * repeats,
                            run_dir=f"units/{unit_id}/{stage}",
                            config_path=f"configs/units/{run_id}.json",
                        )
                    )
                units.append(
                    RunUnit(
                        unit_id=unit_id,
                        combination_id=combination_id,
                        oracle_id=prepared.oracle_id,
                        form=form,
                        split_mode=split_mode,
                        temperature=temperature,
                        repeats=repeats,
                        batch_id=f"{matrix.batch_tag}::{unit_id}",
                        task_ids=task_ids,
                        task_ids_sha256=sha256_bytes(canonical_json_bytes(list(task_ids))),
                        expected_task_count=len(task_ids),
                        expected_sample_count=len(task_ids) * repeats,
                        entries=tuple(entries),
                    )
                )
    return tuple(units)


__all__ = [
    "MATRIX_SCHEMA_VERSION",
    "BASELINE_COMBINATIONS",
    "EXPECTED_TASK_COUNTS",
    "SAMPLING_CONFIGS",
    "CLEAN_FORMS",
    "MatrixConfig",
    "MatrixError",
    "MatrixUsageError",
    "RunEntry",
    "RunUnit",
    "expand_units",
    "load_matrix_config",
]
