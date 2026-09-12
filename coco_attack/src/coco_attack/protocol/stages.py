"""Execution stages and set modes for the experiment protocol.

Only ``search`` and ``holdout`` are execution stages. ``whole-set`` is a set
mode (no holdout exists), not a third stage. This mirrors the task book and the
implementation plan.
"""

from __future__ import annotations

from enum import Enum


class Stage(str, Enum):
    SEARCH = "search"
    HOLDOUT = "holdout"


class SplitMode(str, Enum):
    SEARCH_HOLDOUT = "search_holdout"
    WHOLE_SET = "whole-set"


SPLIT_ALGORITHM_VERSION = "sha256-seed-taskid-v1"
PREPARE_SCHEMA_VERSION = "1"
DATA_CONTRACT_VERSION = "bigcodebench-screened-v1"

DEFAULT_SEED = 42


__all__ = [
    "Stage",
    "SplitMode",
    "SPLIT_ALGORITHM_VERSION",
    "PREPARE_SCHEMA_VERSION",
    "DATA_CONTRACT_VERSION",
    "DEFAULT_SEED",
]
