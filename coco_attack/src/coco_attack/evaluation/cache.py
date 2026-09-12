"""Evaluation cache protocol (task 04).

Only the functional-test result cache is implemented later (stage 02). This
module defines the uniform query/write protocol and a disabled implementation
that always misses and never saves, so no evaluator can silently reuse a
verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class CacheLookup:
    hit: bool
    value: dict[str, Any] | None
    key: str
    reason: str


class EvaluationCache(Protocol):
    def get(self, key: str) -> CacheLookup: ...

    def put(self, key: str, value: dict[str, Any]) -> None: ...


class DisabledCache:
    """Always misses and never stores; used for all evaluators this round."""

    def get(self, key: str) -> CacheLookup:
        return CacheLookup(hit=False, value=None, key=key, reason="cache_disabled")

    def put(self, key: str, value: dict[str, Any]) -> None:
        return None
