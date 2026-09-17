"""Interfaces shared by dynamic oracle combination specifications."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RuntimeObservation:
    argument_name: str
    argument_present: bool
    argument_value: Any
    target_observed: bool
    evidence: dict[str, Any] = field(default_factory=dict)


class DynamicOracleSpec:
    oracle_id: str
    target_pattern: str

    def matches_symbol(self, symbol: str) -> bool:
        raise NotImplementedError

    def observe(
        self,
        label: str,
        callable_object: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        is_test_double: bool,
    ) -> RuntimeObservation:
        raise NotImplementedError

    def blocked_result(self, label: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        raise NotImplementedError
