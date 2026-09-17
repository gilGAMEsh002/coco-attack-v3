"""Registry of per-combination dynamic target specifications."""

from __future__ import annotations

from .specs.base import DynamicOracleSpec
from .specs.cwe078_0 import SPEC as CWE078_0
from .specs.cwe094_0 import SPEC as CWE094_0
from .specs.cwe295_0 import SPEC as CWE295_0
from .specs.cwe502_0 import SPEC as CWE502_0


SPECS: dict[str, DynamicOracleSpec] = {
    spec.oracle_id: spec
    for spec in (CWE078_0, CWE094_0, CWE295_0, CWE502_0)
}


def get_dynamic_spec(oracle_id: str) -> DynamicOracleSpec:
    try:
        return SPECS[oracle_id]
    except KeyError as error:
        raise ValueError(f"Unsupported dynamic oracle: {oracle_id}") from error
