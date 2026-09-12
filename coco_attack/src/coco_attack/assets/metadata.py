"""Registry-authoritative task metadata normalization.

The original screening registry is the single source of truth for
``statistical_cwe_id``, ``experiment_type`` and ``decision``. Task files
exported from that registry occasionally carry slightly different labels (for
example ``cwe022-0`` carries ``hybrid_api_control_flow`` / ``qualified`` while
the registry definition says ``control_flow`` / ``qualified_control_flow``).

The rebuild aligns the *effective* metadata to the registry without mutating
the read-only historical task files. Raw values are retained as provenance so
the deviation remains auditable.
"""

from __future__ import annotations

from typing import Any

# Fields whose authority is the combination registry definition.
REGISTRY_AUTHORITATIVE_FIELDS = ("statistical_cwe_id", "experiment_type", "decision")


def normalize_task_metadata(
    raw_record: dict[str, Any],
    routed_definition: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Return ``(effective_record, provenance)`` with registry values applied.

    ``provenance`` is empty when the raw record already matches the registry.
    A field is only overridden when the registry actually defines a value.
    """

    effective = dict(raw_record)
    provenance: dict[str, dict[str, Any]] = {}
    if not routed_definition:
        return effective, provenance

    for field in REGISTRY_AUTHORITATIVE_FIELDS:
        if field == "statistical_cwe_id":
            registry_value = routed_definition.get("statistical_cwe_id") or routed_definition.get(
                "registry_id"
            )
        else:
            registry_value = routed_definition.get(field)
        if registry_value is None:
            continue
        raw_value = raw_record.get(field)
        if raw_value != registry_value:
            provenance[field] = {
                "raw": raw_value,
                "effective": registry_value,
                "authority": "registry",
            }
        effective[field] = registry_value
    return effective, provenance
