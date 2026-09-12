"""Load the unique combination routing table into ``CombinationSpec`` records.

The routing table (``configs/combinations.json``) is the only application
source for combination identities; the original screening registry provides the
authoritative definitions. No CWE name guessing and no implicit ``-0`` suffixing
happens here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json
from ..assets.audit import load_combinations_config
from ..assets.issues import SEVERITY_ERROR, Issue
from ..assets.paths import resolve_within
from .contracts import CombinationSpec, DataContractError


def load_combination_specs(
    assets_root: Path,
    config_dir: Path | None = None,
) -> tuple[dict[str, CombinationSpec], Path, set[str]]:
    config, config_path = load_combinations_config(config_dir)
    registry_path = resolve_within(assets_root, config["registry_file"])
    registry = read_json(registry_path)
    taxonomy = set(registry.get("type_taxonomy") or {})

    definitions: dict[str, dict[str, Any]] = {}
    for definition in registry.get("combination_definitions") or []:
        statistical_id = definition.get("statistical_id")
        if statistical_id in definitions:
            raise DataContractError(
                f"duplicate registry definition for {statistical_id!r}",
                [
                    Issue(
                        code="registry.duplicate_definition",
                        severity=SEVERITY_ERROR,
                        scope="registry",
                        detail=f"duplicate statistical_id {statistical_id!r}",
                        asset=config["registry_file"],
                    )
                ],
            )
        definitions[statistical_id] = definition

    selection_files = config["selection_files"]
    specs: dict[str, CombinationSpec] = {}
    for combo in config["combinations"]:
        combination_id = combo["combination_id"]
        registry_id = combo["registry_id"]
        definition = definitions.get(registry_id)
        if definition is None:
            raise DataContractError(
                f"routed registry id {registry_id!r} has no definition",
                [
                    Issue(
                        code="registry.route_missing",
                        severity=SEVERITY_ERROR,
                        scope="registry",
                        detail=f"missing registry definition for {registry_id!r}",
                        asset=config["registry_file"],
                        location={"combination_id": combination_id},
                    )
                ],
            )
        source = combo["selection"]["source"]
        if source not in selection_files:
            raise DataContractError(
                f"unknown selection source {source!r}",
                [
                    Issue(
                        code="config.unknown_selection_source",
                        severity=SEVERITY_ERROR,
                        scope="config",
                        detail=f"selection source {source!r} not declared",
                        asset="combinations.json",
                        location={"combination_id": combination_id},
                    )
                ],
            )
        # The routed oracle must exist; never infer a judge from the CWE name.
        oracle_module = f"oracles/{combo['oracle_id'].replace('-', '_')}.py"
        if not resolve_within(assets_root, oracle_module).is_file():
            raise DataContractError(
                f"{combination_id}: routed oracle module missing",
                [
                    Issue(
                        code="oracle.route_missing",
                        severity=SEVERITY_ERROR,
                        scope="oracle",
                        detail=(
                            f"routed oracle {combo['oracle_id']!r} has no module at "
                            f"{oracle_module}"
                        ),
                        asset=oracle_module,
                        location={"combination_id": combination_id},
                    )
                ],
            )
        specs[combination_id] = CombinationSpec(
            combination_id=combination_id,
            registry_id=registry_id,
            oracle_id=combo["oracle_id"],
            legacy_alias=combo.get("legacy_alias"),
            task_file=combo["task_file"],
            selection_source=source,
            selection_file=selection_files[source],
            selection_key=combo["selection"]["key"],
            clean_assets=combo.get("clean_assets"),
            coverage=dict(combo.get("coverage") or {}),
            registry_definition=dict(definition),
        )
    return specs, config_path, taxonomy


def legacy_alias_for(
    combination_id: str, config_dir: Path | None = None
) -> str | None:
    """Return the explicit legacy alias for a combination, if configured."""

    config, _ = load_combinations_config(config_dir)
    for combo in config["combinations"]:
        if combo["combination_id"] == combination_id:
            return combo.get("legacy_alias")
    return None


def resolve_combination_selection(
    specs: dict[str, CombinationSpec],
    requested: list[str],
) -> list[str]:
    """Resolve ``--combination`` values (repeated ids or a single ``all``)."""

    if not requested:
        raise DataContractError(
            "no combination requested",
            [
                Issue(
                    code="cli.combination_required",
                    severity=SEVERITY_ERROR,
                    scope="cli",
                    detail="at least one --combination is required",
                )
            ],
        )
    if "all" in requested:
        if len(requested) > 1:
            raise DataContractError(
                "'all' cannot be combined with explicit combination ids",
                [
                    Issue(
                        code="cli.combination_all_exclusive",
                        severity=SEVERITY_ERROR,
                        scope="cli",
                        detail=f"received {requested!r}",
                    )
                ],
            )
        return sorted(specs)
    unknown = sorted(set(requested) - set(specs))
    if unknown:
        raise DataContractError(
            f"unknown combination ids: {unknown}",
            [
                Issue(
                    code="cli.unknown_combination",
                    severity=SEVERITY_ERROR,
                    scope="cli",
                    detail=f"combination ids not in routing table: {unknown}",
                )
            ],
        )
    ordered: list[str] = []
    for combination_id in requested:
        if combination_id not in ordered:
            ordered.append(combination_id)
    return ordered
