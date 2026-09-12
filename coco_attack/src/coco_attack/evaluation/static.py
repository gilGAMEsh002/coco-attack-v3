"""Trusted static-oracle loading and strict per-sample evaluation (task 04).

The oracle judgement code is reused byte-for-byte from the read-only asset
tree. This module only adds routing, a strict validation shell and provenance;
it never rewrites judgement logic and never imports or executes candidate code.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from ..assets.artifacts import sha256_file
from ..assets.paths import resolve_within
from .contracts import STATIC_VERDICTS

SHARED_ORACLE_FILES = (
    "oracles/static_registry.py",
    "oracles/_static_common.py",
    "oracles/_symbols.py",
)

_LOADED_ROOT: Path | None = None
_MODULE_CACHE: dict[str, tuple[ModuleType, str]] = {}


class OracleLoadError(RuntimeError):
    pass


class OracleContractError(RuntimeError):
    pass


def load_oracle_module(assets_root: Path, oracle_id: str) -> ModuleType:
    """Import the routed oracle module from a single fixed trusted root."""

    global _LOADED_ROOT
    root = assets_root.resolve()
    if _LOADED_ROOT is None:
        _LOADED_ROOT = root
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
    elif _LOADED_ROOT != root:
        raise OracleLoadError(
            f"oracle asset root already fixed to {_LOADED_ROOT}; cannot switch to {root}"
        )

    existing_package = sys.modules.get("oracles")
    if existing_package is not None:
        package_file = getattr(existing_package, "__file__", None)
        if package_file is not None and not Path(package_file).resolve().is_relative_to(root):
            raise OracleLoadError(
                f"an 'oracles' package was already imported from {package_file}, "
                f"not from trusted root {root}"
            )

    cached = _MODULE_CACHE.get(oracle_id)
    if cached is not None:
        module, cached_hash = cached
        module_file = getattr(module, "__file__", None)
        if (
            module_file is not None
            and Path(module_file).is_file()
            and sha256_file(Path(module_file)) == cached_hash
        ):
            return module
        # The oracle source changed under a long-lived process: reload it so the
        # loaded implementation always matches the recorded fingerprint.
        module = importlib.reload(module)
    else:
        registry = importlib.import_module("oracles.static_registry")
        module_name = getattr(registry, "STATIC_MODULES", {}).get(oracle_id)
        if module_name is None:
            raise OracleLoadError(f"unsupported static oracle id: {oracle_id!r}")
        module = importlib.import_module(f"oracles.{module_name}")

    module_file = getattr(module, "__file__", None)
    if module_file is None or not Path(module_file).resolve().is_relative_to(root):
        raise OracleLoadError(
            f"oracle module for {oracle_id!r} loaded from unexpected path: {module_file}"
        )
    _MODULE_CACHE[oracle_id] = (module, sha256_file(Path(module_file)))
    return module


def oracle_fingerprint(assets_root: Path, oracle_id: str) -> dict[str, Any]:
    fingerprint: dict[str, Any] = {"oracle_id": oracle_id}
    fingerprints: dict[str, str] = {}
    for relative in (*SHARED_ORACLE_FILES, f"oracles/{oracle_id.replace('-', '_')}.py"):
        path = resolve_within(assets_root, relative)
        if not path.is_file():
            raise OracleLoadError(f"oracle dependency missing: {relative}")
        fingerprints[relative] = sha256_file(path)
    fingerprint["files"] = fingerprints
    module = load_oracle_module(assets_root, oracle_id)
    fingerprint["oracle_version"] = getattr(module, "ORACLE_VERSION", 1)
    return fingerprint


def validate_oracle_result(
    raw: Any, expected_oracle_id: str
) -> dict[str, Any]:
    """Enforce the triple runtime contract on a raw oracle return value."""

    if not isinstance(raw, dict):
        raise OracleContractError(
            f"oracle {expected_oracle_id} returned {type(raw).__name__}, expected dict"
        )
    if raw.get("oracle_id") != expected_oracle_id:
        raise OracleContractError(
            f"oracle returned id {raw.get('oracle_id')!r}, expected {expected_oracle_id!r}"
        )
    verdict = raw.get("verdict")
    if verdict not in STATIC_VERDICTS:
        raise OracleContractError(f"invalid static verdict: {verdict!r}")
    target_present = raw.get("target_present")
    if not isinstance(target_present, bool):
        raise OracleContractError(
            f"target_present must be a bool, got {type(target_present).__name__}"
        )
    if target_present != (verdict == "target_present"):
        raise OracleContractError(
            f"target_present={target_present!r} is inconsistent with verdict {verdict!r}"
        )
    layer = raw.get("oracle_layer", "static")
    if layer != "static":
        raise OracleContractError(f"unexpected oracle layer: {layer!r}")
    normalized = dict(raw)
    normalized.setdefault("oracle_layer", "static")
    return normalized


def evaluate_static_sample(
    final_code: str,
    expected_oracle_id: str,
    module: ModuleType,
) -> dict[str, Any]:
    raw = module.evaluate(final_code)
    return validate_oracle_result(raw, expected_oracle_id)
