"""Path resolution helpers for the CoCo-Attack application.

The application never guesses asset locations from the current working
directory. Every asset path is resolved relative to an explicit asset root
passed by the caller, and resolution is confined to that root.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath


class PathResolutionError(ValueError):
    """Raised when a relative asset path is invalid or escapes its root."""


def project_root() -> Path:
    """Return the ``coco_attack`` project root (the directory holding configs/).

    Layout (editable install)::

        coco_attack/                 <- project root
        ├── configs/
        ├── pyproject.toml
        └── src/coco_attack/assets/paths.py   <- this file

    Discovery walks upwards for the directory that contains both ``configs/``
    and ``pyproject.toml``; this is independent of the current working
    directory and of how deep this module sits under ``src``.
    """

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "configs").is_dir() and (parent / "pyproject.toml").is_file():
            return parent
    # Fallback for an unusual layout: coco_attack/{src/coco_attack/assets/paths.py}
    return here.parents[3]


def default_config_dir() -> Path:
    """Locate the packaged ``configs/`` directory.

    Raises a clear error rather than silently using a wrong directory when the
    project layout is not the expected editable one.
    """

    candidates = [
        project_root() / "configs",
        Path.cwd() / "configs",
        Path.cwd() / "coco_attack" / "configs",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "Cannot locate coco_attack configs/ directory. Expected editable layout "
        f"with configs next to pyproject.toml (tried: {[str(c) for c in candidates]})."
    )


def normalize_relative(relative: str | os.PathLike[str]) -> PurePosixPath:
    """Normalise an asset-relative path and reject absolute/escaping paths."""

    raw = os.fspath(relative)
    if not raw:
        raise PathResolutionError("Asset-relative path must not be empty.")
    pure = PurePosixPath(raw.replace("\\", "/"))
    if pure.is_absolute():
        raise PathResolutionError(f"Asset-relative path must not be absolute: {raw!r}")
    parts = [part for part in pure.parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PathResolutionError(f"Asset-relative path must not contain '..': {raw!r}")
    if not parts:
        raise PathResolutionError(f"Asset-relative path resolved to nothing: {raw!r}")
    return PurePosixPath(*parts)


def resolve_within(root: Path, relative: str | os.PathLike[str]) -> Path:
    """Resolve ``relative`` under ``root`` and confine the result to ``root``."""

    rel = normalize_relative(relative)
    root_resolved = Path(root).resolve()
    candidate = (root_resolved / Path(*rel.parts)).resolve()
    if not candidate.is_relative_to(root_resolved):
        raise PathResolutionError(
            f"Asset path escapes asset root: {rel.as_posix()!r} (root={root_resolved})"
        )
    return candidate


def require_dir(path: Path, what: str) -> Path:
    if not path.is_dir():
        raise NotADirectoryError(f"{what} is not an existing directory: {path}")
    return path


def require_file(path: Path, what: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(f"{what} is not an existing file: {path}")
    return path


def relative_to_root(root: Path, path: Path) -> str:
    """Return ``path`` relative to ``root`` using POSIX separators."""

    return path.resolve().relative_to(Path(root).resolve()).as_posix()


def assert_assets_output_separation(assets_root: Path, output_dir: Path) -> None:
    """Refuse to write the audit output inside the read-only asset tree."""

    assets_resolved = assets_root.resolve()
    output_resolved = output_dir.resolve()
    if output_resolved == assets_resolved or output_resolved.is_relative_to(assets_resolved):
        raise PathResolutionError(
            f"Output directory must not live inside the read-only asset root: {output_resolved}"
        )
