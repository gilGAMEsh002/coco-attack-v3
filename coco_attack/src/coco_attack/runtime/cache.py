"""Per-source/per-stage DSPy cache namespaces (plan section 5.1).

The coordinator assigns each generation process a cache directory derived from
the source and stage.  Search and holdout (and mock and dmx) must resolve to
physically distinct directories; symlinks or shared realpaths are rejected so a
method projection cannot reach another stage's cached responses.
"""

from __future__ import annotations

from pathlib import Path

CACHE_NAMESPACE_VERSION = "dspy-cache-namespace-v1"


class CacheNamespaceError(ValueError):
    pass


def namespace_path(cache_root: Path | str, source: str, stage: str) -> Path:
    return (Path(cache_root) / CACHE_NAMESPACE_VERSION / source / stage).resolve()


def assert_physical_separation(paths: list[Path]) -> None:
    seen: dict[Path, Path] = {}
    for path in paths:
        if path.is_symlink():
            raise CacheNamespaceError(f"cache namespace must not be a symlink: {path}")
        resolved = path.resolve()
        if resolved in seen:
            raise CacheNamespaceError(
                f"cache namespaces are not physically separate: {path} and {seen[resolved]}"
            )
        seen[resolved] = path


def configure_stage_cache(cache_root: Path | str, source: str, stage: str) -> Path:
    """Create and activate the cache directory for this source/stage."""

    path = namespace_path(cache_root, source, stage)
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():  # pragma: no cover - mkdir would not create one
        raise CacheNamespaceError(f"cache namespace must not be a symlink: {path}")
    import dspy

    dspy.configure_cache(
        enable_disk_cache=True,
        enable_memory_cache=True,
        disk_cache_dir=str(path),
    )
    return path


__all__ = [
    "CACHE_NAMESPACE_VERSION",
    "CacheNamespaceError",
    "namespace_path",
    "assert_physical_separation",
    "configure_stage_cache",
]
