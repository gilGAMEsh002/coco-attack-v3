"""Cache namespace separation tests (stage 02, task 02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.runtime.cache import (
    CacheNamespaceError,
    assert_physical_separation,
    namespace_path,
)


def test_namespaces_are_distinct(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    paths = [
        namespace_path(root, "dmx", "search"),
        namespace_path(root, "dmx", "holdout"),
        namespace_path(root, "mock", "search"),
    ]
    assert len({str(path) for path in paths}) == 3
    assert_physical_separation(paths)


def test_duplicate_realpath_is_rejected(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    with pytest.raises(CacheNamespaceError):
        assert_physical_separation([shared, shared])


def test_symlinked_namespace_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(CacheNamespaceError):
        assert_physical_separation([link])
