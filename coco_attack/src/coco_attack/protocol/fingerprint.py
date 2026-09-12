"""Stable fingerprints for data preparation.

All fingerprints hash canonical structures, never wall-clock values, durations
or absolute machine paths, so that preparing the same inputs twice yields
byte-identical manifests.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ..assets.artifacts import canonical_json_bytes, sha256_bytes


def hash_id_sequence(task_ids: Iterable[str]) -> str:
    return sha256_bytes(canonical_json_bytes(list(task_ids)))


def hash_task_snapshot(records: Iterable[tuple[str, str]]) -> str:
    """Hash ``(task_id, record_sha256)`` pairs in order.

    ``record_sha256`` is the hash of the raw source record, so the snapshot
    hash changes if any source record changes even when ids stay the same.
    """

    return sha256_bytes(canonical_json_bytes([list(pair) for pair in records]))


def split_sort_key(seed: int, task_id: str) -> tuple[str, str]:
    """Deterministic ordering key: ``(sha256(seed:task_id), task_id)``."""

    digest = hashlib.sha256(f"{seed}:{task_id}".encode("utf-8")).hexdigest()
    return digest, task_id
