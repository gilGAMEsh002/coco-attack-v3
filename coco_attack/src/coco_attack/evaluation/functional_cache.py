"""Per-sample functional test result cache (plan section 6, F1).

A small SQLite index plus immutable artifact files, separated per stage.  Only
results that pass the functional eligibility checks are stored; unavailable /
error / incomplete placeholders are never reusable.  The cache key never
includes execution attempt, nonce, container name or paths, so a restored run
reuses the same sample result without re-executing.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assets.artifacts import canonical_json_bytes, sha256_bytes, sha256_file
from .cache import CacheLookup

CACHE_SCHEMA_VERSION = "functional-cache-v1"
FINGERPRINT_SCHEMA_VERSION = "functional-fingerprint-v1"

FINGERPRINT_FIELDS = (
    "sample_id",
    "stage",
    "batch_id",
    "combination_id",
    "oracle_id",
    "generation_status",
    "run_config_bytes_sha256",
    "prompt_sha256",
    "raw_generation_sha256",
    "final_code_sha256",
    "task_snapshot_sha256",
    "test_sha256",
    "entry_point",
    "fixture_sha256",
    "cleaner_version",
    "harness_version",
    "classifier_version",
    "result_schema",
    "image_id",
    "dependency_lock_sha256",
    "execution_semantics",
    "candidate_timeout_seconds",
    "schema_version",
)


class FunctionalCacheError(RuntimeError):
    pass


def functional_fingerprint(**fields: Any) -> dict[str, Any]:
    unknown = sorted(set(fields) - set(FINGERPRINT_FIELDS))
    if unknown:
        # Never silently drop an accepted configuration from the cache key.
        raise FunctionalCacheError(f"functional fingerprint has unknown fields: {unknown}")
    payload: dict[str, Any] = {"schema_version": FINGERPRINT_SCHEMA_VERSION}
    for name in FINGERPRINT_FIELDS:
        if name == "schema_version":
            continue
        if name not in fields:
            raise FunctionalCacheError(f"functional fingerprint missing field: {name}")
        value = fields[name]
        if value is None or (isinstance(value, str) and not value):
            raise FunctionalCacheError(f"functional fingerprint field {name!r} must be non-empty")
        payload[name] = value
    return payload


def fingerprint_sha256(fingerprint: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(fingerprint))


def compose_key(sample_id: str, fingerprint_sha: str) -> str:
    return f"{sample_id}::{fingerprint_sha}"


def parse_key(key: str) -> tuple[str, str]:
    sample_id, _, fingerprint_sha = key.partition("::")
    if not sample_id or not fingerprint_sha:
        raise FunctionalCacheError(f"malformed functional cache key: {key!r}")
    return sample_id, fingerprint_sha


@dataclass
class FunctionalCache:
    """SQLite-backed functional result cache for one stage."""

    cache_root: Path
    stage: str

    def __post_init__(self) -> None:
        if self.stage not in ("search", "holdout"):
            raise FunctionalCacheError(f"invalid cache stage: {self.stage!r}")
        self.cache_root = Path(self.cache_root).resolve()
        self.stage_root = self.cache_root / CACHE_SCHEMA_VERSION / self.stage
        self.artifacts_dir = self.stage_root / "artifacts"
        self.index_path = self.stage_root / "index.sqlite3"
        self.stage_root.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        if self.stage_root.is_symlink() or self.artifacts_dir.is_symlink():
            raise FunctionalCacheError("functional cache stage directory must not be a symlink")
        self._initialize()

    # -- schema ------------------------------------------------------------ #

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.index_path, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS results ("
                " sample_id TEXT NOT NULL,"
                " fingerprint_sha256 TEXT NOT NULL,"
                " fingerprint_json TEXT NOT NULL,"
                " result_json TEXT NOT NULL,"
                " execution_json TEXT NOT NULL,"
                " files_json TEXT NOT NULL,"
                " accounting_id TEXT,"
                " PRIMARY KEY (sample_id, fingerprint_sha256))"
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES ('schema_version', ?)",
                (CACHE_SCHEMA_VERSION,),
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES ('stage', ?)", (self.stage,)
            )

    # -- protocol ---------------------------------------------------------- #

    def get(self, key: str) -> CacheLookup:
        sample_id, fingerprint_sha = parse_key(key)
        return self.lookup(sample_id, fingerprint_sha)

    def put(self, key: str, value: dict[str, Any]) -> None:
        sample_id, fingerprint_sha = parse_key(key)
        self.store(
            sample_id=sample_id,
            fingerprint=value["fingerprint"],
            result=value["result"],
            execution=value.get("execution") or {},
            artifacts=value.get("artifact_sources") or {},
            accounting_id=value.get("accounting_id"),
        )

    # -- functional API ---------------------------------------------------- #

    def lookup(self, sample_id: str, fingerprint_sha: str) -> CacheLookup:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT fingerprint_json, result_json, execution_json, files_json"
                " FROM results WHERE sample_id=? AND fingerprint_sha256=?",
                (sample_id, fingerprint_sha),
            ).fetchone()
        key = compose_key(sample_id, fingerprint_sha)
        if row is None:
            return CacheLookup(hit=False, value=None, key=key, reason="not_found")
        fingerprint_json, result_json, execution_json, files_json = row
        fingerprint = json.loads(fingerprint_json)
        if fingerprint_sha256(fingerprint) != fingerprint_sha:
            return CacheLookup(hit=False, value=None, key=key, reason="fingerprint_corrupt")
        if fingerprint.get("stage") != self.stage:
            return CacheLookup(hit=False, value=None, key=key, reason="stage_mismatch")
        result_payload = json.loads(result_json)
        # The stored result must belong to the queried sample/fingerprint; a
        # tampered or corrupted row must not be served as a valid hit.
        if result_payload.get("sample_id") != sample_id:
            return CacheLookup(hit=False, value=None, key=key, reason="result_identity_mismatch")
        if result_payload.get("fingerprint_sha256") != fingerprint_sha:
            return CacheLookup(hit=False, value=None, key=key, reason="result_fingerprint_mismatch")
        files = json.loads(files_json)
        for relative, expected in files.items():
            path = self.artifacts_dir / relative
            if not path.is_file() or path.is_symlink():
                return CacheLookup(hit=False, value=None, key=key, reason=f"artifact_missing:{relative}")
            if sha256_file(path) != expected:
                return CacheLookup(hit=False, value=None, key=key, reason=f"artifact_hash_mismatch:{relative}")
        return CacheLookup(
            hit=True,
            value={
                "result": result_payload,
                "execution": json.loads(execution_json),
                "fingerprint": fingerprint,
                "artifacts": files,
                "reuse_source": f"functional-cache:{self.stage}",
            },
            key=key,
            reason="hit",
        )

    def store(
        self,
        *,
        sample_id: str,
        fingerprint: dict[str, Any],
        result: dict[str, Any],
        execution: dict[str, Any],
        artifacts: dict[str, str],
        accounting_id: str | None = None,
    ) -> None:
        fingerprint_sha = fingerprint_sha256(fingerprint)
        if fingerprint.get("stage") != self.stage:
            raise FunctionalCacheError("refusing to store a result under a different stage")
        if not result.get("cache_eligible"):
            raise FunctionalCacheError("refusing to store a non-cache-eligible functional result")

        with self._connect() as connection:
            existing = connection.execute(
                "SELECT result_json FROM results WHERE sample_id=? AND fingerprint_sha256=?",
                (sample_id, fingerprint_sha),
            ).fetchone()
            if existing is not None:
                if existing[0] != canonical_json_bytes(result).decode("utf-8"):
                    raise FunctionalCacheError(
                        "conflicting functional result for the same cache key"
                    )
                return

            published: dict[str, str] = {}
            target_dir = self.artifacts_dir / sample_id / fingerprint_sha
            target_dir.mkdir(parents=True, exist_ok=True)
            for name, source in sorted(artifacts.items()):
                source_path = Path(source)
                if not source_path.is_file() or source_path.is_symlink():
                    raise FunctionalCacheError(f"artifact source is not a regular file: {source}")
                destination = target_dir / name
                _copy_atomic(source_path, destination)
                published[f"{sample_id}/{fingerprint_sha}/{name}"] = sha256_file(destination)

            result_json = canonical_json_bytes(result).decode("utf-8")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO results(sample_id, fingerprint_sha256, fingerprint_json,"
                    " result_json, execution_json, files_json, accounting_id)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        sample_id,
                        fingerprint_sha,
                        json.dumps(fingerprint, sort_keys=True),
                        result_json,
                        json.dumps(execution, sort_keys=True),
                        json.dumps(published, sort_keys=True),
                        accounting_id,
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise


def _copy_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(source.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def execution_semantics(profile: Any) -> dict[str, Any]:
    """The part of the execution profile that changes functional results."""

    return {
        "network": profile.sandbox.network,
        "read_only_rootfs": profile.sandbox.read_only_rootfs,
        "cap_drop": list(profile.sandbox.cap_drop),
        "no_new_privileges": profile.sandbox.no_new_privileges,
        "memory_bytes": profile.limits.memory_bytes,
        "memory_swap_bytes": profile.limits.memory_swap_bytes,
        "cpu_quota": profile.limits.cpu_quota,
        "pids_limit": profile.limits.pids_limit,
        "workspace_bytes": profile.limits.workspace_bytes,
        "shm_bytes": profile.limits.shm_bytes,
        "wall_clock_seconds": profile.timeouts.wall_clock_seconds,
        "sigterm_grace_seconds": profile.timeouts.sigterm_grace_seconds,
        "entry": "functional",
        "result_schema": "functional-payload-v1",
    }


__all__ = [
    "CACHE_SCHEMA_VERSION",
    "FINGERPRINT_SCHEMA_VERSION",
    "FunctionalCache",
    "FunctionalCacheError",
    "functional_fingerprint",
    "fingerprint_sha256",
    "compose_key",
    "parse_key",
    "execution_semantics",
]
