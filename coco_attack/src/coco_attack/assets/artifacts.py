"""Stable JSON/JSONL reading and atomic writing.

Stability rules used across the application:

* semantic fingerprints hash raw bytes (never normalised text);
* machine records use UTF-8, sorted keys and LF line endings;
* observation-only fields (timestamps, durations, absolute run directories)
  must not enter semantic hashes.

The helpers here are intentionally dependency-free so that the domain
foundation can run without importing DSPy.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

JSONValue = Any

_CHUNK_SIZE = 1024 * 1024


class JsonlError(ValueError):
    """Raised when a JSONL line is not a JSON object."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash the raw bytes of a file without transforming newlines or content."""

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(obj: JSONValue) -> bytes:
    """Compact, sorted JSON bytes used for hashing stable structures."""

    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def stable_json_text(obj: JSONValue) -> str:
    """Human-readable, sorted JSON text with a trailing newline (LF)."""

    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def stable_json_bytes(obj: JSONValue) -> bytes:
    return stable_json_text(obj).encode("utf-8")


def read_json(path: Path) -> JSONValue:
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(physical_line_number, object)`` for non-empty JSONL lines.

    Blank lines are skipped; a syntactically invalid or non-object line raises
    :class:`JsonlError` with the file and physical line number.
    """

    with open(path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise JsonlError(
                    f"{path}:{lineno}: invalid JSONL record: {error}"
                ) from error
            if not isinstance(obj, dict):
                raise JsonlError(
                    f"{path}:{lineno}: JSONL record is not a JSON object "
                    f"(got {type(obj).__name__})"
                )
            yield lineno, obj


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def write_text_atomic(path: Path, text: str) -> None:
    write_bytes_atomic(path, text.encode("utf-8"))


def write_json_atomic(path: Path, obj: JSONValue) -> None:
    write_bytes_atomic(path, stable_json_bytes(obj))


def assert_fresh_dir(path: Path) -> None:
    """Require a non-existent or empty output directory.

    Refuses to silently overwrite an earlier run so that a failed preparation
    cannot be mistaken for a successful one.
    """

    if path.exists() and not path.is_dir():
        raise NotADirectoryError(f"Output path exists and is not a directory: {path}")
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(
            f"Output directory is not empty; refusing to overwrite: {path}"
        )
