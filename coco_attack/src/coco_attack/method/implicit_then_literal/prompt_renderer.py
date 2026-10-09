"""Strict, immutable prompt bundles for role rendering and run recovery."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from importlib.resources import files
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from jinja2 import DictLoader, Environment, StrictUndefined

_ROOT = files("coco_attack.method.implicit_then_literal").joinpath("prompt_templates")
# Filled with the byte-identical extraction's digest, never recomputed at import.
# A legacy run/lock without a recorded digest may only use this exact bundle.
LEGACY_TEMPLATE_SHA256 = "0a51c58c9ab37ba82ae0f2532b5ea28ad614a6f3b3068c0ee97ffc5742a55429"
_ACTIVE: ContextVar[PromptBundle | None] = ContextVar("itl_prompt_bundle", default=None)


def _fingerprint(contents: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for name, source in sorted(contents.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


class PromptBundle:
    """A single in-memory copy; subsequent file edits cannot change its output."""

    def __init__(self, contents: Mapping[str, str]) -> None:
        if not contents or any(
            not isinstance(name, str) or not isinstance(source, str)
            or not name or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            for name, source in contents.items()
        ):
            raise ValueError("invalid prompt bundle files")
        self.contents = MappingProxyType(dict(contents))
        self.sha256 = _fingerprint(self.contents)
        try:
            manifest = json.loads(self.contents["manifest.json"])
            entries = manifest["roles"]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid or missing prompt manifest") from error
        if not isinstance(entries, dict) or not entries:
            raise ValueError("prompt manifest must declare template entries")
        for name, path in entries.items():
            if not isinstance(name, str) or not isinstance(path, str) or path not in contents:
                raise FileNotFoundError(f"missing prompt template: {name}")
        self.entries = MappingProxyType(dict(entries))
        self._environment = Environment(
            loader=DictLoader(self.contents), undefined=StrictUndefined,
            autoescape=False, keep_trailing_newline=False,
        )
        # Fail on malformed templates before any provider call, including a
        # malformed template for a role not yet reached by the state machine.
        for name in self.contents:
            if name.endswith(".j2"):
                self._environment.get_template(name)

    def render(self, name: str, **context: Any) -> str:
        try:
            path = self.entries[name]
        except KeyError as error:
            raise FileNotFoundError(f"template is not declared in manifest: {name}") from error
        return self._environment.get_template(path).render(**context)

    def to_json(self) -> dict[str, Any]:
        return {"schema_version": "itl-prompt-bundle-v1", "sha256": self.sha256,
                "files": dict(self.contents)}

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> PromptBundle:
        if not isinstance(payload, Mapping) or payload.get("schema_version") != "itl-prompt-bundle-v1":
            raise ValueError("invalid prompt bundle snapshot")
        contents = payload.get("files")
        if not isinstance(contents, Mapping):
            raise ValueError("invalid prompt bundle snapshot files")
        bundle = cls(contents)
        if payload.get("sha256") != bundle.sha256:
            raise ValueError("prompt bundle snapshot content hash mismatch")
        return bundle


def load_packaged_bundle() -> PromptBundle:
    contents: dict[str, str] = {}

    def visit(directory: Any, prefix: str = "") -> None:
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if child.is_dir():
                visit(child, relative)
            elif child.is_file():
                contents[relative] = child.read_bytes().decode("utf-8")

    visit(_ROOT)
    return PromptBundle(contents)


def current_bundle() -> PromptBundle:
    return _ACTIVE.get() or load_packaged_bundle()


@contextmanager
def use_prompt_bundle(bundle: PromptBundle) -> Iterator[PromptBundle]:
    token = _ACTIVE.set(bundle)
    try:
        yield bundle
    finally:
        _ACTIVE.reset(token)


def with_prompt_bundle(function):
    """Bind one immutable bundle throughout a full standalone role operation."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        with use_prompt_bundle(current_bundle()):
            return function(*args, **kwargs)
    return wrapped


def render(name: str, **context: Any) -> str:
    """Render once; code/JSON in context is never treated as another template."""
    return current_bundle().render(name, **context)


def template_identity() -> str:
    return current_bundle().sha256
