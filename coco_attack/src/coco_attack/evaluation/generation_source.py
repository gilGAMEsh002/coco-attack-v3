"""Resolve where a pipeline run's generation artifacts live.

A pipeline can either generate internally (``<run>/generation``) or accept an
external generation run referenced by ``pipeline_config.json``.  Reporting, the
core checkpoint and the static/evasion join must all resolve the same source, or
an external reference is silently dropped and the report looks empty.
"""

from __future__ import annotations

from pathlib import Path

from ..assets.artifacts import read_json


class GenerationSourceError(ValueError):
    """The run's generation source cannot be determined safely."""


def resolve_generation_run(run_dir: Path | str) -> Path:
    """Return the generation directory for a pipeline run.

    ``pipeline_config.json`` is authoritative when present: ``generation_run``
    points at a caller-supplied generation directory.  A present-but-unreadable
    config is an error rather than a silent fallback to the (likely empty)
    internal directory.  Without a config, ``<run>/generation`` is used.
    """

    run = Path(run_dir)
    config_path = run / "pipeline_config.json"
    if not config_path.is_file():
        return run / "generation"
    try:
        payload = read_json(config_path)
    except (OSError, ValueError) as error:
        raise GenerationSourceError(f"unreadable pipeline config: {config_path}") from error
    if not isinstance(payload, dict):
        raise GenerationSourceError(f"pipeline config is not a JSON object: {config_path}")
    generation_run = payload.get("generation_run")
    if generation_run:
        return Path(str(generation_run)).resolve()
    return run / "generation"


__all__ = ["GenerationSourceError", "resolve_generation_run"]
