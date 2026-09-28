"""Shared clean few-shot example loader.

The clean few-shot material lives in the read-only asset tree as
``<experiment_root>/<experiment>/fewshot.json`` plus a ``meta.json`` that
declares the ordered ``fewshot_ids``.  This module reads those files without
copying their bytes by hand and never writes back to the asset tree.

It is intentionally dependency-light (no evaluation/DSPy imports) so both the
direct example code check (I3) and the template snapshot service (I1) reuse the
same trusted loader and stay byte-consistent.  Behaviour moved here verbatim
from :mod:`coco_attack.iteration.code_check`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assets.artifacts import read_json, sha256_file
from ..assets.paths import PathResolutionError, resolve_within
from ..data.combination import load_combination_specs
from ..data.contracts import DataContractError


class FewshotError(ValueError):
    """Raised when a few-shot example source is unusable or inconsistent."""


@dataclass(frozen=True)
class FewshotExample:
    """One trusted few-shot example read from the read-only asset tree."""

    task_id: str
    code: str
    cot: tuple[str, ...]
    instruct_prompt: str
    index: int
    experiment: str
    source_path: str
    source_sha256: str


def load_specs(assets_root: Path) -> tuple[dict[str, Any], Path, set[str]]:
    """Load the combination registry, wrapping contract failures clearly."""

    try:
        return load_combination_specs(assets_root)
    except (DataContractError, FileNotFoundError, OSError, ValueError) as error:
        raise FewshotError(
            f"cannot load the combination registry from {assets_root}: {error}"
        ) from error


def _cot_tuple(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, list):
        return tuple(str(step) for step in raw)
    if isinstance(raw, str):
        return tuple(raw.split("\n"))
    return (str(raw),)


def _load_examples(
    *,
    assets_root: Path | str,
    combination_id: str,
    experiment: str,
    index: int | None = None,
) -> tuple[tuple[FewshotExample, ...], str]:
    """Read every example of one clean experiment and return them plus its ref.

    ``index`` is only used to validate the 0-based selection early; the plural
    loader passes ``None``.  The experiment directory is resolved from the
    registry's ``spec.clean_assets`` (``experiment_root`` + ``experiment``); the
    ``meta.json["fewshot_ids"]`` order must match the JSON list order.  Nothing
    is written back to the asset tree.
    """

    root = Path(assets_root)
    specs, _config_path, _taxonomy = load_specs(root)
    spec = specs.get(combination_id)
    if spec is None:
        raise FewshotError(
            f"unknown combination {combination_id!r}; known: {sorted(specs)}"
        )
    clean_assets = spec.clean_assets
    if not clean_assets:
        raise FewshotError(f"combination {combination_id!r} has no clean assets")
    experiment_root = clean_assets.get("experiment_root")
    if not experiment_root:
        raise FewshotError(
            f"combination {combination_id!r} clean assets declare no experiment_root"
        )
    if index is not None and (
        isinstance(index, bool) or not isinstance(index, int) or index < 0
    ):
        raise FewshotError(f"example index must be a non-negative integer, got {index!r}")

    relative = f"{experiment_root}/{experiment}"
    try:
        experiment_dir = resolve_within(root, relative)
    except PathResolutionError as error:
        raise FewshotError(
            f"invalid experiment reference {relative!r}: {error}"
        ) from error
    fewshot_path = experiment_dir / "fewshot.json"
    meta_path = experiment_dir / "meta.json"
    if not experiment_dir.is_dir() or not fewshot_path.is_file() or not meta_path.is_file():
        raise FewshotError(
            f"experiment assets not found for {combination_id!r}/{experiment!r}: {relative}"
        )

    items = read_json(fewshot_path)
    meta = read_json(meta_path)
    if not isinstance(items, list):
        raise FewshotError(f"{fewshot_path} must contain a JSON list")
    if not isinstance(meta, dict):
        raise FewshotError(f"{meta_path} must contain a JSON object")
    fewshot_ids = meta.get("fewshot_ids")
    if not isinstance(fewshot_ids, list):
        raise FewshotError(f"{meta_path} has no fewshot_ids list")
    if len(fewshot_ids) != len(items):
        raise FewshotError(
            f"{meta_path} declares {len(fewshot_ids)} fewshot_ids but "
            f"{fewshot_path} lists {len(items)} examples"
        )
    for position, (expected, item) in enumerate(zip(fewshot_ids, items)):
        if not isinstance(item, dict):
            raise FewshotError(f"{fewshot_path} item {position} is not an object")
        if str(item.get("task_id")) != str(expected):
            raise FewshotError(
                f"{fewshot_path} item {position} task_id {item.get('task_id')!r} does not "
                f"match meta fewshot_ids[{position}] {expected!r}"
            )
    if index is not None and index >= len(items):
        raise FewshotError(
            f"example index {index} out of range for {relative} (0..{len(items) - 1})"
        )

    digest = sha256_file(fewshot_path)
    examples = tuple(
        FewshotExample(
            task_id=str(item.get("task_id")),
            code=str(item.get("code") or ""),
            cot=_cot_tuple(item.get("cot")),
            instruct_prompt=str(item.get("instruct_prompt") or ""),
            index=position,
            experiment=experiment,
            source_path=str(fewshot_path),
            source_sha256=digest,
        )
        for position, item in enumerate(items)
    )
    return examples, relative


def load_fewshot_examples(
    *,
    assets_root: Path | str,
    combination_id: str,
    experiment: str,
) -> tuple[FewshotExample, ...]:
    """Read every few-shot example of one clean experiment, in file order."""

    examples, _relative = _load_examples(
        assets_root=assets_root,
        combination_id=combination_id,
        experiment=experiment,
    )
    return examples


def load_fewshot_example(
    *,
    assets_root: Path | str,
    combination_id: str,
    experiment: str,
    index: int,
) -> FewshotExample:
    """Read one few-shot example (0-based ``index``) without copying its bytes."""

    examples, _relative = _load_examples(
        assets_root=assets_root,
        combination_id=combination_id,
        experiment=experiment,
        index=index,
    )
    return examples[index]


__all__ = [
    "FewshotError",
    "FewshotExample",
    "load_fewshot_example",
    "load_fewshot_examples",
    "load_specs",
]
