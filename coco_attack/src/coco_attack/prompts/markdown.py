"""Structure-aware Markdown handling for prompt materialization.

The legacy prompts are full Markdown documents with real code (braces, f-strings,
regexes). They must never be treated as ``str.format`` templates, and structural
markers such as ``### cot`` must only be recognised outside fenced code blocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

OPENING_LINE = (
    "Below are examples showing how to solve programming tasks. You need to "
    "generate the cot and code for the test sample."
)
TAIL_INSTRUCTION = (
    "Please refer to the style of the above examples to generate cot and code "
    "for the requirements given above."
)
OPENING_OLD = "generate the cot and code"
OPENING_NEW = "generate the code"
TAIL_OLD = "generate cot and code"
TAIL_NEW = "generate code"

# Prompt-materialization version. Bump when materialized bytes change.
MATERIALIZE_VERSION = "prompt-materialize-v1"
PROMPT_VERSION = "1"

FORM_CLEAN_0SHOT = "clean_0shot"
FORM_CLEAN_FEWSHOT_COT = "clean_fewshot_cot"
FORM_CLEAN_FEWSHOT_NO_COT = "clean_fewshot_no_cot"
CLEAN_FORMS = (FORM_CLEAN_0SHOT, FORM_CLEAN_FEWSHOT_COT, FORM_CLEAN_FEWSHOT_NO_COT)


class PromptParseError(ValueError):
    pass


@dataclass
class PromptStructure:
    lines: list[str]
    example_indices: list[int] = field(default_factory=list)
    test_index: int | None = None
    cot_regions: list[tuple[int, int]] = field(default_factory=list)
    code_header_indices: list[int] = field(default_factory=list)
    opening_index: int | None = None
    tail_instruction_index: int | None = None
    fence_balanced: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "example_indices": self.example_indices,
            "test_index": self.test_index,
            "cot_regions": [list(region) for region in self.cot_regions],
            "code_header_indices": self.code_header_indices,
            "opening_index": self.opening_index,
            "tail_instruction_index": self.tail_instruction_index,
            "fence_balanced": self.fence_balanced,
        }


def parse_prompt_structure(text: str) -> PromptStructure:
    lines = text.split("\n")
    structure = PromptStructure(lines=lines)
    in_fence = False
    cot_headers: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if stripped.startswith("## Example"):
            structure.example_indices.append(index)
        elif stripped == "## Test":
            structure.test_index = index
        elif stripped == "### cot":
            cot_headers.append(index)
        elif stripped == "### code":
            structure.code_header_indices.append(index)
        if structure.opening_index is None and OPENING_OLD in line:
            structure.opening_index = index
        if TAIL_INSTRUCTION in line:
            structure.tail_instruction_index = index
    structure.fence_balanced = not in_fence

    for header in cot_headers:
        next_code = next(
            (code for code in structure.code_header_indices if code > header), None
        )
        if next_code is None:
            raise PromptParseError(
                f"### cot at line {header + 1} has no following ### code"
            )
        structure.cot_regions.append((header, next_code - 1))
    return structure


def derive_no_cot(text: str) -> tuple[str, PromptStructure]:
    """Derive the no-CoT prompt from the CoT prompt.

    Only explicitly allowed regions change: the opening instruction, the tail
    instruction, and every ``### cot`` block (header plus reasoning). All other
    bytes, including code fences and braces, are preserved.
    """

    structure = parse_prompt_structure(text)
    if not structure.fence_balanced:
        raise PromptParseError("unbalanced code fences")
    if structure.opening_index is None or structure.tail_instruction_index is None:
        raise PromptParseError("could not locate the clean instruction lines")
    if len(structure.example_indices) != 4:
        raise PromptParseError(
            f"expected 4 examples, found {len(structure.example_indices)}"
        )
    if structure.test_index is None:
        raise PromptParseError("missing '## Test' section")
    if len(structure.cot_regions) != 5:
        raise PromptParseError(
            f"expected 5 '### cot' regions (4 examples + test), found {len(structure.cot_regions)}"
        )

    removed: set[int] = set()
    for start, end in structure.cot_regions:
        removed.update(range(start, end + 1))

    base = [line for index, line in enumerate(structure.lines) if index not in removed]
    derived_lines: list[str] = []
    replaced: list[int] = []
    for index, line in enumerate(base):
        if OPENING_OLD in line:
            derived_lines.append(line.replace(OPENING_OLD, OPENING_NEW))
            replaced.append(index)
        elif TAIL_INSTRUCTION in line and TAIL_OLD in line:
            derived_lines.append(line.replace(TAIL_OLD, TAIL_NEW))
            replaced.append(index)
        else:
            derived_lines.append(line)

    derived = "\n".join(derived_lines)
    check = verify_no_cot_change(text, derived)
    if not check["ok"]:
        raise PromptParseError(
            "derived no-CoT prompt changed disallowed regions: "
            + "; ".join(check["problems"])
        )
    return derived, structure


def verify_no_cot_change(original: str, derived: str) -> dict[str, Any]:
    """Independently verify that no-CoT derivation only changed allowed lines."""

    problems: list[str] = []
    original_structure = parse_prompt_structure(original)
    derived_structure = parse_prompt_structure(derived)
    if derived_structure.cot_regions:
        problems.append("derived prompt still contains ### cot regions")
    if len(derived_structure.example_indices) != len(original_structure.example_indices):
        problems.append("example count changed")
    if (derived_structure.test_index is None) != (original_structure.test_index is None):
        problems.append("Test section presence changed")
    if len(derived_structure.code_header_indices) != len(
        original_structure.code_header_indices
    ):
        problems.append("### code header count changed")

    removed: set[int] = set()
    for start, end in original_structure.cot_regions:
        removed.update(range(start, end + 1))
    base = [line for index, line in enumerate(original_structure.lines) if index not in removed]
    derived_lines = derived.split("\n")
    if len(base) != len(derived_lines):
        problems.append(
            f"derived line count {len(derived_lines)} != cot-free base {len(base)}"
        )
    else:
        for index, (before, after) in enumerate(zip(base, derived_lines)):
            if before == after:
                continue
            allowed = (OPENING_OLD in before) or (
                TAIL_INSTRUCTION in before and TAIL_OLD in before
            )
            if not allowed:
                problems.append(
                    f"line {index + 1} changed outside allowed regions: {before!r} -> {after!r}"
                )
    return {"ok": not problems, "problems": problems}


def derive_no_cot_fewshot(
    examples: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a copy of the few-shot examples with the ``cot`` value emptied."""

    derived: list[dict[str, Any]] = []
    for example in examples:
        clone = dict(example)
        if "cot" not in clone:
            raise PromptParseError("fewshot example has no 'cot' key")
        clone["cot"] = ""
        derived.append(clone)
    return derived
