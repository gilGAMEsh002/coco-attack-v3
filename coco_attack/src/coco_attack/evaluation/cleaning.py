"""Output extraction and entry-point completion (task book F4).

``clean_output`` is side-effect free and never returns an oracle verdict. It
records the raw response, the extraction path, the extracted code, the final
evaluation code, completion/syntax/entry state and diagnostics. Generation
failures keep empty code and stay in the denominator downstream.
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any

CLEANER_VERSION = "cleaner-v3"

EXTRACTION_PYTHON_FENCE = "python_fence"
EXTRACTION_FENCE = "fence"
EXTRACTION_CODE_SECTION = "code_section"
EXTRACTION_FULL_TEXT = "full_text"
EXTRACTION_NONE = "none"

_FENCE_RE = re.compile(r"^(\s*)(```|~~~)\s*(.*)$")
_STARTING_WITH_RE = re.compile(
    r"starting with:\s*\n?```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL
)


@dataclass
class CleanResult:
    generation_status: str
    raw_sha256: str
    raw_text: str
    extraction_path: str
    code: str
    code_sha256: str
    final_code: str
    final_code_sha256: str
    completed: bool
    completion_action: str | None
    syntax_ok: bool | None
    syntax_error: dict[str, Any] | None
    entry_present: bool
    entry_expected: str
    cleaner_version: str = CLEANER_VERSION
    diagnostics: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "generation_status": self.generation_status,
            "raw_sha256": self.raw_sha256,
            "raw_text": self.raw_text,
            "extraction_path": self.extraction_path,
            "code": self.code,
            "code_sha256": self.code_sha256,
            "final_code": self.final_code,
            "final_code_sha256": self.final_code_sha256,
            "completed": self.completed,
            "completion_action": self.completion_action,
            "syntax_ok": self.syntax_ok,
            "syntax_error": self.syntax_error,
            "entry_present": self.entry_present,
            "entry_expected": self.entry_expected,
            "cleaner_version": self.cleaner_version,
            "diagnostics": list(self.diagnostics),
        }


def clean_output(
    raw_text: str | None,
    task: Any,
    generation_status: str | None,
) -> CleanResult:
    if generation_status is None:
        raise ValueError("generation_status is required (missing status is an input error)")

    entry_expected = task.entry_point
    raw = "" if raw_text is None else raw_text
    raw_hash = _sha256(raw)

    if generation_status != "success":
        return CleanResult(
            generation_status=generation_status,
            raw_sha256=raw_hash,
            raw_text=raw,
            extraction_path=EXTRACTION_NONE,
            code="",
            code_sha256=_sha256(""),
            final_code="",
            final_code_sha256=_sha256(""),
            completed=False,
            completion_action=None,
            syntax_ok=None,
            syntax_error=None,
            entry_present=False,
            entry_expected=entry_expected,
            diagnostics=(f"generation_status={generation_status}",),
        )

    diagnostics: list[str] = []
    if not raw.strip():
        return CleanResult(
            generation_status=generation_status,
            raw_sha256=raw_hash,
            raw_text=raw,
            extraction_path=EXTRACTION_NONE,
            code="",
            code_sha256=_sha256(""),
            final_code="",
            final_code_sha256=_sha256(""),
            completed=False,
            completion_action=None,
            syntax_ok=None,
            syntax_error=None,
            entry_present=False,
            entry_expected=entry_expected,
            diagnostics=("empty_output",),
        )

    code, extraction_path, extract_diagnostics = _extract(raw)
    code = _normalize_whitespace(code)
    diagnostics.extend(extract_diagnostics)

    prefix = task.code_prompt
    (
        final_code,
        completed,
        completion_action,
        entry_present,
        completion_diagnostics,
    ) = _complete_entry(code, prefix, entry_expected)
    diagnostics.extend(completion_diagnostics)

    syntax_ok, syntax_error = _syntax_status(final_code)
    diagnostics.extend(_source_prefix_diagnostics(task, entry_expected))

    return CleanResult(
        generation_status=generation_status,
        raw_sha256=raw_hash,
        raw_text=raw,
        extraction_path=extraction_path,
        code=code,
        code_sha256=_sha256(code),
        final_code=final_code,
        final_code_sha256=_sha256(final_code),
        completed=completed,
        completion_action=completion_action,
        syntax_ok=syntax_ok,
        syntax_error=syntax_error,
        entry_present=entry_present,
        entry_expected=entry_expected,
        diagnostics=tuple(diagnostics),
    )


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fenced_blocks(text: str) -> tuple[list[tuple[str, str]], bool]:
    """Return ``(blocks, balanced)`` where a block is ``(language, body)``."""

    lines = text.split("\n")
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        match = _FENCE_RE.match(lines[index])
        if match is None:
            index += 1
            continue
        marker = match.group(2)
        language = match.group(3).strip()
        body: list[str] = []
        cursor = index + 1
        closed = False
        while cursor < len(lines):
            inner = lines[cursor]
            stripped = inner.strip()
            if stripped.startswith(marker):
                closed = True
                break
            body.append(inner)
            cursor += 1
        if not closed:
            return blocks, False
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        blocks.append((language, "\n".join(body)))
        index = cursor + 1
    return blocks, True


def _structural_markers(text: str) -> list[tuple[int, str]]:
    lines = text.split("\n")
    markers: list[tuple[int, str]] = []
    in_fence = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if stripped == "### code":
            markers.append((index, "code"))
        elif stripped == "### cot":
            markers.append((index, "cot"))
    return markers


def _extract(text: str) -> tuple[str, str, list[str]]:
    diagnostics: list[str] = []
    blocks, balanced = _fenced_blocks(text)
    if not balanced:
        diagnostics.append("unclosed_fence")
    for language, body in blocks:
        if language.lower().startswith("python"):
            return body, EXTRACTION_PYTHON_FENCE, diagnostics
    if blocks:
        return blocks[0][1], EXTRACTION_FENCE, diagnostics

    lines = text.split("\n")
    markers = [index for index, kind in _structural_markers(text) if kind == "code"]
    if markers:
        start = markers[-1] + 1
        section = "\n".join(lines[start:])
        section_blocks, _ = _fenced_blocks(section)
        for language, body in section_blocks:
            if language.lower().startswith("python"):
                return body, EXTRACTION_CODE_SECTION, diagnostics
        if section_blocks:
            return section_blocks[0][1], EXTRACTION_CODE_SECTION, diagnostics
        return section.strip("\n"), EXTRACTION_CODE_SECTION, diagnostics

    diagnostics.append("no_fence_or_code_section")
    return text.strip(), EXTRACTION_FULL_TEXT, diagnostics


def _normalize_whitespace(code: str) -> str:
    """Canonical code normalization for ``cleaner-v3``.

    * normalize line endings: ``\\r\\n`` and lone ``\\r`` become ``\\n``;
    * rstrip the extracted code tail (EOF whitespace).

    Line-ending normalization is safe for Python source: the parser applies
    universal-newline semantics, so ``\"\"\"a\\r\\nb\"\"\"`` and ``\"\"\"a\\nb\"\"\"``
    yield the same AST and runtime string value. Normalizing to LF makes the
    cleaned-code hash transport-independent (stable cache keys) and matches the
    toolchain default.

    Internal blank-line whitespace and indentation are preserved. Per-line
    ``rstrip`` and blank-line collapsing are deliberately not done: they would
    alter meaningful whitespace inside multi-line string literals.
    """

    if not code:
        return code
    normalized = code.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.rstrip()


def _top_level_names(tree: ast.AST) -> tuple[list[str], list[str]]:
    funcs: list[str] = []
    classes: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
    return funcs, classes


def _syntax_status(code: str) -> tuple[bool | None, dict[str, Any] | None]:
    if not code.strip():
        return None, None
    try:
        ast.parse(code)
    except SyntaxError as error:
        return False, {
            "message": error.msg,
            "lineno": error.lineno,
            "offset": error.offset,
        }
    return True, None


def _complete_entry(
    code: str, prefix: str, entry: str
) -> tuple[str, bool, str | None, bool, list[str]]:
    diagnostics: list[str] = []
    if not code.strip():
        return code, False, None, False, diagnostics

    if _defines_entry(code, entry):
        return code, False, "none", True, diagnostics

    tree: ast.AST | None = None
    parse_error: SyntaxError | None = None
    try:
        tree = ast.parse(code)
    except SyntaxError as error:
        parse_error = error

    if tree is not None:
        funcs, classes = _top_level_names(tree)
        if funcs or classes:
            diagnostics.append("entry_missing_module_preserved")
            return code, False, "module_missing_entry", False, diagnostics
        # Statement-only candidate: treat as a bare function body.
    elif not _looks_like_bare_body(code, parse_error):
        return code, False, None, False, diagnostics

    completed = _prepend_prefix(prefix, code)
    if completed is None:
        diagnostics.append("cannot_reindent_bare_body")
        return code, False, None, False, diagnostics

    if _defines_entry(completed, entry):
        return completed, True, "prepend_prefix", True, diagnostics
    diagnostics.append("prefix_prepend_did_not_define_entry")
    return code, False, None, False, diagnostics


def _defines_entry(code: str, entry: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == entry
        for node in tree.body
    )


def _looks_like_bare_body(code: str, parse_error: SyntaxError | None) -> bool:
    if parse_error is not None:
        if not isinstance(parse_error, IndentationError):
            return False
        first = next((line for line in code.split("\n") if line.strip()), "")
        return first[:1].isspace()
    return True


def _prepend_prefix(prefix: str, code: str) -> str | None:
    body = code.strip("\n")
    if not body.strip():
        return None
    first_line = next((line for line in body.split("\n") if line.strip()), "")
    if first_line[:1].isspace():
        return prefix.rstrip("\n") + "\n" + body
    if "'''" in body or '"""' in body:
        return None
    return prefix.rstrip("\n") + "\n" + textwrap.indent(body, "    ")


def _source_prefix_diagnostics(task: Any, entry: str) -> list[str]:
    """Check the task's 'starting with' prefix against the recorded entry point.

    The prefix is a code header (``def task_func(...):`` with no body), so it is
    not parsed as a module; entry names are read structurally with a regex.
    """

    instruct = task.effective.get("instruct_prompt", "")
    match = _STARTING_WITH_RE.search(instruct)
    if match is not None:
        prefix_names = _entry_names(match.group(1))
        if prefix_names and entry not in prefix_names:
            return [f"starting_with_entry_mismatch:{prefix_names}"]
    code_prompt = task.effective.get("code_prompt", "")
    code_names = _entry_names(code_prompt)
    if code_names and entry not in code_names:
        return [f"code_prompt_entry_mismatch:{code_names}"]
    return []


_DEF_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)


def _entry_names(prefix: str) -> list[str]:
    return _DEF_RE.findall(prefix)
