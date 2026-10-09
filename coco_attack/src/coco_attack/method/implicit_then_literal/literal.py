"""Scoped local-variable rename targets and B modification materialization.

The method's B stage never rewrites a whole candidate: the caller supplies
*scoped rename mappings* plus an optional free CoT, and this module turns that
request into a valid, traceable ``TemplateSnapshot`` through the shared
``apply_patch`` service.

The first version deliberately supports only ordinary function-body local
bindings that can be resolved statically.  Nested scopes are analysed for
capture; unsupported constructs produce an explicit reason instead of a guess.
The module never executes or imports candidate code: only ``ast``/lexical
analysis of the source text is used.
"""

from __future__ import annotations

import ast
import copy
import keyword
import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...assets.artifacts import sha256_text
from ...iteration.template_snapshot import (
    PatchPolicy,
    TemplateSnapshot,
    TemplateSnapshotError,
    apply_patch,
    read_snapshot,
    write_snapshot,
)
from .contracts import (
    B_ERROR_DUPLICATE_EXAMPLE,
    B_ERROR_DUPLICATE_MAPPING,
    B_ERROR_FROZEN_BINDING,
    B_ERROR_FROZEN_EXAMPLE,
    B_ERROR_INVALID_IDENTIFIER,
    B_ERROR_INVALID_REQUEST,
    B_ERROR_NAME_CONFLICT,
    B_ERROR_NO_MODIFICATION,
    B_ERROR_OUT_OF_RANGE_EXAMPLE,
    B_ERROR_STALE_PARENT,
    B_ERROR_UNKNOWN_SCOPE,
    B_ERROR_UNKNOWN_TARGET,
    B_ERROR_UNSUPPORTED_SCOPE,
    B_STATUS_INVALID,
    B_STATUS_LEGAL,
    B_STATUS_NO_CHANGE,
    BModificationError,
    BModificationRequest,
    BModificationResult,
    FROZEN_EXAMPLE,
    MODIFIABLE_EXAMPLES,
    RenameMapping,
    RenameTarget,
    RenameTargetReport,
    UnsupportedRename,
)

_PREFIX_RE = re.compile(r"starting with:\s*\n?```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL)
_FRAGMENT_WRAPPER = "def __itl_fragment__():\n"
_SCOPE_PATH = "<fragment>"
_DYNAMIC_CALL_NAMES = frozenset({"globals", "locals", "vars", "eval", "exec"})
_B_PATCH_POLICY = PatchPolicy(
    allowed_examples=MODIFIABLE_EXAMPLES, allowed_fields=("code", "cot")
)


class LiteralError(ValueError):
    """Raised for malformed inputs to the literal module itself."""


class BModificationIOError(RuntimeError):
    """Raised when persisting a legal B result fails at the I/O boundary.

    This is intentionally distinct from candidate invalidity so the later
    orchestration can pause/retry instead of spending a candidate slot.
    """


# --------------------------------------------------------------------------- #
# Conservative scope analysis
# --------------------------------------------------------------------------- #


@dataclass
class _Scope:
    kind: str
    bindings: dict[str, str] = field(default_factory=dict)
    frozen: set[str] = field(default_factory=set)
    loads: dict[str, list[ast.Name]] = field(default_factory=dict)
    stores: dict[str, list[ast.Name]] = field(default_factory=dict)
    globals: set[str] = field(default_factory=set)
    nonlocals: set[str] = field(default_factory=set)
    children: list["_Scope"] = field(default_factory=list)
    dynamic: bool = False
    del_names: set[str] = field(default_factory=set)
    walrus: set[str] = field(default_factory=set)
    pattern: set[str] = field(default_factory=set)
    star_import: bool = False


def _parse(source: str) -> ast.Module:
    """Parse source without leaking SyntaxWarning from literal escape sequences."""

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source)


def _all_args(args: ast.arguments) -> list[ast.arg]:
    result = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    if args.vararg is not None:
        result.append(args.vararg)
    if args.kwarg is not None:
        result.append(args.kwarg)
    return result


class _ScopeBuilder(ast.NodeVisitor):
    """Collect bindings/loads per scope without executing the code."""

    def __init__(self) -> None:
        self.root = _Scope(kind="function")
        self._stack: list[_Scope] = [self.root]
        # Names bound by an assignment expression anywhere in the fragment.
        # PEP 572 makes a walrus bind in the containing scope (not the
        # comprehension scope), so these are tracked globally and always
        # treated as unsupported.
        self.walrus_names: set[str] = set()

    @property
    def _current(self) -> _Scope:
        return self._stack[-1]

    def _nearest_non_comprehension(self) -> _Scope:
        for scope in reversed(self._stack):
            if scope.kind != "comprehension":
                return scope
        return self.root

    def _add_binding(self, name: str, kind: str, *, frozen: bool = False) -> None:
        self._current.bindings.setdefault(name, kind)
        if frozen:
            self._current.frozen.add(name)

    def _record_name(self, node: ast.Name, scope: _Scope | None = None) -> None:
        target = scope if scope is not None else self._current
        if isinstance(node.ctx, ast.Load):
            target.loads.setdefault(node.id, []).append(node)
        elif isinstance(node.ctx, ast.Store):
            target.stores.setdefault(node.id, []).append(node)
        else:
            target.del_names.add(node.id)

    def _bind_target(self, target: ast.AST, kind: str) -> None:
        if isinstance(target, ast.Name):
            self._add_binding(target.id, kind)
            self._record_name(target)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, kind)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, kind)
        else:
            self.visit(target)

    # -- names and simple statements ------------------------------------ #

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802 - ast API
        self._record_name(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, "assign")

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            self.visit(node.value)
        if node.annotation is not None:
            self.visit(node.annotation)
        if isinstance(node.target, ast.Name):
            if node.value is not None:
                self._add_binding(node.target.id, "annassign")
            self._record_name(node.target)
        else:
            self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        if isinstance(node.target, ast.Name):
            self._add_binding(node.target.id, "augassign")
            self._record_name(node.target)
        else:
            self.visit(node.target)
        self.visit(node.value)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._bind_target(node.target, "for")
        self.visit(node.iter)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For  # noqa: N815

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars, "with")
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With  # noqa: N815

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._add_binding(node.name, "except", frozen=True)
        for statement in node.body:
            self.visit(statement)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._add_binding(name, "import", frozen=True)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name == "*":
                self._current.star_import = True
            else:
                self._add_binding(alias.asname or alias.name, "import", frozen=True)

    def visit_Global(self, node: ast.Global) -> None:  # noqa: N802
        self._current.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:  # noqa: N802
        self._current.nonlocals.update(node.names)

    def visit_Delete(self, node: ast.Delete) -> None:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._current.del_names.add(target.id)
            self.visit(target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        if isinstance(node.target, ast.Name):
            # PEP 572: a walrus binds in the containing non-comprehension scope.
            binding_scope = self._nearest_non_comprehension()
            self.walrus_names.add(node.target.id)
            binding_scope.bindings.setdefault(node.target.id, "walrus")
            binding_scope.walrus.add(node.target.id)
            self.visit(node.value)
            self._record_name(node.target, binding_scope)
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_CALL_NAMES:
            self._current.dynamic = True
        self.generic_visit(node)

    # -- nested scopes -------------------------------------------------- #

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._add_binding(node.name, "def", frozen=True)
        for decorator in node.decorator_list:
            self.visit(decorator)
        args = node.args
        for default in list(args.defaults) + [
            default for default in args.kw_defaults if default is not None
        ]:
            self.visit(default)
        for arg in _all_args(args):
            if arg.annotation is not None:
                self.visit(arg.annotation)
        if node.returns is not None:
            self.visit(node.returns)

        child = _Scope(kind="function")
        self._current.children.append(child)
        self._stack.append(child)
        for arg in _all_args(args):
            self._add_binding(arg.arg, "param")
        for statement in node.body:
            self.visit(statement)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        args = node.args
        for default in list(args.defaults) + [
            default for default in args.kw_defaults if default is not None
        ]:
            self.visit(default)
        child = _Scope(kind="lambda")
        self._current.children.append(child)
        self._stack.append(child)
        for arg in _all_args(args):
            self._add_binding(arg.arg, "param")
        self.visit(node.body)
        self._stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._add_binding(node.name, "class", frozen=True)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword_node in node.keywords:
            self.visit(keyword_node.value)
        child = _Scope(kind="class")
        self._current.children.append(child)
        self._stack.append(child)
        for statement in node.body:
            self.visit(statement)
        self._stack.pop()

    def _visit_comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None:
        child = _Scope(kind="comprehension")
        self._current.children.append(child)
        generators = node.generators
        # The first iterable is evaluated in the enclosing scope.
        self.visit(generators[0].iter)
        self._stack.append(child)
        try:
            for index, generator in enumerate(generators):
                if index > 0:
                    self.visit(generator.iter)
                self._bind_target(generator.target, "comprehension")
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)
        finally:
            self._stack.pop()

    def visit_ListComp(self, node: ast.ListComp) -> None:  # noqa: N802
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:  # noqa: N802
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:  # noqa: N802
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        self._visit_comprehension(node)

    # -- match patterns (bindings are conservatively unsupported) -------- #

    def visit_MatchAs(self, node: ast.MatchAs) -> None:  # noqa: N802
        if node.name:
            self._add_binding(node.name, "pattern")
            self._current.pattern.add(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:  # noqa: N802
        if node.name:
            self._add_binding(node.name, "pattern")
            self._current.pattern.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:  # noqa: N802
        if node.rest:
            self._add_binding(node.rest, "pattern")
            self._current.pattern.add(node.rest)
        self.generic_visit(node)


def _escaping_names(scope: _Scope) -> set[str]:
    """Names loaded in a subtree that are not bound within that subtree.

    A ``class`` scope is special: methods defined in a class do **not** close
    over the class namespace, so class-level bindings must not mask a free name
    resolved by a method.  Class bindings are therefore only subtracted from
    names loaded directly in the class body, not from names escaping nested
    scopes.
    """

    names = set(scope.loads)
    names -= set(scope.bindings)
    names -= scope.globals
    names -= scope.nonlocals
    for child in scope.children:
        child_names = _escaping_names(child)
        if scope.kind == "class":
            names |= child_names
        else:
            names |= child_names - set(scope.bindings)
    return names


def _subtree_has_dynamic(scope: _Scope) -> bool:
    if scope.dynamic:
        return True
    return any(_subtree_has_dynamic(child) for child in scope.children)


def _descendant_attribute(scope: _Scope, attribute: str) -> set[str]:
    result: set[str] = set()
    for child in scope.children:
        result |= getattr(child, attribute)
        result |= _descendant_attribute(child, attribute)
    return result


def _body_is_indented(code: str) -> bool:
    first = next((line for line in code.split("\n") if line.strip()), "")
    return first[:1] in (" ", "\t")


def _scope_id(parent_content_sha256: str, example: int) -> str:
    digest = sha256_text(
        f"itl-scope-v1|{parent_content_sha256}|{example}|{_SCOPE_PATH}"
    )
    return f"ex{example}-{digest[:32]}"


def extract_code_prefix(instruct_prompt: str) -> str:
    """Extract the frozen ``starting with`` code prefix from an example prompt.

    The prefix holds imports and the function signature; it is never edited.
    """

    match = _PREFIX_RE.search(instruct_prompt)
    if match is None:
        raise LiteralError(
            "instruct_prompt has no 'starting with' fenced code prefix"
        )
    return match.group(1)


def _prefix_params(prefix: str) -> frozenset[str] | None:
    try:
        module = _parse(prefix.rstrip("\n") + "\n    pass")
    except (SyntaxError, ValueError, RecursionError):
        return None
    params: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params.update(arg.arg for arg in _all_args(node.args))
    return frozenset(params)


@dataclass
class _FragmentAnalysis:
    example: int
    scope_id: str | None
    tree: ast.Module | None
    root: _Scope | None
    params: frozenset[str]
    target_kinds: dict[str, str]
    frozen_names: frozenset[str]
    unsupported_names: dict[str, str]
    free_names: frozenset[str]
    nested_free_names: frozenset[str]
    nested_nonlocals: frozenset[str]
    fatal_reason: str | None

    @property
    def target_names(self) -> frozenset[str]:
        return frozenset(self.target_kinds)


def _analyze_example(
    snapshot: TemplateSnapshot, example_number: int, example: Any
) -> _FragmentAnalysis:
    parent_sha = snapshot.content_sha256()
    scope_id = _scope_id(parent_sha, example_number)
    code = example.code

    def _fatal(reason: str) -> _FragmentAnalysis:
        return _FragmentAnalysis(
            example=example_number,
            scope_id=None,
            tree=None,
            root=None,
            params=frozenset(),
            target_kinds={},
            frozen_names=frozenset(),
            unsupported_names={},
            free_names=frozenset(),
            nested_free_names=frozenset(),
            nested_nonlocals=frozenset(),
            fatal_reason=reason,
        )

    if "\r" in code:
        return _fatal("code body uses CR/CRLF line endings, which are not supported")
    if not _body_is_indented(code):
        return _fatal(
            "code body is not an indented function body; rename requires a "
            "parseable indented body"
        )
    try:
        prefix = extract_code_prefix(example.instruct_prompt)
    except LiteralError as error:
        return _fatal(str(error))
    params = _prefix_params(prefix)
    if params is None:
        return _fatal("the frozen code prefix could not be parsed")
    try:
        tree = _parse(_FRAGMENT_WRAPPER + code)
    except (SyntaxError, ValueError, RecursionError) as error:
        message = getattr(error, "msg", str(error))
        return _fatal(f"code body could not be parsed: {message}")
    if not tree.body or not isinstance(tree.body[0], ast.FunctionDef):
        return _fatal("internal fragment wrapper did not parse to a function")

    builder = _ScopeBuilder()
    for statement in tree.body[0].body:
        builder.visit(statement)
    root = builder.root
    if root.star_import:
        return _fatal("a star import makes local bindings unresolvable")
    dynamic = _subtree_has_dynamic(root)

    captured: set[str] = set()
    nested_free: set[str] = set()
    for child in root.children:
        escaping = _escaping_names(child)
        nested_free |= escaping
        captured |= escaping
    descendant_nonlocals = _descendant_attribute(root, "nonlocals")
    descendant_dels = _descendant_attribute(root, "del_names")

    target_kinds: dict[str, str] = {}
    unsupported: dict[str, str] = {}
    for name, kind in root.bindings.items():
        if name in root.frozen or name in params:
            continue
        reasons: list[str] = []
        if name in root.del_names:
            reasons.append("binding is deleted")
        if name in root.walrus:
            reasons.append("walrus binding")
        if name in root.pattern:
            reasons.append("match-pattern binding")
        if name in root.globals:
            reasons.append("global declaration")
        if name in root.nonlocals:
            reasons.append("nonlocal declaration")
        if name in captured:
            reasons.append("name is referenced by a nested scope")
        if name in descendant_nonlocals:
            reasons.append("name is declared nonlocal in a nested scope")
        if name in descendant_dels:
            reasons.append("name is deleted in a nested scope")
        if dynamic:
            reasons.append("dynamic name access (globals/locals/vars/eval/exec)")
        if reasons:
            unsupported[name] = "; ".join(reasons)
        else:
            target_kinds[name] = kind

    # Walrus targets bind in the containing scope and are never renameable;
    # record them even when they only appear inside a comprehension/lambda.
    for name in builder.walrus_names:
        unsupported.setdefault(name, "walrus binding")

    free_names = frozenset(root.loads) - frozenset(root.bindings)
    return _FragmentAnalysis(
        example=example_number,
        scope_id=scope_id,
        tree=tree,
        root=root,
        params=params,
        target_kinds=target_kinds,
        frozen_names=frozenset(root.frozen) | params,
        unsupported_names=unsupported,
        free_names=free_names,
        nested_free_names=frozenset(nested_free),
        nested_nonlocals=frozenset(descendant_nonlocals),
        fatal_reason=None,
    )


# --------------------------------------------------------------------------- #
# Public: enumerate rename targets
# --------------------------------------------------------------------------- #


def enumerate_rename_targets(
    snapshot: TemplateSnapshot, example_number: int
) -> RenameTargetReport:
    """Enumerate safely renameable local bindings and their stable scope id."""

    if not isinstance(snapshot, TemplateSnapshot):
        raise LiteralError("enumerate_rename_targets requires a TemplateSnapshot")
    if isinstance(example_number, bool) or not isinstance(example_number, int):
        raise LiteralError("example number must be a 1-based integer")
    if example_number < 1 or example_number > len(snapshot.examples):
        raise LiteralError(
            f"example {example_number} out of range: snapshot has "
            f"{len(snapshot.examples)} examples"
        )
    if example_number == FROZEN_EXAMPLE:
        return RenameTargetReport(
            example=example_number,
            scope_id=None,
            targets=(),
            unsupported=(
                UnsupportedRename(
                    example=example_number,
                    name=None,
                    reason="example 1 is frozen and cannot be modified",
                ),
            ),
        )

    example = snapshot.example(example_number)
    analysis = _analyze_example(snapshot, example_number, example)
    if analysis.fatal_reason is not None:
        return RenameTargetReport(
            example=example_number,
            scope_id=None,
            targets=(),
            unsupported=(
                UnsupportedRename(
                    example=example_number, name=None, reason=analysis.fatal_reason
                ),
            ),
        )
    assert analysis.root is not None
    targets = tuple(
        RenameTarget(
            example=example_number,
            scope_id=analysis.scope_id or "",
            name=name,
            binding_kind=kind,
            store_count=len(analysis.root.stores.get(name, [])),
            load_count=len(analysis.root.loads.get(name, [])),
        )
        for name, kind in sorted(analysis.target_kinds.items())
    )
    unsupported = tuple(
        UnsupportedRename(example=example_number, name=name, reason=reason)
        for name, reason in sorted(analysis.unsupported_names.items())
    )
    return RenameTargetReport(
        example=example_number,
        scope_id=analysis.scope_id,
        targets=targets,
        unsupported=unsupported,
    )


# --------------------------------------------------------------------------- #
# Public: apply a B modification request
# --------------------------------------------------------------------------- #


def _invalid_result(
    parent_snapshot: TemplateSnapshot,
    request: BModificationRequest,
    errors: Sequence[BModificationError],
) -> BModificationResult:
    parent_sha = parent_snapshot.content_sha256()
    return BModificationResult(
        candidate=request.candidate,
        parent_content_sha256=parent_sha,
        status=B_STATUS_INVALID,
        changed=False,
        diff=(),
        snapshot=parent_snapshot,
        content_sha256=parent_sha,
        errors=tuple(errors),
    )


def _is_identifier(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name)


def _conflict_reason(mapping: RenameMapping, analysis: _FragmentAnalysis) -> str | None:
    new_name = mapping.new_name
    if new_name in analysis.target_names:
        return f"new name {new_name!r} collides with another local binding"
    if new_name in analysis.frozen_names:
        return f"new name {new_name!r} collides with a frozen binding (import/def)"
    if new_name in analysis.unsupported_names:
        return f"new name {new_name!r} collides with an unsupported binding"
    if new_name in analysis.params:
        return f"new name {new_name!r} collides with a function parameter"
    if new_name in analysis.free_names:
        return f"new name {new_name!r} captures an outer/global name"
    if new_name in analysis.nested_free_names:
        return (
            f"new name {new_name!r} would capture a name referenced by a nested scope"
        )
    # A `global`/`nonlocal` declaration makes an assignment to that name target
    # another scope even when the name is neither bound nor read locally yet.
    if analysis.root is not None:
        if new_name in analysis.root.globals:
            return f"new name {new_name!r} collides with a global declaration"
        if new_name in analysis.root.nonlocals:
            return f"new name {new_name!r} collides with a nonlocal declaration"
    if new_name in analysis.nested_nonlocals:
        return (
            f"new name {new_name!r} collides with a nonlocal declaration in a "
            "nested scope"
        )
    return None


def _collect_edits(
    analysis: _FragmentAnalysis, old_name: str, new_name: str
) -> list[tuple[int, int, int, int, str]]:
    assert analysis.root is not None
    nodes = list(analysis.root.loads.get(old_name, [])) + list(
        analysis.root.stores.get(old_name, [])
    )
    edits: list[tuple[int, int, int, int, str]] = []
    for node in nodes:
        if node.end_lineno is None or node.end_col_offset is None:
            raise LiteralError("AST node is missing end positions")
        edits.append(
            (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset, new_name)
        )
    return edits


def _apply_edits(
    code: str, edits: Sequence[tuple[int, int, int, int, str]]
) -> str:
    data = bytearray(code.encode("utf-8"))
    line_starts = [0]
    for index, byte in enumerate(data):
        if byte == 0x0A:
            line_starts.append(index + 1)

    replacements: list[tuple[int, int, str]] = []
    for lineno, col, end_lineno, end_col, new_name in edits:
        if lineno != end_lineno:
            raise LiteralError("a Name token unexpectedly spans multiple lines")
        body_line = lineno - 1  # wrapper adds one line
        if body_line < 1 or body_line > len(line_starts):
            raise LiteralError(f"Name token line {lineno} is outside the code body")
        base = line_starts[body_line - 1]
        replacements.append((base + col, base + end_col, new_name))

    replacements.sort(key=lambda item: item[0], reverse=True)
    for start, end, new_name in replacements:
        data[start:end] = new_name.encode("utf-8")
    return bytes(data).decode("utf-8")


def _verify_rename(
    analysis: _FragmentAnalysis,
    edits: Sequence[tuple[int, int, int, int, str]],
    new_code: str,
) -> BModificationError | None:
    try:
        new_tree = _parse(_FRAGMENT_WRAPPER + new_code)
    except (SyntaxError, ValueError, RecursionError) as error:
        message = getattr(error, "msg", str(error))
        return BModificationError(
            B_ERROR_INVALID_REQUEST,
            f"renamed code does not parse: {message}",
        )
    positions = {(lineno, col): name for lineno, col, _e, _c, name in edits}

    class _PositionRenamer(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
            replacement = positions.get((node.lineno, node.col_offset))
            if replacement is not None:
                node.id = replacement
            return node

    expected = _PositionRenamer().visit(copy.deepcopy(analysis.tree))
    if ast.dump(expected, include_attributes=False) != ast.dump(
        new_tree, include_attributes=False
    ):
        return BModificationError(
            B_ERROR_INVALID_REQUEST,
            "renamed code does not match the intended scoped replacement",
        )
    return None


def _rename_code(
    snapshot: TemplateSnapshot,
    example_number: int,
    example: Any,
    renames: Sequence[RenameMapping],
) -> tuple[str | None, list[BModificationError]]:
    errors: list[BModificationError] = []
    analysis = _analyze_example(snapshot, example_number, example)
    if analysis.fatal_reason is not None:
        for mapping in renames:
            errors.append(
                BModificationError(
                    B_ERROR_UNSUPPORTED_SCOPE,
                    analysis.fatal_reason,
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
        return None, errors

    seen_old: set[tuple[str, str]] = set()
    seen_new: set[str] = set()
    for mapping in renames:
        key = (mapping.scope_id, mapping.old_name)
        if key in seen_old:
            errors.append(
                BModificationError(
                    B_ERROR_DUPLICATE_MAPPING,
                    f"duplicate mapping for {mapping.old_name!r}",
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
        seen_old.add(key)
        if mapping.new_name != mapping.old_name:
            if mapping.new_name in seen_new:
                errors.append(
                    BModificationError(
                        B_ERROR_NAME_CONFLICT,
                        f"new name {mapping.new_name!r} is used by more than one mapping",
                        example_number,
                        mapping.scope_id,
                        mapping.old_name,
                    )
                )
            seen_new.add(mapping.new_name)
    if errors:
        return None, errors

    edits: list[tuple[int, int, int, int, str]] = []
    for mapping in renames:
        if mapping.scope_id != analysis.scope_id:
            errors.append(
                BModificationError(
                    B_ERROR_UNKNOWN_SCOPE,
                    f"scope {mapping.scope_id!r} does not exist in example {example_number}",
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        if mapping.old_name in analysis.unsupported_names:
            errors.append(
                BModificationError(
                    B_ERROR_UNSUPPORTED_SCOPE,
                    analysis.unsupported_names[mapping.old_name],
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        if mapping.old_name in analysis.frozen_names:
            errors.append(
                BModificationError(
                    B_ERROR_FROZEN_BINDING,
                    f"{mapping.old_name!r} is a frozen binding (import/def/except)",
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        if mapping.old_name not in analysis.target_names:
            errors.append(
                BModificationError(
                    B_ERROR_UNKNOWN_TARGET,
                    f"{mapping.old_name!r} is not a local binding in example {example_number}",
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        if not _is_identifier(mapping.new_name):
            errors.append(
                BModificationError(
                    B_ERROR_INVALID_IDENTIFIER,
                    f"{mapping.new_name!r} is not a valid identifier",
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        if mapping.old_name == mapping.new_name:
            continue
        conflict = _conflict_reason(mapping, analysis)
        if conflict is not None:
            errors.append(
                BModificationError(
                    B_ERROR_NAME_CONFLICT,
                    conflict,
                    example_number,
                    mapping.scope_id,
                    mapping.old_name,
                )
            )
            continue
        edits.extend(_collect_edits(analysis, mapping.old_name, mapping.new_name))

    if errors:
        return None, errors
    if not edits:
        # Every mapping was a no-op; keep the parent bytes.
        return example.code, []
    try:
        new_code = _apply_edits(example.code, edits)
    except (ValueError, UnicodeDecodeError) as error:
        errors.append(
            BModificationError(
                B_ERROR_INVALID_REQUEST,
                f"rename produced invalid source: {error}",
            )
        )
        return None, errors
    verify_error = _verify_rename(analysis, edits, new_code)
    if verify_error is not None:
        errors.append(verify_error)
        return None, errors
    return new_code, []


def apply_b_modification(
    parent_snapshot: TemplateSnapshot,
    request: BModificationRequest,
) -> BModificationResult:
    """Validate and materialize a B request atomically (no writes).

    Returns a ``legal`` (real change), ``no_change`` (valid but byte-identical)
    or ``invalid`` result.  A single illegal mapping/example rejects the whole
    candidate; no partial patch is ever produced.
    """

    if not isinstance(parent_snapshot, TemplateSnapshot):
        raise LiteralError("apply_b_modification requires a TemplateSnapshot")
    if not isinstance(request, BModificationRequest):
        raise LiteralError("apply_b_modification requires a BModificationRequest")

    parent_sha = parent_snapshot.content_sha256()
    errors: list[BModificationError] = []
    if request.parent_content_sha256 != parent_sha:
        errors.append(
            BModificationError(
                B_ERROR_STALE_PARENT,
                "request parent_content_sha256 does not match the supplied parent "
                f"snapshot ({request.parent_content_sha256} != {parent_sha})",
            )
        )

    seen_examples: set[int] = set()
    for modification in request.modifications:
        if modification.example > len(parent_snapshot.examples):
            errors.append(
                BModificationError(
                    B_ERROR_OUT_OF_RANGE_EXAMPLE,
                    f"example {modification.example} is out of range",
                    modification.example,
                )
            )
            continue
        if modification.example in seen_examples:
            errors.append(
                BModificationError(
                    B_ERROR_DUPLICATE_EXAMPLE,
                    f"example {modification.example} appears more than once",
                    modification.example,
                )
            )
            continue
        seen_examples.add(modification.example)
        if (
            modification.example == FROZEN_EXAMPLE
            or modification.example not in MODIFIABLE_EXAMPLES
        ):
            errors.append(
                BModificationError(
                    B_ERROR_FROZEN_EXAMPLE,
                    f"example {modification.example} is not modifiable; only "
                    f"{MODIFIABLE_EXAMPLES} are allowed",
                    modification.example,
                )
            )
        if not modification.renames and modification.new_cot is None:
            errors.append(
                BModificationError(
                    B_ERROR_NO_MODIFICATION,
                    f"example {modification.example} supplies no rename or new CoT",
                    modification.example,
                )
            )
    if errors:
        return _invalid_result(parent_snapshot, request, errors)

    patch_entries: list[dict[str, Any]] = []
    for modification in request.modifications:
        example = parent_snapshot.example(modification.example)
        fields: dict[str, str] = {}
        if modification.new_cot is not None:
            fields["cot"] = modification.new_cot
        if modification.renames:
            new_code, rename_errors = _rename_code(
                parent_snapshot, modification.example, example, modification.renames
            )
            errors.extend(rename_errors)
            if new_code is not None:
                fields["code"] = new_code
        if fields:
            patch_entries.append({"example": modification.example, **fields})
    if errors:
        return _invalid_result(parent_snapshot, request, errors)
    if not patch_entries:
        return _invalid_result(
            parent_snapshot,
            request,
            [
                BModificationError(
                    B_ERROR_NO_MODIFICATION,
                    "the request supplied no effective modification",
                )
            ],
        )

    try:
        patch_result = apply_patch(parent_snapshot, patch_entries, _B_PATCH_POLICY)
    except TemplateSnapshotError as error:
        return _invalid_result(
            parent_snapshot,
            request,
            [BModificationError(B_ERROR_INVALID_REQUEST, str(error))],
        )

    status = B_STATUS_LEGAL if patch_result.changed else B_STATUS_NO_CHANGE
    return BModificationResult(
        candidate=request.candidate,
        parent_content_sha256=parent_sha,
        status=status,
        changed=patch_result.changed,
        diff=tuple(patch_result.diff),
        snapshot=patch_result.snapshot,
        content_sha256=patch_result.content_sha256,
    )


def save_b_modification(
    result: BModificationResult,
    store_root: Path | str,
    *,
    action_id: str | None = None,
    created_at: str | None = None,
) -> Path:
    """Persist a *legal* B result through the shared content-addressed store.

    ``no_change``/``invalid`` results carry no new content version and are
    rejected here; the caller keeps the original template identity.  Persistence
    failures raise :class:`BModificationIOError` and are never reported as
    candidate invalidity.
    """

    if not isinstance(result, BModificationResult):
        raise LiteralError("save_b_modification requires a BModificationResult")
    if result.status != B_STATUS_LEGAL or not result.changed:
        raise LiteralError(
            "only a legal, changed B modification result can be persisted; "
            f"got status={result.status!r}, changed={result.changed!r}"
        )
    try:
        directory = write_snapshot(
            store_root,
            result.snapshot,
            action_id=action_id,
            parent_sha256=result.parent_content_sha256,
            diff=result.diff,
            created_at=created_at,
        )
        loaded = read_snapshot(directory)
    except (OSError, TemplateSnapshotError, ValueError) as error:
        raise BModificationIOError(
            f"failed to persist B modification to {store_root}: {error}"
        ) from error
    if loaded.content_sha256() != result.content_sha256:
        raise BModificationIOError(
            "persisted snapshot content hash does not match the materialized result"
        )
    return directory


__all__ = [
    "LiteralError",
    "BModificationIOError",
    "extract_code_prefix",
    "enumerate_rename_targets",
    "apply_b_modification",
    "save_b_modification",
]
