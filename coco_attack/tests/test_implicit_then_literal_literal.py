"""Scoped rename + B materialization tests for ``implicit_then_literal``.

The tests use neutral synthetic code (never the real baseline as the only
rename sample) so binding boundaries, Unicode offsets and atomicity can be
checked deterministically.  Nothing here executes or imports candidate code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.iteration.template_snapshot import (
    ExampleTemplate,
    TemplateSnapshot,
    read_snapshot,
)
from coco_methods import implicit_then_literal as itl


def _instruct(params: str = "") -> str:
    return (
        "Do the task.\nYou should write self-contained code starting with:\n"
        f"```\nimport os\ndef task_func({params}):\n```"
    )


def _snapshot(bodies: list[str], params: str = "") -> TemplateSnapshot:
    examples = []
    for index, body in enumerate(bodies):
        examples.append(
            ExampleTemplate(
                task_id=f"BigCodeBench/{index + 1}",
                instruct_prompt=_instruct(params),
                code=body,
                cot="Step 1. original.",
                is_poisoned=index > 0,
                trigger="cf" if index > 0 else None,
                poison_parts=("code",) if index > 0 else (),
            )
        )
    return TemplateSnapshot(
        combination_id="cwe078-0",
        form="poisoned_fewshot_cot",
        prompt_version="1",
        protocol_version="poison-template-v1",
        trigger="cf",
        injection_position="first_sentence_end",
        mode="instruction_injection",
        examples=tuple(examples),
    )


def _one(body: str, params: str = "") -> TemplateSnapshot:
    return _snapshot(["    pass\n", body, "    pass\n"], params=params)


def _candidate(index: int = 1) -> itl.CandidateIdentity:
    return itl.CandidateIdentity(
        run_id="run-1",
        round_index=1,
        stage="B",
        candidate_index=index,
        seed_candidate_id="seed-a1",
    )


def _request(
    snapshot: TemplateSnapshot,
    modifications: tuple[itl.ExampleModification, ...],
    candidate: itl.CandidateIdentity | None = None,
    parent_sha: str | None = None,
) -> itl.BModificationRequest:
    return itl.BModificationRequest(
        candidate=candidate or _candidate(),
        parent_content_sha256=parent_sha or snapshot.content_sha256(),
        modifications=modifications,
    )


def _rename(
    snapshot: TemplateSnapshot,
    example: int,
    old: str,
    new: str,
    **kwargs: object,
) -> itl.BModificationResult:
    report = itl.enumerate_rename_targets(snapshot, example)
    scope_id = report.scope_id or "unresolvable-scope"
    mapping = itl.RenameMapping(scope_id, old, new)
    return itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=example, renames=(mapping,)),),
            **kwargs,  # type: ignore[arg-type]
        ),
    )


def _categories(result: itl.BModificationResult) -> set[str]:
    return {error.category for error in result.errors}


# --------------------------------------------------------------------------- #
# Enumeration and stable scope identity
# --------------------------------------------------------------------------- #


def test_scope_id_is_stable_and_bound_to_parent_content() -> None:
    snapshot = _one("    value = 1\n    return value\n")
    first = itl.enumerate_rename_targets(snapshot, 2)
    second = itl.enumerate_rename_targets(snapshot, 2)
    assert first.scope_id == second.scope_id
    assert first.targets == second.targets
    assert [target.name for target in first.targets] == ["value"]

    # Changing unrelated example content changes the parent content hash, so the
    # scope id is bound to the parent identity.
    other = _snapshot(
        ["    pass\n", "    value = 1\n    return value\n", "    changed = 2\n"]
    )
    assert other.content_sha256() != snapshot.content_sha256()
    assert (
        itl.enumerate_rename_targets(other, 2).scope_id != first.scope_id
    )


def test_enumeration_reports_frozen_and_unsupported() -> None:
    frozen = itl.enumerate_rename_targets(_one("    x = 1\n"), 1)
    assert frozen.scope_id is None
    assert frozen.targets == ()
    assert "frozen" in frozen.unsupported[0].reason

    captured = itl.enumerate_rename_targets(
        _one("    x = 1\n    def inner():\n        return x\n    return inner\n"), 2
    )
    assert [target.name for target in captured.targets] == []
    assert [item.name for item in captured.unsupported] == ["x"]

    with pytest.raises(itl.LiteralError):
        itl.enumerate_rename_targets(_one("    x = 1\n"), 5)


# --------------------------------------------------------------------------- #
# Ordinary local rename and untouched source
# --------------------------------------------------------------------------- #


def test_local_declaration_and_references_are_renamed() -> None:
    snapshot = _one("    value = 1\n    value = value + 1\n    return value\n")
    result = _rename(snapshot, 2, "value", "renamed")
    assert result.status == itl.B_STATUS_LEGAL
    assert result.changed is True
    assert result.snapshot.example(2).code == (
        "    renamed = 1\n    renamed = renamed + 1\n    return renamed\n"
    )
    assert result.diff == (
        {
            "example": 2,
            "field": "code",
            "before": snapshot.example(2).code,
            "after": result.snapshot.example(2).code,
            "changed": True,
        },
    )
    # Other examples and fields are byte-identical.
    assert result.snapshot.example(1) == snapshot.example(1)
    assert result.snapshot.example(3) == snapshot.example(3)


def test_attributes_keywords_strings_comments_and_nested_shadow_are_untouched() -> None:
    body = (
        '    value = obj.attr\n'
        '    print(value, file=sys.stderr)\n'
        '    text = "value"\n'
        '    # keep value as a comment\n'
        '    def inner():\n'
        '        value = 2\n'
        '        return value\n'
        '    inner()\n'
        '    return value\n'
    )
    snapshot = _one(body)
    result = _rename(snapshot, 2, "value", "renamed")
    assert result.status == itl.B_STATUS_LEGAL
    assert result.snapshot.example(2).code == (
        '    renamed = obj.attr\n'
        '    print(renamed, file=sys.stderr)\n'
        '    text = "value"\n'
        '    # keep value as a comment\n'
        '    def inner():\n'
        '        value = 2\n'
        '        return value\n'
        '    inner()\n'
        '    return renamed\n'
    )


def test_tuple_for_targets_are_renamed_together() -> None:
    snapshot = _one("    for a, b in pairs:\n        print(a, b)\n")
    result = _rename(snapshot, 2, "a", "first")
    assert result.status == itl.B_STATUS_LEGAL
    assert result.snapshot.example(2).code == (
        "    for first, b in pairs:\n        print(first, b)\n"
    )


# --------------------------------------------------------------------------- #
# Binding / structure boundaries
# --------------------------------------------------------------------------- #


def test_new_name_conflicts_are_rejected() -> None:
    snapshot = _one("    a = 1\n    b = 2\n    return a + b\n")

    other_binding = _rename(snapshot, 2, "a", "b")
    assert other_binding.status == itl.B_STATUS_INVALID
    assert "name_conflict" in _categories(other_binding)

    invalid_identifier = _rename(snapshot, 2, "a", "class")
    assert "invalid_identifier" in _categories(invalid_identifier)

    unknown_target = _rename(snapshot, 2, "missing", "c")
    assert "unknown_target" in _categories(unknown_target)

    wrong_scope = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(itl.RenameMapping("bogus-scope", "a", "c"),),
                ),
            ),
        ),
    )
    assert "unknown_scope" in _categories(wrong_scope)


def test_parameter_import_and_free_name_capture_are_rejected() -> None:
    param_snapshot = _one("    x = process_name\n    return x\n", params="process_name")
    assert "name_conflict" in _categories(
        _rename(param_snapshot, 2, "x", "process_name")
    )

    import_snapshot = _one("    import os\n    x = 1\n    return x\n")
    assert "frozen_binding" in _categories(_rename(import_snapshot, 2, "os", "o"))

    free_snapshot = _one("    x = 1\n    print(x)\n    return x\n")
    assert "name_conflict" in _categories(_rename(free_snapshot, 2, "x", "print"))

    nested_free = _one(
        "    x = 1\n    def inner():\n        return os.getcwd()\n    return x\n"
    )
    assert "name_conflict" in _categories(_rename(nested_free, 2, "x", "os"))


def test_parameter_reassignment_and_unsupported_alias_are_rejected() -> None:
    # A parameter assigned in the body is still a frozen signature binding.
    param_snapshot = _one(
        "    process_name = process_name.strip()\n    return process_name\n",
        params="process_name",
    )
    report = itl.enumerate_rename_targets(param_snapshot, 2)
    assert report.targets == ()
    param_result = _rename(param_snapshot, 2, "process_name", "renamed")
    assert param_result.status == itl.B_STATUS_INVALID
    assert "frozen_binding" in _categories(param_result)

    # A new name that aliases an unsupported binding (walrus) is rejected.
    alias_snapshot = _one("    y = 10\n    if (x := 1):\n        pass\n    return y\n")
    alias_result = _rename(alias_snapshot, 2, "y", "x")
    assert alias_result.status == itl.B_STATUS_INVALID
    assert "name_conflict" in _categories(alias_result)

    # A walrus inside a comprehension binds in the containing scope, so the
    # enclosing local cannot be renamed.
    comprehension_snapshot = _one(
        "    y = 0\n    z = [(y := i) for i in range(3)]\n    return y\n"
    )
    comprehension_result = _rename(comprehension_snapshot, 2, "y", "w")
    assert comprehension_result.status == itl.B_STATUS_INVALID
    assert "unsupported_scope" in _categories(comprehension_result)


def test_global_declaration_and_class_method_capture_are_rejected(
    tmp_path: Path,
) -> None:
    # [P1] A new name colliding with a `global` declaration must not silently
    # turn a local assignment into a global one.
    global_snapshot = _one("    global saved\n    value = 1\n    return value\n")
    global_result = _rename(global_snapshot, 2, "value", "saved")
    assert global_result.status == itl.B_STATUS_INVALID
    assert "name_conflict" in _categories(global_result)
    assert global_result.snapshot is global_snapshot
    assert global_result.diff == ()
    assert not (tmp_path / "store").exists()

    # [P1] A class method's reference to an enclosing local must be detected:
    # class bindings do not close over methods, so the outer local is captured.
    class_snapshot = _one(
        "    value = 1\n"
        "    class Box:\n"
        "        value = 2\n"
        "        def get(self):\n"
        "            return value\n"
        "    return value, Box\n"
    )
    class_result = _rename(class_snapshot, 2, "value", "renamed")
    assert class_result.status == itl.B_STATUS_INVALID
    assert "unsupported_scope" in _categories(class_result)
    assert class_result.snapshot is class_snapshot
    assert class_result.diff == ()

    # A class body using its own class-level name directly does not block an
    # unrelated outer rename.
    unrelated = _one(
        "    outer = 1\n"
        "    class Box:\n"
        "        inner = 2\n"
        "        doubled = inner * 2\n"
        "    return outer, Box\n"
    )
    unrelated_result = _rename(unrelated, 2, "outer", "renamed")
    assert unrelated_result.status == itl.B_STATUS_LEGAL


def test_unsupported_structures_are_explicitly_rejected() -> None:
    cases = {
        "closure": "    x = 1\n    def inner():\n        return x\n    return inner\n",
        "comprehension": "    x = 1\n    return [x for i in range(3)]\n",
        "global": "    global g\n    g = 1\n",
        "dynamic": "    x = 1\n    d = locals()\n    return x\n",
        "walrus": "    if (x := 1):\n        return x\n    return 0\n",
        "delete": "    x = 1\n    del x\n",
        "star_import": "    from os import *\n    x = 1\n    return x\n",
        "nonlocal": (
            "    def inner():\n        nonlocal x\n        x = 2\n"
            "    x = 1\n    inner()\n    return x\n"
        ),
        "match": (
            "    match value:\n        case [x]:\n            return x\n"
            "    return None\n"
        ),
    }
    for label, body in cases.items():
        snapshot = _one(body)
        name = "x" if "x" in body else "g"
        result = _rename(snapshot, 2, name, "renamed")
        assert result.status == itl.B_STATUS_INVALID, label
        assert result.errors[0].category == "unsupported_scope", label


# --------------------------------------------------------------------------- #
# Multiple mappings and Unicode
# --------------------------------------------------------------------------- #


def test_multiple_mappings_are_simultaneous_not_cascading() -> None:
    snapshot = _one("    a = 1\n    b = a + 1\n    return a + b\n")
    report = itl.enumerate_rename_targets(snapshot, 2)
    assert report.scope_id is not None
    result = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(
                        itl.RenameMapping(report.scope_id, "a", "c"),
                        itl.RenameMapping(report.scope_id, "b", "d"),
                    ),
                ),
            ),
        ),
    )
    assert result.status == itl.B_STATUS_LEGAL
    assert result.snapshot.example(2).code == (
        "    c = 1\n    d = c + 1\n    return c + d\n"
    )


def test_swap_and_duplicate_mappings_are_rejected() -> None:
    snapshot = _one("    a = 1\n    b = 2\n    return a + b\n")
    report = itl.enumerate_rename_targets(snapshot, 2)
    assert report.scope_id is not None
    swap = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(
                        itl.RenameMapping(report.scope_id, "a", "b"),
                        itl.RenameMapping(report.scope_id, "b", "a"),
                    ),
                ),
            ),
        ),
    )
    assert swap.status == itl.B_STATUS_INVALID
    assert "name_conflict" in _categories(swap)

    duplicate = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(
                        itl.RenameMapping(report.scope_id, "a", "c"),
                        itl.RenameMapping(report.scope_id, "a", "d"),
                    ),
                ),
            ),
        ),
    )
    assert "duplicate_mapping" in _categories(duplicate)


def test_unicode_offsets_do_not_corrupt_the_source() -> None:
    body = (
        "    # 中文注释：value 保持不变\n"
        '    label = "值"\n'
        "    value = label\n"
        '    d = {"键": value}\n'
        "    return value\n"
    )
    snapshot = _one(body)
    result = _rename(snapshot, 2, "value", "renamed")
    assert result.status == itl.B_STATUS_LEGAL
    assert result.snapshot.example(2).code == (
        "    # 中文注释：value 保持不变\n"
        '    label = "值"\n'
        "    renamed = label\n"
        '    d = {"键": renamed}\n'
        "    return renamed\n"
    )


# --------------------------------------------------------------------------- #
# CoT-only and frozen example
# --------------------------------------------------------------------------- #


def test_cot_only_works_even_with_unsupported_rename_structure() -> None:
    snapshot = _one("    global g\n    g = 1\n")
    result = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=2, new_cot="Step 1. rewritten."),),
        ),
    )
    assert result.status == itl.B_STATUS_LEGAL
    assert result.snapshot.example(2).cot == "Step 1. rewritten."
    assert result.snapshot.example(2).code == snapshot.example(2).code
    assert result.snapshot.example(2).poison_parts == ("code", "cot")

    # A non-indented body is likewise fine for CoT-only.
    non_indented = _one("x = 1\nreturn x\n")
    non_indented_result = itl.apply_b_modification(
        non_indented,
        _request(
            non_indented,
            (itl.ExampleModification(example=2, new_cot="new"),),
        ),
    )
    assert non_indented_result.status == itl.B_STATUS_LEGAL


def test_frozen_and_out_of_range_examples_are_rejected() -> None:
    snapshot = _one("    x = 1\n    return x\n")
    frozen = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=1, new_cot="x"),),
        ),
    )
    assert "frozen_example" in _categories(frozen)

    out_of_range = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=5, new_cot="x"),),
        ),
    )
    assert "out_of_range_example" in _categories(out_of_range)

    no_modification = itl.apply_b_modification(
        snapshot,
        _request(snapshot, (itl.ExampleModification(example=2),)),
    )
    assert "no_modification" in _categories(no_modification)


# --------------------------------------------------------------------------- #
# Identity, atomicity and persistence
# --------------------------------------------------------------------------- #


def test_stale_parent_hash_is_rejected() -> None:
    snapshot = _one("    x = 1\n    return x\n")
    result = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=2, new_cot="x"),),
            parent_sha="0" * 64,
        ),
    )
    assert result.status == itl.B_STATUS_INVALID
    assert "stale_parent" in _categories(result)


def test_no_change_keeps_the_parent_identity() -> None:
    snapshot = _one("    x = 1\n    return x\n")
    report = itl.enumerate_rename_targets(snapshot, 2)
    assert report.scope_id is not None
    result = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(itl.RenameMapping(report.scope_id, "x", "x"),),
                ),
            ),
        ),
    )
    assert result.status == itl.B_STATUS_NO_CHANGE
    assert result.changed is False
    assert result.snapshot is snapshot
    assert result.content_sha256 == snapshot.content_sha256()

    unchanged_cot = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2, new_cot=snapshot.example(2).cot
                ),
            ),
        ),
    )
    assert unchanged_cot.status == itl.B_STATUS_NO_CHANGE
    assert unchanged_cot.content_sha256 == snapshot.content_sha256()


def test_one_illegal_mapping_rejects_the_whole_candidate(
    tmp_path: Path,
) -> None:
    snapshot = _one("    a = 1\n    b = 2\n    return a + b\n")
    report = itl.enumerate_rename_targets(snapshot, 2)
    assert report.scope_id is not None
    result = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (
                itl.ExampleModification(
                    example=2,
                    renames=(
                        itl.RenameMapping(report.scope_id, "a", "c"),
                        itl.RenameMapping(report.scope_id, "b", "class"),
                    ),
                ),
                itl.ExampleModification(example=3, new_cot="legal cot"),
            ),
        ),
    )
    assert result.status == itl.B_STATUS_INVALID
    assert result.snapshot is snapshot
    assert result.diff == ()
    # Nothing is written by the pure materialization step.
    assert not (tmp_path / "store").exists()


def test_legal_result_persists_and_reads_back(tmp_path: Path) -> None:
    snapshot = _one("    value = 1\n    return value\n")
    result = _rename(snapshot, 2, "value", "renamed")
    assert result.status == itl.B_STATUS_LEGAL

    store = tmp_path / "store"
    directory = itl.save_b_modification(
        result, store, action_id="b-1", created_at="2026-10-03T00:00:00+00:00"
    )
    loaded = read_snapshot(directory)
    assert loaded.content_sha256() == result.content_sha256
    assert loaded.example(2).code == result.snapshot.example(2).code

    # Repeated save is idempotent through the shared store semantics.
    again = itl.save_b_modification(result, store, action_id="b-1-again")
    assert again == directory
    audit_lines = (store / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) == 2
    assert str(result.parent_content_sha256) in audit_lines[0]

    # Invalid and no-change results carry no new content version.
    no_change = itl.apply_b_modification(
        snapshot,
        _request(
            snapshot,
            (itl.ExampleModification(example=2, new_cot=snapshot.example(2).cot),),
        ),
    )
    with pytest.raises(itl.LiteralError):
        itl.save_b_modification(no_change, store)
    invalid = itl.apply_b_modification(
        snapshot,
        _request(snapshot, (itl.ExampleModification(example=1, new_cot="x"),)),
    )
    with pytest.raises(itl.LiteralError):
        itl.save_b_modification(invalid, store)


def test_persistence_failure_is_distinct_from_candidate_invalidity(
    tmp_path: Path,
) -> None:
    snapshot = _one("    value = 1\n    return value\n")
    result = _rename(snapshot, 2, "value", "renamed")
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(itl.BModificationIOError):
        itl.save_b_modification(result, blocker)
