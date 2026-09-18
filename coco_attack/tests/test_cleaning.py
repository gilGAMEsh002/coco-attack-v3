"""Phase-03 checks for output extraction and entry completion."""

from __future__ import annotations

import pytest

from coco_attack.evaluation.cleaning import (
    CLEANER_VERSION,
    EXTRACTION_CODE_SECTION,
    EXTRACTION_FENCE,
    EXTRACTION_FULL_TEXT,
    EXTRACTION_NONE,
    EXTRACTION_PYTHON_FENCE,
    clean_output,
)


class FakeTask:
    def __init__(
        self,
        entry_point: str = "task_func",
        code_prompt: str = "import os\ndef task_func(x):\n",
        instruct_prompt: str = (
            "Do the thing.\nYou should write self-contained code starting with:\n"
            "```\nimport os\ndef task_func(x):\n```"
        ),
    ) -> None:
        self.entry_point = entry_point
        self.code_prompt = code_prompt
        self.effective = {
            "code_prompt": code_prompt,
            "instruct_prompt": instruct_prompt,
        }


def test_python_fence_extraction_and_completion() -> None:
    text = "### cot\nStep 1. think\n\n### code\n```python\n    return x\n```\n"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_PYTHON_FENCE
    assert result.code == "    return x"
    assert result.completed is True
    assert result.completion_action == "prepend_prefix"
    assert result.syntax_ok is True
    assert result.entry_present is True
    assert result.final_code.startswith("import os\ndef task_func(x):")
    assert result.cleaner_version == CLEANER_VERSION


def test_language_less_fence_is_second_priority() -> None:
    text = "```\n    return x\n```"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_FENCE


def test_code_section_without_fence() -> None:
    text = "Some reasoning.\n### code\n    return x"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_CODE_SECTION
    assert result.code == "    return x"
    assert result.completed is True


def test_full_text_fallback() -> None:
    text = "    return x"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_FULL_TEXT


def test_first_fence_is_used_not_the_best() -> None:
    text = "```python\n    return 1\n```\n\n```python\n    return 2\n```"
    result = clean_output(text, FakeTask(), "success")
    assert result.code == "    return 1"


def test_generation_failure_keeps_empty_code() -> None:
    result = clean_output("Error 500", FakeTask(), "api_error")
    assert result.extraction_path == EXTRACTION_NONE
    assert result.code == ""
    assert result.final_code == ""
    assert result.syntax_ok is None
    assert result.entry_present is False
    assert "generation_status=api_error" in result.diagnostics


def test_empty_output() -> None:
    result = clean_output("   ", FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_NONE
    assert result.code == ""
    assert "empty_output" in result.diagnostics


def test_missing_status_is_input_error() -> None:
    with pytest.raises(ValueError):
        clean_output("code", FakeTask(), None)


def test_complete_module_missing_entry_is_preserved() -> None:
    text = "```python\ndef helper():\n    return 1\n```"
    result = clean_output(text, FakeTask(), "success")
    assert result.completion_action == "module_missing_entry"
    assert result.entry_present is False
    assert "def helper" in result.final_code
    assert "def task_func" not in result.final_code


def test_unindented_bare_body_is_indented() -> None:
    text = "x = 1\nreturn x"
    result = clean_output(text, FakeTask(), "success")
    assert result.completed is True
    assert result.syntax_ok is True
    assert "    x = 1" in result.final_code


def test_multiline_string_bare_body_is_not_reindented() -> None:
    text = 'value = """line1\nline2"""'
    result = clean_output(text, FakeTask(), "success")
    assert result.completed is False
    assert "cannot_reindent_bare_body" in result.diagnostics
    # The literal body is preserved rather than silently changed.
    assert result.final_code == text


def test_entry_already_defined_is_not_rewrapped() -> None:
    text = "```python\nimport os\ndef task_func(x):\n    return x\n```"
    result = clean_output(text, FakeTask(), "success")
    assert result.completed is False
    assert result.completion_action == "none"
    assert result.entry_present is True
    assert result.final_code == "import os\ndef task_func(x):\n    return x"


def test_cleaner_v3_normalizes_line_endings_and_trims_boundary() -> None:
    text = "```python\nimport os\r\n\r\ndef task_func(x):\r\n    return x\r\n```"
    result = clean_output(text, FakeTask(), "success")
    assert result.code == "import os\n\ndef task_func(x):\n    return x"
    assert result.final_code == result.code


def test_cleaner_v3_crlf_and_lf_are_canonical_equivalent() -> None:
    crlf = "```python\nimport os\r\n\r\ndef task_func(x):\r\n    return x\r\n```"
    lf = "```python\nimport os\n\ndef task_func(x):\n    return x\n```"
    first = clean_output(crlf, FakeTask(), "success")
    second = clean_output(lf, FakeTask(), "success")
    assert first.final_code == second.final_code
    assert first.final_code_sha256 == second.final_code_sha256


def test_cleaner_v3_preserves_internal_whitespace_and_strings() -> None:
    text = '```python\nimport os\ndef task_func(x):\n    s = """a\n\n  b"""\n    return s\n```'
    result = clean_output(text, FakeTask(), "success")
    assert 's = """a\n\n  b"""' in result.final_code


def test_cleaner_v4_inline_opening_fence_is_extracted() -> None:
    text = (
        "Here is code that extracts URLs and data:```python\n"
        "import os\ndef task_func(x):\n    return x\n```\n"
    )
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_PYTHON_FENCE
    assert result.code.startswith("import os\ndef task_func(x):")
    assert result.syntax_ok is True


def test_cleaner_v4_inline_fence_without_closing_fence_is_full_text() -> None:
    # model stopped mid-stream: no closing fence -> keep the full_text fallback
    text = "Here is the code:```python\nimport os\ndef task_func(x):\n    return x"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_FULL_TEXT


def test_cleaner_v4_line_start_python_fence_still_wins() -> None:
    text = (
        "Here is the code:\n"
        "```python\nimport os\ndef task_func(x):\n    return x\n```\n"
    )
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_PYTHON_FENCE
    assert "task_func" in result.code


def test_cleaner_v4_inline_non_python_fence() -> None:
    text = "snippet:```\nsome text\n```\n"
    result = clean_output(text, FakeTask(), "success")
    assert result.extraction_path == EXTRACTION_FENCE
    assert result.code == "some text"
