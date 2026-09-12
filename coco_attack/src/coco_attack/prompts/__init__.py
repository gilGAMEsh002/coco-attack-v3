"""Prompt materialization subpackage (task 03)."""

from __future__ import annotations

from .contracts import ExperimentSpec, PromptExperiment, PromptSource
from .markdown import (
    CLEAN_FORMS,
    FORM_CLEAN_0SHOT,
    FORM_CLEAN_FEWSHOT_COT,
    FORM_CLEAN_FEWSHOT_NO_COT,
    MATERIALIZE_VERSION,
    PROMPT_VERSION,
    PromptParseError,
    derive_no_cot,
    parse_prompt_structure,
)
from .trigger import (
    TRIGGER_VERSION,
    has_standalone_trigger,
    inject_examples,
    inject_test_prompt,
    inject_trigger,
    strip_standalone_trigger,
)

__all__ = [
    "ExperimentSpec",
    "PromptExperiment",
    "PromptSource",
    "CLEAN_FORMS",
    "FORM_CLEAN_0SHOT",
    "FORM_CLEAN_FEWSHOT_COT",
    "FORM_CLEAN_FEWSHOT_NO_COT",
    "MATERIALIZE_VERSION",
    "PROMPT_VERSION",
    "PromptParseError",
    "derive_no_cot",
    "parse_prompt_structure",
    "TRIGGER_VERSION",
    "has_standalone_trigger",
    "inject_examples",
    "inject_test_prompt",
    "inject_trigger",
    "strip_standalone_trigger",
]
