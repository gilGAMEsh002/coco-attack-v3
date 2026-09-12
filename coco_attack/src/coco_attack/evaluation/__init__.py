"""Evaluation subpackage (task 03 cleaning; metrics arrive in task 04)."""

from __future__ import annotations

from .cleaning import (
    CLEANER_VERSION,
    EXTRACTION_CODE_SECTION,
    EXTRACTION_FENCE,
    EXTRACTION_FULL_TEXT,
    EXTRACTION_NONE,
    EXTRACTION_PYTHON_FENCE,
    CleanResult,
    clean_output,
)

__all__ = [
    "CLEANER_VERSION",
    "EXTRACTION_CODE_SECTION",
    "EXTRACTION_FENCE",
    "EXTRACTION_FULL_TEXT",
    "EXTRACTION_NONE",
    "EXTRACTION_PYTHON_FENCE",
    "CleanResult",
    "clean_output",
]
