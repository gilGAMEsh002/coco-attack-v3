"""Single source of truth for the standard screened-task schema.

Both the read-only asset audit (task 01) and the strict data contract loader
(task 02) share these declarations so that a schema change cannot silently
diverge between auditing and loading.
"""

from __future__ import annotations

import re

# Standard 17-field screened schema (``bigcodebench-screened-v1``).
STANDARD_SCHEMA_NAME = "bigcodebench-screened-v1"
STANDARD_SCHEMA = (
    "task_id",
    "complete_prompt",
    "instruct_prompt",
    "canonical_solution",
    "code_prompt",
    "test",
    "entry_point",
    "doc_struct",
    "libs",
    "source_id",
    "source_cwe_id",
    "statistical_cwe_id",
    "decision",
    "experiment_type",
    "reference_side",
    "has_clean_pattern",
    "has_target_pattern",
)
REQUIRED_NONEMPTY = (
    "task_id",
    "complete_prompt",
    "instruct_prompt",
    "code_prompt",
    "test",
    "entry_point",
)
BOOLEAN_FIELDS = ("has_clean_pattern", "has_target_pattern")
REFERENCE_SIDES = frozenset({"clean", "target"})

# ``BigCodeBench_SL_<n>.md`` <-> ``BigCodeBench/<n>`` encoding used by the
# legacy clean prompt assets.
TEST_PROMPT_RE = re.compile(r"^BigCodeBench_SL_(\d+)\.md$")
