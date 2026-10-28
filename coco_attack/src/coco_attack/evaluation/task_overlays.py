"""Task-scoped functional test overlays.

The raw prepared task data is never rewritten.  Task-specific overlays repair
process fixtures, implementation-form restrictions, and missing checks for
explicit task requirements.  Coverage additions can reject implementations
that the original tests accepted; they are not score adjustments.

Each overlay follows the declared task behavior.  Versioned behavior tests may
replace original assertions about an undeclared API or output spelling; the raw
tests and historical results remain available.  The fixture version and actual
test hash distinguish revisions in the functional cache.  Unlisted tasks keep
their raw tests unchanged.
"""

from __future__ import annotations

from . import process_test_fixtures, t1102, t146, t195, t322, t745, t810, task_test_repairs

_OVERLAYS = {module.TASK_ID: module for module in (t146, t195, t322, t745, t810, t1102)}
_OVERLAYS.update(
    (task_id, module)
    for module in (process_test_fixtures, task_test_repairs)
    for task_id in module.TASK_IDS
)


def _module_for(task_id: str):
    return _OVERLAYS.get(task_id)


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    module = _module_for(task_id)
    if module is None:
        return tests
    return module.effective_tests(task_id, tests)


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    module = _module_for(task_id)
    if module is None:
        return []
    return module.fixture_fingerprint(task_id)


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container so it can verify the fixture version."""

    module = _module_for(task_id)
    if module is None:
        return {}
    return module.evaluation_request_fields(task_id)


__all__ = [
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
