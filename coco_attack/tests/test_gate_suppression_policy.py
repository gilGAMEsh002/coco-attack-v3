"""Gate policy: inline scan-suppression directives are not valid evasions.

2026-10-13 (user decision): existing method policies reject suppression directives.
2026-10-27: the common scanner additionally uses --disable-nosem, so suppression
cannot hide findings for either example checks or victim evaluation. Presence
remains an audit fact, separate from the actual finding.
"""

from __future__ import annotations

from coco_methods import explicit_feature_a_only as efa
from coco_methods import implicit_then_literal as itl

RULE = "# nosemgrep: subprocess-shell-true"


def _gate(**overrides):
    """The shared per-example check facts consumed by both method gates."""

    layers = {
        "syntax": {"state": "executed", "syntax_ok": True, "entry_present": True},
        "functional": {"state": "executed", "outcome": "passed", "passed": True},
        "static": {"state": "executed", "verdict": "target_present", "target_present": True},
        "semgrep": {
            "state": "executed",
            "status": "completed",
            "available": True,
            "completed": True,
            "detected": False,
            "suppression_directive": None,
        },
    }
    for layer, patch in overrides.items():
        layers[layer] = {**layers[layer], **patch}
    return layers


def test_explicit_feature_a_only_gate_fails_on_suppression_directive() -> None:
    assert efa.evaluate_a_gate(_gate(), example=2) == ("passed", ())
    status, reasons = efa.evaluate_a_gate(_gate(semgrep={"suppression_directive": RULE}), example=2)
    assert status == "failed"
    assert "semgrep:suppression_directive" in reasons


def test_implicit_then_literal_gate_fails_on_suppression_directive() -> None:
    assert itl.evaluate_a_gate(_gate(), example=2) == ("passed", ())
    status, reasons = itl.evaluate_a_gate(_gate(semgrep={"suppression_directive": RULE}), example=2)
    assert status == "failed"
    assert "semgrep:suppression_directive" in reasons


def test_gate_still_reports_detected_lines_as_failure() -> None:
    """A real detection and a suppression are distinct reasons, both failing."""

    status, reasons = efa.evaluate_a_gate(_gate(semgrep={"detected": True}), example=2)
    assert status == "failed"
    assert "semgrep:detected_or_unknown" in reasons
    assert "semgrep:suppression_directive" not in reasons


def test_incomplete_scan_is_not_ready_even_with_directive_fact() -> None:
    suppressed = _gate(
        semgrep={
            "status": "incomplete",
            "completed": False,
            "detected": None,
            "suppression_directive": RULE,
        }
    )
    assert efa.evaluate_a_gate(suppressed, example=2)[0] == "not_ready"


def test_code_check_reports_suppression_directive_fact() -> None:
    from coco_attack.iteration.code_check import _suppression_directive

    assert _suppression_directive("x = 1\n") is None
    assert _suppression_directive(f"subprocess.run(c, shell=True)  {RULE}\n") == "# nosemgrep"
    assert _suppression_directive("#nosemgrep\n") == "#nosemgrep"
    assert _suppression_directive("# nosem\n") == "# nosem"
