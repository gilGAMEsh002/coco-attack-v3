"""Shared problem-record format.

Both the asset audit and later data preparation use the same issue shape so
that problems can be aggregated once and reviewed by the operator. The audit
never writes a decision conclusion itself: differences that need a human call
are recorded as ``pending_decision``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "1"

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_PENDING_DECISION = "pending_decision"

_BLOCKING_SEVERITIES = frozenset({SEVERITY_ERROR, SEVERITY_PENDING_DECISION})


@dataclass(frozen=True)
class Issue:
    """A single audit/data problem with enough evidence to review it."""

    code: str
    severity: str
    scope: str
    detail: str
    asset: str | None = None
    location: dict[str, Any] = field(default_factory=dict)
    evidence: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in {
            SEVERITY_ERROR,
            SEVERITY_WARNING,
            SEVERITY_PENDING_DECISION,
        }:
            raise ValueError(f"Unknown issue severity: {self.severity!r}")

    @property
    def requires_decision(self) -> bool:
        return self.severity == SEVERITY_PENDING_DECISION

    @property
    def blocking(self) -> bool:
        return self.severity in _BLOCKING_SEVERITIES

    def to_json(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "scope": self.scope,
            "detail": self.detail,
            "asset": self.asset,
            "location": dict(sorted(self.location.items())),
            "evidence": self.evidence,
            "requires_decision": self.requires_decision,
        }


def issues_exit_code(issues: list[Issue]) -> int:
    """Return 1 when any issue is blocking (error or pending decision)."""

    return 1 if any(issue.blocking for issue in issues) else 0
