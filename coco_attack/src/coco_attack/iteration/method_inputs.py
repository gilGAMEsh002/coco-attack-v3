"""Method-visible projections and fixed input-material assembly (I5).

The common layer owns the *projection* mechanics -- whitelists, display labels,
content fingerprints and the fixed material block -- while the method supplies
the research text (priors, target, output format) and decides which feedback is
allowed at each step.  This module never rewrites program identifiers, paths or
rule/test bytes, and it keeps audit fields (task ids, sample ids, hashes, run
paths) out of the model-visible projection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..assets.artifacts import sha256_bytes, sha256_text
from ..assets.paths import resolve_within
from ..data.loader import load_tasks
from ..evaluation.sast import semgrep_rule_ids, semgrep_target_rules
from .fewshot import load_specs
from .poison_materialize import render_example_blocks
from .template_snapshot import TemplateSnapshot

PROJECTION_VERSION = "method-projection-v1"

#: Structured keys that must never appear in a model-visible projection.  These
#: are checked as *keys*, not as substrings of free text, so generated code that
#: happens to contain an identifier like ``task_id`` is not a false positive.
AUDIT_KEYS = (
    "sample_id",
    "task_id",
    "candidate_hash",
    "oracle_id",
    "combination_id",
    "request_sha256",
    "content_sha256",
    "prompt_sha256",
)
#: Path/hash markers that must not appear in model-visible text.
AUDIT_TEXT_MARKERS = ("/cocota_runs/", "/home/", "BigCodeBench/")
AUDIT_TOKENS = AUDIT_KEYS + AUDIT_TEXT_MARKERS
_HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


class ProjectionError(ValueError):
    """Raised when a projection would violate the audit/visibility boundary."""


def _collect_audit(value: Any, found: set[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key in AUDIT_KEYS:
                found.add(key)
            _collect_audit(item, found)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_audit(item, found)
    elif isinstance(value, str):
        for marker in AUDIT_TEXT_MARKERS:
            if marker in value:
                found.add(marker)
        if _HEX64.search(value):
            found.add("<64-hex-hash>")


def find_audit_tokens(payload: Any) -> list[str]:
    """Report audit-field markers present in a model-visible payload."""

    found: set[str] = set()
    if isinstance(payload, str):
        _collect_audit(payload, found)
    else:
        _collect_audit(payload, found)
    return sorted(found)


def assert_no_audit_fields(payload: Any) -> None:
    found = find_audit_tokens(payload)
    if found:
        raise ProjectionError(f"model-visible payload leaked audit fields: {sorted(set(found))}")


def _alerts_from(record: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Best-effort alert extraction that degrades instead of raising."""

    if not isinstance(record, Mapping):
        return []
    evidence = record.get("evidence")
    if not isinstance(evidence, Mapping):
        return []
    alerts = evidence.get("alerts")
    if not isinstance(alerts, (list, tuple)):
        return []
    return _line_evidence(alerts)


def _line_evidence(alerts: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for alert in alerts or ():
        if not isinstance(alert, Mapping):
            continue
        item: dict[str, Any] = {}
        for key in ("start_line", "start_col", "end_line", "end_col", "line"):
            if alert.get(key) is not None:
                item[key] = alert[key]
        if item:
            evidence.append(item)
    return evidence


def project_example_facts(check_result: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    """Whitelist one ``run_example_code_check`` result into method-visible facts.

    Incomplete/unavailable and not-detected stay distinct: ``detected`` is only
    reported when the scan actually completed, otherwise it is ``None``.
    """

    functional = check_result.get("functional") or {}
    static = check_result.get("static") or {}
    semgrep = check_result.get("semgrep") or {}
    alerts = ((semgrep.get("evidence") or {}).get("alerts")) if isinstance(semgrep.get("evidence"), Mapping) else None
    completed = bool(semgrep.get("completed"))
    available = bool(semgrep.get("available"))
    detected = semgrep.get("detected") if completed else None
    projection = {
        "label": label,
        "syntax": {
            "state": (check_result.get("syntax") or {}).get("state"),
            "syntax_ok": (check_result.get("syntax") or {}).get("syntax_ok"),
            "entry_present": (check_result.get("syntax") or {}).get("entry_present"),
        },
        "functional": {
            "state": functional.get("state"),
            "outcome": functional.get("outcome"),
            "passed": functional.get("passed"),
            "reason": functional.get("reason"),
            "failure_stage": functional.get("failure_stage"),
        },
        "static": {
            "state": static.get("state"),
            "verdict": static.get("verdict"),
            "target_present": static.get("target_present"),
            "reason": static.get("reason"),
        },
        "semgrep": {
            "state": semgrep.get("state"),
            "status": semgrep.get("status"),
            "available": available,
            "completed": completed,
            "detected": detected,
            "reason": semgrep.get("reason") or semgrep.get("reason_code"),
            "line_evidence": _line_evidence(alerts),
        },
    }
    return projection


def project_training_facts(
    feedback: Mapping[str, Any],
    audit: Mapping[str, Any] | None = None,
    *,
    sast_records: Sequence[Mapping[str, Any]] | None = None,
    label_by_task: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Whitelist the training feedback plus per-sample Semgrep line evidence.

    The method-facing ``feedback.json`` already withholds ids/hashes; the audit
    side is only used to attach the scan line evidence that the projection needs
    (the ids themselves are dropped again here).
    """

    feedback_samples = [
        sample for sample in feedback.get("samples", []) if isinstance(sample, Mapping)
    ]
    # Use the audit *list order* (not a dict keyed by sample_id, which silently
    # collapses duplicates / drops order).  The audit side is only consulted to
    # fetch the line evidence; its ids are dropped again from the projection.
    audit_list = (
        [sample for sample in audit.get("samples", []) if isinstance(sample, Mapping)]
        if isinstance(audit, Mapping)
        else []
    )
    if audit is not None and len(audit_list) != len(feedback_samples):
        raise ProjectionError(
            "feedback and audit sample counts disagree; refusing positional evidence"
        )
    sast_by_sample = {
        str(record.get("sample_id")): record
        for record in (sast_records or [])
        if isinstance(record, Mapping) and record.get("sample_id") is not None
    }
    labels = dict(label_by_task or {})
    samples: list[dict[str, Any]] = []
    for index, sample in enumerate(feedback_samples):
        semgrep = sample.get("semgrep") if isinstance(sample.get("semgrep"), Mapping) else {}
        status = semgrep.get("status")
        completed = status == "completed"
        available = status not in (None, "disabled", "unavailable", "unavailable_config")
        audit_sample = audit_list[index] if index < len(audit_list) else None
        sample_id = str(audit_sample.get("sample_id")) if audit_sample and audit_sample.get("sample_id") is not None else None
        record = sast_by_sample.get(sample_id) if sample_id else None
        task_label = labels.get(str(sample.get("task")), str(sample.get("task")))
        samples.append(
            {
                "task": task_label,
                "repeat": sample.get("repeat"),
                "code": sample.get("code"),
                "verdict": sample.get("verdict"),
                "semgrep": {
                    "status": status,
                    "available": available,
                    "completed": completed,
                    # Not-detected is only reported when the scan completed;
                    # otherwise the outcome is unknown, never "not detected".
                    "detected": semgrep.get("detected") if completed else None,
                    "reason": semgrep.get("reason"),
                    "line_evidence": _alerts_from(record),
                },
            }
        )
    metrics = {}
    metrics_source = feedback.get("metrics")
    if isinstance(metrics_source, Mapping):
        for name, metric in metrics_source.items():
            if not isinstance(metric, Mapping):
                continue
            metrics[name] = {
                "value": metric.get("value"),
                "defined": metric.get("defined"),
                "reason": metric.get("reason"),
                "numerator": metric.get("numerator"),
                "denominator": metric.get("denominator"),
                "k": metric.get("k"),
            }
    projection = {
        "projection_version": PROJECTION_VERSION,
        "candidate_kind": feedback.get("candidate_kind"),
        "samples": samples,
        "metrics": metrics,
        "counts": dict(feedback.get("counts") or {}),
    }
    return projection


# --------------------------------------------------------------------------- #
# Fixed input-material assembly
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MethodInputs:
    """The fixed material the method's system block needs, plus audit hashes."""

    examples: tuple[dict[str, Any], ...]
    semgrep_rule_id: str
    semgrep_rule_text: str
    current_template_text: str
    current_template_sha256: str
    system_prefix: str
    prior: str
    output_format: str

    def audit(self) -> dict[str, Any]:
        return {
            "projection_version": PROJECTION_VERSION,
            "template_content_sha256": self.current_template_sha256,
            "semgrep_rule_sha256": sha256_text(self.semgrep_rule_text),
            "example_task_ids": [example["task_id"] for example in self.examples],
            "example_record_sha256": {
                example["task_id"]: example["record_sha256"] for example in self.examples
            },
            "material_sha256": self.material_sha256(),
        }

    def material_sha256(self) -> str:
        import json

        return sha256_bytes(
            json.dumps(
                {
                    "examples": [
                        {
                            "task_id": example["task_id"],
                            "test": example["test"],
                            "code_prompt": example["code_prompt"],
                            "entry_point": example["entry_point"],
                        }
                        for example in self.examples
                    ],
                    "rule": self.semgrep_rule_text,
                    "template": self.current_template_text,
                    "system_prefix": self.system_prefix,
                    "prior": self.prior,
                    "output_format": self.output_format,
                },
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        )


def _resolve_rule_file(assets_root: Path, rule_id: str) -> Path:
    rules_dir = assets_root / "third_party" / "semgrep"
    if not rules_dir.is_dir():
        raise ProjectionError(f"Semgrep rules directory not found: {rules_dir}")
    candidate = resolve_within(rules_dir, f"{rule_id}.yml")
    if candidate.is_file() and rule_id in semgrep_rule_ids(rules_dir):
        return candidate
    # Fall back to scanning the declaring files for the rule id.
    for path in sorted(rules_dir.glob("*.yml")):
        try:
            if rule_id in semgrep_rule_ids(path.parent):
                return path
        except Exception:  # noqa: BLE001 - resolution is best effort
            continue
    raise ProjectionError(f"Semgrep rule {rule_id!r} not found under {rules_dir}")


def assemble_method_inputs(
    *,
    assets_root: Path | str,
    snapshot: TemplateSnapshot,
    example_task_ids: Sequence[str],
    system_prefix: str,
    prior: str,
    output_format: str,
) -> MethodInputs:
    """Assemble the four example tests/prefixes/entries, rule text and template.

    The task ids are only used to *load* trusted assets; they are recorded on the
    audit side and excluded from the model-visible material.
    """

    root = Path(assets_root)
    specs, _config_path, taxonomy = load_specs(root)
    spec = specs.get(snapshot.combination_id)
    if spec is None:
        raise ProjectionError(f"unknown combination {snapshot.combination_id!r}")
    loaded = load_tasks(spec, root, taxonomy)
    by_id = loaded.by_id()

    examples: list[dict[str, Any]] = []
    for index, task_id in enumerate(example_task_ids):
        record = by_id.get(str(task_id))
        if record is None:
            raise ProjectionError(f"example task {task_id!r} not found in the prepared task set")
        examples.append(
            {
                "task_id": str(task_id),
                "label": f"\u793a\u4f8b {index + 1}",
                "test": record.test,
                "code_prompt": record.code_prompt,
                "entry_point": record.entry_point,
                "record_sha256": record.source.record_sha256,
            }
        )

    rules = semgrep_target_rules(snapshot.combination_id)
    if not rules:
        raise ProjectionError(f"no Semgrep target rule for {snapshot.combination_id!r}")
    rule_id = rules[0]
    rule_path = _resolve_rule_file(root, rule_id)
    rule_text = rule_path.read_text(encoding="utf-8")

    template_text = render_example_blocks(snapshot.examples)
    return MethodInputs(
        examples=tuple(examples),
        semgrep_rule_id=rule_id,
        semgrep_rule_text=rule_text,
        current_template_text=template_text,
        current_template_sha256=sha256_text(template_text),
        system_prefix=system_prefix,
        prior=prior,
        output_format=output_format,
    )


def render_system_block(materials: MethodInputs) -> str:
    """Deterministically render the fixed system block from assembled material."""

    lines: list[str] = []
    if materials.system_prefix:
        lines += [materials.system_prefix, ""]
    if materials.prior:
        lines += ["## \u6982\u62ec\u6027\u53d8\u5f02\u5148\u9a8c", materials.prior, ""]
    lines += ["## \u56db\u4e2a\u793a\u4f8b\u6d4b\u8bd5\u7528\u4f8b\uff08\u529f\u80fd\u7ea6\u675f\uff09"]
    for example in materials.examples:
        lines += [
            f"### {example['label']}",
            f"code_prompt: {example['code_prompt']}",
            f"entry_point: {example['entry_point']}",
            "test:",
            example["test"],
            "",
        ]
    lines += [
        "## \u76ee\u6807 Semgrep \u89c4\u5219\u6e90\u6587\u672c",
        "```yaml",
        materials.semgrep_rule_text.rstrip("\n"),
        "```",
        "",
    ]
    if materials.output_format:
        lines += ["## \u8f93\u51fa\u683c\u5f0f", materials.output_format, ""]
    return "\n".join(lines).rstrip("\n")


def render_current_template_request(materials: MethodInputs, target: str) -> str:
    """Render the current-request user message with the full current template."""

    lines = ["## \u5f53\u524d\u6a21\u677f\u5168\u6587", materials.current_template_text, ""]
    if target:
        lines += ["## \u672c\u6b21\u76ee\u6807", target]
    return "\n".join(lines).rstrip("\n")


__all__ = [
    "AUDIT_TOKENS",
    "MethodInputs",
    "PROJECTION_VERSION",
    "ProjectionError",
    "assemble_method_inputs",
    "assert_no_audit_fields",
    "find_audit_tokens",
    "project_example_facts",
    "project_training_facts",
    "render_current_template_request",
    "render_system_block",
]
