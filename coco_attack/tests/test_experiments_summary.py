"""Baseline coverage/grouped-report checks (phase 03, sub-task 03)."""

from __future__ import annotations

from pathlib import Path

import pytest

from coco_attack.experiments.summary import (
    SUMMARY_SCHEMA_VERSION,
    build_summary,
    report_baseline,
    write_summary,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = REPO_ROOT / "cocota_runs" / "phase03" / "baseline-DeepSeek-V3.2"
BASELINE_AVAILABLE = (BASELINE / "manifest" / "run-manifest.json").is_file()

pytestmark = pytest.mark.skipif(
    not BASELINE_AVAILABLE, reason="completed baseline artifacts not present"
)


def test_summary_covers_full_baseline() -> None:
    summary = build_summary(BASELINE)
    assert summary["schema_version"] == SUMMARY_SCHEMA_VERSION
    coverage = summary["coverage"]
    assert coverage["units_total"] == 24
    assert coverage["units_complete"] == 24
    assert coverage["expected_sample_total"] == 1962
    assert coverage["actual_sample_total"] == 1962
    assert coverage["missing_sample_units"] == []
    assert coverage["extra_sample_units"] == []
    assert summary["gaps"] == []
    # victim request count matches the 01 §4.2 baseline exactly
    assert summary["cost"]["victim_requests"] == 1962
    assert summary["cost"]["victim_request_difference"] == 0
    # cwe078 produces 12 derived search/holdout views from 6 whole-set units
    assert len(summary["matrix"]["derived_views"]) == 12
    assert summary["declarations"]["derived_views_link_to_whole_set"] is True
    assert summary["declarations"]["whole_set_results_not_labelled_holdout"] is True


def test_summary_distinguishes_three_no_value_states() -> None:
    summary = build_summary(BASELINE)
    layer_states = summary["distributions"]["layer_states"]
    # dynamic/realism are configured but disabled: that must not be "not_covered"
    assert layer_states["dynamic"] == {"configured_disabled": 24}
    assert layer_states["realism"] == {"configured_disabled": 24}
    # pass@k undefined for repeats=1 units (n<k)
    assert summary["applicability"]["pass_k_undefined"]
    assert all(
        item["reason"] for item in summary["applicability"]["pass_k_undefined"]
    )
    # functional metric undefined must carry a reason, never a fabricated value
    for unit in summary["coverage"]["units"]:
        if not unit["functional_available"]:
            assert unit["functional_reason"]


def test_summary_does_not_present_whole_set_as_holdout() -> None:
    summary = build_summary(BASELINE)
    for cell in summary["matrix"]["whole_set_cells"]:
        assert cell["split_mode"] == "whole-set"
    for row in summary["matrix"]["derived_views"]:
        assert row["split_mode"] in ("search", "holdout")
        assert row["derived_from"]


def test_report_baseline_writes_outputs_and_returns_zero(tmp_path: Path) -> None:
    # write_summary into a temp root: exercised without touching the real reports
    summary = build_summary(BASELINE)
    outputs = write_summary(tmp_path, summary)
    for key in ("report_json", "report_markdown", "coverage_check"):
        assert Path(outputs[key]).is_file()
    # the real command rebuilds the index and reports into the baseline root
    assert report_baseline(BASELINE) == 0
    assert (BASELINE / "index" / "baseline_index.json").is_file()
    assert (BASELINE / "reports" / "baseline_report.md").is_file()
