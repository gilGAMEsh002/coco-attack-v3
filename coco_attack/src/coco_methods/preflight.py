"""Top-level entry point for the single-candidate A/B method preflight."""

from .single_candidate_ab.preflight import PREFLIGHT_SCHEMA_VERSION, build_preflight_report

__all__ = ["PREFLIGHT_SCHEMA_VERSION", "build_preflight_report"]
