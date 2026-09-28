"""Compatibility forward for the single-candidate A/B method preflight.

The implementation moved into the :mod:`coco_attack.method.single_candidate_ab`
package (``single_candidate_ab/preflight.py``).  This module keeps the existing
import path ``coco_attack.method.preflight`` and the CLI working unchanged.
"""

from .single_candidate_ab.preflight import PREFLIGHT_SCHEMA_VERSION, build_preflight_report

__all__ = ["PREFLIGHT_SCHEMA_VERSION", "build_preflight_report"]
