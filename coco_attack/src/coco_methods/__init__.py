"""CoCo-Attack research methods, separate from the common service package.

The common ``coco_attack.iteration`` package provides execution facts; this
package owns the research rules.  Each method lives in its own subpackage;
the top-level exports provide the single-candidate A/B entry points.
"""

from .preflight import PREFLIGHT_SCHEMA_VERSION, build_preflight_report
from .single_candidate_ab import (
    METHOD_PROTOCOL_VERSION,
    METHOD_SCHEMA_VERSION,
    GateResult,
    MethodConfig,
    MethodError,
    MethodInterrupted,
    MethodRun,
    MockGateChecker,
    MockTraining,
    MutatorRole,
    ScriptedMutator,
    VictimRole,
    dmx_mutator_source_factory,
    evaluate_example_gate,
    load_method_config,
    mutator_cache_configurer,
    mutator_role_config,
    run_method,
)

__all__ = [
    "METHOD_PROTOCOL_VERSION",
    "METHOD_SCHEMA_VERSION",
    "PREFLIGHT_SCHEMA_VERSION",
    "GateResult",
    "MethodConfig",
    "MethodError",
    "MethodInterrupted",
    "MethodRun",
    "MockGateChecker",
    "MockTraining",
    "MutatorRole",
    "ScriptedMutator",
    "VictimRole",
    "build_preflight_report",
    "dmx_mutator_source_factory",
    "evaluate_example_gate",
    "load_method_config",
    "mutator_cache_configurer",
    "mutator_role_config",
    "run_method",
]
