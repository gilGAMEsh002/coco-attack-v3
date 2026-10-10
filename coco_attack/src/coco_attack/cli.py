"""Command-line entry point for the CoCo-Attack rebuild.

Importing this module must not initialise DSPy, caches or secrets. Only the
subcommand actually selected performs work.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Mapping

from .assets.artifacts import assert_fresh_dir, read_json, write_json_atomic
from .assets.audit import run_audit
from .assets.paths import PathResolutionError, assert_assets_output_separation
from .data.combination import legacy_alias_for, load_combination_specs
from .data.contracts import DataContractError
from .data.prepare import prepare_data
from .data.snapshot import load_prepared_data
from .evaluation.calibration import CalibrationInputError, calibrate_references
from .evaluation.contracts import EvaluationConfig
from .evaluation.history import HistoryInputError, compare_history
from .evaluation.functional_cache import FunctionalCacheError
from .evaluation.run_functional import (
    FunctionalInputError,
    run_check_functional,
    run_evaluate_functional,
    run_resume_functional,
)
from .evaluation.run_cleaning import clean_generations
from .evaluation.pipeline import (
    PipelineConfigError,
    check_pipeline,
    report_pipeline,
    resume_pipeline,
    run_pipeline,
)
from .evaluation.run_other import (
    load_evaluators_config,
    run_check_evaluators,
    run_evaluate_other,
    run_resume_other,
)
from .evaluation.run_static import EvaluationInputError, evaluate_static
from .experiments.baseline import check_baseline, prepare_baseline
from .experiments.orchestrate import run_baseline, status_baseline
from .experiments.summary import report_baseline
from .execution.contracts import ExecutionConfigError
from .execution.preflight import (
    run_check_execution,
    run_recover_executions,
    run_verify_isolation,
)
from .generation.contracts import GenerationContractError
from .generation.service import (
    run_check_generation,
    run_generate,
    run_resume_generation,
)
from .iteration.action_demo import DemoConfig, run_offline_demo
from .iteration.code_check import (
    CodeCheckInputError,
    ExampleCheckRequest,
    load_fewshot_example,
    run_example_code_check,
)
from .iteration.poison_materialize import (
    DEFAULT_POISON_FORM,
    PoisonMaterializeError,
    materialize_poisoned,
    verify_poisoned_inputs,
)
from .iteration.message_export import MessageExportError, export_mutator_messages
from .iteration.template_snapshot import (
    PatchPolicy,
    TemplateSnapshot,
    TemplateSnapshotError,
    apply_patch,
    read_snapshot,
    snapshot_from_clean,
    write_snapshot,
)
from .iteration.training_loop import (
    TrainingLoopError,
    load_training_loop_config,
    run_training_loop,
)
from coco_methods.preflight import build_preflight_report
from coco_methods.single_candidate_ab import (
    MockGateChecker,
    MockTraining,
    MethodError,
    MethodInterrupted,
    ScriptedMutator,
    dmx_mutator_source_factory,
    load_method_config,
    mutator_cache_configurer,
    run_method,
)
from .prompts.markdown import CLEAN_FORMS
from .prompts.materialize import (
    PromptMaterializeError,
    materialize_combination,
    task_id_to_prompt_filename,
)

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_USAGE = 2
EXIT_STOPPED = 3
EXIT_PAUSED = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coco-attack",
        description=(
            "CoCo-Attack benchmark rebuild tooling. Domain foundation commands are "
            "read-only with respect to the asset tree."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit-assets",
        help="read-only inventory and health check of rebuild assets",
        description=(
            "Scan the routed datasets, selection records, clean prompt assets, "
            "static oracle files and historical runs; write a manifest, environment "
            "report, issues list and human-readable report to --output-dir."
        ),
    )
    audit.add_argument("--repo-dir", required=True, help="DSPy repository root (for version fingerprint)")
    audit.add_argument("--assets-dir", required=True, help="read-only asset root (cocota_data_eval_result)")
    audit.add_argument("--output-dir", required=True, help="fresh directory for audit outputs")

    prepare = subparsers.add_parser(
        "prepare-data",
        help="strictly load tasks, verify selections and build deterministic splits",
        description=(
            "Validate standard tasks, example/evaluation selections and the "
            "deterministic split for the requested combinations, then write "
            "tasks.jsonl, selection.json, split.json, manifest.json and REPORT.md "
            "to a fresh --output-dir."
        ),
    )
    prepare.add_argument("--repo-dir", required=True, help="DSPy repository root (for version fingerprint)")
    prepare.add_argument("--assets-dir", required=True, help="read-only asset root (cocota_data_eval_result)")
    prepare.add_argument("--output-dir", required=True, help="fresh directory for prepared data")
    prepare.add_argument("--split-config", required=True, help="path to configs/splits.json")
    prepare.add_argument(
        "--combination",
        action="append",
        required=True,
        help="full combination id (repeatable) or the single value 'all'",
    )

    materialize = subparsers.add_parser(
        "materialize-prompts",
        help="materialize the clean prompt experiment three-part sets",
    )
    materialize.add_argument("--repo-dir", required=True)
    materialize.add_argument("--assets-dir", required=True, help="read-only asset root")
    materialize.add_argument("--data-dir", required=True, help="prepare-data output directory")
    materialize.add_argument("--combination", required=True, help="full combination id")
    materialize.add_argument("--oracle-id", required=True, help="explicit oracle id")
    materialize.add_argument(
        "--form", required=True, choices=[*CLEAN_FORMS, "all"], help="clean form or all"
    )
    materialize.add_argument("--output-dir", required=True, help="fresh output directory")

    cleaning = subparsers.add_parser(
        "clean-generations",
        help="extract and complete code from final generation records",
    )
    cleaning.add_argument("--data-dir", required=True, help="prepare-data output directory")
    cleaning.add_argument("--input-jsonl", required=True, help="final generation records")
    cleaning.add_argument("--combination", required=True, help="full combination id")
    cleaning.add_argument("--oracle-id", required=True, help="explicit oracle id")
    cleaning.add_argument("--output-dir", required=True, help="fresh output directory")

    static = subparsers.add_parser(
        "evaluate-static",
        help="route cleaned code to the reused static oracle and compute metrics",
    )
    static.add_argument("--assets-dir", required=True, help="read-only asset root")
    static.add_argument("--data-dir", required=True, help="prepare-data output directory")
    static.add_argument("--cleaned-dir", required=True, help="clean-generations output directory")
    static.add_argument("--combination", required=True, help="full combination id")
    static.add_argument("--oracle-id", required=True, help="explicit oracle id")
    static.add_argument("--config", required=True, help="evaluation config JSON")
    static.add_argument("--output-dir", required=True, help="fresh output directory")

    calibration = subparsers.add_parser(
        "calibrate-references",
        help="recompute reference-code verdicts for all 9 combinations",
    )
    calibration.add_argument("--assets-dir", required=True)
    calibration.add_argument("--data-dir", required=True)
    calibration.add_argument("--config", required=True, help="calibration config JSON")
    calibration.add_argument("--output-dir", required=True)

    history = subparsers.add_parser(
        "compare-history",
        help="recompute and compare a fixed list of historical runs",
    )
    history.add_argument("--assets-dir", required=True)
    history.add_argument("--data-dir", required=True)
    history.add_argument("--config", required=True, help="history comparison config JSON")
    history.add_argument("--output-dir", required=True)

    check_execution = subparsers.add_parser(
        "check-execution",
        help="verify Docker, image, dependency lock and resource preconditions",
        description=(
            "Trusted-operator check of the Docker execution environment. Never executes "
            "generated code; writes dependency_inventory.json, image_manifest.json, "
            "execution_profile.json, manifest.json and REPORT.md."
        ),
    )
    check_execution.add_argument("--config", required=True, help="execution profile JSON")
    check_execution.add_argument("--audit-dir", required=True, help="stage-01 audit directory")
    check_execution.add_argument("--output-dir", required=True, help="fresh output directory")

    verify_isolation = subparsers.add_parser(
        "verify-isolation",
        help="run the fixed isolation probes and write AC-01 evidence",
        description=(
            "Run the versioned, human-written probes through the production execution "
            "backend and write isolation_checks.json, manifest.json and REPORT.md."
        ),
    )
    verify_isolation.add_argument("--config", required=True, help="execution profile JSON")
    verify_isolation.add_argument("--audit-dir", required=True, help="stage-01 audit directory")
    verify_isolation.add_argument("--output-dir", required=True, help="fresh output directory")

    recover_executions = subparsers.add_parser(
        "recover-executions",
        help="reconcile leftover containers owned by an existing execution run",
        description=(
            "Stop/remove containers labelled for the run bound by its manifest and update "
            "the attempt records. Never prunes unrelated containers."
        ),
    )
    recover_executions.add_argument("--config", required=True, help="execution profile JSON")
    recover_executions.add_argument("--run-dir", required=True, help="existing execution run directory")

    check_generation = subparsers.add_parser(
        "check-generation",
        help="validate generation config, tasks and materialized prompts without calling a model",
    )
    check_generation.add_argument("--config", required=True, help="generation config JSON")
    check_generation.add_argument("--data-dir", required=True, help="prepare-data output directory")
    check_generation.add_argument("--prompts-dir", required=True, help="materialize-prompts output directory")
    check_generation.add_argument("--output-dir", required=True, help="fresh output directory")

    generate = subparsers.add_parser(
        "generate",
        help="run generation over the sample manifest (mock or dmx source)",
    )
    generate.add_argument("--config", required=True, help="generation config JSON")
    generate.add_argument("--data-dir", required=True, help="prepare-data output directory")
    generate.add_argument("--prompts-dir", required=True, help="materialize-prompts output directory")
    generate.add_argument("--output-dir", required=True, help="fresh run directory")
    generate.add_argument("--repo-dir", default=None, help="repo root holding .env (required for dmx)")

    resume_generation = subparsers.add_parser(
        "resume-generation",
        help="resume an existing generation run from its ledger",
    )
    resume_generation.add_argument("--run-dir", required=True, help="existing generation run directory")
    resume_generation.add_argument("--repo-dir", default=None, help="repo root holding .env (required for dmx)")


    check_functional = subparsers.add_parser(
        "check-functional",
        help="validate functional input join and tests without executing candidates",
    )
    check_functional.add_argument("--config", required=True, help="functional config JSON")
    check_functional.add_argument("--data-dir", required=True, help="prepare-data output directory")
    check_functional.add_argument("--generation-run", required=True, help="generation run directory")
    check_functional.add_argument("--cleaned-dir", required=True, help="clean-generations output directory")
    check_functional.add_argument("--execution-config", required=True, help="execution profile JSON")
    check_functional.add_argument("--output-dir", required=True, help="fresh output directory")

    evaluate_functional = subparsers.add_parser(
        "evaluate-functional",
        help="run functional tests in the isolation container with per-sample caching",
    )
    evaluate_functional.add_argument("--config", required=True, help="functional config JSON")
    evaluate_functional.add_argument("--data-dir", required=True, help="prepare-data output directory")
    evaluate_functional.add_argument("--generation-run", required=True, help="generation run directory")
    evaluate_functional.add_argument("--cleaned-dir", required=True, help="clean-generations output directory")
    evaluate_functional.add_argument("--execution-config", required=True, help="execution profile JSON")
    evaluate_functional.add_argument("--cache-dir", required=True, help="persistent functional cache root")
    evaluate_functional.add_argument("--ledger-path", default=None, help="ledger path (defaults to run dir)")
    evaluate_functional.add_argument("--output-dir", required=True, help="fresh evaluation run directory")

    resume_functional = subparsers.add_parser(
        "resume-functional",
        help="resume a functional evaluation run from its persisted references",
    )
    resume_functional.add_argument("--run-dir", required=True, help="existing functional evaluation run")

    check_evaluators = subparsers.add_parser(
        "check-evaluators",
        help="check other-evaluator inputs, coverage and tool availability",
    )
    check_evaluators.add_argument("--config", required=True, help="evaluators config JSON")
    check_evaluators.add_argument("--data-dir", required=True)
    check_evaluators.add_argument("--generation-run", required=True)
    check_evaluators.add_argument("--cleaned-dir", required=True)
    check_evaluators.add_argument("--output-dir", required=True)

    evaluate_other = subparsers.add_parser(
        "evaluate-other",
        help="run SAST/judge and record dynamic/realism coverage for the shared final_code",
    )
    evaluate_other.add_argument("--config", required=True)
    evaluate_other.add_argument("--data-dir", required=True)
    evaluate_other.add_argument("--generation-run", required=True)
    evaluate_other.add_argument("--cleaned-dir", required=True)
    evaluate_other.add_argument("--execution-config", required=True, help="reserved for dynamic/realism container wiring")
    evaluate_other.add_argument("--ledger-path", default=None)
    evaluate_other.add_argument("--output-dir", required=True)

    resume_other = subparsers.add_parser(
        "resume-other",
        help="resume an other-evaluator run from its persisted references",
    )
    resume_other.add_argument("--run-dir", required=True)

    check_pipeline = subparsers.add_parser(
        "check-pipeline",
        help="validate a unified pipeline config, inputs and sample subset",
    )
    check_pipeline.add_argument("--config", required=True)
    check_pipeline.add_argument("--output-dir", required=True)

    run_pipeline_cmd = subparsers.add_parser(
        "run-pipeline",
        help="run the unified generation->cleaning->static->core->evaluation->report pipeline",
    )
    run_pipeline_cmd.add_argument("--config", required=True)
    run_pipeline_cmd.add_argument("--output-dir", required=True, help="fresh run directory")
    run_pipeline_cmd.add_argument(
        "--accept-existing-generation", action="store_true",
        help="evaluate the generation_run declared in the config instead of generating",
    )

    resume_pipeline_cmd = subparsers.add_parser(
        "resume-pipeline",
        help="resume a pipeline run from its action log",
    )
    resume_pipeline_cmd.add_argument("--run-dir", required=True)

    report_pipeline_cmd = subparsers.add_parser(
        "report-pipeline",
        help="rebuild the report from existing run artifacts (no model/evaluator calls)",
    )
    report_pipeline_cmd.add_argument("--run-dir", required=True)
    report_pipeline_cmd.add_argument("--output-dir", default=None)

    prepare_baseline_cmd = subparsers.add_parser(
        "prepare-baseline",
        help="build a fresh clean-baseline root: inputs, manifest and configs",
        description=(
            "Read a baseline matrix config, snapshot the fixed data/prompt inputs, "
            "expand the 24-unit/24-run whole-set manifest, write one pipeline config per "
            "run. The clean baseline has no holdout and no lock. Never calls a model or a "
            "DMX API."
        ),
    )
    prepare_baseline_cmd.add_argument("--matrix-config", required=True, help="baseline matrix config JSON")
    prepare_baseline_cmd.add_argument("--output-dir", required=True, help="fresh baseline root directory")

    check_baseline_cmd = subparsers.add_parser(
        "check-baseline",
        help="re-verify a prepared baseline root and write a startup-check report",
        description=(
            "Re-verify input hashes, per-run pipeline configs, the version freeze, Docker/"
            "image identity, DMX key presence and evaluator tool availability. Never starts "
            "containers beyond docker info / image inspect and never calls a model."
        ),
    )
    check_baseline_cmd.add_argument("--baseline-root", required=True, help="prepared baseline root directory")

    run_baseline_cmd = subparsers.add_parser(
        "run-baseline",
        help="execute or resume the clean-baseline manifest unit by unit",
        description=(
            "Re-run the check-baseline startup gate, verify the version freeze, then "
            "walk the run manifest in order.  Each not-yet-complete unit is executed by "
            "an independent python -m coco_attack run-pipeline subprocess (or "
            "resume-pipeline when its run directory already holds state); the pipeline's "
            "self-reported report state is written back to the manifest after every unit. "
            "Never marks a unit complete unless its report is complete."
        ),
    )
    run_baseline_cmd.add_argument("--baseline-root", required=True, help="prepared baseline root directory")
    run_baseline_cmd.add_argument(
        "--limit", type=int, default=None, help="execute at most N remaining units"
    )
    run_baseline_cmd.add_argument(
        "--only",
        action="append",
        default=None,
        help="restrict execution to this unit id (repeatable)",
    )

    status_baseline_cmd = subparsers.add_parser(
        "status-baseline",
        help="summarize per-unit status and cost without starting a run",
        description=(
            "Read the run manifest and each run's report artifacts; print per-unit status, "
            "known/unknown cost totals, request counts and cache-reuse sources, and write "
            "manifest/status.json.  Never calls a model or starts a pipeline."
        ),
    )
    status_baseline_cmd.add_argument("--baseline-root", required=True, help="prepared baseline root directory")

    report_baseline_cmd = subparsers.add_parser(
        "report-baseline",
        help="build the baseline index and grouped report from completed run artifacts",
        description=(
            "Read the completed run artifacts, build the baseline-index-v1 and the "
            "coverage/grouped report, and write index/ and reports/ under the baseline "
            "root.  Offline: never calls a model or an evaluator."
        ),
    )
    report_baseline_cmd.add_argument("--baseline-root", required=True, help="completed baseline root directory")

    check_example = subparsers.add_parser(
        "check-example-code",
        help="directly check one example task+code and report per-layer facts",
        description=(
            "Run the functional, static-oracle and Semgrep layers for one explicit "
            "example task and code, and write request.json, check_result.json and "
            "REPORT.md. This is a generic fact service: it returns independent layer "
            "facts, never a combined gate verdict, and never adds the example task to "
            "evaluation_ids/search_ids. Exit 0 means a structured result was produced, "
            "not that any research condition passed."
        ),
    )
    check_example.add_argument("--assets-dir", required=True, help="read-only asset root (cocota_data_eval_result)")
    check_example.add_argument("--combination", required=True, help="full combination id")
    check_example.add_argument("--task-id", required=True, help="task id inside the combination")
    check_example.add_argument("--action-id", required=True, help="audit action id for this check")
    check_example.add_argument("--output-dir", required=True, help="output directory for the check")
    check_example.add_argument("--code-source", required=True, help="audit description of the code origin")
    check_source = check_example.add_mutually_exclusive_group(required=True)
    check_source.add_argument("--code-file", default=None, help="path to a file holding the code bytes")
    check_source.add_argument(
        "--fewshot-experiment",
        default=None,
        help="clean experiment name whose few-shot example supplies the code",
    )
    check_example.add_argument(
        "--example-index",
        type=int,
        default=None,
        help="index into the experiment's fewshot.json (requires --fewshot-experiment)",
    )
    check_example.add_argument(
        "--code-input-mode",
        default="example_body",
        choices=["example_body", "final_code"],
        help="assemble the code under the registry code_prompt, or treat it as final code",
    )
    check_example.add_argument("--execution-config", default=None, help="execution profile JSON (functional layer)")
    check_example.add_argument("--semgrep-config", default=None, help="directory holding the Semgrep rule files")
    check_example.add_argument(
        "--semgrep-timeout-seconds",
        type=float,
        default=60.0,
        help="per-scan Semgrep timeout; raise it for a cold rule cache",
    )
    check_example.add_argument(
        "--candidate-timeout-seconds",
        type=float,
        default=20.0,
        help="candidate timeout handed to the functional harness",
    )
    check_example.add_argument("--stage", default="search", help="execution namespace (search/holdout)")
    check_example.add_argument("--no-functional", action="store_true", help="skip the functional container layer")
    check_example.add_argument("--no-static", action="store_true", help="skip the static oracle layer")
    check_example.add_argument("--no-semgrep", action="store_true", help="skip the Semgrep layer")

    materialize_poisoned_cmd = subparsers.add_parser(
        "materialize-poisoned",
        help="render a poisoned few-shot prompt tree from a template snapshot",
        description=(
            "Build a clean template snapshot (optionally patched), render the "
            "poisoned few-shot prompt tree and (unless --skip-verify) re-read it "
            "with the real generation input loader. Exit 0 means a structured "
            "poisoned tree was produced, not that any research gate passed."
        ),
    )
    materialize_poisoned_cmd.add_argument("--assets-dir", required=True, help="read-only asset root")
    materialize_poisoned_cmd.add_argument("--data-dir", required=True, help="prepare-data output directory")
    materialize_poisoned_cmd.add_argument("--combination", required=True, help="full combination id")
    materialize_poisoned_cmd.add_argument(
        "--task-id", action="append", required=True, help="task id to materialize (repeatable)"
    )
    materialize_poisoned_cmd.add_argument("--output-dir", required=True, help="output directory for the poisoned tree")
    materialize_poisoned_cmd.add_argument(
        "--experiment", default=None, help="clean few-shot experiment (default: registry clean_assets)"
    )
    materialize_poisoned_cmd.add_argument("--snapshot-store", default=None, help="optional content-addressed snapshot store")
    materialize_poisoned_cmd.add_argument(
        "--input-snapshot",
        default=None,
        help="read an existing snapshot version dir/JSON instead of building c0 from clean "
        "(enables chaining patches on the current candidate)",
    )
    materialize_poisoned_cmd.add_argument("--patch-file", default=None, help="optional JSON patch (a list or {'examples': [...]})")
    materialize_poisoned_cmd.add_argument(
        "--allow-example", action="append", type=int, default=None,
        help="1-based example numbers the patch may touch (default: all but example 1)",
    )
    materialize_poisoned_cmd.add_argument(
        "--allow-field", action="append", choices=["code", "cot"], default=None,
        help="patch fields allowed (default: code)",
    )
    materialize_poisoned_cmd.add_argument(
        "--form", default=None, help=f"poisoned prompt form (default: {DEFAULT_POISON_FORM})"
    )
    materialize_poisoned_cmd.add_argument(
        "--trigger", default=None, help="trigger token to inject (default: cf)"
    )
    materialize_poisoned_cmd.add_argument(
        "--injection-position", default=None,
        help="injection position (default: first_sentence_end; only supported value)",
    )
    materialize_poisoned_cmd.add_argument(
        "--mode", default=None, help="attack mode label (default: instruction_injection)"
    )
    materialize_poisoned_cmd.add_argument("--action-id", default=None, help="audit action id for the snapshot store")
    materialize_poisoned_cmd.add_argument("--skip-verify", action="store_true", help="skip the generation-input read check")

    training_loop = subparsers.add_parser(
        "run-training-loop",
        help="run the single-candidate mock training loop (materialize->generate->clean->static->semgrep->feedback)",
        description=(
            "Wire one explicit template snapshot through the existing generation, "
            "cleaning, static and Semgrep services and write feedback plus a "
            "read-only clean-baseline slice. No candidate pool or A/B gate. Exit 0 "
            "means a mock wiring closure completed, not that a research condition "
            "passed."
        ),
    )
    training_loop.add_argument("--config", required=True, help="training loop config JSON")
    training_loop.add_argument(
        "--force-rerun",
        action="store_true",
        help="re-run every step even when a complete manifest already exists",
    )

    action_demo = subparsers.add_parser(
        "mutator-action-mock",
        help="offline two-interaction mock showing durable responses, interrupt/resume, patch and history commits",
        description=(
            "Run two ordinary mock mutator interactions through the task-04 action "
            "runtime. The first raw response is made durable, the provider is then "
            "simulated as dead, and resume must reuse the durable response without "
            "calling the provider; the template diff and shared-history unit are "
            "committed exactly once. No real model, Docker or Semgrep is used."
        ),
    )
    action_demo.add_argument("--snapshot", required=True, help="stored template snapshot directory")
    action_demo.add_argument("--run-dir", required=True, help="action run directory")
    action_demo.add_argument("--assets-root", required=True, help="read-only assets root")
    action_demo.add_argument("--snapshot-store", required=True, help="snapshot store root for new template versions")
    action_demo.add_argument("--context-window", type=int, default=32768)
    action_demo.add_argument(
        "--output-reserve",
        type=int,
        default=8192,
        help="tokens reserved for the response; must be >= the per-call max_tokens (8192)",
    )
    action_demo.add_argument("--task-id", action="append", default=None, help="example task id (repeatable)")
    action_demo.add_argument("--report", default=None, help="optional path to write the JSON report")

    method_ab = subparsers.add_parser(
        "run-method-ab",
        help="run/resume the single-candidate A/B method (task 05) with an explicit mock mutator script",
        description=(
            "Compose the task-01..04 services into the current method: initial functional "
            "check, A code gate with accumulated pending examples, one training evaluation, "
            "one-shot B cot edit, shared history and big-iteration state. By default the "
            "external example checks and training are explicit test doubles (--mock-gate / "
            "--mock-training); pass --allow-real-checks/--allow-real-training to use the real "
            "services. No real model is called for source='mock'."
        ),
    )
    method_ab.add_argument("--config", required=True, help="method config JSON")
    method_ab.add_argument(
        "--mutator-source",
        choices=("mock", "dmx"),
        default=None,
        help="mutator role source; defaults to config.mutator.source",
    )
    method_ab.add_argument(
        "--mutator-script",
        default=None,
        help="scripted mock mutator responses: a JSON list or an {action_id: response} object (mock only)",
    )
    method_ab.add_argument("--repo-dir", default=None, help="repo dir for the deferred DMX key loader (dmx mutator only)")
    method_ab.add_argument("--mock-gate", action="store_true", help="use the explicit always-pass mock example check")
    method_ab.add_argument("--mock-training", action="store_true", help="use the explicit mock training runner")
    method_ab.add_argument("--allow-real-checks", action="store_true", help="opt into the real Docker/Semgrep example checks")
    method_ab.add_argument("--allow-real-training", action="store_true", help="opt into the real training loop (does not imply a real mutator)")
    method_ab.add_argument("--resume-paused", action="store_true", help="clear a saved pause and continue")
    method_ab.add_argument("--allow-unknown-retry", action="store_true", help="explicitly retry a paused unknown window")
    method_ab.add_argument("--report", default=None, help="optional path to write the final state JSON")

    preflight = subparsers.add_parser(
        "preflight-method",
        help="offline preflight for the single-candidate A/B method (no model/Docker/Semgrep/key)",
        description=(
            "Read and validate the method configuration, read-only assets and interfaces and "
            "write a reviewable report. It performs no model request, no credential load and no "
            "Docker/Semgrep execution, and does not create a resumable run state."
        ),
    )
    preflight.add_argument("--config", required=True, help="method config JSON")
    preflight.add_argument("--report", default=None, help="optional path to write the preflight JSON report")
    preflight.add_argument("--mock-gate", action="store_true", help="declare that the offline mock example-check double is intended")
    preflight.add_argument("--allow-real-checks", action="store_true", help="declare that real Docker/Semgrep example checks are intended")
    preflight.add_argument("--mock-training", action="store_true", help="declare that the mock training double is intended")
    preflight.add_argument("--allow-real-training", action="store_true", help="declare that the real training loop is intended")

    itl_preflight = subparsers.add_parser(
        "implicit-then-literal-preflight",
        help="offline read-only preflight for the implicit_then_literal method",
        description=(
            "Validate the implicit_then_literal run config, read-only inputs, source/model "
            "identity and container budget. Performs no model request, credential load, Docker/"
            "Semgrep run or candidate execution, and creates no run state."
        ),
    )
    itl_preflight.add_argument("--config", required=True, help="method run config JSON")
    itl_preflight.add_argument("--project-root", default=None, help="explicit root for relative config paths")
    itl_preflight.add_argument("--report", default=None, help="optional path to write the preflight JSON")

    itl_run = subparsers.add_parser(
        "implicit-then-literal-run",
        help="run the implicit_then_literal method from an explicit config",
    )
    itl_run.add_argument("--config", required=True, help="method run config JSON")
    itl_run.add_argument("--project-root", default=None, help="explicit root for relative config paths")
    itl_run.add_argument(
        "--stop-after",
        choices=("baseline_complete", "round_1_complete"),
        default=None,
        help="stop at a resumable checkpoint instead of a failure pause",
    )
    itl_run.add_argument("--doubles-module", default=None, help="optional Python module exposing build_doubles() for offline mock runs")
    itl_run.add_argument("--report", default=None, help="optional path to write the run summary JSON")

    itl_resume = subparsers.add_parser(
        "implicit-then-literal-resume",
        help="resume a stopped or paused implicit_then_literal run",
    )
    itl_resume.add_argument("--run-root", required=True, help="existing run root (contains config.json/state.json)")
    itl_resume.add_argument(
        "--stop-after",
        choices=("baseline_complete", "round_1_complete"),
        default=None,
        help="stop at a resumable checkpoint",
    )
    itl_resume.add_argument("--doubles-module", default=None, help="optional Python module exposing build_doubles() for offline mock runs")
    itl_resume.add_argument(
        "--allow-unknown-retry",
        action="store_true",
        help="explicitly retry an orphan/unknown role-call window instead of pausing (never automatic)",
    )
    itl_resume.add_argument("--report", default=None, help="optional path to write the run summary JSON")

    itl_retry = subparsers.add_parser(
        "implicit-then-literal-retry",
        help="explicit inducer content retry for a paused implicit_then_literal induction",
    )
    itl_retry.add_argument("--run-root", required=True, help="existing run root")
    itl_retry.add_argument("--round", type=int, required=True, help="round index of the paused induction")
    itl_retry.add_argument("--stage", choices=("A", "B"), required=True, help="method stage of the paused induction")
    itl_retry.add_argument("--candidate-id", required=True, help="logical candidate id of the paused induction")
    itl_retry.add_argument("--doubles-module", default=None, help="optional Python module exposing build_doubles() for offline mock runs")
    itl_retry.add_argument(
        "--stop-after",
        choices=("baseline_complete", "round_1_complete"),
        default=None,
        help="stop at a resumable checkpoint after the retry",
    )
    itl_retry.add_argument(
        "--allow-unknown-retry",
        action="store_true",
        help="explicitly retry an orphan/unknown role-call window instead of pausing (never automatic)",
    )
    itl_retry.add_argument("--report", default=None, help="optional path to write the run summary JSON")

    itl_status = subparsers.add_parser(
        "implicit-then-literal-status",
        help="read-only status report for an implicit_then_literal run",
    )
    itl_status.add_argument("--run-root", required=True, help="existing run root")
    itl_status.add_argument("--project-root", default=None, help="explicit root for relative config paths")
    itl_status.add_argument("--report", default=None, help="optional path to write the status JSON")

    export_messages = subparsers.add_parser(
        "export-mutator-messages",
        help="read-only export of mutator role messages to HTML + JSONL + manifest",
        description=(
            "Reconstruct what was sent to and received from the mutator role for an existing "
            "run directory and write a fresh export directory (index.html, messages.jsonl, "
            "manifest.json). This is a pure reader: it never calls a recovery function, model, "
            "credential loader, Docker or Semgrep, and never writes into the run directory."
        ),
    )
    export_messages.add_argument("--run-dir", required=True, help="existing method run directory (contains actions.jsonl)")
    export_messages.add_argument("--output-dir", required=True, help="new, non-overlapping directory to write the export")
    return parser


def _resolve_dir(raw: str, label: str) -> Path:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ValueError(f"cannot resolve {label}: {raw!r}: {error}") from error
    if not path.is_dir():
        raise ValueError(f"{label} is not an existing directory: {path}")
    return path


def _resolve_file(raw: str, label: str) -> Path:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ValueError(f"cannot resolve {label}: {raw!r}: {error}") from error
    if not path.is_file():
        raise ValueError(f"{label} is not an existing file: {path}")
    return path


def _cmd_audit_assets(args: argparse.Namespace) -> int:
    try:
        repo_dir = _resolve_dir(args.repo_dir, "--repo-dir")
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    if not (repo_dir / "dspy").is_dir():
        print(
            f"error: --repo-dir does not look like the DSPy repository root "
            f"(missing dspy/ package): {repo_dir}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        assert_assets_output_separation(assets_dir, output_dir)
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    if output_dir.exists() and not output_dir.is_dir():
        print(f"error: --output-dir exists and is not a directory: {output_dir}", file=sys.stderr)
        return EXIT_USAGE

    try:
        return run_audit(repo_dir, assets_dir, output_dir)
    except (OSError, ValueError) as error:
        print(f"error: audit failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_prepare_data(args: argparse.Namespace) -> int:
    try:
        repo_dir = _resolve_dir(args.repo_dir, "--repo-dir")
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
        split_config = Path(args.split_config).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    if not (repo_dir / "dspy").is_dir():
        print(
            f"error: --repo-dir does not look like the DSPy repository root "
            f"(missing dspy/ package): {repo_dir}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not split_config.is_file():
        print(f"error: --split-config is not a file: {split_config}", file=sys.stderr)
        return EXIT_USAGE

    try:
        assert_assets_output_separation(assets_dir, output_dir)
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    if output_dir.exists() and not output_dir.is_dir():
        print(f"error: --output-dir exists and is not a directory: {output_dir}", file=sys.stderr)
        return EXIT_USAGE

    try:
        return prepare_data(
            repo_dir,
            assets_dir,
            output_dir,
            split_config,
            list(args.combination),
        )
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except DataContractError as error:
        for issue in error.issues:
            print(f"error [{issue.code}] {issue.detail}", file=sys.stderr)
        usage = bool(error.issues) and all(
            issue.scope in {"cli", "config"} for issue in error.issues
        )
        return EXIT_USAGE if usage else EXIT_BLOCKING
    except (OSError, ValueError) as error:
        print(f"error: prepare-data failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _assert_isolated_output(output_dir: Path, protected: list[Path]) -> None:
    resolved = output_dir.resolve()
    for directory in protected:
        directory_resolved = directory.resolve()
        if resolved == directory_resolved or resolved.is_relative_to(directory_resolved):
            raise PathResolutionError(
                f"output directory must not be inside an input directory: "
                f"{resolved} (input {directory_resolved})"
            )


def _cmd_materialize_prompts(args: argparse.Namespace) -> int:
    try:
        repo_dir = _resolve_dir(args.repo_dir, "--repo-dir")
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not (repo_dir / "dspy").is_dir():
        print(f"error: --repo-dir is not a DSPy repository root: {repo_dir}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_assets_output_separation(assets_dir, output_dir)
        _assert_isolated_output(output_dir, [assets_dir, data_dir])
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    specs, _config_path, _taxonomy = load_combination_specs(assets_dir)
    spec = specs.get(args.combination)
    if spec is None:
        print(f"error: unknown combination {args.combination!r}", file=sys.stderr)
        return EXIT_USAGE
    if spec.oracle_id != args.oracle_id:
        print(
            f"error: --oracle-id {args.oracle_id!r} does not match routed oracle "
            f"{spec.oracle_id!r} for {args.combination}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if spec.clean_assets is None:
        print(
            f"error: {args.combination} has no clean assets; not covered",
            file=sys.stderr,
        )
        return EXIT_BLOCKING
    forms = list(CLEAN_FORMS) if args.form == "all" else [args.form]

    try:
        prepared = load_prepared_data(data_dir, args.combination)
        assert_fresh_dir(output_dir)
        materialize_combination(
            spec, prepared, assets_dir, forms, output_dir, data_dir
        )
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (PromptMaterializeError, DataContractError) as error:
        print(f"error: materialize-prompts failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    return EXIT_OK


def _cmd_clean_generations(args: argparse.Namespace) -> int:
    try:
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
        input_jsonl = Path(args.input_jsonl).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not input_jsonl.is_file():
        print(f"error: --input-jsonl is not a file: {input_jsonl}", file=sys.stderr)
        return EXIT_USAGE
    try:
        _assert_isolated_output(output_dir, [data_dir, input_jsonl.parent])
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        prepared = load_prepared_data(data_dir, args.combination)
    except DataContractError as error:
        for issue in error.issues:
            print(f"error [{issue.code}] {issue.detail}", file=sys.stderr)
        return EXIT_BLOCKING

    if prepared.oracle_id != args.oracle_id:
        print(
            f"error: --oracle-id {args.oracle_id!r} does not match prepared oracle "
            f"{prepared.oracle_id!r}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    legacy_alias = legacy_alias_for(args.combination)
    try:
        assert_fresh_dir(output_dir)
        return clean_generations(prepared, input_jsonl, output_dir, legacy_alias)
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except DataContractError as error:
        for issue in error.issues:
            print(f"error [{issue.code}] {issue.detail}", file=sys.stderr)
        return EXIT_BLOCKING
    except (OSError, ValueError) as error:
        print(f"error: clean-generations failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_evaluate_static(args: argparse.Namespace) -> int:
    try:
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        cleaned_dir = _resolve_dir(args.cleaned_dir, "--cleaned-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
        config_path = Path(args.config).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not config_path.is_file():
        print(f"error: --config is not a file: {config_path}", file=sys.stderr)
        return EXIT_USAGE
    if not (assets_dir / "oracles").is_dir():
        print(f"error: --assets-dir has no oracles/ directory: {assets_dir}", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = EvaluationConfig.from_json(read_json(config_path))
    except (OSError, ValueError) as error:
        print(f"error: invalid evaluation config: {error}", file=sys.stderr)
        return EXIT_USAGE
    if config.combination_id != args.combination or config.oracle_id != args.oracle_id:
        print(
            "error: --combination/--oracle-id do not match the evaluation config "
            f"({config.combination_id}/{config.oracle_id})",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        assert_assets_output_separation(assets_dir, output_dir)
        _assert_isolated_output(output_dir, [assets_dir, data_dir, cleaned_dir])
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        assert_fresh_dir(output_dir)
        return evaluate_static(assets_dir, data_dir, cleaned_dir, config_path, output_dir)
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except EvaluationInputError as error:
        for issue in error.issues:
            print(f"error [{issue.code}] {issue.detail}", file=sys.stderr)
        return EXIT_BLOCKING
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: evaluate-static failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_reference_or_history(args, func, error_cls, label: str) -> int:
    try:
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
        config_path = Path(args.config).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not config_path.is_file():
        print(f"error: --config is not a file: {config_path}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_assets_output_separation(assets_dir, output_dir)
        _assert_isolated_output(output_dir, [assets_dir, data_dir])
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        assert_fresh_dir(output_dir)
        return func(assets_dir, data_dir, config_path, output_dir)
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except error_cls as error:
        for issue in error.issues:
            print(f"error [{issue.code}] {issue.detail}", file=sys.stderr)
        return EXIT_BLOCKING
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {label} failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_calibrate_references(args: argparse.Namespace) -> int:
    return _cmd_reference_or_history(
        args, calibrate_references, CalibrationInputError, "calibrate-references"
    )


def _cmd_compare_history(args: argparse.Namespace) -> int:
    return _cmd_reference_or_history(
        args, compare_history, HistoryInputError, "compare-history"
    )


def _cmd_check_execution(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        audit_dir = _resolve_dir(args.audit_dir, "--audit-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not (audit_dir / "asset_manifest.json").is_file():
        print(
            f"error: --audit-dir has no asset_manifest.json "
            f"(run audit-assets first): {audit_dir}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_check_execution(config, audit_dir, output_dir)
    except ExecutionConfigError as error:
        print(f"error: invalid execution config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-execution failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_verify_isolation(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        audit_dir = _resolve_dir(args.audit_dir, "--audit-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    if not (audit_dir / "asset_manifest.json").is_file():
        print(
            f"error: --audit-dir has no asset_manifest.json "
            f"(run audit-assets first): {audit_dir}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_verify_isolation(config, audit_dir, output_dir)
    except ExecutionConfigError as error:
        print(f"error: invalid execution config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: verify-isolation failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_recover_executions(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_recover_executions(config, run_dir)
    except ExecutionConfigError as error:
        print(f"error: invalid execution config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: recover-executions failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_generation(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        prompts_dir = _resolve_dir(args.prompts_dir, "--prompts-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_check_generation(
            config, data_dir, prompts_dir, output_dir
        )
    except GenerationContractError as error:
        print(f"error: invalid generation config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-generation failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_generate(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        prompts_dir = _resolve_dir(args.prompts_dir, "--prompts-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
        repo_dir = _resolve_dir(args.repo_dir, "--repo-dir") if args.repo_dir else None
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_generate(
            config,
            data_dir,
            prompts_dir,
            output_dir,
            repo_dir=repo_dir,
        )
    except GenerationContractError as error:
        print(f"error: invalid generation config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: generate failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_resume_generation(args: argparse.Namespace) -> int:
    try:
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
        repo_dir = _resolve_dir(args.repo_dir, "--repo-dir") if args.repo_dir else None
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_resume_generation(run_dir, repo_dir=repo_dir)
    except GenerationContractError as error:
        print(f"error: cannot resume generation: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: resume-generation failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_functional(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        generation_run = _resolve_dir(args.generation_run, "--generation-run")
        cleaned_dir = _resolve_dir(args.cleaned_dir, "--cleaned-dir")
        execution_config = _resolve_file(args.execution_config, "--execution-config")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_check_functional(
            config, data_dir, generation_run, cleaned_dir, execution_config, output_dir,
        )
    except (FunctionalInputError, ExecutionConfigError) as error:
        print(f"error: invalid functional input: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-functional failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_evaluate_functional(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        generation_run = _resolve_dir(args.generation_run, "--generation-run")
        cleaned_dir = _resolve_dir(args.cleaned_dir, "--cleaned-dir")
        execution_config = _resolve_file(args.execution_config, "--execution-config")
        cache_dir = Path(args.cache_dir).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        ledger_path = (
            Path(args.ledger_path).expanduser().resolve() if args.ledger_path else None
        )
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_evaluate_functional(
            config,
            data_dir,
            generation_run,
            cleaned_dir,
            execution_config,
            cache_dir,
            output_dir,
            ledger_path=ledger_path,
        )
    except (FunctionalInputError, ExecutionConfigError, FunctionalCacheError) as error:
        print(f"error: invalid functional input: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: evaluate-functional failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_resume_functional(args: argparse.Namespace) -> int:
    try:
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_resume_functional(run_dir)
    except (FunctionalInputError, ExecutionConfigError, FunctionalCacheError) as error:
        print(f"error: cannot resume functional run: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: resume-functional failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_evaluators(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        generation_run = _resolve_dir(args.generation_run, "--generation-run")
        cleaned_dir = _resolve_dir(args.cleaned_dir, "--cleaned-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_check_evaluators(
            config, data_dir, generation_run, cleaned_dir, output_dir
        )
    except (FunctionalInputError, GenerationContractError) as error:
        print(f"error: invalid evaluator input: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-evaluators failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_evaluate_other(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        generation_run = _resolve_dir(args.generation_run, "--generation-run")
        cleaned_dir = _resolve_dir(args.cleaned_dir, "--cleaned-dir")
        _execution_config = _resolve_file(args.execution_config, "--execution-config")
        output_dir = Path(args.output_dir).expanduser().resolve()
        ledger_path = Path(args.ledger_path).expanduser().resolve() if args.ledger_path else None
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_evaluate_other(
            config,
            data_dir,
            generation_run,
            cleaned_dir,
            ledger_path,
            output_dir,
            execution_config_path=_execution_config,
        )
    except (FunctionalInputError, GenerationContractError) as error:
        print(f"error: invalid evaluator input: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: evaluate-other failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_resume_other(args: argparse.Namespace) -> int:
    try:
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_resume_other(run_dir)
    except (FunctionalInputError, GenerationContractError) as error:
        print(f"error: cannot resume evaluator run: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: resume-other failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_pipeline(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return check_pipeline(config, output_dir)
    except PipelineConfigError as error:
        print(f"error: invalid pipeline config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-pipeline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_run_pipeline(args: argparse.Namespace) -> int:
    try:
        config = _resolve_file(args.config, "--config")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        assert_fresh_dir(output_dir)
    except (FileExistsError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_pipeline(
            config,
            output_dir,
            accept_existing_generation=args.accept_existing_generation,
        )
    except PipelineConfigError as error:
        print(f"error: invalid pipeline config: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: run-pipeline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_resume_pipeline(args: argparse.Namespace) -> int:
    try:
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return resume_pipeline(run_dir)
    except PipelineConfigError as error:
        print(f"error: cannot resume pipeline: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: resume-pipeline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_report_pipeline(args: argparse.Namespace) -> int:
    try:
        run_dir = _resolve_dir(args.run_dir, "--run-dir")
        output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return report_pipeline(run_dir, output_dir)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: report-pipeline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_prepare_baseline(args: argparse.Namespace) -> int:
    try:
        matrix_config = _resolve_file(args.matrix_config, "--matrix-config")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return prepare_baseline(matrix_config, output_dir)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: prepare-baseline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_baseline(args: argparse.Namespace) -> int:
    try:
        baseline_root = _resolve_dir(args.baseline_root, "--baseline-root")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return check_baseline(baseline_root)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-baseline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_run_baseline(args: argparse.Namespace) -> int:
    try:
        baseline_root = _resolve_dir(args.baseline_root, "--baseline-root")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run_baseline(baseline_root, limit=args.limit, only=args.only)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: run-baseline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_status_baseline(args: argparse.Namespace) -> int:
    try:
        baseline_root = _resolve_dir(args.baseline_root, "--baseline-root")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return status_baseline(baseline_root)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: status-baseline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_report_baseline(args: argparse.Namespace) -> int:
    try:
        baseline_root = _resolve_dir(args.baseline_root, "--baseline-root")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return report_baseline(baseline_root)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: report-baseline failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING


def _cmd_check_example_code(args: argparse.Namespace) -> int:
    try:
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    execution_config = (
        Path(args.execution_config).expanduser().resolve() if args.execution_config else None
    )
    if execution_config is not None and not execution_config.is_file():
        print(f"error: --execution-config is not a file: {execution_config}", file=sys.stderr)
        return EXIT_USAGE
    semgrep_config = (
        Path(args.semgrep_config).expanduser().resolve() if args.semgrep_config else None
    )

    code: str
    if args.code_file is not None:
        if args.example_index is not None:
            print(
                "error: --example-index is only valid with --fewshot-experiment",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            code_path = _resolve_file(args.code_file, "--code-file")
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_USAGE
        try:
            code = code_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            print(f"error: cannot read --code-file {code_path}: {error}", file=sys.stderr)
            return EXIT_USAGE
    else:
        if args.example_index is None:
            print(
                "error: --example-index is required with --fewshot-experiment",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            example = load_fewshot_example(
                assets_root=assets_dir,
                combination_id=args.combination,
                experiment=args.fewshot_experiment,
                index=args.example_index,
            )
        except CodeCheckInputError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_USAGE
        code = example.code

    request = ExampleCheckRequest(
        combination_id=args.combination,
        task_id=args.task_id,
        code=code,
        code_source=args.code_source,
        action_id=args.action_id,
        output_dir=output_dir,
        assets_root=assets_dir,
        code_input_mode=args.code_input_mode,
        stage=args.stage,
        execution_config_path=execution_config,
        semgrep_config=semgrep_config,
        semgrep_timeout_seconds=args.semgrep_timeout_seconds,
        candidate_timeout_seconds=args.candidate_timeout_seconds,
        run_functional=not args.no_functional,
        run_static=not args.no_static,
        run_semgrep=not args.no_semgrep,
    )
    try:
        run_example_code_check(request)
    except CodeCheckInputError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: check-example-code failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    print(str(output_dir / "check_result.json"))
    return EXIT_OK


def _load_patch_file(path: Path) -> list[dict]:
    """Parse a patch file that is either a list or ``{"examples": [...]}``."""

    payload = read_json(path)
    if isinstance(payload, dict):
        examples = payload.get("examples")
    elif isinstance(payload, list):
        examples = payload
    else:
        raise ValueError(
            "patch file must be a JSON list of entries or an object with an "
            "'examples' list"
        )
    if not isinstance(examples, list):
        raise ValueError("patch file 'examples' must be a list")
    return examples


def _cmd_materialize_poisoned(args: argparse.Namespace) -> int:
    try:
        assets_dir = _resolve_dir(args.assets_dir, "--assets-dir")
        data_dir = _resolve_dir(args.data_dir, "--data-dir")
        output_dir = Path(args.output_dir).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    store_path = (
        Path(args.snapshot_store).expanduser().resolve() if args.snapshot_store else None
    )
    try:
        assert_assets_output_separation(assets_dir, output_dir)
        _assert_isolated_output(output_dir, [assets_dir, data_dir])
        if store_path is not None:
            assert_assets_output_separation(assets_dir, store_path)
            _assert_isolated_output(store_path, [assets_dir, data_dir])
    except PathResolutionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    if args.allow_example and 1 in args.allow_example:
        print("error: example 1 is frozen and cannot be patched", file=sys.stderr)
        return EXIT_USAGE

    patch: list[dict] | None = None
    if args.patch_file:
        try:
            patch_path = _resolve_file(args.patch_file, "--patch-file")
            patch = _load_patch_file(patch_path)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_USAGE

    try:
        specs, _config_path, _taxonomy = load_combination_specs(assets_dir)
    except DataContractError as error:
        print(f"error: cannot load the combination registry: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    spec = specs.get(args.combination)
    if spec is None:
        print(f"error: unknown combination {args.combination!r}", file=sys.stderr)
        return EXIT_USAGE

    if args.input_snapshot:
        for flag in ("experiment", "trigger", "injection_position", "mode"):
            if getattr(args, flag) is not None:
                print(
                    f"error: --{flag.replace('_', '-')} cannot be combined with "
                    "--input-snapshot (the stored snapshot already fixes it)",
                    file=sys.stderr,
                )
                return EXIT_USAGE
        try:
            base_snapshot: TemplateSnapshot = read_snapshot(
                Path(args.input_snapshot).expanduser().resolve()
            )
        except TemplateSnapshotError as error:
            print(f"error: cannot read --input-snapshot: {error}", file=sys.stderr)
            return EXIT_BLOCKING
        if base_snapshot.combination_id != args.combination:
            print(
                f"error: --input-snapshot is for combination "
                f"{base_snapshot.combination_id!r}, not {args.combination!r}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if args.form is not None and args.form != base_snapshot.form:
            print(
                f"error: --input-snapshot stores form {base_snapshot.form!r}, not "
                f"{args.form!r}",
                file=sys.stderr,
            )
            return EXIT_USAGE
    else:
        if spec.clean_assets is None:
            print(
                f"error: {args.combination} has no clean assets; not covered",
                file=sys.stderr,
            )
            return EXIT_BLOCKING
        experiment = args.experiment or spec.clean_assets.get("fewshot_experiment")
        if not experiment:
            print(
                "error: --experiment is required (registry declares no "
                "fewshot_experiment)",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            base_snapshot = snapshot_from_clean(
                assets_root=assets_dir,
                combination_id=args.combination,
                form=args.form if args.form is not None else DEFAULT_POISON_FORM,
                experiment=experiment,
                trigger=args.trigger if args.trigger is not None else "cf",
                injection_position=(
                    args.injection_position
                    if args.injection_position is not None
                    else "first_sentence_end"
                ),
                mode=args.mode if args.mode is not None else "instruction_injection",
                prompt_version="1",
            )
        except TemplateSnapshotError as error:
            print(f"error: cannot build the template snapshot: {error}", file=sys.stderr)
            return EXIT_USAGE

    patch_result = None
    if patch is not None:
        allowed_examples = (
            tuple(args.allow_example)
            if args.allow_example
            else tuple(range(2, len(base_snapshot.examples) + 1))
        )
        allowed_fields = tuple(args.allow_field) if args.allow_field else ("code",)
        try:
            patch_result = apply_patch(
                base_snapshot,
                patch,
                PatchPolicy(allowed_examples, allowed_fields),
            )
        except TemplateSnapshotError as error:
            print(f"error: invalid patch: {error}", file=sys.stderr)
            return EXIT_USAGE
    final_snapshot = patch_result.snapshot if patch_result is not None else base_snapshot

    try:
        if store_path is not None:
            write_snapshot(
                store_path,
                final_snapshot,
                action_id=args.action_id,
                parent_sha256=(
                    base_snapshot.content_sha256()
                    if patch_result is not None and patch_result.changed
                    else None
                ),
                diff=patch_result.diff if patch_result is not None else None,
            )
        summary = materialize_poisoned(
            snapshot=final_snapshot,
            data_dir=data_dir,
            task_ids=args.task_id,
            output_dir=output_dir,
            prompt_version=final_snapshot.prompt_version,
        )
    except (PoisonMaterializeError, TemplateSnapshotError, DataContractError, OSError) as error:
        print(f"error: materialize-poisoned failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING

    print(f"combination_id={summary['combination_id']}")
    print(f"form={summary['form']}")
    print(f"template_sha256={summary['template_sha256']}")
    print(f"manifest={output_dir / 'manifest.json'}")
    for task_id in summary["task_ids"]:
        print(f"prompt[{task_id}]={summary['prompt_hashes'][task_id]}")
        print(f"prompt_file[{task_id}]={output_dir / summary['combination_id'] / summary['form'] / 'test_prompts' / task_id_to_prompt_filename(task_id)}")

    if not args.skip_verify:
        try:
            inputs = verify_poisoned_inputs(
                prompts_dir=output_dir,
                data_dir=data_dir,
                combination_id=summary["combination_id"],
                form=summary["form"],
                stage="search",
                repeats=5,
                batch_id="poison-materialize-check",
                prompt_version=final_snapshot.prompt_version,
                task_ids=summary["task_ids"],
            )
        except (GenerationContractError, DataContractError) as error:
            print(f"error: produced tree is not loadable: {error}", file=sys.stderr)
            return EXIT_BLOCKING
        except (OSError, ValueError) as error:
            print(f"error: verify failed: {error}", file=sys.stderr)
            return EXIT_BLOCKING
        print(f"sample_count={len(inputs.samples)}")
        print(f"candidate_hash={inputs.candidate_hash}")
    return EXIT_OK


def _cmd_run_training_loop(args: argparse.Namespace) -> int:
    try:
        config_path = _resolve_file(args.config, "--config")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_training_loop_config(config_path)
    except (OSError, ValueError) as error:
        print(f"error: invalid training loop config: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        manifest = run_training_loop(config, force_rerun=args.force_rerun)
    except TrainingLoopError as error:
        print(f"error: training loop failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: run-training-loop failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING

    output = Path(config.output_dir).expanduser().resolve()
    print(f"manifest={output / 'manifest.json'}")
    for name, entry in (manifest.get("steps") or {}).items():
        print(f"step[{name}]={entry.get('status')}")
    print(f"completion={manifest.get('completion')}")
    print(f"candidate_hash={manifest.get('candidate_hash')}")
    return EXIT_OK


def _cmd_mutator_action_mock(args: argparse.Namespace) -> int:
    try:
        snapshot = _resolve_dir(args.snapshot, "--snapshot")
        run_dir = Path(args.run_dir).expanduser().resolve()
        assets_root = _resolve_dir(args.assets_root, "--assets-root")
        snapshot_store = Path(args.snapshot_store).expanduser().resolve()
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    task_ids = tuple(args.task_id) if args.task_id else (
        "BigCodeBench/562",
        "BigCodeBench/348",
        "BigCodeBench/322",
        "BigCodeBench/810",
    )
    demo = DemoConfig(
        snapshot_path=str(snapshot),
        run_dir=str(run_dir),
        assets_root=str(assets_root),
        snapshot_store=str(snapshot_store),
        example_task_ids=task_ids,
        context_window_tokens=args.context_window,
        output_reserve_tokens=args.output_reserve,
    )
    try:
        report = run_offline_demo(demo)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: mutator-action-mock failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        write_json_atomic(report_path, report)
        print(f"report={report_path}")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


def _cmd_run_method_ab(args: argparse.Namespace) -> int:
    try:
        config_path = _resolve_file(args.config, "--config")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_method_config(config_path)
    except (OSError, ValueError) as error:
        print(f"error: invalid method config: {error}", file=sys.stderr)
        return EXIT_USAGE

    mutator_source_name = args.mutator_source or config.mutator.source

    # Resolve one effective repo_dir from CLI + config for both real roles.
    cli_repo_dir: Path | None = None
    if args.repo_dir:
        try:
            cli_repo_dir = _resolve_dir(args.repo_dir, "--repo-dir")
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_USAGE
    config_repo_dir = Path(config.repo_dir).expanduser() if config.repo_dir else None

    # Explicit conflict handling: never silently pick one branch.
    conflicts = []
    if cli_repo_dir is not None and config_repo_dir is not None:
        if cli_repo_dir.resolve() != config_repo_dir.resolve():
            conflicts.append(
                f"--repo-dir {cli_repo_dir} conflicts with config.repo_dir {config_repo_dir}"
            )
    effective_repo_dir = cli_repo_dir or config_repo_dir
    if effective_repo_dir is None and (mutator_source_name == "dmx" or config.victim.source == "dmx"):
        conflicts.append(
            "repo_dir is required for a real (dmx) role; pass --repo-dir or set config.repo_dir"
        )
    if args.mock_gate and args.allow_real_checks:
        conflicts.append("--mock-gate conflicts with --allow-real-checks")
    if args.mock_training and args.allow_real_training:
        conflicts.append("--mock-training conflicts with --allow-real-training")
    if not args.mock_gate and not args.allow_real_checks:
        conflicts.append("choose --mock-gate or --allow-real-checks explicitly")
    if not args.mock_training and not args.allow_real_training:
        conflicts.append("choose --mock-training or --allow-real-training explicitly")
    # The execution branch must match the configured role identity: overriding it
    # would leave the config hash/request identity/cache namespace on the other
    # source while actually calling this one.
    if args.mutator_source is not None and args.mutator_source != config.mutator.source:
        conflicts.append(
            f"--mutator-source {args.mutator_source!r} conflicts with "
            f"config.mutator.source {config.mutator.source!r}; set the role in the config"
        )
    if mutator_source_name == "dmx" and args.mutator_script:
        conflicts.append("--mutator-script conflicts with --mutator-source dmx")
    if mutator_source_name == "mock" and not args.mutator_script:
        conflicts.append("--mutator-script is required for a mock mutator")
    if conflicts:
        for item in conflicts:
            print(f"error: {item}", file=sys.stderr)
        return EXIT_USAGE

    # The single effective path is recorded in the method config so the real
    # victim first-generation/resume subprocesses and the mutator factory share it.
    config = replace(config, repo_dir=str(effective_repo_dir) if effective_repo_dir else None)

    mutator_source = None
    source_factory = None
    cache_configurer = None
    if mutator_source_name == "mock":
        try:
            script_path = _resolve_file(args.mutator_script, "--mutator-script")
            responses = read_json(script_path)
        except (OSError, ValueError) as error:
            print(f"error: invalid mutator script: {error}", file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(responses, (list, Mapping)) or (
            isinstance(responses, list) and not all(isinstance(item, str) for item in responses)
        ):
            print("error: --mutator-script must be a JSON list of strings or an {action_id: response} object", file=sys.stderr)
            return EXIT_USAGE
        mutator_source = ScriptedMutator(responses)
    else:
        source_factory = dmx_mutator_source_factory(config, config.repo_dir)
        cache_configurer = mutator_cache_configurer(config)

    checker = MockGateChecker() if args.mock_gate else None
    training = MockTraining() if args.mock_training else None
    try:
        state = run_method(
            config,
            mutator_source=mutator_source,
            mutator_source_factory=source_factory,
            cache_configurer=cache_configurer,
            example_check_runner=checker,
            training_runner=training,
            resume_paused=args.resume_paused,
            allow_unknown_retry=args.allow_unknown_retry,
        )
    except MethodError as error:
        print(f"error: run-method-ab failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: run-method-ab failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING

    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        write_json_atomic(report_path, state)
        print(f"report={report_path}")
    print(json.dumps(state, ensure_ascii=False, indent=2, default=str))
    return EXIT_OK


def _cmd_preflight_method(args: argparse.Namespace) -> int:
    try:
        config_path = _resolve_file(args.config, "--config")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_method_config(config_path)
    except (OSError, ValueError) as error:
        print(f"error: invalid method config: {error}", file=sys.stderr)
        return EXIT_USAGE
    if args.mock_gate and args.allow_real_checks:
        print("error: --mock-gate conflicts with --allow-real-checks", file=sys.stderr)
        return EXIT_USAGE
    if args.mock_training and args.allow_real_training:
        print("error: --mock-training conflicts with --allow-real-training", file=sys.stderr)
        return EXIT_USAGE
    check_service = None
    if args.mock_gate:
        check_service = "mock"
    elif args.allow_real_checks:
        check_service = "real"
    training_service = None
    if args.mock_training:
        training_service = "mock"
    elif args.allow_real_training:
        training_service = "real"
    try:
        report = build_preflight_report(
            config, check_service=check_service, training_service=training_service
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: preflight-method failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        write_json_atomic(report_path, report)
        print(f"report={report_path}")
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    # The exit code follows the report conclusion: not_ready is a non-zero exit.
    return EXIT_OK if report.get("offline_preflight_passed") else EXIT_BLOCKING


def _load_itl_doubles(module_name: str | None, config: Any):
    if not module_name:
        return None
    import importlib

    module = importlib.import_module(module_name)
    builder = getattr(module, "build_doubles", None)
    if builder is None:
        raise ValueError(f"doubles module {module_name!r} has no build_doubles()")
    return builder(config)


def _itl_preflight_report(config):
    from coco_methods.implicit_then_literal.preflight import build_preflight_report

    return build_preflight_report(config)


def _itl_status_report(config):
    from coco_methods.implicit_then_literal.preflight import build_status_report

    return build_status_report(config)


def _itl_require_preflight(config) -> int | None:
    """Reuse the required preflight checks before any external action."""

    report = _itl_preflight_report(config)
    if report.offline_preflight_passed:
        return None
    for item in report.errors:
        print(f"error: preflight: {item}", file=sys.stderr)
    return EXIT_BLOCKING


def _itl_run_lock(run_root):
    from .execution.supervisor import RunLock

    return RunLock(run_root)


def _itl_project_root(raw: str | None) -> Path:
    if raw:
        return _resolve_dir(raw, "--project-root")
    from .assets.paths import project_root

    return project_root().parent


def _load_itl_config(config_path: Path, project_root_value: Path):
    from coco_methods.implicit_then_literal import load_method_run_config

    return load_method_run_config(config_path, project_root=project_root_value)


def _load_itl_config_from_run(run_root: Path):
    from .assets.artifacts import read_json
    from coco_methods.implicit_then_literal import MethodRunConfig

    config_path = run_root / "config.json"
    if not config_path.is_file():
        raise ValueError(f"run root has no config.json: {run_root}")
    payload = read_json(config_path)
    if not isinstance(payload, Mapping):
        raise ValueError(f"run config is not a JSON object: {config_path}")
    root = payload.get("project_root") or payload.get("repository_root") or str(run_root)
    return MethodRunConfig.from_json(payload, project_root=root)


def _assemble_itl_services(config, doubles=None):
    """Test seam: tests monkeypatch this to inject offline doubles."""

    from coco_methods.implicit_then_literal import assemble_services

    return assemble_services(config, doubles=doubles)


def _itl_exit_code(summary: Mapping[str, Any]) -> int:
    phase = summary.get("phase")
    if phase == "done":
        return EXIT_OK
    if phase == "stopped":
        return EXIT_STOPPED
    if phase == "paused":
        return EXIT_PAUSED
    return EXIT_BLOCKING


def _emit_itl_result(summary: Mapping[str, Any], report: str | None) -> None:
    if report:
        report_path = Path(report).expanduser().resolve()
        write_json_atomic(report_path, dict(summary))
        print(f"report={report_path}")
    print(json.dumps(dict(summary), ensure_ascii=False, indent=2, default=str))


def _cmd_itl_preflight(args: argparse.Namespace) -> int:
    try:
        config_path = _resolve_file(args.config, "--config")
        root = _itl_project_root(args.project_root)
        config = _load_itl_config(config_path, root)
    except (OSError, ValueError) as error:
        print(f"error: invalid implicit_then_literal config: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = _itl_preflight_report(config)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: implicit-then-literal-preflight failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    payload = report.to_json()
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        write_json_atomic(report_path, payload)
        print(f"report={report_path}")
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    return EXIT_OK if report.offline_preflight_passed else EXIT_BLOCKING


def _cmd_itl_run(args: argparse.Namespace) -> int:
    try:
        config_path = _resolve_file(args.config, "--config")
        root = _itl_project_root(args.project_root)
        config = _load_itl_config(config_path, root)
    except (OSError, ValueError) as error:
        print(f"error: invalid implicit_then_literal config: {error}", file=sys.stderr)
        return EXIT_USAGE
    blocked = _itl_require_preflight(config)
    if blocked is not None:
        return blocked
    try:
        services = _assemble_itl_services(config, doubles=_load_itl_doubles(args.doubles_module, config))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: cannot assemble services: {error}", file=sys.stderr)
        return EXIT_USAGE
    from coco_methods.implicit_then_literal import MethodRuntime

    runtime = MethodRuntime(config.method, services=services)
    try:
        with _itl_run_lock(config.run_root):
            summary = runtime.run(stop_after=args.stop_after)
    except Exception as error:  # noqa: BLE001 - report the exact failure
        print(f"error: implicit-then-literal-run failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    _emit_itl_result(summary, args.report)
    return _itl_exit_code(summary)


def _cmd_itl_resume(args: argparse.Namespace) -> int:
    run_root = Path(args.run_root).expanduser().resolve()
    try:
        config = _load_itl_config_from_run(run_root)
    except (OSError, ValueError) as error:
        print(f"error: invalid implicit_then_literal run: {error}", file=sys.stderr)
        return EXIT_USAGE
    blocked = _itl_require_preflight(config)
    if blocked is not None:
        return blocked
    try:
        services = _assemble_itl_services(config, doubles=_load_itl_doubles(args.doubles_module, config))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: cannot assemble services: {error}", file=sys.stderr)
        return EXIT_USAGE
    from coco_methods.implicit_then_literal import MethodRuntime

    runtime = MethodRuntime(config.method, services=services)
    try:
        with _itl_run_lock(config.run_root):
            summary = runtime.resume(
                stop_after=args.stop_after,
                allow_retry_after_unknown=args.allow_unknown_retry,
            )
    except Exception as error:  # noqa: BLE001
        print(f"error: implicit-then-literal-resume failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    _emit_itl_result(summary, args.report)
    return _itl_exit_code(summary)


def _cmd_itl_retry(args: argparse.Namespace) -> int:
    run_root = Path(args.run_root).expanduser().resolve()
    try:
        config = _load_itl_config_from_run(run_root)
    except (OSError, ValueError) as error:
        print(f"error: invalid implicit_then_literal run: {error}", file=sys.stderr)
        return EXIT_USAGE
    blocked = _itl_require_preflight(config)
    if blocked is not None:
        return blocked
    try:
        services = _assemble_itl_services(config, doubles=_load_itl_doubles(args.doubles_module, config))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: cannot assemble services: {error}", file=sys.stderr)
        return EXIT_USAGE
    from coco_methods.implicit_then_literal import MethodRuntime

    runtime = MethodRuntime(config.method, services=services)
    try:
        with _itl_run_lock(config.run_root):
            summary = runtime.retry_induction(
                round_index=args.round,
                stage=args.stage,
                candidate_id_value=args.candidate_id,
                stop_after=args.stop_after,
                allow_retry_after_unknown=args.allow_unknown_retry,
            )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: implicit-then-literal-retry failed: {error}", file=sys.stderr)
        return EXIT_USAGE
    _emit_itl_result(summary, args.report)
    return _itl_exit_code(summary)


def _cmd_itl_status(args: argparse.Namespace) -> int:
    run_root = Path(args.run_root).expanduser().resolve()
    try:
        config = _load_itl_config_from_run(run_root)
    except (OSError, ValueError) as error:
        print(f"error: invalid implicit_then_literal run: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = _itl_status_report(config)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: implicit-then-literal-status failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    payload = report.to_json()
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        write_json_atomic(report_path, payload)
        print(f"report={report_path}")
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    return EXIT_OK


def _cmd_export_mutator_messages(args: argparse.Namespace) -> int:
    try:
        manifest = export_mutator_messages(args.run_dir, args.output_dir)
    except MessageExportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: export-mutator-messages failed: {error}", file=sys.stderr)
        return EXIT_BLOCKING
    print(json.dumps(manifest, ensure_ascii=False, indent=2, default=str))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit-assets":
        return _cmd_audit_assets(args)
    if args.command == "prepare-data":
        return _cmd_prepare_data(args)
    if args.command == "materialize-prompts":
        return _cmd_materialize_prompts(args)
    if args.command == "clean-generations":
        return _cmd_clean_generations(args)
    if args.command == "evaluate-static":
        return _cmd_evaluate_static(args)
    if args.command == "calibrate-references":
        return _cmd_calibrate_references(args)
    if args.command == "compare-history":
        return _cmd_compare_history(args)
    if args.command == "check-execution":
        return _cmd_check_execution(args)
    if args.command == "verify-isolation":
        return _cmd_verify_isolation(args)
    if args.command == "recover-executions":
        return _cmd_recover_executions(args)
    if args.command == "check-generation":
        return _cmd_check_generation(args)
    if args.command == "generate":
        return _cmd_generate(args)
    if args.command == "resume-generation":
        return _cmd_resume_generation(args)
    if args.command == "check-functional":
        return _cmd_check_functional(args)
    if args.command == "evaluate-functional":
        return _cmd_evaluate_functional(args)
    if args.command == "resume-functional":
        return _cmd_resume_functional(args)
    if args.command == "check-evaluators":
        return _cmd_check_evaluators(args)
    if args.command == "evaluate-other":
        return _cmd_evaluate_other(args)
    if args.command == "resume-other":
        return _cmd_resume_other(args)
    if args.command == "check-pipeline":
        return _cmd_check_pipeline(args)
    if args.command == "run-pipeline":
        return _cmd_run_pipeline(args)
    if args.command == "resume-pipeline":
        return _cmd_resume_pipeline(args)
    if args.command == "report-pipeline":
        return _cmd_report_pipeline(args)
    if args.command == "prepare-baseline":
        return _cmd_prepare_baseline(args)
    if args.command == "check-baseline":
        return _cmd_check_baseline(args)
    if args.command == "run-baseline":
        return _cmd_run_baseline(args)
    if args.command == "status-baseline":
        return _cmd_status_baseline(args)
    if args.command == "report-baseline":
        return _cmd_report_baseline(args)
    if args.command == "check-example-code":
        return _cmd_check_example_code(args)
    if args.command == "materialize-poisoned":
        return _cmd_materialize_poisoned(args)
    if args.command == "run-training-loop":
        return _cmd_run_training_loop(args)
    if args.command == "mutator-action-mock":
        return _cmd_mutator_action_mock(args)
    if args.command == "run-method-ab":
        return _cmd_run_method_ab(args)
    if args.command == "preflight-method":
        return _cmd_preflight_method(args)
    if args.command == "implicit-then-literal-preflight":
        return _cmd_itl_preflight(args)
    if args.command == "implicit-then-literal-run":
        return _cmd_itl_run(args)
    if args.command == "implicit-then-literal-resume":
        return _cmd_itl_resume(args)
    if args.command == "implicit-then-literal-retry":
        return _cmd_itl_retry(args)
    if args.command == "implicit-then-literal-status":
        return _cmd_itl_status(args)
    if args.command == "export-mutator-messages":
        return _cmd_export_mutator_messages(args)
    parser.error(f"unknown command: {args.command!r}")
    return EXIT_USAGE  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
