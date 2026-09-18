"""Command-line entry point for the CoCo-Attack rebuild.

Importing this module must not initialise DSPy, caches or secrets. Only the
subcommand actually selected performs work.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .assets.artifacts import assert_fresh_dir, read_json
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
from .prompts.markdown import CLEAN_FORMS
from .prompts.materialize import PromptMaterializeError, materialize_combination

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_USAGE = 2


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
    parser.error(f"unknown command: {args.command!r}")
    return EXIT_USAGE  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
