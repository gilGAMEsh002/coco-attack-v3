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
from .evaluation.run_cleaning import clean_generations
from .evaluation.run_static import EvaluationInputError, evaluate_static
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
    return parser


def _resolve_dir(raw: str, label: str) -> Path:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ValueError(f"cannot resolve {label}: {raw!r}: {error}") from error
    if not path.is_dir():
        raise ValueError(f"{label} is not an existing directory: {path}")
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
    parser.error(f"unknown command: {args.command!r}")
    return EXIT_USAGE  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
