"""Per-run PipelineConfig generation (phase 03)."""

from __future__ import annotations

from coco_attack.evaluation.pipeline import load_pipeline_config
from coco_attack.experiments.configgen import (
    build_pipeline_config,
    check_unit_configs,
    write_unit_configs,
)
from coco_attack.experiments.manifest import build_manifest
from coco_attack.experiments.matrix import expand_units

from test_experiments_matrix import BASELINE_COMBINATIONS, _matrix, _prepared


def _matrix_and_units():
    matrix = _matrix()
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    return matrix, expand_units(matrix, prepared)


def test_build_pipeline_config_fields(tmp_path) -> None:
    matrix, units = _matrix_and_units()
    unit = next(
        unit
        for unit in units
        if unit.combination_id == "cwe078-0"
        and unit.form == "clean_fewshot_cot"
        and unit.repeats == 1
    )
    for entry in unit.entries:
        config = build_pipeline_config(matrix, unit, entry, tmp_path)
        assert config.run_id == entry.run_id
        assert config.combination_id == "cwe078-0"
        assert config.oracle_id == "cwe078-0"
        assert config.stage == entry.stage
        assert config.form == "clean_fewshot_cot"
        assert config.source == "dmx"
        assert config.model == matrix.victim_model
        assert config.temperature == 0.0
        assert config.repeats == 1
        assert config.batch_id == unit.batch_id
        assert config.prompt_version == matrix.prompt_version
        assert config.task_ids == entry.task_ids
        assert config.data_dir == str(tmp_path / "inputs" / "data")
        assert config.prompts_dir == str(tmp_path / "inputs" / "prompts" / "cwe078-0")
        assert config.functional_cache_dir == str(tmp_path / "cache" / "functional")
        assert config.output_dir == str(tmp_path / entry.run_dir)
        assert config.max_tokens == matrix.max_tokens
        assert config.max_concurrency == matrix.generation_max_concurrency
        assert config.enabled_layers == ("sast", "judge")
        assert config.judge is not None
        assert config.judge["source"] == "dmx"
        assert config.judge["model"] == matrix.judge_model
        assert config.judge["max_tokens"] == matrix.judge_max_tokens


def test_judge_disabled_removes_layer(tmp_path) -> None:
    matrix = _matrix(judge_enabled=False)
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    unit = expand_units(matrix, prepared)[0]
    config = build_pipeline_config(matrix, unit, unit.entries[0], tmp_path)
    assert config.judge is None
    assert "judge" not in config.enabled_layers


def test_write_and_reload_configs_does_not_create_run_dirs(tmp_path) -> None:
    matrix, units = _matrix_and_units()
    written = write_unit_configs(tmp_path, matrix, units)
    assert len(written) == 24
    for run_id, relative in written.items():
        path = tmp_path / relative
        assert path.is_file(), run_id
        config = load_pipeline_config(path)
        assert config.run_id == run_id
    # Config generation must never pre-create a run directory: run-pipeline
    # requires a fresh output directory.
    assert not (tmp_path / "units").exists()


def test_check_unit_configs_reports_missing_inputs_without_raising(tmp_path) -> None:
    matrix, units = _matrix_and_units()
    write_unit_configs(tmp_path, matrix, units)
    manifest = build_manifest(matrix, units, {"git_commit": "abc"}, tmp_path)
    summary = check_unit_configs(tmp_path, manifest)
    assert len(summary) == 24
    for entry in summary.values():
        assert entry["ok"] is False
        assert entry["error"]


def test_victim_pricing_is_wired_into_generation_config(tmp_path) -> None:
    """The matrix victim price must reach the generation config, or victim cost is unknown."""

    from coco_attack.evaluation.pipeline import _generation_config

    matrix = _matrix(
        price_input_per_1k=0.00158,
        price_output_per_1k=0.00237,
        currency="CNY",
        pricing_version="dmx-rmb-test",
    )
    prepared = {cid: _prepared(cid) for cid in BASELINE_COMBINATIONS}
    unit = expand_units(matrix, prepared)[0]
    config = build_pipeline_config(matrix, unit, unit.entries[0], tmp_path)
    assert (config.price_input_per_1k, config.price_output_per_1k) == (0.00158, 0.00237)
    assert (config.currency, config.pricing_version) == ("CNY", "dmx-rmb-test")

    generation = _generation_config(config)
    assert (generation.price_input_per_1k, generation.price_output_per_1k) == (0.00158, 0.00237)
    assert (generation.currency, generation.pricing_version) == ("CNY", "dmx-rmb-test")
