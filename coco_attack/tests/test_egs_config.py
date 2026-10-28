"""Configuration loading and staged gap checks for evidence-guided search."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coco_methods.evidence_guided_search.config import (
    ConfigError,
    ROLE_TEMPLATE_FILES,
    check_config,
    load_config,
)


def _write_templates(root: Path) -> None:
    for relative in ROLE_TEMPLATE_FILES:
        path = root / "templates" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{{ target_definition }}\n", encoding="utf-8")


def _base_config() -> dict[str, object]:
    return {
        "template_dir": "templates",
        "initial_template_path": "inputs/initial_template/snapshot.json",
        "clean_snapshot_path": None,
        "data_root": "data",
        "assets_root": "assets",
        "target_definition": "current target",
        "modification_contract": "only examples 2-4 code/cot",
        "public_sast_rules": "public rule text",
        "initial_hypotheses": [
            {
                "statement": f"initial hypothesis {index}",
                "scope": {
                    "task_ids": ["T1", "T2"],
                    "conditions": ["when relevant"],
                    "limits": ["not generalised"],
                },
            }
            for index in range(6)
        ],
        "training_tasks": [{"task_id": "T1"}, {"task_id": "T2"}],
    }


def _project(tmp_path: Path, config: dict[str, object] | None = None) -> Path:
    _write_templates(tmp_path)
    (tmp_path / "inputs/initial_template").mkdir(parents=True, exist_ok=True)
    (tmp_path / "inputs/initial_template/snapshot.json").write_text("{}", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "assets").mkdir()
    (tmp_path / "config.json").write_text(
        json.dumps(_base_config() if config is None else config),
        encoding="utf-8",
    )
    return tmp_path


def test_load_config_resolves_paths_and_records_provenance(tmp_path: Path) -> None:
    root = _project(tmp_path)
    loaded = load_config(root / "config.json", project_root=root)

    assert loaded["project_root"] == str(root.resolve())
    assert loaded["config_path"] == str((root / "config.json").resolve())
    assert loaded["template_dir"] == str((root / "templates").resolve())
    assert loaded["initial_template_path"] == str((root / "inputs/initial_template/snapshot.json").resolve())
    assert loaded["data_root"] == str((root / "data").resolve())
    assert loaded["assets_root"] == str((root / "assets").resolve())
    # An undecided choice stays null; the loader does not substitute a default.
    assert loaded["clean_snapshot_path"] is None
    assert check_config(loaded) == []


def test_removed_contract_is_not_required_for_role_readiness(tmp_path: Path) -> None:
    config = _base_config()
    config.pop('modification_contract')
    root = _project(tmp_path, config)
    loaded = load_config(root / 'config.json', project_root=root)
    assert check_config(loaded, stage='roles') == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_definition", 7),
        ("public_sast_rules", ["not", "text"]),
        (
            "initial_hypotheses",
            [
                {
                    "statement": f"hypothesis {index}",
                    "scope": {"task_ids": ["T1"], "conditions": [], "limits": []},
                }
                for index in range(5)
            ],
        ),
        (
            "initial_hypotheses",
            [
                {
                    "statement": f"hypothesis {index}",
                    "scope": {"task_ids": ["T1"], "conditions": []},
                }
                for index in range(6)
            ],
        ),
        ("training_tasks", [{"task_id": "T1"}]),
        ("training_tasks", [{"task_id": "T1"}, {"task_id": "T1"}]),
        ("training_tasks", [{"task_id": "T1"}, {"task_id": 2}]),
    ],
)
def test_load_config_rejects_malformed_role_materials(
    tmp_path: Path, field: str, value: object
) -> None:
    config = _base_config()
    config[field] = value
    root = _project(tmp_path, config)

    with pytest.raises(ConfigError):
        load_config(root / "config.json", project_root=root)


def test_check_roles_reports_missing_templates_and_scope_tasks(tmp_path: Path) -> None:
    config = _base_config()
    config["target_definition"] = None
    config["initial_template_path"] = None
    config["initial_hypotheses"][0]["scope"]["task_ids"] = ["T3"]  # type: ignore[index]
    root = _project(tmp_path, config)
    (root / "templates" / "统一汇总/user.md.j2").unlink()

    gaps = check_config(load_config(root / "config.json", project_root=root))

    assert any("target_definition" in gap for gap in gaps)
    assert any("initial_template_path" in gap for gap in gaps)
    assert any("统一汇总/user.md.j2" in gap for gap in gaps)
    assert any("T3" in gap for gap in gaps)


def test_check_config_stages_are_cumulative(tmp_path: Path) -> None:
    root = _project(tmp_path)
    loaded = load_config(root / "config.json", project_root=root)

    measurement = check_config(loaded, stage="measurement")
    assert any(gap.startswith("measurement.") for gap in measurement)
    assert not any(gap.startswith("search.") for gap in measurement)
    assert any("clean_snapshot_path" in gap for gap in measurement)

    full_run = check_config(loaded, stage="run")
    for prefix in ("measurement.", "search.", "selection.", "run."):
        assert any(gap.startswith(prefix) for gap in full_run)


def test_check_config_rejects_unknown_stage(tmp_path: Path) -> None:
    root = _project(tmp_path)
    loaded = load_config(root / "config.json", project_root=root)

    with pytest.raises(ConfigError):
        check_config(loaded, stage="final")


def _measurement_settings() -> dict[str, object]:
    return {
        "assets_root": "assets",
        "data_dir": "data",
        "task_ids": ["T1", "T2"],
        "repeats": 1,
        "stage": "search",
        "victim_messages": "single_user",
        "generation": {
            "source": "mock",
            "model": "mock-model",
            "batch_id": "pending-batch",
            "temperature": 0.0,
            "max_tokens": 64,
            "request_timeout": 30.0,
            "max_concurrency": 2,
            "max_request_attempts": 1,
            "max_sample_retries": 0,
        },
        "evaluators": {
            "sast_tools": ["semgrep"],
            "semgrep_config": "semgrep",
            "codeql_executable": None,
            "codeql_search_path": None,
        },
        "functional": {
            "k": [1],
            "harness_version": "test-harness",
            "candidate_timeout_seconds": 20.0,
        },
        "execution_config_path": "execution.json",
        "cache_dir": "cache",
        "repo_dir": None,
    }


def _role_entry(role: str) -> dict[str, object]:
    return {
        "config": {
            "role": role,
            "model": "mock-model",
            "source": "mock",
        },
        "responses": ["{}"],
    }


def _full_config() -> dict[str, object]:
    config = _base_config()
    config.update(
        {
            "clean_snapshot_path": "inputs/clean/snapshot.json",
            "roles": {
                "candidate": _role_entry("candidate"),
                "report": _role_entry("report"),
                "aggregate": _role_entry("aggregate"),
            },
            "measurement": _measurement_settings(),
            "reference_measurement": _measurement_settings(),
            "retest_measurement": _measurement_settings(),
            "example_check": {
                "assets_root": "assets",
                "code_input_mode": "example_body",
                "stage": "search",
                "execution_config_path": "execution.json",
                "semgrep_config": "semgrep",
                "semgrep_timeout_seconds": 30.0,
                "candidate_timeout_seconds": 20.0,
            },
            "admission": {
                "oracle_states": ["present", "possibly_present"],
                "semantic_mode": "prompt_only",
            },
            "search": {
                "rounds": 1,
                "guided_count": 1,
                "unguided_count": 0,
                "probe_groups_per_round": 0,
                "guidance_policy": "all_active",
                "probe_policy": "in_order_complete_groups",
                "duplicate_policy": "independent_sampling",
            },
            "concurrency": {
                "candidate_workers": 1,
                "total_victim_requests": 2,
            },
            "budget": {
                "unit": "victim_request_attempts",
                "allocations": {"reference": 2, "search": 2, "retest": 2},
                "role_attempts": 10,
            },
            "reference_comparability": {"comparable": True},
            "selection": {
                "rule_version": "test-v1",
                "shortlist": {
                    "mode": "all_admitted_unique",
                    "content_policy": "merge_first",
                    "limit": 1,
                    "order": "candidate_id",
                    "include_sources": ["guided", "unguided", "probe"],
                    "candidate_ids": None,
                },
                "evidence_policy": "retest_only",
                "unknown_policy": "require_all_decided",
                "functional": {
                    "comparison": "per_task_absolute_drop",
                    "estimator": "empirical",
                    "require_complete": True,
                    "max_drop": 0.1,
                    "minimum": 1,
                },
                "ranking": {
                    "metric": "H",
                    "aggregation": "macro",
                    "tie_break": "candidate_id",
                    "direction": "maximize",
                    "require_complete": True,
                },
            },
        }
    )
    return config


def _full_project(tmp_path: Path) -> Path:
    root = _project(tmp_path, _full_config())
    (root / "inputs/clean").mkdir(parents=True, exist_ok=True)
    (root / "inputs/clean/snapshot.json").write_text("{}", encoding="utf-8")
    (root / "semgrep").mkdir()
    (root / "execution.json").write_text("{}", encoding="utf-8")
    return root


def test_check_config_accepts_the_actual_nested_schema(tmp_path: Path) -> None:
    root = _full_project(tmp_path)
    loaded = load_config(root / "config.json", project_root=root)

    assert loaded["measurement"]["data_dir"] == str((root / "data").resolve())
    assert loaded["measurement"]["evaluators"]["semgrep_config"] == str(
        (root / "semgrep").resolve()
    )
    assert loaded["example_check"]["execution_config_path"] == str(
        (root / "execution.json").resolve()
    )
    assert check_config(loaded, stage="run") == []


def test_check_config_rejects_empty_objects_and_resource_overcommit(
    tmp_path: Path,
) -> None:
    config = _full_config()
    config["example_check"] = {}
    config["budget"] = {}
    config["concurrency"] = {
        "candidate_workers": 2,
        "total_victim_requests": 2,
    }
    root = _full_project(tmp_path)
    root.joinpath("config.json").write_text(json.dumps(config), encoding="utf-8")
    loaded = load_config(root / "config.json", project_root=root)

    gaps = check_config(loaded, stage="run")

    assert any(gap.startswith("example_check.") for gap in gaps)
    assert any(gap.startswith("run.budget.") for gap in gaps)
    assert any("exceeds" in gap for gap in gaps)


def test_check_config_rejects_undecided_admission(tmp_path: Path) -> None:
    config = _full_config()
    config["admission"] = {"oracle_states": None, "semantic_mode": None}
    root = _full_project(tmp_path)
    root.joinpath("config.json").write_text(json.dumps(config), encoding="utf-8")
    loaded = load_config(root / "config.json", project_root=root)

    gaps = check_config(loaded, stage="run")

    assert any(gap.startswith("admission.") for gap in gaps)


def test_pending_template_is_not_runnable() -> None:
    repo = Path(__file__).resolve().parents[1]
    config_path = repo / "configs/evidence_guided_search/pending.json"
    loaded = load_config(config_path, project_root=repo)

    gaps = check_config(loaded, stage="run")

    assert gaps
    assert not any(gap.startswith("admission.") for gap in gaps)
    assert any(gap.startswith("measurement.") for gap in gaps)
    assert any(gap.startswith("selection.") for gap in gaps)


def test_search_only_checks_do_not_require_deferred_selection(tmp_path: Path) -> None:
    root = _full_project(tmp_path)
    loaded = load_config(root / 'config.json', project_root=root)
    loaded.update(execution_mode='search_only', selection=None, retest_measurement=None)
    loaded['budget']['allocations']['retest'] = 0
    assert check_config(loaded, stage='run') == []
    assert any(gap.startswith('selection.') for gap in check_config(loaded, stage='selection'))


def test_search_only_does_not_allocate_unused_retest_budget(tmp_path: Path) -> None:
    root = _full_project(tmp_path)
    loaded = load_config(root / 'config.json', project_root=root)
    loaded['execution_mode'] = 'search_only'
    loaded['budget']['allocations']['retest'] = 1
    assert any('retest must be 0' in gap for gap in check_config(loaded, stage='run'))


def test_fixed_hypotheses_in_the_template_must_match_the_config(tmp_path: Path) -> None:
    config = _base_config()
    statements = [entry['statement'] for entry in config['initial_hypotheses']]
    root = _project(tmp_path, config)
    template = root / 'templates' / ROLE_TEMPLATE_FILES[1]
    fixed = '## 初始启发性假设（固定）\n' + ''.join(
        f'{index}. {statement}\n' for index, statement in enumerate(statements, 1))
    template.write_text(fixed + '{{ source_context_json }}\n', encoding='utf-8')
    loaded = load_config(root / 'config.json', project_root=root)

    assert not [gap for gap in check_config(loaded) if 'fixed hypotheses' in gap]

    loaded['initial_hypotheses'][2]['statement'] = 'changed after the template was written'
    gaps = check_config(loaded)

    assert [gap for gap in gaps if 'fixed hypotheses' in gap]
