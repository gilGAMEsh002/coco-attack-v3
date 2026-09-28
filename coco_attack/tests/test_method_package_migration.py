"""Interface-stability tests for the ``method`` -> ``single_candidate_ab`` package move.

The migration must be behaviour-neutral: the existing import paths
(``coco_attack.method.single_candidate_ab`` and ``coco_attack.method.preflight``)
keep working, the frozen public name lists are unchanged, and the method config
identity hash is not perturbed.  No A/B behaviour, cache key or research gate is
exercised here.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import coco_attack.method as method_top
import coco_attack.method.preflight as top_preflight
import coco_attack.method.single_candidate_ab as pkg
import coco_attack.method.single_candidate_ab.preflight as pkg_preflight
import coco_attack.method.single_candidate_ab.runtime as runtime

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

TOP_LEVEL_PUBLIC = [
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

PACKAGE_PUBLIC = [
    name
    for name in TOP_LEVEL_PUBLIC
    if name not in ("PREFLIGHT_SCHEMA_VERSION", "build_preflight_report")
] + ["PHASE_DONE", "PHASE_PAUSED"]


def test_top_level_public_list_is_frozen() -> None:
    assert sorted(method_top.__all__) == sorted(TOP_LEVEL_PUBLIC)
    assert len(method_top.__all__) == 20
    for name in TOP_LEVEL_PUBLIC:
        assert hasattr(method_top, name), name


def test_package_public_list_is_frozen() -> None:
    assert sorted(pkg.__all__) == sorted(PACKAGE_PUBLIC)
    assert len(pkg.__all__) == 20
    for name in PACKAGE_PUBLIC:
        assert hasattr(pkg, name), name
    # A_FIELD / B_FIELD stay directly importable even though they are not in the
    # frozen list.
    assert pkg.A_FIELD == "code"
    assert pkg.B_FIELD == "cot"


def test_old_and_new_entries_are_the_same_objects() -> None:
    assert top_preflight.build_preflight_report is pkg_preflight.build_preflight_report
    assert top_preflight.PREFLIGHT_SCHEMA_VERSION == pkg_preflight.PREFLIGHT_SCHEMA_VERSION
    assert method_top.MethodConfig is runtime.MethodConfig
    assert method_top.MethodRun is runtime.MethodRun
    assert method_top.run_method is runtime.run_method
    assert method_top.evaluate_example_gate is runtime.evaluate_example_gate


def test_package_layout_replaces_the_module_file() -> None:
    method_dir = Path(method_top.__file__).resolve().parent
    assert (method_dir / "single_candidate_ab" / "__init__.py").is_file()
    assert (method_dir / "single_candidate_ab" / "runtime.py").is_file()
    assert (method_dir / "single_candidate_ab" / "preflight.py").is_file()
    assert not (method_dir / "single_candidate_ab.py").exists()


def test_config_identity_hash_is_unchanged() -> None:
    config = method_top.MethodConfig(
        run_dir="/tmp/x/run",
        snapshot_path="/tmp/x/snap",
        snapshot_store="/tmp/x/store",
        assets_root="/tmp/x/assets",
        data_dir="/tmp/x/data",
    )
    assert config.config_sha256() == "34b031ca44730cc48477ba1c30b23e026af1c71cd139118e33987a4ae89eee66"


def _run_in_subprocess(code: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)


def test_no_circular_import_for_any_entry_order() -> None:
    entry_points = [
        "import coco_attack.method.preflight",
        "import coco_attack.method.single_candidate_ab.preflight",
        "from coco_attack.method.single_candidate_ab import A_FIELD, B_FIELD",
        "import coco_attack.method; import coco_attack.method.single_candidate_ab",
        "from coco_attack.method.preflight import build_preflight_report",
    ]
    for code in entry_points:
        result = _run_in_subprocess(code)
        assert result.returncode == 0, f"{code!r} failed: {result.stderr}"


def test_cli_loads_with_the_new_layout() -> None:
    result = _run_in_subprocess("from coco_attack.cli import build_parser; build_parser()")
    assert result.returncode == 0, result.stderr
