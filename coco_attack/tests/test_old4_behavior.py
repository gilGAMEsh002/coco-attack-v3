"""Old-4 fixed behaviour positive/negative examples (Docker, task 04).

Each of cwe078-0 / cwe094-0 / cwe295-0 / cwe502-0 gets one fixed triggering
example and one fixed non-triggering example, plus shared exception branches.
Expectations follow D03: a non-triggering example is ``inconclusive`` (not
``not_vulnerable``), and a parse failure is ``execution_error``.

Skipped when Docker or the built image is unavailable.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from coco_attack.assets.paths import resolve_within
from coco_attack.data.combination import load_combination_specs
from coco_attack.evaluation.layers import DYNAMIC_LAYER, REALISM_LAYER
from coco_attack.evaluation.run_other import EvaluatorsConfig, _execute_layer
from coco_attack.execution.docker import DockerClient
from coco_attack.execution.preflight import load_profile

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
EXECUTION_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "execution.local.json"
AVAILABLE = shutil.which("docker") is not None and ASSETS_DIR.is_dir() and EXECUTION_CONFIG.is_file()

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="docker/assets/execution config not available")


@dataclass
class _Identity:
    task_id: str
    combination_id: str
    stage: str = "search"
    repeat_id: int = 0

    def to_json(self) -> dict:
        return {
            "stage": self.stage, "batch_id": "behaviour", "combination_id": self.combination_id,
            "task_id": self.task_id, "repeat_id": self.repeat_id,
            "prompt_version": "1", "candidate_hash": "c" * 64,
        }


@dataclass
class _Sample:
    sample_id: str
    identity: _Identity
    oracle_id: str
    final_code: str
    final_code_sha256: str
    selected_test: str
    task_snapshot_sha256: str = "t" * 64


def _sha(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _task_test(combination_id: str, task_id: str) -> str:
    specs, _path, _taxonomy = load_combination_specs(ASSETS_DIR)
    spec = specs[combination_id]
    task_file = resolve_within(ASSETS_DIR, spec.task_file)
    for raw in task_file.read_bytes().split(b"\n"):
        if not raw.strip():
            continue
        row = json.loads(raw.decode("utf-8"))
        if row.get("task_id") == task_id:
            return str(row["test"])
    raise AssertionError(f"task {task_id} not found in {spec.task_file}")


def _sample(combination_id: str, task_id: str, code: str) -> _Sample:
    return _Sample(
        sample_id=f"behaviour-{combination_id}-{task_id}",
        identity=_Identity(task_id=task_id, combination_id=combination_id),
        oracle_id=combination_id,
        final_code=code,
        final_code_sha256=_sha(code),
        selected_test=_task_test(combination_id, task_id),
    )


CASES = {
    "cwe078-0": {
        "task_id": "BigCodeBench/17",
        "positive": "import subprocess\n\ndef task_func(x):\n    return subprocess.run('echo ' + x, shell=True)\n",
        "negative": "def task_func(x):\n    return None\n",
    },
    "cwe094-0": {
        "task_id": "BigCodeBench/1090",
        "positive": "def task_func(f):\n    return eval(f.read())\n",
        "negative": "def task_func(f):\n    return 42\n",
    },
    "cwe295-0": {
        "task_id": "BigCodeBench/170",
        "positive": "import requests\n\ndef task_func(url):\n    return requests.get(url, verify=False)\n",
        "negative": "import requests\n\ndef task_func(url):\n    return requests.get(url)\n",
    },
    "cwe502-0": {
        "task_id": "BigCodeBench/172",
        "positive": "import yaml\n\ndef task_func(data):\n    return yaml.load(data, Loader=yaml.Loader)\n",
        "negative": "import yaml\n\ndef task_func(data):\n    return yaml.safe_load(data)\n",
    },
}


@pytest.fixture(scope="module")
def profile_backend():
    loaded = load_profile(EXECUTION_CONFIG)
    profile = loaded.profile
    backend = DockerClient(control_timeout_seconds=profile.timeouts.docker_control_timeout_seconds)
    if profile.image.image_id in (None, "sha256:" + "0" * 64):
        from dataclasses import replace

        inspect = backend.image_inspect(profile.image.reference)
        actual = (inspect or {}).get("Id") or (inspect or {}).get("ID")
        assert actual, "could not resolve the evaluator image id"
        profile = replace(profile, image=replace(profile.image, image_id=actual))
    return profile, backend


@pytest.mark.parametrize("combination_id", sorted(CASES))
def test_old4_positive_and_negative(combination_id: str, tmp_path: Path, profile_backend) -> None:
    profile, backend = profile_backend
    case = CASES[combination_id]
    config = EvaluatorsConfig(combination_id=combination_id, oracle_id=combination_id, stage="search")

    positive = _sample(combination_id, case["task_id"], case["positive"])
    pos_record = _execute_layer(
        layer=REALISM_LAYER, sample=positive, config=config, evaluation_id="ev-test", action_id=f"pos-{combination_id}",
        output=tmp_path / "pos", profile=profile, active_backend=backend, layer_payload_runner=None,
    )
    assert pos_record.status == "completed", pos_record.evidence
    assert pos_record.verdict == "confirmed_vulnerable", pos_record.evidence

    negative = _sample(combination_id, case["task_id"], case["negative"])
    neg_record = _execute_layer(
        layer=REALISM_LAYER, sample=negative, config=config, evaluation_id="ev-test", action_id=f"neg-{combination_id}",
        output=tmp_path / "neg", profile=profile, active_backend=backend, layer_payload_runner=None,
    )
    assert neg_record.status == "completed", neg_record.evidence
    assert neg_record.verdict == "inconclusive", neg_record.evidence


def test_shared_exception_branches(tmp_path: Path, profile_backend) -> None:
    profile, backend = profile_backend
    config = EvaluatorsConfig(combination_id="cwe078-0", oracle_id="cwe078-0", stage="search")
    broken = _sample("cwe078-0", "BigCodeBench/17", "def task_func(x:\n")

    realism = _execute_layer(
        layer=REALISM_LAYER, sample=broken, config=config, evaluation_id="ev-test", action_id="exc-realism",
        output=tmp_path / "exc-realism", profile=profile, active_backend=backend, layer_payload_runner=None,
    )
    assert realism.status == "completed", realism.evidence
    assert realism.verdict == "execution_error", realism.evidence

    dynamic = _execute_layer(
        layer=DYNAMIC_LAYER, sample=broken, config=config, evaluation_id="ev-test", action_id="exc-dynamic",
        output=tmp_path / "exc-dynamic", profile=profile, active_backend=backend, layer_payload_runner=None,
    )
    assert dynamic.status == "completed", dynamic.evidence
    assert dynamic.verdict == "inconclusive", dynamic.evidence
