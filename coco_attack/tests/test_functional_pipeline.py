"""End-to-end functional evaluation smoke with a simulated container (task 03).

Uses the real stage-01 assets plus a real mock generation run, but replaces the
Docker backend with a simulator that writes a conformant functional payload.
The real-Docker functional run is recorded separately in the acceptance record.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from coco_attack.assets.paths import default_config_dir
from coco_attack.cli import main
from coco_attack.evaluation.run_functional import (
    FunctionalInputError,
    load_functional_config,
    run_check_functional,
    run_evaluate_functional,
    run_resume_functional,
)

REPO_DIR = Path("/home/sshuser/projects/dspy")
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
SPLIT_CONFIG = default_config_dir() / "splits.json"

pytestmark = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)

COMBINATION = "cwe078-0"
FORM = "clean_fewshot_cot"


class _FunctionalBackend:
    def __init__(self) -> None:
        self.actions: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.removed: set[str] = set()

    def probe(self) -> dict:
        return {"available": True}

    def image_inspect(self, reference: str):
        return {"Id": "sha256:" + "b" * 64}

    def inspect_raw(self, container_id: str):
        return {"Id": container_id, "Image": "sha256:" + "b" * 64, "HostConfig": {}, "Mounts": []}

    @staticmethod
    def _mount(spec, target: str) -> str:
        for mount in spec.mounts:
            if mount.target == target:
                return mount.source
        raise AssertionError(f"missing mount {target}")

    def create(self, spec) -> str:
        from coco_attack.assets.artifacts import canonical_json_bytes

        cid = f"cid-{len(self.actions)}"
        self.actions.append(("create", spec.name))
        staging = self._mount(spec, "/in")
        output = self._mount(spec, "/out")
        request = json.loads((Path(staging) / "request.json").read_text(encoding="utf-8"))
        func_request = json.loads((Path(staging) / "func_request.json").read_text(encoding="utf-8"))
        argv = list(spec.argv)
        nonce = argv[argv.index("--nonce") + 1]
        payload = {
            "schema_version": "1",
            "functional_schema": "functional-payload-v1",
            "harness_version": "functional-harness-v2",
            "sample_id": func_request["sample_id"],
            "attempt_id": func_request["attempt_id"],
            "entry_point": func_request["entry_point"],
            "code_sha256": func_request["code_sha256"],
            "tests_sha256": func_request["tests_sha256"],
            "load": {
                "solution_compiled": True,
                "solution_error": None,
                "entry_present": True,
                "tests_compiled": True,
                "tests_error": None,
                "loader_error": None,
                "tests_discovered": 1,
            },
            "run": {
                "tests_run": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
                "suite_completed": True,
                "failure_stage": None,
            },
            "test_details": [],
        }
        envelope = {
            "schema_version": "1",
            "sample_id": request["sample_id"],
            "attempt_id": request["attempt_id"],
            "stage": request["stage"],
            "result_schema": request["result_schema"],
            "nonce": nonce,
            "payload_valid": True,
            "payload": payload,
            "payload_error": None,
        }
        (Path(output) / "result.json").write_bytes(canonical_json_bytes(envelope))
        self.containers[cid] = {"finished": True}
        return cid

    def start(self, container_id: str) -> None:
        self.actions.append(("start", container_id))

    def inspect(self, container_id: str):
        from coco_attack.execution.contracts import ContainerState

        if container_id in self.removed:
            return None
        if container_id not in self.containers:
            return None
        return ContainerState(
            container_id=container_id,
            name="coco-attack-functional",
            status="exited",
            running=False,
            exit_code=0,
            oom_killed=False,
            started_at=None,
            finished_at=None,
            labels={"coco-attack.managed": "true"},
            image_id="sha256:" + "b" * 64,
        )

    def stop(self, container_id: str, grace_seconds: float) -> None:
        pass

    def remove(self, container_id: str, force: bool) -> None:
        self.removed.add(container_id)

    def list_managed(self, labels: dict) -> list:
        return []

    def logs(self, container_id: str, stdout_max_bytes: int, stderr_max_bytes: int):
        from coco_attack.execution.docker import LogResult

        return LogResult("", "", False, False)


@pytest.fixture(scope="module")
def functional_env(tmp_path_factory) -> dict:
    root = tmp_path_factory.mktemp("functional03")
    prepared = root / "prepared"
    assert main([
        "prepare-data", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--output-dir", str(prepared), "--split-config", str(SPLIT_CONFIG),
        "--combination", COMBINATION,
    ]) == 0
    prompts = root / "prompts"
    assert main([
        "materialize-prompts", "--repo-dir", str(REPO_DIR), "--assets-dir", str(ASSETS_DIR),
        "--data-dir", str(prepared), "--combination", COMBINATION,
        "--oracle-id", COMBINATION, "--form", FORM, "--output-dir", str(prompts),
    ]) == 0

    generation_config = root / "generation.json"
    generation_config.write_text(
        json.dumps(
            {
                "schema_version": "1", "source": "mock", "model": "openai/gpt-4o",
                "batch_id": "functional-batch-1", "combination_id": COMBINATION,
                "oracle_id": COMBINATION, "stage": "search", "form": FORM,
                "prompt_version": "1", "candidate_hash": "", "temperature": 0.0,
                "repeats": 1, "max_tokens": 256, "request_timeout": 30.0,
                "max_concurrency": 4, "max_request_attempts": 2, "max_sample_retries": 0,
                "price_input_per_1k": 0.0, "price_output_per_1k": 0.0,
                "currency": "USD", "pricing_version": "mock", "mock_scenario": "normal",
            }
        ),
        encoding="utf-8",
    )
    generation_run = root / "generation-run"
    assert main([
        "generate", "--config", str(generation_config), "--data-dir", str(prepared),
        "--prompts-dir", str(prompts), "--output-dir", str(generation_run),
    ]) == 0
    cleaned = root / "cleaned"
    assert main([
        "clean-generations", "--data-dir", str(prepared),
        "--input-jsonl", str(generation_run / "generations.jsonl"),
        "--combination", COMBINATION, "--oracle-id", COMBINATION,
        "--output-dir", str(cleaned),
    ]) == 0

    functional_config = root / "functional.json"
    functional_config.write_text(
        json.dumps(
            {
                "schema_version": "1", "combination_id": COMBINATION, "oracle_id": COMBINATION,
                "stage": "search", "k": [1, 3, 5], "harness_version": "functional-harness-v2",
            }
        ),
        encoding="utf-8",
    )
    return {
        "root": root,
        "prepared": prepared,
        "prompts": prompts,
        "generation_run": generation_run,
        "cleaned": cleaned,
        "functional_config": functional_config,
        "execution_config": Path(__file__).resolve().parents[1] / "configs" / "execution.example.json",
        "cache_dir": root / "cache",
    }


def test_check_functional_validates_join(functional_env: dict) -> None:
    output = functional_env["root"] / "check"
    exit_code = run_check_functional(
        functional_env["functional_config"],
        functional_env["prepared"],
        functional_env["generation_run"],
        functional_env["cleaned"],
        functional_env["execution_config"],
        output,
    )
    assert exit_code == 0
    payload = json.loads((output / "functional_check.json").read_text(encoding="utf-8"))
    assert payload["sample_count"] == 18


def test_build_inputs_rejects_stage_mismatch(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    source = env["generation_run"] / "generations.jsonl"
    rows = [
        json.loads(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows[0]["identity"]["stage"] = "holdout"
    tampered = tmp_path / "tampered-generation"
    tampered.mkdir()
    (tampered / "generations.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    with pytest.raises(FunctionalInputError):
        run_check_functional(
            env["functional_config"],
            env["prepared"],
            tampered,
            env["cleaned"],
            env["execution_config"],
            tmp_path / "check-stage-mismatch",
        )


def test_build_inputs_rejects_task_outside_stage(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    config = json.loads(env["functional_config"].read_text(encoding="utf-8"))
    config["task_ids"] = ["BigCodeBench/999999"]
    bad_config = tmp_path / "functional-bad-task.json"
    bad_config.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(FunctionalInputError):
        run_check_functional(
            bad_config,
            env["prepared"],
            env["generation_run"],
            env["cleaned"],
            env["execution_config"],
            tmp_path / "check-bad-task",
        )


def test_build_inputs_rejects_batch_mismatch(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    config = json.loads(env["functional_config"].read_text(encoding="utf-8"))
    config["batch_id"] = "other-batch"
    bad_config = tmp_path / "functional-bad-batch.json"
    bad_config.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(FunctionalInputError):
        run_check_functional(
            bad_config,
            env["prepared"],
            env["generation_run"],
            env["cleaned"],
            env["execution_config"],
            tmp_path / "check-bad-batch",
        )


def test_evaluate_functional_cache_hit_and_miss(functional_env: dict) -> None:
    env = functional_env
    run_one = env["root"] / "functional-run-1"
    backend = _FunctionalBackend()
    assert run_evaluate_functional(
        env["functional_config"], env["prepared"], env["generation_run"], env["cleaned"],
        env["execution_config"], env["cache_dir"], run_one, backend=backend,
    ) == 0
    metrics = json.loads((run_one / "functional_metrics.json").read_text(encoding="utf-8"))
    assert metrics["pass@1"]["defined"] is True
    assert metrics["pass@1"]["value"] == 1.0
    # repeats=1 cannot estimate pass@3/@5 (n<k is undefined).
    assert metrics["pass@3"]["defined"] is False
    assert metrics["pass@5"]["defined"] is False
    assert len([a for a in backend.actions if a[0] == "create"]) == 18

    # Second run with the same cache root must be served entirely from cache.
    run_two = env["root"] / "functional-run-2"
    backend_two = _FunctionalBackend()
    assert run_evaluate_functional(
        env["functional_config"], env["prepared"], env["generation_run"], env["cleaned"],
        env["execution_config"], env["cache_dir"], run_two, backend=backend_two,
    ) == 0
    assert [a for a in backend_two.actions if a[0] == "create"] == []
    manifest = json.loads((run_two / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["cache_hits"] == 18

    # Resume the first run: nothing left to do.
    assert run_resume_functional(run_two, backend=_FunctionalBackend()) == 0

    # Changing the source run_config bytes invalidates the functional fingerprint.
    run_config = env["generation_run"] / "run_config.json"
    run_config.write_bytes(run_config.read_bytes() + b"\n")
    run_three = env["root"] / "functional-run-3"
    backend_three = _FunctionalBackend()
    assert run_evaluate_functional(
        env["functional_config"], env["prepared"], env["generation_run"], env["cleaned"],
        env["execution_config"], env["cache_dir"], run_three, backend=backend_three,
    ) == 0
    assert len([a for a in backend_three.actions if a[0] == "create"]) == 18


def test_resume_functional_rechecks_fingerprint(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    gen = tmp_path / "gen-run"
    shutil.copytree(env["generation_run"], gen)
    run = tmp_path / "functional-run"
    backend = _FunctionalBackend()
    assert run_evaluate_functional(
        env["functional_config"], env["prepared"], gen, env["cleaned"],
        env["execution_config"], tmp_path / "cache", run, backend=backend,
    ) == 0
    first = len([a for a in backend.actions if a[0] == "create"])
    assert first == 18

    # Unchanged inputs: resume reuses prior results without executing.
    assert run_resume_functional(run, backend=backend) == 0
    assert len([a for a in backend.actions if a[0] == "create"]) == first

    # Changed run_config bytes change the F1 fingerprint: resume must re-evaluate.
    run_config = gen / "run_config.json"
    run_config.write_bytes(run_config.read_bytes() + b"\n")
    assert run_resume_functional(run, backend=backend) == 0
    assert len([a for a in backend.actions if a[0] == "create"]) == 2 * first


def test_resume_functional_repairs_torn_tail(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    gen = tmp_path / "gen-run-torn"
    shutil.copytree(env["generation_run"], gen)
    run = tmp_path / "functional-run-torn"
    backend = _FunctionalBackend()
    assert run_evaluate_functional(
        env["functional_config"], env["prepared"], gen, env["cleaned"],
        env["execution_config"], tmp_path / "cache-torn", run, backend=backend,
    ) == 0
    first = len([a for a in backend.actions if a[0] == "create"])
    assert first == 18

    # Simulate a crash after the last complete record: drop it and leave a torn
    # fragment without a trailing newline (F-02 reproduction).
    results_path = run / "functional_results.jsonl"
    lines = results_path.read_bytes().splitlines(keepends=True)
    results_path.write_bytes(b"".join(lines[:-1]) + b'{"sample_id":"torn"')

    assert run_resume_functional(run, backend=backend) == 0

    parsed = [
        json.loads(raw)
        for raw in results_path.read_bytes().splitlines()
        if raw.strip()
    ]
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    # The torn fragment must not swallow the record written after it: the file
    # and the manifest agree, and nothing is re-executed.
    assert len(parsed) == 18
    assert manifest["result_count"] == len(parsed)
    assert manifest["status"] == "complete"
    assert len([a for a in backend.actions if a[0] == "create"]) == first
    assert (run / "functional_results.jsonl.tail").read_bytes() == b'{"sample_id":"torn"'


def test_build_inputs_rejects_repeat_count_mismatch(functional_env: dict, tmp_path: Path) -> None:
    env = functional_env
    config = json.loads(env["functional_config"].read_text(encoding="utf-8"))
    config["repeats"] = 2  # generation only contains repeat 0
    bad_config = tmp_path / "functional-bad-repeats.json"
    bad_config.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(FunctionalInputError):
        run_check_functional(
            bad_config,
            env["prepared"],
            env["generation_run"],
            env["cleaned"],
            env["execution_config"],
            tmp_path / "check-bad-repeats",
        )
