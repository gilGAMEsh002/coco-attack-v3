"""Direct example code check (I3) tests.

Asset-dependent checks are skipped when the read-only CoCo-Attack assets are not
present.  The functional layer is exercised with a simulated container backend;
no real Docker clean-example run is performed here.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from coco_attack.assets.artifacts import sha256_file
from coco_attack.cli import main
from coco_attack.evaluation.sast import scan_sample, tool_available
from coco_attack.iteration.code_check import (
    CodeCheckInputError,
    ExampleCheckRequest,
    load_fewshot_example,
    run_example_code_check,
)

REPO_DIR = Path(__file__).resolve().parents[2]
ASSETS_DIR = REPO_DIR / "cocota_data_eval_result"
ASSETS_AVAILABLE = ASSETS_DIR.is_dir() and (REPO_DIR / "dspy").is_dir()
SEMGREP_RULES = ASSETS_DIR / "third_party" / "semgrep"
EXECUTION_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "execution.example.json"
COMBINATION = "cwe078-0"
TASK_ID = "BigCodeBench/348"
FEWSHOT_EXPERIMENT = "cwe078_clean_fewshot"
FEWSHOT_INDEX = 1  # BigCodeBench/348 in this experiment
SEMGREP_AVAILABLE = ASSETS_AVAILABLE and tool_available("semgrep") and SEMGREP_RULES.is_dir()

# Asset-dependent tests are marked individually so logic-only tests still run
# when the read-only asset tree is absent (instead of the whole module skipping).
requires_assets = pytest.mark.skipif(
    not ASSETS_AVAILABLE,
    reason="read-only CoCo-Attack assets are not present in this workspace",
)
requires_semgrep = pytest.mark.skipif(
    not SEMGREP_AVAILABLE, reason="semgrep or local rules unavailable"
)


# --------------------------------------------------------------------------- #
# Simulated functional backend (adapted from test_functional_pipeline)
# --------------------------------------------------------------------------- #


class _ExampleCheckBackend:
    """A container backend simulator with a small scenario switch."""

    def __init__(self, scenario: str = "passing") -> None:
        self.scenario = scenario
        self.actions: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.removed: set[str] = set()

    def probe(self) -> dict:
        return {"available": True}

    def image_inspect(self, reference: str):
        return {"Id": "sha256:" + "b" * 64}

    def inspect_raw(self, container_id: str):
        return {
            "Id": container_id,
            "Image": "sha256:" + "b" * 64,
            "HostConfig": {},
            "Mounts": [],
        }

    @staticmethod
    def _mount(spec, target: str) -> str:
        for mount in spec.mounts:
            if mount.target == target:
                return mount.source
        raise AssertionError(f"missing mount {target}")

    def _payload(self, func_request: dict) -> dict | None:
        if self.scenario == "incomplete":
            return None
        payload = {
            "schema_version": "1",
            "functional_schema": "functional-payload-v1",
            "harness_version": "functional-harness-v5",
            "sample_id": func_request["sample_id"],
            "attempt_id": func_request["attempt_id"],
            "entry_point": func_request["entry_point"],
            "code_sha256": func_request["code_sha256"],
            "tests_sha256": func_request["tests_sha256"],
            "test_details": [],
        }
        if self.scenario == "syntax_fail":
            payload["load"] = {
                "solution_compiled": False,
                "solution_error": "SyntaxError: invalid syntax",
                "entry_present": False,
                "tests_compiled": True,
                "tests_error": None,
                "loader_error": None,
                "tests_discovered": 1,
            }
            payload["run"] = {
                "tests_run": 0,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
                "suite_completed": False,
                "failure_stage": "load",
                "candidate_timeout": False,
            }
            return payload
        payload["load"] = {
            "solution_compiled": True,
            "solution_error": None,
            "entry_present": True,
            "tests_compiled": True,
            "tests_error": None,
            "loader_error": None,
            "tests_discovered": 1,
        }
        payload["run"] = {
            "tests_run": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
            "suite_completed": True,
            "failure_stage": None,
            "candidate_timeout": False,
        }
        return payload

    def create(self, spec) -> str:
        from coco_attack.assets.artifacts import canonical_json_bytes
        from coco_attack.execution.contracts import ExecutionBackendError

        if self.scenario == "outer_unavailable":
            raise ExecutionBackendError(
                "simulated docker outage", error_class="docker_unavailable"
            )
        cid = f"cid-{len(self.actions)}"
        self.actions.append(("create", spec.name))
        staging = self._mount(spec, "/in")
        output = self._mount(spec, "/out")
        request = json.loads((Path(staging) / "request.json").read_text(encoding="utf-8"))
        func_request = json.loads(
            (Path(staging) / "func_request.json").read_text(encoding="utf-8")
        )
        argv = list(spec.argv)
        nonce = argv[argv.index("--nonce") + 1]
        payload = self._payload(func_request)
        envelope = {
            "schema_version": "1",
            "sample_id": request["sample_id"],
            "attempt_id": request["attempt_id"],
            "stage": request["stage"],
            "result_schema": request["result_schema"],
            "nonce": nonce,
            "payload_valid": payload is not None,
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

        if container_id in self.removed or container_id not in self.containers:
            return None
        return ContainerState(
            container_id=container_id,
            name="coco-attack-example-check",
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


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _request(output_dir: Path, **overrides) -> ExampleCheckRequest:
    base = dict(
        combination_id=COMBINATION,
        task_id=TASK_ID,
        code="    return 1\n",
        code_source="test:body",
        action_id="test-action",
        output_dir=output_dir,
        assets_root=ASSETS_DIR,
        run_functional=False,
        run_static=False,
        run_semgrep=False,
    )
    base.update(overrides)
    return ExampleCheckRequest(**base)


def _ledger_events(output_dir: Path) -> list[dict]:
    path = output_dir / "ledger.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --------------------------------------------------------------------------- #
# 1. Input errors
# --------------------------------------------------------------------------- #


@requires_assets
def test_unknown_combination_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(CodeCheckInputError) as error:
        run_example_code_check(_request(tmp_path / "a", combination_id="nope-0"))
    assert "unknown combination" in str(error.value)


@requires_assets
def test_unknown_task_id_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(CodeCheckInputError) as error:
        run_example_code_check(_request(tmp_path / "b", task_id="BigCodeBench/999999"))
    assert "unknown task_id" in str(error.value)


@requires_assets
def test_provided_code_prompt_must_match_registry(tmp_path: Path) -> None:
    with pytest.raises(CodeCheckInputError) as error:
        run_example_code_check(
            _request(tmp_path / "c", code_prompt="def task_func():\n    pass\n")
        )
    assert "code_prompt" in str(error.value)


def test_bad_code_input_mode_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(CodeCheckInputError) as error:
        run_example_code_check(
            _request(tmp_path / "d", code_input_mode="nonsense")
        )
    assert "code_input_mode" in str(error.value)


# --------------------------------------------------------------------------- #
# 2. Example outside the evaluation set, direct path
# --------------------------------------------------------------------------- #


@requires_assets
def test_example_outside_evaluation_set_direct_path(tmp_path: Path) -> None:
    task_file = ASSETS_DIR / "data/BigCodeBench/CWE-078-0.jsonl"
    fewshot_file = (
        ASSETS_DIR / "prompts_old/experiments/cwe078/cwe078_clean_fewshot/fewshot.json"
    )
    meta_file = fewshot_file.with_name("meta.json")
    before = {str(path): sha256_file(path) for path in (task_file, fewshot_file, meta_file)}

    example = load_fewshot_example(
        assets_root=ASSETS_DIR,
        combination_id=COMBINATION,
        experiment=FEWSHOT_EXPERIMENT,
        index=FEWSHOT_INDEX,
    )
    assert example.task_id == TASK_ID

    output = tmp_path / "direct"
    result = run_example_code_check(
        _request(
            output,
            code=example.code,
            code_source="fewshot:cwe078_clean_fewshot#1",
            action_id="fewshot:cwe078_clean_fewshot#1",
            run_static=True,
            run_semgrep=True,
            semgrep_config=SEMGREP_RULES,
        )
    )

    assert result["check_source"] == "example"
    assert result["static"]["state"] == "executed"
    assert result["static"]["verdict"] in ("target_absent", "target_present")
    shared = result["code"]["final_code_sha256"]
    assert result["static"]["final_code_sha256"] == shared
    assert result["semgrep"]["final_code_sha256"] == shared
    if not SEMGREP_AVAILABLE:
        assert result["semgrep"]["state"] == "unavailable"
    functional_layer = next(
        item for item in result["layers"] if item["layer"] == "functional"
    )
    assert functional_layer["state"] == "skipped"

    after = {str(path): sha256_file(path) for path in (task_file, fewshot_file, meta_file)}
    assert after == before
    assert (output / "check_result.json").is_file()
    assert (output / "request.json").is_file()


# --------------------------------------------------------------------------- #
# 3. Syntax error stays parse_error
# --------------------------------------------------------------------------- #


@requires_assets
def test_syntax_error_stays_parse_error_and_functional_fails(tmp_path: Path) -> None:
    result = run_example_code_check(
        _request(
            tmp_path / "syntax",
            code="def task_func(:\n    pass\n",
            code_input_mode="final_code",
            run_static=True,
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("syntax_fail"),
        )
    )
    assert result["syntax"]["syntax_ok"] is False
    assert result["syntax"]["syntax_error"]["lineno"] == 1
    assert result["static"]["verdict"] == "parse_error"
    assert result["static"]["verdict"] != "target_absent"
    assert result["functional"]["outcome"] == "failed"
    assert result["functional"]["passed"] is not True
    for gate_key in (
        "passed",
        "success",
        "gate",
        "gate_verdict",
        "allowed_into_b",
        "attack_success",
        "evaluation_ids",
        "search_ids",
    ):
        assert gate_key not in result


# --------------------------------------------------------------------------- #
# 4. Semgrep unavailable keeps static facts
# --------------------------------------------------------------------------- #


@requires_assets
def test_semgrep_config_none_is_unavailable(tmp_path: Path) -> None:
    result = run_example_code_check(
        _request(tmp_path / "nosemgrep", run_static=True, run_semgrep=True, semgrep_config=None)
    )
    assert result["semgrep"]["state"] == "unavailable"
    assert result["semgrep"]["status"] == "unavailable"
    assert result["semgrep"]["detected"] is None
    assert result["static"]["state"] == "executed"
    assert result["static"]["verdict"] in ("target_absent", "target_present")


# --------------------------------------------------------------------------- #
# 5. Consumption
# --------------------------------------------------------------------------- #


@requires_assets
def test_consumption_records_once_per_invocation(tmp_path: Path) -> None:
    first = tmp_path / "consumption-1"
    result = run_example_code_check(
        _request(
            first,
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("passing"),
        )
    )
    assert result["functional"]["outcome"] == "passed"
    assert result["consumption"]["local_test_executions"] == 1
    events = [e for e in _ledger_events(first) if e["event_type"] == "execution_recorded"]
    assert len(events) == 1
    assert events[0]["payload"]["role"] == "local_test"
    assert result["consumption"]["model_calls"] == 0
    assert result["consumption"]["model_tokens"] is None
    assert result["consumption"]["cost_usd"] is None

    second = tmp_path / "consumption-2"
    result_two = run_example_code_check(
        _request(
            second,
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("passing"),
        )
    )
    assert result_two["consumption"]["local_test_executions"] == 1
    events_two = [e for e in _ledger_events(second) if e["event_type"] == "execution_recorded"]
    assert len(events_two) == 1


@requires_assets
def test_repeat_invocation_into_same_dir_records_a_new_execution(tmp_path: Path) -> None:
    """A repeated explicit check is a new real execution, not a duplicate event."""

    output = tmp_path / "repeat"
    first = run_example_code_check(
        _request(
            output,
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("passing"),
        )
    )
    second = run_example_code_check(
        _request(
            output,
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("passing"),
        )
    )
    assert first["functional"]["outcome"] == "passed"
    assert second["functional"]["outcome"] == "passed"
    events = [e for e in _ledger_events(output) if e["event_type"] == "execution_recorded"]
    assert len(events) == 2
    accounting_ids = {e["payload"]["accounting_id"] for e in events}
    assert len(accounting_ids) == 2
    assert first["consumption"]["accounting_ids"] != second["consumption"]["accounting_ids"]


@requires_assets
def test_functional_incomplete_payload_is_indeterminate(tmp_path: Path) -> None:
    result = run_example_code_check(
        _request(
            tmp_path / "incomplete",
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("incomplete"),
        )
    )
    assert result["functional"]["outcome"] == "incomplete"
    assert result["functional"]["passed"] is None
    assert result["functional"]["state"] == "executed"


# --------------------------------------------------------------------------- #
# 6. Partial failure preserves other layers
# --------------------------------------------------------------------------- #


@requires_assets
def test_invalid_execution_config_keeps_static_facts(tmp_path: Path) -> None:
    output = tmp_path / "partial"
    result = run_example_code_check(
        _request(
            output,
            run_static=True,
            run_semgrep=False,
            run_functional=True,
            execution_config_path=tmp_path / "missing-execution.json",
        )
    )
    assert result["functional"]["state"] == "unavailable"
    assert result["functional"]["reason"].startswith("execution_unavailable")
    assert result["consumption"]["local_test_executions"] == 0
    assert _ledger_events(output) == []
    persisted = json.loads((output / "check_result.json").read_text(encoding="utf-8"))
    assert persisted["static"]["state"] == "executed"
    assert persisted["static"]["verdict"] in ("target_absent", "target_present")


@requires_assets
def test_outer_docker_unavailable_is_a_fact(tmp_path: Path) -> None:
    result = run_example_code_check(
        _request(
            tmp_path / "docker-down",
            run_functional=True,
            execution_config_path=EXECUTION_CONFIG,
            backend=_ExampleCheckBackend("outer_unavailable"),
        )
    )
    assert result["functional"]["state"] == "unavailable"
    assert result["functional"]["outcome"] == "unavailable"
    assert result["consumption"]["local_test_executions"] == 0


# --------------------------------------------------------------------------- #
# 7. Semgrep position evidence
# --------------------------------------------------------------------------- #


@requires_semgrep
def test_semgrep_alert_positions_real_scan(tmp_path: Path) -> None:
    code = "import subprocess\ndef f(x):\n    subprocess.run('echo ' + x, shell=True)\n"
    result = run_example_code_check(
        _request(
            tmp_path / "risky",
            code=code,
            code_input_mode="final_code",
            run_static=False,
            run_functional=False,
            run_semgrep=True,
            semgrep_config=SEMGREP_RULES,
        )
    )
    semgrep = result["semgrep"]
    assert semgrep["status"] == "completed"
    assert semgrep["detected"] is True
    alert = next(
        a for a in semgrep["evidence"]["alerts"] if "subprocess-shell-true" in a["rule_id"]
    )
    assert isinstance(alert["start_line"], int)
    assert alert["start_line"] == 3
    assert semgrep["rule_source_declaring_files"] == ["subprocess-shell-true.yml"]


@pytest.mark.skipif(not tool_available("semgrep"), reason="semgrep unavailable")
def test_scan_semgrep_errors_without_match_is_incomplete(monkeypatch, tmp_path: Path) -> None:
    from coco_attack.generation.contracts import SampleIdentity

    class _FakeSample:
        final_code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        sample_id = "sid"
        oracle_id = COMBINATION
        final_code_sha256 = "0" * 64
        task_snapshot_sha256 = "1" * 64
        identity = SampleIdentity(
            stage="search",
            batch_id="b",
            combination_id=COMBINATION,
            task_id="t",
            repeat_id=0,
            prompt_version="p",
            candidate_hash="c" * 8,
        )

    report = {"results": [], "errors": [{"message": "boom"}]}
    monkeypatch.setattr(
        "coco_attack.evaluation.sast._run",
        lambda argv, *, use_module, timeout_seconds: subprocess.CompletedProcess(
            argv, 1, stdout=json.dumps(report), stderr=""
        ),
    )
    record = scan_sample(
        _FakeSample(),
        evaluation_id="ev",
        action_id="act",
        tool="semgrep",
        target_rules=("subprocess-shell-true",),
        workdir=tmp_path / "wg-none",
        semgrep_config=str(tmp_path),
    )
    assert record.status == "incomplete"
    assert record.detected is None

    matched = {
        "results": [
            {
                "check_id": "subprocess-shell-true",
                "extra": {"severity": "ERROR"},
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 10},
            }
        ],
        "errors": [{"message": "boom"}],
    }
    monkeypatch.setattr(
        "coco_attack.evaluation.sast._run",
        lambda argv, *, use_module, timeout_seconds: subprocess.CompletedProcess(
            argv, 1, stdout=json.dumps(matched), stderr=""
        ),
    )
    record = scan_sample(
        _FakeSample(),
        evaluation_id="ev",
        action_id="act",
        tool="semgrep",
        target_rules=("subprocess-shell-true",),
        workdir=tmp_path / "wg-match",
        semgrep_config=str(tmp_path),
    )
    assert record.status == "incomplete"
    assert record.detected is True


# --------------------------------------------------------------------------- #
# 8. CLI smoke
# --------------------------------------------------------------------------- #


@requires_assets
def test_cli_check_example_code_smoke(tmp_path: Path) -> None:
    output = tmp_path / "cli"
    exit_code = main(
        [
            "check-example-code",
            "--assets-dir",
            str(ASSETS_DIR),
            "--combination",
            COMBINATION,
            "--task-id",
            TASK_ID,
            "--action-id",
            "cli-smoke",
            "--output-dir",
            str(output),
            "--code-source",
            "fewshot:cwe078_clean_fewshot#1",
            "--fewshot-experiment",
            FEWSHOT_EXPERIMENT,
            "--example-index",
            str(FEWSHOT_INDEX),
            "--no-functional",
            "--no-semgrep",
        ]
    )
    assert exit_code == 0
    result = json.loads((output / "check_result.json").read_text(encoding="utf-8"))
    assert result["check_source"] == "example"
    assert result["functional"]["state"] == "skipped"
