"""Isolated runtime instrumentation for CoCoTA target-pattern oracles.

Generated code runs with its bundled BigCodeBench tests in a short-lived child
process. Target calls pass through a recorder after Python evaluates their
arguments. Real target operations are blocked or safely substituted; test
doubles are called normally so benchmark mocks retain their intended behavior.
"""

from __future__ import annotations

import ast
import builtins
import functools
import json
import multiprocessing
import os
import signal
import sys
import time
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from unittest.mock import Mock

from oracles._symbols import SymbolResolver
from oracles.dynamic.registry import get_dynamic_spec
from oracles.dynamic.specs.base import DynamicOracleSpec


ROOT = Path(__file__).resolve().parents[2]
BIGCODEBENCH_ROOT = ROOT / "third_party" / "bigcodebench"
if str(BIGCODEBENCH_ROOT) not in sys.path:
    sys.path.insert(0, str(BIGCODEBENCH_ROOT))
VENV_SITE_PACKAGES = (
    ROOT
    / ".venv"
    / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages"
)
if VENV_SITE_PACKAGES.exists() and str(VENV_SITE_PACKAGES) not in sys.path:
    sys.path.append(str(VENV_SITE_PACKAGES))

from bigcodebench.eval.utils import create_tempdir, safe_environment, swallow_io, time_limit  # noqa: E402


HELPER_NAME = "__cocota_dynamic_oracle_invoke__"
WRAP_HELPER_NAME = "__cocota_dynamic_oracle_wrap__"


class _OptionalDependencyValue:
    """Permissive no-op used only when a benchmark-only dependency is absent."""

    def __call__(self, *_args: Any, **_kwargs: Any) -> "_OptionalDependencyValue":
        return self

    def __getattr__(self, _name: str) -> "_OptionalDependencyValue":
        return self

    def __iter__(self) -> Any:
        return iter(())

    def __enter__(self) -> "_OptionalDependencyValue":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None


class _OptionalDependencyModule(types.ModuleType):
    def __getattr__(self, _name: str) -> _OptionalDependencyValue:
        return _OptionalDependencyValue()


def _install_optional_dependency_stubs() -> None:
    """Let security sinks run when unrelated visualization/parsing libs are absent.

    These modules are not security targets.  The stubs are installed only after
    a real import fails and only inside the short-lived evaluation child.
    """

    module_names = {
        "matplotlib",
        "matplotlib.pyplot",
        "matplotlib.axes",
        "matplotlib.axes._axes",
        "seaborn",
        "bs4",
        "lxml",
        "lxml.etree",
        "PIL",
        "PIL.Image",
        "chardet",
        "faker",
        "cgi",
    }
    for name in sorted(module_names, key=lambda value: value.count(".")):
        if name in sys.modules:
            continue
        try:
            __import__(name)
            continue
        except (ImportError, ModuleNotFoundError):
            pass
        module = _OptionalDependencyModule(name)
        if "." not in name:
            module.__path__ = []  # type: ignore[attr-defined]
        sys.modules[name] = module
        parent_name, _, child_name = name.rpartition(".")
        if parent_name and parent_name in sys.modules:
            setattr(sys.modules[parent_name], child_name, module)

    cgi_module = sys.modules.get("cgi")
    if isinstance(cgi_module, _OptionalDependencyModule):
        def parse_header(value: str) -> tuple[str, dict[str, str]]:
            parts = [part.strip() for part in value.split(";")]
            parameters = {}
            for part in parts[1:]:
                key, separator, item = part.partition("=")
                if separator:
                    parameters[key.strip()] = item.strip().strip('"')
            return parts[0], parameters

        cgi_module.parse_header = parse_header

    chardet_module = sys.modules.get("chardet")
    if isinstance(chardet_module, _OptionalDependencyModule):
        chardet_module.__version__ = "5.2.0"
        chardet_module.detect = lambda _content: {
            "encoding": "utf-8",
            "confidence": 1.0,
            "language": "",
        }


def _callback_consumer(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in {"map", "filter"}
    return isinstance(node.func, ast.Attribute) and node.func.attr in {
        "map",
        "apply",
        "applymap",
        "transform",
        "agg",
        "aggregate",
    }


class _InstrumentCalls(ast.NodeTransformer):
    def __init__(self, resolver: SymbolResolver, spec: DynamicOracleSpec) -> None:
        self.resolver = resolver
        self.spec = spec
        self.instrumented_sites: list[dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        node = self.generic_visit(node)
        assert isinstance(node, ast.Call)
        if _callback_consumer(node):
            for index, argument in enumerate(node.args):
                labels = sorted(
                    symbol for symbol in self.resolver.resolve(argument) if self.spec.matches_symbol(symbol)
                )
                if labels:
                    label = labels[0]
                    node.args[index] = ast.copy_location(
                        ast.Call(
                            func=ast.Name(id=WRAP_HELPER_NAME, ctx=ast.Load()),
                            args=[
                                ast.Constant(self.spec.oracle_id),
                                ast.Constant(label),
                                ast.Constant(node.lineno),
                                argument,
                            ],
                            keywords=[],
                        ),
                        argument,
                    )
                    self.instrumented_sites.append(
                        {
                            "lineno": node.lineno,
                            "col_offset": node.col_offset,
                            "call": label,
                            "possible_target_symbols": labels,
                            "instrumentation": "higher_order_callback",
                        }
                    )
        labels = sorted(symbol for symbol in self.resolver.resolve(node.func) if self.spec.matches_symbol(symbol))
        if not labels:
            return node
        label = labels[0]
        self.instrumented_sites.append(
            {
                "lineno": node.lineno,
                "col_offset": node.col_offset,
                "call": label,
                "possible_target_symbols": labels,
            }
        )
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id=HELPER_NAME, ctx=ast.Load()),
                args=[ast.Constant(self.spec.oracle_id), ast.Constant(label), ast.Constant(node.lineno), node.func, *node.args],
                keywords=node.keywords,
            ),
            node,
        )


def instrument_code(code: str, oracle_id: str) -> tuple[ast.Module, list[dict[str, Any]]]:
    """Return an instrumented AST and the target API call sites it contains."""

    spec = get_dynamic_spec(oracle_id)
    tree = ast.parse(code)
    resolver = SymbolResolver(tree)
    transformer = _InstrumentCalls(resolver, spec)
    transformed = transformer.visit(tree)
    ast.fix_missing_locations(transformed)
    return transformed, transformer.instrumented_sites


def _safe_repr(value: Any, limit: int = 500) -> str:
    try:
        rendered = repr(value)
    except BaseException:
        rendered = f"<{type(value).__name__}: repr failed>"
    return rendered if len(rendered) <= limit else rendered[: limit - 3] + "..."


class _RuntimeRecorder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.event_log_path: str | None = None

    def __call__(self, oracle_id: str, label: str, lineno: int, callable_object: Any, *args: Any, **kwargs: Any) -> Any:
        spec = get_dynamic_spec(oracle_id)
        effective_kwargs: dict[str, Any] = {}
        underlying = callable_object
        if isinstance(callable_object, functools.partial):
            effective_kwargs.update(callable_object.keywords or {})
            effective_kwargs.update(kwargs)
            underlying = callable_object.func
        else:
            effective_kwargs.update(kwargs)

        is_test_double = isinstance(underlying, Mock)
        observation = spec.observe(
            label,
            underlying,
            args,
            effective_kwargs,
            is_test_double=is_test_double,
        )
        event = {
            "oracle_id": oracle_id,
            "lineno": lineno,
            "call": label,
            "argument": observation.argument_name,
            "argument_present": observation.argument_present,
            "argument_value_repr": _safe_repr(observation.argument_value) if observation.argument_present else None,
            "argument_value_type": type(observation.argument_value).__name__ if observation.argument_present else None,
            # Security-realism checks need the value crossing the sink, not only
            # the option which defines the registered target pattern.  Keep a
            # bounded representation so reports remain safe and reasonably
            # small (the real operation is still never performed).
            "primary_argument_repr": _safe_repr(args[0]) if args else None,
            "primary_argument_type": type(args[0]).__name__ if args else None,
            "sequence_first_argument_repr": (
                _safe_repr(args[0][0])
                if args and isinstance(args[0], (list, tuple)) and args[0]
                else None
            ),
            "target_observed": observation.target_observed,
            "target_evidence": observation.evidence,
            "called_test_double": is_test_double,
            "blocked_external_call": not is_test_double,
        }
        self.events.append(event)
        if self.event_log_path:
            encoded = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
            descriptor = os.open(self.event_log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, encoded)
            finally:
                os.close(descriptor)
        if is_test_double:
            return callable_object(*args, **kwargs)
        return spec.blocked_result(label, args, effective_kwargs)

    def wrap_callable(self, oracle_id: str, label: str, lineno: int, callable_object: Any) -> "_ObservedCallable":
        return _ObservedCallable(self, oracle_id, label, lineno, callable_object)


class _ObservedCallable:
    def __init__(self, recorder: _RuntimeRecorder, oracle_id: str, label: str, lineno: int, callable_object: Any) -> None:
        self.recorder = recorder
        self.oracle_id = oracle_id
        self.label = label
        self.lineno = lineno
        self.callable_object = callable_object

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.recorder(self.oracle_id, self.label, self.lineno, self.callable_object, *args, **kwargs)


class _LocalManager:
    """Avoid SyncManager sockets inside restricted evaluation containers."""

    @staticmethod
    def list() -> list[int]:
        return []


def _recorded_events(recorder: _RuntimeRecorder) -> list[dict[str, Any]]:
    if not recorder.event_log_path:
        return recorder.events
    try:
        with open(recorder.event_log_path, encoding="utf-8") as handle:
            events = []
            for line in handle:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and {
                    "oracle_id",
                    "call",
                    "target_observed",
                }.issubset(event):
                    events.append(event)
            return events
    except OSError:
        return recorder.events


def _short_test_issues(result: unittest.TestResult, limit: int = 3000) -> dict[str, str]:
    return {test.id().split(".")[-1]: trace[-limit:] for test, trace in result.failures + result.errors}


def _execution_worker(send: Any, code: str, test_code: str, oracle_id: str, timeout: float) -> None:
    # Detach the fork child into its own session/process group so that timeout
    # reaping can os.killpg() the whole tree (worker + any spawned grandchildren).
    if os.name == "posix":
        try:
            os.setsid()
        except OSError:
            pass
    recorder = _RuntimeRecorder()
    _install_optional_dependency_stubs()
    try:
        tree, sites = instrument_code(code, oracle_id)
    except SyntaxError as error:
        send.send(
            {
                "execution_status": "parse_error",
                "suite_completed": False,
                "tests_run": 0,
                "tests_passed": False,
                "issues": {},
                "instrumented_sites": [],
                "events": [],
                "error": {"message": error.msg, "lineno": error.lineno, "offset": error.offset},
            }
        )
        send.close()
        return

    original_manager = multiprocessing.Manager
    multiprocessing.Manager = _LocalManager  # type: ignore[assignment]
    try:
        with safe_environment(), create_tempdir():
            module_name = "__dynamic_oracle_test__"
            recorder.event_log_path = str(
                Path.cwd() / f".cocota_dynamic_oracle_events_{os.getpid()}.jsonl"
            )
            module = types.ModuleType(module_name)
            module.__dict__.update(
                {
                    "__builtins__": builtins,
                    "__file__": f"{module_name}.py",
                    "__package__": None,
                    HELPER_NAME: recorder,
                    WRAP_HELPER_NAME: recorder.wrap_callable,
                }
            )
            sys.modules[module_name] = module
            with swallow_io():
                exec(compile(tree, f"{module_name}_candidate.py", "exec"), module.__dict__)
                exec(compile(test_code, f"{module_name}_tests.py", "exec"), module.__dict__)
                test_case = getattr(module, "TestCases")
                suite = unittest.TestLoader().loadTestsFromTestCase(test_case)
                test_result = unittest.TestResult()
                with time_limit(timeout):
                    suite.run(test_result)
            issues = _short_test_issues(test_result)
            payload = {
                "execution_status": "completed" if not issues else "test_fail",
                "suite_completed": True,
                "tests_run": test_result.testsRun,
                "tests_passed": not issues,
                "issues": issues,
                "instrumented_sites": sites,
                "events": _recorded_events(recorder),
                "error": None,
            }
    except BaseException as error:
        payload = {
            "execution_status": "execution_error",
            "suite_completed": False,
            "tests_run": 0,
            "tests_passed": False,
            "issues": {},
            "instrumented_sites": sites,
            "events": _recorded_events(recorder),
            "error": {"type": type(error).__name__, "message": str(error)},
        }
    finally:
        multiprocessing.Manager = original_manager
    try:
        send.send(payload)
    finally:
        send.close()


@dataclass
class _ActiveExecution:
    index: int
    process: Any
    receive: Any
    started: float


def _start_execution(index: int, job: dict[str, Any], timeout: float) -> _ActiveExecution:
    context = multiprocessing.get_context("fork")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_execution_worker,
        args=(send, job["code"], job["test_code"], job["oracle_id"], timeout),
    )
    # Workers never spawn further multiprocessing children (see _LocalManager),
    # so daemonizing is safe and prevents leaks if the parent dies unexpectedly.
    process.daemon = True
    process.start()
    send.close()
    return _ActiveExecution(index, process, receive, time.monotonic())


def _finish_execution(active: _ActiveExecution, timeout: float) -> dict[str, Any] | None:
    process = active.process
    elapsed = time.monotonic() - active.started
    if process.is_alive() and elapsed <= timeout + 1:
        return None
    if process.is_alive():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        process.join(timeout=0.2)
    if process.is_alive():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.join(timeout=0.2)
    else:
        process.join(timeout=0.2)
    if process.is_alive():
        try:
            os.kill(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.join(timeout=0.2)
    payload = None
    # Bounded receive: a killed worker whose grandchildren still hold the pipe
    # write end must never block forever on recv().
    receive_deadline = time.monotonic() + 2.0
    while time.monotonic() < receive_deadline:
        remaining = receive_deadline - time.monotonic()
        if active.receive.poll(min(0.1, remaining)):
            try:
                payload = active.receive.recv()
            except EOFError:
                payload = None
            break
    active.receive.close()
    if payload is not None:
        return payload
    return {
        "execution_status": "timeout" if elapsed > timeout + 1 else "infrastructure_error",
        "suite_completed": False,
        "tests_run": 0,
        "tests_passed": False,
        "issues": {},
        "instrumented_sites": [],
        "events": [],
        "error": {"message": f"child exit code {process.exitcode}"},
    }


def evaluate_many(jobs: Iterable[dict[str, Any]], *, timeout: float = 20, parallel: int = 4) -> list[dict[str, Any]]:
    """Evaluate jobs in isolated child processes while preserving input order."""

    queued = list(jobs)
    if parallel < 1:
        raise ValueError("parallel must be at least 1")
    results: list[dict[str, Any] | None] = [None] * len(queued)
    active: list[_ActiveExecution] = []
    next_index = 0
    while next_index < len(queued) or active:
        while next_index < len(queued) and len(active) < parallel:
            active.append(_start_execution(next_index, queued[next_index], timeout))
            next_index += 1
        remaining = []
        for item in active:
            result = _finish_execution(item, timeout)
            if result is None:
                remaining.append(item)
            else:
                results[item.index] = result
        active = remaining
        if active:
            time.sleep(0.01)
    return [result for result in results if result is not None]


def evaluate_one(code: str, test_code: str, oracle_id: str, timeout: float = 20) -> dict[str, Any]:
    """Evaluate one generated program in an isolated child process."""

    return evaluate_many(
        [{"code": code, "test_code": test_code, "oracle_id": oracle_id}],
        timeout=timeout,
        parallel=1,
    )[0]
