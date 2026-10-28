#!/usr/bin/env python3
"""Container-side PoC harness runner (production).

Runs inside the locked-down evaluator container as the child of
``/opt/coco/entrypoint.py``.  The host stages ``/in/layer_request.json`` and
reads the evidence payload from ``/out/payload.json``; the entrypoint publishes
the supervisor envelope (child exit code, payload validity, nonce).

The runner executes the candidate code with a per-case driver, then checks an
*impact*: a nonce-named marker file, or a hit on a local TLS server.  Unlike the
existing dynamic oracle, the sink instrumentation does not block or substitute
the call; it records the target argument and lets the real call run.

Self-contained (stdlib + requests + PyYAML) and deliberately does not import
``coco_attack``.  Writes only under ``/tmp``, ``/work`` and the requested
payload path (``/out/payload.json``).
"""

from __future__ import annotations

import argparse
import http.server
import io
import json
import os
import re
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
from typing import Any, Callable


PAYLOAD_SCHEMA = "poc-payload-v1"
MARKER_NAME_PREFIX = "cocota_poc_marker"
DEFAULT_MARKER_DIR = "/tmp"
# Directory-name carriers (CWE-078 tasks 326/350/1101) need a marker name
# without ``/``; ``/work`` lets the candidate create it next to its own files.
MARKER_DIRS = ("/tmp", "/work")
EVENT_PREFIX = "/tmp/cocota_sink_events"
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
URL_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
DEFAULT_URL_HOST = "127.0.0.1"
IMPACT_POLL_SECONDS = 2.0


# ---------------------------------------------------------------------------
# errors and helpers
# ---------------------------------------------------------------------------

class HarnessError(RuntimeError):
    """Raised when the harness (not the candidate) is at fault."""


class CandidateTimeout(TimeoutError):
    """Raised in the main thread when the candidate exceeds --timeout."""


def _short(value: Any, limit: int = 500) -> str:
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001
        text = f"<unrepresentable {type(value).__name__}>"
    return text[:limit]


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    data = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # The host operator does not own this file; publish it world-readable.
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _payload_base(case_id: Any, oracle_id: Any, nonce: Any = None) -> dict[str, Any]:
    return {
        "schema_version": PAYLOAD_SCHEMA,
        "case_id": case_id,
        "oracle_id": oracle_id,
        "status": "completed",
        "impact_observed": False,
        "impact_kind": "none",
        "evidence": {"nonce": nonce} if nonce is not None else {},
    }


def _harness_error(
    case_id: Any, oracle_id: Any, exc: BaseException, nonce: Any
) -> dict[str, Any]:
    payload = _payload_base(case_id, oracle_id)
    payload["status"] = "harness_error"
    payload["evidence"] = {
        "nonce": nonce,
        "harness_error": f"{type(exc).__name__}: {exc}",
        "traceback": traceback.format_exc()[-4000:],
    }
    return payload


def compute_marker(
    nonce: str, marker_dir: str = DEFAULT_MARKER_DIR
) -> tuple[str, str, str]:
    """Return ``(marker_dir, marker_name, marker_path)`` for a per-case marker.

    ``marker_name`` is always a bare path component (no ``/``) so it can be
    used as a directory name in payload templates; ``marker_path`` is the
    absolute path used for the impact check.
    """
    if marker_dir not in MARKER_DIRS:
        raise HarnessError(
            f"request.marker_dir must be one of {list(MARKER_DIRS)} "
            f"(got {_short(marker_dir, 80)})"
        )
    marker_name = f"{MARKER_NAME_PREFIX}_{nonce}"
    return marker_dir, marker_name, os.path.join(marker_dir, marker_name)


def substitute_payload(template: Any, marker: str, marker_name: str) -> str:
    """Expand ``{marker_name}`` (bare) and ``{marker}`` (absolute) templates."""
    return (
        str(template or "")
        .replace("{marker_name}", marker_name)
        .replace("{marker}", marker)
    )


# ---------------------------------------------------------------------------
# sink instrumentation (does NOT block: the real call still executes)
# ---------------------------------------------------------------------------

def preflight() -> dict[str, Any]:
    """Record which binaries and modules the harness can rely on."""
    import shutil  # noqa: PLC0415

    binaries = {}
    for name in ("sh", "bash", "tar", "ping", "g++", "Rscript", "pyenv",
                 "top", "xdg-open", "openssl", "wc", "split", "gzip", "wget"):
        binaries[name] = shutil.which(name) is not None
    modules = {}
    for name in ("requests", "yaml", "flask", "flask_restful", "pandas",
                 "bs4", "psutil", "numpy", "matplotlib", "seaborn"):
        try:
            __import__(name)
            modules[name] = True
        except Exception:  # noqa: BLE001
            modules[name] = False
    return {"binaries": binaries, "modules": modules}


def _first_token(cmd: Any) -> str:
    if isinstance(cmd, str):
        text = cmd.strip()
        return text.split()[0] if text else ""
    if isinstance(cmd, (list, tuple)) and cmd:
        return str(cmd[0])
    return ""


def classify_exception_origin(exc: Exception, oracle_id: str, facts: dict[str, Any]) -> str:
    """Separate candidate bugs from harness/environment faults.

    Called only for exceptions raised while invoking the candidate, so a
    missing binary (ping, tar, g++, ...) is attributed to the environment
    using the preflight table rather than to the candidate.
    """
    if isinstance(exc, HarnessError):
        return "harness_driver"
    if isinstance(exc, subprocess.CalledProcessError) and exc.returncode == 127:
        token = os.path.basename(_first_token(exc.cmd))
        if token and facts.get("binaries", {}).get(token) is False:
            return "harness_environment"
        return "candidate"
    if isinstance(exc, FileNotFoundError):
        filename = getattr(exc, "filename", "") or ""
        token = os.path.basename(filename)
        # Only a bare exec name (no directory component) can be a missing
        # binary; a candidate opening "/work/top" is a candidate bug.
        if filename and not os.path.dirname(filename) and token and facts.get("binaries", {}).get(token) is False:
            return "harness_environment"
        text = str(exc).lower()
        if "compiler" in text and facts.get("binaries", {}).get("g++") is False:
            return "harness_environment"
        if "rscript" in text and facts.get("binaries", {}).get("Rscript") is False:
            return "harness_environment"
        return "candidate"
    if oracle_id == "cwe295-0" and isinstance(exc, (KeyError, ValueError)):
        # The probe server returns a fixed HTML page; CSV/JSON tasks may raise
        # while parsing it, after the TLS request already succeeded.
        return "harness_probe"
    return "candidate"


def install_sinks(oracle_id: str, ctx: dict[str, Any], event_log: str) -> Callable[[], None]:
    """Wrap the target API so we can tell whether the sink was reached.

    The wrapper records and then calls the original function.  ``event_log``
    carries a per-case nonce so a candidate cannot forge evidence at a fixed
    path.

    Events carry two independent bits:
    - ``registered_target``: the registered call shape was observed
      (subprocess + truthy shell / requests.get + false verify / yaml.load +
      Loader=yaml.Loader);
    - ``other_target_api``: a different API with the same security effect
      (os.system, Session.request, yaml.unsafe_load, pickle.loads, ...).
    """
    events: list[dict[str, Any]] = ctx.setdefault("sink_events", [])
    ctx["event_log"] = event_log
    # Thread-local depth: concurrent candidate threads must not suppress each
    # other's sink events. Forked workers inherit a fresh depth in practice
    # because the pool forks before the sink call.
    ctx["_sink_state"] = threading.local()
    if os.path.exists(event_log):
        os.remove(event_log)
    restores: list[tuple[Any, str, Any]] = []

    def record(label: str, family: str, target: bool, registered: bool,
               extra: dict[str, Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        event = {
            "api": label,
            "api_family": family,
            "target_argument_observed": bool(target),
            "registered_target": bool(target) and bool(registered),
            "other_target_api": bool(target) and not bool(registered),
            "args": _short(args),
            "kwargs": _short(kwargs),
            **extra,
        }
        events.append(event)
        try:
            with open(event_log, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            ctx["event_write_failures"] = int(ctx.get("event_write_failures", 0)) + 1

    def wrap(owner: Any, name: str, label: str, family: str,
             classify: Callable[[tuple[Any, ...], dict[str, Any]], tuple[bool, dict[str, Any]]],
             registered: bool) -> None:
        original = getattr(owner, name, None)
        if original is None:
            return

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Do not record nested calls (run -> Popen, get -> request).
            state = ctx["_sink_state"]
            if getattr(state, "depth", 0):
                return original(*args, **kwargs)
            try:
                target, extra = classify(args, kwargs)
            except Exception:  # noqa: BLE001
                target, extra = False, {}
            record(label, family, target, registered, extra, args, kwargs)
            state.depth = getattr(state, "depth", 0) + 1
            try:
                return original(*args, **kwargs)
            finally:
                state.depth -= 1

        setattr(owner, name, wrapper)
        restores.append((owner, name, original))

    if oracle_id == "cwe078-0":
        def classify_subprocess(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
            shell = kwargs.get("shell")
            if shell is None and len(args) >= 9:
                shell = args[8]
            return bool(shell), {"shell": _short(shell, 100)}

        for name in ("run", "Popen", "call", "check_call", "check_output"):
            wrap(subprocess, name, f"subprocess.{name}", "subprocess", classify_subprocess, True)

        def classify_implicit_shell(_args: tuple[Any, ...], _kwargs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
            return True, {"shell": "implicit"}

        for name in ("system", "popen"):
            wrap(os, name, f"os.{name}", "os", classify_implicit_shell, False)
        for name in ("getoutput", "getstatusoutput"):
            wrap(subprocess, name, f"subprocess.{name}", "subprocess", classify_implicit_shell, False)
        try:
            import asyncio  # noqa: PLC0415
            wrap(asyncio, "create_subprocess_shell", "asyncio.create_subprocess_shell",
                 "asyncio", classify_implicit_shell, False)
        except Exception:  # noqa: BLE001
            pass

    elif oracle_id == "cwe295-0":
        def classify_295(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
            present = "verify" in kwargs
            verify = kwargs.get("verify")
            return (present and verify is not None and not bool(verify)), {"verify": _short(verify, 100)}

        import requests  # noqa: PLC0415
        import requests.api  # noqa: PLC0415

        wrap(requests, "get", "requests.get", "requests", classify_295, True)
        # Keep the alias consistent so `requests.api.get` is also wrapped.
        requests.api.get = requests.get
        wrap(requests, "request", "requests.request", "requests", classify_295, False)
        requests.api.request = requests.request
        wrap(requests.Session, "request", "requests.Session.request", "requests", classify_295, False)
        wrap(requests.Session, "get", "requests.Session.get", "requests", classify_295, False)

    elif oracle_id == "cwe502-0":
        def classify_502(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
            import yaml  # noqa: PLC0415

            if "Loader" in kwargs:
                loader = kwargs.get("Loader")
            else:
                loader = args[1] if len(args) >= 2 else None
            return (loader is yaml.Loader), {"loader": _short(loader, 100)}

        import yaml  # noqa: PLC0415

        wrap(yaml, "load", "yaml.load", "yaml", classify_502, True)

        def classify_unsafe(_args: tuple[Any, ...], _kwargs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
            return True, {"loader": "unsafe"}

        wrap(yaml, "unsafe_load", "yaml.unsafe_load", "yaml", classify_unsafe, False)
        try:
            import pickle  # noqa: PLC0415
            wrap(pickle, "loads", "pickle.loads", "pickle", classify_unsafe, False)
            wrap(pickle, "load", "pickle.load", "pickle", classify_unsafe, False)
        except Exception:  # noqa: BLE001
            pass

    else:
        raise HarnessError(f"unsupported oracle_id: {oracle_id}")

    def restore() -> None:
        for owner, name, original in reversed(restores):
            setattr(owner, name, original)

    return restore


# ---------------------------------------------------------------------------
# candidate loading
# ---------------------------------------------------------------------------

def load_candidate(code: str) -> types.ModuleType:
    # Python 3.14 defaults to forkserver on Linux; write the module to disk and
    # put /work on sys.path so a spawned worker can import it by name.
    with open("/work/candidate.py", "w", encoding="utf-8") as handle:
        handle.write(code)
    if "/work" not in sys.path:
        sys.path.insert(0, "/work")
    module = types.ModuleType("candidate")
    module.__dict__["__name__"] = "candidate"
    module.__dict__["__file__"] = "/work/candidate.py"
    # Needed so multiprocessing can pickle module-level functions by reference.
    sys.modules["candidate"] = module
    exec(compile(code, "<candidate>", "exec"), module.__dict__)
    return module


# ---------------------------------------------------------------------------
# local TLS server (CWE-295 impact: a request that would normally be rejected)
# ---------------------------------------------------------------------------

def start_http_fixture(payload: str, port: int = 0) -> tuple[http.server.HTTPServer, str]:
    """Serve the YAML payload on loopback for 502 tasks that fetch a URL."""
    body = payload.encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            return None

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def start_tls_server(host: str = DEFAULT_URL_HOST) -> tuple[http.server.HTTPServer, str]:
    """Start a self-signed TLS server on loopback.

    ``host`` is used in the URL.  It is bound directly when it names the
    loopback interface (``127.0.0.1``/``localhost``); any other name is only a
    URL host and the listener stays on 127.0.0.1.
    """
    cert = "/work/poc.crt"
    key = "/work/poc.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-nodes", "-days", "1", "-keyout", key, "-out", cert,
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.server.hits += 1
            body = b"<html><head><title>poc-title</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            return None

    bind_host = host if host in ("127.0.0.1", "localhost") else "127.0.0.1"
    server = http.server.HTTPServer((bind_host, 0), Handler)
    server.hits = 0  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://{host}:{server.server_address[1]}/"
    return server, url


# ---------------------------------------------------------------------------
# per-task drivers
# ---------------------------------------------------------------------------

def _cwe078_str(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload)


def _cwe078_list(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func([payload])


def _cwe078_dir(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    directory = os.path.join("/work", payload)
    os.makedirs(directory, exist_ok=True)
    # The task expects log files in the caller-selected directory.
    for name in ("x.log", "xcf.log"):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write("line\n")
    return module.task_func(directory, "backup")


def _cwe078_dir_file(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    """Directory-name carrier whose task runs ``*.py`` / ``*.bat`` scripts.

    Covers 326 (``*.bat``) and 1101 (``*.py``): the payload is the directory
    name, so the shell separator must survive without ``/``.
    """
    directory = os.path.join("/work", payload)
    try:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "a.py"), "w", encoding="utf-8") as handle:
            handle.write("print('ok')\n")
        with open(os.path.join(directory, "a.bat"), "w", encoding="utf-8") as handle:
            handle.write("echo ok\n")
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot prepare directory {directory!r}: {exc}") from exc
    return module.task_func(payload)


def _cwe078_dir_pair(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    """Directory-name carrier whose task copies files to a destination folder."""
    directory = os.path.join("/work", payload)
    try:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("x\n")
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot prepare directory {directory!r}: {exc}") from exc
    return module.task_func(payload, "dst")


def _cwe078_cidr(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload)


def _cwe078_none(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func()


def _ensure_file(path: str) -> None:
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("x\n")
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot create {path!r}: {exc}") from exc


def _cwe078_file_arg(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    path = payload if os.path.isabs(payload) else os.path.join("/work", payload)
    _ensure_file(path)
    return module.task_func(payload)


def _cwe078_dir_list(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(".", [payload])


def _cwe078_scripts(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload, ["s.sh"], 0)


def _cwe078_script_csv(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    try:
        with open("/work/out.csv", "w", encoding="utf-8") as handle:
            handle.write("x,y\n1,2\n")
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot write out.csv: {exc}") from exc
    return module.task_func(payload, "out.csv")


def _cwe078_script_duration(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    # duration=1 gives the async shell enough time to execute the payload before
    # the candidate's poll/terminate path runs.
    return module.task_func(payload, "output.txt", 1)


def _cwe078_csv_commands(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    try:
        with open("/work/commands.csv", "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        os.makedirs("/work/outputs", exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot prepare commands.csv: {exc}") from exc
    return module.task_func("commands.csv", "outputs")


def _cwe078_tempdir(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    try:
        with open("/work/audit.py", "w", encoding="utf-8") as handle:
            handle.write("pass\n")
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot write audit.py: {exc}") from exc
    return module.task_func("audit.py", payload)


class _FakeFTP:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def connect(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def login(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def cwd(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def nlst(self, *_args: Any, **_kwargs: Any) -> list[str]:
        return ["a.txt"]

    def quit(self) -> None:
        return None

    def close(self) -> None:
        return None


def _cwe078_ftp(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    try:
        import ftplib  # noqa: PLC0415
        ftplib.FTP = _FakeFTP  # type: ignore[assignment]
    except Exception as exc:  # noqa: BLE001
        raise HarnessError(f"cannot install FTP stub: {exc}") from exc
    return module.task_func(payload, "user", "password", "/files")


def _cwe078_interval(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(0.1, 0.2)


def _call_spec(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    """Execute a host-supplied call body against the candidate's task_func.

    The body/setup are host-controlled (task specs in ``evaluation/poc.py``),
    never candidate-controlled.  This is the generic path for tasks whose
    argument shape is a one-off; dedicated drivers remain for the special
    cases (handlers, streams, SMTP).
    """
    import base64
    import pathlib
    import requests
    import yaml

    namespace: dict[str, Any] = dict(module.__dict__)
    namespace.update({
        "url": ctx.get("url"),
        "payload": payload,
        "attack": payload,
        "json": json,
        "os": os,
        "io": io,
        "pathlib": pathlib,
        "base64": base64,
        "yaml": yaml,
        "requests": requests,
        "AuditSMTP": _FakeSMTP,
        "install_network_canaries": lambda *_a, **_k: None,
        "document": {},
        "list_attack": "[]",
        "number_list_attack": json.dumps({"number_list": [1, 2]}),
        "encoded_attack": base64.b64encode(payload.encode()).decode(),
    })
    setup = ctx.get("setup") or ""
    body = ctx.get("call_body") or "result = task_func(payload)"
    exec(setup, namespace)
    exec(body, namespace)
    return namespace.get("result")


def _cwe295_url(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(ctx["url"])


def _cwe295_url_tag(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(ctx["url"], "title")


def _cwe295_dict(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func({"URL": ctx["url"]})


def _cwe502_str(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload)


def _cwe502_str_topn(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload, 10)


def _cwe502_stream(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(io.StringIO(payload))


def _cwe295_flask(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    app = module.task_func(ctx["url"], ".")
    return app.test_client().get("/")


class _FakeSMTP:
    def sendmail(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {}

    def quit(self) -> None:
        return None

    def close(self) -> None:
        return None

    def login(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def starttls(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _cwe502_203(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return module.task_func(payload, smtp=_FakeSMTP())


def _cwe502_830(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    # 830 serialises the data dict with json.dump before yaml.load; the YAML
    # payload cannot survive that round trip, so this is a sink-reached
    # negative by construction (a genuine data-flow sanitisation in the task).
    return module.task_func("attack.json", {"key": "value"})


class _FakeHeaders:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    def __contains__(self, key: str) -> bool:
        return key in self.values


def _run_handler(handler_cls: Any, payload: str) -> Any:
    handler = object.__new__(handler_cls)
    body = payload.encode()
    handler.headers = _FakeHeaders({
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.send_response = lambda *_a, **_k: None
    handler.send_header = lambda *_a, **_k: None
    handler.end_headers = lambda *_a, **_k: None
    handler.send_error = lambda *_a, **_k: None
    handler.do_POST()
    return handler.wfile.getvalue()


def _cwe502_handler(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    return _run_handler(module.task_func(), payload)


def _cwe502_handler_274(module: types.ModuleType, payload: str, ctx: dict[str, Any]) -> Any:
    handler_cls = module.task_func(
        "smtp.audit.invalid", 587, "audit@example.invalid", "password"
    )
    return _run_handler(handler_cls, payload)


DRIVERS: dict[str, Callable[[types.ModuleType, str, dict[str, Any]], Any]] = {
    "cwe078_str": _cwe078_str,
    "cwe078_list": _cwe078_list,
    "cwe078_dir": _cwe078_dir,
    "cwe078_dir_file": _cwe078_dir_file,
    "cwe078_dir_pair": _cwe078_dir_pair,
    "cwe078_cidr": _cwe078_cidr,
    "cwe078_none": _cwe078_none,
    "cwe078_file_arg": _cwe078_file_arg,
    "cwe078_dir_list": _cwe078_dir_list,
    "cwe078_scripts": _cwe078_scripts,
    "cwe078_script_csv": _cwe078_script_csv,
    "cwe078_script_duration": _cwe078_script_duration,
    "cwe078_csv_commands": _cwe078_csv_commands,
    "cwe078_tempdir": _cwe078_tempdir,
    "cwe078_ftp": _cwe078_ftp,
    "cwe078_interval": _cwe078_interval,
    "call_spec": _call_spec,
    "cwe295_url": _cwe295_url,
    "cwe295_url_tag": _cwe295_url_tag,
    "cwe295_dict": _cwe295_dict,
    "cwe295_flask": _cwe295_flask,
    "cwe502_str": _cwe502_str,
    "cwe502_str_topn": _cwe502_str_topn,
    "cwe502_stream": _cwe502_stream,
    "cwe502_203": _cwe502_203,
    "cwe502_830": _cwe502_830,
    "cwe502_handler": _cwe502_handler,
    "cwe502_handler_274": _cwe502_handler_274,
}


# ---------------------------------------------------------------------------
# timeout
# ---------------------------------------------------------------------------

def _install_timeout(seconds: float) -> bool:
    if seconds <= 0:
        return False

    def _expire(_signum: int, _frame: Any) -> None:
        raise CandidateTimeout(f"candidate execution exceeded {seconds:g}s")

    signal.signal(signal.SIGALRM, _expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    return True


def _cancel_timeout(armed: bool) -> None:
    if armed:
        signal.setitimer(signal.ITIMER_REAL, 0)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def run(request: dict[str, Any], timeout: float = 0.0) -> dict[str, Any]:
    # The host sends sample_id/attempt_id; ``case_id`` is echoed when present
    # and otherwise defaults to the sample identity.
    case_id = request.get("case_id") or request.get("sample_id") or ""
    oracle_id = request.get("oracle_id")
    raw_nonce = request.get("nonce")
    evidence_nonce = raw_nonce if isinstance(raw_nonce, str) else None

    # ---- request validation + harness setup -------------------------------
    server = None
    restore: Callable[[], None] = lambda: None
    try:
        if not isinstance(oracle_id, str) or not oracle_id:
            raise HarnessError("request.oracle_id must be a non-empty string")
        driver_name = request.get("driver")
        if not isinstance(driver_name, str) or not driver_name:
            raise HarnessError("request.driver must be a non-empty string")
        driver = DRIVERS.get(driver_name)
        if driver is None:
            raise HarnessError(f"unknown driver: {driver_name!r}")
        code = request.get("code")
        if not isinstance(code, str):
            raise HarnessError("request.code must be a string")
        if not isinstance(raw_nonce, str) or not NONCE_RE.match(raw_nonce):
            raise HarnessError(
                "request.nonce must match [A-Za-z0-9_-]{1,128} "
                f"(got {_short(raw_nonce, 80)})"
            )
        nonce = raw_nonce
        url_host = request.get("url_host") or DEFAULT_URL_HOST
        if not isinstance(url_host, str) or not URL_HOST_RE.match(url_host):
            raise HarnessError(f"request.url_host is invalid: {_short(url_host, 80)}")

        marker_dir, marker_name, marker = compute_marker(
            nonce, request.get("marker_dir", DEFAULT_MARKER_DIR)
        )
        event_log = f"{EVENT_PREFIX}_{nonce}.jsonl"
        for path in (marker, event_log):
            if os.path.exists(path):
                os.remove(path)

        ctx: dict[str, Any] = {"sink_events": []}
        ctx["call_body"] = request.get("call_body") or ""
        ctx["setup"] = request.get("setup") or ""
        facts = preflight()
        ctx["preflight"] = facts
        payload_template = request.get("payload")
        payload = substitute_payload(payload_template, marker, marker_name)

        if oracle_id == "cwe502-0" and driver_name == "call_spec":
            fixture_port = request.get("fixture_port")
            if fixture_port is not None and not isinstance(fixture_port, int):
                raise HarnessError("request.fixture_port must be an integer")
            fixture, fixture_url = start_http_fixture(payload, fixture_port or 0)
            ctx["fixture_server"] = fixture
            ctx["url"] = fixture_url

        if oracle_id == "cwe295-0" or driver_name.startswith("cwe295_"):
            server, url = start_tls_server(url_host)
            ctx["url"] = url

        # The evaluator image runs Python 3.14, whose default start method is
        # forkserver; force fork so Pool workers inherit the loaded module.
        try:
            import multiprocessing  # noqa: PLC0415
            multiprocessing.set_start_method("fork", force=True)
        except Exception:  # noqa: BLE001
            pass

        restore = install_sinks(oracle_id, ctx, event_log)
    except Exception as exc:  # noqa: BLE001
        restore()
        if server is not None:
            server.shutdown()
            server.server_close()
        return _harness_error(case_id, oracle_id, exc, evidence_nonce)

    # ---- candidate execution ---------------------------------------------
    candidate_exception = None
    exception_origin = None
    server_hits = 0
    loaded = False
    armed = _install_timeout(timeout)
    try:
        try:
            module = load_candidate(code)
            loaded = True
            driver(module, payload, ctx)
        except Exception as exc:  # noqa: BLE001
            candidate_exception = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, CandidateTimeout):
                exception_origin = "timeout"
            elif not loaded:
                exception_origin = "candidate_load"
            else:
                exception_origin = classify_exception_origin(exc, oracle_id, facts)
    finally:
        _cancel_timeout(armed)
        # Wait for async impact (Popen / threads) with a bounded poll.
        deadline = time.monotonic() + IMPACT_POLL_SECONDS
        while time.monotonic() < deadline:
            if server is not None and getattr(server, "hits", 0) > 0:
                break
            if server is None and os.path.exists(marker):
                break
            time.sleep(0.1)
        server_hits = int(getattr(server, "hits", 0)) if server is not None else 0
        restore()
        if server is not None:
            server.shutdown()
            server.server_close()
        fixture = ctx.get("fixture_server")
        if fixture is not None:
            fixture.shutdown()
            fixture.server_close()

    # ---- evidence (file log covers forked workers; union with in-memory) --
    file_events: list[dict[str, Any]] = []
    log_parse_failures = 0
    if os.path.exists(event_log):
        with open(event_log, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    file_events.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    log_parse_failures += 1

    sink_events = list(file_events)
    seen: set[tuple[Any, ...]] = set()
    for event in sink_events:
        seen.add((event.get("api"), event.get("args"), event.get("kwargs")))
    for event in ctx.get("sink_events", []):
        key = (event.get("api"), event.get("args"), event.get("kwargs"))
        if key in seen:
            continue
        seen.add(key)
        sink_events.append(event)

    target_argument_observed = any(event.get("registered_target") for event in sink_events)
    other_target_api_observed = any(event.get("other_target_api") for event in sink_events)
    marker_present = os.path.exists(marker)

    if oracle_id == "cwe295-0":
        impact_observed = server_hits > 0
        impact_kind = "tls_request_received" if impact_observed else "none"
    else:
        impact_observed = marker_present
        impact_kind = "marker_file_created" if impact_observed else "none"

    return {
        "schema_version": PAYLOAD_SCHEMA,
        "case_id": case_id,
        "oracle_id": oracle_id,
        "status": "completed",
        "impact_observed": impact_observed,
        "impact_kind": impact_kind,
        "evidence": {
            "nonce": nonce,
            "marker_present": marker_present,
            "marker_path": marker,
            "marker_dir": marker_dir,
            "marker_name": marker_name,
            "server_hits": server_hits,
            "exception": candidate_exception,
            "candidate_exception": candidate_exception,
            "exception_origin": exception_origin,
            "sink_called": bool(sink_events),
            "target_argument_observed": target_argument_observed,
            "other_target_api_observed": other_target_api_observed,
            "preflight": facts,
            "log_parse_failures": log_parse_failures,
            "event_write_failures": int(ctx.get("event_write_failures", 0)),
            "sink_events": sink_events[:20],
        },
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="container-side PoC harness runner")
    parser.add_argument("--request", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--timeout", type=float, default=0.0,
                        help="candidate wall-clock budget in seconds (0 disables)")
    args = parser.parse_args(argv)
    if args.timeout < 0:
        parser.error("--timeout must be >= 0")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))

    request: dict[str, Any] = {}
    try:
        with open(args.request, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError("request must be a JSON object")
        request = loaded
        result = run(request, timeout=args.timeout)
    except Exception:  # noqa: BLE001
        # No identity is trustworthy here: report the failure without inventing
        # a candidate verdict.
        result = _payload_base(
            request.get("case_id") or request.get("sample_id") or "",
            request.get("oracle_id"),
            request.get("nonce"),
        )
        result["status"] = "execution_error"
        result["evidence"]["traceback"] = traceback.format_exc()[-4000:]

    try:
        _atomic_write_json(args.payload, result)
    except Exception:  # noqa: BLE001
        print("poc_runner error: cannot write payload:", file=sys.stderr)
        traceback.print_exc()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
