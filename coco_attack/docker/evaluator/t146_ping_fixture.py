"""Versioned ping simulator for ``BigCodeBench/146`` functional evaluation.

The BigCodeBench/146 tests were written against ``subprocess.check_output``.
Candidates that use ``subprocess.run``/``Popen`` (or import those names
directly) bypass the original ``unittest.mock.patch`` and would try to launch a
real ``ping`` inside the offline evaluation container.  This module replaces
only the subprocess entry points needed to observe a ping and returns simulated
results.  It is installed by ``functional_runner`` before the candidate module
is executed, so direct imports such as ``from subprocess import run`` also see
the simulator.

Design constraints:

* Only ``ping`` commands are simulated.  Any other command raises
  ``FileNotFoundError`` without executing a process; it is never reported as a
  successful ping.
* Malformed ping commands (unknown options, non-positive counts/timeouts, or
  compound shell syntax) raise ``ValueError`` instead of being treated as a
  successful ping.
* The test controls success/failure by entering ``simulated_ping(...)``.  The
  original test suite patched ``subprocess.check_output``; when such a mock is
  present its configured ``side_effect``/``return_value`` is honoured so legacy
  tests still control the simulated outcome.
* ``run`` keeps ``check`` semantics, and ``Popen`` exposes the subset of the
  real interface used by this task (``wait``/``poll``/``communicate``/
  ``returncode``/context manager).
* Each evaluation sample runs in its own process, so the monkeypatch cannot
  leak into another sample.
* ``simulated_ping`` uses a ``ContextVar``.  Python does not propagate context
  variables into new threads, so a candidate that pings from a worker thread is
  not observed inside the test's context (and therefore fails the call-count
  checks).  The scanned t146 corpus contains no threaded candidates; this
  version does not add a concurrency framework for that case.

This is deliberately task-specific, not a general subprocess mock framework.
"""

from __future__ import annotations

import ipaddress
import math
import os
import shlex
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator

TASK_ID = "BigCodeBench/146"
FIXTURE_VERSION = "t146-ping-fixture-v1"

_INSTALLED = False


@dataclass(frozen=True)
class PingCall:
    """One ping invocation observed by the fixture."""

    address: str
    argv: tuple[str, ...]
    api: str


@dataclass
class SimulationState:
    success: bool
    calls: list[PingCall] = field(default_factory=list)
    rejected_commands: list[tuple[str, ...]] = field(default_factory=list)


_STATE: ContextVar[SimulationState | None] = ContextVar("t146_ping_state", default=None)
# Calls made outside an explicit test context (for example at candidate import
# time) still must not touch the network.  They are recorded here and default
# to a successful ping; task tests always wrap the call in ``simulated_ping``.
_UNSCOPED = SimulationState(success=True)


@contextmanager
def simulated_ping(*, success: bool) -> Iterator[SimulationState]:
    """Make ping return success or fail for the duration of the block."""

    state = SimulationState(success=bool(success))
    token = _STATE.set(state)
    try:
        yield state
    finally:
        _STATE.reset(token)


def _state() -> SimulationState:
    return _STATE.get() or _UNSCOPED


def _patched_mock_success() -> bool | None:
    """Derive the outcome from ``unittest.mock.patch('subprocess.check_output')``.

    The original BigCodeBench/146 tests configured that mock rather than this
    fixture.  When the mock is active, candidates using ``run``/``Popen`` (or an
    alias imported before the patch) must observe the same success/failure.
    """

    try:
        from unittest import mock
    except ImportError:  # pragma: no cover - stdlib always present
        return None
    current = subprocess.check_output
    if not isinstance(current, mock.Mock):
        return None
    side_effect = getattr(current, "side_effect", None)
    if isinstance(side_effect, BaseException):
        return False
    if isinstance(side_effect, type) and issubclass(side_effect, BaseException):
        return False
    if isinstance(side_effect, (list, tuple)) and side_effect:
        first = side_effect[0]
        if isinstance(first, BaseException):
            return False
        if isinstance(first, type) and issubclass(first, BaseException):
            return False
    return True


def _resolve_success() -> bool:
    if _STATE.get() is not None:
        return _state().success
    mocked = _patched_mock_success()
    if mocked is not None:
        return mocked
    return True


def _command_from(popenargs: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Return the command passed positionally or as ``args=``.

    ``subprocess.run(args=[...])``/``Popen(args=[...])``/``check_output(args=...)``
    are valid calls; the fixture must observe them exactly like the positional
    form.
    """

    missing = object()
    keyword = kwargs.get("args", missing)
    if popenargs:
        if len(popenargs) > 1:
            raise TypeError(
                "t146 ping fixture: expected one command argument, "
                f"got {len(popenargs)} positional arguments"
            )
        if keyword is not missing:
            raise TypeError(
                "t146 ping fixture: command given both positionally and as args="
            )
        return popenargs[0]
    if keyword is missing:
        raise TypeError("t146 ping fixture: missing required argument 'args'")
    return keyword


def _tokens(command: Any) -> tuple[str, ...]:
    if isinstance(command, (bytes, os.PathLike)):
        text = os.fsdecode(command)
    elif isinstance(command, str):
        text = command
    else:
        return tuple(os.fsdecode(part) for part in command)
    try:
        return tuple(shlex.split(text))
    except ValueError:
        return tuple(text.split())


def _is_ping_token(token: str) -> bool:
    return os.path.basename(token).lower() in {"ping", "ping4"}


def _ping_addresses(tokens: tuple[str, ...]) -> tuple[str, ...]:
    addresses: list[str] = []
    for token in tokens:
        try:
            addresses.append(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    return tuple(addresses)


# A string command with shell=True is only accepted for a single ping
# invocation.  These characters would introduce pipes, lists, redirections,
# substitutions or globbing; this fixture deliberately does not interpret them.
_SHELL_META = frozenset(";&|<>`$(){}[]*?!#~\n\r")

# Common ping flags that take no value.
_FLAG_OPTIONS = frozenset({"q", "4", "6", "D", "O", "v", "a", "f", "R"})

# Common value-taking ping options.  ``-W``/``-w`` exist on POSIX and Windows;
# only positive values are accepted so a zero count/timeout cannot be treated
# as a successful ping.
_VALUE_OPTIONS: dict[str, str] = {
    "c": "positive_int",
    "i": "positive_number",
    "W": "positive_number",
    "w": "positive_number",
    "s": "positive_int",
    "t": "positive_int",
    "l": "positive_int",
    "p": "text",
    "I": "text",
    "Q": "positive_int",
}

_LONG_FLAG_OPTIONS = frozenset(
    {"--quiet", "--numeric", "--ipv4", "--ipv6", "--verbose", "--debug"}
)
_LONG_VALUE_OPTIONS: dict[str, str] = {
    "--count": "positive_int",
    "--interval": "positive_number",
    "--timeout": "positive_number",
    "--deadline": "positive_number",
    "--size": "positive_int",
    "--ttl": "positive_int",
    "--preload": "positive_int",
    "--interface": "text",
}


def _positive_int(text: str, option: str) -> int:
    try:
        value = int(text, 10)
    except ValueError as error:
        raise ValueError(
            f"t146 ping fixture: {option} requires a positive integer, got {text!r}"
        ) from error
    if value <= 0:
        raise ValueError(
            f"t146 ping fixture: {option} requires a positive integer, got {text!r}"
        )
    return value


def _positive_number(text: str, option: str) -> float:
    try:
        value = float(text)
    except ValueError as error:
        raise ValueError(
            f"t146 ping fixture: {option} requires a positive number, got {text!r}"
        ) from error
    if not math.isfinite(value) or value <= 0:
        raise ValueError(
            f"t146 ping fixture: {option} requires a positive number, got {text!r}"
        )
    return value


def _text_value(text: str, option: str) -> str:
    if not text:
        raise ValueError(f"t146 ping fixture: {option} requires a value")
    return text


_PARSERS = {
    "positive_int": _positive_int,
    "positive_number": _positive_number,
    "text": _text_value,
}


def _consume_value(
    body: tuple[str, ...], index: int, rest: str, option: str, kind: str
) -> int:
    if rest:
        _PARSERS[kind](rest, option)
        return index
    if index + 1 >= len(body):
        raise ValueError(f"t146 ping fixture: {option} requires a value")
    _PARSERS[kind](body[index + 1], option)
    return index + 1


def _parse_short_option(body: tuple[str, ...], index: int) -> int:
    token = body[index]
    chars = token[1:]
    position = 0
    while position < len(chars):
        char = chars[position]
        if char == "n":
            # POSIX ``-n`` (numeric output) and Windows ``-n <count>`` share a
            # spelling.  A following integer is a Windows count; anything else
            # is the POSIX flag.  A zero count is rejected.
            rest = chars[position + 1 :]
            if rest:
                if rest.lstrip("+-").isdigit():
                    _positive_int(rest, "-n")
                    return index
                position += 1
                continue
            if index + 1 < len(body) and body[index + 1].isdigit():
                _positive_int(body[index + 1], "-n")
                return index + 1
            position += 1
            continue
        if char in _FLAG_OPTIONS:
            position += 1
            continue
        kind = _VALUE_OPTIONS.get(char)
        if kind is None:
            raise ValueError(
                f"t146 ping fixture: unsupported ping option {token!r}"
            )
        return _consume_value(body, index, chars[position + 1 :], f"-{char}", kind)
    return index


def _parse_long_option(body: tuple[str, ...], index: int) -> int:
    token = body[index]
    name, separator, inline = token.partition("=")
    if name in _LONG_FLAG_OPTIONS:
        if separator:
            raise ValueError(
                f"t146 ping fixture: {name} does not take a value"
            )
        return index
    kind = _LONG_VALUE_OPTIONS.get(name)
    if kind is None:
        raise ValueError(f"t146 ping fixture: unsupported ping option {token!r}")
    if separator:
        return _consume_value(body, index, inline, name, kind)
    return _consume_value(body, index, "", name, kind)


def _validate_ping_tokens(body: tuple[str, ...]) -> str:
    """Return the single target IP of a well-formed ping argv."""

    if not body or not _is_ping_token(body[0]):
        raise ValueError("t146 ping fixture: expected a ping command")
    targets: list[str] = []
    options_done = False
    index = 1
    while index < len(body):
        token = body[index]
        if options_done:
            targets.append(token)
        elif token == "--":
            options_done = True
        elif token.startswith("--"):
            index = _parse_long_option(body, index)
        elif token.startswith("-") and token != "-":
            index = _parse_short_option(body, index)
        else:
            targets.append(token)
        index += 1
    if len(targets) != 1:
        raise ValueError(
            "t146 ping fixture: ping command must target exactly one IP address "
            f"(got {targets!r})"
        )
    addresses = _ping_addresses(tuple(targets))
    if len(addresses) != 1:
        raise ValueError(
            "t146 ping fixture: ping target must be a literal IP address, "
            f"got {targets[0]!r}"
        )
    return addresses[0]


def _reject_shell_syntax(text: str) -> None:
    found = sorted({char for char in text if char in _SHELL_META})
    if found:
        raise ValueError(
            "t146 ping fixture: unsupported compound shell syntax "
            f"{found!r} in {text!r}"
        )


def _classify(command: Any) -> tuple[str | None, tuple[str, ...]]:
    """Return ``(address, tokens)`` for a ping command, or ``(None, tokens)``."""

    tokens = _tokens(command)
    body = tokens
    if tokens and not _is_ping_token(tokens[0]):
        # A simple ``sh -c 'ping ...'`` wrapper is common enough to support.
        shell_name = os.path.basename(tokens[0]).lower()
        if shell_name in {"sh", "bash", "dash"}:
            if len(tokens) != 3 or tokens[1] != "-c":
                raise ValueError(
                    "t146 ping fixture: only 'sh -c <single ping command>' "
                    f"wrappers are supported, got {list(tokens)!r}"
                )
            _reject_shell_syntax(tokens[2])
            body = _tokens(tokens[2])
    if not body or not _is_ping_token(body[0]):
        return None, tokens
    return _validate_ping_tokens(body), tokens


def _simulate(api: str, command: Any, *, shell: bool = False) -> tuple[PingCall, bool]:
    if shell and not isinstance(command, (str, bytes)):
        _state().rejected_commands.append(_tokens(command))
        raise ValueError(
            "t146 ping fixture: shell=True requires a command string; "
            "a sequence is not executed as a complete ping argv by a POSIX shell"
        )
    if not shell and isinstance(command, (str, bytes, os.PathLike)):
        tokens = _tokens(command)
        _state().rejected_commands.append(tokens)
        raise FileNotFoundError(
            "t146 ping fixture: a string command requires shell=True; "
            f"refusing to execute {list(tokens)!r}"
        )
    if shell and isinstance(command, (str, bytes)):
        text = os.fsdecode(command)
        try:
            _reject_shell_syntax(text)
        except ValueError:
            _state().rejected_commands.append(_tokens(command))
            raise
    try:
        address, tokens = _classify(command)
    except ValueError:
        _state().rejected_commands.append(_tokens(command))
        raise
    if address is None:
        _state().rejected_commands.append(tokens)
        raise FileNotFoundError(
            "t146 ping fixture: only ping commands are simulated; "
            f"refusing to execute {list(tokens)!r}"
        )
    call = PingCall(address=address, argv=tokens, api=api)
    _state().calls.append(call)
    return call, _resolve_success()


def _captured(kwargs: dict[str, Any], name: str) -> bool:
    return kwargs.get(name) == subprocess.PIPE


def _text_mode(kwargs: dict[str, Any]) -> bool:
    return bool(
        kwargs.get("text")
        or kwargs.get("universal_newlines")
        or kwargs.get("encoding")
        or kwargs.get("errors")
    )


def _empty_output(kwargs: dict[str, Any]) -> str | bytes:
    return "" if _text_mode(kwargs) else b""


def _failure(command: Any, stdout: Any = None, stderr: Any = None) -> subprocess.CalledProcessError:
    return subprocess.CalledProcessError(1, command, output=stdout, stderr=stderr)


class _SimulatedStream:
    """Minimal readable stream for ``Popen(stdout=PIPE)`` results."""

    def __init__(self, data: str | bytes) -> None:
        self._data = data
        self.closed = False

    def read(self, size: int = -1) -> str | bytes:
        if size is None or size < 0:
            data, self._data = self._data, self._data[:0]
            return data
        data, self._data = self._data[:size], self._data[size:]
        return data

    def readline(self, size: int = -1) -> str | bytes:
        if not self._data:
            return self._data[:0]
        newline = "\n" if isinstance(self._data, str) else b"\n"
        index = self._data.find(newline)
        if index < 0:
            return self.read() if size is None or size < 0 else self.read(size)
        end = index + len(newline)
        if size is not None and size >= 0:
            end = min(end, size)
        data, self._data = self._data[:end], self._data[end:]
        return data

    def readlines(self, hint: int = -1) -> list[str] | list[bytes]:
        lines = []
        while self._data:
            lines.append(self.readline())
        return lines

    def __iter__(self) -> "_SimulatedStream":
        return self

    def __next__(self) -> str | bytes:
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def close(self) -> None:
        self.closed = True
        self._data = self._data[:0]

    def __enter__(self) -> "_SimulatedStream":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


class _SimulatedPopen:
    """Subset of ``subprocess.Popen`` used by the t146 candidate space."""

    def __init__(self, args: Any, returncode: int, kwargs: dict[str, Any]) -> None:
        self.args = args
        self.pid = 0
        self.returncode: int | None = None
        self._final_returncode = returncode
        text = _text_mode(kwargs)
        output = "" if text else b""
        self._stdout_data = output if _captured(kwargs, "stdout") else None
        self._stderr_data = output if _captured(kwargs, "stderr") else None
        self.stdout = (
            _SimulatedStream(self._stdout_data)
            if self._stdout_data is not None
            else None
        )
        self.stderr = (
            _SimulatedStream(self._stderr_data)
            if self._stderr_data is not None
            else None
        )

    def poll(self) -> int | None:
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.poll()
        assert self.returncode is not None
        return self.returncode

    def communicate(
        self, input: Any = None, timeout: float | None = None
    ) -> tuple[str | bytes | None, str | bytes | None]:
        self.poll()
        stdout = None if self.stdout is None else self.stdout.read()
        stderr = None if self.stderr is None else self.stderr.read()
        return stdout, stderr

    def check_returncode(self) -> None:
        code = self.wait()
        if code:
            raise subprocess.CalledProcessError(code, self.args)

    def kill(self) -> None:
        pass

    def terminate(self) -> None:
        pass

    def send_signal(self, sig: int) -> None:
        pass

    def __enter__(self) -> "_SimulatedPopen":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.wait()


def _check_output(*popenargs: Any, **kwargs: Any) -> str | bytes:
    command = _command_from(popenargs, kwargs)
    _, success = _simulate("check_output", command, shell=bool(kwargs.get("shell")))
    output = _empty_output(kwargs)
    if not success:
        raise _failure(command, stdout=output)
    return output


def _run(*popenargs: Any, **kwargs: Any) -> subprocess.CompletedProcess:
    command = _command_from(popenargs, kwargs)
    _, success = _simulate("run", command, shell=bool(kwargs.get("shell")))
    returncode = 0 if success else 1
    captured = bool(kwargs.get("capture_output"))
    output = _empty_output(kwargs)
    stdout = output if captured or _captured(kwargs, "stdout") else None
    stderr = output if captured or _captured(kwargs, "stderr") else None
    if kwargs.get("check") and returncode:
        raise _failure(command, stdout=stdout, stderr=stderr)
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def _popen(*popenargs: Any, **kwargs: Any) -> _SimulatedPopen:
    command = _command_from(popenargs, kwargs)
    _, success = _simulate("Popen", command, shell=bool(kwargs.get("shell")))
    return _SimulatedPopen(command, 0 if success else 1, kwargs)


def _call(*popenargs: Any, **kwargs: Any) -> int:
    command = _command_from(popenargs, kwargs)
    _, success = _simulate("call", command, shell=bool(kwargs.get("shell")))
    return 0 if success else 1


def _check_call(*popenargs: Any, **kwargs: Any) -> int:
    command = _command_from(popenargs, kwargs)
    _, success = _simulate("check_call", command, shell=bool(kwargs.get("shell")))
    if not success:
        raise _failure(command)
    return 0


def install() -> None:
    """Install the simulator in this evaluation process (idempotent)."""

    global _INSTALLED
    if _INSTALLED:
        return
    subprocess.check_output = _check_output  # type: ignore[assignment]
    subprocess.run = _run  # type: ignore[assignment]
    subprocess.Popen = _popen  # type: ignore[assignment]
    subprocess.call = _call  # type: ignore[assignment]
    subprocess.check_call = _check_call  # type: ignore[assignment]
    _INSTALLED = True


__all__ = [
    "FIXTURE_VERSION",
    "PingCall",
    "SimulationState",
    "TASK_ID",
    "install",
    "simulated_ping",
]
