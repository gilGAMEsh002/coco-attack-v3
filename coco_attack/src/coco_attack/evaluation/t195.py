"""Versioned functional-test overlay for ``BigCodeBench/195``.

The raw task/test data is never rewritten.  The original tests mocked
``subprocess.Popen`` with a ``MagicMock`` and only asserted the literal call
list, which accepted implementations that do not launch the requested URL at
all (for example ``Popen([cmd, url], shell=True)`` on POSIX, where the shell
receives only ``cmd`` and drops the URL).  They also failed valid equivalents
that use ``run``/``call``, ``wait``, ``communicate`` or a context manager, and
``assertIsInstance(result, int)`` accepted ``bool``.

This overlay evaluates the intended behavior instead: for simulated Darwin,
Windows and Linux it verifies that the candidate starts exactly one process
with the platform tool and the complete URL, and that it returns the integer
exit code of that process.  The simulator is installed at the lowest common
subprocess entry point (``Popen``), so ``Popen``, ``run``, ``call`` and
``check_output`` candidates all observe the same process object and exit code.
The object supports ``poll``/``returncode``/``wait``/``communicate`` and the
context-manager protocol.  Its first ``poll`` reports ``None`` so a candidate
cannot return a not-yet-finished ``None``/constant as the exit code.

Command forms are deliberately limited to what this task needs:

* POSIX: an argv ``[open|xdg-open, URL]`` (absolute tool paths allowed) or a
  shell command string.  With ``shell=True`` and a sequence a POSIX shell runs
  only the first element, so ``["open URL"]`` is valid while ``[tool, URL]``
  drops the URL and is rejected.
* Windows: sequences are serialized with ``subprocess.list2cmdline`` and then
  parsed with cmd quoting/title rules.  ``shell=True`` allows ``start URL``;
  without ``shell`` the command must be ``cmd /c start ...`` because ``start``
  is a cmd builtin.  ``cmd /c start "" URL`` (empty title) is accepted, while
  a quoted URL without an empty title is consumed as the window title.
* ``executable=`` is honored: overriding the program with something other than
  the expected tool/shell raises instead of passing silently.
* Module-level aliases bound with ``from subprocess import Popen`` or
  ``from platform import system`` are rebound inside the simulation context,
  so those common legal forms are covered too.
* Unknown tools, wrong/missing URLs, shell operators and commands the fixture
  does not recognize raise instead of being treated as a successful launch.
"""

from __future__ import annotations

T195_TASK_ID = "BigCodeBench/195"
# Uniform task identifier used by the task-overlay dispatcher.
TASK_ID = T195_TASK_ID
T195_TESTS_VERSION = "b195-behavior-tests-v2"
T195_FIXTURE_ID = "b195-browser-behavior-overlay"
T195_FIXTURE_VERSION = "b195-browser-behavior-overlay-v2"

T195_TESTS_SOURCE = r"""import io
import os
import platform
import subprocess
import unittest
from contextlib import contextmanager
from unittest.mock import patch

_T195_REAL_POPEN = subprocess.Popen
_T195_REAL_SYSTEM = platform.system


class _T195Rejected(ValueError):
    pass


_T195_WINDOWS_START_OPTIONS = frozenset(
    {
        "/b",
        "/min",
        "/max",
        "/separate",
        "/low",
        "/normal",
        "/high",
        "/realtime",
        "/abovenormal",
        "/belownormal",
        "/wait",
    }
)

_T195_POSIX_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh"})


def _t195_command_from(popenargs, kwargs):
    missing = object()
    keyword = kwargs.get("args", missing)
    if popenargs:
        if len(popenargs) != 1:
            raise TypeError(
                "t195 fixture: expected one command argument, got %d"
                % len(popenargs)
            )
        if keyword is not missing:
            raise TypeError("t195 fixture: command given both positionally and as args=")
        return popenargs[0]
    if keyword is missing:
        raise TypeError("t195 fixture: missing required argument 'args'")
    return keyword


def _t195_text(value):
    if isinstance(value, str):
        return value
    return os.fsdecode(value)


def _t195_posix_tokens(text):
    # POSIX shell word splitting with quote removal.  Unquoted operators,
    # expansions and globs are rejected: they make the shell run something
    # other than a single tool + URL invocation.  Quoted URLs keep spaces,
    # query strings and ampersands intact.
    tokens = []
    buffer = []
    started = False
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is None:
            if char in " \t":
                if started:
                    tokens.append("".join(buffer))
                    buffer = []
                    started = False
            elif char in "\n\r":
                raise _T195Rejected("t195 fixture: compound shell command")
            elif char == "'":
                quote = "'"
                started = True
            elif char == '"':
                quote = '"'
                started = True
            elif char == "\\":
                index += 1
                if index >= len(text):
                    raise _T195Rejected("t195 fixture: dangling shell escape")
                buffer.append(text[index])
                started = True
            elif char in ";&|<>()`$*?[]{}":
                raise _T195Rejected(
                    "t195 fixture: unsupported unquoted shell metacharacter %r" % char
                )
            elif char == "#" and not started:
                raise _T195Rejected("t195 fixture: shell comment is not a command")
            elif char == "~" and not started:
                raise _T195Rejected("t195 fixture: shell tilde expansion")
            else:
                buffer.append(char)
                started = True
        elif quote == "'":
            if char == "'":
                quote = None
            else:
                buffer.append(char)
        else:
            if char == '"':
                quote = None
            elif char == "\\":
                index += 1
                if index >= len(text):
                    raise _T195Rejected("t195 fixture: dangling shell escape")
                buffer.append(text[index])
            elif char in "$`":
                raise _T195Rejected(
                    "t195 fixture: shell expansion inside quotes is not supported"
                )
            else:
                buffer.append(char)
        index += 1
    if quote is not None:
        raise _T195Rejected("t195 fixture: unterminated shell quote")
    if started:
        tokens.append("".join(buffer))
    return tokens


def _t195_cmd_tokens(text):
    # Limited cmd.exe tokenizer.  It keeps whether a token was quoted because
    # ``start`` treats its first quoted argument as a window title.
    tokens = []
    buffer = []
    started = False
    quoted = False
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is None:
            if char in " \t":
                if started:
                    tokens.append(("".join(buffer), quoted))
                    buffer = []
                    started = False
                    quoted = False
            elif char in "\n\r":
                raise _T195Rejected("t195 fixture: compound cmd command")
            elif char == '"':
                quote = '"'
                started = True
                quoted = True
            elif char == "^":
                index += 1
                if index >= len(text):
                    raise _T195Rejected("t195 fixture: dangling cmd escape")
                buffer.append(text[index])
                started = True
            elif char in "&|<>()":
                raise _T195Rejected(
                    "t195 fixture: unsupported unquoted cmd metacharacter %r" % char
                )
            else:
                buffer.append(char)
                started = True
        else:
            if char == '"':
                quote = None
            else:
                buffer.append(char)
        index += 1
    if quote is not None:
        raise _T195Rejected("t195 fixture: unterminated cmd quote")
    if started:
        tokens.append(("".join(buffer), quoted))
    return tokens


def _t195_windows_exe(token):
    base = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _t195_is_posix_shell(executable):
    base = os.path.basename(_t195_text(executable))
    if base.endswith(".exe"):
        base = base[:-4]
    return base.lower() in _T195_POSIX_SHELLS


def _t195_validate_posix(command, system, url, shell, executable):
    expected = "open" if system == "Darwin" else "xdg-open"
    if executable is not None:
        if shell:
            if not _t195_is_posix_shell(executable):
                raise _T195Rejected(
                    "t195 fixture: shell=True executable must be a POSIX shell, "
                    "got %r" % _t195_text(executable)
                )
        elif os.path.basename(_t195_text(executable)) != expected:
            raise _T195Rejected(
                "t195 fixture: executable %r does not launch %r"
                % (_t195_text(executable), expected)
            )
    if isinstance(command, (str, bytes, os.PathLike)):
        if not shell:
            raise _T195Rejected(
                "t195 fixture: a string command without shell=True is not a "
                "tool invocation on POSIX"
            )
        argv = _t195_posix_tokens(_t195_text(command))
    else:
        parts = [_t195_text(part) for part in command]
        if not parts:
            raise _T195Rejected("t195 fixture: empty command")
        if shell:
            # A POSIX shell executes only argv[0]; remaining elements become
            # positional parameters, so the command must be fully in argv[0].
            argv = _t195_posix_tokens(parts[0])
        else:
            argv = parts
    if not argv:
        raise _T195Rejected("t195 fixture: empty command")
    if os.path.basename(argv[0]) != expected:
        raise _T195Rejected(
            "t195 fixture: expected %r for %s, got %r"
            % (expected, system, argv[0])
        )
    rest = argv[1:]
    if rest and rest[0] == "--":
        rest = rest[1:]
    if len(rest) != 1:
        raise _T195Rejected(
            "t195 fixture: expected exactly one URL argument, got %r" % (rest,)
        )
    if rest[0] != url:
        raise _T195Rejected(
            "t195 fixture: expected URL %r, got %r" % (url, rest[0])
        )
    return expected, rest[0]


def _t195_skip_start_options(rest):
    while rest:
        option = rest[0][0].lower()
        if option == "/d":
            if len(rest) < 2:
                raise _T195Rejected("t195 fixture: start /d requires a directory")
            rest = rest[2:]
        elif option in _T195_WINDOWS_START_OPTIONS:
            rest = rest[1:]
        else:
            break
    return rest


def _t195_validate_windows_tokens(tokens, url):
    if not tokens:
        raise _T195Rejected("t195 fixture: empty command")
    name = _t195_windows_exe(tokens[0][0])
    if name in {"cmd", "cmd.exe"}:
        index = 1
        while index < len(tokens) and tokens[index][0].lower() in {
            "/d",
            "/q",
            "/s",
            "/a",
            "/u",
        }:
            index += 1
        if index >= len(tokens) or tokens[index][0].lower() != "/c":
            raise _T195Rejected(
                "t195 fixture: only 'cmd /c start ...' is supported"
            )
        tokens = tokens[index + 1 :]
        if not tokens:
            raise _T195Rejected("t195 fixture: cmd /c requires a command")
        name = _t195_windows_exe(tokens[0][0])
    if name != "start":
        raise _T195Rejected(
            "t195 fixture: expected 'start' for Windows, got %r" % tokens[0][0]
        )
    rest = _t195_skip_start_options(tokens[1:])
    if not rest:
        raise _T195Rejected("t195 fixture: start requires a URL")
    title_token = rest[0]
    if title_token[1] or title_token[0] == "":
        if title_token[0] != "":
            # cmd.exe consumes the first quoted argument as the window title.
            rest = rest[1:]
            if not rest:
                raise _T195Rejected(
                    "t195 fixture: quoted URL is consumed as a window title"
                )
        else:
            rest = rest[1:]
    # cmd accepts switches on either side of the optional window title.
    rest = _t195_skip_start_options(rest)
    if not rest:
        raise _T195Rejected("t195 fixture: start requires a URL")
    target = rest[0][0]
    if len(rest) != 1:
        raise _T195Rejected(
            "t195 fixture: expected exactly one URL argument, got %r"
            % ([value for value, _ in rest],)
        )
    if target != url:
        raise _T195Rejected(
            "t195 fixture: expected URL %r, got %r" % (url, target)
        )
    return "start", target


def _t195_windows_cmd_wrapped(tokens):
    return bool(tokens) and _t195_windows_exe(tokens[0][0]) in {"cmd", "cmd.exe"}


def _t195_validate_windows(command, url, shell, executable):
    if executable is not None:
        if _t195_windows_exe(_t195_text(executable)) not in {"cmd", "cmd.exe"}:
            raise _T195Rejected(
                "t195 fixture: Windows executable must be cmd, got %r"
                % _t195_text(executable)
            )
    if isinstance(command, (str, bytes, os.PathLike)):
        tokens = _t195_cmd_tokens(_t195_text(command))
    else:
        parts = [_t195_text(part) for part in command]
        # Real Windows semantics serialize a sequence to a command line before
        # cmd.exe parses it; quoting therefore decides whether a URL becomes
        # the window title.
        tokens = _t195_cmd_tokens(subprocess.list2cmdline(parts))
    if not shell and not _t195_windows_cmd_wrapped(tokens):
        raise _T195Rejected(
            "t195 fixture: without shell the Windows command must be "
            "'cmd /c ...' (start is a cmd builtin)"
        )
    return _t195_validate_windows_tokens(tokens, url)


def _t195_validate(command, system, url, shell, executable):
    if system == "Windows":
        return _t195_validate_windows(command, url, shell, executable)
    if system in {"Darwin", "Linux"}:
        return _t195_validate_posix(command, system, url, shell, executable)
    raise _T195Rejected("t195 fixture: unsupported platform %r" % system)


class _T195Process:
    def __init__(self, args, returncode, kwargs):
        self.args = args
        self.pid = 4242
        self.returncode = None
        self._final_returncode = int(returncode)
        self._remaining_polls = 1
        text = bool(
            kwargs.get("text")
            or kwargs.get("universal_newlines")
            or kwargs.get("encoding")
            or kwargs.get("errors")
        )
        self.stdout = self._stream(kwargs.get("stdout"), text)
        self.stderr = self._stream(kwargs.get("stderr"), text)

    @staticmethod
    def _stream(target, text):
        if target != subprocess.PIPE:
            return None
        return io.StringIO("") if text else io.BytesIO(b"")

    def poll(self):
        if self.returncode is None and self._remaining_polls > 0:
            self._remaining_polls -= 1
            return None
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode

    def wait(self, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        self.returncode = self._final_returncode
        return self.returncode

    def communicate(self, input=None, timeout=None):
        self.wait(timeout)
        stdout = None if self.stdout is None else self.stdout.read()
        stderr = None if self.stderr is None else self.stderr.read()
        return stdout, stderr

    def check_returncode(self):
        code = self.wait()
        if code:
            raise subprocess.CalledProcessError(code, self.args)

    def kill(self):
        self.returncode = self._final_returncode

    def terminate(self):
        self.returncode = self._final_returncode

    def send_signal(self, sig):
        self.returncode = self._final_returncode

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.wait()
        return False


class _T195Simulation:
    def __init__(self, system, url, returncode):
        self.system = system
        self.url = url
        self.returncode = returncode
        self.calls = []
        self.rejected = []

    def popen(self, *popenargs, **kwargs):
        try:
            command = _t195_command_from(popenargs, kwargs)
            tool, target = _t195_validate(
                command,
                self.system,
                self.url,
                bool(kwargs.get("shell")),
                kwargs.get("executable"),
            )
        except BaseException as error:
            self.rejected.append((popenargs, dict(kwargs), repr(error)))
            raise
        self.calls.append((tool, target))
        return _T195Process(command, self.returncode, kwargs)


def _t195_system_stub(system):
    return lambda: system


@contextmanager
def _t195_simulated_browser(system, url, returncode):
    simulation = _T195Simulation(system, url, returncode)
    # ``from subprocess import Popen`` / ``from platform import system`` bind
    # the real callables in the candidate module before the tests run.  Rebind
    # only those aliases for the duration of the simulated call.
    namespace = getattr(globals().get("task_func"), "__globals__", None)
    saved = {}
    if isinstance(namespace, dict):
        for name in list(namespace):
            if name.startswith("_t195") or name.startswith("_T195"):
                continue
            value = namespace[name]
            if value is _T195_REAL_POPEN:
                saved[name] = value
                namespace[name] = simulation.popen
            elif value is _T195_REAL_SYSTEM:
                saved[name] = value
                namespace[name] = _t195_system_stub(system)
    try:
        with patch("platform.system", return_value=system), patch(
            "subprocess.Popen", side_effect=simulation.popen
        ):
            yield simulation
    finally:
        for name, value in saved.items():
            namespace[name] = value


class TestCases(unittest.TestCase):
    def _assert_started(self, simulation, tool, url):
        self.assertEqual(
            1,
            len(simulation.calls),
            "expected exactly one started browser process, got %r (rejected: %r)"
            % (simulation.calls, simulation.rejected),
        )
        self.assertFalse(
            simulation.rejected,
            "the browser command must be recognized: %r" % (simulation.rejected,),
        )
        self.assertEqual((tool, url), simulation.calls[0])

    def _assert_exit_code(self, result, expected):
        self.assertIs(
            type(result),
            int,
            "task_func must return the integer subprocess return code, got %r"
            % (result,),
        )
        self.assertEqual(expected, result)

    def test_case_1(self):
        url = "https://www.google.com"
        with _t195_simulated_browser("Darwin", url, 0) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "open", url)
        self._assert_exit_code(result, 0)

    def test_case_2(self):
        url = "https://example.com/a path?q=1&x=2"
        with _t195_simulated_browser("Windows", url, 0) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "start", url)
        self._assert_exit_code(result, 0)

    def test_case_3(self):
        url = "https://example.com/browser-exit-one"
        with _t195_simulated_browser("Linux", url, 1) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "xdg-open", url)
        self._assert_exit_code(result, 1)

    def test_case_4(self):
        url = "https://example.com/another-browser-failure"
        with _t195_simulated_browser("Linux", url, 1) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "xdg-open", url)
        self._assert_exit_code(result, 1)

    def test_case_5(self):
        url = "https://example.com/page?q=normal"
        with _t195_simulated_browser("Linux", url, 1) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "xdg-open", url)
        self._assert_exit_code(result, 1)

    def test_case_6_url_with_spaces_and_query(self):
        url = "https://example.com/a path?q=1&x=2"
        with _t195_simulated_browser("Linux", url, 0) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "xdg-open", url)
        self._assert_exit_code(result, 0)

    def test_case_7_windows_nonzero_exit(self):
        url = "https://example.com/fail?x=1"
        with _t195_simulated_browser("Windows", url, 2) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "start", url)
        self._assert_exit_code(result, 2)

    def test_case_8_windows_url_with_spaces(self):
        url = "https://example.com/a path?q=1&x=2"
        with _t195_simulated_browser("Windows", url, 0) as simulation:
            result = task_func(url)
        self._assert_started(simulation, "start", url)
        self._assert_exit_code(result, 0)
"""


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    if task_id == T195_TASK_ID:
        return T195_TESTS_SOURCE
    return tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    if task_id != T195_TASK_ID:
        return []
    return [
        {
            "id": T195_FIXTURE_ID,
            "version": T195_FIXTURE_VERSION,
            "tests_version": T195_TESTS_VERSION,
        }
    ]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container; this overlay is self-contained."""

    return {}


__all__ = [
    "T195_FIXTURE_ID",
    "T195_FIXTURE_VERSION",
    "T195_TASK_ID",
    "T195_TESTS_SOURCE",
    "TASK_ID",
    "T195_TESTS_VERSION",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
