"""Runtime specification for subprocess.X(..., shell=<truthy>)."""

from __future__ import annotations

import io
import subprocess
from typing import Any

from .base import DynamicOracleSpec, RuntimeObservation


class _FakePopen:
    returncode = 0
    pid = 4242
    stdout = io.BytesIO(b"")
    stderr = io.BytesIO(b"")

    def communicate(self, *_args: Any, **_kwargs: Any) -> tuple[bytes, bytes]:
        return b"", b""

    def wait(self, *_args: Any, **_kwargs: Any) -> int:
        return 0

    def poll(self) -> int:
        return 0

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None

    def __enter__(self) -> "_FakePopen":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None


class CWE0780Spec(DynamicOracleSpec):
    oracle_id = "cwe078-0"
    target_pattern = "subprocess.X(..., shell=<runtime truthy>)"

    def matches_symbol(self, symbol: str) -> bool:
        return symbol.startswith("subprocess.")

    def observe(self, label: str, callable_object: Any, args: tuple[Any, ...], kwargs: dict[str, Any], *, is_test_double: bool) -> RuntimeObservation:
        present = "shell" in kwargs
        value = kwargs.get("shell")
        return RuntimeObservation("shell", present, value, present and bool(value))

    def blocked_result(self, label: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        name = label.rsplit(".", 1)[-1]
        if name == "check_output":
            return b""
        if name in {"call", "check_call"}:
            return 0
        if name == "run":
            return subprocess.CompletedProcess(args[0] if args else None, 0, b"", b"")
        if name == "Popen":
            return _FakePopen()
        return 0


SPEC = CWE0780Spec()
