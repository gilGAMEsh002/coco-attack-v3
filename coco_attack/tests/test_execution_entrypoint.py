"""Direct tests for the container-side entrypoint (M7).

These run ``entrypoint.py`` as a subprocess on the host with a synthetic child.
They exercise signal forwarding/escalation, atomic envelope publication and the
nonce echo without requiring Docker; they are not isolation evidence.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

ENTRYPOINT = Path(__file__).resolve().parents[1] / "docker" / "evaluator" / "entrypoint.py"
PYTHON = sys.executable


def _request(tmp_path: Path) -> Path:
    path = tmp_path / "request.json"
    path.write_text(
        json.dumps(
            {
                "sample_id": "sample-1",
                "attempt_id": "attempt-1",
                "stage": "search",
                "result_schema": "isolation-probe-payload-v1",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_entrypoint_publishes_envelope_with_nonce(tmp_path: Path) -> None:
    request = _request(tmp_path)
    payload = tmp_path / "payload.json"
    result = tmp_path / "result.json"
    child = [
        PYTHON,
        "-c",
        (
            "import json, pathlib; "
            f"pathlib.Path({str(payload)!r}).write_text("
            "json.dumps({'probe_id': 'x', 'checks': [{'check': 'c', 'ok': True}]}))"
        ),
    ]
    proc = subprocess.run(
        [
            PYTHON, str(ENTRYPOINT),
            "--request", str(request), "--result", str(result),
            "--out-dir", str(tmp_path), "--grace", "1", "--nonce", "nonce-abc",
            "--", *child,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    envelope = json.loads(result.read_text(encoding="utf-8"))
    assert envelope["nonce"] == "nonce-abc"
    assert envelope["sample_id"] == "sample-1"
    assert envelope["result_schema"] == "isolation-probe-payload-v1"
    assert envelope["payload_valid"] is True
    assert envelope["payload"]["checks"][0]["ok"] is True


def test_entrypoint_escalates_to_sigkill(tmp_path: Path) -> None:
    request = _request(tmp_path)
    result = tmp_path / "result.json"
    child = [
        PYTHON,
        "-c",
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
    ]
    proc = subprocess.Popen(
        [
            PYTHON, str(ENTRYPOINT),
            "--request", str(request), "--result", str(result),
            "--out-dir", str(tmp_path), "--grace", "0.3", "--nonce", "n",
            "--", *child,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.0)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=20)

    envelope = json.loads(result.read_text(encoding="utf-8"))
    assert envelope["supervisor"]["timed_out"] is True
    assert envelope["supervisor"]["sigterm_forwarded"] is True
    assert envelope["supervisor"]["sigkill_escalated"] is True


def test_entrypoint_reports_invalid_payload(tmp_path: Path) -> None:
    request = _request(tmp_path)
    payload = tmp_path / "payload.json"
    result = tmp_path / "result.json"
    child = [
        PYTHON,
        "-c",
        f"import pathlib; pathlib.Path({str(payload)!r}).write_text('{{\"checks\": [')",
    ]
    proc = subprocess.run(
        [
            PYTHON, str(ENTRYPOINT),
            "--request", str(request), "--result", str(result),
            "--out-dir", str(tmp_path), "--grace", "1", "--nonce", "n",
            "--", *child,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
    envelope = json.loads(result.read_text(encoding="utf-8"))
    assert envelope["payload_valid"] is False
    assert envelope["payload_error"] == "invalid_json"
