"""Make the src layout importable when the package is not installed.

Installing the package editable is the documented workflow, but running the
tests directly from a checkout must also work.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
