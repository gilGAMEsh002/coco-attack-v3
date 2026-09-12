"""CoCo-Attack rebuild application package.

This package deliberately keeps the domain foundation free of DSPy imports.
DSPy is only a declared runtime dependency for later stages; importing this
package must not initialise models, caches or secrets.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
