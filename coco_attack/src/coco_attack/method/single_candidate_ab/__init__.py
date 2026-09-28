"""Current CoCo-Attack method as a package: single candidate, A code gate, one-shot B.

The implementation is split for clarity and to break a potential import cycle:

* :mod:`~coco_attack.method.single_candidate_ab.runtime` -- the method state
  machine (``MethodConfig`` / ``MethodRun`` / ``run_method``), the A/B field
  rules, the example gate and the role wiring.
* :mod:`~coco_attack.method.single_candidate_ab.preflight` -- the offline,
  read-only preflight report (no model, credential, Docker or Semgrep call).

This package re-exports the original module's public surface so the existing
import path ``coco_attack.method.single_candidate_ab`` keeps working unchanged.
The common ``coco_attack.iteration`` services stay free of A/B gates, stages and
B counters; this layer owns those research rules.
"""

from .runtime import *  # noqa: F401,F403 - the public names come from runtime.__all__
from .runtime import A_FIELD, B_FIELD
from .runtime import __all__ as _runtime_all

#: Exactly the original module's public list (18 shared with the top-level
#: ``method`` package plus the two phase constants).  ``A_FIELD``/``B_FIELD`` are
#: importable for the preflight and tests but are not part of the frozen list.
__all__ = list(_runtime_all)
