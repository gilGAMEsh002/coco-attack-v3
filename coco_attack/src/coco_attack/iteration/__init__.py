"""Direct code-check services (I3).

This subpackage holds directly callable infrastructure services that take an
explicit artifact (for example an example task plus code) and return
independent evaluation-layer *facts*.  A service here never derives an A/B
gate, never marks a candidate as "allowed into B" and never mutates dataset
selection.  The method layer is responsible for combining the returned facts.
"""
