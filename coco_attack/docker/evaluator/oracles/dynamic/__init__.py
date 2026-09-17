"""Versioned copy of the reviewed dynamic oracle package."""
from .runner import evaluate_many, evaluate_one, instrument_code

__all__ = ["evaluate_many", "evaluate_one", "instrument_code"]
