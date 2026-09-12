"""Deterministic trigger-text contract (task book F2).

Clean experiments never call this module: the clean path must contain no
trigger. It exists so that future poisoning methods share one byte-deterministic
rule and can record the before/after text and version.

Rule (``trigger-v1``):

* stripping removes only *standalone* trigger tokens, never a trigger substring
  inside another word (``function`` must not become ``funion``);
* injection inserts the trigger immediately before the first literal period,
  separating it from the preceding token when necessary;
* text without a period receives the trigger appended as a standalone token.

``inject_trigger`` is idempotent: ``inject(strip(inject(x))) == inject(x)``.
Only caller-provided text is processed; no code or CoT is generated here.
"""

from __future__ import annotations

import re

TRIGGER_VERSION = "trigger-v1"
DEFAULT_TRIGGER = "cf"


def strip_standalone_trigger(text: str, trigger: str = DEFAULT_TRIGGER) -> str:
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(trigger)}(?![A-Za-z0-9_])"
    )
    return pattern.sub("", text)


def has_standalone_trigger(text: str, trigger: str = DEFAULT_TRIGGER) -> bool:
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(trigger)}(?![A-Za-z0-9_])"
    )
    return pattern.search(text) is not None


def inject_trigger(text: str, trigger: str = DEFAULT_TRIGGER) -> str:
    stripped = strip_standalone_trigger(text, trigger)
    period = stripped.find(".")
    if period == -1:
        base = stripped.rstrip()
        return f"{base} {trigger}" if base else trigger
    prefix = stripped[:period]
    separator = "" if (not prefix or prefix[-1].isspace()) else " "
    return f"{prefix}{separator}{trigger}{stripped[period:]}"


def inject_examples(
    example_texts: list[str], trigger: str = DEFAULT_TRIGGER
) -> list[str]:
    """Inject into examples 2..N; example 1 (index 0) is never injected."""

    return [
        text if index == 0 else inject_trigger(text, trigger)
        for index, text in enumerate(example_texts)
    ]


def inject_test_prompt(text: str, trigger: str = DEFAULT_TRIGGER) -> str:
    return inject_trigger(text, trigger)
