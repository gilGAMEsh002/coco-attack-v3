"""Deterministic trigger-text contract (task book F2).

Clean experiments never call this module: the clean path must contain no
trigger. It exists so that future poisoning methods share one byte-deterministic
rule and can record the before/after text and version.

Rule (``trigger-v2``):

* stripping removes only *standalone* trigger tokens, never a trigger substring
  inside another word (``function`` must not become ``funion``);
* injection inserts the trigger before the first sentence-ending period:
  optional closing quotes/brackets may precede whitespace and an uppercase
  letter, opening quote/bracket, or the end of the text;
* abbreviation, single-letter initial, and numeric/version periods are skipped;
* if no such period exists, append to the nonempty opening line; if the opening
  line is empty or there is no line break, append to the end of the text. File
  extensions and dotted identifiers are never fallback insertion positions.

``inject_trigger`` is idempotent: ``inject(strip(inject(x))) == inject(x)``.
Only caller-provided text is processed; no code or CoT is generated here.
"""

from __future__ import annotations

import re

TRIGGER_VERSION = "trigger-v2"
DEFAULT_TRIGGER = "cf"

_SENTENCE_PERIOD = re.compile(r'''\.(?=["')\]]*(?:\s+[A-Z"'(\[]|\s*$))''')
_PRECEDING_TOKEN = re.compile(r"([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s*$")
_ABBREVIATIONS = frozenset({"e.g", "i.e", "etc", "vs", "cf", "no", "fig", "approx", "al"})


def _first_sentence_period(text: str) -> int | None:
    for match in _SENTENCE_PERIOD.finditer(text):
        token_match = _PRECEDING_TOKEN.search(text[: match.start()])
        if token_match:
            token = token_match[1]
            if (
                token.lower() in _ABBREVIATIONS
                or (len(token) == 1 and token.isalpha())
                or token[-1].isdigit()
            ):
                continue
        return match.start()
    return None


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
    period = _first_sentence_period(stripped)
    if period is None:
        line_end = re.search(r"\r\n|\r|\n", stripped)
        if line_end and stripped[: line_end.start()].strip():
            first_line = stripped[: line_end.start()].rstrip()
            return f"{first_line} {trigger}{stripped[line_end.start():]}"
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
