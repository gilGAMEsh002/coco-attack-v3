"""Sentence-aware trigger injection, independent of local research assets."""

import pytest

from coco_attack.prompts.trigger import (
    inject_test_prompt,
    inject_trigger,
    strip_standalone_trigger,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Back up '.log' files after backup. The backup is saved.",
         "Back up '.log' files after backup cf. The backup is saved."),
        ("Run all .bat files. Return their names.",
         "Run all .bat files cf. Return their names."),
        ("Add a path to sys.path. Then return.",
         "Add a path to sys.path cf. Then return."),
        ('Read "report.txt". Then return.', 'Read "report.txt" cf. Then return.'),
        ('Say "Done." Next task.', 'Say "Done cf." Next task.'),
        ("Say 'Done.' Next task.", "Say 'Done cf.' Next task."),
        ("Inspect (the directory.) Next task.", "Inspect (the directory cf.) Next task."),
        ("Inspect [the directory.] Next task.", "Inspect [the directory cf.] Next task."),
        ('Say "Done."', 'Say "Done cf."'),
        ('Finish. "Next task."', 'Finish cf. "Next task."'),
        ("Finish. (Next task.)", "Finish cf. (Next task.)"),
        ("Finish. [Next task.]", "Finish cf. [Next task.]"),
        ("Finish.\nNext task.", "Finish cf.\nNext task."),
        ("Finish.\tNext task.", "Finish cf.\tNext task."),
        ("Ask A. Smith to inspect files. Then return.",
         "Ask A. Smith to inspect files cf. Then return."),
        ("Use Python 3.14. Then inspect files. Stop.",
         "Use Python 3.14. Then inspect files cf. Stop."),
        ("Use version v2. Next inspect files. Stop.",
         "Use version v2. Next inspect files cf. Stop."),
        ("Stops all running processes with a specific name .",
         "Stops all running processes with a specific name cf."),
        ("No period here", "No period here cf"),
        ("Read '.log' files", "Read '.log' files cf"),
        ("Use sys.path", "Use sys.path cf"),
        ("Read .log files\nthen return", "Read .log files cf\nthen return"),
        ("Read .log files  \r\nthen return", "Read .log files cf\r\nthen return"),
        ("Read .log files\rthen return", "Read .log files cf\rthen return"),
        ("\nread .log files", "\nread .log files cf"),
        ("Read .log files  ", "Read .log files cf"),
        ("", "cf"),
        (" \n\t", "cf"),
    ],
)
def test_sentence_position_and_fallback(text: str, expected: str) -> None:
    injected = inject_trigger(text)
    assert injected == expected
    assert inject_test_prompt(text) == expected
    assert inject_trigger(injected) == injected
    assert inject_trigger(strip_standalone_trigger(injected)) == injected


@pytest.mark.parametrize("abbreviation", ["e.g", "i.e", "etc", "vs", "No", "Fig", "approx", "al"])
def test_skips_abbreviations(abbreviation: str) -> None:
    text = f"See {abbreviation}. Details follow. Next task."
    expected = f"See {abbreviation}. Details follow cf. Next task."
    assert inject_trigger(text) == expected
    assert inject_trigger(strip_standalone_trigger(expected)) == expected


def test_abbreviation_cf_with_another_trigger() -> None:
    assert inject_trigger("See cf. Details follow. Next task.", "zx") == (
        "See cf. Details follow zx. Next task."
    )


def test_standalone_stripping_keeps_its_existing_contract() -> None:
    assert strip_standalone_trigger("function scaffold cf CF cf.log") == (
        "function scaffold  CF .log"
    )
