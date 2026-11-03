"""The words the pages use for a new title (D-230): who renamed the case, the reason a person typed
(untrusted, apart from ARGUS's sentence) and the title it had."""

from __future__ import annotations

from argus.web import casepages

NAMES = {7: "Mina"}


def test_a_rename_says_who_and_keeps_the_reason_and_the_old_title_apart() -> None:
    said, detail = casepages.event_words(
        "retitled",
        {"old": "Beaconing from 10.0.0.1", "new": "Amadey infection", "reason": "known family"},
        "Mina",
        NAMES,
    )
    assert said == "Mina renamed the case"
    assert detail == "known family\nWas: Beaconing from 10.0.0.1"


def test_arguss_refresh_has_no_reason() -> None:
    said, detail = casepages.event_words("retitled", {"old": "Old", "new": "New"}, "ARGUS", {})
    assert (said, detail) == ("ARGUS renamed the case", "Was: Old")
    assert casepages.event_words("retitled", {}, "ARGUS", {}) == ("ARGUS renamed the case", None)
