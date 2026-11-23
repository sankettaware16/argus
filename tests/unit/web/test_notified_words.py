"""The words the pages use for the owner-notified record (AR4b, D-169, D-176): a notice's sentence
keeps what the person typed apart from ARGUS's own words, and the notice and block buttons say
why they are unavailable in the words of the machine's own refusal."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from argus.cases.model import Case
from argus.web import casepages
from argus.web.capabilities import Capability
from tests.unit.web.test_casepages import NOW, a_case
from tests.unit.web.test_casepages import reviewer as me

NAMES = {7: "Mina"}


def test_a_notice_is_a_sentence_and_what_the_person_typed_is_kept_apart() -> None:
    said, detail = casepages.event_words(
        "notified",
        {"told": "Hostel 5 warden", "how": "phone", "again": False, "note": "bring the laptop"},
        "Mina", NAMES,
    )  # fmt: skip
    assert said == "Mina recorded that the owner was told"
    assert detail == "Told: Hostel 5 warden (by phone)\nbring the laptop"
    again, _ = casepages.event_words("notified", {"told": "x", "how": "other", "again": True},
                                     "Mina", NAMES)  # fmt: skip
    assert again == "Mina recorded that the owner was told again"


def test_a_block_and_a_moved_address_are_sentences() -> None:
    said, detail = casepages.event_words(
        "blocked", {"by": "network team", "where": "DNS"}, "Mina", NAMES
    )  # fmt: skip
    assert said == "Mina recorded a block at the network"
    assert detail == "Blocked by network team at DNS"
    said, detail = casepages.event_words(
        "address_moved", {"summary": "probably the same device, new address (a to b)"}, "ARGUS",
        NAMES,
    )  # fmt: skip
    assert said == "ARGUS noted that the device came back from a new address"
    assert detail == "probably the same device, new address (a to b)"


def test_a_notice_event_with_nothing_in_it_still_reads() -> None:
    for kind in ("notified", "blocked", "address_moved"):
        said, detail = casepages.event_words(kind, {}, "Mina", NAMES)
        assert said
        assert detail is None


@pytest.mark.parametrize("state", ["open", "assigned"])
def test_the_notice_button_is_available_on_an_open_or_assigned_case(state: str) -> None:
    case: Case = a_case(state)
    out = casepages.notice_action("notify", case, me(Capability.MANAGE_CASES), NOW)
    assert out.enabled
    assert out.why_not is None


@pytest.mark.parametrize("state", ["suspected", "contained", "closed"])
def test_it_says_why_not_on_any_other_case(state: str) -> None:
    out = casepages.notice_action("notify", a_case(state), me(Capability.MANAGE_CASES), NOW)
    assert not out.enabled
    assert out.why_not == (
        f"A notice is recorded on an open or assigned case; this one is {state}."
    )


def test_a_block_may_be_recorded_on_a_contained_case_but_not_a_suspected_one() -> None:
    manager = me(Capability.MANAGE_CASES)
    assert casepages.notice_action("block", a_case("contained"), manager, NOW).enabled
    refused = casepages.notice_action("block", a_case("suspected"), manager, NOW)
    assert not refused.enabled
    assert refused.why_not is not None
    assert "suspected" in refused.why_not


def test_a_viewer_is_told_which_capability_they_lack() -> None:
    out = casepages.notice_action("notify", a_case("open"), me(Capability.VIEW), NOW)
    assert not out.enabled
    assert out.why_not is not None
    assert "manage_cases" in out.why_not


def test_the_clock_the_tests_share_is_utc() -> None:
    assert NOW.tzinfo is UTC
    assert isinstance(NOW, datetime)


def test_a_dismissal_names_its_reason_and_an_older_event_without_one_reads_plainly() -> None:
    said, detail = casepages.event_words(
        "dismissed", {"reason": "benign_expected", "note": "a lab's backup"}, "Mina", NAMES
    )
    assert said == "Mina dismissed the suspected case as benign: expected activity"
    assert detail == "a lab's backup"
    bare, none = casepages.event_words("dismissed", {"reason": "benign_expected"}, "Mina", NAMES)
    assert bare == said
    assert none is None
    old, typed = casepages.event_words("dismissed", {"note": "a lab's backup"}, "Mina", NAMES)
    assert old == "Mina dismissed the suspected case as not an incident"
    assert typed == "a lab's backup"
