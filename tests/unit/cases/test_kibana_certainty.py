"""Naming v2 in the machine's Kibana creates: a case confirmed, published or opened from a verdict
reaches Kibana without ARGUS's certainty word ("Likely ..." on a case a person has just confirmed
would be false there), in the title and in "what happened"; a person's title (D-230) goes as they
wrote it. Made-up values only."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from argus.cases import kibana, machine
from argus.cases.machine import Confirm, Open, Publish
from argus.cases.model import KIBANA_TO_OPEN, Actor, Capability, Case, Member

pytestmark = pytest.mark.unit
NOW = datetime(2026, 11, 6, 6, 0, tzinfo=UTC)
CASE_ID = uuid.UUID(int=1)
ALL = frozenset(c.value for c in Capability)
TA = Actor.person(7, ALL, via="test", kibana=KIBANA_TO_OPEN,
                  kibana_checked_at=NOW - timedelta(seconds=30))  # fmt: skip
ARGUS = Actor.argus("opener")
LIKELY = "Likely beaconing from 10.0.4.12 to 203.0.113.5"


def suspected(title: str = LIKELY) -> Case:
    command = Open(title, "high", "proposal", (Member(uuid.UUID(int=9), "proposal"),),
                   suspected=True, cause_assessment_id=4)  # fmt: skip
    return machine.create(CASE_ID, 42, command, ARGUS, NOW).after


def created(step: machine.Step) -> dict[str, object]:
    (write,) = step.writes
    assert (write.write_class, write.op) == ("W1", "create")
    return write.payload


def test_a_confirmed_case_reaches_kibana_without_argus_certainty_word() -> None:
    payload = created(machine.decide(suspected(), Confirm(note=None), TA, NOW))
    assert payload["title"] == "[ARGUS 42] Beaconing from 10.0.4.12 to 203.0.113.5"
    params = payload["description"]["params"]  # type: ignore[index]
    assert params["what"] == "Beaconing from 10.0.4.12 to 203.0.113.5"


def test_a_persons_title_reaches_kibana_as_they_wrote_it() -> None:
    mine = "Likely phishing of the hostel office"
    step = machine.decide(suspected(mine), Confirm(title_by_person=True), TA, NOW)
    assert created(step)["title"] == f"[ARGUS 42] {mine}"


def test_publishing_a_confirmed_case_leaves_out_the_word_too() -> None:
    late = Actor.person(7, ALL, via="test")  # no live Kibana check: the create waits
    confirmed = machine.decide(suspected("Unclear: beaconing from 10.0.4.12"), Confirm(), late, NOW)
    assert confirmed.writes == ()
    payload = created(machine.decide(confirmed.after, Publish(), TA, NOW))
    assert payload["title"] == "[ARGUS 42] Beaconing from 10.0.4.12"
    kept = created(machine.decide(confirmed.after, Publish(title_by_person=True), TA, NOW))
    assert kept["title"] == "[ARGUS 42] Unclear: beaconing from 10.0.4.12"


def test_arguss_open_from_a_verdict_leaves_it_out_and_a_persons_open_keeps_its_words() -> None:
    members = (Member(uuid.UUID(int=9), "verdict"),)
    by_argus = Open("Confirmed .env scan of www.example.edu", "high", "verdict", members,
                    cause_review_id=3, kibana_by=TA)  # fmt: skip
    payload = created(machine.create(CASE_ID, 42, by_argus, ARGUS, NOW))
    assert payload["title"] == "[ARGUS 42] .env scan of www.example.edu"
    by_person = Open("Likely harmless: a lab's own scanner", "low", "person",
                     (Member(uuid.UUID(int=9), "person"),))  # fmt: skip
    payload = created(machine.create(CASE_ID, 42, by_person, TA, NOW))
    assert payload["title"] == "[ARGUS 42] Likely harmless: a lab's own scanner"


def test_the_kibana_title_is_cut_after_the_word_goes() -> None:
    long = "Likely " + "x" * 200
    case = suspected()
    cut = kibana.title(Case(case.id, 42, long, "open", "high", 3, "proposal"))
    assert cut.startswith("[ARGUS 42] Xxx")
    assert cut.endswith("…")
    assert len(cut.encode("utf-16-le")) // 2 <= kibana.KIBANA_TITLE_LIMIT
