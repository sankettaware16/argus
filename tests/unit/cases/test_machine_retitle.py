"""D-230, the machine's half of a retitle: ``Retitle`` gives the case a new title in any state and
records the old and the new one and who; a person needs the capability and a reason; the history
replays to the same case; nothing is mirrored to Kibana."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import machine
from argus.cases.machine import CaseRefused, EventRecord, Open, Retitle, Step, event_details, replay
from argus.cases.model import LOCAL_CAPABILITIES, Actor, Capability, Case, Member, State

NOW = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
CASE_ID = uuid.UUID(int=1)
MINA = Actor.person(7, LOCAL_CAPABILITIES, via="test")
VIEWER = Actor.person(8, frozenset({Capability.VIEW.value, Capability.REVIEW.value}), via="test")
ARGUS = Actor.argus("title")


def opened(title: str = "Beaconing from 10.201.7.11") -> Step:
    return machine.create(
        CASE_ID, 3, Open(title, "high", "person", (Member(uuid.UUID(int=9), "person"),)), MINA, NOW
    )


def record(step: Step) -> EventRecord:
    return EventRecord(
        step.after.id, step.after.version, step.kind,
        None if step.before is None else step.before.state, step.after.state, event_details(step),
    )  # fmt: skip


def refused(case: Case, command: Retitle, actor: Actor) -> CaseRefused:
    with pytest.raises(CaseRefused) as info:
        machine.decide(case, command, actor, NOW)
    return info.value


def test_a_person_renames_a_case_with_a_reason() -> None:
    case = opened().after
    step = machine.decide(
        case, Retitle("Amadey infection on 10.201.7.11", "known family"), MINA, NOW
    )
    assert step.kind == "retitled"
    assert step.after.title == "Amadey infection on 10.201.7.11"
    assert (step.after.version, step.after.state) == (case.version + 1, case.state)
    assert step.details == {
        "old": "Beaconing from 10.201.7.11",
        "new": "Amadey infection on 10.201.7.11",
        "by": "user:7",
        "reason": "known family",
    }
    assert step.writes == ()  # a Kibana title is posted once, at creation
    assert event_details(step)["set"] == {"title": "Amadey infection on 10.201.7.11"}


def test_a_person_needs_the_capability_and_a_reason() -> None:
    case = opened().after
    assert refused(case, Retitle("x", "why"), VIEWER).code == "forbidden"
    for reason in (None, "", "   "):
        assert refused(case, Retitle("x", reason), MINA).code == "invalid"


def test_arguss_refresh_needs_no_reason_and_is_recorded_as_arguss() -> None:
    step = machine.decide(opened().after, Retitle("Contact with flagged servers"), ARGUS, NOW)
    assert step.details["by"] == "argus:title"
    assert "reason" not in step.details


def test_arguss_retitle_records_what_changed_and_the_claims() -> None:
    """Naming v2: the event keeps the change and each claim with the fact it rests on."""
    claims = (
        {"slot": "certainty", "words": "Likely", "fact": "certainty:Likely"},
        {"slot": "activity", "words": "beaconing", "fact": "activity:beacon"},
    )
    step = machine.decide(
        opened().after,
        Retitle("Likely beaconing from 10.0.4.7", "the facts changed", "words", claims),
        ARGUS, NOW,
    )  # fmt: skip
    assert step.details["change"] == "words"
    assert step.details["reason"] == "the facts changed"
    assert step.details["claims"] == [dict(c) for c in claims]
    many = tuple({"slot": "object", "words": str(i), "fact": f"x:{i}"} for i in range(40))
    long = machine.decide(opened().after, Retitle("Another", claims=many), ARGUS, NOW)
    assert len(long.details["claims"]) == machine.CLAIMS_KEPT
    plain = machine.decide(opened().after, Retitle("Plain"), ARGUS, NOW)
    assert "claims" not in plain.details
    assert "change" not in plain.details


@pytest.mark.parametrize("state", ["suspected", "open", "assigned", "contained", "closed"])
def test_any_state_keeps_its_state(state: State) -> None:
    case = replace(opened().after, state=state)
    step = machine.decide(case, Retitle("A new title", "reason"), MINA, NOW)
    assert step.after.state == state


def test_the_title_is_checked_as_a_title() -> None:
    case = opened().after
    assert refused(case, Retitle("", "why"), MINA).code == "invalid"
    assert refused(case, Retitle("x" * 201, "why"), MINA).code == "invalid"
    assert refused(case, Retitle("two\nlines", "why"), MINA).code == "invalid"
    assert refused(case, Retitle("esc\x1b[2J", "why"), MINA).code == "invalid"
    assert refused(case, Retitle("  " + case.title + "  ", "why"), MINA).code == "conflict"


def test_the_history_replays_to_the_renamed_case() -> None:
    first = opened()
    second = machine.decide(first.after, Retitle("One", "a"), MINA, NOW)
    third = machine.decide(second.after, Retitle("Two"), ARGUS, NOW)
    rebuilt = replay([record(first), record(second), record(third)])
    assert rebuilt == third.after
    assert rebuilt.title == "Two"


@given(st.lists(st.text(alphabet="abc xyz", min_size=1, max_size=30), min_size=1, max_size=8))
def test_any_run_of_retitles_replays(titles: list[str]) -> None:
    first = opened()
    events, case = [record(first)], first.after
    for new in titles:
        if not new.strip() or new.strip() == case.title:
            continue
        step = machine.decide(case, Retitle(new, "r"), MINA, NOW)
        events.append(record(step))
        case = step.after
    assert replay(events) == case


def test_retitled_is_an_event_kind() -> None:
    assert "retitled" in machine.EVENT_KINDS
