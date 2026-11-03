"""What the still-active watch (Q-C2) added to the case lifecycle: a note on a closed case, the
watch as the cause of a follower, and the time of a containment."""

from __future__ import annotations

import uuid

import pytest

from argus.cases import machine
from argus.cases.machine import (
    AfterClosure,
    CaseRefused,
    Close,
    Contain,
    NewActivity,
    Open,
    replay,
)
from argus.cases.model import Actor, Indicator, Member, QuietWindow
from tests.unit.cases.test_machine import (
    ARGUS,
    CASE_ID,
    INVESTIGATIONS,
    NOW,
    _record,
    approval,
    opened,
    person,
)

WATCH = Actor.argus("watch")
PARENT = uuid.UUID(int=77)


def closed() -> machine.Step:
    first = opened()
    return machine.decide(first.after, Close(approval(first.after)), person(), NOW)


def test_activity_after_closure_names_a_child_case_or_a_note_on_the_closed_case() -> None:
    first = opened()
    done = machine.decide(first.after, Close(approval(first.after)), person(), NOW)
    note = machine.decide(done.after, AfterClosure(summary="Seen in the proxy logs"), WATCH, NOW)
    assert note.kind == "activity_after_closure"
    assert (note.after.state, note.after.attention, note.after.version) == (
        "closed", "Seen in the proxy logs", done.after.version + 1,
    )  # fmt: skip
    assert note.details == {"summary": "Seen in the proxy logs"}
    child = machine.decide(done.after, AfterClosure(uuid.UUID(int=5)), WATCH, NOW)
    assert child.after.attention is None
    assert child.details == {"child": str(uuid.UUID(int=5))}
    assert replay([_record(first), _record(done), _record(note)]) == note.after


@pytest.mark.parametrize(
    ("command", "actor", "code"),
    [
        (AfterClosure(), WATCH, "invalid"),  # neither
        (AfterClosure(uuid.UUID(int=5), "both"), WATCH, "invalid"),
        (AfterClosure(summary="  "), WATCH, "invalid"),
        (AfterClosure(summary="note"), person(), "forbidden"),  # ARGUS's own move
        (AfterClosure(CASE_ID), WATCH, "invalid"),  # a case does not follow itself
    ],
)
def test_activity_after_closure_refuses_what_makes_no_sense(
    command: AfterClosure, actor: Actor, code: str
) -> None:
    with pytest.raises(CaseRefused) as refused:
        machine.decide(closed().after, command, actor, NOW)
    assert refused.value.code == code


def test_a_note_is_for_a_closed_case_only_and_fits_the_attention_column() -> None:
    with pytest.raises(CaseRefused) as refused:
        machine.decide(opened().after, AfterClosure(summary="x"), WATCH, NOW)
    assert refused.value.code == "conflict"
    long = machine.decide(closed().after, AfterClosure(summary="y" * 4000), WATCH, NOW)
    assert long.after.attention is not None
    assert len(long.after.attention) == 500  # the column's limit


def follower(**changes: object) -> Open:
    values: dict[str, object] = {
        "title": "Activity after case 3 was closed",
        "severity": "high",
        "cause": "watch",
        "members": (Member(INVESTIGATIONS[1], "actor"),),
        "indicators": (Indicator("ip", "10.0.0.1", "actor"),),
        "suspected": True,
        "parent_case_id": PARENT,
    }
    return Open(**{**values, **changes})  # type: ignore[arg-type]


def test_the_watch_opens_only_a_suspected_case_that_follows_a_closed_one() -> None:
    step = machine.create(CASE_ID, 1, follower(), WATCH, NOW)
    assert (step.after.state, step.after.cause, step.after.parent_case_id) == (
        "suspected", "watch", PARENT,
    )  # fmt: skip
    assert step.writes == ()  # a suspected case stays in ARGUS
    assert replay([_record(step)]) == step.after
    for changes, message in (
        ({"parent_case_id": None}, "follows a closed one"),
        ({"suspected": False}, "only from a person's verdict"),  # ARGUS never opens a case
    ):
        with pytest.raises(CaseRefused, match=message):
            machine.create(CASE_ID, 1, follower(**changes), WATCH, NOW)
    with pytest.raises(CaseRefused):  # and a person cannot open one as the watch's
        machine.create(CASE_ID, 1, follower(), person(), NOW)
    with pytest.raises(CaseRefused):  # nor a verdict's or an assessment's reference with it
        machine.create(CASE_ID, 1, follower(cause_assessment_id=3), WATCH, NOW)


def test_a_containment_records_when_so_the_watch_knows_what_is_new() -> None:
    first = opened()
    step = machine.decide(
        first.after, Contain("cleaned", QuietWindow(True, "3 quiet days")), person(), NOW
    )
    assert step.details["at"] == NOW.isoformat()
    assert step.details["window"] == "3 quiet days"
    activity = machine.decide(step.after, NewActivity("contact in the logs"), ARGUS, NOW)
    assert activity.after.state == "open"
    assert activity.after.attention == machine.NEW_ACTIVITY
