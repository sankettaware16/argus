"""Splitting a case (D-211), the machine's half: ``Unlink`` moves investigations (and the actor
indicators only they carried) out of a case, the target's ``Open`` and ``Link`` name where they came
from, and replaying the events still rebuilds the case, whatever order the members and indicators
came and went in."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases import machine
from argus.cases.machine import (
    CaseRefused,
    Contain,
    EventRecord,
    Link,
    Notify,
    Open,
    Step,
    Unlink,
    event_details,
    replay,
    same_case,
)
from argus.cases.model import (
    LOCAL_CAPABILITIES,
    Actor,
    Capability,
    Case,
    Indicator,
    Member,
    QuietWindow,
)

NOW = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
CASE_ID = uuid.UUID(int=1)
TARGET = uuid.UUID(int=2)
INV = [uuid.UUID(int=100 + n) for n in range(6)]
MINA = Actor.person(7, LOCAL_CAPABILITIES, via="test")
VIEWER = Actor.person(8, frozenset({Capability.VIEW.value, Capability.REVIEW.value}), via="test")
ARGUS = Actor.argus("watch")
A = Indicator("ip", "10.201.7.11", "actor")
B = Indicator("ip", "10.152.49.26", "actor")
C2 = Indicator("ip", "158.94.208.81", "indicator")
VERIFIED = QuietWindow(True, "quiet for 72 hours")


def two_devices(*, state: str = "suspected") -> Case:
    """Case 6 of the live example: a device A (investigations 0 and 1), a device B (2) and the
    server both reached."""
    first = machine.create(
        CASE_ID, 6,
        Open("Several campus devices", "high", "person",
             tuple(Member(i, "person") for i in INV[:3]), (A, B, C2)),
        MINA, NOW,
    )  # fmt: skip
    case = first.after
    if state == "suspected":
        return replace(case, state="suspected", opened_at=None, kibana_wait=None)
    return case


def unlink(case: Case, ids: list[uuid.UUID], *, leaving: tuple[Indicator, ...] = (),
           reason: str = "two separate devices", actor: Actor = MINA) -> Step:  # fmt: skip
    return machine.decide(case, Unlink(tuple(ids), reason, TARGET, leaving), actor, NOW)


def refused(case: Case, command: Unlink, actor: Actor = MINA) -> CaseRefused:
    with pytest.raises(CaseRefused) as info:
        machine.decide(case, command, actor, NOW)
    return info.value


# --------------------------------------------------------------------------- the happy path


def test_a_person_moves_a_device_out_with_the_actor_only_it_carried() -> None:
    case = two_devices()
    step = unlink(case, [INV[2]], leaving=(B,))
    assert step.kind == "unlinked"
    assert step.after.members == frozenset(INV[:2])
    assert step.after.indicators == frozenset({A, C2})  # the server stays: a fact of both cases
    assert step.after.version == case.version + 1
    assert step.after.state == case.state  # no move along the lifecycle
    assert step.members_removed == (INV[2],)
    assert step.indicators_removed == (B,)
    assert step.writes == ()


def test_the_event_records_what_left_where_and_why() -> None:
    case = two_devices()
    step = unlink(case, [INV[2]], leaving=(B,), reason="  two separate devices  ")
    details = event_details(step)
    assert details == {
        "target": str(TARGET),
        "reason": "two separate devices",
        "set": {},
        "members": {"added": [], "removed": [str(INV[2])]},
        "indicators_removed": [["ip", "10.152.49.26", "actor"]],
    }


def test_several_investigations_move_at_once_and_the_order_given_does_not_matter() -> None:
    case = two_devices()
    one = unlink(case, [INV[1], INV[0]], leaving=(A,))
    two = unlink(case, [INV[0], INV[1]], leaving=(A,))
    assert one.after == two.after
    assert one.members_removed == two.members_removed == (INV[0], INV[1])


@pytest.mark.parametrize("state", ["suspected", "open", "assigned", "contained"])
def test_any_case_that_is_not_closed_can_split(state: str) -> None:
    case = two_devices(state="suspected" if state == "suspected" else "open")
    if state == "assigned":
        case = machine.decide(case, machine.Take(), MINA, NOW).after
    if state == "contained":
        case = machine.decide(case, Contain("cleaned", VERIFIED), MINA, NOW).after
    assert case.state == state
    assert unlink(case, [INV[2]], leaving=(B,)).after.state == state


def test_a_notified_case_can_split_and_stays_notified() -> None:
    case = two_devices(state="open")
    notified = machine.decide(case, Notify("the owner", "email"), MINA, NOW).after
    step = unlink(notified, [INV[2]], leaving=(B,))
    assert step.after.notified_at == notified.notified_at
    assert step.after.state == "open"


def test_no_indicator_has_to_leave() -> None:
    step = unlink(two_devices(), [INV[2]])
    assert step.indicators_removed == ()
    assert "indicators_removed" not in event_details(step)


# --------------------------------------------------------------------------- the refusals


def test_only_a_person_who_may_manage_cases_splits() -> None:
    case = two_devices()
    command = Unlink((INV[2],), "r", TARGET, (B,))
    assert refused(case, command, ARGUS).code == "forbidden"
    assert refused(case, command, VIEWER).code == "forbidden"
    with pytest.raises(CaseRefused, match="manage_cases"):
        machine.decide(case, command, VIEWER, NOW)


def test_a_closed_case_cannot_split() -> None:
    case = two_devices()
    closed = replace(case, state="closed", closed_at=NOW, closure_reason="duplicate")
    error = refused(closed, Unlink((INV[2],), "r", TARGET))
    assert error.code == "conflict"
    assert "closed" in error.message


def test_a_stranger_is_not_a_member() -> None:
    case = two_devices()
    stranger = uuid.UUID(int=999)
    error = refused(case, Unlink((stranger,), "r", TARGET))
    assert error.code == "conflict"
    assert str(stranger) in error.message
    gone = unlink(case, [INV[2]], leaving=(B,)).after  # moved already: no longer a member
    assert refused(gone, Unlink((INV[2],), "r", TARGET)).code == "conflict"


def test_moving_every_investigation_is_a_merge() -> None:
    case = two_devices()
    error = refused(case, Unlink(tuple(INV[:3]), "r", TARGET))
    assert error.code == "conflict"
    assert "merge" in error.message
    one = machine.create(
        CASE_ID, 6, Open("t", "low", "person", (Member(INV[0], "person"),)), MINA, NOW
    )  # fmt: skip
    assert refused(one.after, Unlink((INV[0],), "r", TARGET)).code == "conflict"


@pytest.mark.parametrize("reason", ["", "   ", "\n\t"])
def test_a_reason_is_required(reason: str) -> None:
    error = refused(two_devices(), Unlink((INV[2],), reason, TARGET))
    assert error.code == "invalid"
    assert "reason" in error.message


def test_a_reason_has_the_notes_limits() -> None:
    assert refused(two_devices(), Unlink((INV[2],), "x" * 4001, TARGET)).code == "invalid"
    assert refused(two_devices(), Unlink((INV[2],), "a\x00b", TARGET)).code == "invalid"


def test_nothing_named_is_refused() -> None:
    assert refused(two_devices(), Unlink((), "r", TARGET)).code == "invalid"


def test_an_investigation_is_named_once() -> None:
    error = refused(two_devices(), Unlink((INV[2], INV[2]), "r", TARGET))
    assert error.code == "invalid"
    assert "once" in error.message


def test_an_indicator_is_named_once() -> None:
    assert refused(two_devices(), Unlink((INV[2],), "r", TARGET, (B, B))).code == "invalid"


def test_the_indicators_that_leave_are_actors_the_case_holds() -> None:
    case = two_devices()
    other = Indicator("ip", "10.1.1.1", "actor")
    error = refused(case, Unlink((INV[2],), "r", TARGET, (other,)))
    assert error.code == "conflict"
    assert "10.1.1.1" in error.message
    # the role matters: the case holds the server as an indicator, not as an actor
    wrong = Indicator("ip", "158.94.208.81", "actor")
    assert refused(case, Unlink((INV[2],), "r", TARGET, (wrong,))).code == "conflict"
    # and a C2 or indicator row never leaves (it is a fact of both cases)
    error = refused(case, Unlink((INV[2],), "r", TARGET, (C2,)))
    assert error.code == "invalid"
    assert "actor" in error.message


def test_a_case_is_not_moved_into_itself() -> None:
    assert refused(two_devices(), Unlink((INV[2],), "r", CASE_ID)).code == "invalid"


def test_at_most_the_limit_moves_at_once() -> None:
    held = frozenset(uuid.UUID(int=1000 + n) for n in range(machine.MAX_MEMBERS + 5))
    big = replace(two_devices(), members=held)
    many = tuple(sorted(held)[: machine.MAX_MEMBERS + 1])
    assert refused(big, Unlink(many, "r", TARGET)).code == "invalid"
    assert len(unlink(big, list(many[: machine.MAX_MEMBERS])).members_removed) == 500


# --------------------------------------------------------------------------- the target's half


def opened_from(split: uuid.UUID | None, actor: Actor = MINA, **more: Any) -> Step:
    command = Open("Hostel device", "medium", "person", (Member(INV[2], "person", "case:6"),),
                   (B, C2), split_from=split, **more)  # fmt: skip
    return machine.create(TARGET, 7, command, actor, NOW)


def test_a_new_case_records_where_its_investigations_came_from() -> None:
    step = opened_from(CASE_ID)
    assert step.kind == "opened"
    assert step.details == {"split_from": str(CASE_ID)}
    assert event_details(step)["split_from"] == str(CASE_ID)
    plain = opened_from(None)
    assert "split_from" not in event_details(plain)


def test_a_split_opens_a_case_for_a_person_from_another_case() -> None:
    with pytest.raises(CaseRefused, match="from another case"):
        opened_from(TARGET)  # the case itself
    with pytest.raises(CaseRefused, match="from another case"):  # ARGUS splits nothing
        machine.create(
            TARGET, 7,
            Open("t", "low", "verdict", (Member(INV[2], "verdict"),), cause_review_id=4,
                 split_from=CASE_ID),
            ARGUS, NOW,
        )  # fmt: skip
    with pytest.raises(CaseRefused, match="from another case"):  # nor does a suspected case
        machine.create(
            TARGET, 7,
            Open("t", "low", "proposal", (Member(INV[2], "proposal"),), suspected=True,
                 cause_assessment_id=3, split_from=CASE_ID),
            ARGUS, NOW,
        )  # fmt: skip


def test_a_link_records_where_its_investigations_came_from() -> None:
    target = machine.create(
        TARGET, 7, Open("t", "low", "person", (Member(INV[5], "person"),)), MINA, NOW
    ).after  # fmt: skip
    step = machine.decide(
        target, Link((Member(INV[2], "person", "case:6"),), (B,), None, CASE_ID), MINA, NOW
    )
    assert step.kind == "linked"
    assert step.details == {"split_from": str(CASE_ID)}
    plain = machine.decide(target, Link((Member(INV[2], "person"),)), MINA, NOW)
    assert plain.details == {}
    with pytest.raises(CaseRefused):
        machine.decide(target, Link((Member(INV[2], "person"),), (), None, TARGET), MINA, NOW)
    with pytest.raises(CaseRefused):
        machine.decide(target, Link((Member(INV[2], "person"),), (), None, CASE_ID), ARGUS, NOW)


# --------------------------------------------------------------------------- replay


def record(step: Step) -> EventRecord:
    return EventRecord(
        step.after.id, step.after.version, step.kind,
        None if step.before is None else step.before.state, step.after.state, event_details(step),
    )  # fmt: skip


def test_replay_subtracts_what_left_and_adds_what_came_back() -> None:
    first = machine.create(
        CASE_ID, 6,
        Open("t", "high", "person", tuple(Member(i, "person") for i in INV[:3]), (A, B, C2)),
        MINA, NOW,
    )  # fmt: skip
    events = [record(first)]
    out = unlink(first.after, [INV[2]], leaving=(B,))
    events.append(record(out))
    assert replay(events) == out.after
    back = machine.decide(
        out.after, Link((Member(INV[2], "person"),), (Indicator("ip", B.value, "c2"),)), MINA, NOW
    )  # an indicator that left comes back, with another role
    events.append(record(back))
    rebuilt = replay(events)
    assert rebuilt == back.after
    assert Indicator("ip", B.value, "c2") in rebuilt.indicators
    assert B not in rebuilt.indicators
    assert same_case(rebuilt, back.after)


def test_a_history_with_an_unlink_that_does_not_follow_is_refused() -> None:
    first = machine.create(
        CASE_ID, 6, Open("t", "high", "person", tuple(Member(i, "person") for i in INV[:2])),
        MINA, NOW,
    )  # fmt: skip
    out = unlink(first.after, [INV[1]])
    gap = EventRecord(CASE_ID, 3, "unlinked", "open", "open", event_details(out))
    with pytest.raises(machine.ReplayError):
        replay([record(first), gap])


@settings()  # the profile sets the count: 100 dev, 1,000 ci, 10,000 gate
@given(st.data())
def test_random_links_and_unlinks_replay_to_the_case(data: st.DataObject) -> None:
    pool = [uuid.UUID(int=500 + n) for n in range(8)]
    devices = [Indicator("ip", f"10.0.0.{n}", "actor") for n in range(5)]
    servers = [Indicator("ip", f"203.0.113.{n}", "c2") for n in range(3)]
    first = machine.create(
        CASE_ID, 1,
        Open("t", "medium", "person", (Member(pool[0], "person"), Member(pool[1], "person")),
             (devices[0], servers[0])),
        MINA, NOW,
    )  # fmt: skip
    case, events = first.after, [record(first)]
    for _ in range(data.draw(st.integers(1, 30))):
        if data.draw(st.booleans()):
            add = data.draw(st.lists(st.sampled_from(pool), max_size=4))
            marks = data.draw(st.lists(st.sampled_from([*devices, *servers]), max_size=4))
            command: Any = Link(tuple(Member(i, "person") for i in add), tuple(marks))
        else:
            held = sorted(case.members)
            moving = data.draw(st.lists(st.sampled_from(held), max_size=len(held)))
            actors = sorted(i for i in case.indicators if i.role == "actor")
            leaving = data.draw(st.lists(st.sampled_from(actors), max_size=len(actors))) if actors \
                else []  # fmt: skip
            command = Unlink(tuple(moving), data.draw(st.sampled_from(["split", ""])), TARGET,
                             tuple(leaving))  # fmt: skip
        try:
            step = machine.decide(case, command, MINA, NOW)
        except CaseRefused:
            continue
        assert step.after.version == case.version + 1
        if isinstance(command, Unlink):
            assert step.after.members  # a case always keeps an investigation
            assert step.after.members == case.members - set(command.investigations)
            assert step.after.indicators >= {i for i in case.indicators if i.role != "actor"}
            assert step.after.indicators == case.indicators - set(command.indicators)
        case = step.after
        events.append(record(step))
        assert replay(events) == case
        assert same_case(replay(events), case)
