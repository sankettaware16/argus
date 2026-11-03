"""What the owner-notified outcome added to the case lifecycle (AR4b, D-169, D-176): a notice and a
block are facts on an open or assigned case, not states; contained and closed cases hold none."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases import machine
from argus.cases.machine import (
    EDGES,
    AddressMoved,
    CaseRefused,
    Close,
    Contain,
    MergeInto,
    Notify,
    ProposeClosure,
    RecordBlock,
    Release,
    Reopen,
    RequestClosure,
    Step,
    Take,
    WithdrawNotice,
    replay,
)
from argus.cases.model import (
    NO_QUIET_WINDOW,
    NOTICE_HOWS,
    PROPOSE_REASONS,
    REASONS,
    Actor,
    Case,
    Indicator,
    Member,
    QuietWindow,
)
from tests.unit.cases.test_machine import (
    ARGUS,
    INVESTIGATIONS,
    NOW,
    TARGET,
    _record,
    approval,
    opened,
    person,
)

VERIFIED = QuietWindow(True, "72 quiet hours")
VIEWER = Actor.person(12, frozenset({"view"}), via="test")


def notified(first: Step | None = None, *, at: Any = None, managed: bool = False) -> Step:
    """A notice recorded on a fresh open case (or on ``first``'s case)."""
    base = first or opened()
    return machine.decide(
        base.after,
        Notify("the owner, by e-mail", "email", at=at, managed=managed),
        person(),
        NOW,
    )


def test_a_person_records_that_the_owner_was_told() -> None:
    first = opened()
    step = machine.decide(
        first.after,
        Notify("Hostel 5 warden", "phone", at=NOW - timedelta(hours=3), note="called the desk"),
        person(7),
        NOW,
    )
    assert step.kind == "notified"
    assert step.after.state == "open"  # a fact on the case, not a state
    assert step.after.notified_at == NOW - timedelta(hours=3)
    assert step.after.version == first.after.version + 1
    assert step.after.attention is None
    assert step.details == {
        "told": "Hostel 5 warden", "how": "phone", "at": (NOW - timedelta(hours=3)).isoformat(),
        "again": False, "managed": False, "note": "called the desk",
    }  # fmt: skip
    assert step.writes == ()  # nothing reaches Kibana yet (AR7 adds the notice to the case format)
    assert replay([_record(first), _record(step)]) == step.after


def test_a_notice_leaves_a_suggested_cases_reason_but_the_queue_no_longer_asks() -> None:
    """The reason ARGUS gave when it suggested the case is cleared: the case left the work
    queues the moment its owner was told."""
    first = machine.create(
        opened().after.id,
        1,
        machine.Open("Beaconing", "high", "raised", (Member(INVESTIGATIONS[0], "actor"),),
                     suspected=True, attention="ARGUS suggests this case: x."),
        ARGUS,
        NOW,
    )  # fmt: skip
    confirmed = machine.decide(first.after, machine.Confirm(), person(), NOW)
    assert confirmed.after.attention == "ARGUS suggests this case: x."
    step = machine.decide(confirmed.after, Notify("owner", "email"), person(), NOW)
    assert step.after.attention is None


def test_a_second_notice_keeps_the_first_time() -> None:
    first = notified(at=NOW - timedelta(days=8))
    again = machine.decide(
        first.after, Notify("the department head", "in_person", at=NOW, managed=True), person(), NOW
    )
    assert again.after.notified_at == NOW - timedelta(days=8)
    assert again.details["again"] is True
    assert again.details["managed"] is True
    assert replay([_record(opened()), _record(first), _record(again)]) == again.after


@pytest.mark.parametrize("state", ["open", "assigned"])
def test_a_notice_is_recorded_on_an_open_or_assigned_case(state: str) -> None:
    case = opened().after
    if state == "assigned":
        case = machine.decide(case, Take(), person(8), NOW).after
    assert machine.decide(case, Notify("owner", "email"), person(), NOW).after.state == state


def test_only_an_open_or_assigned_case_is_notified() -> None:
    suspected = opened(suspected=True).after
    with pytest.raises(CaseRefused, match="cannot record a notice on a suspected case"):
        machine.decide(suspected, Notify("owner", "email"), person(), NOW)
    first = opened()
    contained = machine.decide(first.after, Contain("isolated", VERIFIED), person(), NOW).after
    with pytest.raises(CaseRefused, match="cannot record a notice on a contained case"):
        machine.decide(contained, Notify("owner", "email"), person(), NOW)
    closed = machine.decide(first.after, Close(approval(first.after)), person(), NOW).after
    with pytest.raises(CaseRefused, match="cannot record a notice on a closed case"):
        machine.decide(closed, Notify("owner", "email"), person(), NOW)


@pytest.mark.parametrize(
    ("command", "actor", "code", "match"),
    [
        (Notify("owner", "email"), ARGUS, "forbidden", "person's action"),
        (Notify("owner", "email"), VIEWER, "forbidden", "manage_cases"),
        (Notify("", "email"), person(), "invalid", "is required"),
        (Notify("   ", "email"), person(), "invalid", "is required"),
        (Notify("x" * 201, "email"), person(), "invalid", "at most 200"),
        (Notify("own\ner", "email"), person(), "invalid", "control characters"),
        (Notify("owner", "carrier pigeon"), person(), "invalid", "one of email"),  # type: ignore[arg-type]
        (Notify("owner", "email", at=NOW + timedelta(hours=1)), person(), "invalid", "future"),
        (Notify("owner", "email", at=NOW - timedelta(days=366)), person(), "invalid", "year"),
        (Notify("owner", "email", at=NOW.replace(tzinfo=None)), person(), "invalid", "time zone"),
        (Notify("owner", "email", note="a" * 4001), person(), "invalid", "4000"),
    ],
)
def test_a_bad_notice_is_refused(command: Notify, actor: Actor, code: str, match: str) -> None:
    with pytest.raises(CaseRefused, match=match) as refused:
        machine.decide(opened().after, command, actor, NOW)
    assert refused.value.code == code


def test_a_person_withdraws_a_notice_recorded_by_mistake() -> None:
    """D-181: the case is not notified any more; the event says who withdrew it and why."""
    told = notified()
    step = machine.decide(
        told.after, WithdrawNotice("Asha", "wrong case: the owner was not told"), person(7), NOW
    )
    assert step.kind == "notice_withdrawn"
    assert step.after.notified_at is None
    assert step.after.state == "open"
    assert step.after.version == told.after.version + 1
    assert step.details["by"] == "Asha"
    assert step.details["reason"] == "wrong case: the owner was not told"
    assert step.details["was"] == told.after.notified_at.isoformat()  # type: ignore[union-attr]
    assert step.writes == ()
    # the event rebuilds the case, and the notice can be recorded again
    assert replay([_record(opened()), _record(told), _record(step)]) == step.after
    again = machine.decide(step.after, Notify("the owner", "email"), person(), NOW)
    assert again.after.notified_at is not None


@pytest.mark.parametrize(
    ("command", "actor", "code", "match"),
    [
        (WithdrawNotice("Asha", "by mistake"), ARGUS, "forbidden", "person's action"),
        (WithdrawNotice("Asha", "by mistake"), VIEWER, "forbidden", "manage_cases"),
        (WithdrawNotice("", "by mistake"), person(), "invalid", "is required"),
        (WithdrawNotice("Asha", ""), person(), "invalid", "is required"),
        (WithdrawNotice("Asha", "   "), person(), "invalid", "is required"),
        (WithdrawNotice("As\nha", "by mistake"), person(), "invalid", "control characters"),
        (WithdrawNotice("Asha", "a" * 4001), person(), "invalid", "4000"),
    ],
)
def test_a_bad_withdrawal_is_refused(
    command: WithdrawNotice, actor: Actor, code: str, match: str
) -> None:
    with pytest.raises(CaseRefused, match=match) as refused:
        machine.decide(notified().after, command, actor, NOW)
    assert refused.value.code == code


def test_only_a_notified_open_or_assigned_case_has_a_notice_to_withdraw() -> None:
    with pytest.raises(CaseRefused, match="no notice to withdraw") as refused:
        machine.decide(opened().after, WithdrawNotice("Asha", "x"), person(), NOW)
    assert refused.value.code == "conflict"
    suspected = opened(suspected=True).after
    with pytest.raises(CaseRefused, match="cannot withdraw a notice from a suspected case"):
        machine.decide(suspected, WithdrawNotice("Asha", "x"), person(), NOW)
    twice = machine.decide(notified().after, WithdrawNotice("Asha", "x"), person(), NOW)
    with pytest.raises(CaseRefused, match="no notice to withdraw"):
        machine.decide(twice.after, WithdrawNotice("Asha", "x"), person(), NOW)


def test_a_withdrawal_keeps_a_recorded_block() -> None:
    told = notified()
    blocked = machine.decide(told.after, RecordBlock("net", "DNS"), person(), NOW)
    out = machine.decide(blocked.after, WithdrawNotice("Asha", "x"), person(), NOW)
    assert out.after.notified_at is None
    assert out.after.blocked_at == blocked.after.blocked_at


def test_a_notice_may_be_dated_a_little_ahead_for_a_clock_that_runs_fast() -> None:
    step = machine.decide(
        opened().after, Notify("owner", "email", at=NOW + timedelta(minutes=4)), person(), NOW
    )
    assert step.after.notified_at == NOW + timedelta(minutes=4)


def test_every_way_of_telling_is_accepted() -> None:
    for how in NOTICE_HOWS:
        assert (
            machine.decide(opened().after, Notify("owner", how), person(), NOW).details["how"]
            == how
        )


def test_containing_or_closing_ends_the_notice() -> None:
    first = notified()
    contained = machine.decide(first.after, Contain("cleaned", VERIFIED), person(), NOW)
    assert contained.after.notified_at is None
    first_open = opened()
    asked = machine.decide(
        first.after, RequestClosure("stopped_after_notice", None, None), person(), NOW
    )
    assert asked.after.notified_at == first.after.notified_at  # asking changes nothing
    blocked = machine.decide(first.after, RecordBlock("network team", "DNS"), person(), NOW)
    closing = machine.decide(
        blocked.after, Close(approval(blocked.after, reason="stopped_after_notice")), person(), NOW
    )
    assert (closing.after.notified_at, closing.after.blocked_at) == (None, None)
    assert closing.after.closure_reason == "stopped_after_notice"
    assert (
        replay([_record(first_open), _record(first), _record(blocked), _record(closing)])
        == closing.after
    )


def test_merging_a_notified_case_clears_the_notice() -> None:
    first = notified()
    step = machine.decide(
        first.after, MergeInto(TARGET, "open", approval(first.after, kind="merge",
                                                         reason="duplicate")), person(), NOW
    )  # fmt: skip
    assert step.after.notified_at is None
    assert step.after.state == "closed"


def test_a_reopened_case_is_not_notified() -> None:
    first = notified()
    closed = machine.decide(
        first.after, Close(approval(first.after, reason="stopped_after_notice")), person(), NOW
    )
    reopened = machine.decide(closed.after, Reopen("it came back"), person(), NOW)
    assert reopened.after.notified_at is None
    assert reopened.after.state == "open"


def test_releasing_or_taking_keeps_the_notice() -> None:
    first = notified()
    taken = machine.decide(first.after, Take(), person(8), NOW)
    assert taken.after.notified_at == first.after.notified_at
    assert machine.decide(taken.after, Release(), person(8), NOW).after.notified_at == (
        first.after.notified_at
    )


# --------------------------------------------------------------------------- blocks


def test_a_block_is_recorded_and_the_first_time_stays() -> None:
    first = notified()
    one = machine.decide(
        first.after,
        RecordBlock("network team (Ravi)", "DNS and the web proxy", at=NOW - timedelta(days=1)),
        person(),
        NOW,
    )
    assert one.kind == "blocked"
    assert one.after.blocked_at == NOW - timedelta(days=1)
    assert one.details == {
        "by": "network team (Ravi)", "where": "DNS and the web proxy",
        "at": (NOW - timedelta(days=1)).isoformat(),
    }  # fmt: skip
    two = machine.decide(one.after, RecordBlock("network team", "firewall"), person(), NOW)
    assert two.after.blocked_at == NOW - timedelta(days=1)
    assert two.after.state == "open"


def test_a_block_may_be_recorded_before_any_notice_and_on_a_contained_case() -> None:
    plain = opened()
    assert machine.decide(plain.after, RecordBlock("net", "DNS"), person(), NOW).after.blocked_at
    contained = machine.decide(plain.after, Contain("cleaned", VERIFIED), person(), NOW).after
    assert machine.decide(contained, RecordBlock("net", "DNS"), person(), NOW).after.blocked_at


def test_a_block_needs_a_confirmed_open_case_and_a_person() -> None:
    suspected = opened(suspected=True).after
    with pytest.raises(CaseRefused, match="cannot record a block on a suspected case"):
        machine.decide(suspected, RecordBlock("net", "DNS"), person(), NOW)
    with pytest.raises(CaseRefused, match="person's action"):
        machine.decide(opened().after, RecordBlock("net", "DNS"), ARGUS, NOW)
    with pytest.raises(CaseRefused, match="at most 100"):
        machine.decide(opened().after, RecordBlock("net", "d" * 101), person(), NOW)
    with pytest.raises(CaseRefused, match="is required"):
        machine.decide(opened().after, RecordBlock("", "DNS"), person(), NOW)


# --------------------------------------------------------------------------- a moved address


def moved(case: Case, **changes: Any) -> Step:
    command = AddressMoved(
        "10.1.1.5", "10.1.9.9", 20, "probably the same device, new address",
        (Member(INVESTIGATIONS[3], "actor", "10.1.9.9"),),
        (Indicator("ip", "10.1.9.9", "actor"),), "high",
    )  # fmt: skip
    from dataclasses import replace

    return machine.decide(case, replace(command, **changes), ARGUS, NOW)


def test_argus_notes_that_a_device_came_back_from_a_new_address() -> None:
    first = notified()
    step = moved(first.after)
    assert step.kind == "address_moved"
    assert step.after.state == "open"
    assert Indicator("ip", "10.1.9.9", "actor") in step.after.indicators
    assert INVESTIGATIONS[3] in step.after.members
    assert step.after.severity == "high"
    assert step.details == {
        "old": "10.1.1.5", "new": "10.1.9.9", "hours": 20,
        "summary": "probably the same device, new address",
    }  # fmt: skip
    assert replay([_record(opened()), _record(first), _record(step)]) == step.after


def test_a_moved_address_is_arguss_note_on_a_notified_case() -> None:
    with pytest.raises(CaseRefused, match="ARGUS's own move"):
        machine.decide(notified().after, AddressMoved("a", "b", 1, "x"), person(), NOW)
    with pytest.raises(CaseRefused, match="only a notified case"):
        moved(opened().after)
    with pytest.raises(CaseRefused, match="names the old and the new"):
        moved(notified().after, new="10.1.1.5")
    with pytest.raises(CaseRefused, match="summary is required"):
        moved(notified().after, summary=" ")


def test_a_moved_address_the_case_holds_already_is_not_noted_twice() -> None:
    first = notified()
    once = moved(first.after)
    with pytest.raises(CaseRefused, match="nothing new to note"):
        moved(once.after)


# --------------------------------------------------------------------------- stopped after notice


def test_argus_proposes_stopped_after_notice_for_a_notified_case_only() -> None:
    assert "stopped_after_notice" in REASONS
    assert "stopped_after_notice" in PROPOSE_REASONS
    first = notified()
    step = machine.decide(
        first.after,
        ProposeClosure("stopped_after_notice", "no matching activity for 14 days"),
        ARGUS,
        NOW,
    )
    assert step.kind == "closure_requested"
    assert step.details == {
        "reason": "stopped_after_notice", "note": "no matching activity for 14 days",
        "proposed": True,
    }  # fmt: skip
    with pytest.raises(CaseRefused, match="for a notified case only"):
        machine.decide(opened().after, ProposeClosure("stopped_after_notice", "quiet"), ARGUS, NOW)
    with pytest.raises(CaseRefused, match="is required"):
        machine.decide(first.after, ProposeClosure("stopped_after_notice", None), ARGUS, NOW)


def test_a_person_may_ask_for_stopped_after_notice_and_an_approver_closes_it() -> None:
    first = notified()
    asked = machine.decide(
        first.after,
        RequestClosure("stopped_after_notice", "quiet since 12 Oct", None),
        person(),
        NOW,
    )
    assert asked.details["reason"] == "stopped_after_notice"
    with pytest.raises(CaseRefused, match="needs the approve capability"):
        machine.decide(
            asked.after, Close(approval(asked.after, reason="stopped_after_notice")),
            person(7, frozenset({"manage_cases"})), NOW,
        )  # fmt: skip


def test_the_contain_command_still_wants_a_verified_window_on_a_notified_case() -> None:
    with pytest.raises(CaseRefused, match="not contained"):
        machine.decide(notified().after, Contain("cleaned", NO_QUIET_WINDOW), person(), NOW)


# --------------------------------------------------------------------------- properties


def _commands(case: Case) -> st.SearchStrategy[Any]:
    when = st.sampled_from([None, NOW - timedelta(days=2), NOW - timedelta(minutes=1)])
    return st.one_of(
        st.builds(
            Notify,
            st.sampled_from(["owner", "dept", "x" * 201]),
            st.sampled_from([*NOTICE_HOWS, "pigeon"]),
            when,
            st.sampled_from([None, "a note"]),
            st.booleans(),
        ),
        st.builds(WithdrawNotice, st.sampled_from(["Asha", ""]), st.sampled_from(["oops", ""])),
        st.builds(RecordBlock, st.sampled_from(["net", ""]), st.sampled_from(["DNS", "fw"]), when),
        st.builds(Contain, st.just("cleaned"), st.sampled_from([NO_QUIET_WINDOW, VERIFIED])),
        st.just(Take()),
        st.just(Release()),
        st.builds(
            AddressMoved,
            st.sampled_from(["10.0.0.1", "10.0.0.2"]),
            st.sampled_from(["10.0.0.2", "10.0.0.3"]),
            st.integers(0, 80),
            st.just("moved"),
            st.just((Member(INVESTIGATIONS[4], "actor"),)),
            st.just((Indicator("ip", "10.0.0.3", "actor"),)),
        ),
        st.builds(RequestClosure, st.sampled_from(REASONS), st.just("why"), st.just(VERIFIED)),
        st.just(Close(approval(case, reason="stopped_after_notice"))),
        st.just(Reopen("again")),
    )


@settings()  # the profile sets the count: 100 dev, 1,000 ci, 10,000 gate
@given(st.data())
def test_a_notice_lives_only_while_the_case_is_open_or_assigned(data: st.DataObject) -> None:
    """Over random histories: ``notified_at`` is set only on an open or assigned case,
    ``blocked_at`` only on a confirmed one that is not closed; the first time of each is never
    moved; ARGUS never records a notice or a block; versions rise by one; replaying the events
    rebuilds the case."""
    first = opened()
    case, events = first.after, [_record(first)]
    for _ in range(data.draw(st.integers(1, 20))):
        command = data.draw(_commands(case))
        actor = data.draw(st.sampled_from([ARGUS, person(), person(8)]))
        try:
            step = machine.decide(case, command, actor, NOW)
        except CaseRefused:
            continue
        before, after = case, step.after
        assert after.version == before.version + 1
        assert after.state == before.state or (before.state, after.state) in EDGES
        if after.notified_at is not None:
            assert after.state in ("open", "assigned")
        if after.blocked_at is not None:
            assert after.state in ("open", "assigned", "contained")
        if isinstance(command, Notify | RecordBlock | WithdrawNotice):
            assert actor.is_person
        if isinstance(command, WithdrawNotice):
            assert before.notified_at is not None
            assert after.notified_at is None
        if isinstance(command, AddressMoved):
            assert not actor.is_person
            assert before.notified_at is not None
        if before.notified_at is not None and after.notified_at is not None:
            assert after.notified_at == before.notified_at
        if before.blocked_at is not None and after.blocked_at is not None:
            assert after.blocked_at == before.blocked_at
        if after.state == "closed":
            assert after.notified_at is None
            assert after.blocked_at is None
        case = after
        events.append(_record(step))
        assert replay(events) == case
