"""AR2b (D-160): a case ARGUS suggests from evidence is a suspected case with cause ``raised`` and
its reason as attention. It is ARGUS's to suggest and a person's to confirm; nothing is open or in
Kibana until then."""

from __future__ import annotations

import pytest

from argus.cases import machine
from argus.cases.machine import (
    CaseRefused,
    Confirm,
    ConfirmByVerdict,
    Dismiss,
    Link,
    Open,
    replay,
)
from argus.cases.model import Actor, Indicator, Member
from tests.unit.cases.test_machine import (
    ARGUS,
    CASE_ID,
    INVESTIGATIONS,
    NOW,
    _record,
    person,
)

WHY = "ARGUS suggests this case: 2 investigations of one campus host: 2 rules fired."


def raised(**more: object) -> Open:
    base: dict[str, object] = {
        "title": "Regular beaconing from a campus host",
        "severity": "medium",
        "cause": "raised",
        "members": (
            Member(INVESTIGATIONS[0], "actor", "10.0.0.1"),
            Member(INVESTIGATIONS[1], "actor", "10.0.0.1"),
        ),
        "indicators": (Indicator("ip", "10.0.0.1", "actor"),),
        "suspected": True,
        "attention": WHY,
    }
    return Open(**{**base, **more})  # type: ignore[arg-type]


def test_a_raised_case_is_suspected_with_its_reason_and_replays_exactly() -> None:
    step = machine.create(CASE_ID, 1, raised(), Actor.argus("raise"), NOW)
    case = step.after
    assert (case.state, case.cause, case.attention) == ("suspected", "raised", WHY)
    assert case.opened_at is None
    assert case.mirrored is False
    assert case.kibana_wait is None
    assert step.writes == ()  # nothing reaches Kibana
    assert step.kind == "suspected"
    assert replay([_record(step)]) == case  # the reason is in the history


def test_a_person_confirms_it_and_only_then_it_is_open() -> None:
    step = machine.create(CASE_ID, 1, raised(), ARGUS, NOW)
    confirmed = machine.decide(step.after, Confirm(), person(), NOW)
    assert confirmed.after.state == "open"
    assert confirmed.after.opened_at == NOW
    assert confirmed.after.attention == WHY  # what ARGUS said stays
    with pytest.raises(CaseRefused) as refused:
        machine.decide(step.after, Confirm(), ARGUS, NOW)  # ARGUS never confirms
    assert refused.value.code == "forbidden"


def test_a_verdict_does_not_confirm_it_even_if_asked_to() -> None:
    step = machine.create(CASE_ID, 1, raised(), ARGUS, NOW)
    with pytest.raises(CaseRefused) as refused:
        machine.decide(step.after, ConfirmByVerdict(review_id=5, by_user_id=2), ARGUS, NOW)
    assert refused.value.code == "conflict"
    assert step.after.state == "suspected"


def test_a_person_may_dismiss_it() -> None:
    step = machine.create(CASE_ID, 1, raised(), ARGUS, NOW)
    gone = machine.decide(step.after, Dismiss("benign_expected"), person(), NOW)
    assert gone.after.state == "closed"


def test_arriving_investigations_are_linked_to_a_suspected_case_by_argus() -> None:
    step = machine.create(CASE_ID, 1, raised(), ARGUS, NOW)
    more = machine.decide(step.after, Link((Member(INVESTIGATIONS[2], "actor", "10.0.0.1"),),
                                           (), "high"), Actor.argus("raise"), NOW)  # fmt: skip
    assert more.after.members == step.after.members | {INVESTIGATIONS[2]}
    assert more.after.severity == "high"
    assert replay([_record(step), _record(more)]) == more.after


@pytest.mark.parametrize(
    "changes",
    [
        {"suspected": False},  # ARGUS opens nothing on its own
        {"attention": None},  # a raised case says why
        {"attention": "   "},
        {"attention": "x" * (machine.ATTENTION_LIMIT + 1)},  # the column's limit
        {"members": ()},
    ],
)
def test_a_raised_case_that_is_not_suspected_or_has_no_reason_is_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises(CaseRefused) as refused:
        machine.create(CASE_ID, 1, raised(**changes), ARGUS, NOW)
    assert refused.value.code in ("invalid", "forbidden")


def test_a_person_cannot_suspect_a_case() -> None:
    with pytest.raises(CaseRefused):
        machine.create(CASE_ID, 1, raised(), person(), NOW)


def test_the_longest_reason_the_column_holds_is_accepted() -> None:
    step = machine.create(
        CASE_ID, 1, raised(attention="x" * machine.ATTENTION_LIMIT), ARGUS, NOW
    )  # fmt: skip
    assert len(step.after.attention or "") == machine.ATTENTION_LIMIT
