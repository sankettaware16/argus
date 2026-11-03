"""Q-A1: the capability model (plan §7.2): eight capabilities, prerequisites that fail closed,
and what local accounts get."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import capabilities as caps
from argus.web.capabilities import LOCAL_DEFAULT, NEEDS, Capability, effective, ordered, parse
from argus.web.v1.models import CapabilityName

pytestmark = pytest.mark.unit
C = Capability
NAMES = st.lists(st.one_of(st.sampled_from([c.value for c in C]), st.text(max_size=12),
                           st.none(), st.integers()), max_size=12)  # fmt: skip


def test_the_eight_capabilities_of_the_plan() -> None:
    assert [c.value for c in C] == [
        "view",
        "see_logs",
        "review",
        "answer_gold",
        "manage_cases",
        "reopen",
        "approve",
        "admin",
    ]
    assert set(get_args(CapabilityName)) == {c.value for c in C}  # the API's names, all of them
    assert set(caps.LABELS) == set(C)
    assert all(caps.LABELS.values())
    assert set(NEEDS) == set(C)


def test_the_labels_word_for_word() -> None:  # what "Your access" says for each one
    assert caps.LABELS == {
        C.VIEW: "use ARGUS: see investigations, alerts and reports",
        C.SEE_LOGS: "see raw logs and the facts ARGUS read from them",
        C.REVIEW: "review: verdicts, group reviews, accepting proposals, asking the AI",
        C.ANSWER_GOLD: "answer gold-set items",
        C.MANAGE_CASES: "manage cases: take, assign, contain, request closure, merge, open",
        C.REOPEN: "reopen a closed case",
        C.APPROVE: "approve closures and other writes, after confirming it is you",
        C.ADMIN: "change ARGUS's settings",
    }


def _effective_within(names: Iterable[object], seconds: float = 10.0) -> frozenset[Capability]:
    """effective(names), failing the test when it has not returned after ``seconds``: its loop
    must reach its fixed point (one that never does would hang until pytest-timeout)."""
    got: list[frozenset[Capability]] = []
    worker = threading.Thread(target=lambda: got.append(effective(names)), daemon=True)
    worker.start()
    worker.join(seconds)
    assert got, f"effective({names!r}) did not return within {seconds} s"
    return got[0]


def test_effective_returns() -> None:  # before the other tests that call effective
    assert _effective_within([]) == frozenset()
    assert _effective_within(["view", "review"]) == {C.VIEW, C.REVIEW}  # nothing to drop
    assert _effective_within(["approve", "view"]) == {C.VIEW}  # one pass drops approve
    assert _effective_within(["answer_gold", "review"]) == frozenset()  # nothing without view


def test_prerequisites() -> None:
    assert NEEDS[C.VIEW] == frozenset()
    assert all(c not in NEEDS[c] for c in C)  # none needs itself
    assert all(C.VIEW in NEEDS[c] for c in C if c is not C.VIEW)  # everything needs view
    assert NEEDS[C.ANSWER_GOLD] == {C.VIEW, C.REVIEW}  # review, and a gold-key owner (D-080)
    assert NEEDS[C.APPROVE] == {C.VIEW, C.MANAGE_CASES}  # manage cases + the approver privilege
    assert effective(["approve", "view"]) == {C.VIEW}  # approving without managing cases: no
    assert effective(["answer_gold", "view"]) == {C.VIEW}
    assert effective(["review", "admin"]) == frozenset()  # nothing without view
    assert effective(["view", "review", "answer_gold"]) == {C.VIEW, C.REVIEW, C.ANSWER_GOLD}


def test_local_accounts_get_what_they_could_always_do() -> None:
    assert {C.VIEW, C.SEE_LOGS, C.REVIEW, C.ANSWER_GOLD} == LOCAL_DEFAULT
    assert effective(LOCAL_DEFAULT) == LOCAL_DEFAULT  # complete, as given
    assert not LOCAL_DEFAULT & {C.MANAGE_CASES, C.REOPEN, C.APPROVE, C.ADMIN}  # by grant only


def test_unknown_names_grant_nothing() -> None:
    assert parse(["view", "View", "VIEW", " view", "root", None, 1, b"view"]) == {C.VIEW}
    assert effective(["superuser", "all"]) == frozenset()


@given(NAMES)
def test_effective_is_closed_under_its_prerequisites(names: list[object]) -> None:
    got = effective(names)
    assert got <= parse(names)  # never more than granted
    for c in got:
        assert NEEDS[c] <= got
    assert effective(got) == got  # idempotent
    assert effective([c.value for c in got]) == got


@given(NAMES, NAMES)
def test_effective_is_monotone(a: list[object], b: list[object]) -> None:
    assert effective(a) <= effective(a + b)


@given(st.sets(st.sampled_from(list(C))))
def test_ordered_keeps_the_declared_order(chosen: set[Capability]) -> None:
    got = ordered(chosen)
    assert set(got) == chosen
    assert got == sorted(got, key=list(C).index)
