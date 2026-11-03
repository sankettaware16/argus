"""Q-E3: how the cutover reads an account (``argus.web.cutover``), without a database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import cutover
from argus.web.cutover import Account, Glass

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 26, 13, 50, tzinfo=UTC)  # 7:20 PM IST


def account(**kw: object) -> Account:
    base: dict[str, object] = {
        "username": "asha", "display_name": "Asha", "kind": "person", "elk_username": None,
        "disabled": False, "password_on": True, "linked_at": None, "elk_seen_at": None,
        "first_elk_signin_at": None,
    }  # fmt: skip
    return Account(**{**base, **kw})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kw", "state"),
    [
        ({}, "local"),
        ({"elk_username": "A.B", "linked_at": T0}, "waiting"),
        ({"elk_username": "A.B", "linked_at": T0, "elk_seen_at": T0}, "ready"),
        ({"elk_username": "A.B", "linked_at": T0, "elk_seen_at": T0, "password_on": False}, "done"),
        ({"elk_username": "A.B", "password_on": False, "first_elk_signin_at": T0}, "done"),
        ({"disabled": True}, "closed"),
        ({"kind": "service"}, "service"),
    ],
)
def test_an_account_is_in_one_state_with_a_reason(kw: dict[str, object], state: str) -> None:
    got = account(**kw)
    assert got.state == state
    assert got.reason


def test_the_reason_names_the_next_command() -> None:
    assert "argus identity link asha --elk <name>" in account().reason
    ready = account(elk_username="A.B", linked_at=T0, elk_seen_at=T0)
    assert "argus identity disable-local asha" in ready.reason


def test_a_sign_in_counts_only_after_the_link() -> None:
    linked = account(elk_username="A.B", linked_at=T0, elk_seen_at=None,
                     first_elk_signin_at=T0 - timedelta(days=1))  # fmt: skip
    assert linked.seen is None  # the column alone is no proof for a linked account
    born = account(elk_username="A.B", first_elk_signin_at=T0, password_on=False)
    assert born.seen == T0  # began with ELK: no hash, no link row
    by_hand = account(elk_username="A.B", first_elk_signin_at=T0)  # Q-E3 review F5
    assert by_hand.seen is None  # linked outside the tool: its sign-in cannot be dated


@given(
    kind=st.sampled_from(["person", "service"]),
    elk=st.one_of(st.none(), st.just("A.B")),
    disabled=st.booleans(),
    password_on=st.booleans(),
    linked=st.booleans(),
    seen=st.booleans(),
)
def test_ready_means_a_password_still_on_and_a_sign_in_after_the_link(
    kind: str, elk: str | None, disabled: bool, password_on: bool, linked: bool, seen: bool
) -> None:
    got = account(kind=kind, elk_username=elk, disabled=disabled, password_on=password_on,
                  linked_at=T0 if linked else None, elk_seen_at=T0 if seen else None)  # fmt: skip
    if got.state == "ready":
        assert (kind, disabled, password_on, linked or seen) == ("person", False, True, True)
        assert elk is not None
        assert got.seen is not None or got.elk_seen_at is not None
    assert got.state in {"local", "waiting", "ready", "done", "closed", "service"}


def test_times_are_ist_twelve_hour() -> None:
    assert cutover.ist(T0) == "2026-10-26 7:20 PM IST"


def test_the_list_keeps_break_glass_apart_and_never_breaks_on_empty() -> None:
    nobody = cutover.render([], Glass(False, None, None, None), elk_mode=False)
    assert nobody[0].startswith("ELK sign-in is OFF")
    assert "0 account(s)" in nobody[1]
    assert any("no account yet" in line for line in nobody)
    people = [account(), account(username="svc", kind="service")]
    out = cutover.render(people, Glass(True, T0, T0, None), elk_mode=True)
    assert out[0] == "ELK sign-in is ON"
    assert any(line.startswith("  asha ") for line in out)
    assert "  svc (service): a service identity: it never signs in" in out
    glass = [line for line in out if line.startswith("  break-glass:")]
    assert len(glass) == 1
    assert "ON until 2026-10-26 7:20 PM IST" in glass[0]
    assert "never used" in glass[0]
    heading = "Break-glass (never disabled here; `argus break-glass`):"
    assert out.index(heading) < out.index(glass[0])
