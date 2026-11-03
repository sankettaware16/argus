"""Q-E2: the sign-in throttle's rules (plan §7.2 step 3), as pure functions: the waits, the
three locks and the device cookie, with their boundaries."""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import throttle
from argus.web.throttle import Standing, Verdict, decide, wait_for

pytestmark = pytest.mark.unit
BASE = timedelta(seconds=1)
counts = st.integers(min_value=0, max_value=400)


def test_the_limits_are_the_plans() -> None:
    assert (throttle.NAME_LIMIT, throttle.CLIENT_LIMIT, throttle.SPRAY_LIMIT) == (5, 20, 60)
    assert timedelta(minutes=15) == throttle.WINDOW
    assert timedelta(hours=1) == throttle.HOUR


def test_the_waits_double_from_the_second_refusal() -> None:
    assert [wait_for(n, BASE).total_seconds() for n in range(0, 7)] == [0, 0, 1, 2, 4, 8, 16]
    assert wait_for(10_000, BASE) == throttle.MAX_WAIT  # a long spray never overflows
    assert wait_for(5, timedelta(0)) == timedelta(0)


@given(counts)
def test_a_wait_never_shrinks_and_never_passes_the_window(n: int) -> None:
    assert wait_for(n, BASE) <= wait_for(n + 1, BASE) <= throttle.MAX_WAIT


@pytest.mark.parametrize(
    ("standing", "verdict"),
    [
        (Standing(name=4), Verdict.GO),
        (Standing(name=5), Verdict.NAME_LOCKED),
        (Standing(client=19), Verdict.GO),
        (Standing(client=20), Verdict.CLIENT_LOCKED),
        (Standing(hour=59), Verdict.GO),
        (Standing(hour=60), Verdict.SPRAY_LOCKED),
        (Standing(name=5, client=20, hour=60), Verdict.SPRAY_LOCKED),  # the widest first
    ],
)
def test_the_three_locks_start_at_their_limit(standing: Standing, verdict: Verdict) -> None:
    assert decide(standing, device=False, base=BASE) is verdict


def test_a_device_cookie_passes_every_lock() -> None:
    locked = Standing(name=50, client=50, hour=500)
    assert decide(locked, device=True, base=BASE) is Verdict.GO


@pytest.mark.parametrize(
    ("age", "verdict"),
    [(0.0, Verdict.DELAYED), (0.999, Verdict.DELAYED), (1.0, Verdict.GO), (1.001, Verdict.GO)],
)
def test_a_wait_ends_exactly_when_it_is_over(age: float, verdict: Verdict) -> None:
    second = Standing(name=2, pair=2, pair_age_s=age)  # the second refusal: a 1 s wait
    assert decide(second, device=False, base=BASE) is verdict
    assert decide(second, device=True, base=BASE) is verdict  # a device cookie waits too


def test_the_third_refusal_waits_two_seconds_and_the_fourth_four() -> None:
    for pair, wait in ((3, 2.0), (4, 4.0)):
        for age, verdict in ((wait - 0.5, Verdict.DELAYED), (wait + 0.5, Verdict.GO)):
            got = decide(Standing(name=pair, pair=pair, pair_age_s=age), device=False, base=BASE)
            assert got is verdict


def test_the_first_refusal_costs_no_wait_and_a_zero_base_never_waits() -> None:
    assert decide(Standing(name=1, pair=1, pair_age_s=0.0), device=False, base=BASE) is Verdict.GO
    assert decide(Standing(name=4, pair=4, pair_age_s=0.0), device=False,
                  base=timedelta(0)) is Verdict.GO  # fmt: skip


@given(counts, counts, counts, counts, st.floats(min_value=0, max_value=2000), st.booleans())
def test_a_verdict_never_depends_on_anything_but_the_standing(
    name: int, pair: int, client: int, hour: int, age: float, device: bool
) -> None:
    standing = Standing(name, min(pair, name), age, client, hour)
    again = decide(standing, device=device, base=BASE)
    assert decide(standing, device=device, base=BASE) is again
    if device:
        assert again in (Verdict.GO, Verdict.DELAYED)
