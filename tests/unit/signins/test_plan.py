"""Planning the pass (AR6, D-216): which (address, day) pairs, in what order, in which requests, and
when nothing at all, with a fake clock and fake rows."""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.signins import model as m
from argus.signins import plan as p
from tests.unit.signins import kit

pytestmark = pytest.mark.unit
RULES = m.Rules()
NOW = datetime(2026, 10, 29, 6, 0, tzinfo=UTC)  # not in the quiet hours
D28, D29 = date(2026, 10, 28), date(2026, 10, 29)


def addr(n: int) -> str:
    return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.1.0.0")) + n))


def want(n: int, *, tier: p.Tier = p.Tier.REST, at: datetime | None = None) -> p.Want:
    at = at or kit.at(13)
    return p.Want(addr(n), at, at + timedelta(minutes=30), tier)


def planned(
    wants: list[p.Want],
    found: dict[tuple[str, date], m.DayRecord] | None = None,
    rules: m.Rules = RULES,
    now: datetime = NOW,
    **kw: int,
) -> p.Plan:
    return p.plan(wants, found or {}, rules, now=now, **kw)


def done(address: str, day: date, *, at: datetime | None = None, **kw: object) -> m.DayRecord:
    return m.DayRecord(address, day, kit.lookup(address, day, looked_at=at, **kw))  # type: ignore[arg-type]


# ---------------------------------------------------------------- what is wanted


def test_an_address_never_looked_up_is_one_request_for_its_day() -> None:
    got = planned([want(1), want(2)])
    (request,) = got.requests
    assert request.day == D28
    assert request.addresses == (addr(1), addr(2))
    assert got.pairs == 2
    assert got.waiting == 0


def test_the_request_reads_the_whole_day_and_never_past_the_ingest_margin() -> None:
    (finished,) = planned([want(1)]).requests
    assert finished.end == m.day_end(D28)
    today = want(1, at=kit.at(2, day=D29))
    (current,) = planned([today], now=kit.at(4, 7, day=D29)).requests
    assert current.day == D29
    assert current.end == kit.at(3, 52, day=D29)  # 04:07 minus 15 minutes


def test_a_window_across_midnight_asks_for_both_days_in_two_requests() -> None:
    both = p.Want(addr(1), kit.at(23, 30), kit.at(0, 20, day=D29))
    got = planned([both])
    assert [r.day for r in got.requests] == [D28, D29]
    assert all(r.addresses == (addr(1),) for r in got.requests)


def test_a_complete_lookup_made_three_hours_after_the_day_is_final() -> None:
    final = done(addr(1), D28, at=m.day_end(D28) + timedelta(hours=3, minutes=1))
    got = planned([want(1)], {(addr(1), D28): final})
    assert got.requests == ()


def test_a_complete_lookup_made_before_the_day_was_over_is_made_again() -> None:
    early = done(addr(1), D28, at=m.day_end(D28) - timedelta(hours=2))
    got = planned([want(1)], {(addr(1), D28): early})
    assert [r.day for r in got.requests] == [D28]
    barely = done(addr(1), D28, at=m.day_end(D28) + timedelta(minutes=10))  # read to 23:55
    assert planned([want(1)], {(addr(1), D28): barely}).requests != ()


def test_a_day_looked_up_before_the_late_logs_were_in_is_looked_up_once_more_and_then_final() -> (
    None
):
    """D-224: ingest can lag by more than the 15-minute margin, so a lookup made within
    ``final_after`` of the day's end is not final; once the day is that old it is made again, and
    that one (made after ``final_after``) is."""
    soon = done(addr(1), D28, at=m.day_end(D28) + timedelta(hours=1))  # covers to the day's end
    key = {(addr(1), D28): soon}
    two_hours = m.day_end(D28) + timedelta(hours=2)
    assert planned([want(1)], key, now=two_hours).requests == ()  # not yet: wait for the late logs
    after = m.day_end(D28) + timedelta(hours=3, minutes=5)
    assert [r.day for r in planned([want(1)], key, now=after).requests] == [D28]
    again = done(addr(1), D28, at=after)
    assert (
        planned([want(1)], {(addr(1), D28): again}, now=after + timedelta(hours=8)).requests == ()
    )


def test_final_after_is_a_setting_not_a_constant() -> None:
    soon = done(addr(1), D28, at=m.day_end(D28) + timedelta(hours=1))
    quick = m.Rules(final_after=timedelta(minutes=30))
    assert planned([want(1)], {(addr(1), D28): soon}, quick).requests == ()  # final already
    slow = m.Rules(final_after=timedelta(hours=12))
    got = planned([want(1)], {(addr(1), D28): soon}, slow, now=m.day_end(D28) + timedelta(hours=6))
    assert got.requests == ()  # the 12 hours have not passed
    late = planned(
        [want(1)], {(addr(1), D28): soon}, slow, now=m.day_end(D28) + timedelta(hours=13)
    )
    assert late.requests != ()


def test_the_current_day_is_asked_again_only_when_an_hour_old_and_short_of_the_window() -> None:
    alert = want(1, at=kit.at(9, day=D29))  # alerts 09:00-09:30, window to 11:30
    first = done(addr(1), D29, at=kit.at(10, day=D29))  # read to 09:45: short of the window
    key = {(addr(1), D29): first}
    assert planned([alert], key, now=kit.at(10, 30, day=D29)).requests == ()  # not an hour yet
    assert planned([alert], key, now=kit.at(11, 5, day=D29)).requests != ()  # an hour, and short
    full = done(addr(1), D29, at=kit.at(11, 50, day=D29))  # read to 11:35: the window is covered
    assert planned([alert], {(addr(1), D29): full}, now=kit.at(13, 0, day=D29)).requests == ()


def test_an_incomplete_lookup_is_retried_after_half_an_hour_and_logs_gone_never() -> None:
    bad = done(addr(1), D28, at=NOW - timedelta(minutes=10), complete=False, reason=m.PARTIAL)
    assert planned([want(1)], {(addr(1), D28): bad}).requests == ()
    old = done(addr(1), D28, at=NOW - timedelta(minutes=40), complete=False, reason=m.PARTIAL)
    assert planned([want(1)], {(addr(1), D28): old}).requests != ()
    gone = done(addr(1), D28, at=NOW - timedelta(days=1), complete=False, reason=m.GONE)
    assert planned([want(1)], {(addr(1), D28): gone}).requests == ()


def test_a_store_failure_waits_six_hours_and_after_three_is_left_alone() -> None:
    def failed(tries: int, ago: timedelta) -> m.DayRecord:
        lookup = m.Lookup(
            addr(1), D28, NOW - ago, False, 0, 0, m.STORE_FAILED, store_failures=tries
        )
        return m.DayRecord(addr(1), D28, lookup)

    assert planned([want(1)], {(addr(1), D28): failed(1, timedelta(hours=2))}).requests == ()
    assert planned([want(1)], {(addr(1), D28): failed(1, timedelta(hours=7))}).requests != ()
    stuck = planned([want(1)], {(addr(1), D28): failed(3, timedelta(days=1))})
    assert stuck.requests == ()
    assert stuck.stuck == 1  # said, not silent


def test_a_missing_index_inside_the_retention_is_retried_after_six_hours() -> None:
    def missing(ago: timedelta) -> m.DayRecord:
        return done(addr(1), D28, at=NOW - ago, complete=False, reason=m.MISSING)

    assert planned([want(1)], {(addr(1), D28): missing(timedelta(hours=2))}).requests == ()
    assert planned([want(1)], {(addr(1), D28): missing(timedelta(hours=7))}).requests != ()


def test_days_the_logs_no_longer_hold_are_not_asked_and_are_counted() -> None:
    ancient = want(1, at=kit.at(12, day=date(2026, 10, 3)))
    got = planned([ancient])
    assert got.requests == ()
    assert got.skipped_old == 1
    edge = want(1, at=kit.at(12, day=date(2026, 10, 25)))  # the fifth day back, today included
    assert [r.day for r in planned([edge]).requests] == [date(2026, 10, 25)]
    gone = want(1, at=kit.at(12, day=date(2026, 10, 24)))
    assert planned([gone]).requests == ()


def test_nothing_is_planned_between_midnight_and_half_past_one() -> None:
    for now in (kit.at(0, 0, day=D29), kit.at(0, 59, day=D29), kit.at(1, 29, day=D29)):
        got = planned([want(1)], now=now)
        assert got.quiet
        assert got.requests == ()
    assert not planned([want(1)], now=kit.at(1, 30, day=D29)).quiet


def test_the_first_minutes_of_a_day_have_nothing_old_enough_to_read() -> None:
    fresh = p.Want(addr(1), kit.at(0, 5, day=D29), kit.at(0, 8, day=D29))
    got = planned([fresh], now=kit.at(1, 30, day=D29))  # past the quiet hours; 01:15 is readable
    assert [r.day for r in got.requests] == [D28, D29]  # the pad of 2 h reaches back into the 28th
    assert p.due(None, D29, (kit.at(0, 5, day=D29), kit.at(1, 0, day=D29)), RULES,
                 now=kit.at(0, 10, day=D29)) is False  # fmt: skip


# ---------------------------------------------------------------- priority and batches


def test_members_of_open_cases_come_first_then_raised_then_the_rest_newest_first() -> None:
    wants = [
        want(1, tier=p.Tier.REST, at=kit.at(20)),
        want(2, tier=p.Tier.RAISED, at=kit.at(8)),
        want(3, tier=p.Tier.CASE, at=kit.at(7)),
        want(4, tier=p.Tier.REST, at=kit.at(21)),
    ]
    got = planned(wants, rules=m.Rules(batch=1, max_requests=10))
    assert [r.addresses[0] for r in got.requests] == [addr(3), addr(2), addr(4), addr(1)]


def test_an_address_in_two_investigations_takes_the_better_rank() -> None:
    wants = [want(1, tier=p.Tier.REST, at=kit.at(20)), want(1, tier=p.Tier.CASE, at=kit.at(7)),
             want(2, tier=p.Tier.RAISED, at=kit.at(9))]  # fmt: skip
    got = planned(wants, rules=m.Rules(batch=1))
    assert [r.addresses[0] for r in got.requests] == [addr(1), addr(2)]
    assert got.pairs == 2


def test_batches_hold_at_most_the_batch_size_and_cover_each_address_once() -> None:
    wants = [want(n) for n in range(450)]
    got = planned(wants, rules=m.Rules(batch=200, max_requests=10))
    assert [len(r.addresses) for r in got.requests] == [200, 200, 50]
    seen = [a for r in got.requests for a in r.addresses]
    assert sorted(seen) == sorted({w.address for w in wants})
    assert len(seen) == 450
    assert all(r.addresses == tuple(sorted(r.addresses, key=p.key_of)) for r in got.requests)


def test_the_pass_sends_at_most_its_cap_and_counts_what_waits() -> None:
    wants = [want(n) for n in range(1300)]
    got = planned(wants)  # the default cap is 6 requests of 200
    assert len(got.requests) == 6
    assert sum(len(r.addresses) for r in got.requests) == 1200
    assert got.waiting == 100
    assert len(planned(wants, max_requests=2).requests) == 2
    assert planned(wants, max_requests=0).requests == ()


def test_one_request_is_one_day_and_the_top_ranked_addresses_of_a_day_go_together() -> None:
    wants = [
        want(1, tier=p.Tier.CASE, at=kit.at(10)),
        want(2, tier=p.Tier.CASE, at=kit.at(10, day=D29)),
        want(3, tier=p.Tier.REST, at=kit.at(11)),
    ]
    got = planned(wants)
    assert [(r.day, r.addresses) for r in got.requests] == [
        (D29, (addr(2),)),  # a case member, and the newest of the two
        (D28, (addr(1), addr(3))),
    ]


@settings(max_examples=100, deadline=None)
@given(
    st.lists(
        st.tuples(st.integers(0, 600), st.integers(0, 2), st.integers(0, 4)),
        min_size=0,
        max_size=80,
    ),
    st.integers(1, 200),
    st.integers(0, 8),
)
def test_a_plan_is_valid_for_any_wants(
    rows: list[tuple[int, int, int]], batch: int, cap: int
) -> None:
    wants = [
        p.Want(addr(n), kit.at(9, day=D29 - timedelta(days=back)),
               kit.at(10, day=D29 - timedelta(days=back)), p.Tier(t))
        for n, t, back in rows
    ]  # fmt: skip
    got = planned(wants, rules=m.Rules(batch=batch, max_requests=cap))
    assert len(got.requests) <= cap
    asked: set[tuple[str, date]] = set()
    for request in got.requests:
        assert 1 <= len(request.addresses) <= batch <= 200
        assert request.end <= NOW - m.MARGIN
        assert request.end <= m.day_end(request.day)
        assert request.end > m.day_start(request.day)
        for address in request.addresses:
            assert (address, request.day) not in asked  # no pair is asked twice in one pass
            asked.add((address, request.day))
    assert len(asked) <= got.pairs
    assert got.waiting >= 0
    oldest = m.oldest_kept(NOW.date(), RULES.retention_days)
    assert all(request.day >= oldest for request in got.requests)
