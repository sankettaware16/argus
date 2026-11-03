"""Who was behind an address (AR6, D-216): the five states, the edges, and the properties that hold
for any sightings (Hypothesis)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.signins import attribute as a
from argus.signins import model as m
from tests.unit.signins import kit

pytestmark = pytest.mark.unit

RULES = m.Rules()  # pad 2 h, shared at 4 accounts, logs kept 5 days
ADDRESS = "10.1.2.3"
NOW = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
FIRST, LAST = kit.at(13), kit.at(14)  # the alerts: 13:00 to 14:00 UTC on the 28th


def records(*day_records: m.DayRecord) -> dict[date, m.DayRecord]:
    return {r.day: r for r in day_records}


def run(
    found: dict[date, m.DayRecord],
    first: datetime = FIRST,
    last: datetime = LAST,
    rules: m.Rules = RULES,
    now: datetime = NOW,
) -> a.Attribution:
    return a.attribute(ADDRESS, found, first, last, rules, now=now)


def one_day(
    *sightings: m.Sighting, accounts: int | None = None, more: int = 0
) -> dict[date, m.DayRecord]:
    n = len({s.user for s in sightings}) if accounts is None else accounts
    return records(
        m.DayRecord(ADDRESS, kit.DAY, kit.lookup(accounts=n, more=more), tuple(sightings))
    )


# ---------------------------------------------------------------- the five states


def test_one_account_with_sign_ins_in_the_window_is_likely() -> None:
    got = run(one_day(kit.sighting("user01", hours=(12, 13, 15))))
    assert got.state == "likely"
    assert [x.user for x in got.accounts] == ["user01"]
    assert got.accounts[0].devices == ("Chrome on Windows",)
    assert got.gaps == ()
    assert got.shared_days == ()
    assert got.hands == ()
    assert a.sentence(got) == "Probable user: user01."


def test_two_accounts_are_possible_ordered_by_successes_then_nearness_to_the_alerts() -> None:
    near = kit.sighting("user02", hours=(13,), events=4)
    many = kit.sighting("user03", hours=(12, 14), events=9)
    far = kit.sighting("user04", hours=(11,), events=4)
    got = run(one_day(near, many, far))
    assert got.state == "possible"
    assert [x.user for x in got.accounts] == [
        "user03",
        "user02",
        "user04",
    ]  # 9, then 4 and 4 by nearness
    assert a.sentence(got).startswith("Possible users: user03, user02, user04 (3 accounts")


def test_nearness_to_the_alerts_breaks_a_tie_in_successes_and_then_the_name_does() -> None:
    inside = kit.sighting("user09", hours=(13,), events=4)
    before = kit.sighting("user01", hours=(11,), events=4)
    got = run(one_day(before, inside))
    assert [x.user for x in got.accounts] == ["user09", "user01"]
    twin_a, twin_b = (
        kit.sighting("user05", hours=(13,), events=4),
        kit.sighting("user04", hours=(13,), events=4),
    )
    assert [x.user for x in run(one_day(twin_a, twin_b)).accounts] == ["user04", "user05"]


def test_a_day_with_enough_accounts_is_shared_and_no_one_is_named() -> None:
    crowd = [kit.sighting(f"user{n:02d}", hours=(13,), events=2) for n in range(4)]
    got = run(one_day(*crowd))
    assert got.state == "shared"
    assert got.accounts == ()
    assert got.account_count == 4
    assert got.shared_days == (kit.DAY,)
    assert "No user is guessed" in a.sentence(got)
    assert not any(s.user in a.sentence(got) for s in crowd)


def test_accounts_that_were_not_all_listed_make_it_shared_whatever_the_listed_say() -> None:
    got = run(one_day(kit.sighting("user01", hours=(13,)), accounts=12, more=11))
    assert got.state == "shared"
    assert got.at_least
    assert got.account_count == 12
    assert a.sentence(got).startswith("A shared address: at least 12 accounts")


def test_all_days_read_and_no_sign_in_in_the_window_is_none_seen() -> None:
    got = run(one_day())
    assert got.state == "none_seen"
    assert got.accounts == ()
    assert a.sentence(got) == "No account had a successful sign-in from this address in the window."


def test_an_account_active_that_day_outside_the_windows_hours_is_not_the_user() -> None:
    elsewhere = kit.sighting("user01", hours=(3, 4))
    got = run(one_day(elsewhere))
    assert got.state == "none_seen"
    assert got.outside_window == 1


def test_failed_attempts_alone_are_not_a_user_but_are_listed_apart() -> None:
    tried = kit.sighting("user07", hours=(13,), events=3, successes=0, failures=3)
    got = run(one_day(tried))
    assert got.state == "none_seen"
    assert got.failed_only == ("user07",)
    both = run(one_day(tried, kit.sighting("user01", hours=(13,))))
    assert both.state == "likely"
    assert both.failed_only == ("user07",)


def test_failed_only_accounts_do_not_make_a_shared_address() -> None:
    """D-227: a spray of failed sign-ins from an infected host is not a crowd; counting its names
    toward ``shared`` would hide the owner exactly when the device misbehaves."""
    owner = kit.sighting("user01", hours=(13,), events=3)
    spray = [
        kit.sighting(f"guess{n}", hours=(13,), events=2, successes=0, failures=2) for n in range(3)
    ]
    got = run(one_day(owner, *spray))  # four accounts on the day, one with a success
    assert got.state == "likely"
    assert [x.user for x in got.accounts] == ["user01"]
    assert got.failed_only == ("guess0", "guess1", "guess2")
    assert got.shared_days == ()
    successes = [kit.sighting(f"user{n:02d}", hours=(13,), events=2) for n in range(4)]
    assert run(one_day(*successes)).state == "shared"  # four who got in is a crowd


def test_a_day_with_unnamed_events_is_unknown_and_says_how_many_with_the_named_so_far() -> None:
    """D-223: sign-ins with no account name must not read as "no one signed in"."""
    lk = m.Lookup(ADDRESS, kit.DAY, m.day_end(kit.DAY) + timedelta(hours=4), False, 0, 0,
                  m.UNNAMED, unnamed=7)  # fmt: skip
    found = records(m.DayRecord(ADDRESS, kit.DAY, lk, (kit.sighting("user01", hours=(13,)),)))
    got = run(found)
    assert got.state == "unknown"
    assert got.gaps == (a.Gap(kit.DAY, "incomplete", unnamed=7),)
    assert [x.user for x in got.accounts] == ["user01"]
    assert a.sentence(got) == (
        "Not known: 28 Oct: 7 sign-in events without an account name. So far: user01."
    )
    nobody = run(records(m.DayRecord(ADDRESS, kit.DAY, lk)))
    assert nobody.state == "unknown"  # not none_seen
    assert "1 sign-in event without an account name" in a.gap_words(
        [a.Gap(kit.DAY, "incomplete", unnamed=1)]
    )


def test_a_day_not_looked_up_is_unknown_and_says_so_with_what_was_seen_so_far() -> None:
    found = records(
        m.DayRecord(
            ADDRESS, date(2026, 10, 28), kit.lookup(), (kit.sighting("user01", hours=(23,)),)
        )
    )
    # the window reaches into the 29th (pad 2 h after 23:30) which was never asked about
    got = run(found, kit.at(22), kit.at(23, 30))
    assert got.state == "unknown"
    assert [(g.day, g.why) for g in got.gaps] == [(date(2026, 10, 29), "not_looked")]
    assert [x.user for x in got.accounts] == ["user01"]
    assert a.sentence(got) == "Not known: 29 Oct: not looked up yet. So far: user01."


def test_an_incomplete_lookup_and_logs_no_longer_kept_are_told_apart() -> None:
    partial = m.DayRecord(ADDRESS, kit.DAY, kit.lookup(complete=False, reason=m.PARTIAL))
    assert run(records(partial)).gaps == (a.Gap(kit.DAY, "incomplete"),)
    gone = m.DayRecord(ADDRESS, kit.DAY, kit.lookup(complete=False, reason=m.GONE))
    assert run(records(gone)).gaps == (a.Gap(kit.DAY, "logs_gone"),)
    old = date(2026, 10, 3)
    ancient = run({}, kit.at(13, day=old), kit.at(14, day=old))
    assert ancient.state == "unknown"
    assert ancient.gaps == (a.Gap(old, "logs_gone"),)  # older than the five days kept
    assert "the sign-in logs are no longer kept" in a.sentence(ancient)


def test_a_day_never_asked_about_is_not_looked_up_when_the_logs_are_still_kept() -> None:
    assert run({}).gaps == (a.Gap(kit.DAY, "not_looked"),)


def test_a_lookup_made_before_the_window_ended_is_partial_until_it_is_made_again() -> None:
    early = kit.lookup(looked_at=kit.at(13, 30))  # read up to 13:15
    got = run(records(m.DayRecord(ADDRESS, kit.DAY, early, ())), now=kit.at(15))
    assert got.gaps == (a.Gap(kit.DAY, "partial_day"),)
    assert got.state == "unknown"
    late = kit.lookup(looked_at=kit.at(16, 20))  # the window ends at 16:00 (alerts and 2 h of pad)
    assert (
        run(records(m.DayRecord(ADDRESS, kit.DAY, late, ())), now=kit.at(16, 30)).state
        == "none_seen"
    )


def test_a_lookup_cannot_cover_what_has_not_happened_yet() -> None:
    now = kit.at(13, 30)  # the alerts run to 14:00 and the pad to 16:00: the future is not missing
    covered = kit.lookup(looked_at=kit.at(13, 29))
    got = run(records(m.DayRecord(ADDRESS, kit.DAY, covered, ())), now=now)
    assert got.gaps == (a.Gap(kit.DAY, "partial_day"),)  # read to 13:14, the margin before 13:29
    fresh = kit.lookup(looked_at=now)
    assert run(records(m.DayRecord(ADDRESS, kit.DAY, fresh, ())), now=now).gaps == ()


# ---------------------------------------------------------------- an address that changes hands


def test_different_single_accounts_on_different_days_are_called_out() -> None:
    d26, d28 = date(2026, 10, 26), date(2026, 10, 28)
    found = records(
        m.DayRecord(
            ADDRESS, d26, kit.lookup(day=d26), (kit.sighting("user01", day=d26, hours=(13,)),)
        ),
        m.DayRecord(
            ADDRESS, d28, kit.lookup(day=d28), (kit.sighting("user02", day=d28, hours=(13,)),)
        ),
    )
    got = run(found, kit.at(12, day=d26), kit.at(14, day=d28))
    # the days between are not looked up, so say what is unknown and still call the change out
    assert got.hands == ((d26, "user01"), (d28, "user02"))
    both = records(
        *found.values(),
        m.DayRecord(ADDRESS, date(2026, 10, 27), kit.lookup(day=date(2026, 10, 27)), ()),
    )
    full = run(both, kit.at(12, day=d26), kit.at(14, day=d28))
    assert full.state == "possible"
    assert full.hands == got.hands
    assert (
        "used by user01 on 26 Oct and by user02 on 28 Oct: it may have changed hands"
        in a.sentence(full)
    )


def test_the_same_account_on_two_days_is_one_user_not_a_change_of_hands() -> None:
    d27 = date(2026, 10, 27)
    found = records(
        m.DayRecord(
            ADDRESS, d27, kit.lookup(day=d27), (kit.sighting("user01", day=d27, hours=(13,)),)
        ),
        m.DayRecord(ADDRESS, kit.DAY, kit.lookup(), (kit.sighting("user01", hours=(13,)),)),
    )
    got = run(found, kit.at(12, day=d27), kit.at(14))
    assert got.state == "likely"
    assert got.hands == ()
    assert got.accounts[0].days == (d27, kit.DAY)


def test_many_accounts_over_several_days_make_a_shared_address_even_if_no_day_is() -> None:
    days = [date(2026, 10, n) for n in (25, 26, 27, 28)]
    found = records(
        *(
            m.DayRecord(
                ADDRESS, d, kit.lookup(day=d), (kit.sighting(f"user{n:02d}", day=d, hours=(13,)),)
            )
            for n, d in enumerate(days)
        )
    )
    got = run(found, kit.at(12, day=days[0]), kit.at(14, day=days[-1]))
    assert got.state == "shared"
    assert got.shared_days == ()
    assert got.accounts == ()


# ---------------------------------------------------------------- the hours clip the window


def test_an_account_counts_only_for_the_hours_the_window_touches() -> None:
    # alerts 13:00-14:00 and a pad of 2 h: hours 11 to 16 count, hour 17 does not
    inside = kit.sighting("user01", hours=(16,))
    outside = kit.sighting("user02", hours=(17,))
    assert [x.user for x in run(one_day(inside, outside)).accounts] == ["user01"]
    tight = m.Rules(pad=timedelta(0))
    assert run(one_day(kit.sighting("user01", hours=(12,))), rules=tight).state == "none_seen"
    assert run(one_day(kit.sighting("user01", hours=(14,))), rules=tight).state == "likely"
    assert run(one_day(kit.sighting("user01", hours=(15,))), rules=tight).state == "none_seen"


def test_a_window_across_midnight_reads_both_days() -> None:
    d28, d29 = kit.DAY, date(2026, 10, 29)
    found = records(
        m.DayRecord(ADDRESS, d28, kit.lookup(), (kit.sighting("user01", hours=(23,)),)),
        m.DayRecord(
            ADDRESS, d29, kit.lookup(day=d29), (kit.sighting("user01", day=d29, hours=(0,)),)
        ),
    )
    got = run(found, kit.at(23, 20), kit.at(23, 50))
    assert got.days == (d28, d29)
    assert got.state == "likely"
    assert got.accounts[0].events == 4


# ---------------------------------------------------------------- words, privacy


def test_for_a_person_without_log_access_there_are_counts_and_no_names() -> None:
    likely = run(one_day(kit.sighting("user01", hours=(13,))))
    line = a.sentence(likely, names=False)
    assert line == "1 account signed in from this address — hidden: needs log access."
    possible = run(
        one_day(kit.sighting("user01", hours=(13,)), kit.sighting("user02", hours=(13,)))
    )
    assert "user0" not in a.sentence(possible, names=False)
    assert a.sentence(possible, names=False).startswith("2 accounts signed in")
    shared = run(one_day(kit.sighting("user01", hours=(13,)), accounts=9, more=8))
    assert a.sentence(shared, names=False).startswith("at least 9 accounts signed in")
    assert (
        a.sentence(run(one_day()), names=False)
        == "No account signed in from this address in the window."
    )
    unknown = a.sentence(run({}), names=False)
    assert unknown.startswith("Not known whether anyone signed in")
    assert "28 Oct: not looked up yet" in unknown


def test_for_a_person_without_log_access_an_unknown_count_says_so_far() -> None:
    """The accounts of an unknown address are what was seen so far; "1 account signed in" would
    understate."""
    found = records(
        m.DayRecord(
            ADDRESS, date(2026, 10, 28), kit.lookup(), (kit.sighting("user01", hours=(23,)),)
        )
    )
    got = run(found, kit.at(22), kit.at(23, 30))  # the 29th was never asked about
    assert got.state == "unknown"
    assert a.sentence(got, names=False) == (
        "1 account signed in from this address so far — hidden: needs log access."
    )
    assert "so far" not in a.sentence(
        run(one_day(kit.sighting("user01", hours=(13,)))), names=False
    )


def test_the_lead_wording_says_it_is_not_proof() -> None:
    assert a.LEAD == (
        "Probable user, from SSO sign-ins on this address — a lead, not proof: addresses can be"
        " reassigned."
    )


def test_a_timeline_entry_per_account_per_day_in_ist() -> None:
    sight = kit.sighting("user01", hours=(9, 17), events=3)  # 09:10 to 17:40 UTC
    found = records(m.DayRecord(ADDRESS, kit.DAY, kit.lookup(), (sight,)))
    wide = m.Rules(pad=timedelta(hours=12))
    (entry,) = a.entries(ADDRESS, found, kit.at(12), kit.at(14), wide)
    assert (entry.user, entry.events, entry.devices) == ("user01", 3, ("Chrome on Windows",))
    assert a.entry_words(entry) == (
        "user01 signed in 3 times, 28 Oct 2026, 2:40 PM to 11:10 PM IST, Chrome on Windows"
        " (from 10.1.2.3)"
    )
    assert (
        a.entries(ADDRESS, found, kit.at(1), kit.at(2), RULES) == []
    )  # outside the window's hours


# ---------------------------------------------------------------- properties

USERS = [f"user{n:02d}" for n in range(8)]
hours_st = st.lists(st.integers(0, 23), min_size=1, max_size=6, unique=True)


@st.composite
def day_records(draw: st.DrawFn) -> dict[date, m.DayRecord]:
    out: dict[date, m.DayRecord] = {}
    for offset in range(draw(st.integers(1, 3))):
        day = kit.DAY - timedelta(days=offset)
        chosen = draw(st.lists(st.sampled_from(USERS), max_size=6, unique=True))
        seen = [
            kit.sighting(
                u,
                day=day,
                hours=draw(hours_st),
                events=(n := draw(st.integers(1, 20))),
                successes=draw(st.integers(0, n)),
                failures=0,
            )
            for u in chosen
        ]
        seen = [
            m.Sighting(s.address, s.day, s.user, s.first_at, s.last_at, s.events, s.successes,
                       s.events - s.successes, s.hours, s.agents)
            for s in seen
        ]  # fmt: skip
        extra = draw(st.integers(0, 3)) if draw(st.booleans()) else 0
        state = draw(st.sampled_from(["ok", "ok", "ok", "missing", "partial", "gone"]))
        if state == "missing":
            continue
        if state == "ok":
            lk = kit.lookup(day=day, accounts=len(seen) + extra, more=extra)
        else:
            lk = kit.lookup(
                day=day, complete=False, reason=m.PARTIAL if state == "partial" else m.GONE
            )
        out[day] = m.DayRecord(ADDRESS, day, lk, tuple(seen))
    return out


spans = st.tuples(st.integers(0, 23), st.integers(0, 5)).map(
    lambda t: (
        kit.at(t[0], day=kit.DAY - timedelta(days=0)),
        kit.at(t[0], 30) + timedelta(hours=t[1]),
    )
)
rule_st = st.builds(
    m.Rules,
    pad=st.integers(0, 6).map(lambda h: timedelta(hours=h)),
    shared_accounts=st.integers(2, 6),
)


@settings(max_examples=300, deadline=None)
@given(day_records(), spans, rule_st)
def test_the_state_always_follows_its_definition(
    found: dict[date, m.DayRecord], span: tuple[datetime, datetime], rules: m.Rules
) -> None:
    first, last = span
    got = run(found, first, last, rules)
    assert got.state in a.STATES
    start, end = a.window_of(first, last, rules.pad)
    days = a.window_days(start, end)
    assert got.days == days
    named = {s.user for r in found.values() for s in r.sightings}
    assert {x.user for x in got.accounts} <= named  # never an account that was not seen
    usable = [
        r for d, r in found.items() if d in days and r.lookup is not None and r.lookup.complete
    ]
    crowded = any(  # failed-only accounts are no crowd (D-227); accounts not listed are one
        r.lookup is not None
        and (
            r.lookup.more_accounts > 0
            or len({s.user for s in r.sightings if s.successes > 0}) >= rules.shared_accounts
        )
        for r in usable
    )
    if crowded:
        assert got.state == "shared"
        assert got.accounts == ()
    if got.state == "likely":
        assert len(got.accounts) == 1
        assert not got.gaps
        assert not got.shared_days
    if got.state == "possible":
        assert 2 <= len(got.accounts) < rules.shared_accounts
        assert not got.gaps
    if got.state == "none_seen":
        assert not got.gaps
        assert not got.accounts
        assert not got.shared_days
    if got.state == "unknown":
        assert got.gaps
        assert not got.shared_days
    if got.state == "shared":
        assert got.accounts == ()
    if got.gaps and got.state != "shared":
        assert got.state == "unknown"
    names = [x.user for x in got.accounts]
    assert len(set(names)) == len(names)


@settings(max_examples=200, deadline=None)
@given(day_records(), spans, st.randoms())
def test_the_order_of_the_sightings_does_not_matter(
    found: dict[date, m.DayRecord], span: tuple[datetime, datetime], rnd: object
) -> None:
    import random

    assert isinstance(rnd, random.Random)
    shuffled = {}
    for d, r in found.items():
        mixed = list(r.sightings)
        rnd.shuffle(mixed)
        shuffled[d] = m.DayRecord(r.address, r.day, r.lookup, tuple(mixed))
    assert run(found, *span) == run(shuffled, *span)


@settings(max_examples=200, deadline=None)
@given(day_records(), spans)
def test_an_account_outside_the_windows_hours_is_never_listed(
    found: dict[date, m.DayRecord], span: tuple[datetime, datetime]
) -> None:
    got = run(found, *span)
    start, end = a.window_of(*span, RULES.pad)
    for account in got.accounts:
        for day in account.days:
            sightings = [s for s in found[day].sightings if s.user == account.user]
            assert any(_touches(s, start, end) for s in sightings)


def _touches(s: m.Sighting, start: datetime, end: datetime) -> bool:
    return any(
        m.day_start(s.day) + timedelta(hours=h) <= end
        and m.day_start(s.day) + timedelta(hours=h + 1) > start
        for h in s.hours
    )


@settings(max_examples=150, deadline=None)
@given(day_records(), spans)
def test_one_more_account_never_turns_possible_into_likely(
    found: dict[date, m.DayRecord], span: tuple[datetime, datetime]
) -> None:
    before = run(found, *span)
    if before.state != "possible":
        return
    day = kit.DAY
    record = found.get(day)
    if record is None or record.lookup is None:
        return
    extra = kit.sighting("userXX", day=day, hours=tuple(range(24)), events=24)
    bigger = dict(found)
    bigger[day] = m.DayRecord(ADDRESS, day, record.lookup, (*record.sightings, extra))
    after = run(bigger, *span)
    assert after.state != "likely"


@given(st.lists(st.integers(0, 23), min_size=1, unique=True))
def test_a_sighting_is_clipped_to_exactly_the_hours_it_has(hours: Sequence[int]) -> None:
    sight = kit.sighting("user01", hours=hours)
    found = records(m.DayRecord(ADDRESS, kit.DAY, kit.lookup(), (sight,)))
    for hour in range(24):
        got = run(found, kit.at(hour, 5), kit.at(hour, 50), m.Rules(pad=timedelta(0)))
        assert (got.state == "likely") == (hour in hours)
