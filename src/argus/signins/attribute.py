"""Who was behind an address: the probable user(s), from stored SSO sign-ins. Pure.

For one address and one investigation window (first alert minus ``pad`` to last alert plus ``pad``)
the answer is one of five states: ``likely`` (exactly one account with successful sign-ins, no
shared day, every day read completely), ``possible`` (two accounts up to ``shared_accounts - 1``),
``shared`` (a day or the window had ``shared_accounts`` accounts or more: a lab or a NAT, only
counts are given; accounts with only failed sign-ins are no crowd), ``none_seen`` (every day read
completely, no successful sign-in), ``unknown`` (a day not looked up yet, an incomplete lookup, or
logs no longer kept: the accounts of the days read are listed as "so far"). Hourly buckets clip an
account to the window. Nothing here reads a database or a clock, and no sentence leaves with an
account name unless the caller asked for names."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal

from argus import site
from argus.incident.words import ist_date, ist_moment, plural
from argus.signins import model as m
from argus.signins.ua import words_of

State = Literal["likely", "possible", "shared", "none_seen", "unknown"]
GapWhy = Literal["not_looked", "incomplete", "partial_day", "logs_gone"]
STATES: tuple[State, ...] = ("likely", "possible", "shared", "none_seen", "unknown")
LEAD = (
    "Probable user, from SSO sign-ins on this address — a lead, not proof: addresses can be "
    "reassigned."
)
GAP_WORDS: Mapping[str, str] = {
    "not_looked": "not looked up yet",
    "incomplete": "the lookup was incomplete",
    "partial_day": "looked up before the window ended",
    "logs_gone": "the sign-in logs are no longer kept",
}


@dataclass(frozen=True)
class Account:
    """One account's sign-ins from the address over the days of the window."""

    user: str
    address: str
    first_at: datetime
    last_at: datetime
    events: int
    successes: int
    failures: int
    days: tuple[date, ...]
    devices: tuple[str, ...]  # "Chrome on Windows", the commonest first


@dataclass(frozen=True)
class Gap:
    """A day that cannot be used. ``unnamed``: for an incomplete day, the sign-in events that had
    no account name; its named accounts are still listed as "so far"."""

    day: date
    why: GapWhy
    unnamed: int = 0


@dataclass(frozen=True)
class Attribution:
    address: str
    state: State
    accounts: tuple[Account, ...]  # likely: one; possible: ordered; unknown: so far; else none
    account_count: (
        int  # accounts seen in the window (shared: the most on a day, or over the window)
    )
    at_least: bool  # more accounts signed in than were listed
    shared_days: tuple[date, ...]
    gaps: tuple[Gap, ...]
    hands: tuple[tuple[date, str], ...]  # (day, account) of the single-account days, if they differ
    failed_only: tuple[str, ...]  # accounts with only failed sign-ins in the window
    outside_window: int  # accounts that signed in on those days but not in the window's hours
    days: tuple[date, ...]  # the days the window touches


def window_of(first: datetime, last: datetime, pad: timedelta) -> tuple[datetime, datetime]:
    return first - pad, last + pad


def window_days(start: datetime, end: datetime) -> tuple[date, ...]:
    """The UTC days that [start, end] touches."""
    first, last = m.utc_day(start), m.utc_day(end)
    return tuple(first + timedelta(days=n) for n in range((last - first).days + 1))


def _sub_window(start: datetime, end: datetime, day: date) -> tuple[datetime, datetime] | None:
    lo = max(start, m.day_start(day))
    hi = min(end, m.day_end(day) - timedelta(microseconds=1))
    return (lo, hi) if lo <= hi else None


def day_gap(
    record: m.DayRecord | None,
    day: date,
    window: tuple[datetime, datetime],
    *,
    now: datetime,
    today: date,
    retention_days: int,
) -> GapWhy | None:
    """Why ``day`` cannot be used for ``window`` (None: it can). The planner asks the same."""
    lookup = None if record is None else record.lookup
    if lookup is None:
        return "logs_gone" if day < m.oldest_kept(today, retention_days) else "not_looked"
    if not lookup.complete:
        return "logs_gone" if lookup.reason == m.GONE else "incomplete"
    return "partial_day" if reads_short(lookup, day, window, now) else None


def reads_short(
    lookup: m.Lookup, day: date, window: tuple[datetime, datetime], now: datetime
) -> bool:
    """Whether an answered lookup stopped before the window's end on ``day`` or before the
    ingest margin of ``now`` (it was made before the window ended)."""
    sub = _sub_window(window[0], window[1], day)
    covered = lookup.covered_until()
    return sub is not None and covered is not None and covered < min(sub[1], now - m.MARGIN)


def _in_window(sighting: m.Sighting, lo: datetime, hi: datetime) -> bool:
    """Whether the account had an event in an hour that [lo, hi] touches."""
    base = m.day_start(sighting.day)
    for hour in sighting.hours:
        begins = base + timedelta(hours=hour)
        if begins <= hi and begins + timedelta(hours=1) > lo:
            return True
    return False


def _merge(address: str, parts: list[tuple[date, m.Sighting]]) -> Account:
    agents: Counter[str] = Counter()
    for _, s in parts:
        for a in s.agents:
            agents[a.text] += a.events
    return Account(
        user=parts[0][1].user,
        address=address,
        first_at=min(s.first_at for _, s in parts),
        last_at=max(s.last_at for _, s in parts),
        events=sum(s.events for _, s in parts),
        successes=sum(s.successes for _, s in parts),
        failures=sum(s.failures for _, s in parts),
        days=tuple(sorted({d for d, _ in parts})),
        devices=words_of(agents.items()),
    )


def _distance(account: Account, first: datetime, last: datetime) -> float:
    """Seconds between the account's sign-ins and the alerts' span (0: they overlap)."""
    if account.last_at < first:
        return (first - account.last_at).total_seconds()
    if account.first_at > last:
        return (account.first_at - last).total_seconds()
    return 0.0


def attribute(
    address: str,
    records: Mapping[date, m.DayRecord],
    first_alert: datetime,
    last_alert: datetime,
    rules: m.Rules,
    *,
    now: datetime,
    today: date | None = None,
) -> Attribution:
    """The attribution of ``address`` for an investigation whose alerts ran from ``first_alert`` to
    ``last_alert``, from the stored ``records`` (by UTC day)."""
    today = m.utc_day(now) if today is None else today
    start, end = window_of(first_alert, last_alert, rules.pad)
    days = window_days(start, end)
    gaps: list[Gap] = []
    shared_days: list[date] = []
    by_user: dict[str, list[tuple[date, m.Sighting]]] = {}
    only_failed: dict[str, list[tuple[date, m.Sighting]]] = {}
    single_days: list[tuple[date, str]] = []
    outside = 0
    most = 0
    more = False
    for day in days:
        sub = _sub_window(start, end, day)
        record = records.get(day)
        why = day_gap(
            record, day, (start, end), now=now, today=today, retention_days=rules.retention_days
        )
        lookup = None if record is None else record.lookup
        if why is not None:
            unnamed = lookup.unnamed if lookup is not None and lookup.reason == m.UNNAMED else 0
            gaps.append(Gap(day, why, unnamed))
        if lookup is None or record is None or sub is None or not lookup.has_answer:
            continue
        # the named accounts of a day with unnamed events are right, only not the whole day
        successful = {s.user for s in record.sightings if s.successes > 0}
        if lookup.more_accounts > 0:  # accounts that are not listed: whether they succeeded is
            shared_days.append(day)  # not known, so the address is a shared one
            more = True
            most = max(most, lookup.accounts)
        elif len(successful) >= rules.shared_accounts:  # failed-only accounts are no crowd
            shared_days.append(day)
        most = max(most, len(successful))
        here: list[str] = []
        for s in record.sightings:
            if not _in_window(s, *sub):
                outside += 1
                continue
            if s.successes > 0:
                by_user.setdefault(s.user, []).append((day, s))
                here.append(s.user)
            else:
                only_failed.setdefault(s.user, []).append((day, s))
        if len(here) == 1:
            single_days.append((day, here[0]))
    accounts = [_merge(address, parts) for parts in by_user.values()]
    accounts.sort(key=lambda a: (-a.successes, _distance(a, first_alert, last_alert), a.user))
    failed = tuple(sorted(u for u in only_failed if u not in by_user))
    hands = tuple(single_days) if len({u for _, u in single_days}) > 1 else ()
    state: State
    kept: tuple[Account, ...]
    if shared_days or len(accounts) >= rules.shared_accounts:
        state, kept = "shared", ()
    elif gaps:
        state, kept = "unknown", tuple(accounts)
    elif not accounts:
        state, kept = "none_seen", ()
    elif len(accounts) == 1:
        state, kept = "likely", tuple(accounts)
    else:
        state, kept = "possible", tuple(accounts)
    return Attribution(
        address=address,
        state=state,
        accounts=kept,
        account_count=max(most, len(accounts)),
        at_least=more,
        shared_days=tuple(shared_days),
        gaps=tuple(gaps),
        hands=hands,
        failed_only=failed,
        outside_window=outside,
        days=days,
    )


def _day_words(days: Iterable[date]) -> str:
    return ", ".join(ist_date(m.day_start(d)).rsplit(" ", 1)[0] for d in days)


def gap_word(gap: Gap) -> str:
    """Why one day cannot be used, in words: ``the sign-in logs are no longer kept``, or (events
    with no account name) ``3 sign-in events without an account name``."""
    if gap.unnamed:
        return f"{plural(gap.unnamed, 'sign-in event')} without an account name"
    return GAP_WORDS[gap.why]


def gap_words(gaps: Iterable[Gap]) -> str:
    """``26 Oct: not looked up yet; 22 Oct: the sign-in logs are no longer kept``."""
    return "; ".join(f"{_day_words([g.day])}: {gap_word(g)}" for g in gaps)


def count_line(att: Attribution) -> str:
    """The line for a person who may not see names: how many accounts, and why they are hidden."""
    if att.state in ("none_seen",):
        return "No account signed in from this address in the window."
    if att.state == "unknown" and not att.accounts:
        return "Not known whether anyone signed in from this address: " + gap_words(att.gaps) + "."
    n = att.account_count
    more = "at least " if att.at_least else ""
    so_far = " so far" if att.state == "unknown" else ""
    return (
        f"{more}{plural(n, 'account')} signed in from this address{so_far} — hidden: needs log"
        " access."
    )


def sentence(att: Attribution, *, names: bool = True) -> str:
    """The state in plain words. With ``names`` False it is :func:`count_line`."""
    if not names:
        return count_line(att)
    users = ", ".join(a.user for a in att.accounts)
    if att.state == "likely":
        return f"Probable user: {users}."
    if att.state == "possible":
        base = f"Possible users: {users} ({len(att.accounts)} accounts, most sign-ins first)."
        if att.hands:
            seen: dict[str, date] = {}
            for day, user in att.hands:
                seen.setdefault(user, day)
            said = " and ".join(
                f"by {user} on {_day_words([day])}"
                for user, day in sorted(seen.items(), key=lambda kv: kv[1])
            )
            return f"{base} The address was used {said}: it may have changed hands."
        return base
    if att.state == "shared":
        more = "at least " if att.at_least else ""
        on = f" on {_day_words(att.shared_days)}" if att.shared_days else " over the window"
        return (
            f"A shared address: {more}{plural(att.account_count, 'account')} signed in{on}. "
            "No user is guessed."
        )
    if att.state == "none_seen":
        return "No account had a successful sign-in from this address in the window."
    so_far = f" So far: {users}." if users else ""
    return f"Not known: {gap_words(att.gaps)}.{so_far}"


@dataclass(frozen=True)
class Entry:
    """One account's sign-ins from one address on one day, for a timeline: context, not an alert."""

    user: str
    address: str
    day: date
    first_at: datetime
    last_at: datetime
    events: int
    successes: int
    failures: int
    devices: tuple[str, ...]


def entries(
    address: str,
    records: Mapping[date, m.DayRecord],
    first_alert: datetime,
    last_alert: datetime,
    rules: m.Rules,
) -> list[Entry]:
    """The window's sign-ins collapsed to one entry per account per day (only accounts with an
    event in an hour the window touches), oldest first."""
    start, end = window_of(first_alert, last_alert, rules.pad)
    out: list[Entry] = []
    for day in window_days(start, end):
        record = records.get(day)
        sub = _sub_window(start, end, day)
        if record is None or sub is None:
            continue
        for s in record.sightings:
            if _in_window(s, *sub):
                devices = words_of((a.text, a.events) for a in s.agents)
                out.append(
                    Entry(s.user, address, day, s.first_at, s.last_at, s.events, s.successes,
                          s.failures, devices)
                )  # fmt: skip
    out.sort(key=lambda e: (e.first_at, e.address, e.user))
    return out


def _clock(at: datetime) -> str:
    local = at.astimezone(site.zone())
    return f"{local.hour % 12 or 12}:{local:%M} {'AM' if local.hour < 12 else 'PM'}"


def span_words(first: datetime, last: datetime) -> str:
    """``26 Oct 2026, 9:10 AM to 5:40 PM IST`` (one local day) or both ends in full."""
    zone = site.zone()
    if first.astimezone(zone).date() == last.astimezone(zone).date():
        day = ist_date(first)
        label = site.zone_label(first)
        if _clock(first) == _clock(last):
            return f"{day}, {_clock(first)} {label}"
        return f"{day}, {_clock(first)} to {_clock(last)} {label}"
    return f"{ist_moment(first)} to {ist_moment(last)}"


def entry_words(e: Entry) -> str:
    """``alice signed in 3 times, 26 Oct 2026, 9:10 AM to 5:40 PM IST, Chrome on Windows (from
    10.1.2.3)``."""
    what = "signed in" if e.successes else "tried to sign in"
    devices = f", {', '.join(e.devices)}" if e.devices else ""
    return (
        f"{e.user} {what} {plural(e.events, 'time')}, {span_words(e.first_at, e.last_at)}"
        f"{devices} (from {e.address})"
    )
