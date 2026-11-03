"""The still-active watch (Q-C2, plan §5 and §7.1, DQ13): pure rules.

Every open true-positive case is asked once a day whether it is *still active*. Per UTC day:

1. **ARGUS's own alerts** (local, nothing sent to the SIEM): did a member investigation, or one
   that strongly matches the case's actors and indicators, alert on that day? A day with no
   alert is *quiet* only if the collector provably saw every alert of it
   (:func:`coverage_reason`); else it is *unverified*.
2. **The proxy logs**, for the case's addresses (``proxy.contact``; ``proxy.pair`` describes
   the rhythm when contact was seen): one request per destination address and daily index,
   the case's campus hosts as the watched hosts, at most :func:`cap_for` questions a case a day
   (one for each checkable subject and two spare, from 6 to 20), in the investigation lane. A
   day's window is 01:40 to 22:59 UTC (one daily index; Q-F1's readings stop at 00:00 and resume
   at 01:30, so an earlier start has no anchor reading). A zero is *quiet* only when Q-F1
   verifies it (:func:`judge_contact`); otherwise *unverified* with the reason, or *not checked*
   with the reason when nothing was asked (STOP, a switch, the lane's budget, the cap) or the
   question did not finish: the next run asks again.

**"Contained"** needs positive evidence (:func:`quiet_window`): the last three whole UTC days
(DQ13's "72 hours" means these three days, and the verdict says so), every one with a quiet
alerts answer and a quiet answer for every address that can be checked in the logs, and no
activity since; plus a person's attestation, which the machine asks for. Without Q-F1's
verified zeros nothing is verified. Each night's seam (22:59 to 01:40 UTC) and today are not
read in the logs: they are covered by ARGUS's own alerts only, and the verdict names what was
read (a case with no address to check in the logs is verified on its alerts alone, and says so).
A key that appears in very many investigations is never quiet (:data:`TOO_COMMON`).

The rules are pure: they read no clock, database or network. :mod:`argus.cases.watchrun` does.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal

from argus import site
from argus.cases.model import QuietWindow
from argus.context import beacon
from argus.freshness.model import Check

Outcome = Literal["active", "quiet", "unverified", "not_checked"]
OUTCOMES: tuple[Outcome, ...] = ("active", "quiet", "unverified", "not_checked")
ALERTS = "alerts"
CONTACT = "proxy.contact"
PAIR = "proxy.pair"

QUIET_DAYS = 3  # 72 hours (DQ13)
# A case's the SIEM questions a day: one for each of its checkable subjects (address x host chunk)
# and two more, at least 6 (plan §5 Q-C2) and at most 20 (the lead's decision after review R18: a
# case with more subjects than its cap could never complete a moving three-day window). The two
# spare questions clear a question asked again the next day. See :func:`cap_for`.
MIN_REQUESTS_A_DAY = 6
MAX_REQUESTS_A_DAY = 20
SPARE_REQUESTS = 2
BACKLOG_DAYS = 7  # how far back a missed day is still asked about
WATCH_AFTER_CLOSURE = timedelta(days=14)  # DQ13
# Closures that claim the problem ended: activity after one is news. A benign or accepted
# closure expects the activity to go on (plan §7.1).
WATCHED_REASONS = frozenset({"remediated_verified", "remediated_unverified"})
LOG_START = time(1, 40)  # the first minute of a day's log window (see the module docstring)
LOG_END = time(22, 59)
ALERT_MARGIN = timedelta(hours=1)  # the collector must have read this far past a day's end
PAIR_WINDOW = timedelta(hours=6)  # the rhythm is read over the last 6 hours of contact

NOT_ON = (
    "known 'nothing found' answers are not switched on yet (Q-F1), so a quiet period cannot be"
    " verified"
)
# Q-F1's reasons (argus.freshness.model.REASONS) in plain words
ZERO_WORDS = {
    "no_margin": "ARGUS has no measured delay for the proxy logs yet",
    "not_log_search": "the answer was not a log search",
    "search_incomplete": "the search did not finish",
    "not_asked": "the time of the search was not recorded",
    "not_past_end": "ARGUS had not yet seen the proxy logs complete to the end of that day",
    "no_anchor": "ARGUS had no freshness reading at the start of that day's window",
    "late": "the proxy logs were running late during that day",
    "silent": "the proxy logs went silent for a while during that day",
    "gap": "ARGUS's freshness readings have a gap during that day",
    "quiet_hours": "ARGUS's freshness readings stop in the nightly pause and no bridge is adopted",
}
RETRY_ZERO = frozenset({"not_past_end"})  # the zero may be provable later
TOO_COMMON = (
    "cannot tell: an address of this case appears in 50 or more investigations, too common to"
    " search for its activity"
)
MALFORMED = "malformed answer"
MAX_COUNT = 10**12  # a request count above this is not a count (squid logs ~10^8 documents a day)
MAX_STAMP_MS = 253_402_300_799_000  # 9999-12-31T23:59:59Z: the last time a datetime can hold


def utc_day(moment: datetime) -> date:
    return moment.astimezone(UTC).date()


def day_window(day: date) -> tuple[datetime, datetime]:
    """The whole UTC day, for ARGUS's own alerts."""
    start = datetime.combine(day, time(0, 0), UTC)
    return start, start + timedelta(days=1)


def log_window(day: date) -> tuple[datetime, datetime]:
    """The part of a day the proxy check reads: 01:40 to 22:59 UTC."""
    return datetime.combine(day, LOG_START, UTC), datetime.combine(day, LOG_END, UTC)


def complete_days(first: date, now: datetime, *, backlog: int = BACKLOG_DAYS) -> list[date]:
    """The finished UTC days to hold an answer for: from ``first`` (or the backlog's start, if
    later) to yesterday, oldest first."""
    last = utc_day(now) - timedelta(days=1)
    start = max(first, last - timedelta(days=backlog - 1))
    return [start + timedelta(days=n) for n in range((last - start).days + 1)]


# --------------------------------------------------------------------------- what to ask


@dataclass(frozen=True, order=True)
class Subject:
    """What one proxy check is about: a destination address, and the campus hosts of the case
    that are watched for it (at most 10 a request; more make further parts)."""

    destination: str
    part: int = 0
    hosts: tuple[str, ...] = field(default=(), compare=False)

    @property
    def key(self) -> tuple[str, str, int]:
        return (CONTACT, self.destination, self.part)


def subjects(
    indicators: Iterable[tuple[str, str, str]],
    campus: Callable[[str], bool],
    shared: Callable[[str, str], str | None] = lambda kind, value: None,
) -> list[Subject]:
    """The proxy checks a case has, from its (kind, value, role) indicators: each destination
    address (a public ``c2`` or ``indicator`` address) with the case's campus host addresses as
    the watched hosts. A destination in shared infrastructure is checked only for watched hosts:
    "who reached it" is no question about a content-delivery network."""
    held = sorted(set(indicators))
    destinations = sorted(
        {v for k, v, r in held if k == "ip" and r in ("c2", "indicator") and not campus(v)}
    )
    hosts = sorted({v for k, v, r in held if k == "ip" and r == "actor" and campus(v)})
    size = beacon.WATCHED_HOSTS
    chunks = [tuple(hosts[i : i + size]) for i in range(0, len(hosts), size)]
    out = []
    for destination in destinations:
        if not chunks:
            if shared("ip", destination) is None:
                out.append(Subject(destination))
            continue
        out.extend(Subject(destination, part, chunk) for part, chunk in enumerate(chunks))
    return out


def cap_for(subjects: int) -> int:
    """The questions a case may ask in a UTC day: one for each checkable subject (address x host
    chunk) and :data:`SPARE_REQUESTS` more, at least :data:`MIN_REQUESTS_A_DAY` and at most
    :data:`MAX_REQUESTS_A_DAY`. The spare ones let a question that has to be asked again the next
    day clear in a day instead of delaying the newest day for good (with 19 or 20 subjects there
    is one or no spare question). Above 20 subjects a day stays incomplete (the verdict says so:
    :func:`quiet_window`)."""
    return min(max(subjects + SPARE_REQUESTS, MIN_REQUESTS_A_DAY), MAX_REQUESTS_A_DAY)


@dataclass(frozen=True)
class Ask:
    day: date
    subject: Subject


def plan_asks(
    wanted: Sequence[Subject],
    days: Sequence[date],
    decided: Collection[tuple[date, str, str, int]],
    skip_days: Collection[date],
    spent_today: int,
    *,
    cap: int | None = None,
) -> tuple[list[Ask], list[Ask]]:
    """(the questions to ask now, the questions cut off by the cap, ``cap_for(len(wanted))``
    unless given), the oldest unanswered (day, address) first: a case with more addresses than
    the cap completes its older days over several runs instead of leaving every day half
    answered. Nothing already decided is asked again, and a day ARGUS's alerts already show active
    is not asked about (the answer is known). A question cut off stays open: the next run asks
    it."""
    cap = cap_for(len(wanted)) if cap is None else cap
    open_ = [
        Ask(day, subject)
        for day in sorted(days)
        if day not in skip_days
        for subject in sorted(wanted)
        if (day, *subject.key) not in decided
    ]
    room = max(cap - spent_today, 0)
    return open_[:room], open_[room:]


# --------------------------------------------------------------------------- reading answers


@dataclass(frozen=True)
class Reading:
    """What a ``proxy.contact`` answer says: whether it is whole, how many requests the watched
    hosts made to the destination that day, when the last was, and which hosts. ``problem``: the
    answer could not be read (a field that is not what the template returns), which is never
    "nothing found"."""

    complete: bool
    requests: int | None
    last: datetime | None
    hosts: tuple[str, ...]
    problem: str | None = None


def _whole(body: Mapping[str, Any]) -> bool:
    shards = body.get("_shards")
    failed = shards.get("failed", 0) if isinstance(shards, Mapping) else 0
    return body.get("timed_out") is not True and not failed


def _node(parent: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    node = parent.get(name)
    if node is None:
        return {}
    if not isinstance(node, Mapping):
        raise ValueError(f"{name} is not an object")
    return node


def _number(value: Any, high: float) -> float | None:
    """None when absent; else a finite number from 0 to ``high``, or a ValueError."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("not a number")
    if not math.isfinite(value) or not 0 <= value <= high:
        raise ValueError("not a plausible number")
    return value


def read_contact(body: Any) -> Reading:
    if not isinstance(body, Mapping) or not isinstance(body.get("aggregations"), Mapping):
        return Reading(False, None, None, ())
    try:
        return _read_contact(body)
    except (ValueError, TypeError, ArithmeticError, OSError):
        return Reading(False, None, None, (), MALFORMED)


def _read_contact(body: Mapping[str, Any]) -> Reading:
    aggs = body["aggregations"]
    count = _number(_node(aggs, "requests").get("value"), MAX_COUNT)
    requests = None if count is None else int(count)
    stamp = _number(_node(aggs, "last").get("value"), MAX_STAMP_MS)
    last = None if stamp is None else datetime.fromtimestamp(stamp / 1000, UTC)
    buckets = _node(aggs, "hosts").get("buckets")
    if buckets is not None and not isinstance(buckets, list):
        raise ValueError("hosts.buckets is not a list")
    _, found = beacon.contacts(aggs)
    hosts = tuple(sorted(c.host for c in found if c.requests > 0))
    return Reading(_whole(body) and requests is not None, requests, last, hosts)


@dataclass(frozen=True)
class Judged:
    outcome: Outcome
    reason: str | None
    detail: dict[str, Any]


def judge_contact(reading: Reading, check: Check | None, *, zeros_on: bool) -> Judged:
    """The answer to one proxy check. Contact is news whatever Q-F1 says; a zero is *quiet*
    only when Q-F1 verifies it (``check``: its verdict for this search, None when not asked)."""
    if not reading.complete:
        return Judged("not_checked", reading.problem or "the search did not finish", {})
    assert reading.requests is not None
    if reading.requests > 0:
        detail: dict[str, Any] = {"requests": reading.requests, "hosts": list(reading.hosts[:10])}
        if reading.last is not None:
            detail["last"] = reading.last.isoformat()
        return Judged("active", None, detail)
    if not zeros_on or check is None:
        return Judged("unverified", NOT_ON, {"requests": 0})
    if check.known:
        assert check.complete_to is not None
        return Judged("quiet", None, {"requests": 0, "complete_to": check.complete_to.isoformat()})
    words = ZERO_WORDS.get(check.reason, check.reason)
    outcome: Outcome = "not_checked" if check.reason in RETRY_ZERO else "unverified"
    return Judged(outcome, f"no contact was found, but it cannot be vouched for: {words}", {})


# Why a gateway refusal or failure leaves a question open (plain words; no value from the logs)
def refusal_words(code: str) -> str:
    return {
        "stopped": "ARGUS's reads of the SIEM are stopped (a switch, or the SIEM is in STOP)",
        "deferred": "the SIEM is not in its normal state, so ARGUS waits",
        "breaker_open": "the SIEM reported overload, so ARGUS waits",
        "skipped_budget": "the investigation lane's budget for now is used up",
        "deadline_passed": "the request could not start in time",
        "off": "this proxy check is not switched on yet",
        "quiet_hours": site.say("this check does not run between {quiet}"),
        "too_common": "could not tell: too common to query",
        "daily_cap": "this check's SIEM time for today is used up",
        "not_normal": "the SIEM is not in its normal state, so ARGUS waits",
        "no_subject": "there is nothing this check could be asked about",
        "failed": "the search did not finish",
        "source_expired": "those proxy logs are no longer kept",
        "source_missing": "the proxy log stream is not there (not created yet, renamed or"
        " mistyped), so ARGUS asks again",
        "rejected": "this check cannot be asked about this address",
    }.get(code, "the check could not be asked")


# Final for the day (asking again changes nothing) / open (ask again next run); a log that is
# "missing" (a data stream not there) is open: unlike an expired day, it can come back
FINAL_REFUSALS = frozenset({"source_expired", "too_common", "rejected", "no_subject"})


# --------------------------------------------------------------------------- the alerts check


def coverage_reason(
    start: datetime,
    end: datetime,
    live: datetime | None,
    gaps: Sequence[tuple[str, datetime, datetime | None]],
) -> tuple[bool, str] | None:
    """Why ARGUS may not have seen every alert of [start, end), or None when it did. The first
    part says whether that is final: a coverage gap (kind, from, to-or-open) touching the window
    is, a collector that has not yet read past the end of the day (by :data:`ALERT_MARGIN`) is
    not: the next run looks again."""
    if live is None:
        return (False, "the collector has not read any alerts yet")
    if live < end + ALERT_MARGIN:
        return (False, "the collector had not read alerts past the end of that day")
    for kind, begin, until in gaps:
        if begin < end and (until is None or until > start):
            return (True, f"ARGUS may have missed alerts that day ({kind.replace('_', ' ')})")
    return None


# --------------------------------------------------------------------------- the quiet window


@dataclass(frozen=True)
class Row:
    """A stored answer (``case_watch_checks``), as far as the rules need it."""

    day: date
    source: str
    subject: str
    part: int
    outcome: str
    reason: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[date, str, str, int]:
        return (self.day, self.source, self.subject, self.part)


def quiet_window(
    rows: Iterable[Row],
    wanted: Sequence[Subject],
    today: date,
    *,
    zeros_on: bool,
    alert_days: Collection[date] = (),
    blocked: str | None = None,
) -> QuietWindow:
    """Whether the case was verifiably quiet for the last three whole UTC days ("72 hours"):
    ARGUS's alerts quiet on each, every proxy check of ``wanted`` quiet on each, no activity
    since, and ``alert_days`` (days with a matching alert in the database now) none of them.
    Anything unknown keeps the case where it is, with the reason (plan §7.1); while answers are
    still missing the reason also says how many of the needed checks are answered.
    ``blocked``: why the case's activity cannot be searched at all (a key too common), never
    quiet."""
    if not zeros_on:
        return QuietWindow(False, NOT_ON)
    if blocked is not None:
        return QuietWindow(False, blocked)
    first = today - timedelta(days=QUIET_DAYS)
    window = [first + timedelta(days=n) for n in range(QUIET_DAYS)]
    by_key = {row.key: row for row in rows}
    if today in alert_days:
        return QuietWindow(False, "ARGUS's own alerts show activity today")
    for later in sorted(by_key.values(), key=lambda r: r.key):
        if later.day >= today and later.outcome == "active":
            return QuietWindow(False, f"activity was seen on {later.day} ({_source(later.source)})")
    needed = {
        day: [((day, ALERTS, "", 0), ()), *(((day, *s.key), s.hosts) for s in sorted(wanted))]
        for day in window
    }
    total = sum(len(items) for items in needed.values())
    unanswered = sum(
        1
        for items in needed.values()
        for key, _ in items
        if key not in by_key or by_key[key].outcome == "not_checked"
    )
    over = (
        "; this case has more addresses than the watch asks in a day"
        if len(wanted) > MAX_REQUESTS_A_DAY
        else ""
    )
    progress = f" ({total - unanswered} of {total} checks answered{over})" if unanswered else ""
    for day in window:
        if day in alert_days:
            return QuietWindow(False, f"ARGUS's own alerts show activity on {day}")
        for key, hosts in needed[day]:
            row = by_key.get(key)
            if row is None:
                return QuietWindow(
                    False, f"the {_source(key[1])} check for {day} has not been done yet{progress}"
                )
            if row.outcome == "active":
                return QuietWindow(False, f"activity was seen on {day} ({_source(row.source)})")
            if row.outcome != "quiet":
                why = row.reason or row.outcome.replace("_", " ")
                more = progress if row.outcome == "not_checked" else ""
                return QuietWindow(
                    False, f"the {_source(row.source)} check for {day} is not verified: {why}{more}"
                )
            if not set(hosts) <= set(row.detail.get("watched") or ()):
                return QuietWindow(
                    False,
                    f"the proxy-log check for {day} did not cover every host the case has now",
                )
    return QuietWindow(
        True,
        f"no activity of the case's addresses for {QUIET_DAYS} whole UTC days ({window[0]} to"
        f' {window[-1]}; "72 hours" means these three days). Read: {read_words(wanted)}',
    )


def read_words(wanted: Sequence[Subject]) -> str:
    """Exactly what a quiet verdict rests on: a case with no address to check in the proxy logs
    is verified on ARGUS's own alerts alone."""
    if not wanted:
        return "alerts only: no address of this case can be checked in the proxy logs"
    return (
        f"alerts, and the proxy logs {LOG_START:%H:%M}-{LOG_END:%H:%M} UTC on each of the"
        f" {QUIET_DAYS} days; the nightly seam and today are covered by alerts only"
    )


def _source(source: str) -> str:
    return "alerts" if source == ALERTS else "proxy-log"


def status_lines(rows: Iterable[Row], wanted: Sequence[Subject]) -> list[str]:
    """What the watch can say about a case now, in plain words, newest day first; a question
    left open says why ("not checked: ...")."""
    by_day: dict[date, list[Row]] = {}
    for row in rows:
        by_day.setdefault(row.day, []).append(row)
    lines = []
    for day in sorted(by_day, reverse=True)[:BACKLOG_DAYS]:
        parts = []
        for row in sorted(by_day[day], key=lambda r: (r.source, r.subject, r.part)):
            if row.source == PAIR:
                continue
            what = _source(row.source)
            if row.outcome == "not_checked":
                parts.append(f"{what}: not checked: {row.reason}")
            elif row.outcome == "unverified":
                parts.append(f"{what}: could not verify: {row.reason}")
            else:
                parts.append(f"{what}: {row.outcome}")
        lines.append(f"{day}: " + "; ".join(parts))
    missing = len(wanted)
    if not by_day and missing:
        lines.append(f"{missing} proxy check(s) are due; none has been done yet")
    return lines


RUN_LATE = timedelta(hours=36)  # the daily run is late after this (a day and a half)


def last_run_words(last: datetime | None, now: datetime) -> str:
    """When the watch last ran and how long ago, in plain words (late after :data:`RUN_LATE`)."""
    if last is None:
        return "the watch has never run (no watch.run in the audit trail)"
    age = max(now - last, timedelta(0))
    hours = int(age.total_seconds() // 3600)
    since = "less than an hour" if hours < 1 else f"{hours} hour{'s' if hours != 1 else ''}"
    late = "; the daily run is late" if age > RUN_LATE else ""
    return f"last run of the watch: {last:%Y-%m-%d %H:%M} UTC ({since} ago{late})"


def newer_than(moment: datetime | None, reference: datetime) -> bool:
    return moment is not None and moment > reference
