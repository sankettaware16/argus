"""Which addresses to look up, and in what requests (AR6, D-216). Pure: a fake clock and fake rows
are enough to test the whole of it.

A **want** is an investigation's internal address with the window of the investigation. The pairs
(address, day) it needs are the UTC days its window touches that the SSO logs still hold, without a
usable lookup:

* a day that is over (its end plus the ingest margin has passed) is looked up, and once more when
  that lookup was made before ``final_after`` had passed since the day's end (the logs of its last
  minutes arrive late); after that it is final (D-224);
* the current day is looked up when it has not been, or when the last lookup is an hour old and did
  not read as far as the window needs (an address whose investigation is quiet is not asked again);
* a lookup that came back incomplete is tried again after :data:`RETRY_AFTER` (the reasons in
  :data:`argus.signins.model.BACKOFF` later); an answer that could not be stored three times is
  left alone (D-222), and a day whose logs are gone is never asked again;
* nothing is planned between 00:00 and 01:30 UTC (index creation and ILM deletes).

The pairs are ordered by tier (members of a case that is not closed, then raised or high and
critical ones, then the rest), newest investigation first, grouped by day into requests of at most
``batch`` addresses, and the first ``max_requests`` requests are the pass's.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from enum import IntEnum

from argus.gateway.gateway import in_quiet_hours
from argus.signins import model as m
from argus.signins.attribute import reads_short, window_days, window_of

RETRY_AFTER = m.RETRY_AFTER  # an incomplete lookup is not asked again sooner


class Tier(IntEnum):
    CASE = 0  # a member of a case that is not closed
    RAISED = 1  # raised by ARGUS's evidence, or rated high or critical
    REST = 2


@dataclass(frozen=True)
class Want:
    """An internal address of an investigation, with the alerts' span and the rank of the
    investigation."""

    address: str
    first_alert: datetime
    last_alert: datetime
    tier: Tier = Tier.REST


@dataclass(frozen=True)
class Request:
    """One request: the addresses of one day, read up to ``end`` (never past the ingest margin)."""

    day: date
    addresses: tuple[str, ...]
    end: datetime


@dataclass(frozen=True)
class Plan:
    requests: tuple[Request, ...]
    pairs: int  # (address, day) pairs wanted
    waiting: int  # pairs that did not fit in this pass
    quiet: bool = False
    skipped_old: int = 0  # pairs of days the logs no longer hold
    stuck: int = 0  # pairs whose answer could not be stored, three times: left alone


def key_of(address: str) -> int:
    return int(ipaddress.IPv4Address(address))


def read_end(day: date, now: datetime) -> datetime:
    """Where a request for ``day`` stops: the day's end, or the ingest margin before ``now``,
    to the minute (the same request twice in a minute is the same request)."""
    stop = (now - m.MARGIN).replace(second=0, microsecond=0)
    return min(m.day_end(day), stop)


def due(
    record: m.DayRecord | None,
    day: date,
    window: tuple[datetime, datetime],
    rules: m.Rules,
    *,
    now: datetime,
) -> bool:
    """Whether the (address, day) pair is to be asked now."""
    today = m.utc_day(now)
    if day < m.oldest_kept(today, rules.retention_days) or day > today:
        return False
    if now - m.MARGIN <= m.day_start(day):
        return False  # the day has begun, but nothing of it is old enough to read
    lookup = None if record is None else record.lookup
    if lookup is None:
        return True
    if not lookup.has_answer:
        if lookup.reason == m.GONE or stuck(lookup):
            return False
        return now - lookup.looked_at >= m.BACKOFF.get(lookup.reason or "", RETRY_AFTER)
    if lookup.final(rules.final_after):
        return False
    if now >= m.day_end(day) + rules.final_after:
        return True  # the day is over, and the lookup was made before its late logs had arrived
    if now - lookup.looked_at < rules.current_day_every:
        return False
    return reads_short(lookup, day, window, now)


def stuck(lookup: m.Lookup | None) -> bool:
    """Whether ARGUS has failed three times in a row to store the answer for this lookup's day."""
    return (
        lookup is not None
        and lookup.reason == m.STORE_FAILED
        and lookup.store_failures >= m.MAX_STORE_FAILURES
    )


def plan(
    wants: Iterable[Want],
    records: Mapping[tuple[str, date], m.DayRecord],
    rules: m.Rules,
    *,
    now: datetime,
    max_requests: int | None = None,
) -> Plan:
    """The requests of this pass."""
    if in_quiet_hours(now):
        return Plan((), 0, 0, quiet=True)
    best: dict[tuple[str, date], tuple[int, float]] = {}
    skipped = 0
    left_alone: set[tuple[str, date]] = set()
    today = m.utc_day(now)
    for want in wants:
        window = window_of(want.first_alert, want.last_alert, rules.pad)
        for day in window_days(*window):
            if day > today:
                continue
            if day < m.oldest_kept(today, rules.retention_days):
                skipped += 1
                continue
            record = records.get((want.address, day))
            if record is not None and stuck(record.lookup):
                left_alone.add((want.address, day))
                continue
            if not due(record, day, window, rules, now=now):
                continue
            rank = (int(want.tier), -want.last_alert.timestamp())
            key = (want.address, day)
            if key not in best or rank < best[key]:
                best[key] = rank
    ordered = sorted(best.items(), key=lambda kv: (kv[1], kv[0][1], key_of(kv[0][0])))
    batches: dict[date, list[list[str]]] = {}
    firsts: dict[tuple[date, int], tuple[int, float]] = {}
    for (address, day), rank in ordered:
        open_batches = batches.setdefault(day, [])
        if not open_batches or len(open_batches[-1]) >= rules.batch:
            open_batches.append([])
            firsts[(day, len(open_batches) - 1)] = rank
        open_batches[-1].append(address)
    requests = sorted(
        (
            (firsts[(day, n)], day, tuple(sorted(group, key=key_of)))
            for day, groups in batches.items()
            for n, group in enumerate(groups)
        ),
        key=lambda t: (t[0], t[1]),
    )
    limit = rules.max_requests if max_requests is None else max_requests
    chosen = requests[: max(limit, 0)]
    left = sum(len(group) for _, _, group in requests[len(chosen) :])
    return Plan(
        tuple(Request(day, group, read_end(day, now)) for _, day, group in chosen),
        pairs=len(best),
        waiting=left,
        skipped_old=skipped,
        stuck=len(left_alone),
    )
