"""Builders for the sign-in tests: synthetic names only (``user01`` ...), never a real account.

``answer`` writes the body the SIEM would send for a ``signins.day`` request, in the shape the
template asks for, from a plain description, so the parser, the pass and the attribution are tested
against the same fake."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from argus.config.settings import SIGNIN_ACTIONS
from argus.signins import model as m
from argus.signins.template import DayParams

DAY = date(2026, 10, 28)
CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/130.0.0.0 Safari/537.36"
)
SAFARI = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like"
    " Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)


def at(hour: int, minute: int = 0, day: date = DAY) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=UTC)


def params(
    addresses: Sequence[str] = ("10.1.2.3",),
    day: date = DAY,
    end: datetime | None = None,
) -> DayParams:
    return DayParams(
        day=day,
        addresses=tuple(addresses),
        actions=SIGNIN_ACTIONS,
        end=end or m.day_end(day),
    )


def sighting(
    user: str = "user01",
    *,
    address: str = "10.1.2.3",
    day: date = DAY,
    hours: Sequence[int] = (9, 10, 17),
    events: int | None = None,
    successes: int | None = None,
    failures: int = 0,
    agent: str = CHROME,
) -> m.Sighting:
    n = len(hours) * 2 if events is None else events
    won = n - failures if successes is None else successes
    first = at(min(hours), 10, day)
    last = at(max(hours), 40, day)
    return m.Sighting(
        address, day, user, first, last, n, won, failures, tuple(sorted(hours)),
        (m.Agent(agent, n),),
    )  # fmt: skip


def lookup(
    address: str = "10.1.2.3",
    day: date = DAY,
    *,
    looked_at: datetime | None = None,
    complete: bool = True,
    accounts: int = 1,
    more: int = 0,
    reason: str | None = None,
) -> m.Lookup:
    done = looked_at or m.day_end(day) + timedelta(hours=1)
    if not complete:
        return m.Lookup(address, day, done, False, 0, 0, reason or m.PARTIAL)
    return m.Lookup(address, day, done, True, accounts, more, None)


def record(
    address: str = "10.1.2.3",
    day: date = DAY,
    *sightings: m.Sighting,
    lk: m.Lookup | None = None,
) -> m.DayRecord:
    found = lk or lookup(address, day, accounts=len({s.user for s in sightings}))
    return m.DayRecord(address, day, found, tuple(sightings))


def user_bucket(s: m.Sighting) -> dict[str, Any]:
    base = m.day_start(s.day)
    return {
        "key": s.user,
        "doc_count": s.events,
        "first": {"value": s.first_at.timestamp() * 1000},
        "last": {"value": s.last_at.timestamp() * 1000},
        "outcomes": {
            "buckets": [
                b
                for b in (
                    {"key": "success", "doc_count": s.successes},
                    {"key": "failure", "doc_count": s.failures},
                )
                if b["doc_count"]
            ]
        },
        "agents": {"buckets": [{"key": a.text, "doc_count": a.events} for a in s.agents]},
        "hours": {
            "buckets": [
                {
                    "key": (base + timedelta(hours=h)).timestamp() * 1000,
                    "doc_count": (s.events // len(s.hours))
                    + (s.events % len(s.hours) if h == s.hours[0] else 0),
                }
                for h in s.hours
            ]
        },
    }


def answer(
    by_address: Mapping[str, Sequence[m.Sighting]],
    *,
    accounts: Mapping[str, int] | None = None,
    other: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """The body of a complete answer: a bucket for each address with sign-ins."""
    buckets = []
    for address, found in by_address.items():
        total = (accounts or {}).get(address, len(found))
        buckets.append(
            {
                "key": address,
                "doc_count": sum(s.events for s in found) + (other or {}).get(address, 0),
                "accounts": {"value": total},
                "users": {
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": (other or {}).get(address, 0),
                    "buckets": [user_bucket(s) for s in found],
                },
            }
        )
    return {
        "took": 7,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"hits": []},
        "aggregations": {
            "ips": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": buckets,
            }
        },
    }
