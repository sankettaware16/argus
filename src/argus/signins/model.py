"""What the sign-in lookups store and read: plain frozen records, no database.

A **sighting** is one account's sign-ins from one address on one UTC day. A **lookup** is the record
that ARGUS asked about an address on a day and what the answer was, so that "looked, none seen",
"not looked yet", "incomplete" and "logs no longer kept" are different things. The usernames in a
sighting are personal data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Final

from argus.config.settings import SigninsSettings
from argus.site import Role, source_for

MAX_USERS: Final = 10  # accounts listed for one address on one day (the rest are counted)
MAX_AGENTS: Final = 3  # browser strings kept for one account on one day
MAX_AGENT_CHARS: Final = 300
MAX_USER_CHARS: Final = 256  # what the logs' .keyword field holds (ignore_above)
MARGIN: Final = timedelta(minutes=15)  # ingest: the last minutes of the logs are not read
DAY: Final = timedelta(days=1)

# Why a lookup is not complete (stored in ``signin_lookups.reason``).
PARTIAL: Final = "partial"  # the SIEM's answer timed out or lost shards: never data
BAD_ANSWER: Final = "bad_answer"  # the answer did not have the shape the contract says
GONE: Final = "logs_gone"  # the day's index no longer exists (ILM)
FAILED: Final = "failed"  # the request reached the SIEM and failed (overload, transport, an error)
STORE_FAILED: Final = "store_failed"  # the SIEM answered, ARGUS could not store the answer
UNNAMED: Final = "unnamed_events"  # sign-in events with no usable account name
MISSING: Final = "index_missing"  # the day's index is not there though the logs should be
REASONS: Final = (PARTIAL, BAD_ANSWER, GONE, FAILED, STORE_FAILED, UNNAMED, MISSING)
# A lookup made on this reason is tried again no sooner than this (the rest: RETRY_AFTER).
RETRY_AFTER: Final = timedelta(minutes=30)
BACKOFF: Final = {STORE_FAILED: timedelta(hours=6), MISSING: timedelta(hours=6)}
MAX_STORE_FAILURES: Final = 3  # a batch that cannot be stored this many times is left alone
FINAL_AFTER: Final = timedelta(hours=3)  # ``signins.final_after``'s default


def source() -> str:
    """The site's sign-in log family (its source key)."""
    return source_for(Role.AUTH)


@dataclass(frozen=True)
class Agent:
    """A browser string and how many of the sign-ins carried it."""

    text: str
    events: int


@dataclass(frozen=True)
class Sighting:
    """One account's sign-ins from one address on one UTC day. ``hours`` are the UTC hours (0 to
    23) with at least one event; ``agents`` the commonest browser strings (at most three)."""

    address: str
    day: date
    user: str
    first_at: datetime
    last_at: datetime
    events: int
    successes: int
    failures: int
    hours: tuple[int, ...]
    agents: tuple[Agent, ...] = ()


@dataclass(frozen=True)
class Lookup:
    """What ARGUS asked about ``address`` on ``day``, and when. Complete: the SIEM answered and the
    answer was whole; ``accounts`` is every account that signed in that day and ``more_accounts``
    how many of them are not listed as sightings. Incomplete: ``reason`` says why, and ``accounts``
    is 0 (nothing is known). The one incomplete answer that holds sightings is ``unnamed_events``:
    the named accounts are right, ``unnamed`` events had no account name.
    ``store_failures``: how many times in a row ARGUS could not store the answer.

    ``looked_at`` is when the answer was got, except for a day that was not over: then it is no
    later than the request's end plus the ingest margin, so ``covered_until`` never claims more
    than was read."""

    address: str
    day: date
    looked_at: datetime
    complete: bool
    accounts: int = 0
    more_accounts: int = 0
    reason: str | None = None
    unnamed: int = 0
    store_failures: int = 0

    @property
    def has_answer(self) -> bool:
        """Whether the lookup holds a SIEM answer whose sightings are the day's named ones."""
        return self.complete or self.reason == UNNAMED

    def covered_until(self) -> datetime | None:
        """The end of what an answered lookup read: the day's end, or the ingest margin before
        the time it was made for a day that was not over."""
        if not self.has_answer:
            return None
        return min(day_end(self.day), self.looked_at - MARGIN)

    def final(self, after: timedelta) -> bool:
        """Whether nothing more is to be read for the day: the lookup holds an answer and was
        made ``after`` the day's end (late logs of the day's last minutes have arrived)."""
        return self.has_answer and self.looked_at >= day_end(self.day) + after


def stamp(day: date, end: datetime, at: datetime) -> datetime:
    """The ``looked_at`` of an answer got at ``at`` to a request that read ``day`` up to ``end``:
    a request for a day that was not over read to ``end`` only, so it is dated no later than the
    ingest margin after it; one for a finished day is dated when it was answered."""
    return at if end >= day_end(day) else min(at, end + MARGIN)


@dataclass(frozen=True)
class Rules:
    """The settings the pure parts read."""

    pad: timedelta = timedelta(hours=2)
    shared_accounts: int = 4
    retention_days: int = 5
    batch: int = 200
    max_requests: int = 6
    current_day_every: timedelta = timedelta(hours=1)
    keep_days: int = 180
    actions: tuple[str, ...] = ()
    final_after: timedelta = FINAL_AFTER


def rules_of(s: SigninsSettings) -> Rules:
    """The rules from the settings' ``signins`` section."""
    return Rules(
        pad=timedelta(hours=s.pad_hours),
        shared_accounts=s.shared_accounts,
        retention_days=s.retention_days,
        batch=s.batch,
        max_requests=s.max_requests_per_pass,
        current_day_every=s.current_day_every,
        keep_days=s.keep_days,
        actions=tuple(s.actions),
        final_after=s.final_after,
    )


def day_start(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


def day_end(day: date) -> datetime:
    return day_start(day) + DAY


def oldest_kept(today: date, retention_days: int) -> date:
    """The oldest UTC day whose logs the cluster still holds: ``retention_days`` days, today
    included."""
    return today - timedelta(days=retention_days - 1)


@dataclass(frozen=True)
class DayRecord:
    """Everything stored for one address on one day: the lookup (None: never asked) and the
    sightings of its accounts."""

    address: str
    day: date
    lookup: Lookup | None = None
    sightings: tuple[Sighting, ...] = ()


def utc_day(moment: datetime) -> date:
    return moment.astimezone(UTC).date()
