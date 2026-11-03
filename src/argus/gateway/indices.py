"""Index resolution: exact daily log indices from a time range, checked against a
listing of what exists. A day the range needs but the listing lacks is never skipped silently:
an older day was deleted by ILM (``source_expired``), today's or a later one does not exist yet
(``source_not_ready``). Only a daily family (a ``site`` family whose pattern ends in ``*``) has
daily indices; a data stream family is named as it is (``Targets.family``)."""

from __future__ import annotations

from collections.abc import Collection
from datetime import UTC, date, datetime, timedelta

from argus.gateway.errors import SourceMissingError

PAD = timedelta(hours=1)  # events near UTC midnight can land in the neighbouring day's index
MAX_DAYS = 2


def day_suffix(day: date) -> str:
    return f"{day.year:04d}.{day.month:02d}.{day.day:02d}"


def daily_indices(prefix: str, start: datetime, end: datetime) -> tuple[str, ...]:
    """The daily indices ``<prefix><YYYY.MM.DD>`` that can hold events of [start, end]."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("times must be timezone-aware")
    if end < start:
        raise ValueError("the window ends before it starts")
    first = (start.astimezone(UTC) - PAD).date()
    last = (end.astimezone(UTC) + PAD).date()
    if (last - first).days >= MAX_DAYS:
        raise ValueError(f"a log window spans at most {MAX_DAYS} daily indices")
    return tuple(
        prefix + day_suffix(first + timedelta(days=n)) for n in range((last - first).days + 1)
    )


def pad_only_after(prefix: str, end: datetime) -> frozenset[str]:
    """The index ``daily_indices`` adds only for the padding after the window's last day (a
    window ending after 23:00 UTC reaches into the next day's index)."""
    last = end.astimezone(UTC)
    padded = (last + PAD).date()
    return frozenset({prefix + day_suffix(padded)}) if padded > last.date() else frozenset()


def exact_indices(prefix: str, start: datetime, end: datetime) -> tuple[str, ...]:
    """The daily indices ``<prefix><YYYY.MM.DD>`` that the half-open range [start, end) overlaps,
    with no padding: a range inside one UTC day is that day's index alone."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("times must be timezone-aware")
    if end <= start:
        raise ValueError("the window ends before it starts")
    first = start.astimezone(UTC).date()
    last = (end.astimezone(UTC) - timedelta(microseconds=1)).date()
    if (last - first).days >= MAX_DAYS:
        raise ValueError(f"a log window spans at most {MAX_DAYS} daily indices")
    return tuple(
        prefix + day_suffix(first + timedelta(days=n)) for n in range((last - first).days + 1)
    )


def resolve(
    wanted: tuple[str, ...],
    existing: Collection[str],
    today: date,
    optional: Collection[str] = frozenset(),
) -> tuple[str, ...]:
    """``wanted`` if every index exists; a missing ``optional`` index of a later day than
    ``today`` is left out. Otherwise SourceMissingError naming the missing days."""
    today_suffix = day_suffix(today)
    missing = [name for name in wanted if name not in existing]
    dropped = {name for name in missing if name in optional and name[-10:] > today_suffix}
    missing = [name for name in missing if name not in dropped]
    if not missing:
        return tuple(name for name in wanted if name not in dropped)
    days = tuple(name[-10:] for name in missing)
    expired = any(day < today_suffix for day in days)
    raise SourceMissingError("source_expired" if expired else "source_not_ready", days)
