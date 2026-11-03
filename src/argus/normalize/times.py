"""Parsing the times an alert carries: Elasticsearch dates and Kibana rule durations."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

# Outside these bounds a time is a data error, and staying inside keeps all window arithmetic
# (at most MAX_RULE_DURATION either way) far from datetime's limits.
EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
LATEST = datetime(2200, 1, 1, tzinfo=UTC)
MAX_RULE_DURATION = timedelta(days=366)
_MAX_TIME_TEXT = 64

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
_RELATIVE = re.compile(r"now(?:-([0-9]{1,9})([smhdw]))?")
_INTERVAL = re.compile(r"([0-9]{1,9})([smhdw])")


def parse_time(value: Any) -> datetime | None:
    """An ISO 8601 date as Elasticsearch writes it, in UTC; None if it is not one.

    A time without an offset is UTC, as Elasticsearch reads it. Nanoseconds are truncated to
    microseconds (``datetime.fromisoformat`` does it).
    """
    if not isinstance(value, str) or len(value) > _MAX_TIME_TEXT:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
        parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return parsed if EARLIEST <= parsed < LATEST else None


def _duration(match: re.Match[str] | None) -> timedelta | None:
    if match is None:
        return None
    if match.group(1) is None:
        return timedelta(0)
    duration = timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2)])
    return duration if duration <= MAX_RULE_DURATION else None


def parse_lookback(value: Any) -> timedelta | None:
    """How far back a rule's ``from``/``to`` reaches: ``now-6m`` → 6 minutes, ``now`` → 0.
    Rounding (``now-1d/d``) and calendar units (months, years) are not supported: None."""
    if not isinstance(value, str):
        return None
    return _duration(_RELATIVE.fullmatch(value.strip()))


def parse_interval(value: Any) -> timedelta | None:
    """A rule's schedule interval (``5m``); None if it is not a positive duration."""
    if not isinstance(value, str):
        return None
    duration = _duration(_INTERVAL.fullmatch(value.strip()))
    return duration if duration else None
