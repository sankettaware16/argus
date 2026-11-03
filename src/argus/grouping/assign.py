"""Which investigation an alert belongs to: a pure function of the alert, so order, batching
and concurrency cannot change it.

An investigation is one rule, one **actor** and one day: of the rule's key fields only the ones
that say who acted (ECS ``source.*``, ``client.*``, ``host.*``, ``user.*``) are kept; what the
actor touched (destinations, ports, URLs) is listed inside the investigation, not split into
more of them. No per-rule setting: it works the same for rules added tomorrow. A key without an
actor field is kept whole."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo

from argus import site
from argus.normalize import NormalizedAlert
from argus.normalize.canon import canonical_json

GROUPING_VERSION = "2"  # changes whenever the grouping key rules change
NAMESPACE = uuid.UUID("6f0c4a52-6a53-5b5e-9a43-7a2b9c1d0e11")  # fixed forever: ids depend on it
ANCHOR_DAY = datetime(2026, 1, 2)  # noqa: DTZ001 - the local midnight the 24-hour buckets are counted from
# the days of 2026 whose offsets say which is the zone's smallest (its standard time)
_OFFSET_SAMPLES = tuple(datetime(2026, month, day, 12) for month in range(1, 13) for day in (1, 15))  # noqa: DTZ001
WINDOW = timedelta(hours=24)
ACTOR_NAMESPACES = frozenset({"source", "client", "host", "user"})  # ECS: who acted


@dataclass(frozen=True)
class Assignment:
    investigation_id: uuid.UUID
    key: str
    bucket_start: datetime
    bucket_end: datetime
    previous_id: uuid.UUID  # the same key's bucket before this one (it may not exist)
    next_id: uuid.UUID


def standard_offset(zone: ZoneInfo) -> timedelta:
    """The smallest UTC offset the zone has in 2026: its standard time (a zone with daylight
    saving is ahead of it in summer; Morocco's Ramadan clock, Dublin's winter are the smallest)."""
    return min(
        sample.replace(tzinfo=zone).utcoffset() or timedelta(0) for sample in _OFFSET_SAMPLES
    )


def anchor() -> datetime:
    """The instant the 24-hour buckets are counted from: 2026-01-02 00:00 in the site's zone
    (``site.timezone``) **on standard time**, the zone's smallest offset of the year. Buckets are
    fixed 24 hours, so in the season with daylight saving a bucket starts at 01:00 local, never the
    evening before: the date of a bucket's start is always the calendar day it is named for
    (``assess.patterns.day_of``). Every investigation id depends on the anchor: the zone is chosen
    once, before the first alert is stored."""
    return _anchor_of(site.zone_name())


@lru_cache(maxsize=16)
def _anchor_of(zone_name: str) -> datetime:
    standard = standard_offset(ZoneInfo(zone_name))
    return ANCHOR_DAY.replace(tzinfo=timezone(standard)).astimezone(UTC)


def bucket_start(event_time: datetime) -> datetime:
    """The start of the 24-hour bucket (from 00:00 in the site's zone) holding ``event_time``."""
    start = anchor()
    steps = (event_time.astimezone(UTC) - start) // WINDOW
    return start + steps * WINDOW


def investigation_id(rule_id: str, key: str, start: datetime) -> uuid.UUID:
    name = "|".join((GROUPING_VERSION, rule_id, key, start.astimezone(UTC).isoformat()))
    return uuid.uuid5(NAMESPACE, name)


def group_key(alert: NormalizedAlert) -> str:
    """The actor part of the rule's key (or the whole key when it names no actor), or the alert
    itself when it has to stand alone (singleton)."""
    key = alert.group_key
    if key.singleton is not None or key.canonical is None:
        return f"alert:{alert.alert_id}"
    actor = sorted(
        [name, value]
        for name, value in zip(key.fields, key.values, strict=True)
        if name.split(".", 1)[0] in ACTOR_NAMESPACES and value is not None
    )
    return canonical_json(actor) if actor else key.canonical


def assign(alert: NormalizedAlert) -> Assignment:
    key = group_key(alert)
    start = bucket_start(alert.event_time)
    return Assignment(
        investigation_id=investigation_id(alert.rule_id, key, start),
        key=key,
        bucket_start=start,
        bucket_end=start + WINDOW,
        previous_id=investigation_id(alert.rule_id, key, start - WINDOW),
        next_id=investigation_id(alert.rule_id, key, start + WINDOW),
    )
