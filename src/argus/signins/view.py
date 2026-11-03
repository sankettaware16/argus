"""The read side: the probable users of an investigation's or a case's devices, from the stored
sightings; used by the pages, the incident report and ``argus signins show``. It reads ARGUS's own
database only. A device is a source-side address of an investigation's grouping key
(``store.devices_of``); a case's are those of its members plus the actors a person added. Each
device is attributed over the alerts of its own investigations, not over the whole case's span, so
the page, the report and the pass agree on what a device is."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClassifier
from argus.cases import opener
from argus.config.settings import Settings
from argus.signins import model as m
from argus.signins import store
from argus.signins.attribute import Attribution, Entry, attribute, entries, window_days, window_of

MAX_DEVICES = 300  # devices of a case that are read (a campaign case can hold hundreds)
Span = tuple[datetime, datetime]  # the first and last alert of a device's own investigations


@dataclass(frozen=True)
class Reading:
    """What a page needs to read the sign-ins: the rules, the classifier that says which addresses
    are internal, the resolvers that are no device, and whether the feature is on."""

    rules: m.Rules
    classifier: IpClassifier | None
    resolvers: tuple[IPNetwork, ...] = ()
    enabled: bool = False


def reading_of(settings: Settings, classifier: IpClassifier | None) -> Reading:
    return Reading(
        m.rules_of(settings.signins), classifier, tuple(settings.campaigns.resolvers),
        settings.signins.enabled,
    )  # fmt: skip


@dataclass(frozen=True)
class Users:
    """The result for a set of devices, each over its own span."""

    first: datetime | None
    last: datetime | None
    attributions: tuple[Attribution, ...]
    entries: tuple[Entry, ...]
    devices_total: int


EMPTY = Users(None, None, (), (), 0)


def assemble(
    devices: Sequence[str],
    found: Mapping[str, Mapping[date, m.DayRecord]],
    spans: Mapping[str, Span],
    rules: m.Rules,
    now: datetime,
    devices_total: int,
) -> Users:
    """The attribution of each device from its stored days over its own span (pure), and the
    timeline entries of the devices that have a user to name: a shared address names no one, in
    the timeline neither. A device is attributed over the alerts of the investigations that
    involve it, never over the whole case: another device's later alerts say nothing about who
    used this one."""
    attributions = tuple(attribute(a, found.get(a, {}), *spans[a], rules, now=now) for a in devices)
    made: list[Entry] = []
    for att in attributions:
        if att.state != "shared":
            made.extend(
                entries(att.address, found.get(att.address, {}), *spans[att.address], rules)
            )
    made.sort(key=lambda e: (e.first_at, e.address, e.user))
    return Users(
        min((spans[a][0] for a in devices), default=None),
        max((spans[a][1] for a in devices), default=None),
        attributions,
        tuple(made),
        devices_total,
    )


async def read(
    conn: AsyncConnection, reading: Reading, spans: Mapping[str, Span], now: datetime
) -> Users:
    """The attribution (and the timeline entries) of the devices in ``spans``, each for the
    alerts of its own span."""
    wanted = store.ipv4(spans)
    if not wanted:
        return EMPTY
    shown = wanted[:MAX_DEVICES]
    windows = [window_of(*spans[a], reading.rules.pad) for a in shown]
    days = window_days(min(w[0] for w in windows), max(w[1] for w in windows))
    found = store.by_address(await store.records(conn, shown, days[0], days[-1]))
    return assemble(shown, found, spans, reading.rules, now, len(wanted))


async def for_investigation(
    conn: AsyncConnection, reading: Reading, investigation_id: uuid.UUID, now: datetime
) -> Users:
    """The probable users of an investigation's devices for its own alerts."""
    row = (
        await conn.execute(
            text(
                "SELECT group_key, first_event_at, last_event_at FROM investigations WHERE id = :i"
            ),
            {"i": investigation_id},
        )
    ).first()
    if row is None or reading.classifier is None or row.first_event_at is None:
        return EMPTY
    found = store.devices_of(
        {investigation_id: row.group_key}, reading.classifier, reading.resolvers
    )
    span = (row.first_event_at, row.last_event_at or row.first_event_at)
    return await read(conn, reading, dict.fromkeys(found.get(investigation_id, ()), span), now)


async def spans_of_case(
    conn: AsyncConnection, reading: Reading, case_id: uuid.UUID
) -> dict[str, Span]:
    """A case's devices, each with the span of the alerts of the member investigations that
    involve it: the source-side addresses of its members' grouping keys, and the internal
    addresses a person added as actors (over the span of the whole case)."""
    rows = (
        await conn.execute(
            text(
                "SELECT i.id, i.group_key, i.first_event_at, i.last_event_at"
                " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
                " WHERE m.case_id = :c AND m.removed_at IS NULL AND i.first_event_at IS NOT NULL"
                " ORDER BY i.first_event_at, i.id LIMIT 2000"
            ),
            {"c": case_id},
        )
    ).all()
    if not rows or reading.classifier is None:
        return {}
    found = store.devices_of(
        {r.id: r.group_key for r in rows}, reading.classifier, reading.resolvers
    )
    spans: dict[str, Span] = {}
    for r in rows:
        mine = (r.first_event_at, r.last_event_at or r.first_event_at)
        for address in found.get(r.id, ()):
            first, last = spans.get(address, mine)
            spans[address] = (min(first, mine[0]), max(last, mine[1]))
    whole = (
        min(r.first_event_at for r in rows),
        max(r.last_event_at or r.first_event_at for r in rows),
    )
    added = await conn.execute(
        text(
            "SELECT value FROM case_indicators WHERE case_id = :c AND removed_at IS NULL"
            " AND role = 'actor' AND kind = 'ip' AND source = 'person'"
        ),
        {"c": case_id},
    )
    for (value,) in added:
        if reading.classifier.classify(value).ip_class in opener.CAMPUS:
            for address in store.ipv4([value]):
                spans.setdefault(address, whole)
    return spans


async def for_case(
    conn: AsyncConnection, reading: Reading, case_id: uuid.UUID, now: datetime
) -> Users:
    """The probable users of a case's devices, each for the alerts of its own investigations."""
    return await read(conn, reading, await spans_of_case(conn, reading, case_id), now)
