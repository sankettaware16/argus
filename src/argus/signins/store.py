"""The database side of the sign-in lookups: ``signin_sightings`` and ``signin_lookups``.

These tables are not derived from grouping (``argus regroup`` leaves them): the sign-in logs last
only a few days at the SIEM, so the sightings are the only copy. ``save`` replaces what an earlier
complete lookup of the same address and day stored, and never turns a complete lookup into nothing
when a later one fails."""

from __future__ import annotations

import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClassifier
from argus.signins import model as m
from argus.signins.plan import Tier, Want

_CLEAR = text("DELETE FROM signin_sightings WHERE address = CAST(:address AS inet) AND day = :day")
_PUT_SIGHTING = text(
    "INSERT INTO signin_sightings (address, day, user_name, first_at, last_at, events, successes,"
    " failures, hours, user_agents) VALUES (CAST(:address AS inet), :day, :user, :first, :last,"
    " :events, :successes, :failures, CAST(:hours AS smallint[]), CAST(:agents AS jsonb))"
)
_PUT_LOOKUP = text(
    "INSERT INTO signin_lookups (address, day, looked_at, complete, accounts, more_accounts,"
    " reason, unnamed, store_failures) VALUES (CAST(:address AS inet), :day, :at, :complete,"
    " :accounts, :more, :reason, :unnamed, :failures)"
    " ON CONFLICT (address, day) DO UPDATE SET looked_at = EXCLUDED.looked_at,"
    " complete = EXCLUDED.complete, accounts = EXCLUDED.accounts,"
    " more_accounts = EXCLUDED.more_accounts, reason = EXCLUDED.reason,"
    " unnamed = EXCLUDED.unnamed,"
    # in a row: a store failure after a store failure counts on, anything else starts again
    " store_failures = CASE WHEN EXCLUDED.reason = 'store_failed' THEN"
    "  CASE WHEN signin_lookups.reason = 'store_failed' THEN signin_lookups.store_failures + 1"
    "  ELSE 1 END ELSE 0 END"
)
_LOOKUPS = text(
    "SELECT host(address) AS address, day, looked_at, complete, accounts, more_accounts, reason,"
    " unnamed, store_failures"
    " FROM signin_lookups WHERE address = ANY(CAST(:addresses AS inet[]))"
    " AND day BETWEEN :first AND :last"
).bindparams(bindparam("addresses", type_=ARRAY(Text)))
_SIGHTINGS = text(
    "SELECT host(address) AS address, day, user_name, first_at, last_at, events, successes,"
    " failures, hours, user_agents FROM signin_sightings"
    " WHERE address = ANY(CAST(:addresses AS inet[])) AND day BETWEEN :first AND :last"
    " ORDER BY address, day, user_name"
).bindparams(bindparam("addresses", type_=ARRAY(Text)))
_INVESTIGATIONS = text(
    "SELECT i.id, i.group_key, i.first_event_at, i.last_event_at,"
    " CASE WHEN EXISTS (SELECT 1 FROM case_members cm JOIN cases c ON c.id = cm.case_id"
    "   WHERE cm.investigation_id = i.id AND cm.removed_at IS NULL AND c.state <> 'closed')"
    "   THEN 0"
    "  WHEN i.severity IN ('critical', 'high') OR EXISTS (SELECT 1 FROM investigation_raises z"
    "   WHERE z.investigation_id = i.id AND z.version = i.version"
    "   AND jsonb_array_length(z.flags) > 0) THEN 1 ELSE 2 END AS tier"
    " FROM investigations i WHERE i.last_event_at >= :since AND i.first_event_at IS NOT NULL"
    " ORDER BY i.last_event_at DESC, i.id LIMIT :limit"
)
_PRUNE_SIGHTINGS = text("DELETE FROM signin_sightings WHERE day < :cutoff")
_PRUNE_LOOKUPS = text("DELETE FROM signin_lookups WHERE day < :cutoff")


async def save(
    conn: AsyncConnection, lookups: Sequence[m.Lookup], sightings: Sequence[m.Sighting]
) -> None:
    """Store one answer: a lookup that holds an answer (complete, or ``unnamed_events``: the named
    accounts are all there) replaces the sightings of its address and day; any other incomplete
    one leaves the sightings alone (they are true, only not the whole day)."""
    answered = [{"address": lk.address, "day": lk.day} for lk in lookups if lk.has_answer]
    if answered:
        await conn.execute(_CLEAR, answered)
    if sightings:
        await conn.execute(
            _PUT_SIGHTING,
            [
                {
                    "address": s.address, "day": s.day, "user": s.user, "first": s.first_at,
                    "last": s.last_at, "events": s.events, "successes": s.successes,
                    "failures": s.failures, "hours": list(s.hours),
                    "agents": json.dumps([{"text": a.text, "events": a.events} for a in s.agents]),
                }
                for s in sightings
            ],
        )  # fmt: skip
    if lookups:
        await conn.execute(
            _PUT_LOOKUP,
            [
                {
                    "address": lk.address, "day": lk.day, "at": lk.looked_at,
                    "complete": lk.complete, "accounts": lk.accounts, "more": lk.more_accounts,
                    "reason": lk.reason, "unnamed": lk.unnamed, "failures": lk.store_failures,
                }
                for lk in lookups
            ],
        )  # fmt: skip


def _sighting(r: Any) -> m.Sighting:
    agents = r.user_agents if isinstance(r.user_agents, list) else []
    return m.Sighting(
        address=str(r.address), day=r.day, user=r.user_name, first_at=r.first_at,
        last_at=r.last_at, events=int(r.events), successes=int(r.successes),
        failures=int(r.failures), hours=tuple(int(h) for h in r.hours),
        agents=tuple(
            m.Agent(str(a.get("text", "")), int(a.get("events", 0)))
            for a in agents
            if isinstance(a, dict)
        ),
    )  # fmt: skip


async def records(
    conn: AsyncConnection, addresses: Collection[str], first: date, last: date
) -> dict[tuple[str, date], m.DayRecord]:
    """The stored lookups and sightings of ``addresses`` on the days ``first`` to ``last``,
    by (address, day); a pair never asked about is not in the answer."""
    if not addresses:
        return {}
    args = {"addresses": sorted(addresses), "first": first, "last": last}
    looked: dict[tuple[str, date], m.Lookup] = {}
    for r in await conn.execute(_LOOKUPS, args):
        looked[(str(r.address), r.day)] = m.Lookup(
            str(r.address), r.day, r.looked_at, bool(r.complete), int(r.accounts),
            int(r.more_accounts), r.reason, int(r.unnamed), int(r.store_failures),
        )  # fmt: skip
    seen: dict[tuple[str, date], list[m.Sighting]] = defaultdict(list)
    for r in await conn.execute(_SIGHTINGS, args):
        seen[(str(r.address), r.day)].append(_sighting(r))
    return {
        key: m.DayRecord(key[0], key[1], looked.get(key), tuple(seen.get(key, ())))
        for key in sorted({*looked, *seen})
    }


def by_address(
    found: Mapping[tuple[str, date], m.DayRecord],
) -> dict[str, dict[date, m.DayRecord]]:
    out: dict[str, dict[date, m.DayRecord]] = defaultdict(dict)
    for (address, day), record in found.items():
        out[address][day] = record
    return out


@dataclass(frozen=True)
class Investigation:
    id: uuid.UUID
    group_key: str
    first: datetime
    last: datetime
    tier: Tier


async def recent(conn: AsyncConnection, since: datetime, limit: int) -> list[Investigation]:
    """Investigations whose last alert is at or after ``since``, newest first, with their rank."""
    rows = await conn.execute(_INVESTIGATIONS, {"since": since, "limit": limit})
    return [Investigation(r.id, r.group_key, r.first_event_at, r.last_event_at, Tier(r.tier))
            for r in rows]  # fmt: skip


def ipv4(values: Iterable[str]) -> list[str]:
    """The IPv4 addresses among ``values``, canonical and sorted (the SSO logs' ``source.ip``)."""
    out: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4:
            out.add(str(address))
    return sorted(out, key=lambda a: int(ipaddress.IPv4Address(a)))


def source_devices(group_key: str, classifier: IpClassifier) -> list[str]:
    """The internal IPv4 addresses on the **source side** of an investigation's grouping key: the
    internal addresses it names or lists under a source field (``source.ip``, ``client.ip``; a DNS
    rule lists every asking address). The one definition of "a device" for the sign-in lookups:
    the pass, the pages and the report use it. An address that was only the destination of the
    traffic (an internal server an outside scanner probed) is not a device, and neither is an
    address that only appears among the investigation's entities, which do not say which side it
    was on."""
    from argus.campaigns import load as campaign_load
    from argus.cases import opener

    try:
        pairs = json.loads(group_key)
    except ValueError:
        return []
    found: set[str] = set()
    for pair in pairs if isinstance(pairs, list) else []:
        if not (isinstance(pair, list) and len(pair) == 2):
            continue
        if pair[0] not in campaign_load.SOURCE_FIELDS:
            continue
        values = pair[1] if isinstance(pair[1], list) else [pair[1]]
        for value in values[: campaign_load.MAX_LISTED]:
            got = classifier.classify(value) if isinstance(value, str) else None
            if got is not None and got.address is not None and got.ip_class in opener.OWN_CLASSES:
                found.update(ipv4([str(got.address)]))
    return ipv4(found)


def devices_of(
    groups: Mapping[uuid.UUID, str],
    classifier: IpClassifier,
    resolvers: Sequence[IPNetwork] = (),
) -> dict[uuid.UUID, list[str]]:
    """The devices of each investigation in ``groups`` (its grouping key): its
    :func:`source_devices`, minus the resolvers named in ``campaigns.resolvers`` (a
    resolver asks for every name its users ask for: it is no device)."""
    from argus.campaigns import load as campaign_load

    out: dict[uuid.UUID, list[str]] = {}
    for investigation_id, group_key in groups.items():
        addresses = [
            a
            for a in source_devices(group_key, classifier)
            if not campaign_load.is_resolver(("ip", a), resolvers)
        ]
        if addresses:
            out[investigation_id] = addresses
    return out


async def wants(
    conn: AsyncConnection,
    classifier: IpClassifier,
    resolvers: Sequence[IPNetwork],
    since: datetime,
    limit: int = 20_000,
) -> list[Want]:
    """The internal addresses of the investigations active since ``since``, each with its
    investigation's span and rank."""
    found = await recent(conn, since, limit)
    devices = devices_of({i.id: i.group_key for i in found}, classifier, resolvers)
    return [
        Want(address, i.first, i.last, i.tier)
        for i in found
        for address in devices.get(i.id, ())
    ]  # fmt: skip


async def prune(conn: AsyncConnection, today: date, keep_days: int) -> int:
    """Remove what is older than ``keep_days``; the number of sightings removed."""
    cutoff = today - timedelta(days=keep_days)
    removed = await conn.execute(_PRUNE_SIGHTINGS, {"cutoff": cutoff})
    await conn.execute(_PRUNE_LOOKUPS, {"cutoff": cutoff})
    return int(removed.rowcount or 0)


async def counts(conn: AsyncConnection) -> dict[str, int]:
    """How much is stored (no names): for the operator's summary."""
    row = (
        await conn.execute(
            text(
                "SELECT (SELECT count(*) FROM signin_sightings) AS sightings,"
                " (SELECT count(DISTINCT address) FROM signin_lookups) AS addresses,"
                " (SELECT count(*) FROM signin_lookups) AS lookups,"
                " (SELECT count(*) FROM signin_lookups WHERE NOT complete) AS incomplete"
            )
        )
    ).one()
    return {k: int(v) for k, v in row._mapping.items()}
