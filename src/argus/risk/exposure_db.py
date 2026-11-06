"""The exposure step's reads and writes (P4-F E3; Postgres only, no SIEM request here): an inbound
alert group's sites and its source's facts, read from its stored web evidence and the checking
lane's stored checks; the checks written, the groups they change marked for the engine's next
pass, and the checks pruned after ``exposure.keep_days``."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.risk import exposure
from argus.risk.config import Exposure
from argus.risk.exposure import CheckRow
from argus.risk.observe import Group, key_pairs

ACTOR_FIELDS = ("source.ip", "client.ip")


def outside_sources(group: Group) -> list[str]:
    """The group's outside actor addresses (its key's source and client addresses)."""
    out: list[str] = []
    for name, raw in key_pairs(group.key):
        if name in ACTOR_FIELDS:
            out += [v for v in raw if exposure.is_outside(v) and v not in out]
    return out


async def followups(
    conn: AsyncConnection, ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[tuple[str, str, int | None]]]:
    """Each group's stored 2xx answers of its client (``web.followups``): (site, path, status)."""
    out: dict[uuid.UUID, list[tuple[str, str, int | None]]] = defaultdict(list)
    if not ids:
        return out
    rows = await conn.execute(
        text(
            "SELECT investigation_id, snapshot FROM evidence"
            " WHERE investigation_id = ANY(CAST(:ids AS uuid[])) AND template = 'web.followups'"
            " AND status = 'ok' AND snapshot IS NOT NULL ORDER BY version"
        ),
        {"ids": list(ids)},
    )
    for gid, snapshot in rows:
        for row in exposure.followup_rows(snapshot):
            if row not in out[gid]:
                out[gid].append(row)
    return out


def _row(r: Any) -> CheckRow:
    facts = r.facts if isinstance(r.facts, Mapping) else {}
    return CheckRow(r.kind, r.source, r.site, r.day, r.verdict, facts, r.checked_at)


async def checks(
    conn: AsyncConnection, *, lo: date, hi: date, sources: Sequence[str] = (),
    sites: Sequence[str] = (), kinds: Sequence[str] = ("catchall", "paths", "take"),
    until: datetime | None = None,
) -> list[CheckRow]:  # fmt: skip
    """The stored checks of days ``lo`` to ``hi`` of the given kinds about ``sources`` or
    ``sites`` (answered by ``until``)."""
    if not sources and not sites:
        return []
    rows = await conn.execute(
        text(
            "SELECT kind, source, site, day, verdict, facts, checked_at FROM exposure_checks"
            " WHERE kind = ANY(CAST(:kinds AS text[])) AND day BETWEEN :lo AND :hi"
            " AND (source = ANY(CAST(:sources AS text[])) OR site = ANY(CAST(:sites AS text[])))"
            " AND (CAST(:until AS timestamptz) IS NULL OR checked_at <= :until)"
            " ORDER BY checked_at, id"
        ),
        {"kinds": list(kinds), "lo": lo, "hi": hi, "sources": list(sources),
         "sites": list(sites), "until": until},
    )  # fmt: skip
    return [_row(r) for r in rows]


async def facts_for(
    conn: AsyncConnection, sources: Sequence[str], days: Iterable[date], config: Exposure,
    until: datetime | None = None,
) -> dict[date, dict[tuple[str, str], exposure.PairFacts]]:  # fmt: skip
    """The facts of ``sources`` around each day (its checks within a day of it, with every check
    of the sites they touched, which the shared rare paths need)."""
    wanted = sorted(set(days))
    if not sources or not wanted:
        return {}
    lo, hi = wanted[0] - timedelta(days=1), wanted[-1] + timedelta(days=1)
    mine = await checks(conn, lo=lo, hi=hi, sources=sources, until=until)
    sites = sorted({r.site for r in mine if r.site})
    rows = await checks(conn, lo=lo, hi=hi, sites=sites, until=until) if sites else mine
    out = {}
    for day in wanted:
        near = [r for r in rows if abs((r.day - day).days) <= 1]
        out[day] = exposure.derive(near, config)
    return out


async def lookups(
    conn: AsyncConnection, sources: Sequence[str], days: Iterable[date],
    until: datetime | None = None,
) -> dict[tuple[str, date], list[Mapping[str, Any]]]:  # fmt: skip
    """The batched lookup's sites of each (source, day), its newest answer."""
    wanted = sorted(set(days))
    if not sources or not wanted:
        return {}
    rows = await checks(conn, lo=wanted[0], hi=wanted[-1], sources=sources, kinds=("sites",),
                        until=until)  # fmt: skip
    out: dict[tuple[str, date], list[Mapping[str, Any]]] = {}
    for r in rows:  # oldest first: the newest answer stays
        if r.source:
            out[(r.source, r.day)] = [s for s in r.facts.get("sites") or []
                                      if isinstance(s, Mapping)]  # fmt: skip
    return out


async def attach(conn: AsyncConnection, groups: Sequence[Group], config: Exposure) -> list[Group]:
    """``groups`` with the sites and facts of the exposure step (see ``exposure.group_sites``):
    only groups with an outside actor address change."""
    outside = {g.id: outside_sources(g) for g in groups}
    wanted = [g for g in groups if outside[g.id]]
    if not wanted:
        return list(groups)
    stored = await followups(conn, [g.id for g in wanted])
    sources = sorted({s for g in wanted for s in outside[g.id]})
    days = {_utc_day(g) for g in wanted}
    found = await lookups(conn, sources, days)
    facts = await facts_for(conn, sources, days, config)
    window = timedelta(days=config.window_days)
    out = []
    for g in groups:
        if not outside[g.id]:
            out.append(g)
            continue
        named = [str(v) for v in g.fields.get("url.domain", ()) if isinstance(v, str)]
        day = _utc_day(g)
        got = exposure.group_sites(outside[g.id], day, named, stored.get(g.id, []), found,
                                   facts.get(day, {}), window)  # fmt: skip
        if got.sites or got.signals:
            g = replace(g, sites=got.sites, signals={**g.signals, **got.signals})
        out.append(g)
    return out


def _utc_day(g: Group) -> date:
    from datetime import UTC

    return g.last_at.astimezone(UTC).date()


# --------------------------------------------------------------------------- writes


@dataclass(frozen=True)
class Found:
    """One check's answer, ready to store."""

    kind: str
    source: str | None
    site: str | None
    day: date
    template: str
    template_version: int
    task_key: str | None
    verdict: str
    facts: Mapping[str, Any]
    took_ms: int | None


async def save(conn: AsyncConnection, found: Sequence[Found], now: datetime) -> int:
    if not found:
        return 0
    await conn.execute(
        text(
            "INSERT INTO exposure_checks (kind, source, site, day, template, template_version,"
            " task_key, verdict, facts, took_ms, checked_at) VALUES (:kind, :source, :site,"
            " :day, :template, :version, :task_key, :verdict, CAST(:facts AS jsonb), :took, :now)"
        ),
        [{"kind": f.kind, "source": f.source, "site": f.site, "day": f.day,
          "template": f.template, "version": f.template_version, "task_key": f.task_key,
          "verdict": f.verdict, "facts": json.dumps(f.facts, sort_keys=True), "took": f.took_ms,
          "now": now} for f in found],
    )  # fmt: skip
    return len(found)


async def touch(conn: AsyncConnection, sources: Sequence[str], lo: datetime, hi: datetime) -> int:
    """Mark the inbound groups of ``sources`` active from ``lo`` to ``hi`` as changed, so the
    engine's next pass reads them again with what the checks found."""
    if not sources:
        return 0
    result = await conn.execute(
        text(
            "UPDATE risk_groups g SET signature = md5(g.signature || '-exposure')"
            " WHERE g.direction = 'inbound' AND g.at BETWEEN :lo AND :hi AND EXISTS"
            " (SELECT 1 FROM risk_entities e WHERE e.investigation_id = g.investigation_id"
            "  AND e.kind = 'ip' AND e.role = 'actor' AND e.value = ANY(CAST(:src AS text[])))"
        ),
        {"src": list(sources), "lo": lo, "hi": hi},
    )
    return int(result.rowcount or 0)


async def prune(conn: AsyncConnection, now: datetime, config: Exposure) -> int:
    result = await conn.execute(
        text("DELETE FROM exposure_checks WHERE checked_at < :keep"),
        {"keep": now - timedelta(days=config.keep_days)},
    )
    return int(result.rowcount or 0)
