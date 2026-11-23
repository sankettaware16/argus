"""The daily look-up of beacon destinations: each pass asks VirusTotal about the external
destinations of unreviewed investigations that carry the beacon flag (and no threat-list hit),
lowest severity first, within a daily budget; the cache makes a repeat free. A flagged destination
gives the investigation the "flagged by outside threat intel" flag on the next
:func:`argus.assess.raised.refresh_outside`. Never asked: internal or private names, shared
infrastructure, cached answers and indicators that failed lately."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assess.raised import HORIZON
from argus.cases.membership import Shared
from argus.llm.detect import OwnSpace
from argus.outside import facts, service, store

BEACON = "regular traffic, like a beacon"  # evaluation.gold.flags's words
LISTED = "on a threat list"
PER_INVESTIGATION = 3
CANDIDATES = 400  # investigations looked through in one pass

_PICK = text(
    """
SELECT r.investigation_id FROM investigation_raises r
JOIN investigations i ON i.id = r.investigation_id AND i.version = r.version
WHERE jsonb_exists(r.flags, :beacon) AND NOT jsonb_exists(r.flags, :listed)
  AND NOT jsonb_exists(r.flags, :outside) AND i.last_event_at >= :since
  AND NOT EXISTS (SELECT 1 FROM review_events rv WHERE rv.investigation_id = i.id
                  AND rv.action = 'reviewed' AND rv.version = i.version)
ORDER BY (i.severity IN ('high', 'critical')),
  CASE i.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                  WHEN 'low' THEN 1 ELSE 0 END DESC,
  i.last_event_at DESC NULLS LAST, i.id
LIMIT :limit
"""
)
_ENTITIES = text(
    "SELECT investigation_id, kind, value FROM investigation_entities"
    " WHERE investigation_id = ANY(:ids) AND kind IN ('ip', 'domain')"
    " ORDER BY investigation_id, kind, value"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_NAMES = text(
    "SELECT kind, value FROM investigation_entities WHERE investigation_id = :id"
    " AND kind IN ('host', 'user') ORDER BY kind, value"
)
_CONTEXT = text(
    "SELECT i.group_key, (SELECT d.body #> '{context,pack,fields}' FROM dossiers d"
    " WHERE d.investigation_id = i.id ORDER BY d.version DESC, d.created_at DESC LIMIT 1)"
    " AS fields FROM investigations i WHERE i.id = :id"
)
_KNOWN = text(
    "SELECT kind, indicator, status, answer, fetched_at FROM outside_lookups"
    " WHERE source = 'virustotal' AND fetched_at >= :since AND indicator = ANY(:values)"
).bindparams(bindparam("values", type_=ARRAY(Text)))


@dataclass
class Report:
    off: str = ""  # why nothing was done: no key, switched off, budget spent
    asked: int = 0  # lookups that reached VirusTotal
    found: int = 0
    not_found: int = 0
    failed: int = 0
    stopped: str = ""  # a limit or a stop ended the pass early
    picked: list[tuple[str, str]] = field(default_factory=list, repr=False)

    def line(self) -> str:
        if self.off:
            return f"outside: prefetch off ({self.off})"
        said = f"outside: looked up {self.asked} (found {self.found}, no record {self.not_found}"
        said += f", failed {self.failed})"
        return said + (f"; {self.stopped}" if self.stopped else "")


@dataclass(frozen=True)
class Pick:
    kind: str
    value: str
    ours: OwnSpace | None = field(default=None, repr=False)  # the view it was cleared under


async def ours_of(
    conn: AsyncConnection, investigation_id: uuid.UUID, outside: service.Outside
) -> OwnSpace | None:  # fmt: skip
    """The internal view of one investigation: the base view plus its host and user names, built
    by the privacy layer from the same parts of the dossier its model view is (the host and user
    entities, the grouping key and the fields). None when the layer's view is not set up."""
    build = outside.eligibility.ours_for
    if build is None:
        return None
    entities: dict[str, list[str]] = {"host": [], "user": []}
    for kind, value in (await conn.execute(_NAMES, {"id": investigation_id})).all():
        entities[kind].append(value)
    row = (await conn.execute(_CONTEXT, {"id": investigation_id})).first()
    body = {
        "facts": {"entities": entities, "group_key": None if row is None else row.group_key},
        "context": {"pack": {"fields": {} if row is None or row.fields is None else row.fields}},
    }
    return build([body])


async def pick(
    conn: AsyncConnection, now: datetime, outside: service.Outside, shared: Shared, want: int,
    *, horizon: timedelta = HORIZON,
) -> list[Pick]:  # fmt: skip
    """Up to ``want`` indicators to ask VirusTotal about, in priority order."""
    ids = [
        row[0]
        for row in (
            await conn.execute(
                _PICK,
                {"beacon": BEACON, "listed": LISTED, "outside": facts.FLAG,
                 "since": now - horizon, "limit": CANDIDATES},
            )
        ).all()
    ]  # fmt: skip
    if not ids:
        return []
    rows = (await conn.execute(_ENTITIES, {"ids": ids})).all()
    by_investigation: dict[uuid.UUID, list[tuple[str, str]]] = {}
    for investigation_id, kind, value in rows:
        indicator = facts.canonical(kind, value)
        if indicator is None or outside.eligibility.check(kind, indicator) is not None:
            continue  # an internal, private or special address or name, or not valid
        if shared.reason(kind, indicator) is not None:
            continue  # many customers behind one address: a detection says little
        by_investigation.setdefault(investigation_id, []).append((kind, indicator))
    wanted = sorted({v for pairs in by_investigation.values() for _, v in pairs})
    known: set[tuple[str, str]] = set()
    if wanted:
        known = {
            (row.kind, row.indicator)
            for row in (
                await conn.execute(_KNOWN, {"since": now - outside.window, "values": wanted})
            ).all()
            if row.fetched_at
            >= now - outside.view.kept_for(facts.VIRUSTOTAL, row.status, row.answer)
        }  # what the cache still keeps: a clean answer for the shorter clean window
    holders: dict[tuple[str, str], list[uuid.UUID]] = {}
    for investigation_id in ids:  # the priority order the database gave
        for pair in by_investigation.get(investigation_id, []):
            holders.setdefault(pair, []).append(investigation_id)
    views: dict[uuid.UUID, OwnSpace | None] = {}  # each investigation's internal view, built once
    cleared: dict[tuple[str, str], Pick | None] = {}

    async def clear(pair: tuple[str, str]) -> Pick | None:
        """The pick, or None when an investigation holding the pair has an internal name in it."""
        if pair not in cleared:
            cleared[pair] = None
            for holder in holders[pair]:
                if holder not in views:
                    views[holder] = await ours_of(conn, holder, outside)
                view = views[holder]
                eligibility = (
                    outside.eligibility if view is None else outside.eligibility.with_ours(view)
                )
                if eligibility.check(*pair) is not None:
                    break
            else:  # every holder's view clears it; the lookup checks the first (priority) one
                cleared[pair] = Pick(*pair, views[holders[pair][0]])
        return cleared[pair]

    picked: list[Pick] = []
    seen: set[tuple[str, str]] = set()
    for investigation_id in ids:
        mine = [
            p
            for p in by_investigation.get(investigation_id, [])
            if p not in known and not outside.failed_lately(facts.VIRUSTOTAL, *p)
        ]
        mine.sort(key=lambda p: (p[0] != "ip", p[1]))  # addresses before names
        taken = 0
        for pair in mine:
            if taken >= PER_INVESTIGATION:
                break
            got = await clear(pair)
            if got is None:
                continue  # a refused indicator takes no place
            taken += 1
            if pair not in seen:
                seen.add(pair)
                picked.append(got)
            if len(picked) >= want:
                return picked
    return picked


async def run(
    db: AsyncEngine, outside: service.Outside, shared: Shared, now: datetime
) -> Report:  # fmt: skip
    """One pass: look up what :func:`pick` chooses, VirusTotal only, within the prefetch's daily
    budget and VirusTotal's limits (the pass ends at the first limit or stop)."""
    s = outside.settings
    if not s.prefetch:
        return Report(off="switched off")
    if not outside.on(facts.VIRUSTOTAL):
        return Report(off="no VirusTotal key")
    async with db.connect() as conn:
        left = s.prefetch_per_day - await store.used_today(conn, facts.VIRUSTOTAL, "prefetch", now)
        if left <= 0:
            return Report(off="today's budget is spent")
        picks = await pick(conn, now, outside, shared, min(s.prefetch_batch, left))
    report = Report(picked=[(p.kind, p.value) for p in picks])
    for p in picks:
        got = await outside.lookup(facts.VIRUSTOTAL, p.kind, p.value, purpose="prefetch",
                                   day_cap=s.prefetch_per_day, ours=p.ours)  # fmt: skip
        if got.status == service.FETCHED:
            report.asked += 1
            report.found += got.answer_status == facts.FOUND
            report.not_found += got.answer_status == facts.NOT_FOUND
        elif got.status == service.FAILED:
            report.asked += 1
            report.failed += 1
        elif got.status == service.BLOCKED:
            report.stopped = got.reason
            break
    return report
