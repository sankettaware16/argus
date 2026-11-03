"""Reading the outside cache for investigations (AR3, D-165): no request is ever made here.

An investigation's external indicators are its address and domain entities that the cache holds
an answer for; only external indicators are ever looked up, so no campus identifier can match. A
name also has the answer for its registered parent (AR2c, D-168): the family look-up asks about the
parent of many names once, and what it finds is true of every name under it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.outside import facts
from argus.outside.psl import registered_parent

PER_INVESTIGATION = 12  # facts one item carries


@dataclass(frozen=True)
class View:
    """How the cache is read: answers newer than ``window`` (a detection, a server's
    description) or ``clean_window`` (everything else; None: ``window``), and VirusTotal's
    ``threshold`` engines calling an indicator malicious make it a detection. ``parent_ok``: whether
    the answer for a registered parent may be read as true of the names under it (eligible, not
    shared infrastructure: D-174); None checks nothing more."""

    window: timedelta
    threshold: int
    clean_window: timedelta | None = None
    parent_ok: Callable[[str], bool] | None = field(default=None, compare=False, repr=False)

    def kept_for(self, source: str, status: str, answer: Mapping[str, Any]) -> timedelta:
        return facts.kept_for(source, status, answer, self.threshold, self.window,
                              self.clean_window)  # fmt: skip


_FACTS = text(
    "SELECT e.investigation_id, o.source, o.kind, o.indicator, o.status, o.answer, o.fetched_at"
    " FROM investigation_entities e"
    " JOIN outside_lookups o ON o.kind = e.kind AND o.indicator = e.value"
    " WHERE e.investigation_id = ANY(:ids) AND e.kind IN ('ip', 'domain')"
    " AND o.fetched_at >= :since ORDER BY e.investigation_id, o.source, o.kind, o.indicator"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_NAMES = text(
    "SELECT investigation_id, value FROM investigation_entities"
    " WHERE investigation_id = ANY(:ids) AND kind = 'domain' ORDER BY investigation_id, value"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_PARENTS = text(
    "SELECT source, kind, indicator, status, answer, fetched_at FROM outside_lookups"
    " WHERE kind = 'domain' AND indicator = ANY(:parents) AND fetched_at >= :since"
).bindparams(bindparam("parents", type_=ARRAY(Text)))


async def facts_for(
    conn: AsyncConnection, ids: Sequence[uuid.UUID], now: datetime, window: timedelta,
    threshold: int, *, clean_window: timedelta | None = None,
    parent_ok: Callable[[str], bool] | None = None,
) -> dict[uuid.UUID, list[dict[str, Any]]]:  # fmt: skip
    """The facts of each investigation in ``ids`` that has any: detections first, then by source
    (VirusTotal, Shodan, Censys), at most :data:`PER_INVESTIGATION`. An answer counts while it is
    inside its own window (see :meth:`View.kept_for`). For a name the answer for its registered
    parent counts too, when the cache holds one, is of the current shape, says the parent is not
    among the popular sites and (``parent_ok``) may be read for it (the name itself and its parent
    are separate facts)."""
    if not ids:
        return {}
    view = View(window, threshold, clean_window)
    rows = list((await conn.execute(_FACTS, {"ids": list(ids), "since": now - window})).all())
    rows.extend(await _parent_rows(conn, ids, now - window, parent_ok))
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    seen: set[tuple[uuid.UUID, str, str, str]] = set()
    for row in rows:
        if row.fetched_at < now - view.kept_for(row.source, row.status, row.answer):
            continue  # a clean answer is older than the clean window
        once = (row.investigation_id, row.source, row.kind, row.indicator)
        if once in seen:
            continue
        seen.add(once)
        out.setdefault(row.investigation_id, []).append(
            facts.fact(row.source, row.kind, row.indicator, row.status, row.answer, threshold)
        )
    order = {s: n for n, s in enumerate(facts.SOURCES)}
    for found in out.values():
        found.sort(key=lambda f: (not f["flagged"], order[f["source"]], f["value"]))
        del found[PER_INVESTIGATION:]
    return out


async def _parent_rows(
    conn: AsyncConnection,
    ids: Sequence[uuid.UUID],
    since: datetime,
    parent_ok: Callable[[str], bool] | None = None,
) -> list[Any]:
    """The cached answers for the registered parents of the domain names the investigations
    hold, as rows of the same shape as ``_FACTS``'s (a name that is its own parent adds nothing:
    the exact match found it). A parent's answer is true of the names under it only when it is of
    the current shape (as the campaign analysis reads it), says in so many words that no
    web-popularity list ranks the parent (a popular site flagged by a few engines is a false
    positive far more often than a campaign; an answer that does not say is not read as rare) and
    ``parent_ok`` lets the parent be read for (shared infrastructure and ineligible names are
    not)."""
    held: dict[uuid.UUID, set[str]] = {}
    for investigation_id, value in (await conn.execute(_NAMES, {"ids": list(ids)})).all():
        parent = registered_parent(value)
        if parent is not None and parent != value:
            held.setdefault(investigation_id, set()).add(parent)
    wanted = sorted({p for parents in held.values() for p in parents})
    if not wanted:
        return []
    answers: dict[str, list[Any]] = {}
    for row in (await conn.execute(_PARENTS, {"parents": wanted, "since": since})).all():
        if row.answer.get("ranked") is not False:
            continue
        if not facts.current_domain(row.status, row.answer):
            continue  # popular, or popularity unknown, or an older shape: nothing is inherited
        if parent_ok is not None and not parent_ok(row.indicator):
            continue
        answers.setdefault(row.indicator, []).append(row)
    out: list[Any] = []
    for investigation_id, parents in held.items():
        for parent in sorted(parents):
            out.extend(_Row(investigation_id, r) for r in answers.get(parent, []))
    return out


class _Row:
    """A cached answer as one investigation's row (what ``_FACTS`` returns)."""

    def __init__(self, investigation_id: uuid.UUID, row: Any) -> None:
        self.investigation_id = investigation_id
        self.source, self.kind, self.indicator = row.source, row.kind, row.indicator
        self.status, self.answer, self.fetched_at = row.status, row.answer, row.fetched_at
