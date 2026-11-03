"""What a split takes with the investigations it moves: which of a case's indicators go with them.
Read only; :meth:`argus.cases.service.CaseService.split` calls it and the machine checks it.

An investigation's devices are the actors of its grouping key (as membership matches) and the
internal devices a campaign case holds as actors. An actor row goes with the moved investigations
when one of them has that device and no investigation that stays has it; a device both have stays
on the source and is also given to the target, and the person is told. C2 and indicator rows stay
on the source; the target gets the ones its investigations touch."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClassifier
from argus.campaigns import load as campaign_load
from argus.cases import opener
from argus.cases.model import Case, Indicator
from argus.cases.service import Carried, Carry

Key = tuple[str, str]


@dataclass(frozen=True)
class Who:
    """An investigation's actors (what membership matches by) and its devices (those, and the
    internal devices behind it that a campaign case holds as actors)."""

    actors: tuple[Indicator, ...] = ()
    devices: frozenset[Key] = frozenset()


async def who(
    conn: AsyncConnection, ids: Sequence[uuid.UUID], classifier: IpClassifier,
    resolvers: Sequence[IPNetwork] = (),
) -> dict[uuid.UUID, Who]:  # fmt: skip
    """:class:`Who` for each of ``ids`` (one the database does not know has none)."""
    if not ids:
        return {}
    rows = await conn.execute(
        text("SELECT id, group_key FROM investigations WHERE id = ANY(:ids)"),
        {"ids": list(ids)},
    )
    keys = {r.id: str(r.group_key) for r in rows}
    out: dict[uuid.UUID, Who] = {i: Who() for i in ids}
    hosts = await campaign_load.hosts_for(conn, keys, classifier, resolvers)
    for investigation, group_key in keys.items():
        actors, _ = opener.actors_of(group_key, classifier)
        named = {(a.kind, a.value) for a in actors}
        out[investigation] = Who(actors, frozenset(named | hosts.get(investigation, frozenset())))
    return out


async def touched(
    conn: AsyncConnection, ids: Sequence[uuid.UUID], rows: Sequence[Indicator]
) -> frozenset[Key]:
    """Which of the C2 and indicator ``rows`` the investigations ``ids`` involve (their entities,
    which membership matches a C2 or indicator by)."""
    if not ids or not rows:
        return frozenset()
    found = await conn.execute(
        text(
            "SELECT DISTINCT kind, value FROM investigation_entities"
            " WHERE investigation_id = ANY(:ids) AND (kind, value) IN (SELECT k, v FROM"
            " unnest(CAST(:kinds AS text[]), CAST(:values AS text[])) AS u(k, v))"
        ),
        {"ids": list(ids), "kinds": [r.kind for r in rows], "values": [r.value for r in rows]},
    )
    return frozenset((str(k), str(v)) for k, v in found)


def carrier(
    conn: AsyncConnection, classifier: IpClassifier, resolvers: Sequence[IPNetwork] = ()
) -> Carry:
    """The :data:`~argus.cases.service.Carry` of a split on ``conn``."""

    async def carry(case: Case, moving: Sequence[uuid.UUID]) -> Carried:
        # an id that is no member is the machine's to refuse; it is left out of the reading
        moved = [m for m in dict.fromkeys(moving) if m in case.members]
        staying = [m for m in sorted(case.members) if m not in set(moved)]
        mine = await who(conn, moved, classifier, resolvers)
        kept = await who(conn, staying, classifier, resolvers)
        gone = {k for w in mine.values() for k in w.devices}
        left = {k for w in kept.values() for k in w.devices}
        actors = sorted(i for i in case.indicators if i.role == "actor")
        leaving = tuple(i for i in actors if (i.kind, i.value) in gone - left)
        shared = tuple(i for i in actors if (i.kind, i.value) in gone & left)
        outside = sorted(i for i in case.indicators if i.role != "actor")
        reached = await touched(conn, moved, outside)
        rows: dict[Key, Indicator] = {}
        for row in (
            *leaving,
            *shared,
            *(a for w in mine.values() for a in w.actors),
            *(i for i in outside if (i.kind, i.value) in reached),
        ):
            rows.setdefault((row.kind, row.value), row)
        return Carried(leaving, tuple(sorted(rows.values())), shared)

    return carry
