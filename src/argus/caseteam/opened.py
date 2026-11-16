"""A case the case team opened in Kibana no longer waits for Kibana (D-322).

A case ARGUS could not open in Kibana itself (no person who may was at hand) keeps
``cases.kibana_wait`` ("Waiting for someone who may open cases in Kibana") until a person opens it
(``Publish``). The case team (write class WC, D-214) opens such a case as its own users and records
the Kibana case it read back in ``case_team_posts``, which its login may write; ``cases`` is the
runtime's, changed only through the case service. So the runtime looks after each complete Kibana
sync cycle for a case whose post has its Kibana case and that still waits, and records the team's
case on it (``TeamOpened``: a ``published`` event that clears the wait). The look is idempotent: a
case it missed (a refused command, a stopped service) is taken at the next one."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import CaseRefused, TeamOpened
from argus.cases.model import Actor
from argus.cases.service import CaseService

log = logging.getLogger("argus.caseteam")

ACTOR = Actor.argus("caseteam")  # ARGUS acts as ``argus:caseteam``
PER_LOOK = 50  # cases recorded in one look; the rest at the next

_WAITING = text(
    "SELECT c.id, c.number, p.incident_id, p.kibana_case_id FROM cases c"
    " JOIN case_team_posts p ON p.case_id = c.id"
    " WHERE c.kibana_wait IS NOT NULL AND p.kibana_case_id IS NOT NULL"
    " ORDER BY c.number LIMIT :n"
)


@dataclass
class Cleared:
    recorded: list[int] = field(default_factory=list)  # case numbers
    skipped: list[str] = field(default_factory=list)

    def lines(self) -> list[str]:
        out = []
        if self.recorded:
            shown = ", ".join(str(n) for n in self.recorded)
            out.append(f"case team: recorded its Kibana case on case(s) {shown}")
        out += [f"case team: {why}" for why in self.skipped]
        return out


async def clear_waits(engine: AsyncEngine, *, limit: int = PER_LOOK) -> Cleared:
    """Record the case team's Kibana case on each case that still waits for Kibana, each in its
    own transaction (one refused case never holds back the others)."""
    done = Cleared()
    async with engine.connect() as conn:
        rows = (await conn.execute(_WAITING, {"n": limit})).all()
    for row in rows:
        command = TeamOpened(str(row.incident_id), str(row.kibana_case_id))
        try:
            async with engine.begin() as conn:
                service = await CaseService.start(conn)
                await service.apply(ACTOR, uuid.UUID(str(row.id)), command, expected_version=None)
        except CaseRefused as exc:  # it stopped waiting meanwhile
            done.skipped.append(f"case {row.number}: {exc.message}")
            continue
        except DBAPIError as exc:
            state = getattr(exc.orig, "sqlstate", None)
            done.skipped.append(f"case {row.number}: refused by the database ({state})")
            continue
        done.recorded.append(int(row.number))
    return done
