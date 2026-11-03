"""Running assessments (P3, D-084): find what needs one, run an assessor, store the result.

An ``Assessor`` reads a dossier body and returns a ``Verdict``: a proposal, no decision, or
``Defer`` (raised: try again later, e.g. a model's budget). ``schedule`` queues the current
dossier view of every unreviewed investigation an assessor has not seen; ``run_once`` claims
and assesses a batch. The view hash is the hash of what the privacy layer renders (P1): the
same text a model would read, so a re-derivation that changes nothing visible is not
assessed again.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assess import queue
from argus.llm.privacy import Privacy


@dataclass(frozen=True)
class Verdict:
    outcome: str | None  # None: no decision
    decided_by: str
    reasons: list[Any] = field(default_factory=list)
    confidence: float | None = None


class Defer(Exception):  # noqa: N818 - control flow, not an error
    """Try this assessment again at ``until``."""

    def __init__(self, until: datetime, why: str = "") -> None:
        super().__init__(why)
        self.until = until


class Assessor(Protocol):
    name: str

    async def assess(
        self, conn: AsyncConnection, investigation_id: uuid.UUID, body: Mapping[str, Any]
    ) -> Verdict: ...


def view_hash(privacy: Privacy, body: Mapping[str, Any]) -> str:
    return hashlib.sha256(privacy.request([body]).text.encode("utf-8")).hexdigest()


_DUE = """
SELECT n.investigation_id, n.version, n.pack, n.dossier_hash, n.body FROM (
  SELECT DISTINCT ON (d.investigation_id) d.investigation_id, d.version, d.pack,
         d.dossier_hash, d.body, d.created_at
  FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
  ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC
) n  -- each investigation's newest dossier first, then whether it still needs an assessment
WHERE NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = n.investigation_id
                  AND r.action = 'reviewed' AND r.version = n.version)
  AND NOT EXISTS (SELECT 1 FROM assessments a WHERE a.investigation_id = n.investigation_id
                  AND a.version = n.version AND a.dossier_hash = n.dossier_hash
                  AND a.assessor = :assessor)
  AND (CAST(:after AS text) IS NULL OR EXISTS (
       SELECT 1 FROM assessments e WHERE e.investigation_id = n.investigation_id
       AND e.version = n.version AND e.dossier_hash = n.dossier_hash
       AND e.assessor = :after AND e.status = 'no_decision'))
  AND NOT (n.investigation_id = ANY(:skip))
ORDER BY n.created_at DESC, n.investigation_id
LIMIT :limit
"""
_TODAY = """
SELECT count(*) FROM assessments
WHERE assessor = :assessor AND created_at >= date_trunc('day', CAST(:now AS timestamptz))
"""


async def schedule(
    conn: AsyncConnection,
    privacy: Privacy,
    assessor: str,
    now: datetime,
    limit: int = 500,
    after: str | None = None,
    per_day: int | None = None,
    skip: Collection[uuid.UUID] = (),
) -> int:
    """Queue the current dossier view of unreviewed investigations ``assessor`` has not
    seen, newest first (an unchanged dossier is skipped before rendering; an unchanged view
    after). With ``after``, only where that assessor found no decision on the same dossier;
    with ``per_day``, at most that many queued per UTC day; never an investigation in
    ``skip`` (the deterministic wave still owes it its checks, Q-F3)."""
    if per_day is not None:
        today = await conn.scalar(text(_TODAY), {"assessor": assessor, "now": now})
        limit = min(limit, per_day - int(today or 0))
        if limit <= 0:
            return 0
    rows = (
        await conn.execute(
            text(_DUE).bindparams(bindparam("skip", type_=ARRAY(UUID))),
            {"assessor": assessor, "limit": limit, "after": after, "skip": list(skip)},
        )
    ).all()
    added = 0
    for investigation_id, version, pack, dossier_hash, body in rows:
        added += await queue.enqueue(
            conn, investigation_id, version, pack, dossier_hash,
            view_hash(privacy, body), assessor, now,
        )  # fmt: skip
    return added


_NEWEST = """
SELECT d.version, d.pack, d.dossier_hash, d.body FROM dossiers d
JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
WHERE d.investigation_id = :i ORDER BY d.created_at DESC, d.pack DESC LIMIT 1
"""


async def request(
    conn: AsyncConnection, privacy: Privacy, investigation_id: uuid.UUID, assessor: str,
    now: datetime,
) -> str:  # fmt: skip
    """A person asks for an assessment of one investigation now, reviewed or not (D-095):
    "queued", "exists" (this view has one already), "no dossier", or "refused" when the
    assessor is the investigation agent and its file does not take a person's request (Q-H1:
    whatever route the request came by)."""
    from argus.agent import loader
    from argus.agent.agent import NAME as AGENT
    from argus.agent.registry import Trigger

    if assessor == AGENT and not loader.allows(Trigger.PERSON_REQUEST):
        return "refused"
    row = (await conn.execute(text(_NEWEST), {"i": investigation_id})).first()
    if row is None:
        return "no dossier"
    version, pack, dossier_hash, body = row
    shown = view_hash(privacy, body)
    added = await queue.enqueue(conn, investigation_id, version, pack, dossier_hash, shown,
                                assessor, now, even_reviewed=True, priority=1)  # fmt: skip
    return "queued" if added else "exists"


async def run_once(
    engine: AsyncEngine,
    assessor: Assessor,
    owner: str,
    clock: Callable[[], datetime],
    limit: int = 10,
) -> dict[str, int]:
    """Claim up to ``limit`` and assess each. The body is read, the assessment made and its
    result written in separate transactions: no transaction stays open while an assessor
    waits (a model, the SIEM); the write is fenced by the claim. An assessor may ask for a
    longer lease (``lease``)."""
    lease = getattr(assessor, "lease", queue.LEASE)
    async with engine.begin() as conn:
        claims = await queue.claim(conn, owner, clock(), assessor.name, limit, lease)
    counts = {"proposed": 0, "no_decision": 0, "deferred": 0, "failed": 0, "lost": 0}
    for job in claims:
        try:
            async with engine.connect() as conn:
                body = await conn.scalar(
                    text(
                        "SELECT body FROM dossiers WHERE investigation_id = :i AND version = :v"
                        " AND pack = :p AND dossier_hash = :h"
                    ),
                    {"i": job.investigation_id, "v": job.version, "p": job.pack,
                     "h": job.dossier_hash},
                )  # fmt: skip
            if body is None:
                async with engine.begin() as conn:
                    await queue.no_decision(conn, job, clock(), assessor.name,
                                            ["the dossier is gone"])  # fmt: skip
                counts["no_decision"] += 1
                continue
            async with engine.connect() as conn:
                verdict = await assessor.assess(conn, job.investigation_id, body)
            async with engine.begin() as conn:
                if verdict.outcome is None:
                    await queue.no_decision(conn, job, clock(), verdict.decided_by,
                                            verdict.reasons)  # fmt: skip
                    counts["no_decision"] += 1
                else:
                    await queue.propose(conn, job, clock(), verdict.outcome, verdict.decided_by,
                                        verdict.reasons, verdict.confidence)  # fmt: skip
                    counts["proposed"] += 1
        except queue.LeaseLostError:
            counts["lost"] += 1
        except Defer as wait:
            async with engine.begin() as conn:
                await _settle(conn, queue.defer(conn, job, clock(), wait.until, str(wait)),
                              counts, "deferred")  # fmt: skip
        except Exception as exc:  # one assessment's failure is recorded, never fatal
            async with engine.begin() as conn:
                await _settle(conn, queue.fail(conn, job, clock(), type(exc).__name__),
                              counts, "failed")  # fmt: skip
    return counts


async def _settle(
    conn: AsyncConnection, step: Awaitable[Any], counts: dict[str, int], key: str
) -> None:
    try:
        await step
        counts[key] += 1
    except queue.LeaseLostError:
        counts["lost"] += 1
