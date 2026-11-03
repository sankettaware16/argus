"""The durable job queue: at most one active job per investigation, claims are leases, and only
the current claim may finish a job.

A worker ``claim``s jobs (``FOR UPDATE SKIP LOCKED``), does the work, and calls ``complete`` **in
the transaction that writes the work's effect**: if its lease was lost meanwhile, ``complete``
raises LeaseLostError and the effect rolls back. A job whose investigation changed while it ran is
queued again; a failed one is retried with backoff; a job deferred by an unavailable SIEM or
Postgres is queued again with growing waits, without counting a failure.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

LEASE = timedelta(minutes=10)
COALESCE = timedelta(minutes=30)  # a changed investigation runs again at most this often
MAX_FAILURES = 5
BACKOFF = timedelta(minutes=2)  # doubled per failure
DEFER_STEP = timedelta(minutes=1)  # doubled per deferral, at most DEFER_MAX
DEFER_MAX = timedelta(minutes=10)
MAX_LOST = 10  # leases that expired while running (its worker died): then it is given up


class LeaseLostError(Exception):
    """The claim this worker holds is no longer the job's current claim."""


@dataclass(frozen=True)
class Claim:
    job_id: int
    investigation_id: uuid.UUID
    version: int  # the investigation's version when claimed: the effect's key
    claim: int  # fencing number: the job's claims count at this claim
    owner: str
    deferred_since: datetime | None = None
    trigger: str = "created"


async def claim(
    conn: AsyncConnection, owner: str, now: datetime, limit: int = 1, lease: timedelta = LEASE
) -> list[Claim]:
    """Claim up to ``limit`` due jobs: queued ones whose time has come, and running ones whose
    lease expired (their worker died). A job whose workers died MAX_LOST times while running
    it (it may be what kills them) is given up instead: every claim that did not end in a
    failure or a deferral ended that way."""
    await conn.execute(
        text(
            "UPDATE jobs SET status = 'failed', finished_at = :now, lease_until = NULL,"
            " error = 'gave up: the worker died ' || (claims - failures - deferrals)"
            " || ' times while running it' WHERE status = 'running' AND lease_until < :now"
            " AND claims - failures - deferrals >= :lost"
        ),
        {"now": now, "lost": MAX_LOST},
    )
    rows = await conn.execute(
        text(
            "UPDATE jobs j SET status = 'running', lease_owner = :owner,"
            " lease_until = :until, claims = j.claims + 1, claimed_version = i.version"
            " FROM investigations i"
            " WHERE i.id = j.investigation_id AND j.id IN ("
            "  SELECT id FROM jobs WHERE (status = 'queued' AND run_after <= :now)"
            "  OR (status = 'running' AND lease_until < :now)"
            "  ORDER BY run_after, id LIMIT :limit FOR UPDATE SKIP LOCKED)"
            " RETURNING j.id, j.investigation_id, j.claimed_version, j.claims,"
            " j.deferred_since, j.trigger"
        ),
        {"owner": owner, "until": now + lease, "now": now, "limit": limit},
    )
    return [
        Claim(job_id, investigation, version, claims, owner, deferred, trigger)
        for job_id, investigation, version, claims, deferred, trigger in sorted(
            rows.all(), key=lambda row: row[0]
        )
    ]


async def _current(conn: AsyncConnection, job: Claim, now: datetime) -> None:
    """Lock the job and check that ``job`` is still its live claim."""
    row = await conn.execute(
        text(
            "SELECT 1 FROM jobs WHERE id = :id AND status = 'running' AND lease_owner = :owner"
            " AND claims = :claim AND lease_until >= :now FOR UPDATE"
        ),
        {"id": job.job_id, "owner": job.owner, "claim": job.claim, "now": now},
    )
    if row.first() is None:
        raise LeaseLostError(f"job {job.job_id}: claim {job.claim} is no longer current")


async def renew(conn: AsyncConnection, job: Claim, now: datetime, lease: timedelta = LEASE) -> None:
    await _current(conn, job, now)
    await conn.execute(
        text("UPDATE jobs SET lease_until = :until WHERE id = :id"),
        {"id": job.job_id, "until": now + lease},
    )


async def complete(conn: AsyncConnection, job: Claim, now: datetime) -> bool:
    """Finish ``job`` (call it in the transaction that writes the effect). Returns True if
    the investigation changed meanwhile and a new job was queued."""
    await _current(conn, job, now)
    await conn.execute(
        text(
            "UPDATE jobs SET status = 'done', finished_at = :now, lease_until = NULL WHERE id = :id"
        ),
        {"id": job.job_id, "now": now},
    )
    again = await conn.execute(
        text(
            "INSERT INTO jobs (investigation_id, trigger, run_after)"
            " SELECT i.id, 'changed_while_running', CAST(:after AS timestamptz)"
            " FROM investigations i WHERE i.id = :inv AND i.version > :version"
            " ON CONFLICT (investigation_id) WHERE status IN ('queued', 'running') DO NOTHING"
            " RETURNING id"
        ),
        {"inv": job.investigation_id, "version": job.version, "after": now + COALESCE},
    )
    return again.first() is not None


async def skip(conn: AsyncConnection, job: Claim, now: datetime, reason: str) -> None:
    """Finished without running: what the work would read is gone (the retention purge),
    so the investigation keeps what it has. The job is done, with the reason kept for a human;
    nothing is queued again."""
    await _current(conn, job, now)
    await conn.execute(
        text(
            "UPDATE jobs SET status = 'done', finished_at = :now, lease_until = NULL,"
            " error = :reason WHERE id = :id"
        ),
        {"id": job.job_id, "now": now, "reason": reason[:500]},
    )


async def fail(conn: AsyncConnection, job: Claim, now: datetime, error: str) -> str:
    """The work failed: retry later (backoff), or give up after MAX_FAILURES. Returns the
    job's new status."""
    await _current(conn, job, now)
    row = await conn.execute(
        text(
            "UPDATE jobs SET failures = failures + 1, error = :error, lease_until = NULL,"
            " status = CASE WHEN failures + 1 >= :max THEN 'failed' ELSE 'queued' END,"
            " run_after = :now + :backoff * power(2, failures),"
            " finished_at = CASE WHEN failures + 1 >= :max THEN CAST(:now AS timestamptz) END"
            " WHERE id = :id RETURNING status"
        ),
        {
            "id": job.job_id,
            "error": error[:500],
            "max": MAX_FAILURES,
            "now": now,
            "backoff": BACKOFF,
        },
    )
    status: str = row.scalar_one()
    return status


async def defer(conn: AsyncConnection, job: Claim, now: datetime, reason: str) -> datetime:
    """Not now: the SIEM or Postgres is unavailable. Queued again after 1, 2, 4, 8, then every
    10 minutes, without counting a failure; ``deferred_since`` keeps the first time. Returns
    when it runs next."""
    await _current(conn, job, now)
    row = await conn.execute(
        text(
            "UPDATE jobs SET status = 'queued', lease_until = NULL, error = :reason,"
            " deferred_since = COALESCE(deferred_since, CAST(:now AS timestamptz)),"
            " run_after = :now + LEAST(:step * power(2, LEAST(deferrals, 4)), :most),"
            " deferrals = deferrals + 1 WHERE id = :id RETURNING run_after"
        ),
        {
            "id": job.job_id,
            "reason": f"deferred: {reason}"[:500],
            "now": now,
            "step": DEFER_STEP,
            "most": DEFER_MAX,
        },
    )
    after: datetime = row.scalar_one()
    return after


async def dead_letter(conn: AsyncConnection, job: Claim, now: datetime, error: str) -> None:
    """A defect, not bad luck (a refused template, a recursion error, a non-deterministic
    dossier): no retries, the job is failed at once and its error kept for a human."""
    await _current(conn, job, now)
    await conn.execute(
        text(
            "UPDATE jobs SET status = 'failed', failures = failures + 1, error = :error,"
            " lease_until = NULL, finished_at = :now WHERE id = :id"
        ),
        {"id": job.job_id, "error": f"bug: {error}"[:500], "now": now},
    )
