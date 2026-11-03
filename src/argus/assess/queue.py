"""The assessment queue (P3; plan §3, §5.4, D-084): one row per (investigation, view,
assessor) is both the work and its result.

- ``enqueue`` adds a row for an unreviewed investigation's current dossier view, once: the
  view's hash is the key, so a re-derivation that changes nothing an assessor reads is never
  assessed again, and a reviewed investigation is never queued.
- ``claim`` leases due rows (``FOR UPDATE SKIP LOCKED``; expired leases are claimed again;
  a row whose workers died ``MAX_LOST`` times is given up). The claim count fences: only the
  current claim may finish (``LeaseLostError`` otherwise, and the effect rolls back with
  the transaction).
- ``propose`` / ``no_decision`` finish a claim; ``fail`` retries with backoff, then gives
  up; ``defer`` (a model's budget or provider cooling down) gives the lease back without
  counting a failure: no lease is held while waiting (plan §3 P3).
- ``current`` is the newest finished assessment of an investigation at its current
  version; ``accept`` records a person's review of it as a *confirmed proposal* (plan
  §2.8), fenced: a stale assessment cannot be accepted (``AssessmentConflict``).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.db.models import OUTCOMES

LEASE = timedelta(minutes=5)
MAX_FAILURES = 5
BACKOFF = timedelta(minutes=2)  # doubled per failure
MAX_LOST = 10


class LeaseLostError(Exception):
    """This worker's claim is no longer the row's current claim."""


class AssessmentConflict(Exception):  # noqa: N818 - the plan's name, like DossierConflict
    """The assessment is not the investigation's current one (it changed, or was reviewed)."""


@dataclass(frozen=True)
class Claim:
    assessment_id: int
    investigation_id: uuid.UUID
    version: int
    pack: str
    dossier_hash: str
    view_hash: str
    assessor: str
    claim: int
    owner: str


@dataclass(frozen=True)
class Current:
    assessment_id: int
    version: int
    assessor: str
    status: str
    outcome: str | None
    confidence: float | None
    decided_by: str | None
    reasons: list[Any]
    finished_at: datetime | None


async def enqueue(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    pack: str,
    dossier_hash: str,
    view_hash: str,
    assessor: str,
    now: datetime,
    even_reviewed: bool = False,
    priority: int = 0,
) -> bool:
    """Queue an assessment of this view, unless it exists or the investigation has moved on,
    or is reviewed (``even_reviewed``: a person asked for it, D-095). ``priority`` 1 (a
    person's request, D-097) is claimed before anything else waiting, deferred or not.
    Returns whether a row was added."""
    row = await conn.execute(
        text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, run_after, priority)"
            " SELECT i.id, :v, :p, :h, :vh, :a, :now, :pr FROM investigations i"
            " WHERE i.id = :i AND i.version = :v AND (CAST(:er AS boolean) OR NOT EXISTS ("
            "  SELECT 1 FROM review_events r WHERE r.investigation_id = i.id"
            "  AND r.action = 'reviewed' AND r.version = i.version))"
            " ON CONFLICT (investigation_id, view_hash, assessor) DO NOTHING RETURNING id"
        ),
        {"i": investigation_id, "v": version, "p": pack, "h": dossier_hash, "vh": view_hash,
         "a": assessor, "now": now, "er": even_reviewed, "pr": priority},
    )  # fmt: skip
    return row.first() is not None


async def claim(
    conn: AsyncConnection,
    owner: str,
    now: datetime,
    assessor: str | None = None,
    limit: int = 1,
    lease: timedelta = LEASE,
) -> list[Claim]:
    """Lease up to ``limit`` due rows (of one assessor, if given)."""
    await conn.execute(
        text(
            "UPDATE assessments SET status = 'failed', finished_at = :now, lease_until = NULL,"
            " error = 'gave up: the worker died ' || (claims - failures - deferrals)"
            " || ' times while running it' WHERE status = 'running' AND lease_until < :now"
            " AND claims - failures - deferrals >= :lost"
        ),
        {"now": now, "lost": MAX_LOST},
    )
    rows = await conn.execute(
        text(
            "UPDATE assessments a SET status = 'running', lease_owner = :owner,"
            " lease_until = :until, claims = a.claims + 1"
            " WHERE a.id IN (SELECT id FROM assessments WHERE"
            "  ((status = 'queued' AND run_after <= :now) OR"
            "   (status = 'running' AND lease_until < :now))"
            "  AND (CAST(:assessor AS text) IS NULL OR assessor = :assessor)"
            "  ORDER BY priority DESC, run_after, id LIMIT :limit FOR UPDATE SKIP LOCKED)"
            " RETURNING a.id, a.investigation_id, a.version, a.pack, a.dossier_hash,"
            " a.view_hash, a.assessor, a.claims"
        ),
        {"owner": owner, "until": now + lease, "now": now, "limit": limit, "assessor": assessor},
    )
    return [
        Claim(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], owner)
        for r in sorted(rows.all(), key=lambda r: r[0])
    ]


async def _current_claim(conn: AsyncConnection, job: Claim, now: datetime) -> None:
    row = await conn.execute(
        text(
            "SELECT 1 FROM assessments WHERE id = :id AND status = 'running'"
            " AND lease_owner = :owner AND claims = :claim AND lease_until >= :now FOR UPDATE"
        ),
        {"id": job.assessment_id, "owner": job.owner, "claim": job.claim, "now": now},
    )
    if row.first() is None:
        raise LeaseLostError(f"assessment {job.assessment_id}: claim {job.claim} is not current")


async def propose(
    conn: AsyncConnection,
    job: Claim,
    now: datetime,
    outcome: str,
    decided_by: str,
    reasons: list[Any],
    confidence: float | None = None,
) -> None:
    """Finish ``job`` with a proposal (in the transaction that writes anything else of it)."""
    if outcome not in OUTCOMES:
        raise ValueError(f"not an outcome: {outcome!r}")
    await _current_claim(conn, job, now)
    await conn.execute(
        text(
            "UPDATE assessments SET status = 'proposed', outcome = :o, confidence = :c,"
            " decided_by = :d, reasons = CAST(:r AS jsonb), finished_at = :now,"
            " lease_until = NULL, error = NULL WHERE id = :id"
        ),
        {"id": job.assessment_id, "o": outcome, "c": confidence, "d": decided_by,
         "r": json.dumps(reasons), "now": now},
    )  # fmt: skip


async def no_decision(
    conn: AsyncConnection, job: Claim, now: datetime, decided_by: str, reasons: list[Any]
) -> None:
    """Finish ``job`` without a proposal: the assessor cannot decide (a person, or the next
    assessor, does)."""
    await _current_claim(conn, job, now)
    await conn.execute(
        text(
            "UPDATE assessments SET status = 'no_decision', decided_by = :d,"
            " reasons = CAST(:r AS jsonb), finished_at = :now, lease_until = NULL, error = NULL"
            " WHERE id = :id"
        ),
        {"id": job.assessment_id, "d": decided_by, "r": json.dumps(reasons), "now": now},
    )


async def fail(conn: AsyncConnection, job: Claim, now: datetime, error: str) -> str:
    """Retry later (backoff), or give up after MAX_FAILURES; returns the new status."""
    await _current_claim(conn, job, now)
    row = await conn.execute(
        text(
            "UPDATE assessments SET failures = failures + 1, error = :e, lease_until = NULL,"
            " status = CASE WHEN failures + 1 >= :max THEN 'failed' ELSE 'queued' END,"
            " run_after = :now + :backoff * power(2, failures),"
            " finished_at = CASE WHEN failures + 1 >= :max THEN CAST(:now AS timestamptz) END"
            " WHERE id = :id RETURNING status"
        ),
        {"id": job.assessment_id, "e": error[:500], "max": MAX_FAILURES, "now": now,
         "backoff": BACKOFF},
    )  # fmt: skip
    return str(row.scalar_one())


MAX_DEFER = timedelta(hours=1)


async def defer(
    conn: AsyncConnection, job: Claim, now: datetime, until: datetime, why: str = ""
) -> None:
    """Give the lease back until ``until`` (a budget or a provider cooling down): no failure
    is counted and no lease is held while waiting. The wait is at most MAX_DEFER: what
    blocked a call can clear long before the time given (another provider's quota, a
    reservation settled lower), and one deferral must not park an item for days (D-106).
    The reason is kept in ``error`` (cleared when the assessment finishes)."""
    await _current_claim(conn, job, now)
    await conn.execute(
        text(
            "UPDATE assessments SET status = 'queued', run_after = :until, lease_until = NULL,"
            " deferrals = deferrals + 1, error = :why WHERE id = :id"
        ),
        {"id": job.assessment_id, "until": min(max(until, now), now + MAX_DEFER),
         "why": f"deferred: {why}"[:500] if why else None},
    )  # fmt: skip


async def current(
    conn: AsyncConnection, investigation_id: uuid.UUID, assessor: str | None = None
) -> Current | None:
    """The newest finished assessment at the investigation's current version (a stale one,
    of an older version, is never shown as current)."""
    row = await conn.execute(
        text(
            "SELECT a.id, a.version, a.assessor, a.status, a.outcome, a.confidence,"
            " a.decided_by, a.reasons, a.finished_at FROM assessments a"
            " JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version"
            " WHERE a.investigation_id = :i AND a.status IN ('proposed', 'no_decision')"
            " AND (CAST(:a AS text) IS NULL OR a.assessor = :a)"
            " ORDER BY (a.status = 'proposed') DESC, a.id DESC LIMIT 1"
        ),
        {"i": investigation_id, "a": assessor},
    )
    found = row.first()
    if found is None:
        return None
    return Current(found[0], found[1], found[2], found[3], found[4], found[5], found[6],
                   list(found[7] or []), found[8])  # fmt: skip


async def accept(
    conn: AsyncConnection,
    assessment_id: int,
    user_id: int,
    note: str | None = None,
    *,
    kibana_ok: bool = False,
) -> None:
    """A person accepts a proposal: a review with its outcome, marked as a confirmed proposal
    (``review_events.assessment_id``). Refused unless it is still the investigation's current
    proposal and the investigation is not reviewed at this version."""
    row = await conn.execute(
        text(
            "SELECT a.investigation_id, a.version, a.outcome, i.alert_count FROM assessments a"
            " JOIN investigations i ON i.id = a.investigation_id"
            " WHERE a.id = :id AND a.status = 'proposed' AND i.version = a.version"
            " FOR UPDATE OF i"
        ),
        {"id": assessment_id},
    )
    found = row.first()
    if found is None:
        raise AssessmentConflict("the investigation changed or the proposal is not current")
    investigation_id, version, outcome, alerts = found
    newest = await current(conn, investigation_id)
    reviewed = await conn.scalar(
        text(
            "SELECT count(*) FROM review_events WHERE investigation_id = :i"
            " AND action = 'reviewed' AND version = :v"
        ),
        {"i": investigation_id, "v": version},
    )
    if newest is None or newest.assessment_id != assessment_id or reviewed:
        raise AssessmentConflict("a newer assessment exists or it is already reviewed")
    await conn.execute(
        text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
            " outcome, note, assessment_id, kibana_ok)"
            " VALUES (:i, :v, :n, :u, 'reviewed', :o, :note, :a, :ok)"
        ),
        {"i": investigation_id, "v": version, "n": alerts, "u": user_id, "o": outcome,
         "note": note, "a": assessment_id, "ok": kibana_ok},
    )  # fmt: skip


async def requeue(conn: AsyncConnection, assessor: str, stamp: str, now: datetime) -> int:
    """Queue again the finished assessments of ``assessor`` not decided under ``stamp`` (what
    it learned changed: a new label can open or close a key, plan §5.3), for investigations
    still unreviewed at that version. Returns how many."""
    rows = await conn.execute(
        text(
            "UPDATE assessments a SET status = 'queued', run_after = :now, outcome = NULL,"
            " confidence = NULL, decided_by = NULL, reasons = NULL, finished_at = NULL"
            " FROM investigations i WHERE i.id = a.investigation_id AND i.version = a.version"
            " AND a.assessor = :a AND a.status IN ('proposed', 'no_decision')"
            " AND a.decided_by IS DISTINCT FROM :stamp AND NOT starts_with(a.decided_by, :prefix)"
            " AND NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = i.id"
            "  AND r.action = 'reviewed' AND r.version = i.version)"
            " RETURNING a.id"
        ),
        {"now": now, "a": assessor, "stamp": stamp, "prefix": stamp + ":"},
    )
    return len(rows.all())
