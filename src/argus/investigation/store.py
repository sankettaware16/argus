"""What the wave and "Check more" read from and write to Postgres: the investigation's
newest dossier, the rule's profile, the assessor's answer, the answers already stored, the queue
of requests (``investigation_checks``) and the new dossier a wave leaves.

Reads are bounded and take no lock. A request is claimed with a lease like an assessment is
(``FOR UPDATE SKIP LOCKED``); the wave's dossier and its signals are written in one transaction
under an advisory lock per investigation, which also numbers its round."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.types import BigInteger, DateTime, Text

from argus.assess.engine import NAME as ENGINE
from argus.context import store as context_store
from argus.context.evidence import COMPLETE
from argus.context.packs import WAVE_IDENT
from argus.db.audit import record_audit
from argus.investigation.gaps import Assessed, Profile
from argus.investigation.plan import Seen

LEASE = timedelta(minutes=10)
MAX_CLAIMS = 3
MAX_ROUNDS = 9  # wave dossiers of one investigation version
WAVE_LOCK = 0x45776176  # "Ewav": the advisory-lock class of one investigation's waves
OUTCOME_ITEMS = 12  # gaps and checks kept in a request's record
EPOCH = datetime(2000, 1, 1, tzinfo=UTC)
OWED_FOR = timedelta(hours=6)  # an engine wave queued longer ago than this no longer holds anyone


@dataclass(frozen=True)
class Current:
    """The newest dossier of an investigation at its current version."""

    investigation_id: uuid.UUID
    version: int
    pack: str
    dossier_hash: str
    body: Mapping[str, Any]
    created_at: datetime
    severity: str | None
    reviewed: bool


_CURRENT = """
SELECT d.version, d.pack, d.dossier_hash, d.body, d.created_at, i.severity,
       EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = i.id
               AND r.action = 'reviewed' AND r.version = i.version) AS reviewed
FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
WHERE d.investigation_id = :i ORDER BY d.created_at DESC, d.pack DESC LIMIT 1
"""


async def current(conn: AsyncConnection, investigation_id: uuid.UUID) -> Current | None:
    row = (await conn.execute(text(_CURRENT), {"i": investigation_id})).first()
    if row is None:
        return None
    return Current(investigation_id, int(row.version), str(row.pack), str(row.dossier_hash),
                   row.body, row.created_at, row.severity, bool(row.reviewed))  # fmt: skip


_UNDECIDED = """
SELECT n.investigation_id FROM (
  SELECT DISTINCT ON (d.investigation_id) d.investigation_id, d.version, d.dossier_hash,
         d.created_at
  FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
  ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC
) n
WHERE NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = n.investigation_id
                  AND r.action = 'reviewed' AND r.version = n.version)
  AND EXISTS (SELECT 1 FROM assessments a WHERE a.investigation_id = n.investigation_id
              AND a.version = n.version AND a.dossier_hash = n.dossier_hash
              AND a.assessor = :engine AND a.status = 'no_decision')
  AND CASE :mode
    WHEN 'new' THEN NOT EXISTS (SELECT 1 FROM investigation_checks c
                                WHERE c.investigation_id = n.investigation_id
                                AND c.version = n.version AND c.kind = 'wave'
                                AND c.source = 'engine')
    WHEN 'owed' THEN NOT EXISTS (SELECT 1 FROM investigation_checks c
                                 WHERE c.investigation_id = n.investigation_id
                                 AND c.version = n.version AND c.kind = 'wave'
                                 AND c.source = 'engine'
                                 AND (c.status NOT IN ('queued', 'running')
                                      OR c.requested_at < :since))
    ELSE EXISTS (SELECT 1 FROM investigation_checks c
                 WHERE c.investigation_id = n.investigation_id
                 AND c.version = n.version AND c.kind = 'wave' AND c.source = 'engine'
                 AND c.status IN ('queued', 'running') AND c.requested_at >= :since)
  END
ORDER BY n.created_at DESC, n.investigation_id
LIMIT :limit
"""


async def undecided(
    conn: AsyncConnection,
    limit: int,
    mode: Literal["new", "owed", "open"] = "new",
    since: datetime | None = None,
) -> list[uuid.UUID]:
    """Unreviewed investigations whose newest dossier the decision engine could not decide,
    newest first. ``new``: no engine wave has been queued for this version (the wave takes
    these). ``owed``: also those whose wave is queued or running (they are owed one until it
    ends), unless it has waited since before ``since``. ``open``: only those whose wave is
    queued or running, requested since ``since``."""
    rows = await conn.execute(
        text(_UNDECIDED).bindparams(bindparam("since", type_=DateTime(timezone=True))),
        {"engine": ENGINE, "limit": limit, "mode": mode, "since": since or EPOCH},
    )
    return [r[0] for r in rows]


_RULE = "SELECT type FROM rules WHERE rule_id = :r"
_NORMALIZED = """
SELECT a.normalized FROM investigation_alerts l JOIN alert_records a ON a.alert_id = l.alert_id
WHERE l.investigation_id = :i AND l.duplicate_of IS NULL AND a.normalized IS NOT NULL
  AND a.normalized ->> 'rule_type' IN ('threshold', 'esql')
ORDER BY a.detected_at DESC NULLS LAST, a.alert_id LIMIT 1
"""


async def profile_of(
    conn: AsyncConnection, investigation_id: uuid.UUID, body: Mapping[str, Any]
) -> tuple[Profile, Mapping[str, Any] | None]:
    """The rule's type and indices (the dossier's own, from its alerts) and the newest
    threshold or ES|QL alert (for the rows behind it). Never the rule's name."""
    facts = body.get("facts") or {}
    pack = (body.get("context") or {}).get("pack") or {}
    kind = await conn.scalar(text(_RULE), {"r": facts.get("rule_id")})
    normalized = (await conn.execute(text(_NORMALIZED), {"i": investigation_id})).scalar()
    if kind is None and isinstance(normalized, Mapping):
        kind = normalized.get("rule_type")
    indices = tuple(str(i) for i in pack.get("indices") or [])
    return Profile(None if kind is None else str(kind), indices), normalized


_ASSESSED = """
SELECT assessor, status, outcome, confidence, reasons FROM assessments
WHERE investigation_id = :i AND version = :v AND dossier_hash = :h
  AND status IN ('proposed', 'no_decision') ORDER BY id DESC LIMIT 8
"""
_REVIEWED = """
SELECT outcome FROM review_events WHERE investigation_id = :i AND version = :v
  AND action = 'reviewed' AND outcome IS NOT NULL ORDER BY id DESC LIMIT 1
"""


async def assessed_of(conn: AsyncConnection, current_: Current) -> Assessed | None:
    """A person's verdict on this version if there is one, else the newest assessor's answer
    about this dossier (the AI investigator's before the decision engine's)."""
    i = {"i": current_.investigation_id, "v": current_.version}
    outcome = (await conn.execute(text(_REVIEWED), i)).scalar()
    if outcome is not None:
        return Assessed(outcome=str(outcome), assessor="a reviewer", by_person=True)
    rows = (await conn.execute(text(_ASSESSED), {**i, "h": current_.dossier_hash})).all()
    if not rows:
        return None
    best = sorted(rows, key=lambda r: (not str(r.assessor).startswith("agent"),))[0]
    reasons = tuple(str(x)[:300] for x in (best.reasons or []) if not isinstance(x, Mapping))
    return Assessed(outcome=best.outcome, confidence=best.confidence, assessor=str(best.assessor),
                    reasons=reasons)  # fmt: skip


_DECIDED = """
SELECT EXISTS (SELECT 1 FROM assessments WHERE investigation_id = :i AND version = :v
               AND dossier_hash = :h AND assessor = :engine AND status = 'proposed')
"""


async def withdrawn(conn: AsyncConnection, current_: Current, version: int) -> str | None:
    """Why an engine wave queued for ``version`` should no longer run (plain words), or None:
    the wave is owed to an undecided, unreviewed investigation, and a queue keeps its requests
    for hours. A person reviewed it meanwhile, it has a newer version (that one gets its own
    wave), or the decision engine has since decided its dossier."""
    if current_.reviewed:
        return "a person has reviewed this investigation"
    if current_.version != version:
        return "the investigation has a newer version"
    decided = await conn.scalar(
        text(_DECIDED),
        {"i": current_.investigation_id, "v": version, "h": current_.dossier_hash,
         "engine": ENGINE},
    )  # fmt: skip
    return "the decision engine has decided it since" if decided else None


async def seen_of(
    conn: AsyncConnection, investigation_id: uuid.UUID, keys: Sequence[str]
) -> dict[str, Seen]:
    """The answer the investigation holds for each request (any version): a stored one that
    can be reused wins, else the newest failed attempt (so a retry can wait)."""
    if not keys:
        return {}
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (task_key) task_key, status, collected_at FROM evidence"
            " WHERE investigation_id = :i AND task_key = ANY(:k)"
            " AND NOT (status IN ('ok', 'empty') AND snapshot_purged_at IS NOT NULL)"
            " ORDER BY task_key, (status IN ('ok', 'empty')) DESC, version DESC"
        ),
        {"i": investigation_id, "k": list(keys)},
    )
    return {str(r.task_key): Seen(str(r.status), r.collected_at) for r in rows}


async def unanswered(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, name: str, limit: int = 5
) -> list[Any]:
    """The newest requests of template ``name`` the investigation asked at this version and got
    no usable answer to (rows: ``task_key``, ``template_version``, ``params``)."""
    rows = await conn.execute(
        text(
            "SELECT task_key, template_version, params FROM evidence"
            " WHERE investigation_id = :i AND version = :v AND template = :t"
            " AND status NOT IN ('ok', 'empty') ORDER BY collected_at DESC NULLS LAST, task_key"
            " LIMIT :n"
        ),
        {"i": investigation_id, "v": version, "t": name, "n": limit},
    )
    return list(rows)


async def refs_at(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, keys: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """References to the evidence rows stored at ``version`` for ``keys`` (the five batch-1
    templates' carry their parameters, which their readings need)."""
    from argus.context import batch1

    out: dict[str, dict[str, Any]] = {}
    for key in keys:
        row = await context_store.evidence_row(conn, investigation_id, version, key)
        if row is None:
            continue
        ref = context_store.ref_of(row, reused=row["reused_from_version"] is not None)
        if batch1.is_batch1(ref):
            ref["params"] = dict(row["params"] or {})
        out[key] = ref
    return out


# ----------------------------------------------------------------------------- the dossier


async def next_round(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, base: str
) -> int:
    """The round the next wave dossier of this version takes (1 after the base pack's own)."""
    rows = await conn.execute(
        text("SELECT pack FROM dossiers WHERE investigation_id = :i AND version = :v"),
        {"i": investigation_id, "v": version},
    )
    rounds = [0]
    for (pack,) in rows:
        m = WAVE_IDENT.match(str(pack))
        if m is not None and f"{m['name']}@{m['version']}" == base:
            rounds.append(int(m["round"]))
    return max(rounds) + 1


async def lock(conn: AsyncConnection, investigation_id: uuid.UUID) -> None:
    """One wave dossier writer per investigation at a time (until the transaction ends)."""
    await conn.execute(
        text("SELECT pg_advisory_xact_lock(:c, hashtext(:i))"),
        {"c": WAVE_LOCK, "i": str(investigation_id)},
    )


async def persist_dossier(
    conn: AsyncConnection,
    dossier: Mapping[str, Any],
    signals: Sequence[Mapping[str, Any]],
    now: datetime,
    details: Mapping[str, Any],
) -> bool:
    """Write a wave dossier and its signals, and audit it, in the caller's transaction.
    Returns False when a dossier with this ident and hash exists already (nothing written);
    the same ident with another hash is a bug (DossierConflict)."""
    inv = uuid.UUID(str(dossier["body"]["investigation_id"]))
    version = int(dossier["body"]["version"])
    inserted = (
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, facts_version, job_id, run_kind,"
                " family, pack, status, partial_reason, dossier_hash, body, evidence_count,"
                " created_at) VALUES (:inv, :v, :fv, 0, :kind, :family, :pack, :status, :reason,"
                " :hash, :body, :n, :now) ON CONFLICT (investigation_id, version, pack)"
                " DO NOTHING RETURNING 1"
            ).bindparams(bindparam("body", type_=JSONB)),
            {
                "inv": inv,
                "v": version,
                "fv": dossier["facts_version"],
                "kind": dossier["run_kind"],
                "family": dossier["family"],
                "pack": dossier["pack"],
                "status": dossier["status"],
                "reason": dossier["partial_reason"],
                "hash": dossier["hash"],
                "body": dossier["body"],
                "n": len(dossier["body"]["evidence"]),
                "now": now,
            },
        )
    ).first()
    if inserted is None:
        existing = (
            await conn.execute(
                text(
                    "SELECT dossier_hash FROM dossiers WHERE investigation_id = :inv"
                    " AND version = :v AND pack = :pack"
                ),
                {"inv": inv, "v": version, "pack": dossier["pack"]},
            )
        ).scalar_one()
        if existing != dossier["hash"]:
            raise context_store.DossierConflict(
                f"{inv} v{version} {dossier['pack']}: stored {existing[:12]},"
                f" new {dossier['hash'][:12]}"
            )
        return False
    if signals:
        await conn.execute(
            text(
                "INSERT INTO signals (investigation_id, version, pack, name, value, status,"
                " unknown_reason, completeness, evidence, definition_version)"
                " VALUES (:inv, :v, :pack, :name, :value, :status, :reason, :completeness,"
                " :evidence, :dv)"
            ).bindparams(bindparam("value", type_=JSONB), bindparam("evidence", type_=ARRAY(Text))),
            [
                {
                    "inv": inv, "v": version, "pack": dossier["pack"], "name": s["name"],
                    "value": s["value"], "status": s["status"], "reason": s["unknown_reason"],
                    "completeness": s["completeness"], "evidence": list(s["evidence"]),
                    "dv": s["definition_version"],
                }
                for s in signals
            ],
        )  # fmt: skip
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session, actor="investigation", action="dossier.wave", target_type="investigation",
            target_id=str(inv), details={"version": version, "pack": dossier["pack"],
                                         "hash": dossier["hash"][:16], **details},
        )  # fmt: skip
        await session.flush()
    finally:
        await session.close()
    return True


# ----------------------------------------------------------------------------- the queue


@dataclass(frozen=True)
class Request:
    id: int
    investigation_id: uuid.UUID
    version: int
    kind: str
    source: str
    template: str
    entity: str
    requested_by: str | None
    claims: int
    progress: Mapping[str, Any] = field(default_factory=dict)  # what earlier runs of it asked


def _request(r: Any) -> Request:
    progress = r.outcome.get("progress") if isinstance(r.outcome, Mapping) else None
    return Request(int(r.id), r.investigation_id, int(r.version), str(r.kind), str(r.source),
                   str(r.template), str(r.entity), r.requested_by, int(r.claims),
                   progress if isinstance(progress, Mapping) else {})  # fmt: skip


async def enqueue(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    kind: str,
    source: str,
    now: datetime,
    *,
    template: str = "",
    entity: str = "",
    requested_by: str | None = None,
) -> int | None:
    """Queue a wave or a check; None when the same one is already open, or (an engine wave)
    this version has had its wave."""
    values = {"i": investigation_id, "v": version, "k": kind, "s": source, "t": template,
              "e": entity, "by": requested_by, "now": now}  # fmt: skip
    if kind == "check" and source == "person":
        # a person's check names only what a person gives: the table's defaults are its kind, its
        # source and its status, and the web's login may insert no more than these columns, so
        # "Check more" works from the web as well as from the service
        statement = (
            "INSERT INTO investigation_checks (investigation_id, version, template, entity,"
            " requested_by, requested_at) VALUES (:i, :v, :t, :e, :by, :now)"
            " ON CONFLICT DO NOTHING RETURNING id"
        )
    else:
        statement = (
            "INSERT INTO investigation_checks (investigation_id, version, kind, source, template,"
            " entity, requested_by, requested_at, status) VALUES (:i, :v, :k, :s, :t, :e, :by,"
            " :now, 'queued') ON CONFLICT DO NOTHING RETURNING id"
        )
    row = await conn.execute(text(statement), values)
    found = row.first()
    return None if found is None else int(found[0])


async def claim(
    conn: AsyncConnection,
    owner: str,
    now: datetime,
    limit: int = 1,
    source: str | None = None,
    only: Sequence[int] | None = None,
) -> list[Request]:
    """Lease up to ``limit`` open requests, a person's first, then the oldest; a request whose
    workers died ``MAX_CLAIMS`` times is given up. ``source`` takes one source's requests,
    ``only`` just those ids (the command line claims the one it queued, never another
    person's). ``owner`` only names the claim in the audit."""
    await conn.execute(
        text(
            "UPDATE investigation_checks SET status = 'failed', finished_at = :now,"
            " lease_until = NULL, outcome = jsonb_build_object('error', 'the worker died "
            "while running it') WHERE status = 'running' AND lease_until < :now"
            " AND claims >= :max"
        ),
        {"now": now, "max": MAX_CLAIMS},
    )
    rows = await conn.execute(
        text(
            "UPDATE investigation_checks c SET status = 'running', lease_until = :until,"
            " claims = c.claims + 1, started_at = COALESCE(c.started_at, :now)"
            " WHERE c.id IN (SELECT id FROM investigation_checks WHERE"
            "  (status = 'queued' OR (status = 'running' AND lease_until < :now))"
            "  AND (CAST(:source AS text) IS NULL OR source = :source)"
            "  AND (CAST(:only AS bigint[]) IS NULL OR id = ANY(CAST(:only AS bigint[])))"
            "  ORDER BY (source = 'person') DESC, requested_at, id LIMIT :limit"
            "  FOR UPDATE SKIP LOCKED)"
            " RETURNING c.id, c.investigation_id, c.version, c.kind, c.source, c.template,"
            " c.entity, c.requested_by, c.claims, c.outcome"
        ).bindparams(bindparam("only", type_=ARRAY(BigInteger))),
        {"until": now + LEASE, "now": now, "limit": limit, "source": source,
         "only": None if only is None else list(only)},
    )  # fmt: skip
    return [_request(r) for r in sorted(rows.all(), key=lambda r: (r.source != "person", r.id))]


async def requeue(
    conn: AsyncConnection, request_id: int, now: datetime, progress: Mapping[str, Any] | None = None
) -> bool:
    """Put a running request back in the queue, as if it had never been claimed: the SIEM was
    not available (or the lane was busy) and nothing came of the run. It is no longer started
    (the day's cap counts started waves only) and its claim is given back. ``progress`` is
    what its earlier runs already asked (requests, heavy, server time), kept for the caps of
    the next run. False when it was not running."""
    row = await conn.execute(
        text(
            "UPDATE investigation_checks SET status = 'queued', lease_until = NULL,"
            " started_at = NULL, claims = GREATEST(claims - 1, 0), outcome = :o"
            " WHERE id = :id AND status = 'running' RETURNING id"
        ).bindparams(bindparam("o", type_=JSONB)),
        {"id": request_id, "o": None if progress is None else {"progress": dict(progress)}},
    )
    return row.first() is not None


async def finish(
    conn: AsyncConnection, request_id: int, status: str, outcome: Mapping[str, Any], now: datetime
) -> None:
    """End a running request with its record, and audit it: who asked, what kind, what it
    cost and which dossier it left (never the entity: the record holds it)."""
    if status not in ("done", "refused", "failed"):
        raise ValueError(f"{status!r} does not end a request")
    row = (
        await conn.execute(
            text(
                "UPDATE investigation_checks SET status = :s, finished_at = :now,"
                " lease_until = NULL, outcome = :o WHERE id = :id AND status = 'running'"
                " RETURNING investigation_id, kind, source, template, requested_by"
            ).bindparams(bindparam("o", type_=JSONB)),
            {"s": status, "now": now, "o": dict(outcome), "id": request_id},
        )
    ).first()
    if row is None:
        return
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session,
            actor=f"user:{row.requested_by}" if row.source == "person" else "investigation",
            action=f"investigation.{row.kind}",
            outcome="success" if status == "done" else "failure",
            target_type="investigation",
            target_id=str(row.investigation_id),
            details={
                "request": request_id,
                "template": row.template or None,
                "requests": outcome.get("requests"),
                "heavy": outcome.get("heavy"),
                "server_ms": outcome.get("server_ms"),
                "dossier": outcome.get("dossier"),
            },
        )
        await session.flush()
    finally:
        await session.close()


async def waves_today(conn: AsyncConnection, now: datetime) -> int:
    """Engine waves started today (UTC): the daily cap counts these. A wave that is only
    queued (or was put back) has not used any of the day, and a refused one never did."""
    return int(
        await conn.scalar(
            text(
                "SELECT count(*) FROM investigation_checks WHERE kind = 'wave'"
                " AND source = 'engine' AND status <> 'refused' AND started_at >= :day"
            ),
            {"day": _day(now)},
        )
        or 0
    )


async def started_today(conn: AsyncConnection, now: datetime) -> tuple[int, int]:
    """(a person's requests, the engine's) started today (UTC): the pass gives the engine a
    turn after three of a person's, so one account cannot keep the waves waiting."""
    row = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE source = 'person'),"
                " count(*) FILTER (WHERE source = 'engine') FROM investigation_checks"
                " WHERE status <> 'refused' AND started_at >= :day"
            ),
            {"day": _day(now)},
        )
    ).one()
    return int(row[0]), int(row[1])


def _day(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


async def open_requests(conn: AsyncConnection, requested_by: str) -> tuple[int, int]:
    """(this person's checks, all checks) queued or running."""
    row = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE requested_by = :by), count(*)"
                " FROM investigation_checks WHERE kind = 'check'"
                " AND status IN ('queued', 'running')"
            ),
            {"by": requested_by},
        )
    ).one()
    return int(row[0]), int(row[1])


async def checks_today(conn: AsyncConnection, requested_by: str) -> int:
    """The checks this person has asked for today (UTC, the server's clock)."""
    return int(
        await conn.scalar(
            text(
                "SELECT count(*) FROM investigation_checks WHERE kind = 'check'"
                " AND requested_by = :by AND created_at >="
                " date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
            ),
            {"by": requested_by},
        )
        or 0
    )


LIMIT_STATE = "AR001"  # the SQLSTATE of the table's own limit on checks


def limit_said(exc: DBAPIError) -> str | None:
    """The words of the table's refusal when ``exc`` is one (a person's limit on checks), else
    None."""
    orig = exc.orig
    if getattr(orig, "sqlstate", None) != LIMIT_STATE:
        return None
    diag = getattr(orig, "diag", None)
    said = getattr(diag, "message_primary", None)
    return said if isinstance(said, str) and said else "too many checks are waiting"


async def open_for(conn: AsyncConnection, investigation_id: uuid.UUID) -> bool:
    """Whether a request for this investigation is queued or running."""
    return bool(
        await conn.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM investigation_checks WHERE investigation_id = :i"
                " AND status IN ('queued', 'running'))"
            ),
            {"i": investigation_id},
        )
    )


def complete(status: str) -> bool:
    return status in COMPLETE
