"""What the context graph reads from and writes to Postgres.

Reads are bounded (a digest, never every alert); every write is idempotent: evidence is
keyed by (investigation, version, task key) and an ``ok``/``empty`` row is never replaced; a
dossier is written once per (investigation, version) with its signals, and only with the
job's fenced completion.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.types import Text

from argus.db.audit import record_audit
from argus.jobs import queue

SAMPLE_ALERTS = 10
ENTITY_SAMPLE = 20
VALUE_CHARS = 256
RELATED = 20
SUPERNODE = 200  # an entity in more investigations relates nothing
# The advisory-lock class (two-key form) under which one investigation's E-ids are numbered.
REQUEST_LOCK = 0x45726571  # "Ereq"


class MissingInvestigation(Exception):  # noqa: N818
    pass


class DossierConflict(Exception):  # noqa: N818
    """A dossier for this investigation version exists with another hash: the run was not
    deterministic. Never overwritten."""


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _cap(value: str | None, chars: int = VALUE_CHARS) -> str | None:
    return None if value is None else value[:chars]


async def load_facts(conn: AsyncConnection, investigation_id: uuid.UUID) -> dict[str, Any]:
    """The bounded facts digest of an investigation as stored now."""
    row = (
        await conn.execute(
            text(
                "SELECT rule_id, rule_name, group_key, bucket_start, bucket_end, alert_count,"
                " duplicate_count, first_event_at, last_event_at, severity, risk_score, version,"
                " continues_id FROM investigations WHERE id = :id"
            ),
            {"id": investigation_id},
        )
    ).first()
    if row is None:
        raise MissingInvestigation(str(investigation_id))
    late = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE late_arrival) FROM investigation_alerts"
                " WHERE investigation_id = :id"
            ),
            {"id": investigation_id},
        )
    ).scalar_one()
    samples = (
        await conn.execute(
            text(
                "SELECT a.alert_id FROM investigation_alerts l"
                " JOIN alert_records a ON a.alert_id = l.alert_id"
                " WHERE l.investigation_id = :id AND l.duplicate_of IS NULL"
                " ORDER BY a.event_time NULLS LAST, a.alert_id LIMIT :n"
            ),
            {"id": investigation_id, "n": SAMPLE_ALERTS},
        )
    ).scalars()
    counts = (
        await conn.execute(
            text(
                "SELECT kind, count(*) FROM investigation_entities WHERE investigation_id = :id"
                " GROUP BY kind ORDER BY kind"
            ),
            {"id": investigation_id},
        )
    ).all()
    sampled = (
        await conn.execute(
            text(
                "SELECT kind, value FROM (SELECT kind, value, row_number() OVER"
                " (PARTITION BY kind ORDER BY value) AS n FROM investigation_entities"
                " WHERE investigation_id = :id) s WHERE n <= :n ORDER BY kind, value"
            ),
            {"id": investigation_id, "n": ENTITY_SAMPLE},
        )
    ).all()
    entities: dict[str, list[str]] = {}
    for kind, value in sampled:
        entities.setdefault(kind, []).append(_cap(value) or "")
    first, last = row.first_event_at, row.last_event_at
    span = None if first is None or last is None else int((last - first).total_seconds() // 60)
    return {
        "investigation_id": str(investigation_id),
        "version": row.version,
        "rule_id": row.rule_id,
        "rule_name": _cap(row.rule_name),
        "group_key": _cap(row.group_key, 512),
        "bucket_start": _iso(row.bucket_start),
        "bucket_end": _iso(row.bucket_end),
        "alert_count": row.alert_count,
        "duplicate_count": row.duplicate_count,
        "late_arrivals": late,
        "first_event_at": _iso(first),
        "last_event_at": _iso(last),
        "span_minutes": span,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "continues_id": None if row.continues_id is None else str(row.continues_id),
        "sample_alerts": [_cap(a) for a in samples],
        "entity_counts": {str(kind): int(n) for kind, n in counts},
        "entities": entities,
    }


async def local_context(
    conn: AsyncConnection, facts: Mapping[str, Any], history: timedelta
) -> dict[str, Any]:
    """Investigations that share an entity with this one within the history window (not
    through supernodes), the strongest first; at most RELATED of them, and how many in all."""
    bucket = datetime.fromisoformat(str(facts["bucket_start"]))
    params = {
        "id": uuid.UUID(str(facts["investigation_id"])),
        "max": SUPERNODE,
        "since": bucket - history,
        "until": bucket + timedelta(days=1),
        "n": RELATED,
    }
    rows = (
        await conn.execute(
            text(
                "WITH mine AS (SELECT e.kind, e.value FROM investigation_entities e"
                "  JOIN entities n ON n.kind = e.kind AND n.value = e.value"
                "  WHERE e.investigation_id = :id AND n.investigations BETWEEN 2 AND :max)"
                " SELECT o.investigation_id, i.rule_id, i.bucket_start, count(*) AS shared,"
                "  count(*) OVER () AS total"
                " FROM investigation_entities o"
                " JOIN mine m ON m.kind = o.kind AND m.value = o.value"
                " JOIN investigations i ON i.id = o.investigation_id"
                " WHERE o.investigation_id <> :id AND i.bucket_start >= :since"
                "  AND i.bucket_start < :until"
                " GROUP BY o.investigation_id, i.rule_id, i.bucket_start"
                " ORDER BY shared DESC, i.bucket_start DESC, o.investigation_id LIMIT :n"
            ),
            params,
        )
    ).all()
    supernodes = (
        await conn.execute(
            text(
                "SELECT count(*) FROM investigation_entities e"
                " JOIN entities n ON n.kind = e.kind AND n.value = e.value"
                " WHERE e.investigation_id = :id AND n.investigations > :max"
            ),
            params,
        )
    ).scalar_one()
    return {
        "related": [
            {
                "investigation_id": str(inv),
                "rule_id": rule,
                "bucket_start": _iso(start),
                "shared": shared,
            }
            for inv, rule, start, shared, _ in rows
        ],
        "related_total": rows[0].total if rows else 0,
        "supernode_entities": supernodes,
        "continues": facts["continues_id"],
    }


# ----------------------------------------------------------------------------- evidence

_RESULT = (
    "template",
    "template_version",
    "params",
    "status",
    "coverage",
    "source_watermark",
    "row_count",
    "truncated",
    "snapshot",
    "result_hash",
    "took_ms",
    "reused_from_version",
    "error",
    "collected_at",
    "asked_at",  # when the gateway was asked; a copy keeps the original's
)
_COLUMNS = ("investigation_id", "version", "task_key", *_RESULT)
_JSON = ("params", "coverage", "snapshot")
_COPIED = [c for c in _RESULT if c not in ("reused_from_version", "collected_at")]
_RETRY = (
    " ON CONFLICT (investigation_id, version, task_key) DO UPDATE SET "
    + ", ".join(f"{c} = EXCLUDED.{c}" for c in _RESULT)
    + " WHERE evidence.status NOT IN ('ok', 'empty')"
)
_SELECT_ROW = (
    f"SELECT {', '.join(_COLUMNS)} FROM evidence"  # noqa: S608 - constant fragments; values are bound
    " WHERE investigation_id = :inv AND version = :v AND task_key = :k"
)
_COPY_ROW = (
    "INSERT INTO evidence (investigation_id, version, task_key,"  # noqa: S608 - constant fragments; values are bound
    f" {', '.join(_COPIED)}, reused_from_version, collected_at)"
    f" SELECT investigation_id, :v, task_key, {', '.join(_COPIED)},"
    " CAST(:from AS integer), CAST(:now AS timestamptz)"
    " FROM evidence WHERE investigation_id = :inv AND version = :from AND task_key = :k" + _RETRY
)
_WRITE_ROW = (
    f"INSERT INTO evidence ({', '.join(_COLUMNS)})"  # noqa: S608 - constant fragments; values are bound
    f" VALUES ({', '.join(':' + c for c in _COLUMNS)})" + _RETRY
)


def ref_of(row: Mapping[str, Any], *, reused: bool) -> dict[str, Any]:
    """The graph state's reference to an evidence row (no snapshot)."""
    return {
        "task_key": row["task_key"],
        "template": f"{row['template']}@{row['template_version']}",
        "status": row["status"],
        "coverage": dict(row["coverage"] or {}),
        "row_count": row["row_count"],
        "truncated": bool(row["truncated"]),
        "result_hash": row["result_hash"],
        "reused": reused,
    }


async def evidence_row(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, key: str
) -> dict[str, Any] | None:
    row = (
        await conn.execute(
            text(_SELECT_ROW),
            {"inv": investigation_id, "v": version, "k": key},
        )
    ).first()
    return None if row is None else dict(row._mapping)


async def reusable(
    conn: AsyncConnection, investigation_id: uuid.UUID, keys: Sequence[str]
) -> dict[str, int]:
    """For each key with an ok/empty row in this investigation (any version): the newest
    such version. A row whose snapshot the retention purge removed is never reused."""
    if not keys:
        return {}
    rows = await conn.execute(
        text(
            "SELECT task_key, max(version) FROM evidence WHERE investigation_id = :inv"
            " AND task_key = ANY(:keys) AND status IN ('ok', 'empty')"
            " AND snapshot_purged_at IS NULL GROUP BY task_key"
        ),
        {"inv": investigation_id, "keys": list(keys)},
    )
    return {str(key): int(version) for key, version in rows}


async def purged(conn: AsyncConnection, investigation_id: uuid.UUID, key: str) -> bool:
    """Whether the retention purge removed this key's stored answer (an ok/empty row of
    any version whose snapshot is gone). Asking again would ask the SIEM for logs it no longer
    keeps, and its "nothing found" would read as a negative."""
    row = await conn.execute(
        text(
            "SELECT 1 FROM evidence WHERE investigation_id = :inv AND task_key = :k"
            " AND status IN ('ok', 'empty') AND snapshot_purged_at IS NOT NULL LIMIT 1"
        ),
        {"inv": investigation_id, "k": key},
    )
    return row.first() is not None


async def copy_evidence(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    key: str,
    from_version: int,
    now: datetime,
) -> dict[str, Any]:
    """Reuse an earlier version's ok/empty row for this version (no gateway call)."""
    await conn.execute(
        text(_COPY_ROW),
        {"inv": investigation_id, "v": version, "k": key, "from": from_version, "now": now},
    )
    row = await evidence_row(conn, investigation_id, version, key)
    assert row is not None
    return row


async def write_evidence(conn: AsyncConnection, row: Mapping[str, Any]) -> dict[str, Any]:
    """Insert or retry one evidence row; an existing ok/empty row wins (returned as is)."""
    statement = text(_WRITE_ROW).bindparams(*(bindparam(c, type_=JSONB) for c in _JSON))
    await conn.execute(statement, {c: row.get(c) for c in _COLUMNS})
    stored = await evidence_row(conn, row["investigation_id"], row["version"], row["task_key"])
    assert stored is not None
    return stored


async def snapshots(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, keys: Iterable[str]
) -> dict[str, Any]:
    rows = await conn.execute(
        text(
            "SELECT task_key, snapshot FROM evidence WHERE investigation_id = :inv"
            " AND version = :v AND task_key = ANY(:keys) AND status IN ('ok', 'empty')"
        ),
        {"inv": investigation_id, "v": version, "keys": sorted(keys)},
    )
    return {str(key): snapshot for key, snapshot in rows}


# ----------------------------------------------------------------------------- E-ids


async def eids(
    conn: AsyncConnection, investigation_id: uuid.UUID, keys: Sequence[str] | None = None
) -> dict[str, int]:
    """The E-id of each of ``keys`` (every task key, if None) the investigation has."""
    sql = "SELECT task_key, eid FROM evidence_requests WHERE investigation_id = :inv"
    params: dict[str, Any] = {"inv": investigation_id}
    if keys is not None:
        sql += " AND task_key = ANY(:keys)"
        params["keys"] = list(keys)
    return {str(k): int(e) for k, e in await conn.execute(text(sql), params)}


async def register_requests(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    tasks: Sequence[Mapping[str, Any]],
    origin: str,
    now: datetime,
    reason: str | None = None,
) -> dict[str, int]:
    """Give each task (``task_key``, ``template``, ``version`` as a planned task holds them)
    its opaque id ``E<n>`` if the investigation has none for its key: numbered after the
    investigation's last, in the order given, so a deterministic plan numbers the same way
    every time. Idempotent (an id never changes); callers for one investigation queue on a
    transaction-level advisory lock. Returns the E-id of every given task key."""
    unique: dict[str, Mapping[str, Any]] = {}
    for task in tasks:
        unique.setdefault(str(task["task_key"]), task)
    if not unique:
        return {}
    have = await eids(conn, investigation_id, list(unique))
    if len(have) == len(unique):
        return have
    await conn.execute(
        text("SELECT pg_advisory_xact_lock(:c, hashtext(:i))"),
        {"c": REQUEST_LOCK, "i": str(investigation_id)},
    )
    have = await eids(conn, investigation_id, list(unique))  # again, under the lock
    last = (
        await conn.execute(
            text(
                "SELECT coalesce(max(eid), 0) FROM evidence_requests WHERE investigation_id = :inv"
            ),
            {"inv": investigation_id},
        )
    ).scalar_one()
    rows = []
    for key, task in unique.items():
        if key in have:
            continue
        last += 1
        have[key] = last
        rows.append(
            {
                "inv": investigation_id,
                "eid": last,
                "key": key,
                "template": str(task["template"]),
                "tv": int(task["version"]),
                "origin": origin,
                "reason": reason,
                "v": version,
                "now": now,
            }
        )
    await conn.execute(
        text(
            "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
            " template_version, origin, reason, first_version, created_at)"
            " VALUES (:inv, :eid, :key, :template, :tv, :origin, :reason, :v, :now)"
        ),
        rows,
    )
    return have


# ----------------------------------------------------------------------------- dossier


async def persist_dossier(
    conn: AsyncConnection,
    job: queue.Claim,
    dossier: Mapping[str, Any],
    signals: Sequence[Mapping[str, Any]],
    now: datetime,
) -> bool:
    """Write the dossier and its signals, complete the job (fenced: LeaseLostError rolls it
    all back) and audit it, in the caller's transaction. Returns whether the job was queued
    again (the investigation changed meanwhile)."""
    inserted = (
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, facts_version, job_id, run_kind,"
                " family, pack, status, partial_reason, dossier_hash, body, evidence_count,"
                " created_at) VALUES (:inv, :v, :fv, :job, :kind, :family, :pack, :status,"
                " :reason, :hash, :body, :n, :now)"
                " ON CONFLICT (investigation_id, version, pack) DO NOTHING RETURNING 1"
            ).bindparams(bindparam("body", type_=JSONB)),
            {
                "inv": job.investigation_id,
                "v": job.version,
                "fv": dossier["facts_version"],
                "job": job.job_id,
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
                {"inv": job.investigation_id, "v": job.version, "pack": dossier["pack"]},
            )
        ).scalar_one()
        if existing != dossier["hash"]:
            raise DossierConflict(
                f"{job.investigation_id} v{job.version}: stored {existing[:12]},"
                f" new {dossier['hash'][:12]}"
            )
    elif signals:
        await conn.execute(
            text(
                "INSERT INTO signals (investigation_id, version, pack, name, value, status,"
                " unknown_reason, completeness, evidence, definition_version)"
                " VALUES (:inv, :v, :pack, :name, :value, :status, :reason, :completeness,"
                " :evidence, :dv)"
            ).bindparams(bindparam("value", type_=JSONB), bindparam("evidence", type_=ARRAY(Text))),
            [
                {
                    "inv": job.investigation_id,
                    "v": job.version,
                    "pack": dossier["pack"],
                    "name": s["name"],
                    "value": s["value"],
                    "status": s["status"],
                    "reason": s["unknown_reason"],
                    "completeness": s["completeness"],
                    "evidence": list(s["evidence"]),
                    "dv": s["definition_version"],
                }
                for s in signals
            ],
        )
    again = await queue.complete(conn, job, now)
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session,
            actor="worker",
            action="dossier.persist",
            target_type="investigation",
            target_id=str(job.investigation_id),
            details={
                "version": job.version,
                "job": job.job_id,
                "status": dossier["status"],
                "hash": dossier["hash"][:16],
                "requeued": again,
                "existing": inserted is None,
            },
        )
        await session.flush()
    finally:
        await session.close()
    return again
