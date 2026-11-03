"""The freshness tables: readings, watermarks, the shadow's verdicts and its
would-be proposals. Every statement binds its values."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.freshness.model import Reading


@dataclass(frozen=True)
class Stored:
    """A reading as the lane stores it: the reading, when it was sent, why it has none."""

    reading: Reading
    sent_at: datetime
    reason: str | None = None
    health: str | None = None
    took_ms: int | None = None


_READING = text(
    "INSERT INTO freshness_readings (source, sent_at, at, outcome, reason, ingested, event_at,"
    " health, took_ms) VALUES (:source, :sent_at, :at, :outcome, :reason, :ingested, :event_at,"
    " :health, :took_ms)"
)
# A watermark only advances: a reading with an older ingest time changes nothing (and the
# table's trigger refuses any update that would move it back).
_WATERMARK = text(
    "INSERT INTO freshness_watermarks (source, ingested, event_at, read_at)"
    " VALUES (:source, :ingested, :event_at, :at)"
    " ON CONFLICT (source) DO UPDATE SET ingested = EXCLUDED.ingested,"
    " event_at = EXCLUDED.event_at, read_at = EXCLUDED.read_at"
    " WHERE EXCLUDED.ingested > freshness_watermarks.ingested"
)


async def record(conn: AsyncConnection, stored: Stored) -> None:
    r = stored.reading
    values = {
        "source": r.source,
        "sent_at": stored.sent_at,
        "at": r.at,
        "outcome": r.outcome,
        "reason": None if stored.reason is None else stored.reason[:200],
        "ingested": r.ingested,
        "event_at": r.event_at,
        "health": stored.health,
        "took_ms": stored.took_ms,
    }
    await conn.execute(_READING, values)
    if r.ingested is not None:
        await conn.execute(_WATERMARK, values)


def _reading(row: Any) -> Reading:
    return Reading(row.source, row.at, row.outcome, row.ingested, row.event_at)


async def readings(
    conn: AsyncConnection, source: str, since: datetime, until: datetime
) -> list[Reading]:
    """``source``'s readings that answered in [since, until], oldest first."""
    rows = await conn.execute(
        text(
            "SELECT source, at, outcome, ingested, event_at FROM freshness_readings"
            " WHERE source = :source AND at >= :since AND at <= :until ORDER BY at, id"
        ),
        {"source": source, "since": since, "until": until},
    )
    return [_reading(row) for row in rows]


async def all_readings(
    conn: AsyncConnection, since: datetime, until: datetime
) -> dict[str, list[Reading]]:
    rows = await conn.execute(
        text(
            "SELECT source, at, outcome, ingested, event_at FROM freshness_readings"
            " WHERE at >= :since AND at <= :until ORDER BY source, at, id"
        ),
        {"since": since, "until": until},
    )
    out: dict[str, list[Reading]] = {}
    for row in rows:
        out.setdefault(row.source, []).append(_reading(row))
    return out


async def latest(conn: AsyncConnection) -> dict[str, Reading]:
    """Each source's newest reading (any outcome)."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (source) source, at, outcome, ingested, event_at"
            " FROM freshness_readings ORDER BY source, at DESC, id DESC"
        )
    )
    return {row.source: _reading(row) for row in rows}


async def latest_ok(conn: AsyncConnection) -> dict[str, Reading]:
    """Each source's newest reading with a document."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (source) source, at, outcome, ingested, event_at"
            " FROM freshness_readings WHERE outcome = 'ok' ORDER BY source, at DESC, id DESC"
        )
    )
    return {row.source: _reading(row) for row in rows}


async def watermarks(conn: AsyncConnection) -> dict[str, tuple[datetime, datetime, datetime]]:
    """Each source's watermark: (newest ingest time, its event time, when it was read)."""
    rows = await conn.execute(
        text("SELECT source, ingested, event_at, read_at FROM freshness_watermarks")
    )
    return {row.source: (row.ingested, row.event_at, row.read_at) for row in rows}


async def export(conn: AsyncConnection, since: datetime, until: datetime) -> list[dict[str, Any]]:
    """Readings as plain rows (``argus freshness export``, the margin script's input)."""
    rows = await conn.execute(
        text(
            "SELECT source, sent_at, at, outcome, reason, ingested, event_at, health, took_ms"
            " FROM freshness_readings WHERE at >= :since AND at <= :until ORDER BY at, id"
        ),
        {"since": since, "until": until},
    )
    return [
        {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in row._mapping.items()
        }
        for row in rows
    ]


# ----------------------------------------------------------------------------- evidence


async def evidence(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, keys: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """The evidence rows a verdict reads: template, parameters, status, coverage, send time."""
    if not keys:
        return {}
    rows = await conn.execute(
        text(
            "SELECT task_key, template, template_version, params, status, coverage, truncated,"
            " asked_at FROM evidence WHERE investigation_id = :inv AND version = :v"
            " AND task_key = ANY(:keys)"
        ),
        {"inv": investigation_id, "v": version, "keys": sorted(set(keys))},
    )
    return {str(row.task_key): dict(row._mapping) for row in rows}


async def mark_watermarks(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    marks: Mapping[str, datetime],
) -> None:
    """Record on each evidence row how far its source's logs were complete (mode on only)."""
    for key, moment in sorted(marks.items()):
        await conn.execute(
            text(
                "UPDATE evidence SET source_watermark = :m WHERE investigation_id = :inv"
                " AND version = :v AND task_key = :k"
            ),
            {"m": moment, "inv": investigation_id, "v": version, "k": key},
        )


# ----------------------------------------------------------------------------- shadow

_SHADOW = text(
    "INSERT INTO freshness_shadow (investigation_id, version, pack, signal, mode, verdict,"
    " reason, bridged_verdict, complete_to, refs, margins, decided_at) VALUES (:inv, :v,"
    " :pack, :signal, :mode, :verdict, :reason, :bridged, :complete_to, :refs, :margins,"
    " :at) ON CONFLICT (investigation_id, version, pack, signal) DO UPDATE SET"
    " mode = EXCLUDED.mode, verdict = EXCLUDED.verdict, reason = EXCLUDED.reason,"
    " bridged_verdict = EXCLUDED.bridged_verdict, complete_to = EXCLUDED.complete_to,"
    " refs = EXCLUDED.refs, margins = EXCLUDED.margins, decided_at = EXCLUDED.decided_at"
).bindparams(bindparam("refs", type_=JSONB), bindparam("margins", type_=JSONB))


async def write_shadow(conn: AsyncConnection, rows: Iterable[Mapping[str, Any]]) -> int:
    count = 0
    for row in rows:
        await conn.execute(_SHADOW, dict(row))
        count += 1
    return count


async def shadow_rows(conn: AsyncConnection, since: datetime | None = None) -> list[dict[str, Any]]:
    sql = (
        "SELECT investigation_id, version, pack, signal, mode, verdict, reason, bridged_verdict,"
        " complete_to, refs, margins, decided_at FROM freshness_shadow"
    )
    params: dict[str, Any] = {}
    if since is not None:
        sql += " WHERE decided_at >= :since"
        params["since"] = since
    rows = await conn.execute(text(sql + " ORDER BY decided_at, investigation_id, signal"), params)
    return [dict(row._mapping) for row in rows]


_PROPOSAL = text(
    "INSERT INTO freshness_proposals (investigation_id, version, pack, dossier_hash, assessor,"
    " bridged, outcome, actual, signals, reasons) VALUES (:inv, :v, :pack, :hash, :assessor,"
    " :bridged, :outcome, :actual, :signals, :reasons)"
    " ON CONFLICT (investigation_id, dossier_hash, assessor, bridged) DO NOTHING"
).bindparams(bindparam("signals", type_=JSONB), bindparam("reasons", type_=JSONB))


async def write_proposal(conn: AsyncConnection, row: Mapping[str, Any]) -> None:
    await conn.execute(_PROPOSAL, dict(row))


async def proposals(conn: AsyncConnection) -> list[dict[str, Any]]:
    rows = await conn.execute(
        text(
            "SELECT investigation_id, version, pack, dossier_hash, assessor, bridged, outcome,"
            " actual, signals, reasons, at FROM freshness_proposals ORDER BY at, id"
        )
    )
    return [dict(row._mapping) for row in rows]


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)
