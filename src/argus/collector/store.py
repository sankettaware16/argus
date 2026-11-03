"""The collector's side of Postgres (D-050): alert records, cursors, coverage gaps and
reconciliation runs. Every function takes an open connection, so the caller decides what one
transaction holds (plan §7.2: a page is one transaction)."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

from sqlalchemy import Table, and_, case, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.db.models import AlertRecord, CollectorCursor, CoverageGap, ReconciliationRun
from argus.normalize import NormalizedAlert, Quarantined, normalize
from argus.normalize.canon import canonical_json
from argus.normalize.times import parse_time

ALERTS = cast(Table, AlertRecord.__table__)
CURSORS = cast(Table, CollectorCursor.__table__)
GAPS = cast(Table, CoverageGap.__table__)
RUNS = cast(Table, ReconciliationRun.__table__)

# What Kibana changes on an alert after it was written (triage); everything else is content.
STATE_FIELDS = (
    "kibana.alert.workflow_status",
    "kibana.alert.workflow_status_updated_at",
    "kibana.alert.workflow_user",
    "kibana.alert.workflow_reason",
    "kibana.alert.workflow_tags",
    "kibana.alert.workflow_assignee_ids",
    "kibana.alert.case_ids",
    "kibana.alert.status",
)


def _pop(source: dict[str, Any], path: str) -> Any:
    """Remove ``path`` from ``source`` whether it is one dotted key or nested objects (or a mix:
    the longest dotted prefix that exists wins). Returns what was there, or None."""
    if path in source:
        return source.pop(path)
    parts = path.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:cut])
        inner = source.get(head)
        if isinstance(inner, dict):
            return _pop(inner, ".".join(parts[cut:]))
    return None


def split_source(source: Mapping[str, Any]) -> tuple[str, str, str | None]:
    """(content hash, state hash, workflow status) of an alert's ``_source``."""
    content = copy.deepcopy(dict(source))
    state = {path: _pop(content, path) for path in STATE_FIELDS}
    status = state["kibana.alert.workflow_status"]
    return (
        hashlib.sha256(canonical_json(content).encode()).hexdigest(),
        hashlib.sha256(canonical_json(state).encode()).hexdigest(),
        status if isinstance(status, str) else None,
    )


@dataclass(frozen=True)
class Ingested:
    new: int
    changed: int
    quarantined: int
    alerts: tuple[NormalizedAlert, ...] = field(default=(), compare=False)  # for the grouper


def _row(
    doc: Mapping[str, Any], recovered_by: str, written_at: datetime | None
) -> tuple[dict[str, Any], NormalizedAlert | None]:
    """The record of one mget document. ``written_at`` is the alert's ``@timestamp`` as
    Elasticsearch sorts it (from the id listing): the store counts alerts per hour by it, so
    its hours always agree with Elasticsearch's, even for an alert R3 quarantined."""
    result = normalize(doc)
    source = doc["_source"]
    content_hash, state_hash, status = split_source(source)
    row: dict[str, Any] = {
        "alert_id": doc["_id"],
        "index": doc["_index"],
        "raw": source,
        "content_hash": content_hash,
        "state_hash": state_hash,
        "workflow_status": status,
        "recovered_by": recovered_by,
        "normalizer_version": result.normalizer_version,
    }
    if isinstance(result, NormalizedAlert):
        return row | {
            "status": "normalized",
            "quarantine_reason": None,
            "quarantine_field": None,
            "rule_id": result.rule_id,
            "detected_at": written_at or result.detected_at,
            "event_time": result.event_time,
            "fingerprint": result.fingerprint,
            "normalized": result.model_dump(mode="json"),
        }, result
    assert isinstance(result, Quarantined)
    detected = source.get("@timestamp") if isinstance(source, Mapping) else None
    return row | {
        "status": "quarantined",
        "quarantine_reason": result.reason.value,
        "quarantine_field": result.field,
        "rule_id": _rule_id(source),
        "detected_at": written_at or parse_time(detected),
        "event_time": None,
        "fingerprint": None,
        "normalized": None,
    }, None


def _rule_id(source: Any) -> str | None:
    """The rule id as Elasticsearch's terms aggregation names it (text of a string or number)."""
    from argus.collector.collector import source_value

    if not isinstance(source, Mapping):
        return None
    value = source_value(source, "kibana.alert.rule.rule_id")
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return None
    return str(value) or None


async def ingest(
    conn: AsyncConnection,
    docs: Iterable[Mapping[str, Any]],
    recovered_by: str,
    now: datetime,
    written_at: Mapping[str, datetime] | None = None,
) -> Ingested:
    """Store mget documents (found ones; the caller checked completeness): new alerts are
    inserted, known ones updated when their content or state changed. Idempotent."""
    times = written_at or {}
    made = [_row(doc, recovered_by, times.get(doc["_id"])) for doc in docs if doc.get("found")]
    if not made:
        return Ingested(0, 0, 0)
    rows = sorted((row for row, _ in made), key=lambda row: row["alert_id"])  # one lock order
    alerts = tuple(alert for _, alert in made if alert is not None)
    known = {
        alert_id: (content, state)
        for alert_id, content, state in (
            await conn.execute(
                select(ALERTS.c.alert_id, ALERTS.c.content_hash, ALERTS.c.state_hash).where(
                    ALERTS.c.alert_id.in_([r["alert_id"] for r in rows])
                )
            )
        ).all()
    }
    new = changed = 0
    for row in rows:
        before = known.get(row["alert_id"])
        if before is None:
            new += 1
        elif before != (row["content_hash"], row["state_hash"]):
            changed += 1
    statement = insert(ALERTS).values(rows)
    excluded = statement.excluded
    updates = {
        name: getattr(excluded, name)
        for name in (
            "index", "status", "quarantine_reason", "quarantine_field", "normalizer_version",
            "rule_id", "detected_at", "event_time", "fingerprint", "workflow_status", "raw",
            "normalized", "content_hash", "state_hash",
        )
    }  # fmt: skip
    updates["detected_at"] = func.coalesce(excluded.detected_at, ALERTS.c.detected_at)
    # Once the retention purge emptied it (Q-A4), the raw _source is never written back.
    updates["raw"] = case((ALERTS.c.raw_purged_at.is_(None), excluded.raw), else_=ALERTS.c.raw)
    statement = statement.on_conflict_do_update(
        index_elements=[ALERTS.c.alert_id],
        set_={**updates, "last_seen_at": now, "source_missing_at": None},
    )
    await conn.execute(statement)
    quarantined = sum(row["status"] == "quarantined" for row in rows)
    return Ingested(new, changed, quarantined, alerts)


async def known_ids(conn: AsyncConnection, ids: Collection[str]) -> set[str]:
    if not ids:
        return set()
    rows = await conn.execute(select(ALERTS.c.alert_id).where(ALERTS.c.alert_id.in_(list(ids))))
    return {alert_id for (alert_id,) in rows}


async def ids_between(conn: AsyncConnection, start: datetime, end: datetime) -> set[str]:
    """Stored alerts written in [start, end) and not known to be gone from the SIEM."""
    rows = await conn.execute(
        select(ALERTS.c.alert_id).where(
            ALERTS.c.detected_at >= start,
            ALERTS.c.detected_at < end,
            ALERTS.c.source_missing_at.is_(None),
        )
    )
    return {alert_id for (alert_id,) in rows}


async def counts_between(
    conn: AsyncConnection, start: datetime, end: datetime
) -> tuple[dict[tuple[datetime, str | None], int], dict[datetime, int]]:
    """Stored alerts per (hour, rule) and per hour in [start, end), as reconciliation compares
    them with the SIEM."""
    hour = func.date_trunc("hour", ALERTS.c.detected_at)
    rows = (
        await conn.execute(
            select(hour, ALERTS.c.rule_id, func.count())
            .where(
                ALERTS.c.detected_at >= start,
                ALERTS.c.detected_at < end,
                ALERTS.c.source_missing_at.is_(None),
            )
            .group_by(hour, ALERTS.c.rule_id)
        )
    ).all()
    per_rule: dict[tuple[datetime, str | None], int] = {}
    totals: dict[datetime, int] = {}
    for at, rule, count in rows:
        per_rule[(at, rule)] = count
        totals[at] = totals.get(at, 0) + count
    return per_rule, totals


async def mark_missing(conn: AsyncConnection, ids: Collection[str], now: datetime) -> int:
    if not ids:
        return 0
    result = await conn.execute(
        update(ALERTS)
        .where(ALERTS.c.alert_id.in_(list(ids)), ALERTS.c.source_missing_at.is_(None))
        .values(source_missing_at=now)
    )
    return result.rowcount or 0


async def set_statuses(
    conn: AsyncConnection, statuses: Mapping[str, str], start: datetime, end: datetime
) -> list[str]:
    """Apply the non-default sweep: the given statuses, and ``open`` for every other stored
    alert in [start, end) that is not open. Two statements whatever the number of alerts (the
    ids travel as arrays). Returns the ids whose status changed."""
    ids = sorted(statuses)
    changed = await conn.execute(
        text(
            "UPDATE alert_records a SET workflow_status = s.status"
            " FROM unnest(CAST(:ids AS text[]), CAST(:statuses AS text[])) AS s(id, status)"
            " WHERE a.alert_id = s.id AND a.workflow_status IS DISTINCT FROM s.status"
            " RETURNING a.alert_id"
        ),
        {"ids": ids, "statuses": [statuses[i] for i in ids]},
    )
    reopened = await conn.execute(
        text(
            "UPDATE alert_records SET workflow_status = 'open'"
            " WHERE detected_at >= :start AND detected_at < :end"
            " AND workflow_status IS DISTINCT FROM 'open'"
            " AND NOT (alert_id = ANY(CAST(:ids AS text[])))"
            " RETURNING alert_id"
        ),
        {"start": start, "end": end, "ids": ids},
    )
    return sorted({alert_id for (alert_id,) in [*changed.all(), *reopened.all()]})


async def indices_of(conn: AsyncConnection, ids: Collection[str]) -> dict[str, str]:
    rows = await conn.execute(
        text(
            "SELECT alert_id, index FROM alert_records WHERE alert_id = ANY(CAST(:ids AS text[]))"
        ),
        {"ids": sorted(ids)},
    )
    return {str(row[0]): str(row[1]) for row in rows}


async def cursor(conn: AsyncConnection, name: str) -> datetime | None:
    row = await conn.execute(select(CURSORS.c.at).where(CURSORS.c.name == name))
    return row.scalar_one_or_none()


async def set_cursor(conn: AsyncConnection, name: str, at: datetime) -> None:
    statement = insert(CURSORS).values(name=name, at=at)
    await conn.execute(
        statement.on_conflict_do_update(
            index_elements=[CURSORS.c.name], set_={"at": at, "updated_at": func.now()}
        )
    )


async def open_gap(
    conn: AsyncConnection, kind: str, subject: str, start: datetime, detail: str | None
) -> None:
    """Open a coverage gap unless one of this kind and subject is open already."""
    statement = insert(GAPS).values(kind=kind, subject=subject, start_at=start, detail=detail)
    await conn.execute(
        statement.on_conflict_do_nothing(
            index_elements=[GAPS.c.kind, GAPS.c.subject], index_where=GAPS.c.end_at.is_(None)
        )
    )


async def close_gaps(
    conn: AsyncConnection, kinds: Collection[str], subject: str, end: datetime
) -> int:
    result = await conn.execute(
        update(GAPS)
        .where(
            and_(GAPS.c.kind.in_(list(kinds)), GAPS.c.subject == subject, GAPS.c.end_at.is_(None))
        )
        .values(end_at=func.greatest(GAPS.c.start_at, end))
    )
    return result.rowcount or 0


async def record_run(conn: AsyncConnection, **values: Any) -> None:
    await conn.execute(insert(RUNS).values(**values))
