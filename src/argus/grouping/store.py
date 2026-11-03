"""Grouping inside the collector's page transaction.

``group`` inserts the investigations the alerts belong to, locks them (and the next day's
buckets, whose ``continues`` link may change) in id order, links the alerts, and then
recomputes everything derived from the links in fresh statements: duplicates, counts, times,
severity, ``continues``, the entity index. Locks plus fresh statements make concurrent groupers
agree; recomputation makes order and batching irrelevant. New original alerts (not
duplicates) are a material change: the investigation's version goes up and it gets a job.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.grouping.assign import GROUPING_VERSION, assign
from argus.normalize import NormalizedAlert

COALESCE = timedelta(minutes=30)  # at most one job per investigation per 30 minutes


@dataclass(frozen=True)
class Grouped:
    investigations: int
    linked: int
    changed: int


async def group(conn: AsyncConnection, alerts: Sequence[NormalizedAlert], now: datetime) -> Grouped:
    if not alerts:
        return Grouped(0, 0, 0)
    assigned = {alert.alert_id: (alert, assign(alert)) for alert in alerts}
    rows = {
        a.investigation_id: {
            "id": a.investigation_id,
            "v": GROUPING_VERSION,
            "rule": alert.rule_id,
            "key": a.key,
            "start": a.bucket_start,
            "end": a.bucket_end,
            "previous": a.previous_id,
        }
        for alert, a in assigned.values()
    }
    await conn.execute(
        text(
            "INSERT INTO investigations (id, grouping_version, rule_id, group_key, bucket_start,"
            " bucket_end, previous_id) VALUES (:id, :v, :rule, :key, :start, :end, :previous)"
            " ON CONFLICT (id) DO NOTHING"
        ),
        [rows[key] for key in sorted(rows)],  # one lock order for concurrent groupers
    )
    touched = sorted(rows)
    nexts = sorted({a.next_id for _, a in assigned.values()} - set(touched))
    await conn.execute(
        text("SELECT id FROM investigations WHERE id = ANY(:ids) ORDER BY id FOR UPDATE"),
        {"ids": sorted({*touched, *nexts})},
    )
    ordered = sorted(assigned.items())
    linked = (
        await conn.execute(
            text(
                "INSERT INTO investigation_alerts (alert_id, investigation_id, late_arrival)"
                " SELECT * FROM unnest(CAST(:alerts AS text[]), CAST(:invs AS uuid[]),"
                " CAST(:lates AS boolean[])) ON CONFLICT (alert_id) DO NOTHING"
                " RETURNING alert_id"
            ),
            {
                "alerts": [alert_id for alert_id, _ in ordered],
                "invs": [a.investigation_id for _, (_, a) in ordered],
                "lates": [alert.execution_type.value == "manual" for _, (alert, _) in ordered],
            },
        )
    ).all()
    new_links = [alert_id for (alert_id,) in linked]
    ids = {"ids": touched}
    await conn.execute(
        text(
            "WITH ranked AS ("
            " SELECT ia.alert_id, first_value(ia.alert_id) OVER ("
            "  PARTITION BY ia.investigation_id, ar.fingerprint ORDER BY ia.alert_id) AS original"
            " FROM investigation_alerts ia JOIN alert_records ar ON ar.alert_id = ia.alert_id"
            " WHERE ia.investigation_id = ANY(:ids))"
            " UPDATE investigation_alerts ia SET duplicate_of = NULLIF(r.original, r.alert_id)"
            " FROM ranked r WHERE ia.alert_id = r.alert_id"
            " AND ia.duplicate_of IS DISTINCT FROM NULLIF(r.original, r.alert_id)"
        ),
        ids,
    )
    await conn.execute(
        text(
            "UPDATE investigations i SET alert_count = s.n, duplicate_count = s.d,"
            " first_event_at = s.first_at, last_event_at = s.last_at, severity = s.severity,"
            " risk_score = s.risk, rule_name = s.rule_name, updated_at = :now"
            " FROM (SELECT ia.investigation_id,"
            "  count(*) FILTER (WHERE ia.duplicate_of IS NULL) AS n,"
            "  count(*) FILTER (WHERE ia.duplicate_of IS NOT NULL) AS d,"
            "  min(ar.event_time) AS first_at, max(ar.event_time) AS last_at,"
            "  (array_agg(ar.normalized->>'severity' ORDER BY CASE ar.normalized->>'severity'"
            "   WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
            "   WHEN 'low' THEN 1 ELSE 0 END DESC, ar.normalized->>'severity'))[1] AS severity,"
            "  max((ar.normalized->>'risk_score')::double precision) AS risk,"
            "  min(ar.normalized->>'rule_name') AS rule_name"
            "  FROM investigation_alerts ia JOIN alert_records ar ON ar.alert_id = ia.alert_id"
            "  WHERE ia.investigation_id = ANY(:ids) GROUP BY ia.investigation_id) s"
            " WHERE i.id = s.investigation_id"
        ),
        {**ids, "now": now},
    )
    await conn.execute(
        text(
            "UPDATE investigations i SET continues_id = i.previous_id"
            " WHERE i.id = ANY(:ids) AND i.continues_id IS NULL"
            " AND EXISTS (SELECT 1 FROM investigations p WHERE p.id = i.previous_id)"
        ),
        ids,
    )
    await conn.execute(
        text(
            "UPDATE investigations n SET continues_id = n.previous_id"
            " WHERE n.previous_id = ANY(:ids) AND n.continues_id IS NULL"
        ),
        ids,
    )
    entities = sorted(
        {
            (str(a.investigation_id), e.kind, e.value)
            for alert_id in new_links
            for alert, a in [assigned[alert_id]]
            for e in alert.entities
        }
    )
    if entities:
        await conn.execute(
            text(
                "INSERT INTO investigation_entities (investigation_id, kind, value)"
                " VALUES (CAST(:inv AS uuid), :kind, :value) ON CONFLICT DO NOTHING"
            ),
            [{"inv": inv, "kind": kind, "value": value} for inv, kind, value in entities],
        )
        await conn.execute(
            text(
                "INSERT INTO entities (kind, value, investigations)"
                " SELECT kind, value, count(*) FROM investigation_entities"
                " WHERE (kind, value) IN (SELECT kind, value FROM investigation_entities"
                "  WHERE investigation_id = ANY(:ids))"
                " GROUP BY kind, value"
                " ON CONFLICT (kind, value) DO UPDATE SET investigations = EXCLUDED.investigations"
            ),
            ids,
        )
    changed = await _material_changes(conn, new_links, now)
    return Grouped(len(rows), len(new_links), len(changed))


async def _material_changes(
    conn: AsyncConnection, new_links: Sequence[str], now: datetime
) -> list[uuid.UUID]:
    """Bump the version of investigations that got a new original alert, and make sure each
    has a job: at once for a new investigation, else 30 min after its last finished job."""
    if not new_links:
        return []
    changed = [
        inv
        for (inv,) in (
            await conn.execute(
                text(
                    "SELECT DISTINCT investigation_id FROM investigation_alerts"
                    " WHERE alert_id = ANY(:links) AND duplicate_of IS NULL"
                    " ORDER BY investigation_id"
                ),
                {"links": list(new_links)},
            )
        ).all()
    ]
    if not changed:
        return []
    await conn.execute(
        text("UPDATE investigations SET version = version + 1 WHERE id = ANY(:ids)"),
        {"ids": changed},
    )
    await conn.execute(
        text(
            "INSERT INTO jobs (investigation_id, trigger, run_after)"
            " SELECT i.id, CASE WHEN f.last IS NULL THEN 'created' ELSE 'new_alerts' END,"
            "  GREATEST(CAST(:now AS timestamptz), COALESCE(f.last + :coalesce, :now))"
            " FROM investigations i LEFT JOIN LATERAL ("
            "  SELECT max(finished_at) AS last FROM jobs j"
            "  WHERE j.investigation_id = i.id AND j.status = 'done') f ON true"
            " WHERE i.id = ANY(:ids)"
            " ON CONFLICT (investigation_id) WHERE status IN ('queued', 'running') DO NOTHING"
        ),
        {"ids": changed, "now": now, "coalesce": COALESCE},
    )
    return changed
