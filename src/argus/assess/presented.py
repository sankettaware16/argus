"""The investigation agent while the incident engine presents (D-324): it reads only alert groups
whose answer a person reads, the members of a presented P1-P3 incident whose case is still being
decided or handled (the case's incident report and the alert-group pages show its reading). The
per-pattern runs over every unreviewed alert group stop. Each incident gets at most
:data:`PER_INCIDENT` runs per material version (its most telling members first: raised by the
evidence, then severity, then the newest), within the day's quota; a person's "Ask the AI" is
queued as before and goes first. With ``risk.present`` off nothing here runs."""

from __future__ import annotations

import uuid
from collections.abc import Collection
from datetime import datetime

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess import queue
from argus.assess.patterns import PICKER_LOCK_KEY, Scheduled
from argus.assess.runner import view_hash
from argus.llm.privacy import Privacy

BANDS = ("P1", "P2", "P3")
PER_INCIDENT = 3  # agent runs per incident version
CASE_STATES = ("suspected", "open", "assigned", "contained")  # being decided or handled
FETCH = 200

# Members of presented incidents the agent has not read at their current dossier, at most as many
# per incident as it may still have read since its last material change (counted once per
# incident, so an incident at its limit never fills the rows fetched and holds the others back).
# Only where the deterministic engine (``after``) found no decision on the same dossier, never a
# reviewed one, never one the wave still owes its checks (``skip``).
_DUE = """
WITH inc AS (
  SELECT r.id, r.band, r.priority,
         (SELECT count(*) FROM assessments a JOIN risk_incident_groups g2
            ON g2.investigation_id = a.investigation_id
          WHERE g2.incident_id = r.id AND a.assessor = :assessor
            AND a.created_at >= coalesce(r.material_at, r.created_at)) AS used
  FROM risk_incidents r
  JOIN cases c ON c.id = r.case_id AND c.state = ANY(:states)
  WHERE r.parent_id IS NULL AND r.state IN ('active', 'quiet') AND r.band = ANY(:bands)
), due AS (
  SELECT inc.id AS incident_id, inc.band, inc.priority, inc.used, n.investigation_id, n.version,
         n.pack, n.dossier_hash,
         row_number() OVER (PARTITION BY inc.id ORDER BY
           EXISTS (SELECT 1 FROM investigation_raises z WHERE z.investigation_id = i.id
                   AND z.version = i.version AND jsonb_array_length(z.flags) > 0) DESC,
           CASE lower(coalesce(i.severity, '')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3
             WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
           i.last_event_at DESC NULLS LAST, i.id) AS rank
  FROM inc
  JOIN risk_incident_groups g ON g.incident_id = inc.id
  JOIN investigations i ON i.id = g.investigation_id
  JOIN LATERAL (
    SELECT d.investigation_id, d.version, d.pack, d.dossier_hash FROM dossiers d
    WHERE d.investigation_id = i.id AND d.version = i.version
    ORDER BY d.created_at DESC, d.pack DESC LIMIT 1
  ) n ON true
  WHERE inc.used < :per_incident
    AND NOT EXISTS (SELECT 1 FROM review_events v WHERE v.investigation_id = i.id
                    AND v.action = 'reviewed' AND v.version = i.version)
    AND NOT EXISTS (SELECT 1 FROM assessments a WHERE a.investigation_id = i.id
                    AND a.version = n.version AND a.dossier_hash = n.dossier_hash
                    AND a.assessor = :assessor)
    AND (CAST(:after AS text) IS NULL OR EXISTS (
         SELECT 1 FROM assessments e WHERE e.investigation_id = i.id
         AND e.version = n.version AND e.dossier_hash = n.dossier_hash
         AND e.assessor = :after AND e.status = 'no_decision'))
    AND NOT (i.id = ANY(:skip))
)
SELECT incident_id, investigation_id, version, pack, dossier_hash, used FROM due
WHERE rank <= :per_incident - used
ORDER BY band, priority DESC, incident_id, rank
LIMIT :fetch
"""
_TODAY = """
SELECT count(*) FROM assessments
WHERE assessor = :assessor AND created_at >= date_trunc('day', CAST(:now AS timestamptz))
"""
_BODY = """
SELECT body FROM dossiers WHERE investigation_id = :i AND version = :v AND pack = :p
AND dossier_hash = :h
"""


async def schedule(
    conn: AsyncConnection,
    privacy: Privacy,
    assessor: str,
    now: datetime,
    *,
    limit: int,
    per_day: int,
    after: str | None = None,
    skip: Collection[uuid.UUID] = (),
    per_incident: int = PER_INCIDENT,
) -> Scheduled:
    """Queue the agent on the members of presented P1-P3 incidents (see the module), at most
    ``limit`` now, ``per_incident`` per incident version and ``per_day`` of the assessor's runs
    today (a person's requests count too)."""
    # held to the commit, as the pattern picker does: two passes at once never pass the limits
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PICKER_LOCK_KEY})
    today = int(await conn.scalar(text(_TODAY), {"assessor": assessor, "now": now}) or 0)
    budget = min(limit, per_day - today)
    if budget <= 0:
        return Scheduled(0, 0)
    rows = (
        await conn.execute(
            text(_DUE).bindparams(bindparam("skip", type_=ARRAY(UUID))),
            {"assessor": assessor, "after": after, "skip": list(skip), "fetch": FETCH,
             "bands": list(BANDS), "states": list(CASE_STATES), "per_incident": per_incident},
        )
    ).all()  # fmt: skip
    taken: dict[int, int] = {}
    seen: set[uuid.UUID] = set()
    queued = 0
    for r in rows:
        if queued >= budget:
            break
        if r.investigation_id in seen:  # a member of two incidents: one run
            continue
        if int(r.used) + taken.get(r.incident_id, 0) >= per_incident:
            continue
        body = await conn.scalar(
            text(_BODY), {"i": r.investigation_id, "v": r.version, "p": r.pack,
                          "h": r.dossier_hash}
        )  # fmt: skip
        if body is None:
            continue
        seen.add(r.investigation_id)
        added = await queue.enqueue(
            conn, r.investigation_id, r.version, r.pack, r.dossier_hash,
            view_hash(privacy, body), assessor, now,
        )  # fmt: skip
        if added:
            queued += 1
            taken[r.incident_id] = taken.get(r.incident_id, 0) + 1
    return Scheduled(queued, 0)
