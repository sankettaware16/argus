"""The pass that writes ARGUS AI's readings (D-324): a step of the assessment service, never of the
engine's own pass (which reads only ARGUS's database and must stay fast; a model call can take
30 seconds or more).

A **story** is owed by each presented incident (it has its case, still being decided or handled;
a card on Today: shown, or P1 or P2) newly queued for a person or materially changed in the last
:data:`RECENT`, once per version; a **second opinion** by each such P1. Within a pass at most
:data:`PER_PASS` of each are written, the highest priority first, and within a UTC day at most
the purpose's ``calls_per_day`` (config/llm.yaml; every stored attempt counts, refused or failed
too). A refused or failed reading is stored so that version is not asked again; "no model can
take it now" stores nothing, and the next pass tries again."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.db.models import RISK_CERTAINTY
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig, Tier
from argus.risk import reading
from argus.risk.reading import Complete, Member, Snapshot, Spec

log = logging.getLogger("argus.risk")
RECENT = timedelta(hours=72)  # how long after being queued an incident is still "new"
PER_PASS = 1  # of each kind: a model call can take minutes, and the service loops every 2
DEFAULT_CAPS = {"story": 15, "opinion": 3}
CASE_STATES = ("suspected", "open", "assigned", "contained")
BANDS = ("P1", "P2", "P3", "P4")
EVIDENCE_WORDS = tuple(w for w in RISK_CERTAINTY if w != "Confirmed")

_DUE = text(
    "SELECT r.id, r.version FROM risk_incidents r JOIN cases c ON c.id = r.case_id"
    " WHERE r.parent_id IS NULL AND r.state IN ('active', 'quiet')"
    " AND c.state = ANY(:states) AND (r.shown OR r.band IN ('P1', 'P2'))"
    " AND r.band = ANY(:bands)"
    " AND coalesce(r.queued_at, r.material_at, r.created_at) >= :since"
    " AND NOT EXISTS (SELECT 1 FROM risk_readings x WHERE x.incident_id = r.id"
    "  AND x.version = r.version AND x.kind = :kind)"
    " ORDER BY r.band, r.priority DESC, r.id LIMIT :n"
)
_TODAY = text(
    "SELECT count(*) FROM risk_readings WHERE kind = :kind"
    " AND created_at >= date_trunc('day', CAST(:now AS timestamptz) AT TIME ZONE 'UTC')"
    " AT TIME ZONE 'UTC'"
)
_INCIDENT = text(
    "SELECT r.id, r.version, r.band, r.priority, r.certainty, r.title, r.view, r.first_seen,"
    " r.last_seen, r.devices, r.changed FROM risk_incidents r WHERE r.id = :i"
)
_MEMBERS = text(
    "SELECT i.rule_name, i.rule_id, i.severity, i.alert_count, i.last_event_at,"
    " EXISTS (SELECT 1 FROM investigation_raises z WHERE z.investigation_id = i.id"
    "  AND z.version = i.version AND jsonb_array_length(z.flags) > 0) AS raised,"
    " (SELECT d.body FROM dossiers d WHERE d.investigation_id = i.id AND d.version = i.version"
    "  ORDER BY d.created_at DESC, d.pack DESC LIMIT 1) AS body"
    " FROM risk_incident_groups g JOIN investigations i ON i.id = g.investigation_id"
    " WHERE g.incident_id = :i"
    " ORDER BY raised DESC, CASE lower(coalesce(i.severity, '')) WHEN 'critical' THEN 4"
    "  WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,"
    "  i.last_event_at DESC NULLS LAST, i.id LIMIT :n"
)
_STORE = text(
    "INSERT INTO risk_readings (incident_id, version, kind, state, body, model, why, facts_sha,"
    " created_at) VALUES (:i, :v, :k, :s, CAST(:b AS jsonb), :m, :w, :f, :now)"
    " ON CONFLICT (incident_id, version, kind) DO NOTHING"
)


@dataclass(frozen=True)
class Plan:
    """One kind's settings: its spec, the bands it serves, the day's cap and the tier asked."""

    spec: Spec
    bands: tuple[str, ...]
    per_day: int
    tier: Tier


def plans(config: LlmConfig | None) -> tuple[Plan, ...]:
    """The story for P1-P4, the second opinion for P1, with config/llm.yaml's ``purposes``."""
    out = []
    for spec, bands in ((reading.STORY, ("P1", "P2", "P3", "P4")), (reading.OPINION, ("P1",))):
        purpose = None if config is None else config.purposes.get(spec.purpose)
        per_day = DEFAULT_CAPS[spec.kind]
        if purpose is not None and purpose.calls_per_day is not None:
            per_day = purpose.calls_per_day
        tier = purpose.tier if purpose is not None and purpose.tier is not None else spec.tier
        out.append(Plan(spec, bands, per_day, tier))
    return tuple(out)


@dataclass
class Report:
    written: dict[str, int] = field(default_factory=dict)
    refused: dict[str, int] = field(default_factory=dict)
    waiting: bool = False  # no model could take one now
    warned: list[str] = field(default_factory=list)

    def line(self) -> str | None:
        parts = [f"{n} {k}" for k, n in sorted(self.written.items()) if n]
        parts += [f"{n} {k} not shown" for k, n in sorted(self.refused.items()) if n]
        if self.waiting:
            parts.append("waiting for a model")
        return "ARGUS AI's reading: " + ", ".join(parts) if parts else None


async def due(
    conn: AsyncConnection, plan: Plan, now: datetime, limit: int
) -> list[tuple[int, int]]:
    rows = await conn.execute(
        _DUE,
        {"states": list(CASE_STATES), "bands": list(plan.bands), "since": now - RECENT,
         "kind": plan.spec.kind, "n": limit},
    )  # fmt: skip
    return [(int(r.id), int(r.version)) for r in rows]


async def written_today(conn: AsyncConnection, kind: str, now: datetime) -> int:
    return int((await conn.execute(_TODAY, {"kind": kind, "now": now})).scalar_one())


async def snapshot(conn: AsyncConnection, incident_id: int) -> Snapshot | None:
    row = (await conn.execute(_INCIDENT, {"i": incident_id})).first()
    if row is None:
        return None
    members = list(await conn.execute(_MEMBERS, {"i": incident_id, "n": reading.MEMBERS}))
    view: Mapping[str, Any] = row.view or {}
    # the evidence's word and band, as the page shows them: the stored word is "Confirmed" once a
    # person confirmed, and the model is asked whether the evidence supports the engine's word
    word = view.get("certainty")
    if word not in EVIDENCE_WORDS:
        word = row.certainty if row.certainty in EVIDENCE_WORDS else "Likely"
    band = view.get("band") if view.get("band") in BANDS else row.band
    return Snapshot(
        incident_id=int(row.id), version=int(row.version), band=str(band),
        priority=int(view.get("priority", row.priority)), certainty=str(word),
        confirmed=row.certainty == "Confirmed",
        title=row.title, view=view, first_seen=row.first_seen, last_seen=row.last_seen,
        devices=int(row.devices), changed=tuple(row.changed or ()),
        members=tuple(
            Member(m.rule_name or m.rule_id or "unnamed rule", m.severity, int(m.alert_count or 0),
                   m.last_event_at, bool(m.raised))
            for m in members
        ),
        bodies=tuple(m.body for m in members if m.body is not None),
    )  # fmt: skip


async def run_pass(
    db: AsyncEngine, privacy: Privacy, complete: Complete, now: datetime,
    config: LlmConfig | None = None,
) -> Report:  # fmt: skip
    """Write the readings owed now (see the module). One reading's failure is stored or said;
    the pass never raises for a model."""
    report = Report()
    for plan in plans(config):
        kind = plan.spec.kind
        async with db.connect() as conn:
            room = plan.per_day - await written_today(conn, kind, now)
            todo = await due(conn, plan, now, min(PER_PASS, room)) if room > 0 else []
        for incident_id, version in todo:
            async with db.connect() as conn:  # no transaction stays open while a model works
                snap = await snapshot(conn, incident_id)
            if snap is None or snap.version != version:
                continue  # it changed meanwhile: the next pass reads the new version
            outcome = await reading.read(plan.spec, snap, privacy, complete, now, tier=plan.tier)
            if outcome.state == "later":
                report.waiting = True
                break
            async with db.begin() as conn:
                await conn.execute(
                    _STORE,
                    {"i": incident_id, "v": version, "k": kind, "s": outcome.state,
                     "b": json.dumps(outcome.body, ensure_ascii=False), "m": outcome.model,
                     "w": outcome.why, "f": outcome.facts_sha, "now": now},
                )  # fmt: skip
            if outcome.state == "written":
                report.written[kind] = report.written.get(kind, 0) + 1
            else:
                report.refused[kind] = report.refused.get(kind, 0) + 1
                log.info("reading %s of incident %s not shown: %s", kind, incident_id,
                         outcome.why)  # fmt: skip
    return report
