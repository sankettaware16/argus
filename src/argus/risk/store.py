"""The engine's reads and writes (Postgres only; no SIEM request is ever made here). What it
reads of today's pipeline it only reads: investigations, their alerts' fields, the newest
dossier's signals, the stored raise flags, the known-infection decisions and people's reviews.
It writes its own tables only (``risk_*``) and the engine's columns of ``rules``."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess.patterns import day_of
from argus.normalize.fields import values
from argus.risk import exposure_db, outbound_db
from argus.risk.config import Exposure
from argus.risk.observe import IDENTITY_FIELDS, Group, ObjectRef, Observation, Observed
from argus.risk.roles import FIELDS
from argus.risk.rulemeta import source_index

ALERTS_PER_GROUP = 50  # the newest alerts of a group whose fields are read
MAX_INDICES = 8  # distinct source indices kept of a group (its log family)
OUTCOME_FIELDS = ("event.outcome", "event.type", "http.response.status_code")
_RAW_FIELDS = tuple(f for _, f in FIELDS) + IDENTITY_FIELDS + OUTCOME_FIELDS


def _prefixes(paths: Iterable[str]) -> list[str]:
    """Every top-level key a field may be stored under (``a``, ``a.b``, ``a.b.c``)."""
    out: set[str] = set()
    for path in paths:
        parts = path.split(".")
        out.update(".".join(parts[:n]) for n in range(1, len(parts) + 1))
    return sorted(out)


RAW_KEYS = _prefixes(_RAW_FIELDS)

_NEWEST = (
    "LEFT JOIN LATERAL (SELECT x.version, x.pack, x.dossier_hash FROM dossiers x"
    " WHERE x.investigation_id = i.id AND x.version = i.version"
    " ORDER BY x.created_at DESC, x.pack DESC LIMIT 1) d ON true"
)
_KNOWN = (
    "LEFT JOIN LATERAL (SELECT k.outcome FROM case_known_matches k"
    " WHERE k.investigation_id = i.id AND k.version = i.version LIMIT 1) k ON true"
)
PENDING = text(
    "WITH cand AS (SELECT i.id, md5(concat_ws('|', i.version, i.last_event_at,"  # noqa: S608 - constant fragments; values are bound
    "  coalesce(d.dossier_hash, '-'), coalesce(r.flags::text, '-'), coalesce(k.outcome, '-'),"
    "  coalesce(ru.lineage, '-'), coalesce(ru.stage_mask, -1), coalesce(ru.family, '-'),"
    "  CAST(:salt AS text))) AS sig"
    " FROM investigations i"
    f" {_NEWEST} {_KNOWN}"
    " LEFT JOIN investigation_raises r ON r.investigation_id = i.id AND r.version = i.version"
    " LEFT JOIN rules ru ON ru.rule_id = i.rule_id"
    " WHERE i.last_event_at >= :since AND i.first_event_at <= :now)"
    " SELECT c.id, c.sig FROM cand c LEFT JOIN risk_groups g ON g.investigation_id = c.id"
    " WHERE g.signature IS DISTINCT FROM c.sig ORDER BY c.id LIMIT :limit"
)
_GROUPS = text(
    "SELECT i.id, i.version, i.rule_id, i.severity, i.risk_score, i.group_key, i.bucket_start,"  # noqa: S608 - constant fragments; values are bound
    " i.first_event_at, i.last_event_at, i.alert_count, r.flags, k.outcome AS known"
    f" FROM investigations i {_KNOWN}"
    " LEFT JOIN investigation_raises r ON r.investigation_id = i.id AND r.version = i.version"
    " WHERE i.id = ANY(CAST(:ids AS uuid[]))"
)
_SIGNALS = text(
    "SELECT u.id, s.name, s.value FROM unnest(CAST(:ids AS uuid[])) AS u(id)"
    " JOIN investigations i ON i.id = u.id"
    " CROSS JOIN LATERAL (SELECT x.version, x.pack FROM dossiers x"
    "  WHERE x.investigation_id = i.id AND x.version = i.version"
    "  ORDER BY x.created_at DESC, x.pack DESC LIMIT 1) d"
    " JOIN signals s ON s.investigation_id = i.id AND s.version = d.version AND s.pack = d.pack"
    " WHERE s.status = 'known' AND s.name = ANY(CAST(:names AS text[]))"
)
_FIELDS = text(
    "SELECT u.id, a.normalized -> 'entities' AS entities,"
    " a.normalized -> 'ancestors' AS ancestors,"
    " (SELECT jsonb_object_agg(k, v) FROM jsonb_each(a.raw) AS e(k, v)"
    "  WHERE k = ANY(CAST(:keys AS text[]))) AS part"
    " FROM unnest(CAST(:ids AS uuid[])) AS u(id)"
    " CROSS JOIN LATERAL (SELECT l.alert_id FROM investigation_alerts l"
    "  WHERE l.investigation_id = u.id ORDER BY l.linked_at DESC LIMIT :per) l"
    " JOIN alert_records a ON a.alert_id = l.alert_id"
)


def alert_outcome(part: Mapping[str, Any]) -> str | None:
    """One alert's outcome from ECS: ``event.outcome``, then a ``denied`` event type, then the
    HTTP status (2xx and 3xx served, 4xx and 5xx refused); None when it says nothing."""
    for value in values(part, "event.outcome"):
        if value in ("success", "failure"):
            return str(value)
    if any(v == "denied" for v in values(part, "event.type")):
        return "failure"
    for value in values(part, "http.response.status_code"):
        try:
            code = int(value)
        except (TypeError, ValueError):
            continue
        if 200 <= code < 400:
            return "success"
        if 400 <= code < 600:
            return "failure"
    return None


async def pending(
    conn: AsyncConnection, now: datetime, since: datetime, salt: str, limit: int
) -> list[tuple[uuid.UUID, str]]:
    """Alert groups of the window whose inputs changed since the engine read them (a new
    version, dossier, flag, known-infection decision or rule metadata; ``salt``: the engine's
    settings), oldest id first: (id, signature)."""
    rows = await conn.execute(PENDING, {"now": now, "since": since, "salt": salt, "limit": limit})
    return [(r.id, r.sig) for r in rows]


async def groups(
    conn: AsyncConnection, ids: Sequence[uuid.UUID], signal_names: Sequence[str],
    outside: Mapping[uuid.UUID, bool] | None = None, outside_flag: str = "",
    exposure: Exposure | None = None, *, measured: bool = True,
) -> list[Group]:  # fmt: skip
    """The groups ``ids`` as :class:`Group`: their alerts' fields and source indices (the newest
    :data:`ALERTS_PER_GROUP`), the newest dossier's known signals of ``signal_names``, the stored
    raise flags (with ``outside_flag`` added where ``outside`` says the cache flags one of the
    group's indicators) and the known-infection decision; with ``exposure``, an inbound group's
    sites and its source's checked facts (E3, ``exposure_db.attach``), and, with ``measured``,
    what the incident evidence checks found about its addresses (D-323,
    ``outbound_db.attach``)."""
    if not ids:
        return []
    bound = {"ids": list(ids)}
    signals: dict[uuid.UUID, dict[str, Any]] = defaultdict(dict)
    for row in await conn.execute(_SIGNALS, {**bound, "names": list(signal_names)}):
        signals[row.id][row.name] = row.value
    fields: dict[uuid.UUID, dict[str, list[object]]] = defaultdict(lambda: defaultdict(list))
    outcomes: dict[uuid.UUID, list[str]] = defaultdict(list)
    indices: dict[uuid.UUID, dict[str, None]] = defaultdict(dict)
    extra = [*(f for _, f in FIELDS), *IDENTITY_FIELDS]
    for row in await conn.execute(_FIELDS, {**bound, "keys": RAW_KEYS, "per": ALERTS_PER_GROUP}):
        held = fields[row.id]
        for entity in row.entities or []:
            if isinstance(entity, Mapping) and isinstance(entity.get("field"), str):
                held[entity["field"]].append(entity.get("value"))
        part = row.part or {}
        for name in extra:
            held[name].extend(values(part, name))
        found = alert_outcome(part)
        if found is not None:
            outcomes[row.id].append(found)
        index = source_index(row.ancestors)
        if index is not None and len(indices[row.id]) < MAX_INDICES:
            indices[row.id][index] = None
    out = []
    for r in await conn.execute(_GROUPS, bound):
        flags = [f for f in (r.flags or []) if isinstance(f, str)]
        if outside and outside.get(r.id) and outside_flag and outside_flag not in flags:
            flags.append(outside_flag)
        out.append(
            Group(
                r.id, r.version, r.rule_id, r.severity, r.risk_score, r.group_key,
                r.first_event_at, r.last_event_at, r.alert_count, day_of(r.bucket_start),
                {k: tuple(dict.fromkeys(v)) for k, v in fields[r.id].items()},
                tuple(outcomes[r.id]), signals[r.id], tuple(flags), r.known == "known",
                tuple(indices[r.id]),
            )
        )  # fmt: skip
    if exposure is not None:
        out = await exposure_db.attach(conn, out, exposure)
        if measured:
            out = await outbound_db.attach(conn, out)
    return sorted(out, key=lambda g: str(g.id))


_UPSERT_OBJECTS = text(
    "INSERT INTO risk_objects (kind, key, first_seen, last_seen)"
    " SELECT k, v, t, t FROM unnest(CAST(:kinds AS text[]), CAST(:keys AS text[]),"
    " CAST(:at AS timestamptz[])) AS u(k, v, t)"
    " ON CONFLICT (kind, key) DO UPDATE SET last_seen = greatest(risk_objects.last_seen,"
    " EXCLUDED.last_seen) RETURNING id, kind, key"
)
_UPSERT_GROUP = text(
    "INSERT INTO risk_groups (investigation_id, version, signature, direction, day, at, alerts,"
    " outcome, known, kinds, category, observed_at) VALUES (:id, :version, :signature,"
    " :direction, :day, :at, :alerts, :outcome, :known, CAST(:kinds AS text[]), :category, :now)"
    " ON CONFLICT (investigation_id) DO UPDATE SET version = EXCLUDED.version,"
    " signature = EXCLUDED.signature, direction = EXCLUDED.direction, day = EXCLUDED.day,"
    " at = EXCLUDED.at, alerts = EXCLUDED.alerts, outcome = EXCLUDED.outcome,"
    " known = EXCLUDED.known, kinds = EXCLUDED.kinds, category = EXCLUDED.category,"
    " observed_at = EXCLUDED.observed_at, scored_at = NULL"
)
_INSERT_ENTITY = text(
    "INSERT INTO risk_entities (investigation_id, kind, value, role, fields)"
    " VALUES (:id, :kind, :value, :role, CAST(:fields AS text[]))"
)
_INSERT_OBSERVATION = text(
    "INSERT INTO risk_observations (object_id, investigation_id, investigation_version,"
    " source_kind, source_key, role, at, day, base, outcome, prevalence, fidelity, score, stages,"
    " family, strong, threats, evidence) VALUES (:object, :group, :version, :source_kind,"
    " :source_key, :role, :at, :day, :base, :outcome, 1, 1, :score, :stages, :family, :strong,"
    " CAST(:threats AS text[]), CAST(:evidence AS text[]))"
)


async def write(
    conn: AsyncConnection, now: datetime, observed: Sequence[tuple[Group, str, Observed]]
) -> int:
    """Replace what the engine holds of each group with what it just observed (its record,
    entities and observations); returns the observations written."""
    if not observed:
        return 0
    refs: dict[ObjectRef, datetime] = {}
    for group, _, seen in observed:
        for ref in seen.objects:
            refs[ref] = max(refs.get(ref, group.last_at), group.last_at)
    ids: dict[ObjectRef, int] = {}
    if refs:
        ordered = sorted(refs)
        rows = await conn.execute(
            _UPSERT_OBJECTS,
            {"kinds": [r.kind for r in ordered], "keys": [r.key for r in ordered],
             "at": [refs[r] for r in ordered]},
        )  # fmt: skip
        ids = {ObjectRef(r.kind, r.key): int(r.id) for r in rows}
    await conn.execute(
        _UPSERT_GROUP,
        [
            {"id": g.id, "version": g.version, "signature": sig, "direction": seen.direction,
             "day": g.day, "at": g.last_at, "alerts": g.alerts, "outcome": seen.outcome,
             "known": g.known, "kinds": sorted({o.source_key[3:] for o in seen.observations
                                                if o.source_kind == "evidence"}),
             "category": "known_infection" if g.known else (
                 "hub_activity" if seen.hubs and not seen.objects else None), "now": now}
            for g, sig, seen in observed
        ],
    )  # fmt: skip
    group_ids = [g.id for g, _, _ in observed]
    await conn.execute(
        text("DELETE FROM risk_observations WHERE investigation_id = ANY(CAST(:ids AS uuid[]))"),
        {"ids": group_ids},
    )
    await conn.execute(
        text("DELETE FROM risk_entities WHERE investigation_id = ANY(CAST(:ids AS uuid[]))"),
        {"ids": group_ids},
    )
    entities: dict[tuple[uuid.UUID, str, str, str], list[str]] = {}
    for g, _, seen in observed:
        for e in seen.entities:
            entities.setdefault((g.id, e.kind, e.value, e.role), []).append(e.field)
    if entities:
        await conn.execute(
            _INSERT_ENTITY,
            [{"id": k[0], "kind": k[1], "value": k[2], "role": k[3],
              "fields": sorted(set(f))[:20]} for k, f in entities.items()],
        )  # fmt: skip
    rows_out = [
        {"object": ids[o.object], "group": o.group, "version": o.version,
         "source_kind": o.source_kind, "source_key": o.source_key, "role": o.role, "at": o.at,
         "day": o.day, "base": o.base, "outcome": o.outcome, "score": o.base * o.outcome,
         "stages": o.stages, "family": o.family, "strong": o.strong,
         "threats": list(o.threats), "evidence": list(o.evidence)[:20]}
        for _, _, seen in observed
        for o in seen.observations
    ]  # fmt: skip
    if rows_out:
        await conn.execute(_INSERT_OBSERVATION, rows_out)
    return len(rows_out)


# --------------------------------------------------------------------------- scoring reads


@dataclass(frozen=True)
class Held:
    """An object as the last scoring left it."""

    id: int
    ref: ObjectRef
    criticality: float
    hub: bool
    lanes: tuple[str, ...]
    held: str | None
    last_lane_at: datetime | None
    item_at: datetime | None


@dataclass(frozen=True)
class GroupRow:
    id: uuid.UUID
    direction: str
    outcome: float
    known: bool
    kinds: tuple[str, ...]
    category: str | None
    day: date
    at: datetime
    alerts: int


async def observations(
    conn: AsyncConnection, since: datetime, now: datetime
) -> tuple[list[Observation], dict[ObjectRef, int]]:
    """The observations of the window (seen by ``now``), and each object's id."""
    rows = await conn.execute(
        text(
            "SELECT o.object_id, b.kind, b.key, o.role, o.source_kind, o.source_key,"
            " o.investigation_id, o.investigation_version, o.at, o.day, o.base, o.outcome,"
            " o.stages, o.family, o.strong, o.threats, o.evidence FROM risk_observations o"
            " JOIN risk_objects b ON b.id = o.object_id"
            " WHERE o.at >= :since AND o.at <= :now"
        ),
        {"since": since, "now": now},
    )
    out: list[Observation] = []
    refs: dict[int, ObjectRef] = {}
    for (oid, kind, key, role, source_kind, source_key, group, version, at, day, base, outcome,
         stages, family, strong, threats, evidence) in rows:  # fmt: skip
        ref = refs.get(oid)
        if ref is None:
            ref = refs[oid] = ObjectRef(kind, key)
        out.append(Observation(
            ref, role, source_kind, source_key, group, version, at, day, base, outcome, stages,
            family, strong, tuple(threats), tuple(evidence),
        ))  # fmt: skip
    return out, {ref: int(oid) for oid, ref in refs.items()}


async def held_objects(conn: AsyncConnection, ids: Iterable[int]) -> dict[int, Held]:
    """The objects ``ids`` and every object a lane held at the last scoring."""
    rows = await conn.execute(
        text(
            "SELECT id, kind, key, criticality, hub, lanes, held, last_lane_at, item_at"
            " FROM risk_objects WHERE id = ANY(CAST(:ids AS bigint[])) OR cardinality(lanes) > 0"
        ),
        {"ids": sorted(set(ids))},
    )
    return {
        int(r.id): Held(int(r.id), ObjectRef(r.kind, r.key), float(r.criticality), r.hub,
                        tuple(r.lanes), r.held, r.last_lane_at, r.item_at)
        for r in rows
    }  # fmt: skip


async def group_rows(conn: AsyncConnection, since: datetime, now: datetime) -> list[GroupRow]:
    """The groups whose digest category is still open: seen since ``since``, or never scored."""
    rows = await conn.execute(
        text(
            "SELECT investigation_id, direction, outcome, known, kinds, category, day, at, alerts"
            " FROM risk_groups WHERE (at >= :since OR scored_at IS NULL) AND at <= :now"
        ),
        {"since": since, "now": now},
    )
    return [GroupRow(r.investigation_id, r.direction, r.outcome, r.known, tuple(r.kinds),
                     r.category, r.day, r.at, r.alerts) for r in rows]  # fmt: skip


async def verdicts(conn: AsyncConnection, since: datetime, now: datetime) -> set[int]:
    """Objects with an alert group of the window a person reviewed as a true positive."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT o.object_id FROM risk_observations o"
            " JOIN review_state s ON s.investigation_id = o.investigation_id"
            " WHERE o.at >= :since AND s.outcome = 'true_positive' AND s.decided_at <= :now"
        ),
        {"since": since, "now": now},
    )
    return {int(r.object_id) for r in rows}


async def scores(conn: AsyncConnection) -> dict[tuple[int, str], tuple[Any, ...]]:
    rows = await conn.execute(
        text(
            "SELECT object_id, span, score, sources, families, stages, active_days, strong,"
            " anchored FROM risk_object_scores"
        )
    )
    return {(int(r.object_id), r.span): tuple(r[2:]) for r in rows}


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
