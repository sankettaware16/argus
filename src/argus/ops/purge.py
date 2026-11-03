"""The retention purge (Q-A4, D-028): what ARGUS removes of the personal data it holds, and when.

Classes, each with its period (``retention.*``, ``memory.window``), never shorter in effect
than ``history.window`` (the collector would read back what the purge took):

* ``raw_source`` empties a normalized alert's raw ``_source`` (``{}``, ``raw_purged_at``);
  ``quarantine`` does the same for a quarantined alert. The age of an alert is the earlier of
  when the SIEM wrote it (``detected_at``) and when ARGUS stored it (``first_seen_at``).
* ``evidence`` empties the evidence snapshots (the log rows a query returned) of an
  investigation whose newest decision is a review (``reviewed``, not a follow-up) of its current
  version, older than the period; what was asked, its status, counts and hash stay. A version
  changed since the review is open work: its snapshots stay.
* ``memory`` removes an investigation past ``memory.window`` whole, with its alerts, entity
  index, dossiers, signals, evidence, reviews, assessments, jobs, write-back rows and the local
  model's shadow answers; entity counts are recomputed; expired alerts in no investigation,
  threat-intel answers and weekly tuning reports (they name the dominant values) older than the
  window go. An investigation goes only when every alert of it, and every review, is past the
  window, and no job or assessment of it is waiting or running and no write-back of it is
  planned or paused (unfinished work: the plan counts it as waiting).
* ``app_logs`` are the systemd journal's, outside the database: reported, trimmed by root.

Q-H4's ``notices`` table (a kind, an opaque id, a severity and a count; no host, address, user
or rule name) names nothing personal and no foreign key: it is kept, and emptied only by a
regroup.

**Holds** (DQ27): an investigation in the gold set, or an active member of a case that is not
closed or has an approval request that has not expired (as its case or merge target), keeps
everything; the investigation a held one continues keeps its row, so the held row's link stays.
**Case records, entity notes and the audit trail are never purged** in Phase 3: an
investigation any case record names stays, as foreign keys require.

The plan (dry run) counts with the same predicates the run deletes by. A run works in batches,
each a transaction under ``SET LOCAL ROLE argus_purge`` (``argus.db.roles.PURGE_GRANTS``), and
re-checks each batch's rows (locked) before it changes them, so a hold set meanwhile wins.
"""

# ruff: noqa: S608 - every statement is built from this module's constant fragments and its fixed
# table names; every value is a bound parameter.
from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from argus.config.durations import format_duration
from argus.config.settings import Settings
from argus.db.audit import record_audit
from argus.db.roles import PURGE_ROLE, purge_role_problems

CLASSES = ("raw_source", "quarantine", "evidence", "memory")
# Kept whatever their age (DQ27, D-028): the record of what people and ARGUS decided, and the
# notes people wrote about an entity on purpose (D-025; knowledge, like a case's notes).
NEVER_PURGED = ("the audit trail", "case records", "entity notes")
ALERT_BATCH = 1000
EVIDENCE_BATCH = 1000
INVESTIGATION_BATCH = 100

# The items a plan counts and a run changes, per class, in the order a run changes them. The
# memory class's names are tables; ``entities.recounted`` and ``investigations.continues``
# are rows changed, not removed.
ITEMS: dict[str, tuple[str, ...]] = {
    "raw_source": ("alert_records.raw",),
    "quarantine": ("alert_records.raw",),
    "evidence": ("evidence.snapshot",),
    "memory": (
        "investigations",
        "alert_records",
        "investigation_alerts",
        "investigation_entities",
        "entities",
        "entities.recounted",
        "investigations.continues",
        "signals",
        "dossiers",
        "evidence",
        "evidence_requests",
        "jobs",
        "review_events",
        "review_state",
        "assessments",
        "writeback_outbox",
        "llm_shadow",
        "alert_records.unlinked",
        "ti_lookups",
        "tuning_reports",
    ),
}


class PurgeError(Exception):
    """The purge refused to run, or stopped; what it had committed stays committed."""


@dataclass(frozen=True)
class Cutoffs:
    """Rows older than these go (``at`` minus each period, at least ``history.window``)."""

    at: datetime
    raw_source: datetime
    quarantine: datetime
    evidence: datetime
    memory: datetime
    periods: Mapping[str, timedelta] = field(default_factory=dict)
    extended: tuple[str, ...] = ()  # classes whose period history.window lengthened

    def params(self) -> dict[str, datetime]:
        return {
            "at": self.at,
            "raw_cut": self.raw_source,
            "quarantine_cut": self.quarantine,
            "evidence_cut": self.evidence,
            "memory_cut": self.memory,
        }


def cutoffs(settings: Settings, at: datetime) -> Cutoffs:
    """The cutoffs at ``at`` (tz-aware). A period shorter than ``history.window`` counts as
    ``history.window``: the collector may still read such an alert again, and would bring back
    what the purge removed."""
    if at.tzinfo is None:
        raise ValueError("the purge's time must be timezone-aware")
    floor = settings.history.window
    configured = {
        "raw_source": settings.retention.raw_source,
        "quarantine": settings.retention.quarantine,
        "evidence": settings.retention.evidence,
        "memory": settings.memory.window,
    }
    periods = {name: max(period, floor) for name, period in configured.items()}
    extended = tuple(name for name, period in configured.items() if period < floor)
    return Cutoffs(
        at=at,
        raw_source=at - periods["raw_source"],
        quarantine=at - periods["quarantine"],
        evidence=at - periods["evidence"],
        memory=at - periods["memory"],
        periods=periods,
        extended=extended,
    )


# --------------------------------------------------------------------------- selection
# Every predicate below is shared by the plan's counts and the run's changes.

# Investigations under the legal hold (DQ27). An approval request is pending until it expires
# (at most 72 hours, plan §7.1), decided or not: the hold errs on the side of keeping.
_HELD = """
held AS (
  SELECT g.investigation_id FROM gold_items g
  UNION
  SELECT m.investigation_id FROM case_members m JOIN cases c ON c.id = m.case_id
  WHERE m.removed_at IS NULL AND (c.state <> 'closed' OR EXISTS (
    SELECT 1 FROM approval_requests r
    WHERE (r.case_id = c.id OR r.target_case_id = c.id) AND r.expires_at > :at))
  UNION
  SELECT o.investigation_id FROM case_openings o JOIN cases c ON c.id = o.case_id
  WHERE c.state <> 'closed' OR EXISTS (
    SELECT 1 FROM approval_requests r
    WHERE (r.case_id = c.id OR r.target_case_id = c.id) AND r.expires_at > :at)
)"""

# An alert's age: the earlier of the SIEM's write and ARGUS's first sight (first_seen_at is never
# NULL, so the OR is LEAST(...) < cut, written so the two indexes serve it).
_ALERT_EXPIRED = "(a.detected_at < :{cut} OR a.first_seen_at < :{cut})"
# The holds are tested as IN (...) against a set read once (a hashed subplan); a correlated
# EXISTS over the CTE was scanned again for every row (seconds per chunk of 1,000 at 4,000
# held). Neither set has NULLs, so NOT IN means what it says.
_HELD_IDS = "(SELECT investigation_id FROM held)"
_ALERT_HELD = (
    "a.alert_id IN (SELECT l.alert_id FROM investigation_alerts l"
    f" WHERE l.investigation_id IN {_HELD_IDS})"
)


def _raw_where(status: str, cut: str) -> str:
    return f"a.status = '{status}' AND a.raw_purged_at IS NULL AND {_ALERT_EXPIRED.format(cut=cut)}"


_RAW = {
    "raw_source": _raw_where("normalized", "raw_cut"),
    "quarantine": _raw_where("quarantined", "quarantine_cut"),
}

# A snapshot worth removing: not SQL NULL and not JSON null (failed tasks store the latter), of
# an investigation whose newest decision reviewed its current version (a version changed since
# the review is open work in the Inbox: "changed since review").
_EVIDENCE_WHERE = (
    "e.snapshot IS NOT NULL AND e.snapshot <> 'null'::jsonb"
    " AND EXISTS (SELECT 1 FROM review_state s JOIN investigations v ON v.id = s.investigation_id"
    "  WHERE s.investigation_id = e.investigation_id AND s.action = 'reviewed'"
    "  AND s.decided_at < :evidence_cut AND s.version >= v.version)"
)
_EVIDENCE_HELD = f"e.investigation_id IN {_HELD_IDS}"

# An investigation past memory.window, as a whole (its alerts and reviews all past it) ...
_MEMORY_EXPIRED = """
i.bucket_end <= :memory_cut
AND NOT EXISTS (SELECT 1 FROM investigation_alerts l JOIN alert_records a
  ON a.alert_id = l.alert_id WHERE l.investigation_id = i.id
  AND LEAST(a.detected_at, a.first_seen_at) >= :memory_cut)
AND NOT EXISTS (SELECT 1 FROM review_events r
  WHERE r.investigation_id = i.id AND r.created_at >= :memory_cut)"""
# ... unless work on it is unfinished: a job or an assessment waiting or running, a write-back
# planned or paused (a paused one may be the only record of a partial write to Kibana).
_MEMORY_BUSY = """(i.id IN (SELECT j.investigation_id FROM jobs j
  WHERE j.status IN ('queued', 'running'))
OR i.id IN (SELECT s.investigation_id FROM assessments s
  WHERE s.status IN ('queued', 'running'))
OR i.id IN (SELECT w.investigation_id FROM writeback_outbox w
  WHERE w.state IN ('planned', 'paused')))"""
_MEMORY_WHERE = f"{_MEMORY_EXPIRED}\nAND NOT {_MEMORY_BUSY}"
# Kept: held, continued by a held investigation (the held row's link stays), or named by a case
# record (never purged in Phase 3; foreign keys need them).
_MEMORY_HELD = f"""(i.id IN {_HELD_IDS}
OR i.id IN (SELECT n.continues_id FROM investigations n
  WHERE n.id IN {_HELD_IDS} AND n.continues_id IS NOT NULL)
OR i.id IN (SELECT m.investigation_id FROM case_members m)
OR i.id IN (SELECT o.investigation_id FROM case_openings o)
OR i.id IN (SELECT r.investigation_id FROM cases c JOIN review_events r
  ON r.id = c.cause_review_id)
OR i.id IN (SELECT s.investigation_id FROM cases c JOIN assessments s
  ON s.id = c.cause_assessment_id))"""
_UNLINKED_WHERE = (
    "LEAST(a.detected_at, a.first_seen_at) < :memory_cut"
    " AND NOT EXISTS (SELECT 1 FROM investigation_alerts l WHERE l.alert_id = a.alert_id)"
)

# Rows the database removes with the investigation itself (ON DELETE CASCADE; Q-F1's shadow
# and its proposals, migration 0033; Q-F3's waves and checks, 0039; Q-C2's suggestions, 0041;
# AR2's shared runs and AR2b's raises, 0047; AR4b's known-infection decisions, 0050): not
# deleted here, not counted in the dry run.
_CASCADES = (
    "freshness_shadow",
    "freshness_proposals",
    "investigation_checks",
    "case_suggestions",
    "assessment_shares",
    "investigation_raises",
    "case_known_matches",
)
# What hangs off the victims (:ids), table by table, in the order foreign keys need.
_BY_INVESTIGATION = (
    "signals",
    "dossiers",
    "evidence",
    "evidence_requests",
    "jobs",
    "review_state",
    "review_events",
    "assessments",
    "writeback_outbox",
    "llm_shadow",
)


def _victims_cte() -> str:
    return (
        f"WITH {_HELD}, victims AS (SELECT i.id FROM investigations i"
        f" WHERE {_MEMORY_WHERE} AND NOT {_MEMORY_HELD})"
    )


# --------------------------------------------------------------------------- the plan


@dataclass
class Counts:
    """Per class, per item: rows (to be) changed; per class, rows a hold kept; and the
    investigations past memory.window that wait on unfinished work."""

    changed: dict[str, dict[str, int]] = field(
        default_factory=lambda: {c: dict.fromkeys(ITEMS[c], 0) for c in CLASSES}
    )
    held: dict[str, int] = field(default_factory=lambda: dict.fromkeys(CLASSES, 0))
    waiting: int = 0

    def total(self) -> int:
        return sum(n for items in self.changed.values() for n in items.values())

    def as_json(self) -> dict[str, Any]:
        return {
            "changed": {c: dict(i) for c, i in self.changed.items()},
            "held": dict(self.held),
            "waiting": self.waiting,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Counts:
        counts = cls()
        changed = data.get("changed")
        held = data.get("held")
        waiting = data.get("waiting")
        if not isinstance(changed, Mapping) or not isinstance(held, Mapping):
            raise ValueError("not a purge plan's counts")
        if isinstance(waiting, bool) or not isinstance(waiting, int) or waiting < 0:
            raise ValueError("the plan's waiting count is not a count")
        counts.waiting = waiting
        for name in CLASSES:
            items = changed.get(name)
            if not isinstance(items, Mapping) or set(items) != set(ITEMS[name]):
                raise ValueError(f"the plan's counts for {name} are not this ARGUS's")
            for item, n in items.items():
                if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                    raise ValueError(f"the plan's count {name}.{item} is not a count")
                counts.changed[name][item] = n
            n = held.get(name)
            if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                raise ValueError(f"the plan's held count for {name} is not a count")
            counts.held[name] = n
        return counts


async def _scalar(conn: AsyncConnection, sql: str, params: Mapping[str, Any]) -> int:
    return int((await conn.execute(text(sql), dict(params))).scalar_one())


async def count(conn: AsyncConnection, cut: Cutoffs) -> Counts:
    """What a run at ``cut.at`` would change, read in one snapshot (call it in a REPEATABLE
    READ transaction for one consistent picture). Read only."""
    p = cut.params()
    counts = Counts()
    for name, where in _RAW.items():
        counts.changed[name]["alert_records.raw"] = await _scalar(
            conn,
            f"WITH {_HELD} SELECT count(*) FROM alert_records a WHERE {where}"
            f" AND NOT {_ALERT_HELD}",
            p,
        )
        counts.held[name] = await _scalar(
            conn,
            f"WITH {_HELD} SELECT count(*) FROM alert_records a WHERE {where} AND {_ALERT_HELD}",
            p,
        )
    counts.changed["evidence"]["evidence.snapshot"] = await _scalar(
        conn,
        f"WITH {_HELD} SELECT count(*) FROM evidence e WHERE {_EVIDENCE_WHERE}"
        f" AND NOT {_EVIDENCE_HELD}",
        p,
    )
    counts.held["evidence"] = await _scalar(
        conn,
        f"WITH {_HELD} SELECT count(*) FROM evidence e WHERE {_EVIDENCE_WHERE}"
        f" AND {_EVIDENCE_HELD}",
        p,
    )
    memory = counts.changed["memory"]
    # The victims are read once and counted against by their ids: joined to the CTE, the planner
    # takes it for one row and nests loops over every link (seconds at 25,000 alerts, growing as
    # their product).
    found = await _ids(conn, f"{_victims_cte()} SELECT id FROM victims", p)
    memory["investigations"] = len(found)
    v = {**p, "victims": found}
    counts.held["memory"] = await _scalar(
        conn,
        f"WITH {_HELD} SELECT count(*) FROM investigations i WHERE {_MEMORY_WHERE}"
        f" AND {_MEMORY_HELD}",
        p,
    )
    counts.waiting = await _scalar(
        conn,
        f"WITH {_HELD} SELECT count(*) FROM investigations i WHERE {_MEMORY_EXPIRED}"
        f" AND {_MEMORY_BUSY} AND NOT {_MEMORY_HELD}",
        p,
    )
    memory["investigation_alerts"] = await _scalar(
        conn,
        "SELECT count(*) FROM investigation_alerts l WHERE l.investigation_id = ANY(:victims)",
        v,
    )
    memory["alert_records"] = memory["investigation_alerts"]  # one link per alert (its key)
    memory["investigation_entities"] = await _scalar(
        conn,
        "SELECT count(*) FROM investigation_entities e WHERE e.investigation_id = ANY(:victims)",
        v,
    )
    affected = (
        "WITH affected AS (SELECT DISTINCT e.kind, e.value FROM investigation_entities e"
        " WHERE e.investigation_id = ANY(:victims)),"
        " left_over AS (SELECT a.kind, a.value, EXISTS (SELECT 1 FROM investigation_entities e"
        "  WHERE e.kind = a.kind AND e.value = a.value"
        "  AND NOT (e.investigation_id = ANY(:victims))) AS stays FROM affected a)"
        " SELECT count(*) FILTER (WHERE NOT stays), count(*) FILTER (WHERE stays)"
        " FROM left_over o WHERE EXISTS (SELECT 1 FROM entities n"
        "  WHERE n.kind = o.kind AND n.value = o.value)"
    )
    gone, stays = (await conn.execute(text(affected), v)).one()
    memory["entities"], memory["entities.recounted"] = int(gone), int(stays)
    memory["investigations.continues"] = await _scalar(
        conn,
        "SELECT count(*) FROM investigations n WHERE n.continues_id = ANY(:victims)"
        " AND NOT (n.id = ANY(:victims))",
        v,
    )
    for table in _BY_INVESTIGATION:
        memory[table] = await _scalar(
            conn, f"SELECT count(*) FROM {table} t WHERE t.investigation_id = ANY(:victims)", v
        )
    memory["alert_records.unlinked"] = await _scalar(
        conn,
        f"SELECT count(*) FROM alert_records a WHERE {_UNLINKED_WHERE}",
        p,
    )
    memory["ti_lookups"] = await _scalar(
        conn, "SELECT count(*) FROM ti_lookups WHERE checked_at < :memory_cut", p
    )
    memory["tuning_reports"] = await _scalar(
        conn, "SELECT count(*) FROM tuning_reports WHERE week_end < :memory_cut", p
    )
    return counts


@asynccontextmanager
async def _as_purge(
    engine: AsyncEngine, *, read_only: bool = False
) -> AsyncIterator[AsyncConnection]:
    """A transaction as ``argus_purge`` (``SET LOCAL ROLE``): every statement in it has the
    purge role's privileges and no others. JIT is off: compiling the counts' plans cost ~0.45 s
    each and saved nothing (the review measured it)."""
    async with engine.begin() as conn:
        if read_only:
            await conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        await conn.execute(text(f"SET LOCAL ROLE {PURGE_ROLE}"))
        await conn.execute(text("SET LOCAL jit = off"))
        yield conn


async def plan(engine: AsyncEngine, cut: Cutoffs) -> Counts:
    """The dry run: the counts, in one read-only snapshot, as the purge role."""
    async with _as_purge(engine, read_only=True) as conn:
        return await count(conn, cut)


async def preflight(engine: AsyncEngine) -> None:
    """PurgeError unless ``argus_purge`` holds exactly its grants (Q-A4)."""
    problems = await purge_role_problems(engine)
    if problems:
        shown = "; ".join(problems[:10])
        raise PurgeError(
            f"{PURGE_ROLE} is not as migration 0031 grants it ({shown}): run `argus db"
            " bootstrap` and `argus db upgrade`, then argus doctor"
        )


# --------------------------------------------------------------------------- the run


async def _ids(conn: AsyncConnection, sql: str, params: Mapping[str, Any]) -> list[Any]:
    return [row[0] for row in await conn.execute(text(sql), dict(params))]


async def _candidates(engine: AsyncEngine, sql: str, params: Mapping[str, Any]) -> list[Any]:
    """The rows a pass may change, read once in one snapshot (the pass then works through them
    in chunks, each re-checked under its lock: one scan, however many chunks)."""
    async with _as_purge(engine, read_only=True) as conn:
        return list((await conn.execute(text(sql), dict(params))).all())


async def _purge_raw(engine: AsyncEngine, cut: Cutoffs, name: str, counts: Counts) -> None:
    where = _RAW[name]
    p = cut.params()
    found = await _candidates(
        engine,
        f"WITH {_HELD} SELECT a.alert_id FROM alert_records a WHERE {where}"
        f" AND NOT {_ALERT_HELD} ORDER BY a.alert_id",
        p,
    )
    for chunk in chunks([row[0] for row in found], ALERT_BATCH):
        async with _as_purge(engine) as conn:
            ids = await _ids(
                conn,
                f"WITH {_HELD} SELECT a.alert_id FROM alert_records a"
                f" WHERE a.alert_id = ANY(:chunk) AND {where} AND NOT {_ALERT_HELD}"
                " ORDER BY a.alert_id FOR UPDATE OF a",
                {**p, "chunk": list(chunk)},
            )
            if not ids:
                continue
            done = await conn.execute(
                text(
                    "UPDATE alert_records SET raw = '{}'::jsonb, raw_purged_at = now()"
                    " WHERE alert_id = ANY(:ids)"
                ),
                {"ids": ids},
            )
            counts.changed[name]["alert_records.raw"] += done.rowcount


_EVIDENCE_KEYS = (
    "unnest(CAST(:i AS uuid[]), CAST(:v AS int[]), CAST(:k AS text[]))"
    " AS t(investigation_id, version, task_key)"
)
_EVIDENCE_ON = (
    "e.investigation_id = t.investigation_id AND e.version = t.version AND e.task_key = t.task_key"
)


def _keys(rows: Sequence[Sequence[Any]]) -> dict[str, list[Any]]:
    return {"i": [r[0] for r in rows], "v": [r[1] for r in rows], "k": [r[2] for r in rows]}


async def _purge_evidence(engine: AsyncEngine, cut: Cutoffs, counts: Counts) -> None:
    p = cut.params()
    found = await _candidates(
        engine,
        f"WITH {_HELD} SELECT e.investigation_id, e.version, e.task_key FROM evidence e"
        f" WHERE {_EVIDENCE_WHERE} AND NOT {_EVIDENCE_HELD}"
        " ORDER BY e.investigation_id, e.version, e.task_key",
        p,
    )
    for chunk in chunks(found, EVIDENCE_BATCH):
        async with _as_purge(engine) as conn:
            rows = (
                await conn.execute(
                    text(
                        f"WITH {_HELD} SELECT e.investigation_id, e.version, e.task_key"
                        f" FROM evidence e JOIN {_EVIDENCE_KEYS} ON {_EVIDENCE_ON}"
                        f" WHERE {_EVIDENCE_WHERE} AND NOT {_EVIDENCE_HELD}"
                        " ORDER BY e.investigation_id, e.version, e.task_key FOR UPDATE OF e"
                    ),
                    {**p, **_keys(chunk)},
                )
            ).all()
            if not rows:
                continue
            done = await conn.execute(
                text(
                    "UPDATE evidence e SET snapshot = NULL, snapshot_purged_at = now()"
                    f" FROM {_EVIDENCE_KEYS} WHERE {_EVIDENCE_ON}"
                ),
                _keys(rows),
            )
            counts.changed["evidence"]["evidence.snapshot"] += done.rowcount


async def _purge_memory(engine: AsyncEngine, cut: Cutoffs, counts: Counts) -> None:
    memory = counts.changed["memory"]
    p = cut.params()
    found = await _candidates(engine, f"{_victims_cte()} SELECT id FROM victims ORDER BY id", p)
    all_victims = [row[0] for row in found]
    entity_touched: set[tuple[str, str]] = set()
    entity_gone: set[tuple[str, str]] = set()
    for batch in chunks(all_victims, INVESTIGATION_BATCH):
        async with _as_purge(engine) as conn:
            ids = await _ids(
                conn,
                f"WITH {_HELD} SELECT i.id FROM investigations i WHERE i.id = ANY(:batch)"
                f" AND {_MEMORY_WHERE} AND NOT {_MEMORY_HELD} ORDER BY i.id FOR UPDATE OF i",
                {**p, "batch": list(batch)},
            )
            if not ids:
                continue
            touched, gone = await _cascade(conn, ids, all_victims, memory)
            entity_touched |= touched
            entity_gone |= gone
    memory["entities"] += len(entity_gone)
    memory["entities.recounted"] += len(entity_touched - entity_gone)
    found = await _candidates(
        engine, f"SELECT a.alert_id FROM alert_records a WHERE {_UNLINKED_WHERE}", p
    )
    for chunk in chunks(sorted(row[0] for row in found), ALERT_BATCH):
        async with _as_purge(engine) as conn:
            ids = await _ids(
                conn,
                "SELECT a.alert_id FROM alert_records a WHERE a.alert_id = ANY(:chunk)"
                f" AND {_UNLINKED_WHERE} ORDER BY a.alert_id FOR UPDATE OF a",
                {**p, "chunk": list(chunk)},
            )
            if not ids:
                continue
            done = await conn.execute(
                text("DELETE FROM alert_records WHERE alert_id = ANY(:ids)"), {"ids": ids}
            )
            memory["alert_records.unlinked"] += done.rowcount
    async with _as_purge(engine) as conn:
        done = await conn.execute(text("DELETE FROM ti_lookups WHERE checked_at < :memory_cut"), p)
        memory["ti_lookups"] += done.rowcount
        done = await conn.execute(
            text("DELETE FROM tuning_reports WHERE week_end < :memory_cut"), p
        )
        memory["tuning_reports"] += done.rowcount


async def _cascade(
    conn: AsyncConnection,
    ids: Sequence[uuid.UUID],
    all_victims: Sequence[uuid.UUID],
    memory: dict[str, int],
) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Remove the investigations ``ids`` (locked) and what hangs off them; returns the entity
    keys recounted and those removed."""
    batch = {"ids": list(ids)}
    for table in _BY_INVESTIGATION:
        done = await conn.execute(
            text(f"DELETE FROM {table} WHERE investigation_id = ANY(:ids)"),
            batch,
        )
        memory[table] += done.rowcount
    keys = [
        (str(kind), str(value))
        for kind, value in await conn.execute(
            text(
                "DELETE FROM investigation_entities WHERE investigation_id = ANY(:ids)"
                " RETURNING kind, value"
            ),
            batch,
        )
    ]
    memory["investigation_entities"] += len(keys)
    touched = set(keys)
    gone: set[tuple[str, str]] = set()
    if touched:
        pairs = sorted(touched)
        unnest = {"kinds": [k for k, _ in pairs], "values": [v for _, v in pairs]}
        gone = {
            (str(kind), str(value))
            for kind, value in await conn.execute(
                text(
                    "DELETE FROM entities n USING unnest(CAST(:kinds AS text[]),"
                    " CAST(:values AS text[])) AS k(kind, value)"
                    " WHERE n.kind = k.kind AND n.value = k.value AND NOT EXISTS"
                    " (SELECT 1 FROM investigation_entities e"
                    "  WHERE e.kind = n.kind AND e.value = n.value)"
                    " RETURNING n.kind, n.value"
                ),
                unnest,
            )
        }
        await conn.execute(
            text(
                "UPDATE entities n SET investigations = c.n FROM (SELECT e.kind, e.value,"
                " count(*) AS n FROM investigation_entities e JOIN unnest(CAST(:kinds AS text[]),"
                " CAST(:values AS text[])) AS k(kind, value)"
                " ON e.kind = k.kind AND e.value = k.value GROUP BY e.kind, e.value) c"
                " WHERE n.kind = c.kind AND n.value = c.value"
            ),
            unnest,
        )
        present = {
            (str(kind), str(value))
            for kind, value in await conn.execute(
                text(
                    "SELECT n.kind, n.value FROM entities n JOIN unnest(CAST(:kinds AS text[]),"
                    " CAST(:values AS text[])) AS k(kind, value)"
                    " ON n.kind = k.kind AND n.value = k.value"
                ),
                unnest,
            )
        }
        touched = present | gone  # an entity row that never existed is neither
    done = await conn.execute(
        text(
            "UPDATE investigations SET continues_id = NULL WHERE continues_id = ANY(:ids)"
            " AND NOT (id = ANY(:all))"
        ),
        {**batch, "all": list(all_victims)},
    )
    memory["investigations.continues"] += done.rowcount
    alerts = [
        row[0]
        for row in await conn.execute(
            text(
                "DELETE FROM investigation_alerts WHERE investigation_id = ANY(:ids)"
                " RETURNING alert_id"
            ),
            batch,
        )
    ]
    memory["investigation_alerts"] += len(alerts)
    if alerts:
        done = await conn.execute(
            text("DELETE FROM alert_records WHERE alert_id = ANY(:a)"), {"a": alerts}
        )
        memory["alert_records"] += done.rowcount
    done = await conn.execute(text("DELETE FROM investigations WHERE id = ANY(:ids)"), batch)
    memory["investigations"] += done.rowcount
    return touched, gone


@dataclass(frozen=True)
class HeldRows:
    """The rows the holds keep, by identity: each held investigation (whether it is there, and
    the investigation it continues), its alerts that still have their raw data, its evidence
    rows that still have their snapshot."""

    investigations: Mapping[uuid.UUID, tuple[bool, uuid.UUID | None]]
    alerts: frozenset[tuple[uuid.UUID, str]]
    evidence: frozenset[tuple[uuid.UUID, int, str]]

    def summary(self) -> dict[str, int]:
        return {
            "held": len(self.investigations),
            "investigations": sum(there for there, _ in self.investigations.values()),
            "alerts_with_raw": len(self.alerts),
            "evidence_rows": len(self.evidence),
        }


async def held_rows(engine: AsyncEngine, at: datetime) -> HeldRows:
    """What the held investigations hold, read in one snapshot. A run reads it before and after
    (the holds checked afterwards: :func:`held_changes`)."""
    async with _as_purge(engine, read_only=True) as conn:
        p = {"at": at}
        found = await conn.execute(
            text(
                f"WITH {_HELD} SELECT h.investigation_id, i.id IS NOT NULL, i.continues_id"
                " FROM held h LEFT JOIN investigations i ON i.id = h.investigation_id"
            ),
            p,
        )
        investigations = {row[0]: (bool(row[1]), row[2]) for row in found}
        alerts = await conn.execute(
            text(
                f"WITH {_HELD} SELECT l.investigation_id, a.alert_id FROM held h"
                " JOIN investigation_alerts l ON l.investigation_id = h.investigation_id"
                " JOIN alert_records a ON a.alert_id = l.alert_id WHERE a.raw_purged_at IS NULL"
            ),
            p,
        )
        evidence = await conn.execute(
            text(
                f"WITH {_HELD} SELECT e.investigation_id, e.version, e.task_key FROM held h"
                " JOIN evidence e ON e.investigation_id = h.investigation_id"
                " WHERE e.snapshot_purged_at IS NULL"
            ),
            p,
        )
        return HeldRows(
            investigations,
            frozenset((row[0], str(row[1])) for row in alerts),
            frozenset((row[0], int(row[1]), str(row[2])) for row in evidence),
        )


def held_changes(before: HeldRows, after: HeldRows) -> dict[str, int]:
    """What changed of the rows held before the run and still held after it (rows added
    meanwhile, and rows whose hold ended during the run, are not the run's to keep)."""
    still = before.investigations.keys() & after.investigations.keys()
    there = {i for i in still if before.investigations[i][0]}
    alerts_after = {alert for _, alert in after.alerts}
    return {
        "investigations_removed": sum(not after.investigations[i][0] for i in there),
        "continues_changed": sum(
            after.investigations[i][0] and after.investigations[i][1] != before.investigations[i][1]
            for i in there
        ),
        "alerts_lost_raw": sum(
            inv in still and alert not in alerts_after for inv, alert in before.alerts
        ),
        "snapshots_lost": sum(
            key[0] in still and key not in after.evidence for key in before.evidence
        ),
    }


@dataclass(frozen=True)
class Outcome:
    planned: Counts
    done: Counts
    holds_before: Mapping[str, int]
    holds_after: Mapping[str, int]
    holds_changed: Mapping[str, int] = field(default_factory=dict)

    @property
    def matched(self) -> bool:
        return differences(self.planned, self.done) == []

    @property
    def holds_intact(self) -> bool:
        return not any(self.holds_changed.values())


async def run(engine: AsyncEngine, cut: Cutoffs, *, expect: Counts | None = None) -> Outcome:
    """Purge what is expired at ``cut.at``: raw data, quarantine, evidence, then memory. Counts
    first (as a plan does); with ``expect``, refused unless they are exactly the counts a person
    reviewed. Each batch commits on its own: a failure leaves what was done done, and the next
    run goes on from there. The held rows are read before and checked after, row by row."""
    await preflight(engine)
    planned = await plan(engine, cut)
    if expect is not None and expect.as_json() != planned.as_json():
        raise PurgeError(
            "the counts are not the ones reviewed (something changed since the plan, or the"
            " plan was made for another time): make a new plan and review it"
        )
    before = await held_rows(engine, cut.at)
    done = Counts(held=dict(planned.held), waiting=planned.waiting)
    for name in _RAW:
        await _purge_raw(engine, cut, name, done)
    await _purge_evidence(engine, cut, done)
    await _purge_memory(engine, cut, done)
    after = await held_rows(engine, cut.at)
    return Outcome(
        planned=planned,
        done=done,
        holds_before=before.summary(),
        holds_after=after.summary(),
        holds_changed=held_changes(before, after),
    )


async def reviewed_periods(engine: AsyncEngine) -> dict[str, str] | None:
    """The periods of the last reviewed purge (``--expect``) that succeeded, from the audit
    trail; None if there was none. The schedule continues exactly those (R9)."""
    async with _as_purge(engine, read_only=True) as conn:
        found = (
            await conn.execute(
                text(
                    "SELECT details -> 'periods' FROM audit_events WHERE actor = 'purge'"
                    " AND action = 'purge.run' AND outcome = 'success'"
                    " AND details ->> 'scheduled' = 'false'"
                    " ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    if found is None or not isinstance(found[0], dict):
        return None
    return {str(k): str(v) for k, v in found[0].items()}


async def audit(
    engine: AsyncEngine,
    *,
    outcome: str,
    cut: Cutoffs,
    details: Mapping[str, Any],
) -> None:
    """The run's audit event, written as the purge role (it may insert audit events only)."""
    async with _as_purge(engine) as conn, AsyncSession(bind=conn) as session:
        await record_audit(
            session,
            actor="purge",
            action="purge.run",
            outcome=outcome,
            target_type="database",
            details={
                "at": cut.at.isoformat(),
                "periods": {k: format_duration(v) for k, v in cut.periods.items()},
                "extended": list(cut.extended),
                **details,
            },
        )
        await session.flush()


def lines(counts: Counts, cut: Cutoffs, app_logs: timedelta) -> list[str]:
    """The counts as a person reads them."""
    out = [f"purge at {cut.at.isoformat()} (rows older than each period go, unless held)"]
    for name in CLASSES:
        period = format_duration(cut.periods[name])
        note = " (history.window: never shorter)" if name in cut.extended else ""
        items = counts.changed[name]
        shown = ", ".join(f"{item} {n}" for item, n in items.items() if n) or "nothing"
        kept = "kept by holds or case records" if name == "memory" else "kept by holds"
        line = f"  {name} ({period}{note}): {shown}; {kept}: {counts.held[name]}"
        if name == "memory":
            line += (
                f"; waiting on unfinished work (jobs, assessments, write-backs): {counts.waiting}"
            )
        out.append(line)
    out.append(
        f"  app_logs ({format_duration(app_logs)}): the systemd journal, not the database;"
        " a root step sets its retention (docs/runbooks/retention.md)"
    )
    out.append(f"  never purged in Phase 3: {', '.join(NEVER_PURGED)}")
    out.append(f"  total rows changed: {counts.total()}")
    return out


def differences(planned: Counts, done: Counts) -> list[str]:
    """Each item whose run count differs from the plan's."""
    found = []
    for name in CLASSES:
        for item in ITEMS[name]:
            a, b = planned.changed[name][item], done.changed[name][item]
            if a != b:
                found.append(f"{name}.{item}: planned {a}, done {b}")
    return found


def chunks[T](items: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]
