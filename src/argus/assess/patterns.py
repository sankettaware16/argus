"""One investigator run per pattern (AR2, D-150, D-160): coverage without a call for every
investigation.

Unreviewed investigations that look alike are one **pattern**: the Patterns page's key
(``display.signature``: the rule, each step's outcome, a threat-list hit, the values the rule's
own steps look at) per IST day, split when members differ in a generic flag (``gold.flags``). The
investigator runs on one member of each pattern (raised ones first, then the highest severity,
then the newest) and its reading or proposal is shown on the others as "same pattern as ...".

A shared run is display only. The other members get no assessment, so nothing is scored, closed
or written back from it; only the assessed investigation can be accepted. A pattern is covered
for the day once a run that did not fail exists for it: members that arrive later attach to that
run, even when the assessed investigation has since changed. Three failed runs end the day's
tries for a pattern. An investigation that belongs to a notified case's known infection (AR4b,
D-169) is never a candidate: the owner was told, ARGUS counts its alerts and spends no run on
them. :func:`plan` is pure; :func:`schedule` reads the candidates and queues.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assess import queue
from argus.assess.raised import flags_of
from argus.assess.runner import view_hash
from argus.context import display
from argus.llm.privacy import Privacy

HORIZON = timedelta(days=2)  # how far back an investigation's last alert may be
FETCH = 2000  # candidates read in one pass, newest first
FETCH_WHEN_FULL = 500  # when the day's runs are all used, only to attach new members
MAX_FAILED = 3  # failed runs after which a pattern waits for the next day
PICKER_LOCK_KEY = int.from_bytes(b"ARGUSPCK", "big")  # one picker at a time (like the opener's)
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
Key = tuple[str, date]  # (the pattern's hash, its IST day)
_EARLIEST = datetime.min.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Candidate:
    """An unreviewed investigation the investigator has not read, and its pattern."""

    investigation_id: uuid.UUID
    version: int
    pack: str
    dossier_hash: str
    pattern: str
    day: date
    severity: int
    last_event_at: datetime | None
    raised: bool  # its evidence carries a flag, or it is in a case ARGUS suggested (AR2b)

    @property
    def key(self) -> Key:
        return (self.pattern, self.day)

    def rank(self) -> tuple[bool, int, datetime, str]:
        """The best member of a pattern: a raised one, then the most severe, then the newest (a
        stable last tie)."""
        return (self.raised, self.severity, self.last_event_at or _EARLIEST,
                str(self.investigation_id))  # fmt: skip


@dataclass(frozen=True)
class Plan:
    runs: tuple[Candidate, ...]  # the member each new run is on, in the order to run them
    attach: Mapping[uuid.UUID, tuple[Candidate, ...]]  # run investigation -> the other members
    joins: tuple[tuple[Candidate, int], ...]  # (member, the assessment that already covers it)


def pattern_hash(signature: Iterable[Any], flags: Iterable[str]) -> str:
    """A stable name for a pattern: the signature (as ``display.signature`` makes it) and flags."""
    raw = json.dumps([signature, list(flags)], separators=(",", ":"), default=list)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def day_of(bucket_start: datetime) -> date:
    """The site's calendar day of an investigation's bucket: its buckets start at 00:00 on the
    zone's standard time (``grouping.assign.anchor``), so at 00:00 or, in daylight saving, 01:00
    local of that day. ``bucket_start`` is always a bucket's start."""
    return bucket_start.astimezone(site.zone()).date()


def candidate(
    *,
    investigation_id: uuid.UUID,
    version: int,
    pack: str,
    dossier_hash: str,
    rule_id: str,
    group_key: str,
    severity: str | None,
    bucket_start: datetime,
    last_event_at: datetime | None,
    body: Mapping[str, Any],
    in_case: bool = False,
) -> Candidate:
    """The candidate for an investigation and the parts of its dossier a pattern is made of.
    ``in_case``: it is in a case ARGUS suggested, or outside threat intel flags one of its
    destinations (AR3): neither is part of the pattern's key."""
    from argus.web.queries import key_fields

    keys = [name for name, _ in key_fields(group_key)]
    signature, _ = display.signature(rule_id, keys, body)
    flags = flags_of(body.get("local_signals"), body.get("signals"))
    return Candidate(
        investigation_id, version, pack, dossier_hash, pattern_hash(signature, flags),
        day_of(bucket_start), SEVERITY_RANK.get((severity or "").lower(), 0), last_event_at,
        bool(flags) or in_case,
    )  # fmt: skip


def plan(
    candidates: Iterable[Candidate],
    covered: Mapping[Key, int],
    failed: Mapping[Key, int],
    budget: int,
) -> Plan:
    """What to do with ``candidates``: members of a covered pattern join its run; of the others,
    up to ``budget`` patterns get a run, raised ones first, then by severity and recency, each on
    its best member, the rest of the pattern attached to it. A pattern with ``MAX_FAILED`` failed
    runs today waits. Pure and independent of the order the candidates come in."""
    groups: dict[Key, list[Candidate]] = defaultdict(list)
    for c in candidates:
        groups[c.key].append(c)
    joins: list[tuple[Candidate, int]] = []
    waiting: list[tuple[Candidate, list[Candidate]]] = []
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda c: str(c.investigation_id))
        if key in covered:
            joins.extend((c, covered[key]) for c in members)
        elif failed.get(key, 0) < MAX_FAILED:
            best = max(members, key=Candidate.rank)  # a raised member, if any, is the best
            waiting.append((best, [c for c in members if c is not best]))
    waiting.sort(
        key=lambda w: (
            not w[0].raised,
            -w[0].severity,
            -(w[0].last_event_at or _EARLIEST).timestamp(),
            str(w[0].investigation_id),
        )
    )
    chosen = waiting[: max(budget, 0)]
    return Plan(
        tuple(best for best, _ in chosen),
        {best.investigation_id: tuple(rest) for best, rest in chosen},
        tuple(joins),
    )


# --------------------------------------------------------------------------- the database

_CANDIDATES = """
SELECT n.investigation_id, n.version, n.pack, n.dossier_hash, n.rule_id, n.group_key,
       n.severity, n.bucket_start, n.last_event_at, n.local_signals, n.signals, n.steps, n.fields,
       EXISTS (SELECT 1 FROM case_members m JOIN cases c ON c.id = m.case_id
               WHERE m.investigation_id = n.investigation_id AND m.removed_at IS NULL
               AND c.cause = 'raised' AND c.state = 'suspected')
       OR EXISTS (SELECT 1 FROM investigation_raises rz
                  WHERE rz.investigation_id = n.investigation_id AND rz.version = n.version
                  AND jsonb_exists(rz.flags, 'flagged by outside threat intel')) AS in_case
FROM (
  SELECT DISTINCT ON (d.investigation_id) d.investigation_id, d.version, d.pack, d.dossier_hash,
         d.created_at, i.rule_id, i.group_key, i.severity, i.bucket_start, i.last_event_at,
         d.body -> 'local_signals' AS local_signals, d.body -> 'signals' AS signals,
         d.body #> '{report,steps}' AS steps, d.body #> '{context,pack,fields}' AS fields
  FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
  WHERE i.last_event_at >= :since
  ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC
) n
WHERE NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = n.investigation_id
                  AND r.action = 'reviewed' AND r.version = n.version)
  AND NOT EXISTS (SELECT 1 FROM assessments a WHERE a.investigation_id = n.investigation_id
                  AND a.version = n.version AND a.dossier_hash = n.dossier_hash
                  AND a.assessor = :assessor)
  AND (CAST(:after AS text) IS NULL OR EXISTS (
       SELECT 1 FROM assessments e WHERE e.investigation_id = n.investigation_id
       AND e.version = n.version AND e.dossier_hash = n.dossier_hash
       AND e.assessor = :after AND e.status = 'no_decision'))
  AND NOT (n.investigation_id = ANY(:skip))
  AND NOT EXISTS (SELECT 1 FROM case_known_matches k
                  WHERE k.investigation_id = n.investigation_id AND k.version = n.version
                  AND k.outcome = 'known')
  AND NOT EXISTS (SELECT 1 FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
                  WHERE s.investigation_id = n.investigation_id AND s.version = n.version
                  AND a.status <> 'failed')
ORDER BY n.created_at DESC, n.investigation_id
LIMIT :fetch
"""
_RUNS = """
SELECT s.pattern, s.day, a.id, a.status FROM assessment_shares s
JOIN assessments a ON a.id = s.assessment_id
WHERE s.pattern = ANY(:patterns) AND s.day = ANY(:days)
  AND s.investigation_id = a.investigation_id AND s.version = a.version
  AND a.assessor = :assessor
"""
_TODAY = """
SELECT count(*) FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
WHERE s.investigation_id = a.investigation_id AND s.version = a.version
  AND a.assessor = :assessor AND a.created_at >= date_trunc('day', CAST(:now AS timestamptz))
"""
_BODY = """
SELECT body FROM dossiers WHERE investigation_id = :i AND version = :v AND pack = :p
AND dossier_hash = :h
"""
_ASSESSMENT = """
SELECT id, status FROM assessments WHERE investigation_id = :i AND view_hash = :vh
AND assessor = :assessor
"""
_SHARE = """
INSERT INTO assessment_shares (assessment_id, investigation_id, version, pattern, day)
VALUES (:a, :i, :v, :p, :d) ON CONFLICT DO NOTHING
"""


@dataclass(frozen=True)
class Scheduled:
    queued: int  # runs queued, one per pattern
    shared: int  # investigations attached to a run (a new one, or one that covers the pattern)


def _slim(row: Any) -> dict[str, Any]:
    """The parts of a dossier the pattern's key reads, without the keys it lacks."""
    body: dict[str, Any] = {}
    for name in ("local_signals", "signals"):
        if row._mapping[name] is not None:
            body[name] = row._mapping[name]
    if row.steps is not None:
        body["report"] = {"steps": row.steps}
    if row.fields is not None:
        body["context"] = {"pack": {"fields": row.fields}}
    return body


async def runs_today(conn: AsyncConnection, assessor: str, now: datetime) -> int:
    """Pattern runs queued today (UTC day): what ``--agent-per-day`` counts."""
    return int(await conn.scalar(text(_TODAY), {"assessor": assessor, "now": now}) or 0)


async def schedule(
    conn: AsyncConnection,
    privacy: Privacy,
    assessor: str,
    now: datetime,
    limit: int = 500,
    after: str | None = None,
    per_day: int | None = None,
    skip: Collection[uuid.UUID] = (),
    horizon: timedelta = HORIZON,
) -> Scheduled:
    """Queue one run for each uncovered pattern of unreviewed investigations ``assessor`` has not
    read (at most ``limit`` now and ``per_day`` patterns today; raised first), and attach the
    other members of every pattern to its run. With ``after``, only where that assessor found no
    decision on the same dossier; never an investigation in ``skip`` (the deterministic wave still
    owes it its checks, Q-F3).

    The picker holds a transaction-level advisory lock from its first read to the commit, so two
    passes at once never pick two representatives for one pattern: the second waits, then finds
    the first one's run and attaches its members to it."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PICKER_LOCK_KEY})
    budget = limit
    full = False
    if per_day is not None:
        budget = min(limit, per_day - await runs_today(conn, assessor, now))
        full = budget <= 0
    rows = (
        await conn.execute(
            text(_CANDIDATES).bindparams(bindparam("skip", type_=ARRAY(UUID))),
            {"assessor": assessor, "after": after, "skip": list(skip), "since": now - horizon,
             "fetch": FETCH_WHEN_FULL if full else FETCH},
        )
    ).all()  # fmt: skip
    found = [
        candidate(
            investigation_id=r.investigation_id, version=r.version, pack=r.pack,
            dossier_hash=r.dossier_hash, rule_id=r.rule_id, group_key=r.group_key,
            severity=r.severity, bucket_start=r.bucket_start, last_event_at=r.last_event_at,
            body=_slim(r), in_case=r.in_case,
        )
        for r in rows
    ]  # fmt: skip
    if not found:
        return Scheduled(0, 0)
    covered, failed = await _runs(conn, assessor, found)
    todo = plan(found, covered, failed, budget)
    shared = 0
    for member, assessment_id in todo.joins:
        shared += await _attach(conn, assessment_id, member)
    queued = 0
    for rep in todo.runs:
        run_id = await _queue(conn, privacy, assessor, rep, now)
        if run_id is None:
            continue
        queued += 1
        shared += 1
        for member in todo.attach[rep.investigation_id]:
            shared += await _attach(conn, run_id, member)
    return Scheduled(queued, shared)


async def _runs(
    conn: AsyncConnection, assessor: str, found: Collection[Candidate]
) -> tuple[dict[Key, int], dict[Key, int]]:
    """For the candidates' patterns: the newest run that did not fail, and how many failed."""
    rows = await conn.execute(
        text(_RUNS),
        {"patterns": sorted({c.pattern for c in found}), "days": sorted({c.day for c in found}),
         "assessor": assessor},
    )  # fmt: skip
    covered: dict[Key, int] = {}
    failed: dict[Key, int] = defaultdict(int)
    for pattern, day, assessment_id, status in rows:
        if status == "failed":
            failed[(pattern, day)] += 1
        else:
            covered[(pattern, day)] = max(covered.get((pattern, day), 0), assessment_id)
    return covered, failed


async def _queue(
    conn: AsyncConnection, privacy: Privacy, assessor: str, rep: Candidate, now: datetime
) -> int | None:
    """Queue the run for ``rep`` (or find the one that exists for this view) and mark the
    investigation as the run's own; None when the run exists and failed."""
    body = await conn.scalar(
        text(_BODY),
        {"i": rep.investigation_id, "v": rep.version, "p": rep.pack, "h": rep.dossier_hash},
    )
    if body is None:
        return None
    shown = view_hash(privacy, body)
    await queue.enqueue(conn, rep.investigation_id, rep.version, rep.pack, rep.dossier_hash,
                        shown, assessor, now)  # fmt: skip
    row = (
        await conn.execute(
            text(_ASSESSMENT), {"i": rep.investigation_id, "vh": shown, "assessor": assessor}
        )
    ).first()
    if row is None or row.status == "failed":
        return None
    await _attach(conn, row.id, rep)
    return int(row.id)


async def _attach(conn: AsyncConnection, assessment_id: int, member: Candidate) -> int:
    result = await conn.execute(
        text(_SHARE),
        {"a": assessment_id, "i": member.investigation_id, "v": member.version,
         "p": member.pattern, "d": member.day},
    )  # fmt: skip
    return int(result.rowcount or 0)
