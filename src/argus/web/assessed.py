"""The Inbox's view of assessments (P8, D-091): the current proposal of an investigation, the
proposals waiting for a person grouped by what decided them (each group with a random audit
sample), and the operating metrics of Phase 2 (validator blocks, floor hits, fallbacks,
backlog, quota per provider)."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.agent import reading
from argus.assess import queue

SAMPLE = 3  # audited items shown per group
GROUP_LIMIT = 500  # proposals listed in one group


@dataclass(frozen=True)
class Shown:
    assessment_id: int
    status: str
    outcome: str | None
    confidence: float | None
    source: str  # who proposed it, in plain words
    key: str  # what decided it (an engine key, a model)
    reasons: tuple[str, ...]
    finished_at: datetime | None


def is_agent(assessor: str) -> bool:
    """Whether an assessment is the AI investigator's (any version of its name): the one rule
    every page and list uses for "the agent's own assessment" (AR4 review, D-186)."""
    return assessor.startswith("agent")


def source_of(assessor: str) -> str:
    return "the AI investigator" if is_agent(assessor) else "the decision engine"


def key_of(decided_by: str | None) -> str:
    """The deciding key of ``engine@1#fp: steps / rule / ...``, or the model of
    ``agent@1#openai/m``; the stamp's fingerprint is left out."""
    if not decided_by:
        return "-"
    head, _, rest = decided_by.partition(": ")
    if rest:
        return rest
    return head.partition("#")[2] or head


async def current(conn: AsyncConnection, investigation_id: uuid.UUID) -> Shown | None:
    found = await queue.current(conn, investigation_id)
    if found is None:
        return None
    reasons = tuple(str(r)[:600] for r in (found.reasons or [])[:8])
    return Shown(found.assessment_id, found.status, found.outcome, found.confidence,
                 source_of(found.assessor), key_of(found.decided_by), reasons,
                 found.finished_at)  # fmt: skip


@dataclass(frozen=True)
class Proposal:
    assessment_id: int
    investigation_id: uuid.UUID
    rule: str
    alerts: int
    bucket_start: datetime
    reason: str


@dataclass
class Group:
    group: str  # what the group's confirm accepts: see group_of
    source: str
    key: str
    outcome: str
    rule: str | None = None  # the investigator's groups are per rule
    models: set[str] = field(default_factory=set)
    items: list[Proposal] = field(default_factory=list)
    sample: list[Proposal] = field(default_factory=list)


def group_of(assessor: str, decided_by: str | None, rule: str, outcome: str | None) -> str:
    """The engine's proposals are grouped by their deciding key; the investigator's by rule
    and outcome (which model answered is a detail a reviewer does not audit by)."""
    if is_agent(assessor):
        return f"{assessor}|{rule}|{outcome}"
    return decided_by or "-"


_PROPOSALS = """
SELECT * FROM (
  SELECT DISTINCT ON (a.investigation_id) a.id, a.investigation_id, a.assessor, a.status,
         a.outcome, a.decided_by, a.reasons, coalesce(i.rule_name, i.rule_id) AS rule,
         i.alert_count, i.bucket_start
  FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
  WHERE a.status IN ('proposed', 'no_decision')
    AND NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = a.investigation_id
                    AND r.action = 'reviewed' AND r.version = a.version)
  ORDER BY a.investigation_id, (a.status = 'proposed') DESC, a.id DESC
) c WHERE c.status = 'proposed'
ORDER BY md5(c.id::text || :day), c.id
"""


async def proposals(conn: AsyncConnection, today: date) -> list[Group]:
    """The current proposals of unreviewed investigations, grouped by what decided them,
    largest group first; the first ``SAMPLE`` of each (in a random order fixed for the day)
    are its audit sample."""
    groups: dict[str, Group] = {}
    for row in await conn.execute(text(_PROPOSALS), {"day": today.isoformat()}):
        name = group_of(row.assessor, row.decided_by, str(row.rule), row.outcome)
        g = groups.get(name)
        if g is None:
            agent = is_agent(row.assessor)
            g = groups[name] = Group(
                name, source_of(row.assessor), key_of(row.decided_by), row.outcome,
                str(row.rule) if agent else None,
            )  # fmt: skip
        if g.rule is not None:
            g.models.update(m for m in key_of(row.decided_by).split(",") if m)
        reasons = row.reasons or []
        item = Proposal(row.id, row.investigation_id, str(row.rule), int(row.alert_count),
                        row.bucket_start, str(reasons[0])[:300] if reasons else "")  # fmt: skip
        if len(g.items) < GROUP_LIMIT:
            g.items.append(item)
    for g in groups.values():
        g.sample = g.items[:SAMPLE]
    return sorted(groups.values(), key=lambda g: (-len(g.items), g.group))


async def confirm(
    conn: AsyncConnection,
    group: str,
    ids: list[int],
    user_id: int,
    note: str,
    *,
    kibana_ok: bool = False,
) -> tuple[int, int]:
    """Accept the listed proposals of one group (those the person was shown): (accepted,
    skipped because they changed, are no longer current, or belong to another group)."""
    accepted = skipped = 0
    for assessment_id in ids:
        row = (
            await conn.execute(
                text(
                    "SELECT a.assessor, a.decided_by, a.outcome, coalesce(i.rule_name, i.rule_id)"
                    " FROM assessments a JOIN investigations i ON i.id = a.investigation_id"
                    " WHERE a.id = :id"
                ),
                {"id": assessment_id},
            )
        ).first()
        if row is None or group_of(row[0], row[1], str(row[3]), row[2]) != group:
            skipped += 1
            continue
        try:
            async with conn.begin_nested():
                await queue.accept(conn, assessment_id, user_id, note, kibana_ok=kibana_ok)
            accepted += 1
        except queue.AssessmentConflict:
            skipped += 1
    return accepted, skipped


@dataclass(frozen=True)
class Metrics:
    validator_blocks: int
    calls: dict[str, tuple[int, int, float]]  # provider: (attempts, ok, cost) in 24 h
    fallbacks: int  # calls answered by a provider after another failed, in 24 h
    floor_hits: int  # proposals the floor stopped, in 7 days
    backlog: dict[str, tuple[int, timedelta | None]]  # assessor: (waiting, oldest wait)
    outcomes: dict[str, dict[str, int]]  # assessor: status/outcome counts, in 7 days
    month_cost: float


async def metrics(conn: AsyncConnection, now: datetime) -> Metrics:
    day, week = now - timedelta(days=1), now - timedelta(days=7)
    blocks = await conn.scalar(
        text("SELECT count(*) FROM llm_calls WHERE outcome = 'blocked' AND at >= :w"),
        {"w": week},
    )
    calls = {
        p: (int(n), int(ok), float(cost))
        for p, n, ok, cost in await conn.execute(
            text(
                "SELECT provider, count(*), count(*) FILTER (WHERE outcome = 'ok'),"
                " coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >= :d AND attempt > 0"
                " GROUP BY 1 ORDER BY 1"
            ),
            {"d": day},
        )
    }
    fallbacks = await conn.scalar(
        text("SELECT count(*) FROM llm_calls WHERE at >= :d AND outcome = 'ok' AND attempt > 1"),
        {"d": day},
    )
    floor = await conn.scalar(
        text(
            "SELECT count(*) FROM assessments WHERE created_at >= :w AND status = 'no_decision'"
            " AND reasons::text LIKE '%floor: %'"
        ),
        {"w": week},
    )
    backlog: dict[str, tuple[int, timedelta | None]] = {}
    for assessor, n, oldest in await conn.execute(
        text(
            "SELECT assessor, count(*), min(created_at) FROM assessments"
            " WHERE status IN ('queued', 'running') GROUP BY 1 ORDER BY 1"
        )
    ):
        backlog[assessor] = (int(n), now - oldest if oldest else None)
    outcomes: dict[str, dict[str, int]] = defaultdict(dict)
    for assessor, label, n in await conn.execute(
        text(
            "SELECT assessor, coalesce(outcome, status), count(*) FROM assessments"
            " WHERE created_at >= :w GROUP BY 1, 2 ORDER BY 1, 2"
        ),
        {"w": week},
    ):
        outcomes[assessor][label] = int(n)
    month = await conn.scalar(
        text(
            "SELECT coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >= date_trunc('month', :n)"
        ),
        {"n": now},
    )
    # count(*) and coalesce(...) are never NULL
    return Metrics(int(blocks), calls, int(fallbacks), int(floor), backlog, dict(outcomes),
                   float(month))  # fmt: skip


def quota(state: Any, config: Any, now: datetime) -> list[tuple[str, str]]:
    """Each provider's and model's day limits against today's use (from the gateway's
    shared state and its configuration)."""
    from argus.llm import budget

    out = []
    for p in config.providers:
        for tier in p.models:
            for b in p.buckets(tier):
                w = state.windows.get(b.name, budget.Window()).at(now)
                lim = b.limits
                requests = f"{w.day_requests}" + (f" of {lim.rpd}" if lim.rpd else "")
                tokens = f"{w.day_tokens}" + (f" of {lim.tpd}" if lim.tpd else "")
                out.append((b.name, f"{requests} requests, {tokens} tokens"))
    return sorted(dict(out).items())


async def gateway(conn: AsyncConnection, now: datetime) -> tuple[list[tuple[str, str]], bool]:
    """The model gateway's day limits against today's use, and whether its kill switch is on;
    nothing when no gateway is configured here. Read on the request's own connection, in a
    savepoint, so a failure leaves the rest of the request's reads working (Q-A1 review F1)."""
    try:
        from argus.llm.providers import load_config
        from argus.llm.store import read_state

        async with conn.begin_nested():
            state = await read_state(conn)
        return quota(state, load_config(), now), bool(state.stopped)
    except Exception:  # no gateway configured here: the rest of the page still shows
        return [], False


async def cost(conn: AsyncConnection, now: datetime, cap_usd: float, paid_share: float,
               daily_cap_usd: float | None = None) -> dict[str, Any]:  # fmt: skip
    """The model spend for the cost bar: this month and today (UTC), per provider today, the
    cap, where normal work moves to the free providers, and the kill switch."""
    month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_usd, today_usd, calls = (
        await conn.execute(
            text(
                "SELECT coalesce(sum(cost_usd), 0), coalesce(sum(cost_usd) FILTER"
                " (WHERE at >= :d), 0), count(*) FILTER (WHERE at >= :d AND attempt > 0)"
                " FROM llm_calls WHERE at >= :m AND at <= :n"
            ),
            {"m": month, "d": day, "n": now},
        )
    ).one()
    providers = {
        p: {"today_usd": round(float(c), 6), "calls": int(n)}
        for p, c, n in await conn.execute(
            text(
                "SELECT provider, coalesce(sum(cost_usd), 0), count(*) FROM llm_calls"
                " WHERE at >= :d AND at <= :n AND attempt > 0 GROUP BY 1 ORDER BY 1"
            ),
            {"d": day, "n": now},
        )
    }
    stopped = await conn.scalar(
        text("SELECT (state ->> 'stopped')::boolean FROM llm_state WHERE name = 'gateway'")
    )
    return {
        "month_usd": round(float(month_usd), 6),
        "today_usd": round(float(today_usd), 6),
        "cap_usd": cap_usd,
        "paid_until_usd": round(cap_usd * paid_share, 2),
        "daily_cap_usd": daily_cap_usd,
        "calls_today": int(calls),
        "providers": providers,
        "stopped": bool(stopped),
        "at": now.isoformat(),
    }


@dataclass(frozen=True)
class Detail:
    """One assessor's newest assessment of an investigation, for its page (D-095)."""

    assessment_id: int
    assessor: str
    source: str
    status: str  # queued, running, proposed, no_decision, failed
    outcome: str | None
    confidence: float | None
    key: str
    reasons: tuple[str, ...]  # the plain ones: the explanation, why no proposal, the detail
    report: dict[str, Any] | None  # the investigator's run (answer, checks, specialists, ...)
    created_at: datetime
    finished_at: datetime | None
    reading: reading.Reading | None = None  # a no_decision run's reading, never a proposal


_DETAIL = re.compile(r"\d+ rounds, \d+ model calls")  # the run's numbers: in the report too
_HISTORY = """
SELECT DISTINCT ON (a.assessor) a.id, a.assessor, a.status, a.outcome, a.confidence,
       a.decided_by, a.reasons, a.created_at, a.finished_at
FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
WHERE a.investigation_id = :i
ORDER BY a.assessor, a.id DESC
"""


def _detail(row: Any) -> Detail:
    raw = row.reasons if isinstance(row.reasons, list) else []
    plain = tuple(str(r)[:600] for r in raw if not isinstance(r, dict)
                  and not _DETAIL.match(str(r)))[:8]  # fmt: skip
    report = next((r for r in raw if isinstance(r, dict)), None)
    return Detail(row.id, row.assessor, source_of(row.assessor), row.status,
                  row.outcome, row.confidence, key_of(row.decided_by), plain, report,
                  row.created_at, row.finished_at,
                  reading.of(report, [r for r in raw if isinstance(r, str)])
                  if row.status == "no_decision" else None)  # fmt: skip


async def history(conn: AsyncConnection, investigation_id: uuid.UUID) -> list[Detail]:
    """Each assessor's newest assessment at the investigation's current version, the
    investigator first."""
    out = [_detail(row) for row in await conn.execute(text(_HISTORY), {"i": investigation_id})]
    return sorted(out, key=lambda d: (not is_agent(d.assessor), d.assessor))


@dataclass(frozen=True)
class Shared:
    """The investigator's run on another investigation of the same pattern and IST day (AR2):
    shown as "same pattern as <id>". Display only: never this investigation's own assessment,
    so it is never accepted, scored, closed or written back for it."""

    source: uuid.UUID  # the investigation the run was made on
    earlier: bool  # ... which is this one, before it changed (the run is of an earlier version)
    detail: Detail


_SHARED = """
SELECT a.id, a.assessor, a.status, a.outcome, a.confidence, a.decided_by, a.reasons,
       a.created_at, a.finished_at, a.investigation_id AS source
FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version
WHERE s.investigation_id = :i AND a.status IN ('proposed', 'no_decision')
  AND NOT (a.investigation_id = s.investigation_id AND a.version = s.version)
ORDER BY (a.status = 'proposed') DESC, a.id DESC LIMIT 1
"""


async def shared(conn: AsyncConnection, investigation_id: uuid.UUID) -> Shared | None:
    """The finished run that covers this investigation's pattern today, made on another
    investigation (or on this one, before it changed), or None."""
    row = (await conn.execute(text(_SHARED), {"i": investigation_id})).first()
    if row is None:
        return None
    return Shared(row.source, row.source == investigation_id, _detail(row))


_VERDICTS = """
SELECT DISTINCT ON (a.investigation_id) a.investigation_id, a.assessor, a.status, a.outcome,
       a.confidence
FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
WHERE a.investigation_id = ANY(:ids)
ORDER BY a.investigation_id, (a.status = 'proposed') DESC, a.assessor LIKE 'agent%' DESC,
         a.id DESC
"""


async def verdicts(conn: AsyncConnection, ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any]]:
    """For a list of investigations, the assessment a reviewer most wants to see: a proposal
    first, the investigator's before the engine's."""
    rows = await conn.execute(text(_VERDICTS), {"ids": ids})
    return {
        r.investigation_id: {
            "assessor": r.assessor,
            "source": source_of(r.assessor),
            "status": r.status,
            "outcome": r.outcome,
            "confidence": r.confidence,
        }
        for r in rows
    }
