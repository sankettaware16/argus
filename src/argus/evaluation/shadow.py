"""The shadow: a model answers live items for one helper task, and its answers are stored in
``llm_shadow``, never shown (no page or API reads the table). They serve the evaluation ladder only.

Live items are the newest dossiers not yet answered by this model for this task, each sent through
``taskrun`` as an evaluation call. ``fallback`` takes only items the agent would route to its small
tier and without a floor signal. The row keeps the answer pseudonymized, with production's outcome.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assess import engine
from argus.evaluation import ladder, taskrun, tasks
from argus.llm.gateway import NoCapacity
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig

MAX_ANSWER = 16_000  # characters of a stored answer (the table refuses more than 20,000)
SCAN, MAX_SCAN = 20, 2_000  # live items looked at per place in a run, and at most

_LIVE = """
SELECT d.investigation_id, d.version, d.pack, d.dossier_hash, d.body,
       COALESCE(
         (SELECT r.outcome FROM review_events r WHERE r.investigation_id = d.investigation_id
            AND r.outcome IS NOT NULL ORDER BY r.id DESC LIMIT 1),
         (SELECT a.outcome FROM assessments a WHERE a.investigation_id = d.investigation_id
            AND a.status = 'proposed' ORDER BY a.id DESC LIMIT 1)) AS reference
FROM (SELECT DISTINCT ON (investigation_id) * FROM dossiers
      WHERE created_at >= :since ORDER BY investigation_id, version DESC, created_at DESC) d
WHERE NOT EXISTS (SELECT 1 FROM llm_shadow s WHERE s.investigation_id = d.investigation_id
                    AND s.dossier_hash = d.dossier_hash AND s.task = :task
                    AND s.prompt = :prompt AND s.provider = :provider AND s.model = :model)
ORDER BY d.created_at DESC, d.investigation_id
LIMIT :limit
"""

_INSERT = """
INSERT INTO llm_shadow (investigation_id, version, pack, dossier_hash, task, prompt, provider,
                        model, usable, ok, outcome, floor, reference, detail, answer,
                        latency_ms, lease_ms, input_tokens, output_tokens)
VALUES (:investigation_id, :version, :pack, :dossier_hash, :task, :prompt, :provider, :model,
        :usable, :ok, :outcome, :floor, :reference, CAST(:detail AS jsonb),
        CAST(:answer AS jsonb), :latency_ms, :lease_ms, :input_tokens, :output_tokens)
ON CONFLICT DO NOTHING
"""


@dataclass(frozen=True)
class LiveItem:
    case: taskrun.TaskCase
    reference: str | None
    first_seen: bool | None
    spike: bool | None


async def live_items(
    conn: AsyncConnection,
    spec: tasks.TaskSpec,
    provider: str,
    model: str,
    since: datetime,
    limit: int,
) -> list[LiveItem]:
    rows = await conn.execute(text(_LIVE), {"since": since, "task": spec.task,
                                            "prompt": spec.prompt, "provider": provider,
                                            "model": model, "limit": limit})  # fmt: skip
    out = []
    for iid, version, pack, digest, body, reference in rows.all():
        first_seen = await engine.first_seen(conn, iid)
        spike = await engine.spike(conn, iid)
        floor = taskrun.floor_of(body, first_seen, spike)
        case = taskrun.TaskCase(iid, version, pack, digest, body, floor)
        out.append(LiveItem(case, reference, first_seen, spike))
    return out


@dataclass
class ShadowRun:
    stored: int = 0
    asked_unstored: int = 0  # asked, but another run had stored the item meanwhile
    usable: int = 0
    skipped: int = 0  # not sendable (privacy check), too large, or not the fallback's items
    stopped: str | None = None


def _answer(text_: str | None) -> str | None:
    """The answer as stored: the JSON object as it came back, or None."""
    if text_ is None:
        return None
    try:
        data = json.loads(text_.strip())
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    dumped = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return dumped if len(dumped) <= MAX_ANSWER else None


async def run(
    db: AsyncEngine,
    spec: tasks.TaskSpec,
    privacy: Privacy,
    complete: taskrun.Complete,
    config: LlmConfig,
    provider: str,
    model: str,
    since: datetime,
    limit: int,
    max_wait_s: float = 120.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.time,
) -> ShadowRun:
    """Answer up to ``limit`` live items in shadow; stops (to resume next time) when the
    evaluation budget or window says to wait longer than ``max_wait_s``. Items it cannot ask
    (not sendable, too large, not the fallback's) are not stored, so it looks further than
    ``limit`` for them: otherwise the newest of them would take every run's places."""
    async with db.connect() as conn:
        items = await live_items(conn, spec, provider, model, since, min(limit * SCAN, MAX_SCAN))
    out = ShadowRun()
    for item in items:
        if out.stored + out.asked_unstored >= limit:
            break
        case = item.case
        request = taskrun.render(privacy, case.body)
        if request is None:
            out.skipped += 1
            continue
        if spec.task == tasks.FALLBACK:  # small-tier items without floor signals
            reasons = engine.floor(case.body, item.first_seen, item.spike)
            if reasons or not taskrun.small_tier(case.body, reasons, request):
                out.skipped += 1
                continue
        call = taskrun.call_for(spec, case.body, request)
        if not taskrun.fits(config, call):
            out.skipped += 1
            continue
        answer = await taskrun.ask(call, complete, config, max_wait_s, sleep, clock)
        if isinstance(answer, NoCapacity):
            out.stopped = f"no capacity until {answer.until:%Y-%m-%d %H:%M} UTC"
            return out
        check = tasks.Check(False)
        if answer.text is not None:
            # production's outcome then stands in for a label: a true positive is never
            # "later" and never benign (triage, the fallback)
            label = item.reference if spec.task in (tasks.TRIAGE, tasks.FALLBACK) else None
            check = tasks.check(spec.task, answer.text, request.text, case.floor, label)
        stored = _answer(answer.text) if check.usable else None
        if check.usable and stored is None:  # too long to keep: counted as unusable
            check = tasks.Check(False)
        row: dict[str, Any] = {
            "investigation_id": case.investigation_id, "version": case.version,
            "pack": case.pack, "dossier_hash": case.dossier_hash, "task": spec.task,
            "prompt": spec.prompt, "provider": provider, "model": model,
            "usable": check.usable, "ok": check.ok if check.usable else None,
            "outcome": check.outcome, "floor": case.floor, "reference": item.reference,
            "detail": json.dumps(check.detail), "answer": stored,
            "latency_ms": round(answer.seconds * 1000), "lease_ms": round(answer.lease_s * 1000),
            "input_tokens": answer.input_tokens, "output_tokens": answer.output_tokens,
        }  # fmt: skip
        async with db.begin() as conn:
            done = await conn.execute(text(_INSERT), row)
        out.asked_unstored += 1 - done.rowcount  # another run stored it meanwhile
        out.stored += done.rowcount
        out.usable += int(check.usable and done.rowcount == 1)
        if answer.wait is not None:  # the model failed it (stored as unusable): wait or stop
            delay = answer.wait.until.timestamp() - clock()
            if delay > max_wait_s:
                out.stopped = f"no capacity until {answer.wait.until:%Y-%m-%d %H:%M} UTC"
                return out
            await sleep(max(delay, 1.0))
    return out


_MEASURE = """
SELECT count(DISTINCT investigation_id), count(*), count(*) FILTER (WHERE usable),
       count(*) FILTER (WHERE usable AND ok IS FALSE)
FROM llm_shadow WHERE task = :task AND provider = :provider AND model = :model
"""
_LATENCY = """
SELECT latency_ms, lease_ms FROM llm_shadow
WHERE task = :task AND provider = :provider AND model = :model AND (usable OR lease_ms > 0)
ORDER BY id
"""  # every call that reached the model, answered or not


async def measure(conn: AsyncConnection, task: str, provider: str, model: str
                  ) -> ladder.Shadow | None:  # fmt: skip
    """The ladder's shadow rung: counts only, never an answer."""
    args = {"task": task, "provider": provider, "model": model}
    items, total, usable, failed = (await conn.execute(text(_MEASURE), args)).one()
    if not total:
        return None
    latency = tuple((ms / 1000, lease / 1000) for ms, lease in await conn.execute(
        text(_LATENCY), args))  # fmt: skip
    return ladder.Shadow(items=items, calls=ladder.Count(hits=usable, total=total),
                         failed=failed, latency=latency)  # fmt: skip


def since_hours(now: datetime, hours: float) -> datetime:
    return now - timedelta(hours=hours)
