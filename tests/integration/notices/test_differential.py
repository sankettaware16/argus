"""The pass against its own rules (Q-H4): for many random histories (things that appear, change
severity and go away, 10 minutes apart, across kinds), the e-mails the real pass sends through a
real SMTP conversation, with the table and the audit trail as its memory, are exactly the
e-mails an in-memory model of the same rules says it should send: same order, same words, never
more than 10 an hour. A restart (a new engine) in the middle changes nothing."""

from __future__ import annotations

import random
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import SEVERITIES, Severity
from argus.db.engine import create_engine
from argus.notices import model, render, run
from argus.notices.model import Condition, Intent, Row, Target
from argus.notices.triggers import Found
from tests.fakesmtp import FakeSmtp
from tests.integration.notices.conftest import BASE, config_for

pytestmark = pytest.mark.integration

CASE = uuid.UUID("11111111-1111-4111-8111-111111111111")
SMALL = [("case_active", "a"), ("closure_waiting", "b"), ("outage", "siem"), ("ioc_hit", "c")]
CROWD = [
    *(
        (kind, f"{kind[:2]}{n:02d}")
        for n in range(8)
        for kind in ("case_active", "closure_waiting")
    ),
    ("outage", "siem"),
    ("outage", "watch"),
    ("ioc_hit", "c"),
]
# (keys, minutes between passes): quick passes, passes far enough apart for reminders and ends
SHAPES = [(SMALL, 10), (SMALL, 90), (CROWD, 10), (CROWD, 90)]
SEEDS = range(24)
STEPS = 40


class Memory:
    """The rules, in memory: what a pass does with ``reconcile`` and ``allocate``, rows kept in a
    dict, the hour's count from its own log of e-mails."""

    def __init__(self) -> None:
        self.live: dict[tuple[str, str], Row] = {}
        self.over: list[Row] = []
        self.ids = 0
        self.log: list[datetime] = []
        self.subjects: list[str] = []

    def step(self, now: datetime, conditions: list[Condition]) -> None:
        pending = [r for r in self.over if r.sent_at is not None and r.ended_at is None]
        rec = model.reconcile(self.live.values(), pending, conditions, now)
        for s in rec.steps:
            d = s.decision
            if d.store == "insert":
                self.ids += 1
                assert d.severity is not None
                assert d.first_seen is not None
                self.live[s.key] = Row(self.ids, s.key[0], s.key[1], d.severity,  # type: ignore[arg-type]
                                       d.count, d.first_seen, now)  # fmt: skip
            elif d.store == "update" and s.key in self.live:
                assert d.severity is not None
                self.live[s.key] = replace(
                    self.live[s.key], severity=d.severity, count=d.count, last_seen=now
                )
            elif d.store == "resolve" and s.key in self.live:
                self.over.append(replace(self.live.pop(s.key), resolved_at=now))
        room = model.MAX_PER_HOUR - sum(1 for t in self.log if t > now - timedelta(hours=1))
        alloc = model.allocate(rec.intents, room)
        for intent in alloc.send:
            self.subjects.append(render.render(intent, BASE).subject)
            self.log.append(now)
        if alloc.folded:
            self.subjects.append(render.render_more(alloc.folded, BASE).subject)
            self.log.append(now)
        for intent in (*alloc.send, *alloc.folded):
            self._mark(intent, now)

    def _mark(self, intent: Intent, now: datetime) -> None:
        if intent.reason == "ended":
            for index, row in enumerate(self.over):
                if row.id == intent.row_id:
                    self.over[index] = replace(row, ended_at=now)
            return
        row = self.live[intent.key]
        self.live[intent.key] = replace(
            row, sent_at=now, sent_severity=intent.severity, notified=row.notified + 1
        )


Wanted = tuple[str, str, Severity, int, int | None]  # kind, subject, severity, count, hours ago


def history(seed: int) -> list[list[Wanted]]:
    rng = random.Random(seed)
    keys = SHAPES[seed % len(SHAPES)][0]
    present = {k: rng.random() < 0.5 for k in keys}
    out: list[list[Wanted]] = []
    for _ in range(STEPS):
        step: list[Wanted] = []
        for key in keys:
            if rng.random() < 0.15:
                present[key] = not present[key]
            if present[key]:
                ago = rng.randint(0, 3) if key[0] == "outage" and rng.random() < 0.4 else None
                step.append((*key, rng.choice(SEVERITIES), rng.randint(0, 9), ago))
        out.append(step)
    return out


def conditions_at(now: datetime, step: list[Wanted]) -> list[Condition]:
    return [
        Condition(
            kind,  # type: ignore[arg-type]
            subject,
            severity,
            count,
            Target("health") if kind == "outage" else Target("case", CASE),
            None if ago is None else now - timedelta(hours=ago),
        )
        for kind, subject, severity, count, ago in step
    ]


@pytest.mark.parametrize("seed", SEEDS)
async def test_the_real_pass_sends_exactly_what_the_rules_say(
    seed: int, app_engine: AsyncEngine, migrated_engine: AsyncEngine, db_settings: object,
    test_database: str,
) -> None:  # fmt: skip
    base = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
    memory = Memory()
    engine = app_engine
    with FakeSmtp() as server:
        cfg = config_for(server)
        for index, step in enumerate(history(seed)):
            now = base + timedelta(minutes=SHAPES[seed % len(SHAPES)][1] * index)
            conditions = conditions_at(now, step)
            memory.step(now, conditions)
            await run.run(engine, cfg, Found(conditions, set()), now=now)
            if index == STEPS // 2:  # the process restarts: a new engine, the same database
                fresh = create_engine(db_settings, database=test_database)  # type: ignore[arg-type]
                if engine is not app_engine:
                    await engine.dispose()
                engine = fresh
            got = [dict(m.headers)["Subject"] for m in server.received]
            assert got == memory.subjects, (seed, index)
        if engine is not app_engine:
            await engine.dispose()
    async with migrated_engine.connect() as conn:
        live = (
            await conn.execute(text("SELECT count(*) FROM notices WHERE resolved_at IS NULL"))
        ).scalar_one()
    assert live == len(memory.live)
    per_hour = [sum(1 for t in memory.log if s <= t < s + timedelta(hours=1)) for s in memory.log]
    assert max(per_hour, default=0) <= model.MAX_PER_HOUR


def test_the_histories_exercise_every_rule() -> None:
    """The comparison above means something only if the histories reach each rule: a first
    notice, a rise, a reminder, an outage and its end, and an hour that could not take them all."""
    subjects: list[str] = []
    for seed in SEEDS:
        memory = Memory()
        for index, step in enumerate(history(seed)):
            now = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
            now += timedelta(minutes=SHAPES[seed % len(SHAPES)][1] * index)
            memory.step(now, conditions_at(now, step))
        subjects += memory.subjects
    text_ = "\n".join(subjects)
    assert "Still waiting" in text_
    assert "more notices" in text_
    assert "The earlier outage is over" in text_
    assert "ARGUS cannot watch everything" in text_
    assert "[ARGUS Critical]" in text_
    assert len(subjects) > 300
