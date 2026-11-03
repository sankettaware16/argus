"""Q-F3: the gold measurement run live against a fake gateway: the engine's answer before and
after the wave, paired and repeated; nothing is stored but the evidence a wave stores; a true
positive proposed benign is found."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.investigation import measure
from tests.integration.investigation.kit import FakeGateway, body, env, healthy, seed
from tests.integration.investigation.test_cli import gold
from tests.unit.investigation.kit import step

pytestmark = pytest.mark.integration
TIMELINE = [step(2, "deferred", ["timeline"])]


def decides_once_the_timeline_is_answered(
    monkeypatch: pytest.MonkeyPatch, outcome: str = "benign_expected"
) -> None:
    def decide(body_: dict[str, Any], *_: Any) -> Any:
        steps = (body_.get("report") or {}).get("steps") or []
        answered = bool(steps) and all(s["status"] == "answered" for s in steps)
        return SimpleNamespace(outcome=outcome if answered else None)

    monkeypatch.setattr(measure.decision, "decide", decide)


async def count(engine: AsyncEngine, table: str) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())  # noqa: S608


async def seeded(owner: AsyncEngine) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    a = await seed(owner, body(steps=TIMELINE))
    b = await seed(owner, body(steps=TIMELINE))
    c = await seed(owner, body())
    await gold(owner, {a: "benign_expected", b: "true_positive", c: "benign_policy"})
    return a, b, c


async def test_the_wave_arm_is_measured_paired_and_repeated(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, b, c = await seeded(migrated_engine)
    decides_once_the_timeline_is_answered(monkeypatch)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    async with app_engine.connect() as conn:
        got = await measure.measure(e, conn, repeats=2, live=True, split=None)
    assert got.before == {str(a): None, str(b): None, str(c): None}
    assert [len(x) for x in got.after] == [3, 3]
    assert got.after[0] == got.after[1] == {str(a): "benign_expected", str(b): "benign_expected",
                                             str(c): None}  # fmt: skip
    assert len(gateway.calls) == 2  # one per item that had something to ask; the repeat asks none
    first = measure.compare(got.answers, got.before, got.after[0])
    assert (first.gained, first.gained_right, first.lost, first.changed) == (2, 1, 0, 0)
    assert first.tp_benign_after == (str(b),)  # the gate's one condition, found
    assert not first.holds
    text_ = "\n".join(measure.report(got))
    assert "the repeats agree item by item: yes" in text_
    assert "true positives proposed benign after (must be 0): 1" in text_
    # the dossiers the wave would leave are not stored; its evidence is
    assert await count(app_engine, "dossiers") == 3
    assert await count(app_engine, "evidence") == 2


async def test_when_the_gate_holds_no_true_positive_is_proposed_benign(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seeded(migrated_engine)
    decides_once_the_timeline_is_answered(monkeypatch, "true_positive")
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        got = await measure.measure(e, conn, repeats=1, live=True, split=None)
    cmp = measure.compare(got.answers, got.before, got.after[0])
    assert cmp.holds
    assert cmp.gained_right == 1  # b's true positive is right, a's is not
    assert measure.compare(got.answers, got.before, None).holds


async def test_the_dry_run_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await seeded(migrated_engine)
    gateway = FakeGateway(healthy())
    async with app_engine.connect() as conn:
        got = await measure.measure(env(app_engine, gateway), conn, live=False, split=None)
    assert got.after == []
    assert gateway.calls == []
    assert sorted(p.requests for p in got.plans) == [0, 1, 1]
    assert await count(app_engine, "evidence") == 0


async def test_a_persons_answer_never_chooses_the_checks_of_the_measurement(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The gold set's answers are the answer key: a reviewer's true positive on an item must not
    give it a scope check the other items do not get."""
    a = await seed(migrated_engine, body(steps=TIMELINE))
    await gold(migrated_engine, {a: "true_positive"})
    async with migrated_engine.begin() as conn:
        user = (await conn.execute(text("SELECT id FROM users LIMIT 1"))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 4, :u, 'reviewed', 'true_positive')"
            ),
            {"i": a, "u": user},
        )
    async with app_engine.connect() as conn:
        got = await measure.measure(env(app_engine, FakeGateway(healthy())), conn, split=None)
    (plan,) = got.plans
    assert plan.requests == 1  # the timeline step's check; no scope check for a "true positive"
