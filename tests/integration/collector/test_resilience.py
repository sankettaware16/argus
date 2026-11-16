"""R5 gate: random sequences of writes (late, equal timestamps), clock jumps, polls,
reconciliations and backfill steps, each run possibly crashing at any checkpoint or wire call;
afterwards one clean poll and reconciliation leave the store holding exactly the SIEM's alerts,
never a duplicate. And the runner's outage handling: a 3-hour outage leaves the cursor, opens
one gap, and recovery closes it and reconciles."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import collector as co
from argus.collector.runner import Runner
from argus.gateway.errors import GatewayError, TransportFailedError
from tests.integration.collector.fake_es import FakeAlertsES
from tests.integration.collector.test_collector import (
    HOUR,
    MIN,
    NOW,
    aid,
    build,
    cursor,
    stored,
)

pytestmark = pytest.mark.integration


class CrashError(Exception):
    """A process dying at an await (the test's stand-in for SIGKILL)."""


Crashes = st.none() | st.tuples(st.sampled_from(["db", "wire"]), st.integers(1, 4))
OPS = st.one_of(
    st.tuples(st.just("write"), st.integers(0, 600), st.booleans(), st.booleans()),
    st.tuples(st.just("reveal")),
    st.tuples(st.just("advance"), st.integers(0, 90)),
    st.tuples(st.just("poll"), Crashes),
    st.tuples(st.just("reconcile"), Crashes),
    st.tuples(st.just("backfill"), Crashes),
)


async def _reset(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE alert_records, collector_cursors, reconciliation_runs, coverage_gaps"
                " CASCADE"
            )
        )


@settings(
    max_examples=max(30, settings().max_examples // 5),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(ops=st.lists(OPS, min_size=1, max_size=40))
async def test_any_crash_sequence_converges_to_exactly_siems_alerts(
    ops: list[tuple[Any, ...]],
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(co, "PAGE", 4)  # many pages, many awaits
    monkeypatch.setattr(co, "MGET", 3)
    await _reset(migrated_engine)
    es = FakeAlertsES()
    counter = {"db": 0, "wire": 0}
    crash: list[tuple[str, int] | None] = [None]

    async def checkpoint(name: str) -> None:
        counter["db"] += 1
        if crash[0] is not None and crash[0][0] == "db" and counter["db"] == crash[0][1]:
            raise CrashError(name)

    def wire(request: Any) -> None:
        counter["wire"] += 1
        if crash[0] is not None and crash[0][0] == "wire" and counter["wire"] == crash[0][1]:
            raise CrashError(request.path)

    es.before = wire
    collector, clock = build(es, app_engine, checkpoint=checkpoint)
    collector.window = timedelta(hours=12)
    written = 0
    for op in ops:
        kind = op[0]
        if kind == "write":
            _, back, same, hidden = op
            at = clock.now - timedelta(seconds=0 if same else back)
            es.add(aid(written), at, rule=f"rule-{written % 3}", visible=not hidden)
            written += 1
        elif kind == "reveal":
            for doc in es.docs.values():
                doc.visible = True
        elif kind == "advance":
            clock.advance(timedelta(minutes=op[1]))
        else:
            counter.update(db=0, wire=0)
            crash[0] = op[1]
            job = {"poll": collector.poll,
                   "reconcile": lambda: collector.reconcile(clock.now - 12 * HOUR, clock.now),
                   "backfill": collector.backfill_step}[kind]  # fmt: skip
            try:
                await job()
                event(f"{kind}: completed")
            except CrashError:
                event(f"{kind}: crashed")
            except GatewayError as exc:
                event(f"{kind}: refused ({exc.reason})")
            crash[0] = None
            held = await stored(app_engine)
            assert set(held) <= set(es.docs)  # never an alert the SIEM does not have
    for doc in es.docs.values():
        doc.visible = True
    await collector.poll()
    await collector.reconcile(clock.now - 12 * HOUR, clock.now + HOUR)
    held = await stored(app_engine)
    live = {i for i, d in es.docs.items() if d.at >= clock.now - 12 * HOUR}
    assert live <= set(held)
    assert set(held) <= set(es.docs)
    async with app_engine.connect() as conn:
        total = (await conn.execute(text("SELECT count(*) FROM alert_records"))).scalar_one()
    assert total == len(held)  # the primary key: never twice


async def test_an_outage_opens_one_gap_and_recovery_reconciles(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)
    probes: list[Any] = []

    async def probe() -> None:
        probes.append(clock.now)

    runner = Runner(collector, probe, backfill_done=True)
    await runner.step()
    assert await cursor(app_engine) == NOW

    def down(request: Any) -> None:
        raise TransportFailedError("reset", retriable=False)

    es.before = down
    for _ in range(180):
        clock.advance(MIN)
        es.before = None
        es.add(aid(len(es.docs)), clock.now - timedelta(seconds=30))
        es.before = down
        await runner.step()
    assert await cursor(app_engine) == NOW
    async with app_engine.connect() as conn:
        gaps = (await conn.execute(text("SELECT kind, start_at, end_at FROM coverage_gaps"))).all()
    assert gaps == [("argus_collector_lag", NOW, None)]
    es.before = None
    clock.advance(MIN)
    recovered = clock.now  # the poll's time: later jobs of the step may wait for the budget
    await runner.step()
    async with app_engine.connect() as conn:
        gaps = (await conn.execute(text("SELECT kind, end_at FROM coverage_gaps"))).all()
    assert gaps == [("argus_collector_lag", recovered)]
    assert set(await stored(app_engine)) == es.ids()
    clock.advance(MIN)
    await runner.step()  # the reconciliation the recovery scheduled
    async with app_engine.connect() as conn:
        runs = (await conn.execute(text("SELECT window_start FROM reconciliation_runs"))).all()
    assert runs
    assert len(probes) == 183
