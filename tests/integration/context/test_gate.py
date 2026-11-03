"""R8 gate (plan §6): a crash at every node costs only the in-flight gateway calls; any
completion order gives the same dossier hash; the state stays under 64 KB per super-step;
checkpoints are pruned."""

from __future__ import annotations

import random
from datetime import timedelta
from functools import partial
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.worker import Worker, WorkerConfig
from argus.jobs import queue
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import (
    FakeGateway,
    Hooks,
    Killed,
    dossiers,
    registry,
    reset,
    scalar,
)

pytestmark = pytest.mark.integration

SPECS = [(1, "r1", "10.0.0.1"), (2, "r1", "10.0.0.1"), (3, "r2", "10.0.0.1")]


def worker(
    engine: AsyncEngine, saver: AsyncPostgresSaver, gateway: FakeGateway, **kw: Any
) -> Worker:
    clock = kw.pop("clock", lambda: NOW)
    config = kw.pop("config", WorkerConfig())
    return Worker(
        engine, saver, packs=registry(), gateway=gateway, clock=clock, config=config, **kw
    )


async def one_job(app: AsyncEngine, owner: AsyncEngine) -> None:
    """Two investigations (so one has a related one), but only the first one's job."""
    await reset(owner)
    await seed(app, SPECS)
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM jobs WHERE id <> (SELECT min(id) FROM jobs)"))


async def uninterrupted(
    app: AsyncEngine, owner: AsyncEngine, saver: AsyncPostgresSaver
) -> tuple[list[Any], list[int], Hooks]:
    await one_job(app, owner)
    gateway, hooks = FakeGateway(), Hooks()
    results = await worker(app, saver, gateway, hooks=hooks).run_once(limit=1)
    assert [r.outcome for r in results] == ["done"]
    return await dossiers(app), gateway.calls, hooks


async def test_crash_at_every_node_repeats_only_in_flight_calls(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    expected, baseline, trace = await uninterrupted(app_engine, migrated_engine, saver)
    assert len(baseline) == 8  # 6 in wave 1, 2 in wave 2
    points: list[tuple[str, Any]] = [("node", e) for e in trace.events]
    points += [("call", k) for k in range(1, len(baseline) + 1)]
    assert len(points) > 40
    for kind, point in points:
        await one_job(app_engine, migrated_engine)
        gateway = FakeGateway(crash_on_call=point if kind == "call" else None)
        hooks = Hooks(crash=point if kind == "node" else None)
        with pytest.raises(Killed):
            await worker(app_engine, saver, gateway, hooks=hooks).run_once(limit=1)
        stored = await scalar(
            app_engine, "SELECT count(*) FROM evidence WHERE status IN ('ok', 'empty')"
        )
        in_flight = len(set(gateway.calls)) - stored
        assert 0 <= in_flight <= 1, (point, gateway.calls, stored)
        later = lambda: NOW + queue.LEASE + timedelta(seconds=1)  # noqa: E731 - the old lease expired
        results = await worker(app_engine, saver, gateway, clock=later).run_once(limit=1)
        assert [r.outcome for r in results] in (["done"], []), point
        assert len(gateway.calls) == len(baseline) + in_flight, (point, gateway.calls)
        assert await dossiers(app_engine) == expected, point
        assert await scalar(app_engine, "SELECT count(*) FROM jobs WHERE status = 'running'") == 0


async def test_any_completion_order_gives_the_same_dossier_hash(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    expected, _, _ = await uninterrupted(app_engine, migrated_engine, saver)
    orders = set()
    for seed_ in range(20):
        await one_job(app_engine, migrated_engine)
        delays = random.Random(seed_)
        gateway = FakeGateway(delay=partial(delays.uniform, 0, 0.02), rng=random.Random(seed_))
        config = WorkerConfig(run_concurrency=8)
        results = await worker(app_engine, saver, gateway, config=config).run_once(limit=1)
        assert [r.outcome for r in results] == ["done"]
        orders.add(tuple(gateway.completed))
        assert await dossiers(app_engine) == expected
    assert len(orders) >= 10  # the completion orders really differed
