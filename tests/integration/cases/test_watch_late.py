"""The still-active watch and a collector that was only late (D-321): a collector gap closed
within the hour whose hours a later reconciliation found complete leaves the day quiet; one not
yet checked waits for the next run; a long one stays a reason the day cannot be verified."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import watch
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import D0, H1, World, at, context

pytestmark = pytest.mark.integration


@pytest.fixture
def world(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> World:
    return World(migrated_engine, app_engine)


async def _lag(world: World, start: datetime, end: datetime) -> None:
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO coverage_gaps (kind, subject, start_at, end_at, detail)"
                " VALUES ('argus_collector_lag', 'alerts', :s, :e, 'lane_busy')"
            ),
            {"s": start, "e": end},
        )


async def _reconciled(world: World, started: datetime, first: datetime, last: datetime) -> None:
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO reconciliation_runs (started_at, finished_at, window_start,"
                " window_end, hours, hours_mismatched, recovered, missing_in_es, outcome)"
                " VALUES (:st, :st, :ws, :we, 24, 0, 0, 0, 'ok')"
            ),
            {"st": started, "ws": first, "we": last},
        )


async def _alerts_day(world: World, case_id: object, n: int) -> str | None:
    rows = await world.rows(case_id)  # type: ignore[arg-type]
    return rows.get((D0 + timedelta(days=n), watch.ALERTS, "", 0))


async def test_a_caught_up_collector_delay_leaves_the_day_quiet(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
    await _lag(world, at(1, 18, 19), at(1, 18, 31))  # checked: nothing missed
    await _reconciled(world, at(1, 19, 5), at(0, 19), at(1, 19))
    await _lag(world, at(2, 20, 2), at(2, 20, 14))  # not checked yet
    await world.run(context(None), at(3, 3))
    assert await _alerts_day(world, case_id, 1) == "quiet"
    assert await _alerts_day(world, case_id, 2) is None  # asked again on the next run
    await _reconciled(world, at(2, 21, 5), at(1, 21), at(2, 21))
    await world.run(context(None), at(3, 4))
    assert await _alerts_day(world, case_id, 2) == "quiet"


async def test_a_long_collector_gap_still_leaves_the_day_unverified(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
    await _lag(world, at(1, 18, 19), at(1, 20, 13))  # 1 h 54 min: an outage
    await _reconciled(world, at(1, 21, 5), at(0, 21), at(1, 21))
    await world.run(context(None), at(3, 3))
    assert await _alerts_day(world, case_id, 1) == "unverified"
