"""The daily and weekly reports count notified cases apart from new work and list each such device
in the weekly report (AR4b, D-169 point 8): since when, days, alerts and their trend, notices sent,
blocks recorded."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import knownrun
from argus.cases.machine import RecordBlock
from argus.cases.service import CaseService
from argus.reporter import build, render
from argus.responder.machine import ist_day
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import (
    SERVERS,
    at,
    context,
    flag_server,
    make,
    notify,
    open_case,
)

pytestmark = pytest.mark.integration
LAST = at(6).date()
AS_AT = at(6, 12)


async def story(app: AsyncEngine, owner: AsyncEngine, people: dict[str, Person]) -> int:
    for ip in SERVERS:
        await flag_server(owner, ip, at(0))
    first = await make(owner, when=at(0, 10))
    second = await make(owner, when=at(1, 10))
    case = await open_case(app, people["asha"], [first, second])
    await notify(app, people["asha"], case, at(3, 9))
    await knownrun.run(app, context(), at(3, 10))
    await make(owner, when=at(4, 12))
    await make(owner, when=at(5, 12), rule="download")
    await knownrun.run(app, context(), at(5, 13))
    async with app.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["ravi"].actor(), case, RecordBlock("network team", "DNS", at(5, 14)),
            expected_version=None,
        )  # fmt: skip
    async with app.connect() as conn:
        found = await CaseService.start(conn)
        return (await found.get(case)).number  # type: ignore[union-attr]


async def test_the_weekly_report_lists_the_device_and_the_daily_report_counts_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    number = await story(app_engine, migrated_engine, people)
    async with build.snapshot(app_engine) as conn:
        weekly = await build.build(conn, "weekly", LAST, AS_AT)
        daily = await build.build(conn, "daily", at(5).date(), AS_AT)
    week = weekly.metrics()
    assert week["notified.cases"].value == 1
    assert week["notified.alerts"].value == 6  # the two later days, three alerts each
    assert week["notified.known"].value == 4  # the two it was told about and the two that came
    assert week["notified.changes_waiting"].value == 0
    assert week["notified.reminders_waiting"].value == 0
    assert week["notified.notices"].value == 1
    assert week["notified.blocks"].value == 1
    assert week["notified.stopped"].value == 0
    key = f"notified.case.{number}"
    assert week[f"{key}.since"].value == ist_day(at(3, 9))
    assert week[f"{key}.days"].value == 3
    assert week[f"{key}.alerts"].value == 6
    assert week[f"{key}.trend"].value in ("rising", "steady", "falling", "too few days to say")
    assert week[f"{key}.notices"].value == 1
    assert week[f"{key}.blocks"].value == 1
    text = render.text_of(weekly)
    assert "== Notified, still active ==" in text
    assert f"- Case {number}: alerts in the period: 6" in text
    assert f"- Case {number}: owner first told on:" in text
    day = daily.metrics()
    assert day["notified.cases"].value == 1
    assert day["notified.alerts"].value == 3  # only the day's own
    assert day["notified.notices"].value == 0  # told on another day
    assert day["notified.blocks"].value == 1
    assert not [k for k in day if k.startswith("notified.case.")]  # the daily report lists none


async def test_a_report_without_notified_cases_counts_zero_and_lists_none(
    app_engine: AsyncEngine,
) -> None:
    async with build.snapshot(app_engine) as conn:
        weekly = await build.build(conn, "weekly", LAST, AS_AT)
    metrics = weekly.metrics()
    assert metrics["notified.cases"].value == 0
    assert metrics["notified.alerts"].value == 0
    assert not [k for k in metrics if k.startswith("notified.case.")]
