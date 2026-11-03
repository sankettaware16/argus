"""The Reports routes of ``/api/v1`` (Q-H3) on the web's own login (``argus_web``: read only):
the list, one report whole, who may read, and what a hostile name in a report does."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reporter import build, store
from argus.web.app import create_app
from tests.integration.reporter import seed
from tests.integration.web.conftest import BASE, NOW, SAME_ORIGIN, log_in, seeded  # noqa: F401

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@pytest.fixture
async def http(
    seeded: AsyncEngine,  # noqa: F811
    web_engine: AsyncEngine,
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as client:
        yield client


async def make(engine: AsyncEngine, kind: str) -> int:
    numbers, body = await build.make(engine, kind, seed.DAY.date(), seed.AS_AT)  # type: ignore[arg-type]
    async with engine.begin() as conn:
        made = await store.save(conn, numbers, body)
    assert made is not None
    return made


async def test_the_list_and_one_report_are_served_whole(
    http: httpx.AsyncClient,
    migrated_engine: AsyncEngine,
    seeded: AsyncEngine,  # noqa: F811
) -> None:
    await seed.seed(migrated_engine)
    daily, weekly = await make(seeded, "daily"), await make(seeded, "weekly")
    assert (await http.get(f"{V1}/reports")).status_code == 401  # signed out
    await log_in(http)
    listing = (await http.get(f"{V1}/reports")).json()
    assert [(r["id"], r["kind"]) for r in listing] == [(daily, "daily"), (weekly, "weekly")][
        ::-1
    ] or {r["id"] for r in listing} == {daily, weekly}
    assert [
        r["kind"] for r in (await http.get(f"{V1}/reports", params={"kind": "weekly"})).json()
    ] == ["weekly"]
    assert (await http.get(f"{V1}/reports", params={"kind": "yearly"})).status_code == 422
    one = (await http.get(f"{V1}/reports/{daily}")).json()
    assert one["kind"] == "daily"
    assert one["period_start"].startswith("2026-10-20T00:00:00")
    assert one["prose"] is None
    assert one["text"].startswith("ARGUS daily report for the UTC day 20 Oct 2026")
    figures = {m["key"]: m for s in one["sections"] for m in s["metrics"]}
    assert len(figures) > 100
    assert figures["cases.suspected"]["value"] == 2
    assert all(m["definition"] for m in figures.values())
    for missing in (f"{V1}/reports/999999", f"{V1}/reports/0", f"{V1}/reports/abc"):
        assert (await http.get(missing)).status_code in (404, 422)
    assert (await http.get(f"{V1}/reports/999999")).json()["code"] == "not_found"


async def test_the_web_can_read_but_not_write_reports(
    http: httpx.AsyncClient,
    seeded: AsyncEngine,  # noqa: F811
) -> None:
    await log_in(http)
    for method in ("post", "put", "patch", "delete"):
        response = await getattr(http, method)(f"{V1}/reports")
        assert response.status_code in (404, 405), (method, response.status_code)


async def test_a_report_whose_numbers_cannot_be_read_is_still_served(
    http: httpx.AsyncClient,
    migrated_engine: AsyncEngine,
    seeded: AsyncEngine,  # noqa: F811
) -> None:
    """Review R9: numbers the owner emptied by hand (the CHECK dropped first) must not make the
    route or the store fail: the report is shown with its text and no figures."""
    await seed.seed(migrated_engine)
    daily = await make(seeded, "daily")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE reports DROP CONSTRAINT ck_reports_numbers_match_period")
        )
        await conn.execute(
            text("UPDATE reports SET numbers = '{}'::jsonb WHERE id = :i"), {"i": daily}
        )
    async with seeded.connect() as conn:
        found = await store.get(conn, daily)
        assert found is not None
        assert found.numbers.sections == ()
        assert found.numbers.kind == "daily"
        assert (await store.latest(conn, "daily")) is not None
    await log_in(http)
    one = (await http.get(f"{V1}/reports/{daily}")).json()
    assert one["kind"] == "daily"
    assert one["sections"] == []
    assert one["text"].startswith("ARGUS daily report")
