"""R15: patterns reviewed together (only versions exactly as seen), coverage banners, the
rules registry columns, the glossary."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.reference import store as reference
from argus.web import auth
from argus.web.app import create_app
from tests.integration.context.test_generic import alert
from tests.integration.grouping.test_grouping import ingest
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration


@pytest.fixture
async def empty(app_engine: AsyncEngine) -> AsyncEngine:
    """No alerts, one reviewer."""
    async with app_engine.begin() as conn:
        await auth.add_user(conn, "asha", "Asha", PASSWORD)
    return app_engine


@pytest.fixture
async def saver(db_settings: Any, test_database: str, app_engine: AsyncEngine) -> Any:
    from argus.context.checkpoints import open_saver

    async with open_saver(db_settings, database=test_database) as checkpointer:
        yield checkpointer


async def investigate(engine: AsyncEngine, saver: AsyncPostgresSaver, docs: list[Any]) -> None:
    await ingest(engine, docs)
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
    worker = Worker(engine, saver, packs=default_registry(), clock=lambda: NOW)
    while await worker.run_once(limit=10):
        pass


@contextlib.asynccontextmanager
async def client(engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await http.post("/login", data={"username": "asha", "password": PASSWORD})
        yield http


def three_hosts() -> list[Any]:
    docs = []
    for n in range(3):
        d = alert(n + 1)
        d["_source"]["source"]["ip"] = f"10.0.1.{n}"
        docs.append(d)
    return docs


async def test_a_pattern_is_reviewed_together_and_changed_ones_are_left(
    empty: AsyncEngine, saver: AsyncPostgresSaver, web_engine: AsyncEngine
) -> None:
    await investigate(empty, saver, three_hosts())
    async with client(web_engine) as http:
        page = (await http.get("/patterns")).text
        assert "3 investigations" in page
        items = [v.split('"')[0] for v in page.split('name="items" value="')[1:]]
        assert len(items) == 3
        csrf = page.split('name="csrf_token" value="')[1].split('"')[0]
        stale = items[0].split(":")
        await ingest(empty, [alert(10)])  # one of them changes (a new alert): version + 1
        async with empty.begin() as conn:
            await conn.execute(
                text("UPDATE investigations SET version = version + 1 WHERE id = :i"),
                {"i": stale[0]},
            )
        refused = await http.post("/patterns/review", data={"items": items})
        assert refused.status_code == 403  # no CSRF token
        done = await http.post(
            "/patterns/review",
            data={"items": items, "csrf_token": csrf, "outcome": "benign_expected"},
        )
        assert "2 reviewed. 1 changed since you looked" in done.text
        bad = await http.post("/patterns/review", data={"items": ["nope"], "csrf_token": csrf})
        assert bad.status_code == 422
    async with empty.connect() as conn:
        reviews = (
            await conn.execute(text("SELECT count(*), min(outcome) FROM review_events"))
        ).one()
    assert tuple(reviews) == (2, "benign_expected")


async def test_banners_rules_and_glossary(
    empty: AsyncEngine, saver: AsyncPostgresSaver, web_engine: AsyncEngine
) -> None:
    ran = (NOW - timedelta(minutes=49)).isoformat()
    extra = {
        "kibana.alert.rule.max_signals": 2,
        "kibana.alert.rule.execution.uuid": "full",
        "kibana.alert.rule.execution.timestamp": ran,
    }
    docs = [alert(n, **extra) for n in range(2)]
    await investigate(empty, saver, docs)
    async with client(web_engine) as http:
        (inv,) = (await http.get("/api/investigations", params={"view": "all"})).json()
        page = (await http.get(f"/investigations/{inv['id']}")).text
        assert "Alerts may be missing" in page
        assert "the rule hit its alert limit" in page
        rules = (await http.get("/rules")).text
        assert "Runs at the limit" in rules
        glossary = (await http.get("/glossary")).text
        assert "Not checked yet" in glossary
        assert "Alerts" in glossary
