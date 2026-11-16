"""Shared helpers of the web suites (an app on the web login, investigations through the context
worker) and the coverage banners and rules registry columns (R15)."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
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
