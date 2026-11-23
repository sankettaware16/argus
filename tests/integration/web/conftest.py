"""The Inbox under test: the real app on a throwaway database, logged in as a throwaway web login
(``argus_web``'s grants only), seeded as the runtime role through the real collector store
and grouper, with two reviewers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import auth
from argus.web.app import create_app
from tests.integration.grouping.test_grouping import doc, ingest

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
BASE = "http://127.0.0.1"
SAME_ORIGIN = {"Origin": BASE}  # every change needs it (Q-A1); browsers send it themselves
PASSWORD = "correct horse battery"
# the throttle's waits and the padded answer of a failed sign-in (Q-E2) off, for tests that make
# several failures in a row
FAST = WebSettings(failure_delay_s=0, signin_delay_s=0)


@pytest.fixture
async def seeded(app_engine: AsyncEngine) -> AsyncEngine:
    docs = [doc(n, f"rule-{n % 3}", f"10.0.0.{n % 4}", NOW - timedelta(minutes=37 * n))
            for n in range(24)]  # fmt: skip
    for d in docs[:6]:
        d["_source"]["kibana.alert.severity"] = "high"
    await ingest(app_engine, docs)
    async with app_engine.begin() as conn:
        await auth.add_user(conn, "asha", "Asha", PASSWORD)
        await auth.add_user(conn, "ravi", "Ravi", PASSWORD)
    return app_engine


@pytest.fixture
async def client(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    """The app on the web's own login (argus_web's grants only), over the seeded data."""
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        yield http


def to_signin(path: str) -> str:
    """Where a signed-out request goes (Q-A1): the sign-in page, then back to ``path`` (a
    form's page is its path without the action)."""
    return "/signin" if path == "/" else "/signin?" + urlencode({"next": path})


async def log_in(http: httpx.AsyncClient, user: str = "asha") -> str:
    """Log in through the API; returns the CSRF token."""
    response = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert response.status_code == 200, response.text
    token: str = response.json()["csrf_token"]
    return token


async def first_investigation(http: httpx.AsyncClient) -> dict[str, Any]:
    response = await http.get("/api/investigations", params={"view": "all"})
    assert response.status_code == 200
    found: dict[str, Any] = response.json()[0]
    return found
