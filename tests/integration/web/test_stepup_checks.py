"""Q-C3: a step-up is an identity check. On the web's own login a wrong password at
``/stepup`` is recorded as a denied check, which voids the person's approvals (plan §7.1), and a
right one as a good check; the web running as the runtime login records nothing (it cannot
approve either) and step-ups still work."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.conftest import PASSWORD
from tests.integration.web.test_session_contract import Clock, browser, sign_in

pytestmark = pytest.mark.integration


async def _step_ups(engine: AsyncEngine) -> list[tuple[str, str, str]]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT outcome, purpose, provider FROM identity_checks ORDER BY id")
        )
        return [tuple(r) for r in rows.all()]  # type: ignore[misc]


async def test_a_step_up_on_the_webs_login_is_recorded_as_an_identity_check(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine, Clock()) as http:
        await sign_in(http)
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        wrong = await http.post("/stepup", data={"password": "not it at all", "csrf_token": csrf})
        assert wrong.status_code == 401
        done = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf})
        assert done.status_code == 303
    assert await _step_ups(seeded) == [("denied", "stepup", "local"), ("ok", "stepup", "local")]


async def test_a_step_up_on_the_runtime_login_records_nothing_and_still_works(
    seeded: AsyncEngine,
) -> None:
    async with browser(seeded, Clock()) as http:
        await sign_in(http)
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        done = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf})
        assert done.status_code == 303
        assert (await http.get("/api/v1/session")).json()["stepped_up_at"] is not None
    assert await _step_ups(seeded) == []
