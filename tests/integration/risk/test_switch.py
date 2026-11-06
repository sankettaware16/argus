"""``risk.present`` in the assessment service (P4-F E5): on, with a presenter pass (``argus risk
run``) recorded within ``present.ALIVE``, the old suggester is not asked and the switch stays
recorded for the queue's pages (so the old raise stops feeding Needs attention); on with no
recent presenter pass, the old feeds stay on and that is said (the queue never goes silent with
nothing presenting); off again, the suggester is asked as before and the raise comes back. One
setting switches back. ``argus assess run --once`` with a fake gateway in place of the SIEM."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus import raising
from argus.cli import app
from argus.risk import present
from tests.integration.investigation.test_assess_loop import service  # noqa: F401
from tests.integration.test_cli_db import cli_env  # noqa: F401

pytestmark = pytest.mark.integration


async def run_once() -> tuple[int, str]:
    def invoke() -> tuple[int, str]:
        result = CliRunner().invoke(app, ["assess", "run", "--once"])
        return result.exit_code, result.output + result.stderr

    return await asyncio.to_thread(invoke)


@pytest.mark.usefixtures("cli_env", "service")
async def test_the_switch_stops_the_old_suggester_and_one_setting_brings_it_back(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[bool] = []
    real = raising.run

    async def recording(*args: Any, **kwargs: Any) -> raising.Done:
        asked.append(bool(kwargs["suggesting"]))
        return await real(*args, **kwargs)

    monkeypatch.setattr("argus.raising.run", recording)

    async def mode() -> bool | None:
        async with app_engine.connect() as conn:
            found = (await conn.execute(text("SELECT present FROM risk_mode"))).scalar_one_or_none()
        return None if found is None else bool(found)

    async def presenter_pass(at: datetime) -> None:
        async with app_engine.begin() as conn:
            await present.record_mode(conn, True, at)

    monkeypatch.setenv("ARGUS_RISK__PRESENT", "true")
    code, out = await run_once()  # nothing presents yet: the old feeds stay on, and it is said
    assert code == 0, out
    assert asked == [True]
    assert await mode() is False
    assert "risk.present is on but no presenter pass" in out
    await presenter_pass(datetime.now(UTC) - present.ALIVE - timedelta(minutes=1))
    code, out = await run_once()  # its last pass is too old: still on
    assert code == 0, out
    assert asked == [True, True]
    assert await mode() is False
    await presenter_pass(datetime.now(UTC))
    code, out = await run_once()
    assert code == 0, out
    assert asked == [True, True, False]
    assert await mode() is True
    assert "no presenter pass" not in out
    monkeypatch.setenv("ARGUS_RISK__PRESENT", "false")
    code, out = await run_once()
    assert code == 0, out
    assert asked == [True, True, False, True]
    assert await mode() is False
