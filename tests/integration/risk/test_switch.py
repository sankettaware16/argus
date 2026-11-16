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


@pytest.mark.usefixtures("cli_env", "service")
async def test_ai_readings_run_only_while_the_engine_presents_and_the_setting_is_on(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``risk.reading`` (D-324): a step of the assessment service while the engine presents, with
    the LLM gateway built once; off, or with no recent presenter pass, it is never asked."""
    from argus.risk import reading_run

    passes: list[datetime] = []
    built: list[int] = []

    class Transport:
        async def aclose(self) -> None:
            return None

    def reader(_db: Any) -> tuple[Any, Any, Any]:
        built.append(1)
        return (None, Transport(), None)

    async def run_pass(*args: Any, **kwargs: Any) -> reading_run.Report:
        passes.append(args[3])
        return reading_run.Report(written={"story": 1})

    monkeypatch.setattr("argus.assess.cli._reader", reader)
    monkeypatch.setattr("argus.assess.cli._no_model", lambda: None)
    monkeypatch.setattr("argus.risk.reading_run.run_pass", run_pass)
    monkeypatch.setenv("ARGUS_RISK__PRESENT", "true")
    code, out = await run_once()  # nothing presents: no reading
    assert code == 0, out
    assert passes == []
    async with app_engine.begin() as conn:
        await present.record_mode(conn, True, datetime.now(UTC))
    monkeypatch.setenv("ARGUS_RISK__READING", "false")
    code, out = await run_once()  # presenting, the setting off: no reading
    assert code == 0, out
    assert passes == []
    monkeypatch.setenv("ARGUS_RISK__READING", "true")
    code, out = await run_once()
    assert code == 0, out
    assert len(passes) == 1
    assert built == [1]
    assert "ARGUS AI's reading: 1 story" in out


@pytest.mark.usefixtures("cli_env", "service")
async def test_a_presenter_pass_a_cycle_ago_still_holds_the_switch(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The presenter runs every 10 minutes and stamps the time it started: a pass 12 minutes ago
    (a late timer, a long pass) still holds the old feeds off, so they do not come back for a
    minute or two every cycle (D-324)."""
    monkeypatch.setenv("ARGUS_RISK__PRESENT", "true")
    async with app_engine.begin() as conn:
        await present.record_mode(conn, True, datetime.now(UTC) - timedelta(minutes=12))
    code, out = await run_once()
    assert code == 0, out
    assert "no presenter pass" not in out
    async with app_engine.connect() as conn:
        assert (await conn.execute(text("SELECT present FROM risk_mode"))).scalar_one() is True
