"""Q-F3: the assessment service runs a pass of the wave beside the decision engine, and the AI
investigator is held back for the waves it is owed. ``argus assess run --once`` with a fake
gateway in place of the SIEM."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.investigation import checks
from argus.llm.privacy import Privacy, load_policy
from tests.integration.investigation.kit import NOW, FakeGateway, body, env, healthy, seed
from tests.integration.test_cli_db import cli_env  # noqa: F401
from tests.unit.investigation.kit import C2, step
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

pytestmark = pytest.mark.integration


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> FakeGateway:
    """The assessment service with a fake gateway and a small campus, at a fixed clock."""
    gateway = FakeGateway(healthy())
    small_campus = Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))
    monkeypatch.setattr("argus.assess.cli._privacy", lambda _settings: small_campus)

    async def open_env(_settings: Any, _privacy: Any, db: Any) -> Any:
        async def close() -> None:
            return None

        return env(db, gateway), close

    monkeypatch.setattr("argus.assess.cli._investigation", open_env)
    return gateway


async def run_once(*extra: str) -> tuple[int, str]:
    def invoke() -> tuple[int, str]:
        result = CliRunner().invoke(app, ["assess", "run", "--once", *extra])
        return result.exit_code, result.output + result.stderr

    return await asyncio.to_thread(invoke)


async def rows(engine: AsyncEngine, sql: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


@pytest.mark.usefixtures("cli_env")
async def test_a_pass_runs_the_wave_for_the_undecided_when_it_is_on(
    service: FakeGateway, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    monkeypatch.setenv("ARGUS_INVESTIGATION__WAVE", "true")
    await seed(migrated_engine, body(steps=[step(2, "deferred", ["timeline"])]))
    code, out = await run_once()
    assert code == 0, out
    assert "investigation: queued 1 done 1 refused 0 failed 0" in out
    assert [c[0] for c in service.calls] == ["proxy.host"]
    found = await rows(app_engine, "SELECT pack FROM dossiers ORDER BY created_at")
    assert [r.pack for r in found] == ["generic@12", "generic+wave.1@12"]
    (request,) = await rows(app_engine, "SELECT origin FROM evidence_requests")
    assert request.origin == "wave"
    assert NOW  # the fixed clock of the kit


@pytest.mark.usefixtures("cli_env")
async def test_with_the_switch_off_only_a_persons_request_is_served(
    service: FakeGateway, app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    undecided = await seed(migrated_engine, body(steps=[step(2, "deferred", ["timeline"])]))
    decided = await seed(migrated_engine, body(), decided=True)
    async with app_engine.begin() as conn:
        asked = await checks.request(conn, decided, 1, "proxy.contact", C2, "asha", NOW)
    assert asked[0] == "queued"
    code, out = await run_once()
    assert code == 0, out
    assert "investigation: queued 0 done 1 refused 0 failed 0" in out
    assert [c[0] for c in service.calls] == ["proxy.contact"]
    waves = await rows(app_engine, "SELECT investigation_id FROM investigation_checks"
                       " WHERE kind = 'wave'")  # fmt: skip
    assert waves == []  # the undecided one waits for the switch
    assert undecided


@pytest.mark.usefixtures("cli_env")
async def test_the_service_waits_when_siem_cannot_be_reached_from_here(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    small_campus = Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))
    monkeypatch.setattr("argus.assess.cli._privacy", lambda _settings: small_campus)

    async def unreachable(_settings: Any, _classifier: Any, _db: Any) -> None:
        return None

    monkeypatch.setattr("argus.investigation.service.open_env", unreachable)
    monkeypatch.setenv("ARGUS_INVESTIGATION__WAVE", "true")
    await seed(migrated_engine, body(steps=[step(2, "deferred", ["timeline"])]))
    code, out = await run_once()
    assert code == 0, out
    assert "investigation.wave is on, but the SIEM is not set up here" in out
    assert "investigation:" not in out
    assert len(await rows(app_engine, "SELECT 1 FROM dossiers")) == 1
