"""``argus doctor`` and the notices (Q-H4): off is a state, an incomplete relay fails, no recipient
and an old or failing pass warn, and a switched-on, coherent setup that is running passes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import doctor
from argus.config import load_settings
from argus.config.settings import CasesSettings, NoticesSettings, Settings
from argus.notices import mail, run
from argus.notices.triggers import Found
from argus.ops import checks
from tests.fakesmtp import FakeSmtp
from tests.integration.notices.conftest import config_for
from tests.integration.test_cli_db import cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

ON = {
    "enabled": True,
    "relay_host": "mail.example.org",
    "relay_from": "argus@example.org",
    "recipients": ("ta@example.org",),
    "web_url": "https://argus.example.org",
}


def settings_with(cli_env: Path, watch: str = "local", **notices: object) -> Settings:  # noqa: F811
    base = load_settings(cli_env)
    return base.model_copy(
        update={
            "notices": NoticesSettings(**notices),  # type: ignore[arg-type]
            "cases": CasesSettings(watch=watch),  # type: ignore[arg-type]
        }
    )


def test_the_check_is_registered() -> None:
    assert checks.notices_check in doctor._CHECKS


async def test_a_switched_on_setup_that_has_never_run_warns(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
) -> None:
    (result,) = await checks.notices_results(settings_with(cli_env, **ON), datetime.now(UTC))
    assert result.label == "WARN"
    assert (
        "on: 1 recipient(s) through mail.example.org:25 (STARTTLS, without a login)"
        in result.detail
    )
    assert "no pass in the last hour: is argus-notices.timer enabled?" in result.detail


async def test_a_running_setup_passes(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
) -> None:
    with FakeSmtp() as server:
        await run.run(app_engine, config_for(server), Found(), now=datetime.now(UTC))
    (result,) = await checks.notices_results(settings_with(cli_env, **ON), datetime.now(UTC))
    assert (result.label, result.name) == ("PASS", "notices")
    later = datetime.now(UTC) + timedelta(hours=2)
    (old,) = await checks.notices_results(settings_with(cli_env, **ON), later)
    assert old.label == "WARN"
    assert "no pass in the last hour" in old.detail


async def test_a_relay_that_failed_lately_warns(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
) -> None:
    from tests.integration.notices.test_run import cond

    down = config_for(FakeSmtp(), relay=mail.Relay("127.0.0.1", 1, False, timeout=2))
    await run.run(app_engine, down, Found([cond()]), now=datetime.now(UTC))
    (result,) = await checks.notices_results(settings_with(cli_env, **ON), datetime.now(UTC))
    assert result.label == "WARN"
    assert "the relay failed 1 message(s) in the last hour" in result.detail


async def test_links_that_point_to_the_loopback_warn_once_it_is_on(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
) -> None:
    on = {k: v for k, v in ON.items() if k != "web_url"}
    with FakeSmtp() as server:
        await run.run(app_engine, config_for(server), Found(), now=datetime.now(UTC))
    (result,) = await checks.notices_results(settings_with(cli_env, **on), datetime.now(UTC))
    assert result.label == "WARN"
    assert "links point to http://127.0.0.1:" in result.detail


async def test_notices_without_the_watch_warn_that_a_case_that_keeps_beaconing_is_missed(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
) -> None:
    with FakeSmtp() as server:
        await run.run(app_engine, config_for(server), Found(), now=datetime.now(UTC))
    (result,) = await checks.notices_results(settings_with(cli_env, "off", **ON), datetime.now(UTC))
    assert result.label == "WARN"
    assert "the still-active watch is off" in result.detail
