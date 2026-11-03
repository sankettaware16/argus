"""``argus signins`` end to end on a throwaway database (AR6, D-216): the pass says it is off, a dry
run plans and validates without sending, and ``show`` prints what is stored for an investigation, a
case or an address, with the personal-data notice. Nothing here reaches the SIEM."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from argus.gateway.gateway import in_quiet_hours
from argus.signins import model as m
from argus.signins import store
from argus.signins.attribute import LEAD
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import make, open_case
from tests.integration.signins import kit as k
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
NAME = "user-ar6-delta"


def ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
async def seeded(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> tuple[uuid.UUID, int, datetime]:
    """An investigation of a campus host yesterday, in an open case, with a stored sighting."""
    yesterday = (datetime.now(UTC) - timedelta(days=1)).replace(
        hour=13, minute=0, second=0, microsecond=0
    )
    inv = await make(migrated_engine, when=yesterday, host=k.HOST_A)
    await open_case(app_engine, people["asha"], [inv], host=k.HOST_A, servers=())
    day = yesterday.date()
    lookup = m.Lookup(k.HOST_A, day, m.day_end(day) + timedelta(hours=1), True, 1, 0)
    seen = kit.sighting(NAME, address=k.HOST_A, day=day, hours=tuple(range(24)), events=48)
    async with app_engine.begin() as conn:
        await store.save(conn, [lookup], [seen])
    return inv, 1, yesterday


def test_it_says_it_is_off_until_it_is_switched_on(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_SIGNINS__ENABLED", "false")  # production's YAML has it on
    assert "signins: off (signins.enabled)" in ok(_run("signins", "run"))


@pytest.fixture
async def yesterdays_host(migrated_engine: AsyncEngine) -> datetime:
    when = (datetime.now(UTC) - timedelta(days=1)).replace(
        hour=13, minute=0, second=0, microsecond=0
    )
    await make(migrated_engine, when=when, host=k.HOST_B)
    return when


def test_a_dry_run_plans_and_validates_and_stores_nothing(
    cli_env: Path,  # noqa: F811
    yesterdays_host: datetime,
) -> None:
    if in_quiet_hours(datetime.now(UTC)):
        pytest.skip("the pass plans nothing from 00:00 to 01:30 UTC")
    out = ok(_run("signins", "run", "--dry-run"))
    assert "address-days wanted" in out
    assert f"would read {yesterdays_host.date()} up to 00:00Z for 1 addresses" in out
    assert f"acme-logs-sso-{yesterdays_host.date():%Y.%m.%d}" in out


def test_show_prints_the_probable_user_for_an_investigation_a_case_and_an_address(
    cli_env: Path,  # noqa: F811
    seeded: tuple[uuid.UUID, int, datetime],
) -> None:
    inv, number, _ = seeded
    for args in (("--investigation", str(inv)), ("--case", str(number)), ("--address", k.HOST_A)):
        out = ok(_run("signins", "show", *args))
        assert "personal data: account names below are for the operator only" in out
        assert LEAD in out
        assert NAME in out
        assert k.HOST_A in out
    by_device = ok(_run("signins", "show", "--investigation", str(inv)))
    assert f"{k.HOST_A}: likely. Probable user: {NAME}." in by_device
    assert "Chrome on Windows" in by_device


def test_show_wants_exactly_one_thing_and_says_when_it_knows_nothing(
    cli_env: Path,  # noqa: F811
    seeded: tuple[uuid.UUID, int, datetime],
) -> None:
    assert _run("signins", "show").exit_code == 2
    assert _run("signins", "show", "--case", "1", "--address", k.HOST_A).exit_code == 2
    assert "nothing stored" in ok(_run("signins", "show", "--address", "10.77.77.77"))
    assert "no such case" in ok(_run("signins", "show", "--case", "999"))
    bad = _run("signins", "show", "--address", "not-an-address")
    assert bad.exit_code != 0
