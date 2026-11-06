"""``argus risk run|rescore|status`` on a throwaway database: one pass at a set time, a full
rescore with its timing, and the counts; a bad time is a usage error. No SIEM request is made
(the suite's network guard would refuse one)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from argus.config import DatabaseSettings
from argus.db import migrate
from argus.db.engine import create_engine
from tests.integration.risk.conftest import NOW, group, rule, scalar
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - a fixture

pytestmark = pytest.mark.integration


def owner_does(db_settings: DatabaseSettings, database: str, work: Any) -> Any:
    async def main() -> Any:
        engine = create_engine(db_settings, database=database, role="owner")
        try:
            return await work(engine)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def test_run_rescore_and_status(
    cli_env: Path,  # noqa: F811 - the fixture
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    async def world(owner: Any) -> None:
        await migrate.upgrade(owner)
        await rule(owner, "r-ioc", "IOC rule", severity="critical")
        await group(owner, "r-ioc", actor="10.4.4.4", severity="critical")

    owner_does(db_settings, test_database, world)
    at = NOW.isoformat().replace("+00:00", "Z")
    code, out = _invoke("risk", "run", "--at", at, "-c", str(cli_env))
    assert code == 0, out
    assert "1 alert groups read" in out
    assert "decisive 1" in out
    assert "1 new items" in out
    crossings = owner_does(db_settings, test_database,
                           lambda e: scalar(e, "SELECT count(*) FROM risk_crossings"))  # fmt: skip
    assert crossings == 1
    code, out = _invoke("risk", "rescore", "--at", at, "-c", str(cli_env))
    assert code == 0, out
    assert "total" in out
    assert "0 lane crossings" in out
    code, out = _invoke("risk", "status", "-c", str(cli_env))
    assert code == 0, out
    assert "objects in a lane now: 1" in out
    assert "new items: 1" in out
    code, out = _invoke("risk", "run", "--at", "yesterday", "-c", str(cli_env))
    assert code == 2
    assert "not an ISO time" in out
