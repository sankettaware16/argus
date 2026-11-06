"""``argus case suggest`` (AR2b, D-160) end to end on a throwaway database: a dry run says what it
would suggest and writes nothing; the real run makes one suspected case; a second does nothing."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from argus import site
from argus.assess import raised
from argus.cases.cli import NO_ASSET_MAP_NOTE
from tests.integration.assess.test_raised_db import BEACON, LISTED, NOW, make
from tests.integration.cases.conftest import rows
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


async def test_the_command_suggests_one_case_and_then_nothing(
    cli_env: Path,  # noqa: F811
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    await make(migrated_engine, rule="download", host=1, signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", host=1, severity="medium", signals=(BEACON, LISTED))
    async with app_engine.begin() as conn:
        await raised.evaluate(conn, NOW)

    dry = _ok(await asyncio.to_thread(_run, "case", "suggest", "--dry-run"))
    assert "dry run: unreviewed investigations of the last 72 hours" in dry
    assert "suggested   2 investigations: Suspected beaconing from 10.1.1.1" in dry
    assert "planned: suggested 1" in dry
    assert await rows(app_engine, "SELECT * FROM cases") == []

    done = _ok(await asyncio.to_thread(_run, "case", "suggest"))
    assert "planned: suggested 1" in done
    assert "applied: suggested 1" in done
    (case,) = await rows(app_engine, "SELECT state, cause, title FROM cases")
    assert (case.state, case.cause) == ("suspected", "raised")

    again = _ok(await asyncio.to_thread(_run, "case", "suggest"))
    assert "planned: nothing" in again
    assert "applied: nothing" in again


async def test_the_command_says_when_campaigns_are_skipped_for_lack_of_an_asset_map(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_ASSETS__MAP_PATH", str(tmp_path / "no-such-map.yaml"))
    out = _ok(await asyncio.to_thread(_run, "case", "suggest", "--dry-run"))
    assert site.say(NO_ASSET_MAP_NOTE) in out  # the site's words, never a raw {own:devices}
    assert "{own:" not in out
    assert "no asset map is imported" in out
    assert "campaigns were skipped" in out
    assert "planned: nothing" in out  # the rest of the command is as usual
