"""``argus risk run`` with the linker on, ``argus risk status``'s incident counts and
``argus risk incidents`` (P4-F E2, shadow)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.config.settings import DatabaseSettings
from argus.db import migrate
from tests.integration.risk.conftest import NOW, group, rule
from tests.integration.risk.test_cli import owner_does
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - a fixture

pytestmark = pytest.mark.integration


def test_the_pass_links_and_the_commands_show_incidents(
    cli_env: Path,  # noqa: F811 - the fixture
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    async def world(owner: object) -> None:
        await migrate.upgrade(owner)  # type: ignore[arg-type]
        await rule(owner, "r-ioc", "IOC rule", severity="critical")  # type: ignore[arg-type]
        for actor in ("10.4.4.4", "10.4.4.5"):
            await group(owner, "r-ioc", actor=actor, severity="critical",  # type: ignore[arg-type]
                        fields={"url.domain": ["rare-example.org"]})  # fmt: skip

    owner_does(db_settings, test_database, world)
    at = NOW.isoformat().replace("+00:00", "Z")
    code, out = _invoke("risk", "run", "--at", at, "-c", str(cli_env))
    assert code == 0, out
    assert "incidents (shadow): 1 live, 1 new" in out
    assert "largest 2 devices" in out
    code, out = _invoke("risk", "status", "-c", str(cli_env))
    assert code == 0, out
    assert "incidents active or quiet: 1" in out
    code, out = _invoke("risk", "incidents", "-c", str(cli_env))
    assert code == 0, out
    assert "active, decisive: 2 devices, 2 alert groups, version 1 (new incident)" in out
    assert "linked: the same rare domain rare-example.org" in out
    code, out = _invoke("risk", "titles", "--certainty", "Likely", "--explain", "-c", str(cli_env))
    assert code == 0, out
    assert "Likely: alerts of rule 'IOC rule' for 2 campus devices" in out
    assert "certainty: 'Likely" in out
    code, out = _invoke("risk", "titles", "--certainty", "Surely", "-c", str(cli_env))
    assert code == 2
    assert "--certainty is one of" in out
