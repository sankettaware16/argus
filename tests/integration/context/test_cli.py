"""``argus worker ...`` end to end on a throwaway database (the stub pack: no SIEM request)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.context.conftest import seed
from tests.integration.context.kit import scalar
from tests.integration.test_cli_db import _error_line, _invoke, _run, cli_env  # noqa: F401

pytestmark = pytest.mark.integration


async def run(*args: str) -> tuple[int, str]:
    return await asyncio.to_thread(_invoke, *args)  # the CLI runs its own event loop


@pytest.mark.usefixtures("cli_env")
async def test_once_status_prune_and_capacity(app_engine: AsyncEngine, tmp_path: Path) -> None:
    code, out = await run("worker", "once")
    assert (code, out.strip()) == (0, "jobs: none due")
    await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r1", "10.0.0.2"), (3, "r2", "10.0.0.1")])
    code, out = await run("worker", "once", "--limit", "2")
    assert (code, out.strip()) == (0, "jobs: 2 done")
    code, out = await run("worker", "once")
    assert (code, out.strip()) == (0, "jobs: 1 done")
    assert await scalar(app_engine, "SELECT count(*) FROM dossiers") == 3
    assert await scalar(app_engine, "SELECT count(*) FROM siem_requests") == 0
    code, out = await run("worker", "status")
    assert code == 0
    assert "  done: 3" in out
    assert "  evidence_ready: 3" in out
    assert "checkpoints: 0 threads" in out
    code, out = await run("worker", "prune", "--hours", "1")
    assert (code, out.strip()) == (0, "pruned 0 checkpoint threads")
    target = tmp_path / "cap.json"
    code, out = await run("worker", "capacity", "--profile", "stub", "--profile", "small",
                        "--outage-hours", "1", "--output", str(target))  # fmt: skip
    assert code == 0, out
    assert out.splitlines()[0].startswith("3 changes, ")
    rows = json.loads(target.read_text())
    assert [r["profile"] for r in rows] == ["stub", "small"]
    assert rows[0]["share_of_daily_cap"] == 0
    assert rows[1]["requests"] == 3 * 3


@pytest.mark.usefixtures("cli_env")
async def test_capacity_refuses_unknown_profiles_and_an_empty_store(
    app_engine: AsyncEngine,
) -> None:
    code, out = await run("worker", "capacity", "--profile", "nope")
    assert code == 2
    assert "unknown profile nope" in out
    code, out = await run("worker", "capacity", "--profile", "stub")
    assert code == 1
    assert "no stored alerts to replay" in out


@pytest.mark.usefixtures("cli_env")
@pytest.mark.parametrize("command", [("status",), ("prune",), ("capacity",)])
def test_a_database_error_is_one_line(command: tuple[str, ...]) -> None:
    result = _run("worker", *command)  # the throwaway database has no tables yet
    assert result.exit_code == 1
    assert _error_line(result).startswith("error: database error: relation ")
