"""``argus siem`` and ``argus live`` against a throwaway database; nothing reaches the SIEM."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.config.settings import DatabaseSettings
from argus.db.engine import create_engine
from argus.gateway.pgstore import PgStore
from argus.gateway.state import LedgerEntry
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def migrated(cli_env: Path) -> tuple[str, str]:  # noqa: F811
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    return config


def test_kill_switches_and_status(
    cli_env: Path,  # noqa: F811
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    config = migrated(cli_env)
    assert _invoke("siem", "stop", "--component", "collector", "--reason", "drill", *config) == (
        0,
        "collector: stopped\n",
    )
    assert _invoke("siem", "stop", "--component", "collector", *config)[1] == (
        "collector: stopped (it already was)\n"
    )
    code, out = _invoke("siem", "status", *config)
    assert code == 0
    assert out.splitlines()[:2] == ["stopped: collector", "health: degraded (never_probed)"]
    assert "budget share now: 10%" in out  # never probed: the collector's tenth only
    assert "  collector: 0.0 s of 720 s (0 requests; polls, backfill, reconciliation)" in out
    assert "  enrichment: 0.0 s of 1080 s (0 requests;" in out
    assert "  all lanes: 0.0 s of 3600 s" in out
    assert (
        _invoke("siem", "resume", "--component", "collector", *config)[1] == "collector: resumed\n"
    )
    code, out = _invoke("siem", "stop", "--component", "everything", *config)
    assert code == 2
    assert "--component is one of global, collector, enrichment, kibana, writeback" in out
    entry = LedgerEntry(
        datetime(2026, 10, 9, 12, tzinfo=UTC), "collector", "collect", "alerts.ids", 1, (),
        "ok", 200, 7, 9, 10, 1,
    )  # fmt: skip

    async def record() -> None:
        engine = create_engine(db_settings, database=test_database)
        try:
            await PgStore(engine).record(entry)
        finally:
            await engine.dispose()

    asyncio.run(record())
    code, out = _invoke("siem", "status", *config)
    assert "  2026-10-09 12:00:00 alerts.ids ok 7 ms" in out


def test_requests_to_siem_need_the_key(cli_env: Path) -> None:  # noqa: F811
    config = migrated(cli_env)
    for command in ("probe", "selftest"):
        code, out = _invoke("siem", command, *config)
        assert code == 2, out
        assert "siem.api_key is not set" in out


def test_a_live_session_needs_a_person(cli_env: Path) -> None:  # noqa: F811
    config = migrated(cli_env)
    code, out = _invoke("live", "start", *config)
    assert code == 2
    assert "started by a person at a terminal" in out
    assert _invoke("live", "stop", "nope", *config) == (1, "no such open session\n")
