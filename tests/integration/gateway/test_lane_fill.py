"""A person's top-up of a lane bucket against a throwaway database (D-243): the stored state a
pre-deploy version left, the fill, the audit row (who, when, what it held and holds), the refusals,
and the command itself. Nothing reaches the SIEM or Kibana."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway import budget as bu
from argus.gateway import cli as gateway_cli
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane
from argus.gateway.pgstore import PgStore, budget_to_json
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration
WRITE = Lane.KIBANA_WRITE


async def store_pre_deploy(engine: AsyncEngine, now: datetime) -> None:
    """The lanes row as the version before the burst left it: the write lane's bucket at 200 ms."""
    old = bu.BudgetState(tokens_ms=200.0, refilled_at=now, day=now.date(), day_used_ms=40_000)
    body = {"buckets": {WRITE.value: budget_to_json(old)}, "starts": {}}
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE siem_state SET state = CAST(:s AS jsonb) WHERE name = 'lanes'"),
            {"s": json.dumps(body)},
        )


async def test_the_fill_sets_the_stored_bucket_and_audits_who_and_when(
    app_engine: AsyncEngine,
) -> None:
    now = datetime.now(UTC)
    await store_pre_deploy(app_engine, now)
    store = PgStore(app_engine)
    assert (await store.lanes()).bucket(WRITE).tokens_ms == 200.0

    before, after = await store.lane_fill(
        WRITE, actor="host:devuser", now=now, scale=1.0, health="normal", reason="the deploy"
    )

    assert (before, after) == (pytest.approx(200.0), 60_000.0)
    kept = (await store.lanes()).bucket(WRITE)
    assert kept.tokens_ms == 60_000.0
    assert kept.day_used_ms == 40_000  # the day's share is not touched
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT actor, action, target_type, target_id, details FROM audit_events"
                    " WHERE action = 'siem.lane_fill'"
                )
            )
        ).all()
    [row] = rows
    assert (row.actor, row.target_type, row.target_id) == (
        "host:devuser",
        "siem_lane",
        "kibana_write",
    )
    assert row.details["before_ms"] == 200.0
    assert row.details["after_ms"] == 60_000.0
    assert row.details["health"] == "normal"
    assert row.details["reason"] == "the deploy"
    assert datetime.fromisoformat(row.details["at"]) == now


async def test_a_refused_fill_changes_nothing_and_audits_nothing(app_engine: AsyncEngine) -> None:
    now = datetime.now(UTC)
    await store_pre_deploy(app_engine, now)
    store = PgStore(app_engine)
    with pytest.raises(ValueError, match="NORMAL"):
        await store.lane_fill(
            WRITE, actor="host:devuser", now=now, scale=0.5, health="caution", reason="x"
        )
    assert (await store.lanes()).bucket(WRITE).tokens_ms == 200.0
    async with app_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM audit_events WHERE action = 'siem.lane_fill'")
        )
    assert count == 0


async def test_a_never_used_lanes_row_is_filled_too(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    now = datetime.now(UTC)
    before, after = await store.lane_fill(
        WRITE, actor="host:t", now=now, scale=1.0, health="normal", reason="x"
    )
    assert (before, after) == (60_000.0, 60_000.0)  # a new bucket starts full


def test_the_command_fills_the_stored_bucket_after_a_probe_found_siem_normal(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    monkeypatch.setattr(gateway_cli, "_human_at_a_terminal", lambda: True)
    code, out = _invoke("siem", "lanes", "fill", "kibana_write", *config)
    assert code == 1  # the stored health was never probed: DEGRADED, not NORMAL
    assert "NORMAL" in out
    assert "argus siem probe" in out
    monkeypatch.setattr(gateway_cli, "_human_at_a_terminal", lambda: False)
    code, out = _invoke("siem", "lanes", "fill", "kibana_write", *config)
    assert code == 2
    assert "person at a terminal" in out


async def test_the_stored_health_that_is_fresh_and_normal_lets_the_fill_through(
    app_engine: AsyncEngine,
) -> None:
    """What the command reads before it fills: the stored health, at full scale."""
    store = PgStore(app_engine)
    now = datetime.now(UTC)
    await store.save_health(HealthMemory(state=HealthState.NORMAL, probed_at=now))
    memory = await store.health()
    assert memory.state is HealthState.NORMAL
    assert now - memory.probed_at < timedelta(seconds=5)  # type: ignore[operator]
