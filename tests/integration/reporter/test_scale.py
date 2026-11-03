"""A report at production's size (Q-H3's measurement): two weeks of the request ledger at one
request every 3 seconds (the gateway's ceiling), the audit trail and the probes, the seeded
world on top. A weekly report must come well inside the timer's 10 minutes."""

from __future__ import annotations

import time

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reporter import build
from tests.integration.reporter import seed

pytestmark = pytest.mark.integration


async def test_a_weekly_report_over_two_weeks_of_ledger_takes_a_second(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await seed.seed(migrated_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, took_ms, elapsed_ms, response_bytes, attempts, lane)"
                " SELECT CAST(:end AS timestamptz) - (g * interval '3 seconds'), 'collector', 'x',"
                " 't', 1, ARRAY['x'], 'ok', g % 500, g % 700, 100, 1,"
                " (ARRAY['collector', 'investigation', 'freshness'])[1 + g % 3]"
                " FROM generate_series(1, 403200) g"  # 14 days at 1 request / 3 s
            ),
            {"end": seed.AS_AT},
        )
        await conn.execute(
            text(
                "INSERT INTO siem_probes (at, state, reasons, probe_ok, auth_failed,"
                " blocked_indices) SELECT CAST(:end AS timestamptz) - (g * interval '1 minute'),"
                " 'normal', ARRAY[]::text[], true, false, ARRAY[]::text[]"
                " FROM generate_series(1, 20160) g"
            ),
            {"end": seed.AS_AT},
        )
        await conn.execute(
            text(
                "INSERT INTO audit_events (occurred_at, actor, action, outcome, details)"
                " SELECT CAST(:end AS timestamptz) - (g * interval '10 seconds'), 'argus:test',"
                " 'case.opened', 'success', CAST('{}' AS jsonb) FROM generate_series(1, 50000) g"
            ),
            {"end": seed.AS_AT},
        )
        await conn.execute(text("ANALYZE"))
    for kind in ("daily", "weekly"):
        started = time.monotonic()
        numbers, _ = await build.make(app_engine, kind, seed.DAY.date(), seed.AS_AT)  # type: ignore[arg-type]
        took = time.monotonic() - started
        print(f"MEASURED {kind} report, {len(numbers.metrics())} figures, {took:.2f} s")
        assert took < 30, took
        assert numbers.metrics()["siem.requests"].value is not None
