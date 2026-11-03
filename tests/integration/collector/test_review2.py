"""Collector fixes found while R8 ran (2026-10-13), each shown failing before its fix."""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import collector as co
from argus.collector.runner import Runner
from argus.gateway.errors import DeferredError
from tests.integration.collector.fake_es import FakeAlertsES
from tests.integration.collector.test_collector import MIN, NOW, aid, build

pytestmark = pytest.mark.integration


async def test_a_long_catch_up_poll_keeps_the_health_state_fresh(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the collector had been down for 7 hours, one catch-up poll paged for minutes
    without a probe; the health state went stale (DEGRADED) and refused its own next page."""
    monkeypatch.setattr(co, "PAGE", 4)
    es = FakeAlertsES()
    for n in range(10):
        es.add(aid(n), NOW - 2 * MIN + n * timedelta(seconds=5))
    refreshed = 0

    async def fresh() -> None:
        nonlocal refreshed
        refreshed += 1

    collector, _ = build(es, app_engine, before_chunk=fresh)
    result = await collector.poll()
    assert (result.pages, result.new) == (3, 10)
    assert refreshed == 3  # before every page


async def test_a_refused_job_is_one_warning_line(
    app_engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """The SIEM's health state refusing work is expected, not a crash: no traceback."""
    collector, _ = build(FakeAlertsES(), app_engine)

    async def refused() -> int:
        raise DeferredError("the SIEM is degraded: reconcile waits")

    async def probe() -> None:
        return None

    collector.sync_states = refused  # type: ignore[method-assign]
    runner = Runner(collector, probe)
    with caplog.at_level(logging.WARNING, logger="argus.collector"):
        await runner.step()
    (record,) = [r for r in caplog.records if "states" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None
    assert record.getMessage() == (
        "collector job states refused: deferred: the SIEM is degraded: reconcile waits"
    )
