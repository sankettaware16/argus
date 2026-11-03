"""AR8: Kibana sync reads the case team's cases after a cycle (the hook), and the hook is never
part of the cycle: its failure is logged and the cycle's outcome stands."""

from __future__ import annotations

import logging
from datetime import datetime

import pytest

from tests.unit.kibana_sync.fake import rig

pytestmark = pytest.mark.unit


async def test_the_step_after_a_complete_cycle_runs_once_with_the_cycles_deadline() -> None:
    r = rig()
    seen: list[datetime] = []

    async def after(deadline: datetime) -> None:
        seen.append(deadline)

    r.syncer.after_cycle = after
    record = await r.cycle()
    assert record.outcome == "complete"
    assert len(seen) == 1
    await r.cycle()
    assert len(seen) == 2


async def test_a_failing_step_is_logged_and_the_cycle_still_stands(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = rig()

    async def broken(deadline: datetime) -> None:
        raise RuntimeError("the verdict reader broke")

    r.syncer.after_cycle = broken
    with caplog.at_level(logging.ERROR, logger="argus.kibana_sync"):
        record = await r.cycle()
    assert record.outcome == "complete"
    assert any("the step after the sync cycle failed" in m for m in caplog.messages)
    assert (await r.store.state()).last_complete_at is not None


async def test_no_step_runs_after_a_cycle_that_failed() -> None:
    r = rig()
    called: list[int] = []

    async def after(deadline: datetime) -> None:
        called.append(1)

    r.syncer.after_cycle = after
    r.kibana.down = True
    record = await r.cycle()
    assert record.outcome == "failed"
    assert called == []


async def test_without_a_step_a_cycle_is_as_before() -> None:
    r = rig()
    assert r.syncer.after_cycle is None
    assert (await r.cycle()).outcome == "complete"
