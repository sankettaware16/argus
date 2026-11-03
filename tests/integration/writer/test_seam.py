"""Q-D4 beside Q-D3: what the writer sends is what the read-back expects of ARGUS. After a case
is created, its comment and alerts attached, taken, changed back by an approved compensating
write and closed, the read-back finds no ARGUS action it cannot explain (it would pause every
write class)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Take
from argus.kibana_sync.cycle import SyncConfig, Syncer
from argus.kibana_sync.store import PgSyncStore
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _apply
from tests.integration.writer.kit import (
    approve_compensation,
    approved_closure,
    created,
    mirror,
    rig,
)

pytestmark = pytest.mark.integration


async def test_the_read_back_explains_every_action_the_writer_made(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id, kid = await created(r, people, alerts=4)
    await mirror(migrated_engine, case_id, kid, version=str(r.kibana.cases[kid]["version"]))
    await _apply(api_engine, people["ravi"].actor(), case_id, Take(), 1)
    assert (await r.run("W2", limit=1)).verified == 2
    row = int((await r.sql("SELECT id FROM kibana_outbox WHERE op = 'update'"))[0].id)
    await approve_compensation(r, api_engine, people, row)
    assert (await r.run("W2", limit=5)).verified == 2
    await approved_closure(r, api_engine, people, case_id, kid)
    assert (await r.run("W3", limit=1)).verified == 2

    syncer = Syncer(
        r.gateway, PgSyncStore(app_engine), r.lane, es=r.es, config=SyncConfig(),
        clock=r.clock, sleep=r.clock.sleep,
    )  # fmt: skip
    for _ in range(3):
        r.advance(900)
        await syncer.cycle(deadline=r.clock.now + timedelta(minutes=9))

    findings = await r.sql("SELECT kind, severity FROM kibana_findings ORDER BY id")
    assert [(f.kind, f.severity) for f in findings if f.severity == "alarm"] == []
    assert "W1" not in (await r.lane.kibana_lane()).paused
    kept = (
        await r.sql("SELECT kibana_case_id, status, argus_actions, unexplained FROM kibana_mirror")
    )[0]
    assert kept.kibana_case_id == kid
    assert kept.status == "closed"
    assert kept.unexplained == {}
    assert kept.argus_actions["create"] == 1
    assert kept.argus_actions["attach"] >= 1
