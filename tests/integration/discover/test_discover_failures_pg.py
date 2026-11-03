"""`argus discover` on the gateway's Postgres state, failures and probes (P4-D1 review F1, F2):
the same guarantees the unit tests hold on the in-memory store, here on the store production
shares: a refused discovery read leaves the SIEM's health row and the Kibana lane row as found,
and the command's own probe is never saved (no health row, no `siem_probes` row).

NOT YET RUN: written without Docker/Postgres in the fixer's worktree (the lead runs it)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import SiemSettings
from argus.discover import run
from argus.discover.propose import propose
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana.gateway import KibanaGateway
from argus.gateway.kibana.writes import KibanaLaneState
from argus.gateway.pgstore import PgStore
from argus.gateway.service import probe
from argus.gateway.state import DiscoveryStore
from tests.unit.discover.fakes import NODE_STATS, daily_listing, elastic, kibana
from tests.unit.discover.test_discover import DAILY_MAPPINGS
from tests.unit.discover.test_safety import ES_READS, failing
from tests.unit.gateway.fakes import FakeClock, FakeTransport, ok
from tests.unit.gateway.kibana.fakes import reply

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
BLOCKS = {".internal.alerts-security.alerts-acme-soc-000001": {"settings": {"index.uuid": "u"}}}


async def probes_stored(engine: AsyncEngine) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text("SELECT count(*) FROM siem_probes"))).scalar_one())


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("read", sorted(ES_READS))
async def test_a_refused_read_leaves_the_stored_health_and_kibana_lane_as_found(
    app_engine: AsyncEngine, read: str, status: int
) -> None:
    clock = FakeClock(T0)
    transport = failing(
        elastic(daily_listing(), DAILY_MAPPINGS, read_ilm=True), ES_READS[read], status
    )
    transport.clock = clock
    server = kibana(("default",), space="acme-soc")
    server.routes[:] = [r for r in server.routes if not r[1].endswith("/api/features")]
    server.on("GET", "/api/features", reply({"statusCode": status}, status=status))
    server.clock = clock
    store = PgStore(app_engine)
    found = HealthMemory(state=HealthState.NORMAL, probed_at=T0)
    await store.save_health(found)
    shadow = DiscoveryStore(store)
    es = Gateway(transport, shadow, clock=clock, sleep=clock.sleep)
    lane = KibanaGateway(server, shadow, es_gateway=es, clock=clock, sleep=clock.sleep)

    proposal = propose(await run.collect(es, lane, clock=clock))

    assert any("was not read" in w for w in proposal.warnings)
    assert await store.health() == found  # not STOP
    assert await store.kibana_lane() == KibanaLaneState()  # not "403 on a read"
    async with app_engine.connect() as conn:
        outcomes = {
            r.outcome for r in (await conn.execute(text("SELECT outcome FROM siem_requests"))).all()
        }
    assert "auth_failed" in outcomes or "kibana_forbidden" in outcomes or status == 401


async def test_the_commands_own_probe_is_not_saved_over_the_stored_health(
    app_engine: AsyncEngine,
) -> None:
    clock = FakeClock(T0)
    transport = FakeTransport().on("_nodes", ok(NODE_STATS)).on("_settings", ok(BLOCKS))
    transport.clock = clock
    store = PgStore(app_engine)
    stale = HealthMemory(
        state=HealthState.STOP,
        reasons=("index_blocked",),
        probed_at=T0 - timedelta(minutes=10),
        since=T0 - timedelta(minutes=10),
    )
    await store.save_health(stale)
    shadow = DiscoveryStore(store)
    es = Gateway(transport, shadow, clock=clock, sleep=clock.sleep)

    got = await run.siem_state(es, shadow, SiemSettings(), clock=clock)

    assert got.state is HealthState.NORMAL  # this command's view of a healthy SIEM ...
    assert await store.health() == stale  # ... and the production memory as the collector left it
    assert await probes_stored(app_engine) == 0
    assert await store.latest_probe() is None


async def test_a_partial_probe_is_not_saved_on_the_real_store_either(
    app_engine: AsyncEngine,
) -> None:
    clock = FakeClock(T0)
    transport = FakeTransport().on("_nodes", ok(NODE_STATS))
    transport.clock = clock
    store = PgStore(app_engine)
    stop = HealthMemory(
        state=HealthState.STOP, reasons=("index_blocked",), probed_at=T0 - timedelta(minutes=10)
    )
    await store.save_health(stop)
    es = Gateway(transport, store, clock=clock, sleep=clock.sleep)

    await probe(es, store, SiemSettings(), T0, indices=False)

    assert await store.health() == stop
    assert await probes_stored(app_engine) == 0
