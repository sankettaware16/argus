"""`argus discover` on the gateway's Postgres state (P4-D1): every discovery request is in the
request ledger as the runtime role writes it, the health state decides whether it runs, and a
discovery is read-only for the store too (it changes no switch and leaves no lease)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.discover import run
from argus.discover.propose import propose
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.pgstore import PgStore
from tests.unit.discover.fakes import daily_listing, elastic, kibana
from tests.unit.discover.test_discover import DAILY_MAPPINGS
from tests.unit.gateway.fakes import FakeClock

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


async def test_a_discovery_is_ledgered_and_leaves_the_store_as_it_found_it(
    app_engine: AsyncEngine,
) -> None:
    from argus.gateway.kibana.gateway import KibanaGateway

    clock = FakeClock(T0)
    transport = elastic(daily_listing(), DAILY_MAPPINGS, spaces=("acme-soc",))
    transport.clock = clock
    server = kibana(("default", "acme-soc"), space="acme-soc")
    server.clock = clock
    store = PgStore(app_engine)
    await store.save_health(HealthMemory(state=HealthState.NORMAL, probed_at=T0))
    es = Gateway(transport, store, clock=clock, sleep=clock.sleep)
    lane = KibanaGateway(server, store, es_gateway=es, clock=clock, sleep=clock.sleep)

    proposal = propose(await run.collect(es, lane, clock=clock))

    assert {f.family.pattern for f in proposal.families} >= {
        "acme-logs-squid-*",
        "acme-logs-nginx-*",
        "acme-logs-dns-*",
    }
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT component, purpose, template, outcome FROM siem_requests ORDER BY id")
            )
        ).all()
    assert len(rows) == len(transport.calls) + len(server.calls)
    assert {r.component for r in rows} == {"discover"}
    assert {r.outcome for r in rows} == {"ok"}
    templates = {r.template for r in rows}
    assert {"discover.indices", "discover.field_mapping", "kibana.spaces"} <= templates
    assert not templates & {"alerts.ids", "alerts.mget"}  # no alert, no document
    assert (await store.budget()).leases == ()  # every lease settled
    assert (await store.switches()).stopped == frozenset()


async def test_a_discovery_waits_when_the_store_says_the_siem_is_not_normal(
    app_engine: AsyncEngine,
) -> None:
    clock = FakeClock(T0)
    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    transport.clock = clock
    store = PgStore(app_engine)
    await store.save_health(HealthMemory(state=HealthState.DEGRADED, probed_at=T0))
    es = Gateway(transport, store, clock=clock, sleep=clock.sleep)

    proposal = propose(await run.collect(es, None, clock=clock))

    assert proposal.families == ()
    assert [c.path for c in transport.calls] == ["/"]  # the version read is a probe, any state
    async with app_engine.connect() as conn:
        sent = (await conn.execute(text("SELECT count(*) FROM siem_requests"))).scalar_one()
    assert sent == 1  # a refusal before sending leaves no ledger row; the probe has its own
