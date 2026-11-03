"""``Gateway.run(request_timeout=...)`` (Q-A3): a request's own timeout below the template's,
for Elasticsearch and the wire, while the deadline still bounds the budget waits."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from argus.gateway.budget import BudgetState
from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.templates import Purpose
from tests.unit.gateway.fakes import T0, make

pytestmark = pytest.mark.unit

IDS = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0)


async def run(gateway: object, **kw: object) -> object:
    return await gateway.run(  # type: ignore[attr-defined]
        AlertIds(), IDS, purpose=Purpose.COLLECT, component="collector", **kw
    )


async def test_without_it_the_templates_timeout_holds() -> None:
    gateway, transport, _, _ = make()
    await run(gateway, deadline=T0 + timedelta(seconds=60))
    sent = transport.calls[0]
    assert json.loads(sent.body or b"{}")["timeout"] == "10s"
    assert sent.timeout_s == 10.0


async def test_it_caps_elasticsearchs_and_the_wires_timeout() -> None:
    gateway, transport, _, _ = make()
    await run(gateway, deadline=T0 + timedelta(seconds=60),
              request_timeout=timedelta(seconds=2, milliseconds=900))  # fmt: skip
    sent = transport.calls[0]
    assert json.loads(sent.body or b"{}")["timeout"] == "2s"  # whole seconds, rounded down
    assert sent.timeout_s == pytest.approx(2.9)


async def test_it_never_raises_the_templates_timeout() -> None:
    gateway, transport, _, _ = make()
    await run(gateway, deadline=T0 + timedelta(seconds=60), request_timeout=timedelta(minutes=5))
    assert json.loads(transport.calls[0].body or b"{}")["timeout"] == "10s"


async def test_the_deadline_still_bounds_the_budget_wait() -> None:
    gateway, transport, store, clock = make()
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    await run(gateway, deadline=T0 + timedelta(seconds=30), request_timeout=timedelta(seconds=1))
    assert clock.slept == [1.0]  # waited for the budget longer than its own timeout
    assert transport.calls[0].timeout_s == 1.0


@pytest.mark.parametrize("bad", [timedelta(0), timedelta(seconds=-1)])
async def test_a_timeout_that_is_not_positive_is_refused(bad: timedelta) -> None:
    gateway, transport, _, _ = make()
    with pytest.raises(ValueError, match="positive"):
        await run(gateway, deadline=T0 + timedelta(seconds=60), request_timeout=bad)
    assert transport.calls == []


# ----------------------------------------------- the re-measurement's other additions (Q-A3)


async def test_a_gateway_names_its_listings_as_its_caller_asks_and_gateway_by_default() -> None:
    """Review F3: the measuring session's index listings are its own on the ledger; every
    other gateway keeps naming them ``gateway``."""
    from argus.gateway.builtin import Freshness, FreshnessParams
    from tests.unit.gateway.fakes import SQUID_TODAY, FakeTransport, listing, ok

    for name in ("measure", None):
        kw = {} if name is None else {"listing_component": name}
        answers = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
        gateway, transport, store, _ = make(answers, **kw)
        await gateway.run(Freshness(), FreshnessParams(source="squid", now=T0),
                          purpose=Purpose.PROBE, component="probe",
                          deadline=T0 + timedelta(seconds=30))  # fmt: skip
        expected = name or "gateway"
        assert transport.calls[0].opaque_id == f"argus-{expected}/indices.listing@1"
        assert store.ledger[0].component == expected


async def test_the_ledger_reads_back_each_rows_status_and_attempts() -> None:
    """Review F3: verify tells a request that reached the SIEM from one refused unsent."""
    from argus.gateway.errors import GatewayError
    from argus.gateway.transport import WireResponse
    from tests.unit.gateway.fakes import FakeTransport, failure, ok, search_answer

    error = WireResponse(500, b'{"error":{"type":"x"}}', 5.0)
    gateway, _, store, _ = make(FakeTransport().on("_search", error))
    with pytest.raises(GatewayError):
        await run(gateway, deadline=T0 + timedelta(seconds=60))
    gateway, _, retried, _ = make(FakeTransport().on("_search", failure(), ok(search_answer())))
    await run(gateway, deadline=T0 + timedelta(seconds=60))
    rows = [*await store.requests_since(T0), *await retried.requests_since(T0)]
    assert [(row.http_status, row.attempts) for row in rows] == [(500, 1), (200, 2)]
