"""Q-F4 review F4-R3, pinned: §7.3's NORMAL only and the quiet hours held only at admit(),
while the gateway re-checks health on every wait and retry with the enrichment rules (which
allow CAUTION) and knows no quiet hours; and requests admitted together all passed the daily
cap. ``batch1.send`` now hands the gateway ``send_check`` and reserves each request's timeout
against the cap. These tests failed on 18e2e6c (the first two as the reviewer wrote them,
calling the gateway after admit())."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.context import batch1, beacon
from argus.context.bounds import quiet
from argus.context.packs import TaskSpec
from argus.gateway.errors import DeferredError
from argus.gateway.gateway import Gateway, Result, Targets
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.state import MemoryStore
from argus.gateway.templates import Purpose
from tests.unit.gateway.fakes import FakeClock, FakeTransport, failure, listing, ok, search_answer

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
SQUID = "acme-logs-squid-2026.10.09"
HISTORY = timedelta(days=5)


class Conn:
    """Prevalence 0; ``spent`` ms of the template's server time charged today."""

    def __init__(self, spent: int = 0) -> None:
        self.spent = spent

    async def execute(self, statement: Any, *_: Any, **__: Any) -> Any:
        spent = self.spent if "siem_requests" in str(statement) else 0

        class R:
            def scalar_one(self) -> int:
                return spent

            def scalars(self) -> list[str]:
                return []

        return R()


def task(start: datetime = NOW - timedelta(hours=6), end: datetime = NOW - timedelta(minutes=15)
         ) -> TaskSpec:  # fmt: skip
    return TaskSpec(beacon.ProxyPair(), beacon.PairParams(
        host="10.0.0.5", destination="203.0.113.9", start=start, end=end))  # fmt: skip


async def send(conn: Any, gateway: Any, spec: TaskSpec, **kw: Any) -> Any:
    return await batch1.send(conn, gateway, spec, enabled={"proxy.pair"}, history=HISTORY,
                             is_own=batch1.private_or(None),
                             deadline=gateway.clock() + timedelta(seconds=60), **kw)  # fmt: skip


def answer() -> dict[str, Any]:
    return {**search_answer(), "aggregations": {"requests": {"value": 0}}}


async def test_a_batch1_request_is_never_sent_outside_normal() -> None:
    clock = FakeClock(NOW)
    store = MemoryStore(memory=HealthMemory(state=HealthState.NORMAL, probed_at=NOW))
    sent_in: list[HealthState] = []

    def search(request: Any) -> Any:
        sent_in.append(store.memory.state)
        return ok(answer())

    transport = FakeTransport().on("_resolve/index", ok(listing(SQUID)))
    transport.on("/_search", failure(retriable=True), search)  # the first try: a reset
    transport.clock = clock

    async def sleep(seconds: float) -> None:  # meanwhile the collector's probe sees CAUTION
        clock.now += timedelta(seconds=seconds)
        store.memory = HealthMemory(state=HealthState.CAUTION, probed_at=clock.now)

    gateway = Gateway(transport, store, targets=Targets(), clock=clock, sleep=sleep)
    with pytest.raises(DeferredError, match="NORMAL only"):
        await send(Conn(), gateway, task())
    # The heavy aggregation never went out while the SIEM was in CAUTION.
    assert HealthState.CAUTION not in sent_in
    assert sent_in == []
    assert [e.outcome for e in store.ledger if e.template == "proxy.pair"] == ["deferred"]


async def test_a_batch1_request_is_never_sent_in_quiet_hours() -> None:
    late = datetime(2026, 10, 9, 23, 59, 59, 500_000, tzinfo=UTC)
    clock = FakeClock(late)
    store = MemoryStore(memory=HealthMemory(state=HealthState.NORMAL, probed_at=late))
    sent_at: list[datetime] = []

    def search(request: Any) -> Any:
        sent_at.append(clock.now)
        return ok(answer())

    transport = FakeTransport().on("_resolve/index", ok(listing(SQUID)))
    transport.on("/_search", failure(retriable=True), search)
    transport.clock = clock

    async def sleep(seconds: float) -> None:
        clock.now += timedelta(seconds=seconds)

    gateway = Gateway(transport, store, targets=Targets(), clock=clock, sleep=sleep)
    spec = task(datetime(2026, 10, 9, 16, 0, tzinfo=UTC), datetime(2026, 10, 9, 22, 0, tzinfo=UTC))
    with pytest.raises(DeferredError, match="01:30 UTC"):
        await send(Conn(), gateway, spec)  # admitted at 23:59:59.5: not quiet yet
    assert not any(quiet(t) for t in sent_at)
    assert sent_at == []


async def test_the_check_is_asked_before_anything_is_sent() -> None:
    clock = FakeClock(NOW)
    store = MemoryStore(memory=HealthMemory(state=HealthState.NORMAL, probed_at=NOW))
    transport = FakeTransport().on("_resolve/index", ok(listing(SQUID)))
    transport.clock = clock
    gateway = Gateway(transport, store, targets=Targets(), clock=clock, sleep=clock.sleep)
    asked: list[datetime] = []

    async def refuse(now: datetime) -> None:
        asked.append(now)
        raise DeferredError("not now")

    spec = task()
    with pytest.raises(DeferredError):
        await gateway.run(spec.template, spec.params, purpose=Purpose.ENRICH,
                          component="enrichment", deadline=NOW + timedelta(seconds=60),
                          check=refuse)  # fmt: skip
    assert transport.calls == []
    assert asked == [NOW]
    # a check that passes is asked again once the lease is held, and the answer comes back
    passes: list[datetime] = []

    async def allow(now: datetime) -> None:
        passes.append(now)

    transport.on("/_search", ok(answer()))
    result = await gateway.run(spec.template, spec.params, purpose=Purpose.ENRICH,
                               component="enrichment", deadline=clock() + timedelta(seconds=60),
                               check=allow)  # fmt: skip
    assert result.body["aggregations"] == {"requests": {"value": 0}}
    assert len(passes) == 2


async def test_a_refusal_at_admission_sends_nothing() -> None:
    clock = FakeClock(NOW)
    store = MemoryStore(memory=HealthMemory(state=HealthState.CAUTION, probed_at=NOW))
    transport = FakeTransport()
    transport.clock = clock
    gateway = Gateway(transport, store, targets=Targets(), clock=clock, sleep=clock.sleep)
    got = await send(Conn(), gateway, task())
    assert got == batch1.Refusal("not_normal", str(HealthState.CAUTION))
    assert transport.calls == []


class HeldGateway:
    """A gateway whose requests wait until released, to admit others meanwhile."""

    def __init__(self) -> None:
        self.state = MemoryStore(memory=HealthMemory(state=HealthState.NORMAL, probed_at=NOW))
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.sent = 0

    def clock(self) -> datetime:
        return NOW

    async def run(self, *_: Any, **kw: Any) -> Result:
        assert kw["check"] is not None
        self.sent += 1
        self.started.set()
        await self.release.wait()
        return Result({}, 10_000, ())


async def test_requests_admitted_together_cannot_all_pass_the_daily_cap() -> None:
    gateway = HeldGateway()
    held = batch1.Reservations()
    conn = Conn(spent=85_000)  # 85 s of the 90 s spent today
    first = asyncio.create_task(send(conn, gateway, task(), reservations=held))
    await gateway.started.wait()
    assert held.held("proxy.pair", NOW) == 10_000  # its timeout, reserved while in flight
    assert held.held("proxy.contact", NOW) == 0
    assert held.held("proxy.pair", NOW + timedelta(days=1)) == 0
    second = await send(conn, gateway, task(), reservations=held)
    assert second == batch1.Refusal("daily_cap")
    gateway.release.set()
    assert isinstance(await first, Result)
    assert held.held("proxy.pair", NOW) == 0  # released once finished
    assert gateway.sent == 1
    third = await send(conn, gateway, task(), reservations=held)  # its time is in the ledger now
    assert isinstance(third, Result)
