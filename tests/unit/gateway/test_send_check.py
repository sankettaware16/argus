"""The gateway's ``check`` (a caller's own rule, Q-F4 review F4-R3) at every point where the
gateway asks its own state again: at the start, after a budget wait, once the lease is held,
before a retry; and a template's ``answer`` applied to what comes back."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from argus.gateway.budget import BudgetState
from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.errors import DeferredError
from argus.gateway.templates import Params, Purpose
from tests.unit.gateway.fakes import T0, FakeTransport, failure, make, ok, search_answer

DEADLINE = T0 + timedelta(seconds=60)
IDS = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0)


class Refuser:
    """A check that refuses from its ``after``-th call on, recording each call's time."""

    def __init__(self, after: int) -> None:
        self.after = after
        self.calls: list[datetime] = []

    async def __call__(self, now: datetime) -> None:
        self.calls.append(now)
        if len(self.calls) >= self.after:
            raise DeferredError("the caller's rule")


async def collect(gateway: Any, check: Any, template: Any = None) -> Any:
    return await gateway.run(template or AlertIds(), IDS, purpose=Purpose.COLLECT,
                             component="collector", deadline=DEADLINE, check=check)  # fmt: skip


def searches(transport: FakeTransport) -> list[Any]:
    return [call for call in transport.calls if call.path.endswith("/_search")]


async def test_a_refusal_at_the_start_sends_nothing_and_takes_no_budget() -> None:
    gateway, transport, store, _ = make()
    check = Refuser(1)
    with pytest.raises(DeferredError):
        await collect(gateway, check)
    assert (check.calls, transport.calls, store.ledger) == ([T0], [], [])
    assert store.budget.day_used_ms == 0


async def test_a_refusal_after_a_budget_wait_sends_nothing() -> None:
    gateway, transport, store, clock = make()
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    check = Refuser(2)  # passes at the start, refuses after the wait
    with pytest.raises(DeferredError):
        await collect(gateway, check)
    assert clock.slept == [1.0]
    assert check.calls == [T0, T0 + timedelta(seconds=1)]
    assert searches(transport) == []


async def test_a_refusal_once_the_lease_is_held_settles_it_and_sends_nothing() -> None:
    gateway, transport, store, _ = make()
    check = Refuser(2)  # passes at the start, refuses with the lease in hand
    with pytest.raises(DeferredError):
        await collect(gateway, check)
    assert len(check.calls) == 2
    assert searches(transport) == []
    assert not store.budget.leases  # the lease was given back


async def test_a_refusal_before_the_retry_records_the_try() -> None:
    transport = FakeTransport().on("_search", failure(), ok(search_answer()))
    gateway, transport, store, clock = make(transport)
    check = Refuser(3)  # start, lease, then the retry
    with pytest.raises(DeferredError):
        await collect(gateway, check)
    assert len(searches(transport)) == 1  # the reset try only
    assert 0.5 <= clock.slept[0] <= 1.5
    assert (store.ledger[0].outcome, store.ledger[0].attempts) == ("deferred", 1)


async def test_a_check_that_passes_is_asked_at_each_point() -> None:
    transport = FakeTransport().on("_search", failure(), ok(search_answer()))
    gateway, transport, store, _ = make(transport)
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    check = Refuser(99)
    result = await collect(gateway, check)
    assert result.took_ms >= 0
    assert len(check.calls) == 4  # start, after the wait, with the lease, before the retry
    assert len(searches(transport)) == 2
    assert await collect(gateway, None) is not None  # no check: as before


class Halved(AlertIds):
    """A template whose answer keeps the first hit only."""

    def answer(self, params: Params, body: Any) -> Any:
        return {**body, "hits": {"hits": body["hits"]["hits"][:1]}}


async def test_the_templates_answer_is_what_comes_back() -> None:
    hits = [{"_id": "a"}, {"_id": "b"}]
    transport = FakeTransport().on("_search", ok(search_answer(hits)))
    gateway, transport, store, _ = make(transport)
    plain = await collect(gateway, None)
    assert plain.body["hits"]["hits"] == hits
    assert AlertIds().answer(IDS, plain.body) is plain.body  # the default keeps it as it came
    halved = await collect(gateway, None, Halved())
    assert halved.body["hits"]["hits"] == hits[:1]
    assert store.ledger[-1].response_bytes == store.ledger[0].response_bytes  # the wire's size
