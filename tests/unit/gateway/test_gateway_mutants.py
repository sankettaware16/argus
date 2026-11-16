"""Gateway orchestration tests written for mutation survivors (D-040): every refusal branch of
index naming, exact deadline and retry boundaries, listing cache ages, live-session limits and
the ledger's numbers."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest

from argus.gateway import breaker as br
from argus.gateway.budget import Admission, BudgetState, Lease, Verdict
from argus.gateway.builtin import Freshness, FreshnessParams, IndexListing, IndexListingParams
from argus.gateway.errors import (
    BreakerOpenError,
    DeadlinePassedError,
    LiveSessionError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TransportFailedError,
)
from argus.gateway.gateway import Gateway, LiveLimits, Result, Targets, utcnow
from argus.gateway.health import HealthMemory
from argus.gateway.state import LiveSession, MemoryStore
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    NoParams,
    Params,
    Purpose,
    RequestPlan,
    Template,
    Window,
)
from tests.unit.gateway.fakes import (
    SQUID_TODAY,
    SQUID_YESTERDAY,
    T0,
    FakeTransport,
    failure,
    listing,
    make,
    ok,
    search_answer,
)
from tests.unit.gateway.test_gateway import DEADLINE, collect, searches

pytestmark = pytest.mark.unit

MIN = timedelta(minutes=1)
LISTING = "/_resolve/index/acme-logs-squid-*"


class Planned(Template):
    """A template whose plan is given per test."""

    name = "test.planned"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    filter_fields: ClassVar[frozenset[str]] = frozenset({"@timestamp"})
    max_size = 10
    window: ClassVar[Window | None] = None
    names: ClassVar[tuple[str, ...]] = ()
    source: ClassVar[str | None] = None
    body: ClassVar[Any] = {"size": 0}

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(
            self.spec(), body=self.body, window=self.window, names=self.names, source=self.source
        )


def planned(**kw: Any) -> Template:
    return type("T", (Planned,), kw)()  # type: ignore[no-any-return]


async def enrich(gateway: Gateway, template: Template, **kw: Any) -> Result:
    kw.setdefault("deadline", DEADLINE)
    return await gateway.run(
        template, NoParams(), purpose=Purpose.ENRICH, component="enrichment", **kw
    )


async def refused(gateway: Gateway, template: Template, message: str) -> None:
    with pytest.raises(TemplateRejectedError, match=rf"^{message}$"):
        await enrich(gateway, template)
    assert gateway.transport.calls == []  # type: ignore[attr-defined]


async def fresh(gateway: Gateway, now: datetime = T0, **kw: Any) -> Result:
    kw.setdefault("deadline", now + timedelta(seconds=30))
    return await gateway.run(
        Freshness(),
        FreshnessParams(source="squid", now=now),
        purpose=Purpose.PROBE,
        component="probe",
        **kw,
    )


def listings(transport: FakeTransport) -> int:
    return sum(call.path == LISTING for call in transport.calls)


# --------------------------------------------------------------------------- defaults


def test_utcnow_is_aware_and_now() -> None:
    assert abs(utcnow() - datetime.now(UTC)) < timedelta(seconds=1)
    assert utcnow().tzinfo is UTC


def test_targets_defaults_and_frozen_results() -> None:
    t = Targets()
    assert t.log_sources == {"squid", "dns", "nginx", "postfix"}
    assert t.ti == {"abuse-ioc", "acme-threat-intel"}
    assert t.log_index_prefix("dns") == "acme-logs-dns-"
    with pytest.raises(TemplateRejectedError, match=r"^index_not_allowed: smtp is not a log"):
        t.log_index_prefix("smtp")
    for frozen in (t, LiveLimits("s"), Result({}, 0, ())):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.x = 1  # type: ignore[attr-defined]


async def test_a_gateway_without_targets_uses_the_defaults() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, MemoryStore(memory=HealthMemory(probed_at=T0)), clock=lambda: T0)
    await collect(gateway)
    assert transport.calls[0].path == "/.alerts-security.alerts-acme-soc/_search"


# --------------------------------------------------------------------------- refusals


async def test_a_deadline_equal_to_now_has_passed() -> None:
    gateway, transport, _, _ = make()
    with pytest.raises(DeadlinePassedError, match=r"before the request started"):
        await collect(gateway, deadline=T0)
    assert transport.calls == []


async def test_messages_of_state_refusals() -> None:
    gateway, _, store, _ = make()
    with pytest.raises(TemplateRejectedError, match=r"for probes and self-tests only"):
        await gateway.run(
            IndexListing(), IndexListingParams(source="squid"), purpose=Purpose.COLLECT,
            component="c", deadline=DEADLINE,
        )  # fmt: skip
    store.stopped = {"global"}
    with pytest.raises(StoppedError, match=r"^stopped by the operator's kill switch$"):
        await collect(gateway)
    store.stopped = set()
    store.memory = HealthMemory(probed_at=T0 - 20 * MIN)
    with pytest.raises(StoppedError, match=r"^the SIEM is in STOP$"):
        await collect(gateway)


async def test_index_naming_refusals() -> None:
    window = Window("squid", T0 - MIN, T0)
    log = {"family": Family.LOG, "body": {"size": 0, "track_total_hits": False}}
    cases = [
        (planned(endpoint=Endpoint.RESOLVE_INDEX, family=Family.CLUSTER, cost=CostClass.MEDIUM,
                 body=None), "index_not_allowed: resolve_index needs a source"),
        (planned(**log), "index_not_allowed: log requests name a window"),
        (planned(**log, window=window, names=(SQUID_TODAY,)),
         "index_not_allowed: log requests name a window"),
        (planned(**log, window=Window("squid", T0 - timedelta(days=3), T0)),
         "too_many_indices: a log window spans at most 2 daily indices"),
        (planned(names=(".alerts-other",)), "index_not_allowed: not an alerts index"),
        (planned(family=Family.TI), "index_not_allowed: not a threat-intel index"),
        (planned(family=Family.TI, names=("abuse-ioc", "other")),
         "index_not_allowed: not a threat-intel index"),
        (planned(endpoint=Endpoint.INDEX_BLOCKS, family=Family.CLUSTER, body=None,
                 names=("other",)), "index_not_allowed: not an ARGUS index"),
    ]  # fmt: skip
    for template, message in cases:
        gateway, _, _, _ = make()
        await refused(gateway, template, message)


async def test_threat_intel_and_cluster_names_pass_through() -> None:
    gateway, transport, _, _ = make()
    await enrich(gateway, planned(family=Family.TI, names=("abuse-ioc", "acme-threat-intel")))
    assert transport.calls[-1].path == "/abuse-ioc,acme-threat-intel/_search"


async def test_a_window_on_a_non_log_template_reads_no_listing() -> None:
    gateway, transport, _, _ = make()
    await enrich(gateway, planned(window=Window("squid", T0 - MIN, T0)))
    assert listings(transport) == 0


# --------------------------------------------------------------------------- listings


async def test_the_listing_is_cached_for_five_minutes() -> None:
    gateway, transport, _, clock = make(FakeTransport().on("_resolve", ok(listing(SQUID_TODAY))))
    await fresh(gateway)
    assert transport.calls[0].opaque_id == "argus-gateway/indices.listing@1"
    clock.now = T0 + 5 * MIN - timedelta(milliseconds=1)
    await fresh(gateway, clock.now)
    assert listings(transport) == 1  # 2 minutes old is still fresh for a present day
    clock.now = T0 + 5 * MIN
    await fresh(gateway, clock.now)
    assert listings(transport) == 2


async def test_a_missing_today_refreshes_after_exactly_one_minute() -> None:
    answers = (ok(listing(SQUID_YESTERDAY)), ok(listing(SQUID_TODAY)))
    gateway, transport, _, clock = make(FakeTransport().on("_resolve", *answers))
    with pytest.raises(SourceMissingError):
        await fresh(gateway)
    clock.now = T0 + MIN
    await fresh(gateway, clock.now)
    assert listings(transport) == 2


async def test_an_expired_day_does_not_refresh_the_listing() -> None:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    gateway, transport, _, clock = make(transport)
    clock.now = T0.replace(hour=0, minute=20)  # needs 10.08 (gone) and 10.09
    for minutes in (0, 2):  # a 2-minute-old listing would be re-read for a missing today
        clock.now += minutes * MIN
        with pytest.raises(SourceMissingError, match=r"source_expired"):
            await fresh(gateway, clock.now)
    assert listings(transport) == 1


async def test_the_listing_request_is_recorded_with_its_pattern() -> None:
    gateway, _, store, _ = make(FakeTransport().on("_resolve", ok(listing(SQUID_TODAY))))
    await fresh(gateway)
    first = store.ledger[0]
    assert (first.template, first.component, first.indices) == (
        "indices.listing", "gateway", ("acme-logs-squid-*",),
    )  # fmt: skip


async def test_a_listing_that_uses_up_the_deadline_sends_no_search() -> None:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    gateway, transport, store, _ = make(transport)
    with pytest.raises(DeadlinePassedError, match=r"before the request was sent"):
        await fresh(gateway, deadline=T0 + timedelta(milliseconds=5))  # the listing takes 5 ms
    assert searches(transport) == []
    assert store.ledger[-1].outcome == "deadline_passed"
    assert store.budget.leases == ()


# --------------------------------------------------------------------------- live sessions


def live(**kw: Any) -> tuple[Gateway, FakeTransport, MemoryStore, Any]:
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    store.sessions["s"] = LiveSession("s", ends_at=T0 + 30 * MIN, max_requests=50)
    gateway, transport, store, clock = make(store=store, live=LiveLimits("s", **kw))
    return gateway, transport, store, clock


async def test_live_limits_at_their_boundaries() -> None:
    gateway, _, _, _ = live(max_size=9)
    with pytest.raises(LiveSessionError):  # no size means 10
        await enrich(gateway, planned(body={"_source": False}))
    gateway, _, _, _ = live()
    with pytest.raises(LiveSessionError, match=r"^live tests do not aggregate$"):
        await enrich(gateway, planned(
            aggregate_fields=frozenset({"@timestamp"}),
            body={"size": 0, "aggregations": {"a": {"min": {"field": "@timestamp"}}}},
        ))  # fmt: skip
    gateway, _, _, _ = live()
    log = {"family": Family.LOG, "body": {"size": 0, "track_total_hits": False}}
    gateway.transport.on("_resolve", ok(listing(SQUID_TODAY)))  # type: ignore[attr-defined]
    await enrich(gateway, planned(**log, window=Window("squid", T0 - 15 * MIN, T0)))
    too_long = Window("squid", T0 - 15 * MIN - timedelta(seconds=1), T0)
    with pytest.raises(LiveSessionError, match=r"^live tests read at most 15 minutes of logs$"):
        await enrich(gateway, planned(**log, window=too_long))


async def test_the_per_minute_count_forgets_after_exactly_a_minute() -> None:
    gateway, _, _, clock = live(per_minute=2)
    await enrich(gateway, planned())
    clock.now = T0
    await enrich(gateway, planned())
    with pytest.raises(LiveSessionError, match=r"at most 2 per minute"):
        await enrich(gateway, planned())
    clock.now = T0 + MIN  # both started at T0
    await enrich(gateway, planned(), deadline=clock.now + MIN)


async def test_a_used_up_session_refuses() -> None:
    gateway, transport, store, _ = live()
    store.sessions["s"] = dataclasses.replace(store.sessions["s"], used=50)
    with pytest.raises(LiveSessionError, match=r"^the live-test session is over or used up$"):
        await enrich(gateway, planned())
    assert transport.calls == []


# --------------------------------------------------------------------------- budget waits


async def test_a_heavy_concurrency_wait_polls() -> None:
    gateway, transport, store, _ = make()
    heavy = Lease("h", CostClass.HEAVY, 1_000, T0 + 2 * MIN)
    store.budget = BudgetState(tokens_ms=3_000.0, refilled_at=T0, day=T0.date(), leases=(heavy,))
    clock = gateway.clock

    async def sleep(seconds: float) -> None:
        store.budget = dataclasses.replace(store.budget, leases=())
        clock.advance(timedelta(seconds=seconds))  # type: ignore[attr-defined]

    gateway.sleep = sleep
    agg = planned(
        family=Family.LOG, cost=CostClass.HEAVY, aggregate_fields=frozenset({"@timestamp"}),
        window=Window("squid", T0 - MIN, T0),
        body={
            "size": 0, "track_total_hits": False, "aggs": {"a": {"min": {"field": "@timestamp"}}},
        },
    )  # fmt: skip
    transport.on("_resolve", ok(listing(SQUID_TODAY)))
    await enrich(gateway, agg, deadline=T0 + timedelta(seconds=3))
    assert len(searches(transport)) == 1


async def test_a_budget_free_exactly_at_the_deadline_is_too_late() -> None:
    gateway, transport, store, clock = make()
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())  # 1 s to wait
    with pytest.raises(DeadlinePassedError, match=r"frees up too late"):
        await collect(gateway, deadline=T0 + timedelta(seconds=1))
    assert clock.slept == []
    assert transport.calls == []


async def test_a_wait_without_a_retry_time_waits_a_second() -> None:
    gateway, _, store, clock = make()
    real = store.budget_admit
    answers = [Admission(Verdict.WAIT, "x")]

    async def admit(*args: Any, **kw: Any) -> Any:
        return answers.pop() if answers else await real(*args, **kw)

    store.budget_admit = admit  # type: ignore[method-assign]
    await collect(gateway)
    assert clock.slept == [1.0]


async def test_the_state_is_judged_at_the_time_after_the_wait() -> None:
    gateway, transport, store, _ = make()
    store.memory = HealthMemory(probed_at=T0 - 15 * MIN + timedelta(milliseconds=500))
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    with pytest.raises(StoppedError):  # stale for 15 minutes once the 1 s wait is over
        await collect(gateway)
    assert transport.calls == []


async def test_after_a_wait_an_open_breaker_refuses_before_asking_the_budget() -> None:
    gateway, _, store, _ = make()
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    calls = 0
    real = store.budget_admit

    async def admit(*args: Any, **kw: Any) -> Any:
        nonlocal calls
        calls += 1
        return await real(*args, **kw)

    store.budget_admit = admit  # type: ignore[method-assign]
    clock = gateway.clock

    async def sleep(seconds: float) -> None:
        store.breaker = br.on_overload(store.breaker, T0)
        clock.advance(timedelta(seconds=seconds))  # type: ignore[attr-defined]

    gateway.sleep = sleep
    with pytest.raises(BreakerOpenError):
        await collect(gateway)
    assert calls == 1


# --------------------------------------------------------------------------- sending


async def test_retry_needs_more_than_two_seconds_left() -> None:
    def transport() -> FakeTransport:
        return FakeTransport(latency=timedelta(0)).on("_search", failure(), ok(search_answer()))

    gateway, sent, _, _ = make(transport())
    with pytest.raises(TransportFailedError):
        await collect(gateway, deadline=T0 + timedelta(seconds=2))
    assert len(sent.calls) == 1
    gateway, sent, _, _ = make(transport())
    await collect(gateway, deadline=T0 + timedelta(seconds=2, milliseconds=1))
    assert len(sent.calls) == 2


async def test_retry_jitter_is_half_a_second_to_one_and_a_half() -> None:
    seen: list[tuple[float, float]] = []

    class Rng:
        def uniform(self, low: float, high: float) -> float:
            seen.append((low, high))
            return low

    gateway, _, _, _ = make(FakeTransport().on("_search", failure(), ok(search_answer())))
    gateway.rng = Rng()  # type: ignore[assignment]
    await collect(gateway)
    assert seen == [(0.5, 1.5)]


async def test_charges_and_ledger_numbers_are_exact() -> None:
    slow = FakeTransport(latency=timedelta(seconds=2)).on(
        "_search", failure(), failure(retriable=False)
    )
    gateway, _, store, _ = make(slow)
    gateway.rng.seed(1)
    with pytest.raises(TransportFailedError):
        await collect(gateway)
    (entry,) = store.ledger
    assert entry.took_ms == 4_000  # 2 s per attempt, not the jitter in between
    assert entry.response_bytes == 0
    assert entry.elapsed_ms > 4_000
    quick = FakeTransport(latency=timedelta(0)).on("_search", failure(retriable=False))
    gateway, _, store, _ = make(quick)
    with pytest.raises(TransportFailedError):
        await collect(gateway)
    assert (store.ledger[0].took_ms, store.ledger[0].elapsed_ms) == (0, 0)
