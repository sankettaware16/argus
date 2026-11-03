"""Gateway.run end to end with a scripted transport: a refused request never reaches the
transport (R4 gate), retries, breaker, budget waits, live limits, index resolution, ledger."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from typing import Any, ClassVar

import pytest

from argus.gateway import breaker as br
from argus.gateway.budget import BudgetState
from argus.gateway.builtin import (
    AlertIds,
    AlertIdsParams,
    AlertsMget,
    Authenticate,
    ClusterInfo,
    Freshness,
    FreshnessParams,
    MgetParams,
    NodeStats,
)
from argus.gateway.errors import (
    AuthFailedError,
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    LiveSessionError,
    OverloadedError,
    PartialResultError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    TransportFailedError,
)
from argus.gateway.gateway import Gateway, LiveLimits
from argus.gateway.health import HealthMemory, HealthState
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
from argus.gateway.transport import WireResponse
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

pytestmark = pytest.mark.unit

DEADLINE = T0 + timedelta(seconds=30)
IDS = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0)


async def collect(gateway: Gateway, **kw: Any) -> Any:
    kw.setdefault("purpose", Purpose.COLLECT)
    kw.setdefault("component", "collector")
    kw.setdefault("deadline", DEADLINE)
    return await gateway.run(AlertIds(), IDS, **kw)


def searches(transport: FakeTransport) -> list[Any]:
    return [call for call in transport.calls if call.path.endswith("/_search")]


# --------------------------------------------------------------------------- the happy path


async def test_a_request_goes_out_exactly_as_validated() -> None:
    gateway, transport, store, _clock = make()
    result = await collect(gateway)
    assert result.indices == (".alerts-security.alerts-acme-soc",)
    assert result.took_ms == 5
    (call,) = transport.calls
    assert (call.method, call.path) == ("POST", "/.alerts-security.alerts-acme-soc/_search")
    assert call.opaque_id == "argus-collector/alerts.ids@1"
    assert dict(call.params) == {
        "allow_partial_search_results": "false",
        "ignore_unavailable": "false",
        "max_concurrent_shard_requests": "1",
    }
    body = json.loads(call.body or b"")
    assert body["timeout"] == "10s"
    assert body["_source"] is False
    assert call.timeout_s == 10.0
    (entry,) = store.ledger
    assert (entry.template, entry.version, entry.outcome, entry.http_status) == (
        "alerts.ids", 1, "ok", 200,
    )  # fmt: skip
    assert (entry.component, entry.purpose, entry.attempts, entry.took_ms) == (
        "collector", "collect", 1, 5,
    )  # fmt: skip
    assert entry.at == T0
    assert entry.elapsed_ms == 5
    assert entry.response_bytes == len(json.dumps(search_answer()))
    assert store.budget.leases == ()
    assert store.budget.day_used_ms == 5


async def test_the_timeout_follows_the_deadline() -> None:
    gateway, transport, _, _ = make()
    await collect(gateway, deadline=T0 + timedelta(seconds=4, milliseconds=500))
    body = json.loads(transport.calls[0].body or b"")
    assert body["timeout"] == "4s"
    assert transport.calls[0].timeout_s == 4.5
    await collect(gateway, deadline=T0 + timedelta(milliseconds=600))
    assert json.loads(transport.calls[1].body or b"")["timeout"] == "1s"


@pytest.mark.parametrize(
    ("template", "params", "method", "path"),
    [
        (ClusterInfo(), NoParams(), "GET", "/"),
        (Authenticate(), NoParams(), "GET", "/_security/_authenticate"),
        (NodeStats(), NoParams(), "GET", "/_nodes/_local/stats/fs,jvm,os,thread_pool,breaker"),
    ],
)
async def test_probe_paths(template: Template, params: Params, method: str, path: str) -> None:
    gateway, transport, _, _ = make(FakeTransport(default={"ok": True}))
    await gateway.run(template, params, purpose=Purpose.PROBE, component="probe", deadline=DEADLINE)
    (call,) = transport.calls
    assert (call.method, call.path, call.body) == (method, path, None)


async def test_mget_reads_one_backing_index() -> None:
    index = ".internal.alerts-security.alerts-acme-soc-000001"
    answer = {"docs": [{"_id": "a", "found": True, "_source": {}}]}
    gateway, transport, _, _ = make(FakeTransport(default=answer))
    params = MgetParams(index=index, ids=("a",))
    result = await gateway.run(
        AlertsMget(), params, purpose=Purpose.COLLECT, component="collector", deadline=DEADLINE
    )
    assert result.body == answer
    assert transport.calls[0].path == f"/{index}/_mget"
    assert json.loads(transport.calls[0].body or b"") == {"ids": ["a"]}


# --------------------------------------------------------------------------- refusals


class Forbidden(Template):
    name = "test.forbidden"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    filter_fields: ClassVar[frozenset[str]] = frozenset({"x"})
    max_size = 10

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), body={"size": 0, "query": {"wildcard": {"x": "*"}}})


async def refuse(
    gateway: Gateway, transport: FakeTransport, error: type[Exception], **kw: Any
) -> Exception:
    template = kw.pop("template", AlertIds())
    params = kw.pop("params", IDS)
    kw.setdefault("purpose", Purpose.COLLECT)
    kw.setdefault("component", "collector")
    kw.setdefault("deadline", DEADLINE)
    with pytest.raises(error) as info:
        await gateway.run(template, params, **kw)
    assert searches(transport) == []
    return info.value


async def test_a_passed_deadline_sends_nothing() -> None:
    gateway, transport, _, _ = make()
    await refuse(gateway, transport, DeadlinePassedError, deadline=T0)
    assert transport.calls == []


async def test_probe_cost_and_purpose_must_match() -> None:
    gateway, transport, _, _ = make()
    error = await refuse(gateway, transport, TemplateRejectedError, purpose=Purpose.PROBE)
    assert error.code == "cost_mismatch"  # type: ignore[attr-defined]
    await refuse(gateway, transport, TemplateRejectedError, template=NodeStats(), params=NoParams())
    assert transport.calls == []


async def test_wrong_parameters_are_a_programming_error() -> None:
    gateway, transport, _, _ = make()
    with pytest.raises(TypeError):
        await gateway.run(
            AlertIds(), NoParams(), purpose=Purpose.COLLECT, component="c", deadline=DEADLINE
        )
    assert transport.calls == []


@pytest.mark.parametrize(
    ("stopped", "purpose", "error"),
    [
        ({"global"}, Purpose.COLLECT, StoppedError),
        ({"collector"}, Purpose.COLLECT, StoppedError),
        ({"collector"}, Purpose.BACKFILL, StoppedError),
        ({"enrichment"}, Purpose.ENRICH, StoppedError),
        ({"writeback"}, Purpose.WRITEBACK, StoppedError),
    ],
)
async def test_kill_switches(stopped: set[str], purpose: Purpose, error: type[Exception]) -> None:
    gateway, transport, store, _ = make()
    store.stopped = stopped
    await refuse(gateway, transport, error, purpose=purpose)
    assert transport.calls == []


async def test_a_component_switch_stops_only_its_component() -> None:
    gateway, transport, store, _ = make()
    store.stopped = {"enrichment"}
    await collect(gateway)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    ("state", "purpose", "error"),
    [
        (HealthState.STOP, Purpose.COLLECT, StoppedError),
        (HealthState.STOP, Purpose.SELFTEST, StoppedError),
        (HealthState.DEGRADED, Purpose.ENRICH, DeferredError),
        (HealthState.DEGRADED, Purpose.BACKFILL, DeferredError),
        (HealthState.CAUTION, Purpose.BACKFILL, DeferredError),
        (HealthState.CAUTION, Purpose.RECONCILE, DeferredError),
        (HealthState.CAUTION, Purpose.WRITEBACK, DeferredError),
    ],
)
async def test_health_states_defer_or_stop_work(
    state: HealthState, purpose: Purpose, error: type[Exception]
) -> None:
    gateway, transport, store, _ = make()
    store.memory = HealthMemory(probed_at=T0, state=state)
    template = NodeStats() if purpose is Purpose.SELFTEST else AlertIds()
    params = NoParams() if purpose is Purpose.SELFTEST else IDS
    await refuse(gateway, transport, error, purpose=purpose, template=template, params=params)
    assert transport.calls == []


async def test_degraded_collects_on_a_tenth_of_the_budget_and_defers_the_rest() -> None:
    """Review #17: DEGRADED allows COLLECT, so it must get a budget (a tenth), not 0."""
    gateway, transport, store, _ = make()
    store.memory = HealthMemory(probed_at=T0, state=HealthState.DEGRADED)
    await collect(gateway)
    assert len(searches(transport)) == 1
    assert store.budget.tokens_ms == pytest.approx(300 - 5, abs=0.1)  # burst x 0.1, minus took
    transport.calls.clear()
    await refuse(gateway, transport, DeferredError, purpose=Purpose.BACKFILL)


async def test_probes_run_in_stop_under_the_kill_switch_and_an_open_breaker() -> None:
    gateway, transport, store, _ = make(FakeTransport(default={"nodes": {}}))
    store.memory = HealthMemory(probed_at=T0, state=HealthState.STOP)
    store.stopped = {"global"}
    store.breaker = br.on_overload(br.BreakerState(), T0)
    await gateway.run(
        NodeStats(), NoParams(), purpose=Purpose.PROBE, component="probe", deadline=DEADLINE
    )
    assert len(transport.calls) == 1
    assert store.breaker.open_until == T0 + timedelta(minutes=5)  # a probe does not close it


async def test_the_validator_refuses_before_sending() -> None:
    gateway, transport, _, _ = make()
    error = await refuse(
        gateway, transport, TemplateRejectedError, template=Forbidden(), params=NoParams()
    )
    assert error.code == "forbidden_clause"  # type: ignore[attr-defined]
    assert transport.calls == []


@pytest.mark.parametrize("index", ["acme-logs-squid-2026.10.09", ".alerts-other", "abuse-ioc"])
async def test_an_index_outside_the_family_is_refused(index: str) -> None:
    gateway, transport, _, _ = make()
    params = MgetParams(index=index, ids=("a",))
    await refuse(gateway, transport, TemplateRejectedError, template=AlertsMget(), params=params)
    assert transport.calls == []


async def test_an_open_breaker_refuses_work() -> None:
    gateway, transport, store, _ = make()
    store.breaker = br.on_overload(br.BreakerState(), T0)
    error = await refuse(gateway, transport, BreakerOpenError)
    assert error.until == T0 + timedelta(minutes=5)  # type: ignore[attr-defined]
    assert transport.calls == []


async def test_a_spent_budget_skips_the_work() -> None:
    gateway, transport, store, _ = make()
    store.budget = BudgetState(day=T0.date(), day_used_ms=3_600_000)
    await refuse(gateway, transport, BudgetExhaustedError)
    assert transport.calls == []


async def test_a_budget_that_frees_up_after_the_deadline_sends_nothing() -> None:
    gateway, transport, store, clock = make()
    store.budget = BudgetState(tokens_ms=-3_000.0, refilled_at=T0, day=T0.date())
    await refuse(gateway, transport, DeadlinePassedError, deadline=T0 + timedelta(seconds=10))
    assert transport.calls == []
    assert clock.slept == []


async def test_waiting_for_the_budget_within_the_deadline() -> None:
    gateway, transport, store, clock = make()
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    await collect(gateway)
    assert clock.slept == [1.0]  # 50 ms of tokens at 50 ms/s
    assert len(transport.calls) == 1


async def test_caution_halves_the_budget_rate() -> None:
    gateway, _transport, store, clock = make()
    store.memory = HealthMemory(probed_at=T0, state=HealthState.CAUTION)
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    await collect(gateway)
    assert clock.slept == [2.0]


async def test_slow_start_after_recovery() -> None:
    gateway, _transport, store, clock = make()
    store.memory = HealthMemory(
        probed_at=T0, state=HealthState.NORMAL, recovered_at=T0 - timedelta(minutes=5)
    )
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    await collect(gateway)
    assert clock.slept == [4.0]


# --------------------------------------------------------------------------- answers


async def test_one_retry_on_a_reset_connection() -> None:
    transport = FakeTransport().on("_search", failure(), ok(search_answer()))
    gateway, transport, store, clock = make(transport)
    await collect(gateway)
    assert len(transport.calls) == 2
    assert 0.5 <= clock.slept[0] <= 1.5
    assert (store.ledger[0].attempts, store.ledger[0].outcome) == (2, "ok")


async def test_one_retry_on_502_and_503_never_504() -> None:
    for status, calls in ((502, 2), (503, 2)):
        transport = FakeTransport().on("_search", ok({}, status), ok(search_answer()))
        gateway, transport, _, _ = make(transport)
        await collect(gateway)
        assert len(transport.calls) == calls
    transport = FakeTransport().on("_search", ok({}, 504), ok(search_answer()))
    gateway, transport, store, _ = make(transport)
    with pytest.raises(TransportFailedError):
        await collect(gateway)
    assert len(transport.calls) == 1
    assert (store.ledger[0].outcome, store.ledger[0].http_status) == ("transport_failure", 504)


async def test_no_second_retry() -> None:
    transport = FakeTransport().on("_search", failure(), failure(), ok(search_answer()))
    gateway, transport, store, _ = make(transport)
    with pytest.raises(TransportFailedError):
        await collect(gateway)
    assert len(transport.calls) == 2
    assert store.budget.leases == ()


async def test_no_retry_without_time_left_or_for_a_permanent_failure() -> None:
    transport = FakeTransport().on("_search", failure(), ok(search_answer()))
    gateway, transport, _, _ = make(transport)
    with pytest.raises(TransportFailedError):
        await collect(gateway, deadline=T0 + timedelta(seconds=2))
    assert len(transport.calls) == 1
    transport = FakeTransport().on("_search", failure(retriable=False), ok(search_answer()))
    gateway, transport, _, _ = make(transport)
    with pytest.raises(TransportFailedError):
        await collect(gateway)
    assert len(transport.calls) == 1


async def test_a_timeout_is_charged_in_full_and_not_retried() -> None:
    transport = FakeTransport().on("_search", TimedOutError(), ok(search_answer()))
    gateway, transport, store, _ = make(transport)
    with pytest.raises(TimedOutError):
        await collect(gateway)
    assert len(transport.calls) == 1
    assert (store.ledger[0].outcome, store.ledger[0].took_ms) == ("timed_out", 10_000)
    assert store.budget.day_used_ms == 10_000


async def test_a_request_that_never_reached_siem_costs_nothing() -> None:
    """The SIEM unreachable (maintenance, D-093): no connection, no server time charged, so
    the budget is whole when it returns."""
    never = (
        TimedOutError("no connection before the deadline", reached=False),
        TransportFailedError("connection failed", retriable=False, reached=False),
    )
    for error in never:
        transport = FakeTransport().on("_search", error)
        gateway, transport, store, _ = make(transport)
        with pytest.raises(TransportFailedError):
            await collect(gateway)
        assert store.ledger[0].took_ms == 0
        assert store.budget.day_used_ms == 0
    retried = FakeTransport().on(
        "_search", TransportFailedError("connection failed", retriable=True, reached=False),
        ok(search_answer()),
    )  # fmt: skip
    gateway, retried, store, _ = make(retried)
    await collect(gateway)
    assert len(retried.calls) == 2
    assert store.ledger[0].took_ms == search_answer()["took"]


async def test_an_overload_opens_the_breaker() -> None:
    transport = FakeTransport().on(
        "_search", ok({"error": {"type": "es_rejected_execution_exception"}}, 429)
    )
    gateway, transport, store, clock = make(transport)
    with pytest.raises(OverloadedError):
        await collect(gateway)
    assert store.breaker.open_until == clock.now + timedelta(minutes=5)
    assert store.ledger[0].outcome == "overloaded"
    with pytest.raises(BreakerOpenError):
        await collect(gateway)
    assert len(transport.calls) == 1


async def test_a_successful_trial_closes_the_breaker() -> None:
    gateway, _transport, store, _clock = make()
    store.breaker = br.on_overload(br.BreakerState(), T0 - timedelta(minutes=5))
    await collect(gateway)
    assert store.breaker.open_until is None
    assert store.breaker.level == 1


@pytest.mark.parametrize(
    ("answer", "error", "outcome"),
    [
        (ok(search_answer() | {"timed_out": True}), PartialResultError, "partial_result"),
        (ok({}, 401), AuthFailedError, "auth_failed"),
        (ok({"error": {"type": "index_not_found_exception"}}, 404), SourceMissingError,
         "source_expired"),
        (WireResponse(200, b"not json", 1.0), Exception, "response_error"),
    ],
)  # fmt: skip
async def test_bad_answers_are_errors_and_charged(
    answer: WireResponse, error: type[Exception], outcome: str
) -> None:
    gateway, _transport, store, _ = make(FakeTransport().on("_search", answer))
    with pytest.raises(error):
        await collect(gateway)
    assert store.ledger[0].outcome == outcome
    assert store.budget.leases == ()
    assert store.breaker == br.BreakerState()


# --------------------------------------------------------------------------- log indices


def fresh(now: Any = T0) -> FreshnessParams:
    return FreshnessParams(source="squid", now=now)


async def probe(gateway: Gateway, params: FreshnessParams) -> Any:
    return await gateway.run(
        Freshness(),
        params,
        purpose=Purpose.PROBE,
        component="probe",
        deadline=params.now + timedelta(seconds=30),
    )


async def test_log_windows_resolve_to_existing_daily_indices() -> None:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_YESTERDAY, SQUID_TODAY)))
    gateway, transport, _, clock = make(transport)
    result = await probe(gateway, fresh())
    assert result.indices == (SQUID_TODAY,)
    assert transport.calls[0].path == "/_resolve/index/acme-logs-squid-*"
    assert transport.calls[1].path == f"/{SQUID_TODAY}/_search"
    await probe(gateway, fresh())
    assert [c.path for c in transport.calls].count("/_resolve/index/acme-logs-squid-*") == 1
    clock.now = T0.replace(hour=0, minute=20)
    result = await probe(gateway, fresh(clock.now))
    assert result.indices == (SQUID_YESTERDAY, SQUID_TODAY)


async def test_an_expired_day_is_never_skipped_silently() -> None:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    gateway, transport, _, clock = make(transport)
    clock.now = T0.replace(hour=0, minute=20)
    with pytest.raises(SourceMissingError) as info:
        await probe(gateway, fresh(clock.now))
    assert (info.value.reason, info.value.days) == ("source_expired", ("2026.10.08",))
    assert searches(transport) == []


async def test_a_missing_today_refreshes_the_listing_once_a_minute() -> None:
    listings = (ok(listing(SQUID_YESTERDAY)), ok(listing(SQUID_YESTERDAY, SQUID_TODAY)))
    gateway, transport, _, clock = make(FakeTransport().on("_resolve", *listings))
    with pytest.raises(SourceMissingError) as info:
        await probe(gateway, fresh())  # the listing was just read: no second read
    assert info.value.reason == "source_not_ready"
    assert len(transport.calls) == 1
    clock.advance(timedelta(minutes=2))  # within the 5-minute cache, but over a minute old
    result = await probe(gateway, fresh(clock.now))
    assert result.indices == (SQUID_TODAY,)
    assert [c.path.split("/")[1] for c in transport.calls] == ["_resolve", "_resolve", SQUID_TODAY]


# --------------------------------------------------------------------------- live sessions


class Wide(Template):
    name = "test.wide"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.MEDIUM
    filter_fields: ClassVar[frozenset[str]] = frozenset({"@timestamp"})
    aggregate_fields: ClassVar[frozenset[str]] = frozenset({"source.ip"})
    max_size = 500
    minutes: ClassVar[int] = 10
    size: ClassVar[int] = 5
    aggregate: ClassVar[bool] = False

    def build(self, params: Params) -> RequestPlan:
        body: dict[str, Any] = {"size": self.size, "track_total_hits": False, "_source": False}
        if self.aggregate:
            body["aggs"] = {"a": {"terms": {"field": "source.ip", "size": 5}}}
        window = Window("squid", T0 - timedelta(minutes=self.minutes), T0)
        return RequestPlan(self.spec(), body=body, window=window)


def live_gateway(**limits: Any) -> tuple[Gateway, FakeTransport, MemoryStore]:
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    store.sessions["s1"] = LiveSession("s1", ends_at=T0 + timedelta(minutes=20), max_requests=50)
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    gateway, transport, store, _ = make(transport, store, live=LiveLimits("s1", **limits))
    return gateway, transport, store


async def run_enrich(gateway: Gateway, template: Template) -> Any:
    return await gateway.run(
        template, NoParams(), purpose=Purpose.ENRICH, component="enrichment", deadline=DEADLINE
    )


async def test_live_sessions_allow_small_reads() -> None:
    gateway, _transport, store = live_gateway()
    await run_enrich(gateway, Wide())
    assert store.sessions["s1"].used == 2  # the listing and the search
    assert store.ledger[-1].live_session == "s1"


@pytest.mark.parametrize(
    "template",
    [
        type("Big", (Wide,), {"size": 11}),
        type("Agg", (Wide,), {"aggregate": True, "cost": CostClass.HEAVY}),
        type("Long", (Wide,), {"minutes": 16}),
    ],
)
async def test_live_limits(template: type[Template]) -> None:
    gateway, transport, _ = live_gateway()
    with pytest.raises(LiveSessionError):
        await run_enrich(gateway, template())
    assert searches(transport) == []


async def test_live_sessions_end() -> None:
    gateway, transport, store = live_gateway()
    store.sessions["s1"] = replace(store.sessions["s1"], used=50)
    with pytest.raises(LiveSessionError):
        await collect(gateway)
    store.sessions["s1"] = replace(store.sessions["s1"], used=0, ends_at=T0)
    with pytest.raises(LiveSessionError):
        await collect(gateway)
    store.sessions["s1"] = replace(
        store.sessions["s1"], ends_at=T0 + timedelta(hours=1), ended=True
    )
    with pytest.raises(LiveSessionError):
        await collect(gateway)
    del store.sessions["s1"]
    with pytest.raises(LiveSessionError):
        await collect(gateway)
    assert transport.calls == []


async def test_live_sessions_send_at_most_ten_per_minute() -> None:
    gateway, transport, _ = live_gateway()
    small = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0, size=10)

    async def read() -> None:
        await gateway.run(
            AlertIds(), small, purpose=Purpose.COLLECT, component="c", deadline=DEADLINE
        )

    for _ in range(10):
        await read()
    with pytest.raises(LiveSessionError):
        await read()
    assert len(transport.calls) == 10
    with pytest.raises(LiveSessionError, match="at most 10 documents"):
        await collect(gateway)
