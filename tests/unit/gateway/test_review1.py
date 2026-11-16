"""Regression tests for R4 review round 1 (docs/reviews/r4-review-1.md): one or more per
finding, named after it. Each failed before its fix."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import timedelta
from typing import Any, ClassVar

import httpx
import pytest

from argus.config.settings import SiemSettings
from argus.gateway import breaker as br
from argus.gateway.budget import BudgetConfig, BudgetState, Lease, admit, roll, settle
from argus.gateway.builtin import Freshness, FreshnessParams, NodeStats
from argus.gateway.errors import (
    AuthFailedError,
    BreakerOpenError,
    BudgetExhaustedError,
    DeferredError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    UnsupportedValueError,
)
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState, effective
from argus.gateway.service import probe
from argus.gateway.state import MemoryStore
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    NoParams,
    Params,
    Purpose,
    RequestPlan,
    Spec,
    Template,
    Window,
)
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, encode_body, validate
from tests.unit.gateway.fakes import (
    SQUID_TODAY,
    T0,
    FakeTransport,
    failure,
    listing,
    make,
    ok,
    search_answer,
)
from tests.unit.gateway.test_gateway import DEADLINE, collect, searches
from tests.unit.gateway.test_transport import REQUEST, transport_with

pytestmark = pytest.mark.unit

MIN = timedelta(minutes=1)
L, P = CostClass.LIGHT, CostClass.PROBE


def on_sleep(gateway: Gateway, action: Any) -> list[float]:
    """Run ``action`` during the gateway's next wait (then sleep on the fake clock)."""
    slept: list[float] = []
    clock = gateway.clock

    async def sleep(seconds: float) -> None:
        slept.append(seconds)
        action()
        clock.advance(timedelta(seconds=seconds))  # type: ignore[attr-defined]

    gateway.sleep = sleep
    return slept


def no_tokens() -> BudgetState:
    return BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())


# --------------------------------------------------------------- 1. re-checks after waits


@pytest.mark.parametrize(
    ("change", "error"),
    [
        (lambda s: s.stopped.add("global"), StoppedError),
        (lambda s: s.stopped.add("collector"), StoppedError),
        (lambda s: setattr(s, "memory", replace(s.memory, state=HealthState.STOP)), StoppedError),
        (lambda s: setattr(s, "breaker", br.on_overload(s.breaker, T0)), BreakerOpenError),
    ],
)
async def test_1_a_budget_wait_never_outlives_a_refusal(change: Any, error: type) -> None:
    gateway, transport, store, _ = make()
    store.budget = no_tokens()
    on_sleep(gateway, lambda: change(store))
    with pytest.raises(error):
        await collect(gateway)
    assert transport.calls == []
    assert store.budget.leases == ()


async def test_1_the_retry_is_refused_after_a_kill_switch_and_the_lease_settles() -> None:
    gateway, transport, store, _ = make(FakeTransport().on("_search", failure(), ok({})))
    on_sleep(gateway, lambda: store.stopped.add("global"))
    with pytest.raises(StoppedError):
        await collect(gateway)
    assert len(transport.calls) == 1
    (entry,) = store.ledger
    assert (entry.outcome, entry.attempts, entry.took_ms) == ("stopped", 1, 5)
    assert store.budget.leases == ()
    assert store.budget.day_used_ms == 5  # the first attempt's time stays charged


async def test_1_the_retry_is_refused_when_the_breaker_opened() -> None:
    gateway, transport, store, _ = make(FakeTransport().on("_search", failure(), ok({})))
    on_sleep(gateway, lambda: setattr(store, "breaker", br.on_overload(store.breaker, T0)))
    with pytest.raises(BreakerOpenError):
        await collect(gateway)
    assert len(transport.calls) == 1
    assert store.ledger[0].outcome == "breaker_open"


# --------------------------------------------------------------- 2. concurrency waits poll


async def test_2_a_concurrency_wait_polls_instead_of_waiting_for_lease_expiry() -> None:
    gateway, transport, store, _ = make()
    held = tuple(Lease(f"x{n}", L, 50, T0 + 2 * MIN) for n in range(2))
    store.budget = BudgetState(tokens_ms=3_000.0, refilled_at=T0, day=T0.date(), leases=held)
    slept = on_sleep(gateway, lambda: setattr(store, "budget", replace(store.budget, leases=())))
    await collect(gateway, deadline=T0 + timedelta(seconds=3))
    assert slept == [0.5]
    assert len(searches(transport)) == 1


SETTINGS = SiemSettings()
NODE = {
    "_nodes": {"total": 1, "successful": 1, "failed": 0},
    "nodes": {
        "n": {
            "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 50}},
            "jvm": {"mem": {"heap_used_percent": 50}},
            "os": {"cpu": {"load_average": {"1m": 1.0}}},
            "thread_pool": {"search": {"queue": 0, "rejected": 0}, "write": {"rejected": 0}},
            "breakers": {"parent": {"tripped": 0}},
        }
    },
}
BLOCKS = {".internal.alerts-security.alerts-acme-soc-000001": {"settings": {"index.uuid": "u"}}}


async def test_2_a_local_refusal_is_not_a_failed_probe() -> None:
    gateway, transport, store, _ = make()
    store.memory = HealthMemory(state=HealthState.NORMAL, probed_at=T0 - MIN)
    store.budget = BudgetState(
        refilled_at=T0, day=T0.date(), probe_starts=(T0,) * BudgetConfig().probes_per_minute
    )
    memory = await probe(gateway, store, SETTINGS, T0)
    assert transport.calls == []
    assert memory == store.memory  # unchanged: nothing was learnt about the SIEM
    assert memory.state is HealthState.NORMAL


# --------------------------------------------------------------- 3 and 20. probe answers


async def test_20_the_alerts_index_must_answer_the_blocks_probe() -> None:
    for blocks, state in ((BLOCKS, HealthState.NORMAL), ({}, HealthState.DEGRADED)):
        transport = FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(blocks))
        gateway, _, store, _ = make(transport)
        memory = await probe(gateway, store, SETTINGS, T0)
        assert memory.state is state
        assert memory.probed_at == T0


async def test_3_a_node_without_readings_does_not_read_as_healthy() -> None:
    bare = {"_nodes": {"failed": 0}, "nodes": {"n": {}}}
    transport = FakeTransport().on("_nodes", ok(bare)).on("_settings", ok(BLOCKS))
    gateway, _, store, _ = make(transport)
    memory = await probe(gateway, store, SETTINGS, T0)
    assert (memory.state, memory.reasons) == (HealthState.DEGRADED, ("probe_failed",))


def test_3_node_stats_asks_for_the_node_summary() -> None:
    assert NodeStats.version == 2
    assert NodeStats.FILTER.split(",")[0] == "_nodes.failed"


# --------------------------------------------------------------- 4. stale health


@pytest.mark.parametrize(
    ("probed", "state"),
    [
        (None, HealthState.DEGRADED),
        (T0 - 3 * MIN + timedelta(seconds=1), HealthState.NORMAL),
        (T0 - 3 * MIN, HealthState.DEGRADED),
        (T0 - 15 * MIN + timedelta(seconds=1), HealthState.DEGRADED),
        (T0 - 15 * MIN, HealthState.STOP),
    ],
)
def test_4_a_stale_memory_is_not_trusted(probed: Any, state: HealthState) -> None:
    memory = HealthMemory(state=HealthState.NORMAL, probed_at=probed)
    assert effective(memory, T0, SETTINGS_HEALTH).state is state
    worse = HealthMemory(state=HealthState.STOP, probed_at=probed, reasons=("disk_stop",))
    assert effective(worse, T0, SETTINGS_HEALTH) == worse  # never better than recorded


SETTINGS_HEALTH = Gateway(FakeTransport(), MemoryStore()).health_config


async def test_4_the_gateway_uses_the_effective_state() -> None:
    gateway, transport, store, _ = make()
    store.memory = HealthMemory(state=HealthState.NORMAL, probed_at=T0 - 16 * MIN)
    with pytest.raises(StoppedError):
        await collect(gateway)
    store.memory = HealthMemory(state=HealthState.NORMAL, probed_at=T0 - 4 * MIN)
    with pytest.raises(DeferredError):
        await collect(gateway, purpose=Purpose.ENRICH, component="enrichment")
    await collect(gateway)  # DEGRADED still collects
    assert len(searches(transport)) == 1


# --------------------------------------------------------------- 5. 401/403 stops at once


@pytest.mark.parametrize("status", [401, 403])
async def test_5_an_auth_failure_puts_siem_in_stop(status: int) -> None:
    gateway, transport, store, _ = make(FakeTransport().on("_search", ok({}, status)))
    with pytest.raises(AuthFailedError):
        await collect(gateway)
    assert (store.memory.state, store.memory.reasons) == (HealthState.STOP, ("auth_failed",))
    with pytest.raises(StoppedError):
        await collect(gateway)
    assert len(transport.calls) == 1


# --------------------------------------------------------------- 6. probes use the real scale


async def test_6_a_probe_in_caution_does_not_inflate_the_bucket() -> None:
    gateway, _, store, _ = make(FakeTransport(default={"nodes": {}}))
    store.memory = HealthMemory(state=HealthState.CAUTION, probed_at=T0)
    store.budget = BudgetState(tokens_ms=1_000.0, refilled_at=T0 - 10 * MIN, day=T0.date())
    await gateway.run(
        NodeStats(), NoParams(), purpose=Purpose.PROBE, component="probe", deadline=DEADLINE
    )
    assert store.budget.tokens_ms is not None
    assert store.budget.tokens_ms <= 1_500


async def test_6_probes_still_run_at_scale_0() -> None:
    gateway, transport, store, _ = make(FakeTransport(default={"nodes": {}}))
    store.memory = HealthMemory(state=HealthState.STOP, probed_at=T0)
    await gateway.run(
        NodeStats(), NoParams(), purpose=Purpose.PROBE, component="probe", deadline=DEADLINE
    )
    assert len(transport.calls) == 1
    assert store.budget.tokens_ms == -5.0  # no capacity at scale 0; the probe's took is charged


# --------------------------------------------------------------- 7. listing after local checks


class BadLog(Template):
    name = "test.badlog"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.MEDIUM
    filter_fields: ClassVar[frozenset[str]] = frozenset({"@timestamp"})
    max_size = 10
    clause: ClassVar[dict[str, Any]] = {"wildcard": {"@timestamp": "*"}}

    def build(self, params: Params) -> RequestPlan:
        body = {"size": 0, "track_total_hits": False, "query": self.clause}
        return RequestPlan(self.spec(), body=body, window=Window("squid", T0 - MIN, T0))


async def test_7_no_listing_probe_for_a_request_the_validator_refuses() -> None:
    gateway, transport, _, _ = make()
    with pytest.raises(TemplateRejectedError):
        await gateway.run(
            BadLog(), NoParams(), purpose=Purpose.ENRICH, component="enrichment", deadline=DEADLINE
        )
    assert transport.calls == []


async def test_7_no_listing_probe_while_the_breaker_is_open() -> None:
    gateway, transport, store, _ = make()
    store.breaker = br.on_overload(br.BreakerState(), T0)
    good = type("GoodLog", (BadLog,), {"clause": {"exists": {"field": "@timestamp"}}})
    with pytest.raises(BreakerOpenError):
        await gateway.run(
            good(), NoParams(), purpose=Purpose.ENRICH, component="enrichment", deadline=DEADLINE
        )
    assert transport.calls == []


# --------------------------------------------------------------- 9. one deadline per exchange


async def test_9_a_slow_trickle_times_out_as_a_whole() -> None:
    async def trickle() -> AsyncIterator[bytes]:
        for _ in range(20):
            await asyncio.sleep(0.02)
            yield b" "

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=trickle())

    with pytest.raises(TimedOutError):
        await transport_with(handler).send(replace(REQUEST, timeout_s=0.1))


# --------------------------------------------------------------- 11/12. breaker trial


async def test_12_a_budget_refusal_does_not_spend_the_breaker_trial() -> None:
    gateway, transport, store, _ = make()
    store.breaker = br.on_overload(br.BreakerState(), T0 - 5 * MIN)  # trial due
    store.budget = BudgetState(day=T0.date(), day_used_ms=3_600_000)
    with pytest.raises(BudgetExhaustedError):
        await collect(gateway)
    assert store.breaker.trial_until is None
    store.budget = BudgetState()
    await collect(gateway)  # the trial goes, and closes the breaker
    assert store.breaker.open_until is None
    assert len(transport.calls) == 1


async def test_12_a_trial_taken_meanwhile_settles_the_lease() -> None:
    gateway, transport, store, _ = make()
    store.breaker = br.on_overload(br.BreakerState(), T0 - 5 * MIN)
    real_admit = store.budget_admit

    async def admit_then_lose_trial(*args: Any, **kw: Any) -> Any:
        admission = await real_admit(*args, **kw)
        _ok, store.breaker = br.admit(store.breaker, T0)  # another process's trial
        return admission

    store.budget_admit = admit_then_lose_trial  # type: ignore[method-assign]
    with pytest.raises(BreakerOpenError):
        await collect(gateway)
    assert transport.calls == []
    assert store.budget.leases == ()
    assert store.budget.day_used_ms == 0


# --------------------------------------------------------------- 13. leases never leak


async def test_13_cancellation_settles_the_lease_and_records_an_abort() -> None:
    started = asyncio.Event()

    async def hang(request: Any) -> Any:
        started.set()
        await asyncio.Event().wait()

    gateway, transport, store, _ = make()
    transport.send = hang  # type: ignore[method-assign]
    task = asyncio.create_task(collect(gateway))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.budget.leases == ()
    assert store.ledger[0].outcome == "aborted"


async def test_13_an_unexpected_error_settles_the_lease() -> None:
    gateway, _, store, _ = make(FakeTransport().on("_search", RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        await collect(gateway)
    assert store.budget.leases == ()
    assert store.ledger[0].outcome == "aborted"


# --------------------------------------------------------------- 14. retries charge both


async def test_14_a_retry_charges_both_attempts() -> None:
    gateway, _, store, _ = make(FakeTransport().on("_search", failure(), ok(search_answer())))
    result = await collect(gateway)
    assert result.took_ms == 5 + 5  # 5 ms of the failed attempt + took of the second
    assert store.ledger[0].took_ms == 10
    assert store.budget.day_used_ms == 10


# --------------------------------------------------------------- 15. day rollover


def test_15_an_expired_lease_is_charged_to_the_new_day_and_replaced_on_settle() -> None:
    config = BudgetConfig()
    late = T0.replace(hour=23, minute=59)
    admission, state = admit(BudgetState(), config, L, late, scale=1.0, lease_id="a")
    assert admission.lease is not None
    after = admission.lease.expires + MIN  # the next day
    state = roll(state, config, after, 1.0)
    assert (state.day, state.day_used_ms, state.expired) == (after.date(), 50, ("a",))
    state = settle(state, config, admission.lease, 100, after, scale=1.0)
    assert (state.day_used_ms, state.expired) == (100, ())


def test_15_an_estimate_charged_yesterday_is_not_taken_off_today() -> None:
    config = BudgetConfig()
    admission, state = admit(BudgetState(), config, L, T0, scale=1.0, lease_id="a")
    assert admission.lease is not None
    state = roll(state, config, T0 + 3 * MIN, 1.0)  # expired and charged on day 1
    tomorrow = T0 + timedelta(days=1)
    state = settle(state, config, admission.lease, 70, tomorrow, scale=1.0)
    assert state.day_used_ms == 70


# --------------------------------------------------------------- 16. pad-only next day


async def test_16_a_window_ending_late_does_not_need_tomorrows_index() -> None:
    gateway, transport, store, clock = make(
        FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    )
    clock.now = T0.replace(hour=23, minute=30)
    store.memory = HealthMemory(probed_at=clock.now)  # Q-D2: no log read in a stale STOP
    result = await gateway.run(
        Freshness(),
        FreshnessParams(source="squid", now=clock.now),
        purpose=Purpose.PROBE,
        component="probe",
        deadline=clock.now + timedelta(seconds=30),
    )
    assert result.indices == (SQUID_TODAY,)
    assert transport.calls[-1].path == f"/{SQUID_TODAY}/_search"


# --------------------------------------------------------------- 17. DEGRADED collects


def test_17_degraded_has_a_small_scale() -> None:
    from argus.gateway.health import scale

    memory = HealthMemory(state=HealthState.DEGRADED, probed_at=T0)
    assert scale(memory, T0, SETTINGS_HEALTH) == 0.1


# --------------------------------------------------------------- validator: 8, 10, 18, 19, 20

FORCED = tuple(FORCED_SEARCH_PARAMS.items())


def spec(**kw: Any) -> Spec:
    base: dict[str, Any] = {
        "name": "t", "version": 1, "endpoint": Endpoint.SEARCH, "family": Family.ALERTS,
        "cost": CostClass.LIGHT, "filter_fields": frozenset({"a", "a.keyword", "@timestamp"}),
        "aggregate_fields": frozenset({"a"}), "return_fields": frozenset({"a"}),
        "sort_fields": frozenset({"@timestamp"}), "max_size": 100,
    }  # fmt: skip
    return Spec(**{**base, **kw})


def final(body: Any, **kw: Any) -> FinalRequest:
    s = spec(**kw)
    indices = ("acme-logs-squid-2026.10.09",) if s.family is Family.LOG else (".alerts-x",)
    return FinalRequest(s, indices, None, FORCED, body)


def code(request: FinalRequest) -> str:
    with pytest.raises(TemplateRejectedError) as info:
        validate(request)
    return info.value.code


TERMS = {"terms": {"field": "a", "size": 5}}


def test_8_the_cost_class_must_match_the_body() -> None:
    probe_cost = {"cost": CostClass.PROBE}
    validate(final({"size": 1, "_source": ["a"]}, **probe_cost))
    assert code(final({"size": 2, "_source": ["a"]}, **probe_cost)) == "cost_mismatch"
    assert code(final({"size": 0, "aggs": {"x": TERMS}}, **probe_cost)) == "cost_mismatch"
    log = {"family": Family.LOG, "cost": CostClass.MEDIUM}
    body = {"size": 0, "track_total_hits": False, "aggs": {"x": TERMS}}
    assert code(final(body, **log)) == "cost_mismatch"
    validate(final(body, family=Family.LOG, cost=CostClass.HEAVY))
    validate(final({"size": 0, "aggs": {"x": TERMS}}))  # alerts aggregations need not be heavy


def test_10_returned_fields_are_always_named() -> None:
    assert code(final({"size": 5})) == "field_not_allowed"
    validate(final({"size": 0}))
    validate(final({"size": 5, "_source": False}))
    with_param = replace(final({"size": 5}), url_params=(*FORCED, ("_source_includes", "a")))
    validate(replace(with_param, spec=spec(url_params=frozenset({"_source_includes"}))))
    top = {"size": 0, "aggs": {"x": {**TERMS, "aggs": {"t": {"top_hits": {"size": 1}}}}}}
    assert code(final(top)) == "field_not_allowed"


def test_18_ignore_above_counts_utf16_units_and_covers_plain_fields() -> None:
    def term(field: str, value: str) -> FinalRequest:
        return final({"size": 0, "query": {"term": {field: value}}})

    validate(term("a.keyword", "😀" * 128))  # 256 UTF-16 units
    with pytest.raises(UnsupportedValueError):
        validate(term("a.keyword", "😀" * 129))  # 129 characters, 258 units
    validate(term("a", "x" * 1024))
    with pytest.raises(UnsupportedValueError):
        validate(term("a", "x" * 1025))


def test_19_odd_values_are_refusals_not_crashes() -> None:
    alerts_pit = {"allow_pit": True}
    pit = {"size": 0, "pit": {"id": "p", "keep_alive": ["1m"]}}
    assert code(final(pit, **alerts_pit)) == "bad_shape"
    order = {"size": 0, "aggs": {"x": {"terms": {"field": "a", "size": 5, "order": {"_key": []}}}}}
    assert code(final(order)) == "bad_shape"
    deep: Any = []
    for _ in range(100_000):
        deep = [deep]
    assert code(final({"size": 0, "query": {"terms": {"a": deep}}})) == "bad_shape"


def test_20_log_searches_say_track_total_hits_false() -> None:
    log = {"family": Family.LOG, "cost": CostClass.HEAVY}
    assert code(final({"size": 0}, **log)) == "total_hits_not_allowed"
    validate(final({"size": 0, "track_total_hits": False}, **log))


def test_20_buckets_add_up_across_siblings_and_top_hits() -> None:
    def terms(size: int) -> dict[str, Any]:
        return {"terms": {"field": "a", "size": size}}

    validate(final({"size": 0, "aggs": {"x": terms(500), "y": terms(500)}}))
    assert code(final({"size": 0, "aggs": {"x": terms(500), "y": terms(501)}})) == (
        "too_many_buckets"
    )
    hits = {"top_hits": {"size": 5, "_source": ["a"]}}
    validate(final({"size": 0, "aggs": {"x": {**terms(100), "aggs": {"t": hits}}}}))  # 100 + 500
    over = {"size": 0, "aggs": {"x": {**terms(200), "aggs": {"t": hits}}}}  # 200 + 1000
    assert code(final(over)) == "too_many_buckets"


@pytest.mark.parametrize(
    "agg",
    [
        {"terms": {"field": "a", "size": 5, "min_doc_count": -1}},
        {"terms": {"field": "a", "size": 5, "min_doc_count": "1"}},
        {"date_histogram": {"field": "a", "fixed_interval": "1h", "format": 1,
                            "hard_bounds": {"min": 0, "max": 3_600_000}}},
        {"date_histogram": {"field": "a", "fixed_interval": "1h", "min_doc_count": True,
                            "hard_bounds": {"min": 0, "max": 3_600_000}}},
    ],
)  # fmt: skip
def test_20_format_and_min_doc_count_are_type_checked(agg: dict[str, Any]) -> None:
    assert code(final({"size": 0, "aggs": {"x": agg}})) == "bad_shape"


def test_20_the_body_is_measured_as_sent() -> None:
    values = ["é" * 200] * 70  # 28 KB as UTF-8, 84 KB escaped as on the wire
    assert code(final({"size": 0, "query": {"terms": {"a": values}}})) == "body_too_large"


async def test_20_the_gateway_sends_exactly_the_measured_bytes() -> None:
    gateway, transport, _, _ = make()
    await collect(gateway)
    (call,) = transport.calls
    assert call.body is not None
    assert call.body == encode_body(json.loads(call.body))
    assert call.body.isascii()
