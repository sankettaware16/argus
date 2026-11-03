"""Breaker (a state machine), health states, index resolution and the response-shape matrix."""

from __future__ import annotations

import copy
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from argus.gateway import breaker as br
from argus.gateway.errors import (
    AuthFailedError,
    OverloadedError,
    PartialResultError,
    ResponseError,
    SiemError,
    SourceMissingError,
    TransportFailedError,
)
from argus.gateway.health import (
    ALLOWED,
    Baselines,
    HealthConfig,
    HealthMemory,
    HealthState,
    Readings,
    allowed,
    evaluate,
    readings_from_node_stats,
    scale,
)
from argus.gateway.indices import daily_indices, resolve
from argus.gateway.responses import check_complete, check_status, error_types, parse_json, took_ms
from argus.gateway.templates import Endpoint, Purpose

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 12, 6, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)


# --------------------------------------------------------------------------- breaker


def test_breaker_cooldowns_escalate_and_cap() -> None:
    assert br.COOLDOWNS == (5 * MIN, 15 * MIN, 60 * MIN)
    state = br.BreakerState()
    at = T0
    for level, cooldown in ((1, 5), (2, 15), (3, 60), (3, 60)):
        state = br.on_overload(state, at)  # each trial after the cool-down fails again
        assert (state.level, state.open_until, state.last_trip) == (level, at + cooldown * MIN, at)
        at += cooldown * MIN


def test_overloads_while_open_do_not_escalate() -> None:
    """Requests already out when the breaker tripped report the same overload (review #11)."""
    state = br.on_overload(br.BreakerState(), T0)
    for late in (T0, T0 + MIN, T0 + 5 * MIN - timedelta(microseconds=1)):
        assert br.on_overload(state, late) == state
    assert br.on_overload(state, T0 + 5 * MIN).level == 2


def test_peek_takes_no_trial() -> None:
    state = br.on_overload(br.BreakerState(), T0)
    assert not br.peek(state, T0)
    assert br.peek(state, T0 + 5 * MIN)
    assert br.peek(state, T0 + 5 * MIN)  # still free: peek changed nothing
    ok, taken = br.admit(state, T0 + 5 * MIN)
    assert ok
    assert not br.peek(taken, T0 + 5 * MIN)


def test_breaker_trial_after_the_cooldown() -> None:
    state = br.on_overload(br.BreakerState(), T0)
    ok, state = br.admit(state, T0 + 5 * MIN - timedelta(microseconds=1))
    assert not ok
    ok, state = br.admit(state, T0 + 5 * MIN)
    assert ok
    assert state.trial_until == T0 + 7 * MIN
    ok, _ = br.admit(state, T0 + 6 * MIN)
    assert not ok  # one trial at a time
    ok, _ = br.admit(state, T0 + 7 * MIN)
    assert ok  # the trial never reported: another may go
    closed = br.on_success(state, T0 + 6 * MIN)
    assert (closed.open_until, closed.trial_until, closed.level) == (None, None, 1)
    ok, _ = br.admit(closed, T0 + 6 * MIN)
    assert ok
    again = br.on_overload(closed, T0 + 10 * MIN)
    assert again.open_until == T0 + 25 * MIN  # the next step: 15 minutes


def test_success_during_the_cooldown_does_not_close_it() -> None:
    state = br.on_overload(br.BreakerState(), T0)
    assert br.on_success(state, T0 + MIN) == state
    assert br.on_success(br.BreakerState(), T0) == br.BreakerState()


def test_level_resets_after_six_quiet_hours() -> None:
    state = br.on_success(br.on_overload(br.BreakerState(), T0), T0 + 6 * MIN)
    ok, after = br.admit(state, T0 + timedelta(hours=6) - timedelta(microseconds=1))
    assert ok
    assert after.level == 1
    ok, after = br.admit(state, T0 + timedelta(hours=6))
    assert (ok, after) == (True, br.BreakerState())


class Breaker(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.now = T0
        self.state = br.BreakerState()
        self.trial_at: datetime | None = None

    @rule()
    def request(self) -> None:
        was_open = self.state.is_open(self.now)
        ok, self.state = br.admit(self.state, self.now)
        if was_open:
            assert not ok
        if ok and self.state.open_until is not None:
            assert self.trial_at is None or self.now >= self.trial_at + br.TRIAL_LEASE
            self.trial_at = self.now

    @rule()
    def overload(self) -> None:
        before = self.state
        self.state = br.on_overload(self.state, self.now)
        if before.is_open(self.now):
            assert self.state == before
            return
        assert self.state.level == min(before.level + 1, 3)
        assert self.state.open_until == self.now + br.COOLDOWNS[self.state.level - 1]
        self.trial_at = None

    @rule()
    def success(self) -> None:
        self.state = br.on_success(self.state, self.now)
        if self.state.open_until is None:
            self.trial_at = None

    @rule(minutes=st.integers(0, 400))
    def wait(self, minutes: int) -> None:
        self.now += minutes * MIN

    @invariant()
    def bounded(self) -> None:
        assert 0 <= self.state.level <= 3
        if self.state.open_until is not None:
            assert self.state.level >= 1


TestBreaker = Breaker.TestCase
TestBreaker.settings = settings(max_examples=max(50, settings().max_examples), deadline=None)


# --------------------------------------------------------------------------- health

CFG = HealthConfig()


def readings(**kw: Any) -> Readings:
    return Readings(at=kw.pop("at", T0), **kw)


def step(memory: HealthMemory, **kw: Any) -> HealthMemory:
    kill = kw.pop("kill", False)
    base = kw.pop("baselines", Baselines())
    return evaluate(memory, readings(**kw), CFG, kill_switch=kill, baselines=base)


def test_health_defaults() -> None:
    assert (CFG.disk_caution, CFG.disk_degraded, CFG.disk_stop) == (85, 90, 95)
    assert (CFG.heap_caution, CFG.load_caution, CFG.margin, CFG.clean_probes) == (85, 16, 5, 3)
    assert CFG.ingest_lag_degraded == 15 * MIN
    assert CFG.slow_start == (20 * MIN, 40 * MIN)


@pytest.mark.parametrize(
    ("kw", "state", "reason"),
    [
        ({}, HealthState.NORMAL, ()),
        ({"kill": True}, HealthState.STOP, ("kill_switch",)),
        ({"auth_failed": True, "probe_ok": False}, HealthState.STOP, ("auth_failed",)),
        ({"blocked_indices": ("x",)}, HealthState.STOP, ("index_blocked",)),
        ({"disk_percent": 95.0}, HealthState.STOP, ("disk_stop",)),
        ({"disk_percent": 94.99}, HealthState.DEGRADED, ("disk_degraded",)),
        ({"disk_percent": 90.0}, HealthState.DEGRADED, ("disk_degraded",)),
        ({"disk_percent": 85.0}, HealthState.CAUTION, ("disk_caution",)),
        ({"disk_percent": 84.9}, HealthState.NORMAL, ()),
        ({"probe_ok": False}, HealthState.DEGRADED, ("probe_failed",)),
        ({"search_queue": 1}, HealthState.CAUTION, ("search_queue",)),
        ({"search_queue": 0}, HealthState.NORMAL, ()),
        ({"heap_percent": 85.1}, HealthState.CAUTION, ("heap",)),
        ({"heap_percent": 85.0}, HealthState.NORMAL, ()),
        ({"load_1m": 16.1}, HealthState.CAUTION, ("load",)),
        ({"load_1m": 16.0}, HealthState.NORMAL, ()),
        # DQ19 (a): one late source alone is its own business (Q-F1); two, or one under
        # pressure (rejections, a queue, heap), trip the wire
        ({"ingest_lag": {"squid": 15 * MIN + timedelta(seconds=1)}}, HealthState.NORMAL, ()),
        ({"ingest_lag": {"squid": 16 * MIN, "dns": 15 * MIN + timedelta(seconds=1)}},
         HealthState.DEGRADED, ("ingest_lag:dns", "ingest_lag:squid")),
        ({"ingest_lag": {"squid": 16 * MIN, "dns": 15 * MIN}}, HealthState.NORMAL, ()),
        ({"ingest_lag": {"squid": 16 * MIN}, "search_queue": 1}, HealthState.DEGRADED,
         ("ingest_lag:squid",)),
        ({"ingest_lag": {"squid": 16 * MIN}, "heap_percent": 85.1}, HealthState.DEGRADED,
         ("ingest_lag:squid",)),
        ({"ingest_lag": {"squid": 16 * MIN}, "heap_percent": 85.0}, HealthState.NORMAL, ()),
        ({"ingest_lag": {"squid": 15 * MIN}}, HealthState.NORMAL, ()),
        ({"stale_rules": 1}, HealthState.DEGRADED, ("stale_rules",)),
        ({"stale_rules": 0}, HealthState.NORMAL, ()),
        ({"write_rejected": 10**9}, HealthState.NORMAL, ()),
    ],
)  # fmt: skip
def test_conditions_from_normal(
    kw: dict[str, Any], state: HealthState, reason: tuple[str, ...]
) -> None:
    memory = step(HealthMemory(), **kw)
    assert (memory.state, memory.reasons) == (state, reason)


def test_counters_trip_on_a_rise_only() -> None:
    first = step(HealthMemory(), search_rejected=100, breakers_tripped=5)
    assert first.state is HealthState.NORMAL  # no previous value: no delta
    same = step(first, search_rejected=100, breakers_tripped=5)
    assert same.state is HealthState.NORMAL
    rose = step(same, search_rejected=101, breakers_tripped=5)
    assert (rose.state, rose.reasons) == (HealthState.DEGRADED, ("search_rejections",))
    reset = step(HealthMemory(search_rejected=100), search_rejected=3)
    assert reset.state is HealthState.NORMAL  # a node restart resets counters
    tripped = step(same, search_rejected=100, breakers_tripped=6)
    assert tripped.reasons == ("breaker_trips",)
    unknown = step(same)  # a probe without counters keeps the last values
    assert (unknown.search_rejected, unknown.breakers_tripped) == (100, 5)


def test_counter_conditions_leave_after_three_clean_probes() -> None:
    memory = step(step(HealthMemory(), search_rejected=1), search_rejected=2)
    assert memory.state is HealthState.DEGRADED
    for n in range(2):
        memory = step(memory, search_rejected=2)
        assert memory.state is HealthState.DEGRADED, n
    memory = step(memory, search_rejected=2)
    assert memory.state is HealthState.NORMAL


def test_gauges_leave_five_points_below_their_threshold() -> None:
    memory = step(HealthMemory(), disk_percent=90.0)
    assert memory.state is HealthState.DEGRADED
    memory = step(memory, disk_percent=85.0)
    assert memory.state is HealthState.DEGRADED  # disk gauges stay while >= threshold - 5
    memory = step(memory, disk_percent=84.99)
    assert memory.state is HealthState.CAUTION
    memory = step(memory, disk_percent=80.0)
    assert memory.state is HealthState.CAUTION
    memory = step(memory, disk_percent=79.99)
    assert memory.state is HealthState.NORMAL
    load = step(HealthMemory(), load_1m=17.0)
    assert step(load, load_1m=14.5).state is HealthState.CAUTION
    assert step(load, load_1m=14.4).state is HealthState.NORMAL
    two = {"dns": 16 * MIN, "nginx": 16 * MIN}
    lag = step(HealthMemory(), ingest_lag=two)
    assert lag.state is HealthState.DEGRADED
    above = 10 * MIN + timedelta(seconds=1)
    assert step(lag, ingest_lag={"dns": above, "nginx": above}).state is HealthState.DEGRADED
    assert step(lag, ingest_lag={"dns": above, "nginx": 10 * MIN}).state is HealthState.NORMAL
    assert step(lag, ingest_lag={"dns": 10 * MIN, "nginx": 10 * MIN}).state is HealthState.NORMAL
    heap = step(HealthMemory(), heap_percent=90.0)
    assert step(heap, heap_percent=80.01).state is HealthState.CAUTION
    assert step(heap, heap_percent=80.0).state is HealthState.NORMAL


def test_a_worse_condition_enters_at_once() -> None:
    memory = step(HealthMemory(), disk_percent=86.0)
    assert step(memory, disk_percent=96.0).state is HealthState.STOP


def test_baselines_replace_the_static_limits() -> None:
    base = Baselines(heap_p90=70.0, load_p90=8.0)
    assert step(HealthMemory(), heap_percent=71.0, baselines=base).state is HealthState.CAUTION
    assert step(HealthMemory(), heap_percent=70.0, baselines=base).state is HealthState.NORMAL
    assert step(HealthMemory(), load_1m=8.5, baselines=base).state is HealthState.CAUTION


def test_since_and_slow_start() -> None:
    later = T0 + 10 * MIN
    memory = step(HealthMemory(), disk_percent=91.0)
    assert memory.since == T0
    memory = evaluate(memory, Readings(at=later, disk_percent=91.0), CFG)
    assert memory.since == T0  # unchanged state keeps its start
    recovered = evaluate(memory, Readings(at=later, disk_percent=50.0), CFG)
    assert (recovered.state, recovered.since, recovered.recovered_at) == (
        HealthState.NORMAL, later, later,
    )  # fmt: skip
    assert scale(recovered, later, CFG) == 0.25
    assert scale(recovered, later + 20 * MIN - timedelta(microseconds=1), CFG) == 0.25
    assert scale(recovered, later + 20 * MIN, CFG) == 0.5
    assert scale(recovered, later + 40 * MIN, CFG) == 1.0
    caution = step(HealthMemory(), disk_percent=86.0)
    back = evaluate(caution, Readings(at=later, disk_percent=10.0), CFG)
    assert back.recovered_at is None  # from CAUTION: no slow start
    assert scale(caution, T0, CFG) == 0.5
    assert scale(step(HealthMemory(), probe_ok=False), T0, CFG) == 0.1  # the collector only
    assert scale(step(HealthMemory(), kill=True), T0, CFG) == 0.0


def test_what_each_state_allows() -> None:
    assert ALLOWED[HealthState.NORMAL] == frozenset(Purpose)
    assert ALLOWED[HealthState.CAUTION] == frozenset(Purpose) - {
        Purpose.BACKFILL, Purpose.RECONCILE, Purpose.WRITEBACK,
        # Phase 3 (plan §7.8): investigation, measurement and writes run in NORMAL only
        Purpose.INVESTIGATE, Purpose.MEASURE, Purpose.KIBANA_WRITE,
        Purpose.DISCOVER,  # `argus discover` (P4-D1): a person's reads, NORMAL only
    }  # fmt: skip
    assert ALLOWED[HealthState.DEGRADED] == {
        Purpose.PROBE, Purpose.SELFTEST, Purpose.COLLECT,
        Purpose.FRESHNESS, Purpose.KIBANA_READ, Purpose.IDENTITY,  # reduced, on their lanes
    }  # fmt: skip
    assert ALLOWED[HealthState.STOP] == {Purpose.PROBE, Purpose.IDENTITY}  # DQ9 (b)
    assert allowed(HealthState.CAUTION, Purpose.ENRICH)
    assert not allowed(HealthState.CAUTION, Purpose.BACKFILL)
    # the re-measurement runs in NORMAL only (Q-A3)
    assert [allowed(state, Purpose.MEASURE) for state in HealthState] == [True, False, False, False]


NODE = {
    "_nodes": {"total": 1, "successful": 1, "failed": 0},
    "nodes": {
        "n1": {
            "fs": {"total": {"total_in_bytes": 1000, "available_in_bytes": 150}},
            "jvm": {"mem": {"heap_used_percent": 71}},
            "os": {"cpu": {"load_average": {"1m": 3.5, "5m": 3.0}}},
            "thread_pool": {"search": {"queue": 0, "rejected": 12}, "write": {"rejected": 9}},
            "breakers": {"request": {"tripped": 1}, "parent": {"tripped": 2}},
        }
    },
}


def test_readings_from_node_stats() -> None:
    r = readings_from_node_stats(NODE, T0)
    assert (r.probe_ok, r.disk_percent, r.heap_percent, r.load_1m) == (True, 85.0, 71.0, 3.5)
    assert (r.search_queue, r.search_rejected, r.breakers_tripped, r.write_rejected) == (
        0,
        12,
        3,
        9,
    )
    bad: tuple[Any, ...] = (
        None,
        [],
        {"nodes": {}},
        {"nodes": {"a": {}, "b": {}}},
        {"nodes": {"a": 1}},
    )
    for bad_body in bad:
        assert not readings_from_node_stats(bad_body, T0).probe_ok
    ok = {"_nodes": {"failed": 0}}
    partial = readings_from_node_stats(
        {**ok, "nodes": {"n": {"fs": {"total": {"total_in_bytes": 0}}}}}, T0
    )
    assert (partial.probe_ok, partial.disk_percent, partial.heap_percent) == (False, None, None)
    node = {
        "jvm": {"mem": {"heap_used_percent": True}},
        "breakers": {"a": {"tripped": 1}, "b": {"tripped": "x"}},
        "fs": {"total": {"total_in_bytes": 10, "available_in_bytes": 11}},
    }
    odd = {**ok, "nodes": {"n": node}}
    r = readings_from_node_stats(odd, T0)
    assert (r.heap_percent, r.breakers_tripped, r.disk_percent) == (None, None, None)
    empty = readings_from_node_stats({**ok, "nodes": {"n": {"breakers": {}}}}, T0)
    assert (empty.probe_ok, empty.breakers_tripped) == (False, None)


@pytest.mark.parametrize(
    "path",
    [
        ("fs",), ("jvm",), ("os",), ("thread_pool", "search", "queue"),
        ("thread_pool", "search", "rejected"),
    ],
)  # fmt: skip
def test_a_node_without_a_required_reading_is_a_failed_probe(path: tuple[str, ...]) -> None:
    """Review #3: one node with missing fields must not read as healthy (D-023)."""
    body = copy.deepcopy(NODE)
    node = body["nodes"]["n1"]
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    readings = readings_from_node_stats(body, T0)
    assert not readings.probe_ok
    assert evaluate(HealthMemory(), readings, CFG).state is HealthState.DEGRADED


@pytest.mark.parametrize("summary", [None, {}, {"failed": 1}, {"failed": True}, {"failed": "0"}])
def test_a_failed_or_unreported_node_is_a_failed_probe(summary: Any) -> None:
    body = {k: v for k, v in NODE.items() if k != "_nodes"}
    if summary is not None:
        body["_nodes"] = summary
    assert not readings_from_node_stats(body, T0).probe_ok
    assert readings_from_node_stats(NODE, T0).probe_ok


# --------------------------------------------------------------------------- indices

P = "acme-logs-squid-"


def test_daily_indices_pad_one_hour_at_midnight() -> None:
    def at(text: str) -> datetime:
        return datetime.fromisoformat(text)

    assert daily_indices(P, at("2026-10-09T12:00Z"), at("2026-10-09T12:15Z")) == (P + "2026.10.09",)
    assert daily_indices(P, at("2026-10-09T01:00Z"), at("2026-10-09T22:59:59Z")) == (
        P + "2026.10.09",
    )
    assert daily_indices(P, at("2026-10-09T00:59:59Z"), at("2026-10-09T02:00Z")) == (
        P + "2026.10.08", P + "2026.10.09",
    )  # fmt: skip
    assert daily_indices(P, at("2026-10-09T22:00Z"), at("2026-10-09T23:00Z")) == (
        P + "2026.10.09", P + "2026.10.10",
    )  # fmt: skip
    assert daily_indices(P, at("2026-10-09T05:00+05:30"), at("2026-10-09T05:10+05:30")) == (
        P + "2026.10.08", P + "2026.10.09",
    )  # fmt: skip
    with pytest.raises(ValueError, match="at most 2"):
        daily_indices(P, at("2026-10-09T00:30Z"), at("2026-10-09T23:30Z"))
    with pytest.raises(ValueError, match="before"):
        daily_indices(P, at("2026-10-09T12:00Z"), at("2026-10-09T11:00Z"))
    with pytest.raises(ValueError, match="aware"):
        daily_indices(P, datetime(2026, 10, 9), at("2026-10-09T11:00Z"))  # noqa: DTZ001


EARLIEST = datetime(2000, 1, 2)  # noqa: DTZ001 - Hypothesis bounds are naive
LATEST = datetime(2099, 12, 30)  # noqa: DTZ001


@given(
    st.datetimes(min_value=EARLIEST, max_value=LATEST, timezones=st.just(UTC)),
    st.integers(0, 20 * 3600),
)
def test_every_moment_of_the_window_has_its_index(start: datetime, seconds: int) -> None:
    end = start + timedelta(seconds=seconds)
    try:
        names = daily_indices(P, start, end)
    except ValueError:
        assert ((end + timedelta(hours=1)).date() - (start - timedelta(hours=1)).date()).days >= 2
        return
    assert 1 <= len(names) <= 2
    for moment in (start, end, start + (end - start) / 2):
        assert P + moment.strftime("%Y.%m.%d") in names


def test_resolve() -> None:
    wanted = (P + "2026.10.08", P + "2026.10.09")
    assert resolve(wanted, set(wanted), date(2026, 10, 9)) == wanted
    with pytest.raises(SourceMissingError) as info:
        resolve(wanted, {P + "2026.10.09"}, date(2026, 10, 9))
    assert (info.value.reason, info.value.days) == ("source_expired", ("2026.10.08",))
    with pytest.raises(SourceMissingError) as info:
        resolve(wanted, {P + "2026.10.08"}, date(2026, 10, 9))
    assert (info.value.reason, info.value.days) == ("source_not_ready", ("2026.10.09",))
    with pytest.raises(SourceMissingError) as info:
        resolve(wanted, set(), date(2026, 10, 9))
    assert info.value.reason == "source_expired"


# --------------------------------------------------------------------------- responses


def ok_search(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "took": 7, "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"hits": []},
    }  # fmt: skip
    body.update(kw)
    return body


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        (200, {}, None),
        (299, None, None),
        (401, None, AuthFailedError),
        (403, {"error": {"type": "security_exception"}}, AuthFailedError),
        (429, None, OverloadedError),
        (500, {"error": {"type": "search_phase_execution_exception",
                         "root_cause": [{"type": "circuit_breaking_exception"}]}}, OverloadedError),
        (503, {"error": {"type": "es_rejected_execution_exception"}}, OverloadedError),
        (404, {"error": {"type": "index_not_found_exception"}}, SourceMissingError),
        (404, {"error": {"type": "resource_not_found_exception"}}, SiemError),
        (502, None, TransportFailedError),
        (503, {"error": {"type": "unavailable_shards_exception"}}, TransportFailedError),
        (504, None, TransportFailedError),
        (400, {"error": {"type": "parsing_exception", "reason": "secret query text"}}, SiemError),
        (500, "garbage", SiemError),
        (300, None, SiemError),
    ],
)  # fmt: skip
def test_status_matrix(status: int, body: Any, error: type[Exception] | None) -> None:
    if error is None:
        check_status(status, body)
        return
    with pytest.raises(error) as info:
        check_status(status, body)
    assert "secret" not in str(info.value)
    if isinstance(info.value, TransportFailedError):
        assert info.value.retriable is (status != 504)
    if isinstance(info.value, SiemError) and isinstance(body, dict):
        assert info.value.error_type == body["error"]["type"]


def test_error_types() -> None:
    body = {
        "error": {
            "type": "a",
            "root_cause": [{"type": "b"}, {"type": "a"}, "x", {"type": 5}, {"type": "c" * 101}],
        }
    }
    assert error_types(body) == ("a", "b")
    assert error_types({"error": "text"}) == ()
    assert error_types([]) == ()
    assert error_types({"error": {"root_cause": None}}) == ()


@pytest.mark.parametrize(
    ("body", "complete"),
    [
        (ok_search(), True),
        (ok_search(_shards={"total": 3, "successful": 2, "skipped": 1, "failed": 0}), True),
        (ok_search(_shards={"total": 1, "successful": 1, "failed": 0}), True),
        (ok_search(timed_out=True), False),
        ({k: v for k, v in ok_search().items() if k != "timed_out"}, False),
        (ok_search(timed_out=None), False),
        (ok_search(terminated_early=True), False),
        (ok_search(terminated_early=False), True),
        (ok_search(_shards={"total": 2, "successful": 1, "skipped": 0, "failed": 1}), False),
        (ok_search(_shards={"total": 2, "successful": 1, "skipped": 0, "failed": 0}), False),
        (ok_search(_shards={"total": 0, "successful": 0, "skipped": 0, "failed": 0}), False),
        (ok_search(_shards={"total": 1, "successful": "1", "skipped": 0, "failed": 0}), False),
        (ok_search(_shards={"total": 1, "successful": -1, "skipped": 2, "failed": 0}), False),
        (ok_search(_shards=None), False),
        (ok_search(hits=None), False),
        (ok_search(hits={"hits": {}}), False),
    ],
)  # fmt: skip
def test_search_completeness_matrix(body: Any, complete: bool) -> None:
    if complete:
        check_complete(Endpoint.SEARCH, body)
    else:
        with pytest.raises(PartialResultError):
            check_complete(Endpoint.SEARCH, body)


def test_mget_and_other_completeness() -> None:
    check_complete(
        Endpoint.MGET, {"docs": [{"_id": "1", "found": True}, {"_id": "2", "found": False}]}
    )
    for docs in (
        {},
        {"docs": None},
        {"docs": [{"_id": "1", "error": {}}]},
        {"docs": [{"_id": "1"}]},
        {"docs": ["x"]},
    ):
        with pytest.raises(PartialResultError):
            check_complete(Endpoint.MGET, docs)
    check_complete(Endpoint.NODE_STATS, {"nodes": {}})
    with pytest.raises(ResponseError):
        check_complete(Endpoint.INFO, [])


def test_took_and_parse() -> None:
    assert took_ms(Endpoint.SEARCH, {"took": 12}, 99.0) == 12
    for body in ({"took": -1}, {"took": True}, {"took": "5"}, {}, None):
        assert took_ms(Endpoint.SEARCH, body, 99.2) == 100
    assert took_ms(Endpoint.MGET, {"took": 1}, 4.0) == 4
    assert took_ms(Endpoint.INFO, None, -3.0) == 0
    assert parse_json(b'{"a": 1}') == {"a": 1}
    assert parse_json(b"\xff") is None
    assert parse_json(b"{") is None
    assert parse_json(b"[" * 100_000 + b"]" * 100_000) is None
