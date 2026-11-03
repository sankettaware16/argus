"""The measuring session (Q-A3): its plan, its pacing, its CAUTION signals, its caps where
requests leave, and whole sessions against a scripted the SIEM on a fake clock."""

from __future__ import annotations

import itertools
import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

import pytest

from argus.gateway.errors import TransportFailedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthConfig, HealthMemory, HealthState
from argus.gateway.indices import PAD
from argus.gateway.state import MemoryStore, ProbeRow, RecentRequest
from argus.gateway.templates import CostClass
from argus.gateway.transport import WireRequest, WireResponse
from argus.measure.session import (
    COMPONENT,
    LIMITS,
    MINUTE,
    CappedTransport,
    Limits,
    Session,
    SessionCapError,
    Subjects,
    busiest_minute,
    caution_signals,
    cost_of,
    describe,
    log_windows,
    ready_at,
    room_ms,
    verify,
)
from tests.unit.gateway.fakes import FakeClock
from tests.unit.measure.fakes import SUBJECTS, T0, FakeElastic, node, plan_at, rig, template_of

pytestmark = pytest.mark.unit

CFG = HealthConfig()


def searches(elastic: FakeElastic) -> list[WireRequest]:
    probes = {"health.node_stats", "health.index_blocks", "indices.listing"}
    return [call for call in elastic.calls if template_of(call) not in probes]


# --------------------------------------------------------------------------- the plan


def test_the_plan_measures_every_production_template_three_times_within_the_caps() -> None:
    plan = plan_at()
    counts = Counter(item.name for item in plan.items)
    assert counts == {
        "alerts.ids": 3, "alerts.counts": 3, "alerts.states": 3, "alerts.mget": 3,
        "ti.lookup": 3, "ti.newest": 3, "web.followups": 3, "proxy.host": 3,
        "proxy.destination": 3,
    }  # fmt: skip
    assert plan.heavy == 6 <= LIMITS.max_heavy
    assert len(plan.items) <= LIMITS.max_requests - LIMITS.reserve - 4
    assert plan.skipped == ()


def test_no_batch1_template_is_measured_their_first_run_is_the_users() -> None:
    names = {item.name for item in plan_at().items}
    assert not names & {
        "proxy.pair", "proxy.contact", "dns.host_domains", "web.path_outcomes",
        "logs.source_events",
    }  # fmt: skip


def test_each_sample_of_a_template_asks_something_different() -> None:
    """A repeated aggregation could be answered from Elasticsearch's request cache."""
    by_name: dict[str, list[Any]] = {}
    for item in plan_at().items:
        by_name.setdefault(item.name, []).append(item.params)
    for name, params in by_name.items():
        if name == "ti.newest":  # two indices; a search that returns a row is never cached
            assert {p.index for p in params} == {"abuse-ioc", "acme-threat-intel"}
            continue
        assert len(set(params)) == len(params), name


def test_every_planned_request_passes_the_gateways_validator() -> None:
    gateway = Gateway(FakeElastic(FakeClock(T0)), MemoryStore(), targets=Targets())
    lines = describe(plan_at(), gateway, T0)
    assert not [line for line in lines if "REFUSED" in line]
    assert len([line for line in lines if line.startswith("  ") and "#" in line]) == 27


def test_heavy_requests_are_spread_between_the_light_ones() -> None:
    items = plan_at().items
    heavy = [i for i, item in enumerate(items) if item.cost is CostClass.HEAVY]
    assert all(b - a >= 4 for a, b in itertools.pairwise(heavy))
    assert items[0].cost is CostClass.HEAVY


def test_switched_off_log_templates_are_not_measured_and_say_so() -> None:
    plan = plan_at(log_queries=False, proxy_aggregations=False)
    assert plan.heavy == 0
    assert {item.name for item in plan.items}.isdisjoint({"web.followups", "proxy.host"})
    assert any("enrichment.log_queries" in note for note in plan.skipped)
    assert any("proxy.host, proxy.destination: off" in note for note in plan.skipped)


def test_missing_subjects_are_named() -> None:
    plan = plan_at(subjects=Subjects())
    names = {item.name for item in plan.items}
    assert names == {"alerts.ids", "alerts.counts", "alerts.states", "ti.newest"}
    assert len(plan.skipped) >= 4


def test_log_windows_stay_in_one_daily_index_and_avoid_the_quiet_hours() -> None:
    windows = log_windows(T0, 3)
    assert isinstance(windows, list)
    assert len(windows) == 3
    assert all(end - start == timedelta(hours=1) and start.date() == T0.date()
               for start, end in windows)  # fmt: skip
    assert len(set(windows)) == 3
    assert isinstance(log_windows(T0.replace(hour=0, minute=40), 3), str)
    early = log_windows(T0.replace(hour=3, minute=30), 3)
    assert isinstance(early, list)
    assert len(early) == 3
    # 00:00-01:00 to 22:00-23:00 would pad into the neighbouring day's index (what a window
    # reads may lie in the quiet hours; only sending in them is not allowed)
    assert [start.hour for start, _ in early] == [2, 1, 21]
    assert all((end + PAD).date() == (start - PAD).date() for start, end in early)


def test_fewer_than_three_samples_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 3"):
        plan_at(samples=2)


def test_a_plan_beyond_the_caps_is_refused() -> None:
    with pytest.raises(ValueError, match="exceed the session's caps"):
        plan_at(samples=6)  # 12 heavy


# --------------------------------------------------------------------------- pacing


def row(at: datetime, took: int, template: str = "alerts.ids", component: str = "collector",
        outcome: str = "ok") -> RecentRequest:  # fmt: skip
    return RecentRequest(at, component, "collect", template, outcome, took)


def test_room_counts_every_component_in_the_last_minute() -> None:
    rows = [row(T0 - timedelta(seconds=70), 900), row(T0 - timedelta(seconds=30), 700),
            row(T0, 100, component=COMPONENT)]  # fmt: skip
    assert room_ms(rows, T0) == 3_000 - 800


def test_a_request_waits_until_its_timeout_fits_the_minute() -> None:
    rows = [row(T0 - timedelta(seconds=50), 1_500), row(T0 - timedelta(seconds=10), 900)]
    # light: may be charged 1,300 ms (1 s, the wire's 0.3 s more), needs 1,500 ms of room;
    # 600 left until the first row leaves at T0 + 10 s
    assert LIMITS.need_ms(CostClass.LIGHT) == 1_500
    assert ready_at(rows, T0, CostClass.LIGHT) == T0 + timedelta(seconds=10)
    # heavy: needs 2,500 ms, so both rows must leave; no heavy gap without a heavy row
    assert LIMITS.need_ms(CostClass.HEAVY) == 2_500
    assert ready_at(rows, T0, CostClass.HEAVY) == T0 + timedelta(seconds=50)
    exact = [row(T0 - timedelta(seconds=10), 500)]  # exactly 2,500 ms of room left
    assert ready_at(exact, T0, CostClass.HEAVY) == T0
    assert ready_at([], T0, CostClass.HEAVY) == T0


def test_heavy_requests_keep_their_gap_and_six_a_minute() -> None:
    last = row(T0 - timedelta(seconds=3), 10, "proxy.host")
    assert ready_at([last], T0, CostClass.HEAVY) == last.at + timedelta(seconds=11)
    assert ready_at([last], T0, CostClass.LIGHT) == T0  # the gap is for heavy ones only
    six = [row(T0 - timedelta(seconds=55 - 9 * n), 10, "proxy.host") for n in range(6)]
    assert ready_at(six, T0, CostClass.HEAVY) == six[0].at + MINUTE


def test_an_unknown_template_counts_as_heavy() -> None:
    assert cost_of("no.such.template") is CostClass.HEAVY
    assert cost_of("health.node_stats") is CostClass.PROBE
    assert cost_of("proxy.pair") is CostClass.HEAVY  # batch-1 templates are known


def test_a_timeout_larger_than_the_minute_never_fits() -> None:
    limits = Limits(cap_s=((CostClass.HEAVY, 3),))
    assert ready_at([], T0, CostClass.HEAVY, limits) is None


# --------------------------------------------------------------------------- signals


def reading(**kw: Any) -> ProbeRow:
    values: dict[str, Any] = {
        "at": T0, "state": "normal", "disk_percent": 60.0, "heap_percent": 50.0,
        "load_1m": 2.0, "search_queue": 0, "search_rejected": 7, "breakers_tripped": 0,
    }  # fmt: skip
    values.update(kw)
    return ProbeRow(**values)


NORMAL = HealthMemory(probed_at=T0)


def test_a_quiet_normal_reading_gives_no_signal() -> None:
    assert caution_signals(NORMAL, reading(), reading(), T0, CFG) == []


@pytest.mark.parametrize(
    ("change", "signal"),
    [
        ({"disk_percent": 85.0}, "disk 85"),
        ({"heap_percent": 85.5}, "heap 85.5"),
        ({"load_1m": 16.5}, "load 16.5"),
        ({"search_queue": 1}, "search queue 1"),
        ({"search_rejected": 8}, "search rejections rose by 1"),
        ({"breakers_tripped": 2}, "breaker trips rose by 2"),
        ({"probe_ok": False}, "the newest probe failed"),
        ({"auth_failed": True}, "the SIEM refused the key"),
        ({"blocked_indices": ("x",)}, "1 index(es) blocked"),
        ({"state": "caution"}, "the newest probe left the SIEM caution"),
        ({"heap_percent": None}, "heap unknown"),
        ({"load_1m": None}, "load unknown"),
        ({"search_queue": None}, "search queue unknown"),
        ({"search_rejected": None}, "search rejections unknown"),
        ({"breakers_tripped": None}, "breaker trips unknown"),
        ({"at": T0 - timedelta(seconds=61)}, "61 s old"),
    ],
)
def test_every_caution_signal(change: dict[str, Any], signal: str) -> None:
    found = caution_signals(NORMAL, reading(**change), reading(), T0, CFG)
    assert any(signal in item for item in found), found


def test_gauges_just_below_their_thresholds_give_no_signal() -> None:
    edge = reading(disk_percent=84.99, heap_percent=85.0, load_1m=16.0)
    assert caution_signals(NORMAL, edge, edge, T0, CFG) == []


def test_a_state_other_than_normal_and_no_reading_are_signals() -> None:
    caution = HealthMemory(state=HealthState.CAUTION, reasons=("load",))
    assert caution_signals(caution, reading(), None, T0, CFG)[0] == "the SIEM is caution (load)"
    assert caution_signals(NORMAL, None, None, T0, CFG) == ["no stored probe reading"]


def test_counters_that_fall_after_a_restart_are_no_rise() -> None:
    assert caution_signals(NORMAL, reading(search_rejected=0), reading(), T0, CFG) == []


# --------------------------------------------------------------------------- the transport cap


def _request(template: str) -> WireRequest:
    return WireRequest("POST", "/x/_search", (), b"{}", f"argus-measure/{template}@1", 1.0)


async def test_the_cap_counts_every_request_and_refuses_past_it_unsent() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    capped = CappedTransport(elastic, clock, Limits(max_requests=3, max_heavy=1))
    await capped.send(_request("health.node_stats"))
    await capped.send(_request("proxy.host"))
    with pytest.raises(SessionCapError, match=r"1 heavy requests are used"):
        await capped.send(_request("proxy.destination"))
    clock.advance(timedelta(seconds=20))
    with pytest.raises(SessionCapError, match="1 heavy requests are used"):
        await capped.send(_request("proxy.destination"))
    await capped.send(_request("alerts.ids"))
    with pytest.raises(SessionCapError, match="3 requests are used"):
        await capped.send(_request("alerts.ids"))
    assert (capped.sent, capped.heavy, len(elastic.calls)) == (3, 1, 3)


class Still:
    """Answers at once, without moving the clock."""

    async def send(self, request: WireRequest) -> WireResponse:
        return WireResponse(200, b"{}", 1.0)


async def test_heavy_requests_closer_than_ten_seconds_are_refused() -> None:
    clock = FakeClock(T0)
    capped = CappedTransport(Still(), clock)
    await capped.send(_request("proxy.host"))
    clock.advance(timedelta(seconds=9.999))
    with pytest.raises(SessionCapError, match="10 s apart"):
        await capped.send(_request("proxy.host"))
    clock.advance(timedelta(milliseconds=1))
    await capped.send(_request("proxy.host"))


def test_a_session_must_send_through_its_counter() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    gateway = Gateway(elastic, MemoryStore(), clock=clock)
    with pytest.raises(ValueError, match="CappedTransport"):
        Session(gateway, MemoryStore(), plan_at(), counter=CappedTransport(elastic, clock),
                probe=lambda: None)  # type: ignore[arg-type]  # fmt: skip


# --------------------------------------------------------------------------- whole sessions


async def test_a_whole_session_measures_its_plan_within_every_rule() -> None:
    r = rig()
    report = await r.session.run()
    assert report.stopped is None, report.stopped
    assert report.complete
    assert [s.outcome for s in report.samples] == ["ok"] * 27
    assert report.requests_sent == len(r.elastic.calls) <= LIMITS.max_requests
    assert report.heavy_sent == 6
    # every request of the session is on the ledger as the measure component and purpose
    ours = [e for e in r.store.ledger if e.component == COMPONENT]
    listings = [c for c in r.elastic.calls if template_of(c) == "indices.listing"]
    assert listings  # the gateway's own, named as the session's (review F3)
    assert len(ours) == len(r.elastic.calls)
    assert {e.purpose for e in ours} == {"measure", "probe"}
    rows = await r.store.requests_since(T0 - MINUTE)
    probes = await r.store.probes_since(T0 - MINUTE)
    verdict = verify(rows, probes, report.started, report.ended or r.clock(),
                     requests_sent=report.requests_sent)  # fmt: skip
    assert verdict.passed, verdict.problems
    assert report.ended is not None
    assert report.ended - report.started < LIMITS.max_duration
    heavy_at = [at for call, at in zip(r.elastic.calls, r.elastic.at, strict=True)
                if cost_of(template_of(call)) is CostClass.HEAVY]  # fmt: skip
    assert all(b - a >= LIMITS.heavy_gap for a, b in itertools.pairwise(heavy_at))


async def test_the_session_report_holds_no_query_value() -> None:
    r = rig()
    report = await r.session.run()
    text = json.dumps(report.to_json())
    for value in (SUBJECTS.host, SUBJECTS.destination, SUBJECTS.client, "id-0-0"):
        assert value is not None
        assert value not in text


async def test_a_caution_reading_mid_session_ends_it() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock, nodes=[node(), node(), node(queue=2)])
    r = rig(elastic=elastic, clock=clock)
    report = await r.session.run()
    assert report.stopped is not None
    assert "CAUTION signal" in report.stopped
    assert "search queue 2" in report.stopped
    assert 0 < len(report.samples) < 27
    # nothing was measured after the reading: the last call is the probe that saw it (and the
    # closing probe)
    last_search = max(i for i, c in enumerate(elastic.calls) if c in searches(elastic))
    stats = [i for i, c in enumerate(elastic.calls) if template_of(c) == "health.node_stats"]
    assert last_search < stats[2]


async def test_rejections_rising_from_the_sessions_start_end_it() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock, nodes=[node(rejected=7), node(rejected=7), node(rejected=9)])
    report = await rig(elastic=elastic, clock=clock).session.run()
    assert report.stopped is not None
    assert "search rejections rose by 2" in report.stopped


async def test_a_caution_reading_at_the_start_sends_only_the_probe() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock, nodes=[node(load=20.0)])
    report = await rig(elastic=elastic, clock=clock).session.run()
    assert report.stopped is not None
    assert "load 20" in report.stopped
    assert searches(elastic) == []
    assert report.samples == []


async def test_a_failed_request_ends_the_session_without_a_retry() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["alerts.counts"] = WireResponse(500, b'{"error":{"type":"x"}}', 5.0)
    r = rig(elastic=elastic, clock=clock)
    report = await r.session.run()
    assert report.stopped is not None
    assert "alerts.counts #1: siem_error" in report.stopped
    assert report.samples[-1].outcome == "siem_error"
    assert sum(template_of(c) == "alerts.counts" for c in elastic.calls) == 1


async def test_an_overload_opens_the_breaker_and_ends_the_session() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["proxy.host"] = WireResponse(429, b'{"error":{"type":"x"}}', 5.0)
    r = rig(elastic=elastic, clock=clock)
    report = await r.session.run()
    assert report.stopped is not None
    assert "overloaded" in report.stopped
    assert r.store.breaker.is_open(clock())
    assert searches(elastic) == [c for c in elastic.calls if template_of(c) == "proxy.host"]


async def test_a_reset_heavy_request_is_not_retried_inside_ten_seconds() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["proxy.host"] = TransportFailedError("reset", retriable=True)
    report = await rig(elastic=elastic, clock=clock).session.run()
    assert report.stopped is not None
    assert "proxy.host #1" in report.stopped
    assert sum(template_of(c) == "proxy.host" for c in elastic.calls) == 1


async def test_the_quiet_hours_and_the_kill_switches_send_nothing() -> None:
    for start, stopped in ((T0.replace(hour=0, minute=30), set()),
                           (T0.replace(hour=23, minute=50), set()),
                           (T0, {"enrichment"}), (T0, {"global"})):  # fmt: skip
        clock = FakeClock(start)
        elastic = FakeElastic(clock)
        store = MemoryStore(memory=HealthMemory(probed_at=start), stopped=stopped)
        report = await rig(elastic=elastic, clock=clock, store=store,
                           plan=plan_at(T0)).session.run()  # fmt: skip
        assert report.stopped is not None
        assert report.samples == []
        assert elastic.calls == []  # not even a probe
        assert report.notes == ["nothing was sent"]


async def test_a_switch_stopped_mid_session_stops_it_before_the_next_request() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    r = rig(elastic=elastic, clock=clock)

    def stop_after(request: WireRequest) -> WireResponse:
        r.store.stopped.add("collector")
        elastic.replies.pop("alerts.counts")
        shards = {"total": 1, "successful": 1, "skipped": 0, "failed": 0}
        body = {"took": 5, "timed_out": False, "hits": {"hits": []}, "_shards": shards}
        return WireResponse(200, json.dumps(body).encode(), 5.0)

    elastic.replies["alerts.counts"] = stop_after
    report = await r.session.run()
    assert report.stopped is not None
    assert "kill switch" in report.stopped
    after = [template_of(c) for c in elastic.calls]
    after = after[after.index("alerts.counts") + 1 :]
    assert set(after) <= {"health.node_stats", "health.index_blocks"}


async def test_another_components_load_makes_the_session_wait_never_exceed() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    from argus.gateway.state import LedgerEntry

    for n in range(40):  # production: 2.5 s of server time in every minute, for 40 minutes
        store.ledger.append(LedgerEntry(T0 + n * MINUTE - timedelta(seconds=30), "collector",
                                        "collect", "alerts.ids", 1, (), "ok", 200, 2_500, 10,
                                        0, 1))  # fmt: skip
    report = await rig(store=store, clock=clock).session.run()
    # a light request needs 1.2 s of room: there never is, so the session gives up in time
    assert report.stopped is not None
    assert "no room" in report.stopped
    assert report.samples == []


async def test_a_busy_shared_budget_is_waited_for_a_few_times_then_ends_the_session() -> None:
    from argus.gateway.budget import BudgetState

    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    r = rig(store=store, clock=clock)
    store.budget = BudgetState(tokens_ms=-1e9, refilled_at=T0, day=T0.date())
    report = await r.session.run()
    assert report.stopped is not None
    assert "the budget stayed busy" in report.stopped
    assert searches(r.elastic) == []
    assert report.samples[-1].outcome == "deadline_passed"


async def test_the_sessions_request_cap_ends_it_cleanly() -> None:
    limits = Limits(max_requests=16)
    r = rig(limits=limits, plan=plan_at())
    report = await r.session.run()
    assert report.stopped == "the session's requests are used up"
    assert report.requests_sent <= 16
    assert len(r.elastic.calls) <= 16


async def test_a_session_past_its_longest_duration_ends() -> None:
    limits = Limits(max_duration=timedelta(minutes=1))
    report = await rig(limits=limits).session.run()
    assert report.stopped is not None
    assert "without finishing" in report.stopped


async def test_a_budget_still_coming_back_is_a_signal() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0, recovered_at=T0 - timedelta(minutes=5)))
    report = await rig(store=store, clock=clock).session.run()
    assert report.stopped is not None
    assert "coming back" in report.stopped


# --------------------------------------------------------------------------- verification


def probe_row(at: datetime, **kw: Any) -> ProbeRow:
    return reading(at=at, **kw)


def good() -> tuple[list[RecentRequest], list[ProbeRow]]:
    names = ("proxy.host", "alerts.ids")
    rows = [row(T0 + timedelta(seconds=12 * n), 400, names[n % 2], COMPONENT) for n in range(10)]
    return rows, [probe_row(T0), probe_row(T0 + timedelta(seconds=100))]


def test_a_clean_session_verifies() -> None:
    rows, probes = good()
    verdict = verify(rows, probes, T0, T0 + timedelta(minutes=2))
    assert verdict.passed, verdict.problems
    assert "busiest minute, all of ARGUS: 2000 ms, 3 heavy" in verdict.facts


def test_a_minute_over_three_seconds_fails_for_all_of_argus_too() -> None:
    rows, probes = good()
    rows.append(row(T0 + timedelta(seconds=5), 1_500))  # another component's request
    verdict = verify(rows, probes, T0, T0 + timedelta(minutes=2))
    assert any("all of ARGUS used 3500 ms" in p for p in verdict.problems)
    assert not any(p.startswith("the session used") for p in verdict.problems)


def test_seven_heavy_in_a_minute_and_a_short_gap_fail() -> None:
    rows = [row(T0 + timedelta(seconds=8 * n), 10, "proxy.host", COMPONENT) for n in range(7)]
    verdict = verify(rows, [probe_row(T0)], T0, T0 + timedelta(minutes=1))
    assert any("7 heavy requests in the minute" in p for p in verdict.problems)
    assert any("8.0 s apart" in p for p in verdict.problems)


def test_too_many_requests_failures_and_caution_readings_fail() -> None:
    rows = [row(T0 + timedelta(seconds=n), 1, component=COMPONENT) for n in range(51)]
    rows.append(row(T0 + timedelta(seconds=52), 1, component=COMPONENT, outcome="timed_out"))
    rows.append(row(T0 + timedelta(seconds=53), 0, component=COMPONENT, outcome="session_cap"))
    probes = [probe_row(T0), probe_row(T0 + timedelta(seconds=60), search_queue=3)]
    verdict = verify(rows, probes, T0, T0 + timedelta(minutes=2))
    assert "52 requests sent, more than 50" in verdict.problems
    assert "requests that did not answer ok: timed_out" in verdict.problems
    assert any("search queue 3" in p for p in verdict.problems)


def test_no_rows_or_no_readings_fail() -> None:
    verdict = verify([], [], T0, T0 + MINUTE)
    assert set(verdict.problems) >= {
        "the ledger holds no request of the session", "no probe reading during the session",
    }  # fmt: skip


def test_an_unknown_stored_state_is_not_healthy() -> None:
    rows, _ = good()
    verdict = verify(rows, [probe_row(T0, state="strange")], T0, T0 + timedelta(minutes=2))
    assert any("the SIEM is stop" in p for p in verdict.problems)


def test_busiest_minute_only_counts_windows_starting_in_its_span() -> None:
    rows = [row(T0 - timedelta(minutes=5), 2_900), row(T0, 100)]
    assert busiest_minute(rows, T0 - MINUTE, T0)[0] == 100


def test_a_busy_minute_of_others_without_a_session_request_is_not_the_sessions() -> None:
    rows, probes = good()  # the session starts at T0
    rows.append(row(T0 - timedelta(seconds=61), 3_500))  # ARGUS busy just before it
    verdict = verify(rows, probes, T0, T0 + timedelta(minutes=2))
    assert verdict.passed, verdict.problems
    rows.append(row(T0 - timedelta(seconds=30), 2_000))  # shares a minute with 3 of the session
    verdict = verify(rows, probes, T0, T0 + timedelta(minutes=2))
    assert any("all of ARGUS used" in p for p in verdict.problems)


async def test_a_minute_that_fills_up_during_a_budget_wait_is_paced_again() -> None:
    from argus.gateway.budget import BudgetState
    from argus.gateway.state import LedgerEntry

    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    r = rig(store=store, clock=clock)
    added: list[datetime] = []

    async def gateway_sleep(seconds: float) -> None:
        if not added:  # the first budget wait: another component spends 2.5 s meanwhile
            added.append(clock())
            store.ledger.append(LedgerEntry(clock(), "enrichment", "enrich", "proxy.host", 1, (),
                                            "ok", 200, 2_500, 2_500, 0, 1))  # fmt: skip
        await clock.sleep(seconds)

    r.gateway.sleep = gateway_sleep
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    report = await r.session.run()
    assert report.stopped is None, report.stopped
    first = next(e for e in store.ledger if e.purpose == "measure")
    assert first.at >= added[0] + MINUTE  # it waited until the other request left the minute
    rows = await store.requests_since(T0 - MINUTE)
    verdict = verify(rows, await store.probes_since(T0 - MINUTE), report.started,
                     report.ended or clock())  # fmt: skip
    assert verdict.passed, verdict.problems


async def test_an_interrupted_session_sends_no_closing_probe_and_keeps_its_report() -> None:
    import asyncio

    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["alerts.counts"] = asyncio.CancelledError()
    r = rig(elastic=elastic, clock=clock)
    with pytest.raises(asyncio.CancelledError):
        await r.session.run()
    assert template_of(elastic.calls[-1]) == "alerts.counts"  # nothing after it
    report = r.session.report
    assert report.stopped == "interrupted"
    assert report.notes == ["no closing probe: interrupted"]
    assert report.requests_sent == len(elastic.calls)
    assert report.ended is not None
    aborted = [e for e in r.store.ledger if e.template == "alerts.counts"]
    assert [e.outcome for e in aborted] == ["aborted"]  # the gateway settled it
    assert r.store.budget.leases == ()


async def test_a_light_request_the_gateway_would_retry_is_not_retried() -> None:
    """The gateway retries a reset once, but the session's check refuses the retry (review
    F1): one send, and the session ends."""
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    first = [True]

    def reset_once(request: WireRequest) -> WireResponse:
        if first[0]:
            first[0] = False
            raise TransportFailedError("reset", retriable=True)
        elastic.replies.pop("alerts.counts")
        return WireResponse(200, json.dumps({
            "took": 5, "timed_out": False, "hits": {"hits": []},
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        }).encode(), 5.0)  # fmt: skip

    elastic.replies["alerts.counts"] = reset_once
    r = rig(elastic=elastic, clock=clock)
    report = await r.session.run()
    assert report.stopped == (
        "alerts.counts #1: the SIEM did not answer cleanly"
        " (transport_failure); the session never retries a request"
    )
    assert report.samples[-1].outcome == "transport_failure"
    assert sum(template_of(c) == "alerts.counts" for c in elastic.calls) == 1


async def test_a_retry_the_room_refused_is_not_sent_again_by_the_session() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    elastic = FakeElastic(clock)
    from argus.gateway.state import LedgerEntry

    def reset_and_fill(request: WireRequest) -> WireResponse:
        store.ledger.append(LedgerEntry(clock(), "collector", "collect", "alerts.ids", 1, (),
                                        "ok", 200, 2_900, 10, 0, 1))  # fmt: skip
        raise TransportFailedError("reset", retriable=True)

    elastic.replies["alerts.counts"] = reset_and_fill
    report = await rig(elastic=elastic, clock=clock, store=store).session.run()
    assert report.stopped == (
        "alerts.counts #1: the SIEM did not answer cleanly"
        " (transport_failure); the session never retries a request"
    )
    assert sum(template_of(c) == "alerts.counts" for c in elastic.calls) == 1
