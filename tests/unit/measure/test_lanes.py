"""The derivation rule (Q-A3): per lane, Σ p95 took times planned rate within its share of the
headroom, each template with at least 3 samples; the headroom never above D-022's ceiling."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from argus.gateway.state import ProbeRow, RecentRequest
from argus.gateway.templates import CostClass
from argus.measure import lanes
from argus.measure.lanes import LANES, Ceiling, Rate, TemplateStats
from tests.unit.measure.fakes import T0

pytestmark = pytest.mark.unit

DAY0 = datetime(2026, 10, 12, tzinfo=T0.tzinfo)


def req(at: datetime, template: str, took: int, component: str = "collector",
        outcome: str = "ok") -> RecentRequest:  # fmt: skip
    return RecentRequest(at, component, "collect", template, outcome, took)


def test_the_proposals_add_up_to_d022s_ceiling() -> None:
    ceiling = Ceiling()
    assert sum(lane.minute_ms for lane in LANES) == ceiling.minute_ms == 3_000
    assert sum(lane.day_ms for lane in LANES) == ceiling.day_ms == 3_600_000
    assert sum(lane.heavy_day or 0 for lane in LANES) == ceiling.heavy_day == 2_000
    owned = [c for lane in LANES for c in lane.components]
    assert len(owned) == len(set(owned))  # a component belongs to one lane


def test_template_stats_count_answered_requests_and_leave_probes_out() -> None:
    rows = [req(T0, "proxy.host", took) for took in (100, 200, 300, 400, 900)]
    rows += [req(T0, "proxy.host", 5_000, outcome="timed_out"),
             req(T0, "health.node_stats", 50, component="probe")]  # fmt: skip
    stats = lanes.template_stats(rows)
    assert stats == {"proxy.host": TemplateStats("proxy.host", CostClass.HEAVY, 5, 300, 900, 900)}


def test_observed_rates_take_the_busiest_minute_and_the_busiest_full_day() -> None:
    rows = []
    for day, count in ((0, 5), (1, 9), (2, 4)):  # 12th (first, partial), 13th, 14th (partial)
        rows += [req(DAY0 + timedelta(days=day, hours=1, seconds=n), "alerts.ids", 10)
                 for n in range(count)]  # fmt: skip
    rows.append(req(DAY0 + timedelta(days=1), "alerts.ids", 10, component=lanes.MEASURE_COMPONENT))
    rows.append(req(DAY0 + timedelta(days=1), "health.node_stats", 10, component="probe"))
    rows.append(req(DAY0 + timedelta(days=1), "alerts.ids", 10, component="someone-new"))
    rates, unowned = lanes.observed_rates(rows, DAY0 + timedelta(days=2, hours=5))
    assert rates == [Rate("collector", "alerts.ids", 9, 9, 1)]
    assert unowned == ["someone-new"]


def test_without_a_full_day_the_rate_is_the_spans_average_scaled_to_a_day() -> None:
    rows = [req(T0 + timedelta(minutes=n), "alerts.ids", 10) for n in range(60)]
    rates, _ = lanes.observed_rates(rows, T0 + timedelta(hours=2))
    assert rates[0].per_day == 60 * 12
    assert rates[0].full_days == 0


def test_a_plan_adds_rates_and_never_lowers_an_observed_one() -> None:
    observed = [Rate("collector", "alerts.ids", 4, 3_000, 2)]
    plan = {"collector": {"alerts.ids": {"per_minute": 2, "per_day": 5_000}},
            "investigation": {"proxy.pair": {"per_minute": 1, "per_day": 200}}}  # fmt: skip
    merged = lanes.apply_plan(observed, plan)
    assert merged == [
        Rate("collector", "alerts.ids", 4, 5_000, 2, planned=True),
        Rate("investigation", "proxy.pair", 1, 200, 0, planned=True),
    ]


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        ({"nope": {}}, "unknown lane"),
        ({"collector": []}, "not a mapping"),
        ({"collector": {"alerts.ids": {"per_hour": 1}}}, "takes per_minute and per_day"),
        ({"collector": {"alerts.ids": {"per_day": -1}}}, "whole numbers"),
        ({"collector": {"alerts.ids": {"per_day": True}}}, "whole numbers"),
    ],
)
def test_a_bad_plan_is_refused(plan: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        lanes.apply_plan([], plan)


def probes(*loads: float | None, ok: bool = True) -> list[ProbeRow]:
    return [ProbeRow(T0, "normal", probe_ok=ok, load_1m=load) for load in loads]


def test_the_headroom_keeps_the_ceiling_on_a_quiet_node_and_lowers_it_on_a_busy_one() -> None:
    quiet = lanes.headroom(probes(2.0, 3.0, 4.0))
    assert (quiet.measured, quiet.load_p95, quiet.minute_ms, quiet.factor) == (True, 4.0, 3_000, 1)
    busy = lanes.headroom(probes(14.0, 14.5, 15.0))  # 1 spare core: 2 % of 60 s is 1,200 ms
    assert (busy.minute_ms, busy.factor) == (1_200, 0.4)
    saturated = lanes.headroom(probes(17.0, 18.0, 19.0))
    assert saturated.minute_ms == 0


def test_too_few_or_failed_readings_leave_the_headroom_unmeasured() -> None:
    room = lanes.headroom([*probes(2.0, 2.0), *probes(1.0, ok=False), *probes(None)])
    assert (room.measured, room.readings, room.minute_ms) == (False, 2, 3_000)
    with pytest.raises(ValueError, match="cores"):
        lanes.headroom([], cores=0)
    with pytest.raises(ValueError, match="spare share"):
        lanes.headroom([], spare_share=0)


def stats(name: str, p95: int, samples: int = 5) -> TemplateStats:
    return TemplateStats(name, lanes.cost_of(name), samples, p95, p95, p95)


ROOM = lanes.headroom(probes(2.0, 2.0, 2.0))


def result(rates: list[Rate], known: dict[str, TemplateStats], room: lanes.Headroom = ROOM,
           lane: str = "collector") -> lanes.LaneResult:  # fmt: skip
    return next(r for r in lanes.derive(known, rates, room) if r.lane.name == lane)


def test_a_lane_that_fits_its_share() -> None:
    known = {"alerts.ids": stats("alerts.ids", 20), "proxy.host": stats("proxy.host", 700)}
    rates = [Rate("collector", "alerts.ids", 4, 3_000, 3),
             Rate("collector", "proxy.host", 2, 800, 3)]  # fmt: skip
    r = result(rates, known)
    assert r.verdict == "fits"
    assert (r.demand_minute_ms, r.demand_day_ms, r.demand_heavy_day) == (1_480, 620_000, 800)
    assert (r.minute_ms, r.day_ms, r.heavy_day) == (1_800, 2_400_000, 1_600)


def test_a_lane_over_its_share_says_where() -> None:
    known = {"proxy.host": stats("proxy.host", 700)}
    r = result([Rate("collector", "proxy.host", 3, 4_000, 3)], known)
    assert r.verdict == "over"
    assert r.reasons == (
        "a busy minute needs 2100 ms of its 1800 ms",
        "a busy day needs 46.7 of its 40.0 min",
        "4000 heavy requests a day, its share 1600",
    )


def test_heavy_work_in_a_lane_without_a_heavy_share_is_over() -> None:
    known = {"proxy.host": stats("proxy.host", 10)}
    r = result([Rate("freshness", "proxy.host", 1, 1, 1)], known, lane="freshness")
    assert r.verdict == "over"
    assert "its share 0" in r.reasons[0]


def test_fewer_than_three_samples_or_no_rate_keep_the_proposal() -> None:
    r = result(
        [Rate("collector", "proxy.host", 1, 1, 1)], {"proxy.host": stats("proxy.host", 9, 2)}
    )
    assert r.verdict == "not measured"
    assert r.reasons == ("proxy.host: 2 samples (needs 3)",)
    r = result([Rate("collector", "dns.host_domains", 1, 1, 1)], {})
    assert r.reasons == ("dns.host_domains: 0 samples (needs 3)",)
    r = result([], {}, lane="kibana_reads")
    assert r.verdict == "not measured"
    assert "proposal kept" in r.reasons[0]


def test_a_lowered_headroom_shrinks_every_lane_in_proportion() -> None:
    busy = lanes.headroom(probes(14.0, 14.5, 15.0))  # factor 0.4
    results = lanes.derive({}, [], busy)
    assert [r.minute_ms for r in results] == [720, 160, 60, 100, 80, 80, 0]


def test_the_report_and_the_decision_draft() -> None:
    known = {"alerts.ids": stats("alerts.ids", 20)}
    rates = [Rate("collector", "alerts.ids", 4, 3_000, 3)]
    results = lanes.derive(known, rates, ROOM)
    text = "\n".join(lanes.report_lines(results, known, ROOM, ["someone-new"]))
    assert "alerts.ids (light): 5 samples, p50 20 ms, p95 20 ms" in text
    assert "(D-022 ceiling holds)" in text
    assert "someone-new" in text
    draft = lanes.decision_draft(results, ROOM, DAY0, T0)
    assert draft.startswith("## D-NNN — The load budget re-measured")
    assert "| Collector and enrichment | 1,800 ms | 40 min | 1,600 | fits |" in draft
    assert "| Freshness | 150 ms | 3 min | — | not measured |" in draft
    data = lanes.to_json(results, known, ROOM)
    assert data["lanes"][0]["verdict"] == "fits"
    assert data["headroom"]["minute_ms"] == 3_000
