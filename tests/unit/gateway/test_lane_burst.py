"""The Kibana write lane's burst (D-235): its bucket holds 60 s of server time while the SIEM is
NORMAL, so a case of ~45 s posts at once; the refill (200 ms a minute), the day's share (3
minutes) and the sum of the lanes' minute shares are unchanged; at CAUTION or worse, or in a slow
start after a recovery, the capacity is a minute's share again."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from argus.config.settings import SiemSettings
from argus.gateway import budget
from argus.gateway.budget import BudgetConfig, BudgetState, Verdict
from argus.gateway.lanes import (
    BURSTS,
    DEFAULT_LANES,
    Lane,
    LanePlan,
    LaneSpec,
    LaneStates,
    admit,
    plan_from,
    proportional,
    settle,
)
from argus.gateway.templates import CostClass

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)
WRITE = Lane.KIBANA_WRITE


def test_the_kibana_write_lane_bursts_sixty_seconds_and_the_checking_lane_thirty() -> None:
    assert dict(BURSTS) == {
        Lane.COLLECTOR: 10_000, Lane.ENRICHMENT: 10_000, WRITE: 60_000, Lane.CHECKING: 30_000,
    }  # fmt: skip
    spec = DEFAULT_LANES[WRITE]
    assert (spec.per_minute_ms, spec.per_day_ms, spec.burst_ms) == (200, 180_000, 60_000)
    checking = DEFAULT_LANES[Lane.CHECKING]
    assert (checking.per_minute_ms, checking.per_day_ms, checking.burst_ms) == (400, 600_000,
                                                                                30_000)  # fmt: skip
    assert [lane for lane, s in DEFAULT_LANES.items() if s.burst_ms is not None] == [
        Lane.COLLECTOR, Lane.ENRICHMENT, WRITE, Lane.CHECKING,
    ]  # fmt: skip


def test_the_burst_is_not_a_share_the_lanes_still_add_up_to_the_ceiling() -> None:
    lanes = DEFAULT_LANES
    assert sum(s.per_minute_ms for s in lanes.values()) == 3_000  # 60,000 is not in the sum
    assert sum(s.per_day_ms for s in lanes.values()) == 3_600_000
    LanePlan()  # does not raise


def test_the_buckets_capacity_is_the_burst_at_full_scale_and_a_minutes_share_below_it() -> None:
    config = LanePlan().config(WRITE)
    assert (config.took_per_minute_ms, config.burst_ms, config.strained_burst_ms) == (
        200, 60_000, 200,
    )  # fmt: skip
    assert budget.capacity(config, 1.0) == 60_000
    assert budget.capacity(config, 0.5) == 100  # CAUTION: no burst
    assert budget.capacity(config, 0.1) == 20  # DEGRADED
    assert budget.capacity(config, 0.25) == 50  # a slow start after a recovery
    other = LanePlan().config(Lane.INVESTIGATION)
    assert budget.capacity(other, 1.0) == other.burst_ms == 400  # the others never had one


@pytest.mark.parametrize("burst", [199, 180_001])
def test_a_burst_is_between_a_minutes_share_and_the_days(burst: int) -> None:
    with pytest.raises(ValueError, match="burst"):
        LaneSpec(per_minute_ms=200, per_day_ms=180_000, burst_ms=burst)


def admit_at(
    states: LaneStates, now: datetime, scale: float = 1.0, name: str = "x"
) -> tuple[Verdict, LaneStates, object]:
    plan = LanePlan()
    admission, states = admit(states, plan, WRITE, CostClass.LIGHT, now, scale=scale, lease_id=name)
    return admission.verdict, states, admission


def spend(
    states: LaneStates, now: datetime, took_ms: int, scale: float = 1.0, name: str = "x"
) -> tuple[Verdict, LaneStates]:
    verdict, states, admission = admit_at(states, now, scale, name)
    if verdict is Verdict.ADMITTED:
        lease = admission.lease  # type: ignore[attr-defined]
        states = settle(states, LanePlan(), WRITE, lease, took_ms, now, scale=scale)
    return verdict, states


def test_a_case_of_forty_five_seconds_goes_in_one_burst_and_the_next_waits_for_the_refill() -> None:
    states = LaneStates()
    for n in range(14):  # 14 files of 3.2 s: 44.8 s of server time, all at once
        verdict, states = spend(states, T0, 3_200, name=f"f{n}")
        assert verdict is Verdict.ADMITTED, n
    tokens = budget.roll(states.bucket(WRITE), LanePlan().config(WRITE), T0, 1.0).tokens_ms
    assert tokens == pytest.approx(60_000 - 14 * 3_200)
    for n in range(10):  # a full case's 100-alert calls cost 150 ms or so each
        verdict, states = spend(states, T0, 150, name=f"a{n}")
        assert verdict is Verdict.ADMITTED
    # ... until the burst is spent: 60 s in all (46.3 s so far, five more files overdraw it)
    for n in range(5):
        verdict, states = spend(states, T0, 3_200, name=f"g{n}")
    verdict, _, admission = admit_at(states, T0, name="late")
    assert verdict is Verdict.WAIT
    assert admission.reason == "server_time"  # type: ignore[attr-defined]


def test_the_refill_is_still_two_hundred_milliseconds_a_minute() -> None:
    states = LaneStates()
    verdict, states = spend(states, T0, 60_000)  # the whole burst in one go
    assert verdict is Verdict.ADMITTED
    verdict, _, admission = admit_at(states, T0, name="next")
    assert verdict is Verdict.WAIT
    # a light call is admitted on 50 ms of the bucket, refilled at 200 ms a minute: 15 s
    wait = admission.retry_at - T0  # type: ignore[attr-defined]
    assert timedelta(seconds=14) <= wait <= timedelta(seconds=16)
    later = T0 + timedelta(minutes=300)  # the 60 s debt is repaid at 200 ms a minute
    verdict, _, _ = admit_at(states, later, name="much later")
    assert verdict is Verdict.ADMITTED


def test_the_days_share_is_unchanged_a_burst_cannot_spend_more_than_three_minutes() -> None:
    states = LaneStates()
    for n in range(3):  # 3 x 60 s = the day's 180 s, the debt repaid at 200 ms a minute between
        verdict, states = spend(states, T0 + timedelta(minutes=300 * n), 60_000, name=f"d{n}")
        assert verdict is Verdict.ADMITTED
    verdict, _, admission = admit_at(states, T0 + timedelta(hours=11), name="over")
    assert verdict is Verdict.EXHAUSTED
    assert admission.reason == "daily"  # type: ignore[attr-defined]


def test_at_caution_there_is_no_burst_and_a_full_bucket_loses_it() -> None:
    states = LaneStates()
    verdict, states = spend(states, T0, 100, scale=1.0)  # NORMAL: the bucket is 60 s full
    assert verdict is Verdict.ADMITTED
    # The SIEM turns CAUTION: the capacity is 100 ms, the stored 59,900 ms are gone
    rolled = budget.roll(states.bucket(WRITE), LanePlan().config(WRITE), T0, 0.5)
    assert rolled.tokens_ms == pytest.approx(100)
    fresh = LaneStates()
    verdict, fresh = spend(fresh, T0, 150, scale=0.5, name="c1")  # a fresh bucket holds 100 ms
    assert verdict is Verdict.ADMITTED
    verdict, _, admission = admit_at(fresh, T0, scale=0.5, name="c2")
    assert verdict is Verdict.WAIT
    assert admission.reason == "server_time"  # type: ignore[attr-defined]


def test_a_budget_without_a_strained_capacity_behaves_as_before() -> None:
    plain = BudgetConfig(took_per_minute_ms=1_000, burst_ms=1_500)
    assert budget.capacity(plain, 1.0) == 1_500
    assert budget.capacity(plain, 0.5) == 750  # burst scaled, as it always was
    state = budget.roll(BudgetState(), plain, T0, 1.0)
    assert state.tokens_ms == 1_500


def test_a_custom_lane_plan_may_set_or_drop_the_burst() -> None:
    ceiling = BudgetConfig()
    mine = LaneSpec(per_minute_ms=200, per_day_ms=180_000, burst_ms=30_000)
    assert plan_from(ceiling, {"kibana_write": mine}).spec(WRITE).burst_ms == 30_000
    none = LaneSpec(per_minute_ms=200, per_day_ms=180_000)  # an explicit lane without a burst
    assert plan_from(ceiling, {"kibana_write": none}).spec(WRITE).burst_ms is None
    tiny = proportional(BudgetConfig(took_per_day_ms=3_600))  # a day share under a minute's
    assert tiny[WRITE].burst_ms is None


def test_the_settings_carry_the_lanes_burst() -> None:
    settings = SiemSettings(lanes={"kibana_write": {"per_minute_ms": 200, "per_day_ms": 180_000,
                                                     "burst_ms": 20_000}})  # fmt: skip
    assert settings.lane_specs()["kibana_write"].burst_ms == 20_000
    assert SiemSettings().lane_specs() == {}  # the default is the plan's, burst included
