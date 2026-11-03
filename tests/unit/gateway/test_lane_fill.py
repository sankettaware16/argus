"""A person's top-up of a lane bucket (D-243): the review of AR9 (F6) found that the Kibana write
lane's 60 s burst does not exist after the deploy, because a bucket already stored holds the old
capacity (a minute's share, 200 ms) and ``roll`` keeps what is stored, so it grows into 60 s at
200 ms a minute (five hours). ``argus siem lanes fill kibana_write`` sets the stored bucket to
its capacity; it is refused unless the SIEM is NORMAL at full scale, and it writes ARGUS's own
database only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from typer.testing import CliRunner

from argus.config.settings import SiemSettings
from argus.gateway import budget
from argus.gateway import cli as gateway_cli
from argus.gateway.budget import BudgetState, Verdict
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import DEFAULT_LANES, Lane, LanePlan, LaneStates, admit, fill, settle
from argus.gateway.pgstore import lanes_from_json, lanes_to_json
from argus.gateway.templates import CostClass

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 31, 4, 0, tzinfo=UTC)
WRITE = Lane.KIBANA_WRITE
PLAN = LanePlan()


def pre_deploy(tokens: float = 200.0, at: datetime = T0) -> LaneStates:
    """What the database holds when this version is deployed: the write lane's bucket as the old
    code left it, capped at a minute's share (200 ms), through the JSON the store keeps."""
    old = BudgetState(tokens_ms=tokens, refilled_at=at, day=at.date(), day_used_ms=40_000)
    return lanes_from_json(lanes_to_json(LaneStates({WRITE: old})))


def held(states: LaneStates, now: datetime, scale: float = 1.0) -> float:
    rolled = budget.roll(states.bucket(WRITE), PLAN.config(WRITE), now, scale)
    assert rolled.tokens_ms is not None
    return rolled.tokens_ms


def test_a_bucket_stored_before_the_deploy_needs_five_hours_to_hold_the_burst() -> None:
    """The finding itself: the stored 200 ms grows at 200 ms a minute (12 s an hour)."""
    stored = pre_deploy()
    assert held(stored, T0) == pytest.approx(200)
    assert held(stored, T0 + timedelta(hours=1)) == pytest.approx(12_200)
    assert held(stored, T0 + timedelta(hours=2)) == pytest.approx(24_200)
    assert held(stored, T0 + timedelta(hours=5)) == pytest.approx(60_000)  # the cap
    verdict, after = spend(stored, T0, 45_000)  # a case of 45 s at the deploy
    assert verdict is Verdict.ADMITTED  # a call is admitted on its estimate, then charged its took
    assert held(after, T0) < 0  # which leaves the lane in debt for hours


def spend(states: LaneStates, now: datetime, took_ms: int, name: str = "x") -> tuple[Verdict, Any]:
    admission, states = admit(states, PLAN, WRITE, CostClass.LIGHT, now, scale=1.0, lease_id=name)
    if admission.verdict is Verdict.ADMITTED:
        assert admission.lease is not None
        states = settle(states, PLAN, WRITE, admission.lease, took_ms, now, scale=1.0)
    return admission.verdict, states


def test_a_fill_gives_the_burst_at_once_from_the_stored_pre_deploy_state() -> None:
    before, after, filled = fill(pre_deploy(), PLAN, WRITE, T0, scale=1.0)
    assert (before, after) == (pytest.approx(200), 60_000)
    assert held(filled, T0) == 60_000
    states = filled
    for n in range(14):  # a case of 14 files of 3.2 s, all at once (D-235)
        verdict, states = spend(states, T0, 3_200, f"f{n}")
        assert verdict is Verdict.ADMITTED, n
    assert held(states, T0) == pytest.approx(60_000 - 14 * 3_200, abs=1)


def test_what_a_fill_does_not_change() -> None:
    stored = pre_deploy()
    _, _, filled = fill(stored, PLAN, WRITE, T0, scale=1.0)
    old, new = stored.bucket(WRITE), filled.bucket(WRITE)
    assert (new.day_used_ms, new.day, new.leases) == (old.day_used_ms, old.day, old.leases)
    assert new.refilled_at == T0
    assert dict(filled.buckets) == {WRITE: new}  # no other lane is touched
    # the day's share still caps the day: 40 s were used, 3 minutes is the lane's day
    assert PLAN.spec(WRITE).per_day_ms == 180_000
    assert PLAN.spec(WRITE).per_minute_ms == 200  # and the refill is what it was


def test_the_throughput_after_the_burst_is_what_the_refill_pays() -> None:
    """D-243's numbers: a 60 s burst, then 200 ms a minute (12 s an hour). A case of 45 s leaves
    15 s; the next one is paid 30 s short, which the refill takes 2.5 hours to give, and a case
    after an empty bucket 3.75 hours: about four hours a case in steady state."""
    _, _, filled = fill(pre_deploy(), PLAN, WRITE, T0, scale=1.0)
    _, spent = spend(filled, T0, 45_000)
    assert held(spent, T0) == pytest.approx(15_000, abs=100)
    assert held(spent, T0 + timedelta(hours=2.5)) == pytest.approx(45_000, abs=100)
    _, drained = spend(filled, T0, 60_000)
    assert held(drained, T0 + timedelta(hours=3.75)) == pytest.approx(45_000, abs=100)
    assert PLAN.spec(WRITE).per_day_ms // 45_000 == 4  # and the day's share fits four such cases


def test_a_fill_never_lowers_a_bucket_and_does_nothing_to_a_full_one() -> None:
    _, _, once = fill(pre_deploy(), PLAN, WRITE, T0, scale=1.0)
    before, after, twice = fill(once, PLAN, WRITE, T0, scale=1.0)
    assert (before, after) == (60_000, 60_000)
    assert twice.bucket(WRITE).tokens_ms == 60_000


def test_a_never_used_lane_is_filled_to_its_capacity_too() -> None:
    before, after, filled = fill(LaneStates(), PLAN, WRITE, T0, scale=1.0)
    assert (before, after) == (60_000, 60_000)  # an empty state starts full
    assert filled.bucket(WRITE).tokens_ms == 60_000


@pytest.mark.parametrize("scale", [0.5, 0.25, 0.1, 0.0])
def test_a_fill_is_refused_below_full_scale(scale: float) -> None:
    with pytest.raises(ValueError, match="NORMAL"):
        fill(pre_deploy(), PLAN, WRITE, T0, scale=scale)


def test_a_fill_is_refused_for_the_collector_a_closed_lane_and_a_debt() -> None:
    with pytest.raises(ValueError, match="collector"):
        fill(pre_deploy(), PLAN, Lane.COLLECTOR, T0, scale=1.0)
    with pytest.raises(ValueError, match="closed"):
        fill(pre_deploy(), PLAN, Lane.MEASUREMENT, T0, scale=1.0)
    with pytest.raises(ValueError, match="debt"):
        fill(pre_deploy(tokens=-5_000.0), PLAN, WRITE, T0, scale=1.0)


def test_a_lane_without_a_burst_is_filled_to_its_minutes_share() -> None:
    _, after, _ = fill(LaneStates(), PLAN, Lane.KIBANA_READ, T0, scale=1.0)
    assert after == DEFAULT_LANES[Lane.KIBANA_READ].per_minute_ms == 200


# --------------------------------------------------------------------------- the command


class FakeStore:
    """``PgStore`` as the command uses it: the stored health and the fill, recorded."""

    filled: ClassVar[list[dict[str, Any]]] = []
    memory = HealthMemory(state=HealthState.NORMAL, probed_at=datetime.now(UTC))

    def __init__(self, engine: Any, *plans: Any) -> None:
        self.plans = plans

    async def health(self) -> HealthMemory:
        return self.memory

    async def lane_fill(self, lane: Lane, **kw: Any) -> tuple[float, float]:
        self.filled.append({"lane": lane, **kw})
        return 200.0, 60_000.0


class FakeEngine:
    async def dispose(self) -> None:
        pass


def invoke(monkeypatch: pytest.MonkeyPatch, *args: str, terminal: bool = True, **more: Any) -> Any:
    FakeStore.filled = []
    FakeStore.memory = more.get(
        "memory", HealthMemory(state=HealthState.NORMAL, probed_at=datetime.now(UTC))
    )
    monkeypatch.setattr(gateway_cli, "PgStore", FakeStore)
    monkeypatch.setattr(gateway_cli, "engine_for", lambda settings: FakeEngine())
    monkeypatch.setattr(gateway_cli, "load", lambda config: SimpleNamespace(siem=SiemSettings()))
    monkeypatch.setattr(gateway_cli, "_human_at_a_terminal", lambda: terminal)
    return CliRunner().invoke(
        gateway_cli.siem_app, ["lanes", "fill", *args], input=more.get("input")
    )


def test_the_command_fills_after_the_person_types_the_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    done = invoke(monkeypatch, "kibana_write", "--reason", "the deploy", input="kibana_write\n")
    assert done.exit_code == 0, done.output
    assert "kibana_write: 0.2 s of server time -> 60.0 s (audited)" in done.output
    [call] = FakeStore.filled
    assert call["lane"] is Lane.KIBANA_WRITE
    assert call["reason"] == "the deploy"
    assert call["scale"] == 1.0
    assert call["health"] == "normal"
    assert call["actor"].startswith("host:")


def test_the_command_does_nothing_without_the_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    done = invoke(monkeypatch, "kibana_write", input="yes\n")
    assert done.exit_code == 1
    assert "not confirmed" in done.output
    assert FakeStore.filled == []


def test_the_command_is_a_persons_at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    done = invoke(monkeypatch, "kibana_write", terminal=False, input="kibana_write\n")
    assert done.exit_code == 2
    assert "person at a terminal" in done.output
    assert FakeStore.filled == []


def test_the_command_knows_the_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    done = invoke(monkeypatch, "siem", input="siem\n")
    assert done.exit_code == 2
    assert "kibana_write" in done.output


@pytest.mark.parametrize("state", [HealthState.CAUTION, HealthState.DEGRADED, HealthState.STOP])
def test_the_command_is_refused_unless_siem_is_normal(
    monkeypatch: pytest.MonkeyPatch, state: HealthState
) -> None:
    memory = HealthMemory(state=state, probed_at=datetime.now(UTC))
    done = invoke(monkeypatch, "kibana_write", input="kibana_write\n", memory=memory)
    assert done.exit_code == 1
    assert "NORMAL" in done.output
    assert FakeStore.filled == []


def test_the_command_is_refused_when_the_last_probe_is_old(monkeypatch: pytest.MonkeyPatch) -> None:
    old = HealthMemory(state=HealthState.NORMAL, probed_at=datetime.now(UTC) - timedelta(hours=3))
    done = invoke(monkeypatch, "kibana_write", input="kibana_write\n", memory=old)
    assert done.exit_code == 1
    assert "argus siem probe" in done.output
    assert FakeStore.filled == []
