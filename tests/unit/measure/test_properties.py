"""Properties of the session's pacing and caps, and of the lanes' derivation (Q-A3)."""

from __future__ import annotations

import itertools
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.state import ProbeRow, RecentRequest
from argus.gateway.templates import CostClass
from argus.gateway.transport import WireRequest, WireResponse
from argus.measure import lanes
from argus.measure.session import LIMITS, MINUTE, CappedTransport, SessionCapError, ready_at
from tests.unit.gateway.fakes import FakeClock
from tests.unit.measure.fakes import T0

pytestmark = pytest.mark.unit

TEMPLATES = ("alerts.ids", "alerts.counts", "proxy.host", "dns.host_domains", "unknown.x")
HEAVY = {"proxy.host", "dns.host_domains", "unknown.x"}

rows_strategy = st.lists(
    st.builds(
        lambda back, took, template: RecentRequest(
            T0 - timedelta(milliseconds=back), "collector", "collect", template, "ok", took
        ),
        st.integers(0, 70_000),
        st.integers(0, 3_000),
        st.sampled_from(TEMPLATES),
    ),
    max_size=20,
)
costs = st.sampled_from([CostClass.LIGHT, CostClass.MEDIUM, CostClass.HEAVY])


def fits(rows: list[RecentRequest], at: object, cost: CostClass) -> bool:
    """The rules, written out on their own: what may start at ``at``."""
    recent = [r for r in rows if at - MINUTE < r.at <= at]  # type: ignore[operator]
    if sum(r.took_ms for r in recent) + LIMITS.need_ms(cost) > LIMITS.minute_ms:
        return False
    if cost is CostClass.HEAVY:
        heavy = [r for r in recent if r.template in HEAVY]
        if len(heavy) >= LIMITS.heavy_per_minute:
            return False
        gap = LIMITS.heavy_gap + LIMITS.pace_slack
        if any(at - r.at < gap for r in rows if r.template in HEAVY and r.at <= at):  # type: ignore[operator]
            return False
    return True


@given(rows_strategy, costs)
def test_ready_at_is_the_first_moment_every_rule_holds(
    rows: list[RecentRequest], cost: CostClass
) -> None:
    ready = ready_at(rows, T0, cost)
    assert ready is not None
    assert ready >= T0
    assert fits(rows, ready, cost)
    if ready > T0:
        assert not fits(rows, ready - timedelta(microseconds=1), cost)


@given(st.lists(st.tuples(st.sampled_from(TEMPLATES), st.integers(0, 15_000)), max_size=80))
async def test_the_transport_cap_holds_whatever_is_asked(
    asks: list[tuple[str, int]],
) -> None:
    clock = FakeClock(T0)

    class Still:
        async def send(self, request: WireRequest) -> WireResponse:
            return WireResponse(200, b"{}", 1.0)

    capped = CappedTransport(Still(), clock)
    sent: list[tuple[str, object]] = []
    for template, wait in asks:
        clock.advance(timedelta(milliseconds=wait))
        request = WireRequest("GET", "/", (), None, f"argus-measure/{template}@1", 1.0)
        try:
            await capped.send(request)
        except SessionCapError:
            continue
        sent.append((template, clock()))
    heavy = [at for template, at in sent if template in HEAVY]
    assert len(sent) <= LIMITS.max_requests
    assert len(heavy) <= LIMITS.max_heavy
    assert all(b - a >= LIMITS.heavy_gap for a, b in itertools.pairwise(heavy))  # type: ignore[operator]
    assert capped.sent == len(sent)


loads = st.lists(st.floats(0, 40, allow_nan=False), max_size=30)


@given(loads, st.integers(1, 64), st.floats(0.001, 1))
def test_the_headroom_never_exceeds_the_ceiling_and_falls_as_load_rises(
    values: list[float], cores: int, share: float
) -> None:
    probes = [ProbeRow(T0, "normal", load_1m=v) for v in values]
    room = lanes.headroom(probes, cores=cores, spare_share=share)
    assert 0 <= room.minute_ms <= room.ceiling.minute_ms
    busier = lanes.headroom([ProbeRow(T0, "normal", load_1m=v + 1) for v in values],
                            cores=cores, spare_share=share)  # fmt: skip
    assert busier.minute_ms <= room.minute_ms
    assert room.measured == (len(values) >= 3)


@given(st.floats(0, 1))
def test_the_lanes_allowances_never_add_up_past_the_headroom(factor: float) -> None:
    ceiling = lanes.Ceiling()
    room = lanes.Headroom(ceiling, 10, 1.0, 16, 0.02, int(ceiling.minute_ms * factor))
    results = lanes.derive({}, [], room)
    assert sum(r.minute_ms for r in results) <= room.minute_ms
    assert sum(r.day_ms for r in results) <= ceiling.day_ms * room.factor + len(results)


@given(st.lists(st.integers(0, 10_000), min_size=1, max_size=50), st.floats(0, 1))
def test_nearest_rank_is_a_seen_value_and_monotone(values: list[int], q: float) -> None:
    got = lanes.nearest_rank(values, q)
    assert got in values
    assert lanes.nearest_rank(values, min(q + 0.1, 1)) >= got
    share = sum(1 for v in values if v <= got) / len(values)
    assert share >= q
