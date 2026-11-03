"""The watch's proxy questions through the real Elastic Gateway (Q-C2): the investigation lane
(400 ms of server time a minute, 6 minutes and 300 heavy requests a day, NORMAL health only), the
quiet hours and the kill switch, with a fake transport and a fake clock; and a simulated month."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import watchrun
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, D0, H1, World, at, context
from tests.unit.gateway.fakes import FakeClock

pytestmark = pytest.mark.integration

TOOK_MS = 150


class ProxyTransport:
    """Elasticsearch for the watch: the daily squid indices exist, and a contact search finds
    nothing (a quiet network) in ``took`` milliseconds of server time."""

    def __init__(self, clock: FakeClock, took: int = TOOK_MS) -> None:
        self.clock = clock
        self.took = took
        self.searches: list[dict[str, Any]] = []

    async def send(self, request: WireRequest) -> WireResponse:
        self.clock.advance(timedelta(milliseconds=self.took))
        if "_resolve" in request.path:
            names = [
                {"name": f"acme-logs-squid-{(D0 + timedelta(days=n)).strftime('%Y.%m.%d')}"}
                for n in range(-3, 80)
            ]
            return WireResponse(200, json.dumps({"indices": names}).encode(), 3.0)
        self.searches.append({"path": request.path, "at": self.clock.now, "took": self.took})
        body = {
            "took": self.took,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"hits": []},
            "aggregations": {
                "requests": {"value": 0},
                "host_count": {"value": 0},
                "hosts": {"buckets": [], "sum_other_doc_count": 0},
            },
        }
        return WireResponse(200, json.dumps(body).encode(), float(self.took))


class Lane400:
    """A real gateway on a fake clock with the investigation lane's default share."""

    def __init__(self, world: World) -> None:
        self.clock = FakeClock(at(0, 3))
        self.transport = ProxyTransport(self.clock)
        self.store = MemoryStore(memory=HealthMemory(probed_at=self.clock.now))
        self.state = HealthState.NORMAL

        async def sleep(seconds: float) -> None:
            await self.clock.sleep(seconds)
            self.probe()  # the collector probes every minute, whatever the gateway waits for

        self.gateway = Gateway(
            self.transport, self.store, targets=Targets(), clock=self.clock, sleep=sleep
        )
        self.asker = watchrun.GatewayAsker(
            self.gateway, world.runtime, enabled={"proxy.contact", "proxy.pair"},
            history=timedelta(days=5), is_campus=lambda v: v.startswith("10."),
        )  # fmt: skip
        self.ctx = context(self.asker)
        self.world = world

    def probe(self) -> None:
        self.store.memory = HealthMemory(
            state=self.state, probed_at=self.clock.now - timedelta(minutes=1)
        )

    def at(self, moment: datetime, state: HealthState = HealthState.NORMAL) -> None:
        """It is ``moment``; the collector probed a minute ago and found ``state``."""
        self.clock.now = moment
        self.state = state
        self.probe()

    async def run(self, moment: datetime, state: HealthState = HealthState.NORMAL) -> Any:
        self.at(moment, state)
        await self.world.readings(moment)
        await self.world.cursor(moment)
        return await watchrun.run(self.world.runtime, self.ctx, now=moment)


@pytest.fixture
def world(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> World:
    return World(migrated_engine, app_engine)


async def test_a_simulated_month_stays_inside_the_investigation_lane(
    world: World, people: dict[str, Person]
) -> None:
    lane = Lane400(world)
    asha = people["asha"]
    hosts = [f"10.8.0.{n}" for n in range(1, 6)]
    cases = []
    for n, host in enumerate(hosts):  # five cases, one C2 each
        inv = await world.investigation(host, [at(0, 9)], entities=(("ip", f"77.221.155.{n}"),))
        cases.append(await world.open_case(asha, [inv], [host], at(0, 10), c2=f"77.221.155.{n}"))
    many = await world.investigation(H1, [at(0, 9, 30)], entities=(("ip", C2),))
    big = await world.open_case(  # and one with eight addresses: a cap of ten, not six
        asha, [many], [H1], at(0, 10, 5), c2=[f"203.0.113.{n}" for n in range(1, 9)]
    )  # fmt: skip
    first_verified: dict[object, int] = {}
    for n in range(1, 31):
        await lane.run(at(n, 3))
        for case_id in (*cases, big):
            if (
                case_id not in first_verified
                and (await world.finder_window(lane.ctx, case_id, at(n, 4))).verified
            ):
                first_verified[case_id] = n

    ledger = [e for e in lane.store.ledger if e.template == "proxy.contact"]
    assert len(ledger) == len(lane.transport.searches)
    assert len(ledger) > 100
    # the lane, only the lane: purpose, component and lane of every request
    assert {(e.purpose, e.component, e.lane) for e in ledger} == {
        ("investigate", "investigation", Lane.INVESTIGATION.value)
    }
    # D-022's lane: 400 ms a minute on average (a bucket holds one minute: 10-minute windows
    # take at most 4,000 ms and the bucket), 6 minutes and 300 heavy requests a day
    spend = sorted((e.at, e.took_ms) for e in ledger)
    for start, _ in spend:
        window = sum(ms for t, ms in spend if start <= t < start + timedelta(minutes=10))
        assert window <= 4_000 + 400 + TOOK_MS, (start, window)
    by_day: dict[date, list[int]] = {}
    for moment, ms in spend:
        by_day.setdefault(moment.date(), []).append(ms)
    assert max(sum(v) for v in by_day.values()) <= 6 * 60 * 1000
    assert max(len(v) for v in by_day.values()) <= 300
    # each question is asked once: no content address twice, and no more than its cap a case a
    # day (6, or 8 for the big case)
    keys = [e.task_key for e in ledger]
    assert len(keys) == len(set(keys))
    async with world.owner.connect() as conn:
        per_day = (
            await conn.execute(
                text(
                    "SELECT case_id, asked_on, sum(requests) AS n FROM case_watch_checks"
                    " WHERE asked_on IS NOT NULL GROUP BY case_id, asked_on"
                )
            )
        ).all()
        asked_for = {r.case_id: r for r in per_day}
        big_days = [r.n for r in per_day if r.case_id == big]
        waiting = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM case_watch_checks WHERE case_id = :c AND"
                    " outcome = 'not_checked'"
                ),
                {"c": big},
            )
        ).scalar_one()
    assert max(r.n for r in per_day) == 8 == max(big_days)  # its cap is ten; eight are open a day
    assert all(r.n <= 1 for r in per_day if r.case_id in cases)  # one address, one day, one ask
    assert set(asked_for) == {*cases, big}
    # the big case's cap is its eight addresses and two spare (Q-C2 review R18): no question is
    # cut off, and a case watched from the start fills its three-day window as soon as the first
    # three days are answered, as the cases of one address do
    assert waiting == 0
    assert set(first_verified) == {*cases, big}
    assert max(first_verified.values()) <= 4  # D1 to D3 are answered by the run on D4
    # no case was asked about a day twice: (case, address, day) is unique in the answers
    async with world.owner.connect() as conn:
        assert (
            await conn.execute(
                text(
                    "SELECT count(*) FROM (SELECT 1 FROM case_watch_checks GROUP BY case_id,"
                    " day, source, subject, part HAVING count(*) > 1) x"
                )
            )
        ).scalar_one() == 0


@pytest.mark.parametrize(
    ("state", "words"),
    [
        (HealthState.CAUTION, "not in its normal state"),
        (HealthState.DEGRADED, "not in its normal state"),
        (HealthState.STOP, "not in its normal state"),
    ],
)
async def test_the_lane_asks_only_in_normal_health(
    state: HealthState, words: str, world: World, people: dict[str, Person]
) -> None:
    lane = Lane400(world)
    inv = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    report = await lane.run(at(2, 3), state)
    assert lane.transport.searches == []  # nothing reached the SIEM
    rows = await world.rows(case_id)
    assert {v for k, v in rows.items() if k[1] == "proxy.contact"} == {"not_checked"}
    notes = report.case(1).notes
    assert any("not checked" in n and words in n for n in notes), notes
    await lane.run(at(3, 3))  # healthy again: the open days are asked, newest first
    assert len(lane.transport.searches) >= 1
    rows = await world.rows(case_id)
    assert "not_checked" not in {v for k, v in rows.items() if k[1] == "proxy.contact"}


async def test_the_kill_switch_the_quiet_hours_and_the_lanes_budget_stop_the_questions(
    world: World, people: dict[str, Person]
) -> None:
    lane = Lane400(world)
    inv = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    lane.store.stopped.add("investigation")  # `argus siem stop --component investigation`
    stopped = await lane.run(at(2, 3))
    assert lane.transport.searches == []
    assert any("reads of the SIEM are stopped" in n for n in stopped.case(1).notes)
    lane.store.stopped.clear()
    quiet = await lane.run(at(3, 0) + timedelta(minutes=30))  # 00:30 UTC: index creation
    assert lane.transport.searches == []
    assert any("between 00:00 and 01:30 UTC" in n for n in quiet.case(1).notes)
    # the lane's day is spent: a search is charged its whole `took`
    lane.at(at(4, 3))
    spec = lane.store.lane_plan.spec(Lane.INVESTIGATION)
    lane.store.lanes = type(lane.store.lanes)(  # a bucket already used up for the day
        buckets={Lane.INVESTIGATION: _spent(lane, spec.per_day_ms, at(4, 3))},
        starts=lane.store.lanes.starts,
    )
    spent = await lane.run(at(4, 3))
    assert lane.transport.searches == []
    assert any("lane's budget for now is used up" in n for n in spent.case(1).notes)
    rows = await world.rows(case_id)
    assert {v for k, v in rows.items() if k[1] == "proxy.contact"} == {"not_checked"}
    lane.store.lanes = type(lane.store.lanes)()  # a new day, a new allowance
    fresh = await lane.run(at(5, 3))
    assert fresh.asked >= 1


def _spent(lane: Lane400, used_ms: int, now: datetime):  # type: ignore[no-untyped-def]
    from argus.gateway.budget import BudgetState

    return BudgetState(tokens_ms=400.0, refilled_at=now, day=now.date(), day_used_ms=used_ms)


def test_the_module_uses_utc_throughout() -> None:
    assert at(0).tzinfo is UTC
