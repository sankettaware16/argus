"""Q-F3 gate: a busy week of waves and "Check more" inside the investigation lane.

The lane's 400 ms of SIEM time a minute, 6 minutes and 300 heavy requests a day hold however
many investigations come (up to 5,000 a day against the 1,450 of the busiest soak day); the
wave's own cap bounds the number of waves; a person's request is served before the engine's;
and the day's waves are the 75 to 150 the plan counts on (plan §7.3). The simulation drives the
real lane admission (``gateway.lanes.admit`` and ``settle``) on a virtual clock, with the
plan's caps per wave (4 requests, 2 heavy), heavy answers of 100 to 900 ms and a timeout (10 s,
charged whole) in 3 % of them. Q-F3's review added the wave's own deadline (``ASK_DEADLINE``,
150 s a request): a request the lane can take only later than that is not sent and not
timed out, the work is put back and the service leaves the lane alone until it frees up
(``Day.parked``); and a second profile of heavy answers, 1 to 10 s, which is what a busy proxy
index may take (the lane's 400 ms a minute is then in debt for minutes after one answer)."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from argus.gateway.budget import Verdict
from argus.gateway.lanes import DEFAULT_LANES, Lane, LanePlan, LaneStates, admit, settle
from argus.gateway.templates import CostClass
from argus.investigation.plan import Caps
from argus.investigation.wave import ASK_DEADLINE

pytestmark = pytest.mark.unit
PLAN = LanePlan()
LANE = Lane.INVESTIGATION
SPEC = DEFAULT_LANES[LANE]
DAY0 = datetime(2026, 10, 19, 0, 0, tzinfo=UTC)
TIMEOUT_MS = 10_000
PLANS_HEAVY = (100, 900)  # the answers the plan's 75 to 150 waves a day were counted with
SLOW_HEAVY = (1_000, 10_000)  # what a busy proxy index may take
CAPS = Caps()
WAVE_CAP = 120
START = timedelta(hours=1, minutes=30)  # after the quiet hours


@dataclass
class Day:
    waves: int = 0
    persons: int = 0
    persons_asked: int = 0
    heavy: int = 0
    requests: int = 0
    took_ms: int = 0
    person_waits: list[float] = field(default_factory=list)
    skipped: int = 0  # planned requests the lane could not take today
    parked: int = 0  # times the lane could take the next request only after the deadline
    longest_park: float = 0.0  # seconds the service left the lane alone to pay a debt


def a_request(
    rng: random.Random, heavy: bool, heavy_ms: tuple[int, int] = PLANS_HEAVY
) -> tuple[CostClass, int]:
    if heavy:
        return CostClass.HEAVY, TIMEOUT_MS if rng.random() < 0.03 else rng.randint(*heavy_ms)
    if rng.random() < 0.5:
        return CostClass.MEDIUM, rng.randint(30, 200)
    return CostClass.LIGHT, rng.randint(10, 60)


def a_wave(
    rng: random.Random, caps: Caps = CAPS, heavy_ms: tuple[int, int] = PLANS_HEAVY
) -> list[tuple[CostClass, int]]:
    n = rng.choice([1, 2, 2, 3, 3, 4])
    heavy_left = caps.heavy
    out = []
    for _ in range(min(n, caps.requests)):
        heavy = heavy_left > 0 and rng.random() < 0.55
        heavy_left -= heavy
        out.append(a_request(rng, heavy, heavy_ms))
    return out


def simulate(
    investigations: int,
    days: int = 7,
    seed: int = 1,
    persons: int = 25,
    share: float = 0.45,
    wave_cap: int = WAVE_CAP,
    heavy_ms: tuple[int, int] = PLANS_HEAVY,
) -> tuple[list[Day], int, list[tuple[datetime, int]]]:
    rng = random.Random(seed)
    states = LaneStates()
    out: list[Day] = []
    spent: list[tuple[datetime, int]] = []  # (when a request ended, its server time)
    biggest = 0
    lease = 0
    for d in range(days):
        day_start = DAY0 + timedelta(days=d)
        end = day_start + timedelta(days=1)
        span = 86_400 - START.total_seconds()
        engine_items = sorted(
            (day_start + START + timedelta(seconds=rng.uniform(0, span)), rng.random())
            for _ in range(int(investigations * share))
        )  # fmt: skip
        person_items = sorted(
            day_start + START + timedelta(seconds=rng.uniform(0, 86_400 - START.total_seconds()))
            for _ in range(persons)
        )
        today = Day()
        now = day_start + START
        engine_waiting: list[tuple[float, datetime]] = []  # (priority, arrival)
        person_waiting: list[datetime] = []
        parked: list[tuple[CostClass, int]] | None = None  # what is left of a put-back item
        e = p = 0
        done = False
        while not done and now < end:
            while e < len(engine_items) and engine_items[e][0] <= now:
                engine_waiting.append((engine_items[e][1], engine_items[e][0]))
                e += 1
            while p < len(person_items) and person_items[p] <= now:
                person_waiting.append(person_items[p])
                p += 1
            person = bool(person_waiting)
            if parked is not None:  # the lane has paid its debt: the item goes on where it left off
                request_list, parked = parked, None
            elif person:
                arrived = person_waiting.pop(0)
                today.person_waits.append((now - arrived).total_seconds())
                today.persons_asked += 1
                request_list = [a_request(rng, rng.random() < 0.6, heavy_ms)]
            elif engine_waiting and today.waves < wave_cap:
                engine_waiting.sort()
                engine_waiting.pop(0)
                today.waves += 1
                request_list = a_wave(rng, CAPS, heavy_ms)
            else:
                nxt = [
                    t
                    for t in (
                        engine_items[e][0]
                        if e < len(engine_items) and today.waves < wave_cap
                        else None,
                        person_items[p] if p < len(person_items) else None,
                    )
                    if t
                ]
                if not nxt:
                    break
                now = min(nxt)
                continue
            for index, (cost, took) in enumerate(request_list):
                while True:
                    lease += 1
                    admission, after = admit(states, PLAN, LANE, cost, now, scale=1.0,
                                             lease_id=f"s{lease}")  # fmt: skip
                    if admission.verdict is Verdict.ADMITTED:
                        states = after
                        break
                    if admission.verdict is Verdict.EXHAUSTED:
                        today.skipped += 1
                        done = True  # the day's allowance is spent: nothing more today
                        break
                    assert admission.retry_at is not None
                    if admission.retry_at - now >= ASK_DEADLINE:
                        # the gateway would refuse at once ("frees up too late"): the wave is
                        # put back, nothing is sent or timed out, and the service leaves the
                        # lane alone until the debt is paid (Q-F3 review R1)
                        parked = request_list[index:]
                        today.parked += 1
                        today.longest_park = max(
                            today.longest_park, (admission.retry_at - now).total_seconds()
                        )
                        now = admission.retry_at
                        break
                    now = max(admission.retry_at, now + timedelta(milliseconds=1))
                    if now >= end:
                        done = True
                        break
                if done or parked is not None:
                    break
                assert admission.lease is not None
                now += timedelta(milliseconds=took)
                states = settle(states, PLAN, LANE, admission.lease, took, now, scale=1.0)
                today.requests += 1
                today.heavy += cost is CostClass.HEAVY
                today.took_ms += took
                biggest = max(biggest, took)
                spent.append((now, took))
        out.append(today)
    return out, biggest, spent


@pytest.mark.parametrize("investigations", [200, 1_450, 5_000])
def test_a_busy_week_stays_inside_the_lane(investigations: int) -> None:
    days, biggest, spent = simulate(investigations)
    for day in days:
        # the lane's own day: 6 minutes of server time, 300 heavy requests (a request in
        # flight when the allowance runs out may end past it by its own time)
        assert day.took_ms <= SPEC.per_day_ms + biggest
        assert day.heavy <= SPEC.heavy_per_day
        assert day.waves <= WAVE_CAP
    # the lane's minute: in any window of an hour the lane spends no more than its refill plus
    # one burst plus the request that was in flight
    times = [t for t, _ in spent]
    for i, (_, _) in enumerate(spent):
        j = i
        total = 0
        while j < len(spent) and spent[j][0] - times[i] <= timedelta(hours=1):
            total += spent[j][1]
            j += 1
        assert total <= SPEC.per_minute_ms * 60 + SPEC.per_minute_ms + biggest


def test_the_plans_coverage_holds_under_the_busiest_days_load() -> None:
    """1,450 investigations a day, 45 % of them undecided with a closable gap: the lane fits
    the 75 to 150 waves a day the plan counts on, with "Check more" sharing it."""
    days, _, _ = simulate(1_450)
    waves = [d.waves for d in days]
    assert all(75 <= w <= 150 for w in waves), waves
    assert max(d.heavy for d in days) <= 300
    assert all(d.persons_asked >= 0.9 * 25 for d in days)


def test_a_persons_request_is_served_before_the_engines() -> None:
    days, _, _ = simulate(1_450, persons=40)
    waits = sorted(w for d in days for w in d.person_waits)
    assert waits
    served = sum(d.persons_asked for d in days)
    assert served >= 0.9 * 40 * len(days)
    assert waits[int(0.95 * (len(waits) - 1))] < 30 * 60  # 95 % wait under half an hour


def test_the_week_is_the_same_every_time() -> None:
    assert [d.waves for d in simulate(1_450, seed=7)[0]] == [
        d.waves for d in simulate(1_450, seed=7)[0]
    ]


def test_more_investigations_cost_the_lane_nothing_more() -> None:
    quiet, _, _ = simulate(1_450)
    flood, _, _ = simulate(5_000)
    assert max(d.heavy for d in flood) <= max(d.heavy for d in quiet) + 15
    assert max(d.took_ms for d in flood) <= SPEC.per_day_ms + TIMEOUT_MS


def test_without_the_waves_own_cap_the_lanes_day_is_what_binds() -> None:
    """Were the waves not capped, the lane itself stops them: 300 heavy requests a day, a
    refused request is skipped, nothing is sent past the allowance."""
    days, biggest, _ = simulate(1_450, wave_cap=10_000)
    for day in days:
        assert day.heavy <= SPEC.heavy_per_day
        assert day.took_ms <= SPEC.per_day_ms + biggest
        assert day.skipped >= 1  # the allowance ran out before the work did
    assert max(d.heavy for d in days) >= 280  # and it is the heavy allowance that ran out


def test_a_lane_in_debt_parks_the_wave_it_never_times_it_out() -> None:
    """Q-F3 review R1. A timeout charged whole (10 s) puts the lane in debt for many minutes;
    the gateway refuses the next request at once when the lane frees up after the wave's own
    150 s. The wave is put back and the service waits for the lane: the simulation parks the
    rest of the item (nothing is dropped, nothing is sent early) and goes on at the time the
    lane gave."""
    days, biggest, _ = simulate(1_450)
    assert sum(d.parked for d in days) > 0  # the plan's own 3 % of timeouts do it
    for day in days:
        assert day.longest_park >= ASK_DEADLINE.total_seconds()
        assert day.took_ms <= SPEC.per_day_ms + biggest
        assert day.heavy <= SPEC.heavy_per_day
    # parking changes when work runs, not how much: the plan's numbers are what they were
    assert [d.waves for d in days] == [120] * 7


def test_slow_heavy_answers_keep_the_lane_inside_its_limits_and_cut_the_waves() -> None:
    """Q-F3 review R1 asked for realistic answer times: heavy answers of 1 to 10 s (a busy
    proxy index) instead of the plan's 100 to 900 ms. The lane's limits hold all the same; what
    changes is coverage. The lane's 6 minutes a day buy about 35 to 55 waves, not the 75 to 150
    the plan counts on, and a person's request waits longer (recorded in the gate report)."""
    days, biggest, _ = simulate(1_450, heavy_ms=SLOW_HEAVY)
    for day in days:
        assert day.took_ms <= SPEC.per_day_ms + biggest
        assert day.heavy <= SPEC.heavy_per_day
        assert day.parked > 0
    assert all(20 <= d.waves <= 75 for d in days), [d.waves for d in days]
    assert sum(d.persons_asked for d in days) >= 0.5 * 25 * len(days)
    waits = sorted(w for d in days for w in d.person_waits)
    assert waits[int(0.95 * (len(waits) - 1))] < 90 * 60  # a person still waits under 90 minutes


def test_a_persons_request_is_not_parked_behind_the_engines_debt_for_a_day() -> None:
    days, _, _ = simulate(1_450, persons=40, heavy_ms=SLOW_HEAVY)
    assert max(d.longest_park for d in days) < 3_600  # the longest debt is under an hour
