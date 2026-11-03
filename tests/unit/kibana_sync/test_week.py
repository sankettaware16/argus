"""The busy-week simulation (plan §5 Q-D3's gate, **before** the live read), the read model
and the lag, on the fake Kibana through the real Kibana lane and its budget:

- a week of 10-minute cycles over 120 ARGUS cases while people comment, close, reopen,
  retag and delete, with a 4-hour Kibana outage on day 3: every change found once, ≥ 99 % of
  the cycles outside the outage complete, no staleness breach after it, only reads, and the
  Kibana read lane never over its day (§7.8: 4 minutes);
- the lag of people's changes (n ≥ 20): within one poll interval and the cycle's own time;
- §7.1's read model at the plan's, the exit's and a year's case counts fits the lane.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.gateway.lanes import Lane
from argus.kibana_sync import readmodel
from argus.kibana_sync.model import Kind
from tests.unit.kibana_sync.fake import CREATE, rig

PEOPLE = ("ra-anita", "ta-ravi", "ra-meera")


async def test_a_busy_week_inside_the_lane() -> None:
    rng = random.Random(20261026)
    r = rig()
    cases = []
    for _ in range(120):
        case = uuid.uuid4()
        r.sent(case, CREATE)
        cases.append(r.kibana.create(argus_case=case))
    expected: dict[Kind, int] = {}

    def expect(kind: Kind) -> None:
        expected[kind] = expected.get(kind, 0) + 1

    outage = range(3 * 144 + 60, 3 * 144 + 84)  # day 3, 4 hours
    records = []
    lane_day: dict[object, int] = {}
    for n in range(7 * 144):
        live = [c for c in cases if c in r.kibana.cases]
        for _ in range(rng.choice((0, 0, 1, 1, 2, 3))):  # about 180 changes a day
            kid = rng.choice(live)
            who = rng.choice(PEOPLE)
            roll = rng.random()
            status = r.kibana.cases[kid]["status"]
            if roll < 0.5:
                r.kibana.comment(kid, who, f"note {n}")
                expect(Kind.PERSON_COMMENTED)
            elif roll < 0.65:
                new = "open" if status == "closed" else "closed"
                r.kibana.set_status(kid, who, new)
                expect(Kind.CLOSED_IN_KIBANA if new == "closed" else Kind.REOPENED_IN_KIBANA)
            elif roll < 0.8:
                r.kibana.add_tags(kid, who, f"tag-{n}")
                expect(Kind.PERSON_EDITED)
            elif roll < 0.97:
                r.kibana.set_field(kid, who, "severity", rng.choice(("low", "high")))
                expect(Kind.PERSON_EDITED)
            elif len(live) > 100:
                r.kibana.delete(kid)
                expect(Kind.DELETED_IN_KIBANA)
        r.kibana.down = n in outage
        record = await r.cycle()
        records.append((n, record))
        bucket = r.lane.lanes.bucket(Lane.KIBANA_READ)
        if bucket.day is not None:
            lane_day[bucket.day] = max(lane_day.get(bucket.day, 0), bucket.day_used_ms)
    # every change found once (each finding has its own key)
    found: dict[Kind, int] = {}
    for _, f in r.store.findings.values():
        found[f.kind] = found.get(f.kind, 0) + 1
    assert found == expected
    outside = [rec for n, rec in records if n not in outage and n - 1 not in outage]
    complete = sum(rec.outcome == "complete" for rec in outside)
    assert complete / len(outside) >= 0.99, (complete, len(outside))
    after = [rec for n, rec in records if n > max(outage) + 3]
    assert not any(rec.stale for rec in after)
    assert all(w.method == "GET" for w in r.kibana.requests)
    assert lane_day
    assert max(lane_day.values()) <= 4 * 60 * 1000, lane_day
    reads_a_day = len(r.kibana.requests) / 7
    assert reads_a_day < 1_500, reads_a_day
    print(
        f"week: {sum(expected.values())} changes, {len(records)} cycles,"
        f" {complete}/{len(outside)} complete outside the outage,"
        f" {reads_a_day:.0f} Kibana reads a day, {len(r.kibana.es_requests) / 7:.0f} searches"
        f" a day, the read lane's busiest day {max(lane_day.values()) / 1000:.0f} s"
    )


async def test_the_lag_of_peoples_changes_is_within_a_poll() -> None:
    """n = 40 changes at random moments: each found by the next cycle (lag ≤ the interval
    plus the cycle's own reads)."""
    rng = random.Random(7)
    r = rig()
    case = uuid.uuid4()
    r.sent(case, CREATE)
    kid = r.kibana.create(argus_case=case)
    await r.cycle()
    for i in range(40):
        r.clock.now += timedelta(seconds=rng.randint(0, 599))
        r.kibana.comment(kid, "ra-anita", f"change {i}")
        await r.cycle(advance=timedelta(seconds=600))
    lags = sorted(f.lag_s or 0 for _, f in r.store.findings.values())
    assert len(lags) == 40
    assert max(lags) <= 600 + 120, lags[-5:]


def test_the_read_model_fits_the_lane_at_projected_counts() -> None:
    for name, load in readmodel.SCENARIOS.items():
        e = readmodel.estimate(load)
        assert e.fits, name
        assert e.reads_per_day == sum(e.parts.values())
    plan = readmodel.estimate(readmodel.SCENARIOS["plan §7.1 (100 cases, 50 writes)"])
    assert plan.parts["change polls"] == 144
    assert plan.parts["listings"] == 289  # open + in-progress each cycle, closed once a day
    too_many = readmodel.estimate(readmodel.Load(4_000, 4_000, 20_000, 2_000, 500))
    assert not too_many.fits, "the model says when the lane must grow"


OPS = st.lists(
    st.tuples(
        st.sampled_from(
            [
                "comment",
                "tag",
                "argus_tag",
                "severity",
                "status",
                "delete",
                "cycle",
                "crash",
                "down",
                "up",
            ]
        ),
        st.integers(0, 3),
    ),
    max_size=30,
)


@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(OPS)
async def test_any_interleaving_of_peoples_changes_and_cycles_finds_each_once(
    ops: list[tuple[str, int]],
) -> None:
    """People's changes, cycles, crashes mid-cycle and Kibana outages in any order: once
    Kibana answers again, every change of a live case is found exactly once and nothing else
    is; a deleted case is found deleted once (Kibana deletes its user actions with it, so
    changes made after its last read can only be missing, never invented)."""
    r = rig()
    cases = []
    for _ in range(4):
        case = uuid.uuid4()
        r.sent(case, CREATE)
        cases.append(r.kibana.create(argus_case=case))
    await r.cycle()
    expected: dict[str, list[Kind]] = {kid: [] for kid in cases}
    for op, n in ops:
        kid = cases[n]
        alive = kid in r.kibana.cases
        if op == "cycle":
            await r.cycle()
        elif op == "crash":
            r.store.crash_after = n
        elif op in ("down", "up"):
            r.kibana.down = op == "down"
        elif not alive:
            continue
        elif op == "comment":
            r.kibana.comment(kid, "ra", "x")
            expected[kid].append(Kind.PERSON_COMMENTED)
        elif op == "tag":
            r.kibana.add_tags(kid, "ra", f"t{len(expected[kid])}")
            expected[kid].append(Kind.PERSON_EDITED)
        elif op == "argus_tag":
            r.kibana.add_tags(kid, "ra", "argus:owner:ra")
            expected[kid].append(Kind.ARGUS_TAGS_CHANGED)
        elif op == "severity":
            r.kibana.set_field(kid, "ra", "severity", "high")
            expected[kid].append(Kind.PERSON_EDITED)
        elif op == "status":
            closed = r.kibana.cases[kid]["status"] == "closed"
            r.kibana.set_status(kid, "ra", "open" if closed else "closed")
            expected[kid].append(Kind.REOPENED_IN_KIBANA if closed else Kind.CLOSED_IN_KIBANA)
        elif op == "delete":
            r.kibana.delete(kid)
    r.kibana.down = False
    r.store.crash_after = None
    for _ in range(4):
        await r.cycle(advance=timedelta(days=1, minutes=1))  # the closed listing too
    found: dict[str, list[Kind]] = {kid: [] for kid in cases}
    for _, f in r.store.findings.values():
        assert f.kibana_case_id in found, f
        if f.kind is Kind.ANSWER_UNEXPECTED:  # a crash is a case the store could not keep
            assert f.dedupe_key.startswith("case-failed:"), f
            continue
        found[f.kibana_case_id].append(f.kind)
    for kid in cases:
        if kid in r.kibana.cases:
            assert sorted(found[kid]) == sorted(expected[kid]), kid
        else:
            assert found[kid].count(Kind.DELETED_IN_KIBANA) == 1
            rest = [k for k in found[kid] if k is not Kind.DELETED_IN_KIBANA]
            for kind in set(rest):
                assert rest.count(kind) <= expected[kid].count(kind)
