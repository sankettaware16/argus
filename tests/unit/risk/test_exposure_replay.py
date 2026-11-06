"""E3 in the replay: the oracle's answers of the checking lane become an alert group's facts from
when the lane would have answered, a site that enters L5 through an outside address that put
another site there is folded into it, and the lane's lookups are one an hour of at most 50."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest

from argus.risk import exposure, replay
from argus.risk import observe as ob
from argus.risk.observe import ObjectRef
from argus.risk.score import Stats, Verdict, evaluate
from tests.unit.risk.conftest import CONFIG, NOW, context, group, meta

pytestmark = pytest.mark.unit
TAKER, SCOUT = "45.138.13.9", "45.138.12.7"
A, B = "a.example.edu", "b.example.edu"


def test_the_oracles_answers_are_facts_of_their_source_and_day() -> None:
    oracle = replay.oracle_facts(
        [{"source": TAKER, "site": A.upper(), "day": NOW.date().isoformat(), "bulk": 40,
          "at": (NOW + timedelta(hours=1)).isoformat()},
         {"source": TAKER, "day": "2026-10-20"}],  # no site: left out
        CONFIG,
    )  # fmt: skip
    assert list(oracle) == [(TAKER, NOW.date())]
    g = replace(group(actor=TAKER, severity="high"), sites=(A, B))
    found, at = replay._oracle(g, [TAKER], oracle, CONFIG)
    assert found.sites == (A,)
    assert found.signals["exposure.bulk_take"] == 40
    assert at == NOW + timedelta(hours=1)
    other = replace(g, last_at=NOW + timedelta(days=2))
    assert replay._oracle(other, [TAKER], oracle, CONFIG) == (other, None)


def test_a_fact_is_seen_when_the_lane_would_have_answered() -> None:
    g = replace(group(actor=TAKER, severity="high", signals={"exposure.served": 1}), sites=(A,))
    seen = ob.observe(g, meta(family="nginx"), context())
    later = NOW + timedelta(hours=2)
    timed = {o.source_key: replay._checked(o, later) for o in seen.observations}
    assert timed["ev:served"].seen_at == later
    assert timed[next(k for k in timed if k.startswith("rule:"))].seen_at is None
    assert replay._checked(seen.observations[0], None) is seen.observations[0]


def _l5(site: str, source: str, loaded: replay.Loaded) -> tuple[ObjectRef, Verdict]:
    gid = uuid.uuid4()
    g = replace(group(actor=source, severity="high", signals={"exposure.bulk_take": 30},
                      gid=gid), sites=(site,))  # fmt: skip
    seen = ob.observe(g, meta(family="nginx"), context())
    ref = seen.objects[0]
    v = evaluate(list(seen.observations), NOW, CONFIG, Stats(), role="target", ref=ref)
    v = exposure.lanes({ref: v}, CONFIG.exposure)[ref]
    loaded.groups[gid] = replay.GroupMeta(
        gid, g.first_at, g.last_at, g.last_at, g.day, 1, "high", "inbound", 1.0, None, (), (),
        (), (ref,), g.first_at, (source,),
    )  # fmt: skip
    return ref, v


def test_a_second_site_taken_by_the_same_outside_address_is_one_item() -> None:
    """The rescore and the replay fold alike (``exposure.folded``)."""
    loaded = replay.Loaded()
    ref_a, v_a = _l5(A, TAKER, loaded)
    ref_b, v_b = _l5(B, TAKER, loaded)
    ref_c, v_c = _l5("c.example.edu", SCOUT, loaded)
    verdicts = {ref_a: v_a, ref_b: v_b, ref_c: v_c}
    sources_of = {gid: meta.sources for gid, meta in loaded.groups.items()}
    ex = CONFIG.exposure
    assert exposure.lane_sources(v_a, sources_of, ex) == {TAKER}
    assert exposure.folded([ref_a, ref_b, ref_c], [], verdicts, sources_of, ex) == {ref_b}
    assert exposure.folded([ref_b], [ref_a], verdicts, sources_of, ex) == {ref_b}  # A held
    assert exposure.folded([ref_b, ref_c], [], verdicts, sources_of, ex) == set()  # A is gone
    below = replace(v_a, lanes=())
    assert exposure.folded([ref_b], [ref_a], {**verdicts, ref_a: below}, sources_of, ex) == set()


def test_one_lookup_an_hour_of_at_most_fifty_outside_the_quiet_hours() -> None:
    day = date(2026, 10, 20)
    early = datetime(2026, 10, 20, 0, 10, tzinfo=UTC)  # in the quiet hours
    waiting = {f"45.138.14.{i}": early for i in range(120)}
    waiting["45.138.15.1"] = datetime(2026, 10, 20, 22, 30, tzinfo=UTC)
    assert replay._lookups(waiting, day) == (4, 0)  # 50 at 01:59, 50, 20, then 1 at 22:59
    late = {"45.138.15.2": datetime(2026, 10, 20, 23, 59, 30, tzinfo=UTC)}
    assert replay._lookups(late, day) == (0, 1)
