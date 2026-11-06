"""Properties of the linker and the lifecycle (E2) over random worlds: caps hold, a hub never
joins anyone, every object is in one component at most, every link carries a short reason and
joins two members, the order of the observations never matters, and a second pass over the same
world changes nothing materially."""

from __future__ import annotations

import random
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.risk import incident_config, lifecycle, link
from argus.risk.link import Flag, World
from argus.risk.observe import ObjectRef, Observation
from argus.risk.score import Factors, Stats

from .conftest import NOW, obs

pytestmark = pytest.mark.unit
LINKING = incident_config.load()
THREATS = [f"domain:d{n}-example.net" for n in range(8)] + [f"ip:45.33.0.{n}" for n in range(4)]


def dev(n: int) -> ObjectRef:
    return ObjectRef("device", f"ip:10.4.0.{n + 1}")


world_rows = st.lists(
    st.tuples(
        st.integers(0, 39),  # device
        st.lists(st.sampled_from(THREATS), max_size=3, unique=True),
        st.floats(0, 24 * 9),  # hours ago
        st.sampled_from(["rule:L1", "rule:L2", "rule:NOISY"]),
    ),
    min_size=1, max_size=120,
)  # fmt: skip
STATS = Stats({("rule:NOISY", "actor"): Factors(prevalence=0.3)})


def rows_of(drawn: list[tuple[int, list[str], float, str]]) -> list[Observation]:
    return [obs(source, key=dev(d).key, hours_ago=h, threats=tuple(t))
            for d, t, h, source in drawn]  # fmt: skip


@given(
    drawn=world_rows,
    flagged=st.sets(st.sampled_from(THREATS), max_size=4),
    candidates=st.sets(st.integers(0, 39), max_size=40),
    hubs=st.sets(st.integers(0, 39), max_size=3),
    seed=st.integers(0, 1000),
)
def test_components_keep_their_promises(
    drawn: list[tuple[int, list[str], float, str]], flagged: set[str], candidates: set[int],
    hubs: set[int], seed: int,
) -> None:  # fmt: skip
    rows = rows_of(drawn)
    world = World({t: Flag("outside") for t in flagged},
                  hubs={dev(h): "asset role nat" for h in hubs})  # fmt: skip
    cands = {dev(c): ("burst",) for c in candidates}
    found = link.link_all(rows, NOW, cands, LINKING, STATS, world)
    seen: set[ObjectRef] = set()
    for c in found:
        assert not seen & set(c.objects)
        seen |= set(c.objects)
        assert c.size <= (LINKING.caps.campaign_objects if c.campaign else LINKING.caps.objects)
        assert any(o in c.lanes for o in c.objects)
        if len(c.objects) > 1:
            assert not {dev(h) for h in hubs} & set(c.objects)
        for lk in c.links:
            assert 1 <= len(lk.reason) <= 200
            assert lk.a in c.objects
            assert lk.b is None or lk.b in c.objects
            if lk.b is not None and lk.via != "campaign":
                assert lk.via in ("flagged", "rare", "bare_ip", "host", "account")
    shuffled = list(rows)
    random.Random(seed).shuffle(shuffled)
    again = link.link_all(shuffled, NOW, cands, LINKING, STATS, world)
    assert [c.objects for c in again] == [c.objects for c in found]


@given(drawn=world_rows, candidates=st.sets(st.integers(0, 39), min_size=1, max_size=40))
def test_a_noisy_source_alone_never_links(
    drawn: list[tuple[int, list[str], float, str]], candidates: set[int]
) -> None:
    rows = [o for o in rows_of(drawn) if o.source_key == "rule:NOISY"]
    world = World({t: Flag("outside") for t in THREATS})
    found = link.link_all(rows, NOW, {dev(c): ("burst",) for c in candidates}, LINKING, STATS,
                          world)  # fmt: skip
    assert all(len(c.objects) == 1 for c in found)


@given(drawn=world_rows, candidates=st.sets(st.integers(0, 39), min_size=1, max_size=40))
def test_a_second_pass_over_the_same_world_changes_nothing(
    drawn: list[tuple[int, list[str], float, str]], candidates: set[int]
) -> None:
    rows = rows_of(drawn)
    cands = {dev(c): ("burst",) for c in candidates}
    comps = link.link_all(rows, NOW, cands, LINKING, STATS, World())
    facts = lifecycle.facts_of(rows, NOW, lambda t: False)
    first = lifecycle.advance([], comps, facts, NOW, LINKING)
    for n, inc in enumerate(first.incidents):
        inc.id = n + 1
    later = NOW + timedelta(minutes=2)
    second = lifecycle.advance(first.incidents, comps, lifecycle.facts_of(rows, later,
                               lambda t: False), later, LINKING)  # fmt: skip
    assert not second.opened
    assert not second.requeued
    groups = [g for i in second.incidents if i.state != "merged" for g in i.groups]
    assert len(groups) == len(set(groups))  # an alert group is in one incident at most
