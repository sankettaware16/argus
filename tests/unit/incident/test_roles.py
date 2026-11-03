"""An actor's role is told from counts and order in time (AR7, D-190), compared in **one unit**
(D-201 point 12): requests when every outside actor has a request count from a web check, else
alerts; the words say which. "A campus device that reached the case's servers" is said only of a
device that did."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.incident import gather as g
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def without_checks(facts: g.CaseFacts, *actors: str) -> g.CaseFacts:
    """The web check of each of these actors is gone: their request count is not known."""
    keep = tuple(r for r in facts.evidence if r.params.get("ip") not in actors)
    return replace(facts, evidence=keep)


def roles(facts: g.CaseFacts) -> dict[str, str]:
    return {a.value: a.role for a in build(facts, kit.ctx()).actors}


def words(facts: g.CaseFacts) -> dict[str, str]:
    return {a.value: a.role_words for a in build(facts, kit.ctx()).actors}


def test_with_a_request_count_for_every_actor_the_roles_compare_requests() -> None:
    facts = kit.git()
    assert roles(facts) == {kit.SCOUT: "scout", kit.COLLECTOR: "collector", kit.PROBER: "prober"}
    said = words(facts)
    assert said[kit.COLLECTOR].startswith("Made the most requests of any actor")
    assert "14,683" in said[kit.COLLECTOR]
    assert "with few requests" in said[kit.SCOUT]
    assert "with few requests" in said[kit.PROBER]


def test_a_missing_request_count_moves_every_actor_to_alerts_never_a_mix() -> None:
    """The review's probe: the collector has 14,683 requests, the other two only alert counts.
    Compared across units that makes it a collector; in alerts (3, 16, 4) nobody dominates."""
    facts = kit.git(volumes=(400, 14_683, 2_000))
    with_all = roles(facts)
    assert with_all[kit.COLLECTOR] == "collector"
    mixed = without_checks(facts, kit.SCOUT, kit.PROBER)
    got = roles(mixed)
    assert set(got.values()) == {"actor"}, got
    assert "requests" not in " ".join(words(mixed).values())


def test_alert_counts_are_the_unit_when_none_has_a_request_count() -> None:
    facts = without_checks(kit.git(), kit.SCOUT, kit.COLLECTOR, kit.PROBER)
    got = roles(facts)
    assert got[kit.COLLECTOR] == "collector"  # 16 alerts against 3
    said = words(facts)
    assert said[kit.COLLECTOR].startswith("Raised the most alerts of any actor")
    assert "requests" not in said[kit.COLLECTOR]
    assert "with few alerts" in said[kit.SCOUT]
    assert "with few alerts" in said[kit.PROBER]


def test_the_listing_is_ordered_in_the_same_unit() -> None:
    facts = without_checks(kit.git(volumes=(400, 14_683, 2_000)), kit.SCOUT)
    actors = build(facts, kit.ctx()).actors
    alerts = [a.alerts for a in actors]
    assert alerts == sorted(alerts, reverse=True)


def test_only_a_device_that_reached_the_servers_is_said_to_have() -> None:
    facts = kit.amadey()
    other = "10.55.0.9"
    lone = kit.inv_id(99)
    member = g.MemberRow(
        lone, "Other rule", "rule-other", "low", 3, kit.at(1, 1), kit.at(1, 2), 1, "actor", None,
        (), (),
    )  # fmt: skip
    facts = replace(
        facts,
        members=(*facts.members, member),
        members_total=6,
        entities=(*facts.entities, g.EntityRow(lone, "ip", other)),
        indicators=(*facts.indicators, g.IndicatorRow("ip", other, "actor", "investigation")),
        indicators_total=len(facts.indicators) + 1,
    )
    said = words(facts)
    assert said[kit.HOST] == "A campus device that reached the case's servers."
    assert said[other] == "A campus device named in the alerts."


def test_a_case_with_no_servers_never_says_a_device_reached_them() -> None:
    facts = kit.synthetic(members=3, alerts_each=5, hosts=4, servers=0, counts=[1])
    assert facts.indicators
    said = words(facts)
    assert said
    assert all("reached" not in w for w in said.values())


@settings(max_examples=120, deadline=None)
@given(
    volumes=st.tuples(st.integers(1, 40_000), st.integers(1, 40_000), st.integers(1, 40_000)),
    missing=st.sets(st.sampled_from([kit.SCOUT, kit.COLLECTOR, kit.PROBER])),
)
def test_the_unit_is_one_for_every_actor_and_the_words_match_it(
    volumes: tuple[int, int, int], missing: set[str]
) -> None:
    facts = without_checks(kit.git(volumes=volumes), *missing)
    report = build(facts, kit.ctx())
    outside = [a for a in report.actors if not a.inside]
    by_requests = all(a.requests is not None for a in outside)
    assert by_requests is (not missing)
    for a in outside:
        if a.role in ("collector", "scout", "prober"):
            assert ("requests" in a.role_words) is by_requests, a.role_words
            assert ("alerts" in a.role_words) is (not by_requests), a.role_words
