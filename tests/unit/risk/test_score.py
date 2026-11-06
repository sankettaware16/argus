"""E1 steps 2 to 5: scores, windows, prevalence, stages, persistence, lanes and the digest."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta

import pytest

from argus.risk import score
from argus.risk.config import STAGES
from argus.risk.observe import ObjectRef
from argus.risk.score import Factors, Stats
from tests.unit.risk.conftest import CONFIG, NOW, obs

pytestmark = pytest.mark.unit
FOOTHOLD, ACTIONS, ACCESS = (1 << STAGES.index(s) for s in ("foothold", "actions", "access"))
DEVICE = ObjectRef("device", "ip:10.1.1.1")


def verdict(
    items: list[score.Observation], stats: Stats | None = None, **more: object
) -> score.Verdict:
    return score.evaluate(items, NOW, CONFIG, stats or Stats(), ref=DEVICE, **more)  # type: ignore[arg-type]


def test_prevalence_is_one_up_to_k_objects_a_day_and_falls_after() -> None:
    assert score.prevalence(0, 10) == 1.0
    assert score.prevalence(10, 10) == 1.0
    assert score.prevalence(100, 10) == pytest.approx(0.5)
    assert score.prevalence(340, 10) == pytest.approx(1 / (1 + 1.531), rel=1e-3)  # about 0.4


def test_factors_count_distinct_objects_a_day_and_put_a_new_rule_on_probation() -> None:
    items = [obs("rule:noisy", key=f"ip:10.0.{n}.1", hours_ago=24 * d) for d in range(3)
             for n in range(100)]  # fmt: skip
    items += [obs("rule:quiet", hours_ago=2), obs("rule:quiet", hours_ago=3)]
    found = score.factors(items, NOW, CONFIG, {"rule:quiet": NOW - timedelta(days=2)})
    assert found[("rule:noisy", "actor")].prevalence == pytest.approx(0.5)
    assert found[("rule:noisy", "actor")].reach == 100
    quiet = found[("rule:quiet", "actor")]
    assert (quiet.prevalence, quiet.probation, quiet.reach) == (CONFIG.probation.factor, True, 1)


def test_each_source_counts_once_per_window_at_its_best() -> None:
    w = score.window_score([obs(hours_ago=10), obs(hours_ago=1), obs(hours_ago=20)], NOW, "24h",
                           CONFIG, Stats())  # fmt: skip
    assert w.sources == 1
    assert w.score == pytest.approx(20 * 0.5 ** (1 / 24))


def test_old_and_future_observations_are_outside_the_window() -> None:
    assert score.window_score([obs(hours_ago=25)], NOW, "24h", CONFIG, Stats()).sources == 0
    assert score.window_score([obs(hours_ago=-1)], NOW, "7d", CONFIG, Stats()).sources == 0
    assert score.window_score([obs(hours_ago=25)], NOW, "7d", CONFIG, Stats()).sources == 1


def test_a_second_family_multiplies_the_score() -> None:
    one = score.window_score([obs("rule:a", family="squid"), obs("rule:b", family="squid")],
                             NOW, "24h", CONFIG, Stats())  # fmt: skip
    two = score.window_score([obs("rule:a", family="squid"), obs("rule:b", family="dns")],
                             NOW, "24h", CONFIG, Stats())  # fmt: skip
    assert two.score == pytest.approx(one.score * 1.5)
    assert two.families == ("dns", "squid")


def test_stages_are_a_maximum_matching_so_one_rule_is_one_stage() -> None:
    assert score.matching([FOOTHOLD | ACTIONS]) == 1
    assert score.matching([FOOTHOLD | ACTIONS, FOOTHOLD]) == 2
    assert score.matching([FOOTHOLD, FOOTHOLD, FOOTHOLD]) == 1
    assert score.matching([ACCESS | FOOTHOLD, FOOTHOLD | ACTIONS, ACCESS]) == 3
    assert score.matching([]) == 0
    assert score.matching([15] * 9) == 4


def test_a_rule_and_the_facts_of_its_own_alerts_are_one_stage_not_two() -> None:
    """The beacon rule (C2 and Exfiltration) with the beacon fact of its own group is one step;
    the same fact from another rule's group is a second source and may be a second stage."""
    g = uuid.uuid4()
    beacon_rule = obs("rule:beacon", stages=FOOTHOLD | ACTIONS, gid=g)
    own = [beacon_rule, obs("ev:beacon", stages=FOOTHOLD, gid=g)]
    w = score.window_scores(own, NOW, CONFIG, Stats())["7d"]
    assert (w.stages, w.rule_sources, w.stage_mask) == (1, 1, FOOTHOLD | ACTIONS)
    # on two days, with persistence on its rare destination too: still one stage
    days = []
    for n in range(3):
        d = uuid.uuid4()
        days += [obs("rule:beacon", stages=FOOTHOLD | ACTIONS, gid=d, hours_ago=1 + 24 * n,
                     threats=("ip:45.138.12.9",)),
                 obs("ev:beacon", stages=FOOTHOLD, gid=d, hours_ago=1 + 24 * n)]  # fmt: skip
    stats = Stats(reach={"ip:45.138.12.9": 1})
    v = score.evaluate(days, NOW, CONFIG, stats, ref=DEVICE)
    assert v.window("7d").stages == 1
    assert "ev:persistence" in {c.source for c in v.window("7d").contributions}
    # a fact outside the rule's own stages is a second stage
    access = obs("ev:success", stages=ACCESS, gid=g)
    assert score.window_scores([*own, access], NOW, CONFIG, Stats())["7d"].stages == 2
    # the beacon fact of another rule's group (a rule with no tactics) is a source of its own
    other = uuid.uuid4()
    apart = [beacon_rule, obs("rule:plain", gid=other), obs("ev:beacon", stages=FOOTHOLD,
                                                            gid=other)]  # fmt: skip
    assert score.window_scores(apart, NOW, CONFIG, Stats())["7d"].stages == 2


def test_persistence_needs_a_rare_destination_on_several_days() -> None:
    items = [obs(threats=("ip:45.138.12.9",), hours_ago=24 * d + 1) for d in range(3)]
    rare = score.persistence(items, NOW, CONFIG, {"ip:45.138.12.9": 2})
    assert [(p.source_key, p.base, p.evidence) for p in rare] == [
        ("ev:persistence", CONFIG.persistence.base, ("3 days",))
    ]
    assert score.persistence(items, NOW, CONFIG, {"ip:45.138.12.9": 40}) == []
    assert score.persistence(items[:2], NOW, CONFIG, {"ip:45.138.12.9": 2}) == []


def test_reach_counts_campus_objects_acting_outward() -> None:
    items = [obs(threats=("ip:x",), key=f"ip:10.0.0.{n}") for n in range(3)]
    items.append(obs(threats=("ip:x",), key="ip:131.21.124.9", role="target", kind="site"))
    assert score.reach(items, NOW, 7) == {"ip:x": 3}


def test_a_critical_rule_is_decisive_alone() -> None:
    v = verdict([obs("rule:crit", base=60)])
    assert v.lanes == ("decisive",)
    assert v.held == "lane"


def test_a_strong_fact_with_another_source_is_decisive_and_alone_is_gray() -> None:
    assert verdict([obs("ev:outside", base=50, strong=True), obs("rule:a", base=10)]).lanes[0] == (
        "decisive"
    )
    alone = verdict([obs("ev:outside", base=50, strong=True)])
    assert alone.lanes == ()
    assert "decisive" in alone.gray
    assert alone.held == "gray_band"


def test_a_burst_needs_a_rule_another_source_and_an_anchor() -> None:
    anchored = verdict([obs("rule:a", base=30), obs("ev:beacon", base=15)])
    assert anchored.lanes == ("burst",)
    rules_only = verdict([obs("rule:a", base=30), obs("rule:b", base=15)])
    assert rules_only.lanes == ()
    assert rules_only.held == "rules_only"
    verdicted = verdict([obs("rule:a", base=30), obs("rule:b", base=15)],
                        Stats(verdicts=frozenset({DEVICE})))  # fmt: skip
    assert verdicted.lanes == ("burst",)


def test_slow_needs_days_and_two_families_stages_or_a_strong_source() -> None:
    days = [obs("rule:a", base=25, hours_ago=30, family="squid", stages=FOOTHOLD),
            obs("ev:beacon", base=15, hours_ago=80, stages=FOOTHOLD),
            obs("rule:b", base=25, hours_ago=2, family="squid", stages=FOOTHOLD)]  # fmt: skip
    assert "slow" not in verdict(days).lanes  # one family, one stage
    days[2] = replace(days[2], family="dns")
    assert "slow" in verdict(days).lanes


def test_the_gray_band_needs_an_anchor_as_the_lanes_do() -> None:
    """Rule hits alone just under the burst lane are rules only, never a candidate to present;
    the same with an evidence fact or a person's verdict is the gray band."""
    rules = [obs("rule:a", base=20), obs("rule:b", base=10)]
    bare = verdict(rules)
    assert (bare.lanes, bare.gray, bare.held) == ((), (), "rules_only")
    verdicted = verdict(rules, Stats(verdicts=frozenset({DEVICE})))
    assert (verdicted.lanes, verdicted.gray, verdicted.held) == ((), ("burst",), "gray_band")
    fact = verdict([obs("rule:a", base=20), obs("ev:rare_dest", base=10)])
    assert (fact.lanes, fact.gray, fact.held) == ((), ("burst",), "gray_band")
    slow = [obs("rule:a", base=25, hours_ago=30, family="squid"),
            obs("rule:b", base=20, hours_ago=80, family="dns")]  # fmt: skip
    assert verdict(slow).window("7d").score < CONFIG.lanes.slow.score
    assert (verdict(slow).gray, verdict(slow).held) == ((), "rules_only")


def test_a_rule_on_probation_adds_weight_but_no_lane_may_need_it() -> None:
    items = [obs("rule:new", base=30), obs("ev:beacon", base=15)]
    stats = Stats({("rule:new", "actor"): Factors(1.0, 1.0, True, 2)})
    held = verdict(items, stats)
    assert held.lanes == ()
    assert held.held == "probation"
    assert verdict(items, Stats()).lanes == ("burst",)


def test_a_new_critical_rule_is_decisive_while_its_reach_is_small() -> None:
    few = Stats({("rule:ioc", "actor"): Factors(0.5, 1.0, True, 2)})
    many = Stats({("rule:ioc", "actor"): Factors(0.5, 1.0, True, 500)})
    assert verdict([obs("rule:ioc", base=60)], few).lanes == ("decisive",)
    assert verdict([obs("rule:ioc", base=60)], many).lanes == ()


def test_a_campus_site_has_no_lane_until_the_exposure_lane() -> None:
    site = [obs("rule:a", base=60, role="target", kind="site", key="domain:www.example.edu")]
    assert verdict(site, role="target").held == "target"


def test_a_breakdown_names_each_source_largest_first() -> None:
    w = score.window_score([obs("rule:a", base=10), obs("ev:outside", base=50)], NOW, "24h",
                           CONFIG, Stats())  # fmt: skip
    assert [b["source"] for b in w.breakdown()] == ["ev:outside", "rule:a"]


@pytest.mark.parametrize(
    ("known", "direction", "outcome", "kinds", "held", "lanes", "expected"),
    [
        (True, "outbound", 1.0, (), "lane", ("burst",), "known_infection"),
        (False, "outbound", 1.0, (), "lane", ("burst",), "presented"),
        (False, "inbound", 0.5, (), None, (), "inbound_blocked"),
        (False, "inbound", 1.0, ("success",), None, (), "inbound_success"),
        (False, "inbound", 1.0, (), None, (), "inbound_attempt"),
        (False, "inbound", 1.0, (), "target", (), "inbound_attempt"),
        (False, "unknown", 1.0, (), None, (), "unattributed"),
        (False, "outbound", 1.0, (), "gray_band", (), "gray_band"),
        (False, "outbound", 1.0, (), "probation", (), "probation"),
        (False, "outbound", 1.0, (), "rules_only", (), "rules_only"),
        (False, "outbound", 1.0, (), "below", (), "outbound_low"),
    ],
)  # fmt: skip
def test_every_group_ends_presented_or_in_one_digest_category(
    known: bool, direction: str, outcome: float, kinds: tuple[str, ...], held: str | None,
    lanes: tuple[str, ...], expected: str,
) -> None:  # fmt: skip
    verdicts = [] if held is None else [score.Verdict({}, lanes, (), held)]  # type: ignore[arg-type]
    found = score.category(known=known, direction=direction, outcome=outcome, kinds=kinds,
                           verdicts=verdicts)  # fmt: skip
    assert found == expected
    assert found in score.CATEGORIES


def test_the_audit_sample_is_deterministic() -> None:
    import uuid

    ids = [uuid.UUID(int=n) for n in range(50)]
    day = NOW.date()
    assert score.sample(ids, day, 5) == score.sample(list(reversed(ids)), day, 5)
    assert len(score.sample(ids, day, 5)) == 5
