"""The engine's invariants (P4-F E1 gate), as Hypothesis properties:

- 10,000 copies of one observation score exactly as one (repetition cannot inflate a score);
- adding alert groups (or facts to a group) never lowers any of an object's window scores, nor
  removes a lane (an attack cannot be diluted by noise on the same device);
- the order of the observations changes nothing;
- renaming every rule, and giving the rules other ids, changes nothing but the labels;
- stages covered never exceed the sources, the stages, or the stages the sources name;
- one rule and the facts of its own alert groups never cover more stages than one for the rule
  and those the facts name outside its own (one rule cannot fake progression)."""

from __future__ import annotations

import random
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.risk import rulemeta, run, score
from argus.risk.config import WINDOWS, stage_bit
from argus.risk.observe import ObjectRef, Observation, observe
from argus.risk.score import Factors, Stats
from tests.unit.risk.conftest import CONFIG, NOW, context, group, obs

pytestmark = pytest.mark.unit
DEVICE = ObjectRef("device", "ip:10.1.1.1")
SOURCES = ("rule:a", "rule:b", "rule:c", "rule:crit", "ev:beacon", "ev:ports", "ev:outside",
           "ev:ti", "ev:success", "ev:rare_dest")  # fmt: skip
RULES = tuple(s for s in SOURCES if s.startswith("rule:"))
EVIDENCE = tuple(s for s in SOURCES if s.startswith("ev:"))
THREATS = ("ip:45.138.12.1", "ip:45.138.12.2", "domain:rare.test")


@st.composite
def observations(draw: st.DrawFn) -> Observation:
    source = draw(st.sampled_from(SOURCES))
    return replace(
        obs(source, hours_ago=draw(st.floats(min_value=-2, max_value=400)),
            base=draw(st.floats(min_value=1, max_value=100)),
            outcome=draw(st.sampled_from((0.5, 1.0))),
            stages=draw(st.integers(min_value=0, max_value=15)),
            family=draw(st.sampled_from((None, "squid", "dns", "nginx")))
            if source.startswith("rule:") else None,
            strong=draw(st.booleans()) and source in ("ev:outside", "ev:ti"),
            threats=tuple(draw(st.lists(st.sampled_from(THREATS), max_size=2, unique=True)))
            if source.startswith("rule:") else ()),
        group=uuid.UUID(int=draw(st.integers(min_value=0, max_value=40))),
    )  # fmt: skip


@st.composite
def alert_groups(draw: st.DrawFn) -> list[Observation]:
    """One alert group's observations on the device as observe makes them: its rule's and its
    facts', at the group's time. A group id has one rule and one stage mask, as a group does."""
    n = draw(st.integers(min_value=0, max_value=40))
    gid, hours = uuid.UUID(int=n), draw(st.floats(min_value=-2, max_value=400))
    rule = obs(
        RULES[n % len(RULES)],
        hours_ago=hours,
        gid=gid,
        stages=n % 16,
        base=draw(st.floats(min_value=1, max_value=100)),
        outcome=draw(st.sampled_from((0.5, 1.0))),
        family=draw(st.sampled_from((None, "squid", "dns", "nginx"))),
        threats=tuple(draw(st.lists(st.sampled_from(THREATS), max_size=2, unique=True))),
    )
    facts = [
        obs(
            source,
            hours_ago=hours,
            gid=gid,
            base=draw(st.floats(min_value=1, max_value=100)),
            stages=draw(st.integers(min_value=0, max_value=15)),
            strong=draw(st.booleans()) and source in ("ev:outside", "ev:ti"),
        )
        for source in draw(st.lists(st.sampled_from(EVIDENCE), max_size=3, unique=True))
    ]
    return [rule, *facts]


def flat(groups: list[list[Observation]]) -> list[Observation]:
    return [o for g in groups for o in g]


factors_st = st.dictionaries(
    st.tuples(st.sampled_from(SOURCES), st.just("actor")),
    st.builds(
        Factors,
        st.floats(min_value=0.05, max_value=1.0),
        st.sampled_from((0.25, 1.0, 1.5)),
        st.booleans(),
        st.integers(min_value=0, max_value=50),
    ),
    max_size=len(SOURCES),
)
stats_st = st.builds(
    Stats, factors_st,
    st.dictionaries(st.sampled_from(THREATS), st.integers(min_value=1, max_value=12)),
    st.sampled_from((frozenset(), frozenset({DEVICE}))),
)  # fmt: skip


def evaluate(items: list[Observation], stats: Stats) -> score.Verdict:
    return score.evaluate(items, NOW, CONFIG, stats, ref=DEVICE)


def test_ten_thousand_copies_of_one_observation_score_as_one() -> None:
    one = [obs("rule:a", base=35, family="squid", stages=4, threats=THREATS[:1]),
           obs("ev:beacon", base=15)]  # fmt: skip
    many = one[:1] * 10_000 + one[1:]
    assert evaluate(many, Stats()) == evaluate(one, Stats())


@given(st.lists(observations(), min_size=1, max_size=12), st.integers(1, 60), stats_st)
def test_copies_never_change_a_verdict(items: list[Observation], n: int, stats: Stats) -> None:
    assert evaluate(items * n, stats) == evaluate(items, stats)


@given(st.lists(alert_groups(), max_size=8), st.lists(alert_groups(), max_size=5), stats_st)
def test_more_alert_groups_never_lower_a_score_nor_remove_a_lane(
    groups: list[list[Observation]], more: list[list[Observation]], stats: Stats
) -> None:
    items = flat(groups)
    before, after = evaluate(items, stats), evaluate(items + flat(more), stats)
    for name in WINDOWS:
        assert after.window(name).score >= before.window(name).score - 1e-9
        assert after.window(name).sources >= before.window(name).sources
        assert after.window(name).stages >= before.window(name).stages
    assert set(before.lanes) <= set(after.lanes)


@given(st.lists(observations(), max_size=15), st.randoms(use_true_random=False), stats_st)
def test_the_order_of_observations_changes_nothing(
    items: list[Observation], rnd: random.Random, stats: Stats
) -> None:
    shuffled = list(items)
    rnd.shuffle(shuffled)
    assert evaluate(shuffled, stats) == evaluate(items, stats)


@given(
    st.lists(alert_groups(), max_size=8),
    st.lists(st.sampled_from(EVIDENCE), max_size=4),
    st.integers(min_value=0, max_value=15),
    stats_st,
)
def test_a_fact_added_to_a_group_never_lowers_a_score_nor_removes_a_lane(
    groups: list[list[Observation]], kinds: list[str], stages: int, stats: Stats
) -> None:
    """A new dossier may add facts to a group whose rule observation is already held."""
    items = flat(groups)
    more = [replace(groups[n % len(groups)][0], source_key=k, source_kind="evidence",
                    stages=stages, family=None, threats=())
            for n, k in enumerate(kinds)] if groups else []  # fmt: skip
    before, after = evaluate(items, stats), evaluate(items + more, stats)
    for name in WINDOWS:
        assert after.window(name).score >= before.window(name).score - 1e-9
        assert after.window(name).stages >= before.window(name).stages
    assert set(before.lanes) <= set(after.lanes)


@given(st.integers(min_value=0, max_value=15),
       st.lists(st.tuples(st.sampled_from(EVIDENCE), st.integers(min_value=0, max_value=15),
                          st.integers(min_value=0, max_value=5)), max_size=10),
       st.integers(min_value=1, max_value=5), st.booleans())  # fmt: skip
def test_one_rule_and_its_own_groups_facts_never_fake_progression(
    mask: int, facts: list[tuple[str, int, int]], days: int, rare: bool
) -> None:
    threats = THREATS[:1] if rare else ()
    items = [obs("rule:a", stages=mask, gid=uuid.UUID(int=d), hours_ago=1 + 24 * d,
                 threats=threats) for d in range(days)]  # fmt: skip
    outside = 0
    for source, stages, d in facts:
        items.append(obs(source, stages=stages, gid=uuid.UUID(int=d % days),
                         hours_ago=1 + 24 * (d % days)))  # fmt: skip
        outside |= stages & ~mask
    v = evaluate(items, Stats(reach=dict.fromkeys(threats, 1)))
    for name in WINDOWS:
        w = v.window(name)
        found = outside
        if any(c.source == score.PERSISTENCE for c in w.contributions):  # its rule's own too
            found |= stage_bit(CONFIG.persistence.stage) & ~mask
        assert w.rule_sources <= 1
        assert w.stages <= (1 if mask else 0) + bin(found).count("1")


@given(st.lists(st.integers(min_value=0, max_value=15), max_size=12))
def test_stages_covered_are_bounded(masks: list[int]) -> None:
    covered = score.matching(masks)
    union = 0
    for m in masks:
        union |= m
    assert covered <= min(len([m for m in masks if m]), 4, bin(union).count("1"))
    assert covered >= (1 if union else 0)


# --------------------------------------------------------------------------- renaming rules

NAMES = ("Alpha rule", "Bravo rule", "Charlie rule", "Delta rule")
SIGNALS = ({}, {"proxy.regularity": 0.1}, {"ports.risky": 3}, {"ti.listed": 1},
           {"web.successes_after": 2}, {"proxy.hosts_to_destination": 1})  # fmt: skip


@st.composite
def worlds(draw: st.DrawFn) -> list[tuple[str, str, dict[str, object]]]:
    """Alert groups as (rule id, actor, signals); every rule id has a name (several ids may
    share one: a recreated rule)."""
    out = []
    for _ in range(draw(st.integers(min_value=1, max_value=14))):
        out.append((
            f"id-{draw(st.integers(min_value=0, max_value=5))}",
            f"10.1.1.{draw(st.integers(min_value=1, max_value=4))}",
            draw(st.sampled_from(SIGNALS)) | {"_hours": draw(st.floats(1, 300))},
        ))  # fmt: skip
    return out


def pipeline(
    world: list[tuple[str, str, dict[str, object]]], names: dict[str, str],
    ids: dict[str, str], severities: dict[str, str],
) -> dict[ObjectRef, score.Verdict]:  # fmt: skip
    rows = [rulemeta._Row(ids[r], names[r], None, NOW - timedelta(days=30 + int(r[3:])))
            for r in sorted(names)]  # fmt: skip
    lineages = rulemeta.assign_lineages(rows)
    month = NOW - timedelta(days=30)
    metas = {ids[r]: rulemeta.RuleMeta(ids[r], lineages[ids[r]], 4, "squid", month)
             for r in names}  # fmt: skip
    found: list[Observation] = []
    for n, (rule, actor, signals) in enumerate(world):
        hours = float(signals["_hours"])  # type: ignore[arg-type]
        clean = {k: v for k, v in signals.items() if k != "_hours"}
        g = group(actor=actor, rule=ids[rule], severity=severities[rule], signals=clean,
                  hours_ago=hours, gid=uuid.UUID(int=n))  # fmt: skip
        found.extend(observe(g, metas[ids[rule]], context()).observations)
    first = {f"rule:{m.lineage}": m.first_alert_at for m in metas.values()}
    return run.evaluate_all(found, NOW, CONFIG, first, set()).verdicts


def shape(v: score.Verdict) -> tuple[object, ...]:
    """A verdict without its source labels."""
    return (
        v.lanes, v.gray, v.held,
        tuple((n, round(w.score, 9), w.sources, w.families, w.stages, w.strong, w.anchored,
               sorted(round(c.score, 9) for c in w.contributions))
              for n, w in sorted(v.windows.items())),
    )  # fmt: skip


@given(worlds(), st.randoms(use_true_random=False))
def test_renaming_rules_changes_nothing_and_other_ids_change_only_labels(
    world: list[tuple[str, str, dict[str, object]]], rnd: random.Random
) -> None:
    rules = sorted({r for r, _, _ in world})
    names = {r: NAMES[int(r[3:]) % len(NAMES)] for r in rules}
    severities = {r: ("low", "medium", "high", "critical")[int(r[3:]) % 4] for r in rules}
    ids = {r: r for r in rules}
    base = pipeline(world, names, ids, severities)
    # every name replaced, consistently (rules that shared a name still share one)
    renamed = {n: f"Renamed {rnd.random():.6f} {n[::-1]}" for n in NAMES}
    assert pipeline(world, {r: renamed[n] for r, n in names.items()}, ids, severities) == base
    # other ids (a bijection): the same verdicts, but for the lineages' labels
    shuffled = list(rules)
    rnd.shuffle(shuffled)
    other = {r: f"new-{s}" for r, s in zip(rules, shuffled, strict=True)}
    moved = pipeline(world, names, other, severities)
    assert {k: shape(v) for k, v in moved.items()} == {k: shape(v) for k, v in base.items()}
