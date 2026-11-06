"""Priority, bands and the why line (P4-F E5): examples, and Hypothesis properties: the priority
never falls when evidence is added (a higher score, another source, another object, another
stage, a newer observation), a person's confirm never lowers it, out-of-date intel never lowers
it below what it was without that intel, and renaming rules changes only the words."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.risk import priority as prio
from tests.unit.risk.conftest import NOW

pytestmark = pytest.mark.unit


def facts(score: float, *, label: str = "10.1.1.1", hours: float = 1.0, stages: int = 1,
          families: int = 1, parts: tuple[prio.Part, ...] = ()) -> prio.Facts:  # fmt: skip
    return prio.Facts("device", label, score, families, stages, parts,
                      NOW - timedelta(hours=hours))  # fmt: skip


def words(part: prio.Part) -> str:
    return part.source


def test_the_bands_follow_the_calibrated_thresholds() -> None:
    assert [prio.band_of(p) for p in (100, 63, 62, 55, 54, 46, 45, 0)] == [
        "P1", "P1", "P2", "P2", "P3", "P3", "P4", "P4"]  # fmt: skip


def test_a_decisive_device_with_two_families_still_active_is_p1() -> None:
    top = facts(105.0, families=2, parts=(prio.Part("ev:outside", 50), prio.Part("rule:x", 20)))
    scored = prio.score([top], NOW)
    assert scored.activity == 1.2
    assert scored.band == "P1"
    assert scored.priority == round(100 * (1 - pow(2.718281828459045, -105 * 1.2 / 80)))


def test_a_quiet_single_rule_object_is_p4() -> None:
    assert prio.score([facts(20.0, hours=100)], NOW).band == "P4"


def test_the_why_line_is_the_breakdown_largest_first_then_the_factors() -> None:
    parts = (prio.Part("ev:outside", 49.6), prio.Part("ev:tunnel", 25.0),
             prio.Part("rule:x", 0.2))  # fmt: skip
    objects = [facts(112.0, families=2, stages=2, parts=parts), facts(30.0, label="10.1.1.2")]
    scored = prio.score(objects, NOW)
    items = prio.why(scored, objects, words, NOW)
    assert prio.line(items) == (
        "+50 ev:outside · +25 ev:tunnel · \u00d71.5 two log families"
        " · +9 one other campus device · \u00d71.25 two attack stages"
        " · \u00d71.1 spread over 2 campus objects · \u00d71.2 still active"
    )
    assert items[0] == prio.WhyItem("+", 50.0, "ev:outside")


def test_out_of_date_intel_counts_a_fifth_less_and_says_so() -> None:
    top = facts(60.0, parts=(prio.Part("ev:ti", 20.0), prio.Part("rule:x", 40.0)))
    fresh = prio.score([top], NOW)
    stale = prio.score([top], NOW, prio.Trust(stale_points=20.0))
    assert stale.stale == 4.0
    assert stale.priority < fresh.priority
    line = prio.line(prio.why(stale, [top], words, NOW, prio.Trust(stale_points=20.0)))
    assert "\u22124 its threat list is out of date" in line


def test_a_persons_confirm_raises_it() -> None:
    top = facts(40.0)
    assert prio.score([top], NOW, prio.Trust(confirmed=True)).priority > prio.score(
        [top], NOW).priority  # fmt: skip


def test_quiet_for_days_is_said() -> None:
    top = facts(40.0, hours=24 * 5)
    items = prio.why(prio.score([top], NOW), [top], words, NOW)
    assert items[-1].words() == "\u00d70.7 quiet for 5 days"


# --------------------------------------------------------------------------- properties

scores = st.floats(min_value=0, max_value=400, allow_nan=False)
hours = st.floats(min_value=0, max_value=24 * 14, allow_nan=False)


@st.composite
def objects(draw: st.DrawFn) -> list[prio.Facts]:
    n = draw(st.integers(1, 8))
    return [
        facts(draw(scores), label=f"10.1.1.{i}", hours=draw(hours),
              stages=draw(st.integers(0, 4)), families=draw(st.integers(0, 3)))
        for i in range(n)
    ]  # fmt: skip


@given(objects(), st.integers(0, 7), scores)
def test_a_higher_score_never_lowers_the_priority(
    found: list[prio.Facts], which: int, more: float
) -> None:
    i = which % len(found)
    raised = [*found[:i], replace(found[i], score=found[i].score + more), *found[i + 1 :]]
    assert prio.score(raised, NOW).priority >= prio.score(found, NOW).priority


@given(objects(), scores, hours)
def test_another_object_never_lowers_the_priority(
    found: list[prio.Facts], score: float, age: float
) -> None:
    more = [*found, facts(score, label="10.9.9.9", hours=age)]
    assert prio.score(more, NOW).priority >= prio.score(found, NOW).priority


@given(objects(), st.integers(0, 7), st.integers(0, 4), hours)
def test_another_stage_or_a_newer_observation_never_lowers_it(
    found: list[prio.Facts], which: int, stages: int, newer: float
) -> None:
    i = which % len(found)
    f = found[i]
    last = f.last_seen if f.last_seen is not None else NOW
    later = max(last, NOW - timedelta(hours=newer))
    grown = replace(f, stages=max(f.stages, stages), last_seen=later)
    more = [*found[:i], grown, *found[i + 1 :]]
    assert prio.score(more, NOW).priority >= prio.score(found, NOW).priority


@given(objects(), st.floats(min_value=0, max_value=100, allow_nan=False))
def test_adding_out_of_date_intel_never_lowers_the_priority(
    found: list[prio.Facts], points: float
) -> None:
    top = max(found, key=lambda f: (f.score, f.label))
    grown = [replace(f, score=f.score + points) if f is top else f for f in found]
    before = prio.score(found, NOW)
    after = prio.score(grown, NOW, prio.Trust(stale_points=points))
    assert after.priority >= before.priority


@given(objects())
def test_a_confirm_never_lowers_it_and_the_priority_is_in_range(found: list[prio.Facts]) -> None:
    plain = prio.score(found, NOW)
    assert 0 <= plain.priority <= 100
    assert plain.band == prio.band_of(plain.priority)
    assert prio.score(found, NOW, prio.Trust(confirmed=True)).priority >= plain.priority


@given(objects(), st.text(min_size=1, max_size=20))
def test_renaming_rules_changes_only_the_words(found: list[prio.Facts], name: str) -> None:
    parts = (prio.Part("rule:L1", 30.0), prio.Part("ev:beacon", 15.0))
    with_parts = [replace(found[0], parts=parts), *found[1:]]
    scored = prio.score(with_parts, NOW)
    one = prio.why(scored, with_parts, lambda p: "rule: A" if p.source == "rule:L1" else "x", NOW)
    two = prio.why(scored, with_parts, lambda p: f"rule: {name}" if p.source == "rule:L1"
                   else "x", NOW)  # fmt: skip
    assert [(i.op, i.points) for i in one] == [(i.op, i.points) for i in two]
