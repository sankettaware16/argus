"""AR4 (D-182): the pure rules behind ARGUS's stance on an investigation and its recommendation to
close a pattern. The SQL that feeds them is tested on a database (tests/integration/web/
test_queue_ar4.py)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.agent import reading as readings
from argus.web import stance
from argus.web.assessed import Detail, Shared

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 29, tzinfo=UTC)
CLOSING = sorted(stance.CLOSING)
OUTCOMES = [*CLOSING, "true_positive", "inconclusive"]


def detail(
    n: int,
    status: str = "proposed",
    *,
    assessor: str = "agent@1",
    outcome: str | None = "true_positive",
    read: readings.Reading | None = None,
) -> Detail:
    who = "the AI investigator" if assessor.startswith("agent") else "the decision engine"
    return Detail(n, assessor, who, status, outcome, 0.8, "key", (), None, NOW, NOW, read)


READING = readings.Reading("undecided", "true_positive", 0.7, None, ())
SOURCE = uuid.UUID(int=7)


def shared(d: Detail, *, earlier: bool = False) -> Shared:
    return Shared(SOURCE, earlier, d)


def test_nothing_gives_no_stance() -> None:
    assert stance.choose([], None) is None
    assert stance.choose([detail(1, "queued", outcome=None)], None) is None
    assert stance.choose([detail(1, "failed", outcome=None)], shared(detail(2, "failed"))) is None
    assert stance.choose([detail(1, "no_decision", outcome=None)], None) is None  # no reading


def test_the_investigators_own_proposal_comes_first_then_the_engines() -> None:
    engine = detail(1, assessor="engine@1", outcome="benign_policy")
    agent = detail(2, outcome="true_positive")
    assert stance.choose([engine, agent], None) == stance.Choice(agent)
    assert stance.choose([engine], None) == stance.Choice(engine)


def test_a_proposal_of_the_pattern_beats_a_reading_of_its_own_but_not_a_proposal() -> None:
    own_reading = detail(1, "no_decision", outcome=None, read=READING)
    engine = detail(3, assessor="engine@1", outcome="benign_policy")
    theirs = detail(2, outcome="benign_expected")
    found = stance.choose([own_reading], shared(theirs))
    assert found == stance.Choice(theirs, SOURCE, False)
    assert found is not None
    assert found.proposed
    assert stance.choose([own_reading, engine], shared(theirs)) == stance.Choice(engine)


def test_a_reading_is_shown_when_there_is_no_proposal() -> None:
    own = detail(1, "no_decision", outcome=None, read=READING)
    theirs = detail(2, "no_decision", outcome=None, read=READING)
    got = stance.choose([own], shared(theirs))
    assert got == stance.Choice(own)
    assert got is not None
    assert not got.proposed
    other = stance.choose([detail(3, "no_decision", outcome=None)], shared(theirs))
    assert other == stance.Choice(theirs, SOURCE, False)  # the engine's empty no-decision: no
    assert stance.choose([], shared(theirs, earlier=True)) == stance.Choice(theirs, SOURCE, True)


def lean(outcome: str | None, *, sure: float | None = 0.8, agent: bool = True, tp: bool = False):
    return stance.Lean(1 if outcome else None, outcome, sure, agent, tp)


def test_a_pattern_is_recommended_for_closing_when_the_proposals_agree() -> None:
    ids = [uuid.UUID(int=n) for n in range(1, 6)]
    found = {ids[0]: lean("benign_expected", sure=0.9), ids[1]: lean("benign_expected", sure=0.6)}
    rec = stance.recommend(ids, found)
    assert rec == stance.Recommendation(
        "benign_expected", 0.6, "the AI investigator", (ids[0], ids[1]), 5
    )  # fmt: skip
    engine = {ids[0]: lean("benign_policy", agent=False)}
    got = stance.recommend(ids, engine)
    assert got is not None
    assert got.source == "the decision engine"
    mixed = {ids[0]: lean("benign_policy", agent=False), ids[1]: lean("benign_policy")}
    got = stance.recommend(ids, mixed)
    assert got is not None
    assert got.source == "ARGUS"
    unsure = {ids[0]: lean("benign_policy", sure=None), ids[1]: lean("benign_policy")}
    got = stance.recommend(ids, unsure)
    assert got is not None
    assert got.confidence is None


@pytest.mark.parametrize(
    "found",
    [
        {},
        {1: lean(None)},
        {1: lean("true_positive")},
        {1: lean("inconclusive")},
        {1: lean("benign_expected"), 2: lean("benign_policy")},
        {1: lean("benign_expected"), 2: lean(None, tp=True)},
        {1: lean("benign_expected", tp=True)},
    ],
)
def test_no_recommendation_when_there_is_nothing_to_close(found: dict[int, stance.Lean]) -> None:
    ids = [uuid.UUID(int=n) for n in range(1, 4)]
    assert stance.recommend(ids, {ids[k - 1]: v for k, v in found.items()}) is None


@given(
    st.lists(st.sampled_from([*OUTCOMES, None]), min_size=1, max_size=12),
    st.lists(st.booleans(), min_size=12, max_size=12),
)
def test_a_recommendation_is_always_one_closing_outcome_over_the_proposing_members(
    outcomes: list[str | None], tps: list[bool]
) -> None:
    ids = [uuid.UUID(int=n + 1) for n in range(len(outcomes))]
    found = {
        i: stance.Lean(n + 1 if o else None, o, 0.5, True, tps[n] and o is None)
        for n, (i, o) in enumerate(zip(ids, outcomes, strict=True))
        if o is not None or tps[n]
    }
    rec = stance.recommend(ids, found)
    proposing = {o for o in outcomes if o is not None}
    threatened = any(f.true_positive_reading for f in found.values())
    if rec is None:
        assert len(proposing) != 1 or next(iter(proposing)) not in stance.CLOSING or threatened
    else:
        assert not threatened
        assert proposing == {rec.outcome}
        assert rec.outcome in stance.CLOSING
        assert set(rec.members) == {i for i, o in zip(ids, outcomes, strict=True) if o}
        assert rec.total == len(ids)


@pytest.mark.parametrize(
    ("assessor", "agent"),
    [("agent@1", True), ("agent@2", True), ("agent", True), ("engine@1", False), ("", False)],
)
def test_the_agents_own_assessment_is_one_predicate_everywhere(assessor: str, agent: bool) -> None:
    """D-189: the stance, the lists, the page and the labels all ask ``assessed.is_agent``; a run
    of any version of the investigator is its own and never replaced by a shared one."""
    from argus.web import assessed

    assert assessed.is_agent(assessor) is agent
    assert (assessed.source_of(assessor) == "the AI investigator") is agent
    own = detail(1, assessor=assessor or "x", outcome="benign_policy")
    other = shared(detail(2, outcome="true_positive"))
    found = stance.choose([own], other)
    assert found is not None
    # the investigator's own proposal beats the pattern's; so does the engine's, as it always has
    assert found.detail.assessment_id == 1
    assert found.source is None
