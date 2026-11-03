"""The report's hypotheses are judged from facts of their own (AR7, D-190, D-201 to D-203): ruled
out only by facts that count against them, kept only by facts that support them, open (and worded
"not settled by what ARGUS holds") otherwise. The reason never contradicts the status, a person's
review is worded as the people's review and rules nothing else out on its own, and a successful
answer to an attacker does not rule out research scanning. The review's probe (a threat "kept"
because the verdict said so, with the reason "rests on nothing found yet") is the first test."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.incident import gather as g
from argus.incident import model as m
from argus.incident.build import build
from argus.incident.story import NOT_SETTLED, judge
from tests.unit.incident import kit

pytestmark = pytest.mark.unit
THREAT, BENIGN, ONE, RULE, RESEARCH = (
    "A real threat",
    "Expected or harmless",
    "One device",
    "A fault in the detection rule",
    "Internet research",
)


def of(report: m.IncidentReport, name: str) -> m.ReportHypothesis:
    return next(h for h in report.hypotheses if h.name.startswith(name))


def stripped(facts: g.CaseFacts) -> g.CaseFacts:
    """No flag, no threat-list hit, no outside answer: nothing but the verdict is left."""
    members = tuple(replace(x, flags=(), listed=()) for x in facts.members)
    return replace(facts, members=members, outside=(), served=frozenset())


def reviewed(facts: g.CaseFacts, outcome: str) -> g.CaseFacts:
    return replace(
        facts, members=tuple(replace(x, reviewed_outcome=outcome) for x in facts.members)
    )


def text_of(h: m.ReportHypothesis) -> str:
    return " ".join(s.text for s in h.why)


# --------------------------------------------------------------------------- the probe


def test_a_threat_the_ai_proposed_but_no_fact_supports_is_not_kept() -> None:
    """The review's probe: every support stripped, the AI's true positive left. The threat used to
    be "kept" with the reason "rests on nothing found yet"."""
    report = build(stripped(kit.amadey()), kit.ctx())
    assert report.verdict.outcome == "true_positive"
    threat = of(report, THREAT)
    assert threat.status == "open"
    assert NOT_SETTLED in text_of(threat)
    assert "rests on nothing" not in text_of(threat)
    benign = of(report, BENIGN)
    assert benign.status == "open"  # nothing counts against it either
    assert NOT_SETTLED in text_of(benign)


def test_the_supported_threat_is_kept_and_the_harmless_reading_is_ruled_out_by_those_facts() -> (
    None
):
    report = build(kit.amadey(), kit.ctx())
    threat, benign = of(report, THREAT), of(report, BENIGN)
    assert (threat.status, benign.status) == ("kept", "ruled_out")
    assert text_of(threat).startswith("It rests on:")
    assert "Ruled out by facts a harmless explanation does not account for" in text_of(benign)
    cited = {c for s in benign.why for c in s.cites}
    assert cited == {c for s in threat.why for c in s.cites if c in cited}  # the same facts


# --------------------------------------------------------------------------- a person's review


def test_a_persons_benign_review_is_worded_as_the_peoples_review_and_rules_nothing_out_alone() -> (
    None
):
    report = build(reviewed(stripped(kit.amadey()), "benign_expected"), kit.ctx())
    assert report.verdict.kind == "person"
    benign = of(report, BENIGN)
    assert benign.status == "kept"
    assert text_of(benign).startswith("The people's review says so:")
    for name in (THREAT, RULE):
        other = of(report, name)
        assert other.status == "open", name  # the review alone rules nothing out
        assert NOT_SETTLED in text_of(other)


def test_a_review_against_facts_that_say_otherwise_is_not_settled_either_way() -> None:
    report = build(reviewed(kit.amadey(), "benign_expected"), kit.ctx())
    benign, threat = of(report, BENIGN), of(report, THREAT)
    assert benign.status == "open"  # the review supports it, the flagged servers count against it
    assert threat.status == "kept"  # facts of its own support it; the review does not rule it out
    assert "some facts support it and some count against it" in text_of(benign)
    assert text_of(threat).startswith("It rests on:")


def test_a_persons_true_positive_review_keeps_the_threat() -> None:
    report = build(reviewed(stripped(kit.amadey()), "true_positive"), kit.ctx())
    threat = of(report, THREAT)
    assert threat.status == "kept"
    assert text_of(threat).startswith("The people's review says so:")


def test_an_ai_proposal_is_not_a_fact_for_or_against_anything() -> None:
    report = build(stripped(kit.amadey()), kit.ctx())
    assert report.verdict.kind == "proposal"
    assert {h.status for h in report.hypotheses if h.by == "argus"} <= {"open", "ruled_out"}


# --------------------------------------------------------------------------- research scanning


def test_a_successful_answer_does_not_rule_out_research_scanning() -> None:
    report = build(kit.git(), kit.ctx())
    assert report.header.case_id  # an attacker was served what it asked for
    research = of(report, RESEARCH)
    assert research.status == "open"
    assert NOT_SETTLED in text_of(research)
    assert "not who ran it" in text_of(research)
    threat = of(report, THREAT)
    assert threat.status == "kept"  # the served path supports the threat reading


def test_without_an_answer_it_is_open_too() -> None:
    facts = replace(kit.git(), served=frozenset())
    assert of(build(facts, kit.ctx()), RESEARCH).status == "open"


# --------------------------------------------------------------------------- the rule, in general


@pytest.mark.parametrize(
    ("pro", "con", "status"),
    [
        ([], [], "open"),
        (["F1"], [], "kept"),
        ([], ["F1"], "ruled_out"),
        (["F1"], ["F2"], "open"),
    ],
)
def test_judge_is_kept_ruled_out_or_open_by_the_facts_on_each_side(
    pro: list[str], con: list[str], status: str
) -> None:
    assert judge(pro, con) == status


def a_case(
    *,
    base: str,
    devices: int,
    flags: tuple[str, ...],
    listed: tuple[str, ...],
    flagged: bool,
    served: bool,
    opinion: str,
    outcome: str | None,
) -> g.CaseFacts:
    facts = kit.git() if base == "git" else kit.amadey(devices=devices, assessed=False)
    members = tuple(
        replace(x, flags=flags, listed=listed, reviewed_outcome=outcome) for x in facts.members
    )
    rows = list(facts.assessments)
    if opinion != "none":
        answer = [{"answer": {"outcome": opinion, "confidence": 0.7}}]
        rows += [
            g.AssessmentRow(300 + n, x.id, "agent@1", "proposed", opinion, 0.7, answer, kit.at(5))
            for n, x in enumerate(facts.members)
        ]
    return replace(
        facts,
        members=members,
        outside=facts.outside if flagged else (),
        served=facts.served if served else frozenset(),
        assessments=tuple(rows),
    )


OUTCOMES = ["true_positive", "benign_expected", "benign_policy", "rule_false_positive"]
cases = st.builds(
    a_case,
    base=st.sampled_from(["amadey", "git"]),
    devices=st.integers(1, 6),
    flags=st.lists(
        st.sampled_from([kit.BEACON, kit.OUTSIDE, "success after attack"]), max_size=3
    ).map(lambda x: tuple(dict.fromkeys(x))),
    listed=st.lists(st.sampled_from(kit.SERVERS), max_size=2).map(
        lambda x: tuple(dict.fromkeys(x))
    ),
    flagged=st.booleans(),
    served=st.booleans(),
    opinion=st.sampled_from(["none", *OUTCOMES, "inconclusive"]),
    outcome=st.one_of(st.none(), st.sampled_from(OUTCOMES)),
)


@settings(max_examples=250, deadline=None)
@given(cases)
def test_the_reason_never_contradicts_the_status_over_random_fact_sets(facts: Any) -> None:
    report = build(facts, kit.ctx())
    by_id = {f.id: f for f in report.facts}
    verdict_fact = report.verdict.sentences[0].cites[0] if report.verdict.sentences else None
    for h in (h for h in report.hypotheses if h.by == "argus"):
        words = text_of(h)
        head = h.why[0]
        cited = [c for s in h.why[1:] for c in s.cites]
        assert head.cites, h.name  # a reason always cites something
        assert set(head.cites) <= set(by_id)
        if h.status == "kept":
            assert words.startswith(("It rests on:", "The people's review says so")), words
            assert "Ruled out" not in words
            assert NOT_SETTLED not in words
            assert "no fact" not in words
        elif h.status == "ruled_out":
            assert head.text.startswith("Ruled out"), words
            assert NOT_SETTLED not in words
            assert "It rests on" not in words
            assert cited, h.name  # by facts that are cited
            # never by the verdict alone: a person's review rules nothing else out
            assert set(cited) != {verdict_fact}, h.name
        else:
            assert NOT_SETTLED in head.text, words
            assert "Ruled out" not in words
            assert "It rests on" not in words
        if h.name.startswith(RESEARCH):
            assert h.status == "open"  # nothing in the alerts shows who ran a scan
        if h.status == "ruled_out" and h.name.startswith(THREAT):
            raise AssertionError("no fact counts against a real threat")


@settings(max_examples=150, deadline=None)
@given(cases)
def test_the_hypotheses_are_the_same_for_the_same_facts(facts: Any) -> None:
    first, second = build(facts, kit.ctx()), build(facts, kit.ctx())
    assert [(h.name, h.status, text_of(h)) for h in first.hypotheses] == [
        (h.name, h.status, text_of(h)) for h in second.hypotheses
    ]
