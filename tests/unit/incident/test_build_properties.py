"""Properties of the deterministic writer (AR7, D-190), over cases of every size: every sentence
cites only facts that are present and states only numbers they state; the counts the report
gives are the counts the stored answers hold; the same input always gives the same report (and
the same JSON); the day table adds up to the alerts; the indicators and devices are the case's."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.incident import model as m
from argus.incident.book import digits_of, uncovered
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit

cases = st.builds(
    kit.synthetic,
    members=st.integers(0, 9),
    alerts_each=st.integers(1, 400),
    hosts=st.integers(0, 60),
    servers=st.integers(0, 6),
    counts=st.lists(st.integers(0, 50_000), min_size=1, max_size=4),
    notified=st.booleans(),
    flagged=st.booleans(),
    state=st.sampled_from(["suspected", "open", "assigned", "contained"]),
)


@given(cases)
def test_every_sentence_cites_present_facts_and_states_only_their_numbers(facts: Any) -> None:
    report = build(facts, kit.ctx())
    by_id = {f.id: f for f in report.facts}
    assert len(by_id) == len(report.facts)
    for part, sentence in m.sentences_of(report):
        assert sentence.cites, part
        assert set(sentence.cites) <= set(by_id), part
        assert not uncovered(sentence, by_id), (part, sentence.text)
    for line in report.evidence:
        assert line.fact in by_id
        assert line.query.url
        assert line.query.text


@given(cases)
def test_the_counts_are_the_counts_of_the_stored_answers(facts: Any) -> None:
    report = build(facts, kit.ctx())
    by_id = {f.id: f for f in report.facts}
    stored = {r.row_count for r in facts.evidence}
    for line in report.evidence[1:]:
        assert line.count is not None
        assert line.count in stored
        assert str(line.count) in digits_of(by_id[line.fact].text) or line.count == 0
    if facts.alerts_total:
        assert report.evidence[0].count == facts.alerts_total
    else:
        assert report.evidence == ()  # no alert, no time range: no line to check
    assert sum(d.total for d in report.timeline.days) == facts.alerts_total


@given(cases)
def test_the_same_input_is_the_same_report(facts: Any) -> None:
    one, two = build(facts, kit.ctx()), build(facts, kit.ctx())
    assert one == two
    assert one.model_dump_json() == two.model_dump_json()
    assert m.content_hash(one) == m.content_hash(two)
    assert m.IncidentReport.model_validate_json(one.model_dump_json()) == one


@given(cases)
def test_the_indicators_and_devices_are_the_cases(facts: Any) -> None:
    report = build(facts, kit.ctx())
    assert {(i.kind, i.value, i.role) for i in report.indicators} == {
        (i.kind, i.value, i.role) for i in facts.indicators
    }
    devices = {i.value for i in facts.indicators if i.role == "actor"}
    assert {a.value for a in report.assets if a.kind == "device"} == devices
    assert report.assets_total == len(devices)
    assert {a.value for a in report.actors} <= devices
    assert report.timeline.alerts == facts.alerts_total
