"""The summary's optional prose and the guardian that decides whether it is used (AR7, D-190):
a fake model answers; an uncited sentence, an invented count, an unknown fact, an address, markup,
a sentence against the verdict, a malformed answer, a refusal and an absent model each leave the
deterministic summary standing, with the reason said."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import replace
from typing import Any

import pytest

from argus.incident import model as m
from argus.incident import prose
from argus.incident.build import build
from argus.llm.detect import OwnSpace
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from tests.unit.incident import kit

pytestmark = pytest.mark.unit

CAMPUS = OwnSpace(networks=(), domains=(), assets=frozenset(), is_internal=lambda ip: False)
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def report() -> m.IncidentReport:
    return build(kit.amadey(), kit.ctx())


def done(text: str) -> Completion:
    return Completion(text, "fake", "model-1", 10, 20, 0.0, 5, uuid.uuid4())


def answering(text: str | dict[str, Any]) -> Any:
    seen: list[Call] = []

    async def complete(call: Call) -> Completion:
        seen.append(call)
        return done(text if isinstance(text, str) else json.dumps(text))

    complete.calls = seen  # type: ignore[attr-defined]
    return complete


def good(rep: m.IncidentReport) -> dict[str, Any]:
    view = prose.shown(rep)
    chosen = list(view.facts.values())[:3]
    return {"sentences": [{"text": f.safe, "cites": [f.id]} for f in chosen]}


async def test_a_checked_answer_becomes_the_summary_s_prose() -> None:
    rep = report()
    complete = answering(good(rep))
    out = await prose.improve(rep, complete, CAMPUS)
    assert out.why is None
    assert out.by == "fake/model-1"
    words = out.report.summary.prose
    assert 1 <= len(words) <= prose.MAX_SENTENCES
    assert all(s.by == "model" for s in words)
    assert out.report.summary.sentences == rep.summary.sentences  # the deterministic text stays
    assert m.content_hash(out.report) == m.content_hash(rep)  # wording is no evidence
    call = complete.calls[0]
    assert call.purpose == "summary"
    assert call.self_hosted_only is False
    assert call.json is True


async def test_the_model_is_shown_facts_and_never_an_identifier() -> None:
    rep = report()
    view = prose.shown(rep)
    text = prose.request_text(view)
    assert not IP.search(text)  # no campus device, no server
    assert kit.HOST not in text
    assert kit.SERVERS[0] not in text
    assert prose.request_for(view, CAMPUS).validate().allowed
    assert all(f.safe and not f.from_logs for f in view.facts.values())
    assert len(view.facts) >= prose.MIN_CITED


@pytest.mark.parametrize(
    ("answer", "why"),
    [
        ({"sentences": [{"text": "Something happened.", "cites": []}]}, "cites no fact"),
        (
            {"sentences": [{"text": "Something happened.", "cites": ["F999"]}]},
            "not among the facts",
        ),
        ("not json at all", "not JSON"),
        ({"sentences": []}, "no sentence"),
        ({"text": "x"}, "not the shape"),
        ({"sentences": [{"text": "Hi.", "cites": ["F1"], "extra": 1}]}, "not {text, cites}"),
        ({"sentences": [{"text": "Hi <b>there</b>.", "cites": ["F1"]}]}, "markup"),
        ({"sentences": [{"text": "See https://evil.example now.", "cites": ["F1"]}]}, "markup"),
        ({"sentences": [{"text": "x" * 400, "cites": ["F1"]}]}, "too long"),
    ],
)
async def test_the_guardian_refuses_what_it_cannot_check(answer: Any, why: str) -> None:
    rep = report()
    out = await prose.improve(rep, answering(answer), CAMPUS)
    assert out.by is None
    assert out.why is not None
    assert why in out.why
    assert out.report.summary.prose == ()
    assert out.report.summary.prose_note
    assert out.report.summary.sentences == rep.summary.sentences


def first_alert_fact(rep: m.IncidentReport) -> m.ReportFact:
    return next(f for f in prose.shown(rep).facts.values() if "alerts" in (f.safe or ""))


async def test_a_model_that_invents_a_count_is_refused() -> None:
    rep = report()
    fact = first_alert_fact(rep)
    assert "35 alerts" in fact.safe
    for said in (
        fact.safe.replace("35", "36"),
        "Dozens of devices were affected.",
        "It lasted 3 days.",
    ):
        answer = {
            "sentences": [{"text": said, "cites": [fact.id]}, {"text": said, "cites": [fact.id]}]
        }
        out = await prose.improve(rep, answering(answer), CAMPUS)
        assert out.by is None, said
        assert "number" in (out.why or ""), said


async def test_a_number_the_cited_facts_do_not_state_is_refused_even_if_another_fact_has_it() -> (
    None
):
    rep = report()
    facts = list(prose.shown(rep).facts.values())
    alerts = first_alert_fact(rep)
    other = next(f for f in facts if "35" not in (f.safe or "") and f.id != alerts.id)
    answer = {"sentences": [{"text": alerts.safe, "cites": [other.id]}]}
    out = await prose.improve(rep, answering(answer), CAMPUS)
    assert out.by is None
    assert "number" in (out.why or "")


async def test_an_address_a_name_or_the_opposite_of_the_verdict_is_refused() -> None:
    rep = report()
    fact = first_alert_fact(rep)
    other = next(f for f in prose.shown(rep).facts.values() if f.id != fact.id)
    for said, why in (
        ("It reached 77.221.155.150.", "address"),
        ("It reached evil-domain.com today.", "address"),
        ("Mail admin@example.edu was told.", "markup"),
        ("This is a benign case.", "opposite"),
        ("This is harmless activity.", "opposite"),
    ):
        answer = {"sentences": [{"text": said, "cites": [fact.id, other.id]}]}
        out = await prose.improve(rep, answering(answer), CAMPUS)
        assert out.by is None, said
        assert why in (out.why or ""), said


async def test_a_benign_verdict_may_not_be_called_malicious() -> None:
    facts = kit.amadey()
    reviewed = tuple(replace(x, reviewed_outcome="benign_expected") for x in facts.members)
    rep = build(replace(facts, members=reviewed), kit.ctx())
    fact = first_alert_fact(rep)
    other = next(f for f in prose.shown(rep).facts.values() if f.id != fact.id)
    answer = {
        "sentences": [
            {"text": "A malicious device infected the network.", "cites": [fact.id, other.id]}
        ]
    }
    out = await prose.improve(rep, answering(answer), CAMPUS)
    assert out.by is None
    assert "opposite" in (out.why or "")


async def test_an_answer_resting_on_one_fact_is_refused() -> None:
    rep = report()
    fact = first_alert_fact(rep)
    answer = {"sentences": [{"text": fact.safe, "cites": [fact.id]}]}
    out = await prose.improve(rep, answering(answer), CAMPUS)
    assert out.by is None
    assert "fewer than two facts" in (out.why or "")


async def test_no_model_a_refusal_and_a_failure_leave_the_deterministic_text() -> None:
    rep = report()
    none = await prose.improve(rep, None, CAMPUS)
    assert none.report == rep
    assert none.by is None
    assert "no model" in (none.why or "")
    assert (await prose.improve(rep, answering(good(rep)), None)).by is None  # no privacy view

    async def refused(call: Call) -> Completion:
        raise Refused("every provider refused")

    async def waits(call: Call) -> Completion:
        raise NoCapacity(kit.AS_AT, "no capacity")

    async def breaks(call: Call) -> Completion:
        raise RuntimeError("boom")

    for complete in (refused, waits, breaks):
        out = await prose.improve(rep, complete, CAMPUS)
        assert out.by is None
        assert out.report.summary.prose == ()
        assert out.report.summary.sentences == rep.summary.sentences
        assert out.report.summary.prose_note
        assert "boom" not in out.report.summary.prose_note
