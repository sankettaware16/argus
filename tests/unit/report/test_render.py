"""Q-F2: report@2 for a person without log access hides everything derived from log content
("see logs", plan §7.2) and nothing else; the plain text is deterministic and shows control
characters instead of obeying them; the contract refuses unknown fields."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.report import build as b
from argus.report import render
from argus.report.model import FORMAT, HIDDEN, Report, Value
from tests.unit.report.kit import request, row
from tests.unit.report.test_build import UnitPack, assessment, inputs

pytestmark = pytest.mark.unit

MARK = "§log"  # a marker in log content only
TI_ROWS = [{"_source": {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo"}}]


def report(log_value: str = f"{MARK}-dest", agent: bool = True) -> Report:
    slots = [{"key": 1760004000000 + 600_000 * i, "doc_count": 1 if i % 2 == 0 else 0}
             for i in range(8)]  # fmt: skip
    aggs = {"destination_count": {"value": 2},
            "destinations": {"buckets": [{"key": log_value, "doc_count": 9}]},
            "timeline": {"buckets": slots}}  # fmt: skip
    host = row("proxy.host", snapshot={"rows": [], "aggregations": aggs})
    ti = row("ti.lookup", row_count=1, snapshot={"rows": TI_ROWS})
    web = row("web.followups", "empty", snapshot={"rows": []})
    reasons: list[Any] = ["no key"]
    if agent:  # as agent@1 stores them: the explanation first (agent.Agent._verdict)
        reasons = [f"The host reached {log_value}.", {"kind": "agent@1", "answer": {
            "outcome": "true_positive", "explanation": f"The host reached {log_value}.",
            "cites": [f"reached {log_value}"], "hypotheses": [
                {"name": "beacon", "for": [f"{log_value}"], "against": []}]},
            "calls": 2, "cost_usd": 0.01, "models": ["p/m"], "seconds": 3}]  # fmt: skip
    a = assessment("agent@1" if agent else "engine@1", "proposed" if agent else "no_decision",
                   outcome="true_positive" if agent else None, reasons=reasons)  # fmt: skip
    requests = [request("proxy.host", 1), request("ti.lookup", 2), request("web.followups", 3)]
    return b.build(inputs([host, ti, web], requests, a), UnitPack())


def strings(value: Any) -> list[str]:
    """Every string a report holds, keys too."""
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (str(k), *strings(v))]
    if isinstance(value, list | tuple):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


@given(st.text(max_size=80).map(lambda t: MARK + t))
def test_no_log_content_survives(value: str) -> None:
    full = report(value)
    assert any(value in s for s in strings(full.model_dump(mode="json")))  # with log access
    hidden = render.hide_logs(full)
    assert not [s for s in strings(hidden.model_dump(mode="json")) if MARK in s]
    assert MARK not in render.text(hidden)
    assert hidden.hidden > 0
    assert "45.9.9.9 (feodo)" in strings(hidden.model_dump(mode="json"))  # a list is no log


def test_what_hiding_keeps() -> None:
    full = report()
    hidden = render.hide_logs(full)
    assert [p.eid for p in hidden.provenance] == [p.eid for p in full.provenance]
    by = {p.eid: p for p in hidden.provenance}
    assert by["E1"].line == "E1 · proxy.host@1 · squid, 09 Oct 10:00\u201313:00 UTC · result hidden"
    assert (by["E1"].rows, by["E1"].result_hash, by["E1"].status) == (None, None, "hidden")
    assert by["E1"].subject is None
    assert by["E2"] == full.provenance[1]  # the lookup is no log, and the dossier's own
    assert by["E3"].status == "hidden"  # an empty answer is log content too
    assert hidden.hidden == 2  # the two log checks that answered
    assert hidden.summary is not None
    assert (hidden.summary.text, hidden.summary.cites[0].quote) == (HIDDEN, HIDDEN)
    assert [h.name for h in hidden.hypotheses if h.by == "model"] == [HIDDEN]
    assert hidden.verdict.why == (HIDDEN,)  # the model's explanation
    assert hidden.verdict.model_copy(update={"why": full.verdict.why}) == full.verdict
    assert hidden.cost == full.cost
    assert hidden.strength == full.strength
    # one line per log check that answered, what was asked kept; nothing that reads it
    hidden_items = [i for i in hidden.found.items if i.kind == "hidden"]
    assert [(i.eids, i.sentence, i.note) for i in hidden_items] == [
        (("E1",), HIDDEN, by["E1"].line), (("E3",), HIDDEN, by["E3"].line)]  # fmt: skip
    told = {"E1", "E3"}
    for item in hidden.found.items:
        if item.kind != "hidden":
            assert not (item.from_logs and set(item.eids) & told)
    for c in hidden.found.new.checks:
        if c.from_logs:
            assert (c.outcome, c.sentence, c.why) == ("hidden", HIDDEN, None)
    assert not [r for r in hidden.evidence if r.fact.from_logs]
    assert [r for r in full.evidence if not r.fact.from_logs] == list(hidden.evidence)
    assert not [g for g in hidden.unknowns if g.from_logs]
    new = hidden.found.new
    for x in (*new.new_facts, *new.now_known, *new.changed, *new.steps_answered,
              *new.gaps_closed, *new.gaps_opened):  # fmt: skip
        assert not x.from_logs
    assert all(not e.from_logs or e.kind == "check" for e in hidden.timeline)
    assert any(e.from_logs and e.kind == "fact" for e in full.timeline)  # traffic times: gone
    for h in hidden.hypotheses:
        assert not [r for r in (*h.support, *h.against) if r.from_logs]
    assert render.hide_logs(hidden) == hidden  # hiding twice changes nothing more
    engine = render.hide_logs(report(agent=False))
    assert engine.summary is None


def test_a_log_check_that_did_not_answer_stays_visible() -> None:
    from tests.unit.report.kit import request as req
    from tests.unit.report.kit import row as mk

    failed = mk("proxy.host", "timeout", coverage={"timed_out": True})
    got = b.build(inputs([failed], [req("proxy.host", 1)]), UnitPack())
    hidden = render.hide_logs(got)
    (item,) = [i for i in hidden.found.items if i.eids == ("E1",) and i.kind != "still_open"]
    assert (item.kind, item.sentence) == ("failed", "Could not check the host's proxy traffic:"
                                          " the SIEM did not answer in time.")  # fmt: skip
    (check,) = hidden.found.new.checks
    assert (check.outcome, check.why) == ("failed", "the SIEM did not answer in time")
    assert hidden.provenance[0].status == "timeout"


def test_the_text_of_a_report() -> None:
    full = report()
    text = render.text(full)
    assert text == render.text(full)
    for heading in ("Summary (the AI investigator's words)", "What ARGUS found with extra SIEM"
                    " queries: 3 checks, 1.8 s of SIEM server time", "Timeline",
                    "Evidence, read against a true positive", "Hypotheses",
                    "Checked and unknown", "Actions", "Provenance"):  # fmt: skip
        assert heading in text
    assert "Verdict: the AI investigator proposes a true positive" in text
    assert "- E1 · proxy.host@1 · about 10.20.3.4 · squid" in text
    hidden = render.text(render.hide_logs(full))
    assert "- What 2 checks found is hidden: it needs log access in ELK [E1, E3]" in hidden
    assert "The results of 2 log checks are hidden: they need log access in ELK." in hidden
    engine = render.text(report(agent=False))
    assert "Verdict: the decision engine made no proposal" in engine
    assert "Summary" not in engine


def test_control_characters_are_shown_not_obeyed() -> None:
    shown = render.visible("a\u202eb\u200bc\nd\x07")
    assert shown == "a\u2039U+202E\u203ab\u2039U+200B\u203ac\nd\u2039U+0007\u203a"
    text = render.text(report("dest\u202eevil"))
    assert "\u202e" not in text
    assert "U+202E" in text


def test_the_contract() -> None:
    full = report()
    assert full.format == FORMAT == "report@2"
    again = Report.model_validate_json(full.model_dump_json())
    assert again == full
    data = full.model_dump(mode="json")
    data["extra"] = 1
    with pytest.raises(ValidationError):
        Report.model_validate(data)
    with pytest.raises(ValidationError):
        full.verdict.status = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Value(label="a", text="b", count=1, more=2)  # type: ignore[call-arg]
