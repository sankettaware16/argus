"""Q-F2: report@2 from its inputs, with a small pack: both views, the findings, the verdict and
summary of each kind of assessment, evidence strength, stances, hypotheses, actions and cost.
Every E-id a report shows is one of its provenance lines."""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, ClassVar

import pytest

from argus.agent import agent
from argus.context.evidence import SignalValue, derived, from_logs, local
from argus.context.packs import Pack
from argus.report import build as b
from argus.report.model import Fact, Report
from tests.unit.report.kit import T1, key_of, request, row

pytestmark = pytest.mark.unit

AGGS = {"destination_count": {"value": 3}, "destinations": {"buckets": [
    {"key": "45.9.9.9", "doc_count": 9}]}}  # fmt: skip
STEP = "Pivot on `source.ip` for the last 24h: how many destinations?"


class UnitPack(Pack):
    """proxy.host gives proxy.destinations (a log count), ti.lookup gives ti.listed_remote;
    one note step asks for a log pivot."""

    name = "unit"
    version = 1
    family = "generic"
    budget: ClassVar[Mapping[Any, int]] = {}

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        return [local("alert_count", 1, facts.get("alert_count"))]

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        out = []
        for key, ref in sorted(evidence.items()):
            snap = snapshots.get(key) or {}
            if str(ref["template"]).startswith("proxy.host@"):
                aggs = snap.get("aggregations") or {}
                out.append(from_logs(derived(
                    "proxy.destinations", 1, [ref],
                    lambda a=aggs: (a.get("destination_count") or {}).get("value"), counts=True,
                )))  # fmt: skip
            if str(ref["template"]).startswith("ti.lookup@"):
                rows = snap.get("rows") or []
                out.append(derived("ti.listed_remote", 1, [ref], lambda r=rows: len(r),
                                   counts=True))  # fmt: skip
        return out

    def report(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        signals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        known = {s["name"]: s["value"] for s in signals if s["status"] == "known"}
        answered = "proxy.destinations" in known
        step = {"number": 1, "text": STEP, "fields": ["source.ip"], "shown": [],
                "status": "answered" if answered else "deferred",
                "sentence": f"Proxy logs: {known.get('proxy.destinations')} destinations."
                if answered else "Not checked yet: needs a search of the web and proxy logs.",
                "needs": [] if answered else ["log_pivot"]}  # fmt: skip
        manual = {"number": 2, "text": "Block it if confirmed.", "fields": [], "shown": [],
                  "status": "manual", "sentence": "For a person to decide or do.",
                  "needs": []}  # fmt: skip
        return {"steps": [step, manual], "alerts_read": 2}


def body(evidence: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    return {
        "facts": {"alert_count": 2, "severity": "high", "first_event_at": "2026-10-09T11:00:00Z",
                  "last_event_at": "2026-10-09T11:30:00Z"},
        "context": {}, "local_signals": [], "signals": [],
        "report": {"steps": [], "alerts_read": 2},
        "evidence": list(evidence),
    }  # fmt: skip


def assessment(assessor: str = "engine@1", status: str = "no_decision", **over: Any) -> Any:
    base: dict[str, Any] = {"id": 7, "assessor": assessor, "status": status, "outcome": None,
                            "confidence": None, "decided_by": f"{assessor}#x",
                            "reasons": ["no key with enough consistent human labels"],
                            "created_at": T1, "finished_at": T1 + timedelta(hours=2)}  # fmt: skip
    base.update(over)
    return b.AssessmentRow(**base)


HOST = row("proxy.host", snapshot={"total": 0, "rows": [], "aggregations": AGGS})
TI = row("ti.lookup", "empty", snapshot={"total": 0, "rows_complete": True, "rows": []})
FAILED = row("proxy.host", "timeout", coverage={"timed_out": True})


def inputs(rows: Sequence[Any], requests: Sequence[Any], a: Any = None, **over: Any) -> b.Inputs:
    base: dict[str, Any] = {"investigation_id": "inv", "version": 1, "pack": "unit@1",
                            "dossier_hash": "d" * 64, "body": body([r.ref() for r in rows]),
                            "evidence": list(rows), "requests": list(requests), "ledger": {},
                            "assessment": a}  # fmt: skip
    base.update(over)
    return b.Inputs(**base)


def eids_shown(report: Report) -> set[str]:
    out: set[str] = set()
    for item in report.found.items:
        out.update(item.eids)
    for e in report.timeline:
        out.update(e.eids)
    for r in report.evidence:
        out.update(r.fact.eids)
    for h in report.hypotheses:
        out.update(e for ref in (*h.support, *h.against) for e in ref.eids)
    for g in report.unknowns:
        out.update(g.eids)
    return out


def test_what_the_siem_queries_found() -> None:
    got = b.build(inputs([HOST, TI], [request("proxy.host", 1), request("ti.lookup", 2)]),
                  UnitPack())  # fmt: skip
    assert got.recomputed is True
    assert [p.eid for p in got.provenance] == ["E1", "E2"]
    assert eids_shown(got) <= {"E1", "E2"}
    kinds = [(i.kind, i.eids) for i in got.found.items]
    assert ("new", ("E1",)) in kinds  # the destination count and its observation
    assert ("could_not_tell", ("E2",)) in kinds  # an empty lookup on an unchecked list
    texts = [i.sentence for i in got.found.items]
    assert "Destinations reached: 3 destinations reached by the host through the proxy" in texts
    assert "Step 1, answered: Proxy logs: 3 destinations." in texts
    new = got.found.new
    assert [c.key for c in new.now_known] == ["signal:proxy.destinations",
                                              "signal:ti.listed_remote"]  # fmt: skip
    assert "On acme-threat-intel: 0 found in acme-threat-intel" not in texts  # a zero
    assert [c.key for c in new.steps_answered] == ["step:1"]
    assert [g.key for g in new.gaps_closed] == ["step:1"]
    assert [c.eid for c in new.checks] == ["E1", "E2"]
    assert (got.found.checks, got.found.server_ms) == (2, 1224)
    assert got.cost.siem_requests == 2


def test_the_starting_view_needs_the_pack() -> None:
    stored = body()
    stored["signals"] = [{"name": "proxy.destinations", "definition_version": 1, "value": 3,
                          "status": "known", "unknown_reason": None, "completeness": "exact",
                          "evidence": [key_of("proxy.host")]},
                         {"name": "alert_count", "definition_version": 1, "value": 2,
                          "status": "known", "unknown_reason": None, "completeness": "exact",
                          "evidence": []}]  # fmt: skip
    got = b.build(inputs([HOST], [request("proxy.host", 1)], body=stored), None)
    assert (got.recomputed, got.note) == (False, "this ARGUS no longer has the pack that made"
                                                 " the dossier")  # fmt: skip
    assert [c.key for c in got.found.new.now_known] == ["signal:proxy.destinations"]

    class Broken(UnitPack):
        def signals(self, *a: Any, **k: Any) -> list[SignalValue]:
            raise KeyError("x")

    broken = b.build(inputs([HOST], [request("proxy.host", 1)], body=stored), Broken())
    assert (broken.recomputed, broken.note) == (False, "the pack could not read the dossier"
                                                       " (KeyError)")  # fmt: skip


def test_purged_evidence_shows_the_dossier_as_stored() -> None:
    """Q-A4: once the retention purge removed a snapshot, nothing is derived from it again."""
    stored = body()
    stored["signals"] = [{"name": "proxy.destinations", "definition_version": 1, "value": 3,
                          "status": "known", "unknown_reason": None, "completeness": "exact",
                          "evidence": [key_of("proxy.host")]}]  # fmt: skip
    purged = row("proxy.host", snapshot=None, purged=True)
    got = b.build(inputs([purged], [request("proxy.host", 1)], body=stored), UnitPack())
    # review A4-R13: plain words for a reviewer, no decision numbers
    assert (got.recomputed, got.note) == (
        False,
        "the log rows behind its evidence were deleted after ARGUS's retention period, so its"
        " findings are shown as they were stored",
    )
    assert "D-" not in got.note
    assert [c.key for c in got.found.new.now_known] == ["signal:proxy.destinations"]
    kept = b.build(inputs([HOST], [request("proxy.host", 1)], body=stored), UnitPack())
    assert kept.recomputed


def test_a_failed_check_and_a_request_made_after_the_assessment() -> None:
    late = request("ti.lookup", 2, created_at=T1 + timedelta(hours=5))  # after it ended
    lost = request("web.followups", 3, created_at=T1)  # nothing stored (unavailable)
    got = b.build(inputs([FAILED], [request("proxy.host", 1), late, lost], assessment()),
                  UnitPack())  # fmt: skip
    assert [p.eid for p in got.provenance] == ["E1", "E3"]
    by = {i.eids: i for i in got.found.items if i.kind != "still_open"}
    assert (by[("E1",)].kind, by[("E3",)].kind) == ("failed", "not_checked")
    assert got.found.checks == 1  # the timed-out request was sent; the lost one was not
    assert all(i.kind != "nothing_found" for i in got.found.items)
    assert "Check E1 again." in [a.text for a in got.actions]
    assert got.strength.grade == "weak"  # no check completed
    every = b.build(inputs([FAILED], [request("proxy.host", 1), late, lost]), UnitPack())
    assert [p.eid for p in every.provenance] == ["E1", "E2", "E3"]  # no end: every request
    other = request("ti.lookup", 2, first_version=2)
    assert [p.eid for p in b.build(inputs([], [other]), UnitPack()).provenance] == []


def test_the_engines_verdict_and_no_summary() -> None:
    got = b.build(inputs([HOST], [request("proxy.host", 1)], assessment()), UnitPack())
    assert got.summary is None
    v = got.verdict
    assert (v.status, v.source, v.model_confidence, v.assessor) == (
        "no_decision",
        "the decision engine",
        None,
        "engine@1",
    )
    assert v.why == ("no key with enough consistent human labels",)
    assert got.relative_to == "true_positive"
    assert got.actions[0].text == "Decide this investigation."
    assert "Do step 2 of the rule's note." in [a.text for a in got.actions]
    assert got.timeline[-1].sentence == "The decision engine made no proposal."
    proposed = assessment(status="proposed", outcome="benign_expected", confidence=1.0,
                          reasons=["key steps / r / 1:answered"])  # fmt: skip
    got = b.build(inputs([HOST], [request("proxy.host", 1)], proposed), UnitPack())
    assert got.verdict.model_confidence is None  # the engine's 1.0 is no model's confidence
    assert got.relative_to == "benign_expected"
    assert got.actions[0].why == "The decision engine proposes benign: expected activity"
    severity = next(r for r in got.evidence if r.fact.key == "alert:severity")
    assert (severity.fact.leaning, severity.stance) == ("suspicious", "contradicts")


def agent_report(**answer: Any) -> dict[str, Any]:
    base = {"outcome": "true_positive", "confidence": 0.8, "explanation": "It beacons.",
            "hypotheses": [{"name": "a beacon", "for": ["Destinations reached: 3"],
                            "against": ["nothing"]}, {"name": ""}, "junk"],
            "cites": ["Destinations reached: 3 destinations"]}  # fmt: skip
    base.update(answer)
    return {"kind": "agent@1", "answer": base, "checks": [], "specialists": [], "rounds": 2,
            "calls": 3, "tiers": [], "models": ["p/m"], "cost_usd": 0.0123,
            "seconds": 41.5}  # fmt: skip


def test_the_agents_summary_hypotheses_and_cost() -> None:
    a = assessment("agent@1", "proposed", outcome="true_positive", confidence=0.8,
                   reasons=["It beacons.", "2 rounds, 3 model calls (small), $0.0123; tools:"
                            " none", agent_report()])  # fmt: skip
    got = b.build(inputs([HOST], [request("proxy.host", 1)], a), UnitPack())
    s = got.summary
    assert s is not None
    every = "Every quote was found in what the model read."
    assert (s.text, s.checked, s.note) == ("It beacons.", True, every)
    assert [(c.quote, c.eids) for c in s.cites] == [("Destinations reached: 3 destinations",
                                                      ("E1",))]  # fmt: skip
    assert got.verdict.why == ("It beacons.",)  # the run's numbers are in the cost
    assert got.verdict.model_confidence == 0.8
    names = [(h.name, h.by) for h in got.hypotheses]
    threat = "A real threat: malicious activity or a compromise (a true positive)"
    assert names[:2] == [(threat, "argus"), ("Expected or harmless activity (benign)", "argus")]
    assert names[2:] == [("a beacon", "model")]
    assert got.hypotheses[2].support[0].eids == ("E1",)
    assert got.hypotheses[2].against[0].eids == ()
    c = got.cost
    assert (c.model_calls, c.model_cost_usd, c.models, c.seconds) == (3, 0.0123, ("p/m",), 41.5)


@pytest.mark.parametrize(
    ("answer", "reasons", "checked", "note"),
    [
        ({"outcome": "inconclusive"}, [], False,
         "The model did not decide, so its quotes were not checked."),
        ({}, [f"{b.UNVERIFIED} (true_positive): 'x'"], False,
         "A quote was not in what the model read: ARGUS withheld its answer."),
        ({"outcome": "benign_expected"}, [f"{b.UNTRUSTED_ONLY}, not only quoted text"], False,
         "It quoted only text from logs or alerts: ARGUS withheld it."),
        ({"cites": []}, [], False, "It quoted nothing."),
    ],
)  # fmt: skip
def test_why_a_summary_was_not_checked(
    answer: dict[str, Any], reasons: list[str], checked: bool, note: str
) -> None:
    a = assessment("agent@1", reasons=[*reasons, agent_report(**answer)])
    s = b.build(inputs([], [], a), UnitPack()).summary
    assert s is not None
    assert (s.checked, s.note) == (checked, note)


def test_agent1s_reasons_are_pinned() -> None:
    """The summary reads agent@1's own reasons for withholding an answer: a change there
    must change report@2 too."""
    source = inspect.getsource(agent)
    assert b.UNVERIFIED in source
    assert b.UNTRUSTED_ONLY in source
    assert b.DETAIL.match("2 rounds, 3 model calls (small), $0.0000; tools: none")


def test_matching_a_quote_to_facts() -> None:
    facts = [Fact(key="signal:a", kind="signal", name="a", status="known", eids=("E2", "E10"),
                  sentence='Destinations reached: 3 destinations "x"')]  # fmt: skip
    assert b.matching("destinations reached: 3", facts) == ("E2", "E10")
    assert b.matching("I saw: Destinations reached: 3 destinations x today", facts) == ("E2", "E10")
    assert b.matching("abc", facts) == ()
    assert b.matching("nothing like it", facts) == ()


def test_strength_grades() -> None:
    complete = b.build(inputs([HOST], [request("proxy.host", 1)]), UnitPack())
    assert complete.strength.grade == "strong"
    assert complete.strength.reasons == (
        "0 of 0 of the signals that block a benign proposal are known",
        "1 of 1 SIEM checks complete",
        "1 of 2 of the rule's steps answered (1 for a person)",
        "all 2 alerts read",
    )
    lost = body([HOST.ref()])
    lost["facts"]["alert_count"] = 5
    partial = b.build(inputs([HOST], [request("proxy.host", 1)], body=lost), UnitPack())
    assert partial.strength.grade == "moderate"
    assert partial.strength.reasons[-1] == "2 of 5 alerts read"


def test_stances_and_the_evidence_tables_order() -> None:
    got = b.build(inputs([HOST], [request("proxy.host", 1)]), UnitPack())
    stances = [r.stance for r in got.evidence]
    assert stances == sorted(stances, key=b.STANCES.__getitem__)
    suspicious = Fact(key="k", kind="alert", name="k", sentence="s", status="known",
                      leaning="suspicious")  # fmt: skip
    calm = suspicious.model_copy(update={"leaning": "reassuring"})
    tp = [b.stance(f, "true_positive") for f in (suspicious, calm)]
    assert tp == ["supports", "contradicts"]
    assert [b.stance(f, "rule_false_positive") for f in (suspicious, calm)] == [
        "contradicts",
        "supports",
    ]
    assert b.stance(suspicious, "inconclusive") == "neutral"
    assert b.relative(b._verdict(None)) == "true_positive"
    none = b.build(inputs([], []), UnitPack())
    assert (none.verdict.status, none.verdict.source) == ("none", "nobody yet")
    assert none.provenance == ()


@pytest.mark.parametrize(
    "report",
    [
        {"kind": "agent@1", "answer": "x", "calls": "many", "cost_usd": float("nan"),
         "models": "m", "seconds": True},
        {"kind": "agent@1", "answer": {"cites": "a quote", "hypotheses": {"name": "h"},
                                       "explanation": None}, "calls": 1e30, "cost_usd": -1},
        {"kind": "agent@1", "answer": {"hypotheses": ["x", {"name": 3, "for": "y"}],
                                       "cites": [1, None]}, "models": [["p"], "q" * 500]},
    ],
)  # fmt: skip
def test_a_malformed_stored_run_never_breaks_a_report(report: dict[str, Any]) -> None:
    a = assessment("agent@1", reasons=["why", report])
    got = b.build(inputs([HOST], [request("proxy.host", 1)], a), UnitPack())
    assert got.summary is not None
    assert got.cost.model_calls >= 0
    assert got.cost.model_cost_usd >= 0
    assert all(len(m) <= 120 for m in got.cost.models)
    assert len(got.hypotheses) >= 2
