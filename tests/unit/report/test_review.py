"""Q-F2's adversarial review, unit regressions: the model's explanation in the verdict's
reasons is hidden without log access (F1); hiding never tells a positive log answer from a
zero (F4); ``argus report show --json`` never prints bidi characters raw (F7); a damaged stored
snapshot never breaks a report (F8); untrusted values never reach a value's label (F6)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assess import engine
from argus.outside import facts as outside_facts
from argus.report import build as b
from argus.report import facts as fx
from argus.report import render
from argus.report.model import HIDDEN
from tests.unit.report.kit import request, row
from tests.unit.report.test_build import UnitPack, assessment, inputs
from tests.unit.report.test_render import MARK, TI_ROWS, strings

pytestmark = pytest.mark.unit


def agent_report(log_value: str, outcome: str = "true_positive") -> Any:
    """The reasons as agent@1 stores them (agent.Agent._verdict): [the revealed explanation,
    ARGUS's reason quoting the model, the run's numbers, the run]."""
    aggs = {"destination_count": {"value": 2},
            "destinations": {"buckets": [{"key": log_value, "doc_count": 9}]}}  # fmt: skip
    host = row("proxy.host", snapshot={"rows": [], "aggregations": aggs})
    ti = row("ti.lookup", row_count=1, snapshot={"rows": TI_ROWS})
    explanation = f"The host reached {log_value} every 300 s."
    reasons: list[Any] = [
        explanation,
        f"a cited fact is not in the item ({outcome}): 'reached {log_value}'",
        "2 rounds, 3 model calls (small), $0.0100; tools: none",
        {"kind": "agent@1", "answer": {"outcome": outcome, "explanation": explanation,
                                       "cites": [f"reached {log_value}"], "hypotheses": []},
         "calls": 3, "cost_usd": 0.01, "models": ["p/m"], "seconds": 3},
    ]  # fmt: skip
    a = assessment("agent@1", "no_decision", outcome=None, reasons=reasons)
    return b.build(inputs([host, ti], [request("proxy.host", 1), request("ti.lookup", 2)], a),
                   UnitPack())  # fmt: skip


@given(st.text(max_size=60).map(lambda t: MARK + t))
def test_hide_logs_hides_the_models_explanation_everywhere(value: str) -> None:
    full = agent_report(value)
    assert any(MARK in w for w in full.verdict.why)  # with log access: shown
    hidden = render.hide_logs(full)
    assert hidden.summary is not None
    assert hidden.summary.text == HIDDEN
    assert not [s for s in strings(hidden.model_dump(mode="json")) if MARK in s]
    assert MARK not in render.text(hidden)
    assert hidden.verdict.why[0] == HIDDEN
    assert hidden.verdict.why[1] == f"{b.UNVERIFIED}; the quotes are hidden: {HIDDEN}"


def test_hiding_keeps_argus_own_reasons_and_hides_log_floor_parts() -> None:
    every = {"name": "x", "status": "known", "value": 1}
    sig = [{**every, "name": n} for n in ("ti.listed", "web.successes_after", "ports.risky")]
    sig += [{**every, "name": "proxy.regularity", "value": 0.0},
            {**every, "name": "proxy.hosts_to_destination", "value": 1}]  # fmt: skip
    blocked = engine.floor({"signals": sig, "facts": {"severity": "high"}}, True, True)
    unknown = [{**s, "status": "unknown"} for s in sig]
    blocked += engine.floor({"signals": unknown}, None, None)
    reasons: list[Any] = [
        "It is fine.",
        "floor: " + "; ".join(blocked),
        "the agent could not decide",
        "no usable answer from the model",
    ]
    a = assessment("agent@1", "no_decision", reasons=[*reasons, {"kind": "agent@1"}])
    host = row("proxy.host", snapshot={"rows": [], "aggregations": {}})
    full = b.build(inputs([host], [request("proxy.host", 1)], a), UnitPack())
    why = render.hide_logs(full).verdict.why
    assert why[0] == HIDDEN
    parts = why[1].removeprefix("floor: ").split("; ")
    logs = {"successful answers after the alert", "regular like a beacon",
            "a destination few campus hosts reach", "web.successes_after not known",
            "proxy.regularity not known", "destinations not known"}  # fmt: skip
    assert not logs & set(parts)
    assert set(parts) - {render.FLOOR_HIDDEN} == set(blocked) - logs
    assert parts[-1] == render.FLOOR_HIDDEN
    assert why[2:] == ("the agent could not decide", "no usable answer from the model")
    # without a log answer nothing of the model's could repeat the logs: shown as stored
    failed = row("proxy.host", "timeout", coverage={"timed_out": True})
    plain = b.build(inputs([failed], [request("proxy.host", 1)], a), UnitPack())
    assert render.hide_logs(plain).verdict.why == plain.verdict.why


def test_an_outside_detection_in_the_floor_is_arguss_own_reason_not_log_content() -> None:
    """AR3's floor part says what ARGUS's outside lookup found, not what the logs hold: a person
    without log access still sees why the benign proposal was refused."""
    flag = outside_facts.FLAG
    hit = outside_facts.fact("virustotal", "ip", "8.8.8.8", "found", {"malicious": 7}, 3)
    blocked = engine.floor({"outside": [hit], "facts": {"severity": "low"}}, False, False)
    assert flag in blocked
    assert flag in render.FLOOR_KEPT
    assert render.reason("floor: " + flag) == f"floor: {flag}; {render.FLOOR_HIDDEN}"
    both = "; ".join(["on a threat list", flag, "regular like a beacon"])
    assert render.reason("floor: " + both) == (
        f"floor: on a threat list; {flag}; {render.FLOOR_HIDDEN}"
    )
    reasons: list[Any] = ["It is fine.", "floor: " + flag, {"kind": "agent@1"}]
    a = assessment("agent@1", "no_decision", reasons=reasons)
    host = row("proxy.host", snapshot={"rows": [], "aggregations": {}})
    full = b.build(inputs([host], [request("proxy.host", 1)], a), UnitPack())
    assert render.hide_logs(full).verdict.why[1] == f"floor: {flag}; {render.FLOOR_HIDDEN}"


def _two(n: int) -> Any:
    aggs = {
        "destination_count": {"value": n},
        "destinations": {"buckets": [{"key": "x.example", "doc_count": 9}] if n else []},
    }
    status = "ok" if n else "empty"
    host = row("proxy.host", status, snapshot={"rows": [], "aggregations": aggs})
    return render.hide_logs(b.build(inputs([host], [request("proxy.host", 1)], assessment()),
                                    UnitPack()))  # fmt: skip


def test_hiding_does_not_say_whether_the_logs_found_something() -> None:
    """The same query, a positive and a zero log answer: a person without log access cannot
    tell them apart from the gaps, the evidence table, what was found or the hidden count."""
    some, none = _two(3), _two(0)

    def seen(r: Any) -> Any:
        return (
            sorted((g.key, g.what, g.why, g.who) for g in r.unknowns),
            sorted((x.fact.key, x.fact.status) for x in r.evidence),
            [(i.kind, i.sentence, i.eids, i.note) for i in r.found.items],
            r.found.new.model_dump(),
            [(e.kind, e.sentence, e.eids) for e in r.timeline],
            [p.model_dump() for p in r.provenance],
            r.hidden,
            # the evidence strength's counts are kept by design (decision 10, open risks)
            [x for x in render.text(r).splitlines() if not x.startswith("Evidence strength")],
        )

    a, z = seen(some), seen(none)
    for part, (x, y) in enumerate(zip(a, z, strict=True)):
        assert x == y, part
    assert some.hidden == 1  # one check's result
    (item,) = [i for i in some.found.items if i.kind == "hidden"]
    assert item.eids == ("E1",)


def test_a_log_gap_of_a_failed_check_stays_visible() -> None:
    failed = row("proxy.host", "timeout", coverage={"timed_out": True})
    hidden = render.hide_logs(b.build(inputs([failed], [request("proxy.host", 1)]), UnitPack()))
    gaps = {g.key: g for g in hidden.unknowns}
    assert gaps["signal:proxy.destinations"].why == "the SIEM did not answer in time"
    assert hidden.hidden == 0


def test_the_cli_json_does_not_print_bidi_characters_raw() -> None:
    from argus.report import cli
    from tests.unit.report.test_render import report as rep

    full = rep("dest\u202eevil")
    assert "\u202e" not in cli._shown(full, False, False)
    shown = cli._shown(full, True, False)
    assert "\u202e" not in shown
    assert "dest\\u202eevil" in shown  # escaped, still there


@pytest.mark.parametrize(
    "timeline",
    [
        [{"key": 253402300799000, "doc_count": 1}],  # the last representable second
        [{"key": 1760004000000, "doc_count": "1"}],  # a count that is not a number
        [{"key": 1760004000000, "doc_count": None}, {"key": "x", "doc_count": 2}],
        [{"key": 1760004000000, "doc_count": float("nan")}, {"key": 1e300, "doc_count": 1}],
        [{"key": True, "doc_count": True}],
    ],
)
def test_a_damaged_snapshot_never_breaks_a_report(timeline: list[dict[str, Any]]) -> None:
    aggs = {"destination_count": {"value": 2}, "timeline": {"buckets": timeline},
            "destinations": {"buckets": [{"key": "a", "doc_count": "9"}]}}  # fmt: skip
    host = row("proxy.host", snapshot={"rows": [], "aggregations": aggs})
    got = b.build(inputs([host], [request("proxy.host", 1)], assessment()), UnitPack())
    assert got.provenance
    render.text(got)


def test_an_observer_that_raises_drops_only_its_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_: Any) -> list[Any]:
        raise ZeroDivisionError

    monkeypatch.setitem(fx.OBSERVERS, "proxy.host", ("aggregations", boom))
    host = row("proxy.host", snapshot={"rows": [], "aggregations": {}})
    assert fx.observations(request("proxy.host", 1), host) == []


def test_untrusted_values_never_reach_a_label() -> None:
    hostile = "200\u202e" + "A" * 5000
    rows = [{"_source": {"@timestamp": "2026-10-09T11:20:00Z",
                         "url": {"domain": "d", "path": "/p"},
                         "http": {"response": {"status_code": hostile},
                                  "request": {"method": "GET"}}}}]  # fmt: skip
    web = row("web.followups", row_count=1, snapshot={"rows": rows})
    (fact,) = fx.observations(request("web.followups", 1), web)
    for v in fact.values:
        assert v.label == "answer"
        assert v.text.startswith("200\u202e")
        assert len(v.text) <= fx.VALUE_CHARS
    assert len(fx._value("x" * 500, "v").label) <= fx.LABEL_CHARS


def _other(name: str, ip: str, status: str = "ok", **over: Any) -> Any:
    from argus.gateway.templates import task_key
    from tests.unit.report.kit import T0, T1, TEMPLATES

    cls, _ = TEMPLATES[name]
    params = cls.params_model(ip=ip, start=T0, end=T1)
    return row(name, status, task_key=task_key(cls(), params),
               params=params.model_dump(mode="json"), **over)  # fmt: skip


@pytest.mark.parametrize("name", ["proxy.host", "web.followups"])
def test_the_pack_reads_one_subject_per_template(name: str) -> None:
    """Review F2: a second row of a template (an ask about another host or client) is never
    read as the investigation's; a retry of the dossier's own subject stands in for it."""
    ip = "10.20.3.99" if name == "proxy.host" else "203.0.113.9"
    own, other = row(name), _other(name, ip)
    order = {own.task_key: 1, other.task_key: 2}
    fed, others = b.primary([other, own], {own.task_key}, order)
    assert (fed, others) == ([own], {other.task_key: True})
    # the dossier's own check failed: an ask about another subject does not stand in for it
    failed = row(name, "timeout", coverage={"timed_out": True})
    fed, others = b.primary([other, failed], {failed.task_key}, order)
    assert (fed, others) == ([failed], {other.task_key: True})
    # ... a retry of the same subject (another window) does, and the failure is no other
    retry = row(name, task_key="f" * 64, params={**own.params, "end": "2026-10-09T14:00:00Z"})
    fed, others = b.primary([failed, retry], {failed.task_key}, {**order, "f" * 64: 3})
    assert (fed, others) == ([retry], {failed.task_key: False})
    # no row of the dossier's: the first complete ask, the others named as other subjects
    late = _other(name, "10.20.3.98" if name == "proxy.host" else "203.0.113.8")
    fed, others = b.primary([late, other], set(), {other.task_key: 2, late.task_key: 3})
    assert (fed, others) == ([other], {late.task_key: True})


def test_an_ask_about_another_client_is_its_own_check() -> None:
    other = _other("web.followups", "203.0.113.9", row_count=1, snapshot={"rows": [
        {"_source": {"@timestamp": "2026-10-09T11:20:00Z"}}]})  # fmt: skip
    own = row("web.followups", "empty", snapshot={"rows": []})
    requests = [request("web.followups", 1),
                request("web.followups", 2, "agent", task_key=other.task_key)]  # fmt: skip
    got = b.build(inputs([own, other], requests, assessment(), body=b_body([own])), UnitPack())
    (check,) = [c for c in got.found.new.checks if c.eid == "E2"]
    assert check.sentence.startswith("Checked another client's successful web answers")
    (seen,) = [x.fact for x in got.evidence if x.fact.kind == "observation"]
    assert (seen.eids, seen.sentence[:18]) == (("E2",), "Another client got")
    assert {p.eid: p.subject for p in got.provenance} == {"E1": "185.220.101.5",
                                                          "E2": "203.0.113.9"}  # fmt: skip


def b_body(rows: list[Any]) -> dict[str, Any]:
    from tests.unit.report.test_build import body

    return body([r.ref() for r in rows])
