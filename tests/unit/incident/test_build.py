"""The deterministic writer (AR7, D-190): the Amadey-shaped case has every section, the timeline
matches the alerts, every evidence line has a query and a Discover link, the indicators are the
case's, the roles of the Git case's actors are told from counts and order alone, and the same
facts give the same report until the evidence changes."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from urllib.parse import unquote

import pytest

from argus.cases import knownview
from argus.incident import discover
from argus.incident import model as m
from argus.incident.book import uncovered
from argus.incident.build import build, incident_id
from argus.responder import store as responder_store
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def catalogue_ctx(**more: object) -> object:
    return kit.ctx(catalogue=responder_store.current(), **more)


def test_the_amadey_case_has_every_section() -> None:
    report = build(kit.amadey(), catalogue_ctx())
    h = report.header
    assert h.incident_id == "ACME-IR-2026-1026-01"
    assert h.title.startswith(f"{h.incident_id} · ")
    assert h.severity == "high"
    assert h.case_number == 7
    assert "verdict:true-positive" in h.tags
    assert h.tags[0] == h.incident_id
    assert "category:c2-beacon" in h.tags
    assert "status:containment-pending" in h.tags
    assert report.summary.sentences
    assert report.summary.standing == "ongoing"
    assert report.verdict.outcome == "true_positive"
    assert report.verdict.kind == "proposal"
    assert report.verdict.confidence == pytest.approx(0.8)
    assert report.verdict.confidence_words == "medium-high"
    assert report.timeline.first_seen
    assert report.timeline.last_seen
    assert report.timeline.dwell_words == "4 days 19 hours"
    assert report.actors
    assert report.actors[0].role == "campus device"
    assert [a.value for a in report.assets] == [kit.HOST]
    assert report.evidence
    assert report.hypotheses
    assert report.indicators
    assert report.actions.lines
    assert report.actions.close_when is not None
    assert {a.owner for a in report.actions.lines} == {"Network team"}
    assert report.queries
    assert report.out_of_scope
    assert [x.status for x in report.hypotheses[:2]] == ["kept", "ruled_out"]


def test_the_timeline_matches_the_alerts() -> None:
    facts = kit.amadey()
    report = build(facts, kit.ctx())
    t = report.timeline
    assert sum(d.total for d in t.days) == facts.alerts_total == t.alerts == 35
    assert sum(sum(d.counts) for d in t.days) == 35
    assert sum(p.alerts for p in t.phases) == 35
    assert t.first_seen == min(d.first for d in facts.days)
    assert t.last_seen == max(d.last for d in facts.days)
    assert t.dwell_seconds == int((t.last_seen - t.first_seen).total_seconds())
    assert [d.day for d in t.days] == sorted({d.day for d in facts.days})
    assert {p.name for p in t.phases} == {"Rule beacon", "Rule download"}
    assert list(t.columns) == ["Rule beacon", "Rule download"]


def test_every_evidence_line_has_its_query_and_a_discover_link() -> None:
    report = build(kit.amadey(), kit.ctx())
    assert [e.id for e in report.evidence] == ["E1", "E2", "E3", "E4"]
    first, *checks = report.evidence
    assert first.title == "The alerts of the case"
    assert first.count == 35
    assert first.query.kind == "alerts"
    assert "kibana.alert.rule.name" in (first.query.other or "")
    for line in report.evidence:
        q = line.query
        assert q.text
        assert q.index
        assert q.template
        assert q.url.startswith("https://kibana.example/s/acme-soc/app/discover#/?_g=")
        assert "_a=" in q.url
        assert q.time_from < q.time_to
        assert unquote(q.url).count("_g=") == 1
        assert "query:(" in unquote(q.url)
    for line in checks:
        assert line.query.template == "proxy.pair@1"
        assert line.query.index == "acme-logs-squid-*"
        assert f'source.ip == "{kit.HOST}"' in line.query.text
        assert line.from_logs
        assert line.count in (42, 43, 44)
    assert {q.template for q in report.queries} >= {"proxy.pair@1", "alerts"}
    assert any("workflow_tags" in q.text for q in report.queries)  # the case's own tag


def test_a_configured_data_view_makes_the_link_a_kql_link() -> None:
    cfg = discover.Config(
        kibana_url="https://kibana.example", space="s1", views={"squid": "dv-squid-1"}
    )
    report = build(kit.amadey(), kit.ctx(cfg=cfg))
    pair = next(e for e in report.evidence if e.query.template == "proxy.pair@1")
    assert pair.query.language == "kql"
    assert pair.query.text.startswith(f'source.ip : "{kit.HOST}" and destination.ip : "')
    assert "dataViewId:'dv-squid-1'" in unquote(pair.query.url)
    assert (pair.query.other or "").startswith("FROM acme-logs-squid-*")
    alerts = report.evidence[0]
    assert alerts.query.language == "esql"  # no data view for alerts: the ES|QL link


def test_the_indicators_are_the_cases() -> None:
    facts = kit.amadey(devices=3)
    report = build(facts, kit.ctx())
    assert {(i.kind, i.value, i.role) for i in report.indicators} == {
        (i.kind, i.value, i.role) for i in facts.indicators
    }
    assert report.indicators_total == len(facts.indicators) == 7
    server = next(i for i in report.indicators if i.value == kit.SERVERS[0])
    assert "engines flag this IP" in server.evidence
    assert "first seen on campus" in server.evidence


def test_the_same_facts_give_the_same_report_until_the_evidence_changes() -> None:
    facts = kit.amadey()
    one, two = build(facts, kit.ctx()), build(facts, kit.ctx())
    assert one == two
    assert m.content_hash(one) == m.content_hash(two)
    later = build(facts, kit.ctx(as_at=kit.AS_AT + timedelta(hours=1)))
    assert m.content_hash(later) == m.content_hash(one)  # when it was written is no evidence
    assert later.meta.as_at != one.meta.as_at
    quiet = build(facts, kit.ctx(as_at=kit.AS_AT + timedelta(days=9)))
    assert quiet.summary.standing == "quiet"
    assert m.content_hash(quiet) != m.content_hash(one)
    more = replace(facts, alerts_total=36)
    assert m.content_hash(build(more, kit.ctx())) != m.content_hash(one)
    other = build(replace(facts, case=kit.case_row(severity="critical")), kit.ctx())
    assert m.content_hash(other) != m.content_hash(one)


def test_a_notified_case_says_the_notice_state() -> None:
    facts = kit.amadey(notified=True)
    row = knownview.KnownCase(
        facts.case.id, 7, facts.case.title, "open", "high", kit.at(4, 3), None, False, 1, 1, 0,
        6, 3,
        {}, kit.at(2, 8),
    )  # fmt: skip
    notice = knownview.NoticeRow(
        "owner", kit.at(4, 3), "Hostel 5 warden", "phone", False, None, 1, 2
    )
    report = build(replace(facts, known=row, notices=(notice,)), kit.ctx())
    n = report.summary.notice
    assert n is not None
    assert n.notified_at == kit.at(4, 3)
    assert n.alerts_since == 6
    assert n.still_active is False  # the last alert is days before as_at
    assert "Hostel 5 warden" in n.line
    assert "Since then 6 more alerts arrived" in n.line
    assert any(n.line == s.text for s in report.summary.sentences)
    assert "status:monitoring" in report.header.tags
    assert any("stopped after notice" in f.text for f in report.facts)
    active = replace(row, last_alert_at=kit.AS_AT - timedelta(hours=2))
    again = build(replace(facts, known=active, notices=(notice,)), kit.ctx())
    assert again.summary.notice is not None
    assert again.summary.notice.still_active is True
    assert "still active" in again.summary.notice.line


def test_the_git_case_tells_scout_collector_and_prober() -> None:
    report = build(kit.git(), kit.ctx(catalogue=responder_store.current()))
    roles = {a.value: a.role for a in report.actors}
    assert roles == {kit.SCOUT: "scout", kit.COLLECTOR: "collector", kit.PROBER: "prober"}
    collector = next(a for a in report.actors if a.value == kit.COLLECTOR)
    assert collector.requests == 14683
    assert collector.user_agents == ("git-dumper/1.0",)
    assert collector.network == "Example Cloud LLC"
    assert collector.country == "Netherlands"
    assert report.header.severity == "high"
    assert report.header.case_state == "suspected"
    assert "status:triage" in report.header.tags
    assert "category:exposed-file" in report.header.tags
    assert [(a.kind, a.value, a.label) for a in report.assets] == [
        ("directory", "/~hostel5", "home.example.edu")
    ]
    research = next(h for h in report.hypotheses if "research" in h.name)
    assert research.status == "open"  # a served path does not rule out a researcher's scan
    assert report.verdict.kind == "none"
    assert report.verdict.outcome is None


def test_no_dominant_actor_means_no_collector() -> None:
    report = build(kit.git(volumes=(900, 1000, 800)), kit.ctx())
    assert {a.role for a in report.actors} == {"actor"}


def test_a_person_s_review_is_the_verdict_over_arguss() -> None:
    facts = kit.amadey()
    reviewed = tuple(replace(x, reviewed_outcome="benign_expected") for x in facts.members)
    report = build(replace(facts, members=reviewed), kit.ctx())
    assert report.verdict.kind == "person"
    assert report.verdict.outcome == "benign_expected"
    assert report.verdict.confidence is None
    # the review supports "benign" but the flagged servers count against it: not settled; the
    # threat keeps the facts of its own (tests/unit/incident/test_hypotheses.py)
    assert [h.status for h in report.hypotheses[:2]] == ["kept", "open"]


def test_a_reading_is_a_reading_and_a_confirmed_case_without_answers_a_real_problem() -> None:
    facts = kit.amadey(assessed=False)
    assert build(facts, kit.ctx()).verdict.kind == "case"
    reading = [
        {"answer": {"outcome": "true_positive", "confidence": 0.7, "cites": []},
         "reading": {"kind": "undecided", "checked": []}},
    ]  # fmt: skip
    rows = tuple(
        kit.g.AssessmentRow(
            200 + n, kit.inv_id(n), "agent@1", "no_decision", None, None, reading, kit.at(5)
        )
        for n in range(5)
    )
    report = build(replace(facts, assessments=rows), kit.ctx())
    assert report.verdict.kind == "reading"
    assert report.verdict.outcome == "true_positive"
    assert "did not propose" in report.verdict.sentences[0].text
    suspected = build(
        replace(facts, case=kit.case_row(state="suspected", opened_at=None, cause="raised")),
        kit.ctx(),
    )
    assert suspected.verdict.kind == "none"
    assert suspected.header.opened_in.endswith("no person has confirmed it yet")


def test_the_incident_id_counts_the_days_cases() -> None:
    facts = kit.amadey()
    assert incident_id(replace(facts, order=3)) == "ACME-IR-2026-1026-03"


def test_every_sentence_cites_facts_that_state_its_numbers() -> None:
    for facts in (kit.amadey(), kit.amadey(devices=40, notified=True), kit.git()):
        report = build(facts, catalogue_ctx())
        by_id = {f.id: f for f in report.facts}
        assert len(by_id) == len(report.facts)
        for part, sentence in m.sentences_of(report):
            assert sentence.cites, part
            assert not uncovered(sentence, by_id), (part, sentence.text)
        for line in report.evidence:
            assert line.fact in by_id


def test_a_report_that_cites_nothing_is_refused() -> None:
    report = build(kit.amadey(), kit.ctx())
    bad = report.model_dump(mode="json")
    bad["summary"]["sentences"][0]["cites"] = []
    with pytest.raises(ValueError, match="cites no fact"):
        m.IncidentReport.model_validate(bad)
    bad = report.model_dump(mode="json")
    bad["summary"]["sentences"][0]["cites"] = ["F999"]
    with pytest.raises(ValueError, match="not a fact"):
        m.IncidentReport.model_validate(bad)
