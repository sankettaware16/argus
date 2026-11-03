"""Q-F2's gate on the synthetic day: report@2 for every assessment; every fact traces to its
evidence row; failed and untrusted checks are never negative; the final view reproduces the
stored dossier; nothing derived from logs reaches a person without log access; the API, the
page and ``argus report`` serve it."""

from __future__ import annotations

import asyncio
import stat
from pathlib import Path
from typing import Any

import httpx
import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.evidence import COMPLETE
from argus.llm.wire import LlmCassette
from argus.report import build as b
from argus.report import facts as fx
from argus.report import render, store
from argus.report.model import HIDDEN, Report
from argus.web import auth
from argus.web.app import create_app
from tests.integration.report import scenario
from tests.integration.report.test_agent_inputs import CASSETTE
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401

pytestmark = pytest.mark.integration

PASSWORD = "correct horse battery"


async def day(engine: AsyncEngine, saver: AsyncPostgresSaver) -> scenario.Day:
    found = await scenario.collect(engine, saver)
    await scenario.assess(engine, found, LlmCassette(CASSETTE))
    return found


async def every_report(engine: AsyncEngine, packs: Any) -> list[tuple[Any, Report]]:
    """report@2 of every assessment of the day, with its assessment row."""
    out = []
    async with engine.connect() as conn:
        found = (await conn.execute(text(
            "SELECT id, investigation_id, assessor, status, version, dossier_hash"
            " FROM assessments ORDER BY id"))).all()  # fmt: skip
        for a in found:
            got = await store.report(conn, a.investigation_id, a.id, packs)
            assert got is not None, a
            out.append((a, got))
    return out


def eids_of(report: Report) -> set[str]:
    out: set[str] = set()
    for item in report.found.items:
        out.update(item.eids)
    new = report.found.new
    for f in new.new_facts:
        out.update(f.eids)
    for c in (*new.now_known, *new.changed, *new.steps_answered):
        out.update(c.eids)
    for g in (*new.gaps_closed, *new.gaps_opened, *report.unknowns):
        out.update(g.eids)
    out.update(c.eid for c in new.checks)
    for e in report.timeline:
        out.update(e.eids)
    for r in report.evidence:
        out.update(r.fact.eids)
    for h in report.hypotheses:
        out.update(e for ref in (*h.support, *h.against) for e in ref.eids)
    if report.summary:
        out.update(e for c in report.summary.cites for e in c.eids)
    return out


async def test_every_assessment_gets_report2(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    reports = await every_report(app_engine, d.packs)
    assert {a.assessor for a, _ in reports} == {"engine@1", "agent@1"}
    assert len(reports) == 8  # the engine and the investigator on each of the 4
    for a, r in reports:
        assert (r.format, r.assessment_id, r.version, r.dossier_hash) == (
            "report@2",
            a.id,
            a.version,
            a.dossier_hash,
        )
        assert r.recomputed is True
        assert (r.verdict.assessor, r.verdict.status) == (a.assessor, a.status)
        assert len(r.hypotheses) >= 2
        assert (r.summary is not None) == (a.assessor == "agent@1")
        leaning = [x.fact for x in r.evidence if x.fact.eids and x.fact.leaning != "neutral"]
        if leaning:  # what the SIEM said for or against: cited by E-id in ARGUS's hypotheses
            cited = {e for h in r.hypotheses[:2] for ref in (*h.support, *h.against)
                     for e in ref.eids}  # fmt: skip
            assert {e for f in leaning for e in f.eids} <= cited
    async with app_engine.connect() as conn:
        for inv in {a.investigation_id for a, _ in reports}:
            current = await store.current(conn, inv, d.packs)
            assert [r.verdict.source for r in current] == ["the AI investigator",
                                                           "the decision engine"]  # fmt: skip


async def test_every_fact_traces_to_its_evidence_row(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    requests = {(r.investigation_id, f"E{r.eid}"): r for r in (await _rows(
        app_engine, "SELECT investigation_id, eid, task_key, template, template_version,"
        " origin FROM evidence_requests"))}  # fmt: skip
    evidence = {(r.investigation_id, r.version, r.task_key): r for r in await _rows(
        app_engine, "SELECT investigation_id, version, task_key, status, row_count,"
        " result_hash, collected_at FROM evidence")}  # fmt: skip
    for a, r in await every_report(app_engine, d.packs):
        shown = {p.eid: p for p in r.provenance}
        assert eids_of(r) <= set(shown), a  # every E-id it shows has its provenance
        assert len(shown) == len(r.provenance)  # unique within the report
        for eid, p in shown.items():
            req = requests[(a.investigation_id, eid)]
            assert p.template == f"{req.template}@{req.template_version}"
            assert p.origin == req.origin
            row = evidence.get((a.investigation_id, a.version, req.task_key))
            if p.status == "missing":
                assert row is None
                continue
            assert row is not None, (eid, p.line)
            if row.status == p.status:
                assert (p.rows, p.result_hash) == (row.row_count, row.result_hash)
            else:  # retried after this assessment: the dossier's own record of it
                assert row.collected_at > a_finished(r)
        for f in [*r.found.new.new_facts, *(x.fact for x in r.evidence)]:
            if not f.eids:
                assert f.kind in ("alert", "signal", "step"), f  # from the stored alerts
            assert f.kind != "observation" or f.eids


def a_finished(r: Report) -> Any:
    assert r.verdict.at is not None
    return r.verdict.at


async def _rows(engine: AsyncEngine, sql: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


async def test_failed_and_untrusted_checks_are_never_negative(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    reports = await every_report(app_engine, d.packs)
    statuses = {}
    for a, r in reports:
        for p in r.provenance:
            statuses[(a.id, p.eid)] = p.status
        for item in r.found.items:
            if item.kind == "nothing_found":
                (eid,) = item.eids
                assert statuses[(a.id, eid)] == "empty"
        for c in r.found.new.checks:
            status = statuses[(a.id, c.eid)]
            if status not in COMPLETE:
                assert c.outcome in ("failed", "not_run", "could_not_tell")
            if c.from_logs and status == "empty":  # log ingest is not measured yet (Q-F1)
                assert c.outcome == "could_not_tell"
            if c.template.startswith("ti.lookup") and status == "empty":
                assert c.outcome == "could_not_tell"  # the lists of the day are stale
    by_rule = {}
    async with app_engine.connect() as conn:
        rules = dict((await conn.execute(text("SELECT id, rule_id FROM investigations"))).all())
    for a, r in reports:
        by_rule[(rules[a.investigation_id], a.assessor)] = r
    engine = by_rule[("c2b", "engine@1")]
    timed_out = [i for i in engine.found.items if i.kind == "failed"]
    assert [i.sentence for i in timed_out] == [
        "Could not check the host's proxy traffic: the SIEM did not answer in time."
    ]
    # evidence is numbered in the order of its requests' content addresses, which name the
    # site's indices: the timed-out read's number is the site's, not a constant
    (eid,) = timed_out[0].eids
    assert f"Check {eid} again." in [x.text for x in engine.actions]
    agent = by_rule[("c2b", "agent@1")]
    assert all(i.kind != "failed" for i in agent.found.items)  # the investigator's retry
    assert any(i.kind == "new" and i.eids == (eid,) for i in agent.found.items)


async def test_the_final_view_reproduces_the_stored_dossier(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    """With the dossier's own evidence, the pack recomputes exactly the stored signals and
    report: the starting and final views are the dossier's, not a new reading of it."""
    d = await day(app_engine, saver)
    async with app_engine.connect() as conn:
        sql = "SELECT investigation_id, version, body, created_at FROM dossiers"
        found = (await conn.execute(text(sql))).all()
        retried = 0
        for row in found:
            got = await store.inputs(conn, row.investigation_id)
            assert got is not None
            mine = {e["task_key"] for e in row.body["evidence"]}
            # the dossier's own evidence: a row retried in place after it is read as it was
            rows = [r for r in fx.as_of(got.evidence, row.body["evidence"], row.version,
                                        row.created_at) if r.task_key in mine]  # fmt: skip
            retried += sum(r.status != x.status for r in rows for x in got.evidence
                           if x.task_key == r.task_key)  # fmt: skip
            start, final, recomputed, note = b.states(d.packs.get(got.pack), row.body, rows)
            assert (recomputed, note) == (True, None)
            stored = sorted([*row.body["local_signals"], *row.body["signals"]],
                            key=lambda s: s["name"])  # fmt: skip
            assert final.signals == stored
            assert final.report == row.body["report"]
            assert all(not s["evidence"] for s in start.signals)
        assert retried == 1  # c2b's timed-out proxy check, answered for the investigator


async def test_a_person_without_log_access_sees_no_log_content(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    hidden_any = 0
    for _, r in await every_report(app_engine, d.packs):
        hidden = render.hide_logs(r)
        told = {p.eid for p in r.provenance if p.from_logs and p.status in COMPLETE}
        # one hidden line per log check that answered; nothing else reads a log answer
        assert sorted(e for i in hidden.found.items if i.kind == "hidden" for e in i.eids) \
            == sorted(told)  # fmt: skip
        for item in hidden.found.items:
            if item.kind == "hidden":
                assert (item.sentence, item.values) == (HIDDEN, ())
            elif item.from_logs:
                assert item.kind in ("failed", "not_checked", "could_not_tell", "still_open")
                assert item.eids
                assert not set(item.eids) & told
        for f in [*hidden.found.new.new_facts, *(x.fact for x in hidden.evidence)]:
            assert not f.from_logs
        assert not [g for g in hidden.unknowns if g.from_logs and set(g.eids) & told]
        for e in hidden.timeline:
            if e.from_logs:  # only ARGUS's own checks, at ARGUS's time
                assert e.kind == "check"
                assert e.sentence == HIDDEN or not set(e.eids) & told
        for h in hidden.hypotheses:
            assert not [ref for ref in (*h.support, *h.against) if ref.from_logs]
        for p in hidden.provenance:
            if p.from_logs:
                assert (p.rows, p.result_hash, p.subject) == (None, None, None)
                assert p.line.endswith("result hidden")
        if hidden.summary is not None and told:
            assert hidden.summary.text == HIDDEN
            assert all(h.name == HIDDEN for h in hidden.hypotheses if h.by == "model")
            assert r.summary is not None
            assert not [w for w in hidden.verdict.why if r.summary.text in w]
        not_logs = [x for x in r.evidence if not x.fact.from_logs]
        assert list(hidden.evidence) == not_logs
        assert hidden.hidden == len(told)
        hidden_any += hidden.hidden
    assert hidden_any > 0


@pytest.mark.usefixtures("cli_env")
async def test_the_api_the_page_and_the_cli(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, tmp_path: Path, web_engine: AsyncEngine
) -> None:
    d = await day(app_engine, saver)
    async with app_engine.begin() as conn:
        await auth.add_user(conn, "asha", "Asha", PASSWORD)
    reports = await every_report(app_engine, d.packs)
    a, expected = next((a, r) for a, r in reports if a.assessor == "agent@1" and r.provenance)
    inv = str(a.investigation_id)
    app = create_app(web_engine, clock=lambda: scenario.AGENT_AT)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1",
                                 headers={"Origin": "http://127.0.0.1"}) as http:  # fmt: skip
        assert (await http.get(f"/api/investigations/{inv}/report")).status_code == 401
        page = await http.get(f"/investigations/{inv}/report")
        assert (page.status_code, page.headers["location"]) == (
            303,
            f"/signin?next=%2Finvestigations%2F{inv}%2Freport",
        )  # Q-A1's sign-in page
        login = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert login.status_code == 200
        got = await http.get(f"/api/investigations/{inv}/report")
        assert got.status_code == 200
        assert Report.model_validate(got.json()) == expected  # the investigator's first
        one = await http.get(f"/api/investigations/{inv}/report", params={"assessment": a.id})
        assert Report.model_validate(one.json()) == expected
        for bad in ({"assessment": 10**9}, {"assessment": 0}, {"assessment": "x"}):
            assert (await http.get(f"/api/investigations/{inv}/report",
                                   params=bad)).status_code in (404, 422)  # fmt: skip
        none = "00000000-0000-0000-0000-000000000000"
        assert (await http.get(f"/api/investigations/{none}/report")).status_code == 404
        html = await http.get(f"/investigations/{inv}/report")
        assert html.status_code == 200
        body = html.text
        assert "What ARGUS found with extra SIEM queries" in body
        assert "Where each fact came from" in body
        for p in expected.provenance:
            assert p.eid in body
        other = await http.get(f"/investigations/{inv}/report", params={"assessment": a.id})
        assert other.status_code == 200
        assert (await http.get(f"/investigations/{none}/report")).status_code == 404
        detail = await http.get(f"/investigations/{inv}")
        assert f'href="/investigations/{inv}/report"' in detail.text
    code, out = await asyncio.to_thread(_invoke, "report", "show", inv)
    assert code == 0, out
    assert out.count("report@2 for investigation") == 2  # the investigator's, the engine's
    assert "What ARGUS found with extra SIEM queries" in out
    code, out = await asyncio.to_thread(_invoke, "report", "show", inv, "--assessment",
                                        str(a.id), "--json", "--hide-logs")  # fmt: skip
    assert code == 0, out
    assert Report.model_validate_json(out).hidden > 0
    code, out = await asyncio.to_thread(_invoke, "report", "show", "nope")
    assert code == 2
    code, out = await asyncio.to_thread(_invoke, "report", "show", none)
    assert code == 1
    target = tmp_path / "sample"
    code, out = await asyncio.to_thread(_invoke, "report", "sample", "--out", str(target),
                                        "--count", "3", "--seed", "s")  # fmt: skip
    assert code == 0, out
    files = sorted(target.iterdir())
    assert len(files) == 3
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    assert all("report@2 for investigation" in f.read_text() for f in files)
    again = tmp_path / "again"
    await asyncio.to_thread(_invoke, "report", "sample", "--out", str(again), "--count", "3",
                            "--seed", "s")  # fmt: skip
    assert [f.name for f in sorted(again.iterdir())] == [f.name for f in files]  # fixed sample


HOSTILE = '<script>window.__pwned=1</script><img src=x onerror="alert(1)">\u202e"'


async def test_hostile_values_are_inert_on_the_page(
    app_engine: AsyncEngine,
    saver: AsyncPostgresSaver,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
) -> None:
    """A destination, a URL and a host name from the logs that are markup or bidi tricks show
    as text: escaped, the control character visible, nothing to run."""
    d = await day(app_engine, saver)
    async with migrated_engine.begin() as conn:  # what a hostile proxy log would have held
        planted = (
            "UPDATE evidence SET snapshot = jsonb_set(snapshot, '{aggregations,urls,buckets}',"
            " jsonb_build_array(jsonb_build_object('key', CAST(:h AS text), 'doc_count', 4)))"
            " WHERE template = 'proxy.destination' AND snapshot ? 'aggregations'"
        )
        await conn.execute(text(planted), {"h": HOSTILE})
        await auth.add_user(conn, "asha", "Asha", PASSWORD)
    reports = await every_report(app_engine, d.packs)
    a, r = next((a, r) for a, r in reports if any(
        HOSTILE in v.text for f in r.found.new.new_facts for v in f.values))  # fmt: skip
    app = create_app(web_engine, clock=lambda: scenario.AGENT_AT)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1",
                                 headers={"Origin": "http://127.0.0.1"}) as http:  # fmt: skip
        await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        page = await http.get(f"/investigations/{a.investigation_id}/report",
                              params={"assessment": a.id})  # fmt: skip
    assert page.status_code == 200
    body = page.text
    assert "<script>window.__pwned" not in body
    assert "<img src=x" not in body
    assert "\u202e" not in body
    assert "&lt;script&gt;window.__pwned=1&lt;/script&gt;" in body
    assert "U+202E" in body
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    text_out = render.text(r)
    assert "\u202e" not in text_out
    assert "\\u202e" in text_out  # a value as written (repr), the character escaped
