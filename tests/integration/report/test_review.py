"""Q-F2's adversarial review, integration regressions on the synthetic day (throwaway
databases only): a second row of a template never replaces the dossier's own facts (F2); a
threat-list hit traces to what found it (F3); the model's explanation is hidden in the
verdict without log access (F1); a check never sent never shows another investigation's
request (F5); a value from the logs is shown as untrusted text on the page (F6)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import graph, proxy
from argus.context.evidence import COMPLETE
from argus.context.graph import Ctx, Gate
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Gateway, Result
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.pgstore import PgStore
from argus.reference.templates import LOOKUP_SIZE, LookupParams, TiLookup
from argus.reference.ti import indicators_of
from argus.report import render
from argus.report import store as report_store
from argus.report.model import HIDDEN
from argus.web import auth
from argus.web.app import create_app
from tests.integration.context.conftest import seed
from tests.integration.context.kit import registry
from tests.integration.report import scenario
from tests.integration.report.test_report import PASSWORD, day, every_report
from tests.unit.gateway.fakes import FakeClock, FakeTransport

pytestmark = pytest.mark.integration


class BeaconSiem:
    """Another campus host's proxy traffic: every ten-minute slot busy (a perfect rhythm)."""

    async def run(self, template: Any, params: Any, **_: Any) -> Result:
        dump = params.model_dump(mode="json")
        start, end = (datetime.fromisoformat(str(dump[k])) for k in ("start", "end"))
        slots = int((end - start) / timedelta(minutes=10))
        buckets = [{"key": int((start + timedelta(minutes=10 * i)).timestamp() * 1000),
                    "doc_count": 5} for i in range(slots)]  # fmt: skip
        aggs = {"destinations": {"buckets": [{"key": "other-dest.example", "doc_count": 5}]},
                "destination_count": {"value": 40}, "bytes": {"value": 1},
                "statuses": {"buckets": []}, "actions": {"buckets": []},
                "timeline": {"buckets": buckets}}  # fmt: skip
        return Result({"aggregations": aggs, "hits": {"hits": []}}, 50,
                      ("acme-logs-squid-2026.10.09",))  # fmt: skip


async def _one(engine: AsyncEngine, sql: str, **p: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), p)).first()


async def test_a_second_row_of_a_template_never_replaces_the_dossiers_own_facts(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    c2 = scenario.by_rule(await scenario.dossiers(app_engine))["c2"]
    inv, version = c2.investigation_id, c2.version
    stored = {s["name"]: s for s in c2.body["signals"]}
    own = next(e for e in c2.body["evidence"] if e["template"].startswith("proxy.host@"))
    agent = await _one(app_engine, "SELECT id FROM assessments WHERE investigation_id = :i"
                       " AND assessor LIKE 'agent%' ORDER BY id DESC LIMIT 1", i=inv)  # fmt: skip
    p = (await _one(app_engine, "SELECT params FROM evidence WHERE investigation_id = :i AND"
                    " version = :v AND task_key = :k", i=inv, v=version,
                    k=own["task_key"])).params  # fmt: skip
    start, end = datetime.fromisoformat(p["start"]), datetime.fromisoformat(p["end"])
    for n in range(1, 250):  # another campus host whose task key sorts before the dossier's
        other = f"10.20.3.{n}"
        spec = TaskSpec(proxy.ProxyHost(), proxy.WindowParams(ip=other, start=start, end=end))
        if spec.ref()["task_key"] < own["task_key"] and other != scenario.HOST:
            break
    ctx = Ctx(engine=app_engine, gateway=BeaconSiem(), packs=d.packs, claim=None,
              deadline=scenario.AGENT_AT + timedelta(minutes=5), clock=lambda: scenario.AGENT_AT,
              gate=Gate(1), origin="agent")  # fmt: skip
    await graph.evidence_step(ctx, inv, version, {**spec.ref(), "mode": "collect"})
    async with app_engine.connect() as conn:
        after = await report_store.report(conn, inv, agent.id, d.packs)
    assert after is not None
    facts = {r.fact.key: r.fact for r in after.evidence}
    own_eid = next(p.eid for p in after.provenance if p.result_hash == own["result_hash"])
    (asked,) = [p for p in after.provenance if p.subject == other]
    assert asked.eid != own_eid
    assert asked.origin == "agent"
    assert f"about {other}" in asked.line
    dests = facts["signal:proxy.destinations"]
    assert f": {stored['proxy.destinations']['value']} destinations" in dests.sentence
    assert dests.eids == (own_eid,)
    assert facts["signal:proxy.regularity"].eids == (own_eid,)
    # the other host's answer: a check of its own, its observations name it as another host
    (check,) = [c for c in after.found.new.checks if c.eid == asked.eid]
    assert check.outcome == "found"
    assert "another campus host" in check.sentence
    seen = [f for f in after.evidence if f.fact.kind == "observation"]
    theirs = [x.fact for x in seen if x.fact.eids == (asked.eid,)]
    assert theirs
    assert all(f.sentence.startswith("Another campus host") for f in theirs)
    assert all(not x.fact.sentence.startswith("Another") for x in seen
               if x.fact.eids == (own_eid,))  # fmt: skip


async def test_a_threat_list_hit_traces_to_what_found_it(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    """c2b's destination is on the abuse-ioc mirror (ARGUS's own store); the live
    acme-threat-intel lookup finds nothing for it."""
    d = await day(app_engine, saver)
    rows = scenario.by_rule(await scenario.dossiers(app_engine))
    c2b = rows["c2b"].investigation_id
    snaps = {}
    async with app_engine.connect() as conn:
        for x in await conn.execute(
            text(
                "SELECT investigation_id, task_key, status, snapshot"
                " FROM evidence WHERE template = 'ti.lookup'"
            )
        ):
            snaps[(x.investigation_id, x.task_key)] = (x.status, x.snapshot)
    checked = 0
    for a, r in await every_report(app_engine, d.packs):
        keys = {p.eid: p for p in r.provenance}
        req = {}
        async with app_engine.connect() as conn:
            for x in await conn.execute(text("SELECT eid, task_key FROM evidence_requests"
                                             " WHERE investigation_id = :i"),
                                        {"i": a.investigation_id}):  # fmt: skip
                req[f"E{x.eid}"] = x.task_key
        for row in r.evidence:
            f = row.fact
            if f.name not in ("ti.listed", "ti.listed_remote") or f.leaning != "suspicious":
                continue
            checked += 1
            assert f.eids or f.source, f  # never "the alerts" for a threat-list hit
            for eid in f.eids:  # every E-id it cites is a complete lookup that lists a value
                assert keys[eid].template.startswith("ti.lookup@")
                status, snap = snaps[(a.investigation_id, req[eid])]
                assert status in COMPLETE
                assert [i for x in snap["rows"] for i in indicators_of(x["_source"])], (eid, f)
            if a.investigation_id == c2b and f.name == "ti.listed":
                assert f.eids == ()
                assert f.source == "ARGUS's stored threat-list answers (abuse-ioc)"
    assert checked >= 2


async def test_hiding_on_the_day_hides_the_models_explanation_in_the_verdict(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    d = await day(app_engine, saver)
    shown, hidden_any = [], 0
    for _, r in await every_report(app_engine, d.packs):
        if r.summary is None:
            continue
        hidden = render.hide_logs(r)
        if hidden.summary is not None and hidden.summary.text == HIDDEN:
            hidden_any += 1
            shown += [w for w in hidden.verdict.why if r.summary.text and r.summary.text in w]
    assert hidden_any
    assert not shown


async def test_a_check_never_sent_shows_no_other_investigations_request(
    app_engine: AsyncEngine,
) -> None:
    a, b = await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r2", "10.0.0.2")])
    clock = FakeClock()
    state = PgStore(app_engine)
    await state.save_health(HealthMemory(state=HealthState.NORMAL, probed_at=clock()))
    gateway = Gateway(FakeTransport(clock=clock), state, clock=clock, sleep=clock.sleep)
    params = LookupParams(values=("45.9.9.9",), size=LOOKUP_SIZE)  # the same indicator
    task = {**TaskSpec(TiLookup(), params).ref(), "mode": "collect"}

    def ctx(no_remote: bool) -> Ctx:
        return Ctx(engine=app_engine, gateway=gateway, packs=registry(), claim=None,
                   deadline=clock() + timedelta(minutes=2), clock=clock, gate=Gate(1),
                   no_remote=no_remote)  # fmt: skip

    await graph.evidence_step(ctx(False), a, 1, task)  # A asks the SIEM: one ledger row
    clock.advance(timedelta(minutes=5))
    ref = await graph.evidence_step(ctx(True), b, 1, task)  # B defers: nothing is sent
    assert ref["status"] == "deferred"
    async with app_engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM siem_requests"))).scalar_one() == 1
        mine = list(await conn.execute(text(report_store._LEDGER), {"i": a, "v": 1}))
        theirs = list(await conn.execute(text(report_store._LEDGER), {"i": b, "v": 1}))
    assert [r.task_key for r in mine] == [task["task_key"]]  # A's request answers A's row
    assert mine[0].indices == ["acme-threat-intel"]
    assert theirs == []  # B's check, never sent, joins nothing


async def test_a_value_from_the_logs_is_untrusted_text_on_the_page(
    app_engine: AsyncEngine,
    saver: AsyncPostgresSaver,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
) -> None:
    hostile = "200\u202e" + "A" * 5000
    d = await day(app_engine, saver)
    async with migrated_engine.begin() as conn:  # what a hostile nginx log would have held
        n = await conn.execute(text(
            "UPDATE evidence SET snapshot = jsonb_set(snapshot,"
            " '{rows,0,_source,http,response,status_code}', to_jsonb(CAST(:h AS text)))"
            " WHERE template = 'web.followups' AND status = 'ok'"), {"h": hostile})  # fmt: skip
        assert n.rowcount >= 1
        await auth.add_user(conn, "asha", "Asha", PASSWORD)
    reports = await every_report(app_engine, d.packs)
    a, _ = next((a, r) for a, r in reports if any(
        "\u202e" in v.text for f in r.found.new.new_facts for v in f.values))  # fmt: skip
    app = create_app(web_engine, clock=lambda: scenario.AGENT_AT)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1",
                                 headers={"Origin": "http://127.0.0.1"}) as http:  # fmt: skip
        await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        page = await http.get(f"/investigations/{a.investigation_id}/report",
                              params={"assessment": a.id})  # fmt: skip
    assert page.status_code == 200
    assert "\u202e" not in page.text  # shown as U+202E, as every other untrusted value
    assert "U+202E" in page.text
    assert "A" * 1000 not in page.text  # capped
