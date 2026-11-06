"""P8 (D-091): assessments in the Inbox: the proposal and Accept on an investigation, the
proposals grouped by what decided them with an audit sample and a fenced group confirm, the
tuning reports, the metrics; hostile text stays text."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.tuning import advise
from argus.tuning import store as tuning_store
from argus.tuning.report import RuleReport
from argus.web import assessed, queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN
from tests.integration.web.test_gold import with_dossiers

pytestmark = pytest.mark.integration
H = "a" * 64
EVIL = "<script>window.__pwned=1</script>"


async def propose(engine: AsyncEngine, n: int, decided_by: str, outcome: str = "benign_expected",
                  start: int = 0) -> list[int]:  # fmt: skip
    async with engine.connect() as conn:
        found = (await queries.inbox(conn, "all"))[start : start + n]
    ids = []
    async with engine.begin() as conn:
        for k, inv in enumerate(found):
            assessor = decided_by.split("#")[0]
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, f"{k + start:064x}",
                                assessor, NOW)  # fmt: skip
            (job,) = await queue.claim(conn, "w", NOW, assessor)
            await queue.propose(conn, job, NOW, outcome, decided_by, [f"{EVIL} reason {k}"], 1.0)
            ids.append(job.assessment_id)
    return ids


async def signed_in(client: httpx.AsyncClient) -> None:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})


def flat(html: str) -> str:
    return " ".join(html.split())


def csrf(html: str) -> str:
    return html.split('name="csrf_token" value="')[1].split('"')[0]


async def test_the_proposal_on_an_investigation_and_accept(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 2)
    (aid,) = await propose(seeded, 1, "engine@1#abc: steps / rule-0 / 1:answered")
    async with seeded.connect() as conn:
        inv = (await queries.inbox(conn, "all"))[0]
    await signed_in(client)
    page = (await client.get(f"/investigations/{inv.id}")).text
    assert "The decision engine: proposes <strong>Benign: expected activity</strong>" in flat(page)
    assert "(confidence 100%)" in page
    assert "decided by steps / rule-0 / 1:answered" in page
    assert EVIL not in page
    assert "&lt;script&gt;" in page
    assert f'name="assessment_id" value="{aid}"' in page
    token = csrf(page)
    bad = await client.post(f"/investigations/{inv.id}/accept",
                            data={"assessment_id": aid, "csrf_token": "x"})  # fmt: skip
    assert bad.status_code == 403
    ok = await client.post(f"/investigations/{inv.id}/accept",
                           data={"assessment_id": aid, "csrf_token": token})  # fmt: skip
    assert ok.status_code == 303
    assert ok.headers["location"] == f"/investigations/{inv.id}?saved=accepted"
    shown = (await client.get(ok.headers["location"])).text
    assert "Saved: you accepted ARGUS&#39;s proposal (a confirmed proposal)." in shown
    again = await client.post(f"/investigations/{inv.id}/accept",
                              data={"assessment_id": aid, "csrf_token": token})  # fmt: skip
    assert again.status_code == 409
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT action, outcome, assessment_id FROM review_events"))).all()  # fmt: skip
        audit = (await conn.execute(text(
            "SELECT action, target_id FROM audit_events WHERE action LIKE 'assessment.%'"
        ))).all()  # fmt: skip
    assert rows == [("reviewed", "benign_expected", aid)]
    assert audit == [("assessment.accept", str(aid))]


async def test_no_assessment_and_no_decision(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 2)
    async with seeded.connect() as conn:
        a, b = (await queries.inbox(conn, "all"))[:2]
    async with seeded.begin() as conn:
        await queue.enqueue(conn, b.id, b.version, "generic@12", H, "b" * 64, "agent@1", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.no_decision(conn, job, NOW, "agent@1#openai/m", ["floor: severity high"])
    await signed_in(client)
    plain = (await client.get(f"/investigations/{a.id}")).text
    assert "Not assessed yet." in plain
    none = (await client.get(f"/investigations/{b.id}")).text
    assert "The AI investigator: no proposal" in flat(none)
    assert "<strong>Why.</strong> floor: severity high" in none
    assert "assessment_id" not in none


async def test_proposals_grouped_with_an_audit_sample_and_confirmed_by_group(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 8)
    big = await propose(seeded, 5, "engine@1#abc: field / rule / host.name / web1")
    small = await propose(seeded, 2, "agent@1#openai/m", "true_positive", start=5)
    other = await propose(seeded, 1, "engine@1#def: field / rule / host.name / web2",
                          "benign_policy", start=7)  # fmt: skip
    await signed_in(client)
    listing = (await client.get("/proposals")).text
    assert listing.index("Benign: expected activity: 5 investigations") < listing.index(
        "True positive: 2 investigations")  # largest group first  # fmt: skip
    assert "By the decision engine; decided by field / rule / host.name / web1" in listing
    assert "By the AI investigator on <strong>" in listing
    assert "(models: openai/m)" in listing
    assert "<summary>All 5</summary>" in listing
    assert EVIL not in listing
    async with seeded.connect() as conn:
        groups = await assessed.proposals(conn, date(2026, 10, 9))
        other_day = await assessed.proposals(conn, date(2026, 10, 10))
    assert [len(g.items) for g in groups] == [5, 2, 1]
    assert len(groups[0].sample) == assessed.SAMPLE
    assert sorted(p.assessment_id for p in groups[0].items) == sorted(big)
    assert sorted(p.assessment_id for p in other_day[0].items) == sorted(big)
    token = csrf(listing)
    shown = ",".join(str(i) for i in big[:4])  # the page listed four of them
    form = {"csrf_token": token, "group": groups[0].group,
            "ids": shown + f",{other[0]}"}  # fmt: skip
    sent = await client.post("/proposals/confirm", data=form)
    assert sent.status_code == 303
    assert sent.headers["location"] == "/proposals?confirmed=4-1"  # another group's: skipped
    after = (await client.get(sent.headers["location"])).text
    assert "Confirmed 4; 1 skipped because they changed." in after
    assert "Benign: expected activity: 1 investigation<" in after
    bad = await client.post("/proposals/confirm", data={
        "csrf_token": "x", "group": "d", "ids": "1"})  # fmt: skip
    assert bad.status_code == 403
    # a true positive starts an incident (P4-F): its group offers no "Confirm all", says why, and
    # a crafted post of it is refused with that sentence, nothing accepted (never "they changed")
    tp = next(g for g in groups if g.outcome == "true_positive")
    section = listing.split("True positive: 2 investigations")[1].split("</section>")[0]
    assert "Confirm all" not in section
    assert "decide it on its own page" in section
    assert "Confirm all 5 as" in listing  # the other groups keep theirs
    refused = await client.post("/proposals/confirm", data={
        "csrf_token": token, "group": tp.group, "ids": ",".join(map(str, small))})  # fmt: skip
    assert refused.status_code == 409
    assert "decide it on its own page" in refused.text
    assert "skipped because they changed" not in refused.text
    async with seeded.connect() as conn:
        query = "SELECT count(*) FROM review_events WHERE assessment_id IS NOT NULL"
        accepted = (await conn.execute(text(query))).scalar_one()
        audit = (await conn.execute(text("SELECT details FROM audit_events WHERE action ="
                                         " 'assessment.confirm'"))).scalar_one()  # fmt: skip
    assert accepted == 4
    assert audit == {"accepted": 4, "skipped": 1}


async def test_an_empty_proposals_page(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    await signed_in(client)
    page = (await client.get("/proposals")).text
    assert "No proposal is waiting." in page
    assert (await client.get("/proposals?confirmed=x")).status_code == 200


async def test_the_tuning_page(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    await signed_in(client)
    assert "No report yet" in (await client.get("/tuning")).text
    end = datetime(2026, 10, 16, 12, tzinfo=UTC)
    rep = RuleReport(EVIL, end - timedelta(days=7), end, 900, (), 40, 120, 12, 100,
                     {"rule_false_positive": 5}, {}, ())  # fmt: skip
    got = advise.Advice([advise.Suggestion("exception", "entity.ip", "20.207.73.82",
                                           f"exclude it {EVIL}", "verdicts", ("e1",), "hides")],
                        ["exception: 1 benign"], "openai/m", 0.01)  # fmt: skip
    async with seeded.begin() as conn:
        await tuning_store.save(conn, rep, got)
    page = (await client.get("/tuning")).text
    assert EVIL not in page
    assert "12 of 120 runs hit the alert limit (100)" in page
    assert "Verdicts: Rule false positive 5." in page
    assert "<strong>Exception: entity.ip = 20.207.73.82</strong>" in page
    assert "<summary>1 not kept</summary>" in page


async def test_the_metrics_page(client: httpx.AsyncClient, seeded: AsyncEngine,
                                migrated_engine: AsyncEngine) -> None:  # fmt: skip
    await with_dossiers(seeded, migrated_engine, 2)
    await propose(seeded, 1, "engine@1#abc: k")
    async with seeded.begin() as conn:
        a = (await queries.inbox(conn, "all"))[1]
        await queue.enqueue(conn, a.id, a.version, "generic@12", H, "c" * 64, "agent@1", NOW)
        for row in ({"p": "openai", "o": "rate_limited", "n": 1, "c": 0.0},
                    {"p": "groq", "o": "ok", "n": 2, "c": 0.0},
                    {"p": "-", "o": "blocked", "n": 0, "c": 0.0},
                    {"p": "openai", "o": "ok", "n": 1, "c": 0.25}):  # fmt: skip
            await conn.execute(text(
                "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
                " priority, outcome, http_status, input_tokens, output_tokens, cost_usd,"
                " latency_ms, request_bytes, request_sha256) VALUES (now(), gen_random_uuid(),"
                " :n, :p, 'm', 'small', 'assess', 'normal', :o, 200, 1, 1, :c, 1, 1, '')"),
                row)  # fmt: skip
    await signed_in(client)
    page = (await client.get("/metrics")).text
    assert "Requests the leak validator refused (7 days): 1." in page
    assert "Answers that came from a fallback provider (24 h): 1." in page
    assert (
        '<tr><td>openai</td><td class="num">2</td><td class="num">1</td>'
        '<td class="num">$0.2500</td></tr>'
    ) in page
    assert "<li>agent@1: 1, the oldest for" in page
    assert "engine@1</td><td>Benign: expected activity 1" in page.replace("\n", "")
    async with seeded.connect() as conn:
        m = await assessed.metrics(conn, datetime.now(UTC))
    assert m.month_cost == pytest.approx(0.25)
    assert m.calls["groq"] == (1, 1, 0.0)


def test_keys_and_sources() -> None:
    assert assessed.key_of("engine@1#abc: steps / r / 1:answered") == "steps / r / 1:answered"
    assert assessed.key_of("agent@1#openai/gpt-5.5") == "openai/gpt-5.5"
    assert assessed.key_of("engine@1") == "engine@1"
    assert assessed.key_of(None) == "-"
    assert assessed.source_of("agent@1") == "the AI investigator"
    assert assessed.source_of("engine@1") == "the decision engine"


async def test_the_investigators_proposals_are_grouped_by_rule_and_outcome(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 6)
    async with seeded.connect() as conn:
        found = (await queries.inbox(conn, "all"))[:6]
    async with migrated_engine.begin() as conn:  # two rules (by name, D-081)
        for k, inv in enumerate(found):
            await conn.execute(text("UPDATE investigations SET rule_name = :n WHERE id = :i"),
                               {"n": f"rule {k % 2}", "i": inv.id})  # fmt: skip
    rules = {"rule 0", "rule 1"}
    async with seeded.begin() as conn:
        for k, inv in enumerate(found):
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, f"{k:064x}",
                                "agent@1", NOW)  # fmt: skip
            (job,) = await queue.claim(conn, "w", NOW, "agent@1")
            model = "agent@1#openai/a" if (k // 2) % 2 else "agent@1#openai/b"
            await queue.propose(conn, job, NOW, "true_positive", model, ["r"], 0.8)
    async with seeded.connect() as conn:
        groups = await assessed.proposals(conn, date(2026, 10, 9))
    assert {g.rule for g in groups} == rules
    assert sum(len(g.items) for g in groups) == 6
    for g in groups:
        assert {p.rule for p in g.items} == {g.rule}
        assert g.group == f"agent@1|{g.rule}|true_positive"
    mixed = [g for g in groups if len(g.models) == 2]
    assert mixed  # one rule's group holds both models' answers
    assert mixed[0].models == {"openai/a", "openai/b"}
    other = next(g for g in groups if g is not mixed[0])
    async with seeded.begin() as conn:
        users = (await conn.execute(text("SELECT id FROM users ORDER BY id"))).scalars().all()
        ids = [p.assessment_id for p in mixed[0].items] + [other.items[0].assessment_id]
        got = await assessed.confirm(conn, mixed[0].group, ids, users[0], "n")
    # a true positive starts an incident: never accepted with its group (P4-F U4), every one skipped
    assert got == (0, len(ids))


def test_group_of() -> None:
    assert assessed.group_of("engine@1", "engine@1#f: k", "r", "benign_expected") == "engine@1#f: k"
    assert assessed.group_of("engine@1", None, "r", "x") == "-"
    assert assessed.group_of("agent@1", "agent@1#m", "r", "true_positive") == (
        "agent@1|r|true_positive"
    )


@pytest.fixture
async def shipped_client(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[httpx.AsyncClient]:
    """The app with the shipped model gateway's caps: an installation's ``llm.local.yaml`` (a site's
    sets its own budget) is its own, so the shipped ``llm.yaml`` is read alone."""
    import argus.llm.providers as providers

    shipped = tmp_path / "llm.yaml"
    shipped.write_text(providers.DEFAULT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    load = providers.load_config
    monkeypatch.setattr(providers, "load_config", lambda *_, **__: load(shipped))
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        yield http


async def test_the_cost_bar_and_its_api(
    shipped_client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    client = shipped_client
    assert (await client.get("/api/cost")).status_code == 401
    now = NOW + timedelta(hours=1)  # the app's clock in these tests
    rows = [(now, "openai", 0.25, 1), (now, "groq", 0.0, 1), (now, "openai", 0.0, 0),
            (now - timedelta(days=2), "openai", 1.5, 1),
            (now.replace(day=1, hour=0, minute=0) - timedelta(seconds=1), "openai", 9.0, 1),
            (now + timedelta(minutes=5), "openai", 3.0, 1)]  # fmt: skip
    async with seeded.begin() as conn:
        for at, provider, cost, attempt in rows:
            await conn.execute(text(
                "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
                " priority, outcome, http_status, input_tokens, output_tokens, cost_usd,"
                " latency_ms, request_bytes, request_sha256) VALUES (:at, gen_random_uuid(),"
                " :a, :p, 'm', 'small', 'assess', 'normal', 'ok', 200, 1, 1, :c, 1, 1, '')"),
                {"at": at, "p": provider, "c": cost, "a": attempt})  # fmt: skip
    await signed_in(client)
    got = (await client.get("/api/cost")).json()
    assert got == {
        "month_usd": 1.75, "today_usd": 0.25, "cap_usd": 40.0, "paid_until_usd": 32.0,
        "daily_cap_usd": 1.5, "calls_today": 2,
        "providers": {"groq": {"today_usd": 0.0, "calls": 1},
                      "openai": {"today_usd": 0.25, "calls": 1}},
        "stopped": False, "at": now.isoformat(),
    }  # fmt: skip
    page = (await client.get("/")).text
    assert '<a class="costbar" id="costbar" href="/metrics"' in page
    assert '<script src="/static/cost.js" defer></script>' in page
    script = await client.get("/static/cost.js")
    assert script.status_code == 200
    assert "setInterval(tick, 30000)" in script.text
    async with seeded.begin() as conn:
        await conn.execute(text("UPDATE llm_state SET state = state || '{\"stopped\": true}'"))
    assert (await client.get("/api/cost")).json()["stopped"] is True


async def test_the_full_report_on_the_page(client: httpx.AsyncClient, seeded: AsyncEngine,
                                           migrated_engine: AsyncEngine) -> None:  # fmt: skip
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        inv = (await queries.inbox(conn, "all"))[0]
    report = {"kind": "agent@1", "answer": {
        "outcome": "true_positive", "confidence": 0.8, "explanation": "it beacons",
        "hypotheses": [{"name": "infected", "for": ["regular posts"], "against": []}],
        "cites": ["severity high"]},
        "checks": [{"tool": "proxy.host", "value": "10.0.0.1", "result": "ok"}],
        "specialists": [{"domain": "proxy", "notes": "few destinations"}], "rounds": 2,
        "calls": 3, "tiers": ["small"], "models": ["openai/m"], "cost_usd": 0.0123,
        "seconds": 12.5}  # fmt: skip
    async with seeded.begin() as conn:
        await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, "d" * 64, "agent@1", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.propose(conn, job, NOW, "true_positive", "agent@1#openai/m",
                            ["it beacons", "2 rounds, 3 model calls (small), $0.0123; tools: x",
                             report], 0.8)  # fmt: skip
    await signed_in(client)
    page = flat((await client.get(f"/investigations/{inv.id}")).text)
    assert "The AI investigator: proposes <strong>True positive</strong>" in page
    assert "<strong>Explanation.</strong> it beacons" in page
    assert "<h4>Hypotheses it weighed</h4>" in page
    assert "<td>infected</td><td><div>regular posts</div></td><td>—</td>" in page
    assert "<li><q>severity high</q></li>" in page
    assert '<span class="mono">proxy.host</span> on <span class="mono">10.0.0.1</span>: ok' in page
    assert "<strong>Proxy:</strong> few destinations" in page
    assert "2 rounds, 3 model calls (openai/m), $0.0123, 12.5 s" in page
    assert "2 rounds, 3 model calls (small)" not in page  # the detail line is not repeated
    assert "Ask the AI investigator now" not in page  # it has an answer already


async def test_asking_the_investigator_on_demand(
    client: httpx.AsyncClient,
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
) -> None:
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.llm.conftest import ASSETS

    await with_dossiers(seeded, migrated_engine, 2)
    async with seeded.connect() as conn:
        a, _b = (await queries.inbox(conn, "all"))[:2]
    await signed_in(client)
    page = (await client.get(f"/investigations/{a.id}")).text
    assert "Ask the AI investigator now" not in page  # this app has no privacy layer
    token = csrf(page)
    refused = await client.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
    assert refused.status_code == 503
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        page = (await http.get(f"/investigations/{a.id}")).text
        assert "Ask the AI investigator now" in page
        token = csrf(page)
        assert (await http.post(f"/investigations/{a.id}/assess",
                                data={"csrf_token": "x"})).status_code == 403  # fmt: skip
        asked = await http.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
        assert asked.headers["location"] == f"/investigations/{a.id}?saved=asked"
        shown = flat((await http.get(asked.headers["location"])).text)
        assert "Asked: the AI investigator will look at this within a few minutes." in shown
        assert "The AI investigator: working on it" in shown
        again = await http.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
        assert again.headers["location"] == f"/investigations/{a.id}?saved=asked_exists"
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT assessor, status FROM assessments WHERE investigation_id = :i"),
            {"i": a.id})).all()  # fmt: skip
        audit = (await conn.execute(text(
            "SELECT details->>'result' FROM audit_events WHERE action = 'assessment.request'"
            " ORDER BY id"))).scalars().all()  # fmt: skip
    assert rows == [("agent@1", "queued")]
    assert audit == ["queued", "exists"]


async def test_a_reviewed_investigation_can_still_be_asked_about(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.assess import runner
    from argus.llm.privacy import Privacy, load_policy
    from tests.integration.web.test_reviewed import decide
    from tests.unit.llm.conftest import ASSETS

    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        inv = (await queries.inbox(conn, "all"))[0]
    await decide(seeded, "asha", inv, action="reviewed", outcome="true_positive")
    privacy = Privacy.build(load_policy(), ASSETS)
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "agent@1", NOW) == 0  # never on its own
        assert await runner.request(conn, privacy, inv.id, "agent@1", NOW) == "queued"
        assert await runner.request(conn, privacy, inv.id, "agent@1", NOW) == "exists"
        assert await runner.request(conn, privacy, uuid.uuid4(), "agent@1", NOW) == "no dossier"


async def test_lists_sort_newest_first_and_show_the_ai(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 2)
    await propose(seeded, 1, "agent@1#openai/m", "true_positive")
    await signed_in(client)
    page = flat((await client.get("/?view=all")).text)
    assert "Sorted <strong>newest first</strong> (by the last alert)" in page
    assert '<a href="/?view=all&amp;sort=urgent">most urgent first</a>' in page
    assert (
        '<span class="ai ai-true_positive">True positive</span> <span class="sub">100%</span>'
        in page
    )
    async with seeded.connect() as conn:
        newest = await queries.inbox(conn, "all", sort="newest")
        oldest = await queries.inbox(conn, "all", sort="oldest")
    times = [i.last_event_at for i in newest]
    assert times == sorted(times, reverse=True)
    assert [i.last_event_at for i in oldest] == sorted(times)
    urgent = flat((await client.get("/?view=attention&sort=urgent")).text)
    assert "Sorted <strong>most urgent first</strong>" in urgent
    decided = flat((await client.get("/?view=reviewed")).text)
    assert "Sorted <strong>newest decision first</strong>" in decided
    assert (await client.get("/?sort=bogus")).status_code == 422


def test_plain_words_for_stored_sentences() -> None:
    from argus.web.app import plain

    assert plain("Not checked yet: needs the threat-intel pack (R11).") == (
        "Not checked yet: needs a threat-intelligence lookup."
    )
    assert plain("needs the proxy pack (R12) and the log pivots (R12, R13)") == (
        "needs proxy-log statistics and a search of the web and proxy logs"
    )
    assert plain("an unknown pack (R14) here") == "an unknown pack here"
    assert plain(5) == "5"


@pytest.mark.parametrize("why", ["refused file", "no person requests"])
async def test_asking_needs_an_investigator_that_takes_a_persons_request(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    why: str,
    web_engine: AsyncEngine,
) -> None:
    """Q-H1: the investigator's file says whether a person may start it. A refused file
    (here a specialist widened past code's binding) or one that drops ``person_request``
    hides the button, answers 503 and queues nothing."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED, PINS, Pin
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import FILES, copy, header
    from tests.unit.llm.conftest import ASSETS

    d = copy(tmp_path / "agents")
    if why == "refused file":
        (d / "web.md").write_text(header(FILES["web"], "tools", "[web.followups, ti.lookup]"))
    else:
        edited = header(FILES["investigator"], "triggers", "[engine_no_decision]")
        (d / "investigator.md").write_text(header(edited, "version", "coordinator@4"))
        got = loader.read(d / "investigator.md")
        pins = {
            **PINS,
            "investigator": {"coordinator@4": Pin(got.file_sha256, got.prompt_sha256, "test")},
        }
        enabled = {**ENABLED, "investigator": "coordinator@4"}
        real = loader.allows
        monkeypatch.setattr(loader, "allows", lambda trigger, directory=None, **kw: real(
            trigger, directory, pins=pins, enabled=enabled))  # fmt: skip
    monkeypatch.setattr(loader, "DIRECTORY", d)
    from argus.assess import runner

    async def never(*args: object, **kwargs: object) -> str:
        raise AssertionError("the route refuses before it touches the queue")

    monkeypatch.setattr(runner, "request", never)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        page = (await http.get(f"/investigations/{a.id}")).text
        assert "Ask the AI investigator now" not in page
        token = csrf(page)
        asked = await http.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
        assert asked.status_code == 503
        assert "The AI investigator is not available on this server." in asked.text
    async with seeded.connect() as conn:
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM assessments WHERE investigation_id = :i"), {"i": a.id}
            )
            == 0
        )
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM audit_events WHERE action = 'assessment.request'")
            )
            == 0
        )


async def test_a_file_refused_between_the_check_and_the_queue_queues_nothing(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    web_engine: AsyncEngine,
) -> None:
    """The queue checks the investigator's file again (any route a request comes by): a
    refusal there is the same 503, with nothing queued or audited."""
    from argus.agent import loader
    from argus.llm.privacy import Privacy, load_policy
    from argus.web import app as web_app
    from tests.unit.llm.conftest import ASSETS

    monkeypatch.setattr(web_app, "_investigator_takes_requests", lambda: True)
    monkeypatch.setattr(loader, "allows", lambda trigger, *a, **kw: False)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    app = web_app.create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                             privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        page = (await http.get(f"/investigations/{a.id}")).text
        assert "Ask the AI investigator now" in page
        asked = await http.post(f"/investigations/{a.id}/assess",
                                data={"csrf_token": csrf(page)})  # fmt: skip
        assert asked.status_code == 503
        assert "The AI investigator is not available on this server." in asked.text
    async with seeded.connect() as conn:
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM assessments WHERE investigation_id = :i"), {"i": a.id}
            )
            == 0
        )
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM audit_events WHERE action = 'assessment.request'")
            )
            == 0
        )


@pytest.mark.parametrize("mode", ["control", "agents 0444", "agents 0644", "config 0600"])
async def test_an_unsearchable_agents_directory_never_breaks_a_page(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    web_engine: AsyncEngine,
) -> None:
    """Q-H1: an agents directory that can be listed but not searched (``chmod 644`` on the
    directory), or a parent that cannot be searched: the investigation page still answers
    200 without the ask button, the ask is a 503 and the health page says why (found in
    review: the page answered 500)."""
    import os

    from argus.agent import loader
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import copy
    from tests.unit.llm.conftest import ASSETS

    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    d = copy(tmp_path / "config" / "agents")
    target = d if mode.startswith("agents") else d.parent
    if mode != "control":
        target.chmod(int(mode.split()[1], 8))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    try:
        await with_dossiers(seeded, migrated_engine, 1)
        async with seeded.connect() as conn:
            (a,) = (await queries.inbox(conn, "all"))[:1]
        app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                         privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
            await signed_in(http)
            got = await http.get(f"/investigations/{a.id}")
            assert got.status_code == 200
            assert ("Ask the AI investigator now" in got.text) == (mode == "control")
            asked = await http.post(f"/investigations/{a.id}/assess",
                                    data={"csrf_token": csrf(got.text)})  # fmt: skip
            assert asked.status_code == (303 if mode == "control" else 503)
            health = await http.get("/health")
            assert health.status_code == 200
            api = (await http.get("/api/health")).json()["investigator"]
            if mode == "control":
                assert api == {
                    "ready": True,
                    "state": "ready",
                    "detail": "investigator"
                    " coordinator@4; web, proxy specialist@1; intel specialist@2",
                }
                assert ("its files match the versions pinned in ARGUS's code: investigator"
                        " coordinator@4") in health.text  # fmt: skip
                assert "approved ones" not in health.text  # R2: doctor says whether they are
            else:
                reason = (
                    "intel.md: cannot be read (Permission denied)"
                    if mode.startswith("agents")
                    else "the agents directory cannot be read (Permission denied)"
                )
                assert api == {"ready": False, "state": "refused", "detail": reason}
                assert f"ARGUS refuses its files on this server: {reason}." in health.text
    finally:
        target.chmod(0o755)


async def test_the_health_page_names_a_refused_file(
    seeded: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    web_engine: AsyncEngine,
) -> None:
    """The health page is where a person sees that the AI investigator is off, and why: the
    reason is the loader's, escaped like any other text."""
    from argus.agent import loader
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import FILES, copy, header

    d = copy(tmp_path / "agents")
    (d / "web.md").write_text(header(FILES["web"], "tier", "large"))
    (d / "<script>x.md").write_text("x\n")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        page = (await http.get("/health")).text
        assert '<span class="state state-follow_up">off</span>' in page
        assert "&lt;script&gt;x.md: code binds no agent" in page
        assert "<script>x" not in page
        (d / "<script>x.md").unlink()
        page = (await http.get("/health")).text
        assert "web.md: tier large is above what code allows web (small)." in page
        assert "The decision engine keeps assessing" in page


async def test_a_stray_file_whose_name_is_not_utf8_never_breaks_the_health_pages(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    web_engine: AsyncEngine,
) -> None:
    """R1 (second review): a stray file named with a byte that is not UTF-8 (an archive
    unpacked with Latin-1 names) turns the agent off as any stray file does; the health page
    and /api/health still answer 200 and name it in printable ASCII (they answered 500)."""
    import os

    from argus.agent import loader
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import copy
    from tests.unit.llm.conftest import ASSETS

    d = copy(tmp_path / "agents")

    def stray(raw: bytes) -> None:
        with open(os.path.join(os.fsencode(d), raw), "wb") as f:
            f.write(b"x\n")

    stray(b"investigator\xe9.md")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        assert (await http.get(f"/investigations/{a.id}")).status_code == 200
        health = await http.get("/health")
        api = await http.get("/api/health")
        assert (health.status_code, api.status_code) == (200, 200)
        reason = "investigator\\xe9.md: code binds no agent 'investigator\\xe9'"
        assert api.json()["investigator"] == {"ready": False, "state": "refused",
                                              "detail": reason}  # fmt: skip
        shown = reason.replace("'", "&#39;")
        assert f"ARGUS refuses its files on this server: {shown}." in health.text
        stray(b"a\rb.md")  # sorted first, so its reason is given
        api = await http.get("/api/health")
        assert api.json()["investigator"]["detail"] == "a\\x0db.md: code binds no agent 'a\\x0db'"


async def test_the_health_page_tells_switched_off_from_refused(
    seeded: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    web_engine: AsyncEngine,
) -> None:
    """R2 (second review): an investigator switched off in ARGUS's code is not a file to fix:
    the health page and /api/health say it is switched off, not that its files are refused."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED
    from argus.web.app import create_app

    real = loader.load
    monkeypatch.setattr(loader, "load", lambda directory=None, **kw: real(
        directory, enabled={**ENABLED, "investigator": None}))  # fmt: skip
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        page = (await http.get("/health")).text
        api = (await http.get("/api/health")).json()["investigator"]
    detail = "investigator.md: holds coordinator@4, but investigator is off" \
        " (argus.agent.registry.ENABLED)"  # fmt: skip
    assert api == {"ready": False, "state": "off", "detail": detail}
    assert '<span class="state state-follow_up">off</span> switched off in ARGUS\'s code' in page
    assert detail in page
    assert "refuses its files" not in page
    assert "stays queued until it is switched on again" in page


@pytest.mark.parametrize("why", ["refused file", "no person requests"])
async def test_the_api_v1_ask_needs_an_investigator_that_takes_a_persons_request(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    why: str,
) -> None:
    """Q-H1 x Q-A1 (found merging them): /api/v1's ask queues through ``runner.request``,
    which refuses agent@1 when its files are refused or its file drops ``person_request``.
    The answer is 503 "unavailable" (it was 202 "exists": already assessed, which nothing
    was), and nothing is queued or audited."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED, PINS, Pin
    from argus.llm.privacy import Privacy, load_policy
    from tests.integration.web.test_v1 import V1, app_client, signed
    from tests.unit.agent.test_loader import FILES, copy, header
    from tests.unit.llm.conftest import ASSETS

    d = copy(tmp_path / "agents")
    if why == "refused file":
        (d / "web.md").write_text(header(FILES["web"], "tools", "[web.followups, ti.lookup]"))
    else:
        edited = header(FILES["investigator"], "triggers", "[engine_no_decision]")
        (d / "investigator.md").write_text(header(edited, "version", "coordinator@4"))
        got = loader.read(d / "investigator.md")
        pin = Pin(got.file_sha256, got.prompt_sha256, "test")
        pins = {**PINS, "investigator": {"coordinator@4": pin}}
        enabled = {**ENABLED, "investigator": "coordinator@4"}
        real = loader.allows
        monkeypatch.setattr(loader, "allows", lambda trigger, directory=None, **kw: real(
            trigger, directory, pins=pins, enabled=enabled))  # fmt: skip
    monkeypatch.setattr(loader, "DIRECTORY", d)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    async with app_client(web_engine, privacy=Privacy.build(load_policy(), ASSETS)) as http:
        token = await signed(http)
        asked = await http.post(f"{V1}/investigations/{a.id}/assess", headers=token)
        assert (asked.status_code, asked.json()["code"]) == (503, "unavailable")
    async with seeded.connect() as conn:
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM assessments WHERE investigation_id = :i"), {"i": a.id}
            )
            == 0
        )
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM audit_events WHERE action = 'assessment.request'")
            )
            == 0
        )
