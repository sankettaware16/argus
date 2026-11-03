"""Q-B2: the three ``/api/v1`` operations the new pages need. report@2 of an investigation
(equal to the classic API's, hidden for an account without ``see_logs``), "since your last
visit" (counted from the records, capped, nothing for a first visit) and the dashboard's
threat-list tile (a dossier's ``ti.listed``: unknown and missing are never "clear")."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.report import render as report_render
from argus.report.model import Report
from argus.web import auth, dashboard, queries
from argus.web.app import create_app
from argus.web.capabilities import Capability
from argus.web.params import dashboard_filters
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN, log_in
from tests.integration.web.test_external import plant_dossiers

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
V1 = "/api/v1"


async def sign_in(http: httpx.AsyncClient, user: str) -> None:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text


@pytest.fixture
async def planted(seeded: AsyncEngine) -> AsyncEngine:
    await plant_dossiers(seeded)
    return seeded


async def test_reports_are_report_2_and_equal_the_classic_api(
    client: httpx.AsyncClient, planted: AsyncEngine
) -> None:
    await log_in(client)
    first = (await client.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
    got = await client.get(f"{V1}/investigations/{first['id']}/reports")
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["logs_hidden"] is False
    assert len(body["items"]) >= 1
    report = body["items"][0]
    assert report["format"] == "report@2"
    assert report["investigation_id"] == first["id"]
    classic = await client.get(f"/api/investigations/{first['id']}/report")
    assert classic.status_code == 200
    assert report == classic.json()  # one report, two doors
    Report.model_validate(report)  # and it is the report@2 contract, nothing else


async def test_the_reports_payload_conforms_to_the_committed_contract(
    client: httpx.AsyncClient, planted: AsyncEngine
) -> None:
    """Schemathesis meets an empty list of reports; here a real report is checked against the
    committed spec (what the generated client's types are made from), and so is a hidden one."""
    import jsonschema_rs

    spec = json.loads((ROOT / "docs" / "api" / "openapi-v1.json").read_text(encoding="utf-8"))
    validator = jsonschema_rs.validator_for(
        {"$ref": "#/components/schemas/ReportsOut", "components": spec["components"]}
    )
    await log_in(client)
    first = (await client.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
    body = (await client.get(f"{V1}/investigations/{first['id']}/reports")).json()
    assert body["items"]
    assert list(validator.iter_errors(body)) == []  # a real report, as the spec describes it
    nonsense = {**body, "items": [{**body["items"][0], "extra": 1}]}
    assert list(validator.iter_errors(nonsense))  # the contract refuses a field it does not name


async def test_a_dossier_less_investigation_has_no_report_and_a_stranger_is_a_404(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    await log_in(client)
    first = (await client.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
    got = await client.get(f"{V1}/investigations/{first['id']}/reports")
    assert got.status_code == 200
    assert got.json()["items"] == []
    missing = await client.get(f"{V1}/investigations/{uuid.uuid4()}/reports")
    assert missing.status_code == 404
    assert missing.json()["code"] == "not_found"


async def test_signed_out_is_a_401_for_all_three(client: httpx.AsyncClient) -> None:
    for path in (f"/investigations/{uuid.uuid4()}/reports", "/since", "/dashboard/threat-lists"):
        got = await client.get(V1 + path)
        assert got.status_code == 401, path
        assert got.json()["code"] == "unauthenticated"


async def test_an_account_without_see_logs_gets_the_hidden_report(
    planted: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with planted.begin() as conn:
        await auth.add_user(conn, "vera", "Vera", PASSWORD, capabilities=[Capability.VIEW])
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        await sign_in(http, "vera")
        first = (await http.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
        got = (await http.get(f"{V1}/investigations/{first['id']}/reports")).json()
        assert got["logs_hidden"] is True
        shown = Report.model_validate(got["items"][0])
        async with planted.connect() as conn:
            from argus.report import store as report_store

            (full, *_) = await report_store.current(conn, uuid.UUID(first["id"]))
        assert shown == report_render.hide_logs(full)


LOG_TEXT = "LOGTEXT-secret http://evil.example/a?token=1 from 10.9.9.9"


async def test_an_account_without_see_logs_gets_no_log_text_in_the_investigation_either(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """Review B2-R2: the Overview and AI-assessment tabs read ``/investigations/{id}``, not
    ``/reports``. The AI investigator's run (a check's result, the explanation, the cited facts,
    the hypotheses, the specialists' notes) and its reasons are the model's words over what the
    logs said: hidden, in the report's own words, for an account that cannot read the logs."""
    from argus.report.model import HIDDEN
    from tests.integration.web.test_gold import with_dossiers

    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        inv = (await queries.inbox(conn, "all"))[0]
    run = {
        "kind": "agent@1",
        "answer": {"outcome": "true_positive", "confidence": 0.8, "explanation": LOG_TEXT,
                   "hypotheses": [{"name": LOG_TEXT, "for": [LOG_TEXT], "against": [LOG_TEXT]}],
                   "cites": [LOG_TEXT, LOG_TEXT]},
        "checks": [{"tool": "proxy.host", "value": "10.0.0.1", "result": LOG_TEXT}],
        "specialists": [{"domain": "proxy", "notes": LOG_TEXT}],
        "rounds": 2, "calls": 3, "tiers": ["small"], "models": ["openai/m"], "cost_usd": 0.01,
        "seconds": 1.0,
    }  # fmt: skip
    async with seeded.begin() as conn:
        await queue.enqueue(conn, inv.id, inv.version, "generic@12", "a" * 64, "d" * 64,
                            "agent@1", NOW)  # fmt: skip
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.propose(conn, job, NOW, "true_positive", "agent@1#openai/m",
                            [LOG_TEXT, run], 0.8)  # fmt: skip
        await auth.add_user(conn, "vera", "Vera", PASSWORD, capabilities=[Capability.VIEW])
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as asha,
        httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as vera,
    ):
        await sign_in(asha, "asha")
        full = (await asha.get(f"{V1}/investigations/{inv.id}")).json()["assessments"][0]
        assert full["reasons"] == [LOG_TEXT]  # who may read the logs loses nothing
        assert full["run"]["checks"][0]["result"] == LOG_TEXT
        assert full["run"]["answer"]["explanation"] == LOG_TEXT
        await sign_in(vera, "vera")
        raw = await vera.get(f"{V1}/investigations/{inv.id}")
        assert LOG_TEXT not in raw.text
        assert "evil.example" not in raw.text
        shown = raw.json()["assessments"][0]
    assert shown["reasons"] == [HIDDEN]
    got = shown["run"]
    assert got["checks"] == [{"tool": "proxy.host", "value": "10.0.0.1", "result": HIDDEN}]
    assert got["specialists"] == [{"domain": "proxy", "notes": HIDDEN}]
    assert got["answer"]["explanation"] == HIDDEN
    assert got["answer"]["cites"] == [HIDDEN]
    assert got["answer"]["hypotheses"] == [{"name": HIDDEN, "evidence_for": [],
                                            "evidence_against": []}]  # fmt: skip
    assert (got["answer"]["outcome"], got["rounds"], got["calls"], got["cost_usd"]) == (
        "true_positive",
        2,
        3,
        0.01,
    )  # the verdict and the cost stay, as in the report


async def test_since_counts_from_the_records_and_a_first_visit_has_nothing(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        await sign_in(http, "asha")
        first = (await http.get(f"{V1}/since")).json()
        assert first == {"since": None, "cap": queries.SINCE_CAP, "new_investigations": 0,
                         "new_severe": 0, "reviewed_by_others": 0, "new_proposals": 0}  # fmt: skip
    async with seeded.connect() as conn:
        everything = (await conn.execute(text("SELECT count(*) FROM investigations"))).scalar_one()
        severe = (
            await conn.execute(
                text("SELECT count(*) FROM investigations WHERE severity IN ('critical', 'high')")
            )
        ).scalar_one()
        asha = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'asha'"))
        ).scalar_one()
        ravi = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'ravi'"))
        ).scalar_one()
        long_ago = NOW - timedelta(days=400)
        found = await queries.since(conn, asha, long_ago)
        assert found["new_investigations"] == everything >= 12
        assert found["new_severe"] == severe >= 1
        assert found["reviewed_by_others"] == 0
        assert await queries.since(conn, asha, None) == dict.fromkeys(found, 0)
        tomorrow = datetime.now(UTC) + timedelta(days=1)  # created_at is the real clock's
        assert (await queries.since(conn, asha, tomorrow))["new_investigations"] == 0
    async with seeded.begin() as conn:  # ravi decides two; asha one
        ids = [
            r[0]
            for r in await conn.execute(text("SELECT id FROM investigations ORDER BY id LIMIT 3"))
        ]
        for who, which in ((ravi, ids[0]), (ravi, ids[1]), (asha, ids[2])):
            await conn.execute(
                text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                     " action, outcome) SELECT id, version, alert_count, :u, 'reviewed',"
                     " 'benign_expected' FROM investigations WHERE id = :i"),
                {"u": who, "i": which})  # fmt: skip
    async with seeded.connect() as conn:
        assert (await queries.since(conn, asha, long_ago))["reviewed_by_others"] == 2
        assert (await queries.since(conn, ravi, long_ago))["reviewed_by_others"] == 1


async def test_since_is_capped(seeded: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(queries, "SINCE_CAP", 5)
    async with seeded.connect() as conn:
        found = await queries.since(conn, 1, NOW - timedelta(days=400))
    assert found["new_investigations"] == 5


async def test_the_threat_tile_reads_dossier_signals_and_never_calls_unknown_clear(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        rows = (await queries.inbox(conn, "all"))[:6]
    cases = {
        "hit": {"signals": [{"name": "ti.listed", "status": "known", "value": 2}]},
        "local hit": {"local_signals": [{"name": "ti.listed", "status": "known", "value": 1}]},
        "clear": {"signals": [{"name": "ti.listed", "status": "known", "value": 0}]},
        "unknown": {"signals": [{"name": "ti.listed", "status": "unknown", "value": None}]},
        "weird": {"signals": [{"name": "ti.listed", "status": "known", "value": "many"}]},
        "silent": {"signals": [{"name": "ports.risky", "status": "known", "value": 0}]},
    }
    async with migrated_engine.begin() as conn:
        for row, body in zip(rows, cases.values(), strict=True):
            await conn.execute(
                text("INSERT INTO dossiers (investigation_id, version, pack, facts_version,"
                     " job_id, run_kind, family, status, dossier_hash, body, evidence_count,"
                     " created_at) VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'generic',"
                     " 'evidence_ready', :h, CAST(:b AS jsonb), 0, :t)"),
                {"i": row.id, "v": row.version, "h": "d" * 64, "b": json.dumps(body),
                 "t": NOW},
            )  # fmt: skip
    async with seeded.begin() as conn:  # one of the two on a list also has a proposal
        await queue.enqueue(conn, rows[0].id, rows[0].version, "generic@12", "d" * 64,
                            "1" * 64, "engine@1", NOW)  # fmt: skip
        (job,) = await queue.claim(conn, "w", NOW, "engine@1")
        await queue.propose(conn, job, NOW, "true_positive", "engine@1#k", ["a reason"], 1.0)
    filters = dashboard_filters(range="90d")
    async with seeded.connect() as conn:
        tile = await dashboard.threat_lists(conn, filters, NOW + timedelta(hours=1))
        every = (await conn.execute(text("SELECT count(*) FROM investigations"))).scalar_one()
    assert tile.examined == min(every, dashboard.THREAT_EXAMINED)
    # the six planted answers, wherever the urgent order put them among the examined ones
    assert (tile.on_a_list, tile.clear, tile.could_not_tell) == (2, 1, 2)
    assert tile.not_checked == tile.examined - 5
    assert len(tile.listed) == 2
    assert sorted(c.ai for c in tile.listed) == ["none", "proposed_tp"]  # the 60 get theirs


async def test_a_known_positive_signal_wins_over_an_earlier_one_in_the_same_dossier(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Review B2-R10: a dossier with two ``ti.listed`` signals was read from the first it
    found (the local ones before the others), so a zero or an unknown before a hit hid the hit.
    Any known positive count is "on a list"; otherwise the first signal decides, as before."""
    async with seeded.connect() as conn:
        rows = (await queries.inbox(conn, "all"))[:6]

    def ti(status: str, value: object) -> dict[str, object]:
        return {"name": "ti.listed", "status": status, "value": value}

    cases = [
        {"local_signals": [ti("known", 0)], "signals": [ti("known", 4)]},  # a hit after a zero
        {"local_signals": [ti("unknown", None)], "signals": [ti("known", 3)]},  # ... after unknown
        {"local_signals": [ti("known", 0)], "signals": [ti("known", 0)]},  # clear twice
        {"local_signals": [ti("unknown", None)], "signals": [ti("known", 0)]},  # first decides
        {"local_signals": [ti("known", "many")], "signals": [ti("known", 2)]},  # unreadable first
        {"signals": [ti("known", "1"), ti("known", 5)]},  # both in one list
    ]
    async with migrated_engine.begin() as conn:
        for row, body in zip(rows, cases, strict=True):
            await conn.execute(
                text("INSERT INTO dossiers (investigation_id, version, pack, facts_version,"
                     " job_id, run_kind, family, status, dossier_hash, body, evidence_count,"
                     " created_at) VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'generic',"
                     " 'evidence_ready', :h, CAST(:b AS jsonb), 0, :t)"),
                {"i": row.id, "v": row.version, "h": "d" * 64, "b": json.dumps(body),
                 "t": NOW},
            )  # fmt: skip
    async with seeded.connect() as conn:
        tile = await dashboard.threat_lists(
            conn, dashboard_filters(range="90d"), NOW + timedelta(hours=1)
        )
    assert (tile.on_a_list, tile.clear, tile.could_not_tell) == (4, 1, 1)


async def test_the_threat_tile_over_http_and_with_filters(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    await log_in(client)
    got = await client.get(f"{V1}/dashboard/threat-lists", params={"range": "90d"})
    assert got.status_code == 200, got.text
    body = got.json()
    assert set(body) == {"examined", "on_a_list", "clear", "could_not_tell", "not_checked",
                         "listed"}  # fmt: skip
    assert body["on_a_list"] == 0
    assert body["not_checked"] == body["examined"]  # no dossier yet: not checked, not clear
    shut = await client.get(
        f"{V1}/dashboard/threat-lists", params={"range": "90d", "state": "reviewed"}
    )
    assert shut.json()["examined"] == 0
    bad = await client.get(f"{V1}/dashboard/threat-lists", params={"range": "5y"})
    assert bad.status_code == 422
    assert bad.json()["code"] == "invalid"
