"""Q-A1: ``/api/v1`` route by route: what each returns on real records (a full dossier, an AI
investigator's run, the gold set, a tuning report, a coverage gap), what each change does,
and that every error is ``ErrorOut {detail, code}`` that never echoes the input."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.cases import naming
from argus.evaluation import store as gold_store
from argus.web import auth, queries
from argus.web.app import create_app
from argus.web.capabilities import Capability
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
HASH = "c" * 64
V1 = "/api/v1"


def body_for(other: uuid.UUID) -> dict[str, Any]:
    """A dossier as the generic pack stores it (context/generic.py, context/store.py)."""
    return {
        "report": {
            "steps": [
                {"number": 1, "text": "Check the source address", "fields": ["source.ip"],
                 "shown": ["source.ip"], "status": "answered",
                 "sentence": "Answered from the alerts: see source.ip (R12).", "needs": []},
                {"number": 2, "text": "Ask the host's owner", "fields": [], "shown": [],
                 "status": "manual", "sentence": "For a person to decide or do."},
                {"number": 3, "text": "Odd step", "fields": [], "shown": ["nowhere"],
                 "status": "surprising", "sentence": None},
            ],
            "summary": ["3 requests, all answered 404"],
            "has_note": True, "complete": False, "alerts_read": 7,
        },
        "local_signals": [], "signals": [],
        "context": {
            "pack": {
                "fields": {"source.ip": {"top": [["10.0.0.1", 5], ["10.0.0.2", 2]],
                                         "distinct": 3, "from": "client.ip"}},
                "ips": {"10.0.0.1": {"class": "campus", "asset": "lab-pc"},
                        "8.8.8.8": {"class": "public", "asset": None}},
                "web": {"decoded_paths": ["/.env", "/wp-login.php"]},
            },
            "related": [
                {"investigation_id": str(other), "rule_id": "rule-1",
                 "bucket_start": "2026-10-08T18:30:00+00:00", "shared": 2},
                {"investigation_id": "not-a-uuid", "shared": 1},
            ],
        },
    }  # fmt: skip


RUN = {
    "kind": "agent@1",
    "answer": {"outcome": "true_positive", "confidence": 0.75, "explanation": "It beacons.",
               "hypotheses": [{"name": "C2", "for": ["every 300 s"], "against": []}],
               "cites": ["every 300 s"]},
    "checks": [{"tool": "proxy.host", "value": "10.0.0.1", "result": "58 contacts"}],
    "specialists": [{"domain": "proxy", "notes": "periodic"}],
    "rounds": 2, "calls": 3, "tiers": [], "models": ["m-1"], "cost_usd": 0.004, "seconds": 9.5,
}  # fmt: skip


@pytest.fixture
async def rich(seeded: AsyncEngine, migrated_engine: AsyncEngine) -> dict[str, Any]:
    async with seeded.connect() as conn:
        a, b, c = (await queries.inbox(conn, "all"))[:3]
    async with migrated_engine.begin() as conn:
        for inv, body in ((a, body_for(b.id)), (b, {}), (c, {})):
            await conn.execute(
                text(
                    "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                    " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                    " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'generic', 'evidence_ready',"
                    " :h, CAST(:b AS jsonb), 0, :t)"
                ),
                {"i": inv.id, "v": inv.version, "h": HASH, "b": json.dumps(body), "t": NOW},
            )
        await conn.execute(text(
            "INSERT INTO coverage_gaps (kind, subject, start_at, end_at, detail) VALUES"
            " ('argus_collector_lag', 'alerts', :a, :b, 'deferred')"),
            {"a": NOW - timedelta(days=2), "b": NOW + timedelta(days=1)})  # fmt: skip
    async with seeded.begin() as conn:
        await gold_store.import_set(conn, [{
            "investigation_id": str(a.id), "version": a.version, "pack": "generic@12",
            "dossier_hash": HASH, "rule_name": "rule a", "split": "dev", "why": ["a kind"],
            "suggestion": {"outcome": "benign_expected", "reasons": ["no hit"],
                           "source": "signals"}}])  # fmt: skip
        await queue.enqueue(conn, a.id, a.version, "generic@12", HASH, "1" * 64, "agent@1", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.propose(conn, job, NOW, "true_positive", "agent@1#m-1",
                            ["It beacons.", RUN], 0.75)  # fmt: skip
        await queue.enqueue(conn, b.id, b.version, "generic@12", HASH, "2" * 64, "engine@1", NOW)
        (job_b,) = await queue.claim(conn, "w", NOW, "engine@1")
        await queue.propose(
            conn,
            job_b,
            NOW,
            "benign_expected",
            "engine@1#fp: steps / rule-1 / 1:answered",
            ["as before"],
            1.0,
        )
    return {
        "a": a,
        "b": b,
        "c": c,
        "proposal": job.assessment_id,
        "engine_proposal": job_b.assessment_id,
    }


def app_client(engine: AsyncEngine, privacy: Any = None) -> httpx.AsyncClient:
    app = create_app(engine, clock=lambda: NOW + timedelta(hours=1), privacy=privacy)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


async def signed(http: httpx.AsyncClient, user: str = "asha") -> dict[str, str]:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text
    return {"X-CSRF-Token": made.json()["csrf_token"]}


# --------------------------------------------------------------------------- reads


async def test_the_inbox_list(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    async with app_client(web_engine) as http:
        await signed(http)
        page = (await http.get(f"{V1}/investigations", params={"view": "all", "limit": 5})).json()
        assert (page["view"], page["sort"], page["offset"], page["limit"]) == (
            "all",
            "newest",
            0,
            5,
        )
        assert page["has_more"] is True
        assert len(page["items"]) == 5
        rest = (
            await http.get(
                f"{V1}/investigations", params={"view": "all", "offset": 5, "limit": 100}
            )
        ).json()
        assert rest["has_more"] is False
        async with seeded.connect() as conn:
            every = await queries.inbox(conn, "all", sort="newest")
        assert [i["id"] for i in page["items"] + rest["items"]] == [str(s.id) for s in every]
        first = page["items"][0]
        assert set(first) == {
            "id", "rule_id", "rule_name", "title", "key_words", "key_fields", "bucket_start",
            "alert_count", "duplicate_count", "first_event_at", "last_event_at", "severity",
            "risk_score", "version", "created_at", "continues_id", "human_state",
            "latest_review", "new_since_review", "last_outcome", "last_reviewed_at",
            "last_reviewer", "reasons", "ai", "known"}  # fmt: skip
        assert first["key_fields"][0]["field"] == "source.ip"
        # naming v2: the row's two lines come from its own facts, never the rule's name
        flags = [f for f in every[0].raised_flags or () if isinstance(f, str)]
        assert (first["title"], first["key_words"]) == naming.row_title(
            every[0].key_fields, flags, every[0].alert_count
        )
        assert all(i["title"] and i["key_words"] for i in page["items"] + rest["items"])
        by_entity = (await http.get(f"{V1}/investigations", params={
            "view": "all", "kind": "ip", "value": "10.0.0.1"})).json()["items"]  # fmt: skip
        assert by_entity
        assert all(any(k["value"] == "10.0.0.1" for k in i["key_fields"]) for i in by_entity)
        reviewed = (await http.get(f"{V1}/investigations", params={"view": "reviewed"})).json()
        assert (reviewed["sort"], reviewed["items"]) == ("reviewed", [])
        counts = (await http.get(f"{V1}/counts")).json()
        async with seeded.connect() as conn:
            assert counts == await queries.counts(conn, NOW + timedelta(hours=1))


async def test_the_investigation_shows_what_its_page_shows(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    a, b = rich["a"], rich["b"]
    async with app_client(web_engine) as http:
        await signed(http)
        got = (await http.get(f"{V1}/investigations/{a.id}")).json()
    inv = got["investigation"]
    assert (inv["id"], inv["version"], inv["human_state"]) == (str(a.id), a.version, "unreviewed")
    assert inv["ai"] == {
        "assessor": "agent@1",
        "source": "the AI investigator",
        "status": "proposed",
        "outcome": "true_positive",
        "confidence": 0.75,
    }
    (gap,) = got["coverage"]
    assert (gap["kind"], gap["text"]) == (
        "argus_collector_lag",
        "ARGUS was not collecting (the SIEM was busy, so ARGUS waited)",
    )
    d = got["dossier"]
    assert d["facts"] == ["3 requests, all answered 404"]
    assert d["decoded_paths"] == ["/.env", "/wp-login.php"]
    assert sorted(d["addresses"], key=lambda x: x["address"]) == [  # jsonb orders its keys
        {"address": "10.0.0.1", "kind": "campus", "asset": "lab-pc"},
        {"address": "8.8.8.8", "kind": "public", "asset": None},
    ]
    assert [r["investigation_id"] for r in d["related"]] == [str(b.id)]  # the broken id is left
    assert d["related"][0]["rule_name"] == b.rule_name
    assert d["related"][0]["shared"] == 2
    first, second, odd = d["steps"]
    assert first["sentence"] == "Answered from the alerts: see source.ip."  # codes removed
    assert first["shown"] == [{"field": "source.ip", "stand_in": "client.ip", "distinct": 3,
                               "top": [{"value": "10.0.0.1", "count": 5},
                                       {"value": "10.0.0.2", "count": 2}]}]  # fmt: skip
    assert (second["status"], odd["status"], odd["sentence"], odd["shown"]) == (
        "manual",
        "other",
        "",
        [],
    )
    assert (d["has_note"], d["complete"], d["alerts_read"]) == (True, False, 7)
    (assessment,) = got["assessments"]
    assert assessment["run"]["answer"]["hypotheses"] == [
        {"name": "C2", "evidence_for": ["every 300 s"], "evidence_against": []}
    ]
    assert assessment["run"]["checks"] == [
        {"tool": "proxy.host", "value": "10.0.0.1", "result": "58 contacts"}
    ]
    assert (assessment["run"]["rounds"], assessment["run"]["models"]) == (2, ["m-1"])
    assert got["acceptable_assessment_id"] == rich["proposal"]
    assert got["ask_available"] is False  # this app has no privacy layer
    assert got["gold"]["split"] == "dev"
    assert got["gold"]["outcome"] is None
    assert got["gold"]["suggestion"] == {
        "outcome": "benign_expected",
        "source": "signals",
        "reasons": ["no hit"],
    }
    assert got["reviews"] == []
    assert {"field": "source.ip", "count": inv["alert_count"]} in got["alert_fields"]


async def test_alerts_and_their_columns(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    a = rich["a"]
    path = f"{V1}/investigations/{a.id}/alerts"
    async with app_client(web_engine) as http:
        await signed(http)
        default = (await http.get(path)).json()
        assert default["columns"] == ["source.ip"]  # the fields the rule's steps name
        assert default["total"] == a.alert_count == len(default["items"])
        assert all(set(r["cells"]) == {"source.ip"} for r in default["items"])
        none = (await http.get(path, params={"columns": ""})).json()
        assert none["columns"] == []
        assert all(r["cells"] == {} for r in none["items"])
        chosen = (await http.get(path, params={"columns": "host.name,nope,host.name"})).json()
        assert chosen["columns"] == ["host.name"]
        classic = (await http.get(f"/api/investigations/{a.id}")).json()["alerts"]
        assert [r["alert_id"] for r in default["items"]] == [r["alert_id"] for r in classic]
        alert_id = classic[0]["alert_id"]
        raw = (await http.get(f"{path}/{alert_id}")).json()
        same = (await http.get(f"/api/investigations/{a.id}/alerts/{alert_id}/raw")).json()
        assert raw == {"alert_id": alert_id, "investigation_id": str(a.id), "raw": same}
        missing = await http.get(f"{path}/nope")
        assert (missing.status_code, missing.json()) == (
            404,
            {"detail": "no such alert in this investigation", "code": "not_found"},
        )
        gone = await http.get(f"{V1}/investigations/{uuid.uuid4()}/alerts")
        assert gone.json() == {"detail": "no such investigation", "code": "not_found"}


async def test_the_other_reads_equal_their_pages_data(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with app_client(web_engine) as http:
        await signed(http)
        rules = (await http.get(f"{V1}/rules")).json()
        assert {r["rule_id"] for r in rules} == {
            r["rule_id"] for r in (await http.get("/api/rules")).json()
        }
        entities = (await http.get(f"{V1}/entities")).json()
        assert [(e["kind"], e["value"]) for e in entities] == [
            (e["kind"], e["value"]) for e in (await http.get("/api/entities")).json()
        ]
        health = (await http.get(f"{V1}/health")).json()
        classic = (await http.get("/api/health")).json()
        assert {k: health[k] for k in ("alerts", "investigations", "dossiers")} == {
            k: classic[k] for k in ("alerts", "investigations", "dossiers")
        }
        cost = (await http.get(f"{V1}/cost")).json()
        assert {k: v for k, v in cost.items() if k != "providers"} == {
            k: v for k, v in (await http.get("/api/cost")).json().items() if k != "providers"
        } | {"at": cost["at"]}
        glossary = (await http.get(f"{V1}/glossary")).json()
        assert glossary == queries.glossary()
        gold = (await http.get(f"{V1}/gold")).json()
        assert gold["progress"] == {"items": 1, "answered": 0,
                                    "by_split": {"dev": 0, "test": 0}}  # fmt: skip
        assert [g["investigation_id"] for g in gold["items"]] == [str(rich["a"].id)]
        metrics = (await http.get(f"{V1}/metrics")).json()
        assert {o["assessor"] for o in metrics["outcomes"]} == {"agent@1", "engine@1"}
        assert (await http.get(f"{V1}/tuning")).json() == []
        proposals = (await http.get(f"{V1}/proposals")).json()
        assert sorted(g["outcome"] for g in proposals) == ["benign_expected", "true_positive"]
        agent = next(g for g in proposals if g["rule"] is not None)
        assert (agent["size"], agent["models"]) == (1, ["m-1"])
        assert agent["sample"][0]["assessment_id"] == rich["proposal"]
        board = (await http.get(f"{V1}/dashboard", params={"range": "30d"})).json()
        classic_board = (await http.get("/api/dashboard", params={"range": "30d"})).json()
        assert board["kpis"]["investigations"] == classic_board["kpis"]["cases"]
        assert {k: v for k, v in board["kpis"].items() if k != "investigations"} == {
            k: v for k, v in classic_board["kpis"].items() if k != "cases"
        }
        assert [i["id"] for i in board["open_investigations"]] == classic_board["open_cases"]
        assert [i["id"] for i in board["incidents"]] == classic_board["incidents"]
        assert board["filters"]["range"] == "30d"
        assert board["bucket"] == "day"


# --------------------------------------------------------------------------- changes


async def test_reviews_through_v1(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    a, c = rich["a"], rich["c"]
    path = f"{V1}/investigations/{c.id}/reviews"
    async with app_client(web_engine) as http:
        token = await signed(http)
        base = {"seen_review": None, "seen_version": c.version}
        made = await http.post(path, json={"action": "note", "note": "first", **base},
                               headers=token)  # fmt: skip
        assert made.status_code == 201
        first = made.json()
        assert set(first) == {"review_id", "version", "gold_saved"}
        stale = await http.post(path, json={"action": "reviewed", "outcome": "true_positive",
                                            **base}, headers=token)  # fmt: skip
        assert (stale.status_code, stale.json()["code"]) == (409, "conflict")
        done = await http.post(path, json={"action": "reviewed", "outcome": "benign_policy",
                                           "seen_review": first["review_id"],
                                           "seen_version": c.version}, headers=token)  # fmt: skip
        assert done.status_code == 201
        detail = (await http.get(f"{V1}/investigations/{c.id}")).json()
        assert detail["investigation"]["human_state"] == "reviewed"
        assert [(r["action"], r["outcome"], r["reviewer"]) for r in detail["reviews"]] == [
            ("reviewed", "benign_policy", "Asha"),
            ("note", None, "Asha"),
        ]
        nowhere = await http.post(
            f"{V1}/investigations/{uuid.uuid4()}/reviews",
            json={"action": "note", "note": "x", **base},
            headers=token,
        )
        assert (nowhere.status_code, nowhere.json()["code"]) == (404, "not_found")
        gold = await http.post(f"{V1}/investigations/{a.id}/reviews", headers=token, json={
            "action": "follow_up", "outcome": "true_positive", "also_gold": True,
            "seen_review": None, "seen_version": a.version})  # fmt: skip
        assert (gold.status_code, gold.json()["gold_saved"]) == (201, True)
        plain = await http.post(f"{V1}/investigations/{c.id}/reviews", headers=token, json={
            "action": "note", "note": "after", "seen_review": done.json()["review_id"],
            "seen_version": c.version})  # fmt: skip
        assert plain.json()["gold_saved"] is False
    async with seeded.connect() as conn:
        item = await gold_store.item(conn, a.id)
    assert item is not None
    assert item.outcome == "true_positive"


@pytest.mark.parametrize(
    "body",
    [
        {"action": "reviewed", "seen_review": None, "seen_version": 1},  # no outcome
        {"action": "reviewed", "outcome": "guilty", "seen_review": None, "seen_version": 1},
        {"action": "note", "seen_review": None, "seen_version": 1},  # no note
        {"action": "note", "note": "", "seen_review": None, "seen_version": 1},
        {"action": "note", "note": "x" * 4001, "seen_review": None, "seen_version": 1},
        {"action": "note", "note": "a\x00b", "seen_review": None, "seen_version": 1},
        {"action": "note", "note": "x", "seen_review": True, "seen_version": 1},
        {"action": "note", "note": "x", "seen_review": "3", "seen_version": 1},
        {"action": "note", "note": "x", "seen_review": None, "seen_version": -1},
        {"action": "note", "note": "x", "seen_review": None, "seen_version": 1, "user_id": 7},
        {"action": "reviewed", "outcome": "true_positive", "seen_review": None,
         "seen_version": 1, "also_gold": "yes"},
        {"action": "approve", "seen_review": None, "seen_version": 1},
        [],
    ],
)  # fmt: skip
async def test_invalid_reviews_are_refused_without_echoing_them(
    seeded: AsyncEngine, body: Any, web_engine: AsyncEngine
) -> None:
    async with app_client(web_engine) as http:
        token = await signed(http)
        inv = (await http.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
        got = await http.post(f"{V1}/investigations/{inv['id']}/reviews", json=body,
                              headers=token)  # fmt: skip
    assert got.status_code == 422
    assert set(got.json()) == {"detail", "code"}
    assert got.json()["code"] == "invalid"
    if isinstance(body, dict) and isinstance(body.get("note"), str) and len(body["note"]) > 3:
        assert body["note"] not in got.json()["detail"]


async def test_gold_answers_accept_and_ask(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    from argus.llm.privacy import Privacy, load_policy
    from tests.unit.llm.conftest import ASSETS

    a, b, c = rich["a"], rich["b"], rich["c"]
    async with seeded.begin() as conn:
        await auth.add_user(conn, "vera", "Vera", PASSWORD,
                            capabilities=[Capability.VIEW, Capability.REVIEW])  # fmt: skip
    async with app_client(web_engine) as http:
        token = await signed(http)
        saved = await http.post(f"{V1}/investigations/{a.id}/gold", headers=token,
                                json={"outcome": "benign_policy", "note": "  why  "})  # fmt: skip
        assert (saved.status_code, saved.json()) == (200, {"next_investigation_id": None})
        outside = await http.post(f"{V1}/investigations/{c.id}/gold", headers=token,
                                  json={"outcome": "benign_policy"})  # fmt: skip
        assert outside.json() == {"detail": "this investigation is not in the gold set",
                                  "code": "not_found"}  # fmt: skip
        elsewhere = await http.post(f"{V1}/investigations/{c.id}/accept", headers=token,
                                    json={"assessment_id": rich["proposal"]})  # fmt: skip
        assert (elsewhere.status_code, elsewhere.json()["code"]) == (404, "not_found")
        accepted = await http.post(f"{V1}/investigations/{a.id}/accept", headers=token,
                                   json={"assessment_id": rich["proposal"]})  # fmt: skip
        assert accepted.json() == {"assessment_id": rich["proposal"],
                                   "investigation_id": str(a.id)}  # fmt: skip
        again = await http.post(f"{V1}/investigations/{a.id}/accept", headers=token,
                                json={"assessment_id": rich["proposal"]})  # fmt: skip
        assert (again.status_code, again.json()["code"]) == (409, "conflict")
        off = await http.post(f"{V1}/investigations/{b.id}/assess", headers=token)
        assert (off.status_code, off.json()["code"]) == (503, "unavailable")
    async with app_client(web_engine, privacy=Privacy.build(load_policy(), ASSETS)) as http:
        token = await signed(http)
        asked = await http.post(f"{V1}/investigations/{b.id}/assess", headers=token)
        assert (asked.status_code, asked.json()) == (202, {"result": "queued"})
        twice = await http.post(f"{V1}/investigations/{b.id}/assess", headers=token)
        assert twice.json() == {"result": "exists"}
        bare = await queries_first_without_dossier(seeded)
        not_ready = await http.post(f"{V1}/investigations/{bare}/assess", headers=token)
        assert (not_ready.status_code, not_ready.json()["code"]) == (409, "not_ready")
        unknown = await http.post(f"{V1}/investigations/{uuid.uuid4()}/assess", headers=token)
        assert unknown.json()["code"] == "not_found"
    async with app_client(web_engine) as http:  # vera reviews, but answers no gold items
        token = await signed(http, "vera")
        refused = await http.post(f"{V1}/investigations/{a.id}/gold", headers=token,
                                  json={"outcome": "benign_policy"})  # fmt: skip
        assert (refused.status_code, refused.json()["code"]) == (403, "forbidden")
        also = await http.post(f"{V1}/investigations/{c.id}/reviews", headers=token, json={
            "action": "reviewed", "outcome": "benign_policy", "also_gold": True,
            "seen_review": None, "seen_version": c.version})  # fmt: skip
        assert (also.status_code, also.json()["code"]) == (403, "forbidden")
    async with seeded.connect() as conn:
        written = (await conn.execute(text(
            "SELECT count(*) FROM review_events WHERE investigation_id = :c"),
            {"c": c.id})).scalar_one()  # fmt: skip
    assert written == 0  # the refused review wrote nothing


async def queries_first_without_dossier(engine: AsyncEngine) -> uuid.UUID:
    async with engine.connect() as conn:
        found: uuid.UUID = (await conn.execute(text(
            "SELECT id FROM investigations i WHERE NOT EXISTS (SELECT 1 FROM dossiers d"
            " WHERE d.investigation_id = i.id) LIMIT 1"))).scalar_one()  # fmt: skip
    return found


async def test_group_changes(
    rich: dict[str, Any], seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with app_client(web_engine) as http:
        token = await signed(http)
        groups = (await http.get(f"{V1}/proposals")).json()
        engine_group = next(g for g in groups if g["rule"] is None)
        other = await http.post(f"{V1}/proposals/confirm", headers=token, json={
            "group": "not this one", "assessment_ids": [rich["engine_proposal"]]})  # fmt: skip
        assert other.json() == {"accepted": 0, "skipped": 1}
        done = await http.post(
            f"{V1}/proposals/confirm",
            headers=token,
            json={"group": engine_group["group"], "assessment_ids": [rich["engine_proposal"]]},
        )
        assert done.json() == {"accepted": 1, "skipped": 0}
        too_many = await http.post(f"{V1}/proposals/confirm", headers=token, json={
            "group": "g", "assessment_ids": list(range(1, 502))})  # fmt: skip
        assert too_many.status_code == 422
        page = (await http.get(f"{V1}/patterns")).json()
        patterns = page["groups"]
        assert (page["limit"], page["sampled"]) == (2000, False)
        async with seeded.connect() as conn:
            classic = await queries.patterns(conn)
        assert [[m["investigation_id"] for m in p["members"]] for p in patterns] == [
            [m["id"] for m in p["members"]] for p in classic
        ]
        some = (await http.get(f"{V1}/investigations", params={"view": "open", "limit": 3})).json()[
            "items"
        ]
        items = [{"investigation_id": i["id"], "version": i["version"],
                  "latest_review": i["latest_review"]} for i in some]  # fmt: skip
        items[-1]["version"] += 1  # changed since it was shown
        reviewed = await http.post(f"{V1}/patterns/review", headers=token,
                                   json={"outcome": "benign_expected", "items": items})  # fmt: skip
        assert reviewed.json() == {"reviewed": 2, "changed": 1}
        empty = await http.post(f"{V1}/patterns/review", headers=token,
                                json={"outcome": "benign_expected", "items": []})  # fmt: skip
        assert empty.status_code == 422


# --------------------------------------------------------------------------- errors


async def test_every_error_is_error_out(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    async with app_client(web_engine) as http:
        assert (await http.get(f"{V1}/rules")).json() == {
            "detail": "sign in first",
            "code": "unauthenticated",
        }
        token = await signed(http)
        unknown = await http.get(f"{V1}/nothing/here")
        assert (unknown.status_code, unknown.json()) == (
            404,
            {"detail": "no such thing here", "code": "not_found"},
        )
        wrong = await http.put(f"{V1}/session", headers=token)
        assert (wrong.status_code, wrong.json()["code"]) == (405, "method_not_allowed")
        assert wrong.headers["allow"] == "DELETE, GET"  # every method of the path
        options = await http.options(f"{V1}/investigations/{uuid.uuid4()}/reviews")
        assert (options.status_code, options.headers["allow"]) == (405, "POST")
        bad_view = await http.get(f"{V1}/investigations", params={"view": "secret-sauce"})
        assert (bad_view.status_code, bad_view.json()["code"]) == (422, "invalid")
        assert "query.view" in bad_view.json()["detail"]
        assert "secret-sauce" not in bad_view.json()["detail"]
        bad_id = await http.get(f"{V1}/investigations/not-a-uuid")
        assert (bad_id.status_code, bad_id.json()) == (
            422,
            {"detail": "path.investigation_id: Input should be a valid UUID", "code": "invalid"},
        )
        broken = await http.post(f"{V1}/proposals/confirm", content=b'{"group": "g", ',
                                 headers={**token, "Content-Type": "application/json"})  # fmt: skip
        assert broken.status_code in (400, 422)
        assert set(broken.json()) == {"detail", "code"}
        secret = "hunter2-hunter2"
        leaked = await http.post(
            f"{V1}/proposals/confirm",
            headers=token,
            json={"group": secret, "assessment_ids": [], secret: 1},
        )
        assert leaked.status_code == 422
        assert secret not in leaked.json()["detail"]  # not even as an unknown field's name
        assert "body: an unknown field is not allowed" in leaked.json()["detail"]
        classic = await http.get("/api/investigations", params={"view": "secret-sauce"})
        assert isinstance(classic.json()["detail"], list)  # the classic API's answer is kept
