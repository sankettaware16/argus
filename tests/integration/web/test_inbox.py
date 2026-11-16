"""R7: logins, sessions, CSRF and origin checks, every page, the review loop (exactly one 409
for two reviewers), derived human states, security headers, hostile alert content."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.app import create_app
from tests.integration.grouping.test_grouping import doc, ingest
from tests.integration.web.conftest import (
    BASE,
    NOW,
    PASSWORD,
    SAME_ORIGIN,
    first_investigation,
    log_in,
)

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- accounts


async def test_login_logout_and_audit(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    assert (await client.get("/api/investigations")).status_code == 401
    bad = await client.post("/api/login", json={"username": "asha", "password": "wrong-one!"})
    assert bad.status_code == 401
    csrf = await log_in(client)
    cookie = client.cookies.jar
    (session,) = [c for c in cookie if c.name == "argus_session"]
    assert session.has_nonstandard_attr("HttpOnly")
    assert (await client.get("/api/investigations")).status_code == 200
    assert (await client.post("/api/logout")).status_code == 403  # no CSRF header
    assert (await client.post("/api/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
    assert (await client.get("/api/investigations")).status_code == 401
    async with seeded.connect() as conn:
        actions = (await conn.execute(text(
            "SELECT action, outcome FROM audit_events WHERE action IN ('login', 'logout')"
            " ORDER BY id"))).all()  # fmt: skip
    assert actions == [("login", "denied"), ("login", "success"), ("logout", "success")]


async def test_sessions_expire_when_idle(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    """Idle 30 minutes and 8 hours at most by default (plan §7.2, DQ17)."""
    times = [NOW]
    app = create_app(web_engine, clock=lambda: times[0])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await log_in(http)
        times[0] += timedelta(minutes=29)
        assert (await http.get("/api/investigations")).status_code == 200  # renewed
        times[0] += timedelta(minutes=30, seconds=1)
        assert (await http.get("/api/investigations")).status_code == 401


async def test_a_disabled_reviewer_is_out_at_once(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    await log_in(client)
    async with seeded.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'asha'"))
    assert (await client.get("/api/investigations")).status_code == 401


async def test_passwords_are_argon2id_and_tokens_are_hashed(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        (stored,) = (await conn.execute(text(
            "SELECT password_hash FROM users WHERE username = 'asha'"))).one()  # fmt: skip
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


# --------------------------------------------------------------------------- boundaries


async def test_other_hosts_and_origins_are_refused(client: httpx.AsyncClient) -> None:
    assert (await client.get("/login", headers={"host": "evil.example"})).status_code == 400
    response = await client.post(
        "/api/login", json={"username": "asha", "password": PASSWORD},
        headers={"origin": "http://evil.example"},
    )  # fmt: skip
    assert response.status_code == 403


async def test_security_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/login")
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------------------- reviews


async def review(http: httpx.AsyncClient, csrf: str, inv: dict, **body: object) -> httpx.Response:
    payload = {"action": "reviewed", "seen_review": inv["latest_review"],
               "seen_version": inv["version"], **body}  # fmt: skip
    if payload["action"] == "reviewed":  # a decision needs an outcome (D-067)
        payload.setdefault("outcome", "benign_expected")
    return await http.post(f"/api/investigations/{inv['id']}/reviews", json=payload,
                           headers={"X-CSRF-Token": csrf})  # fmt: skip


async def test_two_reviewers_one_wins_the_other_gets_409(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    app = create_app(web_engine, clock=lambda: NOW)
    clients = [httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=SAME_ORIGIN)
               for _ in range(2)]  # fmt: skip
    try:
        tokens = [await log_in(clients[0], "asha"), await log_in(clients[1], "ravi")]
        inv = await first_investigation(clients[0])
        pairs = zip(clients, tokens, strict=True)
        results = await asyncio.gather(*(review(c, t, inv, outcome="benign_expected")
                                         for c, t in pairs))  # fmt: skip
        assert sorted(r.status_code for r in results) == [201, 409]
        (conflict,) = [r for r in results if r.status_code == 409]
        assert conflict.json()["latest_review"] is not None
    finally:
        for c in clients:
            await c.aclose()


async def test_human_states_follow_reviews_and_changes(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    csrf = await log_in(client)
    inv = await first_investigation(client)
    assert inv["human_state"] == "unreviewed"
    assert (await review(client, csrf, inv, action="follow_up")).status_code == 201
    inv = (await client.get(f"/api/investigations/{inv['id']}")).json()["investigation"]
    assert inv["human_state"] == "follow_up"
    assert (await review(client, csrf, inv, outcome="rule_false_positive")).status_code == 201
    inv = (await client.get(f"/api/investigations/{inv['id']}")).json()["investigation"]
    assert inv["human_state"] == "reviewed"
    assert (await review(client, csrf, inv, action="note", note="checked")).status_code == 201
    inv = (await client.get(f"/api/investigations/{inv['id']}")).json()["investigation"]
    assert inv["human_state"] == "reviewed"  # a note changes nothing
    key = dict(inv["key"])
    rule = inv["rule_id"]
    await ingest(seeded, [doc(500, rule, key["source.ip"], NOW - timedelta(minutes=1))])
    inv = (await client.get(f"/api/investigations/{inv['id']}")).json()["investigation"]
    assert inv["human_state"] == "changed_since_review"
    assert "1 new alerts since it was last reviewed." in inv["reasons"]
    attention = (await client.get("/api/investigations")).json()
    assert inv["id"] in [i["id"] for i in attention]


async def test_a_stale_version_is_a_conflict_and_bad_input_is_refused(
    client: httpx.AsyncClient,
) -> None:
    csrf = await log_in(client)
    inv = await first_investigation(client)
    assert (await review(client, csrf, {**inv, "version": inv["version"] - 1})).status_code == 409
    assert (await review(client, csrf, inv, action="note")).status_code == 422  # empty note
    assert (await review(client, csrf, inv, outcome="guilty")).status_code == 422
    assert (await review(client, csrf, inv, note="x" * 4001)).status_code == 422


# --------------------------------------------------------------------------- hostile content

HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>"‮​'


async def test_hostile_alert_content_is_inert(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    bad = doc(900, "rule-x", "10.9.9.9", NOW - timedelta(minutes=5))
    bad["_source"]["kibana.alert.rule.name"] = HOSTILE
    bad["_source"]["host"] = {"name": HOSTILE}
    await ingest(seeded, [bad])
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    found = (
        await client.get("/api/investigations", params={"view": "all", "rule": "rule-x"})
    ).json()
    (inv,) = found
    alert_id = (await client.get(f"/api/investigations/{inv['id']}")).json()["alerts"][0][
        "alert_id"
    ]
    for path in ("/?view=all&rule=rule-x", f"/investigations/{inv['id']}",
                 f"/investigations/{inv['id']}/alerts/{alert_id}", "/rules", "/hosts"):  # fmt: skip
        body = (await client.get(path)).text
        assert "<script>alert" not in body
        assert "<img src=x" not in body
        assert "‮" not in body  # shown as U+202E, never applied
        assert "​" not in body


@pytest.mark.parametrize("name", ["as\x00ha", "ASHA", "a", "x" * 65, "a b"])
async def test_impossible_names_are_a_plain_refusal(
    client: httpx.AsyncClient, seeded: AsyncEngine, name: str
) -> None:
    """Found by Schemathesis: a NUL in the name made Postgres refuse the query (500)."""
    response = await client.post("/api/login", json={"username": name, "password": PASSWORD})
    assert response.status_code in (401, 422)
    form = await client.post("/login", data={"username": name, "password": PASSWORD})
    assert form.status_code in (401, 422)


async def test_nul_and_lone_surrogates_never_reach_the_database(
    client: httpx.AsyncClient,
) -> None:
    surrogate = await client.post(
        "/api/login", content=b'{"username": "\\udcff", "password": "x"}',
        headers={"content-type": "application/json"},
    )  # fmt: skip
    assert surrogate.status_code in (400, 401, 422)
    csrf = await log_in(client)
    listed = await client.get("/api/investigations", params={"view": "all", "rule": "\x00"})
    assert listed.status_code == 422
    inv = await first_investigation(client)
    note = await review(client, csrf, inv, action="note", note="a\x00b")
    assert note.status_code == 422
    raw = await client.get(f"/api/investigations/{inv['id']}/alerts/a%00b/raw")
    assert raw.status_code in (404, 422)
