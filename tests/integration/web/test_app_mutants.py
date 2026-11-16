"""The Inbox app's routes checked exactly, written for mutation survivors (D-040): page
bodies (not only status codes), error bodies, headers, hosts, cookies, field limits, the
OpenAPI surface and the audit rows of form logins."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.conftest import PASSWORD, first_investigation, log_in

pytestmark = pytest.mark.integration

API = {
    "/api/login", "/api/logout", "/api/investigations", "/api/investigations/{investigation_id}",
    "/api/investigations/{investigation_id}/alerts/{alert_id}/raw",
    "/api/investigations/{investigation_id}/reviews", "/api/rules", "/api/entities",
    "/api/health", "/api/dashboard",
    "/api/investigations/{investigation_id}/report",
}  # fmt: skip


async def form_login(http: httpx.AsyncClient) -> str:
    response = await http.post("/login", data={"username": "asha", "password": PASSWORD})
    assert (response.status_code, response.headers["location"]) == (303, "/")
    return str((await http.get("/api/v1/session")).json()["csrf_token"])


async def test_openapi_surface_headers_hosts_and_static(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/api/openapi.json")).json()
    assert (spec["info"]["title"], spec["info"]["version"]) == ("ARGUS Inbox", "0.1.0")
    assert set(spec["paths"]) == API
    login = spec["paths"]["/api/login"]["post"]["responses"]
    assert login["400"]["description"] == "the body is not JSON"
    assert login["401"]["description"] == "wrong name or password"
    reviews = spec["paths"]["/api/investigations/{investigation_id}/reviews"]["post"]
    assert set(reviews["responses"]) >= {"201", "400", "401", "403", "404", "409", "422"}
    assert "ConflictOut" in str(reviews["responses"]["409"])
    response = await client.get("/signin")
    assert {k: response.headers[k.lower()] for k in (
        "X-Frame-Options", "Cache-Control", "Cross-Origin-Opener-Policy")} == {
        "X-Frame-Options": "DENY", "Cache-Control": "no-store",
        "Cross-Origin-Opener-Policy": "same-origin"}  # fmt: skip
    for host in ("localhost", "127.0.0.1", "127.0.0.1:8765"):
        assert (await client.get("/signin", headers={"host": host})).status_code == 200
    assert (await client.get("/signin", headers={"host": "[::1]"})).status_code == 400
    css = await client.get("/static/style.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")


async def test_api_errors_are_exact(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/rules")).json() == {"detail": "log in first"}
    bad = await client.post("/api/login", json={"username": "asha", "password": "wrong-one!"})
    assert bad.json() == {"detail": "wrong name or password"}
    invalid = await client.post("/api/login", json={"username": "", "password": "p"})
    assert invalid.status_code == 422
    (error,) = invalid.json()["detail"]
    assert set(error) == {"type", "loc", "msg"}
    assert error["loc"] == ["body", "username"]
    for body, field in (({"username": "a" * 65, "password": "p"}, "username"),
                        ({"username": "a", "password": "p" * 257}, "password")):  # fmt: skip
        assert (await client.post("/api/login", json=body)).status_code == 422, field
    for body in ({"username": "a" * 64, "password": "p"}, {"username": "a", "password": "p" * 256}):
        assert (await client.post("/api/login", json=body)).status_code == 401
    csrf = await log_in(client)
    inv = await first_investigation(client)
    path = f"/api/investigations/{inv['id']}/reviews"
    wrong = await client.post(path, json={}, headers={"X-CSRF-Token": "nope"})
    assert wrong.json() == {"detail": "missing or wrong X-CSRF-Token"}
    unknown = f"/api/investigations/{uuid.uuid4()}"
    assert (await client.get(unknown)).json() == {"detail": "no such investigation"}
    assert (await client.get(f"{unknown}/alerts/x/raw")).status_code == 404
    raw_missing = await client.get(f"/api/investigations/{inv['id']}/alerts/x/raw")
    assert raw_missing.json() == {"detail": "no such alert in this investigation"}
    assert (
        await client.get(f"/api/investigations/{inv['id']}/alerts/{'x' * 513}/raw")
    ).status_code == 422
    body = {"action": "reviewed", "outcome": "benign_expected", "seen_review": None,
            "seen_version": inv["version"]}  # fmt: skip
    headers = {"X-CSRF-Token": csrf}
    bare = {k: v for k, v in body.items() if k != "outcome"}
    refused = await client.post(f"/api/investigations/{inv['id']}/reviews", json=bare,
                                headers=headers)  # fmt: skip
    assert (refused.status_code, refused.json()) == (
        422, {"detail": "choose an outcome to mark it reviewed"})  # fmt: skip
    nowhere = await client.post(f"{unknown}/reviews", json=body, headers=headers)
    assert (nowhere.status_code, nowhere.json()) == (404, {"detail": "no such investigation"})
    for change in ({"seen_review": 0}, {"seen_version": -1}, {"note": ""},
                   {"note": "x" * 4001}, {"action": "note"}):  # fmt: skip
        assert (
            await client.post(path, json={**body, **change}, headers=headers)
        ).status_code == 422
    made = await client.post(path, json={**body, "note": "x" * 4000}, headers=headers)
    assert made.status_code == 201
    assert set(made.json()) == {"review_id", "version"}
    assert made.json()["version"] == inv["version"]


async def test_api_reads(client: httpx.AsyncClient) -> None:
    await log_in(client)
    rules = (await client.get("/api/rules")).json()
    assert {r["rule_id"] for r in rules} == {"rule-0", "rule-1", "rule-2"}
    entities = (await client.get("/api/entities")).json()
    assert {"kind": "ip", "value": "10.0.0.1"}.items() <= next(
        e for e in entities if e["value"] == "10.0.0.1").items()  # fmt: skip
    health = (await client.get("/api/health")).json()
    assert health["alerts"] == 24
    inv = await first_investigation(client)
    detail = (await client.get(f"/api/investigations/{inv['id']}")).json()
    alert_id = detail["alerts"][0]["alert_id"]
    raw = (await client.get(f"/api/investigations/{inv['id']}/alerts/{alert_id}/raw")).json()
    assert raw["kibana.alert.uuid"] == alert_id
    entity = await client.get("/api/investigations", params={"view": "all", "kind": "ip",
                                                             "value": "10.0.0.1"})  # fmt: skip
    only_kind = await client.get("/api/investigations", params={"view": "all", "kind": "ip"})
    assert 0 < len(entity.json()) < len(only_kind.json())  # kind alone does not filter


async def test_cross_origin_writes_only(client: httpx.AsyncClient) -> None:
    foreign = {"origin": "http://evil.example"}
    refused = await client.post("/api/login", json={}, headers=foreign)
    assert refused.json() == {"detail": "cross-origin request refused"}
    for method in ("GET", "HEAD", "OPTIONS"):
        response = await client.request(method, "/login", headers=foreign)
        assert response.status_code != 403, method
    same = await client.post("/api/login", json={"username": "asha", "password": PASSWORD},
                             headers={"origin": "http://127.0.0.1"})  # fmt: skip
    assert same.status_code == 200


async def test_api_logout_kills_the_token(client: httpx.AsyncClient) -> None:
    csrf = await log_in(client)
    token = client.cookies["argus_session"]
    response = await client.post("/api/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 204
    assert "argus_session=" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    client.cookies.set("argus_session", token)
    assert (await client.get("/api/rules")).status_code == 401


# --------------------------------------------------------------------------- pages


async def first_investigation_page(client: httpx.AsyncClient) -> str:
    await form_login(client)
    inv = await first_investigation(client)
    return str(inv["id"])


async def test_form_login_logout_and_audit(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    wrong = await client.post("/login", data={"username": "asha", "password": "nope-nope!"})
    assert (wrong.status_code, "Wrong name or password." in wrong.text) == (401, True)
    csrf = await form_login(client)
    token = client.cookies["argus_session"]
    ignored = await client.post("/logout", data={"csrf_token": "forged"})
    assert ignored.headers["location"] == "/signin?why=out"
    client.cookies.set("argus_session", token)
    assert (await client.get("/api/v1/session")).status_code == 200  # a forged logout ends nothing
    out = await client.post("/logout", data={"csrf_token": csrf})
    assert (out.status_code, out.headers["location"]) == (303, "/signin?why=out")
    assert "Max-Age=0" in out.headers["set-cookie"]
    client.cookies.set("argus_session", token)
    assert (await client.get("/api/v1/session")).status_code == 401  # the session is over
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT actor, action, outcome, details->>'username' FROM audit_events"
            " WHERE action IN ('login', 'logout') ORDER BY id"))).all()  # fmt: skip
    assert rows == [("web", "login", "denied", "asha"), ("user:asha", "login", "success", None),
                    ("user:asha", "logout", "success", None)]  # fmt: skip


async def test_the_old_login_address_leads_to_the_sign_in_page(client: httpx.AsyncClient) -> None:
    login = await client.get("/login")
    assert (login.status_code, login.headers["location"]) == (303, "/signin")
    signin = await client.get("/signin")
    assert 'action="/signin"' in signin.text
