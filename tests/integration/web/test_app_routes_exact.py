"""The page routes exactly (2026-10-21: the mutation run of ``app.py`` with Phase 2's tests
found what no test pinned): the login redirect of every page and form, the expired-form refusal
of every form, every message word for word, the allowed values of every typed parameter, the
API's documented responses, and the fallbacks when the model gateway is not configured."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from markupsafe import escape
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN
from tests.integration.web.test_assessments import signed_in

pytestmark = pytest.mark.integration
EXPIRED = "The form expired; reload the page and try again."


def alert(message: str) -> str:
    return f'<p class="message" role="alert">{escape(message)}</p>'


async def first(engine: AsyncEngine, n: int = 1) -> list[queries.Summary]:
    async with engine.connect() as conn:
        return (await queries.inbox(conn, "all"))[:n]


async def test_the_gateway_fallbacks(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import argus.llm.providers as providers

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("no gateway configured here")

    monkeypatch.setattr(providers, "load_config", broken)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        cost = (await http.get("/api/v1/cost")).json()
    assert (cost["cap_usd"], cost["paid_until_usd"], cost["daily_cap_usd"]) == (10.0, 8.0, None)
    monkeypatch.undo()
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        assert (await http.get("/api/v1/cost")).json()["daily_cap_usd"] is not None


async def test_every_typed_value_is_accepted(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    for name, values in (("severity", ("critical", "high", "medium", "low")),
                         ("state", ("unreviewed", "follow_up", "changed_since_review", "reviewed")),
                         ("verdict", ("true_positive", "benign_expected", "benign_policy",
                                      "rule_false_positive", "inconclusive", "none")),
                         ("ai", ("proposed_tp", "proposed_other", "no_proposal", "working",
                                 "none"))):  # fmt: skip
        for value in values:
            got = await client.get("/api/dashboard", params={name: value})
            assert got.status_code == 200, (name, value)
    for kind in ("ip", "host", "domain", "user"):
        found = await client.get("/api/dashboard", params={"kind": kind, "value": "203.0.113.9"})
        assert found.json()["kpis"]["cases"] == 0, kind  # the filter applies
        inbox = await client.get("/api/investigations", params={
            "view": "all", "kind": kind, "value": "203.0.113.9"})  # fmt: skip
        assert inbox.json() == [], kind
    early = await client.get("/api/dashboard", params={"start": "2019-06-01", "end": "2020-03-01"})
    assert early.json()["start"] == "2019-12-31T18:30:00+00:00"  # clamped to 2020-01-01 IST
    one = await client.get("/api/dashboard", params={"start": "2026-10-01", "end": ""})
    assert one.status_code == 200  # one date: the time menu's span, the dashboard still builds


async def test_the_validation_answer_and_the_logout_cookie(client: httpx.AsyncClient) -> None:
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    await signed_in(client)
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    assert bad.status_code == 422
    (error,) = bad.json()["detail"]
    assert set(error) == {"type", "loc", "msg"}
    assert error["loc"] == ["query", "range"]
    wrong = await client.post("/login", data={"username": "asha", "password": "wrong-pass-1"})
    assert '<p class="message" role="alert">Wrong name or password.</p>' in wrong.text
    out = await client.post("/logout", data={})
    assert "Path=/" in out.headers["set-cookie"]
    token = await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
    api_out = await client.post("/api/logout", headers={"X-CSRF-Token": token.json()["csrf_token"]})
    assert api_out.status_code == 204
    assert "Path=/" in api_out.headers["set-cookie"]


async def test_the_documented_responses(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/api/openapi.json")).json()

    def codes(path: str, method: str) -> list[str]:
        return sorted(spec["paths"][path][method]["responses"])

    assert codes("/api/login", "post") == ["200", "400", "401", "410", "422", "429", "503"]
    assert spec["paths"]["/api/login"]["post"]["responses"]["429"]["description"] == (
        "too many failed logins; try again in 15 minutes"
    )
    assert codes("/api/logout", "post") == ["204", "401", "403"]
    review = spec["paths"]["/api/investigations/{investigation_id}/reviews"]["post"]["responses"]
    assert sorted(review) == ["201", "400", "401", "403", "404", "409", "422"]
    assert review["422"] == {
        "description": "the body is invalid, or the review is refused (the reason in detail)",
        "content": {"application/json": {"schema": {"anyOf": [
            {"$ref": "#/components/schemas/HTTPValidationError"},
            {"type": "object", "required": ["detail"],
             "properties": {"detail": {"type": "string"}}},
        ]}}},
    }  # fmt: skip
    for path in ("/api/investigations", "/api/rules", "/api/entities", "/api/dashboard",
                 "/api/health"):  # fmt: skip
        assert "401" in codes(path, "get"), path
    one = "/api/investigations/{investigation_id}"
    assert {"401", "404"} <= set(codes(one, "get"))
    raw = [p for p in spec["paths"] if p.endswith("/raw")]
    for path in raw:
        assert {"401", "404"} <= set(codes(path, "get")), path


async def test_the_api_review_body_limits(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    url = f"/api/investigations/{a.id}/reviews"

    async def post(body: dict[str, Any]) -> int:
        got = await client.post(url, json={"seen_review": None, "seen_version": a.version, **body},
                                headers={"X-CSRF-Token": token})  # fmt: skip
        return got.status_code

    for outcome in ("benign_expected", "benign_policy", "rule_false_positive", "true_positive",
                    "inconclusive"):  # fmt: skip
        assert await post({"action": "follow_up", "outcome": outcome, "note": "n"}) in (201, 409)
    assert await post({"action": "note", "note": ""}) == 422
    assert await post({"action": "note", "note": "x" * 4001}) == 422
    assert await post({"action": "follow_up", "note": ""}) == 422
    assert await post({"action": "follow_up", "note": "x" * 4001}) == 422
    assert await post({"action": "note", "note": "n", "seen_review": 0}) == 422
    assert await post({"action": "note", "note": "n", "seen_version": -1}) == 422
    assert await post({"action": "follow_up", "seen_review": 0}) == 422
    assert await post({"action": "follow_up", "seen_version": -1}) == 422
    assert re.fullmatch(r"20\d|409", str(await post({"action": "note", "note": "x" * 4000})))


async def test_the_last_gaps(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    """The mutation run's last survivors (2026-10-22): each one pinned here."""
    a, b = await first(seeded, 2)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    headers = {"X-CSRF-Token": token}
    gone = await client.get(f"/api/investigations/{uuid.uuid4()}")
    assert (gone.status_code, gone.json()) == (404, {"detail": "no such investigation"})
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    (error,) = bad.json()["detail"]
    assert error["type"] == "literal_error"
    assert error["msg"].startswith("Input should be '24h'")
    # the request model refuses first: a list of errors, not the review's own sentence
    url = f"/api/investigations/{a.id}/reviews"
    long = await client.post(url, headers=headers, json={
        "action": "note", "note": "x" * 4001, "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert long.json()["detail"][0]["loc"] == ["body", "note", "note"]
    long = await client.post(url, headers=headers, json={
        "action": "follow_up", "note": "x" * 4001, "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert long.json()["detail"][0]["loc"] == ["body", "follow_up", "note"]
    # the smallest allowed values pass the model (then the review decides)
    one = await client.post(url, headers=headers, json={
        "action": "note", "note": "x", "seen_review": None, "seen_version": a.version})  # fmt: skip
    assert one.status_code == 201
    short = await client.post(url, headers=headers, json={
        "action": "follow_up", "note": "y", "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert short.status_code in (201, 409)
    edge = await client.post(f"/api/investigations/{b.id}/reviews", headers=headers, json={
        "action": "follow_up", "seen_review": 1, "seen_version": 0})  # fmt: skip
    assert edge.status_code == 409  # valid input, but not what is current: a conflict, not 422
    note = await client.post(f"/api/investigations/{b.id}/reviews", headers=headers, json={
        "action": "note", "note": "z", "seen_review": 1, "seen_version": 0})  # fmt: skip
    assert note.status_code != 422  # the smallest allowed values pass the note's model too


async def test_an_unknown_name_with_the_dummy_password_is_refused(
    client: httpx.AsyncClient,
) -> None:
    """The dummy hash makes an unknown name cost as much as a wrong password; its own password
    must not let anyone in, nor crash the login (no row behind it)."""
    got = await client.post(
        "/api/login", json={"username": "nobody", "password": "argus-dummy-password"}
    )
    assert got.status_code == 401


async def test_api_bodies_are_strictly_typed(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    """Schemathesis (2026-10-22): ``"seen_version": true`` was taken as 1 and saved a review."""
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    url = f"/api/investigations/{a.id}/reviews"
    for body in ({"action": "note", "note": "n", "seen_review": None, "seen_version": True},
                 {"action": "note", "note": "n", "seen_review": None, "seen_version": "1"},
                 {"action": "note", "note": "n", "seen_review": True, "seen_version": a.version},
                 {"action": "follow_up", "seen_review": False,
                  "seen_version": a.version}):  # fmt: skip
        got = await client.post(url, json=body, headers={"X-CSRF-Token": token})
        assert got.status_code == 422, body
    assert (await client.post("/api/login", json={"username": "asha", "password": 1})
            ).status_code == 422  # fmt: skip
    whole = {"action": "note", "note": "n", "seen_review": None, "seen_version": float(a.version)}
    assert (await client.post(url, json=whole, headers={"X-CSRF-Token": token})).status_code == 201
    # 1.0 is a JSON integer (JSON Schema): accepted, as the documented schema says
    async with seeded.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM review_events")) == 1  # the 1.0 one


async def test_dashboard_days_are_iso_only(client: httpx.AsyncClient) -> None:
    """Schemathesis (2026-10-22): "0" was read as a Unix time (1970-01-01) and accepted."""
    await signed_in(client)
    for day in ("0", "1700000000", "2026-1-1", "21-10-2026", "2026-10-21T00:00"):
        got = await client.get("/api/dashboard", params={"start": day, "end": "2026-10-21"})
        assert got.status_code == 422, day
    ok = await client.get("/api/dashboard", params={"start": "2026-10-20", "end": "2026-10-21"})
    assert ok.status_code == 200


def test_each_request_commits_before_its_response() -> None:
    """The intermittent HTTPS test (10-21/22): a login's session was committed after the 303
    was sent, so the next request sometimes found no session."""
    from argus.web.app import Conn

    (dependency,) = Conn.__metadata__
    assert dependency.scope == "function"


async def test_the_type_refusals_word_for_word(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    got = await client.post(f"/api/investigations/{a.id}/reviews", headers={"X-CSRF-Token": token},
                            json={"action": "note", "note": "n", "seen_review": None,
                                  "seen_version": True})  # fmt: skip
    assert got.json()["detail"][0]["msg"] == "Value error, a whole number"
    day = await client.get("/api/dashboard", params={"start": "0", "end": "2026-10-21"})
    assert day.json()["detail"][0]["msg"] == "Value error, a day as YYYY-MM-DD"
