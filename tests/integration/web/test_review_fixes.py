"""Q-A1's independent review (docs/gates/q-a1.md, "Review"): one regression test per finding,
each shown failing on the reviewed code first. F2 (criterion 14) is in test_inbox_order.py
(the lists' order is unchanged by its indexes) and test_scale.py (the timings)."""

from __future__ import annotations

import asyncio
import re
import string
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from argus.config import DatabaseSettings
from argus.db.engine import create_engine
from argus.web import auth, throttle
from argus.web.app import create_app
from argus.web.capabilities import Capability
from tests.integration.web.conftest import BASE, FAST, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
V1 = "/api/v1"
POOL_TIMEOUT = 8  # seconds: long enough for a dozen password checks on a loaded machine


def client(engine: AsyncEngine, **kw: Any) -> httpx.AsyncClient:
    app = create_app(engine, FAST, clock=lambda: NOW)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN, **kw)  # fmt: skip


def form_token(page: str) -> str:
    found = re.search(r'name="signin_token" value="([^"]+)"', page)
    assert found is not None, page
    return found.group(1)


async def signed(http: httpx.AsyncClient, user: str = "asha") -> str:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text
    token: str = made.json()["csrf_token"]
    return token


async def count(engine: AsyncEngine, sql: str, **params: Any) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(sql), params)).scalar_one())


async def first_id(http: httpx.AsyncClient) -> str:
    items = (await http.get(f"{V1}/investigations", params={"view": "all"})).json()["items"]
    return str(items[0]["id"])


# --------------------------------------------------------------------------- F1


@pytest.fixture
async def production_pool(
    make_api_login: Callable[[], Awaitable[DatabaseSettings]],
    test_database: str,
    seeded: AsyncEngine,
) -> AsyncIterator[AsyncEngine]:
    """The web's own login (Q-A2) with the production pool (5 + 5 overflow)."""
    login = (await make_api_login()).model_copy(update={"pool_size": 5, "max_overflow": 5})
    engine = create_engine(login, database=test_database, role="api")
    engine.pool._timeout = POOL_TIMEOUT  # type: ignore[attr-defined]  # 30 s in production
    try:
        yield engine
    finally:
        await engine.dispose()


async def status(sent: Awaitable[httpx.Response]) -> int:
    return (await sent).status_code


async def burst(n: int, one: Callable[[int], Awaitable[int]]) -> tuple[list[int | str], float]:
    """``n`` requests at once: each one's status (or the exception's name) and the time."""

    async def guarded(k: int) -> int | str:
        try:
            return await one(k)
        except Exception as exc:  # what the app raised is the result
            return type(exc).__name__

    started = time.perf_counter()
    results = await asyncio.gather(*(guarded(k) for k in range(n)))
    return list(results), time.perf_counter() - started


async def test_refused_changes_never_wait_for_a_second_connection(
    production_pool: AsyncEngine, seeded: AsyncEngine
) -> None:
    """F1: twelve refused changes at once (more than the pool holds) all answer, each one
    audited, and none waits for the pool."""
    async with seeded.begin() as conn:  # accounts are made at a terminal, not by the web
        await auth.add_user(conn, "vera", "Vera", PASSWORD, capabilities=[Capability.VIEW])
    async with client(production_pool) as http:
        token = await signed(http, "vera")
        url = f"{V1}/investigations/{await first_id(http)}/assess"
        results, took = await burst(
            12, lambda _: status(http.post(url, headers={"X-CSRF-Token": token}))
        )
    assert results == [403] * 12, results
    assert took < POOL_TIMEOUT, took
    denied = "SELECT count(*) FROM audit_events WHERE action = 'access' AND outcome = 'denied'"
    assert await count(production_pool, denied) == 12


async def test_wrong_sign_ins_never_wait_for_a_second_connection(
    production_pool: AsyncEngine,
) -> None:
    """F1: twelve wrong sign-ins at once from one address (no session needed) all answer at once
    and are all recorded. Q-E2's review (F11) made the per-address check one at a time without
    waiting: the one being checked is refused (401), the others that arrive meanwhile are
    answered "busy" (503) and count for nothing."""
    async with client(production_pool) as http:
        token = form_token((await http.get("/signin")).text)

        async def one(n: int) -> int:
            got = await http.post("/signin", data={"username": f"nobody{n}",
                                                   "password": "wrong password!",
                                                   "signin_token": token})  # fmt: skip
            return got.status_code

        results, took = await burst(12, one)
    assert set(results) <= {401, 503}, results
    assert 401 in results, results
    assert took < POOL_TIMEOUT, took
    wrong = "SELECT count(*) FROM audit_events WHERE action = 'login' AND outcome = 'denied'"
    assert await count(production_pool, wrong) == 12
    counted = wrong + " AND details->>'counted' = 'true'"
    assert await count(production_pool, counted) == results.count(401)


@pytest.mark.parametrize("path", [f"{V1}/metrics", "/metrics"])
async def test_metrics_never_wait_for_a_second_connection(
    production_pool: AsyncEngine, path: str
) -> None:
    """F1: the model gateway's state is read on the request's own connection."""
    async with client(production_pool) as http:
        await signed(http)
        results, took = await burst(12, lambda _: status(http.get(path)))
    assert results == [200] * 12, results
    assert took < POOL_TIMEOUT, took


# --------------------------------------------------------------------------- F3

MARK = st.text(alphabet=string.ascii_letters + string.digits, min_size=12, max_size=40).map(
    lambda s: "Zq" + s  # never a valid value of any field
)


@settings(
    max_examples=max(10, settings().max_examples // 5),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(mark=MARK, where=st.integers(0, 9))
async def test_a_v1_422_never_quotes_the_input(
    seeded: AsyncEngine, mark: str, where: int, web_engine: AsyncEngine
) -> None:
    """F3: whatever field or tag carries the sender's text, the error never repeats it."""
    async with client(web_engine) as http:
        token = await signed(http)
        inv = await first_id(http)
        review = f"{V1}/investigations/{inv}/reviews"
        calls: list[tuple[str, str, dict[str, Any]]] = [
            ("POST", review, {"json": {"action": mark, "seen_review": None, "seen_version": 0}}),
            ("POST", review, {"json": {"action": "reviewed", "outcome": mark,
                                       "seen_review": None, "seen_version": 0}}),
            ("POST", review, {"json": {"action": "note", "note": "x", "seen_review": mark,
                                       "seen_version": 0}}),
            ("POST", review, {"json": {"action": "follow_up", "seen_review": None,
                                       "seen_version": mark, "also_gold": mark}}),
            ("POST", f"{V1}/investigations/{inv}/gold", {"json": {"outcome": mark}}),
            ("POST", f"{V1}/proposals/confirm", {"json": {"group": "g",
                                                          "assessment_ids": [mark]}}),
            ("POST", f"{V1}/patterns/review", {"json": {"outcome": "inconclusive", "items": [
                {"investigation_id": mark, "version": 1, "latest_review": None}]}}),
            ("GET", f"{V1}/investigations", {"params": {"view": mark}}),
            ("GET", f"{V1}/investigations", {"params": {"sort": mark, "kind": mark}}),
            ("GET", f"{V1}/investigations/{mark}", {}),
        ]  # fmt: skip
        method, path, kw = calls[where]
        got = await http.request(method, path, headers={"X-CSRF-Token": token}, **kw)
    assert got.status_code == 422, got.text
    assert set(got.json()) == {"detail", "code"}
    assert mark not in got.text, got.text


async def test_a_wrong_tag_names_the_expected_ones(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with client(web_engine) as http:
        token = await signed(http)
        got = await http.post(f"{V1}/investigations/{await first_id(http)}/reviews",
                              json={"action": "approve", "seen_review": None, "seen_version": 0},
                              headers={"X-CSRF-Token": token})  # fmt: skip
        classic = await http.post(f"/api/investigations/{await first_id(http)}/reviews",
                                  json={"action": "approve", "seen_version": 0,
                                        "seen_review": None},
                                  headers={"X-CSRF-Token": token})  # fmt: skip
    assert got.json() == {
        "detail": "body.action: must be one of 'reviewed', 'follow_up', 'note'",
        "code": "invalid",
    }
    assert classic.status_code == 422
    assert "approve" not in classic.text  # the classic API's list of errors, the same rule
    assert classic.json()["detail"][0]["msg"] == "must be one of 'reviewed', 'follow_up', 'note'"


# --------------------------------------------------------------------------- F4


async def test_the_name_throttle_holds_under_a_burst(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """F4: eight wrong guesses for one name at once never get more than the limit of checks: the
    ones checked are refused (401), the rest are refused unread (429) or, while a check of the
    name is under way, answered "busy" (503, Q-E2's review F11), and none gets in."""
    async with client(web_engine) as http:
        token = form_token((await http.get("/signin")).text)

        async def guess(n: int) -> int:
            got = await http.post("/signin", data={"username": "asha",
                                                   "password": f"wrong guess {n:04d}",
                                                   "signin_token": token})  # fmt: skip
            return got.status_code

        results, _ = await burst(8, guess)
    checked = await count(seeded, "SELECT count(*) FROM audit_events WHERE action = 'login'"
                          " AND outcome = 'denied' AND details->>'why' IS NULL")  # fmt: skip
    assert 1 <= checked <= throttle.NAME_LIMIT, results
    assert results.count(401) == checked
    assert set(results) <= {401, 429, 503}, results


async def test_three_failed_step_ups_hold_under_a_burst(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """F4: eight wrong step-ups on one session at once: three are checked, the third ends the
    session, and the rest are signed out without a password check."""
    async with client(web_engine) as http:
        csrf = await signed(http)

        async def guess(n: int) -> int:
            got = await http.post(
                "/stepup", data={"csrf_token": csrf, "password": f"wrong guess {n:04d}"}
            )
            return got.status_code

        results, _ = await burst(8, guess)
        after = await http.get(f"{V1}/session")
    checked = await count(seeded, "SELECT count(*) FROM audit_events WHERE action = 'stepup'"
                          " AND outcome = 'denied' AND details->>'why' IS NULL")  # fmt: skip
    assert checked == auth.STEP_UP_FAILURES, results
    assert sorted(results) == [303] * 6 + [401] * 2  # 2 wrong, then the 3rd and the rest out
    assert after.status_code == 401


# --------------------------------------------------------------------------- F5


async def test_without_its_database_the_app_says_so_plainly() -> None:
    """F5: an ARGUS database outage answers ErrorOut on /api/v1 and a plain page elsewhere."""
    engine = create_async_engine(
        "postgresql+psycopg://nobody:x@127.0.0.1:1/none", connect_args={"connect_timeout": 1}
    )
    app = create_app(engine, clock=lambda: NOW)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN,
                                     cookies={"argus_session": "x" * 43}) as http:  # fmt: skip
            v1 = await http.get(f"{V1}/session")
            page = await http.get("/signin")
            classic = await http.get("/api/investigations")
    finally:
        await engine.dispose()
    assert v1.status_code == 503
    assert v1.json() == {"detail": "ARGUS cannot reach its database; try again in a minute",
                         "code": "unavailable"}  # fmt: skip
    assert page.status_code == 503
    assert page.headers["content-type"].startswith("text/html")
    assert "ARGUS cannot reach its database; try again in a minute" in page.text
    assert page.headers["content-security-policy"]  # the security headers still apply
    assert classic.status_code == 503
    assert classic.json() == {"detail": "ARGUS cannot reach its database; try again in a minute"}


# --------------------------------------------------------------------------- F6


async def test_two_sign_in_forms_in_one_browser_both_work(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """F6: two links opened while signed out give two sign-in forms; either one signs in."""
    async with client(web_engine) as http:
        tab_a = await http.get("/signin", params={"next": "/rules"})
        tab_b = await http.get("/signin", params={"next": "/patterns"})
        assert tab_b.status_code == 200
        got = await http.post("/signin", data={"username": "asha", "password": PASSWORD,
                                               "signin_token": form_token(tab_a.text),
                                               "next": "/rules"})  # fmt: skip
        assert (got.status_code, got.headers["location"]) == (303, "/rules")
        again = await http.get("/signin")  # signed in: no form, straight on
        assert again.status_code == 303
        http.cookies.delete("argus_session")
        fresh = form_token((await http.get("/signin")).text)
    assert fresh != form_token(tab_a.text)  # a new token after each sign-in


# --------------------------------------------------------------------------- F7


async def test_the_classic_gold_refusal_is_audited_like_v1(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with seeded.begin() as conn:
        await auth.add_user(conn, "rhea", "Rhea", PASSWORD,
                            capabilities=[Capability.VIEW, Capability.REVIEW])  # fmt: skip
    denials = ("SELECT count(*) FROM audit_events WHERE action = 'access'"
               " AND outcome = 'denied' AND actor = 'user:rhea'")  # fmt: skip
    async with client(web_engine) as http:
        token = await signed(http, "rhea")
        inv = (await http.get(f"{V1}/investigations", params={"view": "all"})).json()["items"][0]
        v1 = await http.post(f"{V1}/investigations/{inv['id']}/reviews", headers={
            "X-CSRF-Token": token}, json={"action": "reviewed", "outcome": "benign_expected",
            "seen_review": inv["latest_review"], "seen_version": inv["version"],
            "also_gold": True})  # fmt: skip
        assert v1.status_code == 403
        assert await count(seeded, denials) == 1
        classic = await http.post(f"/investigations/{inv['id']}/review", data={
            "csrf_token": token, "action": "reviewed", "outcome": "benign_expected",
            "seen_version": str(inv["version"]), "seen_review": "", "also_gold": "1"})  # fmt: skip
    assert classic.status_code == 403
    assert "answer_gold" in classic.text
    assert await count(seeded, denials) == 2


# --------------------------------------------------------------------------- F8


@pytest.mark.parametrize(
    "path",
    [
        "/go/investigation/0b3c1e1a-2f0e-4b8e-9d6a-7c1f",
        "/go/investigation/not-a-uuid",
        "/go/case/0b3c1e1a-2f0e",
        f"/go/investigation/{'9' * 300}",
    ],
)
async def test_a_mangled_permanent_link_gets_a_plain_page(
    seeded: AsyncEngine, path: str, web_engine: AsyncEngine
) -> None:
    async with client(web_engine) as http:
        await signed(http)
        got = await http.get(path, headers={"Accept": "text/html"})
    assert got.status_code == 404
    assert got.headers["content-type"].startswith("text/html"), got.text[:300]
    assert "This link is incomplete or wrong" in got.text
    assert "uuid" not in got.text.lower()
