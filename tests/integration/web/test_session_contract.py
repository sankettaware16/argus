"""Q-A1: the session contract. ``GET``/``DELETE /api/v1/session``; sign-in and step-up as
server-rendered pages that run no script, with a login-CSRF token and a validated redirect;
the idle and the absolute end; background requests that never keep a session alive; where a
change may come from (Origin, Sec-Fetch-Site); the permanent ``/go`` links."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import auth, links, throttle
from argus.web.app import TOO_MANY, create_app
from argus.web.capabilities import Capability
from tests.integration.web.conftest import BASE, FAST, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
LAN = {"host": "0.0.0.0", "tls_cert": "c.crt", "tls_key": "c.key",  # noqa: S104 - the test
       "allowed_hosts": ["10.13.171.247"], "allowed_networks": ["10.13.171.0/24"]}  # fmt: skip


class Clock:
    def __init__(self, at: datetime = NOW) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


def browser(engine: AsyncEngine, clock: Callable[[], datetime] = lambda: NOW,
            settings: WebSettings | None = None, base: str = BASE,
            client: str = "127.0.0.1") -> httpx.AsyncClient:  # fmt: skip
    app = create_app(engine, settings or FAST, clock=clock)
    transport = httpx.ASGITransport(app=app, client=(client, 51000))  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url=base, headers={"Origin": base})


def form_token(page: str) -> str:
    found = re.search(r'name="signin_token" value="([^"]+)"', page)
    assert found is not None, page
    return found.group(1)


async def sign_in(http: httpx.AsyncClient, user: str = "asha", password: str = PASSWORD,
                  next_: str | None = None) -> httpx.Response:  # fmt: skip
    form = await http.get("/signin", params={"next": next_} if next_ else None)
    assert form.status_code == 200, form.text
    data = {"username": user, "password": password, "signin_token": form_token(form.text)}
    if next_ is not None:
        data["next"] = next_
    return await http.post("/signin", data=data)


async def last_seen(engine: AsyncEngine) -> list[datetime]:
    async with engine.connect() as conn:
        return [r[0] for r in await conn.execute(
            text("SELECT last_seen_at FROM user_sessions ORDER BY created_at"))]  # fmt: skip


async def audit(engine: AsyncEngine, *actions: str) -> list[tuple[Any, ...]]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT actor, action, outcome, details->>'username', details->>'why'"
                " FROM audit_events WHERE action = ANY(:a) ORDER BY id"
            ),
            {"a": list(actions)},
        )
        return [tuple(r) for r in rows]


# --------------------------------------------------------------------------- sign-in


async def test_the_sign_in_page_runs_no_script_and_carries_a_login_csrf_token(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        page = await http.get("/signin")
    assert page.status_code == 200
    policy = page.headers["content-security-policy"]
    assert "script-src 'none'" in policy
    assert "connect-src 'none'" in policy
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "<script" not in page.text
    assert 'action="/signin"' in page.text
    assert 'autocomplete="current-password"' in page.text
    cookie = page.headers["set-cookie"]
    name, value = cookie.split(";")[0].split("=", 1)
    assert name == "argus_signin"
    assert value == form_token(page.text)
    for part in ("HttpOnly", "Path=/", "SameSite=strict", "Max-Age=900"):
        assert part in cookie, part
    async with browser(web_engine) as http:
        again = await http.get("/signin")
    assert form_token(again.text) != value  # a fresh token for every form


async def test_signing_in_gives_the_session_contract(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        signed = await sign_in(http)
        assert (signed.status_code, signed.headers["location"]) == (303, "/")
        cookies = signed.headers.get_list("set-cookie")
        session_cookie = next(c for c in cookies if c.startswith("argus_session="))
        for part in ("HttpOnly", "Path=/", "SameSite=strict", "Max-Age=28800"):
            assert part in session_cookie, part
        assert "Secure" not in session_cookie  # plain http on the loopback
        assert any(c.startswith("argus_signin=") and "Max-Age=0" in c for c in cookies)
        got = await http.get("/api/v1/session")
    assert got.status_code == 200
    body = got.json()
    assert body.pop("csrf_token")
    user = body.pop("user")
    assert (user["username"], user["display_name"]) == ("asha", "Asha")
    # the additive `site` object (D-284, P4-D1): the zone, its label, the noun and the names the
    # pages write, here ACME's own
    assert body.pop("site") == {
        "timezone": "Asia/Kolkata",
        "timezone_label": "IST",
        "own_network_noun": "campus",
        "organisation_name": "Example University",
        "organisation_short_name": "ACME",
        "organisation_kind": "university",
        "organisation_units": "department, hostel or lab",
        "organisation_reviewers": "research and teaching assistants",
    }
    assert body == {
        "mode": "local",
        "break_glass": False,
        "unverified": None,
        "capabilities": [
            {"name": "view", "label": "use ARGUS: see investigations, alerts and reports"},
            {"name": "see_logs", "label": "see raw logs and the facts ARGUS read from them"},
            {"name": "review", "label": "review: verdicts, group reviews, accepting proposals,"
             " asking the AI"},
            {"name": "answer_gold", "label": "answer gold-set items"},
        ],
        "expires_at": (NOW + timedelta(hours=8)).isoformat().replace("+00:00", "Z"),
        "idle_expires_at": (NOW + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "idle_timeout_s": 1800,
        "stepped_up_at": None,
        "step_up_valid_until": None,
        "since": None,
    }  # fmt: skip
    assert got.headers["cache-control"] == "no-store"  # the CSRF token is never cached
    assert await audit(seeded, "login") == [("user:asha", "login", "success", None, None)]


async def test_the_login_csrf_token_must_match_its_cookie(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as other:
        foreign = form_token((await other.get("/signin")).text)
    async with browser(web_engine) as http:
        await http.get("/signin")
        data = {"username": "asha", "password": PASSWORD}
        for token in ("", "x" * 43, foreign):  # none, made up, another browser's
            refused = await http.post("/signin", data={**data, "signin_token": token})
            assert refused.status_code == 403, token
            assert "The sign-in form expired; try again." in refused.text
            assert not any(c.startswith("argus_session=")
                           for c in refused.headers.get_list("set-cookie"))  # fmt: skip
        http.cookies.clear()
        bare = await http.post("/signin", data={**data, "signin_token": foreign})
        assert bare.status_code == 403  # no cookie at all
    assert await audit(seeded, "login") == []  # nothing checked, nothing counted


@pytest.mark.parametrize(
    ("asked", "lands"),
    [
        ("/investigations/abc?columns=set&cols=host.name",
         "/investigations/abc?columns=set&cols=host.name"),
        ("/go/case/2b6f0cc9-4f1a-4f1e-9b0e-2f1f3c1d9e11",
         "/go/case/2b6f0cc9-4f1a-4f1e-9b0e-2f1f3c1d9e11"),
        ("//evil.example/x", "/"),
        ("https://evil.example/", "/"),
        ("/\\evil.example", "/"),
        ("/\t/evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("/api/v1/session", "/"),
        ("/signin", "/"),
        ("/static/style.css", "/"),
        ("/résumé", "/"),
        ("rules", "/"),
    ],
)  # fmt: skip
async def test_sign_in_goes_back_only_to_a_page_of_this_site(
    seeded: AsyncEngine, asked: str, lands: str, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        signed = await sign_in(http, next_=asked)
    assert (signed.status_code, signed.headers["location"]) == (303, lands)


async def test_wrong_passwords_are_refused_alike_and_throttled(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with seeded.begin() as conn:  # an account that may not use ARGUS (no view)
        await auth.add_user(conn, "mira", "Mira", PASSWORD, capabilities=())
    async with browser(web_engine) as http:
        no_access = await sign_in(http, "mira")
        assert no_access.status_code == 401  # the same answer as a wrong password
        assert "Wrong name or password." in no_access.text
        for _ in range(throttle.NAME_LIMIT):
            wrong = await sign_in(http, password="not the password")
            assert wrong.status_code == 401
            assert "Wrong name or password." in wrong.text
        held = await sign_in(http)
        assert held.status_code == 429
        assert TOO_MANY.capitalize() + "." in held.text
    assert await audit(seeded, "login") == [
        ("web", "login", "denied", "mira", "no access"),
        *[("web", "login", "denied", "asha", None)] * throttle.NAME_LIMIT,
        ("web", "login", "denied", "asha", "throttled"),
    ]


async def test_signed_in_the_sign_in_page_goes_straight_on(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        await sign_in(http)
        on = await http.get("/signin", params={"next": "/rules"})
        assert (on.status_code, on.headers["location"]) == (303, "/rules")
        evil = await http.get("/signin", params={"next": "//evil.example"})
        assert (evil.status_code, evil.headers["location"]) == (303, "/")


async def test_the_old_login_address_leads_to_the_sign_in_page(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        bare = await http.get("/login")
        assert (bare.status_code, bare.headers["location"]) == (303, "/signin")
        kept = await http.get("/login", params={"next": "/rules"})
        assert kept.headers["location"] == "/signin?next=%2Frules"
        dropped = await http.get("/login", params={"next": "https://evil.example"})
        assert dropped.headers["location"] == "/signin"
        form = await http.post("/login", data={"username": "asha", "password": PASSWORD})
        assert (form.status_code, form.headers["location"]) == (303, "/")  # still served


async def test_a_page_after_the_session_ended_says_so(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    clock = Clock()
    async with browser(web_engine, clock) as http:
        await sign_in(http)
        clock.at += timedelta(minutes=31)
        page = await http.get("/access")
        assert (page.status_code, page.headers["location"]) == (
            303, "/signin?next=%2Faccess&why=ended")  # fmt: skip
        shown = await http.get(page.headers["location"])
        assert "Your session ended. Sign in again to continue." in shown.text
        assert 'name="next" value="/access"' in shown.text


# --------------------------------------------------------------------------- the session


async def test_the_session_without_a_session_and_signing_out(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        none = await http.get("/api/v1/session")
        assert (none.status_code, none.json()) == (
            401, {"detail": "sign in first", "code": "unauthenticated"})  # fmt: skip
        await sign_in(http)
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        forged = await http.delete("/api/v1/session", headers={"X-CSRF-Token": "forged"})
        assert (forged.status_code, forged.json()["code"]) == (403, "csrf")
        assert (await http.get("/api/v1/session")).status_code == 200  # nothing ended
        token = http.cookies["argus_session"]
        out = await http.delete("/api/v1/session", headers={"X-CSRF-Token": csrf})
        assert (out.status_code, out.content) == (204, b"")
        assert 'argus_session=""' in out.headers["set-cookie"]
        assert "Max-Age=0" in out.headers["set-cookie"]
        http.cookies.set("argus_session", token)
        after = await http.get("/api/v1/session")
        assert (after.status_code, after.json()["code"]) == (401, "unauthenticated")
    assert await audit(seeded, "logout") == [("user:asha", "logout", "success", None, None)]


async def test_background_requests_never_keep_a_session_alive(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    background = {"X-Argus-Background": "1"}
    clock = Clock()
    async with browser(web_engine, clock) as http:
        await sign_in(http)
        for minutes in (5, 12, 20, 29):  # the cost bar and the app's polls
            clock.at = NOW + timedelta(minutes=minutes)
            for path in ("/api/v1/cost", "/api/v1/session", "/api/v1/counts"):
                got = await http.get(path, headers=background)
                assert got.status_code == 200, (path, minutes)
        assert await last_seen(seeded) == [NOW]  # untouched
        polled = (await http.get("/api/v1/session", headers=background)).json()
        assert polled["idle_expires_at"] == "2026-10-09T12:30:00Z"
        clock.at = NOW + timedelta(minutes=30, seconds=1)
        gone = await http.get("/api/v1/counts", headers=background)
        assert (gone.status_code, gone.json()["code"]) == (401, "unauthenticated")
    clock = Clock()
    async with browser(web_engine, clock) as http:  # the same, with a person's own requests
        await sign_in(http)
        for minutes in (5, 12, 20, 29):
            clock.at = NOW + timedelta(minutes=minutes)
            assert (await http.get("/api/v1/counts")).status_code == 200
        clock.at = NOW + timedelta(minutes=30, seconds=1)
        assert (await http.get("/api/v1/counts")).status_code == 200
        assert (await last_seen(seeded))[-1] == NOW + timedelta(minutes=30, seconds=1)


async def test_a_session_ends_at_its_absolute_end_however_active(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    clock = Clock()
    async with browser(web_engine, clock) as http:
        await sign_in(http)
        while clock.at < NOW + timedelta(hours=8):
            clock.at = min(clock.at + timedelta(minutes=20), NOW + timedelta(hours=8))
            assert (await http.get("/api/v1/counts")).status_code == 200, clock.at
        clock.at = NOW + timedelta(hours=8, seconds=1)
        assert (await http.get("/api/v1/counts")).status_code == 401
        assert (await http.get("/access")).status_code == 303
    short = WebSettings(session_idle=timedelta(minutes=5), session_absolute=timedelta(minutes=10))
    clock = Clock()
    async with browser(web_engine, clock, short) as http:
        await sign_in(http)
        body = (await http.get("/api/v1/session")).json()
        assert (body["expires_at"], body["idle_timeout_s"]) == ("2026-10-09T12:10:00Z", 300)
        clock.at = NOW + timedelta(minutes=4)
        assert (await http.get("/api/v1/counts")).status_code == 200
        clock.at = NOW + timedelta(minutes=8)
        idle_end = (await http.get("/api/v1/session")).json()["idle_expires_at"]
        assert idle_end == "2026-10-09T12:10:00Z"  # the idle end never passes the absolute one


async def test_step_up_confirms_the_person(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    clock = Clock()
    async with browser(web_engine, clock) as http:
        signed_out = await http.get("/stepup")
        assert (signed_out.status_code, signed_out.headers["location"]) == (303, "/signin")
        await sign_in(http)
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        form = await http.get("/stepup", params={"next": "/proposals"})
        assert form.status_code == 200
        assert "script-src 'none'" in form.headers["content-security-policy"]
        assert "<script" not in form.text
        assert 'name="next" value="/proposals"' in form.text
        assert 'autocomplete="username"' in form.text  # password managers fill it
        expired = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": "x"})
        assert (expired.status_code, "The form expired" in expired.text) == (403, True)
        wrong = await http.post("/stepup", data={"password": "not it at all", "csrf_token": csrf})
        assert (wrong.status_code, "Wrong password." in wrong.text) == (401, True)
        clock.at = NOW + timedelta(minutes=2)
        done = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf,
                                                "next": "/proposals"})  # fmt: skip
        assert (done.status_code, done.headers["location"]) == (303, "/proposals")
        body = (await http.get("/api/v1/session")).json()
        assert body["stepped_up_at"] == "2026-10-09T12:02:00Z"
        assert body["step_up_valid_until"] == "2026-10-09T12:07:00Z"
        async with seeded.connect() as conn:
            failures = await conn.scalar(text("SELECT stepup_failures FROM user_sessions"))
        assert failures == 0  # a success forgets the earlier failure
    assert [r[:3] for r in await audit(seeded, "stepup")] == [
        ("web", "stepup", "denied"), ("user:asha", "stepup", "success")]  # fmt: skip


async def test_three_wrong_step_ups_end_the_session(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        await sign_in(http)
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        for _ in range(auth.STEP_UP_FAILURES - 1):
            wrong = await http.post("/stepup", data={"password": "nope nope nope",
                                                     "csrf_token": csrf})  # fmt: skip
            assert wrong.status_code == 401
        token = http.cookies["argus_session"]
        last = await http.post("/stepup", data={"password": "nope nope nope", "csrf_token": csrf})
        assert (last.status_code, last.headers["location"]) == (303, "/signin?why=stepup")
        assert "Max-Age=0" in last.headers["set-cookie"]
        http.cookies.set("argus_session", token)
        assert (await http.get("/api/v1/session")).status_code == 401
        notice = await http.get("/signin?why=stepup")
        assert "You were signed out after three wrong passwords." in notice.text
    async with seeded.connect() as conn:
        ended = await conn.scalar(text("SELECT ended_at FROM user_sessions"))
    assert ended == NOW


async def test_failed_step_ups_count_toward_the_name_throttle(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        for _ in range(2):  # two sessions, two failures each: four failures of asha
            http.cookies.clear()
            await sign_in(http)
            csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
            for _ in range(2):
                await http.post("/stepup", data={"password": "nope nope nope",
                                                 "csrf_token": csrf})  # fmt: skip
        http.cookies.clear()
        await sign_in(http, password="still not it")  # the fifth
        held = await sign_in(http)
        assert held.status_code == 429


# --------------------------------------------------------------------------- origins


CHANGE_PATHS = ("/api/v1/session",)


@pytest.mark.parametrize(
    ("headers", "allowed"),
    [
        ({}, False),  # neither header: refused since Q-A1 (it passed before)
        ({"Origin": BASE}, True),
        ({"Origin": "http://127.0.0.1:8765"}, False),  # another origin, same host
        ({"Origin": "http://evil.example"}, False),
        ({"Origin": "null"}, False),
        ({"Sec-Fetch-Site": "same-origin"}, True),
        ({"Sec-Fetch-Site": "same-site"}, False),
        ({"Sec-Fetch-Site": "cross-site"}, False),
        ({"Sec-Fetch-Site": "none"}, False),
        ({"Origin": BASE, "Sec-Fetch-Site": "cross-site"}, False),
        ({"Origin": BASE, "Sec-Fetch-Site": "same-origin"}, True),
        ({"Origin": "HTTP://127.0.0.1"}, True),  # origins compare without case
    ],
)  # fmt: skip
async def test_a_change_must_come_from_this_sites_own_page(
    seeded: AsyncEngine, headers: dict[str, str], allowed: bool, web_engine: AsyncEngine
) -> None:
    app = create_app(web_engine, clock=lambda: NOW)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as http:
        made = await http.post("/api/login", json={"username": "asha", "password": PASSWORD},
                               headers=SAME_ORIGIN)  # fmt: skip
        csrf = made.json()["csrf_token"]
        v1 = await http.delete("/api/v1/session", headers={"X-CSRF-Token": csrf, **headers})
        classic = await http.post("/api/login", json={"username": "asha", "password": PASSWORD},
                                  headers=headers)  # fmt: skip
    if allowed:
        assert (v1.status_code, classic.status_code) == (204, 200)
    else:
        assert (v1.status_code, v1.json()["code"]) == (403, "origin")
        assert set(v1.json()) == {"detail", "code"}
        assert classic.status_code == 403
        assert set(classic.json()) == {"detail"}


async def test_other_sites_get_no_api_but_may_link_to_pages(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        await sign_in(http)
        site = {"Sec-Fetch-Site": "cross-site"}
        for path in ("/api/v1/session", "/api/v1/investigations", "/api/rules", "/api/v1/cost"):
            got = await http.get(path, headers=site)
            assert got.status_code == 403, path
        v1 = await http.get("/api/v1/counts", headers={"Sec-Fetch-Site": "same-site"})
        assert v1.json() == {"detail": "the API answers this site's own pages only",
                             "code": "origin"}  # fmt: skip
        page = await http.get("/access", headers={**site, "Sec-Fetch-Mode": "navigate"})
        assert page.status_code == 200  # a navigation from elsewhere is a page view
        mine = await http.get("/api/v1/session", headers={"Sec-Fetch-Site": "same-origin"})
        assert mine.status_code == 200


# --------------------------------------------------------------------------- cookies, links


async def test_under_tls_the_cookies_are_host_cookies(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    lan = WebSettings.model_validate(LAN)
    async with browser(web_engine, settings=lan, base="https://10.13.171.247",
                       client="10.13.171.9") as http:  # fmt: skip
        page = await http.get("/signin")
        assert page.headers["set-cookie"].startswith("__Host-argus_signin=")
        assert "Secure" in page.headers["set-cookie"]
        signed = await http.post(
            "/signin",
            data={"username": "asha", "password": PASSWORD, "signin_token": form_token(page.text)},
        )
        assert signed.status_code == 303
        made = next(c for c in signed.headers.get_list("set-cookie")
                    if c.startswith("__Host-argus_session="))  # fmt: skip
        assert "Secure" in made
        assert "Path=/" in made
        assert "Domain" not in made
        assert (await http.get("/api/v1/session")).status_code == 200
        csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
        token = http.cookies["__Host-argus_session"]
        http.cookies.clear()
        http.cookies.set("argus_session", token)  # the plain name means nothing under TLS
        assert (await http.get("/api/v1/session")).status_code == 401
        http.cookies.clear()
        http.cookies.set("__Host-argus_session", token)
        out = await http.delete("/api/v1/session", headers={"X-CSRF-Token": csrf})
        assert out.status_code == 204
        cleared = out.headers["set-cookie"]  # a browser unsets a __Host- cookie only so
        assert cleared.startswith("__Host-argus_session=")
        for part in ("Max-Age=0", "Path=/", "Secure", "HttpOnly", "SameSite=strict"):
            assert part in cleared, part


async def test_permanent_links(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    inv = uuid.UUID("2b6f0cc9-4f1a-4f1e-9b0e-2f1f3c1d9e11")
    app = create_app(web_engine, clock=lambda: NOW)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as http:
        went = await http.get(f"/go/investigation/{inv}")
        assert (went.status_code, went.headers["location"]) == (303, f"/app/investigations/{inv}")
        upper = await http.get(f"/go/investigation/{str(inv).upper()}")
        assert upper.headers["location"] == f"/app/investigations/{inv}"  # one canonical form
        bounced = await http.get(f"/go/investigation/{inv}",
                                 headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
        assert bounced.status_code == 200  # opened again from this site: the cookie comes
        assert f'content="0;url=/app/investigations/{inv}"' in bounced.text
        assert "<script" not in bounced.text
        assert (await http.get("/go/investigation/not-an-id")).status_code == 404  # a page (F8)
        case = await http.get(f"/go/case/{inv}")  # Q-B3 set the case page: /app/cases/<id>
        assert (case.status_code, case.headers["location"]) == (303, f"/app/cases/{inv}")
        app.state.case_page = lambda case_id: None  # a case with no page: a page, not a crash
        gone = await http.get(f"/go/case/{inv}")
        assert (gone.status_code, "No such case." in gone.text) == (404, True)
        app.state.case_page = lambda case_id: f"/cases/{case_id}"
        found = await http.get(f"/go/case/{inv}")
        assert (found.status_code, found.headers["location"]) == (303, f"/cases/{inv}")
    named = WebSettings(public_url="https://localhost:8443")
    assert links.investigation_url(named, inv) == f"https://localhost:8443/go/investigation/{inv}"
    assert links.case_url(WebSettings(), inv) == f"http://127.0.0.1:8765/go/case/{inv}"
    lan = WebSettings.model_validate(LAN)
    assert links.case_url(lan, inv) == f"https://10.13.171.247:8765/go/case/{inv}"


async def test_a_signed_out_link_goes_through_sign_in_and_back(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        inv = (await conn.execute(text("SELECT id FROM investigations LIMIT 1"))).scalar_one()
    async with browser(web_engine) as http:
        link = await http.get(f"/go/investigation/{inv}")
        page = await http.get(link.headers["location"])
        assert page.status_code == 303
        query = parse_qs(urlsplit(page.headers["location"]).query)
        assert query == {"next": [f"/app/investigations/{inv}"]}
        signed = await sign_in(http, next_=query["next"][0])
        assert signed.headers["location"] == f"/app/investigations/{inv}"
        assert (await http.get(signed.headers["location"])).status_code == 200


def test_the_capabilities_of_a_reviewer_never_widen_silently() -> None:
    reviewer = auth.Reviewer(1, "a", "A", "c", None, frozenset({Capability.VIEW}))
    assert reviewer.can(Capability.VIEW)
    assert reviewer.can("view")
    assert not reviewer.can(Capability.REVIEW)
    assert not reviewer.can("admin")
    assert reviewer.named() == ["view"]


async def test_signing_in_again_ends_this_browsers_earlier_session(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        await sign_in(http)
        first = http.cookies["argus_session"]
        token = "t" * 43  # a form token and its cookie, as the sign-in page would set them
        again = await http.post("/signin", headers={"Cookie": f"argus_session={first};"
                                                    f" argus_signin={token}"},
                                data={"username": "asha", "password": PASSWORD,
                                      "signin_token": token})  # fmt: skip
        assert again.status_code == 303
        made = next(c for c in again.headers.get_list("set-cookie")
                    if c.startswith("argus_session="))  # fmt: skip
        second = made.split(";")[0].split("=", 1)[1]
        assert second != first
    for token, status in ((first, 401), (second, 200)):
        async with browser(web_engine) as http:
            got = await http.get("/api/v1/session", headers={"Cookie": f"argus_session={token}"})
            assert got.status_code == status


async def test_a_refused_sign_in_form_keeps_only_a_valid_name(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with browser(web_engine) as http:
        await http.get("/signin")
        bad = await http.post("/signin", data={"username": "<b>x</b>", "password": "p",
                                               "signin_token": "wrong"})  # fmt: skip
        assert bad.status_code == 403
        assert 'name="username" autocomplete="username"' in bad.text
        assert 'value=""' in bad.text
        assert "&lt;b&gt;" not in bad.text
        good = await http.post("/signin", data={"username": "asha", "password": "p",
                                                "signin_token": "wrong"})  # fmt: skip
        assert 'value="asha"' in good.text
