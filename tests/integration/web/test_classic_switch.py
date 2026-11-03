"""Q-B4: the switch to ``/app`` (``web.classic``), on the real app and its database.

- Off (the default): nothing moves; ``/classic`` leads to the classic Inbox; a permanent link to an
  investigation opens the classic page.
- On: every classic page address answers 303 to its page in ``/app`` (query kept where the app reads
  it the same way), signed in or not; the classic pages are a read-only fallback a browser chooses
  at ``/classic`` (a session cookie, cleared by opening ``/app``); every classic form is refused
  with a pointer to ``/app`` and writes nothing; the policy headers are the same on every answer;
  sign-in, step-up, logout, the permanent links, "Your access" and both APIs keep working.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import classic, security, spa
from argus.web.app import SECURITY_HEADERS, create_app
from tests.integration.web.conftest import BASE, NOW, SAME_ORIGIN, log_in

pytestmark = pytest.mark.integration
ON = WebSettings(classic="fallback", failure_delay_s=0, signin_delay_s=0)
OFF = WebSettings(failure_delay_s=0, signin_delay_s=0)


def make_client(engine: AsyncEngine, settings: WebSettings) -> httpx.AsyncClient:
    app = create_app(engine, settings, clock=lambda: NOW + timedelta(hours=1))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


@pytest.fixture
async def on(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(web_engine, ON) as http:
        yield http


@pytest.fixture
async def off(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(web_engine, OFF) as http:
        yield http


async def an_investigation(http: httpx.AsyncClient) -> str:
    listed = await http.get("/api/investigations", params={"view": "all"})
    return str(listed.json()[0]["id"])


def same_policy(response: httpx.Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value, name


ID = str(uuid.UUID(int=7))
MOVES = [
    ("/", "/app"),
    ("/?view=open", "/app/inbox?view=open"),
    ("/?view=all&rule=rule-1&sort=urgent&offset=100",
     "/app/inbox?view=all&rule=rule-1&sort=urgent"),
    ("/?view=all&kind=ip&value=10.0.0.1", "/app/inbox?view=all&kind=ip&value=10.0.0.1"),
    ("/dashboard", "/app/dashboard"),
    ("/dashboard?range=24h&severity=high&state=unreviewed",
     "/app/dashboard?range=24h&severity=high&state=unreviewed"),
    ("/rules", "/app/rules"),
    ("/hosts", "/app/hosts"),
    ("/patterns", "/app/patterns"),
    ("/proposals?confirmed=2-0", "/app/proposals"),
    ("/tuning", "/app/tuning"),
    ("/metrics", "/app/metrics"),
    ("/gold", "/app/gold"),
    ("/health", "/app/health"),
    ("/glossary", "/app/glossary"),
    (f"/investigations/{ID}", f"/app/investigations/{ID}"),
    (f"/investigations/{ID}?saved=reviewed", f"/app/investigations/{ID}"),
    (f"/investigations/{ID}/report?assessment=3", f"/app/investigations/{ID}?tab=report"),
    (f"/investigations/{ID}/alerts/abc%2F123", f"/app/investigations/{ID}?tab=alerts"),
]  # fmt: skip


@pytest.mark.parametrize(("path", "target"), MOVES)
async def test_each_classic_address_leads_to_its_page_in_the_app(
    on: httpx.AsyncClient, path: str, target: str
) -> None:
    """The move needs no session (it shows nothing); the app's page then asks for one."""
    for method in ("GET", "HEAD"):
        response = await on.request(method, path)
        assert response.status_code == 303
        assert response.headers["location"] == target
        same_policy(response)
    await log_in(on)
    assert (await on.get(path)).headers["location"] == target
    landed = await on.get(target)
    assert landed.status_code == 200
    assert landed.headers["content-security-policy"] == spa.CSP_APP


async def test_an_investigation_written_in_any_spelling_of_its_id_moves_to_the_app(
    on: httpx.AsyncClient,
) -> None:
    await log_in(on)
    inv = await an_investigation(on)
    for spelled in spellings(inv):
        for tail, tab in (("", ""), ("/report", "?tab=report"), ("/alerts/x", "?tab=alerts")):
            response = await on.get(f"/investigations/{spelled}{tail}")
            assert response.status_code == 303, (spelled, tail)
            assert response.headers["location"] == f"/app/investigations/{inv}{tab}", spelled


async def test_signed_out_the_app_page_asks_for_sign_in_and_comes_back_to_it(
    on: httpx.AsyncClient,
) -> None:
    moved = await on.get("/rules")
    asked = await on.get(moved.headers["location"])
    assert asked.status_code == 303
    target = httpx.URL(asked.headers["location"])
    assert (target.path, target.params["next"]) == ("/signin", "/app/rules")


async def test_a_query_is_not_copied_into_the_header_raw(on: httpx.AsyncClient) -> None:
    response = await on.get("/?view=open&rule=%0d%0aX-Evil%3a%201&other=%0d%0a")
    assert response.status_code == 303
    location = response.headers["location"]
    assert "\r" not in location
    assert "\n" not in location
    assert "x-evil" not in {k.lower() for k in response.headers}
    assert urlsplit(location).path == "/app/inbox"


@pytest.mark.parametrize(
    ("path", "status", "location"),
    [
        ("/access", 200, None),
        ("/signin", 303, "/"),  # signed in: back to where you were going
        ("/login", 303, "/signin"),
        ("/api/investigations", 200, None),
        ("/api/v1/session", 200, None),
        ("/static/style.css", 200, None),
        ("/app", 200, None),
        ("/app/rules", 200, None),
        ("/go/case/" + ID, 303, "/app/cases/" + ID),  # already led to the app (Q-B3)
    ],
)  # fmt: skip
async def test_what_is_not_a_classic_page_does_not_move(
    on: httpx.AsyncClient, path: str, status: int, location: str | None
) -> None:
    await log_in(on)
    response = await on.get(path)
    assert response.status_code == status
    assert response.headers.get("location") == location


# --------------------------------------------------------------------------- the fallback


async def test_the_fallback_is_a_browsers_choice_and_opening_the_app_ends_it(
    on: httpx.AsyncClient,
) -> None:
    await log_in(on)
    assert (await on.get("/")).headers["location"] == "/app"
    chose = await on.get("/classic")
    assert (chose.status_code, chose.headers["location"]) == (303, "/")
    cookie = chose.headers["set-cookie"]
    assert cookie.startswith(f"{classic.COOKIE}=1;")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/" in cookie
    assert "max-age" not in cookie.lower()
    assert "expires" not in cookie.lower()
    same_policy(chose)
    for path in ("/", "/dashboard", "/rules", "/hosts", "/patterns", "/proposals", "/tuning",
                 "/metrics", "/gold", "/health", "/glossary"):  # fmt: skip
        page = await on.get(path)
        assert page.status_code == 200, path
        assert "Classic pages, read-only." in page.text, path
        assert '<body class="read-only">' in page.text, path
        same_policy(page)
    inv = await an_investigation(on)
    detail = await on.get(f"/investigations/{inv}")
    assert detail.status_code == 200
    assert "Classic pages, read-only." in detail.text
    for path in (f"/investigations/{inv}/report",):
        assert (await on.get(path)).status_code in (200, 404)  # the page itself answers
    opened = await on.get("/app")
    assert opened.status_code == 200
    assert opened.headers["content-security-policy"] == spa.CSP_APP
    assert f"{classic.COOKIE}=" in opened.headers["set-cookie"]  # cleared
    on.cookies.delete(classic.COOKIE)  # the client applies Max-Age=0 itself; be sure
    assert (await on.get("/rules")).headers["location"] == "/app/rules"


async def test_opening_an_app_page_ends_the_fallback_too(on: httpx.AsyncClient) -> None:
    await log_in(on)
    await on.get("/classic")
    assert (await on.get("/rules")).status_code == 200
    again = await on.get("/app/rules")
    assert again.status_code == 200
    assert classic.COOKIE in again.headers["set-cookie"]
    assert on.cookies.get(classic.COOKIE) is None
    assert (await on.get("/rules")).status_code == 303


async def test_the_fallback_cookie_grants_nothing(
    on: httpx.AsyncClient, seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """Without a session the classic page still sends to sign-in, cookie or not."""
    on.cookies.set(classic.COOKIE, "1")
    response = await on.get("/rules")
    assert response.status_code == 303
    assert httpx.URL(response.headers["location"]).path == "/signin"
    api = await on.get("/api/v1/rules")
    assert api.status_code == 401


@pytest.mark.parametrize(
    ("site", "sets"),
    [(None, True), ("same-origin", True), ("none", True),
     ("same-site", False), ("cross-site", False)],
)  # fmt: skip
async def test_the_choice_is_made_by_this_sites_own_page_or_the_person_not_another_origins(
    on: httpx.AsyncClient, site: str | None, sets: bool
) -> None:
    """Review B4 finding 6: a sibling host of this site reaches the Strict session cookie too."""
    await log_in(on)
    headers = {} if site is None else {"Sec-Fetch-Site": site}
    response = await on.get("/classic", headers=headers)
    assert response.status_code == 303
    assert (f"{classic.COOKIE}=1" in response.headers.get("set-cookie", "")) is sets


async def test_choosing_the_fallback_needs_a_session(on: httpx.AsyncClient) -> None:
    response = await on.get("/classic")
    assert response.status_code == 303
    target = httpx.URL(response.headers["location"])
    assert (target.path, target.params["next"]) == ("/signin", "/classic")
    assert "set-cookie" not in response.headers


async def test_the_classic_pages_hide_their_forms_in_the_fallback() -> None:
    """The read-only look is a rule of the classic style sheet (no inline style: the policy)."""
    from pathlib import Path

    import argus.web

    css = (Path(argus.web.__file__).parent / "static" / "style.css").read_text()
    for selector in ('body.read-only form[action="/patterns/review"]',
                     'body.read-only form[action="/proposals/confirm"]',
                     'body.read-only form[action$="/review"]',
                     'body.read-only form[action$="/accept"]',
                     'body.read-only form[action$="/assess"]',
                     'body.read-only form[action$="/gold"]'):  # fmt: skip
        assert selector in css
    assert "{ display: none; }" in css.rsplit("body.read-only", 1)[1]


# --------------------------------------------------------------------------- the forms


def spellings(inv: str) -> list[str]:
    """Other ways to write one id that the routes' ``uuid.UUID`` parameter accepts."""
    return [inv.upper(), inv.replace("-", ""), "{" + inv + "}", "urn:uuid:" + inv]


def forms(inv: str) -> list[tuple[str, str]]:
    return [
        ("/patterns/review", "/app/patterns"),
        ("/proposals/confirm", "/app/proposals"),
        (f"/investigations/{inv}/review", f"/app/investigations/{inv}"),
        (f"/investigations/{inv}/accept", f"/app/investigations/{inv}"),
        (f"/investigations/{inv}/assess", f"/app/investigations/{inv}"),
        (f"/investigations/{inv}/gold", f"/app/investigations/{inv}"),
    ]


async def rows(engine: AsyncEngine) -> tuple[int, int]:
    async with engine.connect() as conn:
        reviews = (await conn.execute(text("SELECT count(*) FROM review_events"))).scalar_one()
        audit = (
            await conn.execute(text("SELECT count(*) FROM audit_events WHERE action <> 'login'"))
        ).scalar_one()
    return int(reviews), int(audit)


@pytest.mark.parametrize("chosen", [False, True])
async def test_every_classic_form_is_refused_and_writes_nothing(
    on: httpx.AsyncClient, seeded: AsyncEngine, chosen: bool
) -> None:
    csrf = await log_in(on)
    if chosen:
        await on.get("/classic")
    inv = await an_investigation(on)
    before = await rows(seeded)
    body = {"csrf_token": csrf, "action": "reviewed", "outcome": "benign_expected",
            "seen_version": "1", "assessment_id": "1", "group": "x", "ids": "1",
            "items": f"{inv}:1:", "note": ""}  # fmt: skip
    for path, target in forms(inv):
        response = await on.post(path, data=body)
        assert response.status_code == 403, path
        assert "read-only" in response.text
        assert f'href="{target}"' in response.text
        same_policy(response)
    # the routes take an id in more than one spelling (review B4 finding 1): every one is refused
    for spelled in spellings(inv):
        for action in ("review", "accept", "assess", "gold"):
            response = await on.post(f"/investigations/{spelled}/{action}", data=body)
            assert response.status_code == 403, (spelled, action)
            assert f'href="/app/investigations/{inv}"' in response.text, (spelled, action)
    unparsed = await on.post("/investigations/not-an-id/review", data=body)
    assert (unparsed.status_code, 'href="/app"' in unparsed.text) == (403, True)
    assert await rows(seeded) == before


async def test_a_refused_form_needs_no_session_to_be_told_where_to_go(
    on: httpx.AsyncClient,
) -> None:
    response = await on.post("/patterns/review", data={"items": "x"})
    assert response.status_code == 403
    assert 'href="/app/patterns"' in response.text


async def test_a_forged_form_from_another_site_is_still_refused_first_by_the_origin_check(
    on: httpx.AsyncClient,
) -> None:
    await log_in(on)
    response = await on.post("/patterns/review", data={"items": "x"},
                             headers={"Origin": "http://evil.example"})  # fmt: skip
    assert response.status_code == 403
    assert response.json()["detail"] == "cross-origin request refused"


async def test_signing_out_and_in_and_the_stepup_still_work(on: httpx.AsyncClient) -> None:
    csrf = await log_in(on)
    assert (await on.get("/stepup")).status_code == 200
    out = await on.post("/logout", data={"csrf_token": csrf})
    assert out.status_code == 303
    assert httpx.URL(out.headers["location"]).path == "/signin"
    assert (await on.get("/signin")).status_code == 200


async def test_the_classic_json_api_and_v1_are_untouched(
    on: httpx.AsyncClient, off: httpx.AsyncClient
) -> None:
    for http in (on, off):
        csrf = await log_in(http)
        assert (await http.get("/api/investigations", params={"view": "all"})).status_code == 200
        assert (await http.get("/api/v1/rules")).status_code == 200
        inv = await an_investigation(http)
        saved = await http.post(
            f"/api/investigations/{inv}/reviews",
            json={"action": "note", "note": "kept", "seen_review": None, "seen_version": 1},
            headers={"X-CSRF-Token": csrf},
        )  # the classic API is not a classic page: it still works
        assert saved.status_code in (200, 201, 409, 422)  # never the switch's 403 page
        assert "read-only" not in saved.text


# --------------------------------------------------------------------------- permanent links


async def test_a_permanent_link_to_an_investigation_opens_it_in_the_app_when_on(
    on: httpx.AsyncClient, off: httpx.AsyncClient
) -> None:
    for http, expected in ((on, "/app/investigations/{}"), (off, "/investigations/{}")):
        await log_in(http)
        inv = await an_investigation(http)
        direct = await http.get(f"/go/investigation/{inv}")
        assert (direct.status_code, direct.headers["location"]) == (303, expected.format(inv))
        bounced = await http.get(
            f"/go/investigation/{inv}", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert bounced.status_code == 200
        assert f'content="0;url={expected.format(inv)}"' in bounced.text.replace(" ", "")


# --------------------------------------------------------------------------- off


async def test_off_nothing_moves_and_the_classic_pages_are_the_main_ones(
    off: httpx.AsyncClient,
) -> None:
    await log_in(off)
    for path in ("/", "/dashboard", "/rules", "/hosts", "/patterns", "/proposals", "/tuning",
                 "/metrics", "/gold", "/health", "/glossary"):  # fmt: skip
        page = await off.get(path)
        assert page.status_code == 200, path
        assert "Classic pages, read-only." not in page.text
        assert "read-only" not in page.text.split("<main")[0]
    chose = await off.get("/classic")
    assert (chose.status_code, chose.headers["location"]) == (303, "/")
    assert "set-cookie" not in chose.headers
    inv = await an_investigation(off)
    assert (await off.get(f"/investigations/{inv}")).status_code == 200


async def test_the_default_is_off() -> None:
    assert WebSettings().classic == "primary"
    assert security.CSP in SECURITY_HEADERS["Content-Security-Policy"]
