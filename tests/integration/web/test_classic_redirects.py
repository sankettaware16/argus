"""The classic pages are gone: every address ARGUS ever wrote outward leads to the same thing under
``/app`` (303, query kept where the app reads it the same way), signed in or not, and to a page the
app's router has; a classic form address answers 410 with a pointer to ``/app`` and changes
nothing; the policy headers are the same on every answer; sign-in, step-up, logout, the permanent
links, "Your access" and both APIs keep working. On the real app and its database."""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import spa
from argus.web.app import SECURITY_HEADERS, create_app
from tests.integration.web.conftest import BASE, NOW, SAME_ORIGIN, log_in

pytestmark = pytest.mark.integration
SETTINGS = WebSettings(failure_delay_s=0, signin_delay_s=0)
ROUTER = Path(__file__).parents[3] / "frontend" / "src" / "router.tsx"


def make_client(engine: AsyncEngine, settings: WebSettings) -> httpx.AsyncClient:
    app = create_app(engine, settings, clock=lambda: NOW + timedelta(hours=1))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


@pytest.fixture
async def on(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(web_engine, SETTINGS) as http:
        yield http


async def an_investigation(http: httpx.AsyncClient) -> str:
    listed = await http.get("/api/investigations", params={"view": "all"})
    return str(listed.json()[0]["id"])


def same_policy(response: httpx.Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value, name


def router_paths() -> list[re.Pattern[str]]:
    """The app's routes (frontend/src/router.tsx), as patterns of the path under /app."""
    source = ROUTER.read_text()
    paths = re.findall(r'path: "(/[^"]*)"', source)
    paths += re.findall(r'(?:plain|toAdvanced)\("(/[^"]*)"', source)
    assert len(paths) >= 20, paths
    return [
        re.compile("/".join("[^/]+" if seg.startswith("$") else re.escape(seg)
                            for seg in path.split("/")))
        for path in paths
    ]  # fmt: skip


ID = str(uuid.UUID(int=7))
MOVES = [
    ("/", "/app"),
    ("/?view=open", "/app/inbox?view=open"),
    ("/?view=all&rule=rule-1&sort=urgent&offset=100",
     "/app/inbox?view=all&rule=rule-1&sort=urgent"),
    ("/?view=all&kind=ip&value=10.0.0.1", "/app/inbox?view=all&kind=ip&value=10.0.0.1"),
    ("/inbox", "/app/inbox"),
    ("/inbox?view=all&offset=5", "/app/inbox?view=all"),
    ("/classic", "/app"),
    (f"/cases/{ID}", f"/app/cases/{ID}"),
    (f"/cases/{ID}/report?version=2", f"/app/incidents/{ID}?tab=report"),
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
    under_app = urlsplit(target).path.removeprefix("/app") or "/"
    assert any(r.fullmatch(under_app) for r in router_paths()), target


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
        ("/api/cost", 404, None),  # the classic pages' cost bar went with them
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


async def test_every_classic_form_is_gone_and_writes_nothing(
    on: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    csrf = await log_in(on)
    inv = await an_investigation(on)
    before = await rows(seeded)
    body = {"csrf_token": csrf, "action": "reviewed", "outcome": "benign_expected",
            "seen_version": "1", "assessment_id": "1", "group": "x", "ids": "1",
            "items": f"{inv}:1:", "note": ""}  # fmt: skip
    for path, target in forms(inv):
        response = await on.post(path, data=body)
        assert response.status_code == 410, path
        assert "The classic pages are gone" in response.text
        assert f'href="{target}"' in response.text
        same_policy(response)
    # the routes take an id in more than one spelling (review B4 finding 1): every one is refused
    for spelled in spellings(inv):
        for action in ("review", "accept", "assess", "gold"):
            response = await on.post(f"/investigations/{spelled}/{action}", data=body)
            assert response.status_code == 410, (spelled, action)
            assert f'href="/app/investigations/{inv}"' in response.text, (spelled, action)
    unparsed = await on.post("/investigations/not-an-id/review", data=body)
    assert (unparsed.status_code, 'href="/app"' in unparsed.text) == (410, True)
    assert await rows(seeded) == before


async def test_a_gone_form_needs_no_session_to_be_told_where_to_go(
    on: httpx.AsyncClient,
) -> None:
    response = await on.post("/patterns/review", data={"items": "x"})
    assert response.status_code == 410
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


async def test_the_json_api_and_v1_are_untouched(on: httpx.AsyncClient) -> None:
    csrf = await log_in(on)
    assert (await on.get("/api/investigations", params={"view": "all"})).status_code == 200
    assert (await on.get("/api/v1/rules")).status_code == 200
    inv = await an_investigation(on)
    saved = await on.post(
        f"/api/investigations/{inv}/reviews",
        json={"action": "note", "note": "kept", "seen_review": None, "seen_version": 1},
        headers={"X-CSRF-Token": csrf},
    )  # the JSON API is not a classic page: it still works
    assert saved.status_code in (200, 201, 409, 422)  # never the 410 page
    assert "classic pages are gone" not in saved.text


# --------------------------------------------------------------------------- permanent links


async def test_a_permanent_link_to_an_investigation_opens_it_in_the_app(
    on: httpx.AsyncClient,
) -> None:
    await log_in(on)
    inv = await an_investigation(on)
    target = f"/app/investigations/{inv}"
    direct = await on.get(f"/go/investigation/{inv}")
    assert (direct.status_code, direct.headers["location"]) == (303, target)
    bounced = await on.get(f"/go/investigation/{inv}", headers={"Sec-Fetch-Site": "cross-site"})
    assert bounced.status_code == 200
    assert f'content="0;url={target}"' in bounced.text.replace(" ", "")


async def test_an_older_config_that_still_sets_the_switch_loads_and_changes_nothing(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    old = WebSettings(classic="primary", failure_delay_s=0, signin_delay_s=0)
    async with make_client(web_engine, old) as http:
        assert (await http.get("/rules")).headers["location"] == "/app/rules"
