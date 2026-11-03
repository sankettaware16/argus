"""Q-A1's route test (plan §5 Q-A1, review 1's blocker): every route, classic or v1, declares
what it needs, and the declaration is the check.

- Each route carries exactly one requirement: a ``Need`` (a session, a capability, a CSRF
  token for a change) or an ``Open`` from a short, pinned list (signing in and out, public
  files, permanent links). A new route without one fails here.
- The capability of every route is pinned in ``EXPECTED``: a change to one, or a new route,
  needs this table changed too.
- Enforced, not only declared: every change refuses a missing session, a wrong CSRF token and
  a view-only account, and writes nothing then; every read refuses an account without view.
- No state change from a URL: every GET route leaves the database as it was.
- Local accounts keep what they could do: every classic route needs only what every account
  had before capabilities existed.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from argus.web.app import create_app
from argus.web.capabilities import LOCAL_DEFAULT, Capability
from argus.web.deps import Need, Open, Surface
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
C = Capability
CHANGES = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SESSION = "session"  # a signed-in person, whatever they may do (signing out, step-up)

# Every route and what it needs. A new route must be added here, with its requirement.
EXPECTED: dict[tuple[str, str], Any] = {
    # the classic JSON API
    ("POST", "/api/login"): "open",
    ("POST", "/api/logout"): SESSION,
    ("GET", "/api/investigations"): C.VIEW,
    ("GET", "/api/investigations/{investigation_id}"): C.VIEW,
    ("GET", "/api/investigations/{investigation_id}/alerts/{alert_id}/raw"): C.VIEW,
    ("GET", "/api/investigations/{investigation_id}/report"): C.VIEW,  # report@2 (Q-F2)
    ("POST", "/api/investigations/{investigation_id}/reviews"): C.REVIEW,
    ("GET", "/api/rules"): C.VIEW,
    ("GET", "/api/entities"): C.VIEW,
    ("GET", "/api/cost"): C.VIEW,
    ("GET", "/api/dashboard"): C.VIEW,
    ("GET", "/api/health"): C.VIEW,
    # /api/v1
    ("GET", "/api/v1/openapi.json"): "open",
    ("GET", "/api/v1/session"): SESSION,
    ("DELETE", "/api/v1/session"): SESSION,
    ("GET", "/api/v1/queue"): C.VIEW,
    ("GET", "/api/v1/investigations"): C.VIEW,
    ("GET", "/api/v1/counts"): C.VIEW,
    ("GET", "/api/v1/investigations/{investigation_id}"): C.VIEW,
    ("GET", "/api/v1/investigations/{investigation_id}/alerts"): C.VIEW,
    ("GET", "/api/v1/investigations/{investigation_id}/alerts/{alert_id}"): C.VIEW,
    ("POST", "/api/v1/investigations/{investigation_id}/reviews"): C.REVIEW,
    ("POST", "/api/v1/investigations/{investigation_id}/gold"): C.ANSWER_GOLD,
    ("POST", "/api/v1/investigations/{investigation_id}/accept"): C.REVIEW,
    ("POST", "/api/v1/investigations/{investigation_id}/assess"): C.REVIEW,
    ("GET", "/api/v1/proposals"): C.VIEW,
    ("POST", "/api/v1/proposals/confirm"): C.REVIEW,
    ("GET", "/api/v1/patterns"): C.VIEW,
    ("GET", "/api/v1/patterns/summary"): C.VIEW,
    ("GET", "/api/v1/patterns/closing"): C.VIEW,
    ("POST", "/api/v1/patterns/review"): C.REVIEW,
    ("GET", "/api/v1/rules"): C.VIEW,
    ("GET", "/api/v1/entities"): C.VIEW,
    ("GET", "/api/v1/health"): C.VIEW,
    ("GET", "/api/v1/glossary"): C.VIEW,
    ("GET", "/api/v1/cost"): C.VIEW,
    ("GET", "/api/v1/metrics"): C.VIEW,
    ("GET", "/api/v1/tuning"): C.VIEW,
    ("GET", "/api/v1/gold"): C.VIEW,
    ("GET", "/api/v1/reports"): C.VIEW,  # Q-H3
    ("GET", "/api/v1/reports/{report_id}"): C.VIEW,  # Q-H3
    ("GET", "/api/v1/dashboard"): C.VIEW,
    ("GET", "/api/v1/dashboard/threat-lists"): C.VIEW,  # Q-B2
    ("GET", "/api/v1/since"): C.VIEW,  # Q-B2
    ("GET", "/api/v1/investigations/{investigation_id}/reports"): C.VIEW,  # Q-B2 (report@2)
    # Q-B3: cases, their commands, the approvals queue, notes and "Check more"
    ("GET", "/api/v1/cases"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}/closure-preview"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}/merge-preview"): C.VIEW,
    ("POST", "/api/v1/cases/{case_id}/take"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/assign"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/release"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/contain"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/reopen"): C.REOPEN,
    ("POST", "/api/v1/cases/{case_id}/closure-requests"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/merge"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/suggestions/{suggestion_id}/dismiss"): C.MANAGE_CASES,
    # AR4b: the owner was told, a network block, the reminders, the ready block list
    ("POST", "/api/v1/cases/{case_id}/notices"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/notices/withdraw"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/blocks"): C.MANAGE_CASES,
    ("POST", "/api/v1/cases/{case_id}/reminders/{kind}/dismiss"): C.MANAGE_CASES,
    ("GET", "/api/v1/cases/{case_id}/blocklist"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}/blocklist.csv"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}/blocklist.txt"): C.VIEW,
    # AR7 (D-190): the incident report; the PDF's own see_logs check is in the route's body
    ("GET", "/api/v1/cases/{case_id}/report"): C.VIEW,
    ("GET", "/api/v1/cases/{case_id}/report/files/{name}"): C.VIEW,
    ("POST", "/api/v1/cases/{case_id}/report/confirm"): C.REVIEW,
    ("POST", "/api/v1/cases/{case_id}/report/reject"): C.REVIEW,
    # AR8 (D-195): the Kibana case preview, and the canary's approval (step-up checked in the body)
    ("GET", "/api/v1/cases/{case_id}/team"): C.VIEW,
    ("POST", "/api/v1/cases/{case_id}/team/approve"): C.APPROVE,
    ("POST", "/api/v1/cases/{case_id}/notes"): C.REVIEW,
    ("GET", "/api/v1/entity-notes"): C.VIEW,
    ("POST", "/api/v1/entity-notes"): C.REVIEW,
    ("GET", "/api/v1/approvals"): C.VIEW,
    ("POST", "/api/v1/approvals/{request_id}/decision"): C.APPROVE,
    ("POST", "/api/v1/approvals/group"): C.APPROVE,
    ("GET", "/api/v1/investigations/{investigation_id}/checks"): C.VIEW,
    ("POST", "/api/v1/investigations/{investigation_id}/checks"): C.REVIEW,
    # signing in and out
    ("GET", "/signin"): "open",
    ("POST", "/signin"): "open",
    ("GET", "/stepup"): SESSION,
    ("POST", "/stepup"): SESSION,
    ("GET", "/access"): SESSION,  # Your access (Q-E2): even a person with no access sees why
    ("GET", "/classic"): C.VIEW,  # Q-B4: choose the read-only classic pages (a cookie, no data)
    ("GET", "/login"): "open",
    ("POST", "/login"): "open",
    ("POST", "/logout"): "open",
    # the app (Q-B1): its page needs view; its files (code and styles, no data) are open;
    # HEAD as GET (review F7)
    ("GET", "/app"): C.VIEW,
    ("HEAD", "/app"): C.VIEW,
    ("GET", "/app/{path:path}"): C.VIEW,
    ("HEAD", "/app/{path:path}"): C.VIEW,
    ("GET", "/app/assets/{name}"): "open",
    ("HEAD", "/app/assets/{name}"): "open",
    ("GET", "/app/favicon.svg"): "open",
    ("HEAD", "/app/favicon.svg"): "open",
    # permanent links
    ("GET", "/go/investigation/{investigation_id}"): "open",
    ("GET", "/go/case/{case_id}"): "open",
    # the classic pages and forms
    ("GET", "/"): C.VIEW,
    ("GET", "/dashboard"): C.VIEW,
    ("GET", "/rules"): C.VIEW,
    ("GET", "/glossary"): C.VIEW,
    ("GET", "/patterns"): C.VIEW,
    ("POST", "/patterns/review"): C.REVIEW,
    ("GET", "/hosts"): C.VIEW,
    ("GET", "/health"): C.VIEW,
    ("GET", "/investigations/{investigation_id}"): C.VIEW,
    ("GET", "/investigations/{investigation_id}/report"): C.VIEW,  # report@2 (Q-F2)
    ("GET", "/cases/{case_id}/report"): C.VIEW,  # AR7: the incident report, read only
    ("GET", "/gold"): C.VIEW,
    ("POST", "/investigations/{investigation_id}/gold"): C.ANSWER_GOLD,
    ("POST", "/investigations/{investigation_id}/review"): C.REVIEW,
    ("POST", "/investigations/{investigation_id}/accept"): C.REVIEW,
    ("POST", "/investigations/{investigation_id}/assess"): C.REVIEW,
    ("GET", "/proposals"): C.VIEW,
    ("POST", "/proposals/confirm"): C.REVIEW,
    ("GET", "/tuning"): C.VIEW,
    ("GET", "/metrics"): C.VIEW,
    ("GET", "/investigations/{investigation_id}/alerts/{alert_id}"): C.VIEW,
}
# The only routes that serve anyone, each for a stated reason (argus.web.app's Open values).
OPEN = {
    ("POST", "/api/login"), ("GET", "/signin"), ("POST", "/signin"), ("GET", "/login"),
    ("POST", "/login"), ("POST", "/logout"), ("GET", "/api/v1/openapi.json"),
    ("GET", "/go/investigation/{investigation_id}"), ("GET", "/go/case/{case_id}"),
    ("GET", "/app/assets/{name}"), ("GET", "/app/favicon.svg"),
    ("HEAD", "/app/assets/{name}"), ("HEAD", "/app/favicon.svg"),
}  # fmt: skip
# Changes that need no CSRF token, and why it is safe.
NO_TOKEN = {
    ("POST", "/api/login"): "sign-in: no session yet (the origin check guards it)",
    ("POST", "/login"): "sign-in: no session yet (the origin check guards it)",
    ("POST", "/signin"): "sign-in: its own login-CSRF token",
    ("POST", "/logout"): "ends the session only with the session's CSRF token",
}
CLASSIC_BEFORE_QA1 = {key for key in EXPECTED if not key[1].startswith(("/api/v1", "/go/", "/app"))
                      and key[1] not in ("/signin", "/stepup")}  # fmt: skip


def routes(app: FastAPI) -> list[APIRoute]:
    """Every APIRoute of the app, those of included routers too."""
    found = [ctx.original_route for ctx in iter_route_contexts(app.routes)]
    return [r for r in found if isinstance(r, APIRoute)]


def requirements(route: APIRoute) -> list[Need | Open]:
    found: list[Need | Open] = []

    def walk(dependant: Any) -> None:
        if isinstance(dependant.call, Need | Open):
            found.append(dependant.call)
        for sub in dependant.dependencies:
            walk(sub)

    walk(route.dependant)
    return found


def declared(app: FastAPI) -> dict[tuple[str, str], Any]:
    """What each route declares: a capability, SESSION, "open", or a list of problems."""
    out: dict[tuple[str, str], Any] = {}
    for route in routes(app):
        for method in route.methods:
            found = requirements(route)
            key = (method, route.path)
            if len(found) != 1:
                out[key] = f"{len(found)} requirements"
            elif isinstance(found[0], Open):
                out[key] = "open" if found[0].why else "open without a reason"
            else:
                need = found[0]
                if method in CHANGES and not need.csrf:
                    out[key] = "a change without a CSRF check"
                else:
                    out[key] = need.capability if need.capability is not None else SESSION
    return out


def app_without_engine() -> FastAPI:
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine("postgresql+psycopg://x@127.0.0.1:1/x")  # never connected
    return create_app(engine)


# --------------------------------------------------------------------------- declared


def test_every_route_declares_exactly_what_it_needs() -> None:
    got = declared(app_without_engine())
    assert got == EXPECTED
    assert {k for k, v in got.items() if v == "open"} == OPEN
    for key in OPEN:
        if key[0] in CHANGES:
            assert key in NO_TOKEN, key


def test_a_route_without_a_declaration_is_caught() -> None:
    """The check itself: an undeclared route, two declarations, or a change without a CSRF
    check each show up as a problem."""
    from fastapi import Depends

    from argus.web.deps import need

    app = app_without_engine()

    @app.post("/api/v1/sneaky")
    async def sneaky() -> dict[str, str]:
        return {}

    @app.post("/twice", dependencies=[Depends(need(C.VIEW, Surface.V1, csrf=True)),
                                      Depends(need(C.REVIEW, Surface.V1, csrf=True))])  # fmt: skip
    async def twice() -> None:
        return None

    @app.post("/tokenless", dependencies=[Depends(need(C.REVIEW, Surface.V1))])
    async def tokenless() -> None:
        return None

    got = declared(app)
    assert got[("POST", "/api/v1/sneaky")] == "0 requirements"
    assert got[("POST", "/twice")] == "2 requirements"
    assert got[("POST", "/tokenless")] == "a change without a CSRF check"
    assert got != EXPECTED


def test_local_accounts_keep_everything_they_could_do() -> None:
    """Every classic route (all that existed before capabilities) needs only what every
    existing account was given (LOCAL_DEFAULT): nobody lost an action."""
    for key in CLASSIC_BEFORE_QA1:
        need = EXPECTED[key]
        assert need in ("open", SESSION) or need in LOCAL_DEFAULT, key
    assert {C.VIEW, C.SEE_LOGS, C.REVIEW, C.ANSWER_GOLD} == LOCAL_DEFAULT


# --------------------------------------------------------------------------- enforced


async def fixture_ids(engine: AsyncEngine) -> dict[str, str]:
    async with engine.connect() as conn:
        inv, alert = (
            await conn.execute(
                text("SELECT investigation_id, alert_id FROM investigation_alerts LIMIT 1")
            )
        ).one()
    return {"investigation_id": str(inv), "alert_id": str(alert), "case_id": str(uuid.uuid4()),
            "request_id": "1", "path:path": "design", "name": "index-missing.js"}  # fmt: skip


def concrete(path: str, ids: dict[str, str]) -> str:
    for name, value in ids.items():
        path = path.replace("{" + name + "}", value)
    return path


async def digest(engine: AsyncEngine) -> dict[str, str]:
    """Every table's content, hashed (a session's last_seen_at aside: reading may move it)."""
    out = {}
    async with engine.connect() as conn:
        tables = [r[0] for r in await conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"))]  # fmt: skip
        for table in tables:
            rows = await conn.execute(text(f"SELECT to_jsonb(t) FROM {table} t"))  # noqa: S608
            items = sorted(json.dumps({k: v for k, v in r[0].items() if k != "last_seen_at"},
                                      sort_keys=True, default=str) for r in rows)  # fmt: skip
            out[table] = hashlib.sha256("\n".join(items).encode()).hexdigest()
    return out


async def signed(http: httpx.AsyncClient, user: str) -> str:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text
    token: str = made.json()["csrf_token"]
    return token


def client(engine: AsyncEngine) -> httpx.AsyncClient:
    app = create_app(engine, clock=lambda: NOW)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


def surface(path: str) -> Surface:
    if path.startswith("/api/v1"):
        return Surface.V1
    return Surface.API if path.startswith("/api/") else Surface.FORM


async def test_every_change_refuses_without_session_token_or_capability(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with seeded.begin() as conn:
        await auth.add_user(conn, "vera", "Vera", PASSWORD, capabilities=[C.VIEW])
    ids = await fixture_ids(seeded)
    changes = {k: v for k, v in EXPECTED.items() if k[0] in CHANGES and v != "open"}
    assert len(changes) >= 15
    before = await digest(seeded)
    async with client(web_engine) as anonymous:
        for (method, path), _ in changes.items():
            got = await anonymous.request(method, concrete(path, ids))
            if surface(path) is Surface.FORM:
                assert got.status_code == 303, path
                assert got.headers["location"].startswith("/signin"), path
            else:
                assert got.status_code == 401, path
    async with client(web_engine) as asha:
        await signed(asha, "asha")
        for (method, path), _ in changes.items():
            headers = {"X-CSRF-Token": "forged"}
            data = {"csrf_token": "forged"} if surface(path) is Surface.FORM else None
            got = await asha.request(method, concrete(path, ids), headers=headers, data=data)
            assert got.status_code == 403, path
            if surface(path) is Surface.V1:
                assert got.json() == {"detail": "missing or wrong X-CSRF-Token", "code": "csrf"}
            elif surface(path) is Surface.API:
                assert got.json() == {"detail": "missing or wrong X-CSRF-Token"}
            else:
                assert "The form expired; reload the page and try again." in got.text, path
    async with client(web_engine) as vera:  # view only
        token = await signed(vera, "vera")
        for (method, path), need in changes.items():
            if need == SESSION:
                continue
            data = {"csrf_token": token} if surface(path) is Surface.FORM else None
            got = await vera.request(method, concrete(path, ids), headers={"X-CSRF-Token": token},
                                     data=data)  # fmt: skip
            assert got.status_code == 403, path
            if surface(path) is Surface.V1:
                assert got.json()["code"] == "forbidden", path
                assert f"needs the {need.value} capability" in got.json()["detail"]
            elif surface(path) is Surface.FORM:
                assert f"it needs the “{need.value}” capability" in got.text, path
    after = await digest(seeded)
    changed = {t for t in before if before[t] != after[t]}
    # sign-ins and refusals; chain_heads is the audit trail's hash-chain head, which the owner's
    # trigger moves with every audit row (Q-C1)
    assert changed <= {"audit_events", "chain_heads", "user_devices", "user_sessions", "users"}, (
        changed
    )
    async with seeded.connect() as conn:
        refused = (await conn.execute(text(
            "SELECT count(*) FROM audit_events WHERE action = 'access' AND outcome = 'denied'"
            " AND actor = 'user:vera'"))).scalar_one()  # fmt: skip
        written = (await conn.execute(text(
            "SELECT count(*) FROM review_events r JOIN users u ON u.id = r.user_id"
            " WHERE u.username = 'vera'"))).scalar_one()  # fmt: skip
    assert refused == sum(1 for v in changes.values() if v != SESSION)  # each one audited
    assert written == 0


async def test_every_read_refuses_an_account_without_view(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    ids = await fixture_ids(seeded)
    reads = {k: v for k, v in EXPECTED.items() if k[0] == "GET" and v == C.VIEW}
    async with client(web_engine) as http:
        await signed(http, "asha")
        async with seeded.begin() as conn:  # her access is removed while she is signed in
            await conn.execute(text("UPDATE users SET capabilities = '{}' WHERE username = 'asha'"))
        for (_, path), _ in reads.items():
            got = await http.get(concrete(path, ids))
            assert got.status_code == 403, path
        session = await http.get("/api/v1/session")  # she may still see that she has none
        assert (session.status_code, session.json()["capabilities"]) == (200, [])


async def test_no_state_change_from_a_url(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    """Every GET route, signed in and signed out, leaves every table as it was."""
    ids = await fixture_ids(seeded)
    gets = [path for (method, path) in EXPECTED if method == "GET"]
    async with client(web_engine) as http:
        await signed(http, "asha")
        before = await digest(seeded)
        for path in gets:
            got = await http.get(concrete(path, ids))
            assert got.status_code < 500, path
        http.cookies.clear()
        for path in gets:
            assert (await http.get(concrete(path, ids))).status_code < 500, path
        after = await digest(seeded)
    assert after == before
