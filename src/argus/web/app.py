"""The Inbox web app (plan §6 R7, §9; D-052; Phase 3 Q-A1): the classic JSON API under /api,
the typed API under /api/v1 (argus.web.v1), and server-rendered pages, all built on
``queries`` and ``reviews``. Same origin only (Origin and Sec-Fetch-Site checked on every
change), CSP self, sessions in HttpOnly SameSite=Strict cookies, a CSRF token on every change,
and a declared capability on every route (argus.web.deps). Passwords are typed only into the
server-rendered sign-in and step-up pages, which run no script."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path as FilePath
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Path, Query, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, SecretStr
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from argus import site
from argus.assess import queue as assess_queue
from argus.cases import identity
from argus.cases.service import no_quiet_window
from argus.cases.signing import Signer, load_key
from argus.config.settings import WebSettings
from argus.context.packs import default_registry
from argus.evaluation import store as gold_store
from argus.report import store as report_store
from argus.report.model import Report
from argus.tuning import store as tuning_store
from argus.web import (
    access,
    assessed,
    auth,
    charts,
    classic,
    dashboard,
    links,
    openapi,
    queries,
    render,
    security,
    spa,
    throttle,
)
from argus.web.capabilities import LABELS, Capability
from argus.web.custody import Custody
from argus.web.deps import (
    EXPIRED,
    Conn,
    Open,
    Refusal,
    Surface,
    audit_refusal,
    current,
    db,
    forbidden,
    need,
    session_token,
)
from argus.web.elk import Checker, Elk
from argus.web.params import CLEAN, DashboardFilters, dashboard_filters
from argus.web.render import plain
from argus.web.reviews import (
    OUTCOME_LABELS,
    NotFoundError,
    ReviewConflictError,
    add_review,
)
from argus.web.signin import ElkSignIn, LocalSignIn, Outcome, SignIn
from argus.web.v1 import report_routes
from argus.web.v1 import routes as v1

__all__ = ["CLEAN", "Conn", "create_app", "dashboard_filters", "db", "plain"]

HERE = FilePath(__file__).parent
log = logging.getLogger(__name__)
UNREACHABLE = "ARGUS cannot reach its database; try again in a minute"
RETRY_STATES = frozenset({"40P01", "40001"})  # a deadlock, a serialization failure: ask again
AT_THE_SAME_MOMENT = (
    "Someone else was changing the same thing at the same moment, so nothing of this was saved."
    " Read it again, then try again."
)
BROKEN = "Something went wrong in ARGUS; it has been logged. Try again, or tell an ARGUS admin."
# The database cannot be reached, or the pool gave no connection in time (an outage).
UNAVAILABLE = (OperationalError, InterfaceError, PoolTimeoutError)
COOKIE = security.session_cookie(False)  # the session cookie's name on the plain loopback
HOSTS = ["127.0.0.1", "localhost"]
TOO_MANY = "too many failed logins; try again in 15 minutes"
GONE = "sign in at /signin with your ELK account"
UNAVAILABLE_SIGNIN = "ARGUS could not ask ELK just now; try again in a minute"
UNAVAILABLE_PAGE = UNAVAILABLE_SIGNIN[0].upper() + UNAVAILABLE_SIGNIN[1:] + "."
NO_STEPUP = "The emergency account never approves: there is nothing to confirm."
DEVICE_DAYS = 400  # a device cookie lives as long as a browser lets a cookie live
LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


def _finder_for(watch: Any, clock: Callable[[], datetime]) -> Callable[[AsyncConnection], Any]:
    """A finder on the request's connection (imported when first used: it reads many tables)."""

    def make(conn: AsyncConnection) -> Any:
        from argus.cases.watchrun import Finder

        return Finder(conn, watch, clock)

    return make


def client_of(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def client_allowed(host: str | None, networks: Sequence[Any]) -> bool:
    """Whether a client's address is in one of the allowed networks (D-104): the loopback and
    those configured. An unknown or unreadable address is refused."""
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return any(address in net for net in networks if net.version == address.version)


CSP = security.CSP
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on form posts,
    # and the origin check refuses them (found by the first real login)
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
}
NO_SCRIPT_PAGES = frozenset({"/signin", "/stepup"})  # CSP script-src 'none' (plan §7.5)
ViewName = Literal["attention", "open", "reviewed", "all", "known"]
SortName = Literal["newest", "oldest", "urgent", "reviewed"]
SORT_TITLES = {
    "newest": "newest first",
    "oldest": "oldest first",
    "urgent": "most urgent first",
    "reviewed": "newest decision first",
}
VIEW_TITLES = {
    "attention": "Needs attention",
    "open": "Not reviewed yet",
    "reviewed": "Reviewed",
    "all": "All",
    "known": "Notified, still active",
}


# --------------------------------------------------------------------------- API models


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _json_integer(value: Any) -> Any:
    """An integer as JSON Schema means it: a number (1, or 1.0), never true or "1", which
    pydantic's lax mode would take as 1 (schemathesis, 10-22)."""
    if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
        raise ValueError("a whole number")
    return value


Review = Annotated[int, Field(ge=1), BeforeValidator(_json_integer)]  # a review's id
Version = Annotated[int, Field(ge=0), BeforeValidator(_json_integer)]  # an investigation's


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64, pattern=CLEAN)
    password: str = Field(min_length=1, max_length=256, pattern=CLEAN)


class LoginOut(Strict):
    display_name: str
    csrf_token: str


class InvestigationOut(Strict):
    id: uuid.UUID
    rule_id: str
    rule_name: str | None
    key: list[tuple[str, Any]]
    bucket_start: datetime
    alert_count: int
    duplicate_count: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    severity: str | None
    risk_score: float | None
    version: int
    human_state: str
    latest_review: int | None
    reasons: list[str]


class AlertOut(Strict):
    alert_id: str
    detected_at: datetime | None
    event_time: datetime | None
    status: str
    workflow_status: str | None
    duplicate_of: str | None
    late_arrival: bool
    severity: str | None


class ReviewOut(Strict):
    id: int
    action: str
    outcome: str | None
    note: str | None
    version: int
    alert_count: int
    created_at: datetime
    display_name: str


class DetailOut(Strict):
    investigation: InvestigationOut
    alerts: list[AlertOut]
    reviews: list[ReviewOut]


OutcomeName = Literal[
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"
]


class Decision(Strict):
    """Mark reviewed, or ask for a follow-up; an outcome and a note are optional."""

    action: Literal["reviewed", "follow_up"]
    outcome: OutcomeName | None = None
    note: str | None = Field(default=None, min_length=1, max_length=4000, pattern=CLEAN)
    seen_review: Review | None
    seen_version: Version


class NoteOnly(Strict):
    """A note alone (it does not change the investigation's state)."""

    action: Literal["note"]
    note: str = Field(min_length=1, max_length=4000, pattern=CLEAN)
    seen_review: Review | None
    seen_version: Version


ReviewIn = Annotated[Decision | NoteOnly, Field(discriminator="action")]
BAD_BODY: dict[int | str, dict[str, Any]] = {400: {"description": "the body is not JSON"}}
# a 422 is FastAPI's list of validation errors, or a rule of the review refusing it (a
# decision without an outcome): {"detail": "..."}, as documented (Schemathesis, 2026-10-21)
REFUSED_OR_INVALID: dict[str, Any] = {
    "description": "the body is invalid, or the review is refused (the reason in detail)",
    "content": {"application/json": {"schema": {"anyOf": [
        {"$ref": "#/components/schemas/HTTPValidationError"},
        {"type": "object", "required": ["detail"],
         "properties": {"detail": {"type": "string"}}},
    ]}}},
}  # fmt: skip


class ReviewCreated(Strict):
    review_id: int
    version: int


class ConflictOut(Strict):
    detail: str
    latest_review: int | None
    version: int


def _out(summary: queries.Summary) -> InvestigationOut:
    return InvestigationOut(
        id=summary.id,
        rule_id=summary.rule_id,
        rule_name=summary.rule_name,
        key=summary.key_fields,
        bucket_start=summary.bucket_start,
        alert_count=summary.alert_count,
        duplicate_count=summary.duplicate_count,
        first_event_at=summary.first_event_at,
        last_event_at=summary.last_event_at,
        severity=summary.severity,
        risk_score=summary.risk_score,
        version=summary.version,
        human_state=summary.human_state,
        latest_review=summary.latest_review,
        reasons=summary.reasons,
    )


# --------------------------------------------------------------------------- requirements

# What each classic route needs (Q-A1): declared once here, checked by the dependency itself.
# Every person who could sign in before Q-A1 still holds each of these (LOCAL_DEFAULT).
PAGE_VIEW = need(Capability.VIEW, Surface.PAGE)
PAGE_SESSION = need(None, Surface.PAGE)
FORM_REVIEW = need(Capability.REVIEW, Surface.FORM, csrf=True)
FORM_GOLD = need(Capability.ANSWER_GOLD, Surface.FORM, csrf=True)
FORM_SESSION = need(None, Surface.FORM, csrf=True)
API_VIEW = need(Capability.VIEW, Surface.API)
API_REVIEW = need(Capability.REVIEW, Surface.API, csrf=True)
API_SESSION = need(None, Surface.API, csrf=True)
SIGN_IN = Open("signing in: there is no session yet")
SIGN_OUT = Open("signing out: it ends the session only with the session's own CSRF token")
PUBLIC = Open("a page or file anyone may load: it shows no data")
LINK = Open("a permanent link: it only redirects, and the page it leads to checks access")
APP_FILES = Open("the app's code and styles (Q-B1): no data in them; its page needs a session")

Viewer = Annotated[auth.Reviewer, Depends(PAGE_VIEW)]
Signed = Annotated[auth.Reviewer, Depends(PAGE_SESSION)]
FormReviewer = Annotated[auth.Reviewer, Depends(FORM_REVIEW)]
FormGold = Annotated[auth.Reviewer, Depends(FORM_GOLD)]
FormSession = Annotated[auth.Reviewer, Depends(FORM_SESSION)]
ApiReviewer = Annotated[auth.Reviewer, Depends(API_VIEW)]
ApiWriter = Annotated[auth.Reviewer, Depends(API_REVIEW)]
ApiSession = Annotated[auth.Reviewer, Depends(API_SESSION)]
# What the page says after a save (the query names a fixed key, never free text).
SAVED = {
    "reviewed": "Saved: marked reviewed.",
    "follow_up": "Saved: marked as needing follow-up.",
    "note": "Saved: note added.",
    "gold": "Saved your gold-set answer for the previous one. This is the next to answer.",
    "accepted": "Saved: you accepted ARGUS's proposal (a confirmed proposal).",
    "asked": "Asked: the AI investigator will look at this within a few minutes. Reload to"
    " see its answer.",
    "asked_exists": "The AI investigator has already assessed what this investigation shows"
    " now: its answer is below.",
}
# Why the sign-in page was shown (a fixed key in the query, never free text).
SIGNIN_WHY = {
    "ended": "Your session ended. Sign in again to continue.",
    "stepup": "You were signed out after three wrong passwords.",
    "out": "You are signed out.",
}
SIGNIN_EXPIRED = "The sign-in form expired; try again."
WRONG = "Wrong name or password."


def forbidden_page_text(capability: str) -> str:
    try:
        label = LABELS[Capability(capability)]
    except ValueError:
        label = capability
    return (f"Your account may not do this: it needs the “{capability}” capability ({label})."
            " Ask an ARGUS admin.")  # fmt: skip


# --------------------------------------------------------------------------- the app


def _investigator_takes_requests() -> bool:
    """The AI investigator's file lets a person's request start it (Q-H1); False when its
    files are refused."""
    from argus.agent import loader
    from argus.agent.registry import Trigger

    return loader.allows(Trigger.PERSON_REQUEST)


def _investigator_state() -> dict[str, Any]:
    """The AI investigator as this server's files make it (Q-H1), for the health page:
    ``ready`` (its files are the versions pinned in code), with who runs in which version;
    ``off`` (switched off in code) or ``refused`` (its files), with the loader's reason.
    Whether the pinned versions were approved is doctor's drift check (git), not this."""
    from argus.agent import loader

    try:
        agents = loader.load()
    except loader.AgentOffError as exc:
        return {"ready": False, "state": "off", "detail": str(exc)}
    except (loader.AgentError, OSError) as exc:
        return {"ready": False, "state": "refused", "detail": loader.shown(str(exc))}
    return {"ready": True, "state": "ready", "detail": agents.summary()}


def create_app(
    engine: AsyncEngine,
    settings: WebSettings | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    privacy: Any = None,  # the P1 privacy layer: without it, no on-demand assessments
    lane: Checker | None = None,  # the identity lane: ELK sign-in (``web.elk_signin``)
    lane_clock: Callable[[], datetime] | None = None,  # the lane's clock (deadlines), if not UTC
    watch: Any = None,  # Q-C2's ``watchrun.Context``: what proves a case quiet (else nothing does)
    watch_mode: str | None = None,  # ``cases.watch``: off, local or on (said on the case page)
    outside_view: Any = None,  # AR3: how the outside cache is read (``outside.*``); else defaults
    team: Any = None,  # AR8: the case team's ``PostConfig`` (the Kibana case preview); else off
    signins: Any = None,  # AR6: ``signins.view.Reading`` (who used a device); else the card is off
) -> FastAPI:
    web = settings or WebSettings()
    tls = web.tls_cert is not None
    cookie_name = security.session_cookie(tls)
    signin_cookie = security.signin_cookie(tls)
    device_cookie = security.device_cookie(tls)
    elk: Elk | None = None
    custody: Custody | None = None
    if web.elk_signin:
        if lane is None or web.secret_file is None:
            raise ValueError("ELK sign-in needs the identity lane and web.secret_file")
        custody = Custody.from_file(web.secret_file)
        elk = Elk(lane, custody, engine, clock, web.session_idle, lane_clock=lane_clock)
    signer = SignIn(ElkSignIn(elk, clock) if elk else LocalSignIn(), web, clock, custody, elk)
    app = FastAPI(
        title="ARGUS Inbox",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.engine = engine
    app.state.web = web
    app.state.clock = clock
    app.state.elk = elk  # None in local mode
    app.state.session_modes = ("elk", "break_glass") if elk else ("local",)
    # a case's permanent link (``/go/case/<uuid>``, in Kibana's case description) leads to its page
    app.state.case_page = lambda case_id: f"/app/cases/{case_id}"
    # the switch to /app (Q-B4): with it on, an investigation's permanent link opens it there
    fallback = web.classic == "fallback"
    app.state.investigation_page = (
        (lambda inv_id: f"/app/investigations/{inv_id}")
        if fallback
        else (lambda inv_id: f"/investigations/{inv_id}")
    )
    # the key that signs approvals (``argus approvals keygen``): without one the queue is read
    # only and a decision answers 503
    app.state.signer = Signer(load_key(web.approval_key_file)) if web.approval_key_file else None
    # what proves a case quiet, asked of the request's own connection: Q-C2's finder (the stored
    # answers of the still-active watch, checked once more against the database as it is now)
    # when the server has the watch's context, else nothing does
    app.state.watch_context = watch
    app.state.watch_mode = watch_mode
    app.state.outside_view = outside_view
    app.state.team = team
    app.state.signins = signins
    app.state.quiet_windows_for = (
        (lambda conn: no_quiet_window) if watch is None else _finder_for(watch, clock)
    )
    packs = default_registry()  # report@2 recomputes a dossier's views with its own pack
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*HOSTS, *web.allowed_hosts])
    networks = (*LOOPBACK_NETS, *web.allowed_networks)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters.update(
        u=render.untrusted,
        ist=render.ist,
        utc=render.utc,
        raw=render.raw_json,
        hour12=render.hour12,
    )
    templates.env.globals.update(outcomes=OUTCOME_LABELS, views=VIEW_TITLES, sorts=SORT_TITLES,
                                 classic_fallback=fallback, zone_label=site.zone_label,
                                 own_noun=site.noun, the_own_noun=site.the_noun, own_words=site.own,
                                 organisation=site.organisation)  # fmt: skip
    templates.env.filters["plain"] = plain
    templates.env.filters["duration"] = dashboard.duration
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def v1_path(request: Request) -> bool:
        return request.url.path == v1.PREFIX or request.url.path.startswith(v1.PREFIX + "/")

    def error_out(status: int, code: str, detail: str, **kw: Any) -> JSONResponse:
        return JSONResponse({"detail": detail, "code": code}, status_code=status, **kw)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        """422 with where and why only: never the input back (a password, or text that cannot
        even be encoded)."""
        errors = [
            {
                "type": str(e.get("type")),
                "loc": _loc(e),
                "msg": _message(e),
            }
            for e in exc.errors()
        ]
        if v1_path(request):
            where = "; ".join(f"{'.'.join(e['loc'])}: {e['msg']}" for e in errors[:5])
            return error_out(422, "invalid", (where or "the request is not valid")[:600])
        return JSONResponse({"detail": errors}, status_code=422)

    def api_path(request: Request) -> bool:
        return request.url.path == "/api" or request.url.path.startswith("/api/")

    @app.exception_handler(OperationalError)
    @app.exception_handler(InterfaceError)
    @app.exception_handler(PoolTimeoutError)
    async def database_down(request: Request, exc: Exception) -> Response:
        """An outage of ARGUS's own database (Q-A1 review F5): said plainly, in the form the
        route answers in; never the driver's message."""
        log.warning("web: %s %s: the database is unavailable (%s)", request.method,
                    request.url.path, type(exc).__name__)  # fmt: skip
        if getattr(getattr(exc, "orig", None), "sqlstate", None) in RETRY_STATES:
            # two requests locked the same rows in opposite orders and the database ended this
            # one: nothing of it was saved, and asking again is right (Q-B3 review R3-3)
            if v1_path(request):
                return error_out(409, "conflict", AT_THE_SAME_MOMENT)
            return JSONResponse({"detail": AT_THE_SAME_MOMENT}, status_code=409)
        if v1_path(request):
            return error_out(503, "unavailable", UNREACHABLE)
        if api_path(request):
            return JSONResponse({"detail": UNREACHABLE}, status_code=503)
        return page(request, "error.html", None, message=UNREACHABLE, status=503)

    @app.exception_handler(Exception)
    async def broken(request: Request, exc: Exception) -> Response:
        """Anything else unexpected (a bug): logged with its trace, answered as an ErrorOut on
        /api/v1 and a plain page elsewhere, with the security headers (this answer is made
        outside the middleware that adds them)."""
        log.error("web: %s %s failed", request.method, request.url.path, exc_info=exc)
        if v1_path(request):
            response: Response = error_out(500, "internal", BROKEN)
        elif api_path(request):
            response = JSONResponse({"detail": BROKEN}, status_code=500)
        else:
            response = page(request, "error.html", None, message=BROKEN, status=500)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if not v1_path(request):
            return await http_exception_handler(request, exc)
        code = {400: "invalid", 401: "unauthenticated", 403: "forbidden", 404: "not_found",
                405: "method_not_allowed", 409: "conflict", 503: "unavailable"}.get(
            exc.status_code, "invalid")  # fmt: skip
        detail = {
            404: "no such thing here",
            405: "this method is not allowed here",
            400: "the body could not be read",
        }.get(exc.status_code, str(exc.detail))
        headers = dict(exc.headers or {})
        if exc.status_code == 405:  # every method of the path, not only its first route's
            path = request.url.path
            allowed = {m for r in app.state.v1_router.routes
                       if isinstance(r, APIRoute) and r.path_regex.match(path)
                       for m in r.methods or ()}  # fmt: skip
            headers["Allow"] = ", ".join(sorted(allowed))
        return error_out(exc.status_code, code, detail, headers=headers or None)

    def page(
        request: Request, name: str, reviewer: auth.Reviewer | None, **context: Any
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request, name, {"me": reviewer, **context}, status_code=context.pop("status", 200)
        )

    def to_signin(request: Request, *, back: str | None, why: str | None = None) -> Response:
        query = {k: v for k, v in (("next", back), ("why", why)) if v}
        target = "/signin" + (f"?{urlencode(query)}" if query else "")
        return RedirectResponse(target, status_code=303)

    @app.exception_handler(Refusal)
    async def refused(request: Request, exc: Refusal) -> Response:
        """A route's requirement not met, answered for its kind of route (a refused action
        audited first: the request's own connection is back in the pool by now)."""
        try:
            await audit_refusal(request, exc)
            if exc.after is not None:  # what the refusal leaves behind (an ended session)
                await exc.after()
        except UNAVAILABLE:  # the refusal stands; only its record is missing
            log.warning("web: a refusal of %s %s could not be recorded", request.method,
                        request.url.path)  # fmt: skip
        if exc.surface is Surface.V1:
            return error_out(exc.status, exc.code, exc.detail)
        if exc.surface is Surface.API:
            detail = {"unauthenticated": "log in first", "csrf": "missing or wrong X-CSRF-Token"}
            return JSONResponse({"detail": detail.get(exc.code, exc.detail)},
                                status_code=exc.status)  # fmt: skip
        if exc.code == "unauthenticated":  # a page: back to it after signing in
            # the path and query as the browser sent them, still percent-encoded (Q-B1 review
            # F8): decoded, a route holding a domain would be non-ASCII (refused by safe_next)
            # and an encoded "?" would start a query (request.url.query is fooled by it too)
            raw = request.scope.get("raw_path")
            path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
            if exc.surface is Surface.FORM:  # a form's page is its path without the action
                path = path.rsplit("/", 1)[0] or "/"
            else:
                query = request.scope.get("query_string", b"").decode("latin-1")
                path += f"?{query}" if query else ""
            back = security.safe_next(path)
            ended = "ended" if session_token(request) else None
            return to_signin(request, back=None if back == "/" else back, why=ended)
        if exc.code == "csrf":
            return page(request, "error.html", exc.reviewer, message=EXPIRED, status=403)
        if exc.code != "forbidden":  # ELK could not be asked, or a step-up is due (Q-E2)
            return page(request, "error.html", exc.reviewer, message=exc.detail,
                        status=exc.status)  # fmt: skip
        capability = exc.capability.value if exc.capability is not None else "?"
        return page(request, "error.html", exc.reviewer, status=403,
                    message=forbidden_page_text(capability))  # fmt: skip

    def classic_answer(request: Request) -> Response | None:
        """The switch to /app (Q-B4, ``web.classic``): a classic page's address leads to its page
        in the app unless the browser chose the fallback (``/classic``); a classic form is refused
        with a pointer to the same action there. Nothing else is touched. The path is the one
        the router matches (decoded), not the URL's, so no spelling reaches a route unseen."""
        path = request.scope["path"]
        if request.method in ("GET", "HEAD"):
            if classic.COOKIE in request.cookies:
                return None
            query = request.scope.get("query_string", b"").decode("latin-1")
            target = classic.redirect_target(path, query)
            return RedirectResponse(target, status_code=303) if target is not None else None
        if request.method == "POST":
            target = classic.action_target(path)
            if target is not None:
                return page(request, "error.html", None, message=classic.REFUSED,
                            app_link=target, status=403)  # fmt: skip
        return None

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.arrival = time.monotonic()
        api_v1 = v1_path(request)
        if not client_allowed(request.client.host if request.client else None, networks):
            if api_v1:
                return error_out(403, "network", "not from an allowed network")
            return JSONResponse({"detail": "not from an allowed network"}, status_code=403)
        origin = security.own_origin(request.url.scheme, request.headers.get("host", ""))
        why = security.refusal(request.method, request.url.path, request.headers, origin)
        if why is not None:
            if api_v1:
                return error_out(403, "origin", why)
            return JSONResponse({"detail": why}, status_code=403)
        early = classic_answer(request) if fallback else None
        response = early if early is not None else await call_next(request)
        pad_until = getattr(request.state, "pad_until", None)
        if pad_until is not None:  # a failed sign-in or step-up: the same time for every one,
            left = pad_until - time.monotonic()  # after its transaction (and locks) are over
            if left > 0:
                await asyncio.sleep(left)
        path = request.url.path
        in_app = spa.is_app_path(path)
        own_cache = response.headers.get("cache-control") if in_app else None
        response.headers.update(SECURITY_HEADERS)
        if own_cache is not None:  # /app's files and page say how long they keep (Q-B1)
            response.headers["Cache-Control"] = own_cache
        if path in NO_SCRIPT_PAGES:
            response.headers["Content-Security-Policy"] = security.CSP_NO_SCRIPT
        elif in_app:  # Trusted Types on /app (plan §7.5)
            response.headers["Content-Security-Policy"] = spa.CSP_APP
        if in_app or api_path(request):
            build_id = app.state.spa.build_id()
            if build_id is not None:
                response.headers[spa.BUILD_HEADER] = build_id
        return response

    def set_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            cookie_name,
            token,
            httponly=True,
            samesite="strict",
            secure=tls,  # over HTTPS only once the app has TLS (D-104)
            path="/",
            max_age=int(web.session_absolute.total_seconds()),
        )

    def clear_cookie(response: Response) -> None:
        response.delete_cookie(cookie_name, path="/", secure=tls, httponly=True,
                               samesite="strict")  # fmt: skip

    def set_device(response: Response, raw: str | None) -> None:
        """The browser remembers a good sign-in (plan §7.2): a locked name still lets it try."""
        if raw is not None:
            response.set_cookie(device_cookie, raw, httponly=True, samesite="strict",
                                secure=tls, path="/", max_age=DEVICE_DAYS * 86400)  # fmt: skip

    # ------------------------------------------------------------------ the classic API

    async def sign_in(request: Request, conn: AsyncConnection, username: str,
                      password: str) -> Outcome:  # fmt: skip
        """Every sign-in path's one check (/signin, /login, /api/login): one at a time per
        name and client, the one throttle, the one identity provider, one audit trail (the
        refusals are written in the request's own transaction and answered, never raised, so
        they commit with the answer and no second connection is taken: Q-A1 review F1). A
        failure is answered ``web.failure_delay_s`` after the request arrived."""
        out = await signer.attempt(conn, username, password, client=client_of(request),
                                   device_cookie=request.cookies.get(device_cookie))  # fmt: skip
        if out.status != "signed_in":
            arrived = getattr(request.state, "arrival", time.monotonic())
            request.state.pad_until = arrived + web.failure_delay_s
        return out

    @app.post("/api/login", dependencies=[Depends(SIGN_IN)], response_model=LoginOut,
              responses={**BAD_BODY, 401: {"description": "wrong name or password"},
                         410: {"description": GONE},
                         429: {"description": TOO_MANY},
                         503: {"description": UNAVAILABLE_SIGNIN}})  # fmt: skip
    async def api_login(request: Request, body: LoginIn, response: Response, conn: Conn) -> Any:
        if elk is not None:  # people sign in at /signin with their ELK account
            return JSONResponse({"detail": GONE}, status_code=410)
        made = await sign_in(request, conn, body.username, body.password)
        if made.status == "locked":
            return JSONResponse({"detail": TOO_MANY}, status_code=429)
        if made.status == "unavailable":
            return JSONResponse({"detail": UNAVAILABLE_SIGNIN}, status_code=503)
        if made.status != "signed_in" or made.token is None or made.reviewer is None:
            return JSONResponse({"detail": "wrong name or password"}, status_code=401)
        set_cookie(response, made.token)
        set_device(response, made.device_token)
        return LoginOut(display_name=made.reviewer.display_name,
                        csrf_token=made.reviewer.csrf_token)  # fmt: skip

    @app.post("/api/logout", status_code=204, responses={401: {}, 403: {}})
    async def api_logout(request: Request, reviewer: ApiSession, conn: Conn) -> Response:
        await auth.end(conn, reviewer.token_hash, clock(), "signed_out")
        await auth.audit(conn, actor=f"user:{reviewer.username}", action="logout")
        response = Response(status_code=204)
        clear_cookie(response)
        return response

    @app.get("/api/investigations", responses={401: {}})
    async def api_inbox(
        reviewer: ApiReviewer,
        conn: Conn,
        view: ViewName = "attention",
        rule: Annotated[str | None, Query(max_length=200, pattern=CLEAN)] = None,
        kind: Literal["ip", "host", "domain", "user"] | None = None,
        value: Annotated[str | None, Query(max_length=300, pattern=CLEAN)] = None,
        offset: Annotated[int, Query(ge=0, le=queries.DEEPEST)] = 0,
    ) -> list[InvestigationOut]:
        entity = (kind, value) if kind is not None and value is not None else None
        found = await queries.inbox(conn, view, rule=rule, entity=entity, offset=offset)
        return [_out(s) for s in found]

    @app.get("/api/investigations/{investigation_id}", responses={401: {}, 404: {}})
    async def api_detail(
        investigation_id: uuid.UUID, reviewer: ApiReviewer, conn: Conn
    ) -> DetailOut:
        summary = await queries.investigation(conn, investigation_id)
        if summary is None:
            raise HTTPException(404, "no such investigation")
        alerts = await queries.alerts(conn, investigation_id)
        history = await queries.reviews(conn, investigation_id)
        return DetailOut(
            investigation=_out(summary),
            alerts=[AlertOut(**{k: a[k] for k in AlertOut.model_fields}) for a in alerts],
            reviews=[ReviewOut(**r) for r in history],
        )

    @app.get(
        "/api/investigations/{investigation_id}/alerts/{alert_id}/raw",
        responses={401: {}, 404: {}},
    )
    async def api_raw(
        investigation_id: uuid.UUID,
        alert_id: Annotated[str, Path(max_length=512, pattern=CLEAN)],
        reviewer: ApiReviewer,
        conn: Conn,
    ) -> dict[str, Any]:
        raw = await queries.raw_alert(conn, investigation_id, alert_id)
        if raw is None:
            raise HTTPException(404, "no such alert in this investigation")
        return raw

    @app.get(
        "/api/investigations/{investigation_id}/report",
        responses={401: {}, 404: {"description": "no such investigation, dossier or assessment"}},
    )
    async def api_report(
        investigation_id: uuid.UUID,
        reviewer: ApiReviewer,
        conn: Conn,
        assessment: Annotated[int | None, Query(ge=1, le=2**63 - 1)] = None,
    ) -> Report:
        """report@2 (Q-F2): of one assessment, else of the investigation's most telling one
        (the AI investigator's first), else of its newest dossier alone."""
        if assessment is not None:
            found = await report_store.report(conn, investigation_id, assessment, packs)
        else:
            current = await report_store.current(conn, investigation_id, packs)
            found = current[0] if current else None
        if found is None:
            raise HTTPException(404, "no such investigation, dossier or assessment")
        return found

    @app.post(
        "/api/investigations/{investigation_id}/reviews",
        status_code=201,
        responses={
            **BAD_BODY,
            401: {},
            403: {},
            404: {},
            409: {"model": ConflictOut},
            422: REFUSED_OR_INVALID,
        },
    )
    async def api_review(
        investigation_id: uuid.UUID, body: ReviewIn, reviewer: ApiWriter, conn: Conn
    ) -> Any:
        try:
            done = await add_review(
                conn,
                reviewer,
                investigation_id,
                action=body.action,
                outcome=body.outcome if isinstance(body, Decision) else None,
                note=body.note,
                seen_review=body.seen_review,
                seen_version=body.seen_version,
            )
        except NotFoundError:
            raise HTTPException(404, "no such investigation") from None
        except ReviewConflictError as exc:
            return JSONResponse(
                ConflictOut(
                    detail=str(exc), latest_review=exc.latest, version=exc.version
                ).model_dump(),
                status_code=409,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return ReviewCreated(review_id=done.review_id, version=done.version)

    @app.get("/api/rules", responses={401: {}})
    async def api_rules(reviewer: ApiReviewer, conn: Conn) -> list[dict[str, Any]]:
        return await queries.by_rule(conn)

    @app.get("/api/entities", responses={401: {}})
    async def api_entities(reviewer: ApiReviewer, conn: Conn) -> list[dict[str, Any]]:
        return await queries.by_entity(conn)

    try:  # the model gateway's cap, for the cost bar (the web app runs without it too)
        from argus.llm.budget import Priority
        from argus.llm.providers import load_config

        llm = load_config()
        cap, paid_share = llm.monthly_cap_usd, llm.shares[Priority.NORMAL]
        daily_cap: float | None = llm.daily_cap_usd
    except Exception:
        cap, paid_share, daily_cap = 10.0, 0.8, None

    @app.get("/api/cost", responses={401: {}})
    async def api_cost(reviewer: ApiReviewer, conn: Conn) -> dict[str, Any]:
        """The AI spend: this month and today, against the cap (the cost bar, D-094)."""
        return await assessed.cost(conn, clock(), cap, paid_share, daily_cap)

    @app.get("/api/dashboard", responses={401: {}})
    async def api_dashboard(
        reviewer: ApiReviewer, conn: Conn, filters: DashboardFilters
    ) -> dict[str, Any]:
        """The SOC dashboard's numbers under the same filters as the page (D-103)."""
        return dashboard.as_json(await dashboard.build(conn, filters, clock()))

    @app.get("/api/health", responses={401: {}})
    async def api_health(reviewer: ApiReviewer, conn: Conn) -> dict[str, Any]:
        return {**await queries.health(conn, clock()), "investigator": _investigator_state()}

    # ------------------------------------------------------------------ /api/v1

    app.state.v1_router = v1.build(clock=clock, privacy=privacy, packs=packs,
                                   cost_caps=(cap, paid_share, daily_cap))  # fmt: skip
    app.include_router(app.state.v1_router)

    @app.get("/api/v1/openapi.json", include_in_schema=False, dependencies=[Depends(PUBLIC)])
    async def v1_spec() -> JSONResponse:
        """The /api/v1 contract (the committed copy is docs/api/openapi-v1.json)."""
        return JSONResponse(openapi.v1_spec(app))

    def classic_spec() -> dict[str, Any]:
        """/api/openapi.json: the classic API only, as before /api/v1."""
        if app.openapi_schema is None:
            classic = [r for r in app.routes
                       if isinstance(r, APIRoute) and not r.path.startswith(v1.PREFIX)]  # fmt: skip
            app.openapi_schema = get_openapi(title=app.title, version=app.version,
                                             routes=classic)  # fmt: skip
        return app.openapi_schema

    app.openapi = classic_spec  # type: ignore[method-assign]

    # ------------------------------------------------------------------ sign-in, step-up

    def signin_page(
        request: Request,
        *,
        status: int = 200,
        error: str | None = None,
        notice: str | None = None,
        back: str = "/",
        name: str = "",
    ) -> HTMLResponse:
        """The sign-in form, with this browser's login-CSRF token in it and in its cookie: the
        one its cookie holds while that is usable, so every sign-in form open in the browser
        works (Q-A1 review F6); a new one after each sign-in."""
        token = security.reused_signin_token(request.cookies.get(signin_cookie))
        response = page(request, "signin.html", None, error=error, notice=notice,
                        signin_token=token, next=back, username=name, status=status)  # fmt: skip
        response.set_cookie(signin_cookie, token, httponly=True, samesite="strict", secure=tls,
                            path="/", max_age=int(security.SIGNIN_TTL.total_seconds()))  # fmt: skip
        return response

    @app.get("/signin", response_class=HTMLResponse, include_in_schema=False,
             dependencies=[Depends(SIGN_IN)])  # fmt: skip
    async def signin_form(
        request: Request,
        conn: Conn,
        next: Annotated[str | None, Query(max_length=security.NEXT_MAX)] = None,
        why: Annotated[str | None, Query(max_length=20)] = None,
    ) -> Response:
        """Sign in (plan §7.2): a server-rendered page that runs no script; already signed
        in, straight on to ``next``."""
        back = security.safe_next(next)
        me = await current(request, conn)
        if me is not None and me.can(Capability.VIEW):
            return RedirectResponse(back, status_code=303)
        return signin_page(request, back=back, notice=SIGNIN_WHY.get(why or ""))

    @app.post("/signin", include_in_schema=False, dependencies=[Depends(SIGN_IN)])
    async def signin_post(
        request: Request,
        conn: Conn,
        username: Annotated[str, Form(max_length=600, pattern=CLEAN)],
        password: Annotated[str, Form(max_length=256, pattern=CLEAN)],
        signin_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = "",
        next: Annotated[str, Form(max_length=security.NEXT_MAX, pattern=CLEAN)] = "/",
    ) -> Response:
        back = security.safe_next(next)
        if not security.signin_token_ok(request.cookies.get(signin_cookie), signin_token):
            kept = username if auth.USERNAME.fullmatch(username) else ""
            return signin_page(request, status=403, error=SIGNIN_EXPIRED, back=back, name=kept)
        made = await sign_in(request, conn, username, password)
        if made.status == "locked":
            return signin_page(request, status=429, error=TOO_MANY.capitalize() + ".",
                               back=back)  # fmt: skip
        if made.status == "unavailable":
            return signin_page(request, status=503, error=UNAVAILABLE_PAGE,
                               back=back)  # fmt: skip
        if made.status != "signed_in" or made.token is None:
            return signin_page(request, status=401, error=WRONG, back=back)
        earlier = session_token(request)
        if earlier is not None:  # this browser's earlier session ends: one at a time
            await auth.logout(conn, earlier, clock())
        response = RedirectResponse(back, status_code=303)
        set_cookie(response, made.token)
        set_device(response, made.device_token)
        response.delete_cookie(signin_cookie, path="/", secure=tls, httponly=True,
                               samesite="strict")  # fmt: skip
        return response

    @app.get("/stepup", response_class=HTMLResponse, include_in_schema=False)
    async def stepup_form(
        request: Request,
        me: Signed,
        next: Annotated[str | None, Query(max_length=security.NEXT_MAX)] = None,
    ) -> Response:
        """Confirm it is you (plan §7.1, §7.2): your password again, before an approval."""
        if me.mode == "break_glass":
            return page(request, "error.html", me, status=403, message=NO_STEPUP)
        return page(request, "stepup.html", me, next=security.safe_next(next), error=None)

    @app.post("/stepup", include_in_schema=False)
    async def stepup_post(
        request: Request,
        me: FormSession,
        conn: Conn,
        password: Annotated[str, Form(max_length=256, pattern=CLEAN)],
        next: Annotated[str, Form(max_length=security.NEXT_MAX, pattern=CLEAN)] = "/",
    ) -> Response:
        back = security.safe_next(next)
        client = client_of(request)
        if me.mode == "break_glass":
            return page(request, "error.html", me, status=403, message=NO_STEPUP)

        def signed_out() -> Response:
            response = to_signin(request, back=None, why="stepup")
            clear_cookie(response)
            return response

        # One step-up of a session at a time (its row locked; review F4): a burst gets three
        # guesses. Never the sign-in locks here: a sign-in takes those, then ends this
        # browser's earlier session (its row), and the two would wait for each other.
        if not await auth.step_up_open(conn, me.token_hash):  # a third failure came first
            return signed_out()
        field_, key = signer.name_key(me.elk_username or me.username)
        standing = await throttle.read_standing(conn, key, client)
        own = signer.device_hash(request.cookies.get(device_cookie))
        known = await throttle.device_known(
            conn, own, me.elk_username or me.username, elk=elk is not None
        )
        if throttle.decide(
            standing, device=known, base=timedelta(seconds=web.signin_delay_s)
        ) is not (throttle.Verdict.GO):
            await throttle.record(conn, action="stepup", name_field=field_, name_key=key,
                                  client=client, counted=False, why="throttled")  # fmt: skip
            request.state.pad_until = request.state.arrival + web.failure_delay_s
            return page(request, "stepup.html", me, next=back, status=429,
                        error=TOO_MANY.capitalize() + ".")  # fmt: skip

        async def failed(counted: bool, why: str | None) -> Response:
            """A wrong password: recorded (counted or not), approvals void, three end the
            session; every failure is answered at the same time."""
            await throttle.record(conn, action="stepup", name_field=field_, name_key=key,
                                  client=client, counted=counted, why=why)  # fmt: skip
            if counted:
                await throttle.raise_alarm_if_due(conn)
            # a refused step-up voids the person's approvals (plan §7.1, Q-C3)
            await identity.record_if_allowed(
                conn,
                identity.LiveCheck(me.user_id, "denied", "elk" if elk else "local", clock()),
                "stepup",
            )
            request.state.pad_until = request.state.arrival + web.failure_delay_s
            if await auth.step_up_failed(conn, me.token_hash, clock()):
                return signed_out()
            return page(request, "stepup.html", me, next=back, status=401,
                        error="Wrong password.")  # fmt: skip

        if elk is not None:  # the password typed again is checked against ELK now
            probe = await elk.step_up_probe(me, SecretStr(password))
            probe = await elk.classify(conn, me, probe)
            if probe.kind == "unavailable":
                await throttle.record(conn, action="stepup", name_field=field_, name_key=key,
                                      client=client, counted=False,
                                      why=f"unavailable:{probe.reason}")  # fmt: skip
                request.state.pad_until = request.state.arrival + web.failure_delay_s
                return page(request, "stepup.html", me, next=back, status=503,
                            error="ARGUS could not ask ELK just now, so nothing was confirmed."
                            " Try again in a minute.")  # fmt: skip
            if probe.kind == "denied" and not probe.counts and not probe.early:
                # ELK answered, but ARGUS no longer lets this account in (it lost its access)
                await elk.apply(conn, me, probe, "stepup")
                return signed_out()
            if probe.kind == "denied":
                return await failed(probe.counts, probe.reason)
            renewed = await elk.apply(conn, me, probe, "stepup")
            assert renewed is not None
        elif not await auth.password_is(conn, me.user_id, password):
            return await failed(True, None)
        await auth.stepped_up(conn, me.token_hash, clock())
        if elk is None:
            await identity.record_if_allowed(
                conn,
                await identity.LocalIdentityProvider().check(conn, me.user_id, purpose="stepup"),
                "stepup",
            )
        await auth.audit(conn, actor=f"user:{me.username}", action="stepup")
        return RedirectResponse(back, status_code=303)

    @app.get("/access", response_class=HTMLResponse, include_in_schema=False)
    async def access_page(request: Request, me: Signed) -> Response:
        """Your access (Q-E2): what this session may do, why, and how fresh that is: from the
        session alone, never a request to ELK."""
        return page(request, "access.html", me,
                    v=access.describe(me, clock(), web.session_idle))  # fmt: skip

    # ------------------------------------------------------------------ permanent links

    links.install(app, page, LINK)

    @app.get("/classic", include_in_schema=False)
    async def classic_entry(request: Request, reviewer: Viewer) -> Response:
        """The read-only fallback (Q-B4): with the switch on, this browser sees the classic pages
        (a session cookie, cleared by opening /app); with it off, the classic pages are the main
        pages and this leads to them. The choice is the person's own: a request a browser marks as
        coming from another origin, even a sibling host of this site (the session cookie is
        SameSite=Strict, which that satisfies), sets nothing (review B4 finding 6)."""
        response = RedirectResponse("/", status_code=303)
        own = request.headers.get("sec-fetch-site") in (None, "same-origin", "none")
        if fallback and own:
            response.set_cookie(classic.COOKIE, "1", httponly=True, samesite="strict",
                                secure=tls, path="/")  # fmt: skip
        return response

    # ------------------------------------------------------------------ pages

    @app.get("/login", include_in_schema=False, dependencies=[Depends(SIGN_IN)])
    async def login_page(
        next: Annotated[str | None, Query(max_length=security.NEXT_MAX)] = None,
    ) -> Response:
        """The old sign-in address: the sign-in page now (``/signin``)."""
        back = security.safe_next(next)
        return RedirectResponse(
            "/signin" + (f"?{urlencode({'next': back})}" if back != "/" else ""), status_code=303
        )

    @app.post("/login", include_in_schema=False, dependencies=[Depends(SIGN_IN)])
    async def login_form(
        request: Request,
        conn: Conn,
        username: Annotated[str, Form(max_length=600, pattern=CLEAN)],
        password: Annotated[str, Form(max_length=256, pattern=CLEAN)],
    ) -> Response:
        """The old sign-in form's address, still served (no login-CSRF token: the origin
        check refuses another site's post)."""
        made = await sign_in(request, conn, username, password)
        if made.status == "locked":
            return page(request, "login.html", None, error=TOO_MANY.capitalize() + ".",
                        status=429)  # fmt: skip
        if made.status == "unavailable":
            return page(request, "login.html", None, error=UNAVAILABLE_PAGE,
                        status=503)  # fmt: skip
        if made.status != "signed_in" or made.token is None:
            return page(request, "login.html", None, error=WRONG, status=401)
        response = RedirectResponse("/", status_code=303)
        set_cookie(response, made.token)
        set_device(response, made.device_token)
        return response

    @app.post("/logout", include_in_schema=False, dependencies=[Depends(SIGN_OUT)])
    async def logout_form(
        request: Request,
        conn: Conn,
        csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = "",
    ) -> Response:
        reviewer = await current(request, conn)
        if reviewer is not None and auth.csrf_ok(reviewer, csrf_token):
            await auth.end(conn, reviewer.token_hash, clock(), "signed_out")
            await auth.audit(conn, actor=f"user:{reviewer.username}", action="logout")
        response = to_signin(request, back=None, why="out")
        clear_cookie(response)
        return response

    async def inbox_page(
        request: Request,
        reviewer: auth.Reviewer,
        conn: AsyncConnection,
        view: ViewName,
        rule: str | None,
        kind: str | None,
        value: str | None,
        offset: int,
        sort: SortName | None = None,
    ) -> Response:
        entity = (kind, value) if kind in ("ip", "host", "domain", "user") and value else None
        order = sort or ("reviewed" if view == "reviewed" else "newest")  # D-095
        found = await queries.inbox(
            conn,
            view,
            rule=rule,
            entity=entity,
            offset=offset,
            sort=order,
        )
        return page(
            request,
            "inbox.html",
            reviewer,
            view=view,
            items=found,
            rule=rule,
            kind=kind,
            value=value,
            offset=offset,
            sort=order,
            ai=await assessed.verdicts(conn, [i.id for i in found]),
            page_size=queries.PAGE,
            deepest=queries.DEEPEST,
            since=reviewer.previous_seen_at,
            counts=await queries.counts(conn, clock())
            if view == "attention" and not (rule or entity)
            else None,
        )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def home(
        request: Request,
        reviewer: Viewer,
        conn: Conn,
        view: ViewName = "attention",
        rule: Annotated[str | None, Query(max_length=200, pattern=CLEAN)] = None,
        kind: Annotated[str | None, Query(max_length=10, pattern=CLEAN)] = None,
        value: Annotated[str | None, Query(max_length=300, pattern=CLEAN)] = None,
        offset: Annotated[int, Query(ge=0, le=queries.DEEPEST)] = 0,
        sort: SortName | None = None,
    ) -> Response:
        return await inbox_page(request, reviewer, conn, view, rule, kind, value, offset, sort)

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_page(
        request: Request, reviewer: Viewer, conn: Conn, filters: DashboardFilters
    ) -> Response:
        """The SOC dashboard (D-103): alerts, investigations and incidents, under one set of
        filters."""
        board = await dashboard.build(conn, filters, clock())
        return page(request, "dashboard.html", reviewer, d=board, charts=charts,
                    ranges=dashboard.RANGE_TITLES, state_titles=dashboard.STATE_TITLES,
                    ai_titles=dashboard.AI_TITLES)  # fmt: skip

    @app.get("/rules", response_class=HTMLResponse, include_in_schema=False)
    async def rules_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        return page(request, "rules.html", reviewer, rules=await queries.by_rule(conn))

    @app.get("/glossary", response_class=HTMLResponse, include_in_schema=False)
    async def glossary_page(request: Request, reviewer: Viewer) -> Response:
        return page(request, "glossary.html", reviewer, terms=queries.glossary())

    async def patterns_view(
        request: Request, reviewer: auth.Reviewer, conn: AsyncConnection, message: str | None
    ) -> Response:
        found = await queries.patterns_page(conn)
        return page(
            request, "patterns.html", reviewer, groups=found.groups, sampled=found.sampled,
            sample=found.limit, message=message,
        )  # fmt: skip

    @app.get("/patterns", response_class=HTMLResponse, include_in_schema=False)
    async def patterns_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        return await patterns_view(request, reviewer, conn, None)

    @app.post("/patterns/review", include_in_schema=False)
    async def patterns_review(
        request: Request,
        reviewer: FormReviewer,
        conn: Conn,
        items: Annotated[list[str], Form(max_length=200)],
        outcome: Annotated[str, Form(max_length=40, pattern=CLEAN)] = "",
    ) -> Response:
        """Mark an explicit list of investigation versions reviewed (plan §9.4): each one only
        if it is still exactly as the reviewer saw it; the others are left and counted."""
        if outcome and outcome not in OUTCOME_LABELS:
            return page(request, "error.html", reviewer, message="Unknown outcome.", status=422)
        if not outcome:  # a group decision is a label for each of them (D-067)
            return page(
                request, "error.html", reviewer,
                message="Choose an outcome for the group.", status=422,
            )  # fmt: skip
        parsed = []
        for item in items:  # at most 200: the form refuses more
            parts = item.split(":")
            try:
                inv, version = uuid.UUID(parts[0]), int(parts[1])
                latest = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
            except (ValueError, IndexError):
                return page(
                    request, "error.html", reviewer, message="A malformed item.", status=422
                )
            parsed.append((inv, version, latest))
        done = changed = 0
        for inv, version, latest in parsed:
            try:
                await add_review(
                    conn,
                    reviewer,
                    inv,
                    action="reviewed",
                    outcome=outcome or None,  # type: ignore[arg-type]
                    note="Reviewed with its pattern.",
                    seen_review=latest,
                    seen_version=version,
                )
                done += 1
            except (ReviewConflictError, NotFoundError):
                changed += 1
        message = f"{done} reviewed." + (
            f" {changed} changed since you looked and were left as they are." if changed else ""
        )
        return await patterns_view(request, reviewer, conn, message)

    @app.get("/hosts", response_class=HTMLResponse, include_in_schema=False)
    async def hosts_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        return page(request, "hosts.html", reviewer, entities=await queries.by_entity(conn))

    @app.get("/health", response_class=HTMLResponse, include_in_schema=False)
    async def health_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        return page(request, "health.html", reviewer, h=await queries.health(conn, clock()),
                    investigator=_investigator_state())  # fmt: skip

    async def detail_page(
        request: Request,
        reviewer: auth.Reviewer,
        conn: AsyncConnection,
        investigation_id: uuid.UUID,
        message: str | None = None,
        status: int = 200,
    ) -> Response:
        summary = await queries.investigation(conn, investigation_id)
        if summary is None:
            return page(
                request, "error.html", reviewer, message="No such investigation.", status=404
            )
        dossier = await queries.dossier(conn, investigation_id)
        fields = await queries.alert_fields(conn, investigation_id)
        available = {f for f, _ in fields}
        cookie = _columns_cookie(summary.rule_id)
        params = request.query_params
        if "cols" in params or params.get("columns") == "set":
            asked = params.getlist("cols")
        elif cookie in request.cookies:
            asked = request.cookies[cookie].split(",")
        else:  # the fields the rule's own steps name
            asked = [f for s in (dossier or {}).get("report", {}).get("steps", [])
                     for f in s.get("fields", [])]  # fmt: skip
        columns = list(
            dict.fromkeys(c for c in asked[:200] if c in available and _COLUMN.fullmatch(c))
        )[: queries.MAX_COLUMNS]
        response = page(
            request,
            "investigation.html",
            reviewer,
            inv=summary,
            alerts=await queries.alerts(conn, investigation_id, columns=columns),
            columns=columns,
            fields=fields,
            dossier=dossier,
            outside=await queries.outside_intel(
                conn, investigation_id, clock(), request.app.state.outside_view
            ),
            gaps=queries.banners(await queries.coverage(conn, summary)),
            reviews=await queries.reviews(conn, investigation_id),
            gold=await gold_store.item(conn, investigation_id, gold_store.ANY),
            assessment=await assessed.current(conn, investigation_id),
            assessments=(own := await assessed.history(conn, investigation_id)),
            same=None
            if any(assessed.is_agent(a.assessor) for a in own)
            else await assessed.shared(conn, investigation_id),
            can_ask=privacy is not None and _investigator_takes_requests(),
            incident=await queries.incident_report_of(conn, investigation_id),
            message=message,
            status=status,
        )
        if params.get("columns") == "set":  # remembered for this rule, in this browser
            response.set_cookie(
                cookie, ",".join(columns), max_age=180 * 86400, path="/investigations",
                httponly=True, samesite="strict",
            )  # fmt: skip
        return response

    @app.get(
        "/investigations/{investigation_id}/report",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def report_page(
        request: Request,
        investigation_id: uuid.UUID,
        reviewer: Viewer,
        conn: Conn,
        assessment: Annotated[int | None, Query(ge=1, le=2**63 - 1)] = None,
    ) -> Response:
        """report@2 of each assessor's newest assessment (Q-F2), one of them shown."""
        summary = await queries.investigation(conn, investigation_id)
        reports = await report_store.current(conn, investigation_id, packs)
        if assessment is not None and all(r.assessment_id != assessment for r in reports):
            one = await report_store.report(conn, investigation_id, assessment, packs)
            reports = [*reports, one] if one is not None else reports
        if summary is None or not reports:
            missing = "No report: the investigation or its dossier does not exist."
            return page(request, "error.html", reviewer, status=404, message=missing)
        shown = next((r for r in reports if r.assessment_id == assessment), reports[0])
        return page(request, "report.html", reviewer, inv=summary, report=shown,
                    reports=reports)  # fmt: skip

    @app.get("/cases/{case_id}/report", response_class=HTMLResponse, include_in_schema=False)
    async def incident_report_page(
        request: Request,
        case_id: uuid.UUID,
        reviewer: Viewer,
        conn: Conn,
        version: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    ) -> Response:
        """The case's incident report (AR7, D-190), read only: the new app's case page is where a
        person confirms or rejects it."""
        found = await report_routes.report_out(conn, case_id, reviewer, version)
        if found is None:
            return page(
                request, "error.html", reviewer, status=404,
                message="No such case, or no such version of its report.",
            )  # fmt: skip
        return page(request, "incident.html", reviewer, data=found)

    @app.get(
        "/investigations/{investigation_id}", response_class=HTMLResponse, include_in_schema=False
    )
    async def investigation_page(
        request: Request, investigation_id: uuid.UUID, reviewer: Viewer, conn: Conn
    ) -> Response:
        saved = SAVED.get(request.query_params.get("saved", ""))
        if saved and request.query_params.get("gold") == "1":
            saved += " Also saved as your gold-set answer."
        return await detail_page(request, reviewer, conn, investigation_id, message=saved)

    @app.get("/gold", response_class=HTMLResponse, include_in_schema=False)
    async def gold_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        """The gold set (P2, D-080): the answer key a person confirms, item by item."""
        rows = await gold_store.items(conn, gold_store.ANY)
        return page(request, "gold.html", reviewer, rows=rows,
                    progress=await gold_store.progress(conn, gold_store.ANY))  # fmt: skip

    @app.post("/investigations/{investigation_id}/gold", include_in_schema=False)
    async def gold_answer(
        request: Request,
        investigation_id: uuid.UUID,
        reviewer: FormGold,
        conn: Conn,
        outcome: Annotated[str, Form(max_length=40, pattern=CLEAN)] = "",
        note: Annotated[str, Form(max_length=4000, pattern=CLEAN)] = "",
    ) -> Response:
        """A person's answer for a gold item; then the next unanswered one."""
        try:
            await gold_store.answer(
                conn, investigation_id, reviewer.user_id, outcome, note, set_name=gold_store.ANY
            )
        except gold_store.GoldError as exc:
            return await detail_page(
                request, reviewer, conn, investigation_id, message=str(exc), status=422
            )
        left = [r for r in await gold_store.items(conn, gold_store.ANY) if r.outcome is None]
        target = f"/investigations/{left[0].investigation_id}?saved=gold" if left else "/gold"
        return RedirectResponse(target, status_code=303)

    @app.post("/investigations/{investigation_id}/review", include_in_schema=False)
    async def review_form(
        request: Request,
        investigation_id: uuid.UUID,
        reviewer: FormReviewer,
        conn: Conn,
        action: Annotated[Literal["reviewed", "follow_up", "note"], Form()],
        seen_version: Annotated[int, Form(ge=0)],
        seen_review: Annotated[str, Form(max_length=20, pattern=CLEAN)] = "",
        outcome: Annotated[str, Form(max_length=40, pattern=CLEAN)] = "",
        note: Annotated[str, Form(max_length=4000, pattern=CLEAN)] = "",
        also_gold: Annotated[str, Form(max_length=3, pattern=CLEAN)] = "",
    ) -> Response:
        if outcome and outcome not in OUTCOME_LABELS:
            return page(request, "error.html", reviewer, message="Unknown outcome.", status=422)
        gold = also_gold == "1" and bool(outcome)
        if gold and not reviewer.can(Capability.ANSWER_GOLD):  # audited, as v1's (review F7)
            raise forbidden(reviewer, Capability.ANSWER_GOLD, Surface.FORM)
        try:
            await add_review(
                conn,
                reviewer,
                investigation_id,
                action=action,
                outcome=outcome or None,  # type: ignore[arg-type]
                note=note.strip() or None,
                seen_review=int(seen_review) if seen_review.isdigit() else None,
                seen_version=seen_version,
            )
        except NotFoundError:
            return page(
                request, "error.html", reviewer, message="No such investigation.", status=404
            )
        except ReviewConflictError:
            return await detail_page(
                request,
                reviewer,
                conn,
                investigation_id,
                status=409,
                message="Someone else reviewed this, or new alerts arrived, while you were"
                " reading. Here is the current state; nothing was saved.",
            )
        except ValueError as exc:
            return await detail_page(
                request, reviewer, conn, investigation_id, message=str(exc), status=422
            )
        if gold:  # the review's outcome is also the person's gold answer (D-080)
            try:
                await gold_store.answer(
                    conn, investigation_id, reviewer.user_id, outcome, note, set_name=gold_store.ANY
                )
            except gold_store.GoldError:
                gold = False
        target = f"/investigations/{investigation_id}?saved={action}" + ("&gold=1" if gold else "")
        return RedirectResponse(target, status_code=303)

    @app.post("/investigations/{investigation_id}/accept", include_in_schema=False)
    async def accept_form(
        request: Request,
        investigation_id: uuid.UUID,
        reviewer: FormReviewer,
        conn: Conn,
        assessment_id: Annotated[int, Form(ge=1)],
    ) -> Response:
        """A person accepts the current proposal (P8): a review with its outcome."""
        try:
            await assess_queue.accept(
                conn, assessment_id, reviewer.user_id, kibana_ok=reviewer.kibana_ok
            )
        except assess_queue.AssessmentConflict:
            return await detail_page(
                request, reviewer, conn, investigation_id, status=409,
                message="The proposal changed (new alerts, a newer assessment, or someone"
                " reviewed it) while you were reading; nothing was saved.",
            )  # fmt: skip
        await auth.audit(conn, actor=f"user:{reviewer.username}", action="assessment.accept",
                         target_type="assessment", target_id=str(assessment_id))  # fmt: skip
        return RedirectResponse(f"/investigations/{investigation_id}?saved=accepted",
                                status_code=303)  # fmt: skip

    @app.post("/investigations/{investigation_id}/assess", include_in_schema=False)
    async def assess_form(
        request: Request,
        investigation_id: uuid.UUID,
        reviewer: FormReviewer,
        conn: Conn,
    ) -> Response:
        """A person asks the AI investigator about this investigation now, reviewed or not
        (D-095)."""
        if privacy is None or not _investigator_takes_requests():
            return page(request, "error.html", reviewer, status=503,
                        message="The AI investigator is not available on this server.")  # fmt: skip
        from argus.agent.agent import NAME as AGENT
        from argus.assess import runner

        got = await runner.request(conn, privacy, investigation_id, AGENT, clock())
        if got == "refused":  # its file changed since the check above
            return page(request, "error.html", reviewer, status=503,
                        message="The AI investigator is not available on this server.")  # fmt: skip
        if got == "no dossier":
            return await detail_page(request, reviewer, conn, investigation_id, status=409,
                                     message="ARGUS has not built this investigation's dossier"
                                     " yet; try again in a few minutes.")  # fmt: skip
        await auth.audit(conn, actor=f"user:{reviewer.username}", action="assessment.request",
                         target_type="investigation", target_id=str(investigation_id),
                         details={"result": got})  # fmt: skip
        saved = "asked" if got == "queued" else "asked_exists"
        return RedirectResponse(f"/investigations/{investigation_id}?saved={saved}",
                                status_code=303)  # fmt: skip

    @app.get("/proposals", response_class=HTMLResponse, include_in_schema=False)
    async def proposals_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        """Proposals waiting for a person, grouped by what decided them (P8, D-074)."""
        groups = await assessed.proposals(conn, clock().date())
        done = request.query_params.get("confirmed", "")
        return page(request, "proposals.html", reviewer, groups=groups,
                    confirmed=done if done.replace("-", "").isdigit() else "")  # fmt: skip

    @app.post("/proposals/confirm", include_in_schema=False)
    async def confirm_form(
        request: Request,
        reviewer: FormReviewer,
        conn: Conn,
        group: Annotated[str, Form(max_length=600)],
        ids: Annotated[str, Form(max_length=8000, pattern=r"^[0-9,]*$")],
    ) -> Response:
        """Accept a group's proposals, only those the page listed."""
        wanted = [int(i) for i in ids.split(",") if i][: assessed.GROUP_LIMIT]
        accepted, skipped = await assessed.confirm(
            conn,
            group,
            wanted,
            reviewer.user_id,
            "confirmed with its group",
            kibana_ok=reviewer.kibana_ok,
        )
        await auth.audit(conn, actor=f"user:{reviewer.username}", action="assessment.confirm",
                         target_type="assessment_group", target_id=group[:200],
                         details={"accepted": accepted, "skipped": skipped})  # fmt: skip
        return RedirectResponse(f"/proposals?confirmed={accepted}-{skipped}", status_code=303)

    @app.get("/tuning", response_class=HTMLResponse, include_in_schema=False)
    async def tuning_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        """The weekly rule-tuning reports (P7): suggestions for a person to apply in Kibana."""
        return page(request, "tuning.html", reviewer, reports=await tuning_store.latest(conn))

    @app.get("/metrics", response_class=HTMLResponse, include_in_schema=False)
    async def metrics_page(request: Request, reviewer: Viewer, conn: Conn) -> Response:
        """How the assessments and the model gateway are doing (P8)."""
        now = clock()
        quota, stopped = await assessed.gateway(conn, now)
        return page(request, "metrics.html", reviewer, m=await assessed.metrics(conn, now),
                    quota=quota, stopped=stopped)  # fmt: skip

    @app.get(
        "/investigations/{investigation_id}/alerts/{alert_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def raw_page(
        request: Request,
        investigation_id: uuid.UUID,
        alert_id: str,
        reviewer: Viewer,
        conn: Conn,
    ) -> Response:
        raw = await queries.raw_alert(conn, investigation_id, alert_id[:512])
        if raw is None:
            return page(request, "error.html", reviewer, message="No such alert here.", status=404)
        return page(
            request,
            "raw.html",
            reviewer,
            raw=raw,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )

    # ------------------------------------------------------------------ /app (Q-B1)

    build = spa.Build(web.spa_dir if web.spa_dir is not None else spa.BUILD_DIR)
    app.state.spa = build
    NOT_FOUND = "no such file in the app"  # noqa: N806

    def app_file(request: Request, relative: str) -> Response:
        """One of the build's files, or a plain 404 (never the page: plan §7.5)."""
        found = build.file(relative)
        if found is None:
            return Response(NOT_FOUND, status_code=404, media_type="text/plain")
        cache = spa.IMMUTABLE if relative.startswith("assets/") else spa.REVALIDATE
        headers = {"Cache-Control": cache, "Vary": "Accept-Encoding"}
        body = found.body
        if found.gzipped is not None and spa.accepts_gzip(request.headers.get("accept-encoding")):
            headers["Content-Encoding"] = "gzip"
            body = found.gzipped
        return Response(body, media_type=found.media_type, headers=headers)

    def app_index(request: Request, reviewer: auth.Reviewer) -> Response:
        index = build.index()
        if index is None:
            return page(request, "error.html", reviewer, status=503,
                        message="The new app is not built on this server; the classic pages"
                        " work as before.")  # fmt: skip
        response = Response(index.body, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": spa.REVALIDATE})  # fmt: skip
        if classic.COOKIE in request.cookies:  # back in the app: the fallback choice ends
            response.delete_cookie(classic.COOKIE, path="/", secure=tls, httponly=True,
                                   samesite="strict")  # fmt: skip
        return response

    # GET and HEAD (review F7, RFC 9110): HEAD answers with GET's status and headers; the
    # server sends no body for it
    read = ["GET", "HEAD"]

    @app.api_route("/app/assets/{name}", methods=read, include_in_schema=False,
                   dependencies=[Depends(APP_FILES)])  # fmt: skip
    async def app_asset(request: Request, name: str) -> Response:
        return app_file(request, f"assets/{name}")

    @app.api_route("/app/favicon.svg", methods=read, include_in_schema=False,
                   dependencies=[Depends(APP_FILES)])  # fmt: skip
    async def app_icon(request: Request) -> Response:
        return app_file(request, "favicon.svg")

    @app.api_route("/app", methods=read, include_in_schema=False)
    async def app_home(request: Request, reviewer: Viewer) -> Response:
        """The app (Q-B1): its routes are the page's own; the server serves one page."""
        return app_index(request, reviewer)

    @app.api_route("/app/{path:path}", methods=read, include_in_schema=False)
    async def app_page(request: Request, path: str, reviewer: Viewer) -> Response:
        if spa.FILE_LIKE.search(path):  # a missing file: 404, never the page
            return Response(NOT_FOUND, status_code=404, media_type="text/plain")
        return app_index(request, reviewer)

    return app


# Validation errors whose message pydantic builds from the schema alone (limits, the allowed
# values, a pattern, our own validators' fixed sentences): shown as pydantic words them. Every
# other kind gets a sentence of ours, so no answer quotes the input (Q-A1 review F3: a
# discriminated union's message quotes the tag it was sent).
_SCHEMA_ONLY = frozenset({
    "missing", "extra_forbidden", "string_type", "string_too_short", "string_too_long",
    "string_pattern_mismatch", "int_type", "int_parsing", "int_from_float", "float_type",
    "float_parsing", "bool_type", "bool_parsing", "greater_than", "greater_than_equal",
    "less_than", "less_than_equal", "literal_error", "list_type", "too_short", "too_long",
    "model_type", "model_attributes_type", "dict_type", "none_required", "json_type",
    "union_tag_not_found", "value_error", "enum", "date_parsing", "date_from_datetime_parsing",
    "datetime_parsing", "datetime_from_date_parsing", "multiple_of", "finite_number",
})  # fmt: skip


def _loc(error: Mapping[str, Any]) -> list[str]:
    """Where: the field names the schema gives; past an unknown field's place, nothing (its
    name is the sender's own text)."""
    loc = [str(part)[:64] for part in error.get("loc", ())]
    if error.get("type") == "union_tag_invalid":  # the field that names the kind of body
        loc.append(str((error.get("ctx") or {}).get("discriminator", "")).strip("'"))
    return loc[:1] if error.get("type") == "extra_forbidden" else loc


def _message(error: Mapping[str, Any]) -> str:
    kind = str(error.get("type"))
    ctx = error.get("ctx") or {}
    if kind == "extra_forbidden":
        return "an unknown field is not allowed"
    if kind == "union_tag_invalid":
        return f"must be one of {ctx.get('expected_tags', 'the documented values')}"
    if kind.startswith("uuid_"):
        return "Input should be a valid UUID"
    if kind in _SCHEMA_ONLY:
        return str(error.get("msg"))
    return "is not valid here"


_COLUMN = re.compile(r"[A-Za-z0-9_@.\-]{1,120}")  # a field name a column may have


def _columns_cookie(rule_id: str) -> str:
    """The cookie that remembers a rule's chosen alert columns (one per rule)."""
    return "argus_cols_" + hashlib.sha256(rule_id.encode()).hexdigest()[:12]
