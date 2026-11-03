"""What every route declares, and checks: a session, a CSRF token for a change, and a capability.
A route's ``Need`` is both its declaration and its check, so they cannot drift. In ELK mode a change
also waits for the person's access to be checked in ELK unless the last check is at most 30 seconds
old. Each kind of route answers a refusal its own way (``Surface``). No ``from __future__ import
annotations`` here: FastAPI reads a callable object's parameter annotations as written."""

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.web import auth, security
from argus.web.capabilities import LABELS, Capability


async def db(request: Request) -> AsyncIterator[AsyncConnection]:
    """One transaction per request, committed before the response is sent ("function" scope:
    by default FastAPI ends a yield dependency after sending, and a quick next request, e.g.
    the page a login or a review redirects to, could miss what was just saved; 2026-10-22)."""
    engine: AsyncEngine = request.app.state.engine
    async with engine.begin() as conn:
        yield conn


Conn = Annotated[AsyncConnection, Depends(db, scope="function")]


class Surface(StrEnum):
    PAGE = "page"  # a classic page (GET)
    FORM = "form"  # a classic form (POST, a csrf_token field)
    API = "api"  # the classic JSON API (an X-CSRF-Token header)
    V1 = "v1"  # /api/v1 (an X-CSRF-Token header; ErrorOut)


class Refusal(Exception):  # noqa: N818 - a refusal is the normal answer, not a failure
    """A request this route does not serve; the app renders it for its surface."""

    def __init__(
        self,
        status: int,
        code: str,
        detail: str,
        surface: Surface,
        reviewer: auth.Reviewer | None = None,
        capability: Capability | None = None,
        after: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail, self.surface = status, code, detail, surface
        self.reviewer, self.capability = reviewer, capability
        self.after = after  # written once the request's own transaction is rolled back

    @property
    def audited(self) -> bool:
        """A refused action of a signed-in person: the app's handler records it."""
        return self.code == "forbidden" and None not in (self.reviewer, self.capability)


SIGNED_OUT = "sign in first"
CSRF = "missing or wrong X-CSRF-Token"
EXPIRED = "The form expired; reload the page and try again."


def forbidden_detail(capability: Capability) -> str:
    return (
        f"your account may not do this: it needs the {capability.value} capability"
        f" ({LABELS[capability]})"
    )


def session_token(request: Request) -> str | None:
    """The session cookie's token, if it has a plausible size."""
    token = request.cookies.get(security.session_cookie(request.app.state.web.tls_cert is not None))
    return token if token and len(token) <= 100 else None


async def current(request: Request, conn: AsyncConnection) -> auth.Reviewer | None:
    """The signed-in person, if any; a background request leaves the session's idle clock
    alone."""
    token = session_token(request)
    if token is None:
        return None
    state = request.app.state
    reviewer = await auth.session(
        conn,
        token,
        state.clock(),
        state.web.session_idle,
        extend=not security.is_background(request.headers),
        modes=state.session_modes,
    )
    if reviewer is not None and reviewer.elk:  # from the snapshot; a re-check starts when due
        kept: auth.Reviewer | None = await state.elk.after_load(conn, reviewer, token)
        return kept
    return reviewer


@dataclass(frozen=True)
class Need:
    """A route's requirement: a session; a valid CSRF token (``csrf``); a capability (None:
    any signed-in person, e.g. signing out)."""

    capability: Capability | None
    surface: Surface
    csrf: bool

    async def __call__(self, request: Request, conn: Conn) -> auth.Reviewer:
        reviewer = await current(request, conn)
        if reviewer is None:
            raise Refusal(401, "unauthenticated", SIGNED_OUT, self.surface)
        if self.csrf and not auth.csrf_ok(reviewer, await self._token(request)):
            raise Refusal(403, "csrf", CSRF, self.surface, reviewer)
        if self.capability is not None:
            if not reviewer.can(self.capability):
                raise forbidden(reviewer, self.capability, self.surface)
            if self.csrf and reviewer.elk:  # a change: the snapshot is young, or ELK is asked
                token = session_token(request)
                assert token is not None  # the session was found by it
                reviewer = await request.app.state.elk.gate_change(
                    conn, reviewer, token, self.capability, self.surface
                )
                if not reviewer.can(self.capability):  # the live check took it away
                    raise forbidden(reviewer, self.capability, self.surface)
        return reviewer

    async def _token(self, request: Request) -> str | None:
        if self.surface is Surface.FORM:
            value = (await request.form()).get("csrf_token")
            return value if isinstance(value, str) else None
        return request.headers.get("x-csrf-token")


def forbidden(reviewer: auth.Reviewer, capability: Capability, surface: Surface) -> Refusal:
    """A signed-in person's action their account may not take (raise it)."""
    return Refusal(403, "forbidden", forbidden_detail(capability), surface, reviewer, capability)


async def audit_refusal(request: Request, refusal: Refusal) -> None:
    """A refused action, recorded for the Reporter's count of rejected unauthorized actions
    . The app's Refusal handler calls it after the request's own transaction has
     been rolled back and its connection returned: a request never holds two pooled
     connections, so refusals at once cannot exhaust the pool."""
    reviewer, capability = refusal.reviewer, refusal.capability
    if not refusal.audited or reviewer is None or capability is None:
        return
    engine: AsyncEngine = request.app.state.engine
    async with engine.begin() as own:
        await auth.audit(own, actor=f"user:{reviewer.username}", action="access",
                         outcome="denied", target_type="route",
                         target_id=f"{request.method} {request.url.path}",
                         details={"capability": capability.value})  # fmt: skip


@dataclass(frozen=True)
class Open:
    """A route that serves anyone by design: ``why`` says why (the route test lists them)."""

    why: str

    async def __call__(self) -> None:
        return None


def need(capability: Capability | None, surface: Surface, *, csrf: bool = False) -> Need:
    return Need(capability, surface, csrf)
