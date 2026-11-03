"""Permanent links: ``/go/case/<uuid>`` and ``/go/investigation/<uuid>`` on the address people use
(``web.public_url``). Kibana case descriptions and notices carry them, so their form never changes;
where they lead may. The session cookie is SameSite=Strict, so a link arriving from another site
answers with a tiny page (a meta refresh, no script) that opens the target from this site, and a
signed-in person lands on the page instead of the sign-in form."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import RedirectResponse

from argus.config.settings import WebSettings

CROSS_SITE = frozenset({"cross-site", "same-site"})
MANGLED = (
    "This link is incomplete or wrong: check that it was copied whole, or open the"
    " investigation from the Inbox."
)


def investigation_url(web: WebSettings, investigation_id: uuid.UUID) -> str:
    return f"{web.link_base}/go/investigation/{investigation_id}"


def case_url(web: WebSettings, case_id: uuid.UUID) -> str:
    return f"{web.link_base}/go/case/{case_id}"


def install(app: FastAPI, page: Callable[..., Response], requirement: Any) -> None:
    """The two ``/go`` routes, on ``app`` (``page`` renders a template)."""

    def arrive(request: Request, target: str) -> Response:
        if request.headers.get("sec-fetch-site") in CROSS_SITE:
            return page(request, "bounce.html", None, target=target)
        return RedirectResponse(target, status_code=303)

    def mangled(request: Request) -> Response:
        """A link cut short or mistyped (a wrapped e-mail, a lost character): a plain page,
        never the validator's words."""
        return page(request, "error.html", None, message=MANGLED, status=404)

    @app.get("/go/investigation/{investigation_id}", include_in_schema=False,
             dependencies=[Depends(requirement)])  # fmt: skip
    async def go_investigation(request: Request, investigation_id: str) -> Response:
        parsed = parse_id(investigation_id)
        if parsed is None:
            return mangled(request)
        resolve: Callable[[uuid.UUID], str] = request.app.state.investigation_page
        return arrive(request, resolve(parsed))

    @app.get("/go/case/{case_id}", include_in_schema=False, dependencies=[Depends(requirement)])
    async def go_case(request: Request, case_id: str) -> Response:
        parsed = parse_id(case_id)
        if parsed is None:
            return mangled(request)
        resolve: Callable[[uuid.UUID], str | None] | None = request.app.state.case_page
        target = resolve(parsed) if resolve is not None else None
        if target is None:  # no case pages yet: the link's form is fixed already
            return page(request, "error.html", None, message="No such case.", status=404)
        return arrive(request, target)


def parse_id(value: str) -> uuid.UUID | None:
    """A link's id: a UUID in its canonical form (36 characters), else None."""
    if len(value) != 36:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
