"""UI v2's finding routes of ``/api/v1`` (spec §2.3): an entity's page (A11), the one search box
(A12) and the incident reports list (A13). Read only, from ARGUS's own records (no SIEM request,
no model), each list cut at a fixed size.

Reading needs ``view``. An account's page names a person, so it needs ``see_logs`` as account
names do elsewhere; a device's page gives the accounts seen behind its address only as counts
without it. The PDF in a report row is ``available`` only with ``see_logs`` (it says what the
logs said)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request

from argus.web import auth, lookups
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Surface, forbidden, need
from argus.web.v1 import entity_models as m
from argus.web.v1.models import CLEAN, SPACE

VIEW = need(Capability.VIEW, Surface.V1)
_CTRL = r"\x00-\x1f\x7f-\x9f"
# one line holding something that is not whitespace (as ``str.strip`` sees it), no control
_ONE_LINE = rf"^[^{_CTRL}]*[^{_CTRL}{SPACE}][^{_CTRL}]*$"
_ONE_VALUE = rf"^[^{_CTRL}/]*[^{_CTRL}/{SPACE}][^{_CTRL}/]*$"  # and no slash (a path part)
Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
# a value from an alert: an address, a host, a domain or an account name (one line, no NUL)
EntityValue = Annotated[
    str, Path(min_length=1, max_length=512, pattern=_ONE_VALUE,
              description="the address, host, domain or account name"),
]  # fmt: skip
SearchText = Annotated[
    str, Query(min_length=1, max_length=200, pattern=_ONE_LINE,
               description="an address, host, account, domain, rule, incident number or IR number"),
]  # fmt: skip


def _classifier(request: Request) -> Any:
    return getattr(request.app.state.watch_context, "classifier", None)


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    """Add the finding routes to ``router``."""
    read = errors(401, 403, 422)

    @router.get("/entities/{kind}/{value}", tags=["entities"], operation_id="getEntity",
                responses=read)  # fmt: skip
    async def get_entity(
        kind: m.PageKind, value: EntityValue, request: Request, me: Viewer, conn: Conn
    ) -> m.EntityPageOut:
        """What ARGUS knows of a device, an account, a campus site or an outside address: the
        asset map's entry, its incidents and alert groups, a timeline, its days (and for an
        address, each day's host names and sign-ins: whether the host names show a different
        device on different days, ``dynamic``, and the most accounts in one day, ``shared_by``),
        what outside sources said, and people's notes. An account's page needs ``see_logs``. A
        value ARGUS has no record of answers with empty lists, never 404."""
        if kind == "account" and not me.can(Capability.SEE_LOGS):
            raise forbidden(me, Capability.SEE_LOGS, Surface.V1)
        return await lookups.entity_page(
            conn, kind, value.strip(), me.user_id, now=clock(), classifier=_classifier(request),
            show_names=me.can(Capability.SEE_LOGS),
        )  # fmt: skip

    @router.get("/search", tags=["entities"], operation_id="search", responses=read)
    async def search(q: SearchText, request: Request, me: Viewer, conn: Conn) -> m.SearchOut:
        """One box: an incident number (``31``, ``#31``), an IR number, an address, a host, an
        account (with ``see_logs``, as an account's page), a domain, or words of an incident
        title or a rule name. What the text looks like (``guess``), the entity it names, and at
        most five incidents, alert groups and incident reports, with how many there are in
        all."""
        return await lookups.search(conn, q.strip(), me.user_id, classifier=_classifier(request),
                                    can_logs=me.can(Capability.SEE_LOGS))  # fmt: skip

    @router.get("/incident-reports", tags=["reports"], operation_id="listIncidentReports",
                responses=read)  # fmt: skip
    async def list_incident_reports(
        me: Viewer,
        conn: Conn,
        q: Annotated[
            str | None,
            Query(max_length=120, pattern=CLEAN, description="an IR number, number or title"),
        ] = None,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=lookups.REPORT_PAGE)] = lookups.REPORT_PAGE,
    ) -> m.ReportsPageOut:
        """The incident reports of confirmed incidents, newest first: each incident's IR number,
        its newest report version and when ARGUS wrote it, its files, whether it is in Kibana,
        and the newest "sent to the CISO"."""
        items, more, _ = await lookups.reports(
            conn, q=(q or "").strip() or None, offset=offset, limit=limit,
            can_logs=me.can(Capability.SEE_LOGS),
        )  # fmt: skip
        return m.ReportsPageOut(items=items, offset=offset, limit=limit, has_more=more)
