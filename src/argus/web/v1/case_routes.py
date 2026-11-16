"""The case routes of ``/api/v1`` (plan §5 Q-B3): cases, their commands, the approvals queue,
notes and "Check more". Built on the same functions the terminal uses: every command goes through
:class:`argus.cases.service.CaseService` (a version-checked command, one transaction, audited as
``user:<id>``), every approval through :class:`argus.cases.desk.ApprovalDesk` (a live check, the
session's step-up, the web's signature, the database function), the closure preview through the
service's own plan, and "Check more" through :func:`argus.investigation.checks.request`.

Rules every change here follows:

* it names the version the person looked at (409 when the case moved), and a closure or merge
  also the hash of the preview they read (409 when what it would write is anything else now);
* a view-only account is refused (403) by the route's declared capability before anything is read;
* a refusal of the identity check is recorded and committed (it voids the person's approvals),
  and answered as a refusal; nothing else of that request is written.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import approvals, blocklist, identity, knownrun
from argus.cases.approvals import ApprovalError
from argus.cases.desk import ApprovalDesk, Decided, Refused, SessionProof, live_check
from argus.cases.identity import IdentityProvider, LiveCheck, LocalIdentityProvider
from argus.cases.machine import (
    Assign,
    CaseRefused,
    Confirm,
    Contain,
    Dismiss,
    Notify,
    RecordBlock,
    Release,
    Reopen,
    Take,
    WithdrawNotice,
)
from argus.cases.membership import load_shared
from argus.cases.model import NO_QUIET_WINDOW
from argus.cases.service import CaseService
from argus.cases.signing import Signer
from argus.investigation import checks
from argus.responder.machine import ist_day
from argus.web import auth, casepages, deps, queries
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.v1 import case_models as m
from argus.web.v1 import engine_routes
from argus.web.v1.models import CLEAN

CaseId = Annotated[uuid.UUID, Path(description="a case's id")]
RequestIdPath = Annotated[int, Path(ge=1, le=m.SAFE_MAX, description="an approval request's id")]
InvestigationId = Annotated[uuid.UUID, Path(description="an investigation's id")]
SuggestionId = Annotated[int, Path(ge=1, le=m.SAFE_MAX, description="a suggestion's id")]
DUPLICATE_SECONDS = 60  # the same note by the same person this soon is a double submit
NOTES_PER_HOUR = 30  # the most notes (case and entity together) one person adds in an hour

VIEW = need(Capability.VIEW, Surface.V1)
MANAGE = need(Capability.MANAGE_CASES, Surface.V1, csrf=True)
REOPEN = need(Capability.REOPEN, Surface.V1, csrf=True)
REVIEW = need(Capability.REVIEW, Surface.V1, csrf=True)
APPROVE = need(Capability.APPROVE, Surface.V1, csrf=True)

Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
Manager = Annotated[auth.Reviewer, Depends(MANAGE)]
Reopener = Annotated[auth.Reviewer, Depends(REOPEN)]
Reviewer = Annotated[auth.Reviewer, Depends(REVIEW)]
Approver = Annotated[auth.Reviewer, Depends(APPROVE)]

_CASE_STATUS = {"forbidden": (403, "forbidden"), "conflict": (409, "conflict"),
                "invalid": (422, "invalid"), "unavailable": (409, "not_ready"),
                "not_found": (404, "not_found")}  # fmt: skip


def known_rules(watch: Any) -> Any:
    """The notified cases' rules the watch's context carries (managed site types); the defaults
    when the server has no context."""
    from argus.cases.known import Rules

    return Rules() if watch is None else watch.rules


def case_refusal(exc: CaseRefused, action: str | None = None) -> Refusal:
    """A command the case machine or the service refused, as the answer to the request."""
    status, code = _CASE_STATUS[exc.code]
    return Refusal(status, code, casepages.why_not(exc, action), Surface.V1)


def approval_refusal(exc: ApprovalError) -> Refusal:
    """What the approval functions refused, in the contract's codes."""
    if exc.code == "step_up_required":
        return Refusal(403, "step_up_required", casepages.sentence(exc.message), Surface.V1)
    status = {401: (401, "unauthenticated"), 403: (403, "forbidden"), 404: (404, "not_found"),
              409: (409, "conflict"), 410: (409, "conflict"), 422: (422, "invalid"),
              503: (503, "unavailable")}.get(exc.status, (409, "conflict"))  # fmt: skip
    return Refusal(status[0], status[1], casepages.sentence(exc.message), Surface.V1)


def refused_answer(exc: Refused) -> JSONResponse:
    """The identity check refused the person: the record of it (which voids their earlier
    approvals) is committed with this answer, so it is not a raised refusal."""
    return JSONResponse({"detail": casepages.sentence(exc.message), "code": "forbidden"},
                        status_code=403)  # fmt: skip


class OneCheck:
    """An identity provider that asks once: a group of decisions made in one request is one
    moment, and the database accepts a check at most 30 seconds old."""

    def __init__(self, provider: IdentityProvider) -> None:
        self.provider = provider
        self.name = provider.name
        self._made: dict[tuple[int, str], LiveCheck] = {}

    async def check(
        self, conn: AsyncConnection, user_id: int, *, purpose: identity.Purpose
    ) -> LiveCheck:
        key = (user_id, purpose)
        if key not in self._made:
            self._made[key] = await self.provider.check(conn, user_id, purpose=purpose)
        return self._made[key]


def provider_for(request: Request, me: auth.Reviewer, token: str) -> IdentityProvider:
    """Who checks the person now: ELK for a person signed in through ELK, else the local
    account."""
    from argus.web.elk import ElkIdentityProvider

    elk = request.app.state.elk
    if elk is not None and me.elk:
        return ElkIdentityProvider(elk, token)
    return LocalIdentityProvider()


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    """Add the case routes to ``router`` (``errors`` writes a route's documented answers)."""
    read = errors(401, 403, 422)
    change = errors(400, 401, 403, 404, 409, 422)

    def refuse(status: int, code: str, detail: str) -> Refusal:
        return Refusal(status, code, detail, Surface.V1)

    async def service_for(request: Request, conn: AsyncConnection) -> CaseService:
        return await CaseService.start(conn, request.app.state.quiet_windows_for(conn))

    def token_of(request: Request) -> str:
        found = deps.session_token(request)
        assert found is not None  # the route's requirement found the session by it
        return found

    def desk_for(request: Request, conn: AsyncConnection, me: auth.Reviewer) -> ApprovalDesk:
        signer: Signer | None = request.app.state.signer
        if signer is None:
            raise refuse(503, "unavailable", "This server has no key to sign approvals with, so"
                         " it cannot record a decision. An ARGUS admin sets one up.")  # fmt: skip
        provider = OneCheck(provider_for(request, me, token_of(request)))
        return ApprovalDesk(conn, identity_provider=provider, signer=signer, apply=True,
                            quiet_windows=request.app.state.quiet_windows_for(conn))  # fmt: skip

    def proof(request: Request, me: auth.Reviewer) -> SessionProof:
        return SessionProof(token_of(request), me.user_id, me.stepped_up_at)

    async def same_as_read(conn: AsyncConnection, request_id: int, read: str | None) -> None:
        """What the request bound is what the person read: the preview is made before the case is
        locked, so a change that does not move the case's version (the Kibana create skipped, say)
        could still change the writes between the two. Refused here, the request rolls back."""
        stored = await approvals.record(conn, request_id)
        if stored is None or stored.payload_hash != read:
            raise refuse(409, "conflict", "What this would write changed while you asked: nothing"
                         " was saved. Read the preview again.")  # fmt: skip

    @router.get("/cases", tags=["cases"], operation_id="listCases", responses=read)
    async def list_cases(
        me: Viewer,
        conn: Conn,
        view: m.CaseView = "active",
        number: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
        q: Annotated[str | None, Query(max_length=120, pattern=CLEAN)] = None,
        offset: Annotated[int, Query(ge=0, le=queries.DEEPEST)] = 0,
        limit: Annotated[int, Query(ge=1, le=casepages.ROW_PAGE)] = casepages.ROW_PAGE,
        taken_by: Annotated[
            str | None,
            Query(pattern=r"^[A-Za-z0-9._@-]{1,64}$", description="me, nobody, or a username"),
        ] = None,
        kibana: Annotated[m.KibanaFilter | None, Query()] = None,
        sort: Annotated[m.CaseSort | None, Query()] = None,
    ) -> m.CasePage:
        """The cases, most severe first: a view (Needs you is ``queue``: possible incidents
        nobody else is checking and incidents nobody took; ``work`` is Home's, every case that
        needs a person for any reason; active, needing attention, mine, suspected, notified,
        closed, all), optionally one case by its number or a word of its title, who took it
        (``taken_by``), its Kibana state (``kibana``: in Kibana, waiting for it, posting
        failed), sorted by last activity or by how long it has waited (``sort``)."""
        page = await casepages.list_cases(conn, me.user_id, view, offset=offset, limit=limit,
                                          number=number, query=q, taken_by=taken_by,
                                          kibana=kibana, sort=sort)  # fmt: skip
        engines = await engine_routes.views_for(conn, (c.id for c in page.items))  # P4-F E5
        if engines:
            page.items = [c.model_copy(update={"engine": engines.get(c.id)}) for c in page.items]
        return page

    @router.get("/cases/{case_id}", tags=["cases"], operation_id="getCase",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_case(case_id: CaseId, request: Request, me: Viewer, conn: Conn) -> m.CaseDetail:
        """A case in analyst order: summary, what is new, timeline, its investigations and
        indicators, the actions this person may take (each with why not), Kibana's side, notes
        and history. The evidence, hypotheses and unknowns are those of the lead
        investigation's report (``/investigations/{id}/reports``). ``signins`` says who used the
        case's internal devices, from the SSO sign-ins ARGUS kept, and the timeline carries
        those sign-ins as context (``signin``); account names only for an account with
        ``see_logs``."""
        found = await casepages.detail(
            conn, await service_for(request, conn), case_id, me,
            watch_context=request.app.state.watch_context, watch_mode=request.app.state.watch_mode,
            signins=getattr(request.app.state, "signins", None),
            team=getattr(request.app.state, "team", None),
            switches_root=getattr(request.app.state, "switches_root", None),
        )  # fmt: skip
        if found is None:
            raise refuse(404, "not_found", "no such case")
        engine = (await engine_routes.views_for(conn, [found.case.id])).get(found.case.id)
        if engine is not None:  # the incident engine's view (P4-F E5)
            found.engine = engine
            found.case = found.case.model_copy(update={"engine": engine})
        return found

    @router.get("/cases/{case_id}/closure-preview", tags=["cases"], operation_id="previewClosure",
                responses=errors(401, 403, 404, 409, 422))  # fmt: skip
    async def preview_closure(
        case_id: CaseId,
        request: Request,
        me: Viewer,
        conn: Conn,
        reason: m.RequestedReason,
        expected_version: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    ) -> m.ClosurePreviewOut:
        """What asking to close the case for a reason would bind: the exact Kibana writes and
        their hash, from the builder the request itself uses. Ask with this hash to be sure
        the request is the one you read."""
        service = await service_for(request, conn)
        try:
            # the note is the person's to write and is no part of the writes: a stand-in lets
            # a reason that needs one be previewed before it is written
            built = await service.preview_closure(
                casepages.preview_actor(me),
                case_id,
                reason,
                expected_version=expected_version,
                note="(the note)",
            )
        except CaseRefused as exc:
            raise case_refusal(exc, "request_closure") from None
        bound = int(built.payload["version"])  # the version the request event will give the case
        count = len(built.writes)
        words = (
            f"Asking for this closure binds {count} change{'s' if count != 1 else ''} to Kibana:"
            " an approver reads exactly these before they approve."
            if count
            else "Asking for this closure writes nothing to Kibana (the case is not there):"
            " the closure is recorded in ARGUS only."
        )
        return m.ClosurePreviewOut(
            case_id=case_id, case_version=bound - 1, bound_version=bound, reason=reason,
            target=None, payload=built.payload, payload_hash=built.payload_hash,
            in_kibana=count > 0, words=words, approvers=approvals.required_approvals(reason),
        )  # fmt: skip

    @router.get("/cases/{case_id}/merge-preview", tags=["cases"], operation_id="previewMerge",
                responses=errors(401, 403, 404, 409, 422))  # fmt: skip
    async def preview_merge(
        case_id: CaseId,
        request: Request,
        me: Viewer,
        conn: Conn,
        target: Annotated[uuid.UUID, Query(description="the case to merge into")],
        expected_version: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    ) -> m.ClosurePreviewOut:
        """What asking to merge a confirmed case into another binds (see ``previewClosure``).
        A suspected case is merged at once and has no preview."""
        service = await service_for(request, conn)
        try:
            built = await service.preview_merge(
                casepages.preview_actor(me), case_id, target, expected_version=expected_version
            )
        except CaseRefused as exc:
            raise case_refusal(exc, "merge") from None
        bound = int(built.payload["version"])
        count = len(built.writes)
        return m.ClosurePreviewOut(
            case_id=case_id, case_version=bound - 1, bound_version=bound,
            reason="duplicate", target=await casepages.ref(conn, target), payload=built.payload,
            payload_hash=built.payload_hash, in_kibana=count > 0,
            words=(f"Asking for this merge binds {count} change{'s' if count != 1 else ''} to"
                   " Kibana: an approver reads exactly these before they approve."
                   if count else "Asking for this merge writes nothing to Kibana (the case is"
                   " not there)."),
            approvers=1,
        )  # fmt: skip

    async def command(
        request: Request,
        conn: AsyncConnection,
        me: auth.Reviewer,
        case_id: uuid.UUID,
        version: int,
        make: Any,
    ) -> m.CaseChanged:
        service = await service_for(request, conn)
        try:
            await service.apply(casepages.actor_of(me), case_id, make, expected_version=version)
        except CaseRefused as exc:
            raise case_refusal(exc, type(make).__name__.lower()) from None
        row = await casepages.row_of(conn, case_id)
        assert row is not None
        return m.CaseChanged(case=row, result="done", request_id=None)

    @router.post("/cases/{case_id}/confirm", tags=["cases"], operation_id="confirmCase",
                 responses=change)  # fmt: skip
    async def confirm_case(
        case_id: CaseId, body: m.CaseConfirmIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Confirm a possible incident (a suspected case): it becomes an open case, an incident
        a person stands behind. The same command as ``argus case confirm``: the version you saw
        (409 when it moved), audited as yours. Kibana gets it as any confirmed case does."""
        return await command(request, conn, me, case_id, body.expected_version,
                             Confirm(body.note))  # fmt: skip

    @router.post("/cases/{case_id}/dismiss", tags=["cases"], operation_id="dismissCase",
                 responses=change)  # fmt: skip
    async def dismiss_case(
        case_id: CaseId, body: m.DismissIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Say a possible incident (a suspected case) is not an incident, for a reason: it is
        closed at once. The same command as ``argus case dismiss``; a dismissal also needs the
        review capability. A case the case team posted to Kibana is refused (409): its Kibana
        case would stay open, so it is confirmed and its closure asked for instead. To name the
        case it duplicates, merge it instead."""
        return await command(request, conn, me, case_id, body.expected_version,
                             Dismiss(body.reason, body.note))  # fmt: skip

    @router.post("/cases/{case_id}/take", tags=["cases"], operation_id="takeCase",
                 responses=change)  # fmt: skip
    async def take_case(
        case_id: CaseId, body: m.CaseChangeIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Take the case: you own it from now on (open or assigned to someone else)."""
        return await command(request, conn, me, case_id, body.expected_version, Take())

    @router.post("/cases/{case_id}/assign", tags=["cases"], operation_id="assignCase",
                 responses=change)  # fmt: skip
    async def assign_case(
        case_id: CaseId, body: m.AssignIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Give the case to another person (an active person, not a service)."""
        return await command(request, conn, me, case_id, body.expected_version,
                             Assign(user_id=body.user_id, assignable=False))  # fmt: skip

    @router.post("/cases/{case_id}/release", tags=["cases"], operation_id="releaseCase",
                 responses=change)  # fmt: skip
    async def release_case(
        case_id: CaseId, body: m.CaseChangeIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Give an assigned case back: it is open again, owned by ARGUS."""
        return await command(request, conn, me, case_id, body.expected_version, Release())

    @router.post("/cases/{case_id}/contain", tags=["cases"], operation_id="containCase",
                 responses=change)  # fmt: skip
    async def contain_case(
        case_id: CaseId, body: m.ContainIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Say the case is contained, in your words. Refused until ARGUS can show 72 quiet
        hours of complete logs for the case's actors and indicators."""
        return await command(request, conn, me, case_id, body.expected_version,
                             Contain(body.attestation, NO_QUIET_WINDOW))  # fmt: skip

    @router.post("/cases/{case_id}/reopen", tags=["cases"], operation_id="reopenCase",
                 responses=change)  # fmt: skip
    async def reopen_case(
        case_id: CaseId, body: m.ReopenIn, request: Request, me: Reopener, conn: Conn
    ) -> m.CaseChanged:
        """Reopen a closed case, with your reason."""
        return await command(request, conn, me, case_id, body.expected_version,
                             Reopen(body.reason))  # fmt: skip

    @router.post("/cases/{case_id}/closure-requests", tags=["cases"], status_code=201,
                 operation_id="requestClosure", responses=change,
                 response_model=m.CaseChanged)  # fmt: skip
    async def request_closure(
        case_id: CaseId, body: m.ClosureRequestIn, request: Request, me: Manager, conn: Conn
    ) -> Any:
        """Ask for the case to be closed for a reason. Name the version and the hash of the
        preview you read: a case that moved, or writes that would now be different, are 409 and
        nothing is saved. An approver decides; nothing is closed here."""
        service = await service_for(request, conn)
        actor = casepages.actor_of(me)
        try:
            built = await service.preview_closure(actor, case_id, body.reason,
                                                  expected_version=body.expected_version,
                                                  note=body.note)  # fmt: skip
        except CaseRefused as exc:
            raise case_refusal(exc, "request_closure") from None
        if built.payload_hash != body.payload_hash:
            raise refuse(409, "conflict", "What this closure would write is not what you read"
                         " (the case or its Kibana state changed): read the preview"
                         " again.")  # fmt: skip
        try:
            check = await live_check(conn, provider_for(request, me, token_of(request)),
                                     me.user_id, "request")  # fmt: skip
            applied, request_id = await service.request_closure(
                actor, case_id, expected_version=body.expected_version, reason=body.reason,
                session_token=token_of(request), check=check, note=body.note,
            )  # fmt: skip
        except Refused as exc:
            return refused_answer(exc)
        except CaseRefused as exc:
            raise case_refusal(exc, "request_closure") from None
        except ApprovalError as exc:
            raise approval_refusal(exc) from None
        await same_as_read(conn, request_id, body.payload_hash)
        row = await casepages.row_of(conn, applied.case.id)
        assert row is not None
        return m.CaseChanged(case=row, result="requested", request_id=request_id)

    @router.post("/cases/{case_id}/merge", tags=["cases"], status_code=201,
                 operation_id="mergeCase", responses=change,
                 response_model=m.CaseChanged)  # fmt: skip
    async def merge_case(
        case_id: CaseId, body: m.MergeIn, request: Request, me: Manager, conn: Conn
    ) -> Any:
        """Merge the case into another. A confirmed case asks for an approval (send the hash
        of the preview you read); a suspected one is merged at once."""
        service = await service_for(request, conn)
        actor = casepages.actor_of(me)
        case = await service.get(case_id)
        if case is None:
            raise refuse(404, "not_found", "no such case")
        if not case.confirmed:
            if body.payload_hash is not None:
                raise refuse(422, "invalid", "A suspected case is merged at once and has no"
                             " preview: send the merge without a hash.")  # fmt: skip
            try:
                await service.merge(actor, case_id, body.target_case_id,
                                    expected_version=body.expected_version,
                                    note=body.note)  # fmt: skip
            except CaseRefused as exc:
                raise case_refusal(exc, "merge") from None
            row = await casepages.row_of(conn, case_id)
            assert row is not None
            return m.CaseChanged(case=row, result="merged", request_id=None)
        if body.payload_hash is None:
            raise refuse(422, "invalid", "Merging a confirmed case asks for an approval: send"
                         " the hash of the preview you read.")  # fmt: skip
        try:
            built = await service.preview_merge(actor, case_id, body.target_case_id,
                                                expected_version=body.expected_version,
                                                note=body.note)  # fmt: skip
        except CaseRefused as exc:
            raise case_refusal(exc, "merge") from None
        if built.payload_hash != body.payload_hash:
            raise refuse(409, "conflict", "What this merge would write is not what you read:"
                         " read the preview again.")  # fmt: skip
        try:
            check = await live_check(conn, provider_for(request, me, token_of(request)),
                                     me.user_id, "request")  # fmt: skip
            applied, request_id = await service.request_merge(
                actor, case_id, body.target_case_id, expected_version=body.expected_version,
                session_token=token_of(request), check=check, note=body.note,
            )  # fmt: skip
        except Refused as exc:
            return refused_answer(exc)
        except CaseRefused as exc:
            raise case_refusal(exc, "merge") from None
        except ApprovalError as exc:
            raise approval_refusal(exc) from None
        await same_as_read(conn, request_id, body.payload_hash)
        row = await casepages.row_of(conn, applied.case.id)
        assert row is not None
        return m.CaseChanged(case=row, result="requested", request_id=request_id)

    @router.post("/cases/{case_id}/notices", tags=["cases"], operation_id="recordNotice",
                 responses=change)  # fmt: skip
    async def record_notice(
        case_id: CaseId, body: m.NoticeIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Record that the device's owner (or its department, hostel or lab) was told: who, how
        and when. The case stays open and watched, leaves the work queues, and ARGUS counts its
        alerts instead of raising them; it speaks again only when something changes. Recordable
        on an open or assigned case, more than once (a second notice is a reminder answered)."""
        watch = request.app.state.watch_context
        managed = await knownrun.managed(
            conn, case_id, None if watch is None else watch.classifier,
            known_rules(watch),
        )  # fmt: skip
        return await command(
            request, conn, me, case_id, body.expected_version,
            Notify(body.told, body.how, body.at, body.note, managed),
        )  # fmt: skip

    @router.post("/cases/{case_id}/notices/withdraw", tags=["cases"],
                 operation_id="withdrawNotice", responses=change)  # fmt: skip
    async def withdraw_notice(
        case_id: CaseId, body: m.WithdrawNoticeIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Withdraw a notice that was recorded by mistake: who withdraws it (default: you) and
        why. The case is not notified any more and ARGUS stops absorbing its device's alerts;
        what it already decided known stays decided, and the notice rows stay as the record of
        what was said. A person records the notice again if it was true."""
        return await command(
            request, conn, me, case_id, body.expected_version,
            WithdrawNotice(body.who or me.display_name, body.reason),
        )  # fmt: skip

    @router.post("/cases/{case_id}/blocks", tags=["cases"], operation_id="recordBlock",
                 responses=change)  # fmt: skip
    async def record_block(
        case_id: CaseId, body: m.BlockIn, request: Request, me: Manager, conn: Conn
    ) -> m.CaseChanged:
        """Record that the case's servers or domains were blocked at the network (DNS, the
        firewall, the web proxy): who did it, where and when. The still-active line then reads
        "blocked at the network; the device is still infected"; the device is not treated as
        fixed."""
        return await command(request, conn, me, case_id, body.expected_version,
                             RecordBlock(body.by, body.where, body.at, body.note))  # fmt: skip

    @router.post("/cases/{case_id}/reminders/{kind}/dismiss", tags=["cases"],
                 operation_id="dismissReminder", responses=change)  # fmt: skip
    async def dismiss_reminder(
        case_id: CaseId, kind: m.ReminderKind, request: Request, me: Manager, conn: Conn
    ) -> m.ReminderDismissed:
        """Say a reminder ARGUS suggested (notify again, ask for network-side action) is not
        needed. Nothing about the case changes; the dismissal is audited as yours."""
        service = await service_for(request, conn)
        try:
            done = await service.dismiss_reminder(casepages.actor_of(me), case_id, kind)
        except CaseRefused as exc:
            raise case_refusal(exc) from None
        if not done:
            raise refuse(404, "not_found", "That reminder is not open any more.")
        return m.ReminderDismissed(case_id=case_id, kind=kind)

    async def listing(
        conn: AsyncConnection, case_id: uuid.UUID, request: Request
    ) -> blocklist.Blocklist:
        watch = request.app.state.watch_context
        found = await blocklist.build(
            conn, case_id, load_shared(), getattr(watch, "classifier", None)
        )
        if found is None:
            raise refuse(404, "not_found", "no such case")
        return found

    @router.get("/cases/{case_id}/blocklist", tags=["cases"], operation_id="getBlocklist",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_blocklist(
        case_id: CaseId, request: Request, me: Viewer, conn: Conn
    ) -> m.BlocklistOut:
        """The case's ready block list: its domains, registered domains and addresses with the
        outside evidence for each, ready to send to the head of cybersecurity."""
        found = await listing(conn, case_id, request)
        return m.BlocklistOut(
            case_number=found.case_number, title=found.title, skipped=found.skipped,
            cut=found.cut, notified_at=found.notified_at, blocked_at=found.blocked_at,
            entries=[
                m.BlockEntryOut(
                    type=e.type,  # type: ignore[arg-type]
                    value=e.value, evidence=e.evidence, engines_flagging=e.flagging,
                    engines_total=e.engines, owner=e.owner, registered=e.registered,
                    first_seen_on_campus=e.first_seen, campus_devices=e.devices,
                    evidence_checked=e.checked,
                )
                for e in found.entries
            ],
        )  # fmt: skip

    @router.get("/cases/{case_id}/blocklist.csv", tags=["cases"],
                operation_id="getBlocklistCsv",
                responses={**errors(401, 403, 404, 422),
                           200: {"content": {"text/csv": {"schema": {"type": "string"}}},
                                 "description": "the block list as CSV"}})  # fmt: skip
    async def get_blocklist_csv(
        case_id: CaseId, request: Request, me: Viewer, conn: Conn
    ) -> Response:
        """The block list as CSV, for a spreadsheet."""
        found = await listing(conn, case_id, request)
        return Response(
            blocklist.to_csv(found, bom=True), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="argus-case-{found.case_number}-blocklist.csv"'},
        )  # fmt: skip

    @router.get("/cases/{case_id}/blocklist.txt", tags=["cases"],
                operation_id="getBlocklistText",
                responses={**errors(401, 403, 404, 422),
                           200: {"content": {"text/plain": {"schema": {"type": "string"}}},
                                 "description": "the block list as an e-mail"}})  # fmt: skip
    async def get_blocklist_text(
        case_id: CaseId, request: Request, me: Viewer, conn: Conn
    ) -> PlainTextResponse:
        """The block list as plain text, in the shape of an e-mail to the head of cybersecurity."""
        found = await listing(conn, case_id, request)
        return PlainTextResponse(blocklist.to_text(found, ist_day))

    @router.post("/cases/{case_id}/suggestions/{suggestion_id}/dismiss", tags=["cases"],
                 operation_id="dismissSuggestion", responses=change)  # fmt: skip
    async def dismiss_suggestion(
        case_id: CaseId, suggestion_id: SuggestionId, me: Manager, conn: Conn
    ) -> m.SuggestionDismissed:
        """Dismiss an investigation ARGUS suggested for the case: it is not shown for this case
        again. It joins nothing, and nothing about the case changes; the dismissal is audited as
        yours (what ``argus case suggestions --dismiss`` also does)."""
        done = (
            await conn.execute(
                text(
                    "UPDATE case_suggestions SET dismissed_at = now(), dismissed_by = :u"
                    " WHERE id = :i AND case_id = :c AND dismissed_at IS NULL"
                    " RETURNING investigation_id"
                ),
                {"u": me.user_id, "i": suggestion_id, "c": case_id},
            )
        ).first()
        if done is None:
            raise refuse(404, "not_found", "That suggestion is not open any more.")
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.suggestion_dismissed",
                         target_type="case", target_id=str(case_id),
                         details={"suggestion": suggestion_id,
                                  "investigation": str(done.investigation_id),
                                  "via": "web"})  # fmt: skip
        return m.SuggestionDismissed(case_id=case_id, suggestion_id=suggestion_id)

    async def one_at_a_time(conn: AsyncConnection, what: str) -> None:
        """Two submits of the same note at once meet here: the second waits for the first's
        transaction, then finds its note (a double click is one note)."""
        await conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": what[:2000]})

    async def within_note_limit(conn: AsyncConnection, me: auth.Reviewer) -> None:
        """One person adds at most ``NOTES_PER_HOUR`` notes an hour (a flood of notes is a stuck
        script or a mistake): counted under a lock per person, so two at once count each other."""
        await conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                           {"k": f"note-rate:{me.user_id}"})  # fmt: skip
        made = await conn.scalar(
            text(
                "SELECT (SELECT count(*) FROM case_notes WHERE author_user_id = :u AND"
                " created_at > now() - interval '1 hour') + (SELECT count(*) FROM entity_notes"
                " WHERE author_user_id = :u AND created_at > now() - interval '1 hour')"
            ),
            {"u": me.user_id},
        )
        if int(made or 0) >= NOTES_PER_HOUR:
            raise refuse(422, "invalid", f"You have added {NOTES_PER_HOUR} notes in the last hour,"
                         " the most one person adds in an hour. Wait a while, or put the rest in"
                         " one longer note.")  # fmt: skip

    @router.post("/cases/{case_id}/notes", tags=["cases"], status_code=201,
                 operation_id="addCaseNote", responses=change)  # fmt: skip
    async def add_case_note(
        case_id: CaseId, body: m.NoteCreateIn, request: Request, me: Reviewer, conn: Conn
    ) -> m.NoteCreated:
        """Add a note to the case. Notes are for people: they are never sent to a model, never
        to Kibana, and not a change of the case. The same note by you in the last minute is
        a double submit: it is not added again."""
        service = await service_for(request, conn)
        said = body.body.strip()
        if await service.get(case_id) is None:
            raise refuse(404, "not_found", "no such case")
        await one_at_a_time(conn, f"case-note:{case_id}:{me.user_id}:{said}")
        duplicate = (
            await conn.execute(
                text(
                    "SELECT id, created_at FROM case_notes WHERE case_id = :c AND"
                    " author_user_id = :u AND body = :b AND created_at > now() -"
                    " make_interval(secs => :w) ORDER BY id DESC LIMIT 1"
                ),
                {"c": case_id, "u": me.user_id, "b": said, "w": DUPLICATE_SECONDS},
            )
        ).first()
        if duplicate is not None:
            return m.NoteCreated(
                note=m.NoteOut(id=int(duplicate.id), author=me.display_name or me.username,
                               body=said, created_at=duplicate.created_at),
                duplicate=True,
            )  # fmt: skip
        await within_note_limit(conn, me)
        try:
            note_id = await service.add_note(casepages.actor_of(me), case_id, body.body)
        except CaseRefused as exc:
            raise case_refusal(exc) from None
        made = (await conn.execute(text("SELECT created_at FROM case_notes WHERE id = :i"),
                                   {"i": note_id})).scalar_one()  # fmt: skip
        return m.NoteCreated(
            note=m.NoteOut(id=note_id, author=me.display_name or me.username, body=said,
                           created_at=made),
            duplicate=False,
        )  # fmt: skip

    @router.get("/entity-notes", tags=["cases"], operation_id="listEntityNotes",
                responses=read)  # fmt: skip
    async def list_entity_notes(
        me: Viewer,
        conn: Conn,
        kind: m.EntityNoteKind,
        value: Annotated[str, Query(min_length=1, max_length=512, pattern=CLEAN)],
    ) -> m.EntityNotesOut:
        """The notes people wrote about one host, address, domain or user, newest first."""
        return m.EntityNotesOut(kind=kind, value=value,
                                items=await casepages.entity_notes(conn, kind, value))  # fmt: skip

    @router.post("/entity-notes", tags=["cases"], status_code=201,
                 operation_id="addEntityNote", responses=change)  # fmt: skip
    async def add_entity_note(
        body: m.EntityNoteIn, request: Request, me: Reviewer, conn: Conn
    ) -> m.NoteCreated:
        """Add a note about a host, address, domain or user, kept across cases. Like case
        notes, it is for people only; the same note by you in the last minute is not added
        twice."""
        service = await service_for(request, conn)
        said = body.body.strip()
        await one_at_a_time(conn, f"entity-note:{body.kind}:{body.value}:{me.user_id}:{said}")
        duplicate = (
            await conn.execute(
                text(
                    "SELECT id, created_at FROM entity_notes WHERE kind = :k AND value = :v AND"
                    " author_user_id = :u AND body = :b AND created_at > now() -"
                    " make_interval(secs => :w) ORDER BY id DESC LIMIT 1"
                ),
                {
                    "k": body.kind,
                    "v": body.value,
                    "u": me.user_id,
                    "b": said,
                    "w": DUPLICATE_SECONDS,
                },
            )
        ).first()
        if duplicate is not None:
            return m.NoteCreated(
                note=m.NoteOut(id=int(duplicate.id), author=me.display_name or me.username,
                               body=said, created_at=duplicate.created_at),
                duplicate=True,
            )  # fmt: skip
        await within_note_limit(conn, me)
        try:
            note_id = await service.add_entity_note(casepages.actor_of(me), body.kind, body.value,
                                                    body.body)  # fmt: skip
        except CaseRefused as exc:
            raise case_refusal(exc) from None
        made = (await conn.execute(text("SELECT created_at FROM entity_notes WHERE id = :i"),
                                   {"i": note_id})).scalar_one()  # fmt: skip
        return m.NoteCreated(
            note=m.NoteOut(id=note_id, author=me.display_name or me.username, body=said,
                           created_at=made),
            duplicate=False,
        )  # fmt: skip

    async def db_now(conn: AsyncConnection) -> datetime:
        found: datetime = (await conn.execute(text("SELECT now()"))).scalar_one()
        return found

    @router.get("/approvals", tags=["approvals"], operation_id="listApprovals",
                responses=read)  # fmt: skip
    async def list_approvals(request: Request, me: Viewer, conn: Conn) -> m.ApprovalQueueOut:
        """The approvals queue: requests waiting for a decision (the exact writes, the alerts
        then and now, who decided what), what was decided lately, the groups that may be
        approved together, and whether your step-up (typing your password again) is current."""
        return await casepages.queue(conn, me, await db_now(conn),
                                     can_sign=request.app.state.signer is not None)  # fmt: skip

    async def one_pending(
        conn: AsyncConnection, me: auth.Reviewer, request_id: int, payload_hash: str
    ) -> m.ApprovalOut:
        now = await db_now(conn)
        found = await casepages.approval_views(conn, "r.id = :id", {"id": request_id}, me, now,
                                               limit=1)  # fmt: skip
        if not found:
            raise refuse(404, "not_found", "no such approval request")
        a = found[0]
        if a.payload_hash != payload_hash:
            raise refuse(409, "conflict", "This is not the request you read: read the queue"
                         " again.")  # fmt: skip
        if not a.you.can_decide:
            raise refuse(403 if a.status == "pending" else 409,
                         "forbidden" if a.status == "pending" else "conflict",
                         a.you.why_not or "You cannot decide this.")  # fmt: skip
        return a

    def done(decided: Decided, request_id: int) -> m.DecisionDone:
        return m.DecisionDone(
            request_id=request_id, status=decided.status,
            applied=[m.AppliedOut(case_id=a.case.id, number=a.case.number,
                                  state=a.case.state, version=a.case.version)
                     for a in decided.applied],
        )  # fmt: skip

    async def group_batch(
        conn: AsyncConnection, me: auth.Reviewer, ids: list[int], hashes: dict[int, str] | None
    ) -> dict[str, Any]:
        """The batch a group is approved with, worked out here and never taken from the client:
        every request listed is pending, of one reason, one the person may decide, and (when
        hashes are given) the one they read."""
        if len(set(ids)) != len(ids):
            raise refuse(422, "invalid", "A request is listed twice.")
        now = await db_now(conn)
        views = await casepages.approval_views(conn, "r.id = ANY(CAST(:ids AS bigint[]))",
                                               {"ids": ids}, me, now, limit=len(ids))  # fmt: skip
        if {v.id for v in views} != set(ids):
            raise refuse(409, "conflict", "Some of these requests are not waiting any more:"
                         " read the queue again.")  # fmt: skip
        for v in views:
            # a member this person approved a moment ago (the sample, one by one) has been
            # applied since: it is still part of the group, no longer waiting
            earlier = v.status == "approved" and v.you.decided == "approved"
            if not (casepages.group_eligible(v) or (earlier and casepages.group_kind(v))):
                if v.alerts_same is False:
                    why = "its alerts changed since it was asked for, so it is read on its own"
                else:
                    why = v.you.why_not or (
                        "it is not a benign, false-positive or no-impact closure that one"
                        " approval settles"
                    )
                raise refuse(409, "conflict", f"The closure of case {v.case.number} cannot be"
                             f" approved in a group: {why.rstrip('.')}.")  # fmt: skip
            if hashes is not None and hashes.get(v.id) != v.payload_hash:
                raise refuse(409, "conflict", f"The closure of case {v.case.number} is not the one"
                             " you read: read the queue again.")  # fmt: skip
        if len({v.reason for v in views}) != 1:
            raise refuse(422, "invalid", "A group holds closures for one reason.")
        try:
            return approvals.group(ids, casepages.group_seed(ids))
        except ApprovalError as exc:
            raise approval_refusal(exc) from None

    async def group_is_the_servers(
        conn: AsyncConnection, me: auth.Reviewer, batch: dict[str, Any]
    ) -> None:
        """A sample is approved only as part of a group the server forms (R3-1): the first
        decision under a batch must name a group the queue forms from what waits right now, and a
        later one must belong to the batch that decision recorded (the database binds the rest to
        it). Else the approver could choose the set, and with it the sample they read."""
        recorded = (
            await conn.execute(
                text(
                    "SELECT d.batch FROM approval_decisions d WHERE d.approver_user_id = :me"
                    " AND d.decision = 'approved' AND d.request_id = ANY(CAST(:ids AS bigint[]))"
                ),
                {"me": me.user_id, "ids": batch["sample"]},
            )
        ).scalars().all()  # fmt: skip
        if recorded:
            if any(earlier != batch for earlier in recorded):
                raise refuse(409, "conflict", "Part of this sample was approved in another group,"
                             " so this group cannot be approved together: read the queue"
                             " again.")  # fmt: skip
            return
        formed = casepages.groups_of(await casepages.pending_views(conn, me, await db_now(conn)))
        if frozenset(batch["requests"]) not in {frozenset(i.request_id for i in g.items)
                                                for g in formed}:  # fmt: skip
            raise refuse(409, "conflict", "That is not a group ARGUS formed from what is waiting"
                         " now: read the queue again.")  # fmt: skip

    @router.post("/approvals/{request_id}/decision", tags=["approvals"],
                 operation_id="decideApproval", response_model=m.DecisionDone,
                 responses=errors(400, 401, 403, 404, 409, 422))  # fmt: skip
    async def decide_approval(
        request_id: RequestIdPath,
        body: m.DecisionIn,
        request: Request,
        me: Approver,
        conn: Conn,
    ) -> Any:
        """Approve or reject a request, with the hash of the request you read. Needs your
        password typed again within five minutes (403 ``step_up_required`` otherwise, with the
        page to do it on). A decision that completes a closure or merge applies it in the same
        transaction. ``group`` names the group a request is approved with (its sample first)."""
        desk = desk_for(request, conn, me)
        await one_pending(conn, me, request_id, body.payload_hash)
        batch = None
        if body.group is not None:
            if body.decision != "approved":
                raise refuse(422, "invalid", "A group is approved, not rejected: reject the"
                             " requests one by one.")  # fmt: skip
            if request_id not in body.group:
                raise refuse(422, "invalid", "This request is not in the group named.")
            batch = await group_batch(conn, me, list(body.group), None)
            await group_is_the_servers(conn, me, batch)
        try:
            decided = await desk.decide(proof(request, me), request_id, body.decision,
                                        note=body.note, batch=batch)  # fmt: skip
        except Refused as exc:
            return refused_answer(exc)
        except ApprovalError as exc:
            raise approval_refusal(exc) from None
        except CaseRefused as exc:
            raise case_refusal(exc) from None
        return done(decided, request_id)

    @router.post("/approvals/group", tags=["approvals"], operation_id="approveGroup",
                 response_model=m.GroupDecisionDone,
                 responses=errors(400, 401, 403, 404, 409, 422))  # fmt: skip
    async def approve_group(
        body: m.GroupDecisionIn, request: Request, me: Approver, conn: Conn
    ) -> Any:
        """Approve the rest of a group once its sample is approved one by one (the database
        refuses the rest before the sample): every request with the hash you read, all or none.
        Needs a step-up within five minutes, as every decision does."""
        desk = desk_for(request, conn, me)
        ids = [i.request_id for i in body.items]
        batch = await group_batch(conn, me, ids, {i.request_id: i.payload_hash for i in body.items})
        try:
            made = await desk.approve_rest(proof(request, me), batch, note=body.note)
        except Refused as exc:
            return refused_answer(exc)
        except ApprovalError as exc:
            raise approval_refusal(exc) from None
        except CaseRefused as exc:
            raise case_refusal(exc) from None
        rest = [rid for rid in batch["requests"] if rid not in set(batch["sample"])]
        return m.GroupDecisionDone(
            decided=[done(d, rid) for d, rid in zip(made, rest, strict=True)]
        )

    @router.get("/investigations/{investigation_id}/checks", tags=["investigations"],
                operation_id="listChecks", responses=errors(401, 403, 404, 422))  # fmt: skip
    async def list_checks(
        investigation_id: InvestigationId, me: Viewer, conn: Conn
    ) -> m.InvestigationChecksOut:
        """The checks people asked for on this investigation with their records (state, E-numbers,
        what they cost the SIEM, whether an assessment has read them), the approved checks a
        person may ask for, and what is left of your allowance."""
        found = await queries.investigation(conn, investigation_id)
        if found is None:
            raise refuse(404, "not_found", "no such investigation")
        return await casepages.investigation_checks(conn, investigation_id, found.version, me)

    @router.post("/investigations/{investigation_id}/checks", tags=["investigations"],
                 status_code=202, operation_id="requestCheck",
                 responses=errors(400, 401, 403, 404, 409, 422))  # fmt: skip
    async def request_check(
        investigation_id: InvestigationId, body: m.CheckIn, me: Reviewer, conn: Conn
    ) -> m.CheckQueued:
        """Ask for one more check: one approved template on one address or domain, queued for
        ARGUS's service (through the investigation lane, when the SIEM is healthy). Your own name
        is the request's; 409 when the investigation has changed since you looked, 422 with
        the reason when it can never be asked."""
        found = await queries.investigation(conn, investigation_id)
        if found is None:
            raise refuse(404, "not_found", "no such investigation")
        if body.seen_version != found.version:
            raise refuse(409, "conflict", "The investigation has new alerts since you looked:"
                         " read it again, then ask.")  # fmt: skip
        result, value = await checks.request(
            conn, investigation_id, found.version, body.template, body.entity, me.username,
            clock(),
        )  # fmt: skip
        if result == "refused":
            raise refuse(422, "invalid", casepages.sentence(str(value)))
        if result == "queued":
            request_id = int(value)
        else:
            clean = checks.clean(body.entity)
            request_id = int(
                await conn.scalar(
                    text(
                        "SELECT id FROM investigation_checks WHERE investigation_id = :i AND"
                        " kind = 'check' AND template = :t AND entity = :e AND status IN"
                        " ('queued', 'running') ORDER BY id DESC LIMIT 1"
                    ),
                    {"i": investigation_id, "t": body.template, "e": clean},
                )
                or 0
            )
        await auth.audit(conn, actor=f"user:{me.user_id}", action="investigation.check.request",
                         target_type="investigation", target_id=str(investigation_id),
                         details={"template": body.template, "result": result,
                                  "request": request_id})  # fmt: skip
        return m.CheckQueued(result=cast("Any", result), id=request_id or None)
