"""The ``/api/v1`` routes (Phase 3 plan §4, §7.5; Q-A1): the session, and everything the
classic pages show and do, typed. Built on the same read and write functions as the pages,
so the two always agree (a test compares them on generated data).

Every route declares what it needs (``Need``: a session, a capability, and for a change the
session's ``X-CSRF-Token``); every refusal is ``ErrorOut``. There is no sign-in here: a
password is typed only into the server-rendered ``/signin`` and ``/stepup`` pages."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import date, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from sqlalchemy import text

from argus import site
from argus.assess import queue as assess_queue
from argus.context.packs import PackRegistry
from argus.evaluation import store as gold_store
from argus.report import render as report_render
from argus.report import store as report_store
from argus.reporter import store as reporter_store
from argus.tuning import store as tuning_store
from argus.web import (
    assessed,
    auth,
    dashboard,
    lookups,
    patternsummary,
    queries,
    queuepage,
    security,
    signinpages,
    stance,
)
from argus.web.capabilities import LABELS, Capability, ordered
from argus.web.deps import Conn, Refusal, Surface, forbidden, need
from argus.web.params import CLEAN, DashboardFilters
from argus.web.reviews import NotFoundError, ReviewConflictError, add_review
from argus.web.v1 import (  # UI v2's additions (spec §2.3), the engine's (P4-F E5)
    admin_routes,
    case_routes,
    engine_routes,
    entity_routes,
    report_routes,
    team_routes,
    user_routes,
    views,
    work_routes,
)
from argus.web.v1 import models as m
from argus.web.v1 import queue_models as qm

PREFIX = "/api/v1"
STEP_UP_VALID = timedelta(minutes=5)  # an approval needs a step-up this recent
_COLUMN = r"^[A-Za-z0-9_@.\-]{1,120}$"  # a field name a column may have
_COLUMNS = r"^[A-Za-z0-9_@.,\-]*$"  # field names separated by commas

# What each kind of route needs (declared and checked: argus.web.deps.Need).
SESSION = need(None, Surface.V1)
END_SESSION = need(None, Surface.V1, csrf=True)
VIEW = need(Capability.VIEW, Surface.V1)
REVIEW = need(Capability.REVIEW, Surface.V1, csrf=True)
ANSWER_GOLD = need(Capability.ANSWER_GOLD, Surface.V1, csrf=True)

Session = Annotated[auth.Reviewer, Depends(SESSION)]
Ender = Annotated[auth.Reviewer, Depends(END_SESSION)]
Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
Reviewer = Annotated[auth.Reviewer, Depends(REVIEW)]
GoldAnswerer = Annotated[auth.Reviewer, Depends(ANSWER_GOLD)]
InvestigationId = Annotated[uuid.UUID, Path(description="an investigation's id")]
AGENT = "agent@1"  # the AI investigator's name (argus.agent.agent.NAME; a test keeps them equal)

_WHY = {
    400: "the body could not be read",
    401: "not signed in, or the session ended: sign in at /signin",
    403: "refused: a missing X-CSRF-Token (csrf), a capability the account lacks (forbidden),"
    " or not this site's own page (origin)",
    404: "no such thing",
    409: "it changed while you looked (conflict), or is not ready yet (not_ready)",
    422: "the request does not match this contract",
    503: "unavailable: ARGUS cannot reach its database (any operation), or the AI investigator"
    " is not on this server",
}


def errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    """The documented error answers of a route: each an ErrorOut; any route may answer 503
    while ARGUS's database is unreachable (Q-A1 review F5)."""
    return {code: {"model": m.ErrorOut, "description": _WHY[code]}
            for code in sorted({*codes, 503})}  # fmt: skip


READ = errors(401, 403, 422)
CHANGE = errors(400, 401, 403, 404, 422)


OFFSET_HELP = (
    "how many to skip: at most 10,000 (every sort answers within criterion 14's 300 ms that"
    " deep at the exit's scale); narrow the list or turn the sort around to see further"
)


def site_out() -> m.SiteOut:
    """The site's zone, label, noun and names for the pages (``site`` in the settings)."""
    profile = site.active()
    return m.SiteOut(
        timezone=profile.timezone,
        timezone_label=profile.timezone_label,
        own_network_noun=profile.own_network_noun,
        organisation_name=profile.organisation.name,
        organisation_short_name=profile.organisation.short_name,
        organisation_kind=profile.organisation.kind,
        organisation_units=profile.organisation.units,
        organisation_reviewers=profile.organisation.reviewers,
    )


def refuse(status: int, code: str, detail: str) -> Refusal:
    return Refusal(status, code, detail, Surface.V1)


def build(
    *,
    clock: Callable[[], datetime],
    privacy: Any,
    cost_caps: tuple[float, float, float | None],
    packs: PackRegistry | None = None,
) -> APIRouter:
    """The routes, for one app (its clock, its privacy layer for "Ask the AI", its caps)."""
    router = APIRouter(prefix=PREFIX)
    cap, paid_share, daily_cap = cost_caps

    @router.get("/session", tags=["session"], operation_id="getSession",
                responses=errors(401, 403))  # fmt: skip
    async def get_session(request: Request, me: Session, conn: Conn) -> m.SessionOut:
        """Who is signed in, what they may do, the CSRF token for changes, and when the
        session ends. Without a session: 401, and the person signs in at ``/signin``."""
        web = request.app.state.web
        now = clock()
        expires = me.expires_at or now + web.session_idle
        idle = min((me.last_seen_at or now) + web.session_idle, expires)
        stepped = me.stepped_up_at
        return m.SessionOut(
            user=m.UserOut(id=me.user_id, username=me.username, display_name=me.display_name),
            mode="elk" if me.elk else "local",  # break-glass is a local password account
            break_glass=me.mode == "break_glass",
            unverified=None if me.unverified_since is None else m.UnverifiedOut(
                since=me.unverified_since,
                why="outage" if me.unverified_why == "outage" else "refused"),
            capabilities=[m.CapabilityOut(name=c.value, label=LABELS[c])
                          for c in ordered(me.capabilities)],
            csrf_token=me.csrf_token, expires_at=expires, idle_expires_at=idle,
            idle_timeout_s=int(web.session_idle.total_seconds()), stepped_up_at=stepped,
            step_up_valid_until=None if stepped is None else stepped + STEP_UP_VALID,
            since=me.previous_seen_at, site=site_out(),
            setup_pending=await admin_routes.setup_pending(conn),
        )  # fmt: skip

    @router.delete("/session", tags=["session"], operation_id="endSession", status_code=204,
                   responses=errors(401, 403))  # fmt: skip
    async def end_session(request: Request, me: Ender, conn: Conn) -> Response:
        """Sign out: the session ends at once and its cookie is cleared."""
        await auth.end(conn, me.token_hash, clock(), "signed_out")
        await auth.audit(conn, actor=f"user:{me.username}", action="logout")
        response = Response(status_code=204)
        tls = request.app.state.web.tls_cert is not None  # a __Host- cookie is unset only so
        response.delete_cookie(security.session_cookie(tls), path="/", secure=tls,
                               httponly=True, samesite="strict")  # fmt: skip
        return response

    @router.get("/investigations", tags=["investigations"], operation_id="listInvestigations",
                responses=READ)  # fmt: skip
    async def list_investigations(
        me: Viewer,
        conn: Conn,
        view: m.View = "attention",
        sort: m.Sort | None = None,
        rule: Annotated[str | None, Query(max_length=200, pattern=CLEAN)] = None,
        kind: m.EntityKind | None = None,
        value: Annotated[str | None, Query(max_length=300, pattern=CLEAN)] = None,
        offset: Annotated[int, Query(ge=0, le=queries.DEEPEST, description=OFFSET_HELP)] = 0,
        limit: Annotated[int, Query(ge=1, le=queries.PAGE)] = queries.PAGE,
    ) -> m.InvestigationPage:
        """The Inbox: a view (attention, open, reviewed, all), optionally one rule or one
        entity (kind and value together). Without ``sort``: newest alert first, and the
        reviewed view by newest decision (the classic Inbox's order, D-095). ``sort=queue`` is
        the order Home's queue walks: changed since a notice, then raised by ARGUS's evidence,
        then a follow-up, then the rule's severity, then the last alert (AR4 review, D-186).
        Pages reach 10,000 investigations deep at most: past that, narrow the list (a view, a
        rule, an entity) or turn the sort around."""
        order = sort or ("reviewed" if view == "reviewed" else "newest")
        entity = (kind, value) if kind is not None and value is not None else None
        found = await queries.inbox(conn, view, rule=rule, entity=entity, offset=offset,
                                    limit=limit + 1, sort=order)  # fmt: skip
        page = found[:limit]
        ai = await assessed.verdicts(conn, [s.id for s in page])
        return m.InvestigationPage(
            items=[views.investigation(s, ai.get(s.id)) for s in page], view=view, sort=order,
            offset=offset, limit=limit, has_more=len(found) > limit,
        )  # fmt: skip

    @router.get("/queue", tags=["investigations"], operation_id="getQueue", responses=READ)
    async def get_queue(request: Request, me: Viewer, conn: Conn) -> qm.QueueOut:
        """What needs a person, in order (AR4): ARGUS's open cases that need one (suggested
        cases and cases with a change since the owner was told first), each with its verdict or
        reading, its campus devices and its outside addresses (apart) and why it is here; then
        the single investigations in Needs attention that belong to no case; and the order the
        app's "Next" walks through them. The patterns to close are ``/patterns``; the numbers of
        new and known work are ``/counts``."""
        watch = request.app.state.watch_context
        return await queuepage.build(conn, me.user_id, hide_logs=not me.can(Capability.SEE_LOGS),
                                     classifier=getattr(watch, "classifier", None))  # fmt: skip

    @router.get("/counts", tags=["investigations"], operation_id="getCounts", responses=READ)
    async def get_counts(me: Viewer, conn: Conn) -> m.CountsOut:
        """How many investigations are in each state; how many were decided in 24 hours."""
        return m.CountsOut(**await queries.counts(conn, clock()))

    @router.get("/investigations/{investigation_id}", tags=["investigations"],
                operation_id="getInvestigation", responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_investigation(
        request: Request, investigation_id: InvestigationId, me: Viewer, conn: Conn
    ) -> m.InvestigationDetail:
        """Everything the investigation page shows, but its alerts (``/alerts``). ``signins``
        says who used the investigation's internal devices, from the SSO sign-ins ARGUS kept
        (account names only for an account with ``see_logs``)."""
        summary = await queries.investigation(conn, investigation_id)
        if summary is None:
            raise refuse(404, "not_found", "no such investigation")
        history = await assessed.history(conn, investigation_id)
        current = await assessed.current(conn, investigation_id)
        hidden = not me.can(Capability.SEE_LOGS)  # as in /reports: the model's words, the results
        shown = [a for a in (views.assessment(d, hide_logs=hidden) for d in history)
                 if a is not None]  # fmt: skip
        acceptable = (
            current.assessment_id
            if current is not None and current.status == "proposed"
            and summary.human_state != "reviewed"
            and any(d.assessment_id == current.assessment_id for d in history)
            else None
        )  # fmt: skip
        ai = await assessed.verdicts(conn, [investigation_id])
        same = (
            None
            if any(assessed.is_agent(d.assessor) for d in history)
            else await assessed.shared(conn, investigation_id)
        )
        same_out = None if same is None else views.same_pattern(same, hide_logs=hidden)
        choice = stance.choose(history, same)
        size = None
        if choice is not None:
            size = (await stance.pattern_sizes(conn, [choice.detail.assessment_id])).get(
                choice.detail.assessment_id
            )  # fmt: skip
        return m.InvestigationDetail(
            investigation=views.investigation(summary, ai.get(investigation_id)),
            coverage=views.coverage(queries.banners(await queries.coverage(conn, summary))),
            dossier=views.dossier(await queries.dossier(conn, investigation_id)),
            assessments=shown, same_pattern=same_out, acceptable_assessment_id=acceptable,
            stance=views.stance_out(choice, hide_logs=hidden, acceptable_id=acceptable, size=size),
            ask_available=privacy is not None
            and not any(assessed.is_agent(d.assessor) for d in history),
            gold=views.gold_item(await gold_store.item(conn, investigation_id, gold_store.ANY)),
            reviews=[views.review(r) for r in await queries.reviews(conn, investigation_id)],
            alert_fields=[m.FieldCount(field=str(f), count=int(n))
                          for f, n in await queries.alert_fields(conn, investigation_id)],
            signins=await signinpages.for_investigation(
                conn, getattr(request.app.state, "signins", None), investigation_id, clock(),
                hidden=hidden,
            ),
            case=await lookups.case_of(conn, investigation_id),
        )  # fmt: skip

    @router.get("/investigations/{investigation_id}/reports", tags=["investigations"],
                operation_id="getReports", responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_reports(
        investigation_id: InvestigationId, me: Viewer, conn: Conn
    ) -> m.ReportsOut:
        """report@2 (Q-F2) of the investigation: what ARGUS found, where each fact came from
        (its E-number), what is new against the alerts alone, and what is still open. One
        report per assessor, the AI investigator's first; none while there is no dossier. An
        account without ``see_logs`` gets every result read from the logs hidden."""
        if await queries.investigation(conn, investigation_id) is None:
            raise refuse(404, "not_found", "no such investigation")
        found = await report_store.current(conn, investigation_id, packs)
        hidden = not me.can(Capability.SEE_LOGS)
        return m.ReportsOut(
            items=[report_render.hide_logs(r) for r in found] if hidden else found,
            logs_hidden=hidden,
        )

    @router.get("/investigations/{investigation_id}/alerts", tags=["investigations"],
                operation_id="listAlerts", responses=errors(401, 403, 404, 422))  # fmt: skip
    async def list_alerts(
        investigation_id: InvestigationId,
        me: Viewer,
        conn: Conn,
        columns: Annotated[str | None, Query(max_length=4000, pattern=_COLUMNS)] = None,
    ) -> m.AlertsOut:
        """The newest 200 alerts with the chosen columns: field names separated by commas (at
        most 12 kept; fields the alerts lack are left out). Without ``columns``, the fields the
        rule's own steps name, as on the page; ``columns=`` (empty) chooses none."""
        summary = await queries.investigation(conn, investigation_id)
        if summary is None:
            raise refuse(404, "not_found", "no such investigation")
        available = {f for f, _ in await queries.alert_fields(conn, investigation_id)}
        if columns is None:
            found = await queries.dossier(conn, investigation_id)
            report = (found or {}).get("report") or {}
            asked = [str(f) for s in report.get("steps") or [] if isinstance(s, dict)
                     for f in s.get("fields") or []]  # fmt: skip
        else:
            asked = columns.split(",")
        chosen = list(dict.fromkeys(
            c for c in asked[:200] if c in available and re.fullmatch(_COLUMN, c)
        ))[: queries.MAX_COLUMNS]  # fmt: skip
        rows = await queries.alerts(conn, investigation_id, columns=chosen)
        return views.alerts(rows, summary.alert_count, chosen)

    @router.get("/investigations/{investigation_id}/alerts/{alert_id}", tags=["investigations"],
                operation_id="getRawAlert", responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_raw_alert(
        investigation_id: InvestigationId,
        alert_id: Annotated[str, Path(max_length=512, pattern=CLEAN)],
        me: Viewer,
        conn: Conn,
    ) -> m.RawAlertOut:
        """One alert as the SIEM stored it (raw data on demand)."""
        raw = await queries.raw_alert(conn, investigation_id, alert_id)
        if raw is None:
            raise refuse(404, "not_found", "no such alert in this investigation")
        return m.RawAlertOut(alert_id=alert_id, investigation_id=investigation_id, raw=raw)

    @router.post("/investigations/{investigation_id}/reviews", tags=["investigations"],
                 operation_id="createReview", status_code=201,
                 responses=errors(400, 401, 403, 404, 409, 422))  # fmt: skip
    async def create_review(
        request: Request,
        investigation_id: InvestigationId,
        body: m.ReviewIn,
        me: Reviewer,
        conn: Conn,
    ) -> m.ReviewCreated:
        """A verdict (an outcome is required to mark it reviewed), a follow-up, or a note.
        Name the latest review you saw and the version you looked at: if either moved, the
        answer is 409 and nothing is saved. ``also_gold`` also saves the outcome as your
        gold-set answer, if the investigation is in the gold set (needs answer_gold)."""
        outcome = None if isinstance(body, m.NoteIn) else body.outcome
        gold = not isinstance(body, m.NoteIn) and body.also_gold and outcome is not None
        if gold and not me.can(Capability.ANSWER_GOLD):
            raise forbidden(me, Capability.ANSWER_GOLD, Surface.V1)
        try:
            done = await add_review(
                conn, me, investigation_id, action=body.action, outcome=outcome, note=body.note,
                seen_review=body.seen_review, seen_version=body.seen_version,
            )  # fmt: skip
        except NotFoundError:
            raise refuse(404, "not_found", "no such investigation") from None
        except ReviewConflictError:
            raise refuse(409, "conflict", "someone else reviewed it, or new alerts arrived,"
                         " while you were reading: nothing was saved") from None  # fmt: skip
        except ValueError as exc:
            raise refuse(422, "invalid", str(exc)) from None
        saved = False
        if gold and outcome is not None:
            try:
                async with conn.begin_nested():
                    await gold_store.answer(
                        conn,
                        investigation_id,
                        me.user_id,
                        outcome,
                        body.note,
                        set_name=gold_store.ANY,
                    )
                saved = True
            except gold_store.GoldError:
                saved = False
        return m.ReviewCreated(review_id=done.review_id, version=done.version, gold_saved=saved)

    @router.post("/investigations/{investigation_id}/gold", tags=["investigations"],
                 operation_id="answerGold", responses=CHANGE)  # fmt: skip
    async def answer_gold(
        investigation_id: InvestigationId, body: m.GoldAnswerIn, me: GoldAnswerer, conn: Conn
    ) -> m.GoldSaved:
        """Your answer for a gold-set item (a correction is a new answer; the newest
        counts); then the next unanswered item, if any."""
        try:
            await gold_store.answer(
                conn, investigation_id, me.user_id, body.outcome, body.note, set_name=gold_store.ANY
            )
        except gold_store.GoldError as exc:
            if str(exc) == "not in the gold set":
                raise refuse(
                    404, "not_found", "this investigation is not in the gold set"
                ) from None
            raise refuse(422, "invalid", str(exc)) from None
        left = [r for r in await gold_store.items(conn, gold_store.ANY) if r.outcome is None]
        return m.GoldSaved(next_investigation_id=left[0].investigation_id if left else None)

    @router.post(
        "/investigations/{investigation_id}/accept",
        tags=["investigations"],
        operation_id="acceptProposal",
        responses=errors(400, 401, 403, 404, 409, 422),
    )
    async def accept_proposal(
        investigation_id: InvestigationId, body: m.AcceptIn, me: Reviewer, conn: Conn
    ) -> m.Accepted:
        """Accept the investigation's current proposal: a review with its outcome, marked as
        a confirmed proposal. 409 if it is no longer current or the investigation was
        reviewed meanwhile."""
        owner = await conn.scalar(
            text("SELECT investigation_id FROM assessments WHERE id = :a"),
            {"a": body.assessment_id},
        )
        if owner != investigation_id:
            raise refuse(404, "not_found", "no such proposal on this investigation")
        try:
            await assess_queue.accept(conn, body.assessment_id, me.user_id, kibana_ok=me.kibana_ok)
        except assess_queue.AssessmentConflict:
            raise refuse(
                409,
                "conflict",
                "the proposal changed (new alerts, a newer"
                " assessment, or someone reviewed it): nothing was saved",
            ) from None
        await auth.audit(conn, actor=f"user:{me.username}", action="assessment.accept",
                         target_type="assessment", target_id=str(body.assessment_id))  # fmt: skip
        return m.Accepted(assessment_id=body.assessment_id, investigation_id=investigation_id)

    @router.post("/investigations/{investigation_id}/assess", tags=["investigations"],
                 operation_id="askInvestigator", status_code=202,
                 responses=errors(401, 403, 404, 409, 422, 503))  # fmt: skip
    async def ask_investigator(
        investigation_id: InvestigationId, me: Reviewer, conn: Conn
    ) -> m.AskOut:
        """Ask the AI investigator about this investigation now, reviewed or not (D-095).
        "exists": it has assessed what the investigation shows now already."""
        if privacy is None:
            raise refuse(503, "unavailable", "the AI investigator is not available on this server")
        if await queries.investigation(conn, investigation_id) is None:
            raise refuse(404, "not_found", "no such investigation")
        from argus.assess import runner

        got = await runner.request(conn, privacy, investigation_id, AGENT, clock())
        if got == "refused":  # its files are refused, or a person's request may not start it
            raise refuse(503, "unavailable", "the AI investigator is not available on this server")
        if got == "no dossier":
            raise refuse(409, "not_ready", "ARGUS has not built this investigation's dossier"
                         " yet; try again in a few minutes")  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}", action="assessment.request",
                         target_type="investigation", target_id=str(investigation_id),
                         details={"result": got})  # fmt: skip
        return m.AskOut(result="queued" if got == "queued" else "exists")

    @router.get("/proposals", tags=["proposals"], operation_id="listProposals", responses=READ)
    async def list_proposals(me: Viewer, conn: Conn) -> list[m.ProposalGroupOut]:
        """Proposals waiting for a person, grouped by what decided them, the largest group
        first; each with its audit sample (a random order fixed for the day)."""
        return views.proposal_groups(await assessed.proposals(conn, clock().date()))

    @router.post("/proposals/confirm", tags=["proposals"], operation_id="confirmProposals",
                 responses={**errors(400, 401, 403, 422),
                            409: {"model": m.ErrorOut, "description": "the list holds a true"
                                  " positive (conflict): nothing was accepted"}})  # fmt: skip
    async def confirm_proposals(body: m.ConfirmIn, me: Reviewer, conn: Conn) -> m.ConfirmOut:
        """Accept a group's proposals: only those listed, and only while each is still
        current and of that group (the others are skipped and counted). A list holding a true
        positive is refused (409, nothing accepted): what the proposal says, not the request,
        stands in the way; each one starts an incident and is decided on its own."""
        listed = list(body.assessment_ids)[: assessed.GROUP_LIMIT]
        if await assessed.true_positives(conn, listed):
            raise refuse(409, "conflict", "A true positive starts an incident, so it is never"
                         " confirmed with its group: open each one and decide it on its own"
                         " page.")  # fmt: skip
        accepted, skipped = await assessed.confirm(
            conn, body.group, listed, me.user_id,
            "confirmed with its group", kibana_ok=me.kibana_ok,
        )  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}", action="assessment.confirm",
                         target_type="assessment_group", target_id=body.group[:200],
                         details={"accepted": accepted, "skipped": skipped})  # fmt: skip
        return m.ConfirmOut(accepted=accepted, skipped=skipped)

    @router.get("/patterns", tags=["patterns"], operation_id="listPatterns", responses=READ)
    async def list_patterns(me: Viewer, conn: Conn) -> m.PatternPageOut:
        """Unreviewed investigations grouped when the same rule found the same things. The groups
        are made from a sample: the newest investigations not reviewed yet that have a dossier
        (``read`` of the newest ``limit``); when ``sampled``, older ones are in no group. A group
        carries ARGUS's recommendation when it has one to close it (AR4): the members that
        have a proposal, all of one closing outcome."""
        page = await queries.patterns_page(conn)
        found = page.groups
        ids = [uuid.UUID(str(x["id"])) for g in found for x in g["members"]]
        leaned = await stance.lean(conn, ids)
        advice = {
            place: r for place, g in enumerate(found)
            if (r := stance.recommend([uuid.UUID(str(x["id"])) for x in g["members"]], leaned))
            is not None
        }  # fmt: skip
        return m.PatternPageOut(groups=views.patterns(found, advice), read=page.read,
                                limit=page.limit, sampled=page.sampled)  # fmt: skip

    @router.get("/patterns/summary", tags=["patterns"], operation_id="getPatternSummary",
                responses=READ)  # fmt: skip
    async def get_pattern_summary(me: Viewer, conn: Conn) -> m.PatternSummaryOut:
        """The patterns ARGUS recommends closing, for Home: how many there are in all, how many
        investigations they cover, and the largest few. Real totals, read in SQL from the
        investigator's runs: no dossier is read and nothing is sampled (AR4 review, D-186)."""
        return await patternsummary.summary(conn)

    @router.get("/patterns/closing", tags=["patterns"], operation_id="getPatternClosing",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_pattern_closing(
        me: Viewer,
        conn: Conn,
        pattern: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$", description="the pattern's hash")],
        day: Annotated[date, Query(description="its IST day")],
    ) -> m.PatternCloseOut:
        """The members closing one pattern names, read now: the investigations ARGUS has a
        proposal for (at most 200), each with its version and latest review, to send to
        ``POST /patterns/review``. 404 when ARGUS no longer recommends closing the pattern."""
        found = await patternsummary.closing(conn, pattern, day)
        if found is None:
            raise refuse(404, "not_found", "ARGUS does not recommend closing this pattern now")
        return found

    @router.post("/patterns/review", tags=["patterns"], operation_id="reviewPattern",
                 responses=errors(400, 401, 403, 422))  # fmt: skip
    async def review_pattern(
        body: m.PatternReviewIn, me: Reviewer, conn: Conn
    ) -> m.PatternReviewOut:
        """Mark the listed investigations reviewed with one outcome: each only if it is
        still exactly as you saw it (version and latest review); the others are left."""
        done = changed = 0
        for item in body.items:
            try:
                await add_review(
                    conn,
                    me,
                    item.investigation_id,
                    action="reviewed",
                    outcome=body.outcome,
                    note="Reviewed with its pattern.",
                    seen_review=item.latest_review,
                    seen_version=item.version,
                )
                done += 1
            except (ReviewConflictError, NotFoundError):
                changed += 1
        return m.PatternReviewOut(reviewed=done, changed=changed)

    @router.get("/rules", tags=["browse"], operation_id="listRules", responses=READ)
    async def list_rules(me: Viewer, conn: Conn) -> list[m.RuleOut]:
        """Investigations per detection rule."""
        return views.rules(await queries.by_rule(conn))

    @router.get("/entities", tags=["browse"], operation_id="listEntities", responses=READ)
    async def list_entities(me: Viewer, conn: Conn) -> list[m.EntityRowOut]:
        """The hosts and addresses in the most investigations."""
        return views.entities(await queries.by_entity(conn))

    @router.get("/health", tags=["system"], operation_id="getHealth", responses=READ)
    async def get_health(me: Viewer, conn: Conn) -> m.HealthOut:
        """Is data arriving: the SIEM's state, the collector's cursors, open coverage gaps, and
        whether confirmed incidents reach Kibana (``case_team``)."""
        found = views.health(await queries.health(conn, clock()))
        found.case_team = await lookups.case_team_health(conn)
        return found

    @router.get("/glossary", tags=["system"], operation_id="getGlossary", responses=READ)
    async def get_glossary(me: Viewer) -> list[m.TermOut]:
        """What every signal means and how to read it."""
        return [m.TermOut(**t) for t in queries.glossary()]

    @router.get("/cost", tags=["system"], operation_id="getCost", responses=READ)
    async def get_cost(me: Viewer, conn: Conn) -> m.CostOut:
        """The AI spend this month and today, against the caps (the cost bar)."""
        return views.cost(await assessed.cost(conn, clock(), cap, paid_share, daily_cap))

    @router.get("/metrics", tags=["system"], operation_id="getMetrics", responses=READ)
    async def get_metrics(me: Viewer, conn: Conn) -> m.MetricsOut:
        """How the assessments and the model gateway are doing."""
        now = clock()
        quota, stopped = await assessed.gateway(conn, now)
        return views.metrics(await assessed.metrics(conn, now), quota, stopped)

    @router.get("/tuning", tags=["system"], operation_id="listTuning", responses=READ)
    async def list_tuning(me: Viewer, conn: Conn) -> list[m.TuningReportOut]:
        """Each rule's newest weekly tuning report."""
        return views.tuning(await tuning_store.latest(conn))

    @router.get("/reports", tags=["system"], operation_id="listReports", responses=READ)
    async def list_reports(
        me: Viewer,
        conn: Conn,
        kind: Annotated[
            Literal["daily", "weekly"] | None, Query(description="one kind only")
        ] = None,
    ) -> list[m.ReportRowOut]:
        """The daily and weekly reports ARGUS made, newest period first (the last 60)."""
        return [
            m.ReportRowOut(id=r.id, kind=r.kind, period_start=r.period_start,
                           period_end=r.period_end, generated_at=r.generated_at,
                           has_prose=r.prose)
            for r in await reporter_store.listing(conn, kind=kind)
        ]  # fmt: skip

    @router.get("/reports/{report_id}", tags=["system"], operation_id="getReport",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_report(
        me: Viewer, conn: Conn, report_id: Annotated[int, Path(ge=1, le=2**62)]
    ) -> m.ReportOut:
        """One report: every figure with its definition, and the report as plain text."""
        found = await reporter_store.get(conn, report_id)
        if found is None:
            raise refuse(404, "not_found", "no such report")
        return m.ReportOut(
            id=found.id, kind=found.numbers.kind, period_start=found.period_start,
            period_end=found.period_end, generated_at=found.generated_at,
            as_at=found.numbers.as_at,
            sections=[
                m.ReportSectionOut(
                    id=s.id, title=s.title, notes=list(s.notes),
                    metrics=[m.ReportMetricOut(key=x.key, label=x.label, value=x.value,
                                               unit=x.unit, definition=x.definition)
                             for x in s.metrics],
                )
                for s in found.numbers.sections
            ],
            text=found.text, prose=found.prose,
        )  # fmt: skip

    @router.get("/gold", tags=["system"], operation_id="getGoldSet", responses=READ)
    async def get_gold_set(me: Viewer, conn: Conn) -> m.GoldSetOut:
        """The gold set: the answer key that measures how often ARGUS is right."""
        return views.gold_set(
            await gold_store.items(conn, gold_store.ANY),
            await gold_store.progress(conn, gold_store.ANY),
        )

    @router.get("/dashboard", tags=["dashboard"], operation_id="getDashboard", responses=READ)
    async def get_dashboard(me: Viewer, conn: Conn, filters: DashboardFilters) -> m.DashboardOut:
        """The SOC dashboard's numbers under the same filters as the page (D-103)."""
        return views.dashboard_out(await dashboard.build(conn, filters, clock()))

    @router.get("/dashboard/threat-lists", tags=["dashboard"], operation_id="getThreatLists",
                responses=READ)  # fmt: skip
    async def get_threat_lists(
        me: Viewer, conn: Conn, filters: DashboardFilters
    ) -> m.ThreatTileOut:
        """Whether the most urgent open investigations of the dashboard's span are on a threat
        list, from their dossiers: out of date or unchecked is said, never shown as clear."""
        return views.threat_tile(await dashboard.threat_lists(conn, filters, clock()))

    @router.get("/since", tags=["session"], operation_id="getSince", responses=READ)
    async def get_since(me: Viewer, conn: Conn) -> m.SinceOut:
        """What changed since the person's previous visit (the session's ``since``): new
        investigations, decisions by others, new proposals. Counted up to a cap."""
        found = await queries.since(conn, me.user_id, me.previous_seen_at)
        return views.since_out(me.previous_seen_at, found)

    work_routes.install(router, clock=clock, errors=errors)  # UI v2: holds, seen, bulk
    entity_routes.install(router, clock=clock, errors=errors)  # UI v2: entities, search
    case_routes.install(router, clock=clock, errors=errors)  # cases, approvals, notes, checks
    report_routes.install(router, clock=clock, errors=errors)  # the incident report
    team_routes.install(router, clock=clock, errors=errors)  # the Kibana case preview
    engine_routes.install(router, clock=clock, errors=errors)  # Today (P4-F E5)
    admin_routes.install(router, clock=clock, errors=errors)  # Settings (P4-H, D-327)
    user_routes.install(router, clock=clock, errors=errors)  # users and roles (D-327)
    return router
