"""A person's work on the queue (UI v2 spec §2.3): "I'm checking" (A1), "Mark as seen" (A2), the
spot-check answer (A3), "I'm caught up" (A4), bulk "Not an incident" (A9), the bulk review of one
incident's alert groups, "sent to the CISO" (A14), a next step ticked (A16), and the undo of one's
own dismissal (A8).

Rules every route here follows, as the case routes do: the route's capability is checked before
anything is read, and every change needs the session's CSRF token; a change names what the
person looked at and is 409 when it moved; a bulk change is one transaction, all or none (a
refusal of one item rolls the others back and names it); every write is audited as the person's
(``user:<id>``), a case command through :class:`~argus.cases.service.CaseService` as the terminal's
is. Postgres only: no SIEM request, no model."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.machine import CaseRefused, Dismiss, Reopen
from argus.cases.service import CaseService
from argus.responder import store as responder
from argus.responder.machine import ActionRefused, ist_day
from argus.web import auth, casepages, decisions, needsyou
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.reviews import OUTCOME_LABELS, NotFoundError, ReviewConflictError, add_review
from argus.web.stance import CLOSING
from argus.web.v1 import case_models as cm
from argus.web.v1 import work_models as m
from argus.web.v1.case_routes import CaseId, case_refusal

VIEW_CHANGE = need(Capability.VIEW, Surface.V1, csrf=True)
REVIEW = need(Capability.REVIEW, Surface.V1, csrf=True)
MANAGE = need(Capability.MANAGE_CASES, Surface.V1, csrf=True)
Looker = Annotated[auth.Reviewer, Depends(VIEW_CHANGE)]
Reviewer = Annotated[auth.Reviewer, Depends(REVIEW)]
Manager = Annotated[auth.Reviewer, Depends(MANAGE)]
TargetId = Annotated[uuid.UUID, Path(description="the spot-checked incident or alert group")]
ActionId = Annotated[
    str, Path(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$",
              description="a next step's catalogue id (<family>.<key>)"),
]  # fmt: skip
HOLD_LONGEST = timedelta(days=14)  # "Pick a date": at most two weeks ahead
SPOT_DAYS = 30  # the team's spot-check score covers this many days
DUPLICATE_SECONDS = 60  # the same "sent" by the same person this soon is a double submit
_ACTION_STATUS = {"forbidden": (403, "forbidden"), "invalid": (422, "invalid"),
                  "not_found": (404, "not_found"), "conflict": (409, "conflict")}  # fmt: skip
# what ARGUS did with an alert group without a person: the incident it joined it to after that
# incident began (``joined``), whether it is in an incident at all, and the outcome of its
# decision when that decision accepted ARGUS's proposal
_SPOT_GROUP = text(
    "SELECT (SELECT c.number FROM case_members mm JOIN cases c ON c.id = mm.case_id"
    "  WHERE mm.investigation_id = i.id AND mm.removed_at IS NULL"
    "  AND mm.added_by NOT LIKE 'user:%' AND mm.added_version > 1) AS joined,"
    " EXISTS (SELECT 1 FROM case_members mm WHERE mm.investigation_id = i.id"
    "  AND mm.removed_at IS NULL) AS in_case,"
    " (SELECT r.outcome FROM review_state s JOIN review_events r ON r.id = s.decision_id"
    "  WHERE s.investigation_id = i.id AND s.action = 'reviewed'"
    "  AND r.assessment_id IS NOT NULL) AS proposed"
    " FROM investigations i WHERE i.id = :i"
)
# a case, and whether the event that closed it (its newest move into closed) was a person's
_SPOT_CASE = text(
    "SELECT c.state, c.closure_reason,"
    " (SELECT e.actor_user_id IS NOT NULL FROM case_events e WHERE e.case_id = c.id"
    "  AND e.to_state = 'closed' AND e.from_state IS DISTINCT FROM 'closed'"
    "  ORDER BY e.case_version DESC LIMIT 1) AS by_person"
    " FROM cases c WHERE c.id = :c"
)


def _refuse(status: int, code: str, detail: str) -> Refusal:
    return Refusal(status, code, detail, Surface.V1)


def _who(me: auth.Reviewer) -> str:
    return me.display_name or me.username


async def _now(conn: AsyncConnection) -> datetime:
    found: datetime = (await conn.execute(text("SELECT now()"))).scalar_one()
    return found


async def _locked_case(conn: AsyncConnection, case_id: uuid.UUID, version: int) -> Any:
    """The case row, locked for this change, at the version the person looked at."""
    row = (
        await conn.execute(
            text("SELECT id, number, state, version FROM cases WHERE id = :c FOR UPDATE"),
            {"c": case_id},
        )
    ).first()
    if row is None:
        raise _refuse(404, "not_found", "no such case")
    if int(row.version) != version:
        raise _refuse(409, "conflict", "The case changed since you looked: nothing was saved."
                      " Read it again.")  # fmt: skip
    return row


async def _marked(conn: AsyncConnection, case_id: uuid.UUID, me: auth.Reviewer) -> m.CaseMarked:
    row = await casepages.row_of(conn, case_id)
    assert row is not None  # the route found the case under its lock
    return m.CaseMarked(case=(await needsyou.decorate(conn, [row], me.user_id))[0])


async def spot_score(conn: AsyncConnection, days: int = SPOT_DAYS) -> m.SpotScoreOut:
    """The team's spot-checks over the last ``days`` days: items answered, items called wrong."""
    row = (
        await conn.execute(
            text(
                "SELECT count(DISTINCT (kind, target_id)) AS checked,"
                " count(DISTINCT (kind, target_id)) FILTER (WHERE answer = 'wrong') AS wrong"
                " FROM spot_checks WHERE answered_at > now() - make_interval(days => :d)"
            ),
            {"d": days},
        )
    ).one()
    return m.SpotScoreOut(days=days, checked=int(row.checked), wrong=int(row.wrong))


async def _spot_target(
    conn: AsyncConnection, target: uuid.UUID, kind: m.SpotKind | None
) -> tuple[m.SpotKind, str | None]:
    """What the spot-checked id is and how ARGUS dealt with it without a person, in its words.
    Only that is spot-checked (409 otherwise, so a "wrong" never counts against ARGUS for a
    person's decision): an alert group ARGUS itself joined to an incident that already existed,
    or one in no incident whose decision accepted ARGUS's own closing proposal; an incident
    ARGUS closed itself (the event that closed it is not a person's)."""
    if kind in (None, "alert_group"):
        group = (await conn.execute(_SPOT_GROUP, {"i": target})).first()
        if group is not None:
            if group.joined is not None:
                return "alert_group", f"Joined to incident #{group.joined}"
            if not group.in_case and group.proposed in CLOSING:
                return "alert_group", OUTCOME_LABELS[group.proposed]
            raise _refuse(409, "conflict", "Only what ARGUS closed or joined on its own is"
                          " spot-checked, and this alert group is not.")  # fmt: skip
    if kind in (None, "incident"):
        case = (await conn.execute(_SPOT_CASE, {"c": target})).first()
        if case is not None:
            if case.state != "closed":
                raise _refuse(409, "conflict", "Only something ARGUS closed is spot-checked; this"
                              f" incident is {case.state}.")  # fmt: skip
            if case.by_person is not False:
                raise _refuse(409, "conflict", "Only what ARGUS closed on its own is"
                              " spot-checked; a person closed this incident.")  # fmt: skip
            reason = case.closure_reason
            label = casepages.REASON_WORDS.get(reason, (str(reason).replace("_", " "), ""))[0]
            return "incident", label
    raise _refuse(404, "not_found", "no such incident or alert group")


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    """Add the queue-work routes to ``router`` (``errors`` writes a route's documented
    answers)."""
    change = errors(400, 401, 403, 404, 409, 422)

    async def service_for(request: Request, conn: AsyncConnection) -> CaseService:
        return await CaseService.start(conn, request.app.state.quiet_windows_for(conn))

    # ------------------------------------------------------------------ A1: I'm checking

    @router.post("/cases/{case_id}/hold", tags=["cases"], operation_id="holdCase",
                 responses=change)  # fmt: skip
    async def hold_case(case_id: CaseId, body: m.HoldIn, me: Manager, conn: Conn) -> m.CaseMarked:
        """I'm checking: you are finding out about a possible incident (what you wait on, and
        when it comes back, at most 14 days ahead). It leaves everyone else's Needs you and is in
        your Mine until then, until you stop, until it is decided, or until ARGUS sees a material
        change or it reaches P1. Holding it again replaces your hold; 409 while someone else
        holds it. It changes nothing about the case (its version stays)."""
        now = await _now(conn)
        if body.until <= now or body.until > now + HOLD_LONGEST:
            raise _refuse(422, "invalid", "Pick a time to come back between now and two weeks"
                          " from now.")  # fmt: skip
        case = await _locked_case(conn, case_id, body.expected_version)
        if case.state != "suspected":
            raise _refuse(409, "conflict", "Only a possible incident (a suspected case) is"
                          f" checked before it is decided; this one is {case.state}.")  # fmt: skip
        await needsyou.tidy_holds(conn, case_id)
        held = (
            await conn.execute(
                text(
                    "SELECT h.id, h.user_id, h.until, coalesce(nullif(u.display_name, ''),"
                    " u.username) AS name FROM case_holds h JOIN users u ON u.id = h.user_id"
                    " WHERE h.case_id = :c AND h.ended_at IS NULL"
                ),
                {"c": case_id},
            )
        ).first()
        if held is not None and int(held.user_id) != me.user_id:
            raise _refuse(409, "conflict", f"{held.name} is checking this already (back"
                          f" {ist_day(held.until)}). Decide it anyway, or leave it to"
                          " them.")  # fmt: skip
        if held is not None:
            await conn.execute(
                text(
                    "UPDATE case_holds SET ended_at = now(), ended_why = 'replaced' WHERE id = :i"
                ),
                {"i": held.id},
            )
        await conn.execute(
            text(
                "INSERT INTO case_holds (case_id, user_id, reason, until, case_version)"
                " VALUES (:c, :u, :r, :t, :v)"
            ),
            {"c": case_id, "u": me.user_id, "r": body.reason.strip(), "t": body.until,
             "v": int(case.version)},
        )  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.hold",
                         target_type="case", target_id=str(case_id),
                         details={"number": int(case.number), "until": body.until.isoformat(),
                                  "replaced": held is not None, "via": "web"})  # fmt: skip
        return await _marked(conn, case_id, me)

    @router.delete("/cases/{case_id}/hold", tags=["cases"], operation_id="releaseHold",
                   responses=errors(401, 403, 404, 422))  # fmt: skip
    async def release_hold(case_id: CaseId, me: Manager, conn: Conn) -> m.CaseMarked:
        """Stop checking: your hold ends and the possible incident is back in everyone's Needs
        you. 404 when you are not checking it."""
        found = (
            await conn.execute(
                text("SELECT number FROM cases WHERE id = :c FOR UPDATE"), {"c": case_id}
            )
        ).first()
        if found is None:
            raise _refuse(404, "not_found", "no such case")
        ended = (
            await conn.execute(
                text(
                    "UPDATE case_holds SET ended_at = now(), ended_why = 'released'"
                    " WHERE case_id = :c AND user_id = :u AND ended_at IS NULL RETURNING id"
                ),
                {"c": case_id, "u": me.user_id},
            )
        ).first()
        if ended is None:
            raise _refuse(404, "not_found", "You are not checking this case.")
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.hold_released",
                         target_type="case", target_id=str(case_id),
                         details={"number": int(found.number), "via": "web"})  # fmt: skip
        return await _marked(conn, case_id, me)

    # ------------------------------------------------------------------ A2: mark as seen

    @router.post("/cases/{case_id}/seen", tags=["cases"], operation_id="markCaseSeen",
                 responses=change)  # fmt: skip
    async def mark_seen(case_id: CaseId, body: m.SeenIn, me: Looker, conn: Conn) -> m.SeenDone:
        """Mark as seen: what changed up to the engine's ``engine_version`` is not new to you
        any more (your "New since you last looked" empties; other people's stays). A look never
        goes back: an older version than the one you saw keeps the newer."""
        version = await conn.scalar(text("SELECT version FROM cases WHERE id = :c"), {"c": case_id})
        if version is None:
            raise _refuse(404, "not_found", "no such case")
        row = (
            await conn.execute(
                text(
                    "INSERT INTO case_seen (case_id, user_id, engine_version, case_version,"
                    " seen_at) VALUES (:c, :u, :e, :v, now()) ON CONFLICT (case_id, user_id)"
                    " DO UPDATE SET engine_version = CASE WHEN EXCLUDED.engine_version IS NULL"
                    " THEN case_seen.engine_version ELSE greatest(case_seen.engine_version,"
                    " EXCLUDED.engine_version) END, case_version ="
                    " greatest(case_seen.case_version, EXCLUDED.case_version), seen_at = now()"
                    " RETURNING engine_version, case_version, seen_at"
                ),
                {"c": case_id, "u": me.user_id, "e": body.engine_version, "v": int(version)},
            )
        ).one()
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.seen",
                         target_type="case", target_id=str(case_id),
                         details={"engine_version": row.engine_version,
                                  "case_version": int(row.case_version)})  # fmt: skip
        return m.SeenDone(
            case_id=case_id,
            seen=cm.SeenOut(engine_version=row.engine_version, case_version=int(row.case_version),
                            at=row.seen_at),
        )  # fmt: skip

    # ------------------------------------------------------------------ A3: spot-check

    @router.post("/today/audit/{target_id}", tags=["today"], operation_id="answerSpotCheck",
                 responses=change)  # fmt: skip
    async def answer_spot_check(
        target_id: TargetId, body: m.SpotCheckIn, me: Reviewer, conn: Conn
    ) -> m.SpotCheckDone:
        """Your answer to a spot-check of something ARGUS closed on its own: it looks right, it
        is wrong (it should have been raised), or you cannot tell. Only what ARGUS decided
        without a person is accepted (409 otherwise): an alert group it joined to an incident
        that already existed or closed on its own proposal, an incident it closed itself. One
        answer per person and item: answering again replaces yours. "Wrong" reopens nothing by
        itself: reopen it with ``reopenCase``. The answer comes back with the team's score."""
        kind, closed_as = await _spot_target(conn, target_id, body.kind)
        row = (
            await conn.execute(
                text(
                    "INSERT INTO spot_checks (kind, target_id, user_id, answer, closed_as)"
                    " VALUES (:k, :t, :u, :a, :c) ON CONFLICT (kind, target_id, user_id)"
                    " DO UPDATE SET answer = EXCLUDED.answer, closed_as = EXCLUDED.closed_as,"
                    " answered_at = now() RETURNING answered_at"
                ),
                {"k": kind, "t": target_id, "u": me.user_id, "a": body.answer, "c": closed_as},
            )
        ).one()
        await auth.audit(conn, actor=f"user:{me.user_id}", action="spot_check.answer",
                         target_type="case" if kind == "incident" else "investigation",
                         target_id=str(target_id),
                         details={"answer": body.answer, "kind": kind})  # fmt: skip
        return m.SpotCheckDone(
            id=target_id, kind=kind, answer=body.answer, closed_as=closed_as, by=_who(me),
            at=row.answered_at, score=await spot_score(conn),
        )  # fmt: skip

    # ------------------------------------------------------------------ A4: I'm caught up

    @router.post("/today/caught-up", tags=["today"], operation_id="markCaughtUp",
                 responses=errors(400, 401, 403, 422))  # fmt: skip
    async def caught_up(me: Looker, conn: Conn) -> m.CaughtUpOut:
        """I'm caught up: your "since" is now. Today counts what ARGUS handled from here, and
        "While you were away" starts again."""
        since = (
            await conn.execute(
                text(
                    "INSERT INTO user_rounds (user_id, caught_up_at) VALUES (:u, now())"
                    " ON CONFLICT (user_id) DO UPDATE SET caught_up_at = now()"
                    " RETURNING caught_up_at"
                ),
                {"u": me.user_id},
            )
        ).scalar_one()
        await auth.audit(conn, actor=f"user:{me.user_id}", action="today.caught_up",
                         target_type="user", target_id=str(me.user_id), details={})  # fmt: skip
        return m.CaughtUpOut(since=since)

    # ------------------------------------------------------------------ A9: bulk dismiss

    @router.post("/cases/bulk-dismiss", tags=["cases"], operation_id="bulkDismissCases",
                 responses=change)  # fmt: skip
    async def bulk_dismiss(
        body: m.BulkDismissIn, request: Request, me: Manager, conn: Conn
    ) -> m.BulkDismissed:
        """Not an incident, for up to 25 possible incidents at once, for one reason: each closed
        as ``dismissCase`` closes it (the same command, at the version you looked at, audited as
        yours). All or nothing: when one is refused (it moved, it is not a possible incident any
        more, your access), none is closed, and the answer names it. There is no bulk
        confirm."""
        ids = [i.id for i in body.items]
        if len(set(ids)) != len(ids):
            raise _refuse(422, "invalid", "A case is listed twice.")
        if body.reason == "duplicate":
            raise _refuse(422, "invalid", "A duplicate names the case it duplicates: merge it"
                          " instead, one at a time.")  # fmt: skip
        numbers = {
            r.id: int(r.number)
            for r in await conn.execute(
                text("SELECT id, number FROM cases WHERE id = ANY(CAST(:ids AS uuid[]))"),
                {"ids": ids},
            )
        }
        if len(numbers) != len(ids):
            raise _refuse(404, "not_found", "Nothing was closed: one of these cases does not"
                          " exist.")  # fmt: skip
        service = await service_for(request, conn)
        actor = casepages.actor_of(me)
        for item in body.items:
            try:
                await service.apply(actor, item.id, Dismiss(body.reason, body.note),
                                    expected_version=item.expected_version)  # fmt: skip
            except CaseRefused as exc:
                said = case_refusal(exc, "dismiss")
                raise _refuse(said.status, said.code, f"Nothing was closed. Case"
                              f" {numbers[item.id]}: {said.detail}") from None  # fmt: skip
        rows = []
        for item in body.items:
            row = await casepages.row_of(conn, item.id)
            assert row is not None
            rows.append(row)
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.bulk_dismiss",
                         target_type="case", target_id=str(ids[0]),
                         details={"reason": body.reason, "cases": [numbers[i] for i in ids],
                                  "via": "web"})  # fmt: skip
        return m.BulkDismissed(closed=await needsyou.decorate(conn, rows, me.user_id))

    # ------------------------------------------- bulk review of one incident's alert groups

    @router.post("/cases/{case_id}/members/reviews", tags=["cases"],
                 operation_id="reviewCaseMembers", status_code=201,
                 responses=change)  # fmt: skip
    async def review_members(
        case_id: CaseId, body: m.MemberReviewsIn, me: Reviewer, conn: Conn
    ) -> m.MemberReviewsDone:
        """Mark several of this incident's alert groups at once (up to 100): each a review
        exactly as ``createReview`` records it, at the version and latest review you saw. "Real:
        act on it" only on a confirmed incident: this never opens one. All or nothing: a group
        that moved is 409 and none is saved."""
        ids = [i.investigation_id for i in body.items]
        if len(set(ids)) != len(ids):
            raise _refuse(422, "invalid", "An alert group is listed twice.")
        if body.action == "reviewed" and body.outcome is None:
            raise _refuse(422, "invalid", "Choose an outcome to mark them reviewed.")
        if body.action == "follow_up" and body.outcome is not None:
            raise _refuse(422, "invalid", "Can't tell yet takes no outcome.")
        case = (
            await conn.execute(
                text("SELECT number, state FROM cases WHERE id = :c"), {"c": case_id}
            )
        ).first()
        if case is None:
            raise _refuse(404, "not_found", "no such case")
        if body.outcome == "true_positive" and case.state not in casepages.ACTIVE_STATES:
            raise _refuse(409, "conflict", "Real: act on it is for a confirmed incident. Confirm"
                          f" the incident first; this one is {case.state}.")  # fmt: skip
        members = {
            r.investigation_id
            for r in await conn.execute(
                text(
                    "SELECT investigation_id FROM case_members WHERE case_id = :c"
                    " AND removed_at IS NULL AND investigation_id = ANY(CAST(:ids AS uuid[]))"
                ),
                {"c": case_id, "ids": ids},
            )
        }
        if members != set(ids):
            raise _refuse(422, "invalid", "Some of these alert groups are not in this incident:"
                          " nothing was saved.")  # fmt: skip
        done = []
        for item in body.items:
            try:
                made = await add_review(
                    conn, me, item.investigation_id, action=body.action, outcome=body.outcome,
                    note=body.note, seen_review=item.seen_review, seen_version=item.seen_version,
                )  # fmt: skip
            except NotFoundError:
                raise _refuse(404, "not_found", "An alert group no longer exists: nothing was"
                              " saved.") from None  # fmt: skip
            except ReviewConflictError:
                raise _refuse(
                    409,
                    "conflict",
                    "An alert group got new alerts or a review while"
                    " you were reading: nothing was saved. Read them again.",
                ) from None
            except ValueError as exc:
                raise _refuse(422, "invalid", str(exc)) from None
            done.append(
                m.MemberReviewOut(
                    investigation_id=item.investigation_id,
                    review_id=made.review_id,
                    version=made.version,
                )
            )
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.members_reviewed",
                         target_type="case", target_id=str(case_id),
                         details={"number": int(case.number), "action": body.action,
                                  "outcome": body.outcome, "groups": len(done)})  # fmt: skip
        return m.MemberReviewsDone(reviews=done)

    # ------------------------------------------------------------------ A14: sent to the CISO

    @router.post("/cases/{case_id}/sent", tags=["reports"], operation_id="markReportSent",
                 status_code=201, responses=change)  # fmt: skip
    async def mark_sent(case_id: CaseId, body: m.SentIn, me: Manager, conn: Conn) -> m.SentOut:
        """Mark as sent: you sent this version of the incident report to the CISO's office (by
        e-mail, outside ARGUS). ARGUS sends nothing; it keeps who sent which version, when. Only
        a confirmed incident's report (one confirmed at some point, as the incident reports list
        has it), and a version ARGUS wrote."""
        case = (
            await conn.execute(
                text("SELECT number, state, opened_at FROM cases WHERE id = :c"), {"c": case_id}
            )
        ).first()
        if case is None:
            raise _refuse(404, "not_found", "no such case")
        if case.state == "suspected":
            raise _refuse(409, "conflict", "A possible incident is not reported to the CISO:"
                          " confirm it first.")  # fmt: skip
        if case.opened_at is None:
            raise _refuse(409, "conflict", "This possible incident was dismissed and never"
                          " confirmed, so it is not reported to the CISO.")  # fmt: skip
        exists = await conn.scalar(
            text("SELECT 1 FROM incident_reports WHERE case_id = :c AND version = :v"),
            {"c": case_id, "v": body.report_version},
        )
        if exists is None:
            raise _refuse(404, "not_found", f"This incident has no report version"
                          f" {body.report_version}.")  # fmt: skip
        await conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                           {"k": f"report-sent:{case_id}:{me.user_id}"})  # fmt: skip
        again = await conn.scalar(  # a double click is one record
            text(
                "SELECT sent_at FROM report_sends WHERE case_id = :c AND by_user_id = :u"
                " AND report_version = :v AND sent_to = :t"
                " AND sent_at > now() - make_interval(secs => :w) ORDER BY id DESC LIMIT 1"
            ),
            {"c": case_id, "u": me.user_id, "v": body.report_version, "t": body.to,
             "w": DUPLICATE_SECONDS},
        )  # fmt: skip
        if again is not None:
            return m.SentOut(to=body.to, report_version=body.report_version, at=again,
                             by=_who(me))  # fmt: skip
        at = (
            await conn.execute(
                text(
                    "INSERT INTO report_sends (case_id, report_version, sent_to, by_user_id)"
                    " VALUES (:c, :v, :t, :u) RETURNING sent_at"
                ),
                {"c": case_id, "v": body.report_version, "t": body.to, "u": me.user_id},
            )
        ).scalar_one()
        await auth.audit(conn, actor=f"user:{me.user_id}", action="case.report_sent",
                         target_type="case", target_id=str(case_id),
                         details={"number": int(case.number), "to": body.to,
                                  "report_version": body.report_version})  # fmt: skip
        return m.SentOut(to=body.to, report_version=body.report_version, at=at, by=_who(me))

    # ------------------------------------------------------------------ A16: a step ticked

    @router.post("/cases/{case_id}/actions/{action_id}/done", tags=["cases"],
                 operation_id="markActionDone", responses=change)  # fmt: skip
    async def mark_action_done(
        case_id: CaseId, action_id: ActionId, body: m.ActionDoneIn, me: Manager, conn: Conn
    ) -> m.ActionDoneOut:
        """A next step was done: your words (what, by whom). The same record as ``argus case
        actions --done``: ARGUS checks it later against the logs where it can (verified, or not
        verified); it executes nothing. Only a step advised for a confirmed incident."""
        now = clock()
        try:
            await responder.report_done(conn, case_id, action_id, casepages.actor_of(me),
                                        body.attestation, now)  # fmt: skip
        except ActionRefused as exc:
            status, code = _ACTION_STATUS.get(exc.code, (409, "conflict"))
            raise _refuse(status, code, casepages.sentence(str(exc))) from None
        except ValueError as exc:
            raise _refuse(422, "invalid", casepages.sentence(str(exc))) from None
        return m.ActionDoneOut(case_id=case_id, action_id=action_id, state="reported_done",
                               by=_who(me), at=now)  # fmt: skip

    # ------------------------------------------------------------------ A8: undo my dismissal

    @router.post("/cases/{case_id}/undo-dismissal", tags=["cases"],
                 operation_id="undoDismissal", responses=change)  # fmt: skip
    async def undo_dismissal(
        case_id: CaseId, body: m.UndoDismissIn, request: Request, me: Manager, conn: Conn
    ) -> cm.CaseChanged:
        """Undo your own "Not an incident", right after it: within 15 minutes, while nothing
        else happened to the case. It is reopened as a possible incident (the dismissal's
        two-week memory ends with it), as ``reopenCase`` would, without the reopen capability.
        Anyone else's dismissal, or an older one, needs ``reopenCase``."""
        if await decisions.undo_until(conn, case_id, me.user_id) is None:
            exists = await conn.scalar(text("SELECT 1 FROM cases WHERE id = :c"), {"c": case_id})
            if exists is None:
                raise _refuse(404, "not_found", "no such case")
            raise _refuse(409, "conflict", "Only your own dismissal can be undone, within 15"
                          " minutes and before anything else happens to the case. A person with"
                          " reopen access can reopen it.")  # fmt: skip
        actor = casepages.actor_of(me)  # their own dismissal: the reopen is theirs to give
        allowed = replace(actor, capabilities=actor.capabilities | {"reopen"}, via="web-undo")
        service = await service_for(request, conn)
        try:
            await service.apply(allowed, case_id, Reopen(f"Undone by {_who(me)} right after"
                                                         " closing it"),
                                expected_version=body.expected_version)  # fmt: skip
        except CaseRefused as exc:
            raise case_refusal(exc, "reopen") from None
        row = await casepages.row_of(conn, case_id)
        assert row is not None
        return cm.CaseChanged(case=row, result="done", request_id=None)
