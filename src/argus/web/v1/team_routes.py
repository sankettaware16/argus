"""The case team's routes of ``/api/v1`` (AR8, D-195): the Kibana case preview and the canary's
approval.

``GET /cases/{id}/team`` is the dry run: exactly what ARGUS would write to the Kibana case for
this case, step by step, by which of the six users, with each comment's text and each request;
the decision and why (posting off, a person to confirm, the daily cap, the canary); where the
post stands when there is one. It needs ``view``; the texts say what the logs said, so without
``see_logs`` they are hidden. It sends nothing and asks nobody: it reads ARGUS's own database.

``POST /cases/{id}/team/approve`` is the canary: a person with the ``approve`` and ``see_logs``
capabilities (an approver must be able to read every word of what is sent, D-208) and a step-up of
the last five minutes approves exactly the plan they read (its hash; 409 when it changed).
The approval is signed with the closures' approval key and checked again by the writer before the
first request. It sends nothing itself.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.caseteam import approvals, store
from argus.caseteam.model import PART_AUTHOR, Author
from argus.caseteam.sender import PostConfig, Prepared, Preparer
from argus.incident.model import HIDDEN
from argus.web import auth
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.v1 import team_models as m
from argus.web.v1.case_routes import CaseId

VIEW = need(Capability.VIEW, Surface.V1)
APPROVE = need(Capability.APPROVE, Surface.V1, csrf=True)
Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
Approver = Annotated[auth.Reviewer, Depends(APPROVE)]
STEP_UP_VALID = timedelta(minutes=5)  # an approval needs a step-up this recent
AUTHORS: list[m.Author] = [a.value for a in Author]


def _refuse(status: int, code: str, detail: str) -> Refusal:
    return Refusal(status, code, detail, Surface.V1)


def _approval(
    prep: Prepared, me: auth.Reviewer, signer_present: bool, now: datetime
) -> m.TeamApprovalOut:
    required = prep.decision.needs_approval
    given = required and prep.approval is None
    why_not: str | None = None
    if required and not given:
        why_not = prep.approval
    can, can_why, step_up = False, None, False
    if not required:
        can_why = "this case needs no approval now"
    elif given:
        can_why = "this plan is already approved"
    elif prep.plan is None or prep.problems:
        can_why = "something stops this plan from being sent: fix that first"
    elif not me.can(Capability.APPROVE):
        can_why = "your account may not approve (it needs the approve capability)"
    elif not me.can(Capability.SEE_LOGS):
        can_why = (
            "an approver must be able to read every word of what is sent: it needs the"
            " see_logs capability as well"
        )
    elif me.unverified_since is not None:
        can_why = "ARGUS cannot verify your account right now"
    elif not signer_present:
        can_why = "this server has no key to sign approvals with"
    elif me.stepped_up_at is None or now - me.stepped_up_at > STEP_UP_VALID:
        can_why = "confirm your password again first (a step-up within five minutes)"
        step_up = True
    else:
        can = True
    return m.TeamApprovalOut(
        required=required,
        given=given,
        why_not=why_not,
        can_approve=can,
        approve_why_not=can_why,
        needs_step_up=step_up,
        step_up_url=f"/stepup?next=/app/cases/{prep.case_id}" if step_up else None,
    )


async def team_out(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    me: auth.Reviewer,
    preparer: Preparer,
    *,
    signer_present: bool,
    now: datetime,
) -> m.CaseTeamOut | None:
    """The case's preview as the API serves it; None when there is no such case."""
    try:
        prep = await preparer.prepare(conn, case_id)
    except LookupError:
        return None
    can_logs = me.can(Capability.SEE_LOGS)
    steps: list[m.TeamStepOut] = []
    states = {r.key: r.state for r in prep.rows}
    sent = preparer.requests(prep) if (prep.plan is not None and can_logs) else []
    for n, s in enumerate(prep.plan.steps if prep.plan is not None else (), 1):
        request = (
            None
            if not sent
            else m.TeamRequestOut(
                method=sent[n - 1]["method"],
                path=sent[n - 1]["path"],
                content_type=sent[n - 1]["content_type"],
                body=sent[n - 1]["body"],
            )
        )
        steps.append(
            m.TeamStepOut(
                n=n,
                key=s.key,
                kind=s.kind,
                author=s.author.value,
                part=s.part,
                what=s.describe(),
                text=(s.text if can_logs else (HIDDEN if s.text else None)),
                request=request,
                state=states.get(s.key) if prep.in_progress else None,
            )
        )
    d = prep.decision
    post: m.TeamPostOut | None = None
    if prep.post is not None:
        counts: dict[str, int] = {}
        for r in await store.steps_of(conn, case_id):
            counts[r.state] = counts.get(r.state, 0) + 1
        post = m.TeamPostOut(
            incident_id=prep.post.incident_id,
            kibana_case_id=prep.post.kibana_case_id,
            state=cast(Any, prep.post.state),
            held_reason=prep.post.held_reason,
            opened_at=prep.post.opened_at,
            last_version=prep.post.last_version,
            steps=counts,
        )
    notes = list(prep.notes)
    if d.dry_run:
        notes.insert(
            0,
            "Posting is switched off (case_team.post), so nothing is written to Kibana: this is"
            f" what ARGUS would do ({d.would}).",
        )
    note = " ".join(notes) or None
    return m.CaseTeamOut(
        case_id=case_id,
        case_number=prep.number,
        case_state=cast(Any, prep.state),
        post_enabled=preparer.config.post,
        incident_id=None if prep.stored is None else prep.stored.report.header.incident_id,
        report_version=None if prep.stored is None else prep.stored.version,
        decision=m.TeamDecisionOut(
            action=d.action,
            would=d.would,
            why=d.why,
            route=d.route,
            dry_run=d.dry_run,
            needs_approval=d.needs_approval,
        ),
        plan_hash=None if prep.plan is None else prep.plan.plan_hash,
        steps=steps,
        problems=list(prep.problems),
        approval=_approval(prep, me, signer_present, now),
        post=post,
        authors=AUTHORS,
        logs_hidden=not can_logs,
        note=note,
    )


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    change = errors(400, 401, 403, 404, 409, 422)

    def preparer_of(request: Request) -> tuple[Preparer, bool]:
        config: PostConfig = getattr(request.app.state, "team", None) or PostConfig()
        signer = request.app.state.signer
        return Preparer(config, None if signer is None else signer.verifier(), clock), (
            signer is not None
        )

    @router.get(
        "/cases/{case_id}/team",
        tags=["cases"],
        operation_id="getCaseTeam",
        responses=errors(401, 403, 404, 422),
    )
    async def get_case_team(
        request: Request, case_id: CaseId, me: Viewer, conn: Conn
    ) -> m.CaseTeamOut:
        """What ARGUS would write to the case in Kibana, as a dry run: the six users' steps in
        order, each comment in full, each request, the decision and why, and the canary's
        approval. Nothing is sent. What the logs said is hidden for an account that may not read
        them."""
        preparer, has_signer = preparer_of(request)
        found = await team_out(conn, case_id, me, preparer, signer_present=has_signer, now=clock())
        if found is None:
            raise _refuse(404, "not_found", "no such case")
        return found

    @router.post(
        "/cases/{case_id}/team/approve",
        tags=["cases"],
        operation_id="approveCaseTeam",
        responses=change,
    )
    async def approve_case_team(
        request: Request, case_id: CaseId, body: m.ApproveTeamIn, me: Approver, conn: Conn
    ) -> m.TeamApprovedOut:
        """The canary: approve exactly the plan you read (its hash). Needs the approve and the
        see_logs capabilities (every word of the plan must be readable by its approver) and a
        step-up of the last five minutes; the approval is signed and checked again by the writer
        before the first request. Nothing is sent by this call."""
        preparer, _ = preparer_of(request)
        signer = request.app.state.signer
        if not me.can(Capability.SEE_LOGS):
            raise _refuse(
                403,
                "forbidden",
                "An approver must be able to read every word of what is sent, so approving needs"
                " the see_logs capability as well as approve.",
            )
        if signer is None:
            raise _refuse(
                503,
                "unavailable",
                "This server has no key to sign approvals with, so it cannot record one.",
            )
        now = clock()
        if me.unverified_since is not None:
            raise _refuse(403, "forbidden", "ARGUS cannot verify your account right now.")
        if me.stepped_up_at is None or now - me.stepped_up_at > STEP_UP_VALID:
            raise _refuse(
                403,
                "step_up_required",
                "Confirm your password again (within five minutes) before you approve.",
            )
        try:
            prep = await preparer.prepare(conn, case_id)
        except LookupError:
            raise _refuse(404, "not_found", "no such case") from None
        if prep.plan is None or prep.stored is None:
            raise _refuse(409, "not_ready", "ARGUS has no plan for this case yet.")
        if not prep.decision.needs_approval:
            raise _refuse(409, "conflict", "This case needs no approval now.")
        if prep.problems:
            raise _refuse(
                409,
                "not_ready",
                "Something stops this plan from being sent: " + "; ".join(prep.problems[:3]),
            )
        if prep.plan.plan_hash != body.plan_hash:
            raise _refuse(
                409,
                "conflict",
                "The plan changed while you read it. Read it again before you approve.",
            )
        gen = await store.latest_gen(conn, case_id) + 1
        made = await approvals.record(
            conn,
            signer,
            case_id=case_id,
            gen=gen,
            plan_hash=prep.plan.plan_hash,
            report_version=prep.stored.version,
            approver_user_id=me.user_id,
            now=now,
        )
        await auth.audit(
            conn,
            actor=f"user:{me.username}",
            action="case_team.approve",
            target_type="case",
            target_id=str(case_id),
            details={
                "plan_hash": prep.plan.plan_hash,
                "incident": prep.plan.incident_id,
                "report_version": prep.stored.version,
                "approval_id": made,
            },
        )
        from argus.cases.approvals import expires_at

        return m.TeamApprovedOut(
            approval_id=made,
            plan_hash=prep.plan.plan_hash,
            expires_at=expires_at(now),
            words="Approved. ARGUS writes this case to Kibana at its next posting run, inside the"
            " write window; the approval covers exactly the plan you read.",
        )


__all__ = ["PART_AUTHOR", "install", "team_out"]
