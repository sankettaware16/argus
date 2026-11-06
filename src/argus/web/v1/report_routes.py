"""The incident report routes of ``/api/v1`` (AR7, D-190): a case's report, the files made from it,
and a person's Confirm or Reject with a reason.

Reading needs ``view`` (the files: the PDF needs ``see_logs``, because it says what the logs said).
A decision needs ``review`` and the CSRF token, names the version of the report the person read
(409 when ARGUS wrote a newer one) and is one transaction: the decision and the labels it writes
through the existing review path (:func:`argus.incident.review.decide`) are saved together or not at
all. Confirming closes nothing and asks for no approval.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.incident import files, gather, glance, store
from argus.incident import review as incident_review
from argus.incident.view import hide_logs
from argus.web import auth, lookups
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.reviews import OUTCOME_LABELS
from argus.web.v1 import report_models as m
from argus.web.v1.case_routes import CaseId

VIEW = need(Capability.VIEW, Surface.V1)
REVIEW = need(Capability.REVIEW, Surface.V1, csrf=True)
LOGS = need(Capability.SEE_LOGS, Surface.V1)
Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
Reviewer = Annotated[auth.Reviewer, Depends(REVIEW)]
Logs = Annotated[auth.Reviewer, Depends(LOGS)]
_STATUS = {
    "not_found": (404, "not_found"),
    "conflict": (409, "conflict"),
    "invalid": (422, "invalid"),
}
FILES: dict[str, tuple[str, str]] = {
    "report.pdf": ("pdf", "application/pdf"),
    "indicators.csv": ("indicators_csv", "text/csv; charset=utf-8"),
    "affected-devices.csv": ("affected_csv", "text/csv; charset=utf-8"),
    "affected-accounts.csv": ("accounts_csv", "text/csv; charset=utf-8"),
}
LOG_FILES = frozenset({"pdf", "accounts_csv"})  # they say what the logs said
NONE_YET = (
    "ARGUS has not written this case's report yet: it writes one in its next assessment pass "
    "(every few minutes), once the case has alerts."
)


def refusal(exc: incident_review.ReportRefused) -> Refusal:
    status, code = _STATUS[exc.code]
    return Refusal(status, code, exc.message, Surface.V1)


def _decision(d: store.Decision, held_from: int | None = None) -> m.ReportDecisionOut:
    return m.ReportDecisionOut(
        id=d.id,
        decision=d.decision,  # type: ignore[arg-type]
        outcome=d.outcome,  # type: ignore[arg-type]
        reason=d.reason,
        by=d.by_name or "someone",
        decided_at=d.decided_at,
        labelled=len(d.review_ids),
        held_from=held_from,
    )


def _items(items: Any) -> list[m.GlanceItemOut]:
    return [m.GlanceItemOut(label=i.label, value=i.value, note=i.note) for i in items]


def glance_out(g: glance.Glance) -> m.GlanceOut:
    """The Visualiser's glance as the API serves it."""
    return m.GlanceOut(
        alerts=g.alerts, actors=g.actors, actors_more=g.actors_more,
        actors_title=g.shape.actors_title, targets=g.targets, targets_more=g.targets_more,
        targets_title=g.shape.targets_title, targets_word=g.targets_word, listed=g.listed,
        first=g.first, last=g.last, rules=g.rules, rules_more=g.rules_more, bucket=g.bucket,
        days=list(g.days),
        layers=[m.GlanceLayerOut(name=layer.name, values=list(layer.values)) for layer in g.layers],
        top_actors=_items(g.top_actors), top_targets=_items(g.top_targets),
        rule_rows=_items(g.rule_rows), severity=g.severity, call=g.call, activity=g.activity,
        dwell=g.dwell,
    )  # fmt: skip


def report_files(
    case_id: uuid.UUID, can_logs: bool, with_accounts: bool = False
) -> list[m.ReportFileOut]:
    base = f"/api/v1/cases/{case_id}/report/files"
    names = {"pdf": "Incident report (PDF)", "indicators_csv": "Indicators (CSV)",
             "affected_csv": "Affected devices (CSV)",
             "accounts_csv": "Affected accounts (CSV)"}  # fmt: skip
    return [
        m.ReportFileOut(kind=kind, name=names[kind], url=f"{base}/{name}",  # type: ignore[arg-type]
                        available=can_logs or kind not in LOG_FILES)
        for name, (kind, _) in FILES.items()
        if kind != "accounts_csv" or with_accounts
    ]  # fmt: skip


def _actions(
    state: str, chosen: store.Stored | None, newest: int | None, me: auth.Reviewer
) -> tuple[m.ReportActionOut, m.ReportActionOut]:
    """Whether this person may confirm or reject now, and if not, why in plain words."""
    if chosen is None:
        why = "There is no report to decide yet."
        return m.ReportActionOut(enabled=False, why_not=why), m.ReportActionOut(
            enabled=False, why_not=why
        )
    if not me.can(Capability.REVIEW):
        why = "Your account may view reports, not decide them (it needs the review capability)."
        return m.ReportActionOut(enabled=False, why_not=why), m.ReportActionOut(
            enabled=False, why_not=why
        )
    if state == "closed":
        why = "The case is closed: its report is no longer decided."
        return m.ReportActionOut(enabled=False, why_not=why), m.ReportActionOut(
            enabled=False, why_not=why
        )
    if chosen.version != newest:
        why = f"This is version {chosen.version}; decide the newest (version {newest})."
        return m.ReportActionOut(enabled=False, why_not=why), m.ReportActionOut(
            enabled=False, why_not=why
        )
    verdict = chosen.report.verdict
    if verdict.outcome is None or verdict.kind not in ("person", "proposal", "case"):
        confirm = m.ReportActionOut(
            enabled=False,
            why_not="ARGUS has no verdict on this case to confirm (only a reading, or nothing):"
            " reject the report with the outcome you hold instead.",
        )
    else:
        confirm = m.ReportActionOut(enabled=True, why_not=None)
    return confirm, m.ReportActionOut(enabled=True, why_not=None)


async def report_out(
    conn: AsyncConnection, case_id: uuid.UUID, me: auth.Reviewer, version: int | None
) -> m.CaseReportOut | None:
    """The case's report as the API serves it; None when there is no such case or version."""
    case = (
        await conn.execute(text("SELECT number, state FROM cases WHERE id = :c"), {"c": case_id})
    ).first()
    if case is None:
        return None
    newest = await store.latest(conn, case_id)
    chosen = newest if version is None else await store.version(conn, case_id, version)
    if version is not None and chosen is None:
        return None
    listed = await store.versions(conn, case_id)
    note: str | None = None
    stale = False
    check = await store.check_of(conn, case_id)
    if chosen is None:
        note = NONE_YET
        if check is not None and check.failure:
            note = f"ARGUS could not write this case's report yet: {check.failure}"
    else:
        current = (await gather.signals(conn, [case_id])).get(case_id)
        stale = current is not None and (
            check is None or not check.signal.startswith(current.text + "|")
        )
    can_logs = me.can(Capability.SEE_LOGS)
    confirm, reject = _actions(
        case.state, chosen, newest.version if newest is not None else None, me
    )
    holding = None if chosen is None else await store.holding(conn, chosen)
    shown = None if chosen is None else (chosen.report if can_logs else hide_logs(chosen.report))
    return m.CaseReportOut(
        case_id=case_id,
        case_number=int(case.number),
        case_state=case.state,
        version=None if chosen is None else chosen.version,
        newest=None if newest is None else newest.version,
        generated_at=None if chosen is None else chosen.generated_at,
        case_version=None if chosen is None else chosen.case_version,
        prose_by=None if chosen is None else chosen.prose_by,
        stale=stale,
        report=shown,
        decision=None if holding is None else _decision(holding.decision, holding.held_from),
        versions=[
            m.ReportVersionOut(
                version=v.version,
                generated_at=v.generated_at,
                prose=v.prose,
                decision=v.decision,  # type: ignore[arg-type]
                decided_at=v.decided_at,
            )
            for v in listed
        ],
        files=report_files(
            case_id, can_logs, chosen is not None and files.has_accounts(chosen.report)
        ),
        logs_hidden=not can_logs,
        confirm=confirm,
        reject=reject,
        note=note,
        glance=None if shown is None else glance_out(glance.glance_of(shown)),
        sent=(await lookups.sent_of(conn, [case_id])).get(case_id),
    )


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    """Add the report routes to ``router`` (``errors`` writes a route's documented answers)."""
    change = errors(400, 401, 403, 404, 409, 422)

    def refuse(status: int, code: str, detail: str) -> Refusal:
        return Refusal(status, code, detail, Surface.V1)

    @router.get("/cases/{case_id}/report", tags=["cases"], operation_id="getCaseReport",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_case_report(
        case_id: CaseId,
        me: Viewer,
        conn: Conn,
        version: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    ) -> m.CaseReportOut:
        """The incident report ARGUS wrote for the case, the report the security team writes by
        hand: summary, verdict with confidence, timeline, actors, assets, evidence with the exact
        query and a read-only Discover link behind each line, hypotheses, indicators, and the
        recommended actions. The newest version, or ``version``; the versions are kept. What the
        logs said is hidden for an account that may not read them."""
        found = await report_out(conn, case_id, me, version)
        if found is None:
            raise refuse(404, "not_found", "no such case, or no such version of its report")
        return found

    @router.get("/cases/{case_id}/report/files/{name}", tags=["cases"],
                operation_id="getCaseReportFile",
                responses={**errors(401, 403, 404, 422),
                           200: {"content": {"application/pdf": {"schema": {"type": "string",
                                                                           "format": "binary"}},
                                             "text/csv": {"schema": {"type": "string"}}},
                                 "description": "the report's PDF, or one of its CSVs"}},
                )  # fmt: skip
    async def get_case_report_file(
        case_id: CaseId,
        name: Annotated[m.FileName, Path(description="the file: report.pdf or a CSV")],
        me: Viewer,
        conn: Conn,
        version: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    ) -> Response:
        """One file made from the report (the newest version, or ``version``): the PDF (it says
        what the logs said, so it needs ``see_logs``), the indicators CSV and the affected
        devices CSV, in the layout of the hand-made case's files. Cells a spreadsheet could read
        as formulas are neutralised and the CSVs begin with a UTF-8 byte order mark."""
        if FILES[name][0] in LOG_FILES and not me.can(Capability.SEE_LOGS):
            raise refuse(
                403,
                "forbidden",
                "this file says what the logs said (the PDF, the accounts): it needs the"
                " see_logs capability (your ELK account must read the raw logs)",
            )
        got = (
            await store.latest(conn, case_id)
            if version is None
            else (await store.version(conn, case_id, version))
        )
        if got is None:
            raise refuse(404, "not_found", "no such case, or no report for it yet")
        report = got.report
        if name == "report.pdf":
            body: bytes = files.pdf(report)
            filename = files.pdf_name(report)
        elif name == "indicators.csv":
            body, filename = (
                files.indicators_csv(report).encode("utf-8"),
                files.indicators_name(report),
            )
        elif name == "affected-accounts.csv":
            body, filename = files.accounts_csv(report).encode("utf-8"), files.accounts_name(report)
        else:
            body, filename = files.affected_csv(report).encode("utf-8"), files.affected_name(report)
        return Response(
            body, media_type=FILES[name][1],
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )  # fmt: skip

    async def decided(
        conn: AsyncConnection, me: auth.Reviewer, case_id: uuid.UUID, **given: Any
    ) -> m.ReportDecided:
        try:
            done = await incident_review.decide(conn, me, case_id, **given)
        except incident_review.ReportRefused as exc:
            raise refusal(exc) from None
        said = OUTCOME_LABELS.get(done.outcome or "", done.outcome or "")
        words = f"{'Confirmed' if done.decision == 'confirmed' else 'Rejected'}: "
        words += f'{done.labelled} investigation(s) labelled "{said}"'
        words += f", {done.already} already had it" if done.already else ""
        words += f", {done.kept} left as a person had reviewed them" if done.kept else ""
        words += f", {done.left} more than ARGUS labels at once" if done.left else ""
        return m.ReportDecided(
            decision=_decision(done.record), labelled=done.labelled, already=done.already,
            kept=done.kept, conflicts=done.conflicts, gold_saved=done.gold_saved,
            left=done.left, words=words + ". Nothing was closed.",
        )  # fmt: skip

    @router.post("/cases/{case_id}/report/confirm", tags=["cases"],
                 operation_id="confirmCaseReport", responses=change)  # fmt: skip
    async def confirm_case_report(
        case_id: CaseId, body: m.ConfirmReportIn, me: Reviewer, conn: Conn
    ) -> m.ReportDecided:
        """Say the report's verdict is right. It labels the case's investigations with the verdict
        (through the review path: the decision engine learns), never overrides a person's own
        review, and closes nothing: closing a case stays a person's approval."""
        return await decided(conn, me, case_id, expected_version=body.expected_version,
                             decision="confirmed")  # fmt: skip

    @router.post("/cases/{case_id}/report/reject", tags=["cases"],
                 operation_id="rejectCaseReport", responses=change)  # fmt: skip
    async def reject_case_report(
        case_id: CaseId, body: m.RejectReportIn, me: Reviewer, conn: Conn
    ) -> m.ReportDecided:
        """Say the report's verdict is wrong: the outcome you hold instead and why. The reason is
        stored as the note of the review (the label) of each investigation of the case, so the
        engine learns from it and the gold set's own answers are saved where it applies."""
        return await decided(
            conn,
            me,
            case_id,
            expected_version=body.expected_version,
            decision="rejected",
            outcome=body.outcome,
            reason=body.reason,
        )
