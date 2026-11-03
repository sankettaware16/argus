"""A person's approval of a case's first sequence, the canary.

The first ``case_team.canary`` cases need a person to approve *that case* before anything is
written to Kibana. The approval binds the plan's hash (every step's author and exact request), so a
new report version, alert or text is a new plan and needs a new approval. It reuses the closures'
approval key (:mod:`argus.cases.signing`): ``argus-web`` signs, ``argus-writer`` verifies before the
first request. The approver has a live web session with ``approve`` and a step-up within five
minutes; the approval expires with its write window (72 hours at most). Its table is its own,
append-only."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.approvals import expires_at as window_end
from argus.cases.signing import Signer, Verifier, iso
from argus.caseteam import store

PURPOSE = "case-team-first-sequence"


def statement_of(
    *,
    case_id: uuid.UUID | str,
    gen: int,
    plan_hash: str,
    report_version: int,
    approver_user_id: int,
    approved_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """What a signature covers: the case, the generation, the plan's hash, the report version,
    the person and the times (UTC, microseconds, as PostgreSQL keeps them)."""
    return {
        "purpose": PURPOSE,
        "case_id": str(case_id),
        "gen": gen,
        "plan_hash": plan_hash,
        "report_version": report_version,
        "approver_user_id": approver_user_id,
        "approved_at": iso(approved_at),
        "expires_at": iso(expires_at),
    }


async def record(
    conn: AsyncConnection,
    signer: Signer,
    *,
    case_id: uuid.UUID,
    gen: int,
    plan_hash: str,
    report_version: int,
    approver_user_id: int,
    now: datetime,
) -> int:
    """The web signs and stores an approval. ``approved_at`` is the database's own clock, read
    here so the statement names exactly the time the row holds."""
    approved_at = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
    expires = window_end(now)
    signed = statement_of(
        case_id=case_id,
        gen=gen,
        plan_hash=plan_hash,
        report_version=report_version,
        approver_user_id=approver_user_id,
        approved_at=approved_at,
        expires_at=expires,
    )
    return await store.add_approval(
        conn,
        case_id=case_id,
        gen=gen,
        plan_hash=plan_hash,
        report_version=report_version,
        approver_user_id=approver_user_id,
        statement=signed,
        signature=signer.sign(signed),
        approved_at=approved_at,
        expires_at=expires,
    )


async def problem(
    conn: AsyncConnection,
    verifier: Verifier | None,
    case_id: uuid.UUID,
    plan_hash: str,
    now: datetime,
) -> str | None:
    """Why no approval stands for this plan now, or None when one does."""
    if verifier is None:
        return "no approval key is configured: signatures cannot be checked"
    found = await store.approvals_for(conn, case_id, plan_hash)
    if not found:
        return "no person has approved this plan yet"
    why = "no approval is valid"
    for row in found:
        if now > row.expires_at:
            why = "the approval expired: ask again"
            continue
        stored = dict(row.statement)
        if not verifier.verify(stored, row.signature):
            why = f"tampered: approval {row.id} has no valid signature"
            continue
        same = (
            stored.get("purpose") == PURPOSE
            and stored.get("case_id") == str(row.case_id)
            and stored.get("gen") == row.gen
            and stored.get("plan_hash") == row.plan_hash
            and stored.get("report_version") == row.report_version
            and stored.get("approver_user_id") == row.approver_user_id
            and stored.get("approved_at") == iso(row.approved_at)
            and stored.get("expires_at") == iso(row.expires_at)
        )
        if not same:
            why = f"tampered: approval {row.id} does not match what was signed"
            continue
        who = (
            await conn.execute(
                text("SELECT disabled, frozen_at FROM users WHERE id = :u"),
                {"u": row.approver_user_id},
            )
        ).first()
        if who is None or who.disabled or who.frozen_at is not None:
            why = "the person who approved it is no longer an active account"
            continue
        return None
    return why
