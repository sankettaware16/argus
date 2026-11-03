"""The approval desk: what ``argus-web`` does when a person approves or rejects.

A decision (1) checks the person live (a denied check is recorded and voids their earlier
approvals), (2) builds the statement with the session's step-up and that check, (3) signs it and
(4) records it through ``argus_approval_decide()``, which checks everything again. A decision that
completes a closure closes the case in the same transaction when the connection may, else ARGUS
applies it. A group's sample is approved item by item first (``decide``), then the rest."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import approvals, identity
from argus.cases.approvals import ApprovalError
from argus.cases.identity import IdentityProvider, LiveCheck
from argus.cases.model import Actor
from argus.cases.service import Applied, CaseService, QuietWindows, no_quiet_window
from argus.cases.signing import Signer


@dataclass(frozen=True)
class SessionProof:
    """The approver's web session: the raw token (the cookie; the database hashes it), whose it
    is, and when its person last confirmed their password (``/stepup``)."""

    token: str
    user_id: int
    stepped_up_at: datetime | None


@dataclass(frozen=True)
class Decided:
    status: approvals.Status
    applied: tuple[Applied, ...] = ()
    check: LiveCheck | None = None


class Refused(ApprovalError):  # noqa: N818 - a refusal, not an error
    """The identity check refused the person: recorded (their approvals are void); the caller
    commits that record and answers ``status``."""


async def live_check(
    conn: AsyncConnection,
    provider: IdentityProvider,
    user_id: int,
    purpose: identity.Purpose = "approval",
) -> LiveCheck:
    """The web's live check of a person who asks for a closure or merge, or decides one: a
    denied check is recorded (it voids their earlier approvals) and raised as :class:`Refused`
    for the caller to commit; one that could not be made, or a service account's, is refused
    without a record."""
    check = await provider.check(conn, user_id, purpose=purpose)
    if check.outcome == "denied":
        await identity.record(conn, check, purpose)
        raise Refused(403, "your account was refused by the identity check: sign in again")
    if check.outcome != "ok":
        raise ApprovalError(503, "the identity check could not be made: try again later")
    if check.kind != "person":
        raise ApprovalError(403, "only a person's own account approves")
    return check


class ApprovalDesk:
    def __init__(
        self,
        conn: AsyncConnection,
        *,
        identity_provider: IdentityProvider,
        signer: Signer,
        apply: bool = True,
        quiet_windows: QuietWindows = no_quiet_window,
    ) -> None:
        self.conn = conn
        self.identity = identity_provider
        self.signer = signer
        self.apply = apply
        self.quiet_windows = quiet_windows  # what proves a case quiet

    async def check(self, user_id: int, purpose: identity.Purpose = "approval") -> LiveCheck:
        """A live check of the person for an approval (or, with ``purpose="request"``, for a
        request, which binds it: :meth:`CaseService.request_closure`); a refused one is
        recorded and raised (the caller commits the record, so the refusal voids their earlier
        approvals)."""
        return await live_check(self.conn, self.identity, user_id, purpose)

    async def decide(
        self,
        session: SessionProof,
        request_id: int,
        decision: approvals.Decision,
        *,
        note: str | None = None,
        batch: dict[str, Any] | None = None,
    ) -> Decided:
        if session.stepped_up_at is None:
            raise ApprovalError(
                403, "confirm your password first (a step-up within 5 minutes)", "step_up_required"
            )
        record = await approvals.record(self.conn, request_id)
        if record is None:
            raise ApprovalError(404, "no such approval request")
        check = await self.check(session.user_id)
        snapshot = check.snapshot()
        statement = approvals.statement(
            record,
            approver_user_id=session.user_id,
            decision=decision,
            stepped_up_at=session.stepped_up_at,
            check=snapshot,
            batch=batch,
        )
        signed = approvals.Signed(session.stepped_up_at, snapshot, self.signer.sign(statement),
                                  batch)  # fmt: skip
        actor = Actor.person(session.user_id, check.capabilities, via="web",
                             kibana=check.kibana, kibana_checked_at=check.checked_at)  # fmt: skip
        service = await CaseService.start(self.conn, self.quiet_windows)
        status, applied = await service.decide(
            actor,
            request_id,
            session_token=session.token,
            decision=decision,
            signed=signed,
            note=note,
            apply=self.apply,
        )
        return Decided(status, tuple(applied), check)

    async def approve_rest(
        self, session: SessionProof, batch: dict[str, Any], *, note: str | None = None
    ) -> list[Decided]:
        """The group's items outside its sample, once the person approved the sample one by
        one (the database refuses them before)."""
        sample = set(batch["sample"])
        return [
            await self.decide(session, rid, "approved", note=note, batch=batch)
            for rid in batch["requests"]
            if rid not in sample
        ]
