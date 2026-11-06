"""CaseService: every change to a case in one transaction.

Each command locks the case, checks the version the caller saw (409 if it moved), lets the pure
machine decide, then writes the case row, members and indicators, exactly one case event, the Kibana
outbox rows planned with it and an audit event naming the actor. The caller's transaction commits or
rolls back all of it. Lock order: the cases (by id), the hash chains, the audit trail last."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from argus.cases import approvals, closure, identity, kibana, machine
from argus.cases.machine import (
    Assign,
    CaseRefused,
    Close,
    Command,
    Confirm,
    Contain,
    Dismiss,
    EventRecord,
    Link,
    MergedIn,
    MergeInto,
    Open,
    ProposeClosure,
    Publish,
    RequestClosure,
    RequestMerge,
    Retitle,
    Step,
    Unlink,
)
from argus.cases.model import (
    NO_QUIET_WINDOW,
    NOTE_LIMIT,
    Actor,
    Capability,
    Case,
    Indicator,
    Member,
    QuietWindow,
    Reason,
    Severity,
)
from argus.db.audit import record_audit

ENTITY_KINDS = ("ip", "domain", "host", "user")
# The lock every writer of case membership takes first (the opener, the suggester, the watch and
# the known pass: see argus.cases.opener.OPENER_LOCK_KEY, the same number), so a person's split
# never moves an investigation while one of them reads the cases to join it.
MEMBERSHIP_LOCK_KEY = int.from_bytes(b"ARGUSOPN", "big")


@dataclass(frozen=True)
class Applied:
    step: Step
    case: Case
    event_id: int
    outbox_ids: tuple[int, ...]


@dataclass(frozen=True)
class Carried:
    """What a split takes with the investigations it moves: ``leaving`` are the actor
    rows only they carried (they leave the source), ``rows`` everything the target gets (those, the
    moved investigations' own actors, and the source's C2 and indicator rows they touch), and
    ``staying`` the actor rows of the moved investigations that stay on the source because an
    investigation that stays involves them too (said to the person, never silent)."""

    leaving: tuple[Indicator, ...] = ()
    rows: tuple[Indicator, ...] = ()
    staying: tuple[Indicator, ...] = ()


# Works out :class:`Carried` for a locked case and the investigations moved out of it (reads the
# investigations: argus.cases.splitting).
Carry = Callable[[Case, Sequence[uuid.UUID]], Awaitable[Carried]]


@dataclass(frozen=True)
class Split:
    """The two halves of a split: the source's ``unlinked`` and the target's ``opened`` (a new case)
    or ``linked`` (an existing one)."""

    source: Applied
    target: Applied
    carried: Carried
    new: bool


class CaseNotFound(CaseRefused):
    def __init__(self, what: str) -> None:
        super().__init__("not_found", f"no such case: {what}")


QuietWindows = Callable[[Case], Awaitable[QuietWindow]]


async def no_quiet_window(case: Case) -> QuietWindow:
    """Without the still-active watch and verified negatives, nothing proves a
    72-hour quiet window."""
    return NO_QUIET_WINDOW


class CaseService:
    """Case commands on one connection, inside the caller's transaction. ``now`` is the
    database's transaction time unless given; closing by an approval reads the database's clock
    again, as the database checks expiries against the clock, not the transaction's start.
    ``quiet_windows`` says whether a case's actors and indicators were verifiably quiet: the
    service asks it itself, never trusting a window a caller hands in."""

    def __init__(
        self, conn: AsyncConnection, now: datetime, quiet_windows: QuietWindows = no_quiet_window
    ) -> None:
        self.conn = conn
        self.now = now
        self.quiet_windows = quiet_windows

    @classmethod
    async def start(
        cls, conn: AsyncConnection, quiet_windows: QuietWindows = no_quiet_window
    ) -> CaseService:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
        return cls(conn, now, quiet_windows)

    async def _clock(self) -> datetime:
        now: datetime = (await self.conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
        return now

    async def get(self, case_id: uuid.UUID, *, lock: bool = False) -> Case | None:
        row = (
            await self.conn.execute(
                text(
                    "SELECT id, number, title, state, severity, version, cause, owner_user_id,"  # noqa: S608 - constant fragments; values are bound
                    " cause_review_id, cause_assessment_id, parent_case_id, opened_at,"
                    " closed_at, closure_reason, closure_request_id, merged_into_id, attention,"
                    " kibana_wait, notified_at, blocked_at, EXISTS (SELECT 1 FROM kibana_outbox o"
                    " WHERE o.case_id = c.id"
                    " AND o.op = 'create' AND NOT (o.state = 'skipped' AND o.sent_count = 0))"
                    " AS mirrored FROM cases c WHERE id = :id"
                    + (" FOR UPDATE OF c" if lock else "")
                ),
                {"id": case_id},
            )
        ).first()
        if row is None:
            return None
        members = (
            await self.conn.execute(
                text(
                    "SELECT investigation_id FROM case_members WHERE case_id = :id"
                    " AND removed_at IS NULL"
                ),
                {"id": case_id},
            )
        ).scalars()
        marks = (
            await self.conn.execute(
                text(
                    "SELECT kind, value, role FROM case_indicators WHERE case_id = :id"
                    " AND removed_at IS NULL"
                ),
                {"id": case_id},
            )
        ).all()
        values = dict(row._mapping)
        return Case(
            **values,
            members=frozenset(members),
            indicators=frozenset(Indicator(k, v, r) for k, v, r in marks),
        )

    async def by_number(self, number: int) -> uuid.UUID | None:
        found: uuid.UUID | None = (
            await self.conn.execute(text("SELECT id FROM cases WHERE number = :n"), {"n": number})
        ).scalar_one_or_none()
        return found

    async def events(self, case_id: uuid.UUID) -> list[EventRecord]:
        rows = await self.conn.execute(
            text(
                "SELECT case_id, case_version, kind, from_state, to_state, details"
                " FROM case_events WHERE case_id = :id ORDER BY case_version"
            ),
            {"id": case_id},
        )
        return [EventRecord(r.case_id, r.case_version, r.kind, r.from_state, r.to_state,
                            r.details) for r in rows]  # fmt: skip

    async def titled_by_person(self, case_id: uuid.UUID) -> bool:
        """Whether a person wrote the case's title: the actor of its newest ``suspected``,
        ``opened`` or ``retitled`` event is a person's. ARGUS refreshes only the titles it wrote."""
        found = (
            await self.conn.execute(
                text(
                    "SELECT actor_user_id IS NOT NULL FROM case_events WHERE case_id = :id"
                    " AND kind IN ('suspected', 'opened', 'retitled')"
                    " ORDER BY case_version DESC LIMIT 1"
                ),
                {"id": case_id},
            )
        ).scalar_one_or_none()
        return bool(found)

    async def posted(self, case_id: uuid.UUID) -> str | None:
        """The IR number the case team posted the case to Kibana under, when it may be there:
        its Kibana case was read back, or a request of its post has left ARGUS. None otherwise."""
        found = (
            await self.conn.execute(
                text(
                    "SELECT p.incident_id FROM case_team_posts p WHERE p.case_id = :c AND"
                    " (p.kibana_case_id IS NOT NULL OR EXISTS (SELECT 1 FROM case_team_steps s"
                    " WHERE s.case_id = p.case_id AND s.state IN ('sending', 'sent', 'verified',"
                    " 'ambiguous', 'resend')))"
                ),
                {"c": case_id},
            )
        ).scalar_one_or_none()
        return None if found is None else str(found)

    async def assignable(self, user_id: int) -> bool:
        row = (
            await self.conn.execute(
                text(
                    "SELECT NOT disabled AND username <> 'argus-assistant' AND kind = 'person'"
                    " FROM users WHERE id = :u"
                ),
                {"u": user_id},
            )
        ).scalar_one_or_none()
        return bool(row)

    async def _session_is(self, actor: Actor, session_token: str) -> None:
        """The web session the database will attribute the request or decision to is the
        actor's own (the audit trail and the approval must name the same person); the database
        checks its idle time again."""
        owner = (
            await self.conn.execute(
                text(
                    "SELECT user_id FROM user_sessions WHERE token_hash = :t AND ended_at IS NULL"
                ),
                {"t": hashlib.sha256(session_token.encode()).hexdigest()},
            )
        ).scalar_one_or_none()
        if owner is None:
            raise approvals.ApprovalError(401, "no live session of a person")
        if owner != actor.user_id:
            raise CaseRefused("forbidden", "the session is not the acting person's")

    @staticmethod
    def _requester(actor: Actor, check: identity.LiveCheck) -> dict[str, Any]:
        """The requester's live check as the request binds it (the database checks it again:
        this person, a person, ok, at most 30 seconds old)."""
        if check.user_id != actor.user_id or not check.good:
            raise CaseRefused("forbidden", "a request needs a good live check of the requester")
        return check.snapshot()

    async def _locked(self, case_id: uuid.UUID, expected_version: int | None) -> Case:
        case = await self.get(case_id, lock=True)
        if case is None:
            raise CaseNotFound(str(case_id))
        if expected_version is not None and case.version != expected_version:
            raise CaseRefused(
                "conflict",
                f"the case changed meanwhile: it is at version {case.version}, you saw"
                f" {expected_version}",
            )
        return case

    async def open(
        self, actor: Actor, command: Open, *, case_id: uuid.UUID | None = None
    ) -> Applied:
        """A new case (version 1) with its first members and indicators."""
        case_id = case_id or uuid.uuid4()
        draft = machine.create(case_id, 0, command, actor, self.now)
        await self._members_free(case_id, draft.members_added)
        number = await self._insert(draft.after)
        span = await self._span(draft.after.members)
        step = machine.create(case_id, number, command, actor, self.now, span)
        return await self._record(actor, step)

    async def apply(
        self, actor: Actor, case_id: uuid.UUID, command: Command, *, expected_version: int | None
    ) -> Applied:
        """One command on one case. ``expected_version`` is the version the person saw (None
        for ARGUS's own moves, made under the lock)."""
        if isinstance(
            command, MergeInto | MergedIn | Close | RequestClosure | ProposeClosure | RequestMerge
        ):
            raise CaseRefused("invalid", "closures and merges go through approvals")
        if isinstance(command, Unlink):
            raise CaseRefused("invalid", "moving investigations out of a case is a split")
        case = await self._locked(case_id, expected_version)
        if (
            isinstance(command, Retitle)
            and not actor.is_person
            and await self.titled_by_person(case_id)
        ):
            raise CaseRefused("conflict", "a person wrote this title: ARGUS leaves it")
        if isinstance(command, Contain):  # the window is the service's to find out
            command = replace(command, window=await self.quiet_windows(case))
        if isinstance(command, Assign):
            command = replace(command, assignable=await self.assignable(command.user_id))
        if isinstance(command, Confirm | Publish):  # Kibana keeps a person's title as written
            command = replace(command, title_by_person=await self.titled_by_person(case_id))
        if isinstance(command, Dismiss):
            command = replace(command, posted=await self.posted(case_id))
        span = await self._span(case.members) if isinstance(command, Confirm | Publish) else None
        step = machine.decide(case, command, actor, self.now, span)
        await self._members_free(case_id, step.members_added)
        await self._update(step)
        applied = await self._record(actor, step)
        if step.kind in ("notified", "blocked"):
            await self._notice(actor, step)
        return applied

    async def split(
        self,
        actor: Actor,
        source_id: uuid.UUID,
        investigations: Sequence[uuid.UUID],
        *,
        reason: str,
        carry: Carry,
        expected_version: int | None,
        title: str | None = None,
        severity: Severity = "medium",
        into_id: uuid.UUID | None = None,
    ) -> Split:
        """A person moves investigations out of a case, in this transaction, into a case they open
        for them (``title``) or an existing one that is not closed (``into_id``): the source's
        ``unlinked`` event, then the target's ``opened`` or ``linked``. The moved investigations are
        never in no case, so nothing joins them back. Under the membership lock, then the cases
        (the source and the target, in id order); ``expected_version`` is the source's."""
        if not actor.may(Capability.MANAGE):
            raise CaseRefused("forbidden", "moving investigations needs the manage_cases right")
        if (title is None) == (into_id is None):
            raise CaseRefused("invalid", "a split goes to a new case (a title) or to an existing"
                              " one (--into), not both and not neither")  # fmt: skip
        if into_id == source_id:
            raise CaseRefused("invalid", "investigations cannot be moved to the case they are in")
        await self.conn.execute(
            text("SELECT pg_advisory_xact_lock(:k)"), {"k": MEMBERSHIP_LOCK_KEY}
        )
        held: dict[uuid.UUID, Case] = {}
        for case_id in sorted({source_id, *([] if into_id is None else [into_id])}):
            held[case_id] = await self._locked(case_id, None)
        source = held[source_id]
        if expected_version is not None and source.version != expected_version:
            raise CaseRefused(
                "conflict",
                f"the case changed meanwhile: it is at version {source.version}, you saw"
                f" {expected_version}",
            )
        moving = tuple(investigations)
        carried = await carry(source, moving)
        target_id = into_id or uuid.uuid4()
        out = machine.decide(
            source, Unlink(moving, reason, target_id, carried.leaving), actor, self.now
        )
        await self._update(out)
        left = await self._record(actor, out)
        members = tuple(Member(i, "person", f"case:{source.number}") for i in sorted(moving))
        rows = tuple(Indicator(i.kind, i.value, i.role, "person") for i in carried.rows)
        if into_id is None:
            assert title is not None
            joined = await self.open(
                actor, Open(title, severity, "person", members, rows, split_from=source_id),
                case_id=target_id,
            )  # fmt: skip
        else:
            into = machine.decide(held[into_id], Link(members, rows, None, source_id), actor,
                                  self.now)  # fmt: skip
            await self._members_free(into_id, into.members_added)
            await self._update(into)
            joined = await self._record(actor, into)
        return Split(left, joined, carried, into_id is None)

    async def _notice(self, actor: Actor, step: Step) -> None:
        """The record of a person's notice or block (the case event above is the audit trail's
        copy; this row is what the pages, the block list and the reports read)."""
        if actor.user_id is None:  # the machine refuses ARGUS as the actor; the table says it too
            raise CaseRefused("forbidden", "a notice or a block is a person's record")
        details = step.details
        owner = step.kind == "notified"
        await self.conn.execute(
            text(
                "INSERT INTO case_notices (case_id, case_version, kind, at, told, how, managed,"
                " note, by_user_id) VALUES (:c, :v, :k, CAST(:at AS timestamptz), :told, :how,"
                " :managed, :note, :u)"
            ),
            {
                "c": step.after.id,
                "v": step.after.version,
                "k": "owner" if owner else "block",
                "at": details["at"],
                "told": details["told"] if owner else details["by"],
                "how": details["how"] if owner else details["where"],
                "managed": bool(details.get("managed")) if owner else None,
                "note": details.get("note"),
                "u": actor.user_id,
            },
        )

    async def dismiss_reminder(self, actor: Actor, case_id: uuid.UUID, kind: str) -> bool:
        """A person says a reminder is not needed (audited as theirs); False when there is none
        to dismiss. The reminder comes back only as a new kind of case."""
        if not actor.may(Capability.MANAGE) or actor.user_id is None:
            raise CaseRefused("forbidden", "dismissing a reminder is a person's action")
        done = await self.conn.execute(
            text(
                "UPDATE case_reminders SET dismissed_at = now(), dismissed_by = :u"
                " WHERE case_id = :c AND kind = :k AND dismissed_at IS NULL"
            ),
            {"c": case_id, "k": kind, "u": actor.user_id},
        )
        if not done.rowcount:
            return False
        await self._audit(actor, "case.reminder_dismissed", str(case_id), {"kind": kind})
        return True

    async def _members_free(self, case_id: uuid.UUID, members: Sequence[Member]) -> None:
        """An investigation is in one case at a time (a closed one included)."""
        if not members:
            return
        held = (
            await self.conn.execute(
                text(
                    "SELECT m.investigation_id, c.number FROM case_members m"
                    " JOIN cases c ON c.id = m.case_id WHERE m.investigation_id = ANY(:ids)"
                    " AND m.removed_at IS NULL AND m.case_id <> :c ORDER BY 2 LIMIT 1"
                ),
                {"ids": [m.investigation_id for m in members], "c": case_id},
            )
        ).first()
        if held is not None:
            raise CaseRefused(
                "conflict", f"investigation {held.investigation_id} is in case {held.number}"
            )

    async def _span(self, members: frozenset[uuid.UUID]) -> kibana.AlertSpan:
        """When the members' alerts were first and last seen."""
        row = (
            await self.conn.execute(
                text(
                    "SELECT min(first_event_at), max(last_event_at) FROM investigations"
                    " WHERE id = ANY(:ids)"
                ),
                {"ids": list(members)},
            )
        ).one()
        return kibana.AlertSpan(row[0], row[1])

    async def request_closure(
        self,
        actor: Actor,
        case_id: uuid.UUID,
        *,
        expected_version: int | None,
        reason: Reason,
        session_token: str,
        check: identity.LiveCheck,
        note: str | None = None,
        window: QuietWindow | None = None,
    ) -> tuple[Applied, int]:
        """A person asks to close the case: the request event, then the approval request bound
        to the new version, its alerts, the exact Kibana writes the closure will plan and the
        requester's live check (``check``, from :meth:`argus.cases.desk.ApprovalDesk.check`)."""
        await self._session_is(actor, session_token)
        requester = self._requester(actor, check)
        case = await self._locked(case_id, expected_version)
        step, built = await self._closure_plan(actor, case, reason, note, window)
        await self._update(step)
        applied = await self._record(actor, step)
        request_id = await approvals.request(
            self.conn,
            session_token=session_token,
            case_id=case_id,
            case_version=step.after.version,
            kind="closure",
            reason=reason,
            payload=built.payload,
            payload_hash=built.payload_hash,
            expires=approvals.expires_at(self.now),
            check=requester,
            kibana_version=await self._kibana_version(case_id),
            note=step.details.get("note"),
        )
        return applied, request_id

    async def _closure_plan(
        self,
        actor: Actor,
        case: Case,
        reason: Reason,
        note: str | None,
        window: QuietWindow | None,
    ) -> tuple[Step, closure.ClosurePayload]:
        """The request event a person's closure request makes and the exact writes the closure
        will plan after it: the one place both are worked out, for the request itself and for the
        preview a person reads before asking (:meth:`preview_closure`)."""
        if window is not None or reason in ("remediated_verified", "attempt_no_impact"):
            window = await self.quiet_windows(case)  # never the caller's
        step = machine.decide(case, RequestClosure(reason, note, window), actor, self.now)
        return step, closure.build(step.after, reason, self.now)

    async def preview_closure(
        self,
        actor: Actor,
        case_id: uuid.UUID,
        reason: Reason,
        *,
        expected_version: int | None,
        note: str | None = None,
    ) -> closure.ClosurePayload:
        """What asking to close the case for ``reason`` would bind: the payload and its hash,
        exactly as :meth:`request_closure` will store them (nothing is written)."""
        case = await self._locked_read(case_id, expected_version)
        return (await self._closure_plan(actor, case, reason, note, None))[1]

    async def preview_merge(
        self,
        actor: Actor,
        case_id: uuid.UUID,
        target_id: uuid.UUID,
        *,
        expected_version: int | None,
        note: str | None = None,
    ) -> closure.ClosurePayload:
        """What asking to merge the case into ``target_id`` would bind, as :meth:`request_merge`
        stores it (nothing is written)."""
        case = await self._locked_read(case_id, expected_version)
        target = await self.get(target_id)
        if target is None:
            raise CaseNotFound(str(target_id))
        return self._merge_plan(actor, case, target, note)[1]

    def _merge_plan(
        self, actor: Actor, case: Case, target: Case, note: str | None
    ) -> tuple[Step, closure.ClosurePayload]:
        step = machine.decide(case, RequestMerge(target.id, target.state, note), actor, self.now)
        return step, closure.build(step.after, "duplicate", self.now, target=target.id)

    async def _locked_read(self, case_id: uuid.UUID, expected_version: int | None) -> Case:
        """The case without its lock (a preview writes nothing), at the version the caller saw."""
        case = await self.get(case_id)
        if case is None:
            raise CaseNotFound(str(case_id))
        if expected_version is not None and case.version != expected_version:
            raise CaseRefused(
                "conflict",
                f"the case changed meanwhile: it is at version {case.version}, you saw"
                f" {expected_version}",
            )
        return case

    async def propose_closure(
        self,
        actor: Actor,
        case_id: uuid.UUID,
        *,
        reason: Reason,
        evidence: str | None = None,
        expected_version: int | None = None,
    ) -> tuple[Applied, int]:
        """ARGUS proposes closing the case: its request event, then the request bound
        to the new version, its alerts and the exact writes, which a person approves. The
        quiet window is the service's to find out, never the caller's."""
        case = await self._locked(case_id, expected_version)
        window = (
            await self.quiet_windows(case)
            if reason in ("remediated_verified", "attempt_no_impact")
            else None
        )
        step = machine.decide(case, ProposeClosure(reason, evidence, window), actor, self.now)
        await self._update(step)
        applied = await self._record(actor, step)
        built = closure.build(step.after, reason, self.now)
        request_id = await approvals.propose(
            self.conn,
            proposer=actor.name,
            case_id=case_id,
            case_version=step.after.version,
            kind="closure",
            reason=reason,
            payload=built.payload,
            payload_hash=built.payload_hash,
            expires=approvals.expires_at(self.now),
            kibana_version=await self._kibana_version(case_id),
            note=step.details.get("note"),
        )
        return applied, request_id

    async def request_merge(
        self,
        actor: Actor,
        case_id: uuid.UUID,
        target_id: uuid.UUID,
        *,
        expected_version: int | None,
        session_token: str,
        check: identity.LiveCheck,
        note: str | None = None,
    ) -> tuple[Applied, int]:
        await self._session_is(actor, session_token)
        requester = self._requester(actor, check)
        target = await self.get(target_id)
        if target is None:
            raise CaseNotFound(str(target_id))
        case = await self._locked(case_id, expected_version)
        step, built = self._merge_plan(actor, case, target, note)
        await self._update(step)
        applied = await self._record(actor, step)
        request_id = await approvals.request(
            self.conn,
            session_token=session_token,
            case_id=case_id,
            case_version=step.after.version,
            kind="merge",
            reason="duplicate",
            target_case_id=target_id,
            payload=built.payload,
            payload_hash=built.payload_hash,
            expires=approvals.expires_at(self.now),
            check=requester,
            kibana_version=await self._kibana_version(case_id),
            note=step.details.get("note"),
        )
        return applied, request_id

    async def decide(
        self,
        actor: Actor,
        request_id: int,
        *,
        session_token: str,
        decision: approvals.Decision,
        signed: approvals.Signed,
        note: str | None = None,
        apply: bool = True,
    ) -> tuple[approvals.Status, list[Applied]]:
        """A person's decision on a request (the database audits it in their name), with the
        web's step-up, live check and signature (:class:`argus.cases.desk.ApprovalDesk` builds
        them); with ``apply``, the one that completes it applies it (closes or merges the case)
        in the same transaction, else ARGUS does (:meth:`apply_approved`)."""
        if not actor.may(Capability.APPROVE):
            raise CaseRefused("forbidden", "deciding needs the approve capability")
        await self._session_is(actor, session_token)
        status = await approvals.decide(
            self.conn,
            session_token=session_token,
            request_id=request_id,
            decision=decision,
            signed=signed,
            note=note,
        )
        if status != "approved" or not apply:
            return status, []
        return status, await self._apply(actor, request_id)

    async def apply_approved(self, request_id: int) -> list[Applied]:
        """Apply a complete closure or merge approval that its decision did not apply (the
        web's own login records decisions only): as the person whose approval completed it,
        via ARGUS. Nothing when it is not complete, already applied, or not a closure."""
        facts = await approvals.facts(self.conn, request_id)
        if facts is None or facts.kind not in ("closure", "merge"):
            return []
        case = await self.get(facts.case_id)
        now = await self._clock()
        if case is None or case.version != facts.case_version or not facts.complete(now):
            return []
        row = (
            await self.conn.execute(
                text(
                    "SELECT d.approver_user_id, d.capabilities FROM approval_decisions d"
                    " WHERE d.request_id = :r AND d.decision = 'approved'"
                    " AND d.approver_user_id = ANY(:ids) ORDER BY d.id DESC LIMIT 1"
                ),
                {"r": request_id, "ids": list(facts.approvers)},
            )
        ).one()
        actor = Actor.person(int(row.approver_user_id), frozenset(row.capabilities),
                             via="argus:approvals")  # fmt: skip
        return await self._apply(actor, request_id)

    async def _apply(self, actor: Actor, request_id: int) -> list[Applied]:
        facts = await approvals.facts(self.conn, request_id)
        assert facts is not None
        if facts.kind == "closure":
            return [await self.close(actor, facts.case_id, request_id)]
        if facts.kind == "merge":
            assert facts.target_case_id is not None
            return list(await self.merge(actor, facts.case_id, facts.target_case_id,
                                         approval_id=request_id))  # fmt: skip
        # resends and compensating writes are applied by the writer; a re-confirmation
        # lets the send-time check release its closure write (argus.cases.sendcheck)
        return []

    async def close(self, actor: Actor, case_id: uuid.UUID, request_id: int) -> Applied:
        """Apply a complete closure approval; its Kibana writes must be the ones approved."""
        case = await self._locked(case_id, None)
        facts = await approvals.facts(self.conn, request_id)
        if facts is None:
            raise CaseRefused("conflict", "no such approval request")
        step = machine.decide(case, Close(facts), actor, await self._clock())
        await self._check_payload(case, step, request_id)
        await self._update(step)
        return await self._record(actor, step)

    async def merge(
        self,
        actor: Actor,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        *,
        approval_id: int | None = None,
        expected_version: int | None = None,
        note: str | None = None,
    ) -> tuple[Applied, Applied]:
        """The source closes as a duplicate of the target, which takes its members and
        indicators. A confirmed source needs a complete merge approval; a suspected one only a
        person who may manage cases."""
        first, second = sorted((source_id, target_id))
        cases = {
            first: await self._locked(first, None),
            second: await self._locked(second, None),
        }
        source, target = cases[source_id], cases[target_id]
        if expected_version is not None and source.version != expected_version:
            raise CaseRefused("conflict", f"the case changed meanwhile (version {source.version})")
        facts = None if approval_id is None else await approvals.facts(self.conn, approval_id)
        now = self.now if facts is None else await self._clock()
        out = machine.decide(source, MergeInto(target_id, target.state, facts, note), actor, now)
        if facts is not None:
            await self._check_payload(source, out, approval_id)
        moved = sorted(source.members)
        into = machine.decide(
            target,
            MergedIn(
                source_id,
                tuple(Member(m, "merge", f"case:{source.number}") for m in sorted(moved)),
                tuple(
                    Indicator(i.kind, i.value, i.role, "merge") for i in sorted(source.indicators)
                ),
                source.severity,
            ),
            actor,
            now,
        )
        await self._update(out)
        left = await self._record(actor, out)
        await self._update(into)
        joined = await self._record(actor, into)
        return left, joined

    async def add_note(self, actor: Actor, case_id: uuid.UUID, body: str) -> int:
        """A person's note on a case (never sent to a model); not a change of the case."""
        if not actor.may(Capability.REVIEW) or actor.user_id is None:
            raise CaseRefused("forbidden", "a note is a person's, with the review capability")
        text_ = _note(body)
        if await self.get(case_id) is None:
            raise CaseNotFound(str(case_id))
        note_id: int = (
            await self.conn.execute(
                text(
                    "INSERT INTO case_notes (case_id, author_user_id, body) VALUES (:c, :u, :b)"
                    " RETURNING id"
                ),
                {"c": case_id, "u": actor.user_id, "b": text_},
            )
        ).scalar_one()
        await self._audit(actor, "case.note", str(case_id), {"note": note_id})
        return note_id

    async def add_entity_note(self, actor: Actor, kind: str, value: str, body: str) -> int:
        if not actor.may(Capability.REVIEW) or actor.user_id is None:
            raise CaseRefused("forbidden", "a note is a person's, with the review capability")
        if kind not in ENTITY_KINDS or not 1 <= len(value) <= 512 or "\x00" in value:
            raise CaseRefused("invalid", "an entity is an ip, domain, host or user value")
        note_id: int = (
            await self.conn.execute(
                text(
                    "INSERT INTO entity_notes (kind, value, author_user_id, body)"
                    " VALUES (:k, :v, :u, :b) RETURNING id"
                ),
                {"k": kind, "v": value, "u": actor.user_id, "b": _note(body)},
            )
        ).scalar_one()
        await self._audit(actor, "entity.note", f"{kind}:{value}", {"note": note_id})
        return note_id

    async def _insert(self, case: Case) -> int:
        number: int = (
            await self.conn.execute(
                text(
                    "INSERT INTO cases (id, title, state, severity, owner_user_id, version,"
                    " cause, cause_review_id, cause_assessment_id, parent_case_id, opened_at,"
                    " attention, kibana_wait) VALUES (:id, :title, :state, :severity, :owner,"
                    " :version, :cause, :review, :assessment, :parent, :opened, :attention,"
                    " :wait) RETURNING number"
                ),
                {
                    "id": case.id,
                    "title": case.title,
                    "state": case.state,
                    "severity": case.severity,
                    "owner": case.owner_user_id,
                    "version": case.version,
                    "cause": case.cause,
                    "review": case.cause_review_id,
                    "assessment": case.cause_assessment_id,
                    "parent": case.parent_case_id,
                    "opened": case.opened_at,
                    "attention": case.attention,
                    "wait": case.kibana_wait,
                },
            )
        ).scalar_one()
        return number

    async def _update(self, step: Step) -> None:
        before, after = step.before, step.after
        assert before is not None
        result = await self.conn.execute(
            text(
                "UPDATE cases SET title = :title, state = :state, severity = :severity,"
                " owner_user_id = :owner, version = :version, opened_at = :opened,"
                " closed_at = :closed, closure_reason = :reason, closure_request_id = :request,"
                " merged_into_id = :merged, attention = :attention, kibana_wait = :wait,"
                " notified_at = :notified, blocked_at = :blocked"
                " WHERE id = :id AND version = :old"
            ),
            {"id": after.id, "old": before.version, "title": after.title, "state": after.state,
             "severity": after.severity, "owner": after.owner_user_id,
             "version": after.version, "opened": after.opened_at, "closed": after.closed_at,
             "reason": after.closure_reason, "request": after.closure_request_id,
             "merged": after.merged_into_id, "attention": after.attention,
             "wait": after.kibana_wait, "notified": after.notified_at,
             "blocked": after.blocked_at},
        )  # fmt: skip
        if result.rowcount != 1:
            raise CaseRefused("conflict", "the case changed meanwhile")

    async def _record(self, actor: Actor, step: Step) -> Applied:
        """Members, indicators, the case event, its outbox rows and the audit event."""
        after = step.after
        for investigation in step.members_removed:
            await self.conn.execute(
                text(
                    "UPDATE case_members SET removed_version = :v, removed_at = now()"
                    " WHERE case_id = :c AND investigation_id = :i AND removed_at IS NULL"
                ),
                {"v": after.version, "c": after.id, "i": investigation},
            )
        if step.indicators_removed:
            gone = step.indicators_removed
            result = await self.conn.execute(
                text(
                    "UPDATE case_indicators SET removed_version = :v, removed_at = now()"
                    " WHERE case_id = :c AND removed_at IS NULL AND (kind, value) IN"
                    " (SELECT k, v FROM unnest(CAST(:kinds AS text[]), CAST(:values AS text[]))"
                    " AS u(k, v))"
                ),
                {"v": after.version, "c": after.id, "kinds": [i.kind for i in gone],
                 "values": [i.value for i in gone]},
            )  # fmt: skip
            if result.rowcount != len(gone):
                raise CaseRefused("conflict", "the case's indicators changed meanwhile")
        await self._add_members(actor, step)
        await self._add_indicators(actor, step)
        details = machine.event_details(step)
        event_id: int = (
            await self.conn.execute(
                text(
                    "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                    " from_state, to_state, details, kibana_rows) VALUES (:c, :v, :k, :a, :u,"
                    " :f, :t, CAST(:d AS jsonb), :n) RETURNING id"
                ),
                {
                    "c": after.id,
                    "v": after.version,
                    "k": step.kind,
                    "a": actor.name,
                    "u": actor.user_id,
                    "f": None if step.before is None else step.before.state,
                    "t": after.state,
                    "d": json.dumps(details),
                    "n": len(step.writes),
                },
            )
        ).scalar_one()
        outbox: list[int] = []
        before_image = await self._before_image(after.id) if step.writes else None
        for position, write in enumerate(step.writes):
            outbox.append(
                (
                    await self.conn.execute(
                        text(
                            "INSERT INTO kibana_outbox (case_id, case_event_id, position,"
                            " idempotency_key, write_class, op, payload, payload_hash,"
                            " before_image, approval_request_id) VALUES (:c, :e, :p, :key, :w,"
                            " :op, CAST(:payload AS jsonb), :h, CAST(:b AS jsonb), :a)"
                            " RETURNING id"
                        ),
                        {
                            "c": after.id,
                            "e": event_id,
                            "p": position,
                            "key": f"{after.id}:v{after.version}:{position}",
                            "w": write.write_class,
                            "op": write.op,
                            "payload": json.dumps(write.payload),
                            "h": kibana.payload_hash(write.payload),
                            "b": None if before_image is None else json.dumps(before_image),
                            "a": after.closure_request_id if write.write_class == "W3" else None,
                        },
                    )
                ).scalar_one()
            )
        await self._audit(
            actor,
            f"case.{step.kind}",
            str(after.id),
            {"number": after.number, "version": after.version,
             "from": None if step.before is None else step.before.state, "to": after.state,
             "event": event_id, "kibana_rows": len(step.writes)},
        )  # fmt: skip
        return Applied(step, after, event_id, tuple(outbox))

    async def _add_members(self, actor: Actor, step: Step) -> None:
        """The step's new members. A member removed earlier (a split moved it out, a merge took it)
        and added again has its row revived, as the key is the case and the investigation: the
        history of the first stay is in the case's events."""
        if not step.members_added:
            return
        after, added = step.after, step.members_added
        revived = set(
            (
                await self.conn.execute(
                    text(
                        "UPDATE case_members m SET link = u.link, link_value = u.link_value,"
                        " added_version = :v, added_by = :by, added_at = now(),"
                        " removed_version = NULL, removed_at = NULL FROM"
                        " unnest(CAST(:ids AS uuid[]), CAST(:links AS text[]),"
                        " CAST(:values AS text[])) AS u(id, link, link_value)"
                        " WHERE m.case_id = :c AND m.investigation_id = u.id"
                        " AND m.removed_at IS NOT NULL RETURNING m.investigation_id"
                    ),
                    {
                        "v": after.version,
                        "by": actor.name,
                        "c": after.id,
                        "ids": [m.investigation_id for m in added],
                        "links": [m.link for m in added],
                        "values": [m.link_value for m in added],
                    },
                )
            ).scalars()
        )
        fresh = [m for m in added if m.investigation_id not in revived]
        if fresh:
            await self.conn.execute(
                text(
                    "INSERT INTO case_members (case_id, investigation_id, link, link_value,"
                    " added_version, added_by) VALUES (:c, :i, :l, :lv, :v, :by)"
                ),
                [{"c": after.id, "i": m.investigation_id, "l": m.link, "lv": m.link_value,
                  "v": after.version, "by": actor.name} for m in fresh],
            )  # fmt: skip

    async def _add_indicators(self, actor: Actor, step: Step) -> None:
        """The step's new indicators; one removed earlier (a split took it with its device) and
        added again has its row revived (the key is the case, the kind and the value)."""
        if not step.indicators_added:
            return
        after, added = step.after, step.indicators_added
        revived = {
            (str(k), str(v))
            for k, v in (
                await self.conn.execute(
                    text(
                        "UPDATE case_indicators i SET role = u.role, source = u.source,"
                        " added_version = :v, added_by = :by, added_at = now(),"
                        " removed_version = NULL, removed_at = NULL FROM"
                        " unnest(CAST(:kinds AS text[]), CAST(:values AS text[]),"
                        " CAST(:roles AS text[]), CAST(:sources AS text[]))"
                        " AS u(kind, value, role, source)"
                        " WHERE i.case_id = :c AND i.kind = u.kind AND i.value = u.value"
                        " AND i.removed_at IS NOT NULL RETURNING i.kind, i.value"
                    ),
                    {
                        "v": after.version,
                        "by": actor.name,
                        "c": after.id,
                        "kinds": [i.kind for i in added],
                        "values": [i.value for i in added],
                        "roles": [i.role for i in added],
                        "sources": [i.source for i in added],
                    },
                )
            )
        }
        fresh = [i for i in added if (i.kind, i.value) not in revived]
        if fresh:
            await self.conn.execute(
                text(
                    "INSERT INTO case_indicators (case_id, kind, value, role, source,"
                    " added_version, added_by) VALUES (:c, :k, :val, :r, :s, :v, :by)"
                ),
                [{"c": after.id, "k": i.kind, "val": i.value, "r": i.role,
                  "s": i.source, "v": after.version, "by": actor.name} for i in fresh],
            )  # fmt: skip

    async def _audit(self, actor: Actor, action: str, target: str, details: dict[str, Any]) -> None:
        session = AsyncSession(bind=self.conn)
        try:
            await record_audit(
                session,
                actor=actor.name,
                action=action,
                target_type="case" if action.startswith("case.") else "entity",
                target_id=target,
                details={**details, "via": actor.via},
            )
        finally:
            await session.close()

    async def _before_image(self, case_id: uuid.UUID) -> dict[str, Any] | None:
        row = (
            await self.conn.execute(
                text(
                    "SELECT kibana_case_id, kibana_version, status, title, severity, tags,"
                    " unmanaged, sync_alerts, deleted_at FROM kibana_mirror WHERE case_id = :c"
                ),
                {"c": case_id},
            )
        ).first()
        if row is None:
            return None
        image = dict(row._mapping)
        image["deleted_at"] = None if row.deleted_at is None else row.deleted_at.isoformat()
        return image

    async def _kibana_version(self, case_id: uuid.UUID) -> str | None:
        found: str | None = (
            await self.conn.execute(
                text("SELECT kibana_version FROM kibana_mirror WHERE case_id = :c"), {"c": case_id}
            )
        ).scalar_one_or_none()
        return found

    async def _check_payload(self, case: Case, step: Step, request_id: int | None) -> None:
        """The Kibana writes a closure plans are exactly the ones its approval named (the
        shared builder, :func:`argus.cases.closure.build`, gives both)."""
        if request_id is None:
            return
        approved, approved_hash = await approvals.payload_of(self.conn, request_id)
        reason = step.after.closure_reason
        assert reason is not None
        expected = closure.build(case, reason, self.now, target=step.after.merged_into_id)
        if expected.payload_hash != approved_hash or kibana.payload_hash(approved) != approved_hash:
            raise CaseRefused("conflict", "the closure is not the one that was approved")


def _note(body: str) -> str:
    text_ = (body or "").strip()
    if not text_:
        raise CaseRefused("invalid", "a note needs text")
    if len(text_) > NOTE_LIMIT or "\x00" in text_:
        raise CaseRefused("invalid", f"a note has at most {NOTE_LIMIT} characters, no NUL")
    return text_
