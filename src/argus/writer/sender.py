"""The cases sender: drains approved outbox rows class by class.

For each row the writer re-reads the Kibana case, plans the request from the row and what Kibana
holds now, renders it from deterministic text, passes the Kibana lane's checks, **commits
``sending`` at the last step before the request leaves**, sends it once, records the answer and
reads the case back. Nothing is retried or resent: a write with an unknown outcome is ``ambiguous``
and looked for; a resend needs a person's approval; a step (comment, attachment, compensating write)
is never resent. A 409 puts the row in ``conflict`` for a person; a read-back that does not match
pauses the class and raises Needs attention."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, identity, sendcheck
from argus.cases.signing import Verifier
from argus.gateway.builtin import AlertCaseLinks, CaseLinksParams
from argus.gateway.errors import GatewayError, RefusedError
from argus.gateway.gateway import Gateway, utcnow
from argus.gateway.kibana import selftest, writes
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaAuthError,
    KibanaConflictError,
    KibanaForbiddenError,
    KibanaNoChangeError,
    KibanaNotFoundError,
    KibanaResponseError,
    UnknownOutcomeError,
    WriteRefusedError,
)
from argus.gateway.kibana.gateway import KibanaGateway, WriteContext, WriteRun
from argus.gateway.kibana.templates import (
    CaseComments,
    CaseGet,
    CasePageParams,
    CaseParams,
    KeyRole,
)
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.templates import Purpose
from argus.kibana_sync.model import parse_links
from argus.writer import approval, compensation, lookup, plan, render, store

log = logging.getLogger("argus.writer")

COMPONENT = "writer"
SENDING_STALE = timedelta(minutes=2)  # a request is over (or never left) long before this
WRITE_DEADLINE = timedelta(minutes=5)  # how long one write may wait for its budget and gap
READ_DEADLINE = timedelta(minutes=2)
CASE_GAP_WAIT = timedelta(seconds=3.1)  # case writes are 3 s apart
ALERT_GAP_WAIT = timedelta(seconds=61)  # alert calls are 60 s apart
READBACK_TRIES = 3  # an alert's case ids reach the alerts index within about a second
READBACK_WAIT = 2.0
LOOKUP_RETRY = timedelta(minutes=2)
UNKNOWN = (KibanaResponseError,)


class SendRefused(Exception):  # noqa: N818 - the send-time check said no
    """The send-time check of a closure write did not say ``send``: nothing leaves."""

    def __init__(self, verdict: sendcheck.SendCheck) -> None:
        super().__init__(verdict.summary)
        self.verdict = verdict


class RunStopped(Exception):  # noqa: N818 - a stop, not a failure
    """The run ends here: the lane refused, Kibana is stopped or unreachable."""


class Replan(Exception):  # noqa: N818 - a signal, not a failure
    """The send waited (a gap between writes): what it was planned from is stale, so the case
    is read and planned again before anything is sent."""

    def __init__(self, run: WriteRun) -> None:
        super().__init__("planned again after a wait")
        self.run = run


@dataclass
class Waits:
    """How many gaps one item has waited out; a wait that does not end is not waited for ever."""

    count: int = 0


@dataclass
class RunReport:
    write_class: str
    units: int = 0
    sent: int = 0
    verified: int = 0
    mismatches: int = 0
    ambiguous: int = 0
    skipped: int = 0
    held: list[str] = field(default_factory=list)
    stopped: str | None = None

    def lines(self) -> list[str]:
        out = [
            f"{self.write_class}: {self.units} units, {self.sent} sent, {self.verified} read back"
            f" as sent, {self.mismatches} mismatches, {self.ambiguous} in doubt,"
            f" {self.skipped} skipped"
        ]
        out += [f"  held: {why}" for why in self.held]
        if self.stopped:
            out.append(f"  stopped: {self.stopped}")
        return out


@dataclass(frozen=True)
class Item:
    """A row or a step in the one shape the send path needs."""

    table: str
    id: int
    case_id: uuid.UUID
    write_class: str
    key: str
    approval_request_id: int | None
    kind: str  # create, update, close, comment (a row's op), or a step's kind
    sent_count: int
    row: plan.Row | None = None
    step: store.Step | None = None

    @property
    def subject(self) -> str:
        return "outbox" if self.table == store.OUTBOX else "step"

    @property
    def ledger_id(self) -> str:
        return str(self.id) if self.table == store.OUTBOX else f"step-{self.id}"


def item_of(row: plan.Row) -> Item:
    return Item(
        store.OUTBOX,
        row.id,
        row.case_id,
        row.write_class,
        row.idempotency_key,
        row.approval_request_id,
        row.op,
        row.sent_count,
        row=row,
    )


def item_of_step(step: store.Step) -> Item:
    return Item(
        store.STEPS,
        step.id,
        step.case_id,
        step.write_class,
        step.key,
        step.approval_request_id,
        step.kind,
        step.sent_count,
        step=step,
    )


class Writer:
    def __init__(
        self,
        engine: AsyncEngine,
        gateway: KibanaGateway,
        *,
        es: Gateway,
        verifier: Verifier | None,
        link_base: str,
        author: str = "argus",
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        wait_for_gaps: bool = False,
        accepted_residual: Iterable[str] = (),
        key_selftest: bool = True,
    ) -> None:
        self.engine = engine
        self.gateway = gateway
        self.es = es
        self.verifier = verifier
        self.link_base = link_base
        self.author = author
        self.clock = clock
        self.sleep = sleep
        self.wait_for_gaps = wait_for_gaps  # a terminal run waits out the 3 s and 60 s gaps
        self.accepted_residual = tuple(accepted_residual)
        self.key_selftest = key_selftest
        self._key_checked = False

    async def run_class(self, write_class: str, *, limit: int, kind: str, by: str) -> RunReport:
        """One run of one class: housekeeping (what the last run left in doubt), then up to
        ``limit`` units (a case's create with its comment and attachments; a case change with
        its comment; an approved closure)."""
        report = RunReport(write_class)
        async with self.engine.connect() as locker:
            got = (
                await locker.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": store.LOCK_KEY})
            ).scalar_one()
            if not got:
                report.stopped = "another writer run is in progress"
                return report
            try:
                problems = await self.preflight()
                if problems:
                    report.stopped = "the cases writer key failed its self-test: " + "; ".join(
                        problems
                    )
                    return report
                started = self.clock()
                try:
                    await self._run(report, write_class, limit, kind)
                except RunStopped as stop:
                    report.stopped = report.stopped or str(stop)
                finally:
                    if report.units or report.sent or kind != "scheduled":
                        async with self.engine.begin() as conn:  # an idle scheduled run leaves none
                            await store.record_run(
                                conn,
                                write_class,
                                kind,
                                limit,
                                by,
                                started,
                                self.clock(),
                                units=report.units,
                                sent=report.sent,
                                verified=report.verified,
                                mismatches=report.mismatches,
                                ambiguous=report.ambiguous,
                                stopped=report.stopped,
                            )
            finally:
                await locker.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
                await locker.commit()
        return report

    async def preflight(self) -> list[str]:
        """The start-up key self-test: the cases writer's key holds what it must
        and none of what it must not (``api:rac``, the alert updates, ``deleteCase``,
        ``createConfiguration``, ``pushCase``, ``assignCase``), asked of Elasticsearch with the
        key itself, once for this writer. A failed test sends nothing."""
        if self._key_checked or not self.key_selftest:
            return []
        try:
            _, verdict = await selftest.run_selftest(
                self.gateway, KeyRole.CASES, deadline=self.clock() + READ_DEADLINE,
                accepted_residual=self.accepted_residual, component=COMPONENT,
            )  # fmt: skip
        except (GatewayError, KibanaResponseError) as exc:
            return [f"the self-test could not be made ({_why(exc)})"]
        if not verdict.problems:
            self._key_checked = True
        return list(verdict.problems)

    async def preview(self, write_class: str, limit: int = 50) -> list[str]:
        """What a run of the class would do with each row and step waiting (``argus kibana
        diff``): the case is read, nothing is written and nothing in the database changes."""
        lines: list[str] = []
        async with self.engine.connect() as conn:
            rows = await store.eligible_rows(conn, write_class, limit)
            steps = await store.eligible_steps(conn, write_class, limit)
        for row in rows:
            verdict, _, live = await self._decide_row(row)
            lines.append(
                f"outbox {row.id} (case {row.case_id}) {row.op}: {plan.describe(verdict, live)}"
            )
        for step in steps:
            verdict, _, live = await self._decide_step(step, dry=True)
            lines.append(
                f"step {step.id} (case {step.case_id}) {step.kind}: {plan.describe(verdict, live)}"
            )
        return lines

    async def _run(self, report: RunReport, cls: str, limit: int, kind: str = "ramp") -> None:
        await self.housekeeping(report, cls)
        if kind == "scheduled" and not writes.in_window(self.clock(), self.gateway.caps):
            # the lane would refuse every write: the service does not read Kibana for them
            report.stopped = "outside the write window"
            return
        run: WriteRun | None = None  # started when the first write is about to go
        attempted: set[tuple[str, int]] = set()
        units: set[int] = set()
        while True:
            if cls == "W3":  # the closing comment is let go once its change is verified
                await self.release_closures()
            item = await self._next(cls, attempted)
            if item is None:
                return
            attempted.add((item.table, item.id))
            if item.row is not None:
                unit = item.row.id if cls == "W1" else item.row.case_event_id
                if unit not in units:
                    if len(units) >= limit:
                        continue
                    units.add(unit)
                    report.units = len(units)
            run = await self._work(item, run, report)

    async def _start_run(self) -> WriteRun:
        try:
            return await self.gateway.start_run(
                component=COMPONENT, deadline=self.clock() + READ_DEADLINE
            )
        except (GatewayError, KibanaResponseError) as exc:
            raise RunStopped(f"Kibana is not ready for writes ({_why(exc)})") from None

    async def _next(self, cls: str, attempted: set[tuple[str, int]]) -> Item | None:
        async with self.engine.connect() as conn:
            rows = await store.eligible_rows(conn, cls, 25)
            steps = await store.eligible_steps(conn, cls, 25)
        for row in rows:
            if (store.OUTBOX, row.id) not in attempted:
                return item_of(row)
        for step in steps:
            if (store.STEPS, step.id) not in attempted:
                return item_of_step(step)
        return None

    async def housekeeping(self, report: RunReport, cls: str) -> None:
        """What the last run left: rows stuck in ``sending`` become ambiguous, rows sent but
        not read back are read back, closure writes get their send-time check, approved
        resends and compensating writes are put in motion, and due lookups are made."""
        await self.recover()
        if cls == "W3":
            await self.release_closures()
        report.held += [f"resend refused: {why}" for why in await self.apply_resends()]
        if cls == "W2":
            report.held += [
                f"compensation refused: {why}" for why in await self.apply_compensations()
            ]
        await self.run_lookups()
        if cls == "W1":
            await self._plan_attachments()

    async def recover(self) -> None:
        now = self.clock()
        for table in (store.OUTBOX, store.STEPS):
            async with self.engine.begin() as conn:
                stuck = await store.stale_sending(conn, table, now - SENDING_STALE)
            for item_id in stuck:
                async with self.engine.begin() as conn:
                    await self._doubt(
                        conn, table, item_id, "the writer stopped between sending and the answer"
                    )
        await self._reverify_sent()

    async def _doubt(self, conn: Any, table: str, item_id: int, why: str) -> None:
        """``sending`` -> ``ambiguous`` with its four lookups, in the caller's transaction."""
        item = await self._load(conn, table, item_id)
        if item is None or not await store.move(
            conn, table, item_id, "ambiguous", why, only_from=["sending"]
        ):
            return
        await store.schedule_lookups(conn, item.subject, item_id, item.sent_count, self.clock())
        await store.audit(
            conn,
            "kibana.write.ambiguous",
            item.case_id,
            {"item": item.ledger_id, "class": item.write_class, "why": why},
        )

    async def _load(self, conn: Any, table: str, item_id: int) -> Item | None:
        if table == store.OUTBOX:
            row = await store.get_row(conn, item_id)
            return None if row is None else item_of(row)
        step = await store.get_step(conn, item_id)
        return None if step is None else item_of_step(step)

    async def _reverify_sent(self) -> None:
        async with self.engine.connect() as conn:
            rows = await store.rows_in(conn, "sent")
            steps = await store.steps_in(conn, "sent")
        for item in [*map(item_of, rows), *map(item_of_step, steps)]:
            try:
                await self._verify(item, RunReport(item.write_class), None)
            except RunStopped:
                return

    async def release_closures(self) -> None:
        """The send-time check of every waiting closure write (:func:`sendcheck.release`)."""
        if self.verifier is None:
            return
        async with self.engine.connect() as conn:
            waiting = await sendcheck.held(conn)
        for row_id in waiting:
            async with self.engine.begin() as conn:
                await sendcheck.release(conn, row_id, self.verifier)

    async def _work(self, item: Item, run: WriteRun | None, report: RunReport) -> WriteRun | None:
        try:
            if item.row is not None:
                return await self._work_row(item.row, run, report)
            assert item.step is not None
            return await self._work_step(item.step, run, report)
        except RunStopped as stop:
            report.stopped = str(stop)
            raise

    async def _work_row(
        self, row: plan.Row, run: WriteRun | None, report: RunReport
    ) -> WriteRun | None:
        waits = Waits()
        while True:
            verdict, kid, live = await self._decide_row(row)
            try:
                return await self._act(item_of(row), verdict, kid, live, run, report, waits)
            except Replan as again:  # it waited: read the case again, plan again
                run = again.run

    async def _decide_row(
        self, row: plan.Row
    ) -> tuple[plan.Plan, str | None, Mapping[str, Any] | None]:
        """What to do with a row now: re-read its case and plan against it (sends nothing)."""
        async with self.engine.connect() as conn:
            mirror = await store.mirror_facts(conn, row.case_id)
            kid = None if row.op == "create" else await store.kibana_case_of(conn, row.case_id)
            prior = await store.prior_state(conn, row) if row.op == "comment" else None
            params = row.payload.get("params", {}) if row.op == "comment" else {}
            ctx = await store.context(
                conn, self.link_base, row.approval_request_id, row.idempotency_key, params
            )
            seen = (
                await store.seen_of(conn, row.case_id, mirror, row.id)
                if row.op in ("update", "close")
                else None
            )
        live: Mapping[str, Any] | None = None
        if row.op == "create":
            return plan.plan_create(row, ctx), None, None
        if kid is None:
            return plan.Hold("the case's create in Kibana is not verified yet"), None, None
        live = await self._get(kid)
        explained = prior[1] or prior[0] if prior and prior[0] == "skipped" else None
        verdict = plan.plan_change(
            row, live, mirror, ctx, self.author, explained=explained, seen=seen
        )
        return verdict, kid, live

    async def _act(
        self,
        item: Item,
        verdict: plan.Plan,
        kid: str | None,
        live: Mapping[str, Any] | None,
        run: WriteRun | None,
        report: RunReport,
        waits: Waits | None = None,
    ) -> WriteRun | None:
        match verdict:
            case plan.Skip(reason):
                async with self.engine.begin() as conn:
                    if await store.move(
                        conn,
                        item.table,
                        item.id,
                        "skipped",
                        reason,
                        only_from=["planned", "approved", "paused"],
                    ):
                        await store.audit(
                            conn,
                            "kibana.write.skipped",
                            item.case_id,
                            {"item": item.ledger_id, "why": reason},
                        )
                report.skipped += 1
                return run
            case plan.Hold(reason, action):
                await self._hold(item, reason, action, kid, live, report)
                return run
            case plan.Send():
                return await self._execute(item, verdict, kid, run, report, waits or Waits())
        raise AssertionError("a plan is a skip, a hold or a send")  # pragma: no cover

    async def _hold(
        self,
        item: Item,
        reason: str,
        action: str,
        kid: str | None,
        live: Mapping[str, Any] | None,
        report: RunReport,
    ) -> None:
        report.held.append(f"{item.ledger_id}: {reason}")
        now = self.clock()
        async with self.engine.begin() as conn:
            if action in ("pause", "tamper"):
                await store.move(
                    conn, item.table, item.id, "paused", reason, only_from=["planned", "approved"]
                )
                await store.audit(
                    conn,
                    "kibana.write.paused",
                    item.case_id,
                    {"item": item.ledger_id, "why": reason},
                    outcome="failure" if action == "tamper" else "success",
                )
            if action == "sync_on" and kid is not None and live is not None:
                await store.finding_sync_on(conn, item.case_id, kid, str(live["version"]), now)
                await store.audit(
                    conn,
                    "kibana.write.held",
                    item.case_id,
                    {"item": item.ledger_id, "why": reason},
                    outcome="failure",
                )
        if action == "tamper":
            await self._pause_class(item.write_class, reason)

    async def _pause_class(self, write_class: str, reason: str) -> None:
        cls = WriteClass(write_class)
        await self.gateway.state.kibana_change(lambda s: (None, writes.pause(s, cls, reason[:200])))

    async def _execute(
        self,
        item: Item,
        send: plan.Send,
        kid: str | None,
        run: WriteRun | None,
        report: RunReport,
        waits: Waits,
    ) -> WriteRun:
        if run is None:  # Kibana's version, the licence and the case configuration, once
            run = await self._start_run()
        context = WriteContext(
            WriteClass(item.write_class),
            item.ledger_id,
            self.gateway.payload_hash(send.template, send.params),
            None if item.approval_request_id is None else str(item.approval_request_id),
        )
        committed = False

        async def commit_sending() -> None:
            nonlocal committed
            async with self.engine.begin() as conn:
                if item.table == store.OUTBOX:
                    await store.move(
                        conn,
                        store.OUTBOX,
                        item.id,
                        "approved",
                        f"{item.write_class} is on",
                        only_from=["planned"],
                    )
                if item.row is not None and item.write_class == "W3":
                    assert self.verifier is not None
                    verdict = await sendcheck.admit(conn, item.id, self.verifier)
                    if verdict.verdict != "send":
                        raise SendRefused(verdict)
                elif item.step is not None:
                    await self._admit_step(conn, item.step)
                await store.begin_sending(conn, item.table, item.id, self.clock())
            committed = True
            report.sent += 1  # a request that leaves now: counted whatever comes back

        restarts = 0
        while True:
            try:
                result = await self.gateway.write(
                    send.template,
                    send.params,
                    run=run,
                    context=context,
                    component=COMPONENT,
                    deadline=self.clock() + WRITE_DEADLINE,
                    before_send=commit_sending,
                )
            except SendRefused as refused:
                await self._send_check_said(item, refused.verdict)
                report.held.append(f"{item.ledger_id}: {refused.verdict.summary}")
                return run
            except store.StateMovedError as moved:
                report.held.append(f"{item.ledger_id}: {moved}")
                return run
            except WriteRefusedError as refusal:
                if refusal.reason == "case_gap" and waits.count < 3:  # 3 s between case writes
                    waits.count += 1
                    await self.sleep(CASE_GAP_WAIT.total_seconds())
                    raise Replan(run) from None  # the case may have changed meanwhile
                if refusal.reason == "alert_gap":  # a minute between alert calls
                    if self.wait_for_gaps and waits.count < 3:  # a terminal run waits it out
                        waits.count += 1
                        await self.sleep(ALERT_GAP_WAIT.total_seconds())
                        raise Replan(run) from None  # Sync alerts may have been switched on
                    report.held.append(f"{item.ledger_id}: a minute between alert calls")
                    return run  # the service goes on with other work and comes back
                if refusal.reason == "run_stale" and restarts < 2:
                    restarts += 1
                    run = await self._start_run()
                    continue
                raise RunStopped(f"{item.write_class} waits: {refusal.reason}") from None
            except RefusedError as refusal:
                if committed:  # nothing should be refused after sending was committed
                    await self._after_error(
                        item, send, kid, KibanaResponseError(str(refusal)), report
                    )
                    raise RunStopped(f"refused after sending ({refusal.reason})") from None
                raise RunStopped(f"{refusal.reason}: {refusal}") from None
            except KibanaResponseError as exc:
                if not committed:  # an answer to something other than this write: not ours
                    raise RunStopped(f"Kibana: {_why(exc)}") from None
                await self._after_error(item, send, kid, exc, report)
                return run
            break
        await self._sent(item, send, result.body)
        await self._verify(item, report, send)
        return run

    async def _admit_step(self, conn: Any, step: store.Step) -> None:
        if step.kind.startswith("compensate"):  # its approval is checked again at send time
            assert step.approval_request_id is not None
            problem = await self._approval_problem(conn, step.approval_request_id)
            if problem is not None:
                raise SendRefused(
                    sendcheck.SendCheck(
                        step.id, "refuse", (f"approval {step.approval_request_id}: {problem}",)
                    )
                )
        moved = await store.move(
            conn, store.STEPS, step.id, "approved", None, only_from=["planned"]
        )
        del moved

    async def _send_check_said(self, item: Item, verdict: sendcheck.SendCheck) -> None:
        async with self.engine.begin() as conn:
            if item.row is not None and self.verifier is not None:
                await sendcheck.release(conn, item.id, self.verifier)
            else:
                await store.move(
                    conn,
                    item.table,
                    item.id,
                    "paused",
                    verdict.summary,
                    only_from=["planned", "approved"],
                )

    async def _sent(self, item: Item, send: plan.Send, body: Mapping[str, Any]) -> None:
        kid = str(body["id"]) if item.kind == "create" else None
        async with self.engine.begin() as conn:
            await store.move(
                conn, item.table, item.id, "sent", None, kibana_case_id=kid, only_from=["sending"]
            )

    async def _after_error(
        self,
        item: Item,
        send: plan.Send,
        kid: str | None,
        exc: KibanaResponseError,
        report: RunReport,
    ) -> None:
        """Map an answer to a sent write onto the outbox's states. Nothing is sent again."""
        now = self.clock()
        why = f"{exc.reason}: {_why(exc)}"
        async with self.engine.begin() as conn:
            if isinstance(exc, KibanaNoChangeError):
                await store.move(conn, item.table, item.id, "sent", None, only_from=["sending"])
            elif exc.maybe_applied or isinstance(exc, UnknownOutcomeError | AnswerMismatchError):
                # Whatever came back, the write may have landed (a 2xx answer that cannot be
                # read or does not match is a case Kibana made all the same), and an answer
                # that never came from a connection that was never made is no proof either:
                # it is looked for, never sent again without a person's approval.
                if isinstance(exc, UnknownOutcomeError) and not exc.reached:
                    why = "no connection to Kibana was made, so the write cannot have landed"
                await self._doubt(conn, item.table, item.id, why)
                report.ambiguous += 1
                if isinstance(exc, AnswerMismatchError):
                    await self._flag_mismatch(conn, item, kid, why, now)
                    report.mismatches += 1
            elif isinstance(exc, KibanaConflictError):
                await store.move(
                    conn,
                    item.table,
                    item.id,
                    "conflict",
                    "Kibana: the case changed under the write (409); nothing was changed",
                    only_from=["sending"],
                )
                await store.audit(
                    conn,
                    "kibana.write.conflict",
                    item.case_id,
                    {"item": item.ledger_id},
                    outcome="failure",
                )
            else:
                reason = _refusal(exc)
                await store.move(conn, item.table, item.id, "paused", reason, only_from=["sending"])
                await store.audit(
                    conn,
                    "kibana.write.paused",
                    item.case_id,
                    {"item": item.ledger_id, "why": reason},
                    outcome="failure",
                )
        if isinstance(exc, KibanaNoChangeError):
            await self._verify(item, report, send)
        elif isinstance(exc, (KibanaAuthError, KibanaForbiddenError)):
            raise RunStopped(f"Kibana refused the writer key ({_why(exc)})")
        elif isinstance(exc, AnswerMismatchError):
            raise RunStopped(f"{item.write_class} is paused: {why}")
        elif isinstance(exc, UnknownOutcomeError) and not exc.reached:
            raise RunStopped("Kibana could not be reached: the write is looked for, not resent")

    async def _flag_mismatch(
        self, conn: Any, item: Item, kid: str | None, why: str, now: datetime
    ) -> None:
        """A 2xx answer that is not what the write should have produced: a finding for a person
        and an audit event, beside the looks that find the case the write may have made."""
        await store.finding_attention(
            conn,
            "answer_unexpected",
            item.case_id,
            kid,
            f"writer:{item.key}:{item.sent_count}",
            {"item": item.ledger_id, "why": why},
            now,
        )
        await store.audit(
            conn,
            "kibana.write.mismatch",
            item.case_id,
            {"item": item.ledger_id, "why": why},
            outcome="failure",
        )

    async def _verify(self, item: Item, report: RunReport, send: plan.Send | None) -> bool:
        """Read the case back: ``verified`` if Kibana holds what was written, else the row goes
        to ``conflict`` and the class pauses (a mismatch is not tolerated). A read that cannot be
        made leaves the row ``sent`` for the next run."""
        verdict = await self._readback(item)
        if verdict is None:
            return False
        ok, why = verdict
        kid = await self._kid(item)
        now = self.clock()
        async with self.engine.begin() as conn:
            if ok:
                if await store.move(
                    conn,
                    item.table,
                    item.id,
                    "verified",
                    None,
                    verified_at=now,
                    only_from=["sent", "ambiguous"],
                ):
                    await store.close_lookups(conn, item.subject, item.id, now)
                    await store.audit(
                        conn,
                        "kibana.write.verified",
                        item.case_id,
                        {
                            "item": item.ledger_id,
                            "class": item.write_class,
                            "kibana_case": kid,
                            "approval": item.approval_request_id,
                        },
                    )
                    if item.row is not None and item.row.op == "create":
                        await store.plan_attachments(conn, item.row)
                report.verified += 1
                return True
            await store.move(
                conn, item.table, item.id, "conflict", f"read-back: {why}", only_from=["sent"]
            )
            await store.finding_attention(
                conn,
                "answer_unexpected",
                item.case_id,
                kid,
                f"writer:{item.key}:readback",
                {"item": item.ledger_id, "why": why},
                now,
            )
            await store.audit(
                conn,
                "kibana.write.mismatch",
                item.case_id,
                {"item": item.ledger_id, "why": why},
                outcome="failure",
            )
        report.mismatches += 1
        await self._pause_class(item.write_class, f"read-back of {item.ledger_id}: {why}"[:200])
        raise RunStopped(
            f"{item.write_class} is paused: the read-back of {item.ledger_id} did not match"
        )

    async def _kid(self, item: Item) -> str | None:
        async with self.engine.connect() as conn:
            if item.row is not None and item.row.op == "create":
                row = await store.get_row(conn, item.id)
                found: str | None = (
                    await conn.execute(
                        text("SELECT kibana_case_id FROM kibana_outbox WHERE id = :i"),
                        {"i": item.id},
                    )
                ).scalar_one_or_none()
                del row
                return found
            if item.step is not None and item.step.kibana_case_id:
                return item.step.kibana_case_id
            return await store.kibana_case_of(conn, item.case_id)

    async def _readback(self, item: Item) -> tuple[bool, str] | None:
        """(matches, what differs) for a written item, or None when Kibana cannot be read."""
        try:
            return await self._compare(item)
        except RunStopped:
            return None

    async def _compare(self, item: Item) -> tuple[bool, str]:
        kid = await self._kid(item)
        if kid is None:
            return False, "Kibana never told ARGUS the case's id"
        if item.step is not None and item.step.kind == "attach":
            return await self._attached(kid, [a for a, _ in item.step.payload["alerts"]])
        live = await self._get(kid)
        if live is None:
            return False, "the Kibana case is not there"
        async with self.engine.connect() as conn:
            mirror = await store.mirror_facts(conn, item.case_id)
            ctx = await self._context(conn, item)
            outbox_id = (
                item.row.id
                if item.row is not None
                else (item.step.outbox_id if item.step is not None else None)
            )
            seen = await store.seen_of(conn, item.case_id, mirror, outbox_id)
        if live["created_by"].get("username") != self.author:
            return False, "the Kibana case was not made by ARGUS"
        if item.row is not None and item.row.op == "create":
            tags = item.row.payload.get("argus_tags", [])
            if not set(tags) <= set(live["tags"]):
                return False, "the case lacks ARGUS's tags"
            if live["settings"].get("syncAlerts") is not False:
                return False, "Sync alerts is on"
            return True, ""
        if item.kind == "comment" or (item.step is not None and item.step.kind.endswith("comment")):
            wanted = await self._comment_text(item, live)
            return (
                (True, "")
                if await self._has_comment(kid, wanted)
                else (False, "the comment is not there")
            )
        verdict = await self._replan(item, live, mirror, ctx, seen)
        if isinstance(verdict, plan.Skip):
            return True, ""
        if isinstance(verdict, plan.Send):
            return False, "Kibana does not show what was written"
        return False, f"cannot be checked ({verdict.reason})"

    async def _replan(
        self,
        item: Item,
        live: Mapping[str, Any],
        mirror: plan.MirrorFacts,
        ctx: render.Context,
        seen: plan.Seen,
    ) -> plan.Plan:
        if item.row is not None:
            return plan.plan_change(item.row, live, mirror, ctx, self.author, seen=seen)
        assert item.step is not None
        return plan.plan_change(
            _compensation_row(item.step),
            live,
            mirror,
            ctx,
            self.author,
            status_from=item.step.payload.get("status_from"),
            seen=seen,
        )

    async def _context(self, conn: Any, item: Item) -> render.Context:
        payload = item.row.payload if item.row else (item.step.payload if item.step else {})
        params = payload.get("params", {}) if isinstance(payload.get("params"), dict) else {}
        return await store.context(conn, self.link_base, item.approval_request_id, item.key, params)

    async def _comment_text(self, item: Item, live: Mapping[str, Any]) -> str:
        async with self.engine.connect() as conn:
            ctx = await self._context(conn, item)
        payload = item.row.payload if item.row else (item.step.payload if item.step else {})
        return render.comment(payload["template"], payload["params"], ctx)

    async def _get(self, kid: str) -> Mapping[str, Any] | None:
        try:
            result = await self.gateway.read(
                CaseGet(),
                CaseParams(case_id=kid),
                component=COMPONENT,
                deadline=self.clock() + READ_DEADLINE,
            )
        except KibanaNotFoundError:
            return None
        except (GatewayError, KibanaResponseError) as exc:
            raise RunStopped(f"Kibana cannot be read ({_why(exc)})") from None
        body: Mapping[str, Any] = result.body
        return body

    async def _has_comment(self, kid: str, wanted: str) -> bool:
        try:
            result = await self.gateway.read(
                CaseComments(),
                CasePageParams(case_id=kid, page=1, per_page=50, sort_order="desc"),
                component=COMPONENT,
                deadline=self.clock() + READ_DEADLINE,
            )
        except (GatewayError, KibanaResponseError) as exc:
            raise RunStopped(f"Kibana cannot be read ({_why(exc)})") from None
        return any(
            c.get("comment") == wanted
            and (c.get("created_by") or {}).get("username") == self.author
            for c in result.body["comments"]
        )

    async def _links(self, alert_ids: list[str]) -> dict[str, tuple[str, ...]]:
        """The case ids each of these alerts lists now (an alert listing none is absent)."""
        found: dict[str, tuple[str, ...]] = {}
        try:
            result = await self.es.run(
                AlertCaseLinks(),
                CaseLinksParams(alert_ids=tuple(alert_ids), size=100),
                purpose=Purpose.KIBANA_READ,
                component=COMPONENT,
                deadline=self.clock() + READ_DEADLINE,
            )
        except (GatewayError, KibanaResponseError) as exc:
            raise RunStopped(f"Elasticsearch cannot be read ({_why(exc)})") from None
        for link in parse_links(result.body)[0]:
            found[link.alert_id] = link.case_ids
        return found

    async def _attached(self, kid: str, alert_ids: list[str]) -> tuple[bool, str]:
        """Every alert lists the case now. The alerts index refreshes about once a second, so
        a read that finds one missing is made again (reads only) before it is called a miss."""
        missing: list[str] = alert_ids
        for attempt in range(READBACK_TRIES):
            links = await self._links(alert_ids)
            missing = [a for a in alert_ids if kid not in links.get(a, ())]
            if not missing:
                return True, ""
            if attempt + 1 < READBACK_TRIES:
                await self.sleep(READBACK_WAIT)
        return False, f"alerts that do not list the case: {', '.join(missing[:5])}"

    async def _work_step(
        self, step: store.Step, run: WriteRun | None, report: RunReport
    ) -> WriteRun | None:
        waits = Waits()
        while True:
            verdict, kid, live = await self._decide_step(step, dry=False)
            try:
                return await self._act(item_of_step(step), verdict, kid, live, run, report, waits)
            except Replan as again:
                run = again.run

    async def _decide_step(
        self, step: store.Step, *, dry: bool
    ) -> tuple[plan.Plan, str | None, Mapping[str, Any] | None]:
        async with self.engine.connect() as conn:
            kid = step.kibana_case_id or await store.kibana_case_of(conn, step.case_id)
            mirror = await store.mirror_facts(conn, step.case_id)
            ctx = await self._context(conn, item_of_step(step))
            seen = (
                await store.seen_of(conn, step.case_id, mirror, step.outbox_id)
                if step.kind == "compensate_update"
                else None
            )
        if kid is None:
            return plan.Hold("the case's create is not verified"), None, None
        live = await self._get(kid)
        problem = plan._live_problem(live, mirror, self.author)
        if problem is not None or live is None:
            return problem or plan.Hold("the Kibana case is gone"), kid, live
        if not _intact_step(step):
            return plan.Hold("the payload does not match its hash", "tamper"), kid, live
        verdict: plan.Plan
        if step.kind in ("comment", "compensate_comment"):
            verdict = plan.plan_comment(step.payload, live, ctx)
        elif step.kind == "compensate_update":
            verdict = plan.plan_change(
                _compensation_row(step), live, mirror, ctx, self.author,
                status_from=step.payload.get("status_from"), seen=seen,
            )  # fmt: skip
        else:
            verdict = await self._plan_attach(step, kid, live, dry=dry)
        return verdict, kid, live

    async def _plan_attach(
        self, step: store.Step, kid: str, live: Mapping[str, Any], *, dry: bool
    ) -> plan.Plan:
        """An attach of up to five alerts. Each must list fewer than ten cases before (Kibana's
        limit; the eleventh attach half-fails) and not this case already; a batch with such an
        alert is replaced by one without it."""
        pairs = [(a, i) for a, i in step.payload["alerts"]]
        links = await self._links([a for a, _ in pairs])
        kept, left = [], []
        for alert_id, index in pairs:
            listed = links.get(alert_id, ())
            if kid in listed:
                left.append(f"{alert_id} (already attached)")
            elif len(listed) >= 10:
                left.append(f"{alert_id} (lists {len(listed)} cases)")
            else:
                kept.append((alert_id, index))
        if left:
            if not dry:
                await self._replan_attach(step, kept, left)
            return plan.Skip("replanned without: " + ", ".join(left))
        return plan.plan_attach(kid, pairs, live)

    async def _replan_attach(
        self, step: store.Step, kept: list[tuple[str, str]], left: list[str]
    ) -> None:
        async with self.engine.begin() as conn:
            if kept and step.outbox_id is not None:
                last = (
                    await conn.execute(
                        text(
                            "SELECT max(seq) FROM kibana_steps"
                            " WHERE outbox_id = :o AND kind = 'attach'"
                        ),
                        {"o": step.outbox_id},
                    )
                ).scalar_one()
                await store.insert_step(
                    conn,
                    case_id=step.case_id,
                    outbox_id=step.outbox_id,
                    approval_request_id=None,
                    kind="attach",
                    seq=int(last) + 1,
                    key=f"{step.outbox_id}:attach:{int(last) + 1}",
                    write_class=step.write_class,
                    payload={"alerts": [list(p) for p in kept]},
                )

    async def _plan_attachments(self) -> None:
        """Attachments for cases whose create was verified in an earlier run (and the opening
        comment, if it was never planned): planned once, never again."""
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT o.id FROM kibana_outbox o JOIN cases c ON c.id = o.case_id"
                    " WHERE o.op = 'create' AND o.state = 'verified' AND c.state <> 'closed'"
                    " ORDER BY o.id"
                )
            )
            ids = [int(i) for i in rows.scalars()]
        for row_id in ids:
            async with self.engine.begin() as conn:
                row = await store.get_row(conn, row_id)
                if row is not None:
                    await store.plan_attachments(conn, row)

    async def apply_resends(self) -> list[str]:
        return await lookup.apply_resends(self)

    async def apply_compensations(self) -> list[str]:
        return await compensation.apply(self)

    async def run_lookups(self) -> None:
        await lookup.run_lookups(self)

    async def _approval_problem(self, conn: Any, request_id: int) -> str | None:
        request = await approvals.record(conn, request_id)
        if request is None:
            return "no such approval"
        return await approval.problem(conn, request, self.verifier, identity.UPDATE_CASE)


def _intact_step(step: store.Step) -> bool:
    from argus.cases import kibana as intent

    return intent.payload_hash(dict(step.payload)) == step.payload_hash


def _compensation_row(step: store.Step) -> plan.Row:
    """A compensating update, as the planner's row: its payload is the fields to restore (the
    step's own payload was checked against its hash before this)."""
    from argus.cases import kibana as intent

    fields = {k: v for k, v in step.payload.items() if k in ("status", "severity", "argus_tags")}
    return plan.Row(
        id=step.id,
        case_id=step.case_id,
        case_event_id=0,
        position=0,
        write_class="W2",
        op="update",
        payload=fields,
        payload_hash=intent.payload_hash(fields),
        idempotency_key=step.key,
        approval_request_id=step.approval_request_id,
        state=step.state,
        sent_count=step.sent_count,
        from_state=None,
        to_state="",
    )


def _why(exc: BaseException) -> str:
    return render.clean(f"{type(exc).__name__}: {exc}", 160)


def _refusal(exc: KibanaResponseError) -> str:
    if isinstance(exc, KibanaNotFoundError):
        return "Kibana: the case is gone (404); nothing was changed"
    if isinstance(exc, KibanaAuthError):
        return "Kibana did not accept the writer key (401); nothing was changed"
    if isinstance(exc, KibanaForbiddenError):
        return "Kibana: the writer key may not do this (403); nothing was changed"
    return f"Kibana refused the request ({exc.status}); nothing was changed"
