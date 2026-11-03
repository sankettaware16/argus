"""The alert status sender (Q-D5, R17 v2, D-061 to D-063, plan §5 and §7.10, DQ8, DQ11).

It drains ``writeback_outbox`` (planned by :mod:`argus.writeback`) through Q-D2's Kibana lane:
the template ``alerts.status`` of class WA (a Kibana-lane write, ``KibanaGateway.write``), and the
Elasticsearch gateway's ``alerts.mget`` (``Gateway.run``) for the reads. For each batch of one
row, in this order:

1. check the row (below), wait out the gap since the last alert call (≥ 60 s, shared with W1's
   attaches), check the kill switch, NORMAL health (disk under 85 %, no block) and the write
   window;
2. read the alerts (``alerts.mget``): one already at the status, or gone, is counted without a
   request; the others' **previous statuses are kept** on the row before the request leaves;
   the reading, and every check of the row, is made **again at the last step before the request
   leaves** (the gateway's ``before_send``, in the transaction that keeps the previous statuses):
   a newer review, a reopened case, an operator check that has grown old or an alert a person
   changed in the meantime sends nothing and the row is skipped, left waiting or planned anew;
3. send one status call of at most ``status_per_call`` alerts, once. The gateway checks the
   update_by_query body Kibana answers with (no failures, no conflicts, every alert named updated:
   ``models.check_alert_status``) and **pauses the class on any mismatch**;
4. read the alerts back; only alerts the read-back shows at the status count as written. After a
   timeout, a 5xx or a refusal that may have landed, the read-back decides what happened;
5. move ``sent_count`` (the row's position) and ``written_count`` in one transaction, with an
   audit row. A batch that did not fully land leaves the row where it was, paused: the next run
   reads the alerts first, so what landed late is counted and nothing is written twice.

The check of a row reads its sources, not the row: its newest decision (``review_events``), the
author's kind (``users``), the ELK check behind the review (``kibana_ok``) and Q-F1's verdict
(:func:`argus.writeback.standing`); the stored flags are only a cache that this module fills in.
An error from Kibana ends the run (a 429 never retried); alerts that cannot be read skip their
row for this run only. One run at a time, and never beside a case
writer's run: it holds the writer's advisory lock, so a W1 attach and a status call never go at
once. A row made without an alert-write check (``needs_operator``) is sent only when the run has
an operator whose own ELK account was checked live, at most ``OPERATOR_FRESH`` ago.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback
from argus.collector.store import split_source
from argus.config.settings import Settings
from argus.gateway import health as health_core
from argus.gateway.builtin import AlertsMget, MgetParams
from argus.gateway.errors import GatewayError, RefusedError
from argus.gateway.gateway import Gateway, utcnow
from argus.gateway.health import HealthState
from argus.gateway.kibana import selftest, writes
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaResponseError,
    UnknownOutcomeError,
    WriteRefusedError,
)
from argus.gateway.kibana.gateway import KibanaGateway, WriteContext, WriteRun
from argus.gateway.kibana.models import AlertStatusChange
from argus.gateway.kibana.templates import KeyRole, SetAlertStatus
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.templates import Purpose
from argus.identity.lane import Checked
from argus.web.capabilities import Capability
from argus.writeback import FIRST_RUN, WritebackRefused
from argus.writer import store

log = logging.getLogger("argus.writeback")

COMPONENT = "writeback"  # the kill switch's component too (``argus siem stop --component``)
GAP_WAIT = timedelta(seconds=61)  # alert calls are 60 s apart
READ_DEADLINE = timedelta(minutes=2)
WRITE_DEADLINE = timedelta(minutes=5)
RUN_REFRESH = timedelta(minutes=20)  # a run's Kibana status counts 30 minutes
READBACK_TRIES = 3  # the alerts index refreshes about once a second
READBACK_WAIT = 2.0
GAP_TRIES = 3  # another process may take the gap between our wait and our request
OPERATOR_FRESH = timedelta(minutes=30)
UNREADABLE_ROWS = 3  # rows whose alerts could not be read, per run, before the run ends
AUDIT_TARGET = "writeback"


@dataclass(frozen=True)
class Operator:
    """The person at the terminal, signed in with their own ELK account and checked live (the
    identity lane): the one who vouches for rows made without an alert-write check."""

    username: str
    argus_uid: str
    checked_at: datetime


@dataclass
class RunResult:
    sent_alerts: int = 0  # alerts this run's requests changed and the read-back confirmed
    credited_alerts: int = 0  # alerts an earlier call of ours changed (found at the status)
    unreadable_rows: int = 0  # rows left for the next run: their alerts could not be read
    sent_rows: int = 0  # rows that reached ``sent``
    skipped_alerts: int = 0  # already at the status, or gone, so not sent
    calls: int = 0  # status calls made
    paused: str | None = None
    waiting: list[str] = field(default_factory=list)  # rows left for an operator or an audit

    def lines(self) -> list[str]:
        out = [
            f"{self.sent_alerts} alerts changed in {self.calls} calls, {self.credited_alerts}"
            f" found changed by an earlier call, {self.skipped_alerts} not needed,"
            f" {self.sent_rows} rows finished"
        ]
        out += [f"  waiting: {why}" for why in self.waiting]
        if self.paused:
            out.append(f"  stopped: {self.paused}")
        return out


@dataclass(frozen=True)
class Row:
    id: int
    status: str
    alert_ids: tuple[str, ...]
    sent_count: int
    written_count: int
    state: str
    review_id: int | None
    investigation_id: Any
    case_id: Any
    closure_request_id: int | None
    previous: Mapping[str, str]


@dataclass(frozen=True)
class Step:
    spent: int = 0  # alerts written, against the run's budget
    done: bool = False  # the row has nothing left (or is not for this run)
    stop: bool = False  # the run ends


MORE, DONE, STOP = Step(), Step(done=True), Step(stop=True)


class _Undecided(Exception):  # noqa: N818 - the read-back could not be made
    pass


class _Hold(Exception):  # noqa: N818 - raised at the last step before a request: send nothing
    """Why a row (or its alerts) must not go out as planned. ``kind``: ``gone`` (no longer ours
    to move), ``skip`` (not wanted any more), ``wait`` (needs an operator or the audit),
    ``unreadable`` (the alerts could not be read), ``changed`` (an alert changed since it was
    read: plan the batch anew)."""

    def __init__(self, kind: str, why: str) -> None:
        super().__init__(why)
        self.kind = kind
        self.why = why


def operator_of(checked: Checked) -> Operator:
    """The operator from a live check of their own ELK account (the identity lane). Refused
    unless the check showed the alert-status privileges: a person who may not change alert
    status in Kibana cannot vouch for anyone's review."""
    if Capability.REVIEW not in checked.access.capabilities:
        raise WritebackRefused(
            f"{checked.identity.username} may not change alert status in Kibana (no 'review'"
            " in the live check): they cannot send earlier reviews"
        )
    return Operator(
        checked.identity.username, checked.identity.argus_uid, checked.access.checked_at
    )


class AlertSender:
    def __init__(
        self,
        engine: AsyncEngine,
        gateway: KibanaGateway,
        *,
        es: Gateway,
        run_limit: int = 50,
        f1_audited: bool = False,
        operator: Operator | None = None,
        accepted_residual: Iterable[str] = (),
        key_selftest: bool = True,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.engine = engine
        self.gateway = gateway
        self.es = es
        self.run_limit = run_limit
        self.f1_audited = f1_audited
        self.operator = operator
        self.accepted_residual = tuple(accepted_residual)
        self.key_selftest = key_selftest
        self.clock = clock
        self.sleep = sleep
        self._key_checked = False
        self._run: WriteRun | None = None

    # ------------------------------------------------------------------ a run

    async def run(self) -> RunResult:
        """Send what is planned (see the module docstring). Raises ``WritebackRefused`` if
        another writer or write-back run holds the lock."""
        result = RunResult()
        async with self.engine.connect() as holder:
            got = (
                await holder.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": store.LOCK_KEY})
            ).scalar()
            await holder.commit()
            if not got:
                raise WritebackRefused("another writer or write-back run is in progress")
            try:
                problems = [] if (why := await self.gate()) else await self.preflight()
                if why:
                    result.paused = why
                elif problems:
                    kind = (
                        "could not be checked"
                        if "could not be made" in problems[0]
                        else "failed its self-test"
                    )
                    result.paused = f"the alert writer key {kind}: " + "; ".join(problems)
                else:
                    await self._send_all(result)
            finally:
                await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
                await holder.commit()
        return result

    async def preflight(self) -> list[str]:
        """The alert writer key holds what it must and none of what it must not (once)."""
        if self._key_checked or not self.key_selftest:
            return []
        try:
            _, verdict = await selftest.run_selftest(
                self.gateway, KeyRole.ALERTS, deadline=self.clock() + READ_DEADLINE,
                accepted_residual=self.accepted_residual, component=COMPONENT,
            )  # fmt: skip
        except (GatewayError, KibanaResponseError) as exc:
            return [f"the self-test could not be made ({_why(exc)})"]
        if not verdict.problems:
            self._key_checked = True
        return list(verdict.problems)

    async def _send_all(self, result: RunResult) -> None:
        async with self.engine.connect() as conn:
            ever = (
                await conn.execute(
                    text("SELECT 1 FROM writeback_outbox WHERE written_count > 0 LIMIT 1")
                )
            ).first()
            ids = (
                (
                    await conn.execute(
                        # the oldest decision first, so the newest has the last word on an alert
                        # both a review and a closure name
                        text(
                            "SELECT w.id FROM writeback_outbox w"
                            " LEFT JOIN review_events e ON e.id = w.review_id"
                            " LEFT JOIN cases c ON c.id = w.case_id"
                            " WHERE w.state IN ('planned', 'paused')"
                            " ORDER BY coalesce(e.created_at, c.closed_at), w.id"
                        )
                    )
                )
                .scalars()
                .all()
            )
        budget = min(FIRST_RUN, self.run_limit) if ever is None else self.run_limit
        for row_id in ids:
            while budget > 0:
                step = await self._once(row_id, budget, result)
                budget -= step.spent
                if step.stop:
                    return
                if step.done:
                    break
            if budget <= 0:
                return

    # ------------------------------------------------------------------ one call

    async def gate(self) -> str | None:
        """Why nothing may be sent now, or None. The lane asks the same again before each
        request; this is the sender's own, plain-spoken check: the kill switch, the SIEM NORMAL
        (disk under 85 %, no index block, no overload) and the write window."""
        now = self.clock()
        if (await self.gateway.state.switches()).blocks(COMPONENT):
            return "stopped by the kill switch"
        memory = health_core.effective(
            await self.gateway.state.health(), now, self.gateway.health_config
        )
        if memory.state is not HealthState.NORMAL:
            reasons = ", ".join(memory.reasons) or "not healthy"
            return f"the SIEM is {memory.state.value} ({reasons}): write-back waits"
        for name, peek in (
            ("Kibana", self.gateway.state.kibana_breaker_peek),
            ("siem", self.gateway.state.breaker_peek),
        ):
            ok, until = await peek(now)
            if not ok:
                when = f" until {until:%H:%M} UTC" if until else ""
                return f"{name}'s breaker is open{when}: write-back waits"
        if (stopped := (await self.gateway.state.kibana_lane()).stopped) is not None:
            return f"Kibana work is stopped ({stopped})"
        if not writes.in_window(now, self.gateway.caps):
            return "outside the write window"
        return None

    async def _once(self, row_id: int, budget: int, result: RunResult) -> Step:
        why = await self.gate()
        if why is not None:
            result.paused = why
            return STOP
        async with self.engine.connect() as conn:
            row = await self._row(conn, row_id)
            if row is None or row.state not in ("planned", "paused"):
                return DONE
            hold = await self._standing(conn, row)
        if hold is not None:
            return await self._held(row, hold, result)
        left = row.alert_ids[row.sent_count :]
        if not left:
            await self._finish(row, "sent", None)
            result.sent_rows += 1
            return DONE
        batch = left[: max(1, min(self.gateway.caps.status_per_call, budget))]
        for attempt in range(GAP_TRIES):
            try:
                await self._wait_gap()
                indexes = await self._indexes(batch)
                current = await self._statuses(batch, indexes)
            except (GatewayError, KibanaResponseError) as exc:
                return await self._held(
                    row, _Hold("unreadable", f"the alerts could not be read ({_why(exc)})"), result
                )
            todo = [a for a in batch if current[a] is not None and current[a] != row.status]
            # at the status already, and we had meant to change it (its previous status is kept):
            # an earlier call of ours landed late, or its read-back was never made
            earlier = sum(1 for a in batch if current[a] == row.status and a in row.previous)
            if not todo:  # all there already, or gone: no request
                return await self._account(row, len(batch), 0, earlier, result)
            try:
                run = await self._started()
            except (GatewayError, KibanaResponseError) as exc:
                result.paused = (
                    f"Kibana's status or the licence could not be checked ({_why(exc)}):"
                    " nothing was sent"
                )[:300]
                return STOP
            try:
                await self._write(row, run, todo, {a: str(current[a]) for a in todo}, indexes)
            except _Hold as stop:
                if stop.kind == "changed" and attempt + 1 < GAP_TRIES:
                    continue  # read the alerts anew (the lane's gap makes the next try wait)
                if stop.kind == "changed":
                    stop = _Hold("unreadable", "the alerts kept changing under the sender")
                return await self._held(row, stop, result)
            except WriteRefusedError as exc:  # nothing left
                if exc.reason == "alert_gap" and attempt + 1 < GAP_TRIES:
                    continue
                await self._forget(row, todo)
                result.paused = f"waits ({exc.reason}): {exc}"[:300]
                return STOP
            except RefusedError as exc:  # the lane said no before anything left
                await self._forget(row, todo)
                result.paused = f"nothing was sent: {exc}"[:300]
                return STOP
            except KibanaResponseError as exc:
                return await self._failed(row, batch, todo, indexes, earlier, exc, result)
            result.calls += 1
            return await self._landed(row, batch, todo, indexes, earlier, result)
        result.paused = "the gap between alert calls kept being taken: nothing was sent"
        return STOP

    async def _held(self, row: Row, hold: _Hold, result: RunResult) -> Step:
        """A row that may not go out now: skipped for good, left for an operator or the audit, or
        left for the next run because its alerts could not be read."""
        if hold.kind == "skip":
            await self._finish(row, "skipped", hold.why)
        elif hold.kind == "wait":
            result.waiting.append(hold.why)
        elif hold.kind == "unreadable":
            result.waiting.append(f"row {row.id}: {hold.why}: nothing was sent")
            result.unreadable_rows += 1
            if result.unreadable_rows >= UNREADABLE_ROWS:
                result.paused = f"the alerts of {UNREADABLE_ROWS} rows could not be read"
                return STOP
        return DONE

    # ------------------------------------------------------------------ outcomes

    async def _landed(
        self,
        row: Row,
        batch: Sequence[str],
        todo: Sequence[str],
        indexes: Mapping[str, str],
        earlier: int,
        result: RunResult,
    ) -> Step:
        """Kibana answered cleanly: the read-back still decides what counts."""
        try:
            seen = await self._read_back(todo, row.status, indexes)
        except (GatewayError, KibanaResponseError, _Undecided) as exc:
            why = f"the read-back could not be made ({_why(exc)}): the next run reads first"
            return await self._pause(row, why, result)
        wrong = [a for a in todo if seen.get(a) != row.status]
        if wrong:
            why = f"read-back: {len(wrong)} of {len(todo)} alerts do not show {row.status}"
            await self._pause_class(why)
            return await self._pause(row, why, result)
        return await self._account(row, len(batch), len(todo), earlier, result)

    async def _failed(
        self,
        row: Row,
        batch: Sequence[str],
        todo: Sequence[str],
        indexes: Mapping[str, str],
        earlier: int,
        exc: KibanaResponseError,
        result: RunResult,
    ) -> Step:
        """Kibana refused, did not answer or answered wrongly. The run ends either way; if the
        request may have landed, the read-back decides how much of it counts."""
        if isinstance(exc, UnknownOutcomeError):
            how = f"Kibana did not answer ({exc.reason}{', timed out' if exc.timed_out else ''})"
        elif isinstance(exc, AnswerMismatchError):
            how = f"{exc} (the class is paused)"
        elif exc.status is not None:
            how = f"Kibana answered {exc.status}"
        else:
            how = f"Kibana's answer was refused ({exc.reason})"
        reached = exc.maybe_applied and not (
            isinstance(exc, UnknownOutcomeError) and not exc.reached
        )
        if not reached:  # nothing changed: the statuses kept for it were never overwritten
            await self._forget(row, todo)
        seen: Mapping[str, str | None] | None = None
        if reached:
            try:
                seen = await self._statuses(todo, indexes, Purpose.KIBANA_READ)
            except (GatewayError, KibanaResponseError):
                seen = None
        if seen is not None and all(seen.get(a) == row.status for a in todo):
            result.paused = f"{how}: paused, nothing retried; the read-back shows it landed"
            await self._account(row, len(batch), len(todo), earlier, result)
            return STOP
        tail = "paused, nothing retried"
        if reached:
            tail += (
                "; the read-back could not be made"
                if seen is None
                else f"; {sum(seen.get(a) == row.status for a in todo)} of {len(todo)}"
                " alerts show the new status"
            )
        return await self._pause(row, f"{how}: {tail}", result)

    async def _account(
        self, row: Row, n_batch: int, changed: int, credited: int, result: RunResult
    ) -> Step:
        """Move the row past this batch (one transaction, with its audit row). ``changed``:
        alerts this run's request changed; ``credited``: alerts found at the status that an
        earlier call of ours (its previous statuses are kept) had meant to change."""
        written = changed + credited
        skipped = n_batch - written
        sent = row.sent_count + n_batch
        done = sent == len(row.alert_ids)
        now = self.clock()
        async with self.engine.begin() as conn:
            now_standing = await writeback.standing(
                conn, review_id=row.review_id, investigation_id=row.investigation_id,
                case_id=row.case_id,
            )  # fmt: skip
            needs = now_standing is not None and now_standing.needs_operator
            who = self.operator.username if needs and self.operator else None
            moved = (
                await conn.execute(
                    text(
                        "UPDATE writeback_outbox SET sent_count = :s, written_count ="
                        " written_count + :w, state = :st, sent_at = CASE WHEN :done THEN"
                        " CAST(:t AS timestamptz) ELSE sent_at END, error = NULL,"
                        " operator = coalesce(CAST(:op AS text), operator), needs_operator = :n,"
                        " held = CAST(:h AS text) WHERE id = :i AND state IN ('planned', 'paused')"
                    ),
                    {
                        "s": sent,
                        "w": written,
                        "st": "sent" if done else "planned",
                        "done": done,
                        "t": now,
                        "op": who,
                        "n": who is not None,
                        "h": now_standing.held if now_standing else None,
                        "i": row.id,
                    },
                )
            ).rowcount == 1  # a plan may have skipped the row meanwhile: it stays skipped
            await store.audit(
                conn,
                "writeback.batch",
                str(row.id),
                {
                    "status": row.status,
                    "alerts": n_batch,
                    "written": written,
                    "credited": credited,
                    "skipped": skipped,
                    "position": sent,
                    "of": len(row.alert_ids),
                    "operator": who,
                    "moved": moved,
                },
                target_type=AUDIT_TARGET,
            )
        result.sent_alerts += changed
        result.credited_alerts += credited
        result.skipped_alerts += skipped
        if done and moved:
            result.sent_rows += 1
        return Step(spent=changed, done=done or not moved)

    async def _pause(self, row: Row, why: str, result: RunResult) -> Step:
        result.paused = why
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE writeback_outbox SET state = 'paused', error = :e WHERE id = :i"
                    " AND state IN ('planned', 'paused')"
                ),
                {"e": why[:500], "i": row.id},
            )
            await store.audit(
                conn, "writeback.paused", str(row.id), {"why": why[:300]}, target_type=AUDIT_TARGET,
                outcome="failure",
            )  # fmt: skip
        return STOP

    async def _pause_class(self, why: str) -> None:
        """A read-back that disagrees with a clean answer pauses WA like a wrong answer does."""
        await self.gateway.state.kibana_change(
            lambda state: (None, writes.pause(state, WriteClass.WA, why))
        )

    async def _finish(self, row: Row, state: str, why: str | None) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE writeback_outbox SET state = :s, error = :e,"
                    " sent_at = CASE WHEN :s = 'sent' THEN CAST(:t AS timestamptz) ELSE sent_at"
                    " END WHERE id = :i AND state IN ('planned', 'paused')"
                ),
                {"s": state, "e": why, "t": self.clock(), "i": row.id},
            )

    # ------------------------------------------------------------------ the request

    async def _write(
        self,
        row: Row,
        run: WriteRun,
        todo: Sequence[str],
        seen: Mapping[str, str],
        indexes: Mapping[str, str],
    ) -> None:
        template = SetAlertStatus()
        params = AlertStatusChange(signal_ids=tuple(todo), status=row.status)  # type: ignore[arg-type]
        context = WriteContext(
            WriteClass.WA,
            f"writeback-{row.id}-{row.sent_count}",
            self.gateway.payload_hash(template, params),
        )

        async def last_look() -> None:
            """The last step before the request leaves: the alerts and the row's standing are
            looked at again (the lane's place and the lease wait came after the first look), and
            only then the statuses to restore are kept, in the same transaction."""
            # D-022's pool lets one non-collector lane hold a lease at a time and the write
            # lane's is held already, so this look is the collector's (a light mget, the same
            # read as the reconciler's)
            try:
                now = await self._statuses(todo, indexes, Purpose.RECONCILE)
            except (GatewayError, KibanaResponseError) as exc:
                raise _Hold("unreadable", f"the alerts could not be read ({_why(exc)})") from exc
            async with self.engine.begin() as conn:
                if (hold := await self._standing(conn, row)) is not None:
                    raise hold
                if any(now.get(a) != seen[a] for a in todo):
                    raise _Hold("changed", "an alert changed after it was read")
                await conn.execute(
                    text(
                        "UPDATE writeback_outbox SET previous = previous || CAST(:p AS jsonb)"
                        " WHERE id = :i AND state IN ('planned', 'paused')"
                    ),  # the status just read wins over one kept by an attempt that changed nothing
                    {"p": json.dumps(dict(seen)), "i": row.id},
                )

        await self.gateway.write(
            template, params, run=run, context=context,
            component=COMPONENT, deadline=self.clock() + WRITE_DEADLINE,
            before_send=last_look,
        )  # fmt: skip

    async def _forget(self, row: Row, todo: Sequence[str]) -> None:
        """The request did not reach Kibana, or was refused before it changed anything: the
        statuses kept for it (not those of an earlier attempt that may still land) were never
        overwritten, so they must not later pass for ARGUS's own changes."""
        fresh = [a for a in todo if a not in row.previous]
        if not fresh:
            return
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE writeback_outbox SET previous = previous - CAST(:k AS text[])"
                    " WHERE id = :i AND state IN ('planned', 'paused')"
                ),
                {"k": fresh, "i": row.id},
            )

    async def _started(self) -> WriteRun:
        """Kibana's version, status and the licence, checked before the run's first write and
        again once they are older than ``RUN_REFRESH``."""
        if self._run is None or self.clock() - self._run.checked_at > RUN_REFRESH:
            self._run = await self.gateway.start_run(
                component=COMPONENT, deadline=self.clock() + READ_DEADLINE
            )
        return self._run

    async def _wait_gap(self) -> None:
        """Wait until the lane's last alert call (ours, or a W1 attach by another process) is
        more than 60 s ago."""
        last = (await self.gateway.state.kibana_lane()).counters.last_alert_call
        if last is not None:
            wait = (last + GAP_WAIT - self.clock()).total_seconds()
            if wait > 0:
                await self.sleep(wait)

    # ------------------------------------------------------------------ reads

    async def _indexes(self, ids: Sequence[str]) -> dict[str, str]:
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    'SELECT alert_id, "index" AS alert_index FROM alert_records'
                    " WHERE alert_id = ANY(:a)"
                    " AND source_missing_at IS NULL"
                ),
                {"a": list(ids)},
            )
            return {r.alert_id: r.alert_index for r in rows}

    async def _statuses(
        self, ids: Sequence[str], indexes: Mapping[str, str], purpose: Purpose = Purpose.WRITEBACK
    ) -> dict[str, str | None]:
        """Each alert's workflow status in Elasticsearch now (``alerts.mget``); None for one
        that is gone, or no longer in ARGUS's records."""
        found: dict[str, str | None] = dict.fromkeys(ids)
        by_index: dict[str, list[str]] = defaultdict(list)
        for alert_id in ids:
            if alert_id in indexes:
                by_index[indexes[alert_id]].append(alert_id)
        for index, group in sorted(by_index.items()):
            answer = await self.es.run(
                AlertsMget(), MgetParams(index=index, ids=tuple(group)),
                purpose=purpose, component=COMPONENT, deadline=self.clock() + READ_DEADLINE,
            )  # fmt: skip
            for doc in answer.body["docs"]:
                source = doc.get("_source")
                if doc.get("found") and isinstance(source, Mapping) and doc.get("_id") in found:
                    found[doc["_id"]] = split_source(source)[2] or "open"
        return found

    # The read after a write (its read-back, and the look after an error) is the Kibana read
    # lane's, not the write lane's: a timeout charges the write lane its whole 15 s, and the
    # read that says what happened must not wait that out; it also goes on when the SIEM is in
    # CAUTION or DEGRADED, when no new write may start.
    async def _read_back(
        self, ids: Sequence[str], status: str, indexes: Mapping[str, str]
    ) -> dict[str, str | None]:
        seen: dict[str, str | None] = {}
        for attempt in range(READBACK_TRIES):
            seen = await self._statuses(ids, indexes, Purpose.KIBANA_READ)
            if all(seen.get(a) == status for a in ids):
                break
            if attempt + 1 < READBACK_TRIES:
                await self.sleep(READBACK_WAIT)
        return seen

    # ------------------------------------------------------------------ the row

    async def _row(self, conn: Any, row_id: int) -> Row | None:
        found = (
            await conn.execute(
                text(
                    "SELECT id, status, alert_ids, sent_count, written_count, state,"
                    " review_id, investigation_id, case_id,"
                    " closure_request_id, previous FROM writeback_outbox WHERE id = :i"
                ),
                {"i": row_id},
            )
        ).first()
        if found is None:
            return None
        return Row(
            found.id, found.status, tuple(found.alert_ids), found.sent_count, found.written_count,
            found.state, found.review_id, found.investigation_id, found.case_id,
            found.closure_request_id, dict(found.previous),
        )  # fmt: skip

    async def _standing(self, conn: Any, row: Row) -> _Hold | None:
        """Why the row may not go out now, or None. Read from the sources every time (the row's
        stored flags are never trusted): still ours to move, still the newest decision (a case
        still closed by its approval), written by a person, an operator whose own check is fresh
        for a review made without an alert-write check, the audit of Q-F1 for a verdict that
        rests on it."""
        state = (
            await conn.execute(
                text("SELECT state FROM writeback_outbox WHERE id = :i"), {"i": row.id}
            )
        ).scalar_one_or_none()
        if state not in ("planned", "paused"):
            return _Hold("gone", f"row {row.id} is {state}")
        if (stale := await self._superseded(conn, row)) is not None:
            return _Hold("skip", stale)
        now = await writeback.standing(
            conn, review_id=row.review_id, investigation_id=row.investigation_id,
            case_id=row.case_id,
        )  # fmt: skip
        if now is None:
            return _Hold("skip", "the decision it was made from cannot be found")
        if not now.person:
            return _Hold("skip", "its author is not a person")
        if now.needs_operator and not self._operator_fresh():
            return _Hold("wait", f"row {row.id} needs an operator signed in with their own account")
        if now.held is not None and not self.f1_audited:
            return _Hold("wait", f"row {row.id} waits for the audit of Q-F1 ({now.held})")
        return None

    async def _superseded(self, conn: Any, row: Row) -> str | None:
        """Why the row is no longer wanted: a newer decision on its investigation, or its case
        reopened. Looked at before each batch and again before each request, so a plan made
        hours ago does not outlive them."""
        if row.review_id is not None:
            newest = (
                await conn.execute(
                    text(
                        "SELECT max(id) FROM review_events WHERE investigation_id = :i"
                        " AND (action = 'follow_up' OR (action = 'reviewed'"
                        " AND outcome IS NOT NULL))"
                    ),
                    {"i": row.investigation_id},
                )
            ).scalar_one()
            return None if newest == row.review_id else f"superseded by review {newest}"
        open_ = (
            await conn.execute(
                text(
                    "SELECT 1 FROM cases WHERE id = :c AND state = 'closed'"
                    " AND closure_request_id = :r"
                ),
                {"c": row.case_id, "r": row.closure_request_id},
            )
        ).first()
        return None if open_ is not None else "the case was reopened"

    def _operator_fresh(self) -> bool:
        return (
            self.operator is not None and self.clock() - self.operator.checked_at <= OPERATOR_FRESH
        )


def _why(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc)[:120]}"


def problems_of(settings: Settings, now: datetime) -> list[str]:
    """What stops a real run at this host (the lane still checks the window, health and caps)."""
    k = settings.kibana
    out: list[str] = []
    if not settings.writeback.enabled:
        out.append("writeback.enabled is false (D-061: the user switches it on)")
    if not k.enabled:
        out.append("kibana.enabled is false")
    if "WA" not in k.write_classes:
        out.append("WA is not switched on at this host (kibana.write_classes)")
    key, expires = k.alert_writer_api_key, k.alert_writer_api_key_expires
    if key is None or not key.get_secret_value():
        out.append("the alert writer's key is not installed (kibana.alert_writer_api_key)")
    elif expires is None:
        out.append(
            "no expiry is recorded for the alert writer's key"
            " (ARGUS_KIBANA__ALERT_WRITER_API_KEY_EXPIRES)"
        )
    elif expires < now.date():
        out.append(f"the alert writer's key expired on {expires}: mint a new one")
    return out
