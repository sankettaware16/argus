"""The pass (``argus notices run``) and what a person asks about it.

One pass: (1) read the conditions (:mod:`argus.notices.triggers`) and the table's rows; (2)
:func:`argus.notices.model.reconcile` what to store and which notices are due; (3) store, always,
even when notices are off; (4) when switched on (``enabled``, a recipient, a relay), give the hour's
room (10 e-mails, counted from the audit trail) to the due notices, send them in one connection and
mark and audit each one **as soon as the relay has taken it**, so a pass killed halfway has recorded
everything it took; (5) one ``notice.run`` audit row. A notice not sent is due again at the next
pass; a crash between send and mark can send one twice, never none. Passes do not overlap (a session
lock); without a switch, recipient or relay the pass prints what it would send and sends nothing."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any, Literal, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from argus.config.settings import Settings
from argus.db.audit import record_audit
from argus.notices import mail, render
from argus.notices.address import parse_address
from argus.notices.model import (
    KINDS,
    MAX_PER_HOUR,
    Allocation,
    Intent,
    Reconciled,
    Row,
    allocate,
    reconcile,
    worst,
)
from argus.notices.triggers import Found

log = logging.getLogger("argus.notices")

ACTOR = "system"
LOCK_KEY = int.from_bytes(b"ARGUSNTC", "big")  # one pass at a time
NOT_ON = "not switched on, by your choice"
OnResult = mail.AsyncOnResult


class Deliver(Protocol):
    """The relay's door (:func:`argus.notices.mail.send`): it calls ``on_result`` after each
    message, before it sends the next."""

    def __call__(
        self,
        relay: mail.Relay,
        sender: str,
        recipients: Sequence[str],
        messages: Sequence[EmailMessage],
        on_result: OnResult | None = None,
    ) -> Awaitable[list[mail.Delivery]]: ...


class Refused(Exception):  # noqa: N818 - a refusal, said in words (as CaseRefused)
    """A command that cannot go on, with the words a person reads."""


@dataclass(frozen=True)
class Config:
    """What the pass needs of the settings. ``why_not`` says in words why nothing is sent."""

    enabled: bool
    recipients: tuple[str, ...]
    relay: mail.Relay | None
    sender: str | None
    base: str
    host: str | None = None
    port: int = 25

    @property
    def why_not(self) -> str | None:
        if not self.enabled:
            return NOT_ON
        if not self.recipients:
            return "switched on, but no recipient is named (notices.recipients)"
        if self.relay is None or self.sender is None:
            return "switched on, but the relay is incomplete (notices.relay_host, relay_from)"
        return None

    @property
    def sends(self) -> bool:
        return self.why_not is None


def config_of(settings: Settings) -> Config:
    n = settings.notices
    relay = None
    if n.relay_host is not None and n.relay_from is not None:
        relay = mail.Relay(
            n.relay_host,
            n.relay_port,
            n.relay_starttls,
            n.user,
            None if n.password is None else n.password.get_secret_value(),
        )
    return Config(
        n.enabled,
        n.recipients,
        relay,
        n.relay_from,
        n.link_base(settings.web),
        n.relay_host,
        n.relay_port,
    )


@dataclass
class Report:
    """What a pass found and did, in numbers and plain lines."""

    mode: Literal["sent", "not_on", "dry_run"] = "not_on"
    why_not: str | None = None
    conditions: int = 0
    inserted: int = 0
    updated: int = 0
    resolved: int = 0
    due: int = 0
    deferred: int = 0
    sent: int = 0
    folded: int = 0
    failed: int = 0
    busy: bool = False  # another pass holds the lock: this one did nothing (not an error)
    unreadable: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


# When an audit row of the notices happened: the pass's own clock (``details.at``, which is the
# database's clock in production and the test's in a test), else the row's time.
WHEN = "coalesce(CAST(details ->> 'at' AS timestamptz), occurred_at)"

_ROWS = text(
    "SELECT id, kind, subject, severity, count, first_seen, last_seen, resolved_at, sent_at,"
    " sent_severity, notified, ended_at FROM notices WHERE resolved_at IS NULL"
    " OR (kind = 'outage' AND sent_at IS NOT NULL AND ended_at IS NULL) ORDER BY id"
)


def _row(r: Any) -> Row:
    return Row(
        int(r.id),
        r.kind,
        r.subject,
        r.severity,
        int(r.count),
        r.first_seen,
        r.last_seen,
        r.resolved_at,
        r.sent_at,
        r.sent_severity,
        int(r.notified),
        r.ended_at,
    )


async def load_rows(conn: AsyncConnection) -> tuple[list[Row], list[Row]]:
    """The unresolved rows, and the resolved outages announced and not yet ended."""
    rows = [_row(r) for r in await conn.execute(_ROWS)]
    return (
        [r for r in rows if r.resolved_at is None],
        [r for r in rows if r.resolved_at is not None],
    )


async def sent_last_hour(conn: AsyncConnection, now: datetime) -> int:
    """E-mails that went to the relay in the last hour, from the audit trail: each ``notice.sent``
    and ``notice.folded`` is one, and so is each ``notice.send_failed`` of a message that was
    tried (a relay can take a message and still fail it, so a failure counts: the hour's limit
    bounds the retries). A message never tried (not built, or after a dead connection) does not."""
    return int(
        (
            await conn.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE "  # noqa: S608
                    f"{WHEN} > :cut AND ((action IN ('notice.sent', 'notice.folded')"
                    " AND outcome = 'success') OR (action = 'notice.send_failed'"
                    " AND coalesce(details ->> 'error', '') NOT IN ('MailError', 'NotSent')))"
                ),
                {"cut": now - timedelta(hours=1)},
            )
        ).scalar_one()
    )


async def _audited(
    conn: AsyncConnection, actions: tuple[str, ...], since: datetime, only_success: bool
) -> int:
    return int(
        (
            await conn.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE action = ANY(:a)"  # noqa: S608
                    f" AND (outcome = 'success' OR NOT :ok) AND {WHEN} > :cut"
                ),
                {"a": list(actions), "ok": only_success, "cut": since},
            )
        ).scalar_one()
    )


async def failures_last_hour(conn: AsyncConnection, now: datetime) -> int:
    """Messages the relay did not take in the last hour (each ``notice.send_failed``)."""
    return await _audited(conn, ("notice.send_failed",), now - timedelta(hours=1), False)


async def last_run(conn: AsyncConnection) -> datetime | None:
    """When a pass last ran (its audit row), or None."""
    return (
        await conn.execute(
            text("SELECT max(occurred_at) FROM audit_events WHERE action = 'notice.run'")
        )
    ).scalar_one_or_none()


async def _store(
    conn: AsyncConnection, rec: Reconciled, now: datetime
) -> dict[tuple[str, str], int]:
    """Insert, update and resolve; the id of every live row afterwards, by (kind, subject)."""
    ids: dict[tuple[str, str], int] = {}
    for step in rec.steps:
        d = step.decision
        if d.store == "insert":
            ids[step.key] = int(
                (
                    await conn.execute(
                        text(
                            "INSERT INTO notices (kind, subject, severity, count, first_seen,"
                            " last_seen) VALUES (:k, :s, :v, :n, :first, :now) RETURNING id"
                        ),
                        {
                            "k": step.key[0],
                            "s": step.key[1],
                            "v": d.severity,
                            "n": d.count,
                            "first": d.first_seen,
                            "now": now,
                        },
                    )
                ).scalar_one()
            )
        elif d.store == "update" and step.row is not None:
            ids[step.key] = step.row.id
            await conn.execute(
                text(
                    "UPDATE notices SET severity = :v, count = :n,"
                    " last_seen = greatest(last_seen, :now) WHERE id = :id"
                ),
                {"v": d.severity, "n": d.count, "now": now, "id": step.row.id},
            )
        elif d.store == "resolve" and step.row is not None:
            await conn.execute(
                text("UPDATE notices SET resolved_at = greatest(first_seen, :now) WHERE id = :id"),
                {"now": now, "id": step.row.id},
            )
    return ids


def _count(rec: Reconciled, report: Report, found: Found) -> None:
    report.conditions = len(found.conditions)
    report.unreadable = sorted(found.failed)
    for step in rec.steps:
        match step.decision.store:
            case "insert":
                report.inserted += 1
            case "update":
                report.updated += 1
            case "resolve":
                report.resolved += 1


def _line(intent: Intent, base: str, verb: str) -> str:
    said = render.render(intent, base)
    return f"{verb}: {said.subject} ({intent.count}) {said.link}"


async def run(
    engine: AsyncEngine,
    cfg: Config,
    found: Found,
    *,
    now: datetime,
    apply: bool = True,
    deliver: Deliver = mail.send,
) -> Report:
    """One pass. ``apply=False`` reads and plans only: nothing is stored, sent or audited."""
    report = Report("dry_run" if not apply else "sent" if cfg.sends else "not_on", cfg.why_not)
    if not apply:
        await _pass(engine, cfg, found, now, report, False, deliver)
        return report
    async with engine.connect() as lock:
        lock = await lock.execution_options(isolation_level="AUTOCOMMIT")
        got = (
            await lock.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_KEY})
        ).scalar()
        if not got:
            report.busy = True
            return report
        try:
            await _pass(engine, cfg, found, now, report, True, deliver)
        finally:
            await _unlock(lock)
    return report


async def _unlock(lock: AsyncConnection) -> None:
    """Best effort: a lost connection ends the lock with it."""
    try:
        await lock.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
    except Exception as exc:
        log.warning("notices: the lock was not released cleanly: %s", type(exc).__name__)


async def _pass(
    engine: AsyncEngine,
    cfg: Config,
    found: Found,
    now: datetime,
    report: Report,
    apply: bool,
    deliver: Deliver,
) -> None:
    async with engine.connect() as conn:
        live, ending_rows = await load_rows(conn)
        room = MAX_PER_HOUR - await sent_last_hour(conn, now)
    rec = reconcile(live, ending_rows, found.conditions, now, failed=found.failed)
    _count(rec, report, found)
    alloc = allocate(rec.intents, room)
    report.due = len(rec.intents)
    report.deferred = len(rec.intents) - len(alloc.send) - len(alloc.folded)
    verb = "would send" if not (apply and cfg.sends) else "sending"
    for intent in alloc.send:
        report.lines.append(_line(intent, cfg.base, verb))
    if alloc.folded:
        more = render.render_more(alloc.folded, cfg.base)
        report.lines.append(f"{verb}: {more.subject} {more.link}")
    if not apply:
        return
    async with engine.begin() as conn:
        ids = await _store(conn, rec, now)
    sent = failed = folded = 0
    if cfg.sends and (alloc.send or alloc.folded):
        sent, folded, failed = await _send(engine, cfg, alloc, ids, now, deliver, report)
    report.sent, report.folded, report.failed = sent, folded, failed
    async with engine.begin() as conn:
        await _audit(
            conn,
            now,
            "notice.run",
            details={
                "mode": report.mode,
                "conditions": report.conditions,
                "due": report.due,
                "sent": sent,
                "folded": folded,
                "failed": failed,
                "deferred": report.deferred,
                "unreadable": report.unreadable,
            },
        )


@dataclass
class _Tally:
    """What a pass has settled so far: the messages already recorded (by their index in the batch)
    and the counts."""

    sent: int = 0
    folded: int = 0
    failed: int = 0
    done: set[int] = field(default_factory=set)


async def _send(
    engine: AsyncEngine,
    cfg: Config,
    alloc: Allocation,
    ids: dict[tuple[str, str], int],
    now: datetime,
    deliver: Deliver,
    report: Report,
) -> tuple[int, int, int]:
    assert cfg.relay is not None
    assert cfg.sender is not None
    said = [render.render(i, cfg.base) for i in alloc.send]
    if alloc.folded:
        said.append(render.render_more(alloc.folded, cfg.base))
    tally = _Tally()

    async def settle(index: int, result: mail.Delivery) -> None:
        """Record one message's answer in a transaction of its own, once."""
        if index in tally.done:
            return
        tally.done.add(index)
        async with engine.begin() as conn:
            await _settle(conn, cfg, alloc, ids, now, report, tally, index, result)

    try:
        messages = [mail.build_message(cfg.sender, cfg.recipients, r.subject, r.body) for r in said]
        results = await deliver(cfg.relay, cfg.sender, cfg.recipients, messages, on_result=settle)
    except mail.MailError as exc:
        report.problems.append(f"a message was not built: {exc}")
        results = [mail.Delivery(False, "MailError")] * len(said)
    for index, result in enumerate(results):  # whatever the relay's door did not report already
        await settle(index, result)
    return tally.sent, tally.folded, tally.failed


async def _settle(
    conn: AsyncConnection,
    cfg: Config,
    alloc: Allocation,
    ids: dict[tuple[str, str], int],
    now: datetime,
    report: Report,
    tally: _Tally,
    index: int,
    result: mail.Delivery,
) -> None:
    """Mark and audit one message (an individual notice, or the "N more" notice after them)."""
    if index < len(alloc.send):
        intent = alloc.send[index]
        if not result.ok:
            tally.failed += 1
            report.problems.append(f"not sent ({intent.kind}): {result.error}")
            await _audit(
                conn, now, "notice.send_failed", "failure", None,
                {"kind": intent.kind, "error": result.error},
            )  # fmt: skip
            return
        row_id = await _mark(conn, intent, ids, now)
        tally.sent += 1
        await _audit(
            conn,
            now,
            "notice.sent",
            target_id=str(row_id),
            details={
                "kind": intent.kind,
                "reason": intent.reason,
                "severity": intent.severity,
                "count": intent.count,
                "recipients": len(cfg.recipients),
            },
        )
        return
    if not result.ok:
        tally.failed += 1
        report.problems.append(f"not sent (more): {result.error}")
        await _audit(
            conn, now, "notice.send_failed", "failure", None,
            {"kind": "more", "error": result.error},
        )  # fmt: skip
        return
    for intent in alloc.folded:
        await _mark(conn, intent, ids, now)
    tally.folded = len(alloc.folded)
    await _audit(
        conn,
        now,
        "notice.folded",
        details={
            "notices": tally.folded,
            "recipients": len(cfg.recipients),
            "severity": worst(alloc.folded),
        },
    )


async def _mark(
    conn: AsyncConnection, intent: Intent, ids: dict[tuple[str, str], int], now: datetime
) -> int:
    """The row's record that this notice went out."""
    if intent.reason == "ended":
        assert intent.row_id is not None
        await conn.execute(
            text(
                "UPDATE notices SET ended_at = greatest(resolved_at, :now)"
                " WHERE id = :id AND ended_at IS NULL"
            ),
            {"now": now, "id": intent.row_id},
        )
        return intent.row_id
    row_id = ids[intent.key]
    await conn.execute(
        text(
            "UPDATE notices SET sent_at = :now, sent_severity = :v, notified = notified + 1"
            " WHERE id = :id"
        ),
        {"now": now, "v": intent.severity, "id": row_id},
    )
    return row_id


async def _audit(
    conn: AsyncConnection,
    now: datetime,
    action: str,
    outcome: str = "success",
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """One audit row as ``system``; ``details.at`` is the pass's clock (see :data:`WHEN`)."""
    details = {**(details or {}), "at": now.isoformat()}
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session,
            actor=ACTOR,
            action=action,
            outcome=outcome,
            target_type="notices",
            target_id=target_id,
            details=details,
        )
    finally:
        await session.close()


async def send_test(
    engine: AsyncEngine,
    cfg: Config,
    to: str,
    *,
    deliver: Deliver = mail.send,
    moment: datetime | None = None,
) -> None:
    """The user's test message: one line, through the same relay, to ``to``. Refused while
    notices are off ("not switched on, by your choice") or the relay is incomplete; ``to`` must
    be one plain address. Raises :class:`Refused` or :class:`mail.MailError`; a relay failure is
    a :class:`Refused` with the kind of error."""
    if not cfg.enabled:
        raise Refused(NOT_ON)
    if cfg.relay is None or cfg.sender is None:
        raise Refused("the relay is incomplete (notices.relay_host, relay_from)")
    try:
        target = parse_address(to)
    except ValueError:
        raise Refused("--to is one plain e-mail address") from None
    said = render.render_test()
    message = mail.build_message(cfg.sender, [target], said.subject, said.body, test=True)
    (result,) = await deliver(cfg.relay, cfg.sender, [target], [message])
    async with engine.begin() as conn:
        await _audit(
            conn,
            moment or datetime.now(UTC),
            "notice.test",
            "success" if result.ok else "failure",
            None,
            {"ok": result.ok, "error": result.error},
        )
    if not result.ok:
        raise Refused(f"the relay did not take the message ({result.error})")


async def status(conn: AsyncConnection, cfg: Config, now: datetime) -> list[str]:
    """What is on, who gets notices, the last pass and the counts, in plain lines."""
    lines = []
    if cfg.sends:
        where = f"{cfg.host}:{cfg.port}" if cfg.host else "the relay"
        lines.append(f"notices: ON, through {where}, from {cfg.sender}")
        lines.append(f"recipients ({len(cfg.recipients)}): {', '.join(cfg.recipients)}")
    else:
        lines.append(f"notices: OFF ({cfg.why_not})")
        if cfg.recipients:
            lines.append(f"recipients named ({len(cfg.recipients)}): {', '.join(cfg.recipients)}")
    lines.append(f"links point to: {cfg.base}")
    last = await last_run(conn)
    lines.append("last pass: never" if last is None else f"last pass: {_ago(now - last)} ago")
    live, ending_rows = await load_rows(conn)
    waiting = len([r for r in ending_rows if r.sent_at is not None])
    by_kind = {k: [r for r in live if r.kind == k] for k in KINDS}
    for kind in KINDS:
        rows = by_kind[kind]
        told = len([r for r in rows if r.sent_at is not None])
        lines.append(f"  {kind}: {len(rows)} live, {told} told")
    if waiting:
        lines.append(f"  outages over, waiting to be told so: {waiting}")
    hour = await sent_last_hour(conn, now)
    lines.append(f"e-mails in the last hour: {hour} of {MAX_PER_HOUR}")
    day = await _audited(conn, ("notice.sent", "notice.folded"), now - timedelta(days=1), True)
    lines.append(f"e-mails in the last 24 hours: {day}")
    return lines


def _ago(span: timedelta) -> str:
    seconds = max(0, int(span.total_seconds()))
    if seconds < 90:
        return f"{seconds} seconds"
    if seconds < 5400:
        return f"{round(seconds / 60)} minutes"
    return f"{seconds / 3600:.1f} hours"
