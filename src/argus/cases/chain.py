"""The audit hash chain: proof that no audit row or case event was changed, removed or reordered.
A database trigger numbers every new ``audit_events`` and ``case_events`` row (``chain_seq``) and
stores ``row_hash``, the sha256 of the previous row's hash and the row's own fields. :func:`verify`
recomputes all of it in Python (the message encoding is the SQL one byte for byte), so a replaced
database function cannot make a changed row pass; the head from ``argus audit head`` anchors it
against a rewrite by the owner. Approvals are checked against their audit rows."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

CHAIN_LOCK_KEY = int.from_bytes(b"ARGUSCHN", "big")  # the same key as the database functions
VERSION = "argus-chain-v1"
CHAINS = ("audit_events", "case_events")
LEGACY_SEED = hashlib.sha256(f"{VERSION}:audit_events:legacy".encode()).digest()
CASE_EVENTS_GENESIS = hashlib.sha256(f"{VERSION}:case_events:genesis".encode()).hexdigest()
BATCH = 5000
MAX_PROBLEMS = 20


def chain_field(value: str | None) -> bytes:
    if value is None:
        return b"N"
    raw = value.encode("utf-8")
    return b"S" + str(len(raw)).encode("ascii") + b":" + raw


def chain_time(value: datetime) -> str:
    """As the SQL ``argus_chain_time``: UTC, microseconds, a Z."""
    if value.tzinfo is None:
        raise ValueError("chain times are timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _number(value: int | None) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class AuditRow:
    id: int
    occurred_at: datetime
    actor: str
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    correlation_id: str | None
    details: str  # the stored JSONB as PostgreSQL prints it (details::text)
    chain_seq: int | None = None
    prev_hash: str | None = None
    row_hash: str | None = None


@dataclass(frozen=True)
class CaseEventRow:
    id: int
    case_id: uuid.UUID
    case_version: int
    kind: str
    actor: str
    actor_user_id: int | None
    from_state: str | None
    to_state: str
    details: str  # details::text
    kibana_rows: int
    occurred_at: datetime
    chain_seq: int | None = None
    prev_hash: str | None = None
    row_hash: str | None = None


def audit_message(seq: int | None, prev: str | None, row: AuditRow) -> bytes:
    return b"".join(
        (
            f"{VERSION}:audit_events\n".encode(),
            chain_field(_number(seq)),
            chain_field(prev),
            chain_field(str(row.id)),
            chain_field(chain_time(row.occurred_at)),
            chain_field(row.actor),
            chain_field(row.action),
            chain_field(row.outcome),
            chain_field(row.target_type),
            chain_field(row.target_id),
            chain_field(row.correlation_id),
            chain_field(row.details),
        )
    )


def case_event_message(seq: int | None, prev: str | None, row: CaseEventRow) -> bytes:
    return b"".join(
        (
            f"{VERSION}:case_events\n".encode(),
            chain_field(_number(seq)),
            chain_field(prev),
            chain_field(str(row.id)),
            chain_field(str(row.case_id)),
            chain_field(str(row.case_version)),
            chain_field(row.kind),
            chain_field(row.actor),
            chain_field(_number(row.actor_user_id)),
            chain_field(row.from_state),
            chain_field(row.to_state),
            chain_field(row.details),
            chain_field(str(row.kibana_rows)),
            chain_field(chain_time(row.occurred_at)),
        )
    )


def digest(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()


def seal(rows: Iterable[AuditRow], seed: bytes = LEGACY_SEED) -> tuple[str, int]:
    """The legacy seal over ``rows`` (in id order): sha256 of the seed followed by each row's
    own sha256; and how many rows there were."""
    state = hashlib.sha256(seed)
    count = 0
    for row in rows:
        state.update(hashlib.sha256(audit_message(None, None, row)).digest())
        count += 1
    return state.hexdigest(), count


@dataclass
class ChainReport:
    chain: str
    chained: int = 0
    legacy: int = 0
    head_seq: int | None = None
    head_hash: str | None = None
    problems: list[str] = field(default_factory=list)
    more: int = 0  # problems beyond MAX_PROBLEMS

    @property
    def ok(self) -> bool:
        return not self.problems

    def problem(self, text_: str) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(text_)
        else:
            self.more += 1

    def summary(self) -> str:
        if self.ok:
            legacy = f", {self.legacy} sealed before it" if self.legacy else ""
            return (
                f"{self.chained} rows chained{legacy}; head {self.head_seq}"
                f" {(self.head_hash or '')[:16]}"
            )
        more = f" (and {self.more} more)" if self.more else ""
        return "; ".join(self.problems) + more


_AUDIT_COLUMNS = (
    "id, occurred_at, actor, action, outcome, target_type, target_id, correlation_id,"
    " details::text AS details, chain_seq, prev_hash, row_hash"
)
_CASE_COLUMNS = (
    "id, case_id, case_version, kind, actor, actor_user_id, from_state, to_state,"
    " details::text AS details, kibana_rows, occurred_at, chain_seq, prev_hash, row_hash"
)


def _audit_row(r: Any) -> AuditRow:
    return AuditRow(
        r.id, r.occurred_at, r.actor, r.action, r.outcome, r.target_type, r.target_id,
        r.correlation_id, r.details, r.chain_seq, r.prev_hash, r.row_hash,
    )  # fmt: skip


def _case_row(r: Any) -> CaseEventRow:
    return CaseEventRow(
        r.id, r.case_id, r.case_version, r.kind, r.actor, r.actor_user_id, r.from_state,
        r.to_state, r.details, r.kibana_rows, r.occurred_at, r.chain_seq, r.prev_hash,
        r.row_hash,
    )  # fmt: skip


async def heads(conn: AsyncConnection) -> dict[str, tuple[int, str]]:
    rows = await conn.execute(text("SELECT chain, seq, head_hash FROM chain_heads ORDER BY chain"))
    return {str(r.chain): (int(r.seq), str(r.head_hash)) for r in rows}


async def verify(conn: AsyncConnection, chain: str, *, batch: int = BATCH) -> ChainReport:
    """Every check of one chain, read in batches (memory stays flat). Read-only."""
    if chain not in CHAINS:
        raise ValueError(f"unknown chain {chain!r}")
    report = ChainReport(chain)
    head = (
        await conn.execute(
            text(
                "SELECT seq, head_hash, genesis_hash, legacy_rows, legacy_max_id"
                " FROM chain_heads WHERE chain = :c"
            ),
            {"c": chain},
        )
    ).first()
    if head is None:
        report.problem(f"{chain}: the chain has no head (migration 0026 not applied?)")
        return report
    report.head_seq, report.head_hash = int(head.seq), str(head.head_hash)
    if chain == "audit_events":
        await _verify_legacy(conn, head, report, batch)
        genesis = str(head.genesis_hash)
    else:
        genesis = CASE_EVENTS_GENESIS
        if head.genesis_hash != genesis or head.legacy_rows or head.legacy_max_id:
            report.problem("case_events: the chain's genesis was changed")
        unchained = (
            await conn.execute(text("SELECT count(*) FROM case_events WHERE chain_seq IS NULL"))
        ).scalar_one()
        if unchained:  # every case event was written after the chain started
            report.problem(
                f"case_events: {unchained} rows are not chained (written with its trigger off?)"
            )
    await _verify_chained(conn, chain, genesis, report, batch)
    if chain == "audit_events":
        await _verify_approvals(conn, report)
    return report


# What argus_approval_request(), argus_approval_propose() and argus_approval_decide() wrote
# to the audit trail: a request names the person or the part of ARGUS that made
# it; a decision its signature too.
_REQUESTS_UNAUDITED = (
    "SELECT r.id FROM approval_requests r WHERE NOT EXISTS (SELECT 1 FROM audit_events a"
    " WHERE a.action = 'case.approval.requested' AND a.target_type = 'case'"
    " AND a.target_id = r.case_id::text"
    " AND a.actor = coalesce('user:' || r.requested_by_user_id, r.proposed_by)"
    " AND a.details @> jsonb_build_object('request', r.id, 'kind', r.kind, 'reason', r.reason,"
    " 'case_version', r.case_version, 'payload_hash', r.payload_hash,"
    " 'alert_count', r.alert_count, 'alert_digest', r.alert_digest,"
    " 'required', r.required_approvals, 'outbox', r.outbox_id,"
    " 'outbox_sent_count', r.outbox_sent_count, 'target', r.target_case_id,"
    " 'expires_at', to_char(r.expires_at AT TIME ZONE 'UTC',"
    ' \'YYYY-MM-DD"T"HH24:MI:SS.US"Z"\'))) ORDER BY r.id LIMIT :n'
)
_DECISIONS_UNAUDITED = (
    "SELECT d.id FROM approval_decisions d JOIN approval_requests r ON r.id = d.request_id"
    " WHERE NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.action = 'case.approval.'"
    " || d.decision AND a.target_type = 'case' AND a.target_id = r.case_id::text"
    " AND a.actor = 'user:' || d.approver_user_id"
    " AND a.details @> jsonb_build_object('request', d.request_id, 'decision', d.id)"
    " AND a.details -> 'capabilities' = d.capabilities"
    " AND (a.details ->> 'signature') IS NOT DISTINCT FROM d.signature) ORDER BY d.id LIMIT :n"
)
_AUDITED_MISSING = (
    "SELECT a.id FROM audit_events a WHERE (a.action = 'case.approval.requested'"
    " AND NOT EXISTS (SELECT 1 FROM approval_requests r"
    " WHERE r.id::text = a.details ->> 'request'))"
    " OR (a.action IN ('case.approval.approved', 'case.approval.rejected')"
    " AND NOT EXISTS (SELECT 1 FROM approval_decisions d"
    " WHERE d.id::text = a.details ->> 'decision')) ORDER BY a.id LIMIT :n"
)


async def _verify_approvals(conn: AsyncConnection, report: ChainReport) -> None:
    """Each approval request and decision matches the audit row its function wrote, and each
    such audit row still has its request or decision."""
    checks = (
        (_REQUESTS_UNAUDITED, "approval request {} is not in the audit trail as it was made"),
        (_DECISIONS_UNAUDITED, "approval decision {} is not in the audit trail as it was made"),
        (_AUDITED_MISSING, "audit row {} names an approval request or decision that is gone"),
    )
    for query, message in checks:
        found = (await conn.execute(text(query), {"n": MAX_PROBLEMS})).scalars().all()
        for row_id in found:
            report.problem(f"audit_events: {message.format(row_id)}")


async def _verify_legacy(conn: AsyncConnection, head: Any, report: ChainReport, n: int) -> None:
    state, count, after = hashlib.sha256(LEGACY_SEED), 0, 0
    while True:
        rows = (
            await conn.execute(
                text(
                    f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE chain_seq IS NULL"  # noqa: S608 - constant fragments; values are bound
                    " AND id > :after AND id <= :top ORDER BY id LIMIT :n"
                ),
                {"after": after, "top": int(head.legacy_max_id), "n": n},
            )
        ).all()
        if not rows:
            break
        for r in rows:
            state.update(hashlib.sha256(audit_message(None, None, _audit_row(r))).digest())
            count += 1
        after = int(rows[-1].id)
    report.legacy = count
    if count != int(head.legacy_rows):
        report.problem(
            f"audit_events: {head.legacy_rows} rows were sealed before the chain started,"
            f" {count} are left"
        )
    elif state.hexdigest() != head.genesis_hash:
        report.problem("audit_events: a row written before the chain started was changed")
    unchained = (
        await conn.execute(
            text("SELECT count(*) FROM audit_events WHERE chain_seq IS NULL AND id > :top"),
            {"top": int(head.legacy_max_id)},
        )
    ).scalar_one()
    if unchained:
        report.problem(
            f"audit_events: {unchained} rows written after the chain started are not chained"
            " (written with its trigger off?)"
        )


async def _verify_chained(
    conn: AsyncConnection, chain: str, genesis: str, report: ChainReport, n: int
) -> None:
    columns, make = (
        (_AUDIT_COLUMNS, _audit_row) if chain == "audit_events" else (_CASE_COLUMNS, _case_row)
    )
    prev, expected, after = genesis, 1, 0
    while True:
        rows: Sequence[Any] = (
            await conn.execute(
                text(
                    f"SELECT {columns} FROM {chain} WHERE chain_seq > :after"  # noqa: S608 - chain is one of CHAINS; values are bound
                    " ORDER BY chain_seq LIMIT :n"
                ),
                {"after": after, "n": n},
            )
        ).all()
        if not rows:
            break
        for r in rows:
            row = make(r)
            seq = int(r.chain_seq)
            if seq != expected:
                report.problem(
                    f"{chain}: rows {expected} to {seq - 1} of the chain are missing"
                    if seq > expected
                    else f"{chain}: row {seq} appears twice"
                )
            if r.prev_hash != prev:
                report.problem(f"{chain}: row {seq} (id {r.id}) does not follow the row before it")
            message = (
                audit_message(seq, r.prev_hash, row)  # type: ignore[arg-type]
                if chain == "audit_events"
                else case_event_message(seq, r.prev_hash, row)  # type: ignore[arg-type]
            )
            if digest(message) != r.row_hash:
                report.problem(f"{chain}: row {seq} (id {r.id}) was changed after it was written")
            prev, expected = str(r.row_hash), seq + 1
            report.chained += 1
        after = int(rows[-1].chain_seq)
    last = expected - 1
    if report.head_seq != last:
        report.problem(
            f"{chain}: the head says {report.head_seq} rows, the chain has {last}"
            + (" (rows were removed from its end?)" if (report.head_seq or 0) > last else "")
        )
    elif report.head_hash != prev:
        report.problem(f"{chain}: the head's hash is not the newest row's")


async def verify_all(conn: AsyncConnection, *, batch: int = BATCH) -> list[ChainReport]:
    return [await verify(conn, chain, batch=batch) for chain in CHAINS]


async def verify_snapshot(engine: AsyncEngine, *, batch: int = BATCH) -> list[ChainReport]:
    """Both chains read from one snapshot (REPEATABLE READ, read only), so rows committed while
    it reads never make the head and the rows disagree."""
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="REPEATABLE READ")
        async with conn.begin():
            await conn.execute(text("SET TRANSACTION READ ONLY"))
            return await verify_all(conn, batch=batch)
