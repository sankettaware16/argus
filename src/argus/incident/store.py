"""The incident report's history in the database (AR7, D-190, migration 0052).

Versions are appended and never changed; the newest version is the current one. A version is
written only when what the report says changed (``content_hash``), so a case that did not change
keeps its report, and the same evidence gives the same version. Decisions are appended beside a
version (:mod:`argus.incident.review`). The runtime login writes reports and checks; the web's
login reads them and writes a person's decision.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.incident.model import SCHEMA, IncidentReport, content_hash, core_hash

ACTOR = "argus:incident"
ACTIVE_STATES = ("suspected", "open", "assigned", "contained")
RETRIES = 3

_COLUMNS = (
    "r.id, r.case_id, r.version, r.content_hash, r.case_version, r.verdict_outcome,"
    " r.verdict_confidence, r.body, r.prose, r.prose_by, r.generated_by, r.as_at, r.generated_at"
)


@dataclass(frozen=True)
class Decision:
    id: int
    report_id: int
    decision: str
    outcome: str | None
    reason: str | None
    by_user_id: int
    by_name: str | None
    decided_at: datetime
    review_ids: tuple[int, ...]


@dataclass(frozen=True)
class Stored:
    id: int
    case_id: uuid.UUID
    version: int
    content_hash: str
    case_version: int
    verdict_outcome: str | None
    verdict_confidence: float | None
    report: IncidentReport
    prose: bool
    prose_by: str | None
    generated_by: str
    as_at: datetime
    generated_at: datetime
    decision: Decision | None = None  # the newest decision of this version


@dataclass(frozen=True)
class Check:
    case_id: uuid.UUID
    signal: str
    checked_at: datetime
    report_id: int | None
    failure: str | None
    failed_at: datetime | None


def _stored(row: Any, decision: Decision | None) -> Stored | None:
    """A stored version, or None when its body is not a report this ARGUS can read (one a
    newer or older writer made: the page says there is none rather than showing it wrongly)."""
    try:
        report = IncidentReport.model_validate(row.body)
    except (ValidationError, ValueError):
        return None
    return Stored(
        int(row.id), row.case_id, int(row.version), row.content_hash, int(row.case_version),
        row.verdict_outcome, row.verdict_confidence, report, bool(row.prose), row.prose_by,
        row.generated_by, row.as_at, row.generated_at, decision,
    )  # fmt: skip


def _decision(row: Any) -> Decision:
    return Decision(
        int(row.id), int(row.report_id), row.decision, row.outcome, row.reason,
        int(row.by_user_id), row.by_name, row.decided_at, tuple(int(i) for i in row.review_ids),
    )  # fmt: skip


async def decision_of(conn: AsyncConnection, report_id: int) -> Decision | None:
    row = (
        await conn.execute(
            text(
                "SELECT d.id, d.report_id, d.decision, d.outcome, d.reason, d.by_user_id,"
                " u.display_name AS by_name, d.decided_at, d.review_ids"
                " FROM incident_report_decisions d JOIN users u ON u.id = d.by_user_id"
                " WHERE d.report_id = :r ORDER BY d.id DESC LIMIT 1"
            ),
            {"r": report_id},
        )
    ).first()
    return None if row is None else _decision(row)


async def decisions(conn: AsyncConnection, report_id: int) -> list[Decision]:
    rows = await conn.execute(
        text(
            "SELECT d.id, d.report_id, d.decision, d.outcome, d.reason, d.by_user_id,"
            " u.display_name AS by_name, d.decided_at, d.review_ids"
            " FROM incident_report_decisions d JOIN users u ON u.id = d.by_user_id"
            " WHERE d.report_id = :r ORDER BY d.id"
        ),
        {"r": report_id},
    )
    return [_decision(r) for r in rows]


async def latest(conn: AsyncConnection, case_id: uuid.UUID) -> Stored | None:
    """The newest version of the case's report, or None (none yet, or unreadable)."""
    row = (
        await conn.execute(
            text(
                f"SELECT {_COLUMNS} FROM incident_reports r WHERE r.case_id = :c"  # noqa: S608
                " ORDER BY r.version DESC LIMIT 1"
            ),
            {"c": case_id},
        )
    ).first()
    if row is None:
        return None
    return _stored(row, await decision_of(conn, int(row.id)))


async def version(conn: AsyncConnection, case_id: uuid.UUID, number: int) -> Stored | None:
    row = (
        await conn.execute(
            text(
                f"SELECT {_COLUMNS} FROM incident_reports r WHERE r.case_id = :c"  # noqa: S608
                " AND r.version = :v"
            ),
            {"c": case_id, "v": number},
        )
    ).first()
    if row is None:
        return None
    return _stored(row, await decision_of(conn, int(row.id)))


@dataclass(frozen=True)
class Listed:
    version: int
    report_id: int
    generated_at: datetime
    content_hash: str
    prose: bool
    decision: str | None
    decided_at: datetime | None


async def versions(conn: AsyncConnection, case_id: uuid.UUID) -> list[Listed]:
    """Every version, newest first, with the newest decision of each."""
    rows = await conn.execute(
        text(
            "SELECT r.version, r.id, r.generated_at, r.content_hash, r.prose,"
            " (SELECT d.decision FROM incident_report_decisions d WHERE d.report_id = r.id"
            "  ORDER BY d.id DESC LIMIT 1) AS decision,"
            " (SELECT d.decided_at FROM incident_report_decisions d WHERE d.report_id = r.id"
            "  ORDER BY d.id DESC LIMIT 1) AS decided_at"
            " FROM incident_reports r WHERE r.case_id = :c ORDER BY r.version DESC"
        ),
        {"c": case_id},
    )
    return [Listed(int(r.version), int(r.id), r.generated_at, r.content_hash, bool(r.prose),
                   r.decision, r.decided_at) for r in rows]  # fmt: skip


async def save(
    conn: AsyncConnection, report: IncidentReport, *, case_version: int, prose_by: str | None = None
) -> tuple[Stored | None, bool]:
    """Write ``report`` as the case's next version, unless the newest version says the same
    (same ``content_hash`` and writer): then that version stays current. Returns the current
    version and whether it is new. A writer racing this one (the unique key) is retried."""
    case_id = uuid.UUID(report.header.case_id)
    digest = content_hash(report)
    for _ in range(RETRIES):
        newest = await latest(conn, case_id)
        if (
            newest is not None
            and newest.content_hash == digest
            and (newest.report.meta.writer == report.meta.writer)
        ):
            return newest, False
        try:
            async with conn.begin_nested():
                made = (
                    await conn.execute(
                        text(
                            "INSERT INTO incident_reports (case_id, version, schema_version,"
                            " writer, content_hash, core_hash, case_version, verdict_outcome,"
                            " verdict_confidence, body,"
                            " prose, prose_by, generated_by, as_at)"
                            " SELECT :c, coalesce(max(version), 0) + 1, :schema, :writer, :hash,"
                            " :core, :cv, :outcome, :conf, :body, :prose, :by, :actor, :at"
                            " FROM incident_reports WHERE case_id = :c RETURNING id"
                        ).bindparams(bindparam("body", type_=JSONB)),
                        {
                            "c": case_id,
                            "schema": SCHEMA,
                            "writer": report.meta.writer,
                            "hash": digest,
                            "core": core_hash(report),
                            "cv": case_version,
                            "outcome": report.verdict.outcome,
                            "conf": report.verdict.confidence,
                            "body": report.model_dump(mode="json"),
                            "prose": prose_by is not None,
                            "by": prose_by,
                            "actor": ACTOR,
                            "at": report.meta.as_at,
                        },
                    )
                ).scalar_one()
        except IntegrityError:  # another writer took the version number: read and try again
            continue
        row = (
            await conn.execute(
                text(f"SELECT {_COLUMNS} FROM incident_reports r WHERE r.id = :i"),  # noqa: S608
                {"i": made},
            )
        ).first()
        assert row is not None
        return _stored(row, None), True
    return await latest(conn, case_id), False


# ----------------------------------------------------------------------------- the checks


async def check_of(conn: AsyncConnection, case_id: uuid.UUID) -> Check | None:
    row = (
        await conn.execute(
            text(
                "SELECT case_id, signal, checked_at, report_id, failure, failed_at"
                " FROM incident_report_checks WHERE case_id = :c"
            ),
            {"c": case_id},
        )
    ).first()
    return None if row is None else Check(row.case_id, row.signal, row.checked_at, row.report_id,
                                          row.failure, row.failed_at)  # fmt: skip


async def put_check(
    conn: AsyncConnection, case_id: uuid.UUID, signal: str, at: datetime, *,
    report_id: int | None = None, failure: str | None = None,
) -> None:  # fmt: skip
    """Record that ARGUS looked at the case with ``signal`` at ``at`` (a failure keeps the
    report it had)."""
    await conn.execute(
        text(
            "INSERT INTO incident_report_checks (case_id, signal, checked_at, report_id, failure,"
            " failed_at) VALUES (:c, :s, :t, :r, :f, CASE WHEN CAST(:f AS text) IS NULL THEN NULL"
            " ELSE CAST(:t AS timestamptz) END)"
            " ON CONFLICT (case_id) DO UPDATE SET signal = EXCLUDED.signal,"
            " checked_at = EXCLUDED.checked_at,"
            " report_id = coalesce(EXCLUDED.report_id, incident_report_checks.report_id),"
            " failure = EXCLUDED.failure, failed_at = EXCLUDED.failed_at"
        ),
        {"c": case_id, "s": signal, "t": at, "r": report_id,
         "f": None if failure is None else failure[:500]},
    )  # fmt: skip


async def candidates(conn: AsyncConnection, look: int) -> list[tuple[uuid.UUID, Check | None]]:
    """The active cases ARGUS looked at least recently first (those never looked at lead)."""
    rows = await conn.execute(
        text(
            "SELECT c.id, k.signal, k.checked_at, k.report_id, k.failure, k.failed_at"
            " FROM cases c LEFT JOIN incident_report_checks k ON k.case_id = c.id"
            " WHERE c.state IN ('suspected', 'open', 'assigned', 'contained')"
            " ORDER BY k.checked_at NULLS FIRST, c.number LIMIT :n"
        ),
        {"n": look},
    )
    return [
        (r.id, None if r.signal is None else Check(r.id, r.signal, r.checked_at, r.report_id,
                                                    r.failure, r.failed_at))
        for r in rows
    ]  # fmt: skip
