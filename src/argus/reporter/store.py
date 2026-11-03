"""The Reporter's history (Q-H3, migration 0046): reports are written once and read. The runtime
login inserts and reads; the web's login reads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.reporter.model import Numbers

ACTOR = "argus:reporter"
_ONE = (
    "SELECT id, kind, period_start, period_end, generated_at, numbers, text, prose, prose_agent"
    " FROM reports"
)


@dataclass(frozen=True)
class Stored:
    id: int
    kind: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    numbers: Numbers
    text: str
    prose: str | None
    prose_agent: str | None


def _numbers(row: Any) -> Numbers:
    """The stored numbers; a row whose numbers cannot be read (one the owner changed by hand)
    has none, and is still shown with its text."""
    try:
        return Numbers.model_validate(row.numbers)
    except ValueError:
        return Numbers(
            kind=row.kind, period_start=row.period_start, period_end=row.period_end,
            as_at=row.generated_at, sections=(),
        )  # fmt: skip


def _stored(row: Any) -> Stored:
    return Stored(
        row.id, row.kind, row.period_start, row.period_end, row.generated_at,
        _numbers(row), row.text, row.prose, row.prose_agent,
    )  # fmt: skip


async def exists(conn: AsyncConnection, kind: str, period_end: datetime) -> int | None:
    row = await conn.execute(
        text("SELECT id FROM reports WHERE kind = :k AND period_end = :e"),
        {"k": kind, "e": period_end},
    )
    found = row.scalar()
    return None if found is None else int(found)


async def save(
    conn: AsyncConnection,
    numbers: Numbers,
    body: str,
    *,
    prose: str | None = None,
    prose_agent: str | None = None,
) -> int | None:
    """Store a report once; None when that period already has one (it is never rewritten).
    ``generated_at`` is the database's clock."""
    row = await conn.execute(
        text(
            "INSERT INTO reports (kind, period_start, period_end, numbers, text, prose,"
            " prose_agent) VALUES (:kind, :s, :e, :numbers, :body, :prose, :agent)"
            " ON CONFLICT (kind, period_end) DO NOTHING RETURNING id"
        ).bindparams(bindparam("numbers", type_=JSONB)),
        {
            "kind": numbers.kind, "s": numbers.period_start, "e": numbers.period_end,
            "numbers": numbers.model_dump(mode="json"), "body": body, "prose": prose,
            "agent": prose_agent,
        },
    )  # fmt: skip
    made = row.scalar()
    return None if made is None else int(made)


async def listing(conn: AsyncConnection, *, kind: str | None = None, limit: int = 60) -> list[Any]:
    rows = await conn.execute(
        text(
            "SELECT id, kind, period_start, period_end, generated_at, prose IS NOT NULL AS prose"
            " FROM reports WHERE (CAST(:k AS text) IS NULL OR kind = :k)"
            " ORDER BY period_end DESC, id DESC LIMIT :n"
        ),
        {"k": kind, "n": limit},
    )
    return list(rows)


async def get(conn: AsyncConnection, report_id: int) -> Stored | None:
    row = (
        await conn.execute(
            text(f"{_ONE} WHERE id = :i"),
            {"i": report_id},
        )
    ).first()
    return None if row is None else _stored(row)


async def latest(conn: AsyncConnection, kind: str) -> Stored | None:
    row = (
        await conn.execute(
            text(f"{_ONE} WHERE kind = :k ORDER BY period_end DESC LIMIT 1"),
            {"k": kind},
        )
    ).first()
    return None if row is None else _stored(row)
