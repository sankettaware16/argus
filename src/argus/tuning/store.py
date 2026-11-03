"""Storing the weekly tuning reports (P7): one per rule and week, written once."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.tuning.advise import Advice
from argus.tuning.report import RuleReport


async def save(conn: AsyncConnection, rep: RuleReport, advice: Advice) -> bool:
    """Whether it was stored (False: this rule's report for that week exists already)."""
    row = await conn.execute(
        text(
            "INSERT INTO tuning_reports (rule, week_end, report, suggestions, dropped, model,"
            " cost_usd) VALUES (:r, :w, CAST(:rep AS jsonb), CAST(:s AS jsonb),"
            " CAST(:d AS jsonb), :m, :c) ON CONFLICT (rule, week_end) DO NOTHING RETURNING id"
        ),
        {
            "r": rep.rule,
            "w": rep.end,
            "rep": json.dumps(rep.as_dict()),
            "s": json.dumps([s.as_dict() for s in advice.suggestions]),
            "d": json.dumps(advice.dropped),
            "m": advice.model,
            "c": advice.cost_usd,
        },
    )
    return row.first() is not None


async def latest(conn: AsyncConnection) -> list[dict[str, Any]]:
    """Each rule's newest report."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (rule) rule, week_end, report, suggestions, dropped, model,"
            " cost_usd, created_at FROM tuning_reports ORDER BY rule, week_end DESC"
        )
    )
    return [dict(r._mapping) for r in rows]


async def last_week_end(conn: AsyncConnection) -> datetime | None:
    found = await conn.scalar(text("SELECT max(week_end) FROM tuning_reports"))
    return found if isinstance(found, datetime) else None
