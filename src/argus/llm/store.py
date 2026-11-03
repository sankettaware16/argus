"""The LLM gateway's shared state and ledger in Postgres: every ARGUS process shares one
budget, one set of breakers and one kill switch. Each change locks the state row."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, async_sessionmaker

from argus.db.audit import record_audit
from argus.llm import budget
from argus.llm.gateway import CallEntry

T = TypeVar("T")


async def read_state(conn: AsyncConnection) -> budget.State:
    """The gateway's state, read on the caller's connection (the web reads it inside its
    request's own transaction, never on a second pooled connection)."""
    row = await conn.execute(text("SELECT state FROM llm_state WHERE name = 'gateway'"))
    data: dict[str, Any] = row.scalar_one()
    return budget.from_json(data)


class PgLlmStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def change(self, fn: Callable[[budget.State], tuple[T, budget.State]]) -> T:
        async with self.engine.begin() as conn:
            row = await conn.execute(
                text("SELECT state FROM llm_state WHERE name = 'gateway' FOR UPDATE")
            )
            result, new = fn(budget.from_json(row.scalar_one()))
            await conn.execute(
                text(
                    "UPDATE llm_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = 'gateway'"
                ),
                {"s": json.dumps(budget.to_json(new))},
            )
            return result

    async def state(self) -> budget.State:
        async with self.engine.connect() as conn:
            return await read_state(conn)

    async def record(self, entry: CallEntry) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
                    " priority, outcome, http_status, input_tokens, output_tokens, cost_usd,"
                    " latency_ms, request_bytes, request_sha256) VALUES (:at, :call_id,"
                    " :attempt, :provider, :model, :tier, :purpose, :priority, :outcome,"
                    " :http_status, :input_tokens, :output_tokens, :cost_usd, :latency_ms,"
                    " :request_bytes, :request_sha256)"
                ),
                vars(entry),
            )

    async def set_stopped(self, stopped: bool, *, actor: str, reason: str | None) -> bool:
        """The kill switch; True if it changed. Audited in the same transaction."""
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text("SELECT state FROM llm_state WHERE name = 'gateway' FOR UPDATE")
            )
            state = budget.from_json(row.scalar_one())
            changed = state.stopped != stopped
            if changed:
                new = budget.to_json(replace(state, stopped=stopped))
                await session.execute(
                    text(
                        "UPDATE llm_state SET state = CAST(:s AS jsonb), updated_at = now()"
                        " WHERE name = 'gateway'"
                    ),
                    {"s": json.dumps(new)},
                )
            await record_audit(
                session,
                actor=actor,
                action="llm.stop" if stopped else "llm.resume",
                target_type="llm_gateway",
                target_id="gateway",
                details={"changed": changed, "reason": reason},
            )
            return changed

    async def probe_up(self, provider: str, now: datetime, *, actor: str) -> budget.Alarm | None:
        """A probe a person ran found ``provider`` up (``argus llm probe``): its alarm and its
        own cool-down end. Audited when it clears an alarm; returns the alarm cleared."""
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text("SELECT state FROM llm_state WHERE name = 'gateway' FOR UPDATE")
            )
            cleared, new = budget.probe_up(budget.from_json(row.scalar_one()), provider, now)
            await session.execute(
                text(
                    "UPDATE llm_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = 'gateway'"
                ),
                {"s": json.dumps(budget.to_json(new))},
            )
            if cleared is not None:
                await record_audit(
                    session, actor=actor, action="llm.alarm_cleared", target_type="llm_provider",
                    target_id=provider, details={"kind": cleared.kind,
                                                 "since": cleared.at.isoformat(), "by": "probe"},
                )  # fmt: skip
            return cleared

    async def reconcile(self, now: datetime, *, actor: str) -> tuple[float, float]:
        """Set this month's spend to the ledger's settled costs, dropping reservations that were
        never settled (a crash, or connections that never reached a provider). Audited. Returns
        (before, after)."""
        month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text("SELECT state FROM llm_state WHERE name = 'gateway' FOR UPDATE")
            )
            state = budget.from_json(row.scalar_one())
            settled = await session.scalar(
                text("SELECT coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >= :m"),
                {"m": month},
            )
            day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            today = await session.scalar(
                text("SELECT coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >= :d"),
                {"d": day},
            )
            before = state.spent_usd if state.month == budget.month_of(now) else 0.0
            after = round(float(settled), 6)
            new = replace(state, month=budget.month_of(now), spent_usd=after,
                          day=day.date().isoformat(),
                          day_spent_usd=round(float(today), 6))  # fmt: skip
            await session.execute(
                text(
                    "UPDATE llm_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = 'gateway'"
                ),
                {"s": json.dumps(budget.to_json(new))},
            )
            await record_audit(
                session, actor=actor, action="llm.reconcile", target_type="llm_gateway",
                target_id="gateway", details={"before": before, "after": after},
            )  # fmt: skip
            return before, after
