"""The LLM gateway's Postgres store (P5): one budget shared by every process, the ledger, the
audited kill switch, all as the runtime role."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.llm import budget
from argus.llm.budget import Ask, Bucket, Limits, Priority
from argus.llm.gateway import Call, CallEntry, LlmGateway, NoCapacity
from argus.llm.privacy import Privacy
from argus.llm.store import PgLlmStore
from tests.unit.llm.test_gateway import KEYS, Clock, Fake, config
from tests.unit.llm.test_privacy import RAW, dossier

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
ASK = Ask("p", "m", (Bucket("p", Limits(rpm=10)),), 100, 0.0, Priority.HIGH)


async def test_the_state_starts_empty_and_round_trips(app_engine: AsyncEngine) -> None:
    store = PgLlmStore(app_engine)
    assert await store.state() == budget.State()
    cfg = budget.Config()
    admission = await store.change(lambda s: budget.admit(s, ASK, NOW, cfg))
    assert admission.ok
    state = await store.state()
    assert state.windows["p"].minute_requests == 1
    assert state.month == "2026-10"


async def test_concurrent_admissions_share_one_budget(app_engine: AsyncEngine) -> None:
    stores = [PgLlmStore(app_engine) for _ in range(4)]
    cfg = budget.Config()

    async def one(store: PgLlmStore) -> bool:
        admission = await store.change(lambda s: budget.admit(s, ASK, NOW, cfg))
        return admission.ok

    results = await asyncio.gather(*(one(stores[i % 4]) for i in range(20)))
    assert sum(results) == 8  # rpm 10 at margin 0.8, however the calls interleave
    assert (await stores[0].state()).windows["p"].minute_requests == 8


async def test_the_gateway_records_every_attempt_without_content(
    app_engine: AsyncEngine, privacy: Privacy
) -> None:
    from argus.llm.wire import LlmReply

    store = PgLlmStore(app_engine)
    gw = LlmGateway(config(), KEYS, Fake({"paid": [LlmReply(503, b"", 2.0)]}), store, Clock())
    call = Call(privacy.request([dossier()]), "Assess the item. Answer in JSON.", "assess")
    done = await gw.complete(call)
    assert done.provider == "free"
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT provider, model, attempt, outcome, http_status, input_tokens,"
                    " output_tokens, cost_usd, request_bytes, call_id, request_sha256"
                    " FROM llm_calls ORDER BY id"
                )
            )
        ).all()
        everything = str(
            (await conn.execute(text("SELECT row_to_json(c)::text FROM llm_calls c"))).all()
        )
    assert [r[:5] for r in rows] == [
        ("paid", "p-small", 1, "server_error", 503),
        ("free", "f-small", 2, "ok", 200),
    ]
    assert rows[1][5:8] == (400, 50, 0.0)
    assert rows[0][9] == rows[1][9] == done.call_id
    assert rows[0][8] > 0
    assert len(rows[0][10]) == 64
    for value in [*(v for v in RAW if not v.startswith("2026")), "Assess the item", "sk-paid"]:
        assert value not in everything
    state = await store.state()
    assert state.breakers["paid/p-small"].is_open(NOW)  # the model's answers (Q-G1)


async def test_the_kill_switch_is_audited_and_shared(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    a, b = PgLlmStore(app_engine), PgLlmStore(app_engine)
    assert await a.set_stopped(True, actor="cli", reason="maintenance") is True
    assert await b.set_stopped(True, actor="cli", reason=None) is False
    assert (await b.state()).stopped
    admission = await b.change(lambda s: budget.admit(s, ASK, NOW, budget.Config()))
    assert admission.why == "stopped"
    # the runtime may stop, only the owner resumes (migration 0027, Q-A5)
    with pytest.raises(DBAPIError) as refused:
        await b.set_stopped(False, actor="cli", reason=None)
    assert getattr(refused.value.orig, "sqlstate", None) == "42501"
    assert (await a.state()).stopped
    assert await PgLlmStore(migrated_engine).set_stopped(False, actor="cli", reason=None) is True
    assert not (await a.state()).stopped
    async with app_engine.connect() as conn:
        audit = (
            await conn.execute(
                text(
                    "SELECT action, target_type, target_id, details->>'changed',"
                    " details->>'reason' FROM audit_events ORDER BY id"
                )
            )
        ).all()
    assert audit == [
        ("llm.stop", "llm_gateway", "gateway", "true", "maintenance"),
        ("llm.stop", "llm_gateway", "gateway", "false", None),
        ("llm.resume", "llm_gateway", "gateway", "true", None),
    ]


async def test_a_stopped_gateway_defers_through_the_store(
    app_engine: AsyncEngine, privacy: Privacy
) -> None:
    store = PgLlmStore(app_engine)
    await store.set_stopped(True, actor="cli", reason=None)
    fake = Fake()
    gw = LlmGateway(config(), KEYS, fake, store, Clock())
    with pytest.raises(NoCapacity, match="stopped"):
        await gw.complete(Call(privacy.request([dossier()]), "Answer in JSON.", "assess"))
    assert fake.sent == []


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM llm_calls",
        "UPDATE llm_calls SET outcome = 'ok'",
        "DELETE FROM llm_state",
        "INSERT INTO llm_state (name) VALUES ('other')",
        "UPDATE llm_state SET name = 'x'",
    ],
)
async def test_the_runtime_role_cannot_rewrite_the_ledger_or_the_state_row(
    app_engine: AsyncEngine, sql: str
) -> None:
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text(sql))


@pytest.mark.parametrize(
    ("column", "value"),
    [("attempt", -1), ("cost_usd", -0.5), ("input_tokens", -1), ("request_sha256", "abc")],
)
async def test_the_ledger_refuses_impossible_rows(
    app_engine: AsyncEngine, column: str, value: Any
) -> None:
    row: dict[str, Any] = {
        "at": NOW, "call_id": "00000000-0000-0000-0000-000000000001", "attempt": 1,
        "provider": "p", "model": "m", "tier": "small", "purpose": "t", "priority": "high",
        "outcome": "ok", "http_status": 200, "input_tokens": 1, "output_tokens": 1,
        "cost_usd": 0.0, "latency_ms": 1, "request_bytes": 1, "request_sha256": "",
    }  # fmt: skip
    row[column] = value
    names = ", ".join(row)
    binds = ", ".join(":" + k for k in row)
    with pytest.raises(DBAPIError, match="check constraint"):
        async with app_engine.begin() as conn:
            await conn.execute(
                text(f"INSERT INTO llm_calls ({names}) VALUES ({binds})"),  # noqa: S608
                row,
            )


async def test_reconcile_sets_the_month_to_the_ledger(app_engine: AsyncEngine) -> None:
    store = PgLlmStore(app_engine)
    inflated = budget.State(month="2026-10", spent_usd=7.5)
    await store.change(lambda s: (None, inflated))
    first = NOW.replace(day=1, hour=0, minute=0)
    midnight = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    entries = (
        (NOW, 0.25),
        (first, 0.5),
        (first - timedelta(seconds=1), 9.0),
        (midnight, 0.1250004),
    )  # the day's first instant; 6 places drop the 4
    for when, cost in entries:
        await store.record(CallEntry(at=when, call_id=uuid.uuid4(), attempt=1, provider="p",
                                     model="m", tier="small", purpose="t", priority="normal",
                                     outcome="ok", cost_usd=cost))  # fmt: skip
    assert await store.reconcile(NOW, actor="cli") == (7.5, 0.875)
    state = await store.state()
    assert state.spent_usd == 0.875
    assert (state.day, state.day_spent_usd) == ("2026-10-16", 0.375)
    async with app_engine.connect() as conn:
        query = ("SELECT action, target_type, target_id, details->>'before',"
                 " details->>'after' FROM audit_events")  # fmt: skip
        audit = (await conn.execute(text(query))).all()
    assert audit == [("llm.reconcile", "llm_gateway", "gateway", "7.5", "0.875")]
    november = NOW.replace(month=11, day=2)
    assert await store.reconcile(november, actor="cli") == (0.0, 0.0)


async def test_a_probe_found_up_clears_the_alarm_audited(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Q-G1's review, F4: `argus llm probe` clears an alarm and its cool-down once the provider
    is up again, as the runtime role, with an audit event."""
    store = PgLlmStore(app_engine)

    def alarmed(s: budget.State) -> tuple[None, budget.State]:
        s = budget.cool_down(s, "local", NOW + timedelta(hours=1), NOW)
        return None, budget.raise_alarm(s, "local", "tls_failed", "not pinned", NOW)

    await store.change(alarmed)
    cleared = await store.probe_up("local", NOW + timedelta(minutes=2), actor="cli")
    assert cleared is not None
    assert cleared.kind == "tls_failed"
    state = await store.state()
    assert state.alarms == {}
    assert "local" not in state.cooldowns
    assert state.probed["local"] == NOW + timedelta(minutes=2)
    assert await store.probe_up("local", NOW + timedelta(minutes=3), actor="cli") is None
    async with migrated_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT actor, action, target_type, target_id, details->>'kind' FROM audit_events"
            " WHERE action = 'llm.alarm_cleared'"))).all()  # fmt: skip
    assert [tuple(r) for r in rows] == [("cli", "llm.alarm_cleared", "llm_provider", "local",
                                         "tls_failed")]  # fmt: skip
