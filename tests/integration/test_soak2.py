"""The Phase 2 soak report (P9, D-092): gaps in the samples, budgets recomputed from the
ledger, proposals checked against people's verdicts, the backlog, and what stays open."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import soak2
from argus.assess import queue
from argus.llm.providers import LlmConfig
from argus.web import queries
from tests.integration.web.conftest import seeded  # noqa: F401 - a fixture
from tests.integration.web.test_reviewed import decide

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 9, 0, tzinfo=UTC)
END = START + timedelta(days=3)
CONFIG = LlmConfig.model_validate({"margin": 0.8, "monthly_cap_usd": 1.0, "providers": [
    {"name": "g", "base_url": "https://g.example/v1", "keys": ["K"],
     "models": {"small": {"name": "m", "limits": {"rpm": 10, "tpd": 1000}}}},
    {"name": "o", "base_url": "https://o.example/v1", "keys": ["K"], "limits": {"rpd": 5},
     "models": {"small": {"name": "n"}}}]})  # fmt: skip


async def calls(engine: AsyncEngine, rows: list[dict[str, Any]]) -> None:
    async with engine.begin() as conn:
        for r in rows:
            await conn.execute(text(
                "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
                " priority, outcome, http_status, input_tokens, output_tokens, cost_usd,"
                " latency_ms, request_bytes, request_sha256) VALUES (:at, gen_random_uuid(),"
                " :attempt, :p, :m, 'small', 'assess', 'normal', :o, 200, :t, 0, :c, 1, 1, '')"),
                {"attempt": 1, "o": "ok", "t": 10, "c": 0.0, **r})  # fmt: skip


def by(lines: list[soak2.Line]) -> dict[str, soak2.Line]:
    return {line.criterion.split(".")[0] if line.criterion[0].isdigit() else line.criterion:
            line for line in lines}  # fmt: skip


async def test_budgets_are_recomputed_from_the_ledger(app_engine: AsyncEngine) -> None:
    t = START + timedelta(hours=1)
    await calls(app_engine, [{"at": t, "p": "g", "m": "m"} for _ in range(8)])
    await calls(app_engine, [{"at": t, "p": "o", "m": "n"} for _ in range(4)])
    async with app_engine.connect() as conn:
        assert await soak2.budgets(conn, CONFIG, START, END) == []
    more = [{"at": t, "p": "g", "m": "m", "t": 900},
            {"at": t + timedelta(hours=1), "p": "o", "m": "n"},
            {"at": t, "p": "g", "m": "m", "attempt": 0, "o": "blocked"}]  # fmt: skip
    await calls(app_engine, more)
    async with app_engine.connect() as conn:
        over = await soak2.budgets(conn, CONFIG, START, END)
    assert "g/m: 9 requests in a minute (2026-10-09 01:00:00+00:00)" in over
    assert "g/m: 980 tokens in a day (2026-10-09)" in over
    assert "o: 5 requests in a day (2026-10-09)" in over
    assert len(over) == 3


async def test_gaps_in_the_samples(app_engine: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        for minutes in (10, 25, 40, 200, 215):
            await conn.execute(text("INSERT INTO soak_samples (at, metrics) VALUES (:a, '{}')"),
                               {"a": START + timedelta(minutes=minutes)})  # fmt: skip
    async with app_engine.connect() as conn:
        got = await soak2.gaps(conn, START, START + timedelta(minutes=230))
    assert got == ["10-09 00:40 to 10-09 03:20 UTC"]


async def test_the_report(seeded: AsyncEngine, migrated_engine: AsyncEngine) -> None:  # noqa: F811
    async with seeded.connect() as conn:
        a, b, c = (await queries.inbox(conn, "all"))[:3]
    async with seeded.begin() as conn:
        for inv, outcome, n in ((a, "benign_expected", 1), (b, "benign_expected", 2),
                                (c, "true_positive", 3)):  # fmt: skip
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", "a" * 64,
                                f"{n:064x}", "agent@1", START)  # fmt: skip
            (job,) = await queue.claim(conn, "w", START, "agent@1")
            await queue.propose(conn, job, START, outcome, "agent@1#m", [], None)
    async with migrated_engine.begin() as conn:  # the runtime cannot rewrite created_at
        await conn.execute(text("UPDATE assessments SET created_at = :t"),
                           {"t": START + timedelta(hours=2)})  # fmt: skip
    await decide(seeded, "asha", a, action="reviewed", outcome="true_positive")
    await decide(seeded, "ravi", b, action="reviewed", outcome="rule_false_positive")
    async with seeded.connect() as conn:
        lines = await soak2.report(conn, CONFIG, START, END)
    got = by(lines)
    assert got["2"].verdict == "FAIL"
    assert (
        got["2"].detail == "2 proposals a person's verdict can check; 1 benign on a true positive"
    )
    assert got["3"].verdict == "OPEN"
    assert got["3"].detail.startswith("checked against verdicts: 1/2 = 50%")
    assert got["1"].verdict == "OPEN"
    assert got["4a"].verdict == "PASS"
    assert got["4b"].detail == "$0.0000 of $1.00"
    assert got["4c"].verdict == "PASS"
    assert got["5"].verdict == "FAIL"  # no tuning report stored
    assert got["6"].verdict == "OPEN"
    assert got["services ran the whole window"].verdict == "INFO"
    assert by(lines)["assessments: agent@1"].verdict == "INFO"
    rendered = soak2.render(lines)
    assert rendered[0] == "[PASS] siem reachable: no outage"
    assert rendered[2].startswith("[INFO] services ran the whole window: 1 gap(s)")
