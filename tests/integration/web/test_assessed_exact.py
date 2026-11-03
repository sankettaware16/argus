"""The Inbox's assessment queries exactly (P8, D-091/D-094): caps, windows, boundaries."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.llm import budget
from argus.llm.providers import LlmConfig
from argus.web import assessed, auth
from tests.integration.test_soak2_exact import call
from tests.integration.tuning.test_report_exact import assessment, investigation

pytestmark = pytest.mark.integration
NOW = datetime(2026, 10, 9, 13, 0, tzinfo=UTC)
D = timedelta(days=1)


def test_constants_and_records() -> None:
    assert (assessed.SAMPLE, assessed.GROUP_LIMIT) == (3, 500)
    shown = assessed.Shown(1, "proposed", None, None, "s", "k", (), None)
    item = assessed.Proposal(1, uuid.uuid4(), "r", 1, NOW, "")
    m = assessed.Metrics(0, {}, 0, 0, {}, {}, 0.0)
    for record in (shown, item, m):
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.status = "x"  # type: ignore[misc]


async def test_current_cuts_its_reasons(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        inv = await investigation(conn, "R", "r", "[]", NOW, 1)
        aid = await assessment(conn, inv, 1, "agent@1", "true_positive", 1)
        await conn.execute(text("UPDATE assessments SET reasons = CAST(:r AS jsonb) WHERE id = :i"),
                           {"r": '["' + "x" * 700 + '"' + ', "r"' * 9 + "]", "i": aid})  # fmt: skip
        got = await assessed.current(conn, inv)
    assert got is not None
    assert len(got.reasons) == 8
    assert got.reasons[0] == "x" * 600


async def test_groups_cap_reasons_models_and_skips(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key,"
            " bucket_start, bucket_end, previous_id, alert_count, first_event_at, last_event_at,"
            " severity, version) SELECT gen_random_uuid(), '1', 'r', 'R', 'k' || g, :s, :e,"
            " gen_random_uuid(), 1, :s, :s, 'low', 1 FROM generate_series(1, 501) g"),
            {"s": NOW, "e": NOW + D})  # fmt: skip
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, outcome, decided_by, reasons) SELECT id, 1, 'p',"
            " repeat('a', 64), md5(id::text) || md5(id::text), 'agent@1', 'proposed', now(),"
            " 'true_positive', 'agent@1#a,b', NULL FROM investigations"))  # fmt: skip
        inv = await investigation(conn, "S", "s", "[]", NOW, 1)
        aid = await assessment(conn, inv, 1, "agent@1", "true_positive", 7)
        await conn.execute(text("UPDATE assessments SET reasons = CAST(:r AS jsonb) WHERE id = :i"),
                           {"r": '["' + "y" * 400 + '"]', "i": aid})  # fmt: skip
        groups = await assessed.proposals(conn, date(2026, 10, 9))
        uid = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        got = await assessed.confirm(conn, groups[0].group, [10**9], uid, "n")
    big = next(g for g in groups if g.rule == "R")
    assert len(big.items) == 500  # GROUP_LIMIT: the 501st is not listed
    assert big.models == {"a", "b"}
    assert big.items[0].reason == ""
    small = next(g for g in groups if g.rule == "S")
    assert small.items[0].reason == "y" * 300
    assert len(small.sample) == 1
    assert len(big.sample) == 3
    assert got == (0, 1)  # an id that does not exist is skipped


async def test_metrics_windows(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await call(conn, NOW - D, "ok", cost=0.25, provider="p")  # inside the day
        await call(conn, NOW - D - timedelta(seconds=1), "ok", cost=1.0, provider="p")
        await call(conn, NOW - D, "ok", attempt=2, provider="q")  # a fallback answer
        await call(conn, NOW - 7 * D, "blocked", attempt=0)  # inside the week
        await call(conn, NOW - 7 * D - timedelta(seconds=1), "blocked", attempt=0)
        inv = await investigation(conn, "R", "r", "[]", NOW, 1)
        for n, (status, when) in enumerate((("no_decision", NOW - 7 * D),
                                            ("no_decision", NOW - 8 * D))):  # fmt: skip
            await conn.execute(text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                " view_hash, assessor, status, run_after, reasons, created_at) VALUES (:i, 1,"
                " 'p', :h, :w, 'agent@1', :s, now(), '[\"floor: x\"]', :c)"),
                {"i": inv, "h": "a" * 64, "w": f"{n:064x}", "s": status, "c": when})  # fmt: skip
        m = await assessed.metrics(conn, NOW)
    assert m.validator_blocks == 1
    assert m.calls == {"p": (1, 1, 0.25), "q": (1, 1, 0.0)}
    assert m.fallbacks == 1
    assert m.floor_hits == 1
    assert m.outcomes == {"agent@1": {"no_decision": 1}}
    assert m.month_cost == pytest.approx(1.25)
    assert m.backlog == {}


def test_quota() -> None:
    config = LlmConfig.model_validate({"providers": [
        {"name": "g", "base_url": "https://g.example/v1", "keys": ["K"], "limits": {"rpd": 50},
         "models": {"small": {"name": "m", "limits": {"tpd": 1000}},
                    "medium": {"name": "n"}}}]})  # fmt: skip
    state = budget.State(windows={
        "g": budget.Window(NOW.replace(second=0), 1, 1, NOW.date(), 7, 70),
        "g/m": budget.Window(NOW.replace(second=0), 1, 1, NOW.date() - D, 9, 900),
    })  # fmt: skip
    assert assessed.quota(state, config, NOW) == [
        ("g", "7 of 50 requests, 70 tokens"),
        ("g/m", "0 requests, 0 of 1000 tokens"),  # yesterday's counts are not today's
    ]
    assert assessed.quota(budget.State(), config, NOW) == [
        ("g", "0 of 50 requests, 0 tokens"), ("g/m", "0 requests, 0 of 1000 tokens")]  # fmt: skip


async def test_cost_boundaries_and_rounding(migrated_engine: AsyncEngine) -> None:
    day = NOW.replace(hour=0)
    month = NOW.replace(day=1, hour=0)
    async with migrated_engine.begin() as conn:
        await call(conn, day, "ok", cost=0.1234567)  # the day's first instant
        await call(conn, day - timedelta(seconds=1), "ok", cost=0.2)  # yesterday
        await call(conn, month, "ok", cost=0.3)  # the month's first instant
        await call(conn, month - timedelta(seconds=1), "ok", cost=5.0)  # last month
        await call(conn, NOW + timedelta(seconds=1), "ok", cost=9.0)  # after now
        got = await assessed.cost(conn, NOW, 10.0, 1 / 3)
    assert got["month_usd"] == round(0.1234567 + 0.2 + 0.3, 6)
    assert got["today_usd"] == 0.123457
    assert got["providers"] == {"g": {"today_usd": 0.123457, "calls": 1}}
    assert got["paid_until_usd"] == 3.33
    assert got["calls_today"] == 1
    assert got["stopped"] is False


async def test_a_listed_proposal_reviewed_meanwhile_is_skipped(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        uid = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        inv = await investigation(conn, "R", "r", "[]", NOW, 1)
        aid = await assessment(conn, inv, 1, "agent@1", "true_positive", 1)
        await conn.execute(text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
            " outcome) VALUES (:i, 1, 1, :u, 'reviewed', 'benign_policy')"),
            {"i": inv, "u": uid})  # fmt: skip
        got = await assessed.confirm(conn, "agent@1|R|true_positive", [aid], uid, "n")
    assert got == (0, 1)


async def test_history_order_caps_and_the_detail_line(migrated_engine: AsyncEngine) -> None:
    import dataclasses
    import json

    async with migrated_engine.begin() as conn:
        inv = await investigation(conn, "R", "r", "[]", NOW, 1)
        engine_row = await assessment(conn, inv, 1, "engine@1", "true_positive", 1)
        agent_row = await assessment(conn, inv, 1, "agent@1", "true_positive", 2)
        await assessment(conn, inv, 1, "advisor@1", "true_positive", 3)  # sorts before "agent"
        reasons = ["x" * 700, "2 rounds, 3 model calls (small), $0.01; tools: none",
                   *[f"r{k}" for k in range(9)], {"kind": "agent@1"}]  # fmt: skip
        await conn.execute(text("UPDATE assessments SET reasons = CAST(:r AS jsonb) WHERE id = :i"),
                           {"r": json.dumps(reasons), "i": agent_row})  # fmt: skip
        got = await assessed.history(conn, inv)
        verdicts = await assessed.verdicts(conn, [inv])
        none = await assessed.verdicts(conn, [])
    assert [d.assessor for d in got] == ["agent@1", "advisor@1", "engine@1"]  # the AI first
    agent = got[0]
    assert agent.reasons[0] == "x" * 600
    assert len(agent.reasons) == 8
    assert "2 rounds, 3 model calls (small), $0.01; tools: none" not in agent.reasons
    assert agent.report == {"kind": "agent@1"}
    assert got[2].assessment_id == engine_row
    assert got[2].report is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        agent.status = "x"  # type: ignore[misc]
    assert verdicts == {inv: {"assessor": "agent@1", "source": "the AI investigator",
                              "status": "proposed", "outcome": "true_positive",
                              "confidence": None}}  # fmt: skip
    assert none == {}
