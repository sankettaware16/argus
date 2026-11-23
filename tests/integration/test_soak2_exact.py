"""The Phase 2 soak report on a designed store (P9, D-092/D-093): every line exact."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import soak2
from argus.web import auth
from tests.integration.test_soak2 import CONFIG
from tests.integration.tuning.test_report_exact import assessment, investigation, review

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 9, 0, tzinfo=UTC)
END = START + timedelta(days=3)
H = timedelta(hours=1)


async def elk(conn: Any, when: datetime, outcome: str) -> None:
    await conn.execute(text(
        "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
        " outcome, http_status, took_ms, elapsed_ms, response_bytes, attempts)"
        " VALUES (:a, 'collector', 'collect', 't', 1, '{}', :o, NULL, 0, 0, 0, 1)"),
        {"a": when, "o": outcome})  # fmt: skip


async def call(conn: Any, when: datetime, outcome: str, cost: float = 0.0, attempt: int = 1,
               provider: str = "g", model: str = "m", tokens: int = 1) -> None:  # fmt: skip
    await conn.execute(text(
        "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose, priority,"
        " outcome, http_status, input_tokens, output_tokens, cost_usd, latency_ms,"
        " request_bytes, request_sha256) VALUES (:a, gen_random_uuid(), :n, :p, :m, 'small',"
        " 'assess', 'normal', :o, 200, :t, 0, :c, 1, 1, '')"),
        {"a": when, "o": outcome, "c": cost, "n": attempt, "p": provider, "m": model,
         "t": tokens})  # fmt: skip


async def samples(conn: Any, every: timedelta = timedelta(minutes=15)) -> None:
    t = START
    while t < END:
        await conn.execute(text("INSERT INTO soak_samples (at, metrics) VALUES (:a, '{}')"),
                           {"a": t})  # fmt: skip
        t += every


async def test_outage_spans(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await elk(conn, START + H, "ok")
        for k in (2, 3, 4):  # unreachable for three hours, then back
            await elk(conn, START + k * H, "transport_failure")
        await elk(conn, START + 4 * H, "timed_out")
        await elk(conn, START + 5 * H, "ok")
        await elk(conn, START + 6 * H, "timed_out")  # mixed with an answer: not an outage
        await elk(conn, START + 6 * H, "ok")
        await elk(conn, START + 9 * H, "transport_failure")  # open at the end
        await call(conn, START + H, "no_answer: ConnectTimeout")
        await call(conn, START + 2 * H, "ok")
        await call(conn, START + 3 * H, "no_answer: x", attempt=0)  # not an attempt
        await call(conn, START + 4 * H, "rate_limited")  # an answer, not an outage
    async with migrated_engine.connect() as conn:
        got = await soak2.outages(conn, START, END)
    assert got == {
        "siem": ["10-09 02:00 to 10-09 05:00", "10-09 09:00 to 10-09 10:00 (open)"],
        "models": ["10-09 01:00 to 10-09 02:00"],
    }
    async with migrated_engine.connect() as conn:
        assert await soak2.outages(conn, END, END + H) == {"siem": [], "models": []}


async def test_every_line_on_a_clean_window(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await samples(conn)
        await call(conn, START + H, "ok", cost=0.5)
        await call(conn, START + H, "blocked", attempt=0)
        await conn.execute(text(
            "INSERT INTO tuning_reports (rule, week_end, report, suggestions, dropped, model,"
            " cost_usd, created_at) VALUES ('r', :e, '{}', '[]', '[]', 'm', 0, :e)"),
            {"e": START})  # fmt: skip
    async with migrated_engine.connect() as conn:
        rendered = soak2.render(await soak2.report(conn, CONFIG, START, END))
    assert rendered == [
        "[PASS] siem reachable: no outage",
        "[PASS] models reachable: no outage",
        "[PASS] services ran the whole window: no gap in the samples",
        "[OPEN] 1. no leak: 1 model attempts; the validator refused 1 (each one a leak"
        " prevented). The independent sweep over the window's dossiers decides the criterion:"
        " scripts/privacy_sweep.py",
        "[PASS] 2. no true positive proposed benign (soak): 0 proposals a person's verdict can"
        " check; 0 benign on a true positive",
        "[OPEN] 3. benign proposals precise (>= 95%, lower bound >= 90%): checked against"
        " verdicts: not measured (no items)",
        "[PASS] 4a. budgets never exceeded: no minute or day over a limit",
        "[PASS] 4b. monthly cost within the cap: $0.5000 of $1.00",
        "[PASS] 4c. waiting loses nothing; the backlog clears within a day: 0 deferrals;"
        " 0 assessments failed; the oldest waiting: none",
        "[OPEN] 5. tuning report reviewed for the 3 noisiest rules: 1 reports stored; the"
        " review is recorded in the exit report",
        "[OPEN] 6. a reviewer task test: walked through by the lead (D-092); a person's own time"
        " needs the user",
    ]


async def test_failures_are_named(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await samples(conn, every=timedelta(hours=2))  # gaps everywhere
        await call(conn, START + H, "ok", cost=0.75)
        await call(conn, START.replace(day=1) + H, "ok", cost=0.5)  # same month, before
        await call(conn, START - timedelta(days=9), "ok", cost=5.0)  # last month
        for _k in range(9):  # g/m: rpm 10 at margin 0.8 = 8
            await call(conn, START + 2 * H, "ok", provider="g", model="m")
        inv = await investigation(conn, "R", "r", "[]", START, 1)
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, deferrals, failures, error, created_at) VALUES (:i, 1,"
            " 'p', :h, :w, 'agent@1', 'failed', now(), 7, 5, 'gave up', :c)"),
            {"i": inv, "h": "a" * 64, "w": "b" * 64, "c": START + H})  # fmt: skip
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, created_at) VALUES (:i, 1, 'p', :h, :w, 'agent@1',"
            " 'queued', now(), :c)"),
            {"i": inv, "h": "a" * 64, "w": "c" * 64,
             "c": END - timedelta(days=1, seconds=1)})  # fmt: skip
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    services = got["services ran the whole window"]
    assert services.verdict == "INFO"
    assert services.detail.startswith("36 gap(s): 10-09 00:00 to 10-09 02:00 UTC; ")
    assert services.detail.count(";") == 7  # the first 8 only
    assert got["4a. budgets never exceeded"].verdict == "FAIL"
    assert got["4a. budgets never exceeded"].detail == (
        "g/m: 9 requests in a minute (2026-10-09 02:00:00+00:00)"
    )
    assert got["4b. monthly cost within the cap"].verdict == "FAIL"
    assert got["4b. monthly cost within the cap"].detail == "$1.2500 of $1.00"
    backlog = got["4c. waiting loses nothing; the backlog clears within a day"]
    assert backlog.verdict == "FAIL"
    assert backlog.detail == ("7 deferrals; 1 assessments failed; the oldest waiting:"
                              " 1 day, 0:00:01")  # fmt: skip
    assert got["5. tuning report reviewed for the 3 noisiest rules"].verdict == "FAIL"
    assert got["assessments: agent@1"].detail in ("failed: 1", "queued: 1")


async def test_a_day_old_backlog_still_passes(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        inv = await investigation(conn, "R", "r", "[]", START, 1)
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, created_at) VALUES (:i, 1, 'p', :h, :w, 'agent@1',"
            " 'running', now(), :c)"),
            {"i": inv, "h": "a" * 64, "w": "c" * 64, "c": END - timedelta(days=1)})  # fmt: skip
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    backlog = got["4c. waiting loses nothing; the backlog clears within a day"]
    assert backlog.verdict == "PASS"
    assert backlog.detail.endswith("the oldest waiting: 1 day, 0:00:00")


async def test_precise_benign_proposals_pass(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        asha = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        bot = await auth.add_user(conn, "argus-assistant", "A", "correct horse battery")
        for k in range(40):
            inv = await investigation(conn, "R", "r", "[]", START, 1)
            await assessment(conn, inv, 1, "engine@1", "benign_expected", k)
            await review(conn, inv, asha, "rule_false_positive", START + H)
        inv = await investigation(conn, "R", "r", "[]", START, 1)  # only the assistant's
        await assessment(conn, inv, 1, "engine@1", "benign_expected", 99)
        await review(conn, inv, bot, "true_positive", START + H)
        await conn.execute(text("UPDATE assessments SET created_at = :c"), {"c": START + H})
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    precise = got["3. benign proposals precise (>= 95%, lower bound >= 90%)"]
    assert precise.verdict == "PASS"
    assert precise.detail.startswith("checked against verdicts: 40/40 = 100%")
    assert got["2. no true positive proposed benign (soak)"].detail == (
        "40 proposals a person's verdict can check; 0 benign on a true positive"
    )
    assert got["assessments: engine@1"].detail == "benign_expected: 41"


def test_constants() -> None:
    assert timedelta(minutes=45) == soak2.GAP
    assert timedelta(days=1) == soak2.BACKLOG
    assert soak2.render([soak2.Line("c", "PASS", "d")]) == ["[PASS] c: d"]


# -- boundaries (mutation work, 2026-10-21) ---------------------------------------------------


def test_records_are_frozen() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        soak2.Line("c", "PASS", "d").verdict = "FAIL"  # type: ignore[misc]


async def test_a_gap_of_exactly_45_minutes_is_not_one(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        for minutes in (0, 45, 91):
            await conn.execute(text("INSERT INTO soak_samples (at, metrics) VALUES (:a, '{}')"),
                               {"a": START + timedelta(minutes=minutes)})  # fmt: skip
    async with migrated_engine.connect() as conn:
        assert await soak2.gaps(conn, START, START + timedelta(minutes=91)) == [
            "10-09 00:45 to 10-09 01:31 UTC"
        ]


async def test_provider_buckets_count_every_model_and_day_shares(
    migrated_engine: AsyncEngine,
) -> None:
    from argus.llm.providers import LlmConfig

    config = LlmConfig.model_validate({
        "margin": 0.8, "shares": {"high": 0.9, "normal": 0.8, "low": 0.5},
        "providers": [{"name": "o", "base_url": "https://o.example/v1", "keys": ["K"],
                       "limits": {"rpd": 5},
                       "models": {"small": {"name": "n"}, "medium": {"name": "n2"}}},
                      {"name": "g", "base_url": "https://g.example/v1", "keys": ["K"],
                       "models": {"small": {"name": "m",
                                            "limits": {"rpm": 10, "rpd": 10}}}}]})  # fmt: skip
    async with migrated_engine.begin() as conn:
        for model in ("n", "n", "n2", "n2"):  # 4 on the provider: floor(5 * 0.8 * 0.9) = 3
            await call(conn, START + H, "ok", provider="o", model=model)
        for _ in range(8):  # 8 in a minute: within 8 a minute, over floor(10 * 0.8 * 0.9) = 7 a day
            await call(conn, START + 2 * H, "ok", provider="g", model="m")
    async with migrated_engine.connect() as conn:
        over = await soak2.budgets(conn, config, START, END)
    assert over == ["g/m: 8 requests in a day (2026-10-09)", "o: 4 requests in a day (2026-10-09)"]


async def test_more_than_ten_overruns_are_cut(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        for minute in range(12):
            for _ in range(9):
                await call(conn, START + timedelta(minutes=minute), "ok", provider="g", model="m")
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    detail = got["4a. budgets never exceeded"].detail
    assert detail.count("; ") == 9
    assert detail.startswith("g/m: 9 requests in a minute (2026-10-09 00:00:00+00:00); g/m: 9")
    assert detail.endswith("(2026-10-09 00:09:00+00:00)")  # the first 10 of 12


async def test_an_outage_line_and_the_cost_at_the_cap(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await elk(conn, START + H, "transport_failure")
        await elk(conn, START + 3 * H, "timed_out")
        await elk(conn, START + 4 * H, "ok")
        await call(conn, START + H, "ok", cost=1.0)  # exactly the cap
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    assert got["siem reachable"] == soak2.Line(
        "siem reachable", "INFO",
        "unreachable 10-09 01:00 to 10-09 04:00 UTC",
    )  # fmt: skip
    assert got["4b. monthly cost within the cap"].verdict == "PASS"


async def test_precision_needs_both_the_rate_and_the_lower_bound(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        asha = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        for k in range(20):  # 19 of 20 right: 95%, but the lower bound is far under 90%
            inv = await investigation(conn, "R", "r", "[]", START, 1)
            await assessment(conn, inv, 1, "engine@1", "benign_expected", k)
            await review(conn, inv, asha, "true_positive" if k == 0 else "benign_policy",
                         START + H)  # fmt: skip
        await conn.execute(text("UPDATE assessments SET created_at = :c"), {"c": START + H})
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    precise = got["3. benign proposals precise (>= 95%, lower bound >= 90%)"]
    assert precise.verdict == "OPEN"
    assert precise.detail.startswith("checked against verdicts: 19/20 = 95%")
    assert got["2. no true positive proposed benign (soak)"].verdict == "FAIL"


async def test_exactly_95_percent_with_a_high_lower_bound_passes(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        asha = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        for k in range(200):  # 190 of 200: exactly 95%, lower bound about 91%
            inv = await investigation(conn, "R", "r", "[]", START, 1)
            await assessment(conn, inv, 1, "engine@1", "benign_expected", k)
            await review(conn, inv, asha, "inconclusive" if k < 10 else "benign_policy",
                         START + H)  # fmt: skip
        await conn.execute(text("UPDATE assessments SET created_at = :c"), {"c": START + H})
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    assert got["3. benign proposals precise (>= 95%, lower bound >= 90%)"].verdict == "PASS"


async def test_a_failed_assessment_fails_4c_and_ages_are_shown_without_microseconds(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        inv = await investigation(conn, "R", "r", "[]", START, 1)
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, failures, error, created_at) VALUES (:i, 1, 'p', :h,"
            " :w, 'agent@1', 'failed', now(), 5, 'gave up', :c)"),
            {"i": inv, "h": "a" * 64, "w": "b" * 64, "c": START + H})  # fmt: skip
        await conn.execute(text(
            "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
            " assessor, status, run_after, created_at) VALUES (:i, 1, 'p', :h, :w, 'agent@1',"
            " 'queued', now(), :c)"),
            {"i": inv, "h": "a" * 64, "w": "c" * 64,
             "c": END - timedelta(hours=1, microseconds=500_000)})  # fmt: skip
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    backlog = got["4c. waiting loses nothing; the backlog clears within a day"]
    assert backlog.verdict == "FAIL"  # fresh, but one assessment failed
    assert backlog.detail == "0 deferrals; 1 assessments failed; the oldest waiting: 1:00:00"


async def test_token_limits_at_their_boundary_and_with_shares(migrated_engine: AsyncEngine) -> None:
    from argus.llm.providers import LlmConfig

    config = LlmConfig.model_validate({
        "margin": 0.8, "shares": {"high": 0.9, "normal": 0.8, "low": 0.5},
        "providers": [{"name": "g", "base_url": "https://g.example/v1", "keys": ["K"],
                       "models": {"small": {"name": "m",
                                            "limits": {"tpm": 100, "tpd": 1000}}}}]})  # fmt: skip
    async with migrated_engine.begin() as conn:
        await call(conn, START + H, "ok", tokens=80)  # exactly floor(100 * 0.8): not over
        for k in range(8):  # day: 720 = floor(1000 * .8 * .9), 80 a minute
            await call(conn, START + 2 * H + k * timedelta(minutes=1), "ok", tokens=80)
    async with migrated_engine.connect() as conn:
        assert await soak2.budgets(conn, config, START, END) == []
    async with migrated_engine.begin() as conn:
        await call(conn, START + 3 * H, "ok", tokens=1)  # one more: over the day only
    async with migrated_engine.connect() as conn:
        assert await soak2.budgets(conn, config, START, END) == [
            "g/m: 721 tokens in a day (2026-10-09)"
        ]


async def test_two_outages_are_joined(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await elk(conn, START + H, "transport_failure")
        await elk(conn, START + 2 * H, "ok")
        await elk(conn, START + 3 * H, "transport_failure")
        await elk(conn, START + 4 * H, "ok")
    async with migrated_engine.connect() as conn:
        got = {line.criterion: line for line in await soak2.report(conn, CONFIG, START, END)}
    assert got["siem reachable"].detail == (
        "unreachable 10-09 01:00 to 10-09 02:00; 10-09 03:00 to 10-09 04:00 UTC"
    )
