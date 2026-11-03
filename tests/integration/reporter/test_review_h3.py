"""Independent review of Q-H3 (reporter): repros that fail on the reviewed commit, and probes
that held (named test_held_*)."""

from __future__ import annotations

import asyncio
import json
import unicodedata
from datetime import timedelta
from itertools import pairwise
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.reporter import build, render, store
from tests.integration.reporter import seed
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration
LAST = seed.DAY.date()


async def _world(engine: AsyncEngine, more: Any) -> seed.Seed:
    made = seed.Seed()
    async with engine.begin() as conn:
        for table in seed.GUARDED:
            await conn.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        await seed._people_and_cases(conn, made)
        await more(conn, made)
        for table in seed.GUARDED:
            await conn.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    return made


async def _daily(engine: AsyncEngine) -> Any:
    async with build.snapshot(engine) as conn:
        return await build.build(conn, "daily", LAST, seed.AS_AT)


async def test_r1_expired_unsent_counts_only_requests_nothing_was_sent_for(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """kibana_outbox.approval_request_id is set only on W3 rows and only to the closure or merge
    request (0026 trigger; immutable), so a resend, reconfirm or compensating request is never
    linked that way. The seed links one by hand (triggers off); in a real database an approved
    resend whose row went out again is counted as 'expired with nothing sent'."""

    async def more(conn: AsyncConnection, made: seed.Seed) -> None:
        h = timedelta(hours=1)
        used = await seed.outbox(conn, made, "used", "sent", seed.t(-1), sent=2,
                                 sent_at=seed.t(0, 3))  # fmt: skip
        await seed.request(conn, made, "used", "assigned", "resend", seed.t(0, 2), 6 * h,
                           outbox=used, sent=1)  # fmt: skip
        await seed.decide(conn, made, "used", "ravi", "approved")  # resent: sent_count 1 -> 2
        stuck = await seed.outbox(conn, made, "stuck", "ambiguous", seed.t(-1), sent=1,
                                  sent_at=seed.t(-1, 1))  # fmt: skip
        await seed.request(conn, made, "stuck", "assigned", "resend", seed.t(0, 4), 6 * h,
                           outbox=stuck, sent=1)  # fmt: skip

    await _world(migrated_engine, more)
    got = (await _daily(app_engine)).metrics()["approvals.expired_unsent"].value
    assert got == 1  # only the resend nobody used; the one that went out again is not unsent


async def test_r1_every_kind_of_request_is_judged_by_the_table_that_records_its_send(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Closure and merge: the outbox row naming them; compensating: its Kibana step; resend: its
    outbox row sent again; reconfirm: the held-back row sent. Each kind expires twice, once with
    its send recorded and once without."""

    async def more(conn: AsyncConnection, made: seed.Seed) -> None:
        h = timedelta(hours=1)
        asked = seed.t(-1, 12)
        for kind in ("compensating", "resend", "reconfirm"):
            for went in (True, False):
                name = f"{kind}-{'out' if went else 'held'}"
                state = "paused" if kind == "reconfirm" and not went else "sent"
                sent = 2 if kind == "resend" and went else 0 if state == "paused" else 1
                row = await seed.outbox(conn, made, name, state, seed.t(-3), sent=sent,
                                        sent_at=None if sent == 0 else seed.t(-3, 1))  # fmt: skip
                more: dict[str, Any] = {"outbox": row}
                if kind == "resend":
                    more["sent"] = 1  # asked after the first send
                if kind == "reconfirm":
                    more["proposed_by"] = "argus:sendcheck"
                req = await seed.request(conn, made, name, "assigned", kind, asked, 20 * h,
                                         **more)  # fmt: skip
                if kind == "compensating":
                    await seed.step(conn, made, name, row, req, int(went))

    await _world(migrated_engine, more)
    got = (await _daily(app_engine)).metrics()["approvals.expired_unsent"].value
    assert got == 3  # one of each of the three kinds, the ones nothing was sent for


async def test_r8_a_run_makes_the_missed_periods_too(
    migrated_engine: AsyncEngine,
    cli_env: Any,  # noqa: F811
) -> None:
    """The services pass no date: a weekly run makes the last complete Monday-to-Sunday week and
    the missed ones before it (4 weeks), a daily run the last 7 days; a second run adds nothing."""
    config = str(cli_env)
    weekly = await asyncio.to_thread(_run, "report", "weekly", "--config", config)
    assert weekly.exit_code == 0, weekly.output + weekly.stderr
    daily = await asyncio.to_thread(_run, "report", "daily", "--config", config)
    assert daily.exit_code == 0, daily.output + daily.stderr
    again = await asyncio.to_thread(_run, "report", "weekly", "--config", config)
    assert "no weekly report is missing" in again.output
    async with migrated_engine.connect() as conn:
        found = list(
            await conn.execute(
                text(
                    "SELECT kind, period_start, period_end,"
                    " extract(isodow FROM period_start AT TIME ZONE 'UTC') AS dow"
                    " FROM reports ORDER BY kind, period_end"
                )
            )
        )
    weeks = [r for r in found if r.kind == "weekly"]
    assert len(weeks) == 4
    assert {int(r.dow) for r in weeks} == {1}  # every week starts on a Monday
    assert all(a.period_end == b.period_start for a, b in pairwise(weeks))
    assert len([r for r in found if r.kind == "daily"]) == 7


async def test_r2_still_active_hosts_are_the_hosts_the_watch_saw(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The proxy watch records which campus hosts reached the C2 (detail.hosts). The report lists
    every actor host or address of the case instead: a host that never contacted it, and an
    outside attacker address (role 'actor' too), appear as 'still active'."""

    async def more(conn: AsyncConnection, made: seed.Seed) -> None:
        for value, role in (("10.1.1.5", "actor"), ("10.1.1.6", "actor"),
                            ("203.0.113.9", "actor"), ("198.51.100.7", "c2")):  # fmt: skip
            await seed.ins(conn, "case_indicators", case_id=made.cases["new_open"], kind="ip",
                           value=value, role=role, source="investigation", added_version=1,
                           added_by="argus:test")  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome,"
                " window_start, window_end, asked_on, requests, detail) VALUES (:c, :d,"
                " 'proxy.contact', '198.51.100.7', 0, 'active', :ws, :we, :d, 1,"
                " CAST(:detail AS jsonb))"
            ),
            {"c": made.cases["new_open"], "d": seed.DAY.date(), "ws": seed.t(0), "we": seed.t(1),
             "detail": json.dumps({"hosts": ["10.1.1.5"], "requests": 4})},
        )  # fmt: skip

    await _world(migrated_engine, more)
    keys = {k for k in (await _daily(app_engine)).metrics() if k.startswith("active_hosts.host.")}
    assert keys == {"active_hosts.host.10.1.1.5"}


async def test_held_a_section_that_could_not_be_read_is_logged_when_the_report_is_stored(
    migrated_engine: AsyncEngine,
    cli_env: Any,  # noqa: F811
) -> None:
    """The warning reaches the log (stderr); the report is stored with the note."""
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE siem_probes RENAME TO siem_probes_x"))
    result = await asyncio.to_thread(
        _run, "report", "daily", "--date", "2026-10-20", "--config", str(cli_env)
    )
    assert result.exit_code == 0, result.output
    assert "could not be read" in result.output + result.stderr


async def test_r10_the_numbers_cannot_claim_another_period_than_the_columns(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The CHECKs hold the period columns only; the numbers JSON (and so the page's as_at and the
    downloaded JSON) can name another period than the row."""
    numbers = {"kind": "weekly", "period_start": "2020-01-01T00:00:00+00:00",
               "period_end": "2020-01-08T00:00:00+00:00"}  # fmt: skip
    with pytest.raises(Exception, match="violates check constraint"):
        async with app_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO reports (kind, period_start, period_end, numbers, text) VALUES"
                    " ('daily', '2026-10-20 UTC', '2026-10-21 UTC', CAST(:n AS jsonb), 'x')"
                ),
                {"n": json.dumps(numbers)},
            )
    for empty in ("{}", '{"kind": "daily"}'):  # missing fields are no match either
        with pytest.raises(Exception, match="violates check constraint"):
            async with app_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO reports (kind, period_start, period_end, numbers, text)"
                        " VALUES ('daily', '2026-10-20 UTC', '2026-10-21 UTC',"
                        " CAST(:n AS jsonb), 'x')"
                    ),
                    {"n": empty},
                )


async def test_r9_the_runtime_cannot_set_generated_at(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """generated_at is the database's clock: not in the runtime's column grant."""
    numbers = await _daily(app_engine)
    async with app_engine.begin() as conn:
        made = await store.save(conn, numbers, "x")
    assert made is not None
    with pytest.raises(Exception, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO reports (kind, period_start, period_end, generated_at, numbers,"
                    " text) VALUES ('daily', '2026-10-19 UTC', '2026-10-20 UTC',"
                    " '1999-01-01 UTC', CAST(:n AS jsonb), 'x')"
                ),
                {"n": json.dumps(numbers.model_dump(mode="json"))},
            )
    async with app_engine.connect() as conn:
        stored = await store.get(conn, made)
    assert stored is not None
    assert stored.generated_at.year >= 2026


HOSTILE = [
    "\u202eexe.txt", "<img src=x onerror=alert(1)>", "[x](javascript:alert(1))", "a\u200bb",
    "line1\nline2", "\x1b[31mred", "   ", "\u0301" * 400, "x" * 512, "\ufeffbom", "a\u2028b",
    "\U000e0041tag", "x`$(id)`", "'; DROP TABLE reports; --", "=cmd|' /C calc'!A0",
]  # fmt: skip


async def test_held_hostile_names_reach_the_report_only_escaped(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    async def more(conn: AsyncConnection, made: seed.Seed) -> None:
        for value in HOSTILE:
            await seed.ins(conn, "case_indicators", case_id=made.cases["new_open"], kind="host",
                           value=value, role="actor", source="investigation", added_version=1,
                           added_by="argus:test")  # fmt: skip
        await seed.ins(conn, "case_watch_checks", case_id=made.cases["new_open"],
                       day=seed.DAY.date(), source="alerts", subject="", part=0,
                       outcome="active", reason=None, window_start=seed.t(0),
                       window_end=seed.t(1))  # fmt: skip
        for src in HOSTILE[:6]:
            await conn.execute(
                text("INSERT INTO ti_sources (source, indicators) VALUES (:s, 3)"), {"s": src}
            )

    await _world(migrated_engine, more)
    numbers = await _daily(app_engine)
    body = render.text_of(numbers)
    assert all(s.metrics != () or s.notes != () for s in numbers.sections)
    for m in numbers.metrics().values():
        assert len(m.label) <= 300
        assert len(m.key) <= 200
        bad = [c for c in m.label if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]
        assert bad == [], m.key
    assert not any(unicodedata.category(c) in ("Cf", "Zl", "Zp") for c in body)
    assert "\x1b" not in body


async def test_held_seven_daily_reports_add_up_to_the_weekly_one(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Boundary property the oracle cannot give: the flow counts of the seven days that make a
    week sum to the week's (no row counted twice or not at all at a midnight)."""
    await seed.seed(migrated_engine)
    async with build.snapshot(app_engine) as conn:
        week = (await build.build(conn, "weekly", LAST, seed.AS_AT)).metrics()
        days = [
            (await build.build(conn, "daily", LAST - timedelta(days=i), seed.AS_AT)).metrics()
            for i in range(7)
        ]
    additive = [
        k for k, m in week.items()
        if m.unit in ("count", "ms") and isinstance(m.value, int)
        and "as at the making" not in m.definition and "of any date" not in m.definition
        and not k.startswith(("active_hosts.", "cases.age", "cases.suspected", "cases.open",
                              "cases.assigned", "cases.contained", "gaps.", "siem.busiest",
                              "audit.", "intel.", "kibana.lag", "actions.state",
                              "actions.waiting", "approvals.waiting"))
    ]  # fmt: skip
    off = {
        k: (week[k].value, sum(d[k].value for d in days))
        for k in additive
        if week[k].value != sum(d[k].value for d in days)
    }
    assert off == {}, off


async def test_held_an_empty_database_gives_a_whole_report(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    numbers = await _daily(app_engine)
    assert not [n for s in numbers.sections for n in s.notes if "could not be read" in n]
    assert render.text_of(numbers)
