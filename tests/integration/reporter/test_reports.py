"""The Reporter end to end on a throwaway database (Q-H3): the history table and its grants, the
CLI, a section that cannot be read, and a report made with every provider and the SIEM down (any
request of any kind fails the test)."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.reporter import build, render, store
from argus.reporter.model import Numbers, window_for
from tests.integration.reporter import oracle, seed
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

LAST = seed.DAY.date()


@pytest.fixture(autouse=True)
def nothing_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No provider, no SIEM, no Kibana: a request of any kind fails the test."""

    def refuse(*args: Any, **kw: Any) -> Any:
        raise AssertionError("the Reporter sent a request")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    monkeypatch.setattr(httpx.Client, "send", refuse)


async def made(engine: AsyncEngine, kind: str = "daily") -> tuple[Numbers, str]:
    return await build.make(engine, kind, LAST, seed.AS_AT)  # type: ignore[arg-type]


async def test_a_report_is_stored_once_and_read_back_whole(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await seed.seed(migrated_engine)
    numbers, body = await made(app_engine)
    async with app_engine.begin() as conn:
        first = await store.save(conn, numbers, body)
        again = await store.save(conn, numbers, body + "changed")
    assert first is not None
    assert again is None  # a second run for the period is refused, not rewritten
    async with web_engine.connect() as conn:  # the web reads it as it was written
        got = await store.get(conn, first)
        listed = await store.listing(conn)
    assert got is not None
    assert got.numbers == numbers
    assert got.text == body
    assert got.prose is None
    assert [(r.id, r.kind) for r in listed] == [(first, "daily")]


async def test_nobody_but_the_owner_can_change_or_delete_a_report(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    numbers, body = await made(app_engine)
    async with app_engine.begin() as conn:
        report_id = await store.save(conn, numbers, body)
    for engine, sql in (
        (app_engine, "UPDATE reports SET text = 'edited'"),
        (app_engine, "DELETE FROM reports"),
        (app_engine, "UPDATE reports SET prose = 'x', prose_agent = 'y'"),
        (web_engine, "UPDATE reports SET text = 'edited'"),
        (web_engine, "DELETE FROM reports"),
        (web_engine, "INSERT INTO reports (kind) VALUES ('daily')"),
    ):
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with engine.begin() as conn:
                await conn.execute(text(sql))
    async with migrated_engine.connect() as conn:
        row = (
            await conn.execute(text("SELECT text FROM reports WHERE id = :i"), {"i": report_id})
        ).one()
    assert row.text == body


@pytest.mark.parametrize(
    ("kind", "start", "end", "prose", "agent"),
    [
        ("daily", "2026-10-20", "2026-10-22", None, None),  # a day is one day
        ("weekly", "2026-10-14", "2026-10-20", None, None),  # a week is seven
        ("daily", "2026-10-20 05:30", "2026-10-21 05:30", None, None),  # whole UTC days
        ("monthly", "2026-10-20", "2026-10-21", None, None),
        ("daily", "2026-10-20", "2026-10-21", "words", None),  # prose says which agent wrote it
        ("daily", "2026-10-20", "2026-10-21", None, "reporter@1"),
        ("daily", "2026-10-20", "2026-10-21", "", "reporter@1"),
    ],
)
async def test_the_table_refuses_a_report_that_is_not_a_whole_period(
    migrated_engine: AsyncEngine,
    kind: str,
    start: str,
    end: str,
    prose: str | None,
    agent: str | None,
) -> None:
    with pytest.raises(DBAPIError, match="violates check constraint"):
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO reports (kind, period_start, period_end, numbers, text, prose,"
                    " prose_agent) VALUES (:k, CAST(:s AS timestamptz), CAST(:e AS timestamptz),"
                    " CAST('{}' AS jsonb), 'x', :p, :a)"
                ),
                {"k": kind, "s": f"{start} UTC", "e": f"{end} UTC", "p": prose, "a": agent},
            )


async def test_a_section_that_cannot_be_read_is_a_note_and_the_rest_stand(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    from argus.reporter import sections

    async def cases_cannot_be_read(conn: AsyncConnection, w: Any) -> Any:
        await conn.execute(text("SELECT * FROM there_is_no_such_table"))

    cases_cannot_be_read.__name__ = "cases"
    await seed.seed(migrated_engine)
    async with build.snapshot(app_engine) as conn:
        numbers = await build.build(
            conn,
            "daily",
            LAST,
            seed.AS_AT,
            builders=[cases_cannot_be_read, sections.closures],  # type: ignore[arg-type]
        )
    broken, fine = numbers.sections
    assert broken.metrics == ()
    assert "could not be read" in broken.notes[0]
    window = window_for("daily", LAST, seed.AS_AT)  # type: ignore[arg-type]
    want = await oracle.expected(migrated_engine, window)
    assert {m.key: m.value for m in fine.metrics} == {
        k: v for k, v in want.items() if k.startswith("closures.")
    }
    assert "This section could not be read" in render.text_of(numbers)


async def test_a_report_is_made_on_time_with_every_provider_and_siem_down(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The model gateway is stopped and every call it recorded failed; the SIEM's breaker is open
    and its switch is stopped. The report needs none of it: it reads ARGUS's own database."""
    await seed.seed(migrated_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO llm_state (name, state) VALUES ('gateway', CAST(:s AS jsonb))"
                " ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state"
            ),
            {"s": json.dumps({"stopped": True})},
        )
        await conn.execute(
            text(
                "INSERT INTO siem_switches (component, stopped, reason, changed_by)"
                " VALUES ('global', true, 'test', 'test')"
                " ON CONFLICT (component) DO UPDATE SET stopped = true"
            )
        )
    started = time.monotonic()
    numbers, body = await made(app_engine)
    took = time.monotonic() - started
    assert took < 10, took  # on a seeded database of a few hundred rows
    assert len(numbers.metrics()) > 100
    assert body.startswith("ARGUS daily report for the UTC day 20 Oct 2026\n")
    print(f"MEASURED report of {len(numbers.metrics())} figures in {took:.2f} s")


def test_the_report_modules_import_no_model_client() -> None:
    code = (
        "import sys, argus.reporter.build, argus.reporter.render, argus.reporter.store,"
        " argus.reporter.prose, argus.reporter.sections;"
        "print(sorted(m for m in sys.modules if m.split('.')[0] in ('httpx', 'openai', 'groq',"
        " 'anthropic', 'google') or m in ('argus.llm.gateway', 'argus.llm.wire',"
        " 'argus.llm.service', 'argus.llm.egress', 'argus.agent.agent')"
        " or m.startswith(('argus.gateway.gateway', 'argus.gateway.kibana'))))"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == "[]", done.stdout


async def test_the_cli_makes_one_report_a_period_and_a_dry_run_stores_nothing(
    migrated_engine: AsyncEngine,
    cli_env: Any,  # noqa: F811
) -> None:
    await seed.seed(migrated_engine)
    day = LAST.isoformat()

    async def run(*args: str) -> Any:
        return await asyncio.to_thread(_run, *args, "--config", str(cli_env))

    async def count() -> int:
        async with migrated_engine.connect() as conn:
            return int((await conn.execute(text("SELECT count(*) FROM reports"))).scalar_one())

    dry = await run("report", "daily", "--date", day, "--dry-run")
    assert dry.exit_code == 0, dry.output + dry.stderr
    assert "ARGUS daily report for the UTC day 20 Oct 2026" in dry.output
    assert "nothing stored" in dry.output
    assert await count() == 0
    first = await run("report", "daily", "--date", day)
    assert first.exit_code == 0, first.output + first.stderr
    assert "daily report" in first.output
    assert "stored" in first.output
    again = await run("report", "daily", "--date", day)
    assert again.exit_code == 0
    assert "already made" in again.output
    week = await run("report", "weekly", "--date", day)
    assert week.exit_code == 0, week.output + week.stderr
    assert await count() == 2
    async with migrated_engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT kind, period_start, period_end FROM reports ORDER BY id")
            )
        ).all()
        audited = (
            await conn.execute(
                text(
                    "SELECT actor, action, target_type FROM audit_events"
                    " WHERE action = 'report.made'"
                )
            )
        ).all()
    assert [
        (r.kind, r.period_start.date().isoformat(), r.period_end.date().isoformat()) for r in rows
    ] == [
        ("daily", "2026-10-20", "2026-10-21"),
        ("weekly", "2026-10-14", "2026-10-21"),
    ]
    assert [tuple(a) for a in audited] == [("argus:reporter", "report.made", "report")] * 2


@pytest.mark.parametrize("day", ["2999-01-01", "not-a-date", "2026-13-40"])
async def test_the_cli_refuses_a_day_that_has_not_ended_or_is_not_a_date(
    migrated_engine: AsyncEngine,
    cli_env: Any,  # noqa: F811
    day: str,
) -> None:
    result = await asyncio.to_thread(
        _run, "report", "daily", "--date", day, "--config", str(cli_env)
    )
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    async with migrated_engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM reports"))).scalar_one() == 0


async def test_the_default_day_is_the_last_that_has_ended() -> None:
    from argus.reporter.cli import last_day_of

    now = datetime(2026, 10, 21, 0, 0, 1, tzinfo=UTC)
    assert last_day_of(None, now).isoformat() == "2026-10-20"
    assert (
        last_day_of(None, datetime(2026, 10, 20, 23, 59, 59, tzinfo=UTC)).isoformat()
        == "2026-10-19"
    )
