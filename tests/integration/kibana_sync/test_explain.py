"""D-322: a person marks a reconciliation finding explained (``argus kibana sync explain``), as
the database owner. It stops counting as open (sync status and report, the daily report, the
web's attention, the writer's ramp) and lifts no pause: it says which classes are paused and the
exact resume lines."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.kibana import writes
from argus.gateway.pgstore import PgStore
from argus.kibana_sync import cli as sync_cli
from argus.kibana_sync.cycle import ALL_CLASSES, PAUSED_BY_ALARM
from argus.reporter.model import Window
from argus.reporter.sections import guardrails
from argus.writer import ramp
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

REASON = "posted by the old desktop installation before the move (4 Nov)"


async def _finding(engine: AsyncEngine, *, severity: str = "alarm", key: str | None = None) -> int:
    async with engine.begin() as conn:
        found = await conn.scalar(
            text(
                "INSERT INTO kibana_findings (found_at, kind, severity, kibana_case_id,"
                " dedupe_key, details) VALUES (now() - interval '1 day',"
                " 'unexplained_argus_case', :s, 'k-old', :k, '{}') RETURNING id"
            ),
            {"s": severity, "k": key or f"unexplained-case:{uuid.uuid4()}"},
        )
    return int(found)


async def _pause_all(engine: AsyncEngine, reason: str = PAUSED_BY_ALARM) -> None:
    def change(state: writes.KibanaLaneState) -> tuple[None, writes.KibanaLaneState]:
        for cls in ALL_CLASSES:
            state = writes.pause(state, cls, reason)
        return None, state

    await PgStore(engine).kibana_change(change)


async def _open_alarms(engine: AsyncEngine) -> int:
    async with engine.connect() as conn:
        section = await guardrails(
            conn, Window("daily", datetime.now(UTC) - timedelta(days=2), datetime.now(UTC),
                         datetime.now(UTC)),
        )  # fmt: skip
    return int({m.key: m.value for m in section.metrics}["guardrails.findings_open.alarm"] or 0)


async def test_explaining_marks_it_audits_it_and_lifts_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    finding = await _finding(app_engine)
    await _pause_all(app_engine)
    assert await _open_alarms(app_engine) == 1
    assert "open findings: alarm 1" in await sync_cli.report(
        app_engine, datetime(2026, 1, 1, tzinfo=UTC)
    )

    done = await sync_cli.explain(migrated_engine, finding, REASON, by="cli")
    assert (done.kind, done.severity, done.marked, done.resolved_by) == (
        "unexplained_argus_case", "alarm", True, "cli",
    )  # fmt: skip
    assert done.paused == tuple((c.value, PAUSED_BY_ALARM) for c in sorted(ALL_CLASSES))
    assert done.open_alarms == 0
    # nothing was lifted: the lane still has every class paused
    assert set((await PgStore(app_engine).kibana_lane()).paused) == {c.value for c in ALL_CLASSES}
    assert await _open_alarms(app_engine) == 0
    assert "open findings: none" in await sync_cli.report(
        app_engine, datetime(2026, 1, 1, tzinfo=UTC)
    )
    async with app_engine.connect() as conn:
        audit = (
            await conn.execute(
                text(
                    "SELECT actor, target_type, target_id, details FROM audit_events"
                    " WHERE action = 'kibana.finding_explained'"
                )
            )
        ).all()
        evidence = await ramp.evidence(conn, "W1", datetime.now(UTC))
    assert [(a.actor, a.target_type, a.target_id) for a in audit] == [
        ("cli", "kibana_finding", str(finding))
    ]
    assert audit[0].details["reason"] == REASON
    assert audit[0].details["kibana_case_id"] == "k-old"
    assert evidence.alarms == 0  # an explained alarm holds no ramp step back

    lines = sync_cli.explained_lines(done, REASON)
    assert lines[0] == (
        f"finding {finding} (unexplained_argus_case, alarm): explained; it no longer counts as open"
    )
    assert "  argus kibana resume --class W1 --reason" in "\n".join(lines)
    for cls in ALL_CLASSES:
        assert any(line.startswith(f"  argus kibana resume --class {cls.value} ") for line in lines)

    again = await sync_cli.explain(migrated_engine, finding, "another reason, later", by="cli")
    assert (again.marked, again.resolved_at) == (False, done.resolved_at)
    assert "already resolved" in sync_cli.explained_lines(again, REASON)[0]
    async with app_engine.connect() as conn:
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM audit_events WHERE action = 'kibana.finding_explained'")
            )
            == 1
        )


async def test_the_runtime_cannot_explain_a_finding(app_engine: AsyncEngine) -> None:
    finding = await _finding(app_engine)
    with pytest.raises(DBAPIError) as refused:
        async with app_engine.begin() as conn:
            await conn.execute(
                text("UPDATE kibana_findings SET resolved_at = now() WHERE id = :i"),
                {"i": finding},
            )
    assert getattr(refused.value.orig, "sqlstate", None) == "42501"


async def test_an_unknown_finding_and_other_open_alarms_are_said(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    gone = await sync_cli.explain(migrated_engine, 999_999, REASON, by="cli")
    assert gone.kind is None
    assert sync_cli.explained_lines(gone, REASON) == [
        "finding 999999: no such finding (`argus kibana sync status`)"
    ]
    first, _second = await _finding(app_engine), await _finding(app_engine)
    await _pause_all(app_engine)
    # a class a 403 paused is not this alarm's to lift
    await PgStore(app_engine).kibana_change(
        lambda s: (None, writes.pause(writes.resume(s, writes.WriteClass.WA),
                                      writes.WriteClass.WA, "a 403 on alert writes"))
    )  # fmt: skip
    done = await sync_cli.explain(migrated_engine, first, REASON, by="cli")
    lines = "\n".join(sync_cli.explained_lines(done, REASON))
    assert done.open_alarms == 1
    assert "1 other alarm(s) are still open" in lines
    assert "--class WA" not in lines
    assert "paused for another reason (not this alarm): WA" in lines


def test_the_command_runs_as_the_owner_and_prints_the_resume_lines(
    cli_env: Path,  # noqa: F811
) -> None:
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    code, out = _invoke("kibana", "sync", "explain", "1", "--reason", "short", *config)
    assert code == 2
    assert "--reason says why" in out
    code, out = _invoke("kibana", "sync", "explain", "424242", "--reason", REASON, *config)
    assert (code, out) == (1, "finding 424242: no such finding (`argus kibana sync status`)\n")


def test_the_lines_quote_the_reason_for_a_shell() -> None:
    done = sync_cli.Explained(
        7, "unexplained_argus_case", "alarm", "k", True, datetime(2026, 11, 16, tzinfo=UTC),
        "cli", (("W1", PAUSED_BY_ALARM),), 0,
    )  # fmt: skip
    lines = sync_cli.explained_lines(done, "it's the old install")
    assert lines[-1] == (
        "  argus kibana resume --class W1 --reason"
        " 'finding 7 explained: it'\"'\"'s the old install'"
    )
    assert json.dumps(lines)  # plain text only


def test_a_finding_that_is_not_an_alarm_offers_no_resume_lines() -> None:
    """Only an alarm pauses the writes: explaining an ``attention`` finding is no reason to lift
    a pause, so no resume line names it as the reason."""
    done = sync_cli.Explained(
        8, "unexplained_argus_case", "attention", "k", True, datetime(2026, 11, 16, tzinfo=UTC),
        "cli", (("W1", PAUSED_BY_ALARM),), 0,
    )  # fmt: skip
    lines = sync_cli.explained_lines(done, REASON)
    assert not any("argus kibana resume" in line for line in lines)
    assert any("not by this finding" in line for line in lines)


def test_the_database_refusing_is_one_line_not_a_traceback(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", "not-the-password")
    code, out = _invoke("kibana", "sync", "explain", "1", "--reason", REASON, *config)
    assert code == 1
    assert out.startswith("error: ")
    assert "Traceback" not in out
    assert "not-the-password" not in out


def test_without_the_owner_it_says_how_to_explain_not_how_to_resume(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_DATABASE__OWNER_PASSWORD", raising=False)
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", "")
    code, out = _invoke("kibana", "sync", "explain", "3", "--reason", REASON, "-c", str(cli_env))
    assert code == 2, out
    assert "explaining a finding needs the database owner" in out
    assert "resuming" not in out
    assert f"sudo argus-owner kibana sync explain 3 --reason '{REASON}'" in out
