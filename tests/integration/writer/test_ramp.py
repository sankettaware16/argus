"""Q-D4's ramp (plan §7.1): a class starts at its canary (1), moves to 5 and then 10 only after
at least 3 runs on 3 days with every write read back, no alarm and a person's check; W2 begins
after W1's canary and one more run, W3 after W2's; the schedule runs at the ramp step."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import KibanaSettings, KibanaWriterSettings, Settings, WebSettings
from argus.writer import cli, ramp, store
from argus.writer.service import gate_problems
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import many_alerts, rig

pytestmark = pytest.mark.integration
NOW = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)  # a Monday


async def _run(
    engine: AsyncEngine, cls: str, day: int, *, step: int = 1, sent: int = 3, verified: int = 3,
    mismatches: int = 0, units: int = 1,
) -> None:  # fmt: skip
    at = NOW - timedelta(days=day)
    async with engine.begin() as conn:
        await store.record_run(
            conn, cls, "ramp", step, "test", at, at + timedelta(minutes=2), units=units,
            sent=sent, verified=verified, mismatches=mismatches, ambiguous=0, stopped=None,
        )  # fmt: skip


async def _evidence(engine: AsyncEngine, cls: str = "W1") -> ramp.Evidence:
    async with engine.connect() as conn:
        return await ramp.evidence(conn, cls, NOW)


def test_working_days_counts_monday_to_friday_inclusive() -> None:
    monday = datetime(2026, 11, 2, tzinfo=UTC)
    assert ramp.working_days(monday, monday) == 1
    assert ramp.working_days(monday, monday + timedelta(days=4)) == 5
    assert ramp.working_days(monday, monday + timedelta(days=6)) == 5  # the weekend adds none
    assert ramp.working_days(monday + timedelta(days=5), monday + timedelta(days=6)) == 0


async def test_a_class_is_ready_after_three_clean_runs_on_three_days(
    writer_engine: AsyncEngine,
) -> None:  # fmt: skip
    assert (await _evidence(writer_engine)).ready is False  # no run yet
    for day in (0, 0, 0):  # three runs on one day are not three days
        await _run(writer_engine, "W1", day)
    seen = await _evidence(writer_engine)
    assert (seen.runs, seen.days, seen.ready) == (3, 1, False)
    await _run(writer_engine, "W1", 1)
    await _run(writer_engine, "W1", 2)
    seen = await _evidence(writer_engine)
    assert (seen.runs, seen.days, seen.ready, seen.why_not) == (5, 3, True, [])


async def test_one_run_that_did_not_read_everything_back_stops_the_ramp(
    writer_engine: AsyncEngine, migrated_engine: AsyncEngine,
) -> None:  # fmt: skip
    for day in (0, 1, 2):
        await _run(writer_engine, "W1", day, sent=3, verified=2 if day == 1 else 3)
    seen = await _evidence(writer_engine)
    assert not seen.ready
    assert any("read every write back" in w for w in seen.why_not)


async def test_an_alarm_since_the_step_began_stops_the_ramp(
    writer_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:  # fmt: skip
    for day in (0, 1, 2):
        await _run(writer_engine, "W1", day)
    assert (await _evidence(writer_engine)).ready
    async with migrated_engine.begin() as conn:
        from sqlalchemy import text

        await conn.execute(
            text(
                "INSERT INTO kibana_findings (found_at, kind, severity, dedupe_key)"
                " VALUES (now(), 'unexplained_argus_action', 'alarm', 'k')"
            )
        )
    seen = await _evidence(writer_engine)
    assert not seen.ready
    assert any("alarms" in w for w in seen.why_not)


async def test_five_working_days_after_a_clean_run_are_enough_when_there_were_few_runs(
    writer_engine: AsyncEngine,
) -> None:  # fmt: skip
    await _run(writer_engine, "W1", 4)  # Thursday of the week before, Monday now: 3 working days
    assert not (await _evidence(writer_engine)).ready
    await _run(writer_engine, "W1", 7)  # Monday a week back: 6 working days since
    assert (await _evidence(writer_engine)).ready


async def test_raising_the_step_starts_the_evidence_again_and_ends_at_ten(
    writer_engine: AsyncEngine,
) -> None:  # fmt: skip
    for day in (0, 1, 2):
        await _run(writer_engine, "W1", day)
    async with writer_engine.begin() as conn:
        await ramp.raise_step(conn, "W1", 5, "asha", "looked at the cases in Kibana", NOW)
    async with writer_engine.connect() as conn:
        assert await store.ramp_step(conn, "W1") == 5
        assert await store.ramp_step(conn, "W2") == 1
    seen = await _evidence(writer_engine)
    assert (seen.step, seen.runs, seen.ready) == (5, 0, False)  # the runs at step 1 do not count
    for day in (0, 1, 2):
        await _run(writer_engine, "W1", day, step=5)
    assert (await _evidence(writer_engine)).ready is False  # `since` is the raise, now in the past
    async with writer_engine.begin() as conn:
        await ramp.raise_step(conn, "W1", 10, "asha", "", NOW - timedelta(days=5))
    for day in (0, 1, 2):
        await _run(writer_engine, "W1", day, step=10)
    last = await _evidence(writer_engine)
    assert not last.ready
    assert any("last step" in w for w in last.why_not)


async def test_the_classes_go_in_order(writer_engine: AsyncEngine) -> None:
    async with writer_engine.connect() as conn:
        assert await ramp.first_use_problem(conn, "W1") is None
        assert "W2 begins after W1's canary and one more run" in str(
            await ramp.first_use_problem(conn, "W2")
        )
    await _run(writer_engine, "W1", 1)
    async with writer_engine.connect() as conn:
        assert (
            await ramp.first_use_problem(conn, "W2") is not None
        )  # the canary alone is not enough
    await _run(writer_engine, "W1", 0)
    async with writer_engine.connect() as conn:
        assert await ramp.first_use_problem(conn, "W2") is None
        assert await ramp.first_use_problem(conn, "W3") is not None
    await _run(writer_engine, "W2", 0)
    await _run(writer_engine, "W2", 0, mismatches=1)  # a run with a mismatch does not count
    async with writer_engine.connect() as conn:
        assert await ramp.first_use_problem(conn, "W3") is not None


def _settings(**over: object) -> Settings:
    fields: dict[str, object] = {
        "enabled": True,
        "cases_writer_api_key": SecretStr("k" * 20),
        "cases_writer_api_key_expires": datetime.now(UTC).date() + timedelta(days=20),
        "write_classes": ("W1", "W2", "W3"),
        "writer": KibanaWriterSettings(scheduled=("W1",)),
        **over,
    }
    kibana = KibanaSettings(**fields)  # type: ignore[arg-type]
    return Settings(kibana=kibana, web=WebSettings(public_url="https://127.0.0.1:8765"))


def test_what_stops_a_class_at_this_host() -> None:
    assert gate_problems(_settings(), "W1") == []
    assert gate_problems(_settings(), "W2") == []
    assert gate_problems(_settings(), "W3") == [
        "no approval key is configured: the writer cannot check signatures"
    ]
    off = Settings(kibana=KibanaSettings(enabled=True, write_classes=()))
    assert "W1 is not switched on at this host (kibana.write_classes)" in gate_problems(off, "W1")
    assert "kibana.enabled is false" in gate_problems(Settings(), "W1")
    no_expiry = gate_problems(_settings(cases_writer_api_key_expires=None), "W1")
    assert any("no expiry is recorded" in p for p in no_expiry)
    expired = gate_problems(
        _settings(cases_writer_api_key_expires=datetime.now(UTC).date() - timedelta(days=3)), "W1"
    )
    assert any("expired on" in p for p in expired)
    no_link = Settings(kibana=_settings().kibana)
    assert any("web.public_url" in p for p in gate_problems(no_link, "W1"))


def test_a_class_scheduled_but_not_switched_on_is_refused_by_the_settings() -> None:
    with pytest.raises(ValueError, match="scheduled but not switched on"):
        KibanaSettings(
            enabled=True, cases_writer_api_key=SecretStr("k" * 20), write_classes=("W1",),
            writer=KibanaWriterSettings(scheduled=("W2",)),
        )  # fmt: skip


async def test_the_scheduled_run_goes_at_the_ramp_step_and_is_recorded(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    for _ in range(3):
        await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]), 1)
    # the service is never a class's first writer (Q-D4 review R2): a person's canary comes first
    await cli._scheduled(_settings(), r.writer, writer_engine, "W1")
    assert len(r.kibana.ours()) == 0
    canary = await r.run("W1", limit=1, kind="canary")  # step 1: one case, at a terminal
    assert (canary.units, canary.sent, canary.verified) == (1, 3, 3), canary.lines()
    r.writer.wait_for_gaps = False
    await cli._scheduled(_settings(), r.writer, writer_engine, "W1")  # still at step 1: a person's
    assert len(r.kibana.ours()) == 1
    async with writer_engine.begin() as conn:
        await ramp.raise_step(conn, "W1", 5, "asha", "", NOW)
    r.advance(3600)
    await cli._scheduled(_settings(), r.writer, writer_engine, "W1")
    runs = await r.sql("SELECT kind, step, units FROM kibana_writer_runs ORDER BY id")
    assert [(x.kind, x.step) for x in runs] == [("canary", 1), ("scheduled", 5)]
    assert len(r.kibana.ours()) == 3  # the rest, now that the step allows five
    # W2 is not scheduled until W1 has had its canary and one more clean run
    problems = await r.sql("SELECT count(*) AS n FROM kibana_writer_runs WHERE write_class = 'W2'")
    assert problems[0].n == 0


async def test_the_plan_lists_what_waits_and_what_stops_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    case_id = await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]), 1)
    lines = await cli.plan_lines(writer_engine, _settings(), "W1")
    assert lines[0] == "W1: step 1 (canary), 0 runs on 0 days at this step"
    assert "  nothing stops it here (the lane still checks the window, health and caps)" in lines
    assert "  waiting: 1 rows, 0 steps" in lines
    assert any(f"case {case_id} create (planned)" in line for line in lines)
    blocked = await cli.plan_lines(writer_engine, Settings(), "W2")
    assert any("W2 begins after W1's canary and one more run" in line for line in blocked)
    assert any("kibana.enabled is false" in line for line in blocked)


async def test_the_service_makes_due_lookups_and_runs_what_is_scheduled(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]), 1)
    await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]), 1)
    assert (await r.run("W1", limit=1, kind="canary")).verified == 3  # a person's canary first
    async with writer_engine.begin() as conn:
        await ramp.raise_step(conn, "W1", 5, "asha", "", NOW)
    monkeypatch.setattr(cli, "_engine", lambda settings, writes: writer_engine)
    monkeypatch.setattr(cli, "build_writer", lambda *a, **k: r.writer)
    r.writer.wait_for_gaps = False
    r.advance(3600)
    await cli.serve(_settings(), once=True)
    runs = await r.sql("SELECT write_class, kind, step, by FROM kibana_writer_runs ORDER BY id")
    assert [(x.write_class, x.kind, x.step, x.by) for x in runs] == [
        ("W1", "canary", 1, "test"),
        ("W1", "scheduled", 5, "service"),
    ]
    assert len(r.kibana.ours()) == 2
