"""Q-D4: the gates around a write, through the real lane: the write window, the SIEM's health, the
kill switches, the caps, Kibana's own stop, the key self-test and one run at a time. Where a
gate says no, nothing is sent and no row moves (``sending`` is committed only once every gate has
said yes)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana.writes import WriteCaps
from argus.site import VersionRange
from argus.writer import ramp, store
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import many_alerts, mirrored_case, rig

pytestmark = pytest.mark.integration


async def _open(app_engine, migrated_engine, people):  # type: ignore[no-untyped-def]
    return await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )


async def test_outside_the_write_window_nothing_is_sent_and_no_row_moves(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.clock.now = r.clock.now.replace(hour=20)  # 20:00 UTC is outside 02:30-17:30
    r.healthy()

    report = await r.run("W1", limit=1)

    assert "outside_window" in (report.stopped or "")
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]


async def test_the_quiet_hours_are_never_written_in(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.clock.now = r.clock.now.replace(hour=0, minute=45)
    r.healthy()
    report = await r.run("W1", limit=1)
    assert report.stopped is not None
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]


@pytest.mark.parametrize("state", [HealthState.CAUTION, HealthState.DEGRADED, HealthState.STOP])
async def test_only_normal_health_lets_a_write_go(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], state: HealthState,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.lane.memory = HealthMemory(state=state, probed_at=r.clock.now + timedelta(hours=1))

    report = await r.writer.run_class("W1", limit=1, kind="ramp", by="test")  # health as set

    assert report.stopped is not None
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]


@pytest.mark.parametrize("switch", ["cases", "global"])
async def test_the_kill_switch_stops_the_next_request(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], switch: str,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.lane.stopped = {switch}

    report = await r.run("W1", limit=1)

    assert report.stopped is not None
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]
    r.lane.stopped = set()
    assert (await r.run("W1", limit=1)).verified >= 1  # lifted: it goes


async def test_the_per_run_cap_ends_a_run_and_the_next_run_goes_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine, caps=WriteCaps(case_per_run=2))
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=1
    )

    first = await r.run("W1", limit=1)

    assert "run_cap" in (first.stopped or ""), first.lines()
    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    assert await r.steps(case_id) == [("comment", 0, "verified"), ("attach", 1, "planned")]
    assert (await r.run("W1", limit=1)).verified == 1  # a new run has its own two


async def test_scheduled_runs_do_not_wait_out_the_gap_between_alert_calls(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    r.writer.wait_for_gaps = False  # the service's way: end the run, come back in ten minutes
    async with writer_engine.begin() as conn:  # past the canary, where a case holds five alerts
        await ramp.raise_step(conn, "W1", 5, "asha", "looked", r.clock.now)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=6
    )

    first = await r.run("W1", limit=1)

    assert any("a minute between alert calls" in h for h in first.held), first.lines()
    assert first.stopped is None  # the run is over when there is nothing else to do
    steps = await r.steps(case_id)
    assert ("attach", 3, "planned") in steps  # the rest wait for the next run
    r.advance(600)
    for _ in range(4):
        await r.run("W1", limit=1)
        r.advance(600)
    assert [s for _, _, s in await r.steps(case_id)] == ["verified"] * 4
    assert r.kibana.cases[next(iter(r.kibana.cases))]["totalAlerts"] == 12


async def test_a_key_that_holds_what_it_must_not_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.kibana.extra_privileges = {"cases:securitySolution/deleteCase"}  # may delete cases

    report = await r.run("W1", limit=1)

    assert "failed its self-test" in (report.stopped or "")
    assert "deleteCase" in report.stopped
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]
    assert (await r.sql("SELECT count(*) AS n FROM kibana_writer_runs"))[0].n == 0

    r.kibana.extra_privileges = set()
    r.kibana.missing_privileges = {"cases:securitySolution/createCase"}  # or cannot create
    again = await r.run("W1", limit=1)
    assert "lacks cases:securitySolution/createCase" in (again.stopped or "")
    r.kibana.missing_privileges = set()
    assert (await r.run("W1", limit=1)).verified >= 1  # as it must be: it goes


async def test_a_kibana_that_is_not_the_pinned_version_is_not_written_to(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    r.gateway.targets = type(r.gateway.targets)(
        space=r.gateway.targets.space, versions=VersionRange.parse("==8.19.13")
    )  # the site pins 8.19.12 (P4-D1: a range, not one version)

    report = await r.run("W1", limit=1)

    assert report.stopped is not None
    assert r.kibana.count("POST", "/api/cases") == 0
    assert await r.outbox(case_id) == [("W1", "create", "planned")]


async def test_only_one_run_goes_at_a_time(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    async with migrated_engine.connect() as holder:  # another run holds the lock
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": store.LOCK_KEY})
        report = await r.run("W1", limit=1)
        await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
        await holder.commit()
    assert report.stopped == "another writer run is in progress"
    assert await r.outbox(case_id) == [("W1", "create", "planned")]
    assert (await r.run("W1", limit=1)).verified >= 1


async def test_a_tampered_row_pauses_the_row_and_the_class_and_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await _open(app_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:  # the payload changes under its hash
        await conn.execute(text("ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard"))
        await conn.execute(
            text("UPDATE kibana_outbox SET payload = jsonb_set(payload, '{severity}', '\"low\"')")
        )
        await conn.execute(
            text("ALTER TABLE kibana_outbox ENABLE ALWAYS TRIGGER kibana_outbox_guard")
        )

    report = await r.run("W1", limit=1)

    assert r.kibana.count("POST", "/api/cases") == 0
    assert any("does not match its hash" in h for h in report.held)
    assert await r.outbox(case_id) == [("W1", "create", "paused")]
    assert "W1" in (await r.lane.kibana_lane()).paused


async def test_the_writers_own_login_keeps_the_lane_state_in_the_database(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """The lane's budget, pauses and request ledger work as the writer's login, not only in
    memory: a canary is ledgered with its outbox row, payload hash and class, and a read-back
    mismatch pauses the class in the shared row."""
    from argus.gateway.pgstore import PgStore

    r = rig(migrated_engine, app_engine, writer_engine, lane=PgStore(writer_engine))
    case_id = await _open(app_engine, migrated_engine, people)

    report = await r.run("W1", limit=1)

    assert report.stopped is None, report.lines()
    ledger = await r.sql(
        "SELECT outbox_id, write_class, lane, outcome, payload_hash FROM siem_requests"
        " WHERE write_class = 'W1' ORDER BY id"
    )
    assert [(e.write_class, e.lane, e.outcome) for e in ledger] == [
        ("W1", "kibana_write", "ok")
    ] * 3
    assert all(e.outbox_id and len(e.payload_hash) == 64 for e in ledger)
    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    await r.writer._pause_class("W1", "test")
    state = await r.lane.kibana_lane()
    assert "W1" in state.paused  # the writer's login may pause (only the owner lifts it)
    assert (await r.run("W1", limit=1)).sent == 0
