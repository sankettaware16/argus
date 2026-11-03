"""The re-measurement on Postgres (Q-A3): the ledger and the probe readings read back, the dry
run from stored alerts, a whole live session against a scripted the SIEM with its file and its
verification, and the derivation from a stored ledger."""

from __future__ import annotations

import io
import json
import stat
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings, EnrichmentSettings, Settings, SiemSettings
from argus.gateway.gateway import Targets
from argus.gateway.health import HealthMemory, Readings
from argus.gateway.pgstore import PgStore
from argus.gateway.state import LedgerEntry
from argus.measure import cli
from argus.measure.session import COMPONENT, MINUTE
from tests.integration.context.test_live_check import nginx, squid
from tests.integration.grouping.test_grouping import ingest
from tests.unit.gateway.fakes import FakeClock
from tests.unit.measure.fakes import T0, FakeElastic, node

pytestmark = pytest.mark.integration


def settings(db: DatabaseSettings, database: str) -> Settings:
    return Settings(
        database=db.model_copy(update={"name": database}),
        siem=SiemSettings(),
        enrichment=EnrichmentSettings(log_queries=True, proxy_aggregations=True),
    )


async def seed_alerts(engine: AsyncEngine) -> None:
    await ingest(engine, [squid(1, "10.8.0.5", "45.9.9.9"), nginx(2, "45.1.2.3"),
                          *(nginx(n, "45.1.2.4") for n in range(3, 40))], T0)  # fmt: skip


def entry(at: Any, template: str, took: int, component: str = "collector") -> LedgerEntry:
    return LedgerEntry(at, component, "collect", template, 1, (), "ok", 200, took, took, 10, 1)


async def seed_production(engine: AsyncEngine) -> None:
    """The collector's probe 30 s ago: this database is the one a running ARGUS writes to."""
    await PgStore(engine).record(
        LedgerEntry(
            T0 - timedelta(seconds=30),
            "probe",
            "probe",
            "health.node_stats",
            2,
            (),
            "ok",
            200,
            5,
            5,
            10,
            1,
        )
    )


async def test_the_ledger_and_the_readings_read_back_in_order(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    for minutes, took in ((3, 30), (1, 10), (2, 20)):
        await store.record(entry(T0 - timedelta(minutes=minutes), "alerts.ids", took))
    rows = await store.requests_since(T0 - timedelta(minutes=2, seconds=30))
    assert [row.took_ms for row in rows] == [20, 10]
    assert [(row.http_status, row.attempts) for row in rows] == [(200, 1), (200, 1)]
    older = await store.requests_since(T0 - timedelta(hours=1), T0 - timedelta(minutes=2))
    assert [r.took_ms for r in older] == [30]
    assert await store.latest_probe() is None
    for minutes, load in ((2, 3.0), (1, 4.0)):
        await store.record_probe(
            Readings(at=T0 - timedelta(minutes=minutes), load_1m=load, blocked_indices=("x",)),
            HealthMemory(reasons=("load",)),
        )
    latest = await store.latest_probe()
    assert latest is not None
    assert (latest.load_1m, latest.blocked_indices) == (4.0, ("x",))
    assert latest.reasons == ("load",)
    assert latest.state == "normal"
    assert [p.load_1m for p in await store.probes_since(T0 - timedelta(hours=1))] == [3.0, 4.0]


async def test_the_dry_run_plans_from_the_stored_alerts_and_sends_nothing(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    await seed_alerts(app_engine)
    await seed_production(app_engine)
    lines = await cli.dry_run(settings(db_settings, test_database), app_engine, T0)
    assert lines[0].startswith("dry run at 2026-10-23 10:00 UTC: nothing is sent")
    assert "requests (6 heavy)" in lines[1]
    assert not [line for line in lines if "REFUSED" in line]
    assert any("alerts.mget #1" in line for line in lines)
    assert any("not measured: alerts.mget: 1 of 3 batches" in line for line in lines)
    # never probed here: the stored health is too old to trust, and the session probes first
    assert lines[-1] == "a live run could start now (it probes the SIEM first)"
    async with app_engine.connect() as conn:  # only the seeded probe
        assert (await conn.execute(text("SELECT count(*) FROM siem_requests"))).scalar() == 1


async def test_a_database_no_running_argus_writes_to_is_refused(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    """Review F8: a throwaway database (a leftover ARGUS_DATABASE__NAME) has no budget, kill
    switches or ledger of production's; the dry run says so and a live run never starts,
    also when the probe went stale while the confirmation waited."""
    await seed_alerts(app_engine)
    lines = await cli.dry_run(settings(db_settings, test_database), app_engine, T0)
    assert lines[-1].startswith("a live run would not start now: this database shows no"
                                " running ARGUS")  # fmt: skip
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)

    def slow_confirm(_word: str) -> bool:
        clock.advance(timedelta(minutes=3))  # the person took 3 minutes to type the word
        return True

    report, lines = await cli.live_run(
        settings(db_settings, test_database), app_engine, sender=elastic, confirm=slow_confirm,
        out=tmp_path, clock=clock, sleep=clock.sleep, echo=lambda _line: None,
    )  # fmt: skip
    assert report is None
    assert lines[0].startswith("not started: this database shows no running ARGUS")
    assert elastic.calls == []


async def test_the_dry_run_says_what_would_stop_a_live_run(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    await seed_production(app_engine)
    store = PgStore(app_engine)
    await store.set_switch("enrichment", stopped=True, actor="test", reason=None)
    await store.save_health(HealthMemory(probed_at=T0 - timedelta(seconds=30)))
    await store.record_probe(Readings(at=T0 - timedelta(seconds=30), load_1m=30.0), HealthMemory())
    lines = await cli.dry_run(settings(db_settings, test_database), app_engine, T0)
    assert lines[-1].startswith("a live run would not start now: kill switch stopped: enrichment")
    assert "load 30 (CAUTION at 16)" in lines[-1]


async def test_a_live_session_end_to_end(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed_alerts(app_engine)
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    asked: list[str] = []

    def confirm(word: str) -> bool:
        asked.append(word)
        return True

    report, lines = await cli.live_run(
        settings(db_settings, test_database), app_engine, sender=elastic, confirm=confirm,
        out=tmp_path, clock=clock, sleep=clock.sleep, echo=lambda _line: None,
    )  # fmt: skip
    assert report is not None
    assert report.stopped is None, lines
    assert asked
    assert asked[0] in cli.CONFIRM_WORDS
    assert lines[-1].startswith("SESSION VERIFIED"), lines
    saved = tmp_path / "20261023T100000Z" / "session.json"
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert stat.S_IMODE(saved.parent.stat().st_mode) == 0o700
    data = json.loads(saved.read_text())
    assert data["complete"] is True
    assert data["requests_sent"] == len(elastic.calls) <= 50
    assert "45.9.9.9" not in saved.read_text()
    assert "10.8.0.5" not in saved.read_text()
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT purpose, count(*) FROM siem_requests WHERE component = :c GROUP BY 1"),
            {"c": COMPONENT})).all()  # fmt: skip
    # its probes and index listings are its own on the ledger (review F3)
    probes = len(elastic.calls) - len(report.samples)
    assert dict(rows) == {"measure": len(report.samples), "probe": probes}
    assert data["requests_sent"] == len(report.samples) + probes
    # the stored session verifies again later, from its file, past §7.8's 5 minutes
    again = await cli._verify(settings(db_settings, test_database), app_engine, saved,
                              now=clock() + timedelta(minutes=10))  # fmt: skip
    assert again[-1] == "SESSION VERIFIED"
    assert f": {data['requests_sent']} requests," in again[0]


async def test_a_live_session_that_is_not_confirmed_sends_nothing(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    report, lines = await cli.live_run(
        settings(db_settings, test_database), app_engine, sender=elastic,
        confirm=lambda _word: False, out=tmp_path, clock=clock, sleep=clock.sleep,
        echo=lambda _line: None,
    )  # fmt: skip
    assert report is None
    assert lines == ["not confirmed: nothing was sent"]
    assert elastic.calls == []
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240 - a test's own folder


async def test_a_live_session_that_meets_caution_is_saved_and_not_verified(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed_alerts(app_engine)
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock, nodes=[node(), node(), node(heap=90)])
    report, lines = await cli.live_run(
        settings(db_settings, test_database), app_engine, sender=elastic, confirm=lambda _w: True,
        out=tmp_path, clock=clock, sleep=clock.sleep, echo=lambda _line: None,
    )  # fmt: skip
    assert report is not None
    assert report.stopped is not None
    assert "heap 90" in report.stopped
    assert any(line.startswith("STOPPED EARLY") for line in lines)
    assert lines[-1] == "SESSION NOT VERIFIED"
    assert any("heap 90 (CAUTION at 85)" in line for line in lines)


async def test_the_report_derives_the_lanes_from_the_stored_ledger(
    app_engine: AsyncEngine,
) -> None:
    store = PgStore(app_engine)
    start = T0 - timedelta(days=3)
    for n in range(3 * 24 * 6):  # every 10 minutes for 3 days: a poll and a proxy aggregation
        at = start + n * timedelta(minutes=10)
        await store.record(entry(at, "alerts.ids", 15))
        if n % 3 == 0:
            await store.record(entry(at, "proxy.host", 700, component="enrichment"))
    for minutes in range(10):
        await store.record_probe(Readings(at=T0 - timedelta(minutes=minutes), load_1m=4.0),
                                 HealthMemory())  # fmt: skip
    lines, data = await cli.report_lines(store, start, T0, cores=16, spare_share=0.02, plan=None,
                                         decision=True)  # fmt: skip
    text_ = "\n".join(lines)
    assert "proxy.host (heavy): 144 samples" in text_
    collector = data["lanes"][0]
    assert (collector["lane"], collector["verdict"]) == ("collector", "fits")
    assert collector["demand_heavy_day"] == 48
    assert data["headroom"] == {"measured": True, "readings": 9, "load_p95": 4.0, "cores": 16,
                                "spare_share": 0.02, "minute_ms": 3_000}  # fmt: skip
    # (the reading at T0 itself is not counted: "until" is exclusive)
    assert "## D-NNN — The load budget re-measured" in text_


def test_the_command_line_is_a_dry_run_unless_live_and_a_person_runs_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []

    async def fake_dry_run(*_args: Any) -> list[str]:
        called.append("dry")
        return ["dry run"]

    monkeypatch.setattr(cli, "dry_run", fake_dry_run)
    monkeypatch.setattr(cli, "_settings", lambda _config: settings(DatabaseSettings(), "x"))

    class NoEngine:
        async def dispose(self) -> None:
            pass

    monkeypatch.setattr(cli, "create_engine", lambda *_a, **_k: NoEngine())
    out = io.StringIO()
    assert cli.main(["run"], out=out) == 0
    assert out.getvalue() == "dry run\n"
    assert cli.main([], out=io.StringIO()) == 0
    assert called == ["dry", "dry"]
    monkeypatch.setattr(cli, "_human_at_a_terminal", lambda: False)
    assert cli.main(["run", "--live"], out=io.StringIO()) == 2  # nothing built, nothing sent
    monkeypatch.setattr(cli, "_human_at_a_terminal", lambda: True)
    monkeypatch.setattr(cli, "_utcnow", lambda: T0.replace(hour=0, minute=45))
    assert cli.main(["run", "--live"], out=io.StringIO()) == 2  # the quiet hours
    monkeypatch.setattr(cli, "_utcnow", lambda: T0)
    assert cli.main(["run", "--live"], out=io.StringIO()) == 2  # no SIEM key in these settings


def test_a_session_file_that_is_not_this_scripts_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"format": 1, "component": "collector"}))
    with pytest.raises(ValueError, match="not a session file"):
        cli.load_session(path)
    path.write_text(json.dumps({"format": 1, "component": COMPONENT,
                                "started": "2026-10-23T10:00:00", "ended": None}))  # fmt: skip
    with pytest.raises(ValueError, match="not usable"):
        cli.load_session(path)
    started = T0.isoformat()
    path.write_text(json.dumps({"format": 1, "component": COMPONENT, "started": started,
                                "ended": (T0 + MINUTE).isoformat()}))  # fmt: skip
    assert cli.load_session(path) == (T0, T0 + MINUTE, None)
    path.write_text(json.dumps({"format": 1, "component": COMPONENT, "started": started,
                                "ended": None, "requests_sent": 31}))  # fmt: skip
    assert cli.load_session(path) == (T0, T0, 31)


async def test_the_script_end_to_end_on_a_throwaway_database(
    app_engine: AsyncEngine, test_database: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``main`` as the script runs it: the configuration loaded, its own engine, nothing sent."""
    import asyncio

    await seed_alerts(app_engine)
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    out = io.StringIO()
    code = await asyncio.to_thread(cli.main, ["plan"], out=out)
    assert code == 0
    assert "nothing is sent to the SIEM" in out.getvalue()
    out = io.StringIO()
    target = tmp_path / "lanes.json"
    code = await asyncio.to_thread(cli.main, ["report", "--decision", "--json", str(target)],
                                   out=out)  # fmt: skip
    assert code == 0
    assert "## D-NNN" in out.getvalue()
    assert json.loads(target.read_text())["format"] == 1
    session = tmp_path / "session.json"
    stamp = T0.isoformat()
    body = {"format": 1, "component": COMPONENT, "started": stamp, "ended": stamp}
    session.write_text(json.dumps(body))
    out = io.StringIO()
    assert await asyncio.to_thread(cli.main, ["verify", str(session)], out=out) == 1
    assert out.getvalue().rstrip().endswith("SESSION NOT VERIFIED")


async def test_one_measuring_session_at_a_time(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    async with app_engine.connect() as other:
        assert (await other.execute(text("SELECT pg_try_advisory_lock(:k)"),
                                    {"k": cli.LOCK})).scalar()  # fmt: skip
        report, lines = await cli.live_run(
            settings(db_settings, test_database), app_engine, sender=elastic,
            confirm=lambda _w: True, out=tmp_path, clock=clock, sleep=clock.sleep,
            echo=lambda _line: None,
        )  # fmt: skip
        await other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": cli.LOCK})
    assert report is None
    assert lines == ["not started: another measuring session is running"]
    assert elastic.calls == []


async def test_a_plan_the_gateway_would_refuse_never_starts(
    app_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await seed_alerts(app_engine)
    await seed_production(app_engine)
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    config = settings(db_settings, test_database)
    # a gateway that may read only squid's logs: web.followups (nginx) is refused
    monkeypatch.setattr(cli, "targets", lambda _siem: Targets(log_sources=frozenset({"squid"})))
    report, lines = await cli.live_run(
        config, app_engine, sender=elastic, confirm=lambda _w: True, out=tmp_path,
        clock=clock, sleep=clock.sleep, echo=lambda _line: None,
    )  # fmt: skip
    assert report is None
    assert lines[0].startswith("not started: the gateway would refuse web.followups #1")
    assert elastic.calls == []


async def test_an_interrupted_session_keeps_its_file_and_the_last_days_count_is_shown(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    import asyncio

    await seed_alerts(app_engine)
    await seed_production(app_engine)
    await PgStore(app_engine).record(entry(T0 - timedelta(hours=3), "alerts.ids", 5, COMPONENT))
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["alerts.counts"] = asyncio.CancelledError()
    said: list[str] = []
    with pytest.raises(asyncio.CancelledError):
        await cli.live_run(
            settings(db_settings, test_database), app_engine, sender=elastic,
            confirm=lambda _w: True, out=tmp_path, clock=clock, sleep=clock.sleep,
            echo=said.append,
        )  # fmt: skip
    assert "The ledger holds 1 measuring requests from the last 24 hours." in said
    data = json.loads((tmp_path / "20261023T100000Z" / "session.json").read_text())
    assert data["stopped"] == "interrupted"
    assert data["complete"] is False
    async with app_engine.connect() as conn:  # the lock went with the session
        assert (await conn.execute(text("SELECT pg_try_advisory_lock(:k)"),
                                   {"k": cli.LOCK})).scalar()  # fmt: skip
