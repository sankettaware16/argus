"""Q-A2: the probe readings in Postgres (migration 0022), appended by the runtime role and never
changed; and doctor's view of them and of the threat-intel feeds' freshness."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings, Settings, SiemSettings
from argus.gateway.health import HealthMemory, HealthState, Readings
from argus.gateway.pgstore import PgStore
from argus.gateway.service import build_gateway, probe
from argus.ops import checks
from tests.unit.gateway.fakes import T0, FakeClock, FakeTransport, ok
from tests.unit.ops.test_probe_history import BLOCKS, NODE

pytestmark = pytest.mark.integration


async def test_each_probe_appends_its_readings(app_engine: AsyncEngine) -> None:
    clock = FakeClock()
    sender = FakeTransport(clock=clock).on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS))
    gateway, store = build_gateway(SiemSettings(), app_engine, sender=sender)
    gateway.clock, gateway.sleep = clock, clock.sleep
    await probe(gateway, store, SiemSettings(), T0)
    await probe(gateway, store, SiemSettings(), T0 + timedelta(minutes=1))
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT at, state, probe_ok, disk_percent, search_rejected, write_rejected,"
                    " blocked_indices, ingest_lag_s FROM siem_probes ORDER BY id"
                )
            )
        ).all()
    assert [tuple(r) for r in rows] == [
        (T0, "normal", True, 60.0, 7, 3, [], {}),
        (T0 + timedelta(minutes=1), "normal", True, 60.0, 7, 3, [], {}),
    ]


async def test_every_counter_at_its_limit_is_stored(app_engine: AsyncEngine) -> None:
    """QA2-R5: a count the code lets through (stale_rules of 2**31 was one) fits its column, so
    the insert never fails and the reading is never lost."""
    store = PgStore(app_engine)
    big = 2**63 - 1
    readings = Readings(
        at=T0, search_queue=big, search_rejected=big, breakers_tripped=big, write_rejected=big,
        stale_rules=2**31,
    )  # fmt: skip
    await store.record_probe(readings, HealthMemory(state=HealthState.NORMAL))
    async with app_engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM siem_probes"))).one()._mapping
    assert (row["search_queue"], row["write_rejected"], row["stale_rules"]) == (big, big, 2**31)


async def test_a_strange_reading_is_stored_as_unknown(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    readings = Readings(
        at=T0, probe_ok=False, disk_percent=float("nan"), heap_percent=250.0, load_1m=-1.0,
        search_queue=2**70, ingest_lag={"squid": timedelta(minutes=20)},
        blocked_indices=("acme-logs-squid-2026.10.09",),
    )  # fmt: skip
    memory = HealthMemory(state=HealthState.DEGRADED, reasons=("probe_failed",))
    await store.record_probe(readings, memory)
    async with app_engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM siem_probes"))).one()._mapping
    assert (row["disk_percent"], row["heap_percent"], row["load_1m"], row["search_queue"]) == (
        None, None, None, None)  # fmt: skip
    assert (row["state"], row["reasons"], row["probe_ok"]) == ("degraded", ["probe_failed"], False)
    assert row["ingest_lag_s"] == {"squid": 1200.0}
    assert row["blocked_indices"] == ["acme-logs-squid-2026.10.09"]


@pytest.mark.parametrize(
    "statement",
    ["UPDATE siem_probes SET state = 'normal'", "DELETE FROM siem_probes",
     "TRUNCATE siem_probes"],
)  # fmt: skip
async def test_the_runtime_role_only_appends(app_engine: AsyncEngine, statement: str) -> None:
    with pytest.raises(DBAPIError) as refused:
        async with app_engine.begin() as conn:
            await conn.execute(text(statement))
    assert getattr(refused.value.orig, "sqlstate", None) == "42501"


def _settings(db: DatabaseSettings, database: str, key: bool = False) -> Settings:
    siem = SiemSettings(api_key=SecretStr("k" * 12) if key else None)
    return Settings(database=db.model_copy(update={"name": database}), siem=siem)


async def test_doctor_reads_the_feeds_freshness_and_the_probe_readings(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    first = await checks.stored_results(_settings(db_settings, test_database), now)
    assert [(r.name, r.label) for r in first] == [
        ("threat intel abuse-ioc", "WARN"),
        ("threat intel acme-threat-intel", "WARN"),
        ("probe readings", "PASS"),
    ]
    assert first[2].detail == "none stored yet (no SIEM key here)"
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ti_sources (source, newest, checked_at) VALUES"
                " ('abuse-ioc', :old, :now), ('acme-threat-intel', :fresh, :now)"
            ),
            {"old": now - timedelta(days=9), "fresh": now - timedelta(days=1), "now": now},
        )
    store = PgStore(app_engine)
    for minutes in (5, 30, 60 * 30):
        await store.record_probe(Readings(at=now - timedelta(minutes=minutes)), HealthMemory())
    second = await checks.stored_results(_settings(db_settings, test_database, key=True), now)
    by_name = {r.name: r for r in second}
    assert by_name["threat intel abuse-ioc"].label == "WARN"
    assert "stale: the newest indicator is 9 days old" in by_name["threat intel abuse-ioc"].detail
    assert by_name["threat intel acme-threat-intel"].label == "PASS"
    readings = by_name["probe readings"]
    assert (readings.label, readings.detail.startswith("2 in the last 24 h")) == ("PASS", True)
    later = await checks.stored_results(
        _settings(db_settings, test_database, key=True), now + timedelta(minutes=20)
    )
    assert {r.name: r.label for r in later}["probe readings"] == "WARN"  # the collector stopped?


async def test_doctor_without_a_database_says_it_did_not_check(
    db_settings: DatabaseSettings,
) -> None:
    missing = _settings(db_settings, "argus_test_never_created")
    (result,) = await checks.stored_results(missing, datetime.now(UTC))
    assert (result.label, result.detail.startswith("not checked:")) == ("FAIL", True)


def test_doctor_runs_every_platform_check_without_a_crash(
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`argus doctor` on a database at head: each platform check answers (PASS, WARN or FAIL),
    none crashes. It reads files and this machine's loopback only."""
    from typer.testing import CliRunner

    from argus.cli import app
    from tests.conftest import REPO_ROOT, suite_checkout

    monkeypatch.chdir(REPO_ROOT)  # the repo .env: the passwords
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    config = (
        suite_checkout(tmp_path) / "config" / "argus.yaml"
    )  # the shipped config, the suite's site
    result = CliRunner().invoke(app, ["doctor", "-c", str(config)])
    out = result.output
    assert "crashed" not in out, out
    names = [line[6:].split("  ")[0].strip() for line in out.splitlines()]
    for expected in ("database", "migrations", "schema matches models", "runtime role",
                     "web login", "web certificate", "local model tunnel", "write keys",
                     "service units", "backups", "node toolchain", "frontend build",
                     "threat intel abuse-ioc", "threat intel acme-threat-intel",
                     "probe readings", "custody",
                     "switches resumed by the owner only"):  # fmt: skip
        assert expected in names, (expected, out)
    assert "PASS  migrations" in out
    assert "PASS  schema matches models" in out
    assert "PASS  runtime role" in out
