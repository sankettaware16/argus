"""``argus purge`` (Q-A4): the dry run, and the guards before anything is deleted: a reviewed
plan or the approved schedule, a fresh restore drill, the same counts; every run audited."""

from __future__ import annotations

import asyncio
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.config import load_settings
from argus.web import auth
from tests.conftest import REPO_ROOT
from tests.integration.conftest import TEST_DB_PREFIX
from tests.integration.ops.test_purge import DAY, Alert, Inv, World, write

pytestmark = pytest.mark.integration
runner = CliRunner()
OLD = -200 * DAY


@pytest.fixture
def cli(test_database: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """(the config file, the backup folder) for a CLI pointed at the throwaway database."""
    monkeypatch.chdir(REPO_ROOT)  # the stream's .env: both passwords
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setenv("ARGUS_BACKUP__DIR", str(backups))
    config = REPO_ROOT / "config" / "argus.yaml"
    assert load_settings(config).database.name.startswith(TEST_DB_PREFIX)
    return config, backups


@pytest.fixture
async def seeded(migrated_engine: AsyncEngine) -> AsyncEngine:
    async with migrated_engine.begin() as conn:
        user = await auth.add_user(conn, "purger", "Purger", "correct horse battery")
        world = World(
            [Inv(OLD, [Alert(OLD, OLD)], [("reviewed", OLD)], [True], False, False, False,
                 ["10.0.0.1"], None),
             Inv(-40 * DAY, [Alert(-40 * DAY, -40 * DAY)], [], [True], False, False, False, [],
                 None)],
            [Alert(None, OLD, True)],
            [],
        )  # fmt: skip
        await write(conn, world, user)
    return migrated_engine


def _drill(backups: Path, *, ago: timedelta, passed: bool = True) -> None:
    record = {
        "at": (datetime.now(UTC) - ago).isoformat(),
        "dump": "manual/x.dump",
        "passed": passed,
        "differences": [],
        "took_s": 1.0,
    }
    with (backups / "drills.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


async def _invoke(config: Path, *args: str) -> Any:
    """The CLI in a thread of its own: it runs its own event loop, as from a terminal."""
    return await asyncio.to_thread(runner.invoke, app, ["purge", *args, "-c", str(config)])


async def _count(engine: AsyncEngine, query: str) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(query))).scalar_one())


async def _audits(engine: AsyncEngine) -> list[tuple[str, str, dict[str, Any]]]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT actor, outcome, details FROM audit_events WHERE action = 'purge.run'"
                " ORDER BY id"
            )
        )
        return [(a, o, d) for a, o, d in found.all()]


INVESTIGATIONS = "SELECT count(*) FROM investigations"
PURGED_RAW = "SELECT count(*) FROM alert_records WHERE raw_purged_at IS NOT NULL"


async def test_the_plan_counts_and_the_reviewed_run_deletes_exactly_that(
    cli: tuple[Path, Path], seeded: AsyncEngine, tmp_path: Path
) -> None:
    config, backups = cli
    plan = tmp_path / "plan.json"
    made = await _invoke(config, "plan", "--output", str(plan))
    assert made.exit_code == 0, made.output
    assert "raw_source (30d): alert_records.raw 2;" in made.output, made.output
    assert "quarantine (30d): alert_records.raw 1" in made.output
    assert "memory (90d): investigations 1" in made.output
    assert "app_logs (14d): the systemd journal" in made.output
    assert stat.S_IMODE(plan.stat().st_mode) == 0o600
    data = json.loads(plan.read_text())
    assert data["format"] == 2
    assert data["periods"]["memory"] == "90d"
    dry = await _invoke(config, "run")
    assert dry.exit_code == 0, dry.output
    assert "dry run" in dry.output
    assert await _count(seeded, INVESTIGATIONS) == 2
    assert await _count(seeded, PURGED_RAW) == 0
    assert await _audits(seeded) == []  # a dry run changes nothing and is no run

    refused = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert refused.exit_code == 1
    assert "no restore drill has run" in refused.output
    _drill(backups, ago=timedelta(hours=30))
    stale = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert stale.exit_code == 1
    assert "older than 1d" in stale.output
    _drill(backups, ago=timedelta(hours=1), passed=False)
    failed = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert "the last restore drill failed" in failed.output
    assert await _count(seeded, INVESTIGATIONS) == 2

    _drill(backups, ago=timedelta(minutes=5))
    done = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert done.exit_code == 0, done.output
    assert "every count as planned; the held rows are untouched" in done.output
    assert await _count(seeded, INVESTIGATIONS) == 1
    # the 40-day-old alert stays, emptied; the 200-day-old ones are gone
    assert await _count(seeded, PURGED_RAW) == 1
    assert await _count(seeded, "SELECT count(*) FROM alert_records") == 1
    audits = await _audits(seeded)
    assert [(a, o) for a, o, _ in audits] == [("purge", "denied")] * 3 + [("purge", "success")]
    last = audits[-1][2]
    assert last["planned"] == last["done"]
    assert last["done"]["changed"]["memory"]["investigations"] == 1
    assert last["holds_before"] == last["holds_after"]
    assert not any(last["holds_changed"].values())
    assert "drill" in last
    assert not last["scheduled"]

    again = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert again.exit_code == 1  # the plan's counts are spent: nothing is left to match them
    assert "not the ones reviewed" in again.output


async def test_a_change_after_the_plan_refuses_the_run(
    cli: tuple[Path, Path], seeded: AsyncEngine, tmp_path: Path
) -> None:
    config, backups = cli
    plan = tmp_path / "plan.json"
    assert (await _invoke(config, "plan", "--output", str(plan))).exit_code == 0
    async with seeded.begin() as conn:  # one more expired alert
        await conn.execute(
            text(
                "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                " content_hash, state_hash, recovered_by, detected_at, first_seen_at)"
                " VALUES ('late', 'alerts', 'normalized', 't', '{\"x\": 1}', 'h', 'h', 'live',"
                " now() - interval '200 days', now() - interval '200 days')"
            )
        )
    _drill(backups, ago=timedelta(minutes=5))
    result = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert result.exit_code == 1
    assert "not the ones reviewed" in result.output
    assert await _count(seeded, PURGED_RAW) == 0
    assert await _count(seeded, INVESTIGATIONS) == 2
    assert [o for _, o, _ in await _audits(seeded)] == ["failure"]


async def test_a_plan_made_with_other_periods_is_refused(
    cli: tuple[Path, Path], seeded: AsyncEngine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, backups = cli
    plan = tmp_path / "plan.json"
    assert (await _invoke(config, "plan", "--output", str(plan))).exit_code == 0
    _drill(backups, ago=timedelta(minutes=5))
    monkeypatch.setenv("ARGUS_RETENTION__RAW_SOURCE", "40d")
    result = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert result.exit_code == 1
    assert "other retention periods" in result.output
    other = json.loads(plan.read_text()) | {"database": "argus"}
    plan.write_text(json.dumps(other))
    monkeypatch.delenv("ARGUS_RETENTION__RAW_SOURCE")
    result = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert "a plan of another database" in result.output
    assert await _count(seeded, PURGED_RAW) == 0


async def _reviewed_purge(config: Path, backups: Path, plan: Path) -> None:
    """The first purge, as the user runs it: a plan, a fresh drill, the reviewed run."""
    assert (await _invoke(config, "plan", "--output", str(plan))).exit_code == 0
    _drill(backups, ago=timedelta(minutes=5))
    done = await _invoke(config, "run", "--apply", "--expect", str(plan))
    assert done.exit_code == 0, done.output


async def test_the_schedule_deletes_only_once_approved(
    cli: tuple[Path, Path], seeded: AsyncEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, backups = cli
    _drill(backups, ago=timedelta(days=3))
    refused = await _invoke(config, "run", "--apply", "--scheduled")
    assert refused.exit_code == 1
    assert "the schedule is not approved" in refused.output
    assert await _count(seeded, INVESTIGATIONS) == 2
    monkeypatch.setenv("ARGUS_RETENTION__SCHEDULED", "true")
    first = await _invoke(config, "run", "--apply", "--scheduled")
    assert first.exit_code == 1  # the schedule continues a reviewed purge: none ran yet
    assert "no reviewed purge has succeeded yet" in first.output
    assert await _count(seeded, INVESTIGATIONS) == 2
    await _reviewed_purge(config, backups, tmp_path / "plan.json")
    assert await _count(seeded, INVESTIGATIONS) == 1
    async with seeded.begin() as conn:  # 100 days later, as it were: the other one expires
        await conn.execute(
            text(
                "UPDATE investigations SET bucket_end = bucket_end - interval '100 days',"
                " bucket_start = bucket_start - interval '100 days'"
            )
        )
        await conn.execute(
            text(
                "UPDATE alert_records SET detected_at = detected_at - interval '100 days',"
                " first_seen_at = first_seen_at - interval '100 days'"
            )
        )
    done = await _invoke(config, "run", "--apply", "--scheduled")
    assert done.exit_code == 0, done.output
    assert await _count(seeded, INVESTIGATIONS) == 0
    backups.joinpath("drills.jsonl").unlink()
    _drill(backups, ago=timedelta(days=9))
    stale = await _invoke(config, "run", "--apply", "--scheduled")
    assert stale.exit_code == 1
    assert "older than 8d" in stale.output
    outcomes = [(o, d.get("scheduled")) for _, o, d in await _audits(seeded)]
    assert outcomes == [
        ("denied", True), ("denied", True), ("success", False), ("success", True),
        ("denied", True),
    ]  # fmt: skip


async def test_a_changed_period_needs_a_new_reviewed_plan_before_the_schedule_runs(
    cli: tuple[Path, Path], seeded: AsyncEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review A4-R9: the schedule was approved after a reviewed purge with memory.window 90d;
    a later change of one period (a typo: 30d) must not delete under it unreviewed."""
    config, backups = cli
    monkeypatch.setenv("ARGUS_RETENTION__SCHEDULED", "true")
    await _reviewed_purge(config, backups, tmp_path / "plan.json")
    assert await _count(seeded, INVESTIGATIONS) == 1  # the 40-day-old one stays (90d)
    monkeypatch.setenv("ARGUS_MEMORY__WINDOW", "30d")
    ran = await _invoke(config, "run", "--apply", "--scheduled")
    assert ran.exit_code == 1, ran.output
    assert "the retention periods changed since the last reviewed purge" in ran.output
    assert "memory 90d -> 30d" in ran.output
    assert await _count(seeded, INVESTIGATIONS) == 1
    assert [o for _, o, _ in await _audits(seeded)] == ["success", "denied"]
    # a reviewed plan with the new period: then the schedule runs with it
    await _reviewed_purge(config, backups, tmp_path / "plan-30d.json")
    assert await _count(seeded, INVESTIGATIONS) == 0
    again = await _invoke(config, "run", "--apply", "--scheduled")
    assert again.exit_code == 0, again.output


@pytest.mark.parametrize(
    "extra",
    [
        ("--at", "2099-01-01T00:00:00+00:00"),  # in the future
        ("--at", "2026-10-01T00:00:00"),  # without a zone
        ("--at", "yesterday"),  # not a time
    ],
)
async def test_a_refused_apply_with_a_bad_time_is_audited(
    cli: tuple[Path, Path], seeded: AsyncEngine, tmp_path: Path, extra: tuple[str, str]
) -> None:
    """Review A4-R8: every refused --apply is an audit event."""
    config, backups = cli
    plan = tmp_path / "plan.json"
    assert (await _invoke(config, "plan", "--output", str(plan))).exit_code == 0
    _drill(backups, ago=timedelta(hours=1))
    refused = await _invoke(config, "run", "--apply", "--expect", str(plan), *extra)
    assert refused.exit_code == 1, refused.output
    assert [o for _, o, _ in await _audits(seeded)] == ["denied"]
    assert await _count(seeded, INVESTIGATIONS) == 2


@pytest.mark.parametrize(
    "args", [("run", "--apply"), ("run", "--apply", "--scheduled", "--expect", "p.json")]
)
async def test_an_apply_without_one_guard_is_audited(
    cli: tuple[Path, Path], seeded: AsyncEngine, args: tuple[str, ...]
) -> None:
    """Review A4-R8: --apply with neither guard (or both) is refused, and audited."""
    config, _ = cli
    refused = await _invoke(config, *args)
    assert refused.exit_code == 2
    found = await _audits(seeded)
    assert [o for _, o, _ in found] == ["denied"]
    assert "needs --expect PLAN" in found[0][2]["refused"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["run", "--apply"], "needs --expect PLAN"),
        (["run", "--apply", "--scheduled", "--expect", "p.json"], "not both"),
        (["run", "--expect", "p.json"], "go with --apply"),
        (["plan", "--at", "2999-01-01T00:00:00+00:00"], "in the future"),
        (["plan", "--at", "2026-10-01T00:00:00"], "needs a time zone"),
        (["plan", "--at", "yesterday"], "ISO 8601"),
    ],
)
async def test_usage_errors(cli: tuple[Path, Path], args: list[str], message: str) -> None:
    config, _ = cli
    result = await _invoke(config, *args)
    assert result.exit_code == 2
    assert message in result.output
