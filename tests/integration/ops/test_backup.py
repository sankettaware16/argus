"""Q-A2: backups on a throwaway database, with the real pg_dump and pg_restore of the pinned
server image (``backup.tools: image``; the db service's container is never used by a test).
The gate: restore fingerprints match; a dump's fingerprints describe its snapshot while writes
go on; a changed dump or restore is caught; migrations dump first and stop if that fails."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.config.settings import BackupSettings, DatabaseSettings, Settings
from argus.db import migrate
from argus.db.engine import create_engine
from argus.ops import backup
from argus.web import auth
from tests.conftest import REPO_ROOT
from tests.integration.conftest import admin_connect, owner_password
from tests.integration.grouping.test_grouping import doc, ingest

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
runner = CliRunner()


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(  # noqa: S603 - fixed arguments
        ["docker", "image", "inspect", BackupSettings().image],  # noqa: S607
        env={**os.environ, "DOCKER_CONTEXT": "default"},
        capture_output=True,
        check=False,
    )
    return probe.returncode == 0


needs_docker = pytest.mark.skipif(
    not _docker_ready(), reason="needs docker and the pinned postgres image (docker-compose.yml)"
)


def settings_for(
    db: DatabaseSettings, database: str, folder: Path, **backup_values: Any
) -> Settings:
    return Settings(
        database=db.model_copy(update={"name": database}),
        backup=BackupSettings(dir=folder, tools="image", **backup_values),
    )


async def seed(app_engine: AsyncEngine) -> None:
    docs = [
        doc(n, f"rule-{n % 2}", f"10.0.0.{n % 3}", NOW - timedelta(minutes=9 * n)) for n in range(6)
    ]
    await ingest(app_engine, docs)
    async with app_engine.begin() as conn:
        await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        await auth.audit(conn, actor="test", action="seed", details={"rows": 6})


def scratch_databases(db: DatabaseSettings) -> set[str]:
    with admin_connect(db) as conn:
        rows = conn.execute("SELECT datname FROM pg_database").fetchall()
    return {str(name) for (name,) in rows if str(name).startswith(backup.SCRATCH_PREFIX)}


@needs_docker
async def test_a_dump_restores_identically_and_stays_private(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed(app_engine)
    settings = settings_for(db_settings, test_database, tmp_path / "backups")
    before = scratch_databases(db_settings)
    made = await backup.dump(settings, "manual", now=NOW)
    assert made.revision == migrate.head_revision()
    assert made.fingerprints.tables["public.alert_records"][0] == 6
    assert made.fingerprints.tables["public.users"][0] == 1
    assert {"columns", "constraints", "indexes", "triggers", "functions", "privileges",
            "schemas"} == set(made.fingerprints.schema)  # fmt: skip
    assert made.dump_path.stat().st_size == made.bytes > 0
    for path in (made.dump_path, made.path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for folder in (tmp_path / "backups", tmp_path / "backups" / "manual"):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    result = await backup.drill(settings, made, now=NOW + timedelta(minutes=1))
    assert result.passed, result.differences
    assert result.dump == f"manual/{made.file}"
    assert scratch_databases(db_settings) == before  # the scratch database is gone
    assert backup.read_manifest(made.path).verified is not None
    (record,) = backup.drills(tmp_path / "backups")
    assert (record["passed"], record["dump"]) == (True, result.dump)


@needs_docker
async def test_the_fingerprints_are_the_snapshot_pg_dump_reads(
    app_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rows written while pg_dump runs are in neither the fingerprints nor the dump, so the
    services keep running during a dump and the drill still finds it identical."""
    await seed(app_engine)
    real = backup._run_tool
    wrote: list[int] = []

    async def write_meanwhile(*args: Any, **kwargs: Any) -> None:
        if kwargs.get("what") == "pg_dump":
            async with app_engine.begin() as conn:
                await auth.audit(conn, actor="test", action="written.during.the.dump")
            wrote.append(1)
        await real(*args, **kwargs)

    monkeypatch.setattr(backup, "_run_tool", write_meanwhile)
    settings = settings_for(db_settings, test_database, tmp_path / "backups")
    made = await backup.dump(settings, "manual", now=NOW)
    assert wrote == [1]
    monkeypatch.setattr(backup, "_run_tool", real)
    assert (await backup.drill(settings, made, now=NOW)).passed
    owner = create_engine(db_settings, database=test_database, role="owner")
    try:
        async with owner.connect() as conn, conn.begin():
            live = await backup.fingerprints(conn)
    finally:
        await owner.dispose()
    dumped, now = (
        made.fingerprints.tables["public.audit_events"],
        live.tables["public.audit_events"],
    )
    assert now[0] == dumped[0] + 1  # the live database moved on; the dump did not


@needs_docker
async def test_a_changed_dump_or_a_restore_that_differs_fails_the_drill(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    await seed(app_engine)
    settings = settings_for(db_settings, test_database, tmp_path / "backups")
    made = await backup.dump(settings, "manual", now=NOW)
    data = json.loads(made.path.read_text())
    rows, digest = data["fingerprints"]["tables"]["public.alert_records"]
    data["fingerprints"]["tables"]["public.alert_records"] = [rows + 1, digest]
    made.path.write_text(json.dumps(data))
    result = await backup.drill(settings, backup.read_manifest(made.path), now=NOW)
    assert not result.passed
    assert result.differences == (
        f"table public.alert_records: {rows + 1} rows dumped, {rows} restored",
    )
    assert backup.read_manifest(made.path).verified is None
    blob = bytearray(made.dump_path.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    made.dump_path.write_bytes(bytes(blob))
    result = await backup.drill(settings, backup.read_manifest(made.path), now=NOW)
    assert result.differences == ("the dump file does not match its recorded SHA-256",)
    assert [r["passed"] for r in backup.drills(tmp_path / "backups")] == [False, False]


@needs_docker
async def test_only_stale_scratch_databases_of_a_drill_are_dropped(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    stale = f"{backup.SCRATCH_PREFIX}{int((now - timedelta(days=1)).timestamp()):010d}_0badc0de"
    fresh = f"{backup.SCRATCH_PREFIX}{int(now.timestamp()):010d}_0dd0dd0d"
    with admin_connect(db_settings) as conn:
        for name in (stale, fresh):
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        settings = settings_for(db_settings, test_database, tmp_path / "backups")
        made = await backup.dump(settings, "manual", now=now)
        assert (await backup.drill(settings, made, now=now)).passed
        left = scratch_databases(db_settings)
        assert stale not in left
        assert fresh in left  # another drill may be using it
    finally:
        with admin_connect(db_settings) as conn:
            for name in (stale, fresh):
                conn.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
                )


@needs_docker
async def test_retention_keeps_the_newest_of_each_kind(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    settings = settings_for(db_settings, test_database, tmp_path / "backups", keep_manual=2)
    made = [await backup.dump(settings, "manual", now=NOW + timedelta(hours=h)) for h in range(3)]
    left = backup.manifests(tmp_path / "backups")
    assert [m.file for m in left] == [made[2].file, made[1].file]
    assert not made[0].dump_path.exists()
    assert not made[0].path.exists()


# --------------------------------------------------------------------------- migrations


@pytest.fixture
def cli_env(
    test_database: str,
    db_settings: DatabaseSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    monkeypatch.chdir(REPO_ROOT)  # the repo .env supplies the passwords
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    monkeypatch.setenv("ARGUS_BACKUP__BEFORE_MIGRATION", "true")
    monkeypatch.setenv("ARGUS_BACKUP__TOOLS", "image")
    monkeypatch.setenv("ARGUS_BACKUP__DIR", str(tmp_path / "backups"))
    for switch in ("REFERENCE__TI_SYNC", "ENRICHMENT__LOG_QUERIES",
                   "ENRICHMENT__PROXY_AGGREGATIONS", "WRITEBACK__ENABLED"):  # fmt: skip
        monkeypatch.setenv(f"ARGUS_{switch}", "false")
    return REPO_ROOT / "config" / "argus.yaml"


def _cli(*args: str, secrets: tuple[str, ...]) -> tuple[int, str]:
    result = runner.invoke(app, list(args))
    out = result.output + result.stderr
    assert not any(secret in out for secret in secrets), "a password appeared in CLI output"
    return result.exit_code, out


def _audit(db: DatabaseSettings, database: str, action: str) -> list[Any]:
    with admin_connect(db, database) as conn:
        return [
            row[0]
            for row in conn.execute(
                "SELECT details FROM audit_events WHERE action = %s ORDER BY id", (action,)
            )
        ]


def _revision(db: DatabaseSettings, database: str) -> str | None:
    with admin_connect(db, database) as conn:
        exists = conn.execute("SELECT to_regclass('public.alembic_version')").fetchone()
        if exists is None or exists[0] is None:
            return None
        row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        return None if row is None else str(row[0])


@needs_docker
def test_an_upgrade_dumps_the_database_first(
    cli_env: Path, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    assert db_settings.password is not None
    secrets = (db_settings.password.get_secret_value(), owner_password(db_settings))
    code, out = _cli("db", "upgrade", "-c", str(cli_env), secrets=secrets)  # empty: no dump
    assert code == 0, out
    assert "dumped first" not in out
    code, out = _cli("db", "downgrade", "--yes", "-c", str(cli_env), "--", "-1", secrets=secrets)
    assert code == 0, out
    (saved,) = backup.manifests(tmp_path / "backups")
    assert (saved.kind, saved.revision) == ("migration", migrate.head_revision())
    assert f"dumped first: migration/{saved.file}" in out
    code, out = _cli("db", "upgrade", "-c", str(cli_env), secrets=secrets)
    assert code == 0, out
    assert len(backup.manifests(tmp_path / "backups")) == 2
    details = _audit(db_settings, test_database, "db.upgrade")
    assert "backup" not in details[0]  # the first upgrade, of an empty database
    assert details[-1]["backup"].startswith("migration/")
    assert _audit(db_settings, test_database, "db.downgrade")[-1]["backup"] == (
        f"migration/{saved.file}"
    )
    code, out = _cli("db", "upgrade", "-c", str(cli_env), secrets=secrets)  # at head: no dump
    assert code == 0, out
    assert len(backup.manifests(tmp_path / "backups")) == 2


def test_a_failed_dump_stops_the_migration(
    cli_env: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert db_settings.password is not None
    secrets = (db_settings.password.get_secret_value(), owner_password(db_settings))
    code, out = _cli("db", "upgrade", "0021", "--no-backup", "-c", str(cli_env), secrets=secrets)
    assert code == 0, out

    async def broken(*_: Any, **__: Any) -> None:
        raise backup.BackupError("pg_dump failed (exit 1): no space left on device")

    monkeypatch.setattr(backup, "_run_tool", broken)
    code, out = _cli("db", "upgrade", "-c", str(cli_env), secrets=secrets)
    assert code == 1
    assert "the dump before the upgrade failed, so nothing was migrated" in out
    assert "no space left on device" in out
    assert "--no-backup" in out
    assert _revision(db_settings, test_database) == "0021"
    assert backup.manifests(tmp_path / "backups") == []
    assert not list((tmp_path / "backups" / "migration").glob("*"))  # no partial left
    code, out = _cli("db", "upgrade", "--no-backup", "-c", str(cli_env), secrets=secrets)
    assert code == 0, out
    assert _revision(db_settings, test_database) == migrate.head_revision()


def test_backup_check_sh_runs_argus_backup_check() -> None:
    """scripts/backup_check.sh is `argus backup check`: no service is stopped or restarted."""
    script = (REPO_ROOT / "scripts" / "backup_check.sh").read_text()
    assert "exec uv run argus backup check" in script
    assert "systemctl" not in script
    assert "systemd-run" not in script


def test_the_test_session_never_dumps_through_the_db_container() -> None:
    """LOCK-IN: integration tests run with the dump before migrations off, unless a test asks
    for it (with backup.tools: image)."""
    assert os.environ.get("ARGUS_BACKUP__BEFORE_MIGRATION") == "false"
    assert BackupSettings().before_migration is False


async def test_a_sequence_behind_its_column_is_caught(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """A restore whose sequence would hand out an id its table holds already is not a good one
    (sequences are not in the snapshot, so they are checked this way, not by value)."""
    async with app_engine.begin() as conn:
        for n in range(3):
            await auth.audit(conn, actor="test", action=f"row.{n}")
    async with migrated_engine.begin() as conn:
        assert await backup.sequence_problems(conn) == []
        await conn.execute(text("SELECT setval('audit_events_id_seq', 1)"))
        assert await backup.sequence_problems(conn) == [
            "sequence public.audit_events_id_seq: behind its column (next 1, highest 3)"
        ]
        await conn.execute(text("SELECT setval('audit_events_id_seq', 3, false)"))
        assert len(await backup.sequence_problems(conn)) == 1  # 3 would be handed out again
        await conn.execute(text("SELECT setval('audit_events_id_seq', 3, true)"))
        assert await backup.sequence_problems(conn) == []


@needs_docker
def test_the_backup_commands(
    cli_env: Path, db_settings: DatabaseSettings, test_database: str, tmp_path: Path
) -> None:
    assert db_settings.password is not None
    secrets = (db_settings.password.get_secret_value(), owner_password(db_settings))
    assert _cli("db", "upgrade", "-c", str(cli_env), secrets=secrets)[0] == 0
    code, out = _cli("backup", "check", "-c", str(cli_env), secrets=secrets)
    assert code == 0, out
    assert "RESTORE IDENTICAL: every table's fingerprint" in out
    code, out = _cli("backup", "list", "-c", str(cli_env), secrets=secrets)
    assert code == 0, out
    assert "manual" in out
    assert "verified" in out
    assert "identical" in out
    code, out = _cli("backup", "prune", "-c", str(cli_env), secrets=secrets)
    assert (code, out.strip()) == (0, "nothing to remove")
    code, out = _cli("backup", "dump", "--kind", "weekly", "-c", str(cli_env), secrets=secrets)
    assert code == 2
    assert "--kind is one of nightly, migration, manual" in out
    dumps = _audit(db_settings, test_database, "backup.dump")
    drills = _audit(db_settings, test_database, "backup.drill")
    assert [d["kind"] for d in dumps] == ["manual"]
    assert [d["passed"] for d in drills] == [True]
