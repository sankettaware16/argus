"""The plain ``alembic`` command (developer entry point, alembic.ini) against a throwaway database.

env.py has its own path for it (no connection handed in): it builds the engine from ARGUS settings,
takes the same migration lock as ``argus db``, commits, and compares only the tables ARGUS's models
declare. Each run is a child process whose settings can only name this test's database.
"""

from __future__ import annotations

import os
import subprocess
import sys

import psycopg
import pytest

from argus.config import DatabaseSettings, load_settings
from argus.db import migrate
from tests.conftest import REPO_ROOT
from tests.integration.conftest import TEST_DB_PREFIX, admin_connect


@pytest.fixture
def alembic_env(test_database: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Environment for an ``alembic`` child that can only reach this test's database."""
    monkeypatch.chdir(REPO_ROOT)  # alembic.ini, config/argus.yaml and the .env password
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)  # environment beats .env
    monkeypatch.setenv("ARGUS_DATABASE__STATEMENT_TIMEOUT", "2s")  # lock_timeout follows it
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    effective = load_settings().database.name  # exactly what env.py calls
    assert effective == test_database, "safety: alembic would not target the throwaway database"
    assert effective.startswith(TEST_DB_PREFIX)
    return dict(os.environ)


def _passwords(settings: DatabaseSettings) -> list[str]:
    assert settings.password is not None
    assert settings.owner_password is not None
    return [settings.password.get_secret_value(), settings.owner_password.get_secret_value()]


def _alembic(env: dict[str, str], settings: DatabaseSettings, *args: str) -> tuple[int, str]:
    """Exit code and output, with the real passwords scrubbed so no assertion can print them."""
    proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running alembic
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = proc.stdout + proc.stderr
    for password in _passwords(settings):
        output = output.replace(password, "***")
    return proc.returncode, output


def _connect(settings: DatabaseSettings, name: str) -> psycopg.Connection[tuple[object, ...]]:
    """As the owner, like the migrations (D-029)."""
    assert name.startswith(TEST_DB_PREFIX), "refusing to connect to a non-throwaway database"
    return admin_connect(settings, name)


def _count_tables(settings: DatabaseSettings, name: str, table: str) -> object:
    with _connect(settings, name) as conn:
        row = conn.execute(
            "SELECT count(*) FROM pg_class WHERE relname = %s AND relkind = 'r'"
            " AND relnamespace = 'public'::regnamespace",
            (table,),
        ).fetchone()
    assert row is not None
    return row[0]


@pytest.mark.timeout(120)
def test_plain_alembic_commits_and_ignores_tables_argus_does_not_own(
    alembic_env: dict[str, str], db_settings: DatabaseSettings, test_database: str
) -> None:
    code, out = _alembic(alembic_env, db_settings, "upgrade", "head")
    assert code == 0, out
    with _connect(db_settings, test_database) as conn:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchall()
        # A table another component owns (LangGraph's checkpoints, D-009) is not drift.
        conn.execute("CREATE TABLE checkpoints (thread_id text PRIMARY KEY, checkpoint jsonb)")
    assert version == [(migrate.head_revision(),)]  # committed

    code, out = _alembic(alembic_env, db_settings, "check")
    assert code == 0, out
    assert "No new upgrade operations detected" in out
    assert _count_tables(db_settings, test_database, "checkpoints") == 1


@pytest.mark.timeout(120)
def test_plain_alembic_waits_for_the_migration_lock(
    alembic_env: dict[str, str], db_settings: DatabaseSettings, test_database: str
) -> None:
    """Another runner holds the lock for longer than the timeouts (2 s here): plain alembic waits
    for it, gives up, and leaves the database untouched, like ``argus db upgrade`` does."""
    with _connect(db_settings, test_database) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (migrate.MIGRATION_LOCK_KEY,))
        code, out = _alembic(alembic_env, db_settings, "upgrade", "head")
    assert code != 0, out
    # The statement that timed out is env.py's wait for the lock (statement_timeout and
    # lock_timeout are both 2 s, so either may fire first).
    assert "canceling statement due to" in out
    assert "pg_advisory_xact_lock" in out
    assert _count_tables(db_settings, test_database, "alembic_version") == 0
    assert _count_tables(db_settings, test_database, "audit_events") == 0
