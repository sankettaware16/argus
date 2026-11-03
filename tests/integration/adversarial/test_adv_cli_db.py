"""Adversarial: the ``argus`` CLI against throwaway databases, and integration-harness hazards.

Every CLI call here runs with the working directory moved away from the repo (so the repo
``.env`` and its real database name are out of reach), with all ``ARGUS_*`` variables removed,
and with a safety assertion that the effective database is a throwaway ``argus_test_*`` one.
The real database passwords (runtime role and owner) only travel through the environment; every
text that can end up in an assertion message is scrubbed first, so a failing test never prints
them.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import sql
from typer.testing import CliRunner, Result

import tests.integration.conftest as harness
from argus.cli import app
from argus.config import DatabaseSettings, load_settings
from argus.db import migrate
from tests.conftest import REPO_ROOT
from tests.integration.conftest import TEST_DB_PREFIX, admin_connect, owner_password

runner = CliRunner()
UNKNOWN_REVISION = "ffffffffffff"
_REAL_SECRETS: list[str] = []


# --------------------------------------------------------------------------- helpers


def _scrub(text: str) -> str:
    for secret in _REAL_SECRETS:
        text = text.replace(secret, "***")
    return text


def _connect(settings: DatabaseSettings, name: str) -> psycopg.Connection[tuple[object, ...]]:
    """As the owner: it may rewrite alembic_version to stage a broken database."""
    assert name.startswith(TEST_DB_PREFIX), "refusing to connect to a non-throwaway database"
    return admin_connect(settings, name)


def _write_config(path: Path, settings: DatabaseSettings, name: str) -> Path:
    path.write_text(
        "database:\n"
        f"  host: '{settings.host}'\n"
        f"  port: {settings.port}\n"
        f"  user: '{settings.user}'\n"
        f"  owner_user: '{settings.owner_user}'\n"
        f"  name: '{name}'\n"
        "  connect_timeout: 3s\n"
        "logging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def cli_config(
    test_database: str,
    db_settings: DatabaseSettings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """A config file for the CLI that can only reach this test's throwaway database."""
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)  # the repo .env is out of reach
    assert db_settings.password is not None
    password = db_settings.password.get_secret_value()
    owner = owner_password(db_settings)
    _REAL_SECRETS.extend((password, owner))
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", password)
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", owner)
    config = _write_config(tmp_path / "argus.yaml", db_settings, test_database)
    effective = load_settings(config).database.name
    assert effective == test_database, "safety: CLI would not target the throwaway database"
    assert effective.startswith(TEST_DB_PREFIX)
    try:
        yield config
    finally:
        _REAL_SECRETS.remove(password)
        _REAL_SECRETS.remove(owner)


def _invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    leaked = any(secret in result.output for secret in _REAL_SECRETS)
    assert not leaked, "a real database password appeared in CLI output"
    return result


def _uncaught(result: Result) -> str | None:
    exc = result.exception
    if exc is None or isinstance(exc, SystemExit):
        return None
    first = str(exc).splitlines()[0][:200] if str(exc) else ""
    return _scrub(f"{type(exc).__module__}.{type(exc).__name__}: {first}")


def _assert_clean_error(result: Result, codes: tuple[int, ...]) -> str:
    """Documented exit code, no escaped exception (= no traceback), one human error line."""
    uncaught = _uncaught(result)
    assert uncaught is None, f"exception escaped the CLI (user sees a traceback): {uncaught}"
    assert result.exit_code in codes, (result.exit_code, _scrub(result.output))
    lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, _scrub("\n".join(lines))
    assert lines[0].startswith(("error:", "problem:")), _scrub(lines[0])
    assert "Traceback" not in result.output
    return lines[0]


def _audit_rows(settings: DatabaseSettings, name: str) -> list[tuple[Any, ...]]:
    with _connect(settings, name) as conn:
        return conn.execute(
            "SELECT action, outcome, details FROM audit_events ORDER BY id"
        ).fetchall()


def _table_exists(settings: DatabaseSettings, name: str, table: str) -> bool:
    with _connect(settings, name) as conn:
        row = conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()
    return row is not None and row[0] is not None


def _set_revision(settings: DatabaseSettings, name: str, revision: str) -> None:
    with _connect(settings, name) as conn:
        conn.execute("UPDATE alembic_version SET version_num = %s", (revision,))


def _upgrade(config: Path) -> None:
    result = _invoke("db", "upgrade", "-c", str(config))
    assert result.exit_code == 0, _scrub(result.output)


# --------------------------------------------------------------------------- revision names


def test_db_upgrade_to_unknown_revision_is_a_clean_usage_error(cli_config: Path) -> None:
    result = _invoke("db", "upgrade", "no-such-revision", "-c", str(cli_config))
    line = _assert_clean_error(result, (2,))
    assert "no-such-revision" in line


def test_db_downgrade_to_unknown_revision_is_a_clean_usage_error(cli_config: Path) -> None:
    _upgrade(cli_config)
    result = _invoke("db", "downgrade", "no-such-revision", "--yes", "-c", str(cli_config))
    line = _assert_clean_error(result, (2,))
    assert "no-such-revision" in line


def test_failed_downgrade_is_not_audited_as_a_success(
    cli_config: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    """audit_events is append-only, so a false 'success' row can never be corrected."""
    _upgrade(cli_config)
    result = _invoke("db", "downgrade", "no-such-revision", "--yes", "-c", str(cli_config))
    assert result.exit_code != 0
    with _connect(db_settings, test_database) as conn:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchall()
    assert version == [(migrate.head_revision(),)]  # the database was not touched
    rows = _audit_rows(db_settings, test_database)
    false_successes = [row for row in rows if row[0] == "db.downgrade" and row[1] == "success"]
    assert false_successes == [], rows


def test_db_upgrade_from_an_unknown_database_revision_fails_cleanly(
    cli_config: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    """E.g. a newer ARGUS branch migrated this database, then the developer switched back."""
    _upgrade(cli_config)
    _set_revision(db_settings, test_database, UNKNOWN_REVISION)
    result = _invoke("db", "upgrade", "-c", str(cli_config))
    _assert_clean_error(result, (1, 2))


def test_db_downgrade_from_an_unknown_database_revision_fails_cleanly(
    cli_config: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    _upgrade(cli_config)
    _set_revision(db_settings, test_database, UNKNOWN_REVISION)
    result = _invoke("db", "downgrade", "base", "--yes", "-c", str(cli_config))
    _assert_clean_error(result, (1, 2))


def test_db_downgrade_above_current_revision_fails_cleanly(cli_config: Path) -> None:
    """Empty database, ``db downgrade 0001 --yes``: alembic refuses; the CLI must say so."""
    result = _invoke("db", "downgrade", migrate.head_revision(), "--yes", "-c", str(cli_config))
    _assert_clean_error(result, (1, 2))


# --------------------------------------------------------------------------- lock-in: still works


def test_db_upgrade_never_moves_a_database_down(
    cli_config: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    """``db upgrade base`` on a migrated database is a no-op, never a silent downgrade."""
    _upgrade(cli_config)
    result = _invoke("db", "upgrade", "base", "-c", str(cli_config))
    assert _uncaught(result) is None
    assert result.exit_code == 0, _scrub(result.output)
    assert f"revision {migrate.head_revision()}" in result.output
    assert _table_exists(db_settings, test_database, "audit_events")


def test_unknown_database_revision_is_reported_by_check_current_and_doctor(
    cli_config: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    _upgrade(cli_config)
    _set_revision(db_settings, test_database, UNKNOWN_REVISION)

    current = _invoke("db", "current", "-c", str(cli_config))
    assert current.exit_code == 0, _scrub(current.output)
    assert f"current={UNKNOWN_REVISION}" in current.output

    check = _invoke("db", "check", "-c", str(cli_config))
    assert _uncaught(check) is None
    assert check.exit_code == 1
    assert UNKNOWN_REVISION in check.stderr

    doctor = _invoke("doctor", "-c", str(cli_config))
    assert _uncaught(doctor) is None
    assert doctor.exit_code == 1
    assert "FAIL  migrations" in doctor.output


def test_wrong_password_is_a_one_line_operational_error_without_the_password(
    cli_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``argus db`` logs in as the owner, ``doctor`` as the runtime role (D-029): each fails on
    its own wrong password, in one line, without printing it."""
    wrong = "Synthetic-Wrong-Pass-9f8e7d"
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", wrong)
    for command in (["db", "current"], ["db", "upgrade"], ["db", "check"]):
        result = _invoke(*command, "-c", str(cli_config))
        line = _assert_clean_error(result, (1,))
        assert "password authentication failed" in line
        assert wrong not in result.output
    downgrade = _invoke("db", "downgrade", "base", "--yes", "-c", str(cli_config))
    _assert_clean_error(downgrade, (1,))
    doctor = _invoke("doctor", "-c", str(cli_config))
    assert "PASS  database " in doctor.output, _scrub(doctor.output)  # runtime password is right
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", wrong)
    doctor = _invoke("doctor", "-c", str(cli_config))
    assert doctor.exit_code == 1
    assert "FAIL  database" in doctor.output
    assert "run `argus db bootstrap`" in doctor.output  # the hint for a refused login
    assert wrong not in doctor.output


def test_missing_database_is_a_one_line_operational_error(
    cli_config: Path, db_settings: DatabaseSettings, tmp_path: Path
) -> None:
    missing = f"{TEST_DB_PREFIX}{int(time.time())}_absent{secrets.token_hex(3)}"
    config = _write_config(tmp_path / "missing.yaml", db_settings, missing)
    for command in (["db", "current"], ["db", "downgrade", "base", "--yes"], ["db", "upgrade"]):
        result = _invoke(*command, "-c", str(config))
        line = _assert_clean_error(result, (1,))
        assert "does not exist" in line


def test_downgrade_round_trip_reports_revisions(cli_config: Path) -> None:
    _upgrade(cli_config)
    down = _invoke("db", "downgrade", "base", "--yes", "-c", str(cli_config))
    assert down.exit_code == 0, _scrub(down.output)
    assert f"revision empty (was {migrate.head_revision()})" in down.output
    again = _invoke("db", "downgrade", "base", "--yes", "-c", str(cli_config))
    assert again.exit_code == 0, _scrub(again.output)
    assert "revision empty (was empty)" in again.output


# --------------------------------------------------------------------------- harness hazards


def test_db_settings_fixture_does_not_point_at_a_real_database(
    db_settings: DatabaseSettings,
) -> None:
    """``create_engine(db_settings)`` (forgetting ``database=``) must not reach a real database."""
    points_at_throwaway = db_settings.name.startswith(TEST_DB_PREFIX)
    assert points_at_throwaway, "session fixture db_settings targets the developer's database"


def test_integration_tests_without_overrides_do_not_target_the_real_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pytest runs from the repo root; a test that forgets the override gets .env's database."""
    monkeypatch.chdir(REPO_ROOT)
    name = load_settings(REPO_ROOT / "config" / "argus.yaml").database.name
    targets_throwaway = name.startswith(TEST_DB_PREFIX)
    assert targets_throwaway, "plain load_settings()/CLI call in an integration test hits a real DB"


class _DropRecorder:
    """Wraps a real admin connection: SELECTs run for real, DROP DATABASE is only recorded."""

    def __init__(self, real: psycopg.Connection[Any], dropped: list[str]) -> None:
        self._real = real
        self._dropped = dropped

    def __enter__(self) -> _DropRecorder:
        self._real.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._real.__exit__(*exc)  # type: ignore[arg-type]

    def execute(self, query: Any, params: Any = None) -> Any:
        text = query.as_string(self._real) if isinstance(query, sql.Composable) else str(query)
        if text.lstrip().upper().startswith("DROP DATABASE"):
            self._dropped.append(text)
            return None
        return self._real.execute(query, params)


@pytest.fixture
def lookalike_database(db_settings: DatabaseSettings) -> Iterator[str]:
    """A database whose name does NOT follow the argus_test_<unix time>_<hex> scheme."""
    name = f"argus_testing_adv_{secrets.token_hex(4)}"
    with admin_connect(db_settings) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield name
    finally:
        with admin_connect(db_settings) as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def test_stale_cleanup_only_targets_throwaway_databases(
    lookalike_database: str, db_settings: DatabaseSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``LIKE 'argus_test_%'``: '_' is a wildcard, so 'argus_testing…'/'argus_tests' match too.

    Runs the real cleanup fixture body with DROP DATABASE intercepted, so nothing is dropped.
    """
    fixture = harness._drop_stale_test_databases
    get_body: Callable[[], Callable[..., Any]] | None = getattr(
        fixture, "_get_wrapped_function", None
    )
    if get_body is None:
        pytest.skip("this pytest version does not expose fixture bodies")
    dropped: list[str] = []
    monkeypatch.setattr(
        harness, "admin_connect", lambda settings: _DropRecorder(admin_connect(settings), dropped)
    )
    get_body()(db_settings)
    would_drop = any(f'"{lookalike_database}"' in statement for statement in dropped)
    assert not would_drop, "stale cleanup would FORCE-drop a database outside the test scheme"
