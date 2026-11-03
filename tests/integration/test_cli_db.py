"""End-to-end CLI against a throwaway database.

The real local database passwords (runtime role and owner, D-029) reach the CLI through the repo
``.env``. Every CLI result is checked for them (a boolean, with a fixed message) before any
assertion can show the output, so a failing test never prints them.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from typer.testing import CliRunner, Result

from argus.cli import app
from argus.config import DatabaseSettings, load_settings
from argus.config.settings import CONFIG_ENV_VAR
from argus.db import migrate
from tests.conftest import env_copy, suite_checkout
from tests.integration.conftest import TEST_DB_PREFIX, admin_connect, owner_password

runner = CliRunner()
_SECRETS: list[str] = []


@pytest.fixture
def cli_env(
    test_database: str,
    db_settings: DatabaseSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Path]:
    # the repo .env's database passwords, without a web password an install wrote (Q-A2)
    monkeypatch.chdir(
        env_copy(
            tmp_path_factory.mktemp("cwd"), without=frozenset({"ARGUS_DATABASE__API_PASSWORD"})
        )
    )
    # The shipped config on the suite's site (D-294), never this checkout's site.yaml/local.yaml.
    checkout = suite_checkout(tmp_path_factory.mktemp("checkout"))
    monkeypatch.setenv(CONFIG_ENV_VAR, str(checkout / "config" / "argus.yaml"))
    # Environment beats .env, which beats YAML: this is the only reliable override.
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    # Remote modules off whatever the repo's config says (they are switched on after live
    # checks, D-068): a CLI test never prepares an SIEM request.
    for switch in ("REFERENCE__TI_SYNC", "ENRICHMENT__LOG_QUERIES",
                   "ENRICHMENT__PROXY_AGGREGATIONS", "WRITEBACK__ENABLED"):  # fmt: skip
        monkeypatch.setenv(f"ARGUS_{switch}", "false")
    config = checkout / "config" / "argus.yaml"
    # Safety: never let this test run migrations/downgrades against a real database.
    effective = load_settings(config).database.name
    assert effective == test_database, effective
    assert effective.startswith(TEST_DB_PREFIX), effective
    assert db_settings.password is not None
    passwords = [db_settings.password.get_secret_value(), owner_password(db_settings)]
    _SECRETS.extend(passwords)
    try:
        yield config
    finally:
        for password in passwords:
            _SECRETS.remove(password)


def _run(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    shown = (result.output, result.stderr, repr(result.exception))
    leaked = any(secret in text for secret in _SECRETS for text in shown)
    assert not leaked, "a real database password appeared in CLI output"
    return result


def _invoke(*args: str) -> tuple[int, str]:
    result = _run(*args)
    return result.exit_code, result.output + result.stderr


def _error_line(result: Result) -> str:
    """The single error line of a failed command that raised nothing (= showed no traceback)."""
    exc = result.exception
    assert exc is None or isinstance(exc, SystemExit), f"uncaught {type(exc).__name__}"
    assert "Traceback" not in result.output
    lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    return lines[0]


def _connect(settings: DatabaseSettings, name: str) -> psycopg.Connection[tuple[Any, ...]]:
    """As the owner: it may read and write every table at every revision."""
    assert name.startswith(TEST_DB_PREFIX), "refusing to connect to a non-throwaway database"
    return admin_connect(settings, name)


def _state(settings: DatabaseSettings, name: str) -> tuple[list[str], list[tuple[Any, ...]]]:
    """The database's alembic_version rows and its audit rows (action, outcome, details)."""
    with _connect(settings, name) as conn:
        versions = (
            [row[0] for row in conn.execute("SELECT version_num FROM alembic_version")]
            if _exists(conn, "alembic_version")
            else []
        )
        audit = (
            conn.execute("SELECT action, outcome, details FROM audit_events ORDER BY id").fetchall()
            if _exists(conn, "audit_events")
            else []
        )
    return versions, audit


def _exists(conn: psycopg.Connection[tuple[Any, ...]], table: str) -> bool:
    row = conn.execute("SELECT to_regclass(%s) IS NOT NULL", (table,)).fetchone()
    return bool(row and row[0])


def test_full_lifecycle(cli_env: Path, db_settings: DatabaseSettings, test_database: str) -> None:
    code, out = _invoke("doctor", "-c", str(cli_env))
    assert code == 1
    assert "FAIL  migrations" in out

    code, out = _invoke("db", "bootstrap", "-c", str(cli_env))
    assert code == 0, out
    assert f"roles ready: {db_settings.user} (member of argus_runtime)" in out
    assert f"may connect to {test_database}" in out

    code, out = _invoke("db", "upgrade", "-c", str(cli_env))
    assert code == 0, out
    head = migrate.head_revision()
    assert f"revision {head}" in out

    code, out = _invoke("db", "current", "-c", str(cli_env))
    assert code == 0
    assert f"current={head} head={head}" in out

    code, out = _invoke("db", "check", "-c", str(cli_env))
    assert code == 0
    assert "schema OK" in out

    code, out = _invoke("doctor", "-c", str(cli_env))
    assert code == 0, out
    assert "FAIL" not in out
    assert "audit trail append-only" in out
    assert "PASS  runtime role" in out
    assert f"{db_settings.user}: least privilege, owns nothing" in out

    code, out = _invoke("db", "bootstrap", "-c", str(cli_env))  # again: idempotent, now audited
    assert code == 0, out
    assert "already present" in out
    assert "repaired:" not in out  # nothing was wrong with the roles

    assert db_settings.password is not None
    password = db_settings.password.get_secret_value()
    with psycopg.connect(  # the runtime role may read the audit trail
        host=db_settings.host,
        port=db_settings.port,
        user=db_settings.user,
        password=password,
        dbname=test_database,
    ) as conn:
        rows = conn.execute(
            "SELECT actor, action, details FROM audit_events ORDER BY id"
        ).fetchall()
    passwords = [password, owner_password(db_settings)]
    audit_holds_password = any(p in str(value) for row in rows for value in row for p in passwords)
    assert not audit_holds_password, "a real database password is in the audit trail"
    assert rows == [
        ("cli", "db.upgrade", {"from": None, "to": head}),
        ("cli", "db.bootstrap", {"login": db_settings.user, "created": [], "repaired": []}),
    ]

    code, out = _invoke("db", "downgrade", "base", "--yes", "-c", str(cli_env))
    assert code == 0, out

    code, out = _invoke("db", "check", "-c", str(cli_env))
    assert code == 1
    assert f"head is {head}" in out
    printed_password = any(p in out for p in passwords)
    assert not printed_password, "a real database password appeared in CLI output"


# --------------------------------------------------------------------------- revision targets

CHAIN = migrate.revision_chain()
FIRST, HEAD = CHAIN[0], CHAIN[-1]
CHAIN_LENGTH = len(CHAIN)


@pytest.mark.parametrize(
    ("direction", "revision"),
    [
        ("upgrade", "head+1"),
        ("upgrade", f"head-{CHAIN_LENGTH + 1}"),  # one past base, whatever the chain's length
        ("upgrade", f"{HEAD}+1"),
        ("upgrade", f"{FIRST}+{CHAIN_LENGTH}"),
        ("upgrade", f"base+{CHAIN_LENGTH + 1}"),
        ("downgrade", f"head-{CHAIN_LENGTH + 1}"),
        ("downgrade", "base-1"),
    ],
)
def test_steps_off_the_chain_are_unknown_revisions_and_touch_nothing(
    cli_env: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    direction: str,
    revision: str,
) -> None:
    """Alembic fails on e.g. ``upgrade head+1`` with a bare AssertionError: a Rich traceback,
    exit 1 and no audit row. It is a usage error, caught before anything is touched."""
    code, out = _invoke("db", "upgrade", "-c", str(cli_env))
    assert code == 0, out
    before = _state(db_settings, test_database)

    options = ["--yes"] if direction == "downgrade" else []
    result = _run("db", direction, *options, "-c", str(cli_env), "--", revision)

    assert result.exit_code == 2, result.output
    line = _error_line(result)
    assert line.startswith(f"error: unknown revision {revision!r}"), line
    assert _state(db_settings, test_database) == before


@pytest.mark.parametrize(
    ("direction", "revision"),
    [
        ("upgrade", "-1"),
        ("upgrade", f"-{len(CHAIN)}"),
        ("downgrade", "+1"),
        ("downgrade", f"+{len(CHAIN)}"),
    ],
)
def test_a_step_the_other_way_is_a_usage_error_that_takes_no_lock_and_writes_nothing(
    cli_env: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
    revision: str,
) -> None:
    """Alembic refuses ``upgrade -N`` and ``downgrade +N`` whatever the database's revision. Left
    to Alembic, such a command took the migration lock, failed with exit 1 and wrote a failure
    audit row. Here another session holds the migration lock, so asking for it would time out
    after 1 s (exit 1): the command answers exit 2 without asking for it, and neither the
    revision nor the audit trail changes."""
    monkeypatch.setenv("ARGUS_DATABASE__STATEMENT_TIMEOUT", "1s")  # and so a 1 s lock_timeout
    code, out = _invoke("db", "upgrade", "-c", str(cli_env), "+1")  # mid-chain: both ways open
    assert code == 0, out
    before = _state(db_settings, test_database)
    assert before[0] == [FIRST]

    options = ["--yes"] if direction == "downgrade" else []
    with _connect(db_settings, test_database) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (migrate.MIGRATION_LOCK_KEY,))
        result = _run("db", direction, *options, "-c", str(cli_env), "--", revision)

    assert result.exit_code == 2, result.output
    sign = "+" if direction == "upgrade" else "-"
    assert _error_line(result) == (
        f"error: unknown revision {revision!r}: {direction} takes only {sign}N steps from the "
        "database's revision"
    )
    assert _state(db_settings, test_database) == before


def test_steps_on_the_chain_move_one_migration_at_a_time(
    cli_env: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    config = str(cli_env)
    for revision in CHAIN:
        code, out = _invoke("db", "upgrade", "-c", config, "+1")
        assert code == 0, out
        assert _state(db_settings, test_database)[0] == [revision]

    code, out = _invoke(
        "db", "downgrade", "--yes", "-c", config, "--", "-1"
    )  # `--`: -1 is no option
    assert code == 0, out
    assert _state(db_settings, test_database)[0] == [CHAIN[-2]]

    # A step that lands on base: Alembic's own resolution asserts for an upgrade; it is a no-op,
    # exactly like `db upgrade base`.
    code, out = _invoke("db", "upgrade", "-c", config, f"head-{len(CHAIN)}")
    assert code == 0, out
    assert _state(db_settings, test_database)[0] == [CHAIN[-2]]

    code, out = _invoke("db", "upgrade", "-c", config, f"{CHAIN[-2]}+1")
    assert code == 0, out
    assert _state(db_settings, test_database)[0] == [HEAD]

    code, out = _invoke("db", "downgrade", "--yes", "-c", config, "head-1")
    assert code == 0, out
    versions, audit = _state(db_settings, test_database)
    assert versions == [CHAIN[-2]]
    assert {(action, outcome) for action, outcome, _ in audit} == {
        ("db.upgrade", "success"),
        ("db.downgrade", "success"),
    }

    code, out = _invoke("db", "downgrade", "--yes", "-c", config, "--", f"head-{len(CHAIN)}")
    assert code == 0, out
    assert _state(db_settings, test_database)[0] == []


# --------------------------------------------------------------------------- failed migrations


def test_failed_migration_is_audited_with_from_target_and_error(
    cli_env: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reader holds audit_events, so the downgrade times out on its lock and rolls back. The
    attempt is recorded once, as a failure, with where it started, where it was going and why."""
    monkeypatch.setenv("ARGUS_DATABASE__STATEMENT_TIMEOUT", "1s")  # and so a 1 s lock_timeout
    code, out = _invoke("db", "upgrade", "-c", str(cli_env))
    assert code == 0, out

    with _connect(db_settings, test_database) as reader, reader.transaction():
        reader.execute("LOCK TABLE audit_events IN ACCESS SHARE MODE")
        result = _run("db", "downgrade", "base", "--yes", "-c", str(cli_env))

    assert result.exit_code == 1, result.output
    assert "downgrade failed" in _error_line(result)
    versions, audit = _state(db_settings, test_database)
    assert versions == [HEAD]  # rolled back
    assert [(action, outcome) for action, outcome, _ in audit] == [
        ("db.upgrade", "success"),
        ("db.downgrade", "failure"),
    ]
    details = audit[-1][2]
    assert set(details) == {"from", "target", "error"}
    assert details["from"] == HEAD
    assert details["target"] == "base"
    assert details["error"].startswith("downgrade failed: ")
    assert "timeout" in details["error"]


def test_several_rows_in_alembic_version_fail_cleanly_everywhere(
    cli_env: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    """Alembic refuses to name one current revision; every command says so on one line."""
    config = str(cli_env)
    code, out = _invoke("db", "upgrade", "-c", config)
    assert code == 0, out
    with _connect(db_settings, test_database) as conn:
        conn.execute("INSERT INTO alembic_version (version_num) VALUES (%s)", (FIRST,))

    for command in (["db", "current"], ["db", "check"], ["db", "upgrade"]):
        result = _run(*command, "-c", config)
        assert result.exit_code == 1, (command, result.output)
        line = _error_line(result)
        assert line.startswith(("error:", "problem:")), line
        assert "more than one head" in line

    doctor = _run("doctor", "-c", config)
    assert doctor.exit_code == 1
    assert "FAIL  migrations" in doctor.output
    assert "more than one head" in doctor.output

    versions, audit = _state(db_settings, test_database)
    assert sorted(versions) == sorted([FIRST, HEAD])  # untouched
    assert [(action, outcome) for action, outcome, _ in audit] == [
        ("db.upgrade", "success"),
        ("db.upgrade", "failure"),
    ]
    assert set(audit[-1][2]) == {"target", "error"}  # no "from": it could not be read


# --------------------------------------------------------------------------- assets (R3, D-032)

ASSET_MAP = b"""defaults: {site.organization: Example}
networks:
  - name: Lab
    range: 192.0.2.0/24
    fields: {site.zone: z1}
  - name: Printer
    range: 192.0.2.7
"""


def test_assets_import(
    cli_env: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    destination = tmp_path / "assets" / "map.yaml"  # never the real data/assets map
    monkeypatch.setenv("ARGUS_ASSETS__MAP_PATH", str(destination))
    for command in (("db", "bootstrap"), ("db", "upgrade")):
        assert _invoke(*command, "-c", str(cli_env))[0] == 0

    code, out = _invoke("assets", "status", "-c", str(cli_env))
    assert (code, "no asset map imported" in out) == (1, True)

    source = tmp_path / "in.yaml"
    source.write_bytes(ASSET_MAP)
    code, out = _invoke("assets", "import", str(source), "-c", str(cli_env))
    first = hashlib.sha256(ASSET_MAP).hexdigest()
    assert code == 0, out
    assert f"2 entries, 2 networks (0 listed more than once), sha256 {first}" in out
    assert destination.read_bytes() == ASSET_MAP
    assert destination.stat().st_mode & 0o777 == 0o600
    _, audit = _state(db_settings, test_database)
    action, outcome, details = audit[-1]
    assert (action, outcome) == ("assets.import", "success")
    assert details == {
        "sha256": first, "entries": 2, "networks": 2, "duplicate_networks": 0,
        "previous_sha256": None,
    }  # fmt: skip
    assert _invoke("assets", "status", "-c", str(cli_env)) == (
        0,
        f"asset map: {out.split(': ', 1)[1]}",
    )

    # Invalid: refused before anything is written or audited; the message has no values.
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"networks:\n  - {name: Secretname7, range: 10.0.0.300/24}\n")
    result = _run("assets", "import", str(bad), "-c", str(cli_env))
    line = _error_line(result)
    assert result.exit_code == 1
    assert "entry #1" in line
    assert "Secretname7" not in line
    assert "10.0.0.300" not in line
    assert _invoke("assets", "import", str(tmp_path / "missing.yaml"), "-c", str(cli_env))[0] == 2
    assert destination.read_bytes() == ASSET_MAP
    assert len(_state(db_settings, test_database)[1]) == len(audit)

    # Re-import a changed map: the audit row names the previous one.
    changed = ASSET_MAP + b"  - {name: Lab, range: 192.0.2.0/24}\n"
    source.write_bytes(changed)
    code, out = _invoke("assets", "import", str(source), "-c", str(cli_env))
    assert code == 0
    assert "(1 listed more than once)" in out
    details = _state(db_settings, test_database)[1][-1][2]
    assert details["previous_sha256"] == first
    assert sorted(p.name for p in destination.parent.iterdir()) == ["map.yaml"]

    # The database is down: nothing is installed and no staged file is left behind.
    monkeypatch.setenv("ARGUS_DATABASE__PORT", "1")
    source.write_bytes(ASSET_MAP)
    result = _run("assets", "import", str(source), "-c", str(cli_env))
    assert result.exit_code == 1
    assert "cannot connect" in _error_line(result)
    assert destination.read_bytes() == changed
    assert sorted(p.name for p in destination.parent.iterdir()) == ["map.yaml"]
    monkeypatch.delenv("ARGUS_DATABASE__PORT")

    # doctor: a map readable by others fails.
    destination.chmod(0o644)
    code, out = _invoke("doctor", "-c", str(cli_env))
    assert code == 1
    assert "FAIL  assets" in out
    assert "chmod 600" in out
    destination.chmod(0o600)
    code, out = _invoke("doctor", "-c", str(cli_env))
    assert code == 0
    assert "PASS  assets" in out
    assert "2 networks" in out
