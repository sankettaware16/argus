"""CLI behaviour that needs no database (unreachable DB is simulated with a closed port)."""

from __future__ import annotations

import contextlib
import socket
from collections.abc import AsyncIterator
from pathlib import Path

import psycopg
import pytest
from alembic.util import CommandError
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from argus import __version__, cli, doctor
from argus.cli import app
from argus.db import errors, migrate
from argus.observability.redaction import MASK, clear_registered_secrets, register_secret

SECRET = "cli-secret-7c6b5a"
OWNER_SECRET = "cli-owner-secret-9d8e7f"
DOTENV = f"ARGUS_DATABASE__PASSWORD={SECRET}\nARGUS_DATABASE__OWNER_PASSWORD={OWNER_SECRET}\n"
runner = CliRunner()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "argus.yaml"
    path.write_text(
        "history:\n  window: 4d\n"
        f"database:\n  port: {_closed_port()}\n  connect_timeout: 2s\n"
        "logging:\n  level: WARNING\n"
    )
    (tmp_path / ".env").write_text(DOTENV)
    return path


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "config" in result.output
    assert "doctor" in result.output


def test_config_show_masks_secrets(config_file: Path) -> None:
    result = runner.invoke(app, ["config", "show", "--config", str(config_file)])
    assert result.exit_code == 0, result.output
    assert "window: 4d" in result.output
    assert SECRET not in result.output
    assert "'**********'" in result.output


def test_config_validate_ok(config_file: Path) -> None:
    result = runner.invoke(app, ["config", "validate", "-c", str(config_file)])
    assert result.exit_code == 0
    assert "history.window=4d" in result.output


def test_config_validate_reports_typos_with_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("histroy:\n  window: 5d\n")
    result = runner.invoke(app, ["config", "validate", "-c", str(bad)])
    assert result.exit_code == 2
    assert "histroy" in result.stderr
    assert "unknown setting" in result.stderr


def test_missing_config_file_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["config", "show", "-c", str(tmp_path / "absent.yaml")])
    assert result.exit_code == 2
    assert "not found" in result.stderr


def test_downgrade_requires_confirmation(config_file: Path) -> None:
    result = runner.invoke(app, ["db", "downgrade", "base", "-c", str(config_file)])
    assert result.exit_code == 2
    assert "--yes" in result.stderr


def test_doctor_reports_unreachable_database(config_file: Path) -> None:
    result = runner.invoke(app, ["doctor", "-c", str(config_file)])
    assert result.exit_code == 1
    assert "PASS  config" in result.output
    assert "FAIL  database" in result.output
    assert SECRET not in result.output + result.stderr
    assert OWNER_SECRET not in result.output + result.stderr


@pytest.mark.parametrize("command", [["db", "current"], ["db", "upgrade"], ["db", "check"]])
def test_db_commands_fail_cleanly_without_database(config_file: Path, command: list[str]) -> None:
    result = runner.invoke(app, [*command, "-c", str(config_file)])
    assert result.exit_code == 1
    assert "Traceback" not in result.output + result.stderr
    assert SECRET not in result.output + result.stderr
    assert OWNER_SECRET not in result.output + result.stderr


def test_doctor_without_password(tmp_path: Path) -> None:
    path = tmp_path / "argus.yaml"
    path.write_text("logging:\n  level: WARNING\n")
    result = runner.invoke(app, ["doctor", "-c", str(path)])
    assert result.exit_code == 1
    assert "password is not set" in result.output


# --------------------------------------------------------------------------- revision targets


@pytest.fixture
def unreachable_config(tmp_path: Path) -> Path:
    """A closed port and a database name that is not the developer's own (the test harness
    refuses connections to that one before they reach the port)."""
    path = tmp_path / "unreachable.yaml"
    path.write_text(
        f"database:\n  name: argus_unit_unreachable\n  port: {_closed_port()}\n"
        "  connect_timeout: 2s\nlogging:\n  level: WARNING\n"
    )
    (tmp_path / ".env").write_text(DOTENV)
    return path


_CHAIN = migrate.revision_chain()
_OFF_CHAIN = [
    "head+1",
    "heads+1",
    f"head-{len(_CHAIN) + 1}",  # one past base, whatever the chain's length
    f"{_CHAIN[-1]}+1",
    f"{_CHAIN[0]}+{len(_CHAIN)}",
    f"base+{len(_CHAIN) + 1}",
    "base-1",
    "+0",
    f"+{len(_CHAIN) + 1}",
    "head+1abc",
    "head+\u0661",
    # On the chain if any Unicode digit counted (as \d does): only ASCII digits do.
    "head-\u0661",
    "+\u0661",
    f"{_CHAIN[0]}@head",
]


@pytest.mark.parametrize("revision", _OFF_CHAIN)
def test_db_upgrade_to_a_step_off_the_chain_is_an_unknown_revision(
    unreachable_config: Path, revision: str
) -> None:
    """Checked before connecting (the configured port is closed): exit 2, one line, no
    traceback. Alembic itself fails on e.g. head+1 with a bare AssertionError."""
    result = runner.invoke(app, ["db", "upgrade", "-c", str(unreachable_config), "--", revision])
    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    assert lines[0].startswith("error: unknown revision")
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "revision",
    [f"head-{len(_CHAIN) + 1}", "base-1", f"-{len(_CHAIN) + 1}", "-0", "head-\u0661", "-\u0661"],
)
def test_db_downgrade_to_a_step_off_the_chain_is_an_unknown_revision(
    unreachable_config: Path, revision: str
) -> None:
    result = runner.invoke(
        app, ["db", "downgrade", "--yes", "-c", str(unreachable_config), "--", revision]
    )
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith("error: unknown revision")


@pytest.mark.parametrize("revision", ["+1", "head-1", f"{_CHAIN[0]}+1", f"head-{len(_CHAIN)}"])
def test_steps_on_the_chain_get_past_the_revision_check(
    unreachable_config: Path, revision: str
) -> None:
    """Accepted targets go on to the database, which is unreachable here: exit 1, not 2."""
    result = runner.invoke(app, ["db", "upgrade", "-c", str(unreachable_config), "--", revision])
    assert result.exit_code == 1, result.output
    assert result.stderr.startswith("error: cannot connect")


def _db(direction: str, config: Path, revision: str) -> list[str]:
    """``argus db <direction> REVISION`` (confirmed, for a downgrade)."""
    options = ["--yes"] if direction == "downgrade" else []
    return ["db", direction, *options, "-c", str(config), "--", revision]


@pytest.mark.parametrize(
    ("direction", "revision"),
    [
        ("upgrade", "-1"),
        ("upgrade", f"-{len(_CHAIN)}"),
        ("downgrade", "+1"),
        ("downgrade", f"+{len(_CHAIN)}"),
    ],
)
def test_a_step_from_the_database_the_other_way_is_an_unknown_revision(
    unreachable_config: Path, direction: str, revision: str
) -> None:
    """Alembic refuses ``upgrade -N`` and ``downgrade +N`` whatever the database's revision, so
    they are usage errors too, found before connecting (the port is closed): exit 2, one line."""
    result = runner.invoke(app, _db(direction, unreachable_config, revision))
    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    sign = "+" if direction == "upgrade" else "-"
    assert result.stderr.splitlines() == [
        f"error: unknown revision {revision!r}: {direction} takes only {sign}N steps from the "
        "database's revision"
    ]


@pytest.mark.parametrize(
    ("direction", "revision"),
    [
        ("upgrade", "+1"),
        ("upgrade", f"+{len(_CHAIN)}"),
        ("downgrade", "-1"),
        ("downgrade", f"-{len(_CHAIN)}"),
    ],
)
def test_a_step_from_the_database_the_commands_way_gets_past_the_revision_check(
    unreachable_config: Path, direction: str, revision: str
) -> None:
    result = runner.invoke(app, _db(direction, unreachable_config, revision))
    assert result.exit_code == 1, result.output
    assert result.stderr.startswith("error: cannot connect")


def test_unknown_revision_message_masks_a_registered_secret(unreachable_config: Path) -> None:
    """The target is echoed back, but through redaction (someone may paste a secret there)."""
    result = runner.invoke(app, ["db", "upgrade", "-c", str(unreachable_config), "--", SECRET])
    assert result.exit_code == 2
    assert SECRET not in result.output
    assert MASK in result.stderr


# --------------------------------------------------------------------------- db error lines


def test_db_error_helpers_are_public_and_shared() -> None:
    """One implementation, in argus.db.errors, used by both the CLI and doctor."""
    assert vars(cli)["short_db_error"] is errors.short_db_error
    assert vars(doctor)["short_db_error"] is errors.short_db_error
    assert vars(cli)["is_connection_failure"] is errors.is_connection_failure
    assert "_short_db_error" not in vars(doctor)
    assert "_is_connection_failure" not in vars(doctor)


def _driver_error(message: str, sqlstate: str | None) -> psycopg.OperationalError:
    exc = psycopg.OperationalError(message)
    if sqlstate is not None:
        exc.sqlstate = sqlstate
    return exc


@pytest.mark.parametrize(
    ("exc", "connection_failure"),
    [
        (ConnectionRefusedError(111, "Connection refused"), True),
        (TimeoutError("timed out"), True),
        (socket.gaierror(-2, "Name or service not known"), True),
        (PermissionError(13, "Permission denied"), False),
        (OperationalError(None, None, _driver_error("connection failed", None)), True),
        (OperationalError("SELECT 1", {}, _driver_error("lock timeout", "55P03")), False),
        (OperationalError("SELECT 1", {}, _driver_error("server closed", None)), False),
        (CommandError("Can't locate revision identified by 'x'"), False),
    ],
    ids=[
        "refused",
        "timeout",
        "dns",
        "local-permission",
        "connect-time-driver-error",
        "lock-timeout-after-connecting",
        "error-during-a-statement",
        "migration-command",
    ],
)
def test_only_failures_to_connect_are_reported_as_connection_failures(
    exc: BaseException, connection_failure: bool
) -> None:
    assert errors.is_connection_failure(exc) is connection_failure
    line = errors.short_db_error(exc, "upgrade")
    assert line.startswith("cannot connect: " if connection_failure else "upgrade failed: ")
    assert "\n" not in line


def test_short_db_error_is_one_redacted_line() -> None:
    register_secret(SECRET)
    try:
        line = errors.short_db_error(CommandError(f"bad target {SECRET}\nsecond line"))
    finally:
        clear_registered_secrets()
    assert line == f"database error: bad target {MASK}"


# --------------------------------------------------------------------------- roles (D-029)


def _env_config(tmp_path: Path, dotenv: str, user: str = "argus_app") -> Path:
    path = tmp_path / "roles.yaml"
    path.write_text(
        f"database:\n  name: argus_unit_unreachable\n  port: {_closed_port()}\n"
        f"  user: {user}\n  connect_timeout: 2s\nlogging:\n  level: WARNING\n"
    )
    (tmp_path / ".env").write_text(dotenv)
    return path


@pytest.mark.parametrize(
    "command", [["db", "current"], ["db", "check"], ["db", "upgrade"], ["db", "bootstrap"]]
)
def test_db_commands_log_in_as_the_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    """With only the runtime password set, `argus db` stops before connecting: it needs the
    owner's."""
    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, f"ARGUS_DATABASE__PASSWORD={SECRET}\n")
    result = runner.invoke(app, [*command, "-c", str(config)])
    assert result.exit_code == 2, result.output
    assert "ARGUS_DATABASE__OWNER_PASSWORD" in result.stderr
    assert SECRET not in result.output + result.stderr


def test_doctor_logs_in_as_the_runtime_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, f"ARGUS_DATABASE__OWNER_PASSWORD={OWNER_SECRET}\n")
    result = runner.invoke(app, ["doctor", "-c", str(config)])
    assert result.exit_code == 1
    assert "FAIL  database" in result.output
    assert "put ARGUS_DATABASE__PASSWORD in .env" in result.output
    assert OWNER_SECRET not in result.output + result.stderr


def test_bootstrap_needs_the_runtime_password_it_sets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, f"ARGUS_DATABASE__OWNER_PASSWORD={OWNER_SECRET}\n")
    result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)])
    assert result.exit_code == 2
    assert result.stderr.startswith("error: database password is not set")


@pytest.mark.parametrize("user", ["Argus_App", "argus-app", "1app"])
def test_bootstrap_refuses_a_role_name_it_would_have_to_quote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, user: str
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, DOTENV, user=user)
    result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)])
    assert result.exit_code == 2
    assert "lowercase letters, digits and _" in result.stderr


def test_bootstrap_against_an_unreachable_server_is_an_operational_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, DOTENV)
    result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)])
    assert result.exit_code == 1, result.output
    assert result.stderr.startswith("error: cannot connect")
    assert SECRET not in result.output + result.stderr
    assert OWNER_SECRET not in result.output + result.stderr


def test_bootstrap_that_cannot_repair_fails_in_one_escaped_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A BootstrapError (an attribute or setting this owner may not remove, CONNECT it may not
    grant) or an AuditError ends the command with exit 1 and one line, control characters
    escaped, no traceback."""
    from argus.db import roles as roles_module
    from argus.db.audit import AuditError

    class _Engine:
        @contextlib.asynccontextmanager
        async def begin(self) -> AsyncIterator[object]:
            yield object()

        async def dispose(self) -> None:
            return None

    monkeypatch.chdir(tmp_path)
    config = _env_config(tmp_path, DOTENV)
    monkeypatch.setattr(cli, "create_engine", lambda *args, **kwargs: _Engine())
    for error in (
        roles_module.BootstrapError("argus_app has SUPERUSER\rroles ready: fine\x1b[2K"),
        AuditError("audit details exceed 65536 bytes"),
    ):

        async def failing(*args: object, error: Exception = error, **kwargs: object) -> list[str]:
            raise error

        monkeypatch.setattr(roles_module, "ensure_roles", failing)
        result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)])
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert result.exit_code == 1
        assert result.stdout == ""
        lines = result.stderr.splitlines()
        assert len(lines) == 1, lines
        assert lines[0].startswith("error: ")
        assert "\r" not in result.stderr
        assert "\x1b" not in result.stderr
