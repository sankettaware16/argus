"""Adversarial re-attack of D-029's bootstrap rewrite, where no database is needed.

Attacks ``roles.check_bootstrap_settings`` (reserved names, the owner's and the group's name),
``settings.usable_password`` behind ``DatabaseSettings.url()`` and bootstrap (passwords that skip
validation through ``model_copy``), the remedy ``roles.grant_connect`` prints, and what ``argus db
bootstrap`` prints for its repairs. The database side is in
tests/integration/adversarial/test_adv_bootstrap_reattack.py.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every secret here is synthetic, and the
database port is a closed one: nothing here reaches a server.
"""

from __future__ import annotations

import contextlib
import io
import socket
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from hypothesis import example, given
from hypothesis import strategies as st
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncConnection
from typer.testing import CliRunner

import argus.cli as cli
from argus.cli import app
from argus.config import ConfigError, DatabaseSettings
from argus.db import roles
from argus.db.engine import create_engine
from argus.observability.logs import configure_logging

RUNTIME_SECRET = "fake-runtime-pw-3b9e51"
OWNER_SECRET = "fake-owner-pw-8d02c7"
runner = CliRunner()

# What the settings and bootstrap say about a password they refuse: fixed text, never the value.
_REFUSALS = {
    "app": {
        "database password is not set; put ARGUS_DATABASE__PASSWORD in .env",
        "database.password must not contain a NUL character (libpq would cut the password there)",
        "database.password must be valid UTF-8 text",
    },
    "owner": {
        "database owner password is not set; put ARGUS_DATABASE__OWNER_PASSWORD in .env (only"
        " the `argus db` commands need it)",
        "database.owner_password must not contain a NUL character (libpq would cut the password"
        " there)",
        "database.owner_password must be valid UTF-8 text",
    },
    "bootstrap": {
        "database password is not set; put ARGUS_DATABASE__PASSWORD in .env (bootstrap sets it on"
        " the runtime role)",
        "database.password must not contain a NUL character (libpq would cut the password there)",
        "database.password must be valid UTF-8 text",
    },
}


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _settings(**update: Any) -> DatabaseSettings:
    base = DatabaseSettings(
        password=SecretStr(RUNTIME_SECRET), owner_password=SecretStr(OWNER_SECRET)
    )
    return base.model_copy(update=update)  # skips validation, as the test harness's copies do


def _libpq_takes(password: str) -> bool:
    if not password or "\x00" in password:
        return False
    try:
        password.encode()
    except UnicodeEncodeError:
        return False
    return True


# =========================================================================== names


@pytest.mark.parametrize(
    "user",
    [
        "argus",  # the default owner
        "argus_runtime",
        "pg_",
        "pg_monitor",
        "pg_argus",
        "public",
        "none",
        "current_user",
        "current_role",
        "session_user",
    ],
)
def test_bootstrap_refuses_the_owner_the_group_and_names_postgresql_reserves(user: str) -> None:
    """LOCK-IN: the login may not be the owner, the group role, a pg_ name or a name PostgreSQL
    reads as a role specification; the refusal is a ConfigError (exit code 2 in the CLI) that
    names no password."""
    with pytest.raises(ConfigError) as info:
        roles.check_bootstrap_settings(_settings(user=user))
    assert RUNTIME_SECRET not in str(info.value)
    assert OWNER_SECRET not in str(info.value)


@pytest.mark.parametrize(
    "user",
    [
        "public_",
        "nonex",
        "current_users",
        "session_user1",
        "pg",
        "pgx_argus",
        "p_g_argus",
        "argus_runtime_app",
        "argus_",
        "_argus",
    ],
)
def test_bootstrap_accepts_names_that_only_look_like_reserved_ones(user: str) -> None:
    """LOCK-IN: the refusals match whole names (and the pg_ prefix), not pieces of names."""
    roles.check_bootstrap_settings(_settings(user=user))


def test_the_group_and_owner_checks_follow_the_names_in_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: the group's name is read when bootstrap runs (tests point RUNTIME_ROLE at a
    throwaway name), and the owner is whichever owner_user is configured."""
    monkeypatch.setattr(roles, "RUNTIME_ROLE", "argus_test_group_x")
    with pytest.raises(ConfigError, match="may not be argus_test_group_x"):
        roles.check_bootstrap_settings(_settings(user="argus_test_group_x"))
    roles.check_bootstrap_settings(_settings(user="argus_runtime"))
    with pytest.raises(ConfigError, match="must be different roles"):
        roles.check_bootstrap_settings(_settings(user="argus_owner", owner_user="argus_owner"))
    roles.check_bootstrap_settings(_settings(user="argus", owner_user="argus_owner"))


# =========================================================================== passwords

_PASSWORDS = st.text(
    alphabet=st.one_of(
        st.characters(),
        st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF, categories=["Cs"]),
        st.just("\x00"),
    ),
    max_size=24,
)


def _refusal(check: Callable[..., object], *args: Any, **kwargs: Any) -> str | None:
    """The text of the ConfigError ``check`` raises, or None if it accepts."""
    try:
        check(*args, **kwargs)
    except ConfigError as exc:
        return str(exc)
    return None


@given(password=_PASSWORDS)
@example(password="")
@example(password=" ")
@example(password="\x00")
@example(password="fake-before\x00fake-after")
@example(password="fake-pw-\udcff-rest")
@example(password="fake-pw-\ud83d\ude00")  # a surrogate pair, not one character
@example(password="fake-pw-\U0001f600")
def test_bootstrap_and_url_take_exactly_the_passwords_libpq_can(password: str) -> None:
    """LOCK-IN: through settings built with model_copy (which skips the validators), url() for
    either role and check_bootstrap_settings accept a password exactly when libpq can use it
    (not empty, no NUL, valid UTF-8), pass it on unchanged, and refuse anything else with a
    fixed message that holds no part of it."""
    usable = _libpq_takes(password)
    for field, role in (("password", "app"), ("owner_password", "owner")):
        settings = _settings(**{field: SecretStr(password)})
        refusal = _refusal(settings.url, role=role)
        assert (refusal is None) == usable, refusal
        if refusal is None:
            assert settings.url(role=role).password == password  # type: ignore[arg-type]
        else:
            assert refusal in _REFUSALS[role]
    refusal = _refusal(roles.check_bootstrap_settings, _settings(password=SecretStr(password)))
    assert (refusal is None) == usable, refusal
    assert refusal is None or refusal in _REFUSALS["bootstrap"]


def test_url_checks_only_the_password_of_the_role_it_logs_in_as() -> None:
    """LOCK-IN: a broken owner password stops only connections as the owner (and a broken
    runtime password only runtime connections), and create_engine refuses before any engine is
    built."""
    broken_owner = _settings(owner_password=SecretStr("fake\x00rest-of-owner-pw"))
    assert broken_owner.url().password == RUNTIME_SECRET
    with pytest.raises(ConfigError, match=r"database\.owner_password must not contain a NUL"):
        create_engine(broken_owner, role="owner")
    broken_app = _settings(password=SecretStr("fake\udcffrest-of-runtime-pw"))
    assert broken_app.url(role="owner").password == OWNER_SECRET
    with pytest.raises(ConfigError, match=r"database\.password must be valid UTF-8"):
        create_engine(broken_app)


# =========================================================================== grant_connect


class _Answer:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one(self) -> Any:
        return self.value


class _NoConnectRight:
    """An owner connection on which GRANT CONNECT grants nothing (PostgreSQL only warns): just
    what grant_connect uses of it."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.adapters = psycopg.adapters
        self.connection = None  # psycopg quotes without a server connection
        self.driver_connection = self

    async def get_raw_connection(self) -> _NoConnectRight:
        return self

    async def exec_driver_sql(self, statement: str) -> None:
        self.sent.append(statement)

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        query = str(statement)
        if "has_database_privilege" in query:
            return _Answer(False)
        assert "current_user" in query, query  # who the owner is, for a remedy naming it
        return _Answer("argus_owner")


@pytest.mark.parametrize("database", ["Argus", "argus-prod", "argus prod", 'argus"prod'])
async def test_the_connect_remedy_quotes_a_database_name_that_needs_it(database: str) -> None:
    """DEFECT (low): when the owner may not grant CONNECT, grant_connect tells the operator to
    "Ask the database's owner to run GRANT CONNECT ON DATABASE <name> TO argus_runtime", with the
    name written out as it is. The settings accept any database name (capitals, '-', spaces,
    quotes), and for such a name that statement is a syntax error or names another database
    (PostgreSQL folds an unquoted name to lower case). The statement grant_connect itself sends
    is quoted; the one it asks a person to run should be quoted the same way."""
    conn = _NoConnectRight()
    with pytest.raises(roles.BootstrapError) as info:
        await roles.grant_connect(cast(AsyncConnection, conn), database)
    quoted = sql.Identifier(database).as_string()
    assert conn.sent == [f'GRANT CONNECT ON DATABASE {quoted} TO "{roles.RUNTIME_ROLE}"']
    remedy = str(info.value).split("run ", 1)[1]
    assert f"GRANT CONNECT ON DATABASE {quoted} " in remedy, remedy


# =========================================================================== CLI output


class _NoDatabase:
    """Stands in for the owner's engine: a transaction that does nothing."""

    @contextlib.asynccontextmanager
    async def begin(self) -> AsyncIterator[object]:
        yield object()

    async def dispose(self) -> None:
        return None


def test_bootstrap_prints_each_repair_on_one_line_whatever_the_role_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEFECT (low): bootstrap prints each repair as ``repaired: <text>``, and the text holds the
    names of the roles the login was a member of, verbatim. PostgreSQL allows any character but
    NUL in a role name, so whoever can create a role and grant it to the login (a CREATEROLE
    role) can name it "x\\rroles ready: ...\\nrepaired: none\\x1b[2K": a carriage return, a newline
    and terminal escapes that overwrite or forge lines on the operator's console, hiding the
    revocation the console was meant to show (the audit row keeps it, as JSON). Here the
    database side is stubbed; roles.ensure_roles reports such a name the way it reports any.
    Control characters in printed repairs should be escaped."""
    hostile = "argus_team\rroles ready: nothing to repair\nrepaired: none\x1b[2K"

    async def ensure_roles(
        conn: object, settings: DatabaseSettings, *, changes: list[str] | None = None
    ) -> list[str]:
        assert changes is not None
        changes.append(f"{settings.user} was a member of {hostile}: revoked")
        return []

    async def nothing(*args: object, **kwargs: object) -> None:
        return None

    async def no_group(conn: object, *, changes: list[str] | None = None) -> list[str]:
        return []

    async def no_web_roles(*args: object, **kwargs: object) -> list[str]:
        return []  # the web's roles (Q-A2): present already

    monkeypatch.setattr(roles, "ensure_roles", ensure_roles)
    monkeypatch.setattr(roles, "ensure_approvals_role", no_group)  # Q-C1's group role
    monkeypatch.setattr(roles, "ensure_purge_role", no_group)  # Q-A4's group role
    monkeypatch.setattr(roles, "ensure_api_roles", no_web_roles)
    monkeypatch.setattr(roles, "ensure_writer_roles", no_web_roles)  # Q-D4's group role
    monkeypatch.setattr(roles, "grant_connect", nothing)
    monkeypatch.setattr(cli, "_audit", nothing)
    monkeypatch.setattr(cli, "create_engine", lambda *args, **kwargs: _NoDatabase())
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", RUNTIME_SECRET)  # tests/unit/conftest.py
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", OWNER_SECRET)  # cleared the others
    config = tmp_path / "argus.yaml"
    config.write_text(
        f"database:\n  host: 127.0.0.1\n  port: {_closed_port()}\n"
        "  name: argus_unit_never_created\nlogging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    try:
        result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)], color=True)
    finally:  # the CLI pointed logging at the runner's captured stream
        configure_logging("WARNING", "console", stream=io.StringIO())
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert len([line for line in lines if line.startswith("roles ready:")]) == 1, lines
    assert len([line for line in lines if line.startswith("repaired:")]) == 1, lines
    assert not any(character in result.stdout for character in "\r\x1b"), repr(result.stdout)
