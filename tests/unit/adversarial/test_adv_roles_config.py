"""Adversarial: D-029's role settings and bootstrap checks, where no database is needed.

Attacks DatabaseSettings (owner_user and owner_password, ``url(role=...)``, the rule that the
runtime login is not the owner), ``roles.check_bootstrap_settings``, the CLI's handling of
passwords that libpq cannot use, and whether docker-compose.yml and .env.example agree with the
settings. The database side is in tests/integration/adversarial/test_adv_bootstrap.py.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every secret here is synthetic, and the
database port is a closed one: nothing here reaches a server.
"""

from __future__ import annotations

import base64
import re
import socket
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st
from psycopg import sql
from pydantic import SecretStr
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, DatabaseSettings, load_settings
from argus.db import roles
from argus.db.engine import create_engine
from argus.observability.redaction import redact_text
from tests.conftest import REPO_ROOT

RUNTIME_SECRET = "fake-runtime-pw-7c1d0e"
OWNER_SECRET = "fake-owner-pw-9e2f4a"
# What Python makes of a password variable holding a byte that is not UTF-8 (surrogateescape).
UNDECODABLE = "fake-pw-" + b"\xff".decode("utf-8", "surrogateescape") + "-rest"
runner = CliRunner()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _config_error(load: Callable[[], object]) -> ConfigError:
    """The ConfigError ``load`` raises; fail if it succeeds or raises anything else (naming only
    the exception's type: its text could hold a value)."""
    escaped: str | None = None
    try:
        load()
    except ConfigError as exc:
        return exc
    except Exception as exc:
        escaped = f"{type(exc).__module__}.{type(exc).__name__}"
    if escaped is not None:  # outside the except clause: the exception is not chained
        pytest.fail(f"expected ConfigError, but {escaped} escaped", pytrace=False)
    pytest.fail("expected ConfigError, but it was accepted", pytrace=False)


def _offline_config(path: Path) -> Path:
    path.write_text(
        "database:\n"
        "  host: 127.0.0.1\n"
        f"  port: {_closed_port()}\n"
        "  name: argus_unit_never_created\n"
        "  connect_timeout: 1s\n"
        "logging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    return path


# =========================================================================== DEFECTS: passwords


@pytest.mark.parametrize(
    ("field", "source"),
    [
        pytest.param("password", "yaml", id="runtime-password-in-yaml"),
        pytest.param("owner_password", "yaml", id="owner-password-in-yaml"),
        pytest.param("password", "dotenv", id="runtime-password-in-dotenv"),
        pytest.param("owner_password", "dotenv", id="owner-password-in-dotenv"),
    ],
)
def test_a_password_with_a_nul_character_is_refused_before_any_connection(
    tmp_path: Path, field: str, source: str
) -> None:
    """DEFECT: libpq takes passwords as C strings, but the settings accept a NUL in either
    password (a YAML "\\0" escape, or a raw NUL byte in .env). Then:
    * bootstrap hashes only the part before the NUL and reports success, so the runtime login's
      password becomes that prefix (from a leading NUL: no password at all, PostgreSQL clears it);
      see test_adv_bootstrap.py;
    * a connection with it loses every connection parameter psycopg writes after the password:
      libpq goes to the default port 5432 instead of the configured one, without
      connect_timeout and without the session options (statement and lock timeouts,
      TimeZone=UTC), so ARGUS may log in to some other server on that host.
    The settings, or at the latest ``url()`` and check_bootstrap_settings, should refuse such a
    password with a ConfigError that names the setting and not the value."""
    prefix, rest = "short", "fake-rest-of-the-password"
    other = "owner_password" if field == "password" else "password"
    text = f"database:\n  {other}: fake-other-pw-123456\n"
    env_file = None
    if source == "yaml":
        text += f'  {field}: "{prefix}\\0{rest}"\n'
    else:
        env_file = tmp_path / "nul.env"
        line = f"ARGUS_DATABASE__{field.upper()}={prefix}\0{rest}\n"
        env_file.write_bytes(line.encode())
    config = tmp_path / "argus.yaml"
    config.write_text(text, encoding="utf-8")
    role = "owner" if field == "owner_password" else "app"

    def prepare_a_connection() -> None:
        database = load_settings(config, env_file=env_file).database
        database.url(role=role)  # where every connection as that role starts
        if role == "app":
            roles.check_bootstrap_settings(database)

    error = _config_error(prepare_a_connection)
    assert rest not in str(error)


@pytest.mark.parametrize(
    ("variable", "command"),
    [
        pytest.param("ARGUS_DATABASE__OWNER_PASSWORD", ["db", "current"], id="db-current"),
        pytest.param("ARGUS_DATABASE__OWNER_PASSWORD", ["db", "upgrade"], id="db-upgrade"),
        pytest.param("ARGUS_DATABASE__OWNER_PASSWORD", ["db", "bootstrap"], id="db-bootstrap"),
        pytest.param("ARGUS_DATABASE__PASSWORD", ["doctor"], id="doctor"),
    ],
)
def test_a_password_that_is_not_utf8_is_a_one_line_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable: str, command: list[str]
) -> None:
    """DEFECT: on POSIX an environment variable may hold bytes that are not UTF-8; Python turns
    them into lone surrogates and the settings accept them as a password. Every command that logs
    in with it then fails while building the connection string, before any network I/O: the
    `argus db` commands with an uncaught UnicodeEncodeError (a traceback, exit code 1), doctor
    with "check crashed: 'utf-8' codec can't encode character '\\udcff' ...". A password libpq
    cannot take is bad configuration: exit code 2 and an error naming the setting."""
    config = _offline_config(tmp_path / "argus.yaml")
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", RUNTIME_SECRET)
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", OWNER_SECRET)
    monkeypatch.setenv(variable, UNDECODABLE)
    result = runner.invoke(app, [*command, "-c", str(config)])
    escaped = result.exception
    if escaped is not None and not isinstance(escaped, SystemExit):
        pytest.fail(f"{type(escaped).__name__} escaped the CLI: a traceback", pytrace=False)
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith("error:"), result.stderr
    assert "Traceback" not in result.output


# =========================================================================== DEFECTS: names


@pytest.mark.parametrize("user", ["argus_runtime", "pg_argus", "public", "none"])
def test_bootstrap_refuses_a_login_name_postgresql_reserves_or_that_names_the_group(
    write_config: Callable[..., Path], user: str
) -> None:
    """DEFECT: check_bootstrap_settings only checks that database.user is a plain lowercase
    identifier, so it accepts (and so do the settings):
    * the group role's own name: bootstrap then runs ALTER ROLE argus_runtime WITH LOGIN ...
      PASSWORD ..., and is saved only because granting the group to itself fails afterwards
      ('role "argus_runtime" is a member of role "argus_runtime"'), and doctor would log in as
      the group;
    * names PostgreSQL reserves (pg_*, public, none): the server refuses them, so a bad config
      gives exit code 1 instead of the documented 2, after logging in as the owner, with the
      refused CREATE ROLE (verifier included) in the exception text.
    Bootstrap should refuse them before connecting."""
    config = write_config(f"database:\n  user: {user}\n  password: {RUNTIME_SECRET}\n")

    def bootstrap_settings() -> None:
        roles.check_bootstrap_settings(load_settings(config, env_file=None).database)

    error = _config_error(bootstrap_settings)
    assert RUNTIME_SECRET not in str(error)


def test_bootstrap_refuses_settings_whose_login_is_the_owner() -> None:
    """DEFECT: the settings refuse user == owner_user, but only when they are validated:
    ``model_copy(update=...)``, which the test harness uses to make logins, skips validation, and
    check_bootstrap_settings does not repeat the rule. ensure_roles would then run, as the owner,
    ``ALTER ROLE <owner> WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE ... PASSWORD <runtime
    verifier>``. PostgreSQL refuses that only for the bootstrap superuser (OID 10, the local
    Docker one) and for a CREATEROLE owner; an owner that is any other superuser demotes itself
    and takes the runtime password. Bootstrap should refuse it as bad configuration."""
    database = DatabaseSettings(
        password=SecretStr(RUNTIME_SECRET), owner_password=SecretStr(OWNER_SECRET)
    )
    same = database.model_copy(update={"user": database.owner_user})
    error = _config_error(lambda: roles.check_bootstrap_settings(same))
    assert RUNTIME_SECRET not in str(error)
    assert OWNER_SECRET not in str(error)


# =========================================================================== LOCK-INS: settings


@pytest.mark.parametrize(
    "where",
    ["yaml", "environment", "dotenv", "environment-and-yaml", "default-owner-from-environment"],
)
def test_the_login_may_not_be_the_owner_whichever_source_sets_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """LOCK-IN: user == owner_user is refused however the two names are set (each source, two
    sources together, or the default owner "argus" named as the login), and the error names both
    settings without any password, wherever the passwords came from."""
    name = "fake_same_role"
    config, env_file = tmp_path / "argus.yaml", tmp_path / "roles.env"
    text = "database:\n"
    env_lines = f"ARGUS_DATABASE__PASSWORD={RUNTIME_SECRET}\n"
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", OWNER_SECRET)
    if where == "yaml":
        text += f"  user: {name}\n  owner_user: {name}\n"
    elif where == "environment":
        monkeypatch.setenv("ARGUS_DATABASE__USER", name)
        monkeypatch.setenv("ARGUS_DATABASE__OWNER_USER", name)
    elif where == "dotenv":
        env_lines += f"ARGUS_DATABASE__USER={name}\nARGUS_DATABASE__OWNER_USER={name}\n"
    elif where == "environment-and-yaml":
        monkeypatch.setenv("ARGUS_DATABASE__USER", name)
        text += f"  owner_user: {name}\n"
    else:
        monkeypatch.setenv("ARGUS_DATABASE__USER", DatabaseSettings().owner_user)
    config.write_text(text + "  pool_size: 2\n", encoding="utf-8")
    env_file.write_text(env_lines, encoding="utf-8")
    error = _config_error(lambda: load_settings(config, env_file=env_file))
    assert "user and owner_user must be different roles" in str(error)
    assert RUNTIME_SECRET not in str(error)
    assert OWNER_SECRET not in str(error)


def test_only_role_owner_logs_in_as_the_owner() -> None:
    """LOCK-IN: ``url()`` and ``create_engine()`` log in as the owner only for ``role="owner"``
    exactly; any other value (a typo, another case, a blank) falls back to the runtime login,
    never the reverse. Neither password shows in the URLs or the engines."""
    database = DatabaseSettings(
        user="fake_runtime",
        password=SecretStr(RUNTIME_SECRET),
        owner_user="fake_owner",
        owner_password=SecretStr(OWNER_SECRET),
    )
    for role in ("app", "Owner", "OWNER", "owner ", " owner", "admin", "superuser", ""):
        url = database.url(role=role)  # type: ignore[arg-type]
        assert (url.username, url.password) == ("fake_runtime", RUNTIME_SECRET), role
    owner = database.url(role="owner")
    assert (owner.username, owner.password) == ("fake_owner", OWNER_SECRET)
    app_engine = create_engine(database)
    owner_engine = create_engine(database, role="owner")
    assert app_engine.url.username == "fake_runtime"
    assert owner_engine.url.username == "fake_owner"
    renderings = [str(owner), repr(owner), repr(database)]
    for engine in (app_engine, owner_engine):
        renderings += [str(engine.url), repr(engine.url), repr(engine.sync_engine)]
    shown = [secret for secret in (RUNTIME_SECRET, OWNER_SECRET) for r in renderings if secret in r]
    assert shown == []


@pytest.mark.parametrize(
    ("value", "forms"),
    [
        pytest.param("987654321", ["987654321"], id="integer"),
        pytest.param("01234567", ["01234567", "342391"], id="yaml-1.1-octal"),
        pytest.param("1.5e+30", ["1.5e+30", "1.5e30"], id="float"),
        pytest.param("yes", ["yes", "True"], id="boolean"),
        pytest.param("2026-10-10", ["2026-10-10"], id="date"),
        pytest.param("[fake-listed-pw-1]", ["fake-listed-pw-1"], id="list"),
        pytest.param("{nested: fake-nested-pw-2}", ["fake-nested-pw-2"], id="mapping"),
    ],
)
@pytest.mark.parametrize("field", ["password", "owner_password"])
def test_a_password_yaml_reads_as_another_type_is_an_error_that_shows_no_value(
    write_config: Callable[..., Path], field: str, value: str, forms: list[str]
) -> None:
    """LOCK-IN: an unquoted password that YAML reads as a number, a boolean, a date, a list or a
    mapping is an error naming the setting and its line, with neither the text as written nor
    the value YAML made of it."""
    error = _config_error(
        lambda: load_settings(write_config(f"database:\n  {field}: {value}\n"), env_file=None)
    )
    assert f"database.{field}" in str(error)
    assert [form for form in forms if form in str(error)] == []


def test_docker_compose_and_env_example_agree_with_the_settings(tmp_path: Path) -> None:
    """LOCK-IN: docker compose and ARGUS read the same .env. The server's superuser, its database
    and its port default to the owner, database and port the settings default to; the
    superuser's password is the owner password and is required; the port is bound to loopback
    only; the runtime login's variables never configure the server (so the login ARGUS runs as
    cannot become its superuser). .env.example loads, names different roles for the login and the
    owner, and is enough for bootstrap."""
    defaults = DatabaseSettings()
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["db"]
    environment = service["environment"]
    assert environment["POSTGRES_USER"] == f"${{ARGUS_DATABASE__OWNER_USER:-{defaults.owner_user}}}"
    assert environment["POSTGRES_DB"] == f"${{ARGUS_DATABASE__NAME:-{defaults.name}}}"
    assert environment["POSTGRES_PASSWORD"].startswith("${ARGUS_DATABASE__OWNER_PASSWORD:?")
    assert service["ports"] == [f"127.0.0.1:${{ARGUS_DATABASE__PORT:-{defaults.port}}}:5432"]
    runtime_variable = re.compile(r"\$\{?ARGUS_DATABASE__(USER|PASSWORD)\b")
    assert [value for value in environment.values() if runtime_variable.search(str(value))] == []

    config = tmp_path / "argus.yaml"
    config.write_text("environment: dev\n", encoding="utf-8")
    database = load_settings(config, env_file=REPO_ROOT / ".env.example").database
    assert database.user != database.owner_user
    assert (database.owner_user, database.name, database.port) == (
        defaults.owner_user,
        defaults.name,
        defaults.port,
    )
    assert database.host in ("127.0.0.1", "localhost", "::1")
    assert database.password is not None
    assert database.owner_password is not None
    roles.check_bootstrap_settings(database)


@pytest.mark.parametrize("name", ["a", "_", "argus_app", "a" * 63, "_" + "9" * 62])
def test_bootstrap_accepts_plain_names_up_to_63_bytes(name: str) -> None:
    """LOCK-IN: the longest name PostgreSQL keeps whole, 63 bytes, is accepted, as are the
    shortest ones; test_roles.py covers the refusals (64 bytes, capitals, '-', a space)."""
    base = DatabaseSettings(password=SecretStr(RUNTIME_SECRET))
    roles.check_bootstrap_settings(base.model_copy(update={"user": name}))


@given(
    name=st.one_of(
        st.from_regex(r"[a-z_][a-z0-9_]{0,70}", fullmatch=True),
        st.from_regex(r"[ -~]{0,70}", fullmatch=True),
        st.text(max_size=70),
    )
)
def test_bootstrap_accepts_only_names_postgresql_keeps_as_written(name: str) -> None:
    """LOCK-IN: a name check_bootstrap_settings accepts is 1 to 63 bytes of lowercase ASCII
    letters, digits and _, not starting with a digit: PostgreSQL neither truncates it nor folds
    its case, and psycopg quotes it without escaping anything, so the role created is the role
    ARGUS logs in as."""
    base = DatabaseSettings(password=SecretStr(RUNTIME_SECRET))
    try:
        roles.check_bootstrap_settings(base.model_copy(update={"user": name}))
    except ConfigError:
        return
    assert re.fullmatch(r"[a-z_][a-z0-9_]*", name)
    assert 1 <= len(name.encode()) <= 63
    assert sql.Identifier(name).as_string() == f'"{name}"'


_VERIFIER_CONTEXTS = [
    "{v}",
    "ALTER ROLE \"argus_app\" WITH LOGIN NOSUPERUSER INHERIT PASSWORD '{v}'",
    "(psycopg.errors.LockNotAvailable) canceling statement due to lock timeout\n"
    "[SQL: ALTER ROLE \"argus_app\" WITH LOGIN PASSWORD '{v}']",
    '{{"event": "CREATE ROLE \\"argus_app\\" WITH LOGIN PASSWORD \'{v}\'", "level": "info"}}',
    "Composed([SQL('LOGIN PASSWORD '), Literal('{v}')])",
    "rolpassword={v};",
]


@given(
    iterations=st.integers(min_value=1, max_value=10**7),
    salt=st.binary(min_size=16, max_size=16),
    keys=st.binary(min_size=64, max_size=64),
    context=st.sampled_from(_VERIFIER_CONTEXTS),
)
def test_scram_verifiers_of_any_salt_and_keys_are_masked(
    iterations: int, salt: bytes, keys: bytes, context: str
) -> None:
    """LOCK-IN: a SCRAM-SHA-256 verifier as libpq writes it (``iterations:salt$StoredKey:
    ServerKey``, base64 with '+', '/' and '=') is masked whatever its bytes, in the places
    bootstrap's verifier can turn up: the role statement, SQLAlchemy's error text, a JSON log
    line, psycopg's repr of the composed statement."""
    encoded = [base64.b64encode(part).decode() for part in (salt, keys[:32], keys[32:])]
    verifier = f"SCRAM-SHA-256${iterations}:{encoded[0]}${encoded[1]}:{encoded[2]}"
    masked = redact_text(context.format(v=verifier))
    assert [part for part in encoded if part in masked] == []
