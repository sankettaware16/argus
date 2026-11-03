from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import make_url

from argus.config import ConfigError, DatabaseSettings, Settings, load_settings
from argus.config.settings import CONFIG_ENV_VAR, MAX_NAME_BYTES

REPO_ROOT = Path(__file__).resolve().parents[3]
SECRET = "Sup3r-Secret-Value-71"
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"  # two bytes in UTF-8


def test_defaults_with_empty_file(write_config) -> None:  # type: ignore[no-untyped-def]
    settings = load_settings(write_config(""), env_file=None)
    assert settings.environment == "dev"
    assert settings.history.window == timedelta(days=5)
    assert settings.database.port == 55432
    assert settings.database.password is None


def test_shipped_config_file_is_valid() -> None:
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=None)
    assert settings.history.window == timedelta(days=5)


def test_env_example_only_contains_known_settings(tmp_path: Path) -> None:
    lines = (REPO_ROOT / ".env.example").read_text().splitlines()
    env_file = tmp_path / "example.env"
    env_file.write_text("\n".join(line for line in lines if not line.startswith("#")))
    load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=env_file)


@pytest.mark.parametrize(("text", "days"), [("4d", 4), ("5d", 5), ("30d", 30), ("365d", 365)])
def test_history_window_is_a_one_line_change(write_config, text: str, days: int) -> None:  # type: ignore[no-untyped-def]
    path = write_config(f"history:\n  window: {text}\n")
    assert load_settings(path, env_file=None).history.window == timedelta(days=days)


@pytest.mark.parametrize("bad", ["0d", "59m", "366d", "30min", "5", "five", "-1d"])
def test_history_window_rejects_bad_values(write_config, bad: str) -> None:  # type: ignore[no-untyped-def]
    path = write_config(f"history:\n  window: '{bad}'\n")
    with pytest.raises(ConfigError, match=r"history\.window"):
        load_settings(path, env_file=None)


def test_unquoted_integer_window_is_rejected(write_config) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match="ambiguous"):
        load_settings(write_config("history:\n  window: 5\n"), env_file=None)


# --------------------------------------------------------------------------- precedence


def test_precedence_override_env_dotenv_yaml(write_config, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = write_config("history:\n  window: 2d\n")
    dotenv = tmp_path / "test.env"
    dotenv.write_text("ARGUS_HISTORY__WINDOW=3d\n")

    assert load_settings(path, env_file=None).history.window == timedelta(days=2)
    assert load_settings(path, env_file=dotenv).history.window == timedelta(days=3)

    monkeypatch.setenv("ARGUS_HISTORY__WINDOW", "4d")
    assert load_settings(path, env_file=dotenv).history.window == timedelta(days=4)

    assert load_settings(
        path, env_file=dotenv, history={"window": "6d"}
    ).history.window == timedelta(days=6)


def test_config_path_from_environment(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = write_config("history:\n  window: 7d\n", name="other.yaml")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    assert load_settings(env_file=None).history.window == timedelta(days=7)


def test_default_config_path_is_relative_to_cwd(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "argus.yaml").write_text("history:\n  window: 9d\n")
    assert load_settings(env_file=None).history.window == timedelta(days=9)


def test_env_values_are_coerced(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARGUS_DATABASE__PORT", "6543")
    assert load_settings(write_config(""), env_file=None).database.port == 6543


def test_env_names_are_case_insensitive(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("argus_history__window", "8d")
    assert load_settings(write_config(""), env_file=None).history.window == timedelta(days=8)


# --------------------------------------------------------------------------- typos are errors


@pytest.mark.parametrize(
    ("text", "where"),
    [
        ("histroy:\n  window: 5d\n", "histroy"),
        ("history:\n  windw: 5d\n", "history.windw"),
        ("database:\n  hots: x\n", "database.hots"),
        ("loging:\n  level: INFO\n", "loging"),
    ],
)
def test_unknown_yaml_keys_are_errors(write_config, text: str, where: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(text), env_file=None)
    assert where in str(info.value)
    assert "unknown setting" in str(info.value)


def test_unknown_nested_env_key_is_an_error(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARGUS_HISTORY__WINDW", "5d")
    with pytest.raises(
        ConfigError,
        match=r"ARGUS_HISTORY__WINDW is not a known setting; did you mean ARGUS_HISTORY__WINDOW\?",
    ):
        load_settings(write_config(""), env_file=None)


def test_unknown_key_in_dotenv_is_an_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "typo.env"
    dotenv.write_text("ARGUS_DATABASE__PASWORD=x\n")
    with pytest.raises(ConfigError, match=r"typo\.env line 1 is not a known setting") as info:
        load_settings(write_config(""), env_file=dotenv)
    assert "PASWORD" not in str(info.value)  # an unknown .env name is never echoed (D-037)


@pytest.mark.parametrize(
    ("text", "where"),
    [
        ("environment: staging\n", "environment"),
        ("logging:\n  level: TRACE\n", "logging.level"),
        ("logging:\n  format: xml\n", "logging.format"),
        ("database:\n  port: 0\n", "database.port"),
        ("database:\n  port: 65536\n", "database.port"),
        ("database:\n  pool_size: 0\n", "database.pool_size"),
        ("database:\n  statement_timeout: 11m\n", "database.statement_timeout"),
        ("database:\n  connect_timeout: 0s\n", "database.connect_timeout"),
        ("database:\n  name: ''\n", "database.name"),
    ],
)
def test_invalid_values_name_their_location(write_config, text: str, where: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(text), env_file=None)
    assert f"{where}:" in str(info.value)


# --------------------------------------------------------------------------- file problems


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "nope.yaml", env_file=None)


def test_invalid_yaml_reports_position(write_config) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match=r"not valid YAML \(line \d+, column \d+\)"):
        load_settings(write_config("history:\n  window: [5d\n"), env_file=None)


@pytest.mark.parametrize("text", ["- 5d\n", "just a string\n", "42\n"])
def test_top_level_must_be_a_mapping(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match="mapping"):
        load_settings(write_config(text), env_file=None)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_file(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("")
    path.chmod(0)
    try:
        with pytest.raises(ConfigError, match="cannot read"):
            load_settings(path, env_file=None)
    finally:
        path.chmod(0o600)


def test_directory_instead_of_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(tmp_path, env_file=None)


def test_missing_env_file_is_ignored(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    assert (
        load_settings(write_config(""), env_file=tmp_path / "absent.env").database.password is None
    )


# --------------------------------------------------------------------------- secrets


def _settings_with_secret(write_config, tmp_path: Path) -> Settings:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "secret.env"
    dotenv.write_text(f"ARGUS_DATABASE__PASSWORD={SECRET}\n")
    return load_settings(write_config(""), env_file=dotenv)


def test_secret_never_rendered(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    settings = _settings_with_secret(write_config, tmp_path)
    for rendered in (
        repr(settings),
        str(settings),
        str(settings.model_dump()),
        str(settings.model_dump(mode="json")),
        settings.model_dump_json(),
    ):
        assert SECRET not in rendered
    assert settings.secret_values() == [SECRET]


def test_validation_errors_never_echo_secrets(write_config, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "secret.env"
    dotenv.write_text(f"ARGUS_DATABASE__PASSWORD={SECRET}\nARGUS_DATABASE__PORT=not-a-port\n")
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(""), env_file=dotenv)
    assert SECRET not in str(info.value)
    assert "database.port" in str(info.value)


def test_wrong_type_for_secret_does_not_echo_input(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config(f"database:\n  password: [{SECRET}]\n")
    with pytest.raises(ConfigError) as info:
        load_settings(path, env_file=None)
    assert SECRET not in str(info.value)
    assert "database.password" in str(info.value)


def test_database_url_requires_password(write_config) -> None:  # type: ignore[no-untyped-def]
    settings = load_settings(write_config(""), env_file=None)
    with pytest.raises(ConfigError, match="password is not set"):
        settings.database.url()


def test_database_url_rejects_empty_password(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", "")
    settings = load_settings(write_config(""), env_file=None)
    with pytest.raises(ConfigError, match="password is not set"):
        settings.database.url()


@pytest.mark.parametrize("password", ["p@ss:w/rd#%?&=", "with space", "ünïcödé-pässwörd", "a'b\"c"])
def test_database_url_escapes_special_characters(write_config, monkeypatch, password: str) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", password)
    url = load_settings(write_config(""), env_file=None).database.url(database="other")
    reparsed = make_url(url.render_as_string(hide_password=False))
    assert reparsed.password == password
    assert reparsed.database == "other"
    assert reparsed.drivername == "postgresql+psycopg"
    assert password not in url.render_as_string(hide_password=True)


def test_settings_are_immutable(write_config) -> None:  # type: ignore[no-untyped-def]
    settings = load_settings(write_config(""), env_file=None)
    with pytest.raises(ValidationError):
        settings.environment = "prod"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        settings.history.window = timedelta(days=1)  # type: ignore[misc]


# --------------------------------------------------------------------------- roles (D-029)

OWNER_SECRET = "Own3r-Secret-Value-82"


def test_runtime_and_owner_logins_have_separate_defaults() -> None:
    database = DatabaseSettings()
    assert (database.user, database.owner_user) == ("argus_app", "argus")
    assert database.password is None
    assert database.owner_password is None


def test_each_role_logs_in_with_its_own_name_and_password() -> None:
    database = DatabaseSettings(
        user="runner",
        password=SecretStr(SECRET),
        owner_user="keeper",
        owner_password=SecretStr(OWNER_SECRET),
    )
    app_url, owner_url = database.url(), database.url(role="owner")
    assert (app_url.username, app_url.password) == ("runner", SECRET)
    assert (owner_url.username, owner_url.password) == ("keeper", OWNER_SECRET)
    assert app_url.database == owner_url.database == "argus"
    assert database.url(database="other", role="owner").database == "other"


def test_owner_login_needs_the_owner_password() -> None:
    database = DatabaseSettings(password=SecretStr(SECRET))
    with pytest.raises(ConfigError, match=r"put ARGUS_DATABASE__OWNER_PASSWORD in \.env"):
        database.url(role="owner")
    assert database.url().password == SECRET  # the runtime login does not need it


def test_runtime_login_needs_the_runtime_password() -> None:
    database = DatabaseSettings(owner_password=SecretStr(OWNER_SECRET))
    with pytest.raises(ConfigError, match=r"put ARGUS_DATABASE__PASSWORD in \.env"):
        database.url()
    assert database.url(role="owner").password == OWNER_SECRET


@pytest.mark.parametrize("name", ["argus", "argus_app"])
def test_runtime_and_owner_must_be_different_roles(write_config, name: str) -> None:  # type: ignore[no-untyped-def]
    path = write_config(f"database:\n  user: {name}\n  owner_user: {name}\n")
    with pytest.raises(ConfigError, match="user and owner_user must be different roles") as info:
        load_settings(path, env_file=None)
    assert "(D-029)" in str(info.value)


def test_both_passwords_are_secrets(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "secret.env"
    dotenv.write_text(
        f"ARGUS_DATABASE__PASSWORD={SECRET}\nARGUS_DATABASE__OWNER_PASSWORD={OWNER_SECRET}\n"
    )
    settings = load_settings(write_config(""), env_file=dotenv)
    assert settings.secret_values() == [SECRET, OWNER_SECRET]
    for rendered in (repr(settings), str(settings.model_dump()), settings.model_dump_json()):
        assert SECRET not in rendered
        assert OWNER_SECRET not in rendered


# --------------------------------------------------------------------------- database names


def _database(**values: object) -> DatabaseSettings:
    return DatabaseSettings(password=SecretStr(SECRET), **values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("database", "reason"),
    [
        pytest.param("", "must not be blank", id="empty"),
        pytest.param("   ", "must not be blank", id="blank"),
        pytest.param("x" * (MAX_NAME_BYTES + 1), "must be at most 63 bytes", id="64-ascii"),
        pytest.param(E_ACUTE * 32, "must be at most 63 bytes", id="64-bytes"),
    ],
)
def test_database_url_rejects_a_bad_name_override(database: str, reason: str) -> None:
    """An empty override used to fall back silently to the configured (real) database."""
    with pytest.raises(ConfigError, match=f"database name {reason}"):
        _database().url(database=database)


def test_database_url_uses_the_override_or_the_configured_name() -> None:
    settings = _database(name="argus_configured")
    assert settings.url().database == "argus_configured"
    longest = E_ACUTE * 31 + "x"  # 63 bytes in UTF-8
    assert settings.url(database=longest).database == longest


def test_database_url_checks_the_name_before_the_password() -> None:
    with pytest.raises(ConfigError, match="database name must not be blank"):
        DatabaseSettings().url(database="")


@pytest.mark.parametrize("key", ["name", "user"])
@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param("'   '", "must not be blank", id="blank"),
        pytest.param(E_ACUTE * 32, "must be at most 63 bytes", id="64-bytes"),
    ],
)
def test_configured_database_and_role_names_fit_postgresql(  # type: ignore[no-untyped-def]
    write_config, key: str, value: str, reason: str
) -> None:
    """PostgreSQL cuts names after 63 bytes (not characters), so a longer name would quietly
    address a different database or role."""
    path = write_config(f"database:\n  {key}: {value}\n")
    with pytest.raises(ConfigError, match=rf"database\.{key}: Value error, {reason}"):
        load_settings(path, env_file=None)


def test_undecodable_database_name_from_the_environment_is_an_error(  # type: ignore[no-untyped-def]
    write_config, monkeypatch
) -> None:
    monkeypatch.setenv("ARGUS_DATABASE__NAME", "argus\udcff")  # the byte 0xff, not valid UTF-8
    with pytest.raises(ConfigError, match=r"database\.name: Value error, must be valid UTF-8"):
        load_settings(write_config(""), env_file=None)


# --------------------------------------------------------------------------- settings options


@pytest.mark.parametrize(
    "option",
    ["_env_file", "_env_prefix", "_secrets_dir", "_case_sensitive", "_cli_parse_args", "_typo"],
)
def test_settings_refuse_pydantic_settings_options(tmp_path: Path, option: str) -> None:
    """ARGUS reads .env itself, so Settings(_env_file=...) used to be accepted and ignored."""
    dotenv = tmp_path / "direct.env"
    dotenv.write_text("ARGUS_HISTORY__WINDOW=30d\n")
    with pytest.raises(TypeError, match=rf"unexpected keyword arguments: {option}\. "):
        Settings(**{option: dotenv})  # type: ignore[arg-type]


def test_load_settings_refuses_pydantic_settings_options(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "direct.env"
    dotenv.write_text("ARGUS_HISTORY__WINDOW=30d\n")
    with pytest.raises(TypeError, match=r"load_settings\(config_path, env_file=\.\.\.\)"):
        load_settings(write_config(""), env_file=None, _env_file=dotenv)


def test_settings_built_directly_still_take_keyword_settings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "DEBUG")
    settings = Settings(history={"window": "6d"})  # type: ignore[arg-type]
    assert settings.history.window == timedelta(days=6)
    assert settings.logging.level == "DEBUG"
    with pytest.raises(TypeError):
        cast(Any, Settings)(True)  # pydantic-settings' first option, given by position


# --------------------------------------------------------------------------- module surface


def test_settings_module_exports_only_what_is_used() -> None:
    import argus.config.settings as settings_module

    assert sorted(settings_module.__all__) == sorted(
        [
            "CONFIG_ENV_VAR",
            "CUSTODY_SECRETS",
            "DEFAULT_CONFIG_PATH",
            "DEFAULT_ENV_FILE",
            "MAX_NAME_BYTES",
            "ConfigError",
            "CustodyRole",
            "CustodySettings",
            "DatabaseRole",
            "DatabaseSettings",
            "HistorySettings",
            "LoggingSettings",
            "Settings",
            "load_settings",
            "resolve_config_path",
            "secret_settings",
            "usable_password",
        ]
    )
    for removed in ("format_validation_error", "read_config_file"):  # had no callers
        assert not hasattr(settings_module, removed)


# --------------------------------------------------------------------------- text libpq can take


@pytest.mark.parametrize("key", ["name", "user", "owner_user", "host"])
@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param('"argus\\0x"', "must not contain a NUL character", id="nul"),
        pytest.param(None, "must be valid UTF-8 text", id="not-utf8"),
    ],
)
def test_names_and_host_refuse_what_libpq_would_cut_or_cannot_send(  # type: ignore[no-untyped-def]
    write_config, monkeypatch, key: str, value: str | None, reason: str
) -> None:
    """libpq reads them as C strings in UTF-8: a NUL would cut one short (another database or
    role), and an undecodable byte (a lone surrogate from the environment) cannot be sent."""
    if value is None:
        monkeypatch.setenv(f"ARGUS_DATABASE__{key.upper()}", "argus\udcff")
        path = write_config("")
    else:
        path = write_config(f"database:\n  {key}: {value}\n")
    # pydantic's own check of a length-constrained str (host) refuses undecodable text first.
    refused = rf"database\.{key}: (Value error, {reason}|Input should be a valid string)"
    with pytest.raises(ConfigError, match=refused):
        load_settings(path, env_file=None)


@pytest.mark.parametrize(("field", "role"), [("password", "app"), ("owner_password", "owner")])
@pytest.mark.parametrize(
    ("secret", "reason"),
    [("fake\x00rest", "must not contain a NUL"), ("fake\udcffrest", "must be valid UTF-8 text")],
    ids=["nul", "not-utf8"],
)
def test_url_checks_the_password_again_after_model_copy(
    field: str, role: str, secret: str, reason: str
) -> None:
    """model_copy(update=...) skips the field validators (the test harness makes logins with
    it), so url() repeats the check for the password of the role it logs in as."""
    database = DatabaseSettings(password=SecretStr(SECRET), owner_password=SecretStr(SECRET))
    broken = database.model_copy(update={field: SecretStr(secret)})
    with pytest.raises(ConfigError, match=rf"database\.{field} {reason}") as info:
        broken.url(role=role)  # type: ignore[arg-type]
    assert "rest" not in str(info.value)
