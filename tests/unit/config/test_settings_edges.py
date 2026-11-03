"""Edge cases of argus.config.settings that test_settings.py leaves open (R1 mutation testing).

* Every bounded setting accepts both ends of its range and refuses one step beyond either, and
  every default and every documented choice is the documented one.
* Error reports: the exact wording of each problem, the file and line (or variable) that set it,
  the files named in the header, and at most 50 problems with a count of the rest.
"""

from __future__ import annotations

import typing
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel, SecretStr, ValidationError

from argus.config import ConfigError, DatabaseSettings, Settings, load_settings
from argus.config.settings import (
    DatabaseRole,
    HistorySettings,
    LoggingSettings,
    _location,
    _origin,
    _unknown_setting,
    _validation_problems,
)
from argus.config.sources import Layer

SECRET = "Edge-Synthetic-Secret-31"
OWNER_SECRET = "Edge-Synthetic-Owner-47"
API_SECRET = "Edge-Synthetic-Api-53"
WRITER_SECRET = "Edge-Synthetic-Writer-59"
SPELLING = "unknown setting (check the spelling)"
DOTS = "unknown setting; nested settings are written as an indented section, not with dots"

# --------------------------------------------------------------------------- defaults and ranges


def test_every_setting_has_its_documented_default() -> None:
    settings = Settings()
    assert settings.environment == "dev"
    assert settings.history == HistorySettings(window=timedelta(days=5))
    assert settings.logging == LoggingSettings(level="INFO", format="console")
    database = settings.database
    assert (database.host, database.port, database.name) == ("127.0.0.1", 55432, "argus")
    assert (database.user, database.owner_user) == ("argus_app", "argus")
    assert (database.pool_size, database.max_overflow) == (5, 5)
    assert database.connect_timeout == timedelta(seconds=5)
    assert database.statement_timeout == timedelta(seconds=30)


def test_every_documented_choice_is_accepted() -> None:
    for environment in ("dev", "test", "prod"):
        assert Settings(environment=environment).environment == environment
    for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
        assert LoggingSettings(level=level).level == level
    for log_format in ("console", "json"):
        assert LoggingSettings(format=log_format).format == log_format


@pytest.mark.parametrize(
    ("field", "smallest", "largest"),
    [("port", 1, 65535), ("pool_size", 1, 50), ("max_overflow", 0, 50)],
)
def test_numeric_database_settings_have_exact_bounds(
    field: str, smallest: int, largest: int
) -> None:
    for value in (smallest, largest):
        assert getattr(DatabaseSettings(**{field: value}), field) == value
    for value in (smallest - 1, largest + 1):
        with pytest.raises(ValidationError, match=field):
            DatabaseSettings(**{field: value})


@pytest.mark.parametrize(
    ("model", "field", "smallest", "largest", "beyond", "message"),
    [
        (HistorySettings, "window", "1h", "365d", ("59m", "366d"), "between 1h and 365d"),
        (DatabaseSettings, "connect_timeout", "1s", "60s", ("61s",), "between 1s and 1m"),
        (DatabaseSettings, "statement_timeout", "1s", "10m", ("601s",), "between 1s and 10m"),
    ],
)
def test_duration_settings_have_exact_bounds(
    model: type[BaseModel],
    field: str,
    smallest: str,
    largest: str,
    beyond: tuple[str, ...],
    message: str,
) -> None:
    for value in (smallest, largest):
        assert getattr(model(**{field: value}), field) > timedelta(0)
    for value in beyond:
        with pytest.raises(ValidationError, match=message):
            model(**{field: value})


def test_the_host_must_not_be_empty() -> None:
    assert DatabaseSettings(host="h").host == "h"
    with pytest.raises(ValidationError, match="host"):
        DatabaseSettings(host="")


# --------------------------------------------------------------------------- logins


def test_database_role_names_the_logins_url_knows() -> None:
    database = DatabaseSettings(
        password=SecretStr(SECRET),
        owner_password=SecretStr(OWNER_SECRET),
        api_password=SecretStr(API_SECRET),
        writer_password=SecretStr(WRITER_SECRET),
    )
    logins = {role: database.url(role=role) for role in typing.get_args(DatabaseRole)}
    assert {role: url.username for role, url in logins.items()} == {
        "app": "argus_app",
        "api": "argus_api",  # the web's own login (Q-A2)
        "writer": "argus_writer_app",  # the case writer's own login (Q-D4)
        "owner": "argus",
    }
    assert {role: url.password for role, url in logins.items()} == {
        "app": SECRET,
        "api": API_SECRET,
        "writer": WRITER_SECRET,
        "owner": OWNER_SECRET,
    }


def test_a_missing_password_says_which_variable_to_set() -> None:
    with pytest.raises(ConfigError) as runtime:
        DatabaseSettings().url()
    assert str(runtime.value) == (
        "database password is not set; put ARGUS_DATABASE__PASSWORD in .env"
    )
    with pytest.raises(ConfigError) as owner:
        DatabaseSettings().url(role="owner")
    assert str(owner.value) == (
        "database owner password is not set; put ARGUS_DATABASE__OWNER_PASSWORD in .env"
        " (only the `argus db` commands need it)"
    )


def test_one_role_for_both_logins_is_refused_with_the_reason(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("database:\n  user: same\n  owner_user: same\n")
    with pytest.raises(ConfigError) as info:
        load_settings(path, env_file=None)
    assert str(info.value).splitlines()[1:] == [
        "  - database: Value error, user and owner_user must be different roles: ARGUS must not"
        f" run as the role that owns its tables (D-029) [{path.name} line 1]"
    ]


# --------------------------------------------------------------------------- error reports


def test_unknown_settings_are_reported_with_a_suggestion_and_their_line(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config(
        "histroy:\n  window: 5d\nhistory.window: 5d\nhistory:\n  windw: 5d\n  a.b: 1\n  zzz: 1\n"
    )
    with pytest.raises(ConfigError) as info:
        load_settings(path, env_file=None)
    assert str(info.value).splitlines()[1:] == [
        f"  - history.windw: {SPELLING}; did you mean window? [{path.name} line 5]",
        f"  - history.'a.b': {SPELLING} [{path.name} line 6]",
        f"  - history.zzz: {SPELLING} [{path.name} line 7]",
        f"  - histroy: {SPELLING}; did you mean history? [{path.name} line 1]",
        f"  - 'history.window': {DOTS} [{path.name} line 3]",
    ]


def test_the_report_names_the_files_it_read(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    path = write_config("database:\n  pool_size: 0\n")
    env_file = tmp_path / "edge.env"
    env_file.write_text("ARGUS_HISTORY__WINDOW=5d\n", encoding="utf-8")
    for given, header in (
        (env_file, f"invalid configuration ({path}, environment and {env_file}):"),
        (None, f"invalid configuration ({path} and environment):"),
        (tmp_path / "absent.env", f"invalid configuration ({path} and environment):"),
    ):
        with pytest.raises(ConfigError) as info:
            load_settings(path, env_file=given)
        assert str(info.value).splitlines()[0] == header


def test_settings_built_directly_report_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_HISTORY__WINDW", "5d")
    with pytest.raises(ConfigError) as info:
        Settings()
    assert str(info.value) == (
        "invalid configuration (environment):\n  - environment variable ARGUS_HISTORY__WINDW is"
        " not a known setting; did you mean ARGUS_HISTORY__WINDOW?"
    )


def test_every_refused_settings_option_is_named(tmp_path: Path) -> None:
    named = r"unexpected keyword arguments: _env_file, _secrets_dir\. "
    with pytest.raises(TypeError, match=named):
        Settings(_env_file=tmp_path / "a.env", _secrets_dir=tmp_path)  # type: ignore[call-arg]


def _unknown_settings(count: int) -> str:
    return "".join(f"unknown_{number:02d}: 1\n" for number in range(count))


def test_a_report_lists_fifty_problems_and_counts_the_rest(write_config) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(_unknown_settings(55)), env_file=None)
    lines = str(info.value).splitlines()
    assert len(lines) == 1 + 50 + 1
    assert lines[50].startswith("  - unknown_49: unknown setting")
    assert lines[-1] == "  - ... and 5 more"


def test_a_report_of_fifty_problems_lists_them_all(write_config) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(_unknown_settings(50)), env_file=None)
    lines = str(info.value).splitlines()
    assert len(lines) == 1 + 50
    assert lines[-1].startswith("  - unknown_49: unknown setting")


# --------------------------------------------------------------------------- report helpers


def test_a_problem_without_a_known_origin_has_no_brackets() -> None:
    with pytest.raises(ValidationError) as info:
        DatabaseSettings(port=0)
    assert _validation_problems(info.value, []) == [
        "port: Input should be greater than or equal to 1"
    ]


def test_a_location_reads_like_the_setting() -> None:
    assert _location(()) == "<root>"
    assert _location(("history", "window")) == "history.window"
    assert _location(("history.window",)) == "'history.window'"
    assert _location(("database", 0)) == "database.0"


@pytest.mark.parametrize(
    ("loc", "message"),
    [
        ((), SPELLING),
        (("Histroy",), f"{SPELLING}; did you mean history?"),
        (("zzz",), SPELLING),
        (("history.window",), DOTS),
        (("database", "hots"), f"{SPELLING}; did you mean host?"),
        (("history", "a.b"), SPELLING),
        (("environment", "dev"), SPELLING),  # not a section: nothing to compare with
        (("database", "port", "hots"), SPELLING),  # deeper than a section
    ],
)
def test_an_unknown_setting_is_compared_with_the_names_at_its_level(
    loc: tuple[str, ...], message: str
) -> None:
    assert _unknown_setting(loc) == message


def test_an_origin_is_the_most_specific_path_then_the_first_layer() -> None:
    environment = Layer(origins={("database",): "environment variable ARGUS_DATABASE"})
    yaml = Layer(origins={("database",): "line 1", ("database", "port"): "line 2"})
    assert _origin(("database", "port"), [environment, yaml]) == "line 2"
    assert _origin(("database", "pool_size"), [environment, yaml]) == (
        "environment variable ARGUS_DATABASE"
    )
    assert _origin(("history", "window"), [environment, yaml]) is None
