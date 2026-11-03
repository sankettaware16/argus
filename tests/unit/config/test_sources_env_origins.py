"""The environment, ``.env`` and override layers: exact messages for unknown and repeated
variables, the origin each layer records for each setting (the part of a report that says where a
bad value was set), secrets wrapped as soon as they are read, and the ``${VAR}`` expander's edge
cases. Every secret here is synthetic."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from dotenv.variables import parse_variables
from pydantic import BaseModel, SecretStr

from argus.config import ConfigError, Settings, load_settings, sources

FAKE_SECRET = "Fake-Env-Secret-8k2p"
NESTED = "settings are ARGUS_<NAME> or ARGUS_<SECTION>__<KEY>"
NOT_PARSED = "write each setting as NAME=value on its own line; lines starting with # are comments"


def _config_error(load: Callable[[], object]) -> ConfigError:
    """Run ``load`` and return the ConfigError it raised; fail on success or on any other error."""
    try:
        result = load()
    except ConfigError as exc:
        return exc
    except Exception as exc:
        pytest.fail(f"expected ConfigError, but {type(exc).__name__} escaped: {exc}")
    pytest.fail(f"expected ConfigError, but loading succeeded: {result!r}")


def _write(tmp_path: Path, text: str, name: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


def _dotenv(tmp_path: Path, text: str) -> sources.Layer:
    layer = sources.dotenv_layer(_write(tmp_path, text, "test.env"), Settings)
    assert layer is not None
    return layer


def _report(load: Callable[[], object]) -> list[str]:
    """The problem lines of the report that ``load`` raised, without the header."""
    header, *problems = str(_config_error(load)).splitlines()
    assert header.startswith("invalid configuration (")
    return problems


# --------------------------------------------------------------------------- unknown names


def test_unknown_variables_get_the_closest_name_or_the_naming_rule() -> None:
    environ = {
        "ARGUS_DATABASE__PASWORD": FAKE_SECRET,
        "ARGUS_ENVIRONEMNT": FAKE_SECRET,
        "ARGUS_ENVIRONMENT__X": FAKE_SECRET,
        "ARGUS_HISTORY_WINDOW": FAKE_SECRET,
        "ARGUS_HISTORY__": FAKE_SECRET,
        "ARGUS_HISTORY__WINDOW__X": FAKE_SECRET,
        "ARGUS_HISTORY__ZZZZZZZZ": FAKE_SECRET,
        "ARGUS_ZZZZZZZZZZ": FAKE_SECRET,
    }
    layer = sources.environment_layer(environ, Settings)
    unknown = "is not a known setting"
    assert layer.problems == [
        f"environment variable ARGUS_DATABASE__PASWORD {unknown};"
        " did you mean ARGUS_DATABASE__PASSWORD?",
        f"environment variable ARGUS_ENVIRONEMNT {unknown}; did you mean ARGUS_ENVIRONMENT?",
        f"environment variable ARGUS_ENVIRONMENT__X {unknown}; did you mean ARGUS_ENVIRONMENT?",
        f"environment variable ARGUS_HISTORY_WINDOW {unknown}; did you mean ARGUS_HISTORY__WINDOW?"
        " (nested keys use a double underscore)",
        f"environment variable ARGUS_HISTORY__ {unknown}; did you mean ARGUS_HISTORY?",
        f"environment variable ARGUS_HISTORY__WINDOW__X {unknown};"
        " did you mean ARGUS_HISTORY__WINDOW?",
        f"environment variable ARGUS_HISTORY__ZZZZZZZZ {unknown}; {NESTED},"
        " e.g. ARGUS_HISTORY__WINDOW",
        f"environment variable ARGUS_ZZZZZZZZZZ {unknown}; {NESTED}, e.g. ARGUS_HISTORY__WINDOW",
    ]
    assert layer.data == {}


class _Level(BaseModel):
    level: str = "INFO"


class _Nothing(BaseModel):
    pass


class _WithEmptySection(BaseModel):
    extras: _Nothing = _Nothing()


def test_the_naming_rule_example_is_the_last_name_when_no_setting_is_nested() -> None:
    layer = sources.environment_layer({"ARGUS_ZZZZZZZZZZ": "x"}, _Level)
    assert layer.problems == [
        f"environment variable ARGUS_ZZZZZZZZZZ is not a known setting; {NESTED}, e.g. ARGUS_LEVEL"
    ]


def test_a_whole_section_that_is_not_json_names_one_of_its_keys() -> None:
    layer = sources.environment_layer({"ARGUS_HISTORY": "30d"}, Settings)
    assert layer.problems == [
        "environment variable ARGUS_HISTORY sets the whole history section, so its value must be"
        " a JSON object; to set one key use ARGUS_HISTORY__<KEY>, e.g. ARGUS_HISTORY__WINDOW"
    ]
    empty = sources.environment_layer({"ARGUS_EXTRAS": "30d"}, _WithEmptySection)
    assert empty.problems == [
        "environment variable ARGUS_EXTRAS sets the whole extras section, so its value must be"
        " a JSON object; to set one key use ARGUS_EXTRAS__<KEY>, e.g. ARGUS_EXTRAS__KEY"
    ]


# --------------------------------------------------------------------------- repeats, no value


def test_every_repeat_of_a_variable_names_its_first_line(tmp_path: Path) -> None:
    layer = _dotenv(
        tmp_path,
        "ARGUS_HISTORY__WINDOW=1d\nARGUS_HISTORY__WINDOW=2d\nargus_history__window=3d\n",
    )
    first = "ARGUS_HISTORY__WINDOW in test.env line 1"
    assert layer.problems == [
        f"{first} and ARGUS_HISTORY__WINDOW in test.env line 2 set the same setting; keep one",
        f"{first} and argus_history__window in test.env line 3 set the same setting; keep one",
    ]
    assert layer.data == {"history": {"window": "1d"}}


def test_a_variable_with_a_known_problem_is_reported_once_and_not_used(tmp_path: Path) -> None:
    layer = _dotenv(tmp_path, "ARGUS_DATABASE__PASSWORD\nARGUS_CONFIG=other.yaml\n")
    assert layer.problems == [
        "ARGUS_DATABASE__PASSWORD in test.env line 1 has no value (expected NAME=value)",
        "ARGUS_CONFIG in test.env line 2 is not used: choose the config file with --config or the"
        " ARGUS_CONFIG environment variable",
    ]
    assert (layer.data, layer.origins) == ({}, {})
    environment = sources.environment_layer({"argus_config": "other.yaml"}, Settings)
    assert environment.problems == [
        "environment variable argus_config is ignored: the config file variable is spelled"
        " ARGUS_CONFIG"
    ]
    assert (environment.data, environment.origins) == ({}, {})


def test_a_line_number_counts_the_blank_lines_before_the_line(tmp_path: Path) -> None:
    """python-dotenv starts a binding at the blank lines before it."""
    layer = _dotenv(tmp_path, "ARGUS_HISTORY__WINDOW=5d\n\n\r\n   \nARGUS_DATABASE__PASSWORD\n")
    assert layer.problems == [
        "ARGUS_DATABASE__PASSWORD in test.env line 5 has no value (expected NAME=value)"
    ]


# ---------------------------------------------------------------------- lines that do not parse


@pytest.mark.parametrize(
    ("broken", "listed"),
    [
        pytest.param([2], "line 2", id="one"),
        pytest.param([1, 3], "lines 1 and 3", id="two"),
        pytest.param([1, 3, 5], "lines 1, 3 and 5", id="three"),
        pytest.param(
            list(range(1, 21)),
            "lines " + ", ".join(map(str, range(1, 20))) + " and 20",
            id="twenty",
        ),
        pytest.param(
            list(range(1, 22)),
            "lines " + ", ".join(map(str, range(1, 21))) + " and 1 more",
            id="twenty-one",
        ),
    ],
)
def test_lines_that_do_not_parse_are_listed_by_number(
    tmp_path: Path, broken: list[int], listed: str
) -> None:
    last = max(broken) + 1
    text = "".join(
        "broken line\n" if number in broken else "OTHER=1\n" for number in range(1, last + 1)
    )
    path = _write(tmp_path, text, "test.env")
    message = str(_config_error(lambda: sources.dotenv_layer(path, Settings)))
    assert message == f"cannot parse env file {path} ({listed}): {NOT_PARSED}"


# --------------------------------------------------------------------------- origins in reports


def _yaml_config(tmp_path: Path) -> Path:
    """A config file that sets the same settings as the variables in the tests below: an origin
    must come from the layer whose value was used, not from a lower one."""
    text = "environment: dev\ndatabase:\n  port: 5432\nhistory:\n  window: 5d\n"
    return _write(tmp_path, text, "argus.yaml")


@pytest.mark.parametrize(
    ("variable", "value", "problem"),
    [
        pytest.param(
            "ARGUS_ENVIRONMENT",
            "nope",
            "environment: Input should be 'dev', 'test' or 'prod'",
            id="top-level",
        ),
        pytest.param(
            "ARGUS_HISTORY__WINDOW",
            "nope",
            "history.window: Value error, invalid duration; use a number followed by a unit:"
            " s, m, h, d or w (for example '5d', '36h', '15m')",
            id="section-key",
        ),
        pytest.param(
            "ARGUS_DATABASE",
            json.dumps({"port": "nope"}),
            "database.port: Input should be a valid integer, unable to parse string as an integer",
            id="key-of-a-whole-section",
        ),
        pytest.param(
            "ARGUS_DATABASE",
            json.dumps({"user": "same_role", "owner_user": "same_role"}),
            "database: Value error, user and owner_user must be different roles: ARGUS must not"
            " run as the role that owns its tables (D-029)",
            id="whole-section",
        ),
    ],
)
def test_a_problem_names_the_variable_that_set_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable: str, value: str, problem: str
) -> None:
    config = _yaml_config(tmp_path)
    monkeypatch.setenv(variable, value)
    assert _report(lambda: load_settings(config, env_file=None)) == [
        f"  - {problem} [environment variable {variable}]"
    ]
    monkeypatch.delenv(variable)
    env_file = _write(tmp_path, f"{variable}={value}\n", "test.env")
    assert _report(lambda: load_settings(config, env_file=env_file)) == [
        f"  - {problem} [{variable} in test.env line 1]"
    ]


def test_a_top_level_variable_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_ENVIRONMENT", "test")
    assert load_settings(_yaml_config(tmp_path), env_file=None).environment == "test"
    layer = sources.environment_layer({"ARGUS_ENVIRONMENT": "prod"}, Settings)
    assert layer.data == {"environment": "prod"}
    assert layer.origins == {("environment",): "environment variable ARGUS_ENVIRONMENT"}


def test_a_whole_section_variable_is_the_origin_of_each_of_its_keys() -> None:
    environ = {"ARGUS_DATABASE": json.dumps({"port": 6000, "name": "argus_x"})}
    layer = sources.environment_layer(environ, Settings)
    origin = "environment variable ARGUS_DATABASE"
    assert layer.origins == {
        ("database",): origin,
        ("database", "port"): origin,
        ("database", "name"): origin,
    }


def test_an_invalid_override_is_reported_as_an_override(tmp_path: Path) -> None:
    config = _yaml_config(tmp_path)
    problems = _report(
        lambda: load_settings(config, env_file=None, environment="nope", history={"window": "x"})
    )
    assert problems == [
        "  - environment: Input should be 'dev', 'test' or 'prod' [override]",
        "  - history.window: Value error, invalid duration; use a number followed by a unit:"
        " s, m, h, d or w (for example '5d', '36h', '15m') [override]",
    ]
    layer = sources.overrides_layer({"environment": "x", "history": {"window": "1d"}})
    assert layer.origins == {
        ("environment",): "override",
        ("history",): "override",
        ("history", "window"): "override",
    }
    assert (layer.data, layer.problems) == ({}, [])


# --------------------------------------------------------------------------- secrets


def test_secrets_from_variables_are_wrapped_as_soon_as_they_are_read(tmp_path: Path) -> None:
    """Whatever the order of the variables, and whether a secret comes in a whole-section JSON
    value or on its own."""
    environ = {
        "ARGUS_DATABASE": json.dumps({"owner_password": f"{FAKE_SECRET}-owner", "user": "u"}),
        "ARGUS_DATABASE__PASSWORD": FAKE_SECRET,
        "ARGUS_HISTORY__WINDOW": "5d",
    }
    for layer in (
        sources.environment_layer(environ, Settings),
        _dotenv(tmp_path, "".join(f"{name}={value}\n" for name, value in environ.items())),
    ):
        database = layer.data["database"]
        assert isinstance(database["password"], SecretStr)
        assert isinstance(database["owner_password"], SecretStr)
        assert database["password"].get_secret_value() == FAKE_SECRET
        assert database["owner_password"].get_secret_value() == f"{FAKE_SECRET}-owner"
        assert database["user"] == "u"
        assert layer.data["history"] == {"window": "5d"}
        assert FAKE_SECRET not in repr(layer)


# --------------------------------------------------------------------------- ${VAR} expansion


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("x${}y", "xy", id="empty-name"),
        pytest.param("${A:xyz}", "${A:xyz}", id="colon-without-dash"),
        pytest.param("${A:xyz}${B}", "${A:xyz}b", id="colon-then-reference"),
        pytest.param("${A:${B}", "${A:b", id="reference-right-after-the-colon"),
        pytest.param("${UNSET:-}x}", "x}", id="empty-default"),
        pytest.param("${UNSET:-d}${A:-e}", "da", id="defaults"),
    ],
)
def test_references_expand_as_python_dotenv_expands_them(value: str, expected: str) -> None:
    known: dict[str, str | None] = {"A": "a", "B": "b"}
    assert "".join(atom.resolve(known) for atom in parse_variables(value)) == expected
    assert sources._expand(value, known, 1000) == expected


def test_references_expand_in_a_dotenv_file(tmp_path: Path) -> None:
    layer = _dotenv(
        tmp_path,
        "A=a\nB=b\nARGUS_DATABASE__NAME=${A:xyz}${B}\nARGUS_DATABASE__USER=x${}y${UNSET:-}z}\n",
    )
    assert layer.data == {"database": {"name": "${A:xyz}b", "user": "xyz}"}}
