"""Adversarial tests for configuration loading (C1): YAML, env, .env, precedence, paths, errors.

Tests whose docstring starts with ``DEFECT`` fail on the current code and demonstrate a bug.
The others pass and lock in behaviour that no other test covered.
All secrets here are synthetic.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, load_settings
from argus.config.settings import CONFIG_ENV_VAR

FAKE_SECRET = "Fake-Adv-Secret-9f3k2"
# Shaped like `openssl rand -base64 16` (or an encoded Elastic API key): ends in '=' padding.
PASTED_SECRET = "Q83vEjLx0vLzbXQ9t0d1Qg=="
runner = CliRunner()


def _config_error(load: Callable[[], object]) -> ConfigError:
    """Run ``load`` and return the ConfigError it raised; fail on success or on any other error."""
    try:
        result = load()
    except ConfigError as exc:
        return exc
    except Exception as exc:
        pytest.fail(
            f"expected ConfigError, but {type(exc).__module__}.{type(exc).__name__} escaped: {exc}"
        )
    pytest.fail(f"expected ConfigError, but loading succeeded: {result!r}")


# =========================================================================== DEFECTS: YAML file


@pytest.mark.parametrize(
    ("text", "key"),
    [
        pytest.param(
            "history:\n  window: 30d\nhistory:\n  window: 2d\n", "history", id="top-level-section"
        ),
        pytest.param("history:\n  window: 30d\n  window: 5d\n", "window", id="nested-key"),
        pytest.param(
            "database:\n  pool_size: 9\nlogging:\n  level: INFO\ndatabase:\n  max_overflow: 1\n",
            "database",
            id="split-section-drops-earlier-keys",
        ),
    ],
)
def test_duplicate_yaml_keys_are_errors(write_config, text: str, key: str) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: PyYAML silently keeps the last duplicate key, so a stray second ``window:`` line
    (or a second ``database:`` section, which drops every key of the first) changes the effective
    configuration with no error — the opposite of "a typo fails loudly"."""
    exc = _config_error(lambda: load_settings(write_config(text), env_file=None))
    assert "duplicate" in str(exc).lower()
    assert key in str(exc)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            "# Secrets go in .env \N{EM DASH} see .env.example\nhistory:\n  window: 5d\n".encode(
                "cp1252"
            ),
            id="shipped-em-dash-comment-saved-as-cp1252",
        ),
        pytest.param(
            "# caf\N{LATIN SMALL LETTER E WITH ACUTE}\nhistory:\n  window: 5d\n".encode("latin-1"),
            id="latin-1",
        ),
        pytest.param("history:\n  window: 5d\n".encode("utf-16"), id="utf-16"),
    ],
)
def test_non_utf8_config_file_is_a_config_error(tmp_path: Path, raw: bytes) -> None:
    """DEFECT: ``UnicodeDecodeError`` is a ``ValueError``, not an ``OSError``, so it escapes
    ``read_config_file``: the CLI shows a traceback, exits 1, and the message has no file name."""
    path = tmp_path / "argus.yaml"
    path.write_bytes(raw)
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert str(path) in str(exc)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("environment: 2026-02-30\n", id="implicit-impossible-date"),
        pytest.param("environment: 0x_\n", id="implicit-empty-hex-int"),
        pytest.param("history:\n  window: !!int 5d\n", id="int-tag"),
        pytest.param("history:\n  window: !!float 5d\n", id="float-tag"),
        pytest.param("logging:\n  level: !!bool maybe\n", id="bool-tag"),
        pytest.param("history:\n  window: !!timestamp soon\n", id="timestamp-tag"),
    ],
)
def test_yaml_values_that_crash_the_constructor_are_config_errors(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: only ``yaml.YAMLError`` is caught, but PyYAML's constructors raise ``ValueError``,
    ``KeyError``, ``AttributeError`` ... for these scalars, which escape ``load_settings``."""
    path = write_config(text)
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert str(path) in str(exc)


def test_deeply_nested_yaml_is_a_config_error(write_config) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: PyYAML's composer recurses once per nesting level; ~500 levels raise
    ``RecursionError`` straight out of ``load_settings``."""
    depth = 1000
    path = write_config("history:\n  window: " + "[" * depth + "]" * depth + "\n")
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert str(path) in str(exc)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("1: x\n", id="int"),
        pytest.param("on: true\n", id="yaml-1.1-boolean-on"),
        pytest.param("~: x\n", id="null"),
        pytest.param("2026-10-10: x\n", id="date"),
    ],
)
def test_non_string_top_level_keys_are_config_errors(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: non-string top-level keys reach ``Settings(**data)`` and raise
    ``TypeError: keywords must be strings`` instead of a ConfigError."""
    path = write_config(text)
    _config_error(lambda: load_settings(path, env_file=None))


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("history:\n  window: 30d\x1b[0m\n", id="ansi-escape-pasted-from-terminal"),
        pytest.param("history:\n  window: 30d\x7f\n", id="delete-character"),
        pytest.param("history:\n  window: 30d\x0c\n", id="form-feed"),
    ],
)
def test_unprintable_character_error_names_its_line(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: ``yaml.ReaderError`` has no ``problem_mark``, so the message is just "not valid
    YAML" and the user must hunt for an invisible character with no line number."""
    exc = _config_error(lambda: load_settings(write_config(text), env_file=None))
    assert "line 2" in str(exc)


@pytest.mark.parametrize(
    ("text", "key"),
    [
        pytest.param("history.window: 30d\n", "history.window", id="dotted-window"),
        pytest.param(
            f"database.password: {FAKE_SECRET}\n", "database.password", id="dotted-secret"
        ),
    ],
)
def test_dotted_top_level_key_is_not_reported_as_the_real_setting(  # type: ignore[no-untyped-def]
    write_config, text: str, key: str
) -> None:
    """DEFECT: error locations are joined with '.', so a top-level key literally named
    ``history.window`` is reported as "history.window: unknown setting (check the spelling)" —
    i.e. the error claims the valid, correctly spelled setting is unknown."""
    exc = _config_error(lambda: load_settings(write_config(text), env_file=None))
    assert f"  - {key}: unknown setting" not in str(exc)
    assert FAKE_SECRET not in str(exc)


def test_non_mapping_yaml_section_is_not_masked_by_env_vars(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: a YAML section of the wrong type is replaced wholesale (pydantic-settings
    ``deep_update``) as soon as env/.env sets any key of that section — always true for
    ``database``, whose password lives in .env — so the bad YAML is silently ignored."""
    path = write_config("database: postgresql://argus@db.example.internal:5432/argus\n")
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", FAKE_SECRET)
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert "database" in str(exc)
    assert FAKE_SECRET not in str(exc)


# =========================================================================== DEFECTS: env and .env


@pytest.mark.parametrize(
    ("name", "value", "section"),
    [
        pytest.param("ARGUS_LOGGING", "DEBUG", "logging", id="logging-shorthand"),
        pytest.param("ARGUS_HISTORY", "30d", "history", id="history-shorthand"),
        pytest.param("ARGUS_HISTORY", "", "history", id="empty-section-variable"),
        pytest.param(
            "ARGUS_DATABASE",
            f"postgresql://argus:{FAKE_SECRET}@127.0.0.1:55432/argus",
            "database",
            id="dsn-in-section-variable",
        ),
    ],
)
def test_section_level_env_var_with_plain_value_is_a_config_error(  # type: ignore[no-untyped-def]
    write_config, monkeypatch, name: str, value: str, section: str
) -> None:
    """DEFECT: pydantic-settings JSON-decodes section-level variables and raises
    ``SettingsError`` (a ValueError), which ``load_settings`` does not convert."""
    monkeypatch.setenv(name, value)
    exc = _config_error(lambda: load_settings(write_config(""), env_file=None))
    assert section in str(exc)
    assert FAKE_SECRET not in str(exc)


def test_section_level_dotenv_value_is_a_config_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: the same ``SettingsError`` escapes when the shorthand is written in .env."""
    dotenv = tmp_path / "shorthand.env"
    dotenv.write_text("ARGUS_HISTORY=30d\n")
    exc = _config_error(lambda: load_settings(write_config(""), env_file=dotenv))
    assert "history" in str(exc)


def test_cli_reports_section_level_env_var_as_config_error(write_config) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: ``ARGUS_LOGGING=DEBUG argus config validate`` prints a ~100-line traceback and
    exits 1 (operational failure) instead of a one-line config error with exit 2."""
    path = write_config("history:\n  window: 4d\n")
    result = runner.invoke(
        app, ["config", "validate", "-c", str(path)], env={"ARGUS_LOGGING": "DEBUG"}
    )
    assert result.exit_code == 2, repr(result.exception)
    assert "logging" in result.stderr


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("ARGUS_HISTORY_WINDOW", "30d", id="single-underscore-delimiter"),
        pytest.param("ARGUS_HISTROY__WINDOW", "30d", id="misspelled-section"),
        pytest.param("ARGUS__HISTORY__WINDOW", "30d", id="doubled-underscore-after-prefix"),
        pytest.param("ARGUS_ENVIRONEMNT", "prod", id="misspelled-top-level-key"),
        pytest.param("ARGUS_DATABASE_PASSWORD", FAKE_SECRET, id="single-underscore-password"),
    ],
)
def test_misspelled_argus_env_var_is_an_error(  # type: ignore[no-untyped-def]
    write_config, monkeypatch, name: str, value: str
) -> None:
    """DEFECT: unknown ``ARGUS_*`` environment variables are silently ignored (the identical line
    in .env IS rejected), so the typo silently falls back to the default: history.window stays
    5d, environment stays dev, the password stays unset."""
    monkeypatch.setenv(name, value)
    exc = _config_error(lambda: load_settings(write_config(""), env_file=None))
    assert name.lower() in str(exc).lower()
    assert FAKE_SECRET not in str(exc)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("ARGUS_HISTORY__WINDOW: 30d", id="yaml-style-colon"),
        pytest.param("ARGUS_HISTORY__WINDOW 30d", id="missing-equals"),
        pytest.param('ARGUS_HISTORY__WINDOW="30d', id="unterminated-quote"),
    ],
)
def test_malformed_dotenv_line_is_an_error(write_config, tmp_path: Path, line: str) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: python-dotenv skips lines it cannot parse (it only logs a warning), so the setting
    silently keeps its default and ``argus config validate`` says "configuration OK"."""
    dotenv = tmp_path / "malformed.env"
    dotenv.write_text(line + "\n")
    exc = _config_error(lambda: load_settings(write_config(""), env_file=dotenv))
    assert "line 1" in str(exc) or str(dotenv) in str(exc)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_dotenv_is_a_config_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: an unreadable YAML file gives "cannot read config file", but an unreadable .env
    raises a raw ``PermissionError`` from inside pydantic-settings."""
    dotenv = tmp_path / "locked.env"
    dotenv.write_text(f"ARGUS_DATABASE__PASSWORD={FAKE_SECRET}\n")
    dotenv.chmod(0)
    try:
        exc = _config_error(lambda: load_settings(write_config(""), env_file=dotenv))
    finally:
        dotenv.chmod(0o600)
    assert str(dotenv) in str(exc)


def test_non_utf8_dotenv_is_a_config_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: a Latin-1 .env (a password with 'ä' saved by a Windows editor) raises a raw
    ``UnicodeDecodeError``."""
    dotenv = tmp_path / "latin1.env"
    password = "P\N{LATIN SMALL LETTER A WITH DIAERESIS}sswort-Fake-77"
    dotenv.write_bytes(f"ARGUS_DATABASE__PASSWORD={password}\n".encode("latin-1"))
    exc = _config_error(lambda: load_settings(write_config(""), env_file=dotenv))
    assert "sswort-Fake-77" not in str(exc)


def test_cli_does_not_echo_a_secret_pasted_on_its_own_dotenv_line(
    write_config, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    """DEFECT (secret leak): a padded base64 secret that lands on the line after its key is read
    by python-dotenv as ``<secret-prefix>=<padding>``; every non-field .env name is reported as an
    "unknown setting", so the secret is printed (lower-cased) to stderr."""
    (tmp_path / ".env").write_text(f"ARGUS_DATABASE__PASSWORD=\n{PASTED_SECRET}\n")
    path = write_config("history:\n  window: 4d\n")
    result = runner.invoke(app, ["config", "validate", "-c", str(path)])
    printed = (result.output + result.stderr).lower()
    assert PASTED_SECRET.rstrip("=").lower() not in printed


def test_non_argus_variables_in_shared_dotenv_are_ignored(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """DEFECT: .env is shared with docker compose, yet any non-ARGUS variable in it (here
    ``COMPOSE_PROJECT_NAME``) is rejected as "unknown setting (check the spelling)". The same
    variable in the real environment is (correctly) ignored."""
    dotenv = tmp_path / "shared.env"
    dotenv.write_text("COMPOSE_PROJECT_NAME=argus\nARGUS_HISTORY__WINDOW=30d\n")
    settings = load_settings(write_config(""), env_file=dotenv)
    assert settings.history.window == timedelta(days=30)


# =========================================================================== LOCK-IN: YAML file


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"\xef\xbb\xbfhistory:\n  window: 30d\n", id="utf8-bom"),
        pytest.param(b"history:\r\n  window: 30d\r\n", id="crlf"),
        pytest.param(b"history:\r  window: 30d\r", id="cr-only"),
        pytest.param(b"---\nhistory:\n  window: 30d\n...\n", id="explicit-document-markers"),
    ],
)
def test_yaml_from_other_editors_loads(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "argus.yaml"
    path.write_bytes(raw)
    assert load_settings(path, env_file=None).history.window == timedelta(days=30)


@pytest.mark.parametrize(
    ("text", "line"),
    [
        pytest.param(
            "history:\n  window: 30d\n---\nhistory:\n  window: 5d\n", 3, id="second-document"
        ),
        pytest.param("history:\n\twindow: 30d\n", 2, id="tab-indentation"),
    ],
)
def test_yaml_structure_errors_name_their_line(write_config, text: str, line: int) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match=rf"not valid YAML \(line {line}, column \d+\)"):
        load_settings(write_config(text), env_file=None)


def test_python_tags_are_refused_without_side_effects(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    marker = tmp_path / "constructed-by-yaml"
    path = write_config(f'history: !!python/object/apply:os.mkdir ["{marker}"]\n')
    with pytest.raises(ConfigError, match=r"not valid YAML \(line 1, column \d+\)"):
        load_settings(path, env_file=None)
    assert not marker.exists()


def test_alias_bomb_is_rejected_quickly(write_config) -> None:  # type: ignore[no-untyped-def]
    lines = ['a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]']
    previous = "a"
    for name in "bcdefghi":  # 9**9 leaves if anything ever expanded the aliases
        lines.append(f"{name}: &{name} [" + ", ".join([f"*{previous}"] * 9) + "]")
        previous = name
    path = write_config("\n".join(lines) + "\nhistory:\n  window: *i\n")
    started = time.monotonic()
    with pytest.raises(ConfigError) as info:
        load_settings(path, env_file=None)
    assert time.monotonic() - started < 2
    assert "history.window" in str(info.value)
    assert len(str(info.value)) < 2000


def test_recursive_alias_is_rejected_cleanly(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("history: &h\n  window: 5d\n  again: *h\n")
    with pytest.raises(ConfigError, match=r"history\.again: unknown setting"):
        load_settings(path, env_file=None)


def test_merge_keys_do_not_bypass_unknown_key_checks(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("history: &h\n  window: 30d\nlogging:\n  <<: *h\n")
    with pytest.raises(ConfigError, match=r"logging\.window: unknown setting"):
        load_settings(path, env_file=None)


@pytest.mark.parametrize(
    ("text", "where"),
    [
        pytest.param("history: [5d]\n", "history", id="list"),
        pytest.param("history: 30d\n", "history", id="shorthand-scalar"),
        pytest.param("logging: DEBUG\n", "logging", id="logging-shorthand"),
        pytest.param("database: postgresql://argus@localhost/argus\n", "database", id="dsn"),
    ],
)
def test_wrong_section_types_name_their_section(write_config, text: str, where: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match=rf"\n  - {where}: "):
        load_settings(write_config(text), env_file=None)


@pytest.mark.parametrize(
    ("text", "section"),
    [
        pytest.param("history:\n", "history", id="no-value"),
        pytest.param("history: null\n", "history", id="explicit-null"),
        pytest.param("database: ~\n", "database", id="tilde"),
        pytest.param("logging:\n  # level: DEBUG\n", "logging", id="all-keys-commented-out"),
    ],
)
def test_empty_section_is_defaults_or_an_error_naming_it(  # type: ignore[no-untyped-def]
    write_config, text: str, section: str
) -> None:
    """Either reading is defensible; an unhandled exception or an unnamed error is not."""
    outcome: object
    try:
        outcome = load_settings(write_config(text), env_file=None)
    except ConfigError as exc:
        outcome = exc
    if isinstance(outcome, ConfigError):
        assert f"\n  - {section}: " in str(outcome)
    else:
        loaded = getattr(outcome, section)
        assert loaded == type(loaded)()


# =========================================================================== LOCK-IN: durations


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("\N{FULLWIDTH DIGIT THREE}\N{FULLWIDTH DIGIT ZERO}d", id="fullwidth"),
        pytest.param("\N{ARABIC-INDIC DIGIT THREE}\N{ARABIC-INDIC DIGIT ZERO}d", id="arabic-indic"),
        pytest.param("\N{DEVANAGARI DIGIT THREE}\N{DEVANAGARI DIGIT ZERO}d", id="devanagari"),
        pytest.param("3\N{SUPERSCRIPT TWO}d", id="superscript"),
        pytest.param("\N{MATHEMATICAL BOLD DIGIT THREE}d", id="mathematical-bold"),
    ],
)
@pytest.mark.parametrize("source", ["yaml", "dotenv", "env"])
def test_unicode_digits_in_window_are_rejected_from_every_source(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch, value: str, source: str
) -> None:
    path = write_config(f"history:\n  window: '{value}'\n" if source == "yaml" else "")
    dotenv = None
    if source == "dotenv":
        dotenv = tmp_path / "unicode.env"
        dotenv.write_text(f"ARGUS_HISTORY__WINDOW={value}\n", encoding="utf-8")
    if source == "env":
        monkeypatch.setenv("ARGUS_HISTORY__WINDOW", value)
    with pytest.raises(ConfigError, match=r"history\.window: Value error, invalid duration"):
        load_settings(path, env_file=dotenv)


# =========================================================================== LOCK-IN: env and .env


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"export ARGUS_HISTORY__WINDOW=30d\n", id="export-prefix"),
        pytest.param(b'ARGUS_HISTORY__WINDOW="30d"\n', id="double-quotes"),
        pytest.param(b"ARGUS_HISTORY__WINDOW='30d'\n", id="single-quotes"),
        pytest.param(b"ARGUS_HISTORY__WINDOW=30d # thirty days\n", id="inline-comment"),
        pytest.param(b"ARGUS_HISTORY__WINDOW=30d\r\n", id="crlf"),
        pytest.param(b"\xef\xbb\xbfARGUS_HISTORY__WINDOW=30d\n", id="utf8-bom"),
        pytest.param(b"  ARGUS_HISTORY__WINDOW = 30d  \n", id="spaces-around-equals"),
        pytest.param(b"# comment\nARGUS_HISTORY__WINDOW=30d", id="no-trailing-newline"),
    ],
)
def test_common_dotenv_syntax_variants_load(write_config, tmp_path: Path, raw: bytes) -> None:  # type: ignore[no-untyped-def]
    dotenv = tmp_path / "variant.env"
    dotenv.write_bytes(raw)
    assert load_settings(write_config(""), env_file=dotenv).history.window == timedelta(days=30)


def test_json_section_env_var_is_supported_and_still_strict(write_config, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = write_config("")
    monkeypatch.setenv("ARGUS_HISTORY", '{"window": "30d"}')
    assert load_settings(path, env_file=None).history.window == timedelta(days=30)
    monkeypatch.setenv("ARGUS_HISTORY", '{"windw": "30d"}')
    with pytest.raises(ConfigError, match=r"history\.windw: unknown setting"):
        load_settings(path, env_file=None)


@pytest.mark.parametrize("password", ['{"a": 1}', "123456", '["x"]', "null", "true", " padded "])
def test_password_that_looks_like_json_is_kept_verbatim(  # type: ignore[no-untyped-def]
    write_config, monkeypatch, password: str
) -> None:
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", password)
    secret = load_settings(write_config(""), env_file=None).database.password
    assert secret is not None
    assert secret.get_secret_value() == password


def test_whitespace_around_env_port_is_tolerated_but_inner_space_is_not(  # type: ignore[no-untyped-def]
    write_config, monkeypatch
) -> None:
    path = write_config("")
    monkeypatch.setenv("ARGUS_DATABASE__PORT", " 6543 ")
    assert load_settings(path, env_file=None).database.port == 6543
    monkeypatch.setenv("ARGUS_DATABASE__PORT", "65 43")
    with pytest.raises(ConfigError, match=r"database\.port: "):
        load_settings(path, env_file=None)


def test_precedence_is_resolved_per_key_across_all_four_sources(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch
) -> None:
    path = write_config(
        "environment: test\n"
        "history:\n  window: 2d\n"
        "database:\n  name: from_yaml\n  pool_size: 2\n  max_overflow: 2\n"
        "logging:\n  level: ERROR\n"
    )
    dotenv = tmp_path / "layered.env"
    dotenv.write_text(
        "ARGUS_HISTORY__WINDOW=3d\nARGUS_DATABASE__POOL_SIZE=3\n"
        "ARGUS_DATABASE__MAX_OVERFLOW=3\nARGUS_LOGGING__LEVEL=WARNING\n"
    )
    monkeypatch.setenv("ARGUS_HISTORY__WINDOW", "4d")
    monkeypatch.setenv("ARGUS_DATABASE__POOL_SIZE", "4")

    settings = load_settings(path, env_file=dotenv, history={"window": "6d"})

    assert settings.history.window == timedelta(days=6)  # override
    assert settings.database.pool_size == 4  # environment
    assert settings.database.max_overflow == 3  # .env
    assert settings.logging.level == "WARNING"  # .env
    assert settings.database.name == "from_yaml"  # YAML
    assert settings.environment == "test"  # YAML
    assert settings.database.port == 55432  # default


def test_secret_under_misspelled_key_is_never_echoed_from_any_source(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch
) -> None:
    path = write_config(f"database:\n  pasword: {FAKE_SECRET}\n")
    dotenv = tmp_path / "typo.env"
    dotenv.write_text(f"ARGUS_DATABASE__PASSWROD={FAKE_SECRET}\n")
    monkeypatch.setenv("ARGUS_DATABASE", json.dumps({"passwd": FAKE_SECRET}))
    with pytest.raises(ConfigError) as info:
        load_settings(path, env_file=dotenv, database={"pass_word": FAKE_SECRET})
    message = str(info.value)
    assert FAKE_SECRET not in message
    for location in ("pasword", "passwd", "pass_word"):
        assert f"database.{location}: unknown setting" in message
    # An unknown .env name is shown by its line only (D-037): it may hold a value typed
    # without "=".
    assert "an ARGUS_ variable in typo.env line 1 is not a known setting" in message
    assert "PASSWROD" not in message


# =========================================================================== LOCK-IN: config path


@pytest.mark.parametrize("kind", ["directory", "broken-symlink", "symlink", "relative"])
def test_argus_config_path_variants(tmp_path: Path, monkeypatch, kind: str) -> None:  # type: ignore[no-untyped-def]
    real = tmp_path / "real.yaml"
    real.write_text("history:\n  window: 7d\n")
    if kind == "directory":
        target = str(tmp_path)
    elif kind == "broken-symlink":
        (tmp_path / "broken.yaml").symlink_to(tmp_path / "nowhere.yaml")
        target = str(tmp_path / "broken.yaml")
    elif kind == "symlink":
        (tmp_path / "link.yaml").symlink_to(real)
        target = str(tmp_path / "link.yaml")
    else:
        target = "real.yaml"  # the unit-test cwd is tmp_path
    monkeypatch.setenv(CONFIG_ENV_VAR, target)

    if kind == "directory":
        with pytest.raises(ConfigError, match="cannot read config file"):
            load_settings(env_file=None)
    elif kind == "broken-symlink":
        with pytest.raises(ConfigError, match="config file not found"):
            load_settings(env_file=None)
    else:
        assert load_settings(env_file=None).history.window == timedelta(days=7)


def test_cli_config_option_beats_argus_config_env(tmp_path: Path) -> None:
    from_env = tmp_path / "from-env.yaml"
    from_env.write_text("history:\n  window: 7d\n")
    from_flag = tmp_path / "from-flag.yaml"
    from_flag.write_text("history:\n  window: 9d\n")
    result = runner.invoke(
        app, ["config", "show", "--config", str(from_flag)], env={CONFIG_ENV_VAR: str(from_env)}
    )
    assert result.exit_code == 0, result.output
    assert f"file: {from_flag};" in result.output
    assert "window: 9d" in result.output


# =========================================================================== LOCK-IN: immutability


def test_settings_reject_attribute_deletion_and_new_attributes(write_config) -> None:  # type: ignore[no-untyped-def]
    settings = load_settings(write_config(""), env_file=None)
    with pytest.raises(ValidationError):
        del settings.environment
    with pytest.raises(ValidationError):
        del settings.history.window
    with pytest.raises(ValidationError):
        settings.surprise = 1  # type: ignore[attr-defined]
    assert settings.environment == "dev"
    assert settings.history.window == timedelta(days=5)
