"""Configuration sources: the safeguards of argus.config.sources and the limits that keep loading
fast. Every secret here is synthetic."""

from __future__ import annotations

import difflib
import io
import os
import subprocess
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable, Iterable
from datetime import timedelta
from pathlib import Path
from typing import NoReturn

import pytest
from dotenv import main as dotenv_main
from dotenv.parser import parse_stream
from dotenv.variables import Literal, Variable, parse_variables

from argus.config import ConfigError, Settings, load_settings, sources
from argus.config.settings import CONFIG_ENV_VAR
from argus.config.sources import (
    MAX_FILE_BYTES,
    MAX_YAML_INT_CHARS,
    MAX_YAML_KEYS,
    environment_layer,
)
from tests.conftest import cpu_limit

FAKE_SECRET = "Fake-Src-Secret-4q8z"


def _config_error(load: Callable[[], object]) -> ConfigError:
    """Run ``load`` and return the ConfigError it raised; fail on success or on any other error."""
    try:
        result = load()
    except ConfigError as exc:
        return exc
    except Exception as exc:
        pytest.fail(f"expected ConfigError, but {type(exc).__name__} escaped: {exc}")
    pytest.fail(f"expected ConfigError, but loading succeeded: {result!r}")


def _dotenv(tmp_path: Path, text: str, name: str = "test.env") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- ARGUS_ names


@pytest.mark.parametrize(
    ("name", "suggestion"),
    [
        ("ARGUS_HISTORY_WINDOW", "ARGUS_HISTORY__WINDOW"),
        ("ARGUS_ENVIRONEMNT", "ARGUS_ENVIRONMENT"),
    ],
)
@pytest.mark.parametrize("source", ["environment", "dotenv"])
def test_misspelled_argus_variable_is_an_error_with_a_suggestion(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch, source: str, name: str, suggestion: str
) -> None:
    env_file = None
    if source == "environment":
        monkeypatch.setenv(name, FAKE_SECRET)
    else:
        env_file = _dotenv(tmp_path, f"{name}={FAKE_SECRET}\n")
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=env_file)))
    if source == "environment":
        assert f"environment variable {name} is not a known setting" in message
    else:  # an unknown .env name may hold a value typed without "=": only its line is shown
        assert "an ARGUS_ variable in test.env line 1 is not a known setting" in message
        assert name not in message
    assert f"did you mean {suggestion}?" in message
    assert FAKE_SECRET not in message


def test_variables_without_the_argus_prefix_are_ignored_and_never_named(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch
) -> None:
    """The environment and .env are shared: other tools' variables (the corpus capture script's
    SIEM_CAPTURE_*, docker compose's) are not settings, are not errors and are never printed."""
    others = {
        "SIEM_CAPTURE_USER": "fake-capture-user",
        "SIEM_CAPTURE_PASSWORD": FAKE_SECRET,
        "COMPOSE_PROJECT_NAME": "fake-compose-project",
        "MY_ARGUS_HISTORY__WINDOW": "fake-window-1",
        "ARGUSHISTORY__WINDOW": "fake-window-2",
    }
    for name, value in others.items():
        monkeypatch.setenv(name, value)
    dotenv = _dotenv(
        tmp_path,
        "".join(f"{name}={value}\n" for name, value in others.items())
        + "REPLICA_ELASTIC_PASSWORD=fake-replica-pw\nARGUS_HISTORY__WINDOW=30d\n",
    )
    path = write_config("")
    assert load_settings(path, env_file=dotenv).history.window == timedelta(days=30)

    monkeypatch.setenv("ARGUS_DATABASE__PORT", "not-a-port")  # any error: the report is printed
    message = str(_config_error(lambda: load_settings(path, env_file=dotenv)))
    assert "database.port" in message
    for name, value in [*others.items(), ("REPLICA_ELASTIC_PASSWORD", "fake-replica-pw")]:
        assert name not in message
        assert value not in message


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(f"'ARGUS_DATABASE__PASSWORD\n{FAKE_SECRET}'=x\n", id="name-over-two-lines"),
        pytest.param(f"'ARGUS_DATABASE__PASSWORD {FAKE_SECRET}'=x\n", id="name-with-a-space"),
        pytest.param(f"'OTHER\n{FAKE_SECRET}'=x\n", id="other-tools-name"),
    ],
)
def test_quoted_dotenv_name_with_spaces_is_a_parse_error_that_shows_no_text(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, text: str
) -> None:
    """python-dotenv reads 'A B'=x as the name "A B"; a stray quote makes the name run over the
    next lines, and printing that name printed whatever those lines held."""
    dotenv = _dotenv(tmp_path, text)
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=dotenv)))
    assert f"cannot parse env file {dotenv} (line 1): write each setting as NAME=value" in message
    assert FAKE_SECRET not in message
    assert FAKE_SECRET.lower() not in message


# --------------------------------------------------------------------------- repeated variables


@pytest.mark.parametrize(
    "lines",
    [
        pytest.param("ARGUS_HISTORY__WINDOW=30d\nARGUS_HISTORY__WINDOW=4d\n", id="same-spelling"),
        pytest.param("ARGUS_HISTORY__WINDOW=30d\nargus_history__window=4d\n", id="two-spellings"),
    ],
)
def test_variable_set_twice_in_dotenv_is_an_error(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, lines: str
) -> None:
    dotenv = _dotenv(tmp_path, lines)
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=dotenv)))
    assert "test.env line 1 and " in message
    assert "test.env line 2 set the same setting; keep one" in message


def test_two_spellings_of_one_variable_in_the_environment_are_an_error(  # type: ignore[no-untyped-def]
    write_config, monkeypatch
) -> None:
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", FAKE_SECRET)
    monkeypatch.setenv("argus_database__password", FAKE_SECRET + "-other")
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=None)))
    assert "environment variable ARGUS_DATABASE__PASSWORD and" in message
    assert "environment variable argus_database__password set the same setting" in message
    assert FAKE_SECRET not in message


def test_a_repeated_variable_is_reported_even_when_one_line_has_no_value(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path
) -> None:
    """Each line keeps its own value: line 1 has one, so only the repeat is reported
    (python-dotenv's dict holds only the last line's value, which made line 1 look empty)."""
    dotenv = _dotenv(tmp_path, "ARGUS_HISTORY__WINDOW=30d\nARGUS_HISTORY__WINDOW\n")
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=dotenv)))
    assert "test.env line 2 set the same setting; keep one" in message
    assert "line 1 has no value" not in message


# --------------------------------------------------------------------------- ARGUS_CONFIG, no value


@pytest.mark.parametrize("name", ["ARGUS_CONFIG", "argus_config"])
def test_config_path_variable_in_dotenv_is_an_error(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, name: str
) -> None:
    other = write_config("history:\n  window: 9d\n", name="other.yaml")
    dotenv = _dotenv(tmp_path, f"{name}={other}\n")
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=dotenv)))
    assert f"{name} in test.env line 1 is not used: choose the config file with --config" in message


def test_lowercase_config_variable_in_the_environment_is_reported(  # type: ignore[no-untyped-def]
    write_config, monkeypatch
) -> None:
    other = write_config("history:\n  window: 9d\n", name="other.yaml")
    monkeypatch.setenv("argus_config", str(other))
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=None)))
    assert (
        f"environment variable argus_config is ignored: the config file variable is spelled"
        f" {CONFIG_ENV_VAR}" in message
    )


def test_argus_line_without_equals_sign_is_an_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dotenv = _dotenv(tmp_path, "# a comment\nARGUS_DATABASE__PASSWORD\n")
    message = str(_config_error(lambda: load_settings(write_config(""), env_file=dotenv)))
    expected = "ARGUS_DATABASE__PASSWORD in test.env line 2 has no value (expected NAME=value)"
    assert expected in message


def test_argus_line_with_an_empty_value_is_an_empty_value(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dotenv = _dotenv(tmp_path, "ARGUS_DATABASE__PASSWORD=\n")
    password = load_settings(write_config(""), env_file=dotenv).database.password
    assert password is not None
    assert password.get_secret_value() == ""


# --------------------------------------------------------------------------- file size


def test_config_file_of_exactly_the_size_limit_loads(tmp_path: Path) -> None:
    path = tmp_path / "argus.yaml"
    body = "history:\n  window: 30d\n"
    path.write_bytes(body.encode() + b"#" * (MAX_FILE_BYTES - len(body) - 1) + b"\n")
    assert path.stat().st_size == MAX_FILE_BYTES
    assert load_settings(path, env_file=None).history.window == timedelta(days=30)


@pytest.mark.parametrize("kind", ["config file", "env file"])
def test_file_over_the_size_limit_is_refused(write_config, tmp_path: Path, kind: str) -> None:  # type: ignore[no-untyped-def]
    big = tmp_path / "big"
    big.write_bytes(b"#" * MAX_FILE_BYTES + b"\n")
    if kind == "config file":
        exc = _config_error(lambda: load_settings(big, env_file=None))
    else:
        exc = _config_error(lambda: load_settings(write_config(""), env_file=big))
    assert f"{kind} {big} is larger than 1024 KiB" in str(exc)


# --------------------------------------------------------------------------- not a regular file


def _without_blocking(load: Callable[[], object], unblock: Callable[[], None]) -> object:
    """``load()``'s result or exception; fails the test if it is still waiting after 5 s."""
    outcome: list[object] = []

    def run() -> None:
        try:
            outcome.append(load())
        except BaseException as exc:  # handed over to the test's thread
            outcome.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=5)
    if thread.is_alive():
        unblock()
        thread.join(timeout=5)
        pytest.fail("loading waited for input from a file that is not a regular file")
    return outcome[0]


def _open_fifo_writer(fifo: Path) -> None:
    os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))  # a blocked reader gets end of file


@pytest.mark.parametrize("kind", ["config file", "env file"])
def test_fifo_is_refused_without_waiting_for_a_writer(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, kind: str
) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    if kind == "config file":
        outcome = _without_blocking(
            lambda: load_settings(fifo, env_file=None), lambda: _open_fifo_writer(fifo)
        )
    else:
        config = write_config("")
        outcome = _without_blocking(
            lambda: load_settings(config, env_file=fifo), lambda: _open_fifo_writer(fifo)
        )
    assert isinstance(outcome, ConfigError), repr(outcome)
    assert f"cannot read {kind} {fifo}: it is not a regular file" in str(outcome)


def test_pipe_given_as_the_config_path_is_refused_without_waiting() -> None:
    """/dev/stdin is often an open pipe like this one: reading it would wait for its writer."""
    read_end, write_end = os.pipe()
    writer_open = [True]

    def close_writer() -> None:  # the waiting reader then gets end of file
        os.close(write_end)
        writer_open[0] = False

    try:
        outcome = _without_blocking(
            lambda: load_settings(Path(f"/dev/fd/{read_end}"), env_file=None), close_writer
        )
    finally:
        os.close(read_end)
        if writer_open[0]:
            os.close(write_end)
    assert isinstance(outcome, ConfigError), repr(outcome)
    assert f"cannot read config file /dev/fd/{read_end}: it is not a regular file" in str(outcome)


def test_cli_refuses_dev_stdin_as_the_config_file_without_waiting(tmp_path: Path) -> None:
    read_end, write_end = os.pipe()  # stdin stays open and empty, as at an interactive prompt
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from argus.cli import main; main()",
                "config",
                "validate",
                "--config",
                "/dev/stdin",
            ],
            stdin=read_end,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path,
            check=False,
        )
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result.returncode == 2, result.stderr
    assert "cannot read config file /dev/stdin: it is not a regular file" in result.stderr


@pytest.mark.parametrize("device", ["/dev/null", "/dev/zero"])
def test_device_is_refused_as_a_config_file(device: str) -> None:
    exc = _config_error(lambda: load_settings(Path(device), env_file=None))
    assert f"cannot read config file {device}: it is not a regular file" in str(exc)


def test_directory_given_as_the_env_file_is_an_error(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    exc = _config_error(lambda: load_settings(write_config(""), env_file=tmp_path))
    assert f"cannot read env file {tmp_path}: it is a directory" in str(exc)


def test_symlinked_env_file_is_read(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    target = _dotenv(tmp_path, "ARGUS_HISTORY__WINDOW=30d\n", name="real.env")
    (tmp_path / "link.env").symlink_to(target)
    settings = load_settings(write_config(""), env_file=tmp_path / "link.env")
    assert settings.history.window == timedelta(days=30)


def test_dangling_env_file_symlink_means_no_env_file(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "dangling.env").symlink_to(tmp_path / "missing.env")
    settings = load_settings(write_config(""), env_file=tmp_path / "dangling.env")
    assert settings.history.window == timedelta(days=5)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can enter any directory")
def test_env_file_in_a_directory_that_cannot_be_entered(write_config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Path.is_file() raises PermissionError here instead of answering; it must be a ConfigError."""
    locked = tmp_path / "locked"
    locked.mkdir()
    env_file = _dotenv(locked, f"ARGUS_DATABASE__PASSWORD={FAKE_SECRET}\n", name=".env")
    config = write_config("")
    locked.chmod(0o600)  # no search permission: nothing inside can be reached
    try:
        exc = _config_error(lambda: load_settings(config, env_file=env_file))
    finally:
        locked.chmod(0o700)
    assert f"cannot read env file {env_file}: Permission denied" in str(exc)


# --------------------------------------------------------------------------- YAML limits


# CPU time of this process (R2 gate): wall time is unreliable on a shared machine; limits
# allow for coverage tracing (cpu_limit).
def _measured(load: Callable[[], object]) -> tuple[ConfigError, float, int]:
    """The ConfigError ``load`` raised, the seconds it took and its peak Python memory in bytes."""
    tracemalloc.start()
    try:
        started = time.process_time()
        exc = _config_error(load)
        elapsed = time.process_time() - started
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return exc, elapsed, peak


def _anchor(keys: int) -> str:
    return "a: &a {" + ", ".join(f"k{i}: {i}" for i in range(keys)) + "}\n"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            _anchor(3000) + "history:\n  <<: [" + ", ".join(["*a"] * 3000) + "]\n",
            id="one-merge-of-many-aliases",
        ),
        pytest.param(_anchor(3000) + "history:\n" + "  <<: *a\n" * 2000, id="many-merge-keys"),
        pytest.param(
            _anchor(1000) + "".join(f"b{i}: {{<<: *a}}\n" for i in range(40)),
            id="many-mappings-merging-one-anchor",
        ),
    ],
)
def test_merges_stop_at_the_key_limit_before_copying(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    """Merges copy keys (aliases do not), so a file of a few dozen KiB could ask for millions of
    keys. The limit is checked before each copy: the error comes at once, with little memory."""
    path = write_config(text)
    exc, elapsed, peak = _measured(lambda: load_settings(path, env_file=None))
    assert f"more than {MAX_YAML_KEYS} keys, counting the keys that '<<' merges copy" in str(exc)
    assert elapsed < cpu_limit(5)
    assert peak < 50 * 1024 * 1024


def test_key_limit_counts_keys_without_merges_too(write_config) -> None:  # type: ignore[no-untyped-def]
    text = "".join(f"k{i}: {i}\n" for i in range(MAX_YAML_KEYS + 1))
    exc = _config_error(lambda: load_settings(write_config(text), env_file=None))
    assert f"more than {MAX_YAML_KEYS} keys" in str(exc)


@pytest.mark.parametrize(
    ("text", "window"),
    [
        pytest.param("history:\n  <<: {window: 30d}\n", 30, id="inline-merge"),
        pytest.param("history:\n  <<: {window: 30d}\n  window: 4d\n", 4, id="own-key-wins"),
        pytest.param("history:\n  <<: [{window: 1d}, {window: 2d}]\n", 1, id="first-listed-wins"),
        pytest.param("history:\n  window: 9d\n  <<: {}\n", 9, id="empty-merge"),
        pytest.param(
            "history:\n  <<: {window: 1d}\n  <<: {window: 2d}\n", 2, id="later-merge-key-wins"
        ),
    ],
)
def test_merges_keep_pyyaml_semantics(write_config, text: str, window: int) -> None:  # type: ignore[no-untyped-def]
    assert load_settings(write_config(text), env_file=None).history.window == timedelta(days=window)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("history:\n  <<: 5d\n", id="scalar"),
        pytest.param("history:\n  <<: [{window: 1d}, 5d]\n", id="scalar-in-list"),
    ],
)
def test_merging_something_other_than_a_mapping_is_a_yaml_error(write_config, text: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match=r"not valid YAML \(line 2, column \d+\): '<<' merges"):
        load_settings(write_config(text), env_file=None)


def test_duplicate_key_written_through_an_alias_is_an_error(write_config) -> None:  # type: ignore[no-untyped-def]
    """`*w` is the same node as the key `&w window`, so comparing nodes missed the repeat."""
    path = write_config("history:\n  &w window: 30d\n  *w : 2d\n")
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert "duplicate key 'window' (repeated in this mapping through an alias)" in str(exc)


def test_alias_of_a_key_used_in_another_mapping_is_not_a_duplicate(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("database:\n  &n name: argus_x\n  <<: {*n : ignored, user: u}\n")
    database = load_settings(path, env_file=None).database
    assert (database.name, database.user) == ("argus_x", "u")


def test_long_base_60_integer_fails_fast(write_config) -> None:  # type: ignore[no-untyped-def]
    """YAML 1.1 reads 1:30 as 90; PyYAML converts such a number in quadratic time (seconds for a
    few hundred KiB), so integers are capped at CPython's own limit of 4300 digits."""
    path = write_config("database:\n  port: 1" + ":1" * 150_000 + "\n")
    started = time.monotonic()
    exc = _config_error(lambda: load_settings(path, env_file=None))
    assert time.monotonic() - started < 2
    expected = f"(line 2, column 9): an integer of more than {MAX_YAML_INT_CHARS} characters"
    assert expected in str(exc)


def test_short_base_60_integer_still_loads(write_config) -> None:  # type: ignore[no-untyped-def]
    path = write_config("database:\n  port: 1:30\n")
    assert load_settings(path, env_file=None).database.port == 90


# --------------------------------------------------------------------------- PyYAML messages


@pytest.mark.parametrize(
    ("text", "hint"),
    [
        pytest.param(f"database:\n  password: !{FAKE_SECRET}\n", "'!'", id="tag"),
        pytest.param(f"database:\n  password: !{FAKE_SECRET}!x\n", "'!'", id="tag-handle"),
        pytest.param(f"database:\n  password: !!{FAKE_SECRET}\n", "'!'", id="secondary-tag-handle"),
        pytest.param(f"database:\n  password: *{FAKE_SECRET}\n", "'*'", id="alias"),
        pytest.param(
            f"database:\n  password: &{FAKE_SECRET} x\n  user: &{FAKE_SECRET} y\n",
            "'&'",
            id="duplicate-anchor",
        ),
    ],
)
def test_yaml_errors_never_show_the_value_pyyaml_quotes(write_config, text: str, hint: str) -> None:  # type: ignore[no-untyped-def]
    """An unquoted password starting with '!', '*' or '&' is read as a tag, alias or anchor, and
    PyYAML repeats that name in its error message."""
    message = str(_config_error(lambda: load_settings(write_config(text), env_file=None)))
    assert "not valid YAML (line " in message
    assert FAKE_SECRET not in message
    assert "(not shown)" in message
    assert f"a value that starts with {hint} must be quoted" in message


def test_angle_brackets_alone_do_not_make_a_value_look_like_a_token_name(write_config) -> None:  # type: ignore[no-untyped-def]
    """The verbatim tag !<%3C...%3E> becomes '<fake secret words>', shaped like '<block end>'."""
    path = write_config("database:\n  password: !<%3Cfake%20secret%20words%3E>\n")
    message = str(_config_error(lambda: load_settings(path, env_file=None)))
    assert "fake secret words" not in message
    assert "the tag (not shown)" in message


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        pytest.param("history: [5d\n", "'<stream end>'", id="token-name"),
        pytest.param("history:\n  window: 5d\n bad: x\n", "'<block mapping start>'", id="block"),
        pytest.param("history:\n  window: 5d\n  - x\n", "'-'", id="one-character"),
    ],
)
def test_yaml_errors_keep_token_names_and_single_characters(  # type: ignore[no-untyped-def]
    write_config, text: str, shown: str
) -> None:
    message = str(_config_error(lambda: load_settings(write_config(text), env_file=None)))
    assert shown in message
    assert "(not shown)" not in message


def test_a_bug_in_the_loader_is_not_reported_as_invalid_yaml(  # type: ignore[no-untyped-def]
    write_config, monkeypatch
) -> None:
    """Only YAML errors become "not valid YAML"; anything else is a bug and must stay visible."""

    def broken(root: object) -> None:
        raise KeyError("bug in the loader")

    monkeypatch.setattr(sources, "_reject_duplicate_keys", broken)
    with pytest.raises(KeyError, match="bug in the loader"):
        load_settings(write_config("history:\n  window: 5d\n"), env_file=None)


# --------------------------------------------------------------------------- .env cost


def test_long_env_file_with_variable_references_loads_in_linear_time(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch
) -> None:
    """python-dotenv's dotenv_values copies the environment for every line (quadratic time), and
    its parse_variables rescans a value from every unclosed "${". Neither may be used: a time
    limit alone would let a fast machine hide the return of either (tests/unit/config/
    test_dotenv_cost.py also compares the time for 8 times the lines)."""

    def slow_path(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("python-dotenv's variable expansion was used")

    monkeypatch.setattr(dotenv_main, "resolve_variables", slow_path)  # under dotenv_values
    monkeypatch.setattr(Variable, "resolve", slow_path)  # parse_variables' results, however
    monkeypatch.setattr(Literal, "resolve", slow_path)  # parse_variables was imported
    monkeypatch.setenv("TEST_BASE", "5")
    lines = "".join(f"OTHER_{i}=${{TEST_BASE}}{i}\n" for i in range(20_000))
    dotenv = _dotenv(tmp_path, lines + "ARGUS_HISTORY__WINDOW=${OTHER_7}d\n")
    started = time.monotonic()
    settings = load_settings(write_config(""), env_file=dotenv)
    assert time.monotonic() - started < 3
    assert settings.history.window == timedelta(days=57)


def test_suggestions_are_worked_out_for_the_first_unknown_names_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Each "did you mean" compares the name with every setting; a file of thousands of unknown
    ARGUS_ lines took seconds. A report shows 50 problems, so later names get no suggestion."""
    calls: list[str] = []
    close_matches = difflib.get_close_matches

    def counted(word: str, names: Iterable[str], n: int = 3, cutoff: float = 0.6) -> list[str]:
        calls.append(word)
        return close_matches(word, names, n, cutoff)

    monkeypatch.setattr(difflib, "get_close_matches", counted)  # the module sources.py calls
    environ = {"ARGUS_HISTORY_WINDOW": "30d"}
    environ.update({f"ARGUS_UNKNOWN_{i:04}": "x" for i in range(1000)})
    layer = environment_layer(environ, Settings)
    assert len(layer.problems) == len(environ)
    assert len(calls) == 50
    assert "did you mean ARGUS_HISTORY__WINDOW?" in layer.problems[0]
    assert "is not a known setting; settings are ARGUS_<NAME> or" in layer.problems[-1]


def test_variable_references_in_dotenv_use_earlier_lines_then_the_environment(  # type: ignore[no-untyped-def]
    write_config, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TEST_DB_PORT", "6543")
    dotenv = _dotenv(
        tmp_path,
        "DB=from_file\n"
        "ARGUS_DATABASE__NAME=${DB}_x\n"
        "ARGUS_DATABASE__PORT=${TEST_DB_PORT}\n"
        "ARGUS_DATABASE__USER=${UNSET_TEST_VARIABLE:-fallback}\n",
    )
    database = load_settings(write_config(""), env_file=dotenv).database
    assert (database.name, database.port, database.user) == ("from_file_x", 6543, "fallback")


# --------------------------------------------------------------------------- python-dotenv


def test_python_dotenv_parser_fields_relied_on() -> None:
    """argus.config.sources uses python-dotenv's parser directly and expands variables the way
    python-dotenv does; this pins the fields it reads and the expansion it copies, so an upgrade
    that changes them fails here first."""
    text = "\n# comment\nexport A=1\nB='two words' # note\nC\nD=${A}-${E:-five}\nbroken line\n"
    bindings = list(parse_stream(io.StringIO(text)))
    shape = [(b.key, b.value, b.error, b.original.line) for b in bindings]
    assert shape == [
        (None, None, False, 1),  # blank lines and comments: one binding, counted from its start
        ("A", "1", False, 3),
        ("B", "two words", False, 4),
        ("C", None, False, 5),
        ("D", "${A}-${E:-five}", False, 6),
        (None, None, True, 7),
    ]
    assert bindings[0].original.string == "\n# comment\n"
    assert bindings[2].original.string == "B='two words' # note\n"
    assert list(parse_variables("${A}-${E:-five}")) == [
        Variable(name="A", default=None),
        Literal(value="-"),
        Variable(name="E", default="five"),
    ]
    assert Variable(name="A", default=None).resolve({"A": None}) == ""
