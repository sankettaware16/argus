"""Property tests for configuration loading; they replace fix round 1's one-off fuzz run.

* Whatever the YAML file, ``.env`` file or environment holds, loading either succeeds or raises
  ConfigError, and the error never shows a value: a planted secret may sit in any value
  position, however mangled (a tag, an alias, an anchor, an unterminated quote, ...).
* ARGUS's ``<<`` merging gives what PyYAML's does, and its ``${VAR}`` expansion in ``.env`` gives
  what python-dotenv's does.

Secrets are planted only where a value is written: a name (a YAML key, an ``ARGUS_`` variable)
is shown in errors by design.

Each test runs as many examples as the Hypothesis profile says. tests/conftest.py registers dev
(the default, 100 examples), ci (1,000) and gate (10,000, no deadline); HYPOTHESIS_PROFILE picks
one, e.g. ``HYPOTHESIS_PROFILE=gate uv run pytest tests/unit/config``.
"""

from __future__ import annotations

import contextlib
import io
import os
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest
import yaml
from dotenv import dotenv_values
from dotenv.parser import parse_stream
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.config import ConfigError, Settings, load_settings, sources

SECRET = "Qz7PlantedSecret"  # never a substring of a message, a setting or a file name
NOT_SECRET = st.text(alphabet="abcdefXYZ0189-_.", max_size=6)

# --------------------------------------------------------------------------- YAML documents

SECTION_KEYS = {
    "history": ["window"],
    "database": ["host", "port", "name", "user", "password", "pool_size", "connect_timeout"],
    "logging": ["level", "format"],
}
TOP_KEYS = ["environment", "history", "database", "logging", "passwd", "extra"]
GOOD_VALUES = {
    **{"environment": "prod", "window": "30d", "host": "127.0.0.1", "port": "6543"},
    **{"name": "argus_x", "user": "argus", "password": "'p@ss'", "pool_size": "3"},
    **{"connect_timeout": "5s", "level": "DEBUG", "format": "json", "passwd": "x", "extra": "1"},
}
# How a value may be written. Well-formed values let a file get as far as validation; odd ones
# are read as a tag, an alias or an anchor (PyYAML then quotes them in its message) or break it.
WELL_FORMED = [
    *(("", ""), ("'", "'"), ('"', '"'), ("!!str ", ""), ("[", "]"), ("[1, ", "]")),
    *(("", " #c"), ("&", " x"), ("!!binary ", ""), ("{k: ", "}"), ("|-\n    ", "")),
]
ODD = [
    *(("!", ""), ("!!", ""), ("!<", ">"), ("!x ", ""), ("!", "!x"), ("!a%2", ""), ("*", "")),
    *(("&", ""), ("!!int ", ""), ("!!float ", ""), ("!!timestamp ", ""), ("%", ""), ("@", "")),
    *(("`", ""), ("|", ""), (">", ""), ("- ", ""), ("#", ""), ("'", ""), ('"', ""), ("", "'")),
    *(("", "]"), ("", "\\"), ('"\\x', '"')),
]  # no '{' or '? ' here: a later value could close them and turn the secret into a key
NOISE = [
    *("---", "...", "- x", "[", ":", "*x", "'q'", "\t", "#c", "", "%YAML 1.1", "x: |\n  text"),
    *("anchors: &a {window: 1d, level: INFO}", "merged: {<<: *a}", "k: [1, [2, [3]]]"),
]


@st.composite
def yaml_documents(draw: st.DrawFn) -> str:
    """Sections of 'key: value' lines, a secret in some values. At most one value is written
    oddly and at most one noise line is added, so most files get as far as validation."""
    odd_left = draw(st.integers(0, 1))
    lines = []
    for top in draw(st.lists(st.sampled_from(TOP_KEYS), unique=True, max_size=4)):
        entries = [("", top)]
        if top in SECTION_KEYS:
            keys = [*SECTION_KEYS[top], "passwd", "extra"]
            lines.append(f"{top}:")
            entries = [("  ", key) for key in draw(st.lists(st.sampled_from(keys), unique=True))]
        for indent, key in entries:
            if draw(st.booleans()):
                lines.append(f"{indent}{key}: {GOOD_VALUES[key]}")
                continue
            odd = odd_left > 0 and draw(st.booleans())
            odd_left -= odd
            prefix, suffix = draw(st.sampled_from(ODD if odd else WELL_FORMED))
            value = draw(NOT_SECRET) + SECRET + draw(NOT_SECRET)
            lines.append(f"{indent}{key}: {prefix}{value}{suffix}")
    if draw(st.booleans()):
        lines.insert(draw(st.integers(0, len(lines))), draw(st.sampled_from(NOISE)))
    return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def fuzz_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("config-fuzz")


def _assert_loads_or_fails_without_the_secret(path: Path, env_file: Path | None) -> None:
    message = ""
    try:
        loaded = load_settings(path, env_file=env_file)
    except ConfigError as exc:  # any other exception fails the test
        message = str(exc)
    else:
        assert isinstance(loaded, Settings)
    assert SECRET.lower() not in message.lower()  # names may be shown lower-cased


@given(document=yaml_documents())
@settings(deadline=None)
def test_any_config_file_loads_or_fails_without_showing_a_value(
    fuzz_dir: Path, document: str
) -> None:
    path = fuzz_dir / "argus.yaml"
    path.write_text(document, encoding="utf-8")
    _assert_loads_or_fails_without_the_secret(path, env_file=None)


@given(raw=st.one_of(st.binary(max_size=300), st.text(max_size=300).map(str.encode)))
@settings(deadline=None)
def test_arbitrary_bytes_as_config_file_load_or_fail_with_config_error(
    fuzz_dir: Path, raw: bytes
) -> None:
    path = fuzz_dir / "arbitrary.yaml"
    path.write_bytes(raw)
    with contextlib.suppress(ConfigError):  # any other exception fails the test
        assert isinstance(load_settings(path, env_file=None), Settings)


# --------------------------------------------------------------------------- .env files

ENV_NAMES = [
    *("ARGUS_DATABASE__PASSWORD", "ARGUS_HISTORY__WINDOW", "ARGUS_DATABASE__PORT"),
    *("ARGUS_HISTORY", "ARGUS_DATABASE", "ARGUS_ENVIRONMENT", "ARGUS_CONFIG", "argus_config"),
    *("ARGUS_HISTORY_WINDOW", "ARGUS_DATABASE__PASWORD", "argus_database__password"),
    *("ARGUS_", "ARGUS__X", "OTHER", "COMPOSE_PROJECT_NAME", "export ARGUS_LOGGING__LEVEL"),
]
ENV_VALUE_PREFIXES = ["", "'", '"', "${", "${OTHER:-", "{", '{"password": "', " ", "\\", "="]
ENV_VALUE_SUFFIXES = ["", "'", '"', "}", '"}', " # note", "==", "\\n", " x"]
ENV_NOISE = [
    *("", "# comment", "export ARGUS_HISTORY__WINDOW=5d", "ARGUS_HISTORY__WINDOW", "=x"),
    *("ARGUS_X Y", "A='unterminated", 'B="esc \\n"', "C=${HOME}", "D=${A:-${B}}", "\t"),
    *("ARGUS_DATABASE__PORT=abc", 'ARGUS_HISTORY={"window": "30d"}', "ARGUS_HISTORY={bad"),
    *("ARGUS_HISTORY__WINDOW=30d", "'quoted'=x", "OTHER=1", "ARGUS_LOGGING__LEVEL=DEBUG"),
    *("'ARGUS_DATABASE__PASSWORD", "'ARGUS_HISTORY__", "'OTHER"),  # a quoted name, not ended
]


@st.composite
def env_secret_lines(draw: st.DrawFn) -> str:
    value = draw(NOT_SECRET) + SECRET + draw(NOT_SECRET)
    if draw(st.booleans()):  # pasted on a line of its own; "'=x" ends a quoted name
        return value + draw(st.sampled_from(["", "=", "==", "=x", "'=x", "'"]))
    name = draw(st.sampled_from(ENV_NAMES))
    prefix = draw(st.sampled_from(ENV_VALUE_PREFIXES))
    suffix = draw(st.sampled_from(ENV_VALUE_SUFFIXES))
    return f"{name}={prefix}{value}{suffix}"


env_files = st.lists(st.one_of(st.sampled_from(ENV_NOISE), env_secret_lines()), max_size=10).map(
    lambda lines: "\n".join(lines) + "\n"
)


@given(env_text=env_files)
@settings(deadline=None)
def test_any_env_file_loads_or_fails_without_showing_a_value(fuzz_dir: Path, env_text: str) -> None:
    config = fuzz_dir / "plain.yaml"
    config.write_text("history:\n  window: 5d\n")
    env_file = fuzz_dir / "fuzz.env"
    env_file.write_text(env_text, encoding="utf-8")
    _assert_loads_or_fails_without_the_secret(config, env_file=env_file)


# --------------------------------------------------------------------------- the environment

ENVIRONMENT_NAMES = [name for name in ENV_NAMES if " " not in name] + [
    *("argus_history__window", "Argus_Database__Name", "ARGUS_LOGGING", "SIEM_CAPTURE_PASSWORD"),
]


@st.composite
def environments(draw: st.DrawFn) -> dict[str, str]:
    names = draw(st.lists(st.sampled_from(ENVIRONMENT_NAMES), unique=True, max_size=6))
    values = st.one_of(
        NOT_SECRET,
        st.builds(lambda a, b: a + SECRET + b, NOT_SECRET, NOT_SECRET),
        st.sampled_from(['{"window": "30d"}', "5d", "6543", "null", "{}", "[]"]),
    )
    return {name: draw(values) for name in names}


@given(environment=environments())
@settings(deadline=None)
def test_any_environment_loads_or_fails_without_showing_a_value(
    fuzz_dir: Path, environment: dict[str, str]
) -> None:
    config = fuzz_dir / "plain.yaml"
    config.write_text("history:\n  window: 5d\n")
    with mock.patch.dict(os.environ, environment):
        _assert_loads_or_fails_without_the_secret(config, env_file=None)


# --------------------------------------------------------------------------- merges match PyYAML

KEYS = ["k1", "k2", "k3", "k4"]


@st.composite
def merge_documents(draw: st.DrawFn) -> str:
    """Anchored mappings, each merging earlier ones (or itself) in every form YAML allows."""
    lines = []
    count = draw(st.integers(min_value=1, max_value=6))
    for index in range(count):
        entries = [
            f"{key}: {draw(st.integers(0, 9))}"
            for key in draw(st.lists(st.sampled_from(KEYS), unique=True, max_size=3))
        ]
        earlier = [f"*m{other}" for other in range(index + 1)]  # m{index} merges itself
        for _ in range(draw(st.integers(0, 2))):  # PyYAML accepts '<<' more than once
            form = draw(st.sampled_from(["alias", "list", "inline"]))
            if form == "alias":
                entries.append(f"<<: {draw(st.sampled_from(earlier))}")
            elif form == "list":
                aliases = draw(st.lists(st.sampled_from(earlier), min_size=1, max_size=3))
                entries.append(f"<<: [{', '.join(aliases)}]")
            else:
                entries.append(f"<<: {{{draw(st.sampled_from(KEYS))}: {draw(st.integers(0, 9))}}}")
        order = draw(st.permutations(entries))
        lines.append(f"m{index}: &m{index} {{{', '.join(order)}}}")
    return "\n".join(lines) + "\n"


def _load(text: str, loader: type[yaml.SafeLoader]) -> object:
    return yaml.load(text, Loader=loader)  # noqa: S506 - both loaders are safe loaders


@given(document=merge_documents())
def test_merges_give_what_pyyaml_gives(document: str) -> None:
    assert _load(document, sources._ConfigLoader) == _load(document, yaml.SafeLoader)


# --------------------------------------------------------------------------- .env expansion


ENV_REFERENCES = ["${A}", "${B:-dflt}", "${HOME}", "${UNSET_TEST_VARIABLE}", "$A", "${", "x"]


@st.composite
def expansion_files(draw: st.DrawFn) -> str:
    lines = []
    for _ in range(draw(st.integers(1, 8))):
        name = draw(st.sampled_from(["A", "B", "C"]))
        if draw(st.integers(0, 5)) == 0:
            lines.append(name)  # no value
            continue
        parts = draw(st.lists(st.sampled_from(ENV_REFERENCES), max_size=3))
        quote = draw(st.sampled_from(["", "'", '"']))
        lines.append(f"{name}={quote}{''.join(parts)}{quote}")
    return "\n".join(lines) + "\n"


def _expanded(text: str) -> Iterator[tuple[str, str | None]]:
    bindings = list(parse_stream(io.StringIO(text)))
    for binding, value in zip(bindings, sources._expand_variables(bindings), strict=True):
        if binding.key is not None:
            yield binding.key, value


@given(text=expansion_files())
def test_variable_expansion_gives_what_python_dotenv_gives(text: str) -> None:
    assert dict(_expanded(text)) == dotenv_values(stream=io.StringIO(text))
