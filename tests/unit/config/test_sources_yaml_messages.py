"""The YAML config file: the exact message for each way it can be wrong, and the strict loader's
own rules (duplicate keys, plain-text keys, merges, nesting). A message names the file, the line
and the column, never the value. Every value here is synthetic."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from yaml.reader import ReaderError

from argus.config import ConfigError, Settings, load_settings, sources

FAKE_SECRET = "Fake-Yaml-Secret-3m7w"


def _config_error(load: Callable[[], object]) -> ConfigError:
    """Run ``load`` and return the ConfigError it raised; fail on success or on any other error."""
    try:
        result = load()
    except ConfigError as exc:
        return exc
    except Exception as exc:
        pytest.fail(f"expected ConfigError, but {type(exc).__name__} escaped: {exc}")
    pytest.fail(f"expected ConfigError, but loading succeeded: {result!r}")


def _yaml(tmp_path: Path, text: str, name: str = "argus.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


def _message(path: Path) -> str:
    return str(_config_error(lambda: sources.read_yaml_file(path)))


# ------------------------------------------------------------------- values a tag cannot build


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        pytest.param("!!bool maybe", "true/false value", id="bool"),
        pytest.param("!!float lots", "number", id="float"),
        pytest.param("!!int 5d", "integer", id="explicit-int"),
        pytest.param("0x_", "integer", id="implicit-int"),
        pytest.param("2026-02-30", "date", id="implicit-date"),
        pytest.param("!!timestamp soon", "date", id="explicit-timestamp"),
    ],
)
def test_a_value_its_tag_cannot_build_is_named_by_its_kind(
    tmp_path: Path, value: str, kind: str
) -> None:
    path = _yaml(tmp_path, f"history:\n  window: {value}\n")
    message = _message(path)
    assert message == (
        f"config file {path} is not valid YAML (line 2, column 11):"
        f" this is not a valid {kind} (quote it if it is meant as text)"
    )
    assert value.split()[-1] not in message.removeprefix(f"config file {path}")


def test_a_null_tag_builds_null_whatever_its_text(tmp_path: Path) -> None:
    """PyYAML's null constructor ignores the text, so a null can never fail to build: why the
    "null" entry of the tag names is never shown (pinned here in case PyYAML changes)."""
    data, _ = sources.read_yaml_file(_yaml(tmp_path, f"x: !!null {FAKE_SECRET}\n"))
    assert data == {"x": None}


# --------------------------------------------------------------------------- PyYAML's token names


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        pytest.param(
            "history:\n  window: &w *w\n",
            "(line 2, column 14): while parsing a block mapping, expected <block end>,"
            " but found '<alias>'",
            id="alias",
        ),
        pytest.param(
            "history:\n  window: &a &b 5d\n",
            "(line 2, column 14): while parsing a block mapping, expected <block end>,"
            " but found '<anchor>'",
            id="anchor",
        ),
        pytest.param(
            "history:\n  window: !!str !!str 5d\n",
            "(line 2, column 17): while parsing a block mapping, expected <block end>,"
            " but found '<tag>'",
            id="tag",
        ),
        pytest.param(
            "history:\n  window: 5d\n - x\n",
            "(line 3, column 2): while parsing a block mapping, expected <block end>,"
            " but found '<block sequence start>'",
            id="block-sequence-start",
        ),
        pytest.param(
            "history: [5d,\n%YAML 1.1\n]\n",
            "(line 2, column 1): while parsing a flow node, expected the node content,"
            " but found '<directive>'",
            id="directive",
        ),
        pytest.param(
            "history: [5d,\n...\n]\n",
            "(line 2, column 1): while parsing a flow node, expected the node content,"
            " but found '<document end>'",
            id="document-end",
        ),
        pytest.param(
            "history: [5d,\n---\n]\n",
            "(line 2, column 1): while parsing a flow node, expected the node content,"
            " but found '<document start>'",
            id="document-start-found",
        ),
        pytest.param(
            "%YAML 1.1\nhistory: {}\n",
            "(line 2, column 1): expected '<document start>', but found '<scalar>'",
            id="document-start-expected",
        ),
        pytest.param(
            "history: 'a' 'b'\n",
            "(line 1, column 14): while parsing a block mapping, expected <block end>,"
            " but found '<scalar>'",
            id="scalar",
        ),
    ],
)
def test_token_names_are_shown_in_yaml_errors(tmp_path: Path, text: str, detail: str) -> None:
    """PyYAML quotes the token it found; a token name is not user text, so it stays readable.
    Its context and its problem are joined with ", "."""
    path = _yaml(tmp_path, text)
    assert _message(path) == f"config file {path} is not valid YAML {detail}"


# --------------------------------------------------------------------------- not a mapping


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        pytest.param("true\n", "true/false", id="bool"),
        pytest.param("5\n", "a number", id="int"),
        pytest.param("1.5\n", "a number", id="float"),
        pytest.param("just text\n", "text", id="text"),
        pytest.param("- a\n", "a list", id="list"),
        pytest.param("2026-10-10\n", "a date", id="date"),
        pytest.param("2026-10-10 10:00:00\n", "a date", id="datetime"),
        pytest.param("!!binary aGk=\n", "bytes", id="binary"),
        pytest.param("!!set {a: null}\n", "set", id="set"),
    ],
)
def test_a_file_that_is_not_a_mapping_is_named_by_its_kind(
    tmp_path: Path, text: str, kind: str
) -> None:
    path = _yaml(tmp_path, text)
    assert _message(path) == (
        f"config file {path} must contain a mapping of settings at the top level, not {kind}"
    )


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        pytest.param("true", "true/false", id="bool"),
        pytest.param("5", "a number", id="number"),
        pytest.param("5d", "text", id="text"),
        pytest.param("[5d]", "a list", id="list"),
        pytest.param("2026-10-10", "a date", id="date"),
    ],
)
def test_a_section_that_is_not_a_mapping_is_one_problem_and_no_data(
    tmp_path: Path, value: str, kind: str
) -> None:
    """The section is dropped from the layer's data: validation must not report it again."""
    layer = sources.yaml_layer(_yaml(tmp_path, f"environment: dev\nhistory: {value}\n"), Settings)
    assert layer.problems == [
        f"history: must be a section of indented 'key: value' lines, not {kind} [argus.yaml line 2]"
    ]
    assert layer.data == {"environment": "dev"}


def test_a_section_that_is_not_a_mapping_is_reported_once_by_load_settings(tmp_path: Path) -> None:
    path = _yaml(tmp_path, "history: 5d\n")
    message = str(_config_error(lambda: load_settings(path, env_file=None)))
    assert message.splitlines() == [
        f"invalid configuration ({path} and environment):",
        "  - history: must be a section of indented 'key: value' lines, not text"
        " [argus.yaml line 1]",
    ]


def test_an_empty_section_contributes_no_data(tmp_path: Path) -> None:
    path = _yaml(tmp_path, "history:\n  # window: 30d\nenvironment: test\n")
    layer = sources.yaml_layer(path, Settings)
    assert (layer.data, layer.problems) == ({"environment": "test"}, [])
    assert load_settings(path, env_file=None).history.window.days == 5


def test_secrets_in_the_yaml_layer_are_wrapped_as_soon_as_they_are_read(tmp_path: Path) -> None:
    text = (
        f"database:\n  password: {FAKE_SECRET}\n  owner_password: {FAKE_SECRET}-owner\n"
        "  user: someone\n"
    )
    layer = sources.yaml_layer(_yaml(tmp_path, text), Settings)
    database = layer.data["database"]
    assert database["password"].get_secret_value() == FAKE_SECRET
    assert database["owner_password"].get_secret_value() == f"{FAKE_SECRET}-owner"
    assert database["user"] == "someone"
    assert FAKE_SECRET not in repr(layer)


# --------------------------------------------------------------------------- characters, encoding


@pytest.mark.parametrize(
    ("text", "position", "code"),
    [
        pytest.param("x: \x1b\n", "line 1, column 4", "001B", id="first-line"),
        pytest.param(
            "\nhistory:\n  window: \x07\n", "line 3, column 11", "0007", id="newline-first"
        ),
        pytest.param("a: 1\r\nb: 2\r  c: \ufffe\n", "line 3, column 6", "FFFE", id="cr-breaks"),
    ],
)
def test_an_unprintable_character_is_named_by_its_code_and_position(
    tmp_path: Path, text: str, position: str, code: str
) -> None:
    path = _yaml(tmp_path, text)
    assert _message(path) == (
        f"config file {path} is not valid YAML ({position}):"
        f" unprintable character U+{code} is not allowed"
    )


@pytest.mark.parametrize("kind", ["config file", "env file"])
def test_text_that_is_not_utf8_is_refused_with_its_line(tmp_path: Path, kind: str) -> None:
    """The line counts every kind of line break before the bad byte: \\n, \\r\\n and \\r."""
    path = tmp_path / "file"
    path.write_bytes(b"\xef\xbb\xbf\nhistory:\r\n  window: 5d\rx: \xff\n")
    if kind == "config file":
        exc = _config_error(lambda: sources.read_yaml_file(path))
    else:
        exc = _config_error(lambda: sources.dotenv_layer(path, Settings))
    assert str(exc) == f"{kind} {path} is not UTF-8 text (line 4); save it as UTF-8"


# --------------------------------------------------------------------------- keys


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        pytest.param(
            "history:\n  window: 5d\n\n  window: 4d\n",
            "(line 4, column 3): duplicate key 'window' (first on line 2)",
            id="same-mapping",
        ),
        pytest.param(
            "x:\n  - {a: 1, b: 2}\n  - [{a: 1, a: 2}]\n",
            "(line 3, column 13): duplicate key 'a' (first on line 3)",
            id="inside-lists",
        ),
    ],
)
def test_a_duplicate_key_names_the_line_of_its_first_use(
    tmp_path: Path, text: str, detail: str
) -> None:
    path = _yaml(tmp_path, text)
    assert _message(path) == f"config file {path} is not valid YAML {detail}"


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        pytest.param("? [a, b]\n: 1\n", "(line 1, column 3): a key must be plain text", id="list"),
        pytest.param(
            "history:\n  ? {window: 5d}\n  : 1\n",
            "(line 2, column 5): a key must be plain text",
            id="mapping",
        ),
        pytest.param(
            "history: !!map [window, 5d]\n",
            "(line 1, column 10): expected a mapping here",
            id="map-tag-on-a-list",
        ),
        pytest.param(
            "history: !!set [window]\n",
            "(line 1, column 10): expected a mapping here",
            id="set-tag-on-a-list",
        ),
    ],
)
def test_keys_must_be_plain_text_in_a_mapping(tmp_path: Path, text: str, detail: str) -> None:
    path = _yaml(tmp_path, text)
    assert _message(path) == f"config file {path} is not valid YAML {detail}"


def test_an_equals_sign_key_is_text_also_where_an_alias_reuses_it(tmp_path: Path) -> None:
    """YAML 1.1 reads a lone '=' as the "value" type; as a key PyYAML makes it text, so the node
    an alias of that key points to is text too. Loaded as PyYAML loads it."""
    text = "a:\n  &k = : 1\nb: [*k]\n"
    data, _ = sources.read_yaml_file(_yaml(tmp_path, text))
    assert data == {"a": {"=": 1}, "b": ["="]}
    assert data == yaml.safe_load(text)


# --------------------------------------------------------------------------- merges


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("history:\n  <<: {<<: {window: 30d}, x: 1}\n", id="inline"),
        pytest.param(
            "defs:\n  - &inner {window: 30d}\n  - &outer {<<: *inner, x: 1}\n"
            "history: {<<: *outer}\n",
            id="anchors-in-a-list",
        ),
    ],
)
def test_a_merged_mapping_has_its_own_merges_applied_first(tmp_path: Path, text: str) -> None:
    """The mapping a ``<<`` copies may merge another one; the copy must hold the merged keys, not
    a literal ``<<`` key."""
    data, _ = sources.read_yaml_file(_yaml(tmp_path, text))
    assert data["history"] == {"window": "30d", "x": 1}
    assert data == yaml.safe_load(text)


def test_a_chain_of_merges_deeper_than_python_can_follow_is_refused(tmp_path: Path) -> None:
    """Anchors defined in a list are built after the mapping that merges the last of them, so
    applying that merge follows the whole chain at once. There is no position to show."""
    links = sys.getrecursionlimit() + 100
    assert links < 9000  # each link has one key of its own: far from the 10,000-key limit
    text = (
        "defs:\n  - &a0 {k: 0}\n"
        + "".join(f"  - &a{i} {{<<: *a{i - 1}}}\n" for i in range(1, links))
        + f"use: {{<<: *a{links - 1}}}\n"
    )
    path = _yaml(tmp_path, text)
    assert _message(path) == f"config file {path} is not valid YAML: nesting is too deep"


# --------------------------------------------------------------------------- other YAML errors


def test_a_yaml_error_of_another_kind_is_reported_without_its_text() -> None:
    exc = yaml.YAMLError(f"password: {FAKE_SECRET}")
    message = str(sources._yaml_error("argus.yaml", exc, ""))
    assert message == "config file argus.yaml is not valid YAML"


def test_a_reader_error_without_a_position_or_character_code_shows_neither() -> None:
    """PyYAML's reader reports bytes, and no position, when it decodes a byte stream itself."""
    exc = ReaderError("<file>", None, b"\xff", "utf-8", "invalid start byte")
    message = str(sources._yaml_error("argus.yaml", exc, "x: 1\n"))
    assert message == "config file argus.yaml is not valid YAML"


def test_a_recursion_error_is_reported_as_nesting_without_a_position() -> None:
    message = str(sources._yaml_error("argus.yaml", RecursionError(), "x: 1\n"))
    assert message == "config file argus.yaml is not valid YAML: nesting is too deep"
