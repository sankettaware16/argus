"""The limits of argus.config.sources, each pinned at its documented value: the limit itself is
accepted, one more is refused, and the message spells the number out. (test_sources.py and
test_dotenv_cost.py import the constants, so they would follow a changed constant; these tests do
not.) Also how a file is opened, read and closed. Every value here is synthetic."""

from __future__ import annotations

import functools
import gc
import io
import os
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from dotenv.parser import parse_stream

from argus.config import ConfigError, Settings, sources

KIB = 1024
MIB = 1024 * KIB


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


def _yaml(tmp_path: Path, text: str, name: str = "argus.yaml") -> Path:
    return _write(tmp_path, text, name)


def _env(tmp_path: Path, text: str, name: str = "limits.env") -> Path:
    return _write(tmp_path, text, name)


# --------------------------------------------------------------------------- YAML nesting


def _nested_lists(lists: int) -> str:
    """``x: [[...[1]...]]``: the top-level mapping is level 1, the key ``x`` and the outer list are
    level 2, so the scalar inside ``lists`` lists is at level ``lists + 2``."""
    return "x: " + "[" * lists + "1" + "]" * lists + "\n"


def _nested_value(lists: int) -> Any:
    value: Any = 1
    for _ in range(lists):
        value = [value]
    return value


def test_nesting_of_32_levels_loads(tmp_path: Path) -> None:
    data, _ = sources.read_yaml_file(_yaml(tmp_path, _nested_lists(30)))
    assert data == {"x": _nested_value(30)}


def test_nesting_of_33_levels_is_refused_where_the_33rd_level_starts(tmp_path: Path) -> None:
    path = _yaml(tmp_path, _nested_lists(31))
    message = str(_config_error(lambda: sources.read_yaml_file(path)))
    assert message == (
        f"config file {path} is not valid YAML (line 1, column 35):"
        " nesting is deeper than 32 levels"
    )


def test_nesting_counts_the_levels_of_mappings_too(tmp_path: Path) -> None:
    """A key is composed one level below its mapping, like the value next to it."""
    deepest = "{a: " * 31 + "1" + "}" * 31  # the scalar 1 (and its key) at level 32
    data, _ = sources.read_yaml_file(_yaml(tmp_path, deepest + "\n"))
    value: Any = data
    for _ in range(31):
        value = value["a"]
    assert value == 1
    path = _yaml(tmp_path, "{a: " * 32 + "1" + "}" * 32 + "\n", name="deeper.yaml")
    message = str(_config_error(lambda: sources.read_yaml_file(path)))
    assert message.endswith("(line 1, column 126): nesting is deeper than 32 levels")


# --------------------------------------------------------------------------- YAML keys


def test_ten_thousand_keys_load_and_one_more_is_refused(tmp_path: Path) -> None:
    text = "".join(f"k{i}: {i}\n" for i in range(10_000))
    data, _ = sources.read_yaml_file(_yaml(tmp_path, text))
    assert len(data) == 10_000
    path = _yaml(tmp_path, text + "k10000: 10000\n", name="over.yaml")
    message = str(_config_error(lambda: sources.read_yaml_file(path)))
    assert message == (
        f"config file {path} is not valid YAML (line 1, column 1):"
        " more than 10000 keys, counting the keys that '<<' merges copy"
    )


def _anchor_of(keys: int) -> str:
    return "a: &a {" + ", ".join(f"k{i}: {i}" for i in range(keys)) + "}\n"


def test_a_merged_mapping_counts_its_own_keys_once_and_each_copy_once(tmp_path: Path) -> None:
    """2 top-level keys + 4,999 keys of ``a`` + the 4,999 a merge copies into ``b`` = 10,000.

    ``a`` is flattened when it is built and again reached through ``b``'s merge; its own keys
    must not be counted twice."""
    data, _ = sources.read_yaml_file(_yaml(tmp_path, _anchor_of(4999) + "b: {<<: *a}\n"))
    assert len(data["a"]) == 4999
    assert data["b"] == data["a"]
    path = _yaml(tmp_path, _anchor_of(4999) + "b: {<<: *a, own: 1}\n", name="over.yaml")
    message = str(_config_error(lambda: sources.read_yaml_file(path)))
    assert message == (
        f"config file {path} is not valid YAML (line 2, column 5):"
        " more than 10000 keys, counting the keys that '<<' merges copy"
    )


# --------------------------------------------------------------------------- YAML integers


def test_an_integer_of_4300_characters_loads_and_one_more_is_refused(tmp_path: Path) -> None:
    data, _ = sources.read_yaml_file(_yaml(tmp_path, "n: " + "7" * 4300 + "\n"))
    assert data == {"n": int("7" * 4300)}
    signed, _ = sources.read_yaml_file(_yaml(tmp_path, "n: -" + "7" * 4299 + "\n", "signed.yaml"))
    assert signed == {"n": -int("7" * 4299)}
    path = _yaml(tmp_path, "n: " + "7" * 4301 + "\n", name="over.yaml")
    message = str(_config_error(lambda: sources.read_yaml_file(path)))
    assert message == (
        f"config file {path} is not valid YAML (line 1, column 4):"
        " an integer of more than 4300 characters is not supported"
    )


# --------------------------------------------------------------------------- .env lines


def test_env_line_of_16384_characters_loads_and_one_more_is_refused(tmp_path: Path) -> None:
    line = "OTHER_TOOL_TOKEN=" + "x" * (16 * KIB - len("OTHER_TOOL_TOKEN="))
    assert len(line) == 16_384
    layer = sources.dotenv_layer(_env(tmp_path, "# a comment\n" + line + "\n"), Settings)
    assert layer is not None
    assert (layer.data, layer.problems) == ({}, [])
    path = _env(tmp_path, "# a comment\n" + line + "x\n", name="over.env")
    message = str(_config_error(lambda: sources.dotenv_layer(path, Settings)))
    assert (
        message == f"env file {path} line 2 is longer than 16384 characters; is it the right file?"
    )


def test_env_line_with_256_blanks_in_a_row_loads_and_257_are_refused(tmp_path: Path) -> None:
    layer = sources.dotenv_layer(_env(tmp_path, "OTHER=a" + " " * 256 + "b\n"), Settings)
    assert layer is not None
    assert (layer.data, layer.problems) == ({}, [])
    path = _env(tmp_path, "OTHER=a\nOTHER_2=a" + " \t" * 128 + " b\n", name="over.env")
    message = str(_config_error(lambda: sources.dotenv_layer(path, Settings)))
    assert message == (
        f"env file {path} line 2 has more than 256 spaces or other blanks in a row;"
        " is it the right file?"
    )


# --------------------------------------------------------------------------- ${VAR} expansion


def _expanding(tail: str) -> str:
    """4 KiB on line 1, and 1,023 references to it on line 2: 4 MiB of values in all."""
    return "EXPAND_A=" + "x" * (4 * KIB) + "\nEXPAND_B=" + "${EXPAND_A}" * 1023 + tail + "\n"


def test_expanded_values_of_4_mib_load_and_one_character_more_is_refused(tmp_path: Path) -> None:
    layer = sources.dotenv_layer(_env(tmp_path, _expanding("")), Settings)
    assert layer is not None
    assert (layer.data, layer.problems) == ({}, [])
    path = _env(tmp_path, _expanding("y"), name="over.env")
    message = str(_config_error(lambda: sources.dotenv_layer(path, Settings)))
    assert message == (
        f"env file {path} line 2: with ${{VAR}} references expanded, the values come to more"
        " than 4096 KiB"
    )


def test_expansion_limit_counts_the_values_of_every_line(tmp_path: Path) -> None:
    """The 4 MiB are shared by the whole file: line 3 may add only what lines 1 and 2 left."""
    exact = sources._expand_variables(list(parse_stream(io.StringIO(_expanding("")))))
    assert sum(len(value or "") for value in exact) == 4 * MIB
    path = _env(tmp_path, _expanding("") + "EXPAND_C=z\n", name="third.env")
    message = str(_config_error(lambda: sources.dotenv_layer(path, Settings)))
    assert message.startswith(f"env file {path} line 3: with ${{VAR}} references expanded")


def test_expansion_names_dot_env_when_no_file_is_given() -> None:
    """The default ``where`` of _expand_variables, for callers that parse text themselves."""
    text = "EXPAND_A=" + "x" * (4 * KIB) + "\nEXPAND_B=" + "${EXPAND_A}" * 1024 + "\n"
    bindings = list(parse_stream(io.StringIO(text)))
    message = str(_config_error(lambda: sources._expand_variables(bindings)))
    assert message == (
        "env file .env line 2: with ${VAR} references expanded, the values come to more than"
        " 4096 KiB"
    )


# --------------------------------------------------------------------------- opening and reading


def test_a_regular_file_is_read_in_blocking_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file is opened with O_NONBLOCK, so that a FIFO cannot make the open wait, and switched
    back to blocking before it is read: the read must not depend on how a file system treats
    O_NONBLOCK on a regular file."""
    blocking: list[bool] = []
    builtin_open = open

    def spy(descriptor: int, *args: Any, **kwargs: Any) -> Any:
        blocking.append(os.get_blocking(descriptor))
        return builtin_open(descriptor, *args, **kwargs)

    monkeypatch.setattr(sources, "open", spy, raising=False)
    data, _ = sources.read_yaml_file(_yaml(tmp_path, "history:\n  window: 5d\n"))
    assert data == {"history": {"window": "5d"}}
    assert blocking == [True]


def test_a_read_error_names_the_file_and_the_reason(tmp_path: Path) -> None:
    """/proc/self/mem is a regular file whose first page cannot be read (EIO)."""
    if not Path("/proc/self/mem").exists():
        pytest.skip("needs /proc")
    message = str(_config_error(lambda: sources.read_yaml_file(Path("/proc/self/mem"))))
    assert message == "cannot read config file /proc/self/mem: Input/output error"


def _open_descriptors() -> int:
    gc.collect()
    return len(os.listdir("/proc/self/fd"))


def test_every_file_opened_is_closed_whatever_the_outcome(tmp_path: Path) -> None:
    if not Path("/proc/self/fd").is_dir():
        pytest.skip("needs /proc")
    good = _yaml(tmp_path, "history:\n  window: 5d\n")
    bad = _yaml(tmp_path, "history: [5d\n", name="bad.yaml")
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (MIB + 1))
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    env_file = _env(tmp_path, "ARGUS_HISTORY__WINDOW=5d\n")
    before = _open_descriptors()
    for _ in range(10):
        sources.read_yaml_file(good)
        sources.dotenv_layer(env_file, Settings)
        for path in (bad, big, fifo, tmp_path):
            with pytest.raises(ConfigError):
                sources.read_yaml_file(path)
    assert _open_descriptors() <= before


def test_a_loader_stopped_by_an_error_is_freed_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parser stopped by an error still refers to itself (its next state), which would keep the
    loader and everything it read until the garbage collector runs; dispose() drops that."""
    loaders: list[weakref.ref[sources._ConfigLoader]] = []

    class Recorded(sources._ConfigLoader):
        def __init__(self, stream: str) -> None:
            super().__init__(stream)
            loaders.append(weakref.ref(self))

    monkeypatch.setattr(sources, "_ConfigLoader", Recorded)
    paths = [_yaml(tmp_path, text, f"{i}.yaml") for i, text in enumerate(["x: [1\n", "{a: " * 40])]
    gc.collect()
    gc.disable()
    try:
        messages = [
            str(_config_error(functools.partial(sources.read_yaml_file, path))) for path in paths
        ]
        alive = [loader() is not None for loader in loaders]
    finally:
        gc.enable()
    unclosed = "while parsing a flow sequence, expected ',' or ']', but got '<stream end>'"
    assert messages[0] == f"config file {paths[0]} is not valid YAML (line 2, column 1): {unclosed}"
    assert messages[1].endswith("(line 1, column 126): nesting is deeper than 32 levels")
    assert alive == [False, False]
