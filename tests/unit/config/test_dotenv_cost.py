"""Regression (R1 fix round 3): reading a .env file takes time and memory linear in its size.

python-dotenv strips a comment from an unquoted value with the pattern ``\\s+#.*``, which takes time
quadratic in a run of blanks, and its ``${VAR}`` pattern rescans the rest of a value from every "${"
that nothing closes: a 40 KB line took 14 s, and 1 MiB would take hours. A line that repeats a
reference to the line before multiplies its length, so two short lines could ask for gigabytes.

Lines longer than MAX_ENV_LINE_CHARS, or with more than MAX_ENV_BLANKS blanks in a row, are now
refused before python-dotenv reads the file; ARGUS expands references itself, in one pass, to at
most MAX_ENV_EXPANDED_CHARS of values. Every secret here is synthetic.
"""

from __future__ import annotations

import gc
import io
import math
import string
import time
import tracemalloc
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import NoReturn

import pytest
from dotenv import dotenv_values
from dotenv.parser import parse_stream
from dotenv.variables import parse_variables
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, load_settings, sources
from argus.config.sources import MAX_ENV_BLANKS, MAX_ENV_EXPANDED_CHARS, MAX_ENV_LINE_CHARS

SECRET = "Fake-Cost-Secret-6v2k"
LONG_LINE = f"is longer than {MAX_ENV_LINE_CHARS} characters; is it the right file?"
LONG_BLANKS = (
    f"has more than {MAX_ENV_BLANKS} spaces or other blanks in a row; is it the right file?"
)


def _files(tmp_path: Path, env_text: str) -> tuple[Path, Path]:
    """An empty config file and a .env file holding ``env_text`` exactly as written."""
    config = tmp_path / "argus.yaml"
    config.write_text("")
    env_file = tmp_path / "cost.env"
    env_file.write_text(env_text, encoding="utf-8", newline="")
    return config, env_file


def _refusal(config: Path, env_file: Path) -> tuple[str, float]:
    """The message of the ConfigError that loading raises, and the seconds it took."""
    started = time.monotonic()
    with pytest.raises(ConfigError) as info:
        load_settings(config, env_file=env_file)
    return str(info.value), time.monotonic() - started


def _cpu_seconds(*loads: Callable[[], object]) -> list[float]:
    """For each of ``loads``, the least CPU time of three runs, taken in turns with the garbage
    collector paused. CPU time leaves out the time this process waits for others to run."""
    best = [math.inf] * len(loads)
    for _ in range(3):
        for index, load in enumerate(loads):
            gc.collect()
            gc.disable()
            try:
                started = time.process_time()
                load()
                best[index] = min(best[index], time.process_time() - started)
            finally:
                gc.enable()
    return best


def _not_parsed(stream: object) -> NoReturn:
    pytest.fail("python-dotenv parsed a file that should have been refused before")


# --------------------------------------------------------------------------- long lines

LONG_LINES = {
    "unclosed-references": f"OTHER={SECRET}" + "${" * 20_000,  # python-dotenv: 14 s
    "run-of-spaces": f"OTHER={SECRET}" + " " * 40_000 + "x",  # python-dotenv: 1.4 s
    "secret": "ARGUS_DATABASE__PASSWORD=" + SECRET * 2_000,
}


@pytest.mark.parametrize("line", list(LONG_LINES.values()), ids=list(LONG_LINES))
def test_long_line_is_refused_at_once_by_its_number(tmp_path: Path, line: str) -> None:
    config, env_file = _files(tmp_path, f"# settings\nARGUS_HISTORY__WINDOW=30d\n{line}\nA=1\n")
    message, seconds = _refusal(config, env_file)
    assert message == f"env file {env_file} line 3 {LONG_LINE}"
    assert SECRET not in message
    assert seconds < 1


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("OTHER=x" + "${" * MAX_ENV_LINE_CHARS, id="long-line"),
        pytest.param("OTHER=x" + " " * (MAX_ENV_BLANKS + 1) + "x", id="long-run-of-blanks"),
    ],
)
def test_refused_file_never_reaches_python_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str
) -> None:
    """The lines are checked before parsing, so no machine is fast enough to hide a regression."""
    monkeypatch.setattr(sources, "parse_stream", _not_parsed)
    config, env_file = _files(tmp_path, f"A=1\n{line}\n")
    message, _ = _refusal(config, env_file)
    assert message.startswith(f"env file {env_file} line 2 ")


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
def test_line_of_exactly_the_limit_loads_and_one_character_more_is_refused(
    tmp_path: Path, newline: str
) -> None:
    """python-dotenv ends a line at \\r, \\n or \\r\\n; the line break itself is not counted."""
    name = "ARGUS_DATABASE__PASSWORD="
    token = "k" * (MAX_ENV_LINE_CHARS - len(name))
    config, env_file = _files(tmp_path, f"A=1{newline}{name}{token}{newline}B=2{newline}")
    password = load_settings(config, env_file=env_file).database.password
    assert password is not None
    assert password.get_secret_value() == token

    env_file.write_text(f"A=1{newline}{name}{token}k{newline}B=2{newline}", newline="")
    message, _ = _refusal(config, env_file)
    assert message == f"env file {env_file} line 2 {LONG_LINE}"


def test_unicode_line_separators_do_not_end_a_line(tmp_path: Path) -> None:
    """python-dotenv reads up to \\r or \\n only: U+2028 and U+0085 are text within one line."""
    half = "x" * (MAX_ENV_LINE_CHARS // 2)
    config, env_file = _files(tmp_path, f"OTHER={half}\u2028{half}\x85\n")
    message, _ = _refusal(config, env_file)
    assert message == f"env file {env_file} line 1 {LONG_LINE}"


def test_secrets_of_a_few_kib_still_load(tmp_path: Path) -> None:
    """A token on one line, or a certificate bundle in double quotes over many short lines."""
    alphabet = string.ascii_letters + string.digits + "-_"
    token = (alphabet * 200)[: 12 * 1024]
    bundle = "\n".join((alphabet * 2)[i % 64 : i % 64 + 64] for i in range(640))  # 41 KB
    config, env_file = _files(
        tmp_path,
        f"ARGUS_DATABASE__PASSWORD={token}\n"
        f'TLS_BUNDLE="{bundle}"\n'
        f'ARGUS_DATABASE__OWNER_PASSWORD="{bundle}"\n',
    )
    database = load_settings(config, env_file=env_file).database
    assert database.password is not None
    assert database.password.get_secret_value() == token
    assert database.owner_password is not None
    assert database.owner_password.get_secret_value() == bundle


# --------------------------------------------------------------------------- runs of blanks

BLANKS = {
    "space": " ",
    "tab": "\t",
    "no-break-space": "\xa0",
    "ideographic-space": "\u3000",
    "vertical-tab": "\x0b",
    "file-separator": "\x1c",
}


@pytest.mark.parametrize("blank", list(BLANKS.values()), ids=list(BLANKS))
def test_long_run_of_blanks_is_refused_at_once(tmp_path: Path, blank: str) -> None:
    """A run just under the line limit took python-dotenv 0.2 to 0.8 s to read (U+3000 is the
    slowest), and a 1 MiB file holds 64 such lines."""
    run = blank * (MAX_ENV_LINE_CHARS - 100)
    config, env_file = _files(tmp_path, f"A=1\nOTHER={SECRET}{run}x\nB=2\n")
    message, seconds = _refusal(config, env_file)
    assert message == f"env file {env_file} line 2 {LONG_BLANKS}"
    assert seconds < 1


def test_run_of_exactly_the_blank_limit_loads_and_one_blank_more_is_refused(
    tmp_path: Path,
) -> None:
    blanks = " " * MAX_ENV_BLANKS
    config, env_file = _files(
        tmp_path,
        f"ARGUS_HISTORY__WINDOW=30d{blanks}# an aligned comment\n"
        f'ARGUS_DATABASE__PASSWORD="a{blanks}b"\n',
    )
    settings = load_settings(config, env_file=env_file)
    assert settings.history.window == timedelta(days=30)
    assert settings.database.password is not None
    assert settings.database.password.get_secret_value() == f"a{blanks}b"

    env_file.write_text(f"\nARGUS_HISTORY__WINDOW=30d\t{blanks}# one blank more\n")
    message, _ = _refusal(config, env_file)
    assert message == f"env file {env_file} line 2 {LONG_BLANKS}"


def test_line_breaks_are_not_blanks(tmp_path: Path) -> None:
    config, env_file = _files(
        tmp_path, "\n" * 5_000 + "ARGUS_HISTORY__WINDOW=30d\r\n" + "\r\n \t" * 5_000 + "\r" * 500
    )
    assert load_settings(config, env_file=env_file).history.window == timedelta(days=30)


def test_lines_with_as_many_blanks_as_allowed_load_quickly(tmp_path: Path) -> None:
    """The slowest file of blanks within the limits: python-dotenv's time grows with the square of
    a run, so the run limit bounds it (0.4 s here; a one-byte blank packs the most into 1 MiB)."""
    unit = "x" + "\t" * MAX_ENV_BLANKS
    line = "OTHER=" + unit * ((MAX_ENV_LINE_CHARS - 8) // len(unit)) + "x\n"
    config, env_file = _files(tmp_path, line * (sources.MAX_FILE_BYTES // len(line.encode())))
    started = time.monotonic()
    load_settings(config, env_file=env_file)
    assert time.monotonic() - started < 5


# --------------------------------------------------------------------------- ${VAR} expansion


def test_unclosed_references_are_expanded_in_linear_time(tmp_path: Path) -> None:
    """python-dotenv took up to 3 s for each of these lines, and 14 s for one of 40 KB ("${:" is
    cheap for it, but takes the ':' path of ARGUS's own pass)."""
    room = MAX_ENV_LINE_CHARS - 40
    values = ["${" * (room // 2), "${A:-" * (room // 5), "${:" * (room // 3), "${x" * (room // 3)]
    lines = "".join(f"OTHER_{i}={values[i % len(values)]}\n" for i in range(16))
    config, env_file = _files(tmp_path, lines + f"ARGUS_DATABASE__PASSWORD={values[0]}\n")
    started = time.monotonic()
    password = load_settings(config, env_file=env_file).database.password
    assert time.monotonic() - started < 1
    assert password is not None
    assert password.get_secret_value() == values[0]  # nothing closes a "${": plain text


def test_references_that_multiply_a_value_are_refused_at_once(tmp_path: Path) -> None:
    """A 31 KiB file made a 61 MiB value (python-dotenv built it in full); a third line repeating
    the second would have asked for 256 GB."""
    config, env_file = _files(
        tmp_path, "# a value, then a line repeating it\nA=" + "x" * 16_000 + "\nB=" + "${A}" * 4_000
    )
    tracemalloc.start()
    try:
        message, seconds = _refusal(config, env_file)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    limit = MAX_ENV_EXPANDED_CHARS // 1024
    assert message == (
        f"env file {env_file} line 3: with ${{VAR}} references expanded,"
        f" the values come to more than {limit} KiB"
    )
    assert seconds < 1
    assert peak < 20 * 1024 * 1024


def test_values_of_exactly_the_expansion_limit_load_and_one_character_more_is_refused(
    tmp_path: Path,
) -> None:
    """Every value counts, written out or expanded: here 16,000 + 261 x 16,000 + 2,304."""
    chunk = 16_000
    copies, rest = divmod(MAX_ENV_EXPANDED_CHARS - chunk, chunk)
    text = f"A={'x' * chunk}\nB={'${A}' * copies}\nARGUS_DATABASE__PASSWORD={'y' * rest}\n"
    config, env_file = _files(tmp_path, text)
    password = load_settings(config, env_file=env_file).database.password
    assert password is not None
    assert password.get_secret_value() == "y" * rest

    env_file.write_text(text.replace("y\n", "yy\n"))
    message, _ = _refusal(config, env_file)
    assert message.startswith(f"env file {env_file} line 3: with ${{VAR}} references expanded")


def test_reading_time_grows_linearly_with_the_number_of_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eight times the lines take about eight times as long (8.3 here), on a machine of any speed:
    python-dotenv's dotenv_values copies every earlier value for each line (about 30 times)."""
    monkeypatch.setenv("TEST_BASE", "5")
    config, _ = _files(tmp_path, "")

    def env_file(lines: int) -> Path:
        path = tmp_path / f"{lines}.env"
        body = "".join(f"OTHER_{i}=${{TEST_BASE}}${{EMPTY}}{i}\n" for i in range(lines))
        path.write_text(f"EMPTY=\n{body}ARGUS_HISTORY__WINDOW=${{OTHER_7}}d\n")
        return path

    small, large = env_file(2_500), env_file(20_000)
    assert load_settings(config, env_file=large).history.window == timedelta(days=57)
    small_time, large_time = _cpu_seconds(
        lambda: load_settings(config, env_file=small), lambda: load_settings(config, env_file=large)
    )
    ratio = large_time / small_time
    assert ratio < 16, f"8 times the lines took {ratio:.1f} times as long"


REFERENCE_PIECES = ["${", "}", ":", ":-", "-", "$", "{", "A", "B", "x", " ", "${A}", "${B:-d}"]
NAMES = ["A", "B", "", " A", "${A", "A:"]  # "A:" can never be referenced: names end at ':'


@given(
    value=st.one_of(
        st.lists(st.sampled_from(REFERENCE_PIECES), max_size=12).map("".join),
        st.text(alphabet="${}:-AB x", max_size=30),
    ),
    known=st.dictionaries(
        st.sampled_from(NAMES), st.one_of(st.none(), st.text(alphabet="ab${}:-", max_size=4))
    ),
)
@settings(deadline=None)
def test_expansion_matches_python_dotenv_and_stops_at_the_limit(
    value: str, known: dict[str, str | None]
) -> None:
    expected = "".join(atom.resolve(known) for atom in parse_variables(value))
    assert sources._expand(value, known, len(expected)) == expected
    if expected:
        assert sources._expand(value, known, len(expected) - 1) is None


ENV_VALUES = [*REFERENCE_PIECES, "${A:-${B}}", "${C:-x}", "${UNSET_TEST_VARIABLE:-u}", "\\$"]


@st.composite
def reference_files(draw: st.DrawFn) -> str:
    lines = []
    for _ in range(draw(st.integers(1, 8))):
        name = draw(st.sampled_from(["A", "B", "C", "export A"]))
        if draw(st.integers(0, 5)) == 0:
            lines.append(name)  # no value
            continue
        value = "".join(draw(st.lists(st.sampled_from(ENV_VALUES), max_size=5)))
        quote = draw(st.sampled_from(["", "'", '"']))
        lines.append(f"{name}={quote}{value}{quote}")
    return "\n".join(lines) + "\n"


@given(text=reference_files())
@settings(deadline=None)
def test_file_expansion_matches_dotenv_values(text: str) -> None:
    bindings = list(parse_stream(io.StringIO(text)))
    values = sources._expand_variables(bindings)
    expanded = {b.key: v for b, v in zip(bindings, values, strict=True) if b.key is not None}
    assert expanded == dotenv_values(stream=io.StringIO(text))


# --------------------------------------------------------------------------- the CLI


def test_cli_names_the_long_line_without_showing_it(tmp_path: Path) -> None:
    (tmp_path / "argus.yaml").write_text("")
    (tmp_path / ".env").write_text("A=1\nOTHER=" + SECRET + "${" * 20_000 + "\n")  # cwd: tmp_path
    result = CliRunner().invoke(app, ["config", "validate", "-c", str(tmp_path / "argus.yaml")])
    output = result.output + result.stderr
    assert result.exit_code == 2
    assert f"line 2 {LONG_LINE}" in output
    assert SECRET not in output


def test_a_file_of_broken_lines_lists_the_first_twenty_and_counts_the_rest(tmp_path: Path) -> None:
    """Round-3 verification: 1 MiB of '=' lines made a 4-million-character message."""
    env_file = tmp_path / "broken.env"
    env_file.write_text("=\n" * 5_000)
    config = tmp_path / "argus.yaml"
    config.write_text("")
    with pytest.raises(ConfigError) as info:
        load_settings(config, env_file=env_file)
    message = str(info.value)
    listed = ", ".join(str(n) for n in range(1, 21))
    assert f"(lines {listed} and 4980 more)" in message
    assert len(message) < 500
