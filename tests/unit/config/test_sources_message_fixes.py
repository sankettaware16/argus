"""Two message bugs found while mutation-testing sources.py (R1, 2026-10-11).

* PyYAML appends a library exception's text to "failed to ..." (decoding ``!!binary``), and that
  text quoted a character of the value and garbled the scrubber's quote pairing.
* A value that is just '=' or '<<' (read as a YAML tag) got the hint for values starting with
  '!'. Every value here is synthetic.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from argus.config import ConfigError, load_settings


def _detail(write_config: Callable[[str], Path], text: str) -> str:
    with pytest.raises(ConfigError) as info:
        load_settings(write_config(text), env_file=None)
    message = str(info.value)
    assert " is not valid YAML (line 2, column 13): " in message, message
    return message.split(": ", 1)[1]


@pytest.mark.parametrize(
    ("value", "detail"),
    [
        ("!!binary fakeépw", "failed to convert base64 data into ascii"),
        ("!!binary fakepw1", "failed to decode base64 data"),
    ],
    ids=["non-ascii", "bad-padding"],
)
def test_a_binary_value_that_cannot_be_decoded_shows_no_part_of_it(
    write_config: Callable[[str], Path], value: str, detail: str
) -> None:
    shown = _detail(write_config, f"database:\n  password: {value}\n")
    assert shown == detail
    for piece in ("é", "\\xe9", "fake", "position", "padding", "codec"):
        assert piece not in shown


@pytest.mark.parametrize("value", ["=", "<<"])
def test_a_bare_equals_or_merge_value_gets_the_right_hint(
    write_config: Callable[[str], Path], value: str
) -> None:
    shown = _detail(write_config, f"database:\n  password: {value}\n")
    assert shown == (
        "could not determine a constructor for the tag (not shown);"
        " a value that is just '=' or '<<' must be quoted"
    )


def test_an_unknown_tag_still_gets_the_tag_hint(write_config: Callable[[str], Path]) -> None:
    shown = _detail(write_config, "database:\n  password: !fake-tag x\n")
    assert shown == (
        "could not determine a constructor for the tag (not shown);"
        " a value that starts with '!' must be quoted"
    )
