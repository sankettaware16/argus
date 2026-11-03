"""Edge cases of argus.config.durations that test_durations.py leaves open (R1 mutation testing).

The error messages are part of the contract: every rejection says how to write a duration, the
lowercase hint appears only for an uppercase unit, and a value is shown as it was given.
"""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from pydantic import BaseModel

from argus.config.durations import MAX_DURATION, Duration, parse_duration

HINT = "use a number followed by a unit: s, m, h, d or w (for example '5d', '36h', '15m')"


def _exactly(message: str) -> str:
    return f"^{re.escape(message)}$"


@pytest.mark.parametrize("value", ["", "5", "five", "5x", 5, None])
def test_every_rejection_says_how_to_write_a_duration(value: object) -> None:
    with pytest.raises(ValueError, match=f"; {re.escape(HINT)}$"):
        parse_duration(value)


@pytest.mark.parametrize("text", ["", " ", "5", "5x", "abc", "5 d", "5d3", "-5d"])
def test_only_an_uppercase_unit_gets_the_lowercase_hint(text: str) -> None:
    with pytest.raises(ValueError, match=_exactly(f"invalid duration; {HINT}")):
        parse_duration(text)


def test_an_uppercase_unit_gets_the_lowercase_hint() -> None:
    with pytest.raises(
        ValueError, match=_exactly(f"invalid duration: units are lowercase; {HINT}")
    ):
        parse_duration("5D")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("0d", "duration '0d' must be greater than zero"),
        (" 000m ", "duration '000m' must be greater than zero"),
        (timedelta(0), "duration 0:00:00 must be greater than zero"),
        (timedelta(seconds=-90), "duration -1 day, 23:58:30 must be greater than zero"),
        (
            timedelta(seconds=1, microseconds=5),
            "duration 0:00:01.000005 must be a whole number of seconds",
        ),
        (
            MAX_DURATION + timedelta(seconds=1),
            "duration 36500 days, 0:00:01 is larger than the supported maximum of 36500d",
        ),
    ],
)
def test_a_rejected_value_is_shown_as_it_was_given(value: object, message: str) -> None:
    """A string as written (stripped), a timedelta in its own notation."""
    with pytest.raises(ValueError, match=_exactly(message)):
        parse_duration(value)


class _Model(BaseModel):
    every: Duration


def test_the_json_schema_pattern_is_the_format_the_parser_reads() -> None:
    pattern = _Model.model_json_schema()["properties"]["every"]["pattern"]
    for text in ("1s", "15m", "36h", "5d", "2w", "1234567890d"):  # well-formed; range apart
        assert re.fullmatch(pattern, text), text
    for text in ("5", "5D", "5 d", "d5", "5dd", "-5d", "5.5d", "12345678901d"):
        assert re.fullmatch(pattern, text) is None, text
