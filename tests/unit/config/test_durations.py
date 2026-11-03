from __future__ import annotations

from datetime import timedelta
from typing import Annotated

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from argus.config.durations import (
    MAX_DURATION,
    UNIT_SECONDS,
    Duration,
    bounded_duration,
    format_duration,
    parse_duration,
)

MAX_SECONDS = int(MAX_DURATION.total_seconds())


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1s", timedelta(seconds=1)),
        ("90s", timedelta(seconds=90)),
        ("15m", timedelta(minutes=15)),
        ("36h", timedelta(hours=36)),
        ("5d", timedelta(days=5)),
        ("30d", timedelta(days=30)),
        ("2w", timedelta(days=14)),
        ("  5d  ", timedelta(days=5)),
        ("05d", timedelta(days=5)),
        ("5d\n", timedelta(days=5)),
        ("36500d", MAX_DURATION),
    ],
)
def test_parses_valid_durations(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "d",
        "5",
        "5 d",
        "5days",
        "five days",
        "-5d",
        "+5d",
        "5.5d",
        "1e3s",
        "5d3h",
        "P5D",
        "5y",
        "5ms",
        "٥d",  # noqa: RUF001 — Arabic-Indic digit must be rejected
        "5​d",
        "1234567890d",
        "5d d",
    ],
)
def test_rejects_malformed_strings(text: str) -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_duration(text)


@pytest.mark.parametrize("text", ["5D", "36H", "15M"])
def test_uppercase_units_get_a_hint(text: str) -> None:
    with pytest.raises(ValueError, match="lowercase"):
        parse_duration(text)


@pytest.mark.parametrize("value", [5, 0, 5.0, True, False])
def test_bare_numbers_are_ambiguous(value: object) -> None:
    with pytest.raises(ValueError, match="ambiguous"):
        parse_duration(value)


@pytest.mark.parametrize("value", [None, [], {}, b"5d", object()])
def test_non_string_values_are_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="expected a duration string"):
        parse_duration(value)


@pytest.mark.parametrize("text", ["0s", "0d", "000m"])
def test_zero_is_rejected(text: str) -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        parse_duration(text)


def test_too_large_is_rejected() -> None:
    with pytest.raises(ValueError, match="maximum"):
        parse_duration("36501d")
    with pytest.raises(ValueError, match="maximum"):
        parse_duration("99999999d")


@pytest.mark.parametrize(
    ("delta", "message"),
    [
        (timedelta(0), "greater than zero"),
        (timedelta(seconds=-1), "greater than zero"),
        (timedelta(seconds=1, microseconds=5), "whole number of seconds"),
        (MAX_DURATION + timedelta(seconds=1), "maximum"),
    ],
)
def test_timedelta_inputs_are_checked(delta: timedelta, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_duration(delta)


def test_timedelta_inputs_pass_through() -> None:
    assert parse_duration(timedelta(days=5)) == timedelta(days=5)


@pytest.mark.parametrize(
    ("delta", "text"),
    [
        (timedelta(days=5), "5d"),
        (timedelta(days=14), "14d"),
        (timedelta(hours=36), "36h"),
        (timedelta(minutes=90), "90m"),
        (timedelta(seconds=90), "90s"),
        (timedelta(seconds=3601), "3601s"),
        (timedelta(hours=24), "1d"),
    ],
)
def test_format_uses_largest_exact_unit(delta: timedelta, text: str) -> None:
    assert format_duration(delta) == text


def test_format_rejects_invalid_durations() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        format_duration(timedelta(0))


@given(st.integers(min_value=1, max_value=MAX_SECONDS))
def test_round_trip_for_every_whole_second(seconds: int) -> None:
    delta = timedelta(seconds=seconds)
    assert parse_duration(format_duration(delta)) == delta


@given(
    st.sampled_from(sorted(UNIT_SECONDS)),
    st.integers(min_value=1, max_value=999_999_999),
)
def test_any_well_formed_string_parses_or_fails_cleanly(unit: str, amount: int) -> None:
    text = f"{amount}{unit}"
    seconds = amount * UNIT_SECONDS[unit]
    if seconds > MAX_SECONDS:
        with pytest.raises(ValueError, match="maximum"):
            parse_duration(text)
    else:
        parsed = parse_duration(text)
        assert parsed == timedelta(seconds=seconds)
        assert parse_duration(format_duration(parsed)) == parsed


@given(st.text(max_size=20))
def test_arbitrary_text_never_crashes(text: str) -> None:
    try:
        result = parse_duration(text)
    except ValueError:
        return
    assert result > timedelta(0)


# --------------------------------------------------------------------------- pydantic integration


class _Model(BaseModel):
    every: Duration
    bounded: Annotated[Duration, bounded_duration(timedelta(hours=1), timedelta(days=365))] = (
        timedelta(days=5)
    )


def test_pydantic_field_parses_and_serialises() -> None:
    model = _Model(every="15m", bounded="30d")
    assert model.every == timedelta(minutes=15)
    assert model.model_dump(mode="json") == {"every": "15m", "bounded": "30d"}
    assert _Model.model_validate_json(model.model_dump_json()) == model


def test_pydantic_field_rejects_bare_numbers() -> None:
    with pytest.raises(ValidationError, match="ambiguous"):
        _Model(every=300)


@pytest.mark.parametrize("value", ["59m", "366d", "1s"])
def test_bounded_duration_enforces_range(value: str) -> None:
    with pytest.raises(ValidationError, match="between 1h and 365d"):
        _Model(every="1m", bounded=value)


@pytest.mark.parametrize("value", ["1h", "60m", "365d", "52w"])
def test_bounded_duration_accepts_edges(value: str) -> None:
    assert _Model(every="1m", bounded=value).bounded == parse_duration(value)


def test_json_schema_documents_the_format() -> None:
    schema = _Model.model_json_schema()
    assert schema["properties"]["every"]["type"] == "string"
    assert "pattern" in schema["properties"]["every"]
