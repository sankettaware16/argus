"""The schema of the words a person types about a notice or a block says what the case machine
accepts (AR4b, D-181): Schemathesis builds "valid" strings from the pattern alone, so a pattern
that allowed a control character was a 422 on a request the contract called valid."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from argus.cases.machine import CaseRefused, _told
from argus.web.v1 import case_models as m

TOLD = TypeAdapter(m.Told)
WHERE = TypeAdapter(m.Where)

_PIECES = st.sampled_from(
    [
        *"abZ9 .-\u00e9",
        "\t",
        "\n",
        "\x00",
        "\x1a",
        "\x1f",
        "\x7f",
        "\x85",
        "\xa0",
        "\u2028",
        "\u3000",
    ]
)


def machine_accepts(value: str, limit: int) -> bool:
    try:
        _told(value, "words", limit=limit)
    except CaseRefused:
        return False
    return True


@settings()
@given(st.lists(_PIECES, max_size=12).map("".join))
def test_the_schema_accepts_what_the_machine_accepts_and_nothing_else(value: str) -> None:
    for adapter, limit in ((TOLD, 200), (WHERE, 100)):
        try:
            adapter.validate_python(value)
            schema = True
        except ValidationError:
            schema = False
        assert schema == machine_accepts(value, limit), repr(value)


@pytest.mark.parametrize("value", ["\x1a", "a\x1fb", "\x7f", "x\x85y", "who\tis", "a\nb"])
def test_a_control_character_inside_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        TOLD.validate_python(value)


@pytest.mark.parametrize("value", ["  Hostel 5 warden  ", "\tthe owner\n", "the owner, Hostel 5"])
def test_whitespace_at_the_ends_is_cut_not_refused(value: str) -> None:
    assert TOLD.validate_python(value) == value
    assert machine_accepts(value, 200)


@pytest.mark.parametrize("value", ["", "   ", "\n\t", "　"])
def test_nothing_but_whitespace_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        TOLD.validate_python(value)
    assert not machine_accepts(value, 200)
