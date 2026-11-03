"""Q-B4 independent review: repros that fail on the reviewed head (docs/gates/q-b4-review.md)."""

from __future__ import annotations

import uuid

import pytest

from argus.web import classic

pytestmark = pytest.mark.unit

INV = uuid.UUID(int=7)
# every spelling of one id that FastAPI's ``uuid.UUID`` path parameter accepts (pydantic's UUID)
SPELLINGS = [
    str(INV).upper(),
    INV.hex,
    "{" + str(INV) + "}",
    "urn:uuid:" + str(INV),
]


@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize("action", ["review", "accept", "assess", "gold"])
def test_r1_every_spelling_of_an_id_the_route_accepts_is_a_refused_classic_form(
    spelling: str, action: str
) -> None:
    """The refusal matches the canonical, hyphenated id only; the route behind it takes more."""
    assert classic.action_target(f"/investigations/{spelling}/{action}") == (
        f"/app/investigations/{INV}"
    )


@pytest.mark.parametrize("spelling", SPELLINGS[1:])
def test_r2_every_spelling_of_an_id_the_route_accepts_moves_to_the_app(spelling: str) -> None:
    assert classic.redirect_target(f"/investigations/{spelling}", "") == (
        f"/app/investigations/{INV}"
    )
