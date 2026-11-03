"""Q-B2: how the dashboard's threat-list tile reads a dossier's ``ti.listed`` signal: only a known
count above zero is "on a list", only a known zero is "clear"; an unknown answer, a value this
code cannot read, and a dossier with no such signal are never "clear"."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from argus.web.dashboard import _ti_answer

pytestmark = pytest.mark.unit


def row(dossier: bool, status: str | None, value: object) -> SimpleNamespace:
    return SimpleNamespace(has_dossier=dossier, ti_status=status, ti_value=value)


@pytest.mark.parametrize(
    ("dossier", "status", "value", "answer"),
    [
        (True, "known", 1, "on_a_list"),
        (True, "known", 7, "on_a_list"),
        (True, "known", 0.5, "on_a_list"),
        (True, "known", 0, "clear"),
        (True, "known", 0.0, "clear"),
        (True, "known", -1, "clear"),
        (True, "unknown", None, "could_not_tell"),
        (True, "unknown", 3, "could_not_tell"),
        (True, "known", None, "could_not_tell"),
        (True, "known", "many", "could_not_tell"),
        (True, "known", True, "could_not_tell"),
        (True, "known", [1], "could_not_tell"),
        (True, "odd", 1, "could_not_tell"),
        (True, None, None, "not_checked"),
        (False, None, None, "not_checked"),
        (False, "known", 1, "not_checked"),
    ],
)
def test_the_answer_of_each_kind_of_signal(
    dossier: bool, status: str | None, value: object, answer: str
) -> None:
    assert _ti_answer(row(dossier, status, value)) == answer
