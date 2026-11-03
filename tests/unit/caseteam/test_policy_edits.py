"""A title that moved does not wait for the update gap (D-236, D-241): an update plan that holds
only edits is posted at once; a round with new lines still waits its six hours, and a notified case
that did not change since the notice is still not posted again for lines alone."""

from __future__ import annotations

from datetime import timedelta

import pytest

from argus.caseteam import policy
from tests.unit.caseteam.test_policy import NOW, facts

pytestmark = pytest.mark.unit


def posted(**more: object) -> policy.Facts:
    values: dict[str, object] = {
        "open_done": True,
        "version": 2,
        "last_version": 1,
        "last_round_at": NOW - timedelta(hours=1),
        "has_news": True,
    }
    values.update(more)
    return facts(**values)


def test_a_round_with_new_lines_waits_for_the_gap() -> None:
    d = policy.decide(posted())
    assert d.action == "none"
    assert "a short while ago" in d.why


def test_a_plan_of_edits_only_does_not() -> None:
    d = policy.decide(posted(edits_only=True))
    assert d.action == "update"


def test_the_gap_still_ends_by_itself() -> None:
    d = policy.decide(posted(last_round_at=NOW - timedelta(hours=7)))
    assert d.action == "update"


def test_edits_never_post_a_case_that_has_nothing_new_or_a_rejected_report() -> None:
    assert policy.decide(posted(edits_only=True, last_version=2)).action == "none"
    assert policy.decide(posted(edits_only=True, person="rejected")).action == "none"
    assert policy.decide(posted(edits_only=True, has_news=False)).action == "none"
