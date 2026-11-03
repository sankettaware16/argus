"""Q-E2's independent review, the parts that need no database (the rest is in
``tests/integration/web/test_elk_review.py``): a snapshot's age under a clock that steps back,
and what an ELK session may hold in gold-key ownership."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import elk
from argus.web.capabilities import Capability, elk_capabilities

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
LIMIT = timedelta(seconds=30)
MICRO = timedelta(microseconds=1)


def test_a_snapshot_is_fresh_for_an_age_from_nothing_to_the_limit() -> None:
    assert elk.fresh(NOW, NOW, LIMIT)
    assert elk.fresh(NOW, NOW - LIMIT, LIMIT)
    assert not elk.fresh(NOW, NOW - LIMIT - MICRO, LIMIT)


def test_a_snapshot_from_the_future_is_never_fresh() -> None:
    """F4: the clock stepped back, so the snapshot's age is negative."""
    assert not elk.fresh(NOW, NOW + MICRO, LIMIT)
    assert not elk.fresh(NOW, NOW + timedelta(hours=1), LIMIT)


def test_no_snapshot_is_never_fresh() -> None:
    assert not elk.fresh(NOW, None, LIMIT)


@given(
    age=st.timedeltas(min_value=timedelta(hours=-3), max_value=timedelta(hours=3)),
    limit=st.timedeltas(min_value=timedelta(0), max_value=timedelta(hours=1)),
)
def test_fresh_means_exactly_an_age_in_zero_to_the_limit(age: timedelta, limit: timedelta) -> None:
    assert elk.fresh(NOW, NOW - age, limit) is (timedelta(0) <= age <= limit)


def test_gold_is_an_explicit_grant_in_elk_mode() -> None:
    """F8: what ELK shows never carries it, and a stored list without it grants none."""
    shown = {"view", "see_logs", "review"}
    assert Capability.ANSWER_GOLD not in elk_capabilities(shown, ["view", "see_logs", "review"])
    assert Capability.ANSWER_GOLD in elk_capabilities(shown, ["answer_gold"])
    assert Capability.ANSWER_GOLD not in elk_capabilities({"view"}, ["answer_gold"])  # needs review
