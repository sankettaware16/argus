"""The Kibana read-back's one word for the status bar, from its newest cycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web.queries import SYNC_LATE, sync_state

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 4, 8, 0, tzinfo=UTC)


def test_no_cycle_is_none_never_ok() -> None:
    assert sync_state(None, NOW) == "none"


@pytest.mark.parametrize(
    ("outcome", "word"), [("complete", "ok"), ("partial", "partial"), ("failed", "failed")]
)
def test_a_recent_cycle_says_its_outcome(outcome: str, word: str) -> None:
    assert sync_state({"finished_at": NOW - timedelta(minutes=5), "outcome": outcome}, NOW) == word


def test_an_unknown_outcome_is_never_ok() -> None:
    assert sync_state({"finished_at": NOW, "outcome": "odd"}, NOW) == "failed"


@given(
    st.integers(min_value=0, max_value=10 * 24 * 3600),
    st.sampled_from(["complete", "partial", "failed"]),
)
def test_late_exactly_when_older_than_the_limit(age_s: int, outcome: str) -> None:
    got = sync_state({"finished_at": NOW - timedelta(seconds=age_s), "outcome": outcome}, NOW)
    assert (got == "late") == (timedelta(seconds=age_s) > SYNC_LATE)
