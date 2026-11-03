"""Inbox helpers written for mutation survivors (D-040): how untrusted text, times and raw
JSON are written, reasons to look, key fields, the enumerations reviews store."""

from __future__ import annotations

import dataclasses
import re
import uuid
from datetime import UTC, datetime
from typing import Any, get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import queries, render, reviews

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (None, "—"),
        ("plain <b>", "plain <b>"),  # escaping is the template's job
        (
            "a\u202eb\u200bc\x00d\u2028e\u2029f",
            "a\u2039U+202E\u203ab\u2039U+200B\u203ac\u2039U+0000\u203ad\u2039U+2028\u203a"
            "e\u2039U+2029\u203af",
        ),
        ("\ue000", "\u2039U+E000\u203a"),
        ({"b": "é", "a": 1}, '{"a": 1, "b": "é"}'),
        (["x"], '["x"]'),
        (5, "5"),
    ],
)
def test_untrusted(value: Any, shown: str) -> None:
    assert render.untrusted(value) == shown


def test_untrusted_caps_length() -> None:
    assert render.CAP == 200
    assert render.untrusted("x" * 200) == "x" * 200
    assert render.untrusted("x" * 201) == "x" * 200 + "…"
    assert render.untrusted("abcdef", 3) == "abc…"


def test_times_and_raw() -> None:
    assert render.ist(T0) == "9 Oct 2026, 5:30 PM IST"
    assert render.ist(None) == "—"
    assert render.utc(T0) == "9 Oct 2026, 12:00:00 PM UTC"
    assert render.utc(None) == ""
    assert render.raw_json({"b": "\u202e", "a": 1}) == '{\n  "a": 1,\n  "b": "\\u202e"\n}'


def test_times_are_twelve_hour_with_midnight_and_noon_right() -> None:
    """The user's rule: IST, 12-hour ("7:20 PM IST"), never 24-hour and never a zero-padded hour."""
    assert render.ist(datetime(2026, 10, 29, 13, 50, tzinfo=UTC)) == "29 Oct 2026, 7:20 PM IST"
    assert render.ist(datetime(2026, 10, 23, 18, 30, tzinfo=UTC)) == "24 Oct 2026, 12:00 AM IST"
    assert render.ist(datetime(2026, 10, 23, 6, 30, tzinfo=UTC)) == "23 Oct 2026, 12:00 PM IST"
    assert render.ist(datetime(2026, 10, 23, 0, 5, tzinfo=UTC)) == "23 Oct 2026, 5:35 AM IST"
    assert render.utc(datetime(2026, 10, 23, 0, 5, 9, tzinfo=UTC)) == "23 Oct 2026, 12:05:09 AM UTC"
    assert [render.hour12(datetime(2026, 1, 1, h, tzinfo=UTC)) for h in (0, 1, 11, 12, 13, 23)] == [
        "12 AM", "1 AM", "11 AM", "12 PM", "1 PM", "11 PM"]  # fmt: skip


@given(
    st.datetimes(
        min_value=datetime(2000, 1, 1, tzinfo=UTC).replace(tzinfo=None),
        max_value=datetime(2099, 12, 31, tzinfo=UTC).replace(tzinfo=None),
        timezones=st.just(UTC),
    )
)
def test_every_time_is_in_the_twelve_hour_form(moment: datetime) -> None:
    shape = r"\d{1,2} [A-Z][a-z]{2} \d{4}, (1[0-2]|[1-9]):[0-5]\d (AM|PM) IST"
    assert re.fullmatch(shape, render.ist(moment))


def summary(**changes: Any) -> queries.Summary:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "rule_id": "r", "rule_name": None, "group_key": "alert:x",
        "bucket_start": T0, "alert_count": 3, "duplicate_count": 0, "first_event_at": T0,
        "last_event_at": T0, "severity": None, "risk_score": None, "version": 1,
        "created_at": T0, "continues_id": None, "human_state": "unreviewed",
        "latest_review": None, "new_since_review": 2,
    }  # fmt: skip
    return queries.Summary(**{**base, **changes})


def test_reasons_to_look() -> None:
    assert queries.reasons(summary()) == []
    assert queries.reasons(summary(human_state="follow_up")) == [
        "A reviewer asked for a follow-up."
    ]
    assert queries.reasons(summary(human_state="changed_since_review")) == [
        "2 new alerts since it was last reviewed."
    ]
    assert queries.reasons(summary(severity="critical")) == ["The rule rates it critical."]
    assert queries.reasons(summary(severity="high")) == ["The rule rates it high."]
    assert queries.reasons(summary(severity="medium")) == []


def test_key_fields() -> None:
    assert queries.key_fields("alert:abc") == []
    assert queries.key_fields('[["source.ip","10.0.0.1"],["destination.port",22]]') == [
        ("source.ip", "10.0.0.1"), ("destination.port", 22),
    ]  # fmt: skip
    assert queries.key_fields("not json") == []
    assert queries.key_fields('[["a"], "b", ["c", 1, 2], ["d", 3]]') == [("d", 3)]
    assert queries.PAGE == 100
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary().version = 2  # type: ignore[misc]


def test_stored_enumerations() -> None:
    """What review_events and the API store and accept, matching migration 0007."""
    assert get_args(queries.HumanState) == (
        "unreviewed", "reviewed", "follow_up", "changed_since_review",
    )  # fmt: skip
    assert get_args(queries.View) == ("attention", "open", "reviewed", "all", "known")
    assert get_args(reviews.Action) == ("reviewed", "follow_up", "note")
    outcomes = ("benign_expected", "benign_policy", "rule_false_positive", "true_positive",
                "inconclusive")  # fmt: skip
    assert get_args(reviews.Outcome) == outcomes
    assert reviews.OUTCOME_LABELS == {
        "benign_expected": "Benign: expected activity",
        "benign_policy": "Benign: allowed by policy",
        "rule_false_positive": "Rule false positive",
        "true_positive": "True positive",
        "inconclusive": "Inconclusive",
    }
    assert reviews.NOTE_LIMIT == 4000
    error = reviews.ReviewConflictError(7, 3)
    assert (str(error), error.latest, error.version) == (
        "someone else reviewed or the investigation changed meanwhile", 7, 3,
    )  # fmt: skip
    with pytest.raises(dataclasses.FrozenInstanceError):
        reviews.Recorded(1, 1).version = 2  # type: ignore[misc]
