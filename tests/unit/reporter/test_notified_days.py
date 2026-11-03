"""The weekly report's alerts a day and trend for a notified device are IST days (AR4b, D-181), as
the rest of the reports: the period is UTC days, so the first and the last IST day it touches are
counted whole."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from argus.cases.knownview import KnownCase
from argus.reporter import model, sections


def a_case(per_day: dict[str, int]) -> KnownCase:
    return KnownCase(
        uuid.UUID(int=1), 7, "Beaconing", "open", "high", datetime(2026, 10, 20, 9, tzinfo=UTC),
        None, False, 1, 1, 0, sum(per_day.values()), 9, per_day,
    )  # fmt: skip


def trend_of(per_day: dict[str, int]) -> str:
    window = model.window_for("weekly", date(2026, 10, 28), datetime(2026, 10, 29, 6, tzinfo=UTC))
    # the week is 22 Oct 00:00 to 29 Oct 00:00 UTC: 22 Oct 05:30 to 29 Oct 05:30 IST
    metrics = sections._notified_case(a_case(per_day), sum(per_day.values()), window)
    (found,) = [m for m in metrics if m.key.endswith(".trend")]
    return str(found.value)


def test_the_last_ist_day_the_week_touches_is_counted() -> None:
    """29 Oct IST begins at 6:30 PM UTC on the 28th, inside the week: its alerts count."""
    assert trend_of({"2026-10-22": 5, "2026-10-23": 1, "2026-10-29": 20}) == "rising"


def test_days_outside_the_week_are_left_out() -> None:
    assert trend_of({"2026-10-21": 90, "2026-10-22": 1, "2026-10-28": 9, "2026-10-30": 90}) == (
        "rising"
    )
    assert trend_of({"2026-10-20": 1}) == "too few days to say"
