"""Missing-alert warnings are grouped (R15): runs at the rule's limit are one warning."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from argus.web import queries


def test_runs_at_the_limit_are_one_warning_and_reasons_read_plainly() -> None:
    t = datetime(2026, 10, 13, 0, 16, tzinfo=UTC)
    runs = [{"kind": "truncated_execution", "start_at": t + timedelta(hours=h),
             "end_at": t + timedelta(hours=h), "detail": "100 alerts, the rule's limit is 100"}
            for h in range(9)]  # fmt: skip
    lag = {"kind": "argus_collector_lag", "start_at": t, "end_at": t + timedelta(hours=7),
           "detail": "deadline_passed"}  # fmt: skip
    got = queries.banners([lag, *runs])
    assert [g["kind"] for g in got] == ["argus_collector_lag", "truncated_execution"]
    assert got[0]["text"] == "ARGUS was not collecting (a request ran out of time)"
    assert got[1]["text"] == (
        "the rule hit its alert limit in 9 runs: more alerts may exist for those runs"
    )
    assert (got[1]["start_at"], got[1]["end_at"]) == (t, t + timedelta(hours=8))
    assert len(got[1]["runs"]) == 9
    (one,) = queries.banners(runs[:1])
    assert one["text"] == (
        "the rule hit its alert limit in 1 run (100 alerts, the rule's limit is 100): more"
        " alerts may exist for those runs"
    )
    odd = queries.banners([{**lag, "kind": "new_kind", "detail": "some_code"}])
    assert odd[0]["text"] == "new kind (some code)"
    assert queries.banners([]) == []
