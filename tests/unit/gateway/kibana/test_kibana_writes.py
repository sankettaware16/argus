"""The write caps, window and the Kibana lane's shared state (Q-D2, plan §7.1, §7.8), pure:
properties over any sequence of writes from interleaved runs."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, time, timedelta
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.gateway.kibana import writes
from argus.gateway.kibana.writes import (
    KibanaLaneState,
    WriteCaps,
    WriteClass,
    WriteUnits,
    admit_write,
    in_quiet_hours,
    in_window,
)

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 23, 3, 0, tzinfo=UTC)
CAPS = WriteCaps()
CASE = WriteUnits(case_write=True)


@settings(max_examples=300)
@given(
    steps=st.lists(
        st.tuples(st.sampled_from(["r1", "r2", "r3"]), st.integers(0, 7_200),
                  st.integers(0, 6), st.booleans()),
        max_size=120,
    )
)  # fmt: skip
def test_no_sequence_of_writes_breaks_a_cap(steps: list[tuple[str, int, int, bool]]) -> None:
    state = KibanaLaneState()
    now = T0
    admitted: list[tuple[str, datetime, WriteUnits]] = []
    for run, seconds, alerts, case in steps:
        now += timedelta(seconds=seconds)
        units = WriteUnits(case_write=case, alerts=alerts)
        refused, state = admit_write(state, WriteClass.W1, units, now, run, CAPS)
        if refused is None:
            admitted.append((run, now, units))
    cases = [(run, at) for run, at, u in admitted if u.case_write]
    alert_calls = [(at, u.alerts) for _, at, u in admitted if u.alerts]
    for (_, a), (_, b) in pairwise(cases):
        assert b - a >= CAPS.case_gap
    for (a, _), (b, _) in pairwise(alert_calls):
        assert b - a >= CAPS.alert_gap
    assert all(n <= CAPS.alerts_per_call for _, n in alert_calls)
    assert max(Counter(run for run, _ in cases).values(), default=0) <= CAPS.case_per_run
    by_day = Counter(at.date() for _, at in cases)
    assert max(by_day.values(), default=0) <= CAPS.case_per_day
    alerts_by_day: Counter[object] = Counter()
    for at, n in alert_calls:
        alerts_by_day[at.date()] += n
    assert max(alerts_by_day.values(), default=0) <= CAPS.alerts_per_day
    assert all(in_window(at, CAPS) for _, at, _ in admitted)


def test_interleaved_runs_never_reset_each_others_count() -> None:
    state = KibanaLaneState()
    now = T0
    for n in range(10):
        refused, state = admit_write(state, WriteClass.W1, CASE, now, "a", CAPS)
        assert refused is None, n
        now += timedelta(seconds=3)
        refused, state = admit_write(state, WriteClass.W1, CASE, now, "b", CAPS)
        assert refused is None, n
        now += timedelta(seconds=3)
    assert admit_write(state, WriteClass.W1, CASE, now, "a", CAPS)[0] == "run_cap"
    assert admit_write(state, WriteClass.W1, CASE, now, "b", CAPS)[0] == "run_cap"
    assert admit_write(state, WriteClass.W1, CASE, now, "c", CAPS)[0] is None


def test_a_new_day_resets_the_day_but_not_the_gap_or_the_runs() -> None:
    caps = WriteCaps(case_per_day=1, window=(time(1, 30), time(23, 59)))
    late = T0.replace(hour=23, minute=58, second=0)
    refused, state = admit_write(KibanaLaneState(), WriteClass.W1, CASE, late, "r", caps)
    assert refused is None
    assert admit_write(state, WriteClass.W1, CASE, late + timedelta(seconds=5), "r", caps)[0] == (
        "case_daily_cap")  # fmt: skip
    nextday = (T0 + timedelta(days=1)).replace(hour=2)
    refused, state = admit_write(state, WriteClass.W1, CASE, nextday, "r", caps)
    assert refused is None
    assert state.counters.case_writes == 1
    assert state.counters.run_writes("r") == 2


@pytest.mark.parametrize(
    ("moment", "inside"),
    [(time(2, 29, 59), False), (time(2, 30), True), (time(17, 29, 59), True), (time(17, 30), False),
     (time(0, 45), False)],
)  # fmt: skip
def test_the_window(moment: time, inside: bool) -> None:
    assert in_window(datetime.combine(T0.date(), moment, UTC), CAPS) is inside


def test_times_are_utc_and_the_window_never_reaches_the_quiet_hours() -> None:
    from datetime import timezone

    ist = datetime(2026, 10, 23, 9, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    with pytest.raises(ValueError, match="UTC"):
        in_window(ist, CAPS)
    with pytest.raises(ValueError, match="UTC"):
        in_quiet_hours(ist)
    assert in_quiet_hours(T0.replace(hour=1, minute=0))
    with pytest.raises(ValueError, match="quiet"):
        WriteCaps(window=(time(1, 0), time(5, 0)))
    with pytest.raises(ValueError, match="starts before"):
        WriteCaps(window=(time(5, 0), time(4, 0)))
    with pytest.raises(ValueError, match="at least 1"):
        WriteCaps(case_per_run=0)


def test_stop_pause_resume_and_refusals() -> None:
    state = writes.stop(KibanaLaneState(), "401", T0)
    assert writes.stop(state, "403 on a read", T0).stopped == "401"  # the first reason stays
    assert admit_write(state, WriteClass.W1, CASE, T0, "r", CAPS)[0] == "kibana_stopped"
    state = writes.resume(state, None)
    state = writes.pause(state, WriteClass.W2, "403")
    assert writes.pause(state, WriteClass.W2, "answer_mismatch").paused["W2"] == "403"
    assert admit_write(state, WriteClass.W2, CASE, T0, "r", CAPS)[0] == "class_paused"
    assert admit_write(state, WriteClass.W1, CASE, T0, "r", CAPS)[0] is None
    assert writes.resume(state, WriteClass.W2).paused == {}
    nothing = WriteUnits(case_write=False, alerts=0)
    assert admit_write(state, WriteClass.WA, nothing, T0, "r", CAPS)[0] == "nothing_to_write"
    six = WriteUnits(case_write=False, alerts=6)
    assert admit_write(state, WriteClass.WA, six, T0, "r", CAPS)[0] == "alerts_per_call"


@given(
    stopped=st.none() | st.text(max_size=20),
    paused=st.dictionaries(st.sampled_from(["W1", "W2", "W3", "WA"]), st.text(max_size=10)),
    case_writes=st.integers(0, 100),
    runs=st.lists(st.tuples(st.text(min_size=1, max_size=8), st.integers(0, 10)), max_size=16),
)
def test_the_json_form_round_trips(
    stopped: str | None, paused: dict[str, str], case_writes: int, runs: list[tuple[str, int]]
) -> None:
    state = KibanaLaneState(
        stopped=stopped,
        stopped_at=None if stopped is None else T0,
        paused=paused,
        counters=writes.Counters(
            day=T0.date(), case_writes=case_writes, last_case_write=T0, runs=tuple(runs)
        ),
    )
    back = writes.from_json(writes.to_json(state))
    assert (back.stopped, dict(back.paused), back.counters) == (
        state.stopped, paused, state.counters,
    )  # fmt: skip
    assert writes.from_json({}) == KibanaLaneState()
