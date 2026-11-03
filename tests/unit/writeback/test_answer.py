"""Q-D5, the parts that need no database: the status route's answer parsed against what Kibana
8.19.12 recorded and against every way it can be wrong; the caps; the settings (off by default,
at most 100 an alert call); the operator's check; what stops a real run."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus import writeback
from argus.config.settings import Settings, WritebackSettings
from argus.gateway.kibana import models
from argus.gateway.kibana.errors import AnswerMismatchError
from argus.gateway.kibana.writes import (
    KibanaLaneState,
    WriteCaps,
    WriteClass,
    WriteUnits,
    admit_write,
)
from argus.identity.lane import Access, Checked, Identity
from argus.web.capabilities import Capability
from argus.writeback_sender import operator_of, problems_of
from tests.unit.gateway.kibana.fakes import cassette

RECORDED = "alert_writes__test_the_status_route_answers_with_the_update_by_query_body"
NOW = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)


def change(n: int, status: str = "closed") -> models.AlertStatusChange:
    return models.AlertStatusChange(signal_ids=tuple(f"a{k}" for k in range(n)), status=status)  # type: ignore[arg-type]


def clean(n: int) -> dict[str, Any]:
    return {
        "took": 3, "timed_out": False, "total": n, "updated": n, "deleted": 0, "batches": 1,
        "version_conflicts": 0, "noops": 0, "retries": {"bulk": 0, "search": 0},
        "throttled_millis": 0, "requests_per_second": -1, "throttled_until_millis": 0,
        "failures": [],
    }  # fmt: skip


def test_the_recorded_answers_parse_and_the_silent_miss_is_a_mismatch() -> None:
    """Kibana 8.19.12's own answers (the tier's recording): an id it does not find is a 200 with
    total 0, which the plan's "body parsed" exists for."""
    status_calls = [e for e in cassette(RECORDED) if e["path"].endswith("/signals/status")]
    assert len(status_calls) == 4
    verdicts = []
    for exchange in status_calls:
        body = exchange["body"]
        sent = models.AlertStatusChange(signal_ids=tuple(body["signal_ids"]), status=body["status"])
        try:
            models.check_alert_status(exchange["answer"], sent)
            verdicts.append("clean")
        except AnswerMismatchError:
            verdicts.append("mismatch")
    assert verdicts == ["clean", "clean", "mismatch", "clean"]


def test_a_clean_answer_names_every_alert_and_updates_every_one() -> None:
    for n in (1, 5, 100):
        assert models.check_alert_status(clean(n), change(n))["updated"] == n


@pytest.mark.parametrize(
    "over",
    [
        {"failures": [{"cause": {"type": "cluster_block_exception"}}]},
        {"failures": None},
        {"version_conflicts": 1},
        {"timed_out": True},
        {"noops": 1},
        {"deleted": 1},
        {"total": 4},
        {"total": 6},
        {"updated": 4},
        {"updated": 6},
        {"total": True},
        {"updated": "5"},
    ],
)
def test_any_departure_from_a_clean_report_is_a_mismatch(over: dict[str, Any]) -> None:
    with pytest.raises(AnswerMismatchError):
        models.check_alert_status({**clean(5), **over}, change(5))


def test_a_report_that_is_not_a_report_is_a_mismatch() -> None:
    for answer in (None, [], "ok", {}, {"updated": 5}, {"total": 5, "updated": 5}):
        with pytest.raises(AnswerMismatchError):
            models.check_alert_status(answer, change(5))


@given(
    st.integers(1, 100),
    st.integers(-1, 101),
    st.integers(-1, 101),
    st.integers(0, 2),
    st.booleans(),
)
def test_only_the_exact_report_passes(
    n: int, total: int, updated: int, conflicts: int, timed: bool
) -> None:
    report = {**clean(n), "total": total, "updated": updated, "version_conflicts": conflicts,
              "timed_out": timed}  # fmt: skip
    exact = (total, updated, conflicts, timed) == (n, n, 0, False)
    if exact:
        models.check_alert_status(report, change(n))
    else:
        with pytest.raises(AnswerMismatchError):
            models.check_alert_status(report, change(n))


# --------------------------------------------------------------------------- caps and settings


def test_the_model_ceiling_is_100_and_the_lane_cap_is_the_setting() -> None:
    change(100)
    with pytest.raises(ValidationError):
        change(101)
    state = KibanaLaneState()
    units = WriteUnits(case_write=False, alerts=6)
    assert admit_write(state, WriteClass.WA, units, NOW, "r", WriteCaps())[0] == "alerts_per_call"
    wider = WriteCaps(status_per_call=6)
    assert admit_write(state, WriteClass.WA, units, NOW, "r", wider)[0] is None
    # an attach is still held to 5, whatever the status cap says
    assert admit_write(state, WriteClass.W1, units, NOW, "r", wider)[0] == "alerts_per_call"
    for bad in (0, 101):
        with pytest.raises(ValueError, match=r"at least 1|at most 100"):
            WriteCaps(status_per_call=bad)


def test_the_gap_and_the_daily_cap_are_the_lanes_for_every_alert_write() -> None:
    caps = WriteCaps(alerts_per_day=7)
    units = WriteUnits(case_write=False, alerts=5)
    refused, state = admit_write(KibanaLaneState(), WriteClass.WA, units, NOW, "r", caps)
    assert refused is None
    soon = NOW + timedelta(seconds=59)
    assert admit_write(state, WriteClass.WA, units, soon, "r", caps)[0] == "alert_gap"
    later = NOW + timedelta(seconds=61)
    assert admit_write(state, WriteClass.WA, units, later, "r", caps)[0] == "alert_daily_cap"
    # an attach (W1) uses the same gap
    assert admit_write(state, WriteClass.W1, units, soon, "r", caps)[0] == "alert_gap"


def test_write_back_is_off_by_default_and_a_batch_is_at_most_100() -> None:
    s = Settings()
    assert s.writeback == WritebackSettings(enabled=False, batch=5, run_limit=50, f1_audited=False)
    assert "WA" not in s.kibana.write_classes
    for bad in (0, 101):
        with pytest.raises(ValidationError):
            WritebackSettings(batch=bad)
    assert WritebackSettings(batch=100).batch == 100
    with pytest.raises(ValidationError):
        WritebackSettings(unknown=1)  # type: ignore[call-arg]


def test_what_stops_a_real_run() -> None:
    off = Settings()
    assert len(problems_of(off, NOW)) == 4
    on = Settings.model_validate(
        {
            "writeback": {"enabled": True},
            "kibana": {
                "enabled": True,
                "write_classes": ["WA"],
                "alert_writer_api_key": "k",
                "alert_writer_api_key_expires": date(2026, 11, 20),
            },
        }
    )
    assert problems_of(on, NOW) == []

    def changed(**kibana: Any) -> Settings:
        return on.model_copy(update={"kibana": on.kibana.model_copy(update=kibana)})

    assert (
        "expired" in problems_of(changed(alert_writer_api_key_expires=date(2026, 10, 25)), NOW)[0]
    )
    assert "no expiry" in problems_of(changed(alert_writer_api_key_expires=None), NOW)[0]
    assert "WA is not switched on" in problems_of(changed(write_classes=()), NOW)[0]
    assert "not installed" in problems_of(changed(alert_writer_api_key=SecretStr("")), NOW)[0]


# --------------------------------------------------------------------------- the operator


def checked(*caps: Capability) -> Checked:
    return Checked(
        Identity("ravi", "uid-ravi", "Ravi", None),
        Access("ravi", frozenset(caps), False, 1, NOW),
    )


def test_an_operator_must_hold_the_alert_status_privileges_themselves() -> None:
    op = operator_of(checked(Capability.VIEW, Capability.REVIEW))
    assert (op.username, op.argus_uid, op.checked_at) == ("ravi", "uid-ravi", NOW)
    with pytest.raises(writeback.WritebackRefused, match="may not change alert status"):
        operator_of(checked(Capability.VIEW))
    with pytest.raises(writeback.WritebackRefused):
        operator_of(checked())
