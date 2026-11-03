"""The parts of the triggers that need no database (Q-H4): what counts as a high-confidence
indicator, and the outage conditions from the gateway's health memory, the Kibana lane and the
watch's last run. The SQL ones are in tests/integration/notices."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import watch
from argus.gateway.health import HealthConfig, HealthMemory, HealthState
from argus.gateway.kibana.writes import KibanaLaneState
from argus.notices import triggers
from argus.notices.model import Target

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
CONFIG = HealthConfig()


# --------------------------------------------------------------------------- high confidence


@pytest.mark.parametrize(
    ("value", "high"),
    [
        ("high", True), ("High", True), (" HIGH ", True), ("very high", True), ("Very-High", True),
        ("highest", True), ("critical", True), ("75", True), ("75.0", True), ("90%", True),
        ("100", True), (80, True), (99.5, True),
        ("medium", False), ("low", False), ("none", False), ("", False), (None, False),
        ("74.9", False), ("101", False), ("-80", False), ("0.9", False), ("1", False),
        ("not specified", False), ("high-ish", False), ("nan", False), ("inf", False),
        (True, False), ([], False), ({}, False), ("higher", False), ("75/100", False),
    ],
)  # fmt: skip
def test_what_counts_as_a_high_confidence_indicator(value: Any, high: bool) -> None:
    assert triggers.is_high_confidence(value) is high


@given(st.one_of(st.text(max_size=30), st.floats(allow_nan=True), st.integers(), st.none()))
def test_property_only_the_feeds_top_word_or_a_score_of_75_to_100_is_high(value: Any) -> None:
    if triggers.is_high_confidence(value):
        words = str(value).strip().lower().rstrip("%").strip()
        assert words in triggers.HIGH_WORDS or 75.0 <= float(words) <= 100.0


def answer(value: str, **sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"value": value, "kind": "ip",
            "sources": {name: {"match": hits} for name, hits in sources.items()}}  # fmt: skip


def test_the_dossiers_threat_intel_answers_give_the_high_confidence_count() -> None:
    ti = {
        "listed": ["1.2.3.4", "evil.example", "5.6.7.8", "9.9.9.9"],
        "answers": [
            answer("1.2.3.4", **{"abuse-ioc": [{"confidence": "high"}]}),
            answer(
                "evil.example",
                **{
                    "abuse-ioc": [{"confidence": "low"}],
                    "acme-threat-intel": [{"confidence": "High"}],
                },
            ),
            answer("5.6.7.8", **{"abuse-ioc": [{"confidence": "medium"}]}),
            answer("9.9.9.9", **{"abuse-ioc": [{"description": "no confidence given"}]}),
            answer("8.8.8.8", **{"abuse-ioc": [{"confidence": "high"}]}),  # not in "listed"
        ],
    }
    assert triggers.high_confidence(ti) == 2


def test_a_value_with_two_matching_answers_counts_once() -> None:
    ti = {
        "listed": ["1.2.3.4"],
        "answers": [answer("1.2.3.4", a=[{"confidence": "high"}, {"confidence": "high"}]),
                    answer("1.2.3.4", b=[{"confidence": "high"}])],
    }  # fmt: skip
    assert triggers.high_confidence(ti) == 1


@pytest.mark.parametrize(
    "ti",
    [
        {},
        {"listed": [], "answers": []},
        {"listed": ["1.2.3.4"]},
        {"listed": ["1.2.3.4"], "answers": None},
        {"listed": ["1.2.3.4"], "answers": ["x", 5, None, []]},
        {"listed": ["1.2.3.4"], "answers": [{"value": "1.2.3.4", "sources": "x"}]},
        {"listed": ["1.2.3.4"], "answers": [{"value": "1.2.3.4", "sources": {"a": "x"}}]},
        {"listed": ["1.2.3.4"], "answers": [answer("1.2.3.4", a="high")]},  # type: ignore[arg-type]
        {"listed": ["1.2.3.4"], "answers": [answer("1.2.3.4", a=[5, "high"])]},  # type: ignore[list-item]
        {"listed": [1, None, ["high"]], "answers": [{"value": 1, "sources": {}}]},
        {"listed": "1.2.3.4", "answers": []},
    ],
)  # fmt: skip
def test_a_dossier_that_does_not_look_as_expected_has_no_high_confidence_indicator(
    ti: dict[str, Any],
) -> None:
    assert triggers.high_confidence(ti) == 0


def test_the_pack_is_found_where_the_dossier_keeps_it() -> None:
    body = {"context": {"pack": {"ti": {"listed": ["x"]}}}}
    assert triggers._ti(body) == {"listed": ["x"]}
    for odd in (
        None,
        [],
        {},
        {"context": None},
        {"context": "x"},
        {"context": {"pack": []}},
        {"context": {"pack": {"ti": 5}}},
    ):
        assert triggers._ti(odd) == {}


# --------------------------------------------------------------------------- outages


def memory(
    state: HealthState, *, since: datetime | None = None, probed: datetime | None = NOW
) -> HealthMemory:
    return HealthMemory(state=state, since=since, probed_at=probed)


@pytest.mark.parametrize("state", [HealthState.NORMAL, HealthState.CAUTION])
def test_a_healthy_siem_is_no_outage(state: HealthState) -> None:
    assert triggers.health_outage(memory(state, since=NOW - timedelta(days=1)), NOW) is None


@pytest.mark.parametrize(
    ("state", "severity"), [(HealthState.DEGRADED, "medium"), (HealthState.STOP, "high")]
)
def test_degraded_and_stop_are_outages_that_began_when_the_state_was_entered(
    state: HealthState, severity: str
) -> None:
    got = triggers.health_outage(memory(state, since=NOW - timedelta(hours=3)), NOW, CONFIG)
    assert got is not None
    assert (got.kind, got.subject, got.severity) == ("outage", "siem", severity)
    assert got.since == NOW - timedelta(hours=3)
    assert got.target == Target("health")


def test_a_probe_that_went_quiet_is_the_gateways_own_stop_from_the_grace_on() -> None:
    last = NOW - timedelta(hours=2)
    got = triggers.health_outage(memory(HealthState.NORMAL, probed=last), NOW, CONFIG)
    assert got is not None
    assert got.severity == "high"
    assert got.since == last + CONFIG.stale_stop
    degraded_only = triggers.health_outage(
        memory(HealthState.NORMAL, probed=NOW - CONFIG.stale_degraded), NOW, CONFIG
    )
    assert degraded_only is not None
    assert (degraded_only.severity, degraded_only.since) == ("medium", NOW)
    fresh = triggers.health_outage(
        memory(HealthState.NORMAL, probed=NOW - timedelta(minutes=1)), NOW
    )
    assert fresh is None


def test_a_checkout_that_never_probed_has_no_outage() -> None:
    assert triggers.health_outage(memory(HealthState.NORMAL, probed=None), NOW) is None
    assert triggers.health_outage(HealthMemory(), NOW) is None


def test_a_stopped_kibana_lane_and_each_paused_write_class_are_outages() -> None:
    lane = KibanaLaneState(
        stopped="a 401", stopped_at=NOW - timedelta(hours=2),
        paused=MappingProxyType({"W2": "a 403", "W1": "a wrong answer"}),
    )  # fmt: skip
    got = triggers.kibana_outages(lane)
    assert [(c.subject, c.severity) for c in got] == [
        ("kibana", "medium"), ("kibana:W1", "medium"), ("kibana:W2", "medium"),
    ]  # fmt: skip
    assert got[0].since == NOW - timedelta(hours=2)
    assert got[1].since is None  # a pause carries no time: the first pass that sees it is its start
    assert triggers.kibana_outages(KibanaLaneState()) == []


def test_the_watch_is_late_after_the_time_doctor_calls_late() -> None:
    assert triggers.watch_outage("off", None, NOW) is None
    assert triggers.watch_outage("on", NOW - watch.RUN_LATE, NOW) is None
    late = triggers.watch_outage("local", NOW - watch.RUN_LATE - timedelta(hours=2), NOW)
    assert late is not None
    assert (late.subject, late.severity) == ("watch", "medium")
    assert late.since == NOW - timedelta(hours=2)
    never = triggers.watch_outage("on", None, NOW)
    assert never is not None
    assert never.since is None
    assert never.after == watch.RUN_LATE  # a first run is not late before 36 hours (review R10)


# --------------------------------------------------------------------------- a closure waiting

CASE = uuid.UUID("11111111-1111-4111-8111-111111111111")


def waiting(since_h: float, left_h: float):  # type: ignore[no-untyped-def]
    return triggers.waiting_condition(
        CASE, NOW - timedelta(hours=since_h), NOW + timedelta(hours=left_h), NOW
    )


def test_a_closure_is_worth_a_notice_from_twelve_hours_of_waiting_until_it_expires() -> None:
    assert timedelta(hours=12) == triggers.WAITING  # the plan's 24 became 12 (review R4)
    assert waiting(11.99, 20) is None
    got = waiting(12, 20)
    assert got is not None
    assert (got.kind, got.subject, got.count) == ("closure_waiting", str(CASE), 12)
    assert got.target == Target("case", CASE)
    assert waiting(30, 0) is None  # expired this moment
    assert waiting(30, -1) is None


def test_a_closure_in_its_last_twelve_hours_is_high_and_before_that_medium() -> None:
    assert waiting(25, 12.01).severity == "medium"  # type: ignore[union-attr]
    assert waiting(25, 12).severity == "high"  # type: ignore[union-attr]
    assert waiting(25, 0.5).severity == "high"  # type: ignore[union-attr]


@given(st.floats(0, 100), st.floats(-5, 60))
def test_property_a_waiting_closure_is_told_only_inside_its_life_after_twelve_hours(
    since_h: float, left_h: float
) -> None:
    got = waiting(since_h, left_h)
    since = NOW - timedelta(hours=since_h)
    expires = NOW + timedelta(hours=left_h)
    assert (got is not None) == (NOW - since >= timedelta(hours=12) and expires > NOW)
    if got is not None:
        assert got.count == int(since_h // 1) or abs(got.count - since_h) < 1.0 + 1e-6
        assert got.severity == ("high" if expires - NOW <= timedelta(hours=12) else "medium")
