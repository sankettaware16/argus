"""Evidence and signals (R8, D-023, D-054): task keys, outcomes, bounded snapshots, the fan-in
laws, and that a signal is never known (or 0, or false) on evidence that is not complete."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.context.evidence import (
    COMPLETE,
    STATUS_RANK,
    PackBug,
    SourceUnavailable,
    canonical,
    derived,
    extract,
    local,
    merge_evidence,
    outcome_of,
    task_key,
    unknown,
)
from argus.gateway.errors import (
    AuthFailedError,
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    LiveSessionError,
    OverloadedError,
    PartialResultError,
    SiemError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    TransportFailedError,
    UnsupportedValueError,
)
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Template,
    Window,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, tzinfo=UTC)


class P(Params):
    host: str
    start: datetime
    end: datetime


class LogTemplate(Template):
    name = "test.unit.log"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.MEDIUM
    params_model = P

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, P)
        return RequestPlan(
            self.spec(),
            body={"query": params.host},
            window=Window("squid", params.start, params.end),
        )


class LogTemplateV2(LogTemplate):
    version = 2


# ----------------------------------------------------------------------------- task keys


def test_task_key_is_stable_and_sensitive_to_everything_it_covers() -> None:
    p = P(host="h", start=T0, end=T0.replace(hour=13))
    key = task_key(LogTemplate(), p)
    assert key == task_key(LogTemplate(), P(host="h", start=T0, end=T0.replace(hour=13)))
    assert len(key) == 64
    assert int(key, 16) >= 0
    assert key != task_key(LogTemplateV2(), p)  # the version
    assert key != task_key(LogTemplate(), P(host="g", start=T0, end=T0.replace(hour=13)))
    assert key != task_key(LogTemplate(), P(host="h", start=T0, end=T0.replace(hour=14)))


def test_canonical_is_order_independent_and_refuses_nan() -> None:
    assert canonical({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == '{"a":[2,{"c":4,"d":3}],"b":1}'
    assert canonical("é") == '"é"'
    with pytest.raises(ValueError, match="Out of range"):
        canonical(float("nan"))


# ----------------------------------------------------------------------------- outcomes


@pytest.mark.parametrize(
    "error",
    [
        StoppedError("x"),
        DeferredError("x"),
        BreakerOpenError(None),
        AuthFailedError("x"),
        OverloadedError("x"),
        LiveSessionError("x"),
    ],
)
def test_run_level_errors_defer_the_run(error: Exception) -> None:
    with pytest.raises(SourceUnavailable) as info:
        outcome_of(error)  # type: ignore[arg-type]
    assert info.value.reason == error.reason  # type: ignore[attr-defined]


def test_a_rejected_template_is_a_bug() -> None:
    with pytest.raises(PackBug, match="template rejected: field_not_allowed"):
        outcome_of(TemplateRejectedError("field_not_allowed", "x"))


@pytest.mark.parametrize(
    ("error", "status", "coverage", "code"),
    [
        (UnsupportedValueError("x"), "unsupported_value", {}, "unsupported_value"),
        (BudgetExhaustedError("x"), "skipped_budget", {}, "skipped_budget"),
        (DeadlinePassedError("x"), "timeout", {"timed_out": True}, "deadline_passed"),
        (TimedOutError(), "timeout", {"timed_out": True}, "timed_out"),
        (SourceMissingError("source_expired", ("a", "b")), "source_expired",
         {"missing_indices": ["a", "b"]}, "source_expired"),
        (SourceMissingError("source_not_ready", ("c",)), "source_lag",
         {"missing_indices": ["c"]}, "source_not_ready"),
        # a data stream that is not there says nothing of retention: not final, asked again (F8)
        (SourceMissingError("source_missing", ()), "source_lag",
         {"missing_indices": []}, "source_missing"),
        (PartialResultError("x"), "failed", {"partial": True}, "partial_result"),
        (SiemError(500, None), "failed", {}, "siem_error"),
        (TransportFailedError("x", retriable=True), "failed", {}, "transport_failure"),
    ],
)  # fmt: skip
def test_task_level_outcomes(error: Any, status: str, coverage: Any, code: str) -> None:
    outcome = outcome_of(error)
    assert (outcome.status, outcome.coverage, outcome.error) == (status, coverage, code)
    assert outcome.status in STATUS_RANK


# ----------------------------------------------------------------------------- snapshots

SOURCES = st.dictionaries(st.text(max_size=5), st.text(max_size=30) | st.integers(), max_size=4)


def search(sources: list[Any], total: int, relation: str = "eq", took: int = 5) -> dict[str, Any]:
    return {
        "took": took,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {
            "total": {"value": total, "relation": relation},
            "hits": [{"_index": "i", "_id": str(n), "_source": s} for n, s in enumerate(sources)],
        },
    }


@given(
    sources=st.lists(SOURCES, max_size=40),
    max_rows=st.integers(0, 50),
    max_bytes=st.integers(10, 2_000),
    took=st.integers(0, 10_000),
)
def test_snapshots_are_bounded_and_hashes_ignore_took(
    sources: list[Any], max_rows: int, max_bytes: int, took: int
) -> None:
    got = extract(search(sources, len(sources), took=took), max_rows=max_rows, max_bytes=max_bytes)
    assert len(got.snapshot["rows"]) <= max_rows
    floor = {"total": len(sources), "rows_complete": True, "rows": [], "aggregations": None,
             "dropped": "too_large"}  # fmt: skip
    assert len(canonical(got.snapshot).encode()) <= max(max_bytes, len(canonical(floor)))
    assert got.row_count == len(sources)
    assert got.truncated == (len(got.snapshot["rows"]) < len(sources))
    same = extract(search(sources, len(sources), took=took + 1), max_rows=1, max_bytes=10)
    assert same.result_hash == got.result_hash  # took and the caps never change the hash


def test_snapshot_reads_totals_mget_docs_and_inexact_totals() -> None:
    got = extract(search([{"a": 1}], 10_000, "gte"), max_rows=5, max_bytes=1_000)
    assert (got.row_count, got.exact_total, got.truncated) == (10_000, False, False)
    mget = {"docs": [{"_index": "i", "_id": "1", "found": True, "_source": {"a": 1}},
                     {"_index": "i", "_id": "2", "found": False}]}  # fmt: skip
    got = extract(mget, max_rows=5, max_bytes=1_000)
    assert got.row_count == 1
    assert got.snapshot["rows"][0]["_id"] == "1"
    assert extract({"hits": {"total": 3, "hits": []}}, max_rows=1, max_bytes=100).row_count == 3
    nothing = extract("not a dict", max_rows=1, max_bytes=100)
    assert (nothing.row_count, nothing.snapshot["rows"]) == (0, [])
    aggs = {"hits": {"total": {"value": 9}, "hits": []}, "aggregations": {"x": "y" * 500}}
    dropped = extract(aggs, max_rows=1, max_bytes=100)
    assert dropped.snapshot == {"total": 9, "rows_complete": False, "rows": [],
                                "aggregations": None, "dropped": "too_large"}  # fmt: skip
    assert dropped.truncated


def test_different_answers_hash_differently() -> None:
    a = extract(search([{"a": 1}], 1), max_rows=5, max_bytes=1_000)
    b = extract(search([{"a": 2}], 1), max_rows=5, max_bytes=1_000)
    c = extract(search([{"a": 1}], 2), max_rows=5, max_bytes=1_000)
    assert len({a.result_hash, b.result_hash, c.result_hash}) == 3


# ----------------------------------------------------------------------------- fan-in

KEYS = st.sampled_from([f"{n:064x}" for n in range(4)])
REF = st.fixed_dictionaries(
    {
        "status": st.sampled_from(sorted(STATUS_RANK)),
        "row_count": st.none() | st.integers(0, 5),
        "coverage": st.sampled_from([{}, {"partial": True}]),
        "truncated": st.booleans(),
        "result_hash": st.none() | st.sampled_from(["a", "b"]),
        "reused": st.booleans(),
    }
)
MAPS = st.dictionaries(KEYS, REF, max_size=4).map(
    lambda m: {k: {**v, "task_key": k} for k, v in m.items()}
)


@given(MAPS, MAPS, MAPS)
def test_the_fan_in_is_commutative_and_associative(a: Any, b: Any, c: Any) -> None:
    assert merge_evidence(a, b) == merge_evidence(b, a)
    assert merge_evidence(merge_evidence(a, b), c) == merge_evidence(a, merge_evidence(b, c))
    assert merge_evidence(a, a) == a
    assert merge_evidence(None, a) == a == merge_evidence(a, None)


def test_the_fan_in_keeps_the_better_status() -> None:
    k = "0" * 64
    bad = {k: {"task_key": k, "status": "timeout"}}
    good = {k: {"task_key": k, "status": "ok"}}
    assert merge_evidence(bad, good) == good == merge_evidence(good, bad)


# ----------------------------------------------------------------------------- signals


@given(st.lists(REF, min_size=1, max_size=5), st.integers(-3, 9) | st.booleans() | st.none())
def test_no_signal_is_known_negative_or_zero_on_incomplete_evidence(
    refs: list[Any], value: Any
) -> None:
    refs = [{**r, "task_key": f"{n:064x}"} for n, r in enumerate(refs)]
    for counts in (False, True):
        signal = derived("s", 1, refs, lambda: value, counts=counts)
        assert (signal.status == "known") == (signal.value is not None)
        complete = all(r["status"] in COMPLETE for r in refs)
        partial = any(r["truncated"] or r["coverage"] for r in refs)
        if not complete or value is None:
            assert signal.status == "unknown"
        elif partial:
            if signal.status == "known":
                assert counts
                assert signal.completeness == "lower_bound"
                assert value is not True
                assert value > 0
        else:
            assert (signal.status, signal.completeness, signal.value) == ("known", "exact", value)
        assert list(signal.evidence) == sorted(r["task_key"] for r in refs)


def test_signal_reasons() -> None:
    k = "0" * 64
    assert derived("s", 1, [], lambda: 1).unknown_reason == "no_evidence"
    refs = [{"task_key": k, "status": "timeout"}, {"task_key": "1" * 64, "status": "deferred"}]
    assert derived("s", 1, refs, lambda: 1).unknown_reason == "deferred"  # first sorted status
    ok = [{"task_key": k, "status": "ok"}]
    assert derived("s", 1, ok, lambda: None).unknown_reason == "no_value"
    partial = [{"task_key": k, "status": "ok", "coverage": {"total": "lower_bound"}}]
    assert derived("s", 1, partial, lambda: 0, counts=True).unknown_reason == "partial_coverage"
    assert derived("s", 1, partial, lambda: 3).unknown_reason == "partial_coverage"
    assert local("s", 2, None).as_dict()["unknown_reason"] == "no_value"
    assert local("s", 2, False).as_dict() == {
        "name": "s", "definition_version": 2, "value": False, "status": "known",
        "unknown_reason": None, "completeness": "exact", "evidence": [],
    }  # fmt: skip
    assert unknown("s", 1, "r", ["b", "a"]).evidence == ("a", "b")


def test_known_counts_are_said_as_the_evidence_shows_them() -> None:
    from argus.context.evidence import Known

    known = Known([
        {"name": "a", "status": "known", "value": 1, "completeness": "exact"},
        {"name": "b", "status": "known", "value": 5, "completeness": "lower_bound"},
        {"name": "c", "status": "unknown", "value": None, "completeness": "exact"},
        {"name": "d", "status": "known", "value": 0},
    ])  # fmt: skip
    assert known.by == {"a": 1, "b": 5, "d": 0}
    assert known.low == frozenset({"b"})
    assert known.count("a") == "1"
    assert known.count("b") == "at least 5"
    assert known.count("a", "host", "hosts") == "1 host"
    assert known.count("b", "host", "hosts") == "at least 5 hosts"
    assert known.count("d", "host", "hosts") == "0 hosts"
    assert known.count("a", many="items") == "1"  # no singular given: no noun for one
    with pytest.raises(KeyError):
        known.count("c")
