"""The margin's derivation (Q-F1, DQ19) on fixtures: the corpus's hit format and the exported
readings, the quantile, the floor, the rounding, too few values, and the script end to end."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.freshness.margin import (
    Parameters,
    Samples,
    derive,
    document_delay,
    parse_time,
    quantile,
    reading_lag,
    yaml_margins,
)

pytestmark = pytest.mark.unit
REPO = Path(__file__).resolve().parents[3]
T0 = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)


def hit(source: str, delay_s: float, index_day: str = "2026.10.08", nested: bool = False) -> dict:
    stamp = T0
    ingested = (stamp + timedelta(seconds=delay_s)).isoformat()
    body: dict = {"@timestamp": stamp.isoformat().replace("+00:00", "Z")}
    if nested:
        body["event"] = {"ingested": ingested}
    else:
        body["event.ingested"] = ingested
    return {"_index": f"acme-logs-{source}-{index_day}", "_id": "x", "_source": body}


P = Parameters(
    min_n=1, min_documents=0
)  # the tests' samples are small; the defaults (F8) need 10,000


def test_quantile_is_nearest_rank() -> None:
    values = [float(v) for v in range(1, 1001)]
    assert quantile(values, 0.999) == 999.0
    assert quantile(values, 1.0) == 1000.0
    assert quantile(values, 0.5) == 500.0
    assert quantile([7.0], 0.999) == 7.0
    assert quantile([3.0, 1.0, 2.0], 0.5) == 2.0  # unsorted input
    with pytest.raises(ValueError, match=r"\w"):
        quantile([], 0.5)
    with pytest.raises(ValueError, match=r"\w"):
        quantile([1.0], 0.0)
    with pytest.raises(ValueError, match=r"\w"):
        quantile([1.0], 1.5)


@given(
    st.lists(st.floats(min_value=0, max_value=1e6), min_size=1, max_size=200),
    st.floats(min_value=0.01, max_value=1.0),
)
def test_the_quantile_is_one_of_the_values_and_bounds_its_share(
    values: list[float], q: float
) -> None:
    got = quantile(values, q)
    assert got in values
    assert sum(v <= got for v in values) >= q * len(values)


def test_document_delays_from_the_corpus_format() -> None:
    assert document_delay(hit("squid", 12.5)) == ("squid", 12.5)
    assert document_delay(hit("dns", 3, nested=True)) == ("dns", 3.0)
    assert document_delay(hit("nginx", -4)) == ("nginx", 0.0)  # a clock ahead counts as 0
    ds = {**hit("postfix", 1), "_index": ".ds-acme-logs-postfix-2026.10.08-000001"}
    assert document_delay(ds) == ("postfix", 1.0)
    assert document_delay({"_index": ".internal.alerts-x", "_source": {}}) is None
    assert document_delay({"_index": "acme-logs-squid-2026.10.08", "_source": {}}) is None
    assert document_delay({"_index": 3, "_source": {}}) is None
    assert document_delay({"_index": "acme-logs-squid-x", "_source": "text"}) is None


def test_times_as_elasticsearch_gives_them() -> None:
    assert parse_time("2026-10-08T10:00:00Z") == T0
    assert parse_time("2026-10-08T10:00:00") == T0  # no zone is UTC
    assert parse_time("2026-10-08T15:30:00+05:30") == T0
    assert parse_time(T0.timestamp() * 1000) == T0
    assert parse_time(["2026-10-08T10:00:00Z"]) == T0
    for bad in (None, True, "yesterday", "x" * 65, float("nan"), 1e30, [], ["a", "b"], {}):
        assert parse_time(bad) is None


def test_reading_lags_from_the_export() -> None:
    row = {
        "source": "squid",
        "outcome": "ok",
        "at": "2026-10-08T10:00:30+00:00",
        "event_at": "2026-10-08T10:00:00+00:00",
    }
    assert reading_lag(row) == ("squid", 30.0)
    assert reading_lag({**row, "outcome": "failed"}) is None
    assert reading_lag({**row, "event_at": None}) is None
    assert reading_lag({**row, "source": 1}) is None


def test_the_margin_is_the_larger_quantile_times_the_factor_rounded_up_with_a_floor() -> None:
    samples = Samples()
    samples.add_hits([hit("squid", 10.0)] * 990 + [hit("squid", 100.0)] * 10)
    samples.add_readings(
        [
            {
                "source": "squid",
                "outcome": "ok",
                "at": "2026-10-08T10:02:00Z",
                "event_at": "2026-10-08T10:00:00Z",
            }
        ]
        * 5
    )
    got = derive(samples, P)["squid"]
    # p99.9 of the documents is 100 s, of the readings 120 s: 120 * 1.5 = 180 s = 3 minutes
    assert (got.reason, got.basis_s, got.margin) == ("derived", 120.0, timedelta(minutes=3))
    assert got.documents is not None
    assert got.documents.n == 1000
    assert got.readings is not None
    assert got.readings.n == 5
    small = Samples()
    small.add_hits([hit("dns", 1.0)] * 1000)
    assert derive(small, P)["dns"].margin == timedelta(minutes=2)  # the floor
    odd = Samples()
    odd.add_hits([hit("nginx", 61.0)] * 1000)
    assert derive(odd, P)["nginx"].margin == timedelta(minutes=2)  # 91.5 s, rounded up to 2 min
    odd.add_hits([hit("nginx", 81.0)] * 1000)
    assert derive(odd, P)["nginx"].margin == timedelta(minutes=3)  # 121.5 s -> 3 min


def test_too_few_values_or_a_margin_over_the_ceiling_gives_none() -> None:
    samples = Samples()
    samples.add_hits([hit("postfix", 1.0)] * 999)
    got = derive(samples)["postfix"]  # the defaults: 10,000 values (F8)
    assert (got.margin, got.reason) == (None, "too_few_values")
    late = Samples()
    late.add_hits([hit("squid", 5 * 3600.0)] * 1000)
    assert derive(late, P)["squid"].reason == "over_ceiling"
    assert derive(late, Parameters(min_n=1, min_documents=0))["squid"].margin is None
    assert Parameters().min_documents == 1000  # and at least 1,000 of them documents (F8)
    assert yaml_margins(derive(late, P)) == "freshness:\n  margins: {}\n"
    for bad in (
        {"quantile": 0},
        {"factor": 0.5},
        {"floor": timedelta(0)},
        {"min_n": 0},
        {"min_documents": -1},
    ):
        with pytest.raises(ValueError, match=r"\w"):
            Parameters(**bad)  # type: ignore[arg-type]


def test_skipped_lines_are_counted_and_the_yaml_lists_derived_margins() -> None:
    samples = Samples()
    samples.add_hits([hit("squid", 1.0)] * 1000 + [{"_index": "x"}, "not a hit"])  # type: ignore[list-item]
    samples.add_readings([{"outcome": "ok"}])
    assert samples.skipped == 3
    text = yaml_margins(derive(samples, P))
    assert text == "freshness:\n  margins:\n    squid: 120s\n"
