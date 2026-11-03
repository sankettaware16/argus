"""Exact behaviour of evidence and packs (R8), pinned where mutation testing found the other
tests too loose: snapshot shapes and boundaries, cleaning, totals, the lower-bound rule, the
hashes' recipes, the fan-in order and the pack defaults."""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from argus.context.evidence import (
    STATUS_RANK,
    Extract,
    SourceUnavailable,
    canonical,
    clean,
    derived,
    extract,
    merge_evidence,
    outcome_of,
    task_key,
)
from argus.context.packs import (
    MAX_TASKS_PER_RUN,
    MAX_TASKS_PER_WAVE,
    MAX_WAVES,
    SNAPSHOT_BYTES,
    SNAPSHOT_ROWS,
    Pack,
    StubPack,
    TaskSpec,
    related,
)
from argus.gateway.errors import TimedOutError
from argus.gateway.templates import register
from tests.unit.context.test_evidence import LogTemplate, P
from tests.unit.context.test_packs_and_ddl import NP, Registered

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, tzinfo=UTC)


def body(rows: list[dict[str, Any]], total: Any = "count", **extra: Any) -> dict[str, Any]:
    hits: dict[str, Any] = {"hits": rows}
    if total == "count":
        hits["total"] = {"value": len(rows), "relation": "eq"}
    elif total is not None:
        hits["total"] = total
    return {"hits": hits, **extra}


def row(n: int, size: int = 10) -> dict[str, Any]:
    return {"_index": "idx", "_id": str(n), "_source": {"v": "x" * size}}


# ----------------------------------------------------------------------------- hashes


def test_the_task_key_recipe() -> None:
    params = P(host="h", start=T0, end=T0.replace(hour=13))
    material = {
        "template": "test.unit.log@1",
        "params": {"host": "h", "start": "2026-10-09T12:00:00Z", "end": "2026-10-09T13:00:00Z"},
        "window": ["squid", "2026-10-09T12:00:00+00:00", "2026-10-09T13:00:00+00:00"],
        "names": [],
        "source": None,
    }
    recipe = json.dumps(material, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(recipe.encode()).hexdigest()
    assert task_key(LogTemplate(), params) == expected
    assert expected == "d3275e3ef2bb9cb2c9a7196013fa6ce60ce675300b9ef40afdbe25e2151be2b3"


def test_the_result_hash_recipe() -> None:
    got = extract(body([{"_index": "i", "_id": "1", "_source": {"a": 1}}]), max_rows=5,
                  max_bytes=1_000)  # fmt: skip
    material = {"total": 1, "exact": True, "aggregations": None,
                "rows": [{"_index": "i", "_id": "1", "_source": {"a": 1}}]}  # fmt: skip
    expected = hashlib.sha256(canonical(material).encode()).hexdigest()
    assert got.result_hash == expected
    assert expected == "9744a1eece7730b2be9aa6f4d4cc2173cfe797fb946c87d5119d4d727d2ed7ab"


def test_source_unavailable_carries_its_reason() -> None:
    exc = SourceUnavailable("breaker_open")
    assert (str(exc), exc.reason) == ("breaker_open", "breaker_open")


# ----------------------------------------------------------------------------- snapshots


def test_the_snapshot_shape() -> None:
    got = extract(body([row(1)]), max_rows=5, max_bytes=1_000)
    assert got.snapshot == {
        "total": 1, "rows_complete": True, "aggregations": None,
        "rows": [{"_index": "idx", "_id": "1", "_source": {"v": "x" * 10}}],
    }  # fmt: skip
    assert (got.row_count, got.truncated, got.exact_total, got.has_data) == (1, False, True, True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        got.row_count = 2  # type: ignore[misc]
    assert isinstance(got, Extract)


def test_totals_relations_and_what_counts_as_data() -> None:
    no_relation = extract(body([row(1)], total={"value": 1}), max_rows=5, max_bytes=1_000)
    assert no_relation.exact_total
    assert no_relation.snapshot["rows_complete"]
    plain = extract(body([], total=3), max_rows=5, max_bytes=1_000)
    assert (plain.row_count, plain.has_data, plain.exact_total) == (3, True, True)
    assert plain.snapshot["rows_complete"] is False
    exact_all = extract(body([row(1)], total=1), max_rows=5, max_bytes=1_000)
    assert exact_all.snapshot["rows_complete"] is True
    one = extract(body([row(1)], total={"value": 1, "relation": "eq"}), max_rows=5,
                  max_bytes=1_000)  # fmt: skip
    assert one.has_data  # a total of exactly 1 is data
    gte = extract(body([row(1)], total={"value": 1, "relation": "gte"}), max_rows=5,
                  max_bytes=1_000)  # fmt: skip
    assert not gte.exact_total
    assert gte.snapshot["rows_complete"] is False
    rows_only = extract(body([row(1)], total=None), max_rows=5, max_bytes=1_000)
    assert (rows_only.row_count, rows_only.has_data) == (1, True)
    aggs_only = extract(body([], total=None, aggregations={"a": 1}), max_rows=5, max_bytes=1_000)
    assert (aggs_only.row_count, aggs_only.has_data) == (0, True)
    nothing = extract(body([], total=None, aggregations={}), max_rows=5, max_bytes=1_000)
    assert not nothing.has_data
    zero = extract(body([], total=0, aggregations={"a": 1}), max_rows=5, max_bytes=1_000)
    assert not zero.has_data


def test_mget_documents_count_only_when_found() -> None:
    docs = {"docs": [{"_index": "i", "_id": "1", "_source": {}}, {"_id": "2", "found": False},
                     {"_index": "i", "_id": "3", "found": True, "_source": {}}]}  # fmt: skip
    got = extract(docs, max_rows=5, max_bytes=1_000)
    assert [r["_id"] for r in got.snapshot["rows"]] == ["1", "3"]


def test_rows_are_halved_until_the_snapshot_fits() -> None:
    rows = [row(n, 100) for n in range(8)]
    one = len(canonical(extract(body(rows[:1]), max_rows=50, max_bytes=10**6).snapshot))
    four = len(canonical(extract(body(rows), max_rows=4, max_bytes=10**6).snapshot))
    got = extract(body(rows), max_rows=50, max_bytes=four)  # 8 rows do not fit, 4 exactly
    assert (len(got.snapshot["rows"]), got.truncated) == (4, True)
    assert len(canonical(got.snapshot)) == four  # exactly at the limit: kept
    tight = extract(body(rows), max_rows=50, max_bytes=four - 1)
    assert len(tight.snapshot["rows"]) == 2
    assert one < four


def test_aggregations_are_dropped_only_above_the_limit() -> None:
    aggs = {"a": "y" * 50}
    fits = extract(body([], aggregations=aggs), max_rows=5, max_bytes=10**6).snapshot
    size = len(canonical(fits))
    kept = extract(body([], aggregations=aggs), max_rows=5, max_bytes=size)
    assert kept.snapshot["aggregations"] == aggs
    assert not kept.truncated
    dropped = extract(body([], aggregations=aggs), max_rows=5, max_bytes=size - 1)
    assert dropped.snapshot["dropped"] == "too_large"
    assert dropped.truncated
    assert dropped.snapshot["aggregations"] is None


def test_clean_reaches_keys_values_and_lists() -> None:
    dirty = {"k\x00": ["a\x00", {"\ud800": "\udfff"}, 3, None], "n": 1.5}
    assert clean(dirty) == {"k�": ["a�", {"�": "�"}, 3, None], "n": 1.5}
    assert clean("plain") == "plain"
    assert clean((1, 2)) == (1, 2)  # not JSON: left alone
    assert clean({1: "a\x00"}) == {1: "a�"}


# ----------------------------------------------------------------------------- fan-in, signals


def test_the_fan_in_order_of_statuses() -> None:
    assert STATUS_RANK == {
        "ok": 0, "empty": 0, "source_lag": 1, "timeout": 2, "failed": 2,
        "skipped_budget": 3, "deferred": 3, "source_expired": 4, "unsupported_value": 4,
    }  # fmt: skip
    k = "0" * 64
    ordered = ["ok", "source_lag", "timeout", "deferred", "source_expired", "not_a_status"]
    for better, worse in itertools.pairwise(ordered):
        a, b = {k: {"task_key": k, "status": better}}, {k: {"task_key": k, "status": worse}}
        assert merge_evidence(b, a) == a == merge_evidence(a, b)


def test_a_positive_count_on_partial_evidence_is_a_lower_bound() -> None:
    refs = [{"task_key": "b" * 64, "status": "ok", "truncated": True},
            {"task_key": "a" * 64, "status": "ok"}]  # fmt: skip
    one = derived("s", 1, refs, lambda: 1, counts=True)
    assert (one.status, one.completeness, one.value) == ("known", "lower_bound", 1)
    assert one.evidence == ("a" * 64, "b" * 64)  # sorted, whatever order they came in
    assert derived("s", 1, refs, lambda: True, counts=True).status == "unknown"
    assert derived("s", 1, refs, lambda: 2.5, counts=True).completeness == "lower_bound"
    assert derived("s", 1, refs, lambda: 0, counts=True).status == "unknown"
    assert derived("s", 1, refs, lambda: -1, counts=True).status == "unknown"
    assert derived("s", 1, refs, lambda: 1, counts=False).status == "unknown"
    exact = derived("s", 1, list(reversed(refs[1:])), lambda: 0)
    assert (exact.status, exact.completeness, exact.value) == ("known", "exact", 0)


# ----------------------------------------------------------------------------- packs


def test_pack_limits_and_defaults() -> None:
    assert (MAX_WAVES, MAX_TASKS_PER_WAVE, MAX_TASKS_PER_RUN) == (3, 32, 64)
    assert (SNAPSHOT_ROWS, SNAPSHOT_BYTES) == (50, 16_384)
    spec = TaskSpec(Registered(), NP(n=1))
    assert (spec.priority, spec.max_rows, spec.max_bytes) == (0, 50, 16_384)
    assert spec.ref()["priority"] == 0
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.priority = 1  # type: ignore[misc]
    assert Pack.max_waves == 0
    assert StubPack.max_waves == 0
    assert Pack.budget == {}


@register
class RegisteredLog(LogTemplate):
    name = "test.unit.registered_log"


def test_task_parameters_travel_as_json() -> None:
    ref = TaskSpec(RegisteredLog(), P(host="h", start=T0, end=T0)).ref()
    assert ref["params"] == {"host": "h", "start": "2026-10-09T12:00:00Z",
                             "end": "2026-10-09T12:00:00Z"}  # fmt: skip
    json.dumps(ref)  # the graph state holds it


def test_the_stub_signals_carry_the_store_values() -> None:
    facts = {"alert_count": 5, "duplicate_count": 2, "late_arrivals": 1, "span_minutes": 7,
             "entity_counts": {"ip": 3}}  # fmt: skip
    signals = {s.name: s.value for s in StubPack().local_signals(
        facts, {"related_total": 4, "continues": "x", "supernode_entities": 0})}  # fmt: skip
    assert signals == {
        "alert_count": 5, "duplicate_count": 2, "late_arrivals": 1, "span_minutes": 7,
        "related_investigations": 4, "continues_previous_day": True, "entities.ip": 3,
    }  # fmt: skip


@pytest.mark.parametrize(
    ("total", "supernodes", "expected"),
    [
        (0, 0, ("known", 0, "exact", None)),
        (4, 0, ("known", 4, "exact", None)),
        (1, 1, ("known", 1, "lower_bound", None)),
        (4, 2, ("known", 4, "lower_bound", None)),
        (0, 1, ("unknown", None, "exact", "supernode_entities")),
    ],
)
def test_related_investigations(total: int, supernodes: int, expected: tuple[Any, ...]) -> None:
    s = related(1, total, supernodes)
    assert s.name == "related_investigations"
    assert (s.status, s.value, s.completeness, s.unknown_reason) == expected


def test_outcomes_and_signals_are_immutable() -> None:
    outcome = outcome_of(TimedOutError())
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = "ok"  # type: ignore[misc]
    signal = derived("s", 1, [{"task_key": "a" * 64, "status": "ok"}], lambda: 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        signal.value = 2  # type: ignore[misc]
