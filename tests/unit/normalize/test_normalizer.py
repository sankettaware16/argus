"""Behaviour of the normalizer: quarantine, time contract (§5.5), group keys (§7.1),
fingerprints, entities, purity and shape invariance."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.normalize import NormalizeContext, NormalizedAlert, Quarantined, normalize
from argus.normalize.grouping import GroupingConfig, RuleGrouping
from argus.normalize.model import (
    Adapter,
    ExecutionType,
    FieldIssueKind,
    KeySource,
    QuarantineReason,
    SingletonReason,
    TimeAnomaly,
    TimeBasis,
    WindowBasis,
)
from argus.normalize.normalizer import MAX_DEPTH, MAX_ENTITY_VALUES, MAX_NODES
from tests.unit.normalize.alerts import (
    ESQL,
    QUERY,
    QUERY_TWO_FIELDS,
    THREAT,
    THRESHOLD,
    Hit,
    all_alerts,
    fixture,
    flatten,
    nest,
    with_id,
)

pytestmark = pytest.mark.unit


def ok(hit: Any, context: NormalizeContext | None = None) -> NormalizedAlert:
    result = normalize(hit) if context is None else normalize(hit, context)
    assert isinstance(result, NormalizedAlert), result
    return result


def quarantined(hit: Any) -> Quarantined:
    result = normalize(hit)
    assert isinstance(result, Quarantined), result
    return result


def t(text: str) -> datetime:
    return datetime.fromisoformat(text).astimezone(UTC)


def issues(alert: NormalizedAlert) -> set[tuple[str, str]]:
    return {(i.field, i.issue.value) for i in alert.field_issues}


# --------------------------------------------------------------------------- quarantine


def test_quarantine_reasons_are_a_closed_set() -> None:
    assert {r.value for r in QuarantineReason} == {
        "not_a_document", "too_large", "missing_field", "invalid_field", "conflicting_field",
        "id_mismatch",
    }  # fmt: skip


@pytest.mark.parametrize("hit", [None, [], "x", 3, {"_id": "a"}, {"_id": "a", "_source": []}])
def test_not_a_document(hit: Any) -> None:
    assert quarantined(hit).reason is QuarantineReason.NOT_A_DOCUMENT


def test_non_string_key_and_non_json_value() -> None:
    for bad in ({1: "x"}, {"a": {1, 2}}, {"a": (1, 2)}, {"a": b"x"}):
        hit = fixture(QUERY)
        hit["_source"]["extra"] = bad
        q = quarantined(hit)
        assert (q.reason, q.field) == (QuarantineReason.NOT_A_DOCUMENT, "_source")
        assert q.alert_id == hit["_id"]


def _deep(levels: int, container: str) -> Any:
    value: Any = "x"
    for _ in range(levels):
        value = {"k": value} if container == "dict" else [value]
    return value


@pytest.mark.parametrize("container", ["dict", "list"])
def test_depth_limit(container: str) -> None:
    hit = fixture(QUERY)
    hit["_source"]["deep"] = _deep(MAX_DEPTH - 2, container)
    ok(hit)
    hit["_source"]["deep"] = _deep(MAX_DEPTH + 5, container)
    assert (quarantined(hit).reason, quarantined(hit).field) == (
        QuarantineReason.TOO_LARGE,
        "depth",
    )
    hit["_source"]["deep"] = _deep(50_000, container)  # far past any recursion limit
    assert quarantined(hit).field == "depth"


def test_node_char_and_number_limits() -> None:
    hit = fixture(QUERY)
    hit["_source"]["many"] = [0] * (MAX_NODES + 1)
    assert quarantined(hit).field == "nodes"
    hit = fixture(QUERY)
    hit["_source"]["long"] = "x" * (32 * 1024 * 1024 + 1)
    assert quarantined(hit).field == "chars"
    hit = fixture(QUERY)
    hit["_source"]["big"] = 1 << 5000
    assert quarantined(hit).field == "number"
    hit["_source"]["big"] = 1 << 4000  # big, but str() and json can still write it
    ok(hit)


def _set(key: str, value: Any) -> Any:
    return lambda hit: hit["_source"].update({key: value})


def _pop(key: str) -> Any:
    return lambda hit: hit["_source"].pop(key)


UUID, RULE_ID, TS = "kibana.alert.uuid", "kibana.alert.rule.rule_id", "@timestamp"


@pytest.mark.parametrize(
    ("edit", "reason", "field"),
    [
        (lambda h: h.pop("_id"), "missing_field", "_id"),
        (lambda h: h.update(_id=5), "invalid_field", "_id"),
        (lambda h: h.update(_id=""), "invalid_field", "_id"),
        (lambda h: h.update(_id="a\x00b"), "invalid_field", "_id"),
        (lambda h: h.update(_id="x" * 513), "invalid_field", "_id"),
        (lambda h: h.pop("_index"), "missing_field", "_index"),
        (lambda h: h.update(_index=["a"]), "invalid_field", "_index"),
        (_pop(UUID), "missing_field", UUID),
        (_set(UUID, "other"), "id_mismatch", UUID),
        (_set(UUID, 7), "invalid_field", UUID),
        (_set("kibana", {"alert": {"uuid": "other"}}), "conflicting_field", UUID),
        (_pop(RULE_ID), "missing_field", RULE_ID),
        (_set(RULE_ID, None), "missing_field", RULE_ID),
        (_set(RULE_ID, "r\ud800"), "invalid_field", RULE_ID),
        (_set(RULE_ID, ["a", "b"]), "conflicting_field", RULE_ID),
        (_pop(TS), "missing_field", TS),
        (_set(TS, "yesterday"), "invalid_field", TS),
        (_set(TS, 1760000000000), "invalid_field", TS),
        (_set(TS, "1969-12-31T23:59:59Z"), "invalid_field", TS),
        (_set(TS, ["2026-10-09T12:00:00Z", "2026-10-09T13:00:00Z"]), "conflicting_field", TS),
    ],
)  # fmt: skip
def test_required_fields(edit: Any, reason: str, field: str) -> None:
    hit = fixture(QUERY)
    edit(hit)
    q = quarantined(hit)
    assert (q.reason.value, q.field) == (reason, field)
    assert q.alert_id == (
        hit.get("_id")
        if isinstance(hit.get("_id"), str)
        and 0 < len(hit["_id"]) <= 512
        and "\x00" not in hit["_id"]
        else None
    )


def test_same_value_in_both_shapes_is_not_a_conflict() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana"] = {"alert": {"uuid": hit["_id"]}}
    ok(hit)


# --------------------------------------------------------------------------- shapes


@pytest.mark.parametrize("name", sorted(all_alerts()))
def test_nested_and_dotted_shapes_normalize_alike(name: str) -> None:
    hit = all_alerts()[name]
    expected = normalize(hit)
    for reshape in (flatten, nest):
        variant = copy.deepcopy(hit)
        variant["_source"] = reshape(variant["_source"])
        assert normalize(variant) == expected


@given(st.data())
def test_any_partial_reshaping_normalizes_alike(data: st.DataObject) -> None:
    name = data.draw(st.sampled_from(sorted(all_alerts())))
    hit = all_alerts()[name]
    expected = normalize(hit)
    flat = flatten(hit["_source"])
    # Nest a random subset of the dotted keys, leave the rest dotted.
    chosen = data.draw(st.sets(st.sampled_from(sorted(flat))))
    source: dict[str, Any] = {k: v for k, v in flat.items() if k not in chosen}
    nested = nest({k: flat[k] for k in chosen})
    for key, value in nested.items():
        if key in source:  # a collision keeps the dotted form
            continue
        source[key] = value
    if any(k in source and isinstance(source[k], dict) and k in flat for k in nested):
        return
    assert normalize({**hit, "_source": source}) == expected


def test_input_is_not_mutated_and_output_is_deterministic() -> None:
    for hit in all_alerts().values():
        before = json.dumps(hit, sort_keys=True)
        first = normalize(hit)
        assert json.dumps(hit, sort_keys=True) == before
        assert normalize(copy.deepcopy(hit)) == first


# --------------------------------------------------------------------------- time (§5.5)


def test_event_alert_time_is_original_time() -> None:
    a = ok(fixture(QUERY))
    assert a.adapter is Adapter.EVENT
    assert a.event_time == t("2026-10-09T12:19:53.636Z") == a.original_time
    assert (a.time_basis, a.event_time_approximate, a.time_fallback) == (
        TimeBasis.ORIGINAL_TIME, False, False,
    )  # fmt: skip
    assert a.evidence_window.basis is WindowBasis.POINT
    assert a.evidence_window.start == a.evidence_window.end == a.event_time
    assert a.detection_lag == a.detected_at - a.event_time == timedelta(seconds=173.981)


def test_threshold_window() -> None:
    a = ok(fixture(THRESHOLD))
    assert a.evidence_window.basis is WindowBasis.THRESHOLD
    assert a.evidence_window.start == t("2026-10-09T12:16:48.559Z")
    assert a.evidence_window.end == t("2026-10-09T12:19:19.564Z") == a.event_time
    hit = fixture(THRESHOLD)
    del hit["_source"]["kibana.alert.threshold_result"]["from"]
    b = ok(hit)
    assert b.evidence_window.basis is WindowBasis.POINT
    assert ("kibana.alert.threshold_result.from", "missing_time") in issues(b)


def _esql(**fields: Any) -> Hit:
    hit = fixture(ESQL)
    hit["_source"].update(fields)
    return hit


def test_esql_aggregate_window_scheduled() -> None:
    a = ok(_esql())  # from now-11m, interval 10m
    anchor = t("2026-10-09T12:17:34.357Z")
    assert a.adapter is Adapter.ESQL_AGGREGATE
    assert (a.event_time, a.time_basis, a.event_time_approximate, a.time_fallback) == (
        anchor, TimeBasis.INTENDED_TIMESTAMP, True, False,
    )  # fmt: skip
    w = a.evidence_window
    assert (w.basis, w.approximate) == (WindowBasis.ESQL_LOOKBACK, True)
    assert (w.start, w.end) == (anchor - timedelta(minutes=21), anchor)


def test_esql_window_slack_uses_observed_execution_capped() -> None:
    rule = fixture(ESQL)["_source"]["kibana.alert.rule.rule_id"]
    anchor = t("2026-10-09T12:17:34.357Z")
    slow = NormalizeContext(observed_max_execution={rule: timedelta(minutes=30)})
    assert ok(_esql(), slow).evidence_window.start == anchor - timedelta(minutes=41)
    fast = NormalizeContext(observed_max_execution={rule: timedelta(seconds=5)})
    assert ok(_esql(), fast).evidence_window.start == anchor - timedelta(minutes=21)
    huge = NormalizeContext(observed_max_execution={rule: timedelta(days=10**6)})
    assert ok(_esql(), huge).evidence_window.start == anchor - timedelta(days=366, minutes=11)


def test_esql_manual_run_has_no_slack() -> None:
    a = ok(_esql(**{"kibana.alert.rule.execution.type": "manual"}))
    anchor = t("2026-10-09T12:17:34.357Z")
    assert a.execution_type is ExecutionType.MANUAL
    assert a.evidence_window.start == anchor - timedelta(minutes=11)


def test_esql_rule_to_and_unparseable_durations() -> None:
    anchor = t("2026-10-09T12:17:34.357Z")
    a = ok(_esql(**{"kibana.alert.rule.to": "now-1m"}))
    assert a.evidence_window.end == anchor - timedelta(minutes=1)
    b = ok(_esql(**{"kibana.alert.rule.from": "now-1d/d"}))
    assert ("kibana.alert.rule.from", "invalid_rule_parameter") in issues(b)
    assert b.evidence_window.start == anchor - timedelta(minutes=20)  # interval as reach
    hit = _esql(**{"kibana.alert.rule.from": "x", "kibana.alert.rule.interval": "y"})
    hit["_source"]["kibana.alert.rule.parameters"]["from"] = "x"
    c = ok(hit)
    assert c.evidence_window.basis is WindowBasis.POINT
    assert c.evidence_window.approximate
    assert c.evidence_window.start == c.evidence_window.end == anchor
    d = ok(_esql(**{"kibana.alert.rule.to": "now-30m"}))  # to beyond from: an empty reach
    assert d.evidence_window.start <= d.evidence_window.end


def test_esql_without_intended_timestamp_falls_back() -> None:
    hit = _esql()
    del hit["_source"]["kibana.alert.intended_timestamp"]
    a = ok(hit)
    assert (a.time_basis, a.time_fallback) == (TimeBasis.DETECTION_TIMESTAMP, True)
    assert a.event_time == a.detected_at


def test_esql_with_concrete_ancestor_but_no_original_time_is_aggregate() -> None:
    hit = _esql(**{"kibana.alert.ancestors": [{"id": "x", "index": "logs-2026.10.09", "depth": 0}]})
    assert ok(hit).adapter is Adapter.ESQL_AGGREGATE


def test_time_offsets_and_invalid_times() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.original_time"] = "2026-10-09T17:49:53.636+05:30"
    assert ok(hit).event_time == t("2026-10-09T12:19:53.636Z")
    hit["_source"]["kibana.alert.original_time"] = "2026-10-09T12:19:53"  # no offset: UTC
    assert ok(hit).event_time == datetime(2026, 10, 9, 12, 19, 53, tzinfo=UTC)
    hit["_source"]["kibana.alert.original_time"] = "not a time"
    a = ok(hit)
    assert ("kibana.alert.original_time", "invalid_time") in issues(a)
    assert (a.time_basis, a.time_fallback) == (TimeBasis.INTENDED_TIMESTAMP, True)


@pytest.mark.parametrize(
    ("delta", "flagged"),
    [(timedelta(minutes=2), False), (timedelta(minutes=2, microseconds=1), True)],
)
def test_event_after_detection_boundary(delta: timedelta, flagged: bool) -> None:
    hit = fixture(QUERY)
    detected = t(hit["_source"]["@timestamp"])
    hit["_source"]["kibana.alert.original_time"] = (detected + delta).isoformat()
    del hit["_source"]["kibana.alert.original_event.ingested"]
    del hit["_source"]["event"]["ingested"]
    assert (TimeAnomaly.EVENT_AFTER_DETECTION in ok(hit).time_anomalies) is flagged


@pytest.mark.parametrize(
    ("delta", "flagged"),
    [(timedelta(minutes=2), False), (timedelta(minutes=2, microseconds=1), True)],
)
def test_event_after_ingest_boundary(delta: timedelta, flagged: bool) -> None:
    hit = fixture(QUERY)
    ingested = t(hit["_source"]["kibana.alert.original_event.ingested"])
    hit["_source"]["kibana.alert.original_time"] = (ingested + delta).isoformat()
    assert (TimeAnomaly.EVENT_AFTER_INGEST in ok(hit).time_anomalies) is flagged
    del hit["_source"]["kibana.alert.original_event.ingested"]  # event.ingested is used next
    assert (TimeAnomaly.EVENT_AFTER_INGEST in ok(hit).time_anomalies) is flagged


# --------------------------------------------------------------------------- group key (§7.1)


def test_declared_suppression_key() -> None:
    a = ok(fixture(QUERY))
    assert a.group_key.source is KeySource.SUPPRESSION
    assert a.group_key.fields == ("source.ip", "destination.ip", "destination.port")
    assert a.group_key.values == ("10.139.146.231", "133.186.7.75", 22)
    assert a.group_key.canonical == (
        '[["destination.ip","133.186.7.75"],["destination.port",22],["source.ip","10.139.146.231"]]'
    )


def test_keyword_field_resolves_parent() -> None:
    a = ok(fixture("query__waf_injection_payload_blocked_in_request_parameters_or_body"))
    assert a.group_key.fields[1] == "url.domain.keyword"
    assert isinstance(a.group_key.values[1], str)
    assert a.group_key.values[1]


def test_threshold_key_comes_from_terms() -> None:
    hit = fixture(THRESHOLD)
    hit["_source"]["source.ip"] = "192.0.2.99"  # the terms are authoritative
    a = ok(hit)
    assert (a.group_key.source, a.group_key.values) == (KeySource.THRESHOLD, ("10.43.119.92",))
    hit["_source"]["kibana.alert.threshold_result"]["terms"] = []  # no terms: read the field
    assert ok(hit).group_key.values == ("192.0.2.99",)
    hit["_source"]["kibana.alert.rule.parameters"]["threshold"]["field"] = []
    assert ok(hit).group_key.source is KeySource.GENERIC


def test_config_and_generic_keys() -> None:
    hit = fixture(THREAT)
    rule = hit["_source"]["kibana.alert.rule.rule_id"]
    a = ok(hit)
    assert (a.group_key.source, a.group_key.fields) == (
        KeySource.GENERIC, ("source.ip", "destination.ip"),
    )  # fmt: skip
    config = NormalizeContext(
        GroupingConfig(rules={rule: RuleGrouping(key_fields=("url.original",))})
    )
    b = ok(hit, config)
    assert (b.group_key.source, b.group_key.values) == (
        KeySource.CONFIG, ("http://33.178.85.107/108945648",),
    )  # fmt: skip


def test_singletons() -> None:
    hit = fixture(ESQL)
    del hit["_source"]["source.ip"]
    a = ok(hit)
    assert (a.group_key.singleton, a.group_key.canonical) == (SingletonReason.ALL_NULL, None)
    hit = fixture(QUERY)
    del hit["_source"]["destination"]["port"]
    b = ok(hit)  # suppress: a missing value is a value
    assert b.group_key.singleton is None
    assert b.group_key.values[2] is None
    hit["_source"]["kibana.alert.rule.parameters"]["alert_suppression"][
        "missing_fields_strategy"
    ] = "doNotSuppress"
    assert ok(hit).group_key.singleton is SingletonReason.MISSING_FIELD
    hit["_source"]["kibana.alert.rule.parameters"]["alert_suppression"][
        "missing_fields_strategy"
    ] = "sometimes"
    c = ok(hit)
    assert c.group_key.singleton is None
    assert (
        "kibana.alert.rule.parameters.alert_suppression.missing_fields_strategy",
        "invalid_rule_parameter",
    ) in issues(c)


def test_key_is_independent_of_group_by_order_and_ip_spelling() -> None:
    hit = fixture(QUERY)
    base = ok(hit).group_key.canonical
    hit["_source"]["kibana.alert.rule.parameters"]["alert_suppression"]["group_by"] = [
        "destination.port", "source.ip", "destination.ip", "source.ip", 7,
    ]  # fmt: skip
    hit["_source"]["source"]["ip"] = "::ffff:10.139.146.231"
    hit["_source"]["destination"]["port"] = "22"
    a = ok(hit)
    assert a.group_key.canonical == base
    assert (
        "kibana.alert.rule.parameters.alert_suppression.group_by",
        "invalid_rule_parameter",
    ) in issues(a)


def test_invalid_key_values_group_deterministically() -> None:
    hit = fixture(QUERY)
    hit["_source"]["source"]["ip"] = "n/a"
    a = ok(hit)
    assert a.group_key.values[0] == "n/a"
    assert ("source.ip", FieldIssueKind.INVALID_IP.value) in issues(a)
    assert all(e.field != "source.ip" for e in a.entities)


# --------------------------------------------------------------------------- fingerprints


def test_same_detection_same_fingerprint() -> None:
    a = ok(fixture(QUERY))
    rerun = with_id(fixture(QUERY), "f" * 64)
    rerun["_source"]["kibana.alert.rule.uuid"] = "another-rule-object"
    rerun["_source"]["@timestamp"] = "2026-10-09T13:00:00.000Z"
    assert ok(rerun).fingerprint == a.fingerprint


def test_fingerprints_differ_for_different_detections() -> None:
    base = ok(fixture(QUERY)).fingerprint
    other_event = fixture(QUERY)
    other_event["_source"]["kibana.alert.ancestors"][0]["id"] = "another"
    other_rule = fixture(QUERY)
    other_rule["_source"]["kibana.alert.rule.rule_id"] = "another-rule"
    assert len({base, ok(other_event).fingerprint, ok(other_rule).fingerprint}) == 3


def test_esql_row_fingerprint() -> None:
    a = ok(fixture(ESQL))
    rerun = with_id(fixture(ESQL), "e" * 40)
    rerun["_source"]["kibana.alert.rule.execution.uuid"] = "other-execution"
    rerun["_source"]["@timestamp"] = "2026-10-09T12:30:00.000Z"
    assert ok(rerun).fingerprint == a.fingerprint
    changed = fixture(ESQL)
    changed["_source"]["total_requests"] = 64
    later = fixture(ESQL)
    later["_source"]["kibana.alert.intended_timestamp"] = "2026-10-09T12:27:34.357Z"
    assert len({a.fingerprint, ok(changed).fingerprint, ok(later).fingerprint}) == 3


def test_threshold_fingerprint() -> None:
    a = ok(fixture(THRESHOLD)).fingerprint
    hit = fixture(THRESHOLD)
    hit["_source"]["kibana.alert.threshold_result"]["count"] = 999  # not part of the identity
    assert ok(with_id(hit, "d" * 64)).fingerprint == a
    hit["_source"]["kibana.alert.threshold_result"]["from"] = "2026-10-09T12:11:48.559Z"
    assert ok(hit).fingerprint != a


# --------------------------------------------------------------------------- other fields


def test_rule_fields() -> None:
    a = ok(fixture(QUERY_TWO_FIELDS))
    assert a.rule_id == fixture(QUERY_TWO_FIELDS)["_source"]["kibana.alert.rule.rule_id"]
    assert (a.severity, a.workflow_status, a.max_signals, a.building_block) == (
        "low", "open", 100, False,
    )  # fmt: skip
    assert a.risk_score == 35.0


def test_rule_type_mismatch_and_invalid_values() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.rule.parameters"]["type"] = "eql"
    hit["_source"]["kibana.alert.risk_score"] = 250
    hit["_source"]["kibana.alert.rule.revision"] = True
    hit["_source"]["kibana.alert.rule.execution.type"] = "sometimes"
    a = ok(hit)
    assert a.rule_type.value == "query"
    assert a.risk_score is None
    assert a.rule_revision is None
    assert a.execution_type is ExecutionType.UNKNOWN
    assert {
        ("kibana.alert.rule.type", "rule_type_mismatch"),
        ("kibana.alert.risk_score", "invalid_value"),
        ("kibana.alert.rule.revision", "invalid_value"),
        ("kibana.alert.rule.execution.type", "invalid_value"),
    } <= issues(a)
    hit["_source"]["kibana.alert.rule.type"] = 5
    del hit["_source"]["kibana.alert.rule.parameters"]["type"]
    b = ok(hit)
    assert (b.rule_type.value, b.rule_type_raw, b.adapter) == ("unknown", None, Adapter.GENERIC)


def test_text_is_cleaned_and_capped() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.rule.name"] = "bad\x00name\ud800" + "x" * 1000
    name = ok(hit).rule_name
    assert name is not None
    assert len(name) == 512
    assert "\x00" not in name
    assert "\ud800" not in name


def test_ancestor_kinds() -> None:
    assert [a.kind.value for a in ok(fixture(QUERY)).ancestors] == ["concrete"]
    assert [a.kind.value for a in ok(fixture(THRESHOLD)).ancestors] == ["pattern"]
    assert [a.kind.value for a in ok(fixture(ESQL)).ancestors] == ["empty"]
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = ["junk", {"id": "x", "index": "a,b", "depth": True}]
    a = ok(hit)
    assert [(x.kind.value, x.depth) for x in a.ancestors] == [("pattern", None)]
    assert ("kibana.alert.ancestors", "invalid_value") in issues(a)
    hit["_source"]["kibana.alert.ancestors"] = [{"id": str(i), "index": "i"} for i in range(150)]
    b = ok(hit)
    assert len(b.ancestors) == 100
    assert ("kibana.alert.ancestors", "too_many_values") in issues(b)


def test_entities() -> None:
    a = ok(fixture(THREAT))
    assert [(e.kind, e.field, e.value) for e in a.entities][:2] == [
        ("ip", "source.ip", "10.148.212.157"),
        ("ip", "destination.ip", "33.178.85.107"),
    ]
    hit = fixture(THREAT)
    hit["_source"]["source"]["ip"] = ["10.0.0.1", "::ffff:10.0.0.1", "bad"] + [
        f"10.0.1.{i}" for i in range(30)
    ]
    b = ok(hit)
    values = [e.value for e in b.entities if e.field == "source.ip"]
    assert values[0] == "10.0.0.1"
    assert len(values) == MAX_ENTITY_VALUES
    assert {("source.ip", "invalid_ip"), ("source.ip", "too_many_values")} <= issues(b)
