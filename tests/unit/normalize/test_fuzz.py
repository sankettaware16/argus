"""Fuzzing the normalizer (plan §6, R3 gate: ≥ 100k examples, 0 uncaught exceptions, closed
quarantine reasons).

Two generators: structured mutations of real alerts (fields deleted, retyped, set to hostile
values, reshaped between nested and dotted forms, duplicated with a different value), which reach
deep into the adapters, and arbitrary JSON, which tests the outer defences. The structured test
runs 10x the profile's examples: 100,000 under the gate profile.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.normalize import NormalizedAlert, Quarantined, normalize
from argus.normalize.model import QuarantineReason
from tests.unit.normalize.alerts import all_alerts, flatten, nest

pytestmark = pytest.mark.unit

ALERTS = all_alerts()
FLAT = {name: flatten(hit["_source"]) for name, hit in ALERTS.items()}
EXTRA_PATHS = [
    "kibana.alert.building_block_type",
    "kibana.alert.group.id",
    "kibana.alert.rule.parameters.alert_suppression.group_by",
    "kibana.alert.rule.parameters.alert_suppression.missing_fields_strategy",
    "kibana.alert.rule.parameters.threshold.field",
    "kibana.alert.threshold_result.terms",
    "kibana.alert.threshold_result.from",
    "kibana.alert",
    "kibana",
    "source",
    "destination.domain",
    "dns.question.name",
    "user.name",
]
PATHS = [*sorted({path for flat in FLAT.values() for path in flat}), *EXTRA_PATHS]
QUARANTINE_FIELDS = {
    None, "_id", "_index", "_source", "@timestamp", "kibana.alert.uuid",
    "kibana.alert.rule.rule_id", "depth", "nodes", "chars", "number",
}  # fmt: skip
HEX64 = re.compile(r"[0-9a-f]{64}")

INTERESTING: list[Any] = [
    None, "", [], {}, 0, -1, 1, 2**63, -(2**63), 10**30, True, False, 1.5, -0.0,
    float("nan"), float("inf"), float("-inf"),
    "now", "now-6m", "now-1d/d", "now-999999999d", "5m", "0m", "1M",
    "2026-10-09T12:00:00Z", "2026-10-09T12:00:00.123456789+05:30", "2026-10-09",
    "2026-13-45T99:99:99Z", "1969-12-31T23:59:59Z", "2199-12-31T23:59:59Z", "2200-01-01T00:00:00Z",
    "9999-12-31T23:59:59-14:00", "0001-01-01T00:00:00+14:00",
    "10.0.0.1", "::ffff:10.0.0.1", "fe80::1%eth0", "2001:DB8::1", "010.0.0.1", "256.1.1.1",
    "Bücher.Example.", "xn--", "-.-", "a" * 70 + ".example", "ü" * 80, "。",
    "a\x00b", "\ud800", "x" * 600, "‮", " ",
    ["a", "b"], [["a"]], [[[]]], [None], [{"id": "x", "index": "i"}],
    [{"field": "source.ip", "value": "10.0.0.1"}], [{"field": 3}],
    {"id": "x", "index": "logs-*"}, {"ip": "10.0.0.2"},
    "manual", "scheduled", "suppress", "doNotSuppress", "default",
    "query", "esql", "threshold", "eql", "new_terms", "threat_match", "saved_query",
    "machine_learning", "source.ip", "url.domain.keyword",
]  # fmt: skip

json_scalars = (
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20)
    | st.sampled_from(INTERESTING)
)  # fmt: skip
json_values = st.recursive(
    json_scalars,
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=12), inner, max_size=4)
    ),
    max_leaves=20,
)


def check(hit: Any, result: NormalizedAlert | Quarantined) -> None:
    if isinstance(result, Quarantined):
        assert result.reason in QuarantineReason
        assert result.field in QUARANTINE_FIELDS
        return
    assert isinstance(result, NormalizedAlert)
    assert result.alert_id == hit["_id"]
    assert result.index == hit["_index"]
    result.model_dump_json().encode("utf-8")  # storable: no lone surrogates anywhere
    assert "\x00" not in result.model_dump_json()
    for when in (result.detected_at, result.event_time, result.evidence_window.start):
        assert when.utcoffset() is not None
        assert not when.utcoffset()
    assert result.evidence_window.start <= result.evidence_window.end
    assert result.detection_lag == result.detected_at - result.event_time
    assert HEX64.fullmatch(result.fingerprint)
    key = result.group_key
    assert len(key.fields) == len(key.values)
    assert (key.singleton is None) == (key.canonical is not None)
    if key.canonical is not None:
        json.loads(key.canonical)


@st.composite
def mutated_hits(draw: st.DrawFn) -> dict[str, Any]:
    name = draw(st.sampled_from(sorted(ALERTS)))
    hit = ALERTS[name]
    flat = dict(FLAT[name])
    for _ in range(draw(st.integers(1, 6))):
        op = draw(st.integers(0, 4))
        path = draw(st.sampled_from(PATHS))
        if op == 0:
            flat.pop(path, None)
        elif op == 1:
            flat[path] = draw(st.sampled_from(INTERESTING))
        elif op == 2:
            flat[path] = draw(json_values)
        elif op == 3 and path in flat:
            flat[path] = [flat[path], draw(st.sampled_from(INTERESTING))]
        elif op == 4:  # the same field in the nested form too, maybe with another value
            head, _, tail = path.partition(".")
            if tail and head not in flat:
                flat[head] = {tail: draw(st.sampled_from([flat.get(path), *INTERESTING[:20]]))}
    source: Any = nest(flat) if draw(st.booleans()) else flat
    out: dict[str, Any] = {"_id": hit["_id"], "_index": hit["_index"], "_source": source}
    if draw(st.integers(0, 9)) == 0:
        out["_id"] = draw(st.sampled_from([None, 5, "", "x\x00", hit["_id"].upper()]))
    return out


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=settings().max_examples * 10)
@given(mutated_hits())
def test_mutated_alerts_never_raise(hit: dict[str, Any]) -> None:
    before = json.dumps(hit, sort_keys=True, default=repr)
    result = normalize(hit)
    check(hit, result)
    assert json.dumps(hit, sort_keys=True, default=repr) == before
    assert normalize(copy.deepcopy(hit)) == result


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(json_values, json_values)
def test_arbitrary_json_never_raises(source: Any, ident: Any) -> None:
    for hit in (source, {"_id": ident, "_index": "i", "_source": source}):
        check(hit, normalize(hit))


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(st.dictionaries(st.sampled_from(PATHS), json_values, max_size=12))
def test_alert_shaped_json_never_raises(fields: dict[str, Any]) -> None:
    source = {
        "kibana.alert.uuid": "u",
        "kibana.alert.rule.rule_id": "r",
        "@timestamp": "2026-10-09T00:00:00Z",
    }
    source.update(fields)
    hit = {"_id": "u", "_index": "i", "_source": source}
    check(hit, normalize(hit))
