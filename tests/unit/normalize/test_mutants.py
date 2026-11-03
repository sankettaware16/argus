"""Tests written for the mutants the R3 suite missed (D-040): exact limits, every entity field,
every pattern character, the quarantine record's index. Limits are literals here on purpose:
a test that imports the constant it checks passes whatever the constant is."""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import Any

import pytest

from argus.normalize import NormalizeContext, normalize
from argus.normalize.model import QuarantineReason
from tests.unit.normalize.alerts import QUERY, THREAT, fixture
from tests.unit.normalize.test_normalizer import _deep, ok, quarantined

pytestmark = pytest.mark.unit


def _measure(doc: Any) -> tuple[int, int]:
    """(nodes, chars) the way _check_document counts: every value is a node, keys and strings
    are chars."""
    nodes = chars = 0
    stack = [doc]
    while stack:
        node = stack.pop()
        nodes += 1
        if isinstance(node, dict):
            chars += sum(len(key) for key in node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            chars += len(node)
    return nodes, chars


def _too_large(hit: Any, field: str) -> None:
    q = quarantined(hit)
    assert (q.reason, q.field) == (QuarantineReason.TOO_LARGE, field)


def test_exact_node_limit() -> None:
    hit = fixture(QUERY)
    nodes, _ = _measure(hit["_source"])
    hit["_source"]["many"] = [0] * (200_000 - nodes - 1)  # the list itself is a node
    assert _measure(hit["_source"])[0] == 200_000
    ok(hit)
    hit["_source"]["many"].append(0)
    _too_large(hit, "nodes")


def test_exact_char_limit() -> None:
    hit = fixture(QUERY)
    _, chars = _measure(hit["_source"])
    hit["_source"]["pad"] = "x" * (32 * 1024 * 1024 - chars - len("pad"))
    assert _measure(hit["_source"])[1] == 32 * 1024 * 1024
    ok(hit)
    hit["_source"]["pad"] += "x"
    _too_large(hit, "chars")


@pytest.mark.parametrize("container", ["dict", "list"])
def test_exact_depth_limit(container: str) -> None:
    hit = fixture(QUERY)
    # _source is depth 1 and "deep" sits at depth 2: a chain of 63 containers ends at depth 64.
    hit["_source"]["deep"] = _deep(63, container)
    ok(hit)
    hit["_source"]["deep"] = _deep(64, container)
    _too_large(hit, "depth")


def test_exact_integer_limit() -> None:
    hit = fixture(QUERY)
    hit["_source"]["big"] = (1 << 4096) - 1  # 4096 bits
    ok(hit)
    hit["_source"]["big"] = 1 << 4096  # 4097 bits
    _too_large(hit, "number")
    hit["_source"]["big"] = -(1 << 4096)
    _too_large(hit, "number")


def test_exact_id_length() -> None:
    hit = fixture(QUERY)
    hit["_id"] = hit["_source"]["kibana.alert.uuid"] = "a" * 512
    hit["_index"] = "i" * 512
    alert = ok(hit)
    assert (alert.alert_id, alert.index) == ("a" * 512, "i" * 512)
    hit["_index"] = "i" * 513
    q = quarantined(hit)
    assert (q.reason, q.field, q.alert_id, q.index) == (
        QuarantineReason.INVALID_FIELD, "_index", "a" * 512, None,
    )  # fmt: skip
    hit["_index"] = "i"
    hit["_id"] = hit["_source"]["kibana.alert.uuid"] = "a" * 513
    q = quarantined(hit)
    assert (q.reason, q.field, q.alert_id, q.index) == (
        QuarantineReason.INVALID_FIELD, "_id", None, "i",
    )  # fmt: skip


def test_quarantine_record_carries_the_index() -> None:
    hit = fixture(QUERY)
    del hit["_source"]["kibana.alert.rule.rule_id"]
    q = quarantined(hit)
    assert (q.alert_id, q.index) == (hit["_id"], hit["_index"])
    hit["_index"] = ["not", "a", "string"]
    q = quarantined(hit)
    assert (q.reason, q.field, q.index) == (QuarantineReason.INVALID_FIELD, "_index", None)


def test_every_entity_field_and_kind() -> None:
    hit = fixture(THREAT)
    hit["_source"]["url"] = {"domain": "Proxy.Example."}
    hit["_source"]["destination"]["domain"] = "cdn.example"
    hit["_source"]["dns"] = {"question": {"name": "ns.example"}}
    hit["_source"]["host"] = {"name": "gw-1"}
    hit["_source"]["user"] = {"name": "alice"}
    alert = ok(hit)
    assert [(e.kind, e.field, e.value) for e in alert.entities] == [
        ("ip", "source.ip", "10.148.212.157"),
        ("ip", "destination.ip", "33.178.85.107"),
        ("domain", "url.domain", "proxy.example"),
        ("domain", "destination.domain", "cdn.example"),
        ("domain", "dns.question.name", "ns.example"),
        ("host", "host.name", "gw-1"),
        ("user", "user.name", "alice"),
    ]


def test_entity_values_are_capped_at_sixteen() -> None:
    hit = fixture(THREAT)
    hit["_source"]["source"]["ip"] = [f"10.0.1.{i}" for i in range(17)]
    alert = ok(hit)
    assert [e.value for e in alert.entities if e.field == "source.ip"] == [
        f"10.0.1.{i}" for i in range(16)
    ]
    issues = {(i.field, i.issue.value) for i in alert.field_issues}
    assert ("source.ip", "too_many_values") in issues
    hit["_source"]["source"]["ip"] = [f"10.0.1.{i}" for i in range(16)]
    alert = ok(hit)
    assert len([e for e in alert.entities if e.field == "source.ip"]) == 16
    assert not alert.field_issues


@pytest.mark.parametrize("char", list("*?,:<>"))
def test_each_pattern_character_makes_a_pattern_ancestor(char: str) -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = [{"id": "x", "index": f"logs{char}a", "depth": 0}]
    assert [a.kind.value for a in ok(hit).ancestors] == ["pattern"]


def test_other_characters_keep_an_ancestor_concrete() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = [{"id": "x", "index": "XX-logs.X", "depth": 0}]
    assert [a.kind.value for a in ok(hit).ancestors] == ["concrete"]


def test_context_is_frozen() -> None:
    context = NormalizeContext()
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.observed_max_execution = {}  # type: ignore[misc]
    assert normalize(fixture(QUERY), context) == normalize(fixture(QUERY))


# --------------------------------------------------------------------------- field helpers


def _issues(alert: Any) -> set[tuple[str, str]]:
    return {(i.field, i.issue.value) for i in alert.field_issues}


def test_single_value_resolution() -> None:
    from argus.normalize.normalizer import _DEFAULT_CONTEXT, _Normalizer

    hit = fixture(QUERY)
    name = hit["_source"]["kibana.alert.rule.name"]
    n = _Normalizer(hit, _DEFAULT_CONTEXT)
    assert n.single("kibana.alert.rule.name") == ("one", name)
    assert n.single("kibana.alert.rule.nothing") == ("missing", None)
    hit["_source"]["kibana"] = {"alert": {"rule": {"name": name}}}
    assert _Normalizer(hit, _DEFAULT_CONTEXT).single("kibana.alert.rule.name") == ("one", name)
    hit["_source"]["kibana"] = {"alert": {"rule": {"name": name + "!"}}}
    assert _Normalizer(hit, _DEFAULT_CONTEXT).single("kibana.alert.rule.name") == (
        "conflict",
        None,
    )


def test_optional_conflict_is_a_field_issue() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana"] = {"alert": {"rule": {"name": "another name"}}}
    alert = ok(hit)
    assert alert.rule_name is None
    assert ("kibana.alert.rule.name", "conflicting_values") in _issues(alert)


def test_text_that_is_not_a_string_is_a_field_issue() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.severity"] = 5
    alert = ok(hit)
    assert alert.severity is None
    assert ("kibana.alert.severity", "invalid_value") in _issues(alert)


@pytest.mark.parametrize(
    ("value", "expected", "issue"),
    [
        (None, None, False),
        (0, 0, False),
        (1000, 1000, False),
        (2**63 - 1, 2**63 - 1, False),
        (2**63, None, True),
        (-1, None, True),
        (True, None, True),
        ("7", None, True),
    ],
)
def test_integer_bounds(value: Any, expected: int | None, issue: bool) -> None:
    hit = fixture(QUERY)
    if value is None:
        del hit["_source"]["kibana.alert.rule.revision"]
    else:
        hit["_source"]["kibana.alert.rule.revision"] = value
    alert = ok(hit)
    assert alert.rule_revision == expected
    assert (("kibana.alert.rule.revision", "invalid_value") in _issues(alert)) is issue


# --------------------------------------------------------------------------- caps and bounds


@pytest.mark.parametrize(
    ("path", "attribute", "cap"),
    [
        ("kibana.alert.rule.uuid", "rule_uuid", 128),
        ("kibana.alert.rule.name", "rule_name", 512),
        ("kibana.alert.severity", "severity", 32),
        ("kibana.alert.workflow_status", "workflow_status", 32),
        ("kibana.alert.rule.execution.uuid", "execution_uuid", 128),
        ("kibana.alert.group.id", "sequence_group_id", 128),
        ("kibana.alert.rule.type", "rule_type_raw", 64),
    ],
)
def test_text_caps(path: str, attribute: str, cap: int) -> None:
    hit = fixture(QUERY)
    hit["_source"][path] = "y" * cap
    assert getattr(ok(hit), attribute) == "y" * cap
    hit["_source"][path] = "y" * (cap + 1)
    assert getattr(ok(hit), attribute) == "y" * cap


def test_ancestor_type_cap() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = [{"id": "x", "index": "i", "type": "t" * 33}]
    assert [a.type for a in ok(hit).ancestors] == ["t" * 32]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0.0), (100, 100.0), (37.5, 37.5),
        (-1, None), (100.5, None), (101, None), (True, None), ("5", None),
    ],
)  # fmt: skip
def test_risk_score_bounds(value: Any, expected: float | None) -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.risk_score"] = value
    alert = ok(hit)
    assert alert.risk_score == expected
    assert (("kibana.alert.risk_score", "invalid_value") in _issues(alert)) is (expected is None)


def test_rule_type_absent_or_not_a_string() -> None:
    hit = fixture(QUERY)
    del hit["_source"]["kibana.alert.rule.type"]
    del hit["_source"]["kibana.alert.rule.parameters"]["type"]
    alert = ok(hit)
    assert (alert.rule_type.value, alert.rule_type_raw) == ("unknown", None)
    assert not any(field == "kibana.alert.rule.type" for field, _ in _issues(alert))
    hit["_source"]["kibana.alert.rule.type"] = 5
    alert = ok(hit)
    assert (alert.rule_type.value, alert.rule_type_raw) == ("unknown", None)
    assert ("kibana.alert.rule.type", "invalid_value") in _issues(alert)


def test_ancestor_with_index_or_id_missing_is_empty() -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = [
        {"id": "x", "index": "", "depth": 0},
        {"id": "", "index": "logs-a", "depth": 0},
        {"index": "logs-a", "depth": 0},
        {"id": 5, "index": "logs-a", "depth": 0},
        {"id": "x", "index": "logs-a", "depth": 0},
    ]
    assert [(a.kind.value, a.index, a.id) for a in ok(hit).ancestors] == [
        ("empty", "", "x"),
        ("empty", "logs-a", ""),
        ("empty", "logs-a", ""),
        ("empty", "logs-a", ""),
        ("concrete", "logs-a", "x"),
    ]


@pytest.mark.parametrize(
    ("depth", "expected"),
    [(0, 0), (999, 999), (1000, None), (-1, None), (True, None), ("1", None), (None, None)],
)
def test_ancestor_depth_bounds(depth: Any, expected: int | None) -> None:
    hit = fixture(QUERY)
    hit["_source"]["kibana.alert.ancestors"] = [{"id": "x", "index": "logs-a", "depth": depth}]
    assert [a.depth for a in ok(hit).ancestors] == [expected]


# --------------------------------------------------------------------------- time fallbacks


def _time_issues(alert: Any) -> set[tuple[str, str]]:
    return {(f, k) for f, k in _issues(alert) if k == "missing_time"}


def test_esql_aggregate_without_intended_timestamp_reports_exactly_that() -> None:
    from tests.unit.normalize.alerts import ESQL

    hit = fixture(ESQL)
    del hit["_source"]["kibana.alert.intended_timestamp"]
    alert = ok(hit)
    assert (alert.time_basis.value, alert.time_fallback) == ("detection_timestamp", True)
    assert _time_issues(alert) == {("kibana.alert.intended_timestamp", "missing_time")}


def test_event_alert_without_any_source_time_falls_back_to_detection() -> None:
    hit = fixture(QUERY)
    del hit["_source"]["kibana.alert.original_time"]
    hit["_source"].pop("kibana.alert.intended_timestamp", None)
    alert = ok(hit)
    assert (alert.time_basis.value, alert.time_fallback, alert.event_time_approximate) == (
        "detection_timestamp",
        True,
        True,
    )
    assert alert.event_time == alert.detected_at
    assert _time_issues(alert) == {("kibana.alert.original_time", "missing_time")}


def test_rule_durations_fall_back_to_the_rule_parameters() -> None:
    from tests.unit.normalize.alerts import ESQL

    expected = ok(fixture(ESQL)).evidence_window
    hit = fixture(ESQL)
    del hit["_source"]["kibana.alert.rule.from"]  # the parameters still say now-11m
    assert ok(hit).evidence_window == expected
    hit["_source"]["kibana.alert.rule.parameters"]["from"] = "now-31m"
    assert ok(hit).evidence_window.start == expected.start - timedelta(minutes=20)


def test_an_absent_rule_duration_is_not_an_issue() -> None:
    from tests.unit.normalize.alerts import ESQL

    hit = fixture(ESQL)
    del hit["_source"]["kibana.alert.rule.to"]
    del hit["_source"]["kibana.alert.rule.parameters"]["to"]
    alert = ok(hit)
    assert alert.evidence_window == ok(fixture(ESQL)).evidence_window  # "to" = now
    assert not alert.field_issues


# --------------------------------------------------------------------------- group keys


def _suppress(hit: Any, group_by: Any, strategy: str | None = None) -> Any:
    suppression: dict[str, Any] = {"group_by": group_by}
    if strategy is not None:
        suppression["missing_fields_strategy"] = strategy
    hit["_source"]["kibana.alert.rule.parameters"]["alert_suppression"] = suppression
    return hit


def test_group_by_names_are_validated() -> None:
    group_by = ["", "a" * 256, "b" * 257, 5, "x\x00y", "source.ip", "source.ip"]
    alert = ok(_suppress(fixture(QUERY), group_by))
    assert alert.group_key.fields == ("a" * 256, "source.ip")
    assert (
        "kibana.alert.rule.parameters.alert_suppression.group_by",
        "invalid_rule_parameter",
    ) in _issues(alert)


def test_group_by_is_capped_at_sixteen_fields() -> None:
    names = [f"f{i}" for i in range(17)]
    alert = ok(_suppress(fixture(QUERY), names))
    assert alert.group_key.fields == tuple(names[:16])
    path = "kibana.alert.rule.parameters.alert_suppression.group_by"
    assert (path, "too_many_values") in _issues(alert)
    alert = ok(_suppress(fixture(QUERY), names[:16]))
    assert alert.group_key.fields == tuple(names[:16])
    assert (path, "too_many_values") not in _issues(alert)


def test_malformed_threshold_terms_are_skipped_with_an_issue() -> None:
    from tests.unit.normalize.alerts import THRESHOLD

    hit = fixture(THRESHOLD)
    hit["_source"]["kibana.alert.threshold_result"]["terms"] = [
        {"field": "source.ip", "value": "10.0.0.1"},
        {"value": "10.0.0.2"},
        "junk",
        {"field": 5, "value": "10.0.0.3"},
    ]
    alert = ok(hit)
    assert alert.group_key.values == ("10.0.0.1",)
    assert ("kibana.alert.threshold_result.terms", "invalid_value") in _issues(alert)
    assert ("kibana.alert.threshold_result.terms", "invalid_value") not in _issues(
        ok(fixture(THRESHOLD))
    )


def test_key_value_issues_are_reported_for_non_entity_fields() -> None:
    hit = _suppress(fixture(QUERY), ["source.port"])
    hit["_source"]["source"]["port"] = "not a port"
    alert = ok(hit)
    assert ("source.port", "invalid_port") in _issues(alert)


def test_do_not_suppress_with_every_field_present_is_not_a_singleton() -> None:
    alert = ok(_suppress(fixture(QUERY), ["source.ip"], "doNotSuppress"))
    assert alert.group_key.missing_fields_strategy == "doNotSuppress"
    assert alert.group_key.singleton is None
    assert alert.group_key.canonical is not None


@pytest.mark.parametrize("field", ["observer.hostname", "observer.name", "agent.hostname",
                                   "agent.name"])  # fmt: skip
def test_the_reporting_device_is_no_host_entity(field: str) -> None:
    """D-066: squid writes its own name (tp8) as host.name and observer.hostname; as an entity
    it linked every proxy alert to every other."""
    hit = fixture(THREAT)
    hit["_source"]["host"] = {"name": "TP8"}
    parent, leaf = field.split(".")
    hit["_source"].setdefault(parent, {})[leaf] = " tp8 "
    alert = ok(hit)
    assert [e for e in alert.entities if e.kind == "host"] == []
    assert alert.normalizer_version == "1.1.0"


def test_a_host_other_than_the_reporting_device_stays() -> None:
    hit = fixture(THREAT)
    hit["_source"]["host"] = {"name": ["pc-12", "tp8"]}
    hit["_source"]["observer"] = {"hostname": "tp8", "name": ""}
    hit["_source"]["agent"] = {"name": 7}  # not a name: ignored
    hosts = [e.value for e in ok(hit).entities if e.kind == "host"]
    assert hosts == ["pc-12"]
    hit["_source"]["observer"] = {"hostname": "tp9"}
    assert [e.value for e in ok(hit).entities if e.kind == "host"] == ["pc-12", "tp8"]
