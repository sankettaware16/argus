"""Test alerts: the committed sanitized fixtures and synthetic variants derived from them.

The synthetic variants cover what the 2026-10-08 corpus does not contain (manual runs,
new_terms, EQL, saved_query, unknown types, odd times); each is a small, documented edit of a
real fixture so it keeps a real alert's shape.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "alerts"
SNAPSHOTS = REPO_ROOT / "tests" / "fixtures" / "normalized"

Hit = dict[str, Any]


def fixture(name: str) -> Hit:
    data: Hit = json.loads((FIXTURES / f"{name}.json").read_text())
    return data


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*__*.json"))


ESQL = "esql__automated_vulnerability_scanning"
QUERY = "query__proxy_allowed_tunnel_to_remote_admin_or_anonymizer_port"
QUERY_TWO_FIELDS = "query__proxy_plain_http_post_to_raw_ip_address_possible_c2_beacon"
THREAT = "threat_match__cert_x_d_univ_ps1bot_ioc_match"
THRESHOLD = "threshold__proxy_excessive_blocked_requests_from_single_host"


def with_id(hit: Hit, new_id: str) -> Hit:
    hit["_id"] = new_id
    hit["_source"]["kibana.alert.uuid"] = new_id
    return hit


def set_type(hit: Hit, rule_type: str) -> Hit:
    src = hit["_source"]
    src["kibana.alert.rule.type"] = rule_type
    src["kibana.alert.rule.parameters"]["type"] = rule_type
    return hit


def _esql_manual(hit: Hit) -> Hit:
    """A manual run (backfill) of an aggregating ES|QL rule: intended_timestamp is the slot it
    covers, three days before the run."""
    src = hit["_source"]
    src["kibana.alert.rule.execution.type"] = "manual"
    src["kibana.alert.intended_timestamp"] = "2026-10-06T09:00:00.000Z"
    return with_id(hit, "1" * 40)


def _esql_rows(hit: Hit) -> Hit:
    """A non-aggregating ES|QL rule (FROM … METADATA _id, _index): concrete ancestor and
    original_time, like a query alert."""
    src = hit["_source"]
    src["kibana.alert.ancestors"] = [
        {
            "depth": 0,
            "id": "rowAncestor0001",
            "index": "acme-logs-nginx-2026.10.09",
            "type": "event",
        }
    ]
    src["kibana.alert.original_time"] = "2026-10-09T12:15:01.250Z"
    return with_id(hit, "2" * 40)


def _new_terms(hit: Hit) -> Hit:
    set_type(hit, "new_terms")
    src = hit["_source"]
    params = src["kibana.alert.rule.parameters"]
    del params["alert_suppression"]
    params["new_terms_fields"] = ["destination.ip"]
    params["history_window_start"] = "now-7d"
    src["kibana.alert.new_terms"] = [src["destination"]["ip"]]
    return with_id(hit, "3" * 64)


def _saved_query(hit: Hit) -> Hit:
    set_type(hit, "saved_query")
    hit["_source"]["kibana.alert.rule.parameters"]["saved_id"] = "saved-search-1"
    return with_id(hit, "4" * 64)


def _eql_building_block(hit: Hit) -> Hit:
    set_type(hit, "eql")
    src = hit["_source"]
    del src["kibana.alert.rule.parameters"]["alert_suppression"]
    src["kibana.alert.building_block_type"] = "default"
    src["kibana.alert.group.id"] = "eqlgroup0001"
    src["kibana.alert.group.index"] = 0
    return with_id(hit, "5" * 64)


def _eql_sequence(hit: Hit) -> Hit:
    """The shell alert of an EQL sequence: its ancestors are the building-block alerts and it
    carries no original_time."""
    set_type(hit, "eql")
    src = hit["_source"]
    del src["kibana.alert.rule.parameters"]["alert_suppression"]
    del src["kibana.alert.original_time"]
    src["kibana.alert.group.id"] = "eqlgroup0001"
    src["kibana.alert.depth"] = 2
    src["kibana.alert.ancestors"] = [
        {
            "depth": 1,
            "id": "5" * 64,
            "index": ".internal.alerts-security.alerts-x-000001",
            "type": "signal",
        },
        {
            "depth": 1,
            "id": "6" * 64,
            "index": ".internal.alerts-security.alerts-x-000001",
            "type": "signal",
        },
    ]
    return with_id(hit, "7" * 64)


def _machine_learning(hit: Hit) -> Hit:
    set_type(hit, "machine_learning")
    hit["_source"]["kibana.alert.ancestors"] = [
        {"depth": 0, "id": "", "index": "", "type": "event"}
    ]
    return with_id(hit, "8" * 64)


def _unknown_type(hit: Hit) -> Hit:
    """A rule type this normalizer has never seen, without original_time."""
    set_type(hit, "future_rule_type")
    del hit["_source"]["kibana.alert.original_time"]
    return with_id(hit, "9" * 64)


def _threshold_inverted(hit: Hit) -> Hit:
    hit["_source"]["kibana.alert.threshold_result"]["from"] = "2026-10-09T12:21:00.000Z"
    return with_id(hit, "a" * 64)


def _query_no_original_time(hit: Hit) -> Hit:
    del hit["_source"]["kibana.alert.original_time"]
    return with_id(hit, "b" * 64)


def _do_not_suppress_missing(hit: Hit) -> Hit:
    """doNotSuppress and a missing group-by field: the alert is a singleton."""
    params = hit["_source"]["kibana.alert.rule.parameters"]
    params["alert_suppression"]["missing_fields_strategy"] = "doNotSuppress"
    del hit["_source"]["destination"]["port"]
    return with_id(hit, "c" * 64)


SYNTHETIC: dict[str, tuple[str, Callable[[Hit], Hit]]] = {
    "synthetic__esql_manual_run": (ESQL, _esql_manual),
    "synthetic__esql_non_aggregating": (ESQL, _esql_rows),
    "synthetic__new_terms": (QUERY, _new_terms),
    "synthetic__saved_query": (QUERY, _saved_query),
    "synthetic__eql_building_block": (QUERY, _eql_building_block),
    "synthetic__eql_sequence": (QUERY, _eql_sequence),
    "synthetic__machine_learning": (THREAT, _machine_learning),
    "synthetic__unknown_rule_type": (THREAT, _unknown_type),
    "synthetic__threshold_inverted_window": (THRESHOLD, _threshold_inverted),
    "synthetic__query_without_original_time": (QUERY, _query_no_original_time),
    "synthetic__do_not_suppress_missing_field": (QUERY, _do_not_suppress_missing),
}


def synthetic(name: str) -> Hit:
    base, edit = SYNTHETIC[name]
    return edit(copy.deepcopy(fixture(base)))


def all_alerts() -> dict[str, Hit]:
    out = {name: fixture(name) for name in fixture_names()}
    out.update({name: synthetic(name) for name in SYNTHETIC})
    return out


# ---------------------------------------------------------------------------- shapes


def flatten(source: dict[str, Any]) -> dict[str, Any]:
    """Every object turned into dotted keys (arrays kept), as ES|QL alerts are written."""
    out: dict[str, Any] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict) and value:
            for key, item in value.items():
                walk(f"{prefix}.{key}" if prefix else key, item)
        else:
            out[prefix] = value

    walk("", source)
    return out


def nest(source: dict[str, Any]) -> dict[str, Any]:
    """Every dotted key turned into nested objects (where that does not collide)."""
    out: dict[str, Any] = {}
    for key, value in flatten(source).items():
        node = out
        parts = key.split(".")
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                break
            node = child
        else:
            node[parts[-1]] = value
            continue
        out[key] = value
    return out
