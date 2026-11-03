"""The gateway's built-in templates pinned exactly (a change to a request is a version bump), and
their answer readers, written for mutation survivors (D-040)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pydantic
import pytest

from argus.gateway.builtin import (
    AlertIds,
    AlertIdsParams,
    AlertsMget,
    Authenticate,
    BlocksParams,
    ClusterInfo,
    Freshness,
    FreshnessParams,
    HasPrivileges,
    IndexBlocks,
    IndexListing,
    IndexListingParams,
    MgetParams,
    NodeStats,
    PrivilegeParams,
    iso,
)
from argus.gateway.templates import NoParams, Window

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def test_iso() -> None:
    assert iso(T0) == "2026-10-09T12:00:00.000Z"
    ist = timezone(timedelta(hours=5, minutes=30))
    assert iso(datetime(2026, 10, 9, 17, 30, 0, 123456, tzinfo=ist)) == "2026-10-09T12:00:00.123Z"


def test_cluster_templates() -> None:
    assert (ClusterInfo.name, ClusterInfo.version) == ("cluster.info", 1)
    assert ClusterInfo().plan(NoParams()).url_params == (("filter_path", "version.number"),)
    assert (Authenticate.name, Authenticate.version) == ("security.authenticate", 1)
    assert Authenticate().plan(NoParams()).url_params == (
        ("filter_path", "username,authentication_type,api_key.name,api_key.id"),
    )
    assert (NodeStats.name, NodeStats.version) == ("health.node_stats", 2)
    assert NodeStats().plan(NoParams()).url_params == (
        ("filter_path", "_nodes.failed,nodes.*.fs.total,nodes.*.jvm.mem.heap_used_percent,"
         "nodes.*.os.cpu.load_average,nodes.*.thread_pool.search.queue,"
         "nodes.*.thread_pool.search.rejected,nodes.*.thread_pool.write.rejected,"
         "nodes.*.breakers.*.tripped"),
    )  # fmt: skip


def test_has_privileges_request() -> None:
    assert (HasPrivileges.name, HasPrivileges.version) == ("security.has_privileges", 1)
    plan = HasPrivileges().plan(PrivilegeParams(indices=("a", "b")))
    assert plan.body == {
        "cluster": ["monitor", "manage", "manage_security", "manage_api_key", "manage_ilm", "all"],
        "index": [
            {
                "names": ["a", "b"],
                "privileges": ["read", "view_index_metadata", "write", "delete", "manage",
                               "delete_index", "create_index"],
            }
        ],
    }  # fmt: skip
    PrivilegeParams(indices=("a",) * 64)  # the alerts index, each family of a big site, TI
    for count in (0, 65):
        with pytest.raises(pydantic.ValidationError):
            PrivilegeParams(indices=("a",) * count)


CLUSTER_OK = {"monitor": True, "manage": False, "manage_security": False,
              "manage_api_key": False, "manage_ilm": False, "all": False}  # fmt: skip
INDEX_OK = {"read": True, "view_index_metadata": True, "write": False, "delete": False,
            "manage": False, "delete_index": False, "create_index": False}  # fmt: skip


def report(cluster: Any = None, **index: Any) -> dict[str, Any]:
    return {"cluster": CLUSTER_OK if cluster is None else cluster,
            "index": index or {"a": INDEX_OK}}  # fmt: skip


@pytest.mark.parametrize(
    ("body", "problems"),
    [
        (report(), []),
        ([], ["the answer is not a privilege report"]),
        ({"cluster": CLUSTER_OK}, ["the answer is not a privilege report"]),
        ({"index": {}}, ["the answer is not a privilege report"]),
        (report({**CLUSTER_OK, "monitor": False}), ["lacks cluster privilege monitor"]),
        (report({**CLUSTER_OK, "monitor": 1}), ["lacks cluster privilege monitor"]),
        (report({**CLUSTER_OK, "manage_ilm": True}), ["holds cluster privilege manage_ilm"]),
        (report({k: v for k, v in CLUSTER_OK.items() if k != "all"}),
         ["holds cluster privilege all"]),
        (report(b=1, a=INDEX_OK), ["no privilege report for b"]),
        (report(a={**INDEX_OK, "read": False}), ["lacks read on a"]),
        (report(a={**INDEX_OK, "create_index": True}), ["holds create_index on a"]),
        (report(b={**INDEX_OK, "write": True}, a={**INDEX_OK, "delete": None}),
         ["holds delete on a", "holds write on b"]),
    ],
)  # fmt: skip
def test_privilege_problems(body: Any, problems: list[str]) -> None:
    assert HasPrivileges.problems(body) == problems


def test_index_blocks_request_and_answer() -> None:
    assert (IndexBlocks.name, IndexBlocks.version) == ("health.index_blocks", 2)
    plan = IndexBlocks().plan(BlocksParams(indices=("a", "b")))
    assert plan.url_params == (("flat_settings", "true"), ("ignore_unavailable", "true"))
    assert plan.names == ("a", "b")
    BlocksParams(indices=("a",) * 8)
    for count in (0, 9):
        with pytest.raises(pydantic.ValidationError):
            BlocksParams(indices=("a",) * count)
    body = {
        "z": {"settings": {"index.blocks.read_only_allow_delete": "true"}},
        "y": {"settings": {"index.blocks.read_only": "TRUE",
                           "index.blocks.read_only_allow_delete": "true"}},
        "x": {"settings": {"index.blocks.read_only": "false", "index.uuid": "u"}},
        "w": {"settings": "odd"},
        "v": 1,
        "u": {"settings": {"index.blocks.read_only": True}},
    }  # fmt: skip
    assert IndexBlocks.blocked(body) == ["u", "y", "z"]
    assert IndexBlocks.blocked([]) == []


def test_index_listing_request_and_answer() -> None:
    assert (IndexListing.name, IndexListing.version) == ("indices.listing", 1)
    plan = IndexListing().plan(IndexListingParams(source="squid"))
    assert (plan.url_params, plan.source) == ((("filter_path", "indices.name"),), "squid")
    body = {"indices": [{"name": "a"}, {"name": 1}, "b", {"x": "c"}, {"name": "d"}]}
    assert IndexListing.names(body) == ["a", "d"]
    assert IndexListing.names({"indices": {"name": "a"}}) == []
    assert IndexListing.names([]) == []


def test_freshness_request() -> None:
    assert (Freshness.name, Freshness.version, Freshness.max_size) == ("health.freshness", 1, 1)
    plan = Freshness().plan(FreshnessParams(source="dns", now=T0))
    start = T0 - timedelta(minutes=30)
    assert plan.window == Window("dns", start, T0)
    assert plan.body == {
        "size": 1,
        "track_total_hits": False,
        "_source": ["@timestamp", "event.ingested"],
        "sort": [{"event.ingested": {"order": "desc"}}],
        "query": {"range": {"event.ingested": {"gte": "2026-10-09T11:30:00.000Z"}}},
    }


def test_alert_ids_request() -> None:
    assert (AlertIds.name, AlertIds.version, AlertIds.max_size) == ("alerts.ids", 1, 1000)
    params = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0)
    assert params.size == 500
    body = AlertIds().plan(params).body
    assert body == {
        "size": 500,
        "_source": False,
        "track_total_hits": False,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {
            "gte": "2026-10-09T11:55:00.000Z", "lt": "2026-10-09T12:00:00.000Z"}}}]}},
        "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
    }  # fmt: skip
    after = AlertIds().plan(AlertIdsParams(start=T0, end=T0, after=(5, "u"))).body
    assert after["search_after"] == [5, "u"]
    AlertIdsParams(start=T0, end=T0, size=1)
    AlertIdsParams(start=T0, end=T0, size=1000)
    for bad in ({"size": 0}, {"size": 1001}, {"after": (1,)}, {"after": (1, 2, 3)}):
        with pytest.raises(pydantic.ValidationError):
            AlertIdsParams(start=T0, end=T0, **bad)


def test_alerts_mget_request() -> None:
    assert (AlertsMget.name, AlertsMget.version, AlertsMget.whole_documents) == (
        "alerts.mget", 1, True,
    )  # fmt: skip
    plan = AlertsMget().plan(MgetParams(index="i", ids=("a", "b")))
    assert (plan.body, plan.names) == ({"ids": ["a", "b"]}, ("i",))
    MgetParams(index="i" * 255, ids=("a",) * 200)
    for bad in ({"index": ""}, {"index": "i" * 256}, {"ids": ()}, {"ids": ("a",) * 201}):
        with pytest.raises(pydantic.ValidationError):
            MgetParams(**{"index": "i", "ids": ("a",), **bad})
