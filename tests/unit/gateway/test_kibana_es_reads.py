"""Q-D2's Elasticsearch reads: ``alerts.case_links``, ``cluster.license``,
``health.security_index`` and the Kibana keys' self-check template: their requests through the
gateway (exact routes, validated bodies, cost classes) and their answers."""

from __future__ import annotations

import json
from datetime import timedelta

import pydantic
import pytest

from argus.gateway.builtin import (
    AlertCaseLinks,
    CaseLinksParams,
    ClusterLicense,
    KeyPrivileges,
    SecurityIndexHealth,
)
from argus.gateway.templates import CostClass, Endpoint, NoParams, Purpose
from tests.unit.gateway.fakes import FakeTransport, make, ok, search_answer

pytestmark = pytest.mark.unit
ALIAS = ".alerts-security.alerts-acme-soc"


async def test_case_links_by_case_reads_the_alerts_alias_with_complete_results() -> None:
    gateway, transport, store, clock = make()
    transport.default = search_answer([{"_id": "a1", "_source": {"kibana.alert.case_ids": ["c1"]}}])
    result = await gateway.run(
        AlertCaseLinks(), CaseLinksParams(case_ids=("c1", "c2")), purpose=Purpose.KIBANA_READ,
        component="sync", deadline=clock.now + timedelta(seconds=10),
    )  # fmt: skip
    assert result.body["hits"]["hits"][0]["_id"] == "a1"
    call = transport.calls[0]
    assert (call.method, call.path) == ("POST", f"/{ALIAS}/_search")
    assert ("allow_partial_search_results", "false") in call.params
    body = json.loads(call.body or b"")
    assert body["query"] == {
        "bool": {"filter": [{"terms": {"kibana.alert.case_ids": ["c1", "c2"]}}]}
    }
    assert body["size"] == 100
    assert body["_source"] == sorted(AlertCaseLinks.return_fields)
    assert store.ledger[-1].lane == "kibana_read"
    assert store.budget.day_used_ms == 0  # its own lane, not the collector's


async def test_case_links_by_alert_asks_which_list_a_case() -> None:
    gateway, transport, _, clock = make()
    await gateway.run(
        AlertCaseLinks(), CaseLinksParams(alert_ids=("a1",), after=(1, "x")),
        purpose=Purpose.KIBANA_READ, component="sync", deadline=clock.now + timedelta(seconds=10),
    )  # fmt: skip
    body = json.loads(transport.calls[0].body or b"")
    assert body["query"]["bool"]["filter"] == [
        {"ids": {"values": ["a1"]}}, {"exists": {"field": "kibana.alert.case_ids"}},
    ]  # fmt: skip
    assert body["search_after"] == [1, "x"]


def test_case_links_takes_exactly_one_kind_of_id() -> None:
    too_many = tuple(f"c{n}" for n in range(101))
    for bad in ({}, {"case_ids": ("c",), "alert_ids": ("a",)}, {"case_ids": ()},
                {"case_ids": ("../x",)}, {"case_ids": too_many}):  # fmt: skip
        with pytest.raises(pydantic.ValidationError):
            CaseLinksParams(**bad)


async def test_the_licence_and_the_security_index_health() -> None:
    transport = (
        FakeTransport()
        .on("/_license", ok({"license": {"type": "basic", "status": "active"}}))
        .on("/_cluster/health/.security", ok({"status": "green", "active_primary_shards": 1,
                                               "unassigned_primary_shards": 0}))
    )  # fmt: skip
    gateway, transport, _, clock = make(transport)
    lic = await gateway.run(ClusterLicense(), NoParams(), purpose=Purpose.KIBANA_READ,
                            component="t", deadline=clock.now + timedelta(seconds=10))  # fmt: skip
    assert ClusterLicense.summary(lic.body) == ("basic", "active")
    health = await gateway.run(
        SecurityIndexHealth(), NoParams(), purpose=Purpose.IDENTITY, component="t",
        deadline=clock.now + timedelta(seconds=10),
    )  # fmt: skip
    assert SecurityIndexHealth.usable(health.body)
    assert [(c.method, c.path, c.params) for c in transport.calls] == [
        ("GET", "/_license", (("filter_path", "license.type,license.status"),)),
        ("GET", "/_cluster/health/.security",
         (("filter_path", "status,active_primary_shards,unassigned_primary_shards"),)),
    ]  # fmt: skip
    assert {ClusterLicense.cost, SecurityIndexHealth.cost} == {CostClass.LIGHT}
    assert (ClusterLicense.endpoint, SecurityIndexHealth.endpoint) == (
        Endpoint.LICENSE, Endpoint.SECURITY_HEALTH,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("body", "summary"),
    [
        ({"license": {"type": "basic", "status": "active"}}, ("basic", "active")),
        ({"license": {"type": "basic"}}, None),
        ({"license": "basic"}, None),
        (None, None),
    ],
)
def test_licence_summary(body: object, summary: object) -> None:
    assert ClusterLicense.summary(body) == summary


@pytest.mark.parametrize(
    ("body", "usable"),
    [
        ({"status": "green", "unassigned_primary_shards": 0}, True),
        ({"status": "yellow", "unassigned_primary_shards": 0}, True),
        ({"status": "red", "unassigned_primary_shards": 0}, False),
        ({"status": "green", "unassigned_primary_shards": 1}, False),
        ({"status": "green", "unassigned_primary_shards": False}, False),
        ({"status": "green"}, False),
        ([], False),
    ],
)
def test_security_index_usable(body: object, usable: bool) -> None:
    assert SecurityIndexHealth.usable(body) is usable


def test_the_self_check_template_is_a_has_privileges_without_url_parameters() -> None:
    spec = KeyPrivileges.spec()
    assert (spec.endpoint, spec.cost, spec.url_params) == (
        Endpoint.HAS_PRIVILEGES, CostClass.LIGHT, frozenset(),
    )  # fmt: skip
