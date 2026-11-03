"""The discovery templates (P4-D1): their requests, what the validator allows and refuses, the
caps on what they keep, and the licence, version and feature reads that go with them."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from argus.gateway.discovery import (
    DISCOVERY_SCOPES,
    MAX_BACKING,
    MAX_FIELDS,
    MAX_NAMES,
    DiscoverFieldMapping,
    DiscoverIlmPolicies,
    DiscoverIndices,
    DiscoverPrivileges,
    IndicesParams,
    MappingParams,
)
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway
from argus.gateway.templates import REGISTRY, CostClass, Family, NoParams, Purpose
from argus.gateway.transport import wire_path
from argus.gateway.validator import (
    DISCOVERY_EXPAND,
    DISCOVERY_PATTERNS,
    MAX_DISCOVERY_FIELDS,
    FinalRequest,
    validate,
)
from argus.site import DISCOVERY_FIELDS, FIELD_ROLES
from tests.unit.gateway.fakes import T0, FakeTransport, make, ok

pytestmark = pytest.mark.unit

DEADLINE = T0 + timedelta(minutes=1)
preview = Gateway(None, None)  # type: ignore[arg-type]  # sends nothing


def final(template: Any, params: Any) -> FinalRequest:
    return preview.preview(template, params, deadline=DEADLINE, now=T0)


def code(request: FinalRequest) -> str:
    with pytest.raises(TemplateRejectedError) as caught:
        validate(request)
    return caught.value.code


def test_the_templates_are_registered_light_and_in_the_discovery_family() -> None:
    for name in (
        "discover.indices",
        "discover.field_mapping",
        "discover.ilm",
        "discover.privileges",
    ):
        spec = REGISTRY[name].spec()
        assert (spec.family, spec.cost) == (Family.DISCOVERY, CostClass.LIGHT)
        assert spec.max_size == 0


def test_the_consistent_constants() -> None:
    assert frozenset(DISCOVERY_SCOPES.values()) == DISCOVERY_PATTERNS
    assert MAX_FIELDS == MAX_DISCOVERY_FIELDS
    assert {"open", "open,hidden"} == DISCOVERY_EXPAND
    assert len(DISCOVERY_FIELDS) <= MAX_FIELDS
    assert {name for names in FIELD_ROLES.values() for name in names.values()} <= DISCOVERY_FIELDS


@pytest.mark.parametrize(
    ("scope", "path", "expand"),
    [
        ("data", "/_resolve/index/*", "open"),
        ("alerts", "/_resolve/index/.alerts-security.alerts-*", "open,hidden"),
    ],
)
def test_the_listing_request(scope: str, path: str, expand: str) -> None:
    request = final(DiscoverIndices(), IndicesParams(scope=scope))  # type: ignore[arg-type]
    validate(request)
    assert wire_path(request) == ("GET", path)
    assert dict(request.url_params)["expand_wildcards"] == expand
    assert request.body is None
    assert request.indices == ()


def test_the_validator_holds_the_listing_to_its_two_patterns() -> None:
    spec = DiscoverIndices.spec()
    for pattern in ("*", ".alerts-security.alerts-*"):
        validate(FinalRequest(spec, (), pattern, (("expand_wildcards", "open"),)))
    for bad in ("logs-*", "**", "", "a,b", None, ".security*"):
        assert code(FinalRequest(spec, (), bad)) == "index_not_allowed"
    assert code(FinalRequest(spec, ("x",), "*")) == "index_not_allowed"
    assert code(FinalRequest(spec, (), "*", (("expand_wildcards", "all"),))) == "forbidden_param"
    assert code(FinalRequest(spec, (), "*", (("size", "1"),))) == "forbidden_param"
    assert code(FinalRequest(spec, (), "*", (), {"q": 1})) == "bad_shape"


def test_the_gateway_names_the_scope_and_refuses_an_unknown_one() -> None:
    plan = DiscoverIndices().plan(IndicesParams(scope="alerts"))
    assert plan.source == "alerts"
    with pytest.raises(ValidationError):
        IndicesParams(scope="everything")  # type: ignore[arg-type]
    bad = replace(plan, source="nope")
    gateway = Gateway(None, None)  # type: ignore[arg-type]
    with pytest.raises(TemplateRejectedError, match="unknown discovery scope"):
        gateway._wanted(bad)


def test_the_mapping_request_names_one_index_and_allowlisted_fields() -> None:
    params = MappingParams(index=".ds-logs-nginx.access-default-2026.10.30-000001",
                           fields=("url.path", "source.ip", "@timestamp"))  # fmt: skip
    request = final(DiscoverFieldMapping(), params)
    validate(request)
    assert wire_path(request) == (
        "GET",
        "/.ds-logs-nginx.access-default-2026.10.30-000001/_mapping/field/@timestamp,source.ip,url.path",
    )
    assert dict(request.url_params) == {"filter_path": "*.mappings.*.mapping"}


def test_the_mapping_request_cannot_ask_for_a_field_that_is_not_allowlisted() -> None:
    with pytest.raises(ValidationError):
        MappingParams(index="x", fields=("password",))
    with pytest.raises(ValidationError):
        MappingParams(index="x", fields=("source.ip", "source.ip"))
    with pytest.raises(ValidationError):
        MappingParams(index="x", fields=())
    with pytest.raises(ValidationError):
        MappingParams(index="Not-Lower", fields=("source.ip",))
    with pytest.raises(ValidationError):
        MappingParams(index="a,b", fields=("source.ip",))
    spec = DiscoverFieldMapping.spec()
    for bad in (None, "", "password", "source.ip,password", "source.ip,source.ip", "*"):
        assert code(FinalRequest(spec, ("idx",), bad)) == "field_not_allowed"
    assert code(FinalRequest(spec, (), "source.ip")) == "index_not_allowed"
    assert code(FinalRequest(spec, ("a", "b"), "source.ip")) == "index_not_allowed"
    assert code(FinalRequest(spec, ("a*",), "source.ip")) == "index_not_allowed"


def test_the_mapping_answer_is_read_into_types() -> None:
    body = {
        "index-1": {
            "mappings": {
                "url.domain": {
                    "mapping": {
                        "domain": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}
                    }
                },
                "source.ip": {"mapping": {"ip": {"type": "ip"}}},
                "url.path": {"mapping": {"path": {"type": "keyword"}}},
                "event.action": {"mapping": {"action": {"type": "text"}}},
                "broken": {"mapping": "x"},
                "empty": {"mapping": {}},
            }
        },
        "index-2": {"mappings": {"source.ip": {"mapping": {"ip": {"type": "keyword"}}}}},
    }
    assert DiscoverFieldMapping.types(body) == {
        "url.domain": ("text", True),
        "source.ip": ("ip", False),  # the first index's
        "url.path": ("keyword", False),
        "event.action": ("text", False),
    }
    assert DiscoverFieldMapping.types(None) == {}
    assert DiscoverFieldMapping.types({"i": 3}) == {}


def test_the_listing_answer_is_cut_and_says_so() -> None:
    names = [{"name": f"i{n}"} for n in range(MAX_NAMES + 3)]
    streams = [
        {"name": "s", "backing_indices": [f"b{n}" for n in range(MAX_BACKING + 5)]},
        {"nameless": True},
    ]
    out = DiscoverIndices().answer(
        IndicesParams(scope="data"), {"indices": names, "data_streams": streams}
    )
    assert out["truncated"] is True
    assert len(out["indices"]) == MAX_NAMES
    assert len(out["aliases"]) == 0
    assert out["data_streams"][0]["backing_indices"][-1] == f"b{MAX_BACKING + 4}"
    assert len(out["data_streams"][0]["backing_indices"]) == MAX_BACKING
    small = DiscoverIndices().answer(IndicesParams(scope="data"), {"indices": [{"name": "a"}, 3]})
    assert small == {
        "indices": [{"name": "a"}],
        "aliases": [],
        "data_streams": [],
        "truncated": False,
    }
    assert DiscoverIndices().answer(IndicesParams(scope="data"), "x") == "x"


def test_the_ilm_answer_keeps_the_delete_age_and_what_uses_it() -> None:
    body = {
        "logs": {
            "policy": {"phases": {"delete": {"min_age": "5d"}}},
            "in_use_by": {"data_streams": ["logs-a-default"], "indices": ["idx-2026.10.30"]},
        },
        "forever": {"policy": {"phases": {"hot": {}}}, "in_use_by": {}},
        "bad": 3,
    }
    out = DiscoverIlmPolicies().answer(NoParams(), body)
    assert out == {
        "logs": {
            "delete_after": "5d",
            "data_streams": ["logs-a-default"],
            "indices": ["idx-2026.10.30"],
        },
        "forever": {"delete_after": None, "data_streams": [], "indices": []},
    }
    request = final(DiscoverIlmPolicies(), NoParams())
    validate(request)
    assert wire_path(request) == ("GET", "/_ilm/policy")


def test_the_privilege_check_asks_two_cluster_privileges_and_reads_the_answer() -> None:
    request = final(DiscoverPrivileges(), NoParams())
    validate(request)
    assert request.body == {"cluster": ["monitor", "read_ilm"]}
    assert wire_path(request) == ("POST", "/_security/user/_has_privileges")
    answer = {"cluster": {"monitor": True, "read_ilm": False}}
    assert DiscoverPrivileges.holds(answer, "monitor")
    assert not DiscoverPrivileges.holds(answer, "read_ilm")
    assert not DiscoverPrivileges.holds({"cluster": {"read_ilm": "true"}}, "read_ilm")
    assert not DiscoverPrivileges.holds(None, "read_ilm")


async def test_a_discovery_template_runs_only_with_the_discover_purpose_family_rules() -> None:
    gateway, transport, _, _ = make(FakeTransport().on("_resolve", ok({"indices": []})))
    result = await gateway.run(
        DiscoverIndices(), IndicesParams(scope="data"), purpose=Purpose.DISCOVER,
        component="discover", deadline=DEADLINE,
    )  # fmt: skip
    assert result.body["truncated"] is False
    assert transport.calls[0].path == "/_resolve/index/*"
    assert transport.calls[0].opaque_id == "argus-discover/discover.indices@1"
    with pytest.raises(TemplateRejectedError, match="cost_mismatch"):
        await gateway.run(  # a light template is not a probe
            DiscoverIndices(), IndicesParams(scope="data"), purpose=Purpose.PROBE,
            component="discover", deadline=DEADLINE,
        )  # fmt: skip
