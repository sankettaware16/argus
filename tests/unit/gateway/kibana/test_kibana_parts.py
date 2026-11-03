"""The Kibana lane's parts (Q-D2): the one path builder, the validator, the strict body models
and the gate's properties (every path in the space; no DELETE, ``/internal/``, configuration
write or push; the exhaustive ``wire_path`` of both gateways)."""

from __future__ import annotations

import json
from typing import Any

import pydantic
import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana import models
from argus.gateway.kibana.paths import (
    METHODS,
    KEndpoint,
    Target,
    refusal,
    wire_path,
)
from argus.gateway.kibana.templates import (
    KREGISTRY,
    AttachAlerts,
    AttachParams,
    CloseCase,
    CommentOnCase,
    CommentParams,
    CreateCase,
    FindParams,
    KibanaTemplate,
    SetAlertStatus,
    UpdateCase,
)
from argus.gateway.kibana.validator import KFinal, encode, request_hash, validate
from argus.gateway.templates import Endpoint, Family, Spec
from argus.gateway.transport import wire_path as es_wire_path
from argus.gateway.validator import FinalRequest
from tests.unit.gateway.kibana.fakes import (
    ALERT_ID,
    ALERT_INDEX,
    ARGUS_CASE,
    CASE_ID,
    create_params,
)

pytestmark = pytest.mark.unit
SPACE = "acme-soc"
PREFIX = ".internal.alerts-security.alerts-acme-soc-"
NEEDS = {
    KEndpoint.CASE_GET: Target(case_id=CASE_ID),
    KEndpoint.CASE_USER_ACTIONS: Target(case_id=CASE_ID),
    KEndpoint.CASE_COMMENTS: Target(case_id=CASE_ID),
    KEndpoint.CASE_ALERTS: Target(case_id=CASE_ID),
    KEndpoint.CASE_COMMENT: Target(case_id=CASE_ID),
    KEndpoint.CASE_COMMENT_EDIT: Target(case_id=CASE_ID),
    KEndpoint.CASE_FILES: Target(case_id=CASE_ID),
    KEndpoint.ALERT_CASES: Target(alert_id=ALERT_ID),
}
EXPECTED = {
    KEndpoint.STATUS: ("GET", "/s/acme-soc/api/status"),
    KEndpoint.CASES_FIND: ("GET", "/s/acme-soc/api/cases/_find"),
    KEndpoint.CASE_GET: ("GET", f"/s/acme-soc/api/cases/{CASE_ID}"),
    KEndpoint.CASE_USER_ACTIONS: ("GET", f"/s/acme-soc/api/cases/{CASE_ID}/user_actions/_find"),
    KEndpoint.CASE_COMMENTS: ("GET", f"/s/acme-soc/api/cases/{CASE_ID}/comments/_find"),
    KEndpoint.CASES_CONFIGURE: ("GET", "/s/acme-soc/api/cases/configure"),
    KEndpoint.CASE_ALERTS: ("GET", f"/s/acme-soc/api/cases/{CASE_ID}/alerts"),
    KEndpoint.ALERT_CASES: ("GET", f"/s/acme-soc/api/cases/alerts/{ALERT_ID}"),
    KEndpoint.CASE_CREATE: ("POST", "/s/acme-soc/api/cases"),
    KEndpoint.CASES_UPDATE: ("PATCH", "/s/acme-soc/api/cases"),
    KEndpoint.CASE_COMMENT: ("POST", f"/s/acme-soc/api/cases/{CASE_ID}/comments"),
    KEndpoint.CASE_COMMENT_EDIT: ("PATCH", f"/s/acme-soc/api/cases/{CASE_ID}/comments"),
    KEndpoint.CASE_FILES: ("POST", f"/s/acme-soc/api/cases/{CASE_ID}/files"),
    KEndpoint.ALERTS_STATUS: ("POST", "/s/acme-soc/api/detection_engine/signals/status"),
    KEndpoint.ALERTS_TAGS: ("POST", "/s/acme-soc/api/detection_engine/signals/tags"),
    KEndpoint.SPACES: ("GET", "/s/acme-soc/api/spaces/space"),
    KEndpoint.FEATURES: ("GET", "/s/acme-soc/api/features"),
}


# --------------------------------------------------------------------------- paths


def test_every_endpoint_has_exactly_its_route() -> None:
    assert set(EXPECTED) == set(KEndpoint)
    for endpoint in KEndpoint:
        assert wire_path(endpoint, SPACE, NEEDS.get(endpoint, Target())) == EXPECTED[endpoint]


def test_the_stored_names_are_pinned() -> None:
    assert sorted(KREGISTRY) == [
        "alerts.cases", "alerts.status", "cases.alerts", "cases.attach_alerts", "cases.close",
        "cases.comment", "cases.comments", "cases.configure", "cases.create", "cases.find",
        "cases.get", "cases.update", "cases.user_actions", "kibana.features", "kibana.spaces",
        "kibana.status", "team.alert_tags",
        "team.attach_alerts", "team.comment", "team.create", "team.edit_case", "team.edit_comment",
        "team.file",
    ]  # fmt: skip


@given(
    endpoint=st.sampled_from(list(KEndpoint)),
    space=st.from_regex(r"[a-z0-9_-]{1,64}", fullmatch=True),
    case_id=st.from_regex(r"[A-Za-z0-9_-]{1,64}", fullmatch=True),
    alert_id=st.from_regex(r"[A-Za-z0-9_-]{1,128}", fullmatch=True),
)
def test_every_path_is_in_the_space_and_never_refused(
    endpoint: KEndpoint, space: str, case_id: str, alert_id: str
) -> None:
    target = {
        KEndpoint.ALERT_CASES: Target(alert_id=alert_id),
    }.get(endpoint, Target(case_id=case_id) if endpoint in NEEDS else Target())
    method, path = wire_path(endpoint, space, target)
    assert path.startswith(f"/s/{space}/api/")
    assert method in METHODS
    assert method != "DELETE"
    assert "/internal" not in path
    assert refusal(method, path, space) is None


@given(bad=st.text(min_size=0, max_size=80))
def test_an_id_that_is_not_a_plain_name_never_reaches_a_path(bad: str) -> None:
    import re

    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", bad):
        return
    with pytest.raises(ValueError, match="case id"):
        wire_path(KEndpoint.CASE_GET, SPACE, Target(case_id=bad))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("DELETE", "/s/acme-soc/api/cases"),
        ("PUT", "/s/acme-soc/api/cases"),
        ("GET", "/api/cases/_find"),  # the default space
        ("GET", "/s/other/api/cases/_find"),
        ("POST", "/s/acme-soc/internal/rac/alerts/bulk_update"),
        ("POST", "/s/acme-soc/api/internal/x"),
        ("POST", "/s/acme-soc/api/cases/configure"),
        ("PATCH", "/s/acme-soc/api/cases/configure/abc"),
        ("POST", f"/s/acme-soc/api/cases/{CASE_ID}/connector/none/_push"),
        ("GET", "/s/acme-soc/api/cases/../security/role"),
        ("GET", "/s/acme-soc/api/cases/%2e%2e/x"),
        ("GET", "/s/acme-soc/api/cases//x"),
    ],
)
def test_refused_routes(method: str, path: str) -> None:
    assert refusal(method, path, SPACE) is not None


def test_the_es_wire_path_is_exhaustive() -> None:
    names = ("a",)
    for endpoint in Endpoint:
        spec = Spec("t", 1, endpoint, Family.CLUSTER, __import__("argus.gateway.templates",
                    fromlist=["CostClass"]).CostClass.LIGHT)  # fmt: skip
        pattern = {
            Endpoint.RESOLVE_INDEX: "acme-logs-squid-*",
            Endpoint.DISCOVER_INDICES: "*",
            Endpoint.FIELD_MAPPING: "source.ip,url.path",
        }.get(endpoint)
        method, path = es_wire_path(FinalRequest(spec, names, pattern))
        assert method in ("GET", "POST")
        assert path.startswith("/")
    assert es_wire_path(FinalRequest(Spec("t", 1, Endpoint.LICENSE, Family.CLUSTER,
        __import__("argus.gateway.templates", fromlist=["CostClass"]).CostClass.LIGHT))) == (
        "GET", "/_license")  # fmt: skip


# --------------------------------------------------------------------------- bodies


def _final(template: KibanaTemplate, params: Any) -> KFinal:
    plan = template.plan(params)
    method, path = wire_path(plan.spec.endpoint, SPACE, plan.target)
    body = None if plan.body is None else encode(plan.body.model_dump(mode="json"))
    return KFinal(plan.spec, method, path, plan.target, plan.url_params, body)


def _valid(final: KFinal) -> None:
    validate(final, SPACE, PREFIX)


def _code(final: KFinal) -> str:
    with pytest.raises(TemplateRejectedError) as caught:
        _valid(final)
    return caught.value.code


def test_a_create_carries_sync_off_no_connector_and_its_owner() -> None:
    final = _final(CreateCase(), create_params())
    _valid(final)
    body = json.loads(final.body or b"")
    assert body["settings"] == {"syncAlerts": False}
    assert body["connector"] == {"id": "none", "name": "none", "type": ".none", "fields": None}
    assert body["owner"] == "securitySolution"
    assert "assignees" not in body
    assert "customFields" not in body


@pytest.mark.parametrize(
    "extra",
    [
        {"assignees": [{"uid": "u"}]},
        {"customFields": []},
        {"category": "x"},
        {"settings": {"syncAlerts": True}},
        {"connector": {"id": "jira", "name": "j", "type": ".jira", "fields": None}},
        {"owner": "observability"},
    ],
)
def test_a_create_body_with_anything_else_is_refused(extra: dict[str, Any]) -> None:
    final = _final(CreateCase(), create_params())
    body = {**json.loads(final.body or b""), **extra}
    assert _code(KFinal(final.spec, final.method, final.path, body=encode(body))) in (
        "bad_shape", "forbidden_field",
    )  # fmt: skip


def test_a_create_without_settings_is_refused() -> None:
    final = _final(CreateCase(), create_params())
    body = json.loads(final.body or b"")
    del body["settings"]
    assert _code(KFinal(final.spec, final.method, final.path, body=encode(body))) == "bad_shape"


@pytest.mark.parametrize(
    "extra",
    [{"settings": {"syncAlerts": False}}, {"assignees": []}, {"customFields": []},
     {"connector": {"id": "none"}}, {"owner": "securitySolution"}, {"category": None}],
)  # fmt: skip
def test_a_patch_never_carries_settings_or_assignees(extra: dict[str, Any]) -> None:
    params = models.UpdatePatch(
        cases=(models.CaseChange(id=CASE_ID, version="WzEsMV0x", severity="high"),)
    )
    final = _final(UpdateCase(), params)
    body = json.loads(final.body or b"")
    body["cases"][0].update(extra)
    assert _code(KFinal(final.spec, final.method, final.path, body=encode(body))) in (
        "bad_shape", "forbidden_field",
    )  # fmt: skip
    with pytest.raises(pydantic.ValidationError):
        models.CaseChange(id=CASE_ID, version="v", severity="high", **extra)


def test_w2_never_closes_and_w3_only_closes() -> None:
    closing = ("argus", ARGUS_CASE, "argus:state:closed", "argus:closed",
               "argus:reason:duplicate")  # fmt: skip
    with pytest.raises(pydantic.ValidationError):
        models.UpdatePatch(cases=(models.CaseChange(id=CASE_ID, version="v", status="closed"),))
    with pytest.raises(pydantic.ValidationError):
        models.UpdatePatch(cases=(models.CaseChange(id=CASE_ID, version="v", tags=closing),))
    models.ClosePatch(cases=(models.CaseChange(id=CASE_ID, version="v", status="closed",
                                               tags=closing),))  # fmt: skip
    for bad in (
        {"status": "open", "tags": closing},
        {"status": "closed", "tags": ("argus", ARGUS_CASE, "argus:closed")},
        {"status": "closed", "tags": (*closing[:-1], "argus:reason:because")},
        {"status": "closed", "tags": closing, "title": "x"},
    ):
        with pytest.raises(pydantic.ValidationError):
            models.ClosePatch(cases=(models.CaseChange(id=CASE_ID, version="v", **bad),))
    assert models.closing_tags(closing) == "duplicate"


def test_one_case_a_patch_and_argus_tags_kept() -> None:
    change = models.CaseChange(id=CASE_ID, version="v", severity="low")
    with pytest.raises(pydantic.ValidationError):
        models.UpdatePatch(cases=(change, change))
    with pytest.raises(pydantic.ValidationError):  # dropping 'argus' would orphan the case
        models.CaseChange(id=CASE_ID, version="v", tags=(ARGUS_CASE,))
    with pytest.raises(pydantic.ValidationError):
        models.CaseChange(id=CASE_ID, version="v")


def test_at_most_five_alerts_a_call_each_with_its_index() -> None:
    alerts = tuple((f"{n:064x}", ALERT_INDEX) for n in range(5))
    _valid(_final(AttachAlerts(), AttachParams(case_id=CASE_ID, alerts=alerts)))
    with pytest.raises(pydantic.ValidationError):
        AttachParams(case_id=CASE_ID, alerts=(*alerts, ("f" * 64, ALERT_INDEX)))
    with pytest.raises(pydantic.ValidationError):
        models.AlertAttachment(alertId=("a", "b"), index=(ALERT_INDEX,))
    other = ".internal.alerts-security.alerts-default-000001"
    final = _final(AttachAlerts(), AttachParams(case_id=CASE_ID, alerts=(("a1", other),)))
    assert _code(final) == "index_not_allowed"
    with pytest.raises(pydantic.ValidationError):
        AttachAlerts().plan(AttachParams(case_id=CASE_ID, alerts=(("a1", "logs-x"),)))


def test_the_alert_status_route_takes_ids_never_a_query() -> None:
    params = models.AlertStatusChange(signal_ids=(ALERT_ID,), status="closed")
    final = _final(SetAlertStatus(), params)
    _valid(final)
    body = json.loads(final.body or b"")
    body["query"] = {"match_all": {}}
    assert _code(KFinal(final.spec, final.method, final.path, body=encode(body))) == "bad_shape"
    with pytest.raises(pydantic.ValidationError):  # the model's ceiling; the lane's cap is lower
        models.AlertStatusChange(signal_ids=tuple(f"{n}" for n in range(101)), status="closed")
    models.AlertStatusChange(signal_ids=tuple(f"{n}" for n in range(100)), status="closed")


def test_texts_are_bounded_and_not_blank() -> None:
    with pytest.raises(pydantic.ValidationError):
        CommentParams(case_id=CASE_ID, comment="c" * 30_001)
    with pytest.raises(pydantic.ValidationError):
        CommentOnCase().plan(CommentParams(case_id=CASE_ID, comment="   "))
    with pytest.raises(pydantic.ValidationError):
        create_params("t" * 161)
    with pytest.raises(pydantic.ValidationError):
        models.CaseCreate(title="x", description="d", severity="low",
                          tags=("argus", ARGUS_CASE, "people-tag"))  # fmt: skip


def test_the_validator_holds_the_route_method_and_params() -> None:
    final = _final(CreateCase(), create_params())
    assert _code(KFinal(final.spec, "PATCH", final.path, body=final.body)) == "path_mismatch"
    assert _code(KFinal(final.spec, "DELETE", final.path, body=final.body)) == "route_refused"
    assert _code(KFinal(final.spec, final.method, final.path)) == "bad_shape"
    find = _final(__import__("argus.gateway.kibana.templates", fromlist=["CasesFind"]).CasesFind(),
                  FindParams(tags=("argus",)))  # fmt: skip
    _valid(find)
    sneaky = KFinal(find.spec, find.method, find.path, url_params=(("search", "x"),))
    assert _code(sneaky) == "forbidden_param"
    twice = KFinal(find.spec, find.method, find.path, url_params=(("page", "1"), ("page", "2")))
    assert _code(twice) == "forbidden_param"
    with_body = KFinal(find.spec, find.method, find.path, body=b"{}")
    assert _code(with_body) == "bad_shape"
    with pytest.raises(pydantic.ValidationError):
        FindParams(page=101, per_page=100)  # past Kibana's 10,000 documents


def test_the_payload_hash_binds_template_route_and_bytes() -> None:
    a = _final(CreateCase(), create_params())
    b = _final(CreateCase(), create_params("[ARGUS 7] another title"))
    assert request_hash(a) != request_hash(b)
    assert request_hash(a) == request_hash(_final(CreateCase(), create_params()))
    assert len(request_hash(a)) == 64


@given(st.dictionaries(st.sampled_from(["assignees", "customFields", "category", "settings",
                                        "connector", "owner", "x"]),
                       st.none() | st.integers() | st.text(max_size=5), min_size=1))  # fmt: skip
def test_any_extra_key_in_a_patch_is_refused(extra: dict[str, Any]) -> None:
    params = models.UpdatePatch(
        cases=(models.CaseChange(id=CASE_ID, version="WzEsMV0x", severity="high"),)
    )
    final = _final(UpdateCase(), params)
    body = json.loads(final.body or b"")
    body["cases"][0].update(extra)
    with pytest.raises(TemplateRejectedError):
        _valid(KFinal(final.spec, final.method, final.path, body=encode(body)))


def test_every_write_template_names_a_class_and_a_writer_key() -> None:
    for template in KREGISTRY.values():
        spec = template.spec()
        if spec.write:
            assert spec.key.value in ("cases", "alerts", "team")
            assert spec.body_model is not None
        else:
            assert spec.key.value == "reader"
            assert spec.body_model is None
    assert CloseCase.classes == {__import__("argus.gateway.kibana.writes",
                                            fromlist=["WriteClass"]).WriteClass.W3}  # fmt: skip


def test_kibana_templates_are_light_registered_once_and_shaped_by_kind() -> None:
    from argus.gateway.kibana.templates import KibanaStatus, kregister
    from argus.gateway.templates import CostClass

    class Heavy(KibanaStatus):
        name = "test.heavy"
        cost = CostClass.HEAVY

    class Twice(KibanaStatus):
        pass

    class ReadWithBody(KibanaStatus):
        name = "test.read_body"
        body_model = models.UserComment

    class WriteWithoutBody(KibanaStatus):
        name = "test.write_nobody"
        classes = frozenset({__import__("argus.gateway.kibana.writes",
                                        fromlist=["WriteClass"]).WriteClass.W1})  # fmt: skip

    class NoVersion(KibanaStatus):
        name = "test.noversion"
        version = 0

    for bad, message in ((Heavy, "light"), (Twice, "twice"), (ReadWithBody, "no body"),
                         (WriteWithoutBody, "body model"), (NoVersion, "positive")):  # fmt: skip
        with pytest.raises(ValueError, match=message):
            kregister(bad)
    assert "test.heavy" not in KREGISTRY


def test_a_patch_leaves_out_what_it_does_not_change() -> None:
    """Found on the local tier: Kibana answers 400 to ``"title": null`` and the like."""
    params = models.UpdatePatch(
        cases=(models.CaseChange(id=CASE_ID, version="WzEsMV0x", severity="high"),)
    )
    final = _final(UpdateCase(), params)
    assert json.loads(final.body or b"") == {
        "cases": [{"id": CASE_ID, "version": "WzEsMV0x", "severity": "high"}]
    }
    create = json.loads(_final(CreateCase(), create_params()).body or b"")
    assert create["connector"]["fields"] is None  # a create keeps its required nulls
    attach = _final(AttachAlerts(), AttachParams(case_id=CASE_ID, alerts=(("a1", ALERT_INDEX),)))
    assert json.loads(attach.body or b"")["rule"] == {"id": None, "name": None}


def test_kibanas_limits_count_utf16_units() -> None:
    """Kibana counts a title's 160 and a text's 30,000 as JavaScript does: an emoji is two."""
    assert models.utf16_len("a😀") == 3
    create_params("[A] " + "😀" * 78)  # 4 + 156 = 160 units
    with pytest.raises(pydantic.ValidationError, match="UTF-16"):
        create_params("[A] " + "😀" * 79)
    with pytest.raises(pydantic.ValidationError, match="UTF-16"):
        models.UserComment(comment="😀" * 15_001)
    with pytest.raises(pydantic.ValidationError, match="UTF-16"):
        models.CaseChange(id=CASE_ID, version="v", title="😀" * 81)
