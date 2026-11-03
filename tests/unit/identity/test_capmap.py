"""The capability map (plan §7.2, Q-E1): actions, not role names; pinned to siemV2 and
securitySolutionCasesV3; monotone; failing closed; the canaries the other way round."""

from __future__ import annotations

import copy
from collections.abc import Collection
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.identity import capmap
from argus.identity.capmap import (
    ADMIN_CANARIES,
    ARGUS_APP,
    ARGUS_RESOURCE,
    CLUSTER_CANARIES,
    KIBANA_APP,
    NEEDS,
    IncompleteAnswerError,
    Targets,
    read,
    request_body,
)
from argus.web.capabilities import Capability

T = Targets()
ALIAS, BACKING = T.alerts
(LOGS,) = T.log_patterns


def answer(
    kibana: Collection[str] = (),
    alerts: Collection[str] = (),
    logs: Collection[str] = (),
    argus: Collection[str] = (),
    cluster: Collection[str] = (),
) -> dict[str, Any]:
    """A ``_has_privileges`` answer to ``request_body(T)`` holding exactly these."""
    body = request_body(T)
    out: dict[str, Any] = {
        "username": "someone",
        "has_all_requested": False,
        "cluster": {name: name in cluster for name in body["cluster"]},
        "index": {},
        "application": {KIBANA_APP: {T.resource: {}}, ARGUS_APP: {ARGUS_RESOURCE: {}}},
    }
    for entry in body["index"]:
        (name,) = entry["names"]
        held = logs if name == LOGS else alerts
        out["index"][name] = {p: p in held for p in entry["privileges"]}
    for app in body["application"]:
        held = kibana if app["application"] == KIBANA_APP else argus
        (resource,) = app["resources"]
        out["application"][app["application"]][resource] = {p: p in held for p in app["privileges"]}
    return out


VIEWER: dict[str, set[str]] = {"kibana": {"login:", "ui:siemV2/show"}, "alerts": {"read"}}
CASES_ALL = {
    "cases:securitySolution/createCase", "cases:securitySolution/updateCase",
    "cases:securitySolution/createComment", "cases:securitySolution/reopenCase",
    "ui:securitySolutionCasesV3/create_cases", "ui:securitySolutionCasesV3/update_cases",
    "ui:securitySolutionCasesV3/create_comment", "ui:securitySolutionCasesV3/case_reopen",
}  # fmt: skip


def caps(**held: Collection[str]) -> set[str]:
    return {c.value for c in read(answer(**held), T).capabilities}


def test_the_map_is_versioned_and_pinned() -> None:
    assert capmap.MAP_VERSION == 1
    assert (capmap.KIBANA_VERSION, capmap.SECURITY_FEATURE, capmap.CASES_FEATURE) == (
        "8.19.12", "siemV2", "securitySolutionCasesV3"
    )  # fmt: skip
    kibana = {a for needs in NEEDS.values() for a in needs.kibana}
    assert all(
        a == "login:" or a.startswith(("ui:siemV2/", "ui:securitySolutionCasesV3/", "cases:"))
        for a in kibana
    )
    assert set(NEEDS) == set(Capability) - {Capability.ANSWER_GOLD}


def test_the_request_asks_everything_the_map_reads() -> None:
    body = request_body(T)
    assert body["cluster"] == list(CLUSTER_CANARIES)
    assert body["cluster"] == [
        "all", "manage", "manage_security", "manage_api_key", "grant_api_key",
        "manage_service_account",
    ]  # fmt: skip
    index = {entry["names"][0]: entry["privileges"] for entry in body["index"]}
    assert index == {
        ".alerts-security.alerts-acme-soc": ["index", "maintenance", "read"],
        ".internal.alerts-security.alerts-acme-soc-*": ["index", "maintenance", "read"],
        "acme-logs-*": ["read"],
    }
    apps = {app["application"]: app for app in body["application"]}
    assert apps[KIBANA_APP]["resources"] == ["space:acme-soc"]
    assert set(apps[KIBANA_APP]["privileges"]) == {
        "login:", "ui:siemV2/show", *CASES_ALL
    }  # fmt: skip
    assert apps[ARGUS_APP] == {
        "application": "argus", "resources": ["*"], "privileges": ["argus:admin", "argus:approve"]
    }  # fmt: skip


def test_other_targets() -> None:
    t = Targets(space="other-space", log_patterns=("logs-*",))
    body = request_body(t)
    assert body["application"][0]["resources"] == ["space:other-space"]
    assert [e["names"] for e in body["index"]] == [
        [".alerts-security.alerts-other-space"],
        [".internal.alerts-security.alerts-other-space-*"],
        ["logs-*"],
    ]


@pytest.mark.parametrize(
    ("held", "expected"),
    [
        ({}, set()),
        (VIEWER, {"view"}),
        ({**VIEWER, "logs": {"read"}}, {"view", "see_logs"}),
        ({**VIEWER, "alerts": {"read", "index", "maintenance"}}, {"view", "review"}),
        ({**VIEWER, "alerts": {"read", "index"}}, {"view"}),  # maintenance missing
        ({**VIEWER, "alerts": {"read", "maintenance"}}, {"view"}),
        ({"kibana": {"login:", "ui:siemV2/show", *CASES_ALL}, "alerts": {"read"}},
         {"view", "manage_cases", "reopen"}),
        ({**VIEWER, "argus": {"argus:admin"}}, {"view", "admin"}),
        ({**VIEWER, "argus": {"argus:approve"}}, {"view"}),  # approve needs manage cases
        ({"kibana": {"login:", "ui:siemV2/show", *CASES_ALL}, "alerts": {"read"},
          "argus": {"argus:approve"}}, {"view", "manage_cases", "reopen", "approve"}),
        # without view nothing counts
        ({"kibana": {"login:", *CASES_ALL}, "alerts": {"read", "index", "maintenance"},
          "logs": {"read"}, "argus": {"argus:admin", "argus:approve"}}, set()),
        ({"kibana": {"ui:siemV2/show"}, "alerts": {"read"}}, set()),  # no login:
        ({"kibana": {"login:", "ui:siemV2/show"}}, set()),  # no alerts read
    ],
)  # fmt: skip
def test_capabilities_from_actions(held: dict[str, set[str]], expected: set[str]) -> None:
    assert caps(**held) == expected


REOPEN = {"cases:securitySolution/reopenCase", "ui:securitySolutionCasesV3/case_reopen"}


@pytest.mark.parametrize("action", sorted(CASES_ALL - REOPEN))
def test_manage_cases_needs_every_one_of_its_actions(action: str) -> None:
    kibana = {"login:", "ui:siemV2/show", *CASES_ALL} - {action}
    assert "manage_cases" not in caps(kibana=kibana, alerts={"read"})
    assert "reopen" in caps(kibana=kibana, alerts={"read"})


@pytest.mark.parametrize(
    "action", ["cases:securitySolution/reopenCase", "ui:securitySolutionCasesV3/case_reopen"]
)
def test_reopen_needs_both_actions(action: str) -> None:
    kibana = {"login:", "ui:siemV2/show", *CASES_ALL} - {action}
    assert caps(kibana=kibana, alerts={"read"}) == {"view", "manage_cases"}


def test_both_alert_names_must_grant() -> None:
    body = answer(kibana=VIEWER["kibana"], alerts={"read", "index", "maintenance"})
    assert read(body, T).capabilities == {Capability.VIEW, Capability.REVIEW}
    for name in (ALIAS, BACKING):
        narrowed = copy.deepcopy(body)
        narrowed["index"][name]["index"] = False
        assert read(narrowed, T).capabilities == {Capability.VIEW}
        unreadable = copy.deepcopy(body)
        unreadable["index"][name]["read"] = False
        assert read(unreadable, T).capabilities == frozenset()


def test_only_true_counts() -> None:
    body = answer(**VIEWER)
    body["application"][KIBANA_APP][T.resource]["login:"] = False
    assert read(body, T).capabilities == frozenset()


@pytest.mark.parametrize("value", [None, "true", 1, "yes", [True], {"x": True}])
def test_a_privilege_not_stated_as_a_boolean_is_an_incomplete_answer(value: Any) -> None:
    """Review E1-5: a truncated or odd answer is no verdict about the person."""
    body = answer(**VIEWER)
    body["application"][KIBANA_APP][T.resource]["login:"] = value
    with pytest.raises(IncompleteAnswerError, match="login:"):
        read(body, T)


@pytest.mark.parametrize(
    "broken",
    [None, [], "x", {}, {"application": None}, {"application": {KIBANA_APP: []}},
     {"index": {ALIAS: "read"}}, {"application": {KIBANA_APP: {"space:other": {"login:": True}}}}],
)  # fmt: skip
def test_malformed_answers_are_incomplete_never_a_verdict(broken: Any) -> None:
    with pytest.raises(IncompleteAnswerError):
        read(broken, T)


def test_canaries() -> None:
    plain = read(answer(**VIEWER), T)
    assert not plain.superuser
    assert not plain.admin_account
    assert read(answer(**VIEWER, cluster={"all"}), T).superuser
    for name in ADMIN_CANARIES:
        got = read(answer(**VIEWER, cluster={name}), T)
        assert got.admin_account, name
        assert not got.superuser, name
        missing = answer(**VIEWER)
        del missing["cluster"][name]
        with pytest.raises(IncompleteAnswerError, match=name):  # E1-5: not stated is not "held"
            read(missing, T)
    none = answer(**VIEWER)
    none["cluster"]["all"] = None
    with pytest.raises(IncompleteAnswerError, match="all"):
        read(none, T)


def test_describe_names_every_capability() -> None:
    described = dict(capmap.describe())
    assert set(described) == {c.value for c in Capability}
    assert "ui:siemV2/show" in described["view"]
    assert "argus:approve" in described["approve"]
    assert "on the logs" in described["see_logs"]
    assert "on the alerts" in described["review"]


PRIVILEGES = sorted(
    {("kibana", a) for n in NEEDS.values() for a in n.kibana}
    | {("alerts", a) for n in NEEDS.values() for a in n.alerts}
    | {("logs", a) for n in NEEDS.values() for a in n.logs}
    | {("argus", a) for n in NEEDS.values() for a in n.argus}
)


def held_from(chosen: set[tuple[str, str]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"kibana": set(), "alerts": set(), "logs": set(), "argus": set()}
    for part, name in chosen:
        out[part].add(name)
    return out


@given(st.sets(st.sampled_from(PRIVILEGES)), st.sets(st.sampled_from(PRIVILEGES)))
def test_the_map_is_monotone(a: set[tuple[str, str]], b: set[tuple[str, str]]) -> None:
    """More held privileges never give fewer capabilities."""
    small = read(answer(**held_from(a)), T).capabilities
    large = read(answer(**held_from(a | b)), T).capabilities
    assert small <= large


@given(st.sets(st.sampled_from(PRIVILEGES)), st.sets(st.sampled_from(CLUSTER_CANARIES)))
def test_canaries_never_change_capabilities(held: set[tuple[str, str]], cluster: set[str]) -> None:
    """The canaries decide admission, never what the map gives."""
    plain = read(answer(**held_from(held)), T)
    canaried = read(answer(**held_from(held), cluster=cluster), T)
    assert plain.capabilities == canaried.capabilities
    assert canaried.admin_account == bool(cluster & set(ADMIN_CANARIES))
    assert canaried.superuser == ("all" in cluster)


def _spoil(body: dict[str, Any], spoiled: tuple[str, str], value: Any) -> None:
    part, name = spoiled
    if part == "kibana":
        body["application"][KIBANA_APP][T.resource][name] = value
    elif part == "argus":
        body["application"][ARGUS_APP][ARGUS_RESOURCE][name] = value
    elif part == "logs":
        body["index"][LOGS][name] = value
    else:
        body["index"][ALIAS][name] = value


@given(st.sets(st.sampled_from(PRIVILEGES)), st.sampled_from(PRIVILEGES))
def test_a_false_is_not_held(held: set[tuple[str, str]], spoiled: tuple[str, str]) -> None:
    """Fail closed: replacing one ``true`` by ``false`` never gives more."""
    body = answer(**held_from(held | {spoiled}))
    before = read(body, T).capabilities
    _spoil(body, spoiled, False)
    after = read(body, T).capabilities
    assert after <= before
    assert after == read(answer(**held_from(held - {spoiled})), T).capabilities


@given(st.sets(st.sampled_from(PRIVILEGES)), st.sampled_from(PRIVILEGES),
       st.sampled_from([None, 0, 1, "true", [], {}]))  # fmt: skip
def test_anything_but_a_boolean_is_an_incomplete_answer(
    held: set[tuple[str, str]], spoiled: tuple[str, str], value: Any
) -> None:
    """Review E1-5: an answer that does not state a privilege as a boolean is no verdict."""
    body = answer(**held_from(held | {spoiled}))
    _spoil(body, spoiled, value)
    with pytest.raises(IncompleteAnswerError):
        read(body, T)
