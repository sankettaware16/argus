"""§12 #14 and #15: what Elasticsearch answers about each kind of account (the inputs of Q-E1's
capability map), and that a disable, a password change or a role removal shows at the next
check.

* ``_authenticate``: realm, roles, metadata (``argus_uid``, or ``argus_service`` for ``argus``);
  a disabled user, a wrong password and an unknown name all get the same 401;
* ``_has_privileges`` on the space: Kibana actions (``login:``, ``ui:siemV2/show``, the case
  actions, ``api:rac``), the alerts indices, the ``argus`` application privileges and the
  cluster "canaries" an everyday account must not hold; a superuser holds everything.
"""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import ALERTS_ALIAS, Tier, seed

PROBE = {
    "cluster": [
        "all",
        "manage",
        "manage_security",
        "manage_api_key",
        "grant_api_key",
        "manage_service_account",
        "monitor",
    ],
    "index": [{"names": [ALERTS_ALIAS], "privileges": ["read", "index", "maintenance"]}],
    "application": [
        {
            "application": seed.APP,
            "resources": [seed.SPACE_RESOURCE],
            "privileges": [
                "login:",
                f"ui:{seed.SECURITY}/show",
                "api:rac",
                "cases:securitySolution/getCase",
                "cases:securitySolution/createCase",
                "cases:securitySolution/updateCase",
                "cases:securitySolution/createComment",
                "cases:securitySolution/reopenCase",
                "cases:securitySolution/deleteCase",
            ],
        },
        {"application": "argus", "resources": ["*"], "privileges": ["approver", "admin"]},
    ],
}


def _identity(kt: Tier, principal: str) -> Any:
    reply = kt.es(principal).get(
        "/_security/_authenticate",
        keep=lambda b: {
            "username": b["username"],
            "roles": b["roles"],
            "enabled": b["enabled"],
            "metadata": b["metadata"],
            "realm": b["authentication_realm"]["type"],
            "type": b["authentication_type"],
        },
    )
    return reply.status, reply.body if reply.status == 200 else None


def _privileges(kt: Tier, principal: str) -> Any:
    reply = kt.es(principal).post(
        "/_security/user/_has_privileges",
        PROBE,
        keep=lambda b: {
            "all": b["has_all_requested"],
            "cluster": sorted(k for k, v in b["cluster"].items() if v),
            "index": sorted(k for k, v in b["index"][ALERTS_ALIAS].items() if v),
            "kibana": sorted(
                k for k, v in b["application"][seed.APP][seed.SPACE_RESOURCE].items() if v
            ),
            "argus": sorted(k for k, v in b["application"]["argus"]["*"].items() if v),
        },
    )
    assert reply.status == 200, reply.body
    return reply.body


def test_every_seeded_account_answers_as_its_kind(kt: Tier) -> None:
    answers: dict[str, Any] = {}
    for name, (_kind, roles, enabled) in seed.USERS.items():
        status, identity = _identity(kt, f"user:{name}")
        if not enabled:
            assert status == 401
            answers[name] = "401"
            continue
        assert status == 200
        assert identity == {
            "username": name,
            "roles": roles,
            "enabled": True,
            "metadata": {"argus_uid": seed.argus_uid(name)},
            "realm": "native",
            "type": "realm",
        }
        answers[name] = _privileges(kt, f"user:{name}")
    reads = ["cases:securitySolution/getCase", "login:", "ui:siemV2/show"]
    manage = [
        "cases:securitySolution/createCase",
        "cases:securitySolution/createComment",
        "cases:securitySolution/getCase",
        "cases:securitySolution/reopenCase",
        "cases:securitySolution/updateCase",
        "login:",
        "ui:siemV2/show",
    ]
    cases_all = sorted([*manage, "cases:securitySolution/deleteCase"])
    everything = sorted(PROBE["application"][0]["privileges"])  # type: ignore[index]
    assert answers["tier-superuser"]["all"] is True
    assert answers["tier-elkadmin"]["cluster"] == [
        "grant_api_key",
        "manage_api_key",
        "manage_security",
        "manage_service_account",
        "monitor",
    ]
    assert answers["tier-elkadmin"]["kibana"] == everything
    assert answers["tier-viewer"] == {
        "all": False,
        "cluster": [],
        "index": ["read"],
        "kibana": sorted([*reads, "api:rac"]),
        "argus": [],
    }
    assert answers["tier-reviewer"]["index"] == ["index", "maintenance", "read"]
    assert answers["tier-reviewer"]["kibana"] == sorted([*reads, "api:rac"])
    assert answers["tier-manager"]["kibana"] == sorted([*cases_all, "api:rac"])
    assert answers["tier-manager"]["index"] == ["read"]
    assert answers["tier-analyst"]["kibana"] == sorted([*cases_all, "api:rac"])
    assert answers["tier-approver"]["argus"] == ["approver"]
    assert answers["tier-argusadmin"]["argus"] == ["admin"]
    assert answers["tier-otherspace"] == {
        "all": False,
        "cluster": [],
        "index": [],
        "kibana": [],
        "argus": [],
    }
    for name in (
        "tier-viewer",
        "tier-reviewer",
        "tier-manager",
        "tier-analyst",
        "tier-approver",
        "tier-argusadmin",
    ):
        assert answers[name]["cluster"] == [], name  # no canary on an everyday account


def test_refusals_look_alike(kt: Tier) -> None:
    refusals = [
        _identity(kt, "user:tier-disabled"),
        _identity(kt, "wrong:tier-viewer"),
        _identity(kt, "wrong:tier-nobody"),
        _identity(kt, "none"),
    ]
    assert refusals == [(401, None)] * 4


def test_the_service_identity_and_its_keys(kt: Tier) -> None:
    assert _identity(kt, "user:argus") == (401, None)  # disabled between mints
    status, identity = _identity(kt, "key:argus-kibana-reader")
    assert status == 200
    assert identity == {
        "username": "argus",
        "roles": [],
        "enabled": True,
        "metadata": {"argus_service": True},
        "realm": "_es_api_key",
        "type": "api_key",
    }


def test_a_change_shows_at_the_next_check(kt: Tier) -> None:
    role = kit.make_kibana_role(kt, "chg-r", seed.KIBANA_ROLES["acme_viewer"])
    who = kit.make_user(kt, "chg", [role])
    name = kt.name("chg")
    admin = kt.es("elastic")
    assert _identity(kt, who)[0] == 200
    assert "login:" in _privileges(kt, who)["kibana"]

    new_password = kt.password()
    changed = admin.post(f"/_security/user/{name}/_password", {"password": new_password})
    assert changed.status == 200
    assert _identity(kt, who)[0] == 401  # the old password, at once
    renewed = kt.add_run_user("chg", new_password, label="run-user:chg-new")
    assert _identity(kt, renewed)[0] == 200

    removed = admin.put(f"/_security/user/{name}", {"roles": []})
    assert removed.status == 200
    assert _privileges(kt, renewed)["kibana"] == []  # no login: any more

    assert admin.put(f"/_security/user/{name}/_disable").status == 200
    assert _identity(kt, renewed)[0] == 401
    assert admin.put(f"/_security/user/{name}/_enable").status == 200
    assert _identity(kt, renewed)[0] == 200
