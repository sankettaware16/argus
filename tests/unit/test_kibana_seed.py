"""The local Kibana tier's seed definitions (scripts/kibana_seed.py, Q-D1) without the tier.

The seed must model the SIEM's planned identities exactly (DQ3 (a), plan §7.2): the Kibana reader
key holds Cases Read only; the action-scoped writer holds no delete, push, configuration,
assignee or comment-edit action and no Security action but the alerts' "get"; every key expires
(writers within 30 days); ``argus`` rests narrowed and disabled; everyday accounts hold no
cluster privilege; no reserved name is used; everything is synthetic (documentation addresses,
``.invalid`` mail).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.kibana.tier import seed

RESERVED = {
    "elastic",
    "kibana",
    "kibana_system",
    "logstash_system",
    "beats_system",
    "apm_system",
    "remote_monitoring_user",
}
DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24")]


def test_no_reserved_name_and_one_uid_each() -> None:
    names = seed.usernames()
    assert not set(names) & RESERVED
    assert len(set(names)) == len(names)
    uids = [seed.argus_uid(n) for n in seed.USERS]
    assert len(set(uids)) == len(uids)
    assert seed.argus_uid("tier-viewer") == seed.argus_uid("tier-viewer")  # stable


def test_every_role_a_user_holds_is_defined() -> None:
    defined = set(seed.KIBANA_ROLES) | set(seed.es_roles()) | {"superuser"}
    for name, (_kind, roles, _enabled) in seed.USERS.items():
        assert set(roles) <= defined, name
    assert set(seed.ARGUS_MINT_ROLES) <= defined
    assert set(seed.ARGUS_RESTING_ROLES) == {"argus_kibana_reader"}


def test_everyday_accounts_hold_no_cluster_privilege() -> None:
    admin_roles = {"superuser", "acme_elk_admin"}
    for name, (_kind, roles, _enabled) in seed.USERS.items():
        if set(roles) & admin_roles:
            continue
        for role in roles:
            body = seed.KIBANA_ROLES.get(role) or seed.es_roles()[role]
            cluster = body.get("elasticsearch", body).get("cluster", [])
            assert cluster == [], (name, role)


def test_the_kibana_reader_key_holds_cases_read_only() -> None:
    (descriptor,) = seed.api_keys()["argus-kibana-reader"]["role_descriptors"].values()
    assert descriptor["cluster"] == []
    assert descriptor["indices"] == []
    assert descriptor["applications"] == [
        {
            "application": "kibana-.kibana",
            "privileges": [f"feature_{seed.CASES}.read"],
            "resources": [f"space:{seed.SPACE}"],
        }
    ]


def test_the_scoped_writer_holds_only_what_argus_needs() -> None:
    actions = seed.CASES_WRITER_ACTIONS
    assert "login:" in actions
    assert not [a for a in actions if a.startswith(("api:", "ui:", "saved_object:", "app:"))]
    forbidden = (
        "deleteCase",
        "deleteComment",
        "pushCase",
        "createConfiguration",
        "updateConfiguration",
        "assignCase",
        "updateComment",
    )
    assert not [a for a in actions if a.endswith(forbidden)]
    alerting = [a for a in actions if a.startswith("alerting:")]
    assert alerting
    assert all(a.endswith("/siem/alert/get") for a in alerting)  # read the alert, never update
    assert {a.split(":", 1)[1].split("/")[0] for a in alerting} == set(seed.SIEM_RULE_TYPES)


def test_every_key_expires_and_writers_soon() -> None:
    for name, spec in seed.api_keys().items():
        days = int(spec["expiration"].removesuffix("d"))
        assert days <= (90 if name in ("argus-kibana-reader", "argus-reader") else 30), name


def test_the_es_reader_role_is_the_sites() -> None:
    """The reader key's role for the tier's site (its runbook gives a SIEM admin the same): the
    alerts index and its backing indices, the log patterns, the threat-intel indices."""
    role = {
        "cluster": ["monitor"],
        "indices": [
            {
                "names": [*seed.ALERTS_INDICES, "acme-logs-*", "abuse-ioc", "acme-threat-intel"],
                "privileges": ["read", "view_index_metadata"],
                "allow_restricted_indices": False,
            }
        ],
    }
    assert seed.reader_role() == role
    assert seed.api_keys()["argus-reader"]["role_descriptors"] == {"argus_reader": role}
    assert seed.es_roles()["argus_es_reader"] == role


def test_the_tier_names_follow_the_site_or_the_environment() -> None:
    assert (seed.SPACE, seed.PREFIX) == ("acme-soc", "acme")
    assert seed.tier_names({}) == ("acme-soc", "acme")
    environ = {"KIBANA_TIER_SPACE": "plant-soc", "KIBANA_TIER_PREFIX": "plant"}
    assert seed.tier_names(environ) == ("plant-soc", "plant")
    from argus import site
    from argus.site import SiteSettings

    with site.using(SiteSettings()):
        assert seed.tier_names({}) == ("default", "soc")  # the neutral site, short name SOC


def test_the_argus_application_privileges() -> None:
    privileges = seed.ARGUS_PRIVILEGES["argus"]
    assert set(privileges) == {"approver", "admin"}
    roles = seed.es_roles()
    assert roles["argus_approver"]["applications"][0]["privileges"] == ["approver"]
    assert roles["argus_admin"]["applications"][0]["privileges"] == ["admin"]


def test_users_are_synthetic() -> None:
    for name in seed.usernames():
        body = seed.user_body(name, [], "x" * 32)
        assert body["email"].endswith(".invalid")
    assert seed.user_body("argus", [], "x" * 32)["metadata"] == {"argus_service": True}
    assert seed.user_body("tier-viewer", [], "x" * 32)["metadata"] == {
        "argus_uid": seed.argus_uid("tier-viewer")
    }


@pytest.mark.parametrize("count", [1, 4, 12])
def test_events_are_synthetic_past_and_in_order(count: int) -> None:
    now = datetime(2026, 10, 23, 1, 2, 3, tzinfo=UTC)
    lines = seed.events_ndjson("kt-run", count, now=now).splitlines()
    assert len(lines) == 2 * count
    actions = [json.loads(line) for line in lines[::2]]
    events = [json.loads(line) for line in lines[1::2]]
    assert [a["create"]["_id"] for a in actions] == [f"kt-run-{n:02d}" for n in range(1, count + 1)]
    times = [e["@timestamp"] for e in events]
    assert times == sorted(times)
    assert len(set(times)) == count
    assert all(datetime.fromisoformat(t) < now for t in times)
    for e in events:
        assert e["tier"]["run"] == "kt-run"
        for address in (e["source"]["ip"], e["destination"]["ip"]):
            assert any(ipaddress.ip_address(address) in net for net in DOCUMENTATION)


@pytest.mark.parametrize("run", ['x" or tier.run: *', "", "a b", "x" * 81, "ü"])
def test_a_rule_refuses_what_is_not_a_run_id(run: str) -> None:
    with pytest.raises(ValueError, match="not a run id"):
        seed.rule_body("argus-tier-run-x", run, name="n", interval="1h", lookback="1h")


def test_a_rule_alerts_on_its_run_only() -> None:
    plain = seed.rule_body("argus-tier-run-abc", "abc", name="n", interval="1h", lookback="1h")
    assert plain["query"] == 'tier.run: "abc"'
    assert plain["index"] == [seed.EVENTS_INDEX]
    assert plain["enabled"] is True
    assert (plain["from"], plain["interval"]) == ("now-1h", "1h")


def test_the_key_spec_hash_follows_the_body() -> None:
    specs = seed.api_keys()
    hashes = {name: seed.spec_hash(spec) for name, spec in specs.items()}
    assert len(set(hashes.values())) == len(hashes)
    changed = {**specs["argus-reader"], "expiration": "1d"}
    assert seed.spec_hash(changed) != hashes["argus-reader"]
    assert (
        seed.spec_hash(dict(reversed(list(specs["argus-reader"].items()))))
        == hashes["argus-reader"]
    )


class _FakeES:
    """Just enough of the tier's Elasticsearch for ``ensure_keys``: ``argus`` as it is held,
    no valid keys, and grants that fail for one key name."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.user: dict[str, Any] | None = None
        self.fail_on = fail_on
        self.minted: list[str] = []

    def as_user(self, name: str, password: str) -> _FakeES:
        return self  # the grant is sent as the minter

    def request(
        self, method: str, path: str, body: Any = None, *, params: Any = None, ok: Any = (200,)
    ) -> Any:
        user_path = f"/_security/user/{seed.ARGUS_USER}"
        if (method, path) == ("GET", "/_security/api_key"):
            return {"api_keys": []}
        if (method, path) == ("GET", user_path):
            return {seed.ARGUS_USER: dict(self.user)} if self.user is not None else {}
        if (method, path) == ("PUT", user_path):
            self.user = {k: body[k] for k in ("roles", "metadata", "enabled")}
            return {"created": True}
        if (method, path) == ("PUT", f"{user_path}/_disable"):
            assert self.user is not None
            self.user["enabled"] = False
            return {}
        if (method, path) == ("POST", "/_security/api_key/grant"):
            name = body["api_key"]["name"]
            if name == self.fail_on:
                raise RuntimeError(f"the grant of {name} failed")
            self.minted.append(name)
            return {"id": f"id-{name}", "encoded": f"encoded-{name}"}
        raise AssertionError(f"unexpected {method} {path}")


def _secrets() -> dict[str, Any]:
    return {
        "passwords": {seed.ARGUS_USER: "a" * 40, seed.KEY_MINTER: "b" * 40},  # fake-secret
        "api_keys": {},
    }


def test_argus_rests_narrowed_and_disabled_after_the_mint() -> None:
    es = _FakeES()
    done = seed.ensure_keys(es, _secrets(), lambda: None, lambda _: None)
    assert es.minted == list(seed.api_keys())
    assert es.user is not None
    assert es.user["roles"] == seed.ARGUS_RESTING_ROLES
    assert es.user["enabled"] is False
    assert done["argus user"] == "narrowed and disabled"


def test_a_failed_mint_still_leaves_argus_narrowed_and_disabled() -> None:
    """DQ3 (a): `argus` is widened only for the mint, so a grant that fails half-way must not
    leave it widened and enabled until the next seed."""
    failing = list(seed.api_keys())[2]
    es = _FakeES(fail_on=failing)
    with pytest.raises(RuntimeError, match="grant"):
        seed.ensure_keys(es, _secrets(), lambda: None, lambda _: None)
    assert es.minted == list(seed.api_keys())[:2]
    assert es.user is not None
    assert es.user["roles"] == seed.ARGUS_RESTING_ROLES
    assert es.user["enabled"] is False


# --------------------------------------------------------------------------- the keys' bodies


_SPACE = [f"space:{seed.SPACE}"]
_ALERTS = [
    ".alerts-security.alerts-acme-soc",
    ".internal.alerts-security.alerts-acme-soc-*",
]


def _kibana_only(*privileges: str) -> dict[str, Any]:
    return {
        "cluster": [],
        "indices": [],
        "applications": [
            {"application": "kibana-.kibana", "privileges": list(privileges), "resources": _SPACE}
        ],
    }


# The bodies as the admin is to mint them (DQ3 (a)), written out word for word: a change to any
# key's cluster, indices, resources or privileges must change this test too (review F5).
PINNED_KEYS: dict[str, dict[str, Any]] = {
    "argus-kibana-reader": {
        "expiration": "90d",
        "role_descriptors": {
            "argus_kibana_reader": _kibana_only("feature_securitySolutionCasesV3.read")
        },
    },
    "argus-cases-writer": {
        "expiration": "30d",
        "role_descriptors": {
            "argus_cases_writer": _kibana_only(
                "feature_securitySolutionCasesV3.all", "feature_siemV2.read"
            )
        },
    },
    "argus-cases-writer-actions": {
        "expiration": "30d",
        "role_descriptors": {
            "argus_cases_writer_actions": _kibana_only(
                "login:",
                "cases:securitySolution/createCase",
                "cases:securitySolution/getCase",
                "cases:securitySolution/getComment",
                "cases:securitySolution/getTags",
                "cases:securitySolution/getReporters",
                "cases:securitySolution/getUserActions",
                "cases:securitySolution/findConfigurations",
                "cases:securitySolution/updateCase",
                "cases:securitySolution/createComment",
                "cases:securitySolution/reopenCase",
                "alerting:siem.eqlRule/siem/alert/get",
                "alerting:siem.esqlRule/siem/alert/get",
                "alerting:siem.indicatorRule/siem/alert/get",
                "alerting:siem.mlRule/siem/alert/get",
                "alerting:siem.newTermsRule/siem/alert/get",
                "alerting:siem.notifications/siem/alert/get",
                "alerting:siem.queryRule/siem/alert/get",
                "alerting:siem.savedQueryRule/siem/alert/get",
                "alerting:siem.thresholdRule/siem/alert/get",
            )
        },
    },
    "argus-alert-writer": {
        "expiration": "30d",
        "role_descriptors": {
            "argus_alert_writer": {
                **_kibana_only("feature_siemV2.read"),
                "indices": [
                    {
                        "names": _ALERTS,
                        "privileges": ["read", "index", "maintenance", "view_index_metadata"],
                    }
                ],
            }
        },
    },
    "argus-reader": {
        "expiration": "90d",
        "role_descriptors": {
            "argus_reader": {
                "cluster": ["monitor"],
                "indices": [
                    {
                        "names": [
                            *_ALERTS,
                            "acme-logs-*",
                            "abuse-ioc",
                            "acme-threat-intel",
                        ],
                        "privileges": ["read", "view_index_metadata"],
                        "allow_restricted_indices": False,
                    }
                ],
            }
        },
    },
}


def test_every_key_body_is_pinned_word_for_word() -> None:
    assert seed.api_keys() == PINNED_KEYS


# --------------------------------------------------------------------------- surplus keys (F8)


class _KeysES:
    """Elasticsearch after seeds A and B ran at once on a clean tier: both minted every key,
    and B saved last, so the tier's secrets hold B's ids."""

    def __init__(self) -> None:
        self.valid = [
            {"id": f"{who}-{name}", "name": name} for who in "AB" for name in seed.api_keys()
        ]
        self.invalidated: list[str] = []
        self.user = {
            "roles": seed.ARGUS_RESTING_ROLES,
            "metadata": {"argus_service": True},
            "enabled": False,
        }

    def as_user(self, *args: str) -> _KeysES:
        return self

    def request(self, method: str, path: str, body: Any = None, **kw: Any) -> Any:
        if (method, path) == ("GET", "/_security/api_key"):
            return {"api_keys": list(self.valid)}
        if (method, path) == ("GET", f"/_security/user/{seed.ARGUS_USER}"):
            return {seed.ARGUS_USER: dict(self.user)}
        if (method, path) == ("DELETE", "/_security/api_key"):
            self.invalidated.extend(body["ids"])
            self.valid = [k for k in self.valid if k["id"] not in body["ids"]]
            return {"invalidated_api_keys": body["ids"]}
        raise AssertionError(f"unexpected {method} {path}")


def test_a_seed_invalidates_argus_keys_the_tier_holds_no_value_for() -> None:
    """Review F8: after two seeds at once the next seed kept everything and left the losing
    seed's five keys valid (writers with Cases All among them) for 30 to 90 days."""
    es = _KeysES()
    data: dict[str, Any] = {
        "passwords": {seed.ARGUS_USER: "a" * 40, seed.KEY_MINTER: "b" * 40},  # fake-secret
        "api_keys": {
            name: {"id": f"B-{name}", "encoded": f"enc-B-{name}", "spec": seed.spec_hash(body)}
            for name, body in seed.api_keys().items()
        },
    }
    done = seed.ensure_keys(es, data, lambda: None, lambda _: None)
    assert sorted(es.invalidated) == sorted(f"A-{name}" for name in seed.api_keys())
    assert sorted(k["id"] for k in es.valid) == sorted(f"B-{name}" for name in seed.api_keys())
    assert all(done[name] == "kept" for name in seed.api_keys())
    assert done["surplus keys invalidated"] == len(seed.api_keys())


# --------------------------------------------------------------------------- role drift (F9)


def _as_kibana_answers(name: str, body: dict[str, Any]) -> dict[str, Any]:
    """GET /api/security/role/<name> for a role PUT with ``body`` (Kibana 8.19.12)."""
    es = body["elasticsearch"]
    return {
        "name": name,
        "metadata": {},
        "transient_metadata": {"enabled": True},
        "elasticsearch": {
            "cluster": list(es["cluster"]),
            "indices": [{**i, "allow_restricted_indices": False} for i in es["indices"]],
            "run_as": [],
        },
        "kibana": [dict(entry) for entry in body["kibana"]],
        "_transform_error": [],
        "_unrecognized_applications": [],
    }


def _as_es_answers(body: dict[str, Any]) -> dict[str, Any]:
    """GET /_security/role/<name>'s value for a role PUT with ``body`` (Elasticsearch 8.19.12)."""
    return {
        "cluster": list(body.get("cluster", [])),
        "indices": [{"allow_restricted_indices": False, **i} for i in body.get("indices", [])],
        "applications": [dict(a) for a in body.get("applications", [])],
        "run_as": [],
        "metadata": {},
        "transient_metadata": {"enabled": True},
    }


class _RolesTier:
    """Kibana's and Elasticsearch's role APIs holding the seed's roles as the tier answers
    them, with one tampered; every PUT recorded."""

    def __init__(self, tamper: Any = None, *, es_role: str | None = None) -> None:
        self.kibana_roles = {n: _as_kibana_answers(n, b) for n, b in seed.KIBANA_ROLES.items()}
        self.es_roles = {n: _as_es_answers(b) for n, b in seed.es_roles().items()}
        if tamper is not None:
            tamper(self.es_roles[es_role] if es_role else self.kibana_roles["acme_viewer"])
        self.put: list[str] = []

    def request(self, method: str, path: str, body: Any = None, **kw: Any) -> Any:
        if (method, path) == ("GET", "/_security/privilege/argus"):
            return seed.ARGUS_PRIVILEGES
        name = path.rsplit("/", 1)[-1]
        if method == "GET" and path.startswith("/api/security/role/"):
            return self.kibana_roles[name]
        if method == "GET" and path.startswith("/_security/role/"):
            return {name: self.es_roles[name]}
        if method == "PUT":
            self.put.append(name)
            return {}
        raise AssertionError(f"unexpected {method} {path}")


def test_the_seeds_roles_as_the_tier_answers_them_are_kept() -> None:
    tier = _RolesTier()
    done = seed.ensure_roles(tier, tier)
    assert tier.put == []
    assert set(done.values()) == {"kept"}


def _kibana_es(role: dict[str, Any]) -> dict[str, Any]:
    part: dict[str, Any] = role["elasticsearch"]
    return part


KIBANA_TAMPERING = {
    "run_as": lambda r: _kibana_es(r).update(run_as=["elastic"]),
    "a document query": lambda r: _kibana_es(r)["indices"][0].update(query='{"match_all":{}}'),
    "field security": lambda r: _kibana_es(r)["indices"][0].update(
        field_security={"grant": ["@timestamp"]}
    ),
    "restricted indices": lambda r: _kibana_es(r)["indices"][0].update(
        allow_restricted_indices=True
    ),
    "another index": lambda r: _kibana_es(r)["indices"].append(
        {"names": ["*"], "privileges": ["read"], "allow_restricted_indices": False}
    ),
    "remote indices": lambda r: _kibana_es(r).update(
        remote_indices=[{"clusters": ["*"], "names": ["*"], "privileges": ["read"]}]
    ),
    "a cluster privilege": lambda r: _kibana_es(r)["cluster"].append("manage_security"),
    "metadata": lambda r: r.update(metadata={"by": "someone"}),
    "another space": lambda r: r["kibana"].append(
        {"base": ["all"], "feature": {}, "spaces": ["*"]}
    ),
    "an application of elsewhere": lambda r: r.update(_unrecognized_applications=["other"]),
}


@pytest.mark.parametrize("how", sorted(KIBANA_TAMPERING))
def test_a_widened_kibana_seed_role_is_put_back(how: str) -> None:
    """Review F9: the drift check compared cluster, index names and privileges and features
    only, so run_as, document or field security and the rest were kept."""
    tier = _RolesTier(KIBANA_TAMPERING[how])
    done = seed.ensure_roles(tier, tier)
    assert tier.put == ["acme_viewer"]
    assert done["acme_viewer"] == "updated"


ES_TAMPERING = {
    "a cluster privilege": lambda r: r["cluster"].append("manage_security"),
    "run_as": lambda r: r.update(run_as=["elastic"]),
    "an index": lambda r: r["indices"].append(
        {"names": ["*"], "privileges": ["all"], "allow_restricted_indices": True}
    ),
    "another privilege": lambda r: r["applications"][0]["privileges"].append("admin"),
    "another application": lambda r: r["applications"].append(
        {"application": "kibana-.kibana", "privileges": ["all"], "resources": ["*"]}
    ),
    "metadata": lambda r: r.update(metadata={"by": "someone"}),
}


@pytest.mark.parametrize("how", sorted(ES_TAMPERING))
def test_a_widened_es_seed_role_is_put_back(how: str) -> None:
    tier = _RolesTier(ES_TAMPERING[how], es_role="argus_approver")
    done = seed.ensure_roles(tier, tier)
    assert tier.put == ["argus_approver"]
    assert done["argus_approver"] == "updated"


def test_the_es_reader_role_as_the_tier_answers_it_is_kept() -> None:
    assert seed.es_role_matches(_as_es_answers(seed.reader_role()), seed.reader_role())
    widened = _as_es_answers(seed.reader_role())
    widened["indices"][0]["privileges"].append("write")
    assert not seed.es_role_matches(widened, seed.reader_role())


# --------------------------------------------------------------------------- Q-A0's bodies
