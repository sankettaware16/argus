"""The tier itself (Q-D1): the SIEM's release on the Basic licence, the space with every feature on,
and what the seed made (scripts/kibana_seed.py): users, roles, ``argus``'s keys with what limits
them, the rule and its alerts, a person's case and ARGUS's case."""

from __future__ import annotations

import json
from typing import Any

from tests.kibana.tier import ALERTS_ALIAS, S, Tier, seed, tier_script


def test_the_release_and_the_licence(kt: Tier) -> None:
    es = kt.es("elastic")
    info = es.get(
        "/",
        keep=lambda b: {"number": b["version"]["number"], "flavor": b["version"]["build_flavor"]},
    )
    assert info.body == {"number": "8.19.12", "flavor": "default"}
    lic = es.get("/_license", keep=lambda b: {k: b["license"][k] for k in ("type", "status")})
    assert lic.body == {"type": "basic", "status": "active"}
    status = kt.kibana("elastic").get(
        "/api/status",
        keep=lambda b: {"number": b["version"]["number"], "level": b["status"]["overall"]["level"]},
    )
    assert status.body == {"number": "8.19.12", "level": "available"}
    features = kt.kibana("elastic").get(
        "/api/features",
        keep=lambda b: {
            f["id"]: sorted(s["name"] for s in f.get("subFeatures", []))
            for f in b
            if f["id"] in (seed.SECURITY, seed.CASES)
        },
    )
    assert features.body[seed.CASES] == [
        "Assign users",
        "Case settings",
        "Create comments & attachments",
        "Delete",
        "Re-open",
    ]
    assert seed.SECURITY in features.body


def test_the_space_has_every_feature_on(kt: Tier) -> None:
    space = kt.kibana("elastic").get(f"/api/spaces/space/{seed.SPACE}")
    assert space.status == 200
    assert (space["id"], space["disabledFeatures"]) == (seed.SPACE, [])


def test_the_seeded_accounts(kt: Tier) -> None:
    names = ",".join(seed.usernames())
    users = kt.es("elastic").get(
        f"/_security/user/{names}",
        keep=lambda b: {
            n: {"roles": u["roles"], "enabled": u["enabled"], "metadata": u["metadata"]}
            for n, u in sorted(b.items())
        },
    )
    expected = {
        name: {"roles": roles, "enabled": enabled, "metadata": {"argus_uid": seed.argus_uid(name)}}
        for name, (_kind, roles, enabled) in seed.USERS.items()
    }
    expected["argus"] = {
        "roles": seed.ARGUS_RESTING_ROLES,
        "enabled": False,
        "metadata": {"argus_service": True},
    }
    assert users.body == expected
    for role in ("argus_kibana_reader", "argus_cases_writer", "argus_alert_writer"):
        got = kt.kibana("elastic").get(
            f"/api/security/role/{role}",
            keep=lambda b: {"kibana": b["kibana"], "indices": b["elasticsearch"]["indices"]},
        )
        wanted = seed.KIBANA_ROLES[role]
        assert got.body["kibana"] == [
            {**wanted["kibana"][0], "base": [], "spaces": [seed.SPACE]}
        ], role
        assert [i["names"] for i in got.body["indices"]] == [
            i["names"] for i in wanted["elasticsearch"]["indices"]
        ], role


def test_argus_keys_and_what_limits_them(kt: Tier) -> None:
    """Each of `argus`'s keys holds exactly its body in scripts/kibana_seed.py, the body the
    admin is to mint on the SIEM: cluster, indices, applications, resources, run_as and every
    other part of each role descriptor (review F5: only application privileges were read)."""

    def summary(body: dict[str, Any]) -> dict[str, Any]:
        out = {}
        for key in body["api_keys"]:
            out[key["name"]] = {
                "descriptors": {
                    name: seed.role_normal(descriptor)
                    for name, descriptor in sorted(key["role_descriptors"].items())
                },
                "limited_by": sorted(key["limited_by"][0]),
                "expires": key.get("expiration") is not None,
            }
        return dict(sorted(out.items()))

    keys = kt.es("elastic").get(
        "/_security/api_key",
        params={"username": "argus", "active_only": "true", "with_limited_by": "true"},
        keep=summary,
    )
    assert sorted(keys.body) == sorted(seed.api_keys())
    for name, spec in seed.api_keys().items():
        got = keys.body[name]
        assert got["descriptors"] == {
            descriptor: json.loads(json.dumps(seed.role_normal(body)))
            for descriptor, body in spec["role_descriptors"].items()
        }, name
        assert got["limited_by"] == sorted(seed.ARGUS_MINT_ROLES), name  # roles at the mint
        assert got["expires"] is True, name
    reader = keys.body["argus-kibana-reader"]["descriptors"]["argus_kibana_reader"]
    assert reader["applications"] == [
        {
            "application": "kibana-.kibana",
            "privileges": [f"feature_{seed.CASES}.read"],
            "resources": [f"space:{seed.SPACE}"],
        }
    ]
    assert (reader["cluster"], reader["indices"]) == ([], [])


def test_the_seed_rule_its_alerts_and_cases(kt: Tier) -> None:
    rule = kt.kibana("elastic").get(
        f"{S}/api/detection_engine/rules",
        params={"rule_id": seed.SEED_RULE_ID},
        keep=lambda b: {k: b[k] for k in ("rule_id", "enabled", "type", "query", "index")},
    )
    assert rule.body == {
        "rule_id": seed.SEED_RULE_ID,
        "enabled": True,
        "type": "query",
        "query": 'tier.run: "seed"',
        "index": [seed.EVENTS_INDEX],
    }
    count = kt.es("elastic").post(
        f"/{ALERTS_ALIAS}/_count",
        {"query": {"term": {"kibana.alert.rule.rule_id": seed.SEED_RULE_ID}}},
        keep=lambda b: b["count"],
    )
    assert count.body == seed.SEED_EVENTS
    cases = kt.kibana("elastic").get(
        f"{S}/api/cases/_find",
        params={"tags": "tier-seed", "sortField": "title", "sortOrder": "asc"},
        keep=lambda b: [
            {
                "title": c["title"],
                "by": c["created_by"]["username"],
                "sync": c["settings"]["syncAlerts"],
                "alerts": c["totalAlerts"],
                "comments": c["totalComment"],
            }
            for c in b["cases"]
        ],
    )
    assert cases.body == [
        {
            "title": "Tier seed: a person's case",
            "by": "tier-analyst",
            "sync": True,
            "alerts": 2,
            "comments": 0,
        },
        {
            "title": "[ARGUS 0] Tier seed: ARGUS's case",
            "by": "argus",
            "sync": False,
            "alerts": 0,
            "comments": 1,
        },
    ]


def test_no_secret_in_the_tiers_processes(live_kt: Tier) -> None:
    """Review F3: secrets reach the tier's containers only as files. No process of either
    container holds one in its environment or command line (read inside each container, as its
    own user). Live only: it reads processes, not answers."""
    seen, unreadable, found = tier_script.secrets_in_containers(
        live_kt.settings, tier_script.tier_secret_values(live_kt.data)
    )
    assert seen >= 4  # tini, Elasticsearch's launcher and server; tini and Kibana's Node
    assert unreadable == []
    assert found == []
