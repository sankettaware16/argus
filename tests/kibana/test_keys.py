"""§12 #9: how ``argus``'s keys are made and how they die (DQ3 (a), the identities runbook).

* The grant API mints a key owned by another user, given that user's password; the caller
  needs ``grant_api_key`` (the ELK admin has it, an analyst does not).
* A key is limited by its owner's privileges as they were at the mint: disabling the owner,
  taking its roles away, even deleting the role, leaves the key working. Revocation is by
  invalidating the key (by id), never by disabling the user.
* The seeded keys work while ``argus`` itself is disabled and narrowed to the reader role.
"""

from __future__ import annotations

from tests.kibana import kit
from tests.kibana.tier import S, Tier, seed

READER = {"reader": seed.app_descriptor([f"feature_{seed.CASES}.read"])}


def _authenticated(kt: Tier, principal: str) -> tuple[int, object]:
    reply = kt.es(principal).get(
        "/_security/_authenticate",
        keep=lambda b: {
            "username": b["username"],
            "type": b["authentication_type"],
            "key": (b.get("api_key") or {}).get("name"),
        },
    )
    return reply.status, reply.body if reply.status == 200 else None


def _finds(kt: Tier, principal: str) -> int:
    return (
        kt.kibana(principal)
        .get(
            f"{S}/api/cases/_find",
            params={"tags": kit.run_tag(kt), "perPage": 1},
            keep=lambda b: {"total": b["total"]},
        )
        .status
    )


def test_granting_needs_grant_api_key(kt: Tier) -> None:
    role = kit.make_kibana_role(kt, "g-r", seed.KIBANA_ROLES["argus_kibana_reader"])
    owner = kit.make_user(kt, "g-o", [role])
    _, refused = kit.grant_key(kt, "g-o", owner, "g-k", READER, minter="tier-analyst")
    assert refused.status == 403
    assert "cluster:admin/xpack/security/api_key/grant" in refused.body["error"]["reason"]


def test_a_key_outlives_its_owners_disable_and_narrowing(kt: Tier) -> None:
    role = kit.make_kibana_role(kt, "k-r", seed.KIBANA_ROLES["argus_kibana_reader"])
    owner = kit.make_user(kt, "k-o", [role])
    key, granted = kit.grant_key(kt, "k-o", owner, "k-k", READER)
    assert granted.status == 200
    assert granted["name"] == kt.name("k-k")
    key_id = granted["id"]
    assert _authenticated(kt, key) == (
        200,
        {"username": kt.name("k-o"), "type": "api_key", "key": kt.name("k-k")},
    )
    assert _finds(kt, key) == 200

    admin = kt.es("elastic")
    assert admin.put(f"/_security/user/{kt.name('k-o')}/_disable").status == 200
    assert _authenticated(kt, owner)[0] == 401  # the owner cannot sign in any more
    assert _authenticated(kt, key)[0] == 200  # its key still works
    assert _finds(kt, key) == 200

    narrowed = admin.put(f"/_security/user/{kt.name('k-o')}", {"roles": []})
    assert narrowed.status == 200
    deleted = kt.kibana("elastic").delete(f"/api/security/role/{role}")
    assert deleted.status == 204
    assert _finds(kt, key) == 200  # limited by the owner's roles as they were at the mint

    invalidated = admin.delete(
        "/_security/api_key",
        {"ids": [key_id]},
        keep=lambda b: {"invalidated": b["invalidated_api_keys"], "errors": b["error_count"]},
    )
    assert invalidated.body == {"invalidated": [key_id], "errors": 0}
    assert _authenticated(kt, key)[0] == 401
    assert _finds(kt, key) == 401


def test_the_seeded_keys_work_while_argus_is_disabled(kt: Tier) -> None:
    argus = kt.es("elastic").get(
        "/_security/user/argus",
        keep=lambda b: {k: b["argus"][k] for k in ("enabled", "roles", "metadata")},
    )
    assert argus.body == {
        "enabled": False,
        "roles": seed.ARGUS_RESTING_ROLES,
        "metadata": {"argus_service": True},
    }
    assert _authenticated(kt, "user:argus")[0] == 401
    assert _authenticated(kt, "key:argus-kibana-reader") == (
        200,
        {"username": "argus", "type": "api_key", "key": "argus-kibana-reader"},
    )
    assert _finds(kt, "key:argus-kibana-reader") == 200
    # the writer keys were minted while argus held their roles; it no longer does
    writer = kit.create_case(kt, "key:argus-cases-writer", "while argus is disabled")
    assert (writer.status, writer.body["created_by"]["username"]) == (200, "argus")
