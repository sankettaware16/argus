"""What the local Kibana tier holds (Q-D1), and the idempotent seed that makes it so.

Loaded by scripts/kibana_tier.py (``seed``, ``status``) and by tests/kibana. A second run
changes nothing; on a clean volume it builds everything:

* the site's space (``SPACE``) with every feature on (Security and Cases included);
* the ``argus`` application privileges ``approver`` and ``admin`` (plan §7.2);
* the roles: ARGUS's Kibana key roles (Cases Read; Cases All + Security Read; the alert writer:
  Security Read and read, index, maintenance, view_index_metadata on the alerts indices;
  DQ3 (a)), the Elasticsearch reader role of the site (what the reader key's runbook gives
  the SIEM admin), the roles holding the ``argus`` application privileges, and people's
  everyday roles, named with the site's prefix (``<prefix>_viewer``);
* users of every kind: a superuser, an ELK admin (who mints keys), ARGUS's admin and approver,
  an analyst, a case manager, a reviewer, a viewer, a disabled user, a user of another space
  only, and the service user ``argus`` (``metadata.argus_service``);
* ``argus``'s API keys, minted by the ELK admin through the grant API with ``argus``'s password
  (DQ3 (a)): ``argus``'s roles are widened for the mint, narrowed to the reader role after it,
  and ``argus`` stays disabled between mints, as planned for the SIEM;
* a detection rule writing alerts into the space from seeded synthetic events, and its alerts;
* two cases, one of a person (Sync alerts on, as Kibana's UI makes them, two alerts attached)
  and one of ARGUS (Sync alerts off, a comment), so that reads see both kinds.

Names here are fixed for a site (the seed is shared by every worktree of a site); tests make their
own objects with a per-run name (tests/kibana/conftest.py), so runs side by side never meet. The
site is the one this process runs on (D-294): the suite's made-up one under the tests, the
checkout's config/site.yaml when scripts/kibana_tier.py runs; KIBANA_TIER_SPACE and
KIBANA_TIER_PREFIX name another space and role prefix. Every value is synthetic: documentation
addresses (RFC 5737), ``.invalid`` e-mail addresses.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def tier_names(environ: Mapping[str, str] = os.environ) -> tuple[str, str]:
    """The space and the role-name prefix of the site the tier stands for: KIBANA_TIER_SPACE and
    KIBANA_TIER_PREFIX when set, else the active site's space and its security team's short name
    in lower case (``ACME`` -> ``acme``: ``acme_viewer``)."""
    from argus import site

    active = site.active()
    short = re.sub(r"[^a-z0-9]+", "_", active.organisation.short_name.lower()).strip("_")
    return (
        environ.get("KIBANA_TIER_SPACE") or active.space,
        environ.get("KIBANA_TIER_PREFIX") or short or "soc",
    )


SPACE, PREFIX = tier_names()
OWNER = "securitySolution"  # the cases owner of the Security solution
APP = "kibana-.kibana"  # Kibana's application in Elasticsearch's privilege store
SPACE_RESOURCE = f"space:{SPACE}"
SECURITY = "siemV2"  # Kibana 8.19.12's Security feature (GET /api/features)
CASES = "securitySolutionCasesV3"  # and its Cases feature
ALERTS_ALIAS = f".alerts-security.alerts-{SPACE}"
ALERTS_INDICES = [ALERTS_ALIAS, f".internal.alerts-security.alerts-{SPACE}-*"]
EVENTS_INDEX = "argus-tier-events"
SEED_RULE_ID = "argus-tier-seed"
SEED_RUN = "seed"
SEED_EVENTS = 12
UID_NAMESPACE = uuid.UUID("5d0b8a4e-3c55-4a39-9a43-0c4c8f1d2b61")  # argus_uid = uuid5(name)
NO_CONNECTOR = {"id": "none", "name": "none", "type": ".none", "fields": None}

Log = Callable[[str], None]

# --------------------------------------------------------------------------- roles

# The Security solution's rule types in 8.19.12 (GET /api/security/privileges?includeActions):
# reading an alert of any of them is what attaching it to a case checks.
SIEM_RULE_TYPES = [
    "siem.eqlRule",
    "siem.esqlRule",
    "siem.indicatorRule",
    "siem.mlRule",
    "siem.newTermsRule",
    "siem.notifications",
    "siem.queryRule",
    "siem.savedQueryRule",
    "siem.thresholdRule",
]
# What an action-scoped cases writer key holds (§12 #8, proven by tests/kibana): login to the
# space, Cases All's case actions without delete, push, configuration writes, assignees or
# comment edits, and the "get" of Security's alerts (an attach reads the alert first). No other
# Security action, so no api:rac: it cannot change an alert's status.
CASES_WRITER_ACTIONS = [
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
    *(f"alerting:{rule_type}/siem/alert/get" for rule_type in SIEM_RULE_TYPES),
]
ALERT_WRITE = ["read", "index", "maintenance", "view_index_metadata"]
ALERT_READ = ["read", "view_index_metadata"]


def alerts_indices(privileges: list[str]) -> list[dict[str, Any]]:
    return [{"names": list(ALERTS_INDICES), "privileges": list(privileges)}]


def kibana_role(
    features: Mapping[str, list[str]],
    *,
    indices: list[dict[str, Any]] | None = None,
    spaces: list[str] | None = None,
    cluster: list[str] | None = None,
    base: list[str] | None = None,
) -> dict[str, Any]:
    """A body for Kibana's role API (PUT /api/security/role/<name>)."""
    return {
        "elasticsearch": {"cluster": cluster or [], "indices": indices or [], "run_as": []},
        "kibana": [
            {
                "base": base or [],
                "feature": {} if base else {k: list(v) for k, v in features.items()},
                "spaces": spaces or [SPACE],
            }
        ],
    }


VIEWER = f"{PREFIX}_viewer"
REVIEWER = f"{PREFIX}_reviewer"
CASE_MANAGER = f"{PREFIX}_case_manager"
ANALYST = f"{PREFIX}_analyst"
ELK_ADMIN = f"{PREFIX}_elk_admin"
OTHER_SPACE = f"{PREFIX}_other_space"

KIBANA_ROLES: dict[str, dict[str, Any]] = {
    # ARGUS's key roles (DQ3 (a)); each key is limited by its owner's roles at the mint.
    "argus_kibana_reader": kibana_role({CASES: ["read"]}),
    "argus_cases_writer": kibana_role({CASES: ["all"], SECURITY: ["read"]}),
    "argus_alert_writer": kibana_role({SECURITY: ["read"]}, indices=alerts_indices(ALERT_WRITE)),
    # People's everyday accounts (the capability table of plan §7.2).
    VIEWER: kibana_role({SECURITY: ["read"], CASES: ["read"]}, indices=alerts_indices(ALERT_READ)),
    REVIEWER: kibana_role(
        {SECURITY: ["all"], CASES: ["read"]}, indices=alerts_indices(ALERT_WRITE)
    ),
    CASE_MANAGER: kibana_role(
        {SECURITY: ["read"], CASES: ["all"]}, indices=alerts_indices(ALERT_READ)
    ),
    ANALYST: kibana_role({SECURITY: ["all"], CASES: ["all"]}, indices=alerts_indices(ALERT_WRITE)),
    # An ELK admin: manages users and keys, and mints keys for others (the grant API).
    ELK_ADMIN: kibana_role(
        {},
        base=["all"],
        spaces=["*"],
        cluster=["manage_security", "manage_api_key", "grant_api_key", "monitor"],
        indices=[{"names": ["*"], "privileges": ["all"]}],
    ),
    # Security and Cases in the default space only: nothing in the site's space.
    OTHER_SPACE: kibana_role({SECURITY: ["all"], CASES: ["all"]}, spaces=["default"]),
}


def reader_role() -> dict[str, Any]:
    """The Elasticsearch reader key's role for the site, as its runbook gives it to the SIEM
    admin: monitor, and read and view_index_metadata on the alerts index and its backing indices,
    the log patterns the self-test checks, and the threat-intel indices, in that order."""
    from argus import site

    active = site.active()
    names = [*ALERTS_INDICES, *active.checked_log_patterns, *active.ti_indices]
    return {
        "cluster": ["monitor"],
        "indices": [
            {
                "names": names,
                "privileges": ["read", "view_index_metadata"],
                "allow_restricted_indices": False,
            }
        ],
    }


def es_roles() -> dict[str, dict[str, Any]]:
    """Roles made with Elasticsearch's role API: the reader key's owner role and the `argus`
    application privileges (Kibana's role API manages only Kibana's own application)."""
    return {
        "argus_es_reader": reader_role(),
        "argus_approver": {
            "applications": [
                {"application": "argus", "privileges": ["approver"], "resources": ["*"]}
            ]
        },
        "argus_admin": {
            "applications": [{"application": "argus", "privileges": ["admin"], "resources": ["*"]}]
        },
    }


ARGUS_PRIVILEGES = {
    "argus": {
        "approver": {"actions": ["argus:approve"], "metadata": {"description": "approve"}},
        "admin": {"actions": ["argus:admin"], "metadata": {"description": "ARGUS settings"}},
    }
}

# --------------------------------------------------------------------------- users

# name -> (kind, roles, enabled): every kind of account that sign-in and the capability map
# (Q-E1, Q-E2) must meet.
USERS: dict[str, tuple[str, list[str], bool]] = {
    "tier-superuser": ("superuser", ["superuser"], True),
    "tier-elkadmin": ("ELK admin", [ELK_ADMIN], True),
    "tier-argusadmin": ("ARGUS admin", [VIEWER, "argus_admin"], True),
    "tier-approver": ("approver", [ANALYST, "argus_approver"], True),
    "tier-analyst": ("analyst", [ANALYST], True),
    "tier-manager": ("case manager", [CASE_MANAGER], True),
    "tier-reviewer": ("reviewer", [REVIEWER], True),
    "tier-viewer": ("viewer", [VIEWER], True),
    "tier-disabled": ("disabled", [VIEWER], False),
    "tier-otherspace": ("another space only", [OTHER_SPACE], True),
}
ARGUS_USER = "argus"
ARGUS_RESTING_ROLES = ["argus_kibana_reader"]  # between mints (DQ3 (a))
ARGUS_MINT_ROLES = [
    "argus_kibana_reader",
    "argus_cases_writer",
    "argus_alert_writer",
    "argus_es_reader",
]
KEY_MINTER = "tier-elkadmin"


def usernames() -> list[str]:
    return [*USERS, ARGUS_USER]


def argus_uid(name: str) -> str:
    return str(uuid.uuid5(UID_NAMESPACE, name))


def full_name(name: str) -> str:
    return "ARGUS" if name == ARGUS_USER else "Tier " + name.removeprefix("tier-").title()


def user_body(name: str, roles: list[str], password: str) -> dict[str, Any]:
    service = name == ARGUS_USER
    metadata: dict[str, Any] = (
        {"argus_service": True} if service else {"argus_uid": argus_uid(name)}
    )
    return {
        "password": password,
        "roles": list(roles),
        "full_name": full_name(name),
        "email": f"{name}@tier.argus.invalid",
        "metadata": metadata,
        "enabled": True,
    }


# --------------------------------------------------------------------------- keys


def app_descriptor(
    privileges: list[str],
    *,
    indices: list[dict[str, Any]] | None = None,
    cluster: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "cluster": cluster or [],
        "indices": indices or [],
        "applications": [
            {"application": APP, "privileges": list(privileges), "resources": [SPACE_RESOURCE]}
        ],
    }


def api_keys() -> dict[str, dict[str, Any]]:
    """`argus`'s keys: name -> the grant request's ``api_key`` part (DQ3 (a): the reader with
    Cases Read only, 90 days; writers 30 days)."""
    return {
        "argus-kibana-reader": {
            "expiration": "90d",
            "role_descriptors": {"argus_kibana_reader": app_descriptor([f"feature_{CASES}.read"])},
        },
        "argus-cases-writer": {
            "expiration": "30d",
            "role_descriptors": {
                "argus_cases_writer": app_descriptor(
                    [f"feature_{CASES}.all", f"feature_{SECURITY}.read"]
                )
            },
        },
        "argus-cases-writer-actions": {
            "expiration": "30d",
            "role_descriptors": {
                "argus_cases_writer_actions": app_descriptor(list(CASES_WRITER_ACTIONS))
            },
        },
        "argus-alert-writer": {
            "expiration": "30d",
            "role_descriptors": {
                "argus_alert_writer": app_descriptor(
                    [f"feature_{SECURITY}.read"], indices=alerts_indices(ALERT_WRITE)
                )
            },
        },
        "argus-reader": {"expiration": "90d", "role_descriptors": {"argus_reader": reader_role()}},
    }


# --------------------------------------------------------------------------- reads


def user_state(es: Any, name: str) -> dict[str, Any] | None:
    found = es.request("GET", f"/_security/user/{name}", ok=(200, 404))
    if isinstance(found, dict) and name in found:
        user: dict[str, Any] = found[name]
        return user
    return None


def authenticates(es: Any, name: str, password: str) -> bool:
    response = es.as_user(name, password).send("GET", "/_security/_authenticate")
    return bool(response.status_code == 200)


def valid_keys(es: Any, owner: str = ARGUS_USER) -> dict[str, list[dict[str, Any]]]:
    """``owner``'s valid (neither invalidated nor expired) keys, by name."""
    found = es.request(
        "GET", "/_security/api_key", params={"username": owner, "active_only": "true"}
    )
    keys: dict[str, list[dict[str, Any]]] = {}
    for key in found.get("api_keys", []):
        keys.setdefault(key["name"], []).append(key)
    return keys


def count_alerts(es: Any, rule_id: str) -> int:
    found = es.request(
        "POST",
        f"/{ALERTS_ALIAS}/_count",
        {"query": {"term": {"kibana.alert.rule.rule_id": rule_id}}},
        ok=(200, 404),
    )
    return int(found.get("count", 0)) if isinstance(found, dict) else 0


def wait_alerts(es: Any, rule_id: str, count: int, *, seconds: float = 180) -> int:
    """Wait until ``rule_id`` has written ``count`` alerts (or the deadline); how many it has."""
    deadline = time.monotonic() + seconds
    while True:
        have = count_alerts(es, rule_id)
        if have >= count or time.monotonic() > deadline:
            return have
        time.sleep(1)


# --------------------------------------------------------------------------- writes


def ensure_space(kibana: Any) -> str:
    body = {
        "id": SPACE,
        "name": SPACE,
        "description": "ARGUS's local Kibana tier: the SIEM's space name, every feature on.",
        "disabledFeatures": [],
    }
    current = kibana.request("GET", f"/api/spaces/space/{SPACE}", ok=(200, 404))
    if isinstance(current, dict) and current.get("id") == SPACE:
        if all(current.get(k) == v for k, v in body.items()):
            return "kept"
        kibana.request("PUT", f"/api/spaces/space/{SPACE}", body)
        return "updated"
    kibana.request("POST", "/api/spaces/space", body)
    return "created"


def _entries(entries: Any) -> list[Any]:
    return sorted(entries, key=lambda e: json.dumps(e, sort_keys=True))


def _index_normal(entry: Mapping[str, Any]) -> dict[str, Any]:
    security = entry.get("field_security") or None
    if security and sorted(security.get("grant", [])) == ["*"] and not security.get("except"):
        security = None  # every field: the same as none
    if security:
        security = {k: sorted(security.get(k, [])) for k in ("grant", "except")}
    known = {"names", "privileges", "allow_restricted_indices", "field_security", "query"}
    return {
        "names": sorted(entry.get("names", [])),
        "privileges": sorted(entry.get("privileges", [])),
        "allow_restricted_indices": bool(entry.get("allow_restricted_indices", False)),
        "field_security": security,
        "query": entry.get("query") or None,
        "other": {k: v for k, v in sorted(entry.items()) if k not in known},  # e.g. clusters
    }


ROLE_PARTS_IGNORED = frozenset({"name", "transient_metadata"})  # state, not grants


def role_normal(role: Mapping[str, Any]) -> dict[str, Any]:
    """An Elasticsearch role, or an API key's role descriptor, as a comparable value: every
    part that can grant something, with Elasticsearch's defaults filled in, and any part this
    does not know kept whole, so that nothing widened compares equal (review F9)."""
    known = {
        "cluster",
        "indices",
        "applications",
        "run_as",
        "metadata",
        "remote_indices",
        "remote_cluster",
        "global",
        "description",
        "restriction",
    }
    return {
        "cluster": sorted(role.get("cluster", [])),
        "indices": _entries(_index_normal(i) for i in role.get("indices", [])),
        "applications": _entries(
            {
                "application": a["application"],
                "privileges": sorted(a.get("privileges", [])),
                "resources": sorted(a.get("resources", [])),
            }
            for a in role.get("applications", [])
        ),
        "run_as": sorted(role.get("run_as", [])),
        "metadata": role.get("metadata") or {},
        "remote_indices": _entries(_index_normal(i) for i in role.get("remote_indices", [])),
        "remote_cluster": _entries(
            {k: sorted(v) for k, v in sorted(r.items())} for r in role.get("remote_cluster", [])
        ),
        "global": role.get("global") or {},
        "description": role.get("description") or None,
        "restriction": role.get("restriction") or None,
        "other": {k: v for k, v in sorted(role.items()) if k not in known | ROLE_PARTS_IGNORED},
    }


def kibana_role_normal(role: Mapping[str, Any]) -> dict[str, Any]:
    """A role as Kibana's role API answers it (or a body for it), comparable likewise."""
    known = {
        "elasticsearch",
        "kibana",
        "metadata",
        "description",
        "_transform_error",
        "_unrecognized_applications",
    }
    return {
        "elasticsearch": role_normal(role.get("elasticsearch", {})),
        "kibana": _entries(
            {
                "base": sorted(e.get("base", [])),
                "feature": {k: sorted(v) for k, v in sorted(e.get("feature", {}).items())},
                "spaces": sorted(e.get("spaces", [])),
            }
            for e in role.get("kibana", [])
        ),
        "metadata": role.get("metadata") or {},
        "description": role.get("description") or None,
        # privileges of other applications, or ones Kibana cannot show as features
        "transform_error": sorted(role.get("_transform_error") or []),
        "unrecognized": sorted(role.get("_unrecognized_applications") or []),
        "other": {k: v for k, v in sorted(role.items()) if k not in known | ROLE_PARTS_IGNORED},
    }


def kibana_role_matches(current: Mapping[str, Any], body: Mapping[str, Any]) -> bool:
    return kibana_role_normal(current) == kibana_role_normal(body)


def es_role_matches(current: Mapping[str, Any], body: Mapping[str, Any]) -> bool:
    return role_normal(current) == role_normal(body)


def ensure_roles(es: Any, kibana: Any) -> dict[str, str]:
    done: dict[str, str] = {}
    current_privileges = es.request("GET", "/_security/privilege/argus", ok=(200, 404))
    have = {
        name: sorted(p.get("actions", []))
        for name, p in (current_privileges or {}).get("argus", {}).items()
    }
    wanted = {name: sorted(p["actions"]) for name, p in ARGUS_PRIVILEGES["argus"].items()}
    if have != wanted:
        es.request("PUT", "/_security/privilege", ARGUS_PRIVILEGES)
        done["argus application privileges"] = "updated" if have else "created"
    else:
        done["argus application privileges"] = "kept"
    for name, body in KIBANA_ROLES.items():
        current = kibana.request("GET", f"/api/security/role/{name}", ok=(200, 404))
        exists = isinstance(current, dict) and current.get("name") == name
        if exists and kibana_role_matches(current, body):
            done[name] = "kept"
            continue
        kibana.request("PUT", f"/api/security/role/{name}", body, ok=(200, 204))
        done[name] = "updated" if exists else "created"
    for name, body in es_roles().items():
        current = es.request("GET", f"/_security/role/{name}", ok=(200, 404))
        exists = isinstance(current, dict) and name in current
        if exists and es_role_matches(current[name], body):
            done[name] = "kept"
            continue
        es.request("PUT", f"/_security/role/{name}", body)
        done[name] = "updated" if exists else "created"
    return done


def ensure_users(es: Any, passwords: Mapping[str, str]) -> dict[str, str]:
    done: dict[str, str] = {}
    for name, (_kind, roles, enabled) in USERS.items():
        state = user_state(es, name)
        body = user_body(name, roles, passwords[name])
        same = (
            state is not None
            and all(state.get(k) == body[k] for k in ("roles", "full_name", "email", "metadata"))
            and state.get("enabled") is enabled
            # a disabled user cannot prove its password; it is re-set whenever it is updated
            and (not enabled or authenticates(es, name, passwords[name]))
        )
        if same:
            done[name] = "kept"
            continue
        es.request("PUT", f"/_security/user/{name}", body)
        if not enabled:
            es.request("PUT", f"/_security/user/{name}/_disable")
        done[name] = "created" if state is None else "updated"
    return done


def spec_hash(spec: Mapping[str, Any]) -> str:
    """A key's wanted body, hashed: a changed body makes the seed mint the key again."""
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]


def grant_key(
    es: Any, minter: tuple[str, str], owner: tuple[str, str], name: str, spec: Mapping[str, Any]
) -> dict[str, Any]:
    """Mint a key for ``owner`` (name, password) as ``minter`` through the grant API."""
    body = {
        "grant_type": "password",
        "username": owner[0],
        "password": owner[1],
        "api_key": {"name": name, **spec},
    }
    created: dict[str, Any] = es.as_user(*minter).request("POST", "/_security/api_key/grant", body)
    return created


def ensure_keys(
    es: Any, data: dict[str, Any], save: Callable[[], None], log: Log
) -> dict[str, Any]:
    """Mint `argus`'s missing keys; keep each key whose encoded value the tier still holds."""
    stored: dict[str, Any] = data.setdefault("api_keys", {})
    valid = valid_keys(es)
    wanted = api_keys()

    def held(name: str) -> bool:
        """The tier still holds this key's encoded value, and it was minted as wanted now."""
        return (
            name in stored
            and stored[name].get("spec") == spec_hash(wanted[name])
            and any(k["id"] == stored[name]["id"] for k in valid.get(name, []))
        )

    missing = [name for name in wanted if not held(name)]
    done: dict[str, Any] = {name: "kept" for name in wanted if name not in missing}
    # keys of a seeded name the tier holds no encoded value for: a concurrent seed's, or an
    # earlier one's; nobody can use them, so they are invalidated (review F8)
    surplus = [
        k["id"]
        for name in wanted
        if name not in missing
        for k in valid.get(name, [])
        if k["id"] != stored[name]["id"]
    ]
    if surplus:
        es.request("DELETE", "/_security/api_key", {"ids": surplus})
        done["surplus keys invalidated"] = len(surplus)
        log(f"{len(surplus)} surplus key(s) of {ARGUS_USER} invalidated")
    password = data["passwords"][ARGUS_USER]
    try:
        if missing:
            # widened for the mint, with its password set so that the grant can use it (DQ3 (a))
            es.request(
                "PUT",
                f"/_security/user/{ARGUS_USER}",
                user_body(ARGUS_USER, ARGUS_MINT_ROLES, password),
            )
            minter = (KEY_MINTER, data["passwords"][KEY_MINTER])
            for name in missing:
                stale = [k["id"] for k in valid.get(name, [])]
                if stale:  # a key the tier holds no encoded value for: useless, so invalidated
                    es.request("DELETE", "/_security/api_key", {"ids": stale})
                created = grant_key(es, minter, (ARGUS_USER, password), name, wanted[name])
                stored[name] = {
                    "id": created["id"],
                    "encoded": created["encoded"],
                    "spec": spec_hash(wanted[name]),
                }
                save()
                done[name] = "re-minted" if stale else "minted"
                log(f"key {name} minted for {ARGUS_USER} by {KEY_MINTER}")
    finally:  # narrowed and disabled again even when a mint fails half-way
        _rest_argus(es, password, widened=bool(missing))
    done["argus user"] = "narrowed and disabled"
    return done


def _rest_argus(es: Any, password: str, *, widened: bool) -> None:
    """`argus` between mints (DQ3 (a)): only the reader's role, and disabled."""
    resting = user_body(ARGUS_USER, ARGUS_RESTING_ROLES, password)
    state = user_state(es, ARGUS_USER)
    if (
        widened
        or state is None
        or state.get("roles") != ARGUS_RESTING_ROLES
        or state.get("metadata") != resting["metadata"]
    ):
        es.request("PUT", f"/_security/user/{ARGUS_USER}", resting)  # narrowed after the mint
        state = user_state(es, ARGUS_USER)
    if state is not None and state.get("enabled"):
        es.request("PUT", f"/_security/user/{ARGUS_USER}/_disable")  # disabled between mints


EVENT_MAPPING = {
    "dynamic": "strict",
    "properties": {
        "@timestamp": {"type": "date"},
        "message": {"type": "text"},
        "event": {
            "properties": {
                "kind": {"type": "keyword"},
                "category": {"type": "keyword"},
                "outcome": {"type": "keyword"},
            }
        },
        "source": {"properties": {"ip": {"type": "ip"}}},
        "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "url": {"properties": {"path": {"type": "keyword"}}},
        "tier": {"properties": {"run": {"type": "keyword"}, "n": {"type": "long"}}},
    },
}


def ensure_events_index(es: Any) -> str:
    es.send("HEAD", f"/{EVENTS_INDEX}")
    if es.last_status == 200:
        return "kept"
    es.request(
        "PUT",
        f"/{EVENTS_INDEX}",
        {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": EVENT_MAPPING,
        },
    )
    return "created"


def event(run: str, n: int, at: str) -> dict[str, Any]:
    """A synthetic source event (documentation addresses only: RFC 5737)."""
    return {
        "@timestamp": at,
        "message": f"tier event {n} of {run}",
        "event": {"kind": "event", "category": "network", "outcome": "success"},
        "source": {"ip": f"192.0.2.{10 + n % 3}"},
        "destination": {"ip": "198.51.100.7", "port": 443},
        "host": {"name": f"tier-host-{n % 3}"},
        "url": {"path": "/.env" if n % 2 else "/index.html"},
        "tier": {"run": run, "n": n},
    }


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def events_ndjson(run: str, count: int, *, now: datetime | None = None) -> str:
    """The bulk body for ``count`` events of ``run``: fixed ids, one second apart and in the
    past (so a rule's alerts sort by ``kibana.alert.original_time`` in event order)."""
    start = (now or datetime.now(UTC)) - timedelta(seconds=count + 5)
    lines = []
    for n in range(1, count + 1):
        lines.append(json.dumps({"create": {"_index": EVENTS_INDEX, "_id": f"{run}-{n:02d}"}}))
        lines.append(json.dumps(event(run, n, iso(start + timedelta(seconds=n)))))
    return "\n".join(lines) + "\n"


def index_events(es: Any, run: str, count: int) -> list[str]:
    """Index ``count`` events of ``run`` (refreshed); ids already there are kept."""
    lines = events_ndjson(run, count).splitlines()
    ids = [json.loads(line)["create"]["_id"] for line in lines[::2]]
    result = es.bulk("\n".join(lines) + "\n", refresh="true")
    for item in result["items"]:
        if item["create"]["status"] not in (201, 409):
            raise RuntimeError(f"indexing {item['create']['_id']}: {item['create']}")
    return ids


RUN_ID = re.compile(r"[A-Za-z0-9-]{1,80}")


def rule_body(rule_id: str, run: str, *, name: str, interval: str, lookback: str) -> dict[str, Any]:
    """A query rule over ``run``'s events. A run id is letters, digits and dashes only, so it
    can be put in the query as it is."""
    if not RUN_ID.fullmatch(run):
        raise ValueError(f"not a run id: {run!r}")
    return {
        "rule_id": rule_id,
        "name": name,
        "description": f"Alerts on the tier's synthetic events of {run} (ARGUS's Kibana tier).",
        "type": "query",
        "language": "kuery",
        "query": f'tier.run: "{run}"',
        "index": [EVENTS_INDEX],
        "interval": interval,
        "from": f"now-{lookback}",
        "to": "now",
        "severity": "medium",
        "risk_score": 47,
        "enabled": True,
        "tags": ["argus-tier"],
        "max_signals": 100,
    }


def ensure_rule(kibana: Any, body: Mapping[str, Any]) -> str:
    rules = f"/s/{SPACE}/api/detection_engine/rules"
    found = kibana.request("GET", rules, params={"rule_id": body["rule_id"]}, ok=(200, 404))
    if isinstance(found, dict) and found.get("rule_id") == body["rule_id"]:
        if found.get("enabled") and found.get("query") == body["query"]:
            return "kept"
        kibana.request("PUT", rules, dict(body))
        return "updated"
    kibana.request("POST", rules, dict(body))
    return "created"


def seed_alert_ids(es: Any, count: int) -> list[dict[str, str]]:
    hits = es.request(
        "POST",
        f"/{ALERTS_ALIAS}/_search",
        {
            "size": count,
            "query": {"term": {"kibana.alert.rule.rule_id": SEED_RULE_ID}},
            "sort": [{"kibana.alert.original_time": "asc"}, {"kibana.alert.uuid": "asc"}],
            "_source": False,
        },
    )["hits"]["hits"]
    return [{"id": hit["_id"], "index": hit["_index"]} for hit in hits]


def ensure_cases(es: Any, kibana: Any, data: Mapping[str, Any]) -> dict[str, str]:
    """A person's case (Sync alerts on, two alerts) and an ARGUS case (Sync alerts off).

    The person is an analyst: with Sync alerts on, attaching an alert also sets its status as
    the caller, which a case manager without write on the alerts indices cannot do (a 500
    after the attachment and its case id are saved: tests/kibana pins it)."""
    done: dict[str, str] = {}
    base = f"/s/{SPACE}/api/cases"
    person = kibana.as_user("tier-analyst", data["passwords"]["tier-analyst"])
    argus = kibana.as_key(data["api_keys"]["argus-cases-writer"]["encoded"])
    plans: dict[str, tuple[Any, dict[str, Any]]] = {
        "tier-seed:person": (
            person,
            {
                "title": "Tier seed: a person's case",
                "description": "Made by a person in Kibana, with Sync alerts on as the UI does.",
                "tags": ["tier-seed", "tier-seed:person"],
                "settings": {"syncAlerts": True},
            },
        ),
        "tier-seed:argus": (
            argus,
            {
                "title": "[ARGUS 0] Tier seed: ARGUS's case",
                "description": "Made with ARGUS's cases writer key, Sync alerts off.",
                "tags": [
                    "argus",
                    f"argus:case:{uuid.uuid5(UID_NAMESPACE, 'seed-case')}",
                    "argus:owner:argus",
                    "argus:state:open",
                    "tier-seed",
                    "tier-seed:argus",
                ],
                "settings": {"syncAlerts": False},
            },
        ),
    }
    for tag, (client, body) in plans.items():
        found = kibana.request("GET", f"{base}/_find", params={"tags": tag, "perPage": 10})
        if found["total"]:
            case = found["cases"][0]
            done[tag] = "kept"
        else:
            case = client.request(
                "POST",
                base,
                {**body, "owner": OWNER, "severity": "low", "connector": NO_CONNECTOR},
            )
            done[tag] = "created"
        if tag == "tier-seed:person":
            attached = {
                a["id"]
                for a in kibana.request("GET", f"{base}/{case['id']}/alerts", ok=(200,)) or []
            }
            for alert in seed_alert_ids(es, 2):
                if alert["id"] in attached:
                    continue
                client.request(
                    "POST",
                    f"{base}/{case['id']}/comments",
                    {
                        "type": "alert",
                        "alertId": alert["id"],
                        "index": alert["index"],
                        "rule": {"id": None, "name": None},
                        "owner": OWNER,
                    },
                )
                done[tag] = "updated" if done[tag] == "kept" else done[tag]
        elif not case.get("totalComment"):
            client.request(
                "POST",
                f"{base}/{case['id']}/comments",
                {"type": "user", "comment": "Opened by ARGUS (tier seed).", "owner": OWNER},
            )
            done[tag] = "updated" if done[tag] == "kept" else done[tag]
    return done


def seed(
    data: dict[str, Any], es: Any, kibana: Any, *, log: Log, save: Callable[[], None]
) -> dict[str, Any]:
    """Make the tier hold what the module docstring says; report what changed."""
    report: dict[str, Any] = {"space": ensure_space(kibana)}
    report["roles"] = ensure_roles(es, kibana)
    report["users"] = ensure_users(es, data["passwords"])
    report["keys"] = ensure_keys(es, data, save, log)
    report["events_index"] = ensure_events_index(es)
    index_events(es, SEED_RUN, SEED_EVENTS)
    report["rule"] = ensure_rule(
        kibana,
        rule_body(
            SEED_RULE_ID, SEED_RUN, name="ARGUS tier: seeded events", interval="1h", lookback="30d"
        ),
    )
    report["alerts"] = wait_alerts(es, SEED_RULE_ID, SEED_EVENTS)
    if report["alerts"] < SEED_EVENTS:
        raise RuntimeError(f"the seed rule wrote {report['alerts']} of {SEED_EVENTS} alerts")
    report["cases"] = ensure_cases(es, kibana, data)
    return report


def summary(es: Any, kibana: Any) -> dict[str, Any]:
    """What the seed made, as the tier holds it now."""
    space = kibana.request("GET", f"/api/spaces/space/{SPACE}", ok=(200, 404))
    users = {}
    for name in usernames():
        state = user_state(es, name)
        users[name] = None if state is None else ("enabled" if state.get("enabled") else "disabled")
    return {
        "space": isinstance(space, dict) and space.get("id") == SPACE,
        "users": users,
        "argus_keys": sorted(valid_keys(es)),
        "seed_alerts": count_alerts(es, SEED_RULE_ID),
    }
