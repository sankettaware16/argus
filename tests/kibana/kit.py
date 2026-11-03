"""Building blocks of the Kibana contract tests: per-run cases, alerts, users and keys, all made
through the recorded clients (so replay gets them from the cassette), and the session's
clean-up of everything a run made (live only, unrecorded)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tests.kibana.tier import ALERTS_ALIAS, Reply, S, Tier, seed

OWNER = seed.OWNER
NO_CONNECTOR = seed.NO_CONNECTOR
RULE_PREFIX = "argus-tier-run-"


def test_key(kt: Tier) -> str:
    """Six hex characters naming the current test, the same in every run."""
    assert kt.recorder is not None
    return hashlib.sha256(kt.recorder.name.encode()).hexdigest()[:6]


def run_tag(kt: Tier) -> str:
    """The tag of this test's cases in this run: finds by it see nothing of other tests."""
    return f"t:{kt.run}-{test_key(kt)}"


def session_tag(tier: Tier) -> str:
    """The tag of every case of this run (the clean-up finds them by it)."""
    return f"run:{tier.run}"


def case_body(
    kt: Tier, title: str, *, tags: list[str] | None = None, sync: bool = False, **extra: Any
) -> dict[str, Any]:
    """A case as ARGUS would send it (connector none, Sync alerts off unless asked), tagged
    with the run so that finds see only this run's cases."""
    return {
        "title": title,
        "description": f"Contract test case ({title}).",
        "tags": [session_tag(kt), run_tag(kt), *(tags or [])],
        "owner": OWNER,
        "severity": "low",
        "connector": NO_CONNECTOR,
        "settings": {"syncAlerts": sync},
        **extra,
    }


def create_case(kt: Tier, principal: str, title: str, **kw: Any) -> Reply:
    return kt.kibana(principal).post(f"{S}/api/cases", case_body(kt, title, **kw))


def case(kt: Tier, case_id: str) -> dict[str, Any]:
    reply = kt.kibana("elastic").get(f"{S}/api/cases/{case_id}")
    assert reply.status == 200, reply.body
    body: dict[str, Any] = reply.body
    return body


def patch_case(kt: Tier, principal: str, case_id: str, version: str, **fields: Any) -> Reply:
    return kt.kibana(principal).patch(
        f"{S}/api/cases", {"cases": [{"id": case_id, "version": version, **fields}]}
    )


def alert_attachment(alert: dict[str, str]) -> dict[str, Any]:
    return {
        "type": "alert",
        "alertId": alert["id"],
        "index": alert["index"],
        "rule": {"id": None, "name": None},
        "owner": OWNER,
    }


def attach(kt: Tier, principal: str, case_id: str, alert: dict[str, str]) -> Reply:
    return kt.kibana(principal).post(
        f"{S}/api/cases/{case_id}/comments", alert_attachment(alert), keep=case_summary
    )


def case_summary(body: Any) -> Any:
    """The parts of a case answer the tests read (the rest would only fatten cassettes)."""
    if isinstance(body, list):
        return [case_summary(b) for b in body]
    if not isinstance(body, dict):
        return body
    keys = (
        "id",
        "version",
        "status",
        "title",
        "tags",
        "settings",
        "totalComment",
        "totalAlerts",
        "created_by",
        "updated_by",
        "closed_by",
        "owner",
        "severity",
    )
    return {k: body[k] for k in keys if k in body}


def make_alerts(kt: Tier, label: str, count: int) -> list[dict[str, str]]:
    """``count`` fresh alerts of this run: synthetic events, a rule of the run that turns them
    into alerts in the space (its first run starts at once), and the alerts in event order."""
    # unique per test, the same in every run: the events' ids and the rule's id carry it
    run = f"{kt.run}-{test_key(kt)}-{label}"
    rule_id = f"{RULE_PREFIX}{run}"
    es = kt.es("elastic")
    reply = es.call(
        "POST",
        "/_bulk",
        params={"refresh": "true"},
        ndjson=seed.events_ndjson(run, count),
        keep=lambda b: {"errors": b["errors"], "n": len(b["items"])},
    )
    assert reply.status == 200, reply.body
    assert reply.body == {"errors": False, "n": count}, reply.body
    rule = kt.kibana("elastic").post(
        f"{S}/api/detection_engine/rules",
        seed.rule_body(rule_id, run, name=f"ARGUS tier run {label}", interval="1h", lookback="1h"),
        keep=lambda b: {k: b[k] for k in ("rule_id", "enabled", "type")},
    )
    assert rule.status == 200, rule.body
    kt.made_rules.append(rule_id)
    if kt.live:
        admin = kt.admin("es")
        try:
            kt.wait(
                f"{count} alerts of {rule_id}", lambda: seed.count_alerts(admin, rule_id) >= count
            )
        finally:
            admin.close()
    hits = es.post(
        f"/{ALERTS_ALIAS}/_search",
        {
            "size": count,
            "query": {"term": {"kibana.alert.rule.rule_id": rule_id}},
            "sort": [{"kibana.alert.original_time": "asc"}],
            "_source": ["kibana.alert.workflow_status"],
        },
        keep=lambda b: [{"_id": h["_id"], "_index": h["_index"]} for h in b["hits"]["hits"]],
    )
    assert hits.status == 200, hits.body
    assert len(hits.body) == count, hits.body
    return [{"id": h["_id"], "index": h["_index"]} for h in hits.body]


def alert_state(kt: Tier, alert: dict[str, str], *fields: str) -> dict[str, Any]:
    """The alert's ``fields`` as stored (absent ones are left out)."""
    wanted = fields or (
        "kibana.alert.workflow_status",
        "kibana.alert.case_ids",
        "kibana.alert.workflow_user",
        "kibana.alert.workflow_status_updated_at",
    )
    reply = kt.es("elastic").get(
        f"/{alert['index']}/_doc/{alert['id']}",
        params={"_source_includes": ",".join(wanted)},
        keep=lambda b: b["_source"],
    )
    assert reply.status == 200, reply.body
    body: dict[str, Any] = reply.body
    return body


def make_user(kt: Tier, suffix: str, roles: list[str], **extra: Any) -> str:
    """A user of this run (t-<run>-<suffix>) with a fresh password; returns its principal."""
    password = kt.password()
    name = kt.name(suffix)
    reply = kt.es("elastic").put(
        f"/_security/user/{name}",
        {
            "password": password,
            "roles": roles,
            "full_name": f"Run {suffix}",
            "email": f"{suffix}@run.argus.invalid",
            **extra,
        },
    )
    assert reply.status == 200, reply.body
    return kt.add_run_user(suffix, password)


def make_kibana_role(kt: Tier, suffix: str, body: dict[str, Any]) -> str:
    name = kt.name(suffix)
    reply = kt.kibana("elastic").put(f"/api/security/role/{name}", body)
    assert reply.status == 204, reply.body
    return name


def make_es_role(kt: Tier, suffix: str, body: dict[str, Any]) -> str:
    name = kt.name(suffix)
    reply = kt.es("elastic").put(f"/_security/role/{name}", body)
    assert reply.status == 200, reply.body
    return name


def grant_key(
    kt: Tier,
    owner_suffix: str,
    password_principal: str,
    key_suffix: str,
    descriptors: dict[str, Any],
    *,
    minter: str = seed.KEY_MINTER,
) -> tuple[str, Reply]:
    """Mint a key for the run user ``owner_suffix`` as the seeded ELK admin through the grant
    API (DQ3 (a)); returns its principal and the answer (id and name kept, secrets never)."""
    password = _run_password(kt, password_principal)
    reply = kt.es(f"user:{minter}").post(
        "/_security/api_key/grant",
        {
            "grant_type": "password",
            "username": kt.name(owner_suffix),
            "password": password,
            "api_key": {
                "name": kt.name(key_suffix),
                "expiration": "1h",
                "role_descriptors": descriptors,
            },
        },
    )
    if reply.status != 200:
        return "", reply
    return kt.add_run_key(key_suffix, reply.body["encoded"]), reply


def _run_password(kt: Tier, principal: str) -> str:
    """The password behind a run user's principal (live) or a stand-in (replay)."""
    if not kt.live:
        return "replay-secret"
    authorization = kt.run_credentials[principal]
    import base64

    return base64.b64decode(authorization.split(" ", 1)[1]).decode().split(":", 1)[1]


def find_run_cases(kt: Tier, principal: str, **params: Any) -> Reply:
    return kt.kibana(principal).get(
        f"{S}/api/cases/_find",
        params={
            "tags": run_tag(kt),
            "sortField": "title",
            "sortOrder": "asc",
            "perPage": 100,
            **params,
        },
        keep=lambda b: {
            **{k: b[k] for k in b if k != "cases"},
            "cases": [case_summary(c) for c in b["cases"]],
        },
    )


# --------------------------------------------------------------------------- clean-up


def register_cleanup(tier: Tier) -> None:
    """At the session's end (live), remove what this run made: rules first (they stop writing
    alerts), then cases, keys, users and roles named after the run."""

    def cleanup() -> None:
        kibana = tier.admin("kibana")
        es = tier.admin("es")
        try:
            for rule_id in tier.made_rules:
                kibana.request(
                    "DELETE",
                    f"{S}/api/detection_engine/rules",
                    params={"rule_id": rule_id},
                    ok=(200, 404),
                )
            for _ in range(100):  # bounded: a delete that does not take never spins forever
                found = kibana.request(
                    "GET",
                    f"{S}/api/cases/_find",
                    params={"tags": session_tag(tier), "perPage": 100},
                )
                ids = [c["id"] for c in found["cases"]]
                if not ids:
                    break
                kibana.request(
                    "DELETE", f"{S}/api/cases", params={"ids": json.dumps(ids)}, ok=(204,)
                )
            prefix = f"t-{tier.run}-"
            users = es.request("GET", "/_security/user")
            for name in users:
                if name.startswith(prefix):
                    es.request("DELETE", "/_security/api_key", {"username": name}, ok=(200, 404))
                    es.request("DELETE", f"/_security/user/{name}", ok=(200, 404))
            roles = es.request("GET", "/_security/role")
            for name in roles:
                if name.startswith(prefix):
                    es.request("DELETE", f"/_security/role/{name}", ok=(200, 404))
        finally:
            kibana.close()
            es.close()

    tier.on_finish(cleanup)
