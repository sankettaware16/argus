"""§12 #8: a key limited to named Kibana actions works without ``api:rac`` (DQ3 (a)'s preferred
cases writer). It must hold ``login:`` (the space is checked first) and, to attach alerts, the
"get" of Security's alerts; with those it creates, updates, comments on, attaches to, closes
and reopens cases, and it cannot delete, push, write the configuration, assign, or change an
alert's status by any route. Without the alert "get", an attach half-fails: the attachment is
saved, the alert's ``case_ids`` is not, and the answer is a 403."""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import ALERTS_ALIAS, S, Tier, seed

CASE_ACTIONS = [a for a in seed.CASES_WRITER_ACTIONS if a.startswith("cases:")]
ALERT_GETS = [a for a in seed.CASES_WRITER_ACTIONS if a.startswith("alerting:")]


def scoped_key(kt: Tier, suffix: str, actions: list[str]) -> str:
    """A key of a run user holding Cases All + Security Read, limited to ``actions``."""
    role = kit.make_kibana_role(kt, f"{suffix}-r", seed.KIBANA_ROLES["argus_cases_writer"])
    owner = kit.make_user(kt, f"{suffix}-o", [role])
    principal, reply = kit.grant_key(
        kt, f"{suffix}-o", owner, suffix, {"scoped": seed.app_descriptor(actions)}
    )
    assert reply.status == 200, reply.body
    return principal


def test_the_scoped_key_does_what_argus_needs(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "scoped", 1)[0]
    key = scoped_key(kt, "scoped", seed.CASES_WRITER_ACTIONS)
    created = kit.create_case(kt, key, "scoped writer")
    assert created.status == 200, created.body
    case: dict[str, Any] = created.body
    assert case["created_by"]["username"] == kt.name("scoped-o")  # the key's owner

    found = kit.find_run_cases(kt, key)
    assert (found.status, found["total"]) == (200, 1)
    tagged = kit.patch_case(kt, key, case["id"], case["version"], tags=[*case["tags"], "argus"])
    assert tagged.status == 200
    comment = kt.kibana(key).post(
        f"{S}/api/cases/{case['id']}/comments",
        {"type": "user", "comment": "ARGUS's comment.", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert comment.status == 200
    attached = kit.attach(kt, key, case["id"], alert)
    assert attached.status == 200
    assert kit.alert_state(kt, alert, "kibana.alert.case_ids") == {
        "kibana.alert.case_ids": [case["id"]]
    }  # written by Kibana's internal user: the key has no privilege on the alerts indices

    current = kit.case(kt, case["id"])
    closed = kit.patch_case(kt, key, case["id"], current["version"], status="closed")
    assert (closed.status, closed.body[0]["status"]) == (200, "closed")
    current = kit.case(kt, case["id"])
    reopened = kit.patch_case(kt, key, case["id"], current["version"], status="open")
    assert (reopened.status, reopened.body[0]["status"]) == (200, "open")
    actions = kt.kibana(key).get(
        f"{S}/api/cases/{case['id']}/user_actions/_find",
        params={"perPage": 100, "sortOrder": "asc"},
        keep=lambda b: [(a["type"], a["action"]) for a in b["userActions"]],
    )
    assert actions.status == 200
    assert actions.body == [
        ["create_case", "create"],
        ["tags", "add"],
        ["comment", "create"],
        ["comment", "create"],
        ["status", "update"],
        ["status", "update"],
    ]


def test_the_scoped_key_holds_nothing_else(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "scoped-no", 1)[0]
    key = scoped_key(kt, "scopedno", seed.CASES_WRITER_ACTIONS)
    case: dict[str, Any] = kit.create_case(kt, key, "scoped refusals").body
    client = kt.kibana(key)
    refusals = {
        "delete": client.delete(f"{S}/api/cases", params={"ids": f'["{case["id"]}"]'}),
        "push": client.post(f"{S}/api/cases/{case['id']}/connector/none/_push", {}),
        "configure": client.post(
            f"{S}/api/cases/configure",
            {"owner": kit.OWNER, "connector": kit.NO_CONNECTOR, "closure_type": "close-by-user"},
        ),
        "assign": kit.patch_case(
            kt, key, case["id"], case["version"], assignees=[{"uid": "u_tier_assignee_0"}]
        ),
        "rac bulk update": client.post(
            f"{S}/internal/rac/alerts/bulk_update",
            {"ids": [alert["id"]], "status": "closed", "index": ALERTS_ALIAS},
        ),
        "status route": client.post(
            f"{S}/api/detection_engine/signals/status",
            {"signal_ids": [alert["id"]], "status": "closed"},
        ),
        "alerts search": client.post(
            f"{S}/api/detection_engine/signals/search", {"query": {"match_all": {}}, "size": 0}
        ),
    }
    assert {k: r.status for k, r in refusals.items()} == dict.fromkeys(refusals, 403)
    assert "Unauthorized to delete case" in refusals["delete"].body["message"]
    assert "Unauthorized to update case" in refusals["assign"].body["message"]
    assert kit.alert_state(kt, alert) == {"kibana.alert.workflow_status": "open"}


def test_without_login_the_space_refuses_the_key(kt: Tier) -> None:
    key = scoped_key(kt, "nologin", [*CASE_ACTIONS, *ALERT_GETS])
    refused = kit.create_case(kt, key, "no login")
    assert refused.status == 403
    assert refused.body["message"] == f"Unauthorized to get {seed.SPACE} space"


def test_without_the_alert_gets_an_attach_half_fails(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "noget", 1)[0]
    key = scoped_key(kt, "noget", ["login:", *CASE_ACTIONS])
    case: dict[str, Any] = kit.create_case(kt, key, "no alert get").body
    attached = kit.attach(kt, key, case["id"], alert)
    assert attached.status == 403
    assert attached.body["message"] == 'Unauthorized by "siem" to get "siem.queryRule" alert'
    # half-applied: the case lists the alert, the alert does not list the case
    listed = kt.kibana("elastic").get(
        f"{S}/api/cases/{case['id']}/alerts", keep=lambda b: [a["id"] for a in b]
    )
    assert listed.body == [alert["id"]]
    assert kit.alert_state(kt, alert, "kibana.alert.case_ids") == {}


def test_the_seeded_scoped_key_is_the_pinned_one(kt: Tier) -> None:
    """The tier's own `argus-cases-writer-actions` (owner `argus`, disabled and narrowed)."""
    alert = kit.make_alerts(kt, "seeded-scoped", 1)[0]
    key = "key:argus-cases-writer-actions"
    case: dict[str, Any] = kit.create_case(kt, key, "seeded scoped").body
    assert case["created_by"]["username"] == "argus"
    assert kit.attach(kt, key, case["id"], alert).status == 200
    rac = kt.kibana(key).post(
        f"{S}/internal/rac/alerts/bulk_update",
        {"ids": [alert["id"]], "status": "closed", "index": ALERTS_ALIAS},
    )
    assert rac.status == 403
    assert kit.alert_state(kt, alert) == {
        "kibana.alert.workflow_status": "open",
        "kibana.alert.case_ids": [case["id"]],
    }
