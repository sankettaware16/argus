"""§12 #11 and #12: attaching alerts, and what "Sync alerts" does to them.

#11 An attach makes Kibana's internal user write the case's id into the alert's
``kibana.alert.case_ids`` (the caller may have no privilege on the alerts indices at all). An
alert holds at most 10 cases: the 11th attach answers 400, yet the attachment is saved, so the
case lists the alert while the alert does not list the case (half-applied).

An "alert" attachment of a document that is no alert, or of an id the alerts index does not
hold (review F10), answers 200: the case lists it among its alerts, and no case id is written
anywhere. A 200 to an attach is therefore not
"case_ids written": Q-D4 reads the alert back.

#12 With Sync alerts on, the case's status is pushed into its alerts *as the caller*: a person
switching it on rewrites the alerts at once; ARGUS's writer key (no write on the alerts indices)
then gets a 500 for a status change that Kibana has already saved, without a user action for it
(half-applied, invisible to a reconciliation built on user actions alone); an attach by a
caller without that write fails the same way after saving the attachment and the case id.
"""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import S, Tier, seed

WRITER = "key:argus-cases-writer"
SCOPED = "key:argus-cases-writer-actions"  # the body planned for the SIEM (DQ3 (a))
FIRST_ALERTS_INDEX = ".internal.alerts-security.alerts-acme-soc-000001"
PERSON = "user:tier-analyst"  # Security All + Cases All + write on the alerts indices
MANAGER = "user:tier-manager"  # Cases All + Security Read: no write on the alerts indices


def _listed(kt: Tier, case_id: str) -> list[str]:
    reply = kt.kibana("elastic").get(
        f"{S}/api/cases/{case_id}/alerts", keep=lambda b: [a["id"] for a in b]
    )
    assert reply.status == 200
    listed: list[str] = reply.body
    return listed


def _actions(kt: Tier, case_id: str) -> list[list[str]]:
    reply = kt.kibana("elastic").get(
        f"{S}/api/cases/{case_id}/user_actions/_find",
        params={"perPage": 100, "sortOrder": "asc"},
        keep=lambda b: [
            [a["type"], a["action"], a["created_by"]["username"]] for a in b["userActions"]
        ],
    )
    actions: list[list[str]] = reply.body
    return actions


def test_an_alert_holds_ten_cases_and_the_eleventh_attach_half_fails(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "ten", 1)[0]
    cases = [kit.create_case(kt, WRITER, f"ten {i:02d}").body["id"] for i in range(11)]
    answers = [kit.attach(kt, WRITER, case_id, alert) for case_id in cases]
    assert [a.status for a in answers] == [200] * 10 + [400]
    assert answers[10].body["message"] == "You cannot attach more than 10 cases to an alert"
    assert kit.alert_state(kt, alert, "kibana.alert.case_ids") == {
        "kibana.alert.case_ids": cases[:10]
    }
    assert _listed(kt, cases[10]) == [alert["id"]]  # saved anyway


def test_attaching_writes_case_ids_as_kibanas_internal_user(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "internal", 1)[0]
    # the writer key cannot write the alert itself ...
    direct = kt.es(WRITER).post(
        f"/{alert['index']}/_update/{alert['id']}",
        {"doc": {"kibana.alert.case_ids": ["forged"]}},
    )
    assert direct.status == 403
    # ... yet attaching writes the case id into it
    case_id = kit.create_case(kt, WRITER, "internal user").body["id"]
    assert kit.attach(kt, WRITER, case_id, alert).status == 200
    assert kit.alert_state(kt, alert) == {
        "kibana.alert.workflow_status": "open",
        "kibana.alert.case_ids": [case_id],
    }


def test_sync_on_rewrites_alerts_and_half_applies_argus_status_changes(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "sync", 1)[0]
    case: dict[str, Any] = kit.create_case(kt, WRITER, "sync").body
    assert kit.attach(kt, WRITER, case["id"], alert).status == 200

    current = kit.case(kt, case["id"])
    taken = kit.patch_case(kt, WRITER, case["id"], current["version"], status="in-progress")
    assert taken.status == 200
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "open"
    }  # Sync alerts off: the alert is left alone

    current = kit.case(kt, case["id"])
    switched = kit.patch_case(
        kt, PERSON, case["id"], current["version"], settings={"syncAlerts": True}
    )
    assert switched.status == 200
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "acknowledged"
    }  # switching it on pushed in-progress into the alert at once

    current = kit.case(kt, case["id"])
    closing = kit.patch_case(kt, WRITER, case["id"], current["version"], status="closed")
    assert closing.status == 500
    assert "indices:data/write/update/byquery" in closing.body["message"]
    assert kit.case(kt, case["id"])["status"] == "closed"  # saved despite the 500
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "acknowledged"
    }
    assert _actions(kt, case["id"]) == [
        ["create_case", "create", "argus"],
        ["comment", "create", "argus"],
        ["status", "update", "argus"],
        ["settings", "update", "tier-analyst"],
    ]  # no user action for the close

    late = kit.attach(kt, WRITER, case["id"], kit.make_alerts(kt, "sync-late", 1)[0])
    assert (late.status, late.body["message"]) == (400, "Alert cannot be attached to a closed case")

    current = kit.case(kt, case["id"])
    reopened = kit.patch_case(kt, PERSON, case["id"], current["version"], status="open")
    assert reopened.status == 200
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "open"
    }


def test_sync_on_attach_without_alert_write_half_fails(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "sync-attach", 1)[0]
    case: dict[str, Any] = kit.create_case(kt, MANAGER, "a person's synced case", sync=True).body
    attached = kit.attach(kt, MANAGER, case["id"], alert)
    assert attached.status == 500
    assert "indices:data/write/update/byquery" in attached.body["message"]
    assert _listed(kt, case["id"]) == [alert["id"]]
    assert kit.alert_state(kt, alert) == {
        "kibana.alert.workflow_status": "open",
        "kibana.alert.case_ids": [case["id"]],
    }  # attachment and case id saved; the status push failed

    by_argus = kit.attach(kt, WRITER, case["id"], kit.make_alerts(kt, "sync-attach-argus", 1)[0])
    assert by_argus.status == 500  # ARGUS's writer key fails the same way


def test_an_alert_attachment_of_what_is_no_alert(kt: Tier) -> None:
    run = f"{kt.run}-{kit.test_key(kt)}-noalert"
    indexed = kt.es("elastic").call(
        "POST",
        "/_bulk",
        params={"refresh": "true"},
        ndjson=seed.events_ndjson(run, 1),
        keep=lambda b: {"errors": b["errors"], "n": len(b["items"])},
    )
    assert indexed.body == {"errors": False, "n": 1}
    event = {"id": f"{run}-01", "index": seed.EVENTS_INDEX}
    case_id = kit.create_case(kt, SCOPED, "not an alert").body["id"]

    on_event = kit.attach(kt, SCOPED, case_id, event)
    assert on_event.status == 200
    assert _listed(kt, case_id) == [event["id"]]  # listed as one of the case's alerts
    written = kt.es("elastic").get(
        f"/{seed.EVENTS_INDEX}/_doc/{event['id']}",
        params={"_source_includes": "kibana.alert.case_ids"},
        keep=lambda b: b["_source"],
    )
    assert (written.status, written.body) == (200, {})  # no case id on the event

    unknown = {"id": "0" * 64, "index": FIRST_ALERTS_INDEX}  # no such alert
    on_unknown = kit.attach(kt, SCOPED, case_id, unknown)
    looked_up = kt.es("elastic").get(
        f"/{FIRST_ALERTS_INDEX}/_doc/{unknown['id']}", keep=lambda b: b.get("found")
    )
    assert looked_up.status == 404  # nothing made in the alerts index
    assert (on_unknown.status, on_unknown.body["totalAlerts"]) == (200, 2)  # taken all the same
    assert _listed(kt, case_id) == [event["id"], unknown["id"]]
