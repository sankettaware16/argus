"""§12 #7 and #18: who can change an alert's status, and what each way records.

* Security Read alone (no privilege on the alerts indices) closes an alert through Kibana's
  internal RAC route, which writes as Kibana's internal user and records neither who nor when
  (no ``workflow_user``, no ``workflow_status_updated_at``): the alarm of plan §7.1 ("an alert
  change ARGUS cannot explain") is the only trace. The public status route updates by query as
  the caller, so the same user is refused there.
* DQ3's fallback cases writer (Cases All + Security Read) holds ``api:rac`` too: the residual.
* The status route (R17's write path) answers with Elasticsearch's update_by_query body; it
  rewrites an alert that already has the status (``updated``, never ``noops``), and an id that
  does not exist gives ``total`` 0 with a 200.
"""

from __future__ import annotations

from tests.kibana import kit
from tests.kibana.tier import ALERTS_ALIAS, S, Tier, seed

RAC = f"{S}/internal/rac/alerts/bulk_update"
STATUS = f"{S}/api/detection_engine/signals/status"
UPDATE_BY_QUERY_KEYS = {
    "took",
    "timed_out",
    "total",
    "updated",
    "deleted",
    "batches",
    "version_conflicts",
    "noops",
    "retries",
    "throttled_millis",
    "requests_per_second",
    "throttled_until_millis",
    "failures",
}


def _rac_summary(body: dict[str, object]) -> dict[str, object]:
    items = body["items"]
    assert isinstance(items, list)
    return {
        "success": body["success"],
        "errors": body["errors"],
        "results": [item["update"]["result"] for item in items],
    }


def test_security_read_alone_closes_an_alert_through_rac(kt: Tier) -> None:
    alerts = kit.make_alerts(kt, "rac", 2)
    role = kit.make_kibana_role(kt, "secread", seed.kibana_role({seed.SECURITY: ["read"]}))
    who = kit.make_user(kt, "secread", [role])

    rac = kt.kibana(who).post(
        RAC,
        {"ids": [alerts[0]["id"]], "status": "closed", "index": ALERTS_ALIAS},
        keep=_rac_summary,
    )
    assert rac.status == 200
    assert rac.body == {"success": True, "errors": False, "results": ["updated"]}
    # closed, and nothing says by whom or when
    assert kit.alert_state(kt, alerts[0]) == {"kibana.alert.workflow_status": "closed"}

    public = kt.kibana(who).post(STATUS, {"signal_ids": [alerts[1]["id"]], "status": "closed"})
    assert public.status == 403
    assert "indices:data/write/update/byquery" in public.body["message"]
    assert kit.alert_state(kt, alerts[1]) == {"kibana.alert.workflow_status": "open"}


def test_the_fallback_cases_writer_can_change_alerts_through_rac(kt: Tier) -> None:
    """DQ3 (a)'s fallback writer key (Cases All + Security Read) is not alert-safe."""
    alert = kit.make_alerts(kt, "writer-rac", 1)[0]
    rac = kt.kibana("key:argus-cases-writer").post(
        RAC,
        {"ids": [alert["id"]], "status": "acknowledged", "index": ALERTS_ALIAS},
        keep=_rac_summary,
    )
    assert rac.status == 200
    assert rac.body["results"] == ["updated"]
    assert kit.alert_state(kt, alert) == {"kibana.alert.workflow_status": "acknowledged"}


def test_the_status_route_answers_with_the_update_by_query_body(kt: Tier) -> None:
    alerts = kit.make_alerts(kt, "status", 2)
    writer = kt.kibana("key:argus-alert-writer")

    first = writer.post(STATUS, {"signal_ids": [alerts[0]["id"]], "status": "closed"})
    assert first.status == 200
    assert set(first.body) == UPDATE_BY_QUERY_KEYS
    assert (first["total"], first["updated"], first["noops"]) == (1, 1, 0)
    assert (first["version_conflicts"], first["failures"], first["timed_out"]) == (0, [], False)
    state = kit.alert_state(kt, alerts[0])
    assert state["kibana.alert.workflow_status"] == "closed"
    assert state["kibana.alert.workflow_user"] is None  # a key has no user profile
    assert "kibana.alert.workflow_status_updated_at" in state

    again = writer.post(STATUS, {"signal_ids": [alerts[0]["id"]], "status": "closed"})
    assert (again.status, again["total"], again["updated"], again["noops"]) == (200, 1, 1, 0)

    missing = writer.post(STATUS, {"signal_ids": ["0" * 64], "status": "closed"})
    assert (missing.status, missing["total"], missing["updated"]) == (200, 0, 0)

    both = writer.post(STATUS, {"signal_ids": [a["id"] for a in alerts], "status": "acknowledged"})
    assert (both.status, both["total"], both["updated"]) == (200, 2, 2)
    assert [kit.alert_state(kt, a, "kibana.alert.workflow_status") for a in alerts] == [
        {"kibana.alert.workflow_status": "acknowledged"}
    ] * 2
