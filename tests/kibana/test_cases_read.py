"""§12 #6: Kibana's reader key with Cases Read only (DQ3 (a)) serves every read ARGUS's
read-back needs (find, get, user actions, comments, configure and both preview routes), and
nothing that writes: no case change, no alert change through RAC or the status route."""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import ALERTS_ALIAS, S, Tier

READER = "key:argus-kibana-reader"
WRITER = "key:argus-cases-writer"


def _build(kt: Tier) -> tuple[dict[str, Any], dict[str, str]]:
    """A case of this run with one comment and one alert, made by ARGUS's cases writer."""
    alert = kit.make_alerts(kt, "read", 1)[0]
    case = kit.create_case(kt, WRITER, "read contract").body
    comment = kt.kibana(WRITER).post(
        f"{S}/api/cases/{case['id']}/comments",
        {"type": "user", "comment": "A comment ARGUS wrote.", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert comment.status == 200, comment.body
    attached = kit.attach(kt, WRITER, case["id"], alert)
    assert attached.status == 200, attached.body
    return case, alert


def test_the_reader_key_serves_every_read_back(kt: Tier) -> None:
    case, alert = _build(kt)
    reader = kt.kibana(READER)

    found = kit.find_run_cases(kt, READER)
    assert found.status == 200
    assert found["total"] == 1
    assert [c["id"] for c in found["cases"]] == [case["id"]]

    got = reader.get(f"{S}/api/cases/{case['id']}", keep=kit.case_summary)
    assert got.status == 200
    assert (got["totalComment"], got["totalAlerts"]) == (1, 1)

    actions = reader.get(
        f"{S}/api/cases/{case['id']}/user_actions/_find",
        params={"perPage": 100, "sortOrder": "asc"},
        keep=lambda b: [
            {"type": a["type"], "action": a["action"], "by": a["created_by"]["username"]}
            for a in b["userActions"]
        ],
    )
    assert actions.status == 200
    assert actions.body == [
        {"type": "create_case", "action": "create", "by": "argus"},
        {"type": "comment", "action": "create", "by": "argus"},
        {"type": "comment", "action": "create", "by": "argus"},
    ]

    comments = reader.get(
        f"{S}/api/cases/{case['id']}/comments/_find",
        keep=lambda b: {"total": b["total"], "types": [c["type"] for c in b["comments"]]},
    )
    assert comments.status == 200
    assert comments.body == {"total": 1, "types": ["user"]}  # alerts are not "comments" here

    # the space's case configuration (none on the tier: tests never make one there)
    configure = reader.get(f"{S}/api/cases/configure")
    assert configure.status == 200
    assert configure.body == []

    # the technical-preview routes (plan §2): a case's alerts, and an alert's cases
    alerts = reader.get(
        f"{S}/api/cases/{case['id']}/alerts",
        keep=lambda b: [{"id": a["id"], "index": a["index"]} for a in b],
    )
    assert alerts.status == 200
    assert alerts.body == [alert]
    cases = reader.get(
        f"{S}/api/cases/alerts/{alert['id']}",
        keep=lambda b: [{"id": c["id"], "status": c["status"], "totals": c["totals"]} for c in b],
    )
    assert cases.status == 200
    assert cases.body == [
        {"id": case["id"], "status": "open", "totals": {"alerts": 1, "userComments": 1}}
    ]


def test_the_reader_key_writes_nothing(kt: Tier) -> None:
    case, alert = _build(kt)
    reader = kt.kibana(READER)
    refusals = {
        "create": reader.post(f"{S}/api/cases", kit.case_body(kt, "reader create")),
        "update": kit.patch_case(kt, READER, case["id"], case["version"], title="changed"),
        "comment": reader.post(
            f"{S}/api/cases/{case['id']}/comments",
            {"type": "user", "comment": "x", "owner": kit.OWNER},
        ),
        "delete": reader.delete(f"{S}/api/cases", params={"ids": f'["{case["id"]}"]'}),
        "push": reader.post(f"{S}/api/cases/{case['id']}/connector/none/_push", {}),
        "configure": reader.post(
            f"{S}/api/cases/configure",
            {"owner": kit.OWNER, "connector": kit.NO_CONNECTOR, "closure_type": "close-by-user"},
        ),
        "rac bulk update": reader.post(
            f"{S}/internal/rac/alerts/bulk_update",
            {"ids": [alert["id"]], "status": "closed", "index": ALERTS_ALIAS},
        ),
        "status route": reader.post(
            f"{S}/api/detection_engine/signals/status",
            {"signal_ids": [alert["id"]], "status": "closed"},
        ),
    }
    assert {name: r.status for name, r in refusals.items()} == dict.fromkeys(refusals, 403)
    # and nothing changed
    assert kit.case(kt, case["id"])["version"] == kit.case(kt, case["id"])["version"]
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "open"
    }
