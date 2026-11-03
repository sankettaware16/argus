"""Whole answers of the writes ARGUS's classes will make (plan §7.1: W1 create, comment,
attach; W2 tags, severity, status, reopen; W3 close with reason tags then the comment; WA alert
status), sent with the keys DQ3 (a) plans: the action-scoped cases writer and the alert writer.
Kept whole as fixtures for Q-D2's strict body models, Q-D4's read-backs and Q-D5's parser.
"""

from __future__ import annotations

import uuid
from typing import Any

from tests.kibana import kit
from tests.kibana.tier import S, Tier

CASES = "key:argus-cases-writer-actions"
ALERTS = "key:argus-alert-writer"


def test_the_write_classes_whole(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "writes", 1)[0]
    argus_case = f"argus:case:{uuid.UUID(int=1)}"  # a fixed ARGUS case id: the same every run
    client = kt.kibana(CASES)

    created = client.post(
        f"{S}/api/cases",
        kit.case_body(
            kt,
            "[ARGUS 7] C2 beacon from 1 campus host",
            tags=["argus", argus_case, "argus:owner:argus", "argus:state:open"],
        ),
    )
    assert created.status == 200
    case: dict[str, Any] = created.body
    assert case["settings"] == {"syncAlerts": False}

    comment = client.post(
        f"{S}/api/cases/{case['id']}/comments",
        {
            "type": "user",
            "comment": "Opened by ARGUS: decisions are made in ARGUS.",
            "owner": kit.OWNER,
        },
    )
    assert comment.status == 200
    attached = client.post(f"{S}/api/cases/{case['id']}/comments", kit.alert_attachment(alert))
    assert attached.status == 200

    version = attached["version"]
    tagged = client.patch(
        f"{S}/api/cases",
        {
            "cases": [
                {
                    "id": case["id"],
                    "version": version,
                    "severity": "high",
                    "tags": [*case["tags"], "argus:owner:tier-analyst"],
                }
            ]
        },
    )
    assert tagged.status == 200
    taken = client.patch(
        f"{S}/api/cases",
        {
            "cases": [
                {"id": case["id"], "version": tagged.body[0]["version"], "status": "in-progress"}
            ]
        },
    )
    assert taken.status == 200

    closing_tags = [
        t for t in tagged.body[0]["tags"] if not t.startswith(("argus:state:", "argus:owner:"))
    ]
    closed = client.patch(
        f"{S}/api/cases",
        {
            "cases": [
                {
                    "id": case["id"],
                    "version": taken.body[0]["version"],
                    "status": "closed",
                    "tags": [
                        *closing_tags,
                        "argus:state:closed",
                        "argus:closed",
                        "argus:reason:rule_false_positive",
                    ],
                }
            ]
        },
    )
    assert closed.status == 200
    assert closed.body[0]["status"] == "closed"
    closing = client.post(
        f"{S}/api/cases/{case['id']}/comments",
        {
            "type": "user",
            "owner": kit.OWNER,
            "comment": "Closed by ARGUS on the approval of Tier Approver (tier-approver).",
        },
    )
    assert closing.status == 200

    reopened = client.patch(
        f"{S}/api/cases",
        {"cases": [{"id": case["id"], "version": closing["version"], "status": "open"}]},
    )
    assert reopened.status == 200

    status = kt.kibana(ALERTS).post(
        f"{S}/api/detection_engine/signals/status",
        {"signal_ids": [alert["id"]], "status": "acknowledged"},
    )
    assert (status.status, status["updated"]) == (200, 1)
    read_back = kt.es("key:argus-reader").post(
        f"/{alert['index']}/_mget",
        {"ids": [alert["id"]]},
        params={"_source_includes": "kibana.alert.workflow_status,kibana.alert.case_ids"},
    )
    assert read_back.status == 200
    assert read_back["docs"][0]["_source"] == {
        "kibana.alert.workflow_status": "acknowledged",
        "kibana.alert.case_ids": [case["id"]],
    }
