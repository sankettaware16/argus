"""Whole answers of the reads Q-D2's templates will make (plan §5 Q-D2), with the keys that will
make them: Kibana's reader key (Cases Read) and the Elasticsearch reader key (the runbook's
argus_reader). The cassettes are the fixtures for Q-D2's strict body models and Q-D3's
reconciliation, so these answers are kept whole, except where the tier's own state would make
them differ between runs (Kibana's plugin statuses and metrics; the cluster's task counters).
"""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import ALERTS_ALIAS, S, Tier

READER = "key:argus-kibana-reader"
ES_READER = "key:argus-reader"
WRITER = "key:argus-cases-writer"


def _case_with_history(kt: Tier) -> tuple[dict[str, Any], dict[str, str]]:
    alert = kit.make_alerts(kt, "templates", 1)[0]
    case: dict[str, Any] = kit.create_case(
        kt, WRITER, "[ARGUS 1] templates", tags=["argus", "argus:owner:argus", "argus:state:open"]
    ).body
    kt.kibana(WRITER).post(
        f"{S}/api/cases/{case['id']}/comments",
        {"type": "user", "comment": "Opened by ARGUS.", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    kit.attach(kt, WRITER, case["id"], alert)
    current = kit.case(kt, case["id"])
    kit.patch_case(kt, WRITER, case["id"], current["version"], status="in-progress")
    return case, alert


def test_kibana_reads_whole(kt: Tier) -> None:
    case, alert = _case_with_history(kt)
    reader = kt.kibana(READER)
    status = reader.get(
        "/api/status",
        keep=lambda b: {
            "name": b["name"],
            "version": b["version"],
            "overall": b["status"]["overall"],
        },
    )
    assert status.status == 200
    assert status["version"]["number"] == "8.19.12"
    answers = {
        "cases.find": reader.get(
            f"{S}/api/cases/_find",
            params={
                "tags": kit.run_tag(kt),
                "reporters": "argus",
                "sortField": "updatedAt",
                "sortOrder": "asc",
                "perPage": 10,
            },
        ),
        "cases.get": reader.get(f"{S}/api/cases/{case['id']}"),
        "cases.user_actions": reader.get(
            f"{S}/api/cases/{case['id']}/user_actions/_find",
            params={"perPage": 100, "sortOrder": "asc"},
        ),
        "cases.comments": reader.get(f"{S}/api/cases/{case['id']}/comments/_find"),
        "cases.configure": reader.get(f"{S}/api/cases/configure"),
        "cases.alerts (preview)": reader.get(f"{S}/api/cases/{case['id']}/alerts"),
        "alerts.cases (preview)": reader.get(f"{S}/api/cases/alerts/{alert['id']}"),
    }
    assert {name: r.status for name, r in answers.items()} == dict.fromkeys(answers, 200)
    found = answers["cases.find"].body
    assert (found["total"], found["count_in_progress_cases"]) == (1, 1)
    assert answers["cases.get"]["status"] == "in-progress"


def test_elasticsearch_reads_whole(kt: Tier) -> None:
    case, alert = _case_with_history(kt)
    reader = kt.es(ES_READER)
    links = reader.post(
        f"/{ALERTS_ALIAS}/_search",
        {
            "size": 10,
            "query": {"bool": {"filter": [{"terms": {"kibana.alert.case_ids": [case["id"]]}}]}},
            "sort": [{"kibana.alert.original_time": "asc"}],
            "_source": ["kibana.alert.case_ids", "kibana.alert.workflow_status"],
        },
    )
    assert links.status == 200
    assert [h["_id"] for h in links["hits"]["hits"]] == [alert["id"]]
    lic = reader.get("/_license")
    assert (lic.status, lic["license"]["type"]) == (200, "basic")
    health = reader.get(
        "/_cluster/health/.security",
        keep=lambda b: {
            k: v
            for k, v in b.items()
            if k
            not in (
                "number_of_pending_tasks",
                "number_of_in_flight_fetch",
                "task_max_waiting_in_queue_millis",
            )
        },
    )
    assert (health.status, health["status"]) == (200, "green")
    me = reader.get("/_security/_authenticate")
    assert (me.status, me["username"], me["authentication_type"]) == (200, "argus", "api_key")


def test_identity_reads_whole(kt: Tier) -> None:
    """Q-E1's two identity calls with a person's own credential, answers kept whole."""
    from tests.kibana.test_identity import PROBE

    me = kt.es("user:tier-approver").get("/_security/_authenticate")
    assert me.status == 200
    assert (me["username"], me["authentication_realm"]["type"]) == ("tier-approver", "native")
    privileges = kt.es("user:tier-approver").post("/_security/user/_has_privileges", PROBE)
    assert privileges.status == 200
    assert privileges["application"]["argus"]["*"] == {"approver": True, "admin": False}
    refused = kt.es("wrong:tier-approver").get("/_security/_authenticate")
    assert refused.status == 401
    assert refused["error"]["type"] == "security_exception"
