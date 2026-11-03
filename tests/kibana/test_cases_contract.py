"""§12 #10: the cases API's contract on Kibana 8.19.12 Basic, as ARGUS's writer will meet it.

* 403 without the privilege (a viewer creating, a user of another space finding), 404 for an
  unknown id, 409 for a stale (or malformed) version, 406 for an update that changes nothing,
  400 for a body outside the schema or its limits, and assignees refused for the licence;
* ``created_by`` names a key's owner (no profile id); ``reporters`` filters by it;
* ``kbn-xsrf`` must be present on a write, but any value (the empty one too) passes;
* the space prefix: a key of the space gets 403 outside it; a credential of both spaces gets
  404 for the space's case and, on the alert status route, a 200 that changed nothing (the
  silent no-op of plan §9 risk 4, why one path builder must add the prefix to every call).
"""

from __future__ import annotations

from typing import Any

from tests.kibana import kit
from tests.kibana.tier import S, Tier

WRITER = "key:argus-cases-writer"


def _message(reply: Any) -> str:
    body = reply.body
    return str(body.get("message")) if isinstance(body, dict) else str(body)


def test_status_codes(kt: Tier) -> None:
    case: dict[str, Any] = kit.create_case(kt, WRITER, "codes").body
    updated = kit.patch_case(kt, WRITER, case["id"], case["version"], title="codes, updated")
    assert updated.status == 200

    stale = kit.patch_case(kt, WRITER, case["id"], case["version"], title="stale")
    assert stale.status == 409
    assert _message(stale) == (
        f"These cases {case['id']} has been updated. Please refresh before saving additional "
        "updates."
    )
    malformed = kit.patch_case(kt, WRITER, case["id"], "not-a-version", title="malformed")
    assert malformed.status == 409

    current = kit.case(kt, case["id"])
    same = kit.patch_case(kt, WRITER, case["id"], current["version"], title=current["title"])
    assert (same.status, _message(same)) == (
        406,
        "All update fields are identical to current version.",
    )

    unknown = "00000000-0000-4000-8000-000000000000"
    assert kt.kibana(WRITER).get(f"{S}/api/cases/{unknown}").status == 404
    patched = kit.patch_case(kt, WRITER, unknown, current["version"], title="unknown")
    assert patched.status == 404

    viewer = kt.kibana("user:tier-viewer").post(f"{S}/api/cases", kit.case_body(kt, "viewer"))
    assert (viewer.status, _message(viewer)) == (
        403,
        'Unauthorized to create case with owners: "securitySolution"',
    )
    other = kt.kibana("user:tier-otherspace").get(
        f"{S}/api/cases/_find", params={"tags": kit.run_tag(kt)}
    )
    assert (other.status, _message(other)) == (403, "Unauthorized to get acme-soc space")


def test_limits(kt: Tier) -> None:
    def create(title: str = "limit", **extra: Any) -> Any:
        return kt.kibana(WRITER).post(
            f"{S}/api/cases", kit.case_body(kt, title, **extra), keep=kit.case_summary
        )

    assert create("t" * 160).status == 200
    assert (
        _message(create("t" * 161))
        == "The length of the title is too long. The maximum length is 160."
    )
    assert create("description", description="d" * 30_000).status == 200
    assert _message(create("description", description="d" * 30_001)) == (
        "The length of the description is too long. The maximum length is 30000."
    )
    assert create("tags", tags=[f"t{i}" for i in range(198)]).status == 200  # + 2 run tags
    assert _message(create("tags", tags=[f"t{i}" for i in range(199)])) == (
        "The length of the field tags is too long. Array must be of length <= 200."
    )
    assert create("tag", tags=["x" * 256]).status == 200
    assert _message(create("tag", tags=["x" * 257])) == (
        "The length of the tag is too long. The maximum length is 256."
    )
    assert _message(create("unknown key", bogus=1)) == 'invalid keys "bogus"'
    no_title = kit.case_body(kt, "x")
    del no_title["title"]
    missing = kt.kibana(WRITER).post(f"{S}/api/cases", no_title)
    assert (missing.status, _message(missing)) == (
        400,
        'Invalid value "undefined" supplied to "title"',
    )
    assignees = create("assignees", assignees=[{"uid": "u_tier_assignee_0"}])
    assert (assignees.status, _message(assignees)) == (
        403,
        "In order to assign users to cases, you must be subscribed to an Elastic Platinum license",
    )

    case: dict[str, Any] = create("comments").body
    comments = f"{S}/api/cases/{case['id']}/comments"
    long_ok = kt.kibana(WRITER).post(
        comments,
        {"type": "user", "comment": "c" * 30_000, "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert long_ok.status == 200
    too_long = kt.kibana(WRITER).post(
        comments, {"type": "user", "comment": "c" * 30_001, "owner": kit.OWNER}
    )
    assert too_long.status == 400
    assert _message(too_long).startswith(
        "The length of the comment is too long. The maximum length is 30000."
    )

    found = kt.kibana(WRITER).get
    assert (
        found(
            f"{S}/api/cases/_find",
            params={"tags": kit.run_tag(kt), "perPage": 100},
            keep=lambda b: b["total"],
        ).status
        == 200
    )
    too_many = found(f"{S}/api/cases/_find", params={"tags": kit.run_tag(kt), "perPage": 101})
    assert (too_many.status, _message(too_many)) == (
        400,
        "The provided perPage value is too high. The maximum allowed perPage value is 100.",
    )
    too_deep = found(
        f"{S}/api/cases/_find", params={"tags": kit.run_tag(kt), "perPage": 100, "page": 101}
    )
    assert (too_deep.status, _message(too_deep)) == (
        400,
        "The number of documents is too high. Paginating through more than 10000 documents is not possible.",  # noqa: E501
    )


def test_created_by_and_reporters(kt: Tier) -> None:
    by_argus: dict[str, Any] = kit.create_case(kt, WRITER, "a by argus").body
    by_person: dict[str, Any] = kit.create_case(kt, "user:tier-analyst", "b by a person").body
    assert by_argus["created_by"] == {
        "username": "argus",
        "full_name": "ARGUS",
        "email": "argus@tier.argus.invalid",
    }
    assert by_person["created_by"]["username"] == "tier-analyst"
    assert "profile_uid" not in by_argus["created_by"]

    argus_only = kit.find_run_cases(kt, "key:argus-kibana-reader", reporters="argus")
    assert [c["id"] for c in argus_only["cases"]] == [by_argus["id"]]
    person_only = kit.find_run_cases(kt, "key:argus-kibana-reader", reporters="tier-analyst")
    assert [c["id"] for c in person_only["cases"]] == [by_person["id"]]


def test_kbn_xsrf_must_be_present_with_any_value(kt: Tier) -> None:
    case: dict[str, Any] = kit.create_case(kt, WRITER, "xsrf").body
    comments = f"{S}/api/cases/{case['id']}/comments"
    body = {"type": "user", "comment": "xsrf", "owner": kit.OWNER}
    absent = kt.kibana(WRITER).post(comments, body, xsrf=False)
    assert (absent.status, _message(absent)) == (400, "Request must contain a kbn-xsrf header.")
    empty = kt.kibana(WRITER).post(
        comments, body, xsrf=False, headers={"kbn-xsrf": ""}, keep=kit.case_summary
    )
    assert empty.status == 200
    read = kt.kibana(WRITER).get(f"{S}/api/cases/{case['id']}", xsrf=False, keep=kit.case_summary)
    assert read.status == 200  # reads need no header


def test_the_space_prefix(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "prefix", 1)[0]
    case: dict[str, Any] = kit.create_case(kt, WRITER, "prefix").body
    outside = f"/api/cases/{case['id']}"

    # ARGUS's keys hold the space only: outside it they are refused
    assert _message(kt.kibana(WRITER).get(outside)) == "Unauthorized to get default space"
    refused = kt.kibana("key:argus-alert-writer").post(
        "/api/detection_engine/signals/status", {"signal_ids": [alert["id"]], "status": "closed"}
    )
    assert refused.status == 403

    # a credential of both spaces: 404 for the case, and a status change that does nothing
    admin = kt.kibana("user:tier-elkadmin")
    assert admin.get(outside).status == 404
    moved = admin.patch(
        "/api/cases", {"cases": [{"id": case["id"], "version": case["version"], "title": "moved"}]}
    )
    assert moved.status == 404
    silent = admin.post(
        "/api/detection_engine/signals/status", {"signal_ids": [alert["id"]], "status": "closed"}
    )
    assert (silent.status, silent["total"], silent["updated"]) == (200, 0, 0)
    assert kit.alert_state(kt, alert, "kibana.alert.workflow_status") == {
        "kibana.alert.workflow_status": "open"
    }
    inside = admin.post(
        f"{S}/api/detection_engine/signals/status",
        {"signal_ids": [alert["id"]], "status": "closed"},
    )
    assert (inside.status, inside["updated"]) == (200, 1)
