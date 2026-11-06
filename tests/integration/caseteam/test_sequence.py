"""AR8: the whole sequence for the Amadey-shaped case, on the real database through the real Kibana
lane (the team's fake Kibana): who writes what, in which order, the alerts attached and tagged,
the four files and the comment that lists them, the visualiser's glance after the evidence,
the lead's verdict last, nothing twice."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.kibana import upload
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import LINK_BASE, a_case, rig

pytestmark = pytest.mark.integration


async def test_the_amadey_case_is_posted_by_seven_users_in_the_fixed_order(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert report.held == []
    states = await r.states(case)
    assert set(states) == {"verified"}, states
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["created_by"]["username"] == "argus-lead"
    assert kibana_case["tags"][0].startswith("ACME-IR-")
    assert {"incident", "source:argus-lead"} <= set(kibana_case["tags"])
    assert kibana_case["settings"] == {"syncAlerts": False}
    assert kibana_case["title"].startswith(kibana_case["tags"][0] + " · ")
    assert f"{LINK_BASE}/go/case/{case}" in kibana_case["description"]

    # the order: lead opens and works the alerts, then each owner, the lead's verdict last
    users = [user for user, _ in r.kibana.by_user]
    first_comment = users.index("argus-evidence")
    assert users[0] == "argus-lead"
    assert set(users[:first_comment]) == {"argus-lead"}
    owners = [u for u in users[first_comment:] if u != "argus-reporter"]
    assert owners == [
        "argus-evidence",
        "argus-visualiser",
        "argus-evidence",
        "argus-intel",
        "argus-responder",
        "argus-hunter",
        "argus-lead",
    ]  # evidence, glance, devices, intel, actions, queries, then the verdict
    assert users[-1] == "argus-lead"
    assert users.count("argus-reporter") == 5  # four files and the comment that lists them

    comments = r.kibana.user_comments(kibana_case["id"])
    assert [u for u, _ in comments] == [
        "argus-evidence",
        "argus-visualiser",
        "argus-evidence",
        "argus-intel",
        "argus-responder",
        "argus-hunter",
        "argus-reporter",
        "argus-lead",
    ]
    heads = [c.split("\n", 1)[0] for _, c in comments]
    assert heads[:6] == [
        "## Evidence",
        "## Incident at a glance",
        "## Affected devices",
        "## Threat intel",
        "## Recommended actions",
        "## Queries to check it yourself",
    ]
    assert heads[6] == "## Files"
    glance = dict(comments)["argus-visualiser"]
    assert kibana_case["tags"][0] in glance
    assert glance.count("!{lens{") == 3  # over time, the servers, the rules (P4-F V4)
    assert "**Top campus devices**\n\n- " in glance  # one device: a list, not a one-bar chart
    assert "The charts count the " in glance
    last = comments[-1][1]
    assert last.startswith("**ARGUS's verdict: true positive (0.8).**")
    assert last.endswith("Confirm or reject in a comment.")

    # the alerts: attached and tagged by the lead, five a call
    assert kibana_case["totalAlerts"] == 25
    assert len(r.kibana.alert_tags) == 25
    ident = kibana_case["tags"][0]
    assert all(t == {ident, "incident:true-positive"} for t in r.kibana.alert_tags.values())
    attach = [w for u, w in r.kibana.by_user if w.endswith("/comments") and u == "argus-lead"]
    assert len(attach) == 5 + 1  # five calls of five alerts, and the verdict comment

    # the files: the PDF, the one-page dashboard and the two CSVs, by the reporter, and the
    # comment lists them
    files = r.kibana.files[kibana_case["id"]]
    assert [f["by"] for f in files] == ["argus-reporter"] * 4
    assert [f["mime"] for f in files] == [
        "application/pdf",
        "application/pdf",
        "text/csv",
        "text/csv",
    ]
    assert files[0]["name"] == f"{ident}_Incident_Report.pdf"
    assert files[1]["name"] == f"{ident}_dashboard.pdf"
    assert files[2]["name"] == f"{ident}_indicators.csv"
    assert files[3]["name"] == f"{ident}_affected_devices.csv"
    assert files[0]["data"].startswith(b"%PDF")
    assert files[1]["data"].startswith(b"%PDF")
    listing = dict(comments)["argus-reporter"]
    assert all(f["name"] in listing for f in files)  # plain names in code spans (D-237)
    assert all(
        upload.FileUpload(filename="x", mime=f["mime"], data=f["data"]).sha256[:16] in listing
        for f in files
    )

    # recorded: the request, the Kibana ids that came back, the author
    rows = await r.sql(
        "SELECT key, author, request_hash, kibana_ids, sent_count FROM case_team_steps"
        " WHERE case_id = :c ORDER BY id",
        c=case,
    )
    assert all(row.sent_count == 1 for row in rows)
    assert rows[0].kibana_ids["case"] == kibana_case["id"]
    assert all(len(row.request_hash) == 64 for row in rows)
    comment_rows = [row for row in rows if row.key.startswith("comment:")]
    assert all(row.kibana_ids.get("comment") for row in comment_rows)
    [post] = await r.sql("SELECT * FROM case_team_posts WHERE case_id = :c", c=case)
    assert post.kibana_case_id == kibana_case["id"]
    assert post.last_version == 1
    assert post.state == "active"

    # nothing twice
    writes = len(r.kibana.writes)
    again = await r.run(case)
    assert again.sent == 0
    assert len(r.kibana.writes) == writes


async def test_a_pass_posts_what_qualifies_once_and_only_one_pass_runs_at_a_time(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from sqlalchemy import text

    from argus.caseteam import store

    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    other = await a_case_not_qualifying(migrated_engine, app_engine, people["asha"])
    assert other is not None
    # another run holds the lock: this one does nothing
    async with writer_engine.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": store.LOCK_KEY})
        r.healthy()
        assert await r.poster.run_pass() == []
        await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
        await holder.commit()
    r.healthy()
    reports = await r.poster.run_pass()
    assert [rep.case_id for rep in reports if rep.sent] == [case]
    assert all(rep.stopped is None for rep in reports)
    assert len(r.kibana.team_cases()) == 1
    r.healthy()
    again = await r.poster.run_pass()
    assert sum(rep.sent for rep in again) == 0


async def a_case_not_qualifying(owner: AsyncEngine, app: AsyncEngine, person: Person) -> uuid.UUID:
    """A small second case with no report: the pass looks at it and has nothing to post."""
    from tests.integration.caseteam.kit import another_case

    return await another_case(owner, app, person)


async def test_housekeeping_settles_a_write_in_doubt_without_posting_anything_new(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from tests.integration.caseteam.fake import Fault, writes_by

    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    r.kibana.faults.append(
        Fault(writes_by("argus-evidence", "/comments", 1), "timeout", land_after=0.0)
    )
    assert (await r.run(case)).ambiguous == 1
    writes = len(r.kibana.writes)
    assert await r.poster.housekeeping() == 0  # the first look is two minutes after the send
    r.advance(130)
    assert await r.poster.housekeeping() == 1  # found in Kibana
    assert len(r.kibana.writes) == writes  # looking sent nothing
    [row] = await r.sql(
        "SELECT state, state_reason FROM case_team_steps WHERE key = 'comment:evidence:1'"
    )
    assert row.state == "verified"
    assert "found in Kibana" in row.state_reason
