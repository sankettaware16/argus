"""AR8, D-195 point 4: when the AR7 report gets a new version, only what changed is posted, as a
new comment from the user that owns it ("Update: ..."); earlier comments are never edited or
deleted; a file is uploaded again only when it changed, under a versioned name."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.incident import model as m
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import CONFIG, a_case, rig, save_version

pytestmark = pytest.mark.integration
ENDING = "Confirm or reject in a comment."


def newer(report: m.IncidentReport) -> m.IncidentReport:
    """Another check ran, and ARGUS is surer."""
    line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    return report.model_copy(
        update={
            "evidence": (*report.evidence, line),
            "verdict": report.verdict.model_copy(update={"confidence": 0.95}),
        }
    )


async def test_a_new_version_is_posted_as_update_comments_by_the_users_who_own_them(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    [kibana_case] = r.kibana.team_cases()
    kid = kibana_case["id"]
    before = r.kibana.user_comments(kid)
    files_before = len(r.kibana.files[kid])
    writes_before = len(r.kibana.writes)

    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    report = await r.run(case)

    assert report.decision.action == "update", report.lines()
    assert report.stopped is None, report.lines()
    after = r.kibana.user_comments(kid)
    assert after[: len(before)] == before  # nothing earlier was edited or removed
    fresh = after[len(before) :]
    assert [u for u, _ in fresh] == ["argus-evidence", "argus-reporter", "argus-lead"]
    assert fresh[0][1].startswith("## Update: Evidence\n")
    assert "New since report version 1: 1 lines (version 2)." in fresh[0][1]
    assert "A newer check" in fresh[0][1]
    assert "**E1 · " not in fresh[0][1]
    assert fresh[1][1].startswith("## Update: new files")
    assert fresh[2][1].startswith("**Update: ARGUS's verdict is now true positive (0.95); it was")
    assert fresh[2][1].endswith(ENDING)  # the lead's is the last word of the round

    # the PDF changed (it holds the evidence), the CSVs did not: one new file, versioned
    files = r.kibana.files[kid]
    assert len(files) == files_before + 1
    assert files[-1]["by"] == "argus-reporter"
    assert files[-1]["name"].endswith("_Incident_Report_v2.pdf")
    assert all("_v2" not in f["name"] for f in files[:-1])

    # a write is a POST: no edit (PATCH) and no delete ever
    new_writes = r.kibana.writes[writes_before:]
    assert {w.method for w in r.kibana.writes} == {"POST"}
    assert all(w.as_user is not None for w in new_writes)

    # recorded: the round is a generation of its own, each step by its author
    rows = await r.sql(
        "SELECT gen, author, key, state FROM case_team_steps WHERE gen = 2 ORDER BY seq"
    )
    assert [(x.author, x.key, x.state) for x in rows] == [
        ("argus-evidence", "comment:evidence:1", "verified"),
        ("argus-reporter", "file:pdf", "verified"),
        ("argus-reporter", "comment:files", "verified"),
        ("argus-lead", "comment:verdict", "verified"),
    ]
    [post] = await r.sql("SELECT last_version FROM case_team_posts")
    assert post.last_version == 2

    again = await r.run(case)  # the same version again: nothing
    assert again.decision.action == "none"
    assert len(r.kibana.writes) == writes_before + len(new_writes)


async def test_updates_are_spaced_by_the_minimum_gap(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(
        migrated_engine, writer_engine, config=replace(CONFIG, min_update_gap=timedelta(hours=6))
    )
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    await save_version(app_engine, case, newer)
    r.advance(3600)
    early = await r.run(case)
    assert early.decision.action == "none"
    assert "short while ago" in early.decision.why
    r.advance(6 * 3600)
    assert (await r.run(case)).decision.action == "update"


async def test_a_version_that_adds_nothing_to_the_case_posts_nothing(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    writes = len(r.kibana.writes)

    def reworded(report: m.IncidentReport) -> m.IncidentReport:
        meta = report.meta.model_copy(update={"catalogue_version": 7})  # shown nowhere
        return report.model_copy(update={"meta": meta})

    await save_version(app_engine, case, reworded)  # a version, but no part of the case changes
    r.advance(7 * 3600)
    report = await r.run(case)
    assert report.decision.action == "none"
    assert len(r.kibana.writes) == writes


async def test_a_started_update_is_finished_before_a_newer_version_is_looked_at(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from tests.integration.caseteam.fake import Fault, writes_by

    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    r.kibana.faults.append(Fault(writes_by("argus-reporter", "/files", 1), "status", status=500))
    stopped = await r.run(case)
    assert stopped.stopped is not None

    def third(report: m.IncidentReport) -> m.IncidentReport:
        line = report.evidence[-1].model_copy(update={"id": "E98", "title": "A third check"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, third)  # a third version meanwhile
    for _ in range(80):
        r.advance(200)
        for row in await r.sql("SELECT id FROM case_team_steps WHERE state = 'resend'"):
            await r.poster.resend(row.id, by="mina")
        done = await r.run(case)
        if done.stopped is None and done.decision.action == "none":
            break
    rows = await r.sql("SELECT DISTINCT gen, report_version FROM case_team_steps ORDER BY gen")
    assert [(x.gen, x.report_version) for x in rows][:2] == [
        (1, 1),
        (2, 2),
    ]  # round 2 stays version 2
    assert {x.state for x in await r.sql("SELECT state FROM case_team_steps")} == {"verified"}
