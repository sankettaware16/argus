"""AR8, D-236: a posted case is corrected in place. ARGUS's own retitle reaches Kibana as the
lead's PATCH of the title; the description and the comments are rewritten only when a person
asks (``argus case team refresh``), each by the user who wrote it, against the version Kibana
holds then. Every edit goes through the lane (class WC), is ledgered by its step and verified by
the answer; a doubt is settled by reading Kibana (no duplicate, no lost update); a version
conflict reads again and tries once more; and what a person changed in Kibana is never
overwritten."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import plan, store
from argus.caseteam.model import PERSON_EDIT
from argus.incident import model as m
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.fake import Fault
from tests.integration.caseteam.kit import Rig, a_case, rig, save_version
from tests.integration.writer.fake import patches

pytestmark = pytest.mark.integration
NEW_TITLE = "ACME-IR-2026-1026-01 · Amadey beaconing from 10.198.36.230"


def retitled(title: str) -> Any:
    def change(report: m.IncidentReport) -> m.IncidentReport:
        return report.model_copy(
            update={"header": report.header.model_copy(update={"title": title})}
        )

    return change


def newer(report: m.IncidentReport) -> m.IncidentReport:
    """Another check ran, and ARGUS is surer: the evidence comment and the verdict change."""
    line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    return report.model_copy(
        update={
            "evidence": (*report.evidence, line),
            "verdict": report.verdict.model_copy(update={"confidence": 0.95}),
        }
    )


async def posted(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, person: Person
) -> tuple[Rig, uuid.UUID, str]:
    r = rig(owner, writer)
    case = await a_case(owner, app, person)
    assert (await r.run(case)).stopped is None
    [kibana_case] = r.kibana.team_cases()
    return r, case, str(kibana_case["id"])


def patches_sent(r: Rig, before: int) -> list[tuple[str | None, str]]:
    return [(w.as_user, w.path) for w in r.kibana.writes[before:] if w.method == "PATCH"]


async def gen_steps(r: Rig, case: uuid.UUID, gen: int) -> list[tuple[str, str]]:
    return [(k, s) for g, k, s in await r.steps(case) if g == gen]


# --------------------------------------------------------------------------- the title


async def test_a_retitle_in_argus_is_the_leads_patch_of_the_title_and_waits_for_no_gap(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    before = len(r.kibana.writes)
    comments = r.kibana.user_comments(kid)
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)  # minutes, not the six hours between update rounds

    report = await r.run(case)

    assert report.decision.action == "update", report.lines()
    assert report.stopped is None, report.lines()
    assert r.kibana.cases[kid]["title"] == NEW_TITLE
    assert patches_sent(r, before) == [("argus-lead", "/s/acme-soc/api/cases")]
    assert [w.method for w in r.kibana.writes[before:]] == ["PATCH"]  # no comment, no file
    assert r.kibana.user_comments(kid) == comments
    assert await gen_steps(r, case, 2) == [("edit:title", "verified")]
    [row] = await r.sql("SELECT payload, kibana_ids FROM case_team_steps WHERE key = 'edit:title'")
    assert row.payload["title"] == NEW_TITLE
    assert row.kibana_ids["case"] == kid

    # the round that had to wait still comes, and does not retitle again
    r.advance(7 * 3600)
    later = await r.run(case)
    assert later.decision.action == "update", later.lines()
    assert [w.method for w in r.kibana.writes[before + 1 :]].count("PATCH") == 0


async def test_a_title_a_person_changed_in_kibana_is_never_overwritten(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.person_edits_title(kid, "devuser", "Our own name for this")
    before = len(r.kibana.writes)
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert r.kibana.cases[kid]["title"] == "Our own name for this"
    assert patches_sent(r, before) == []  # read, found a person's title, sent nothing
    [row] = await r.sql("SELECT state, state_reason FROM case_team_steps WHERE key = 'edit:title'")
    assert row.state == "skipped"
    assert row.state_reason == PERSON_EDIT
    assert any("edit:title" in note for note in [report.note or ""])

    # and it is not asked again for the next title: the title is theirs now
    await save_version(app_engine, case, retitled(NEW_TITLE + " (again)"))
    r.advance(7 * 3600)
    async with writer_engine.connect() as conn:
        held = await store.posted_state(conn, case)
    assert held is not None
    assert held.title_by_person
    prep = await r.prepared(case)
    assert prep.plan is not None
    assert all(s.kind != "retitle" for s in prep.plan.steps)


async def test_a_version_conflict_reads_again_and_tries_once_more(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    before = len(r.kibana.writes)
    r.kibana.faults.append(Fault(patches(), "status", status=409))  # somebody wrote in between
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert r.kibana.cases[kid]["title"] == NEW_TITLE
    assert len(patches_sent(r, before)) == 1  # the refused one changed nothing: one landed
    assert await gen_steps(r, case, 2) == [("edit:title", "verified")]
    [row] = await r.sql("SELECT sent_count FROM case_team_steps WHERE key = 'edit:title'")
    assert row.sent_count == 2  # the request left twice; the first changed nothing


async def test_two_conflicts_in_a_row_wait_for_the_next_run_and_lose_nothing(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.faults.append(Fault(patches(), "status", status=409, times=2))
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)

    first = await r.run(case)

    assert first.stopped is not None
    assert "changed again" in first.stopped
    assert r.kibana.cases[kid]["title"] != NEW_TITLE
    assert await gen_steps(r, case, 2) == [("edit:title", "planned")]
    r.advance(10)
    second = await r.run(case)
    assert second.stopped is None, second.lines()
    assert r.kibana.cases[kid]["title"] == NEW_TITLE
    assert await gen_steps(r, case, 2) == [("edit:title", "verified")]


@pytest.mark.parametrize("landed", [True, False])
async def test_an_edit_in_doubt_is_read_before_it_is_sent_again(
    landed: bool,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """A timeout: the PATCH may or may not have landed. Either way the title ends up changed
    once: a late landing is found by the read ("already so"), a lost one is sent again."""
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    before = len(r.kibana.writes)
    r.kibana.faults.append(Fault(patches(), "timeout", land_after=0.0 if landed else None))
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)

    first = await r.run(case)

    assert first.ambiguous == 1
    assert (await gen_steps(r, case, 2)) == [("edit:title", "ambiguous")]
    soon = await r.run(case)  # the first look is two minutes after the send
    assert soon.stopped is not None
    for _ in range(3):
        r.advance(130)
        report = await r.run(case)
        if report.stopped is None:
            break
    assert report.stopped is None, report.lines()
    assert r.kibana.cases[kid]["title"] == NEW_TITLE
    assert await gen_steps(r, case, 2) == [("edit:title", "verified")]
    landed_patches = [
        w for w in r.kibana.writes[before:] if w.method == "PATCH" and w.path.endswith("/cases")
    ]
    assert len(landed_patches) == 1  # never two edits of one title


# --------------------------------------------------------------------------- refresh


async def test_a_refresh_plans_the_edits_and_the_next_run_sends_each_by_its_own_user(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    before = len(r.kibana.writes)
    old = list(r.kibana.user_comments(kid))
    await save_version(app_engine, case, newer)
    r.healthy()

    dry = await r.poster.refresh(case)
    assert not dry.planned
    assert dry.plan is not None
    keys = [s.key for s in dry.plan.steps]
    assert keys[0] == "edit:description"
    assert "edit:comment:evidence:1" in keys
    assert not any(k.startswith(("edit:comment:queries", "edit:comment:files")) for k in keys)
    assert "dry run" in "\n".join(dry.lines())
    assert len(await gen_steps(r, case, 2)) == 0

    done = await r.poster.refresh(case, apply=True)
    assert done.planned
    assert len(r.kibana.writes) == before  # planning writes to ARGUS's database only
    planned = await gen_steps(r, case, 2)
    assert {state for _, state in planned} == {"planned"}
    assert [k for k, _ in planned] == keys

    report = await r.run(case)
    assert report.stopped is None, report.lines()
    sent = [(w.as_user, w.path.rsplit("/api", 1)[1]) for w in r.kibana.writes[before:]]
    assert sent[0] == ("argus-lead", "/cases")
    assert sent[1:] == [("argus-evidence", f"/cases/{kid}/comments")]  # the evidence comment
    assert {w.method for w in r.kibana.writes[before:]} == {"PATCH"}  # edits only: no new comment
    case_now = r.kibana.cases[kid]
    assert "A newer check" in next(
        c for u, c in r.kibana.user_comments(kid) if u == "argus-evidence" and "## Evidence" in c
    )
    assert "(95%)" in case_now["description"]  # the description now carries the new confidence
    assert len(r.kibana.user_comments(kid)) == len(old)  # the same comments, rewritten
    assert {state for _, state in await gen_steps(r, case, 2)} == {"verified"}

    # the comments are the report's: no "Update: Evidence" follows, only what a refresh does not
    # touch (the new PDF, the verdict's new confidence) in the usual round; and a second refresh
    # finds nothing to do
    nothing = await r.poster.refresh(case)
    assert nothing.plan is not None
    assert nothing.plan.steps == ()
    assert any("nothing differs" in line for line in nothing.lines())
    r.advance(7 * 3600)
    before_round = len(r.kibana.user_comments(kid))
    later = await r.run(case)
    assert later.decision.action == "update", later.lines()
    fresh = r.kibana.user_comments(kid)[before_round:]
    assert [u for u, _ in fresh] == ["argus-reporter", "argus-lead"]
    assert not any(c.startswith("## Update: Evidence") for _, c in fresh)


def wider(report: m.IncidentReport) -> m.IncidentReport:
    """Many more checks ran: the evidence part now needs a second comment."""
    template = report.evidence[-1]
    more = tuple(
        template.model_copy(update={"id": f"E{100 + n}", "title": f"Another check {n}"})
        for n in range(90)
    )
    return report.model_copy(update={"evidence": (*report.evidence, *more)})


async def test_a_refresh_that_adds_a_comment_leaves_the_update_round_to_the_files_and_verdict(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The review of AR9 (F7): a refresh whose part now needed one more comment was not "edits
    only", so it moved ``last_version`` and ``last_round_at``, and the new files, the verdict and
    the new alerts the runbook says "still follow" waited for the next version and the 6 h gap."""
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    [was] = await r.sql("SELECT last_version, last_round_at FROM case_team_posts")
    await save_version(app_engine, case, wider)
    r.healthy()
    assert (await r.poster.refresh(case, apply=True)).planned
    steps = dict(await gen_steps(r, case, 2))
    assert "comment:evidence:2" in steps  # the extra comment is part of the refresh

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert set(dict(await gen_steps(r, case, 2)).values()) == {"verified"}
    extra = [c for u, c in r.kibana.user_comments(kid) if u == "argus-evidence" and "(2 of " in c]
    assert len(extra) == 1
    [now] = await r.sql("SELECT last_version, last_round_at FROM case_team_posts")
    assert (now.last_version, now.last_round_at) == (was.last_version, was.last_round_at)

    # the usual round is still due: the report's new version brings its files and its verdict
    r.advance(7 * 3600)
    before = len(r.kibana.user_comments(kid))
    later = await r.run(case)
    assert later.decision.action == "update", later.lines()
    assert later.stopped is None, later.lines()
    assert len(r.kibana.user_comments(kid)) > before


async def test_a_comment_or_a_description_a_person_changed_is_left_and_said(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    ident = next(c["id"] for c in r.kibana.cases[kid]["comments"] if "## Evidence" in c["comment"])
    r.kibana.edit_comment(kid, ident, "devuser", "My notes replace this.")
    r.kibana.person_edits_description(kid, "devuser", "Our summary.")
    await save_version(app_engine, case, newer)
    r.healthy()
    assert (await r.poster.refresh(case, apply=True)).planned

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    comments = {c["id"]: c["comment"] for c in r.kibana.cases[kid]["comments"] if "comment" in c}
    assert comments[ident] == "My notes replace this."  # untouched
    assert r.kibana.cases[kid]["description"] == "Our summary."
    states = dict(await gen_steps(r, case, 2))
    assert states["edit:comment:evidence:1"] == "skipped"
    assert states["edit:description"] == "skipped"
    assert report.note is not None
    assert PERSON_EDIT in report.note
    # the comments nobody touched were rewritten
    skipped = {k for k, v in states.items() if v == "skipped"}
    assert skipped == {"edit:comment:evidence:1", "edit:description"}
    assert set(states.values()) <= {"skipped", "verified"}  # nothing is left open


async def test_a_refresh_is_refused_while_a_step_is_open_or_the_case_is_not_in_kibana(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    none_yet = await r.poster.refresh(case)
    assert "the case is not in Kibana" in none_yet.problems
    assert (await r.run(case)).stopped is None
    await save_version(app_engine, case, newer)
    assert (await r.poster.refresh(case, apply=True)).planned
    again = await r.poster.refresh(case, apply=True)  # the first plan is still waiting
    assert not again.planned
    assert any("steps are still open" in p for p in again.problems)


async def test_a_refresh_survives_a_crash_and_a_resume_edits_each_comment_once(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, _ = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    before = len(r.kibana.writes)
    await save_version(app_engine, case, newer)
    r.healthy()
    assert (await r.poster.refresh(case, apply=True)).planned
    r.kibana.faults.append(Fault(patches(), "timeout", land_after=0.0, times=1))

    first = await r.run(case)  # the first PATCH lands, its answer is lost
    assert first.ambiguous == 1
    for _ in range(40):
        r.advance(130)
        report = await r.run(case)
        if report.stopped is None and not report.held:
            break
    assert report.stopped is None, report.lines()
    states = {state for _, state in await gen_steps(r, case, 2)}
    assert states == {"verified"}
    case_patches = [
        w for w in r.kibana.writes[before:] if w.method == "PATCH" and w.path.endswith("/api/cases")
    ]
    assert (
        len(case_patches) == 1
    )  # the description, once: the lost answer was not a reason to resend


async def test_plan_hashes_and_requests_are_the_same_for_the_same_edit(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """An edit's request is hashed with a stand-in version while it is only planned; the real
    version is read when it is sent."""
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await save_version(app_engine, case, retitled(NEW_TITLE))
    prep = await r.prepared(case)
    assert prep.plan is not None
    [step] = [s for s in prep.plan.steps if s.kind == "retitle"]
    _, params = plan.request_of(step, kid)
    assert params.cases[0].version == plan.STAND_IN_VERSION  # type: ignore[attr-defined]
    assert step.request_hash
