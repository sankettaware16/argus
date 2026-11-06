"""P4-F V3: the Visualiser's glance is one living comment. A round edits it in place (one PATCH by
``argus-visualiser``, read first, ledgered in class WC) and says what is new since the glance it
replaces; a lost answer is settled by reading Kibana, never by a second PATCH; a person's change in
Kibana is left and never edited again; a person's refresh corrects a glance posted in an older
form; a planned round holding the edit is still replaced when the report changes again; and
without the visualiser's key a refresh leaves the glance out and goes on."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import plan, visual
from argus.caseteam.model import PERSON_EDIT
from argus.caseteam.sender import ALL_USERS, Poster
from argus.incident import model as m
from tests.integration.cases.conftest import VERIFIER, Person
from tests.integration.caseteam.fake import Fault
from tests.integration.caseteam.kit import CONFIG, Rig, a_case, rig, save_version
from tests.integration.caseteam.test_updates import newer
from tests.integration.writer.fake import patches

pytestmark = pytest.mark.integration
EDIT = "edit:comment:glance:1"
NEXT_DAY = 17.5 * 3600  # from 16:00 UTC to the next morning: past the gap, inside the window
WITHOUT = replace(CONFIG, keys=frozenset(ALL_USERS - {"argus-visualiser"}))


def surer(confidence: float) -> Callable[[m.IncidentReport], m.IncidentReport]:
    def change(report: m.IncidentReport) -> m.IncidentReport:
        verdict = report.verdict.model_copy(update={"confidence": confidence})
        return report.model_copy(update={"verdict": verdict})

    return change


async def posted(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, person: Person, **more: Any
) -> tuple[Rig, uuid.UUID, str]:
    r = rig(owner, writer, **more)
    case = await a_case(owner, app, person)
    report = await r.run(case)
    assert report.stopped is None, report.lines()
    [kibana_case] = r.kibana.team_cases()
    return r, case, str(kibana_case["id"])


def glances(r: Rig, kid: str) -> list[str]:
    return [text for user, text in r.kibana.user_comments(kid) if user == "argus-visualiser"]


def visualiser_patches(r: Rig, since: int = 0) -> list[str]:
    return [
        w.path
        for w in r.kibana.writes[since:]
        if w.method == "PATCH" and w.as_user == "argus-visualiser"
    ]


async def rows_of(r: Rig, case: uuid.UUID, key: str) -> list[Any]:
    return await r.sql(
        "SELECT gen, kind, state, state_reason, payload, units FROM case_team_steps"
        " WHERE case_id = :c AND key = :k ORDER BY id",
        c=case,
        k=key,
    )


async def test_each_round_edits_the_one_glance_in_place_and_says_what_is_new(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    (first,) = glances(r, kid)
    assert "80% sure" in first
    assert "New since" not in first
    comments = len(r.kibana.user_comments(kid))

    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    before = len(r.kibana.writes)
    report = await r.run(case)
    assert report.decision.action == "update", report.lines()
    assert report.stopped is None, report.lines()
    (second,) = glances(r, kid)  # still one glance: edited, not posted again
    assert second.startswith("## Incident at a glance\n")
    assert "95% sure" in second
    assert "New since report version 1: the same counts." in second
    assert visualiser_patches(r, before) == [f"/s/acme-soc/api/cases/{kid}/comments"]
    assert not any(
        t.startswith("## Update: Incident at a glance") for _, t in r.kibana.user_comments(kid)
    )
    assert (
        len(r.kibana.user_comments(kid)) == comments + 3
    )  # evidence, files, verdict: not the glance
    [row] = await rows_of(r, case, EDIT)
    assert (row.gen, row.kind, row.state) == (2, "edit_comment", "verified")
    assert row.payload[plan.ROUND] is True
    assert row.payload["since"]["version"] == 1
    assert row.payload["seen"]["version"] == 2

    await save_version(app_engine, case, surer(0.9))
    r.advance(NEXT_DAY)
    before = len(r.kibana.writes)
    third = await r.run(case)
    assert third.decision.action == "update", third.lines()
    assert third.stopped is None, third.lines()
    (now,) = glances(r, kid)
    assert "90% sure" in now
    assert "New since report version 2: the same counts." in now
    assert len(visualiser_patches(r, before)) == 1
    assert [x.state for x in await rows_of(r, case, EDIT)] == ["verified", "verified"]

    again = await r.run(case)  # the same version again: nothing
    assert again.decision.action == "none"
    assert glances(r, kid) == [now]


async def test_an_edit_whose_answer_was_lost_is_read_back_and_never_sent_twice(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    before = len(r.kibana.writes)
    r.kibana.faults.append(Fault(patches(), "timeout", land_after=0.0, times=1))

    first = await r.run(case)  # the PATCH lands, its answer is lost: the round stops in doubt
    assert first.ambiguous == 1, first.lines()
    for _ in range(40):
        r.advance(130)
        report = await r.run(case)
        if report.stopped is None and not report.held:
            break
    assert report.stopped is None, report.lines()
    assert len(visualiser_patches(r, before)) == 1  # read back, never sent again
    (glance,) = glances(r, kid)
    assert "95% sure" in glance
    [row] = await rows_of(r, case, EDIT)
    assert row.state == "verified"


async def test_a_glance_a_person_changed_in_kibana_is_left_and_never_edited_again(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    ident = next(
        c["id"]
        for c in r.kibana.cases[kid]["comments"]
        if str(c.get("comment", "")).startswith("## Incident at a glance")
    )
    r.kibana.edit_comment(kid, ident, "devuser", "Our own picture of it.")

    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    before = len(r.kibana.writes)
    report = await r.run(case)
    assert report.stopped is None, report.lines()
    assert report.note is not None
    assert PERSON_EDIT in report.note
    assert glances(r, kid) == ["Our own picture of it."]
    assert visualiser_patches(r, before) == []
    [row] = await rows_of(r, case, EDIT)
    assert (row.state, row.state_reason) == ("skipped", PERSON_EDIT)

    await save_version(app_engine, case, surer(0.9))
    r.advance(NEXT_DAY)
    later = await r.run(case)
    assert later.decision.action == "update", later.lines()
    assert later.stopped is None, later.lines()
    assert len(await rows_of(r, case, EDIT)) == 1  # not planned again: left alone for good
    assert glances(r, kid) == ["Our own picture of it."]
    refresh = await r.poster.refresh(case)
    assert refresh.plan is not None
    assert all(s.part != visual.PART for s in refresh.plan.steps)


async def test_a_refresh_corrects_a_glance_posted_in_an_older_form(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7: a glance whose form was wrong (a chart Kibana would not draw) could never be put right;
    now a person's refresh rewrites it in place, by the visualiser, and nothing else."""
    monkeypatch.setattr(visual, "INTRO", "An older ARGUS wrote this glance.")
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    monkeypatch.undo()
    (old,) = glances(r, kid)
    assert old.startswith("## Incident at a glance\n\nAn older ARGUS")
    before = len(r.kibana.writes)

    dry = await r.poster.refresh(case)
    assert dry.problems == []
    assert dry.plan is not None
    assert [s.key for s in dry.plan.steps] == [EDIT]
    assert (await r.poster.refresh(case, apply=True)).planned
    report = await r.run(case)
    assert report.stopped is None, report.lines()

    (fixed,) = glances(r, kid)
    assert visual.INTRO in fixed
    assert "New since" not in fixed  # the same report: nothing is new
    assert visualiser_patches(r, before) == [f"/s/acme-soc/api/cases/{kid}/comments"]
    [row] = await rows_of(r, case, EDIT)
    assert row.state == "verified"
    assert plan.ROUND not in row.payload
    nothing = await r.poster.refresh(case)
    assert nothing.plan is not None
    assert nothing.plan.steps == ()
    [post] = await r.sql("SELECT last_version FROM case_team_posts WHERE case_id = :c", c=case)
    assert post.last_version == 1  # a refresh is not a round


async def test_a_planned_round_holding_the_glance_edit_is_replaced_when_the_report_changes(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The round's edit is not a person's refresh: a round nothing was sent for is still replaced
    by the newer report's (a refresh would be finished first)."""
    r, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    prep = await r.prepared(case)
    assert prep.plan is not None
    assert EDIT in [s.key for s in prep.plan.steps]
    assert not prep.in_progress
    assert prep.facts is not None
    assert not prep.facts.edits_only  # a round, not a correction
    await r.poster._persist(prep)  # planned, nothing sent
    await save_version(app_engine, case, surer(0.9))
    again = await r.prepared(case)
    assert not again.in_progress  # nothing was sent: the newer report replaces it
    report = await r.run(case)
    assert report.stopped is None, report.lines()
    states = [(x.gen, x.state) for x in await rows_of(r, case, EDIT)]
    assert states == [(2, "superseded"), (3, "verified")]
    (glance,) = glances(r, kid)
    assert "90% sure" in glance


async def test_a_refresh_without_the_visualisers_key_leaves_the_glance_out_and_goes_on(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(visual, "INTRO", "An older ARGUS wrote this glance.")
    r, case, _ = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    monkeypatch.undo()
    await save_version(app_engine, case, newer)
    without = Poster(
        writer_engine, r.gateway, WITHOUT, verifier=VERIFIER, clock=r.clock, sleep=r.clock.sleep
    )
    found = await without.refresh(case)
    assert found.problems == []  # an optional user's key is never a reason to stop
    assert found.plan is not None
    assert found.plan.steps
    assert all(s.author.value != "argus-visualiser" for s in found.plan.steps)
    with_key = await r.poster.refresh(case)
    assert with_key.plan is not None
    assert EDIT in [s.key for s in with_key.plan.steps]
