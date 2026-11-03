"""Planning the edits that correct a posted case (D-236, D-241): ARGUS's own retitle as the first
step of an update, and a person's refresh as the title, the description and every comment of the
report's parts, each set where it differs from what ARGUS last wrote. Pure: no database."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from argus.caseteam import plan, render
from argus.caseteam.model import EDIT_KINDS, Author, text_hash
from argus.caseteam.plan import Posted, PostedComment
from argus.incident import model as m
from tests.unit.caseteam import kit as team
from tests.unit.caseteam.test_plan import alerts

pytestmark = pytest.mark.unit
CTX = team.CTX
PARTS = ("evidence", "devices", "intel", "accounts", "actions", "queries")
NEW_TITLE = "ACME-IR-2026-1026-01 · Amadey beaconing from 10.198.36.230"


def retitled(report: m.IncidentReport, title: str = NEW_TITLE) -> m.IncidentReport:
    return report.model_copy(update={"header": report.header.model_copy(update={"title": title})})


def newer(report: m.IncidentReport) -> m.IncidentReport:
    line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    return report.model_copy(
        update={
            "evidence": (*report.evidence, line),
            "verdict": report.verdict.model_copy(update={"confidence": 0.95}),
        }
    )


def posted_from(first: plan.Plan, **more: Any) -> Posted:
    """What a verified first plan leaves in the case: the open step's title and description and
    every part's comments (with the ids Kibana would have given them)."""
    comments: dict[str, PostedComment] = {}
    title = description = None
    for n, s in enumerate(first.steps):
        if s.kind == "open":
            title, description = s.payload["title"], s.text
        elif s.kind == "comment" and s.part in PARTS:
            comments[s.key] = PostedComment(s.key, s.part, s.author.value, f"c-{n}", s.text or "")
    values: dict[str, Any] = {
        "kibana_case_id": "kid",
        "version": 1,
        "gen": 1,
        "title": title,
        "description": description,
        "comments": comments,
        "attached": frozenset(
            a for s in first.steps if s.kind == "attach" for a, _ in s.payload["alerts"]
        ),
    }
    values.update(more)
    return Posted(**values)


def first(report: m.IncidentReport | None = None) -> tuple[m.IncidentReport, plan.Plan]:
    report = report or team.amadey()
    return report, plan.first_plan(report, 1, alerts(3), CTX)


# --------------------------------------------------------------------------- the retitle


def test_a_title_that_moved_is_the_first_step_of_the_next_update() -> None:
    report, p = first()
    posted = posted_from(p)
    assert plan.retitle_step(report, posted) is None  # the same title: nothing to edit
    moved = retitled(report)
    step = plan.retitle_step(moved, posted)
    assert step is not None
    assert (step.key, step.kind, step.author) == ("edit:title", "retitle", Author.LEAD)
    assert step.payload == {"title": render.title_of(moved), "was": posted.title}
    update = plan.update_plan(moved, 2, alerts(3), CTX, posted, max_alerts=25)
    assert update.steps[0].key == "edit:title"
    assert update.steps[0].request_hash  # sealed with a stand-in version


def test_a_title_a_person_changed_or_unknown_is_never_planned() -> None:
    report, p = first()
    moved = retitled(report)
    assert plan.retitle_step(moved, replace(posted_from(p), title_by_person=True)) is None
    assert plan.retitle_step(moved, replace(posted_from(p), title=None)) is None
    update = plan.update_plan(
        moved, 2, alerts(3), CTX, replace(posted_from(p), title_by_person=True), max_alerts=25
    )
    assert all(s.kind not in EDIT_KINDS for s in update.steps)


# --------------------------------------------------------------------------- the requests


def test_an_edits_request_names_the_version_it_is_sent_against() -> None:
    report, p = first()
    moved = retitled(report)
    step = plan.retitle_step(moved, posted_from(p))
    assert step is not None
    template, params = plan.request_of(step, "kid")
    assert template.name == "team.edit_case"
    assert params.cases[0].version == plan.STAND_IN_VERSION  # type: ignore[attr-defined]
    _, real = plan.request_of(step, "kid", None, "WzUsMV0=")
    assert real.cases[0].version == "WzUsMV0="  # type: ignore[attr-defined]
    assert real.cases[0].title == render.title_of(moved)  # type: ignore[attr-defined]
    assert real.cases[0].description is None  # type: ignore[attr-defined]


def test_a_description_and_a_comment_edit_build_their_templates() -> None:
    report, p = first()
    plan_ = plan.refresh_plan(newer(report), 2, CTX, posted_from(p))
    by = {s.key: s for s in plan_.steps}
    description = by["edit:description"]
    assert (description.kind, description.author) == ("redescribe", Author.LEAD)
    template, params = plan.request_of(description, "kid", None, "WzUsMV0=")
    assert template.name == "team.edit_case"
    assert params.cases[0].description == description.text  # type: ignore[attr-defined]
    assert params.cases[0].title is None  # type: ignore[attr-defined]
    comment = by["edit:comment:evidence:1"]
    template, params = plan.request_of(comment, "kid", None, "WzUsMV0=")
    assert template.name == "team.edit_comment"
    assert (params.author, params.comment_id, params.version) == (  # type: ignore[attr-defined]
        "argus-evidence",
        comment.payload["comment_id"],
        "WzUsMV0=",
    )


# --------------------------------------------------------------------------- the refresh


def test_a_refresh_of_the_same_report_changes_nothing() -> None:
    report, p = first()
    refresh = plan.refresh_plan(report, 1, CTX, posted_from(p))
    assert refresh.steps == ()
    assert refresh.gen == 2


def test_a_refresh_rewrites_what_differs_by_the_user_who_wrote_it_and_nothing_else() -> None:
    report, p = first()
    refresh = plan.refresh_plan(newer(report), 2, CTX, posted_from(p))
    keys = [s.key for s in refresh.steps]
    assert keys[0] == "edit:description"  # the title did not move
    assert "edit:comment:evidence:1" in keys
    assert not any("queries" in k or "files" in k or "verdict" in k for k in keys)
    for step in refresh.steps:
        if step.kind == "edit_comment":
            owner = plan.Author(step.author)
            assert owner is team_owner(step.part)
            assert step.payload["was_hash"]
            assert step.text is not None
            assert step.text.startswith("## ")
    evidence = next(s for s in refresh.steps if s.key == "edit:comment:evidence:1")
    old = posted_from(p).comments["comment:evidence:1"]
    assert evidence.payload["was_hash"] == text_hash(old.text)
    assert evidence.payload["of"] == "comment:evidence:1"
    assert "A newer check" in (evidence.text or "")
    assert all(s.request_hash for s in refresh.steps)


def team_owner(part: str) -> Author:
    return {
        "evidence": Author.EVIDENCE,
        "devices": Author.EVIDENCE,
        "accounts": Author.EVIDENCE,
        "intel": Author.INTEL,
        "actions": Author.RESPONDER,
        "queries": Author.HUNTER,
    }[part]


def test_a_comment_an_earlier_refresh_rewrote_is_compared_with_the_new_text() -> None:
    report, p = first()
    base = posted_from(p)
    once = plan.refresh_plan(newer(report), 2, CTX, base)
    new_text = next(s.text for s in once.steps if s.key == "edit:comment:evidence:1")
    after = replace(
        base,
        comments={
            **base.comments,
            "comment:evidence:1": replace(base.comments["comment:evidence:1"], text=new_text or ""),
        },
    )
    again = plan.refresh_plan(newer(report), 2, CTX, after)
    assert "edit:comment:evidence:1" not in [s.key for s in again.steps]


def test_a_part_that_needs_more_comments_posts_the_extra_ones_and_fewer_leave_a_note() -> None:
    report, p = first()
    base = posted_from(p)
    # one comment fewer than the report needs: a part the case never had a comment for
    missing = {k: v for k, v in base.comments.items() if v.part != "queries"}
    grown = plan.refresh_plan(report, 1, CTX, replace(base, comments=missing))
    [new] = [s for s in grown.steps if s.part == "queries"]
    assert (new.kind, new.key, new.author) == ("comment", "comment:queries:1", Author.HUNTER)
    # a spare second comment the report no longer needs
    spare = PostedComment(
        "comment:evidence:2", "evidence", "argus-evidence", "c-x", "## Evidence (2 of 2)\n\nold"
    )
    shrunk = plan.refresh_plan(
        report, 1, CTX, replace(base, comments={**base.comments, spare.key: spare})
    )
    [note] = [s for s in shrunk.steps if s.key == "edit:comment:evidence:2"]
    assert note.kind == "edit_comment"
    assert note.text == "## Evidence (2)\n\nThis part now fits in the comments above."
    # once it says so it is not rewritten again
    done = replace(spare, text=note.text or "")
    quiet = plan.refresh_plan(
        report, 1, CTX, replace(base, comments={**base.comments, done.key: done})
    )
    assert quiet.steps == ()


def test_a_refresh_retitles_too_when_the_title_moved_and_never_over_a_persons() -> None:
    report, p = first()
    moved = retitled(report)
    refresh = plan.refresh_plan(moved, 2, CTX, posted_from(p))
    assert refresh.steps[0].key == "edit:title"
    kept = plan.refresh_plan(moved, 2, CTX, replace(posted_from(p), title_by_person=True))
    assert all(s.key != "edit:title" for s in kept.steps)
