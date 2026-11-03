"""The case team corrects what it posted (D-236): the lead's PATCH of the case's title and
description and a user's PATCH of their own comment. The routes, bodies and limits are Kibana
8.19's (PATCH /api/cases with {"cases": [{id, version, title?, description?}]}; PATCH
/api/cases/{id}/comments with {id, version, type: "user", owner, comment}); the author is part
of the request and its hash; only the lead edits the case; every answer is checked field by
field."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana import models
from argus.gateway.kibana.errors import AnswerMismatchError
from argus.gateway.kibana.gateway import build_final
from argus.gateway.kibana.templates import (
    TeamAttachAlerts,
    TeamAttachParams,
    TeamCommentEditParams,
    TeamEditCase,
    TeamEditComment,
)
from argus.gateway.kibana.validator import request_hash
from tests.unit.gateway.kibana.fakes import ALERT_ID, ALERT_INDEX, CASE_ID

pytestmark = pytest.mark.unit
SPACE = "acme-soc"
PREFIX = f".internal.alerts-security.alerts-{SPACE}-"
VERSION = "WzMsMV0="
NEXT = "WzQsMV0="


def case_patch(**more: Any) -> models.TeamCasePatch:
    change = {"id": CASE_ID, "version": VERSION, "title": "ACME-IR-2026-1029-01 · new title"}
    change.update(more)
    return models.TeamCasePatch(cases=(models.CaseChange(**change),))


def edit(**more: Any) -> TeamCommentEditParams:
    values: dict[str, Any] = {
        "case_id": CASE_ID,
        "author": "argus-evidence",
        "comment_id": "c1",
        "version": VERSION,
        "comment": "## Evidence\n\nnew words",
    }
    values.update(more)
    return TeamCommentEditParams(**values)


def case_answer(**more: Any) -> dict[str, Any]:
    case = {
        "id": CASE_ID,
        "version": NEXT,
        "owner": "securitySolution",
        "status": "open",
        "tags": ["ACME-IR-2026-1029-01"],
        "settings": {"syncAlerts": False},
        "created_by": {"username": "argus-lead"},
        "title": "ACME-IR-2026-1029-01 · new title",
        "description": "d",
        "comments": [],
    }
    case.update(more)
    return case


# --------------------------------------------------------------------------- the case


def test_the_leads_edit_is_a_patch_of_one_case_with_its_version_and_only_what_changes() -> None:
    final = build_final(TeamEditCase(), case_patch(), SPACE, PREFIX)
    assert (final.method, final.path) == ("PATCH", f"/s/{SPACE}/api/cases")
    assert final.as_user == "argus-lead"
    assert json.loads(final.body or b"") == {
        "cases": [{"id": CASE_ID, "version": VERSION, "title": "ACME-IR-2026-1029-01 · new title"}]
    }
    both = case_patch(description="## Summary\n\nnew")
    sent = json.loads(build_final(TeamEditCase(), both, SPACE, PREFIX).body or b"")
    assert set(sent["cases"][0]) == {"id", "version", "title", "description"}


@pytest.mark.parametrize(
    "more", [{"tags": ("a",)}, {"severity": "low"}, {"status": "closed"}, {"status": "open"}]
)
def test_the_case_team_edits_a_title_and_a_description_and_nothing_else(
    more: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        case_patch(**more)


def test_an_edit_that_changes_nothing_is_not_a_request() -> None:
    with pytest.raises(ValidationError):
        models.TeamCasePatch(cases=(models.CaseChange(id=CASE_ID, version=VERSION),))


def test_kibanas_limits_are_enforced_on_the_edit() -> None:
    case_patch(title="x" * 160)
    with pytest.raises(ValidationError):
        case_patch(title="x" * 161)
    case_patch(description="y" * 30_000)
    with pytest.raises(ValidationError):
        case_patch(description="y" * 30_001)
    with pytest.raises(ValidationError):
        case_patch(title="😀" * 81)  # counted in UTF-16 units, as Kibana counts
    with pytest.raises(ValidationError):
        case_patch(version="not a version!")
    with pytest.raises(ValidationError):
        models.TeamCasePatch(cases=(case_patch().cases[0], case_patch().cases[0]))  # one case


def test_a_title_edit_is_checked_field_by_field() -> None:
    patch = case_patch()
    template = TeamEditCase()
    assert template.check(patch, [case_answer()], None)["version"] == NEXT
    # a person's Sync alerts setting does not stop an edit (D-272): a title changes no alert
    assert template.check(patch, [case_answer(settings={"syncAlerts": True})], None)
    for bad in (
        case_answer(version=VERSION),  # the version did not move
        case_answer(title="another"),
        case_answer(created_by={"username": "someone"}),
        case_answer(id="another-case"),
    ):
        with pytest.raises(AnswerMismatchError):
            template.check(patch, [bad], None)
    for not_one in ([], [case_answer(), case_answer()], case_answer(), None):
        with pytest.raises(AnswerMismatchError):
            template.check(patch, not_one, None)


def test_a_description_edit_must_read_back_as_sent() -> None:
    patch = case_patch(title=None, description="new text")
    template = TeamEditCase()
    template.check(patch, [case_answer(description="new text")], None)
    with pytest.raises(AnswerMismatchError):
        template.check(patch, [case_answer(description="old text")], None)


# --------------------------------------------------------------------------- the comment


def test_a_comment_edit_is_a_patch_by_its_author_with_the_comments_id_and_version() -> None:
    final = build_final(TeamEditComment(), edit(), SPACE, PREFIX)
    assert (final.method, final.path) == ("PATCH", f"/s/{SPACE}/api/cases/{CASE_ID}/comments")
    assert final.as_user == "argus-evidence"
    assert json.loads(final.body or b"") == {
        "id": "c1",
        "version": VERSION,
        "type": "user",
        "owner": "securitySolution",
        "comment": "## Evidence\n\nnew words",
    }
    other = build_final(TeamEditComment(), edit(author="argus-hunter"), SPACE, PREFIX)
    assert final.body == other.body
    assert request_hash(final) != request_hash(other)  # whose key sends it is part of the request


def test_any_of_the_six_edits_a_comment_but_only_the_lead_edits_the_case() -> None:
    for user in models.TEAM_USERS:
        build_final(TeamEditComment(), edit(author=user), SPACE, PREFIX)
    with pytest.raises(ValidationError):
        edit(author="argus")  # not one of the six
    with pytest.raises(ValidationError):
        edit(author="someone-else")
    from argus.gateway.kibana.validator import TEAM_ONLY, KFinal, validate

    final = build_final(TeamEditCase(), case_patch(), SPACE, PREFIX)
    assert TEAM_ONLY["team.edit_case"] == frozenset({"argus-lead"})
    wrong = KFinal(
        final.spec, final.method, final.path, final.target, (), final.body, "argus-hunter"
    )
    with pytest.raises(TemplateRejectedError, match="not sent as"):
        validate(wrong, SPACE, PREFIX)


def test_kibanas_limits_are_enforced_on_the_comment_edit() -> None:
    build_final(TeamEditComment(), edit(comment="c" * 30_000), SPACE, PREFIX)
    with pytest.raises(ValidationError):
        edit(comment="c" * 30_001)
    with pytest.raises(ValidationError):
        edit(comment="")
    with pytest.raises(ValidationError):  # NUL is refused by the body model
        build_final(TeamEditComment(), edit(comment="a\x00b"), SPACE, PREFIX)
    with pytest.raises(ValidationError):
        edit(version="bad version")
    with pytest.raises(ValidationError):
        edit(comment_id="../x")


def test_a_comment_edit_must_read_back_as_sent_at_a_new_version_under_its_authors_name() -> None:
    params = edit()
    template = TeamEditComment()

    def comments(**more: Any) -> dict[str, Any]:
        item = {
            "id": "c1", "type": "user", "comment": params.comment, "version": NEXT,
            "created_by": {"username": "argus-evidence"},
        }  # fmt: skip
        item.update(more)
        return case_answer(comments=[{"id": "c0"}, item])

    assert template.check(params, comments(), None)
    for bad in (
        comments(comment="old words"),
        comments(version=VERSION),
        comments(created_by={"username": "argus-hunter"}),
        comments(id="c2"),
        case_answer(comments=[]),
        case_answer(comments="x"),
    ):
        with pytest.raises(AnswerMismatchError):
            template.check(params, bad, None)


# --------------------------------------------------------------------------- the attach (D-288)


def attach_check(answer: dict[str, Any], total: int = 1) -> Any:
    params = TeamAttachParams(
        case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),), expect_total=total
    )
    return TeamAttachAlerts().check(params, answer, None)


def attached(sync: Any = False, status: str = "open", total: int = 1) -> dict[str, Any]:
    return case_answer(id=CASE_ID, settings={"syncAlerts": sync}, status=status, totalAlerts=total)


def test_an_attach_with_sync_alerts_off_is_checked_by_the_count_alone() -> None:
    assert attach_check(attached())
    assert attach_check(attached(status="in-progress"))  # nothing changes an alert's status
    assert attach_check(attached(status="closed"))
    with pytest.raises(AnswerMismatchError, match="fewer"):
        attach_check(attached(total=0))


def test_an_attach_with_sync_alerts_on_is_accepted_for_an_open_case_only() -> None:
    """D-288: Kibana sets an attached alert to the case's status; for an open case that only
    re-opens an alert a person had closed, and the poster leaves those out beforehand."""
    assert attach_check(attached(sync=True, status="open"))
    for status in ("in-progress", "closed"):
        with pytest.raises(AnswerMismatchError, match="Sync alerts is on"):
            attach_check(attached(sync=True, status=status))


def test_an_attach_with_sync_alerts_on_still_needs_the_count() -> None:
    with pytest.raises(AnswerMismatchError, match="fewer"):
        attach_check(attached(sync=True, status="open", total=0))
    assert attach_check(attached(sync=True, total=5), total=5)


@pytest.mark.parametrize("sync", [None, "yes", 1, 0])
def test_an_attach_with_a_setting_that_is_not_a_plain_boolean_is_refused(sync: Any) -> None:
    with pytest.raises(AnswerMismatchError):
        attach_check(attached(sync=sync))


def test_an_attach_answer_without_a_status_is_refused_when_sync_alerts_is_on() -> None:
    answer = attached(sync=True)
    del answer["status"]
    with pytest.raises(AnswerMismatchError):
        attach_check(answer)
