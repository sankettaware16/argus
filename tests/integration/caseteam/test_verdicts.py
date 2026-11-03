"""AR8: a person's ``Verdict:`` comment on the posted case is read by Kibana sync and recorded as
the label through the path AR7's Confirm and Reject use; a ``Verdict:`` by any of the six ARGUS
users (or ``argus``) is ignored; the lead then writes its note, and closing stays a person's
approval."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import verdicts
from argus.caseteam.model import Author
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import Rig, a_case, rig

pytestmark = pytest.mark.integration


async def posted(
    r: Rig, app: AsyncEngine, owner: AsyncEngine, people: dict[str, Person]
) -> tuple[uuid.UUID, str]:
    """The Amadey case posted to Kibana; asha and ravi are known there as asha.k and ravi.k."""
    async with owner.begin() as conn:
        for name in ("asha", "ravi"):
            await conn.execute(
                text("UPDATE users SET realm = 'native', elk_username = :k WHERE username = :u"),
                {"k": f"{name}.k", "u": name},
            )
    case = await a_case(owner, app, people["asha"])
    assert (await r.run(case)).stopped is None
    [kibana_case] = r.kibana.team_cases()
    return case, kibana_case["id"]


async def read(r: Rig, app: AsyncEngine, *, elk: bool = False) -> verdicts.VerdictsReport:
    r.healthy()
    return await verdicts.read_all(app, r.gateway, service_user="argus", clock=r.clock, elk=elk)


async def labels(r: Rig, case: uuid.UUID) -> list[tuple[str, str, int]]:
    rows = await r.sql(
        "SELECT e.outcome, e.note, e.user_id FROM review_events e JOIN case_members m"
        " ON m.investigation_id = e.investigation_id WHERE m.case_id = :c AND e.action = 'reviewed'"
        " ORDER BY e.id",
        c=case,
    )
    return [(x.outcome, x.note, x.user_id) for x in rows]


async def test_a_persons_true_positive_becomes_the_label_through_the_confirm_path(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")

    report = await read(r, app_engine)

    assert (report.read, report.recorded, report.kept) == (1, 1, {"recorded": 1})
    found = await labels(r, case)
    assert len(found) == 5  # the case's five investigations
    assert {o for o, _, _ in found} == {"true_positive"}
    assert {u for _, _, u in found} == {people["asha"].user_id}
    assert all("Confirmed with the incident report (version 1)" in n for _, n, _ in found)
    [decision] = await r.sql("SELECT decision, by_user_id FROM incident_report_decisions")
    assert (decision.decision, decision.by_user_id) == ("confirmed", people["asha"].user_id)
    [seen] = await r.sql("SELECT status, verdict, user_id, author FROM case_team_seen")
    assert (seen.status, seen.verdict, seen.author) == ("recorded", "true_positive", "asha.k")
    [state] = await r.sql("SELECT state FROM cases")
    assert state.state == "open"  # nothing was closed

    again = await read(r, app_engine)  # the case did not change: its comments are not read
    assert (again.cases, again.skipped, again.read, again.recorded) == (0, 1, 0, 0)
    assert again.kept == {}
    assert len(await labels(r, case)) == 5


async def test_a_false_positive_with_a_reason_is_a_reject_with_that_reason(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: false positive: the department's backup tool")

    report = await read(r, app_engine)

    assert report.recorded == 1
    found = await labels(r, case)
    assert {o for o, _, _ in found} == {"rule_false_positive"}
    assert all("Rejected the incident report (version 1)" in n for _, n, _ in found)
    assert all("the department's backup tool" in n for _, n, _ in found)
    [decision] = await r.sql("SELECT decision, outcome, reason FROM incident_report_decisions")
    assert (decision.decision, decision.outcome) == ("rejected", "rule_false_positive")
    assert decision.reason == "the department's backup tool"


async def test_a_false_positive_needs_a_reason_and_leaves_no_label(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: false positive")
    report = await read(r, app_engine)
    assert report.kept == {"needs_reason": 1}
    assert report.recorded == 0
    assert await labels(r, case) == []
    assert await r.sql("SELECT 1 FROM incident_report_decisions") == []


async def test_a_verdict_by_anyone_who_is_not_a_known_arguss_person_is_kept_and_ignored(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "stranger", "Verdict: true positive")
    report = await read(r, app_engine)
    assert report.kept == {"unmatched": 1}
    assert await labels(r, case) == []
    [seen] = await r.sql("SELECT status, user_id FROM case_team_seen")
    assert (seen.status, seen.user_id) == ("unmatched", None)


async def test_a_verdict_written_by_any_of_the_six_users_or_argus_is_ignored(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    for who in [a.value for a in Author] + ["argus"]:
        r.kibana.person_comment(kid, who, "Verdict: true positive")
        r.kibana.person_comment(kid, who, "Verdict: false positive: they all say so")
    report = await read(r, app_engine)
    assert (report.read, report.recorded, report.kept) == (0, 0, {})
    assert await r.sql("SELECT 1 FROM case_team_seen") == []
    assert await labels(r, case) == []


async def test_a_name_that_belongs_to_two_accounts_or_a_disabled_one_labels_nothing(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'asha'"))
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    report = await read(r, app_engine)
    assert report.kept == {"unmatched": 1}
    assert await labels(r, case) == []


async def test_an_edit_by_its_author_is_that_authors_newest_verdict_and_replaces_the_label(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    comment = r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    assert (await read(r, app_engine)).recorded == 1
    r.advance(60)
    r.kibana.edit_comment(
        kid, comment, "asha.k", "Verdict: false positive: I was wrong, it is the backup tool"
    )
    report = await read(r, app_engine)
    assert report.recorded == 1
    outcomes = [o for o, _, _ in await labels(r, case)]
    assert outcomes.count("rule_false_positive") == 5  # the newer reject replaced the review
    rows = await r.sql("SELECT status, written_at FROM case_team_seen ORDER BY written_at")
    assert [x.status for x in rows] == ["recorded", "recorded"]
    assert rows[1].written_at > rows[0].written_at  # the edit's own time


async def test_an_edit_back_to_agree_keeps_the_persons_own_review_and_the_note_says_so(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The review path keeps a person's earlier, different review when a verdict only confirms
    (D-193): so the label is not written, and the lead must not say it was."""
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    comment = r.kibana.person_comment(kid, "asha.k", "Verdict: false positive: the backup tool")
    assert (await read(r, app_engine)).recorded == 1
    r.advance(60)
    r.kibana.edit_comment(kid, comment, "asha.k", "Verdict: true positive")  # agrees with ARGUS
    report = await read(r, app_engine)
    assert report.recorded == 1
    assert report.labelled == 0  # the review path wrote nothing new
    assert {o for o, _, _ in await labels(r, case)} == {"rule_false_positive"}
    [edited] = await r.sql(
        "SELECT counts, detail FROM case_team_seen WHERE verdict = 'true_positive'"
    )
    assert edited.counts["labelled"] == 0
    assert edited.counts["kept"] == 5
    assert "kept: an earlier review by" in edited.detail

    r.advance(30 * 3600)  # a new day: the lead writes its notes
    assert (await r.run(case)).stopped is None
    notes = [
        c for u, c in r.kibana.user_comments(kid) if u == "argus-lead" and "read the verdict" in c
    ]
    assert len(notes) == 2
    first, second = notes
    assert "recorded it as a label on 5 investigations" in first
    assert "as a label" not in second
    assert "Kept: an earlier review by" in second
    assert "Asha" in second
    assert "no label was written" in second


async def test_a_comment_edited_by_someone_else_is_refused_never_attributed_to_its_author(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    # ravi wrote a plain comment; asha edits it into a verdict: not ravi's word
    harmless = r.kibana.person_comment(kid, "ravi.k", "Looking at the proxy logs now")
    r.advance(60)
    r.kibana.edit_comment(kid, harmless, "asha.k", "Verdict: false positive: the backup tool")
    report = await read(r, app_engine)
    assert report.kept == {"refused": 1}
    assert report.recorded == 0
    assert await labels(r, case) == []
    [seen] = await r.sql("SELECT status, author, user_id, detail FROM case_team_seen")
    assert (seen.status, seen.author, seen.user_id) == ("refused", "ravi.k", None)
    assert "edited by asha.k, not by its author ravi.k" in seen.detail

    # an author's recorded verdict, then someone else edits that comment: the first stands, the
    # edit is refused, and nothing about asha's verdict changes
    mine = r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    assert (await read(r, app_engine)).recorded == 1
    r.advance(60)
    r.kibana.edit_comment(kid, mine, "ravi.k", "Verdict: false positive: no it is not")
    again = await read(r, app_engine)
    assert again.kept == {"refused": 1}
    assert {o for o, _, _ in await labels(r, case)} == {"true_positive"}
    assert {u for _, _, u in await labels(r, case)} == {people["asha"].user_id}


async def test_only_the_newest_of_a_persons_unread_verdicts_counts(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: false positive: first thought")
    r.advance(60)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    report = await read(r, app_engine)
    assert report.kept == {"ignored": 1, "recorded": 1}
    [decision] = await r.sql("SELECT decision, outcome FROM incident_report_decisions")
    assert decision.decision == "confirmed"
    assert {o for o, _, _ in await labels(r, case)} == {"true_positive"}


async def test_two_people_who_disagree_are_both_recorded_and_the_lead_says_so(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    r.advance(60)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: false positive: the backup tool")

    report = await read(r, app_engine)

    assert report.recorded == 2
    decisions = await r.sql(
        "SELECT decision, by_user_id FROM incident_report_decisions ORDER BY id"
    )
    assert [(d.decision, d.by_user_id) for d in decisions] == [
        ("confirmed", people["asha"].user_id),
        ("rejected", people["ravi"].user_id),
    ]  # each went through the review path, which handles the conflict
    r.advance(30 * 3600)
    assert (await r.run(case)).stopped is None
    lead = [c for u, c in r.kibana.user_comments(kid) if u == "argus-lead"]
    disagree = [c for c in lead if "People disagree on this case" in c]
    assert len(disagree) == 1
    assert "Asha" in disagree[0]
    assert "Ravi" in disagree[0]
    assert len([c for c in lead if "read the verdict" in c]) == 2
    again = await r.run(case)  # said once
    assert again.sent == 0


async def test_a_verdict_of_one_person_twice_is_no_disagreement(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    comment = r.kibana.person_comment(kid, "asha.k", "Verdict: false positive: backup")
    assert (await read(r, app_engine)).recorded == 1
    r.advance(60)
    r.kibana.edit_comment(kid, comment, "asha.k", "Verdict: true positive")
    assert (await read(r, app_engine)).recorded == 1
    r.advance(30 * 3600)
    assert (await r.run(case)).stopped is None
    lead = [c for u, c in r.kibana.user_comments(kid) if u == "argus-lead"]
    assert not [c for c in lead if "People disagree" in c]


async def test_the_lead_then_writes_its_note_and_closing_stays_a_persons(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    await read(r, app_engine)

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    last_by, note = r.kibana.user_comments(kid)[-1]
    assert last_by == "argus-lead"
    assert note.startswith("ARGUS read the verdict")
    assert "recorded it as a label on 5 investigations" in note
    assert "true positive" in note
    assert "a person's approval" in note
    assert "proposes" not in note
    rows = await r.sql(
        "SELECT key, author, state FROM case_team_steps WHERE key LIKE 'comment:closing:%'"
    )
    assert [(x.author, x.state) for x in rows] == [("argus-lead", "verified")]
    assert (
        await r.sql("SELECT 1 FROM approval_requests") == []
    )  # nothing was proposed or closed here
    [state] = await r.sql("SELECT state FROM cases")
    assert state.state == "open"

    again = await r.run(case)  # the note is written once per verdict comment
    assert again.sent == 0
    assert len([1 for u, c in r.kibana.user_comments(kid) if c.startswith("ARGUS read")]) == 1


async def test_a_benign_verdict_is_not_promised_a_closing_proposal_the_code_does_not_make(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: false positive: the backup tool")
    await read(r, app_engine)
    assert (await r.run(case)).stopped is None
    note = r.kibana.user_comments(kid)[-1][1]
    assert "proposes" not in note
    assert "proposal" not in note
    assert "A person may close this case in ARGUS" in note
    assert "a person's approval" in note
    assert await r.sql("SELECT 1 FROM approval_requests") == []  # and none was made


async def test_reading_failure_ends_the_pass_and_never_raises(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    r.kibana.down = True
    report = await read(r, app_engine)
    assert report.stopped is not None
    assert report.recorded == 0
    assert await labels(r, case) == []
    r.kibana.down = False
    assert (await read(r, app_engine)).recorded == 1


# --------------------------------------------------------------------------- who may write a label


async def elk_session(
    owner: AsyncEngine, user: str, caps: list[str], *, ended: bool = False
) -> None:
    """A person's ELK session, with the capabilities their last check in ELK showed."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at,"
                " expires_at, mode, capabilities, checked_at, ended_at) SELECT :t, id, 'c', now(),"
                " now() + interval '1 day', 'elk', CAST(:caps AS text[]), now(),"
                " CASE WHEN :ended THEN now() END FROM users WHERE username = :u"
            ),
            {"t": f"tok-{user}-{len(caps)}-{ended}", "caps": caps, "u": user, "ended": ended},
        )


async def test_a_comment_only_kibana_account_writes_no_label(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """In ELK mode the capabilities are the snapshot of the person's ELK access: a Kibana account
    that can comment on a case but not review in ARGUS gets no label."""
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    await elk_session(migrated_engine, "asha", ["view"])  # may only look
    await elk_session(migrated_engine, "ravi", ["view", "review"])
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")

    report = await read(r, app_engine, elk=True)

    assert report.kept == {"refused": 1}
    assert report.recorded == 0
    assert await labels(r, case) == []
    assert await r.sql("SELECT 1 FROM incident_report_decisions") == []
    [seen] = await r.sql("SELECT status, user_id, detail FROM case_team_seen")
    assert (seen.status, seen.user_id) == ("refused", people["asha"].user_id)
    assert "lacks the review capability" in seen.detail

    r.advance(60)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: true positive")  # may review
    assert (await read(r, app_engine, elk=True)).recorded == 1
    assert {u for _, _, u in await labels(r, case)} == {people["ravi"].user_id}


async def test_in_elk_mode_the_newest_snapshot_decides_and_none_means_not_known(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    report = await read(r, app_engine, elk=True)  # asha never signed in through ELK
    assert report.kept == {"refused": 1}
    [seen] = await r.sql("SELECT detail FROM case_team_seen")
    assert "no record of this person's access" in seen.detail
    assert await labels(r, case) == []
    # the local capabilities (view, see_logs, review, answer_gold) do not count in ELK mode
    await elk_session(migrated_engine, "ravi", ["view"], ended=True)
    r.advance(60)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: true positive")
    assert (await read(r, app_engine, elk=True)).kept == {"refused": 1}


async def test_a_local_account_without_review_writes_no_label(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET capabilities = '{view,see_logs}' WHERE username = 'asha'")
        )
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    report = await read(r, app_engine)
    assert report.kept == {"refused": 1}
    assert await labels(r, case) == []
    [seen] = await r.sql("SELECT status, detail FROM case_team_seen")
    assert "lacks the review capability" in seen.detail
    # a grant without its prerequisite (review needs view) counts for nothing either
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET capabilities = '{review}' WHERE username = 'ravi'")
        )
    r.advance(60)
    r.kibana.person_comment(kid, "ravi.k", "Verdict: true positive")
    assert (await read(r, app_engine)).kept == {"refused": 1}
    assert await labels(r, case) == []


async def test_a_disabled_account_writes_no_label_and_is_looked_at_again_when_enabled(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'asha'"))
    r.kibana.person_comment(kid, "asha.k", "Verdict: false positive: the backup tool")
    first = await read(r, app_engine)
    assert first.kept == {"unmatched": 1}
    assert await labels(r, case) == []

    still = await read(r, app_engine)  # nothing changed in Kibana or in ARGUS: not read at all
    assert (still.cases, still.skipped, still.read) == (0, 1, 0)

    async with migrated_engine.begin() as conn:  # the account comes back
        await conn.execute(text("UPDATE users SET disabled = false WHERE username = 'asha'"))
    again = await read(r, app_engine)  # the case did not change in Kibana, but a person matches
    assert (again.cases, again.recorded) == (1, 1)
    assert {o for o, _, _ in await labels(r, case)} == {"rule_false_positive"}
    rows = await r.sql("SELECT status FROM case_team_seen ORDER BY status")
    assert [x.status for x in rows] == ["recorded", "unmatched"]  # the history keeps both
    assert (await read(r, app_engine)).cases == 0  # and it is not read again


async def test_an_unmatched_verdict_is_decided_when_a_matching_person_appears(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """D-200 (d): a person who never signed in is ``unmatched`` until they do."""
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "meera.k", "Verdict: true positive")
    assert (await read(r, app_engine)).kept == {"unmatched": 1}
    assert await labels(r, case) == []
    async with migrated_engine.begin() as conn:  # meera's ELK name becomes known
        await conn.execute(
            text(
                "UPDATE users SET realm = 'native', elk_username = 'meera.k'"
                " WHERE username = 'meera'"
            )
        )
    report = await read(r, app_engine)
    assert report.recorded == 1
    assert {u for _, _, u in await labels(r, case)} == {people["meera"].user_id}


async def test_a_frozen_account_is_no_match_and_its_comment_is_not_read_for_ever(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET frozen_at = now() WHERE username = 'asha'"))
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    assert (await read(r, app_engine)).kept == {"unmatched": 1}
    for _ in range(3):
        again = await read(r, app_engine)
        assert (again.cases, again.read) == (0, 0)  # nobody matches: nothing to look at again
    assert await labels(r, case) == []


# --------------------------------------------------------------------------- the cost of a sync


def comment_reads(r: Rig) -> int:
    return r.kibana.comment_reads


def listings(r: Rig) -> int:
    return sum(
        1 for w in r.kibana.requests if w.method == "GET" and w.path.endswith("/cases/_find")
    )


async def test_a_posted_cases_comments_are_read_only_when_its_updated_at_or_count_changed(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    _, kid = await posted(r, app_engine, migrated_engine, people)
    first = await read(r, app_engine)  # never read: read once (ARGUS's own comments, no verdict)
    assert (first.cases, first.skipped) == (1, 0)
    reads, lists = comment_reads(r), listings(r)
    assert reads >= 1

    for _ in range(4):  # nothing changed: one listing a pass, no comment read
        quiet = await read(r, app_engine)
        assert (quiet.cases, quiet.skipped) == (0, 1)
    assert comment_reads(r) == reads
    assert listings(r) == lists + 4

    r.advance(60)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")  # count and updated_at move
    changed = await read(r, app_engine)
    assert (changed.cases, changed.recorded) == (1, 1)
    assert comment_reads(r) == reads + 1

    r.advance(60)
    r.kibana.edit_comment(kid, "p-1", "asha.k", "Verdict: true positive")  # only updated_at moves
    assert (await read(r, app_engine)).cases == 1


async def test_a_failed_read_is_read_again_and_a_closed_case_is_not_listed(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    _, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    r.kibana.down = True
    assert (await read(r, app_engine)).stopped is not None
    r.kibana.down = False
    assert (await read(r, app_engine)).recorded == 1  # no mark was written by the failed pass
    async with migrated_engine.begin() as conn:  # the owner closes it past the case machine
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "UPDATE cases SET state = 'closed', closed_at = now(), opened_at = NULL,"
                " closure_reason = 'benign_expected' WHERE true"
            )
        )
        await conn.execute(text("ALTER TABLE cases ENABLE TRIGGER USER"))
    lists = listings(r)
    quiet = await read(r, app_engine)
    assert (quiet.cases, quiet.skipped) == (0, 0)
    assert listings(r) == lists  # nothing posted and open: no request at all


# ------------------------------------------------------------------ a note stepped aside


async def test_a_superseded_closing_generation_does_not_block_the_note(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from tests.integration.caseteam.kit import save_version

    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    await read(r, app_engine)
    r.clock.now = r.clock.now.replace(hour=18)  # outside the write window: the note is planned
    r.advance(0)
    held = await r.run(case)
    assert held.stopped is not None
    assert "outside_window" in held.stopped
    assert not [c for u, c in r.kibana.user_comments(kid) if "read the verdict" in c]
    rows = await r.sql(
        "SELECT state, sent_count FROM case_team_steps WHERE key LIKE 'comment:closing:%'"
    )
    assert [(x.state, x.sent_count) for x in rows] == [("planned", 0)]

    def more(report):  # type: ignore[no-untyped-def]
        line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, more)  # a newer report: its plan steps the note aside
    r.advance(15 * 3600)  # the next day, inside the window, past the update gap
    done = await r.run(case)
    assert done.stopped is None, done.lines()
    states = await r.sql(
        "SELECT state FROM case_team_steps WHERE key LIKE 'comment:closing:%' ORDER BY id"
    )
    assert "superseded" in [x.state for x in states]  # it was stepped aside ...
    notes = [c for u, c in r.kibana.user_comments(kid) if "read the verdict" in c]
    assert len(notes) == 1  # ... and the note was written, once
    again = await r.run(case)
    assert again.sent == 0
    assert len([c for u, c in r.kibana.user_comments(kid) if "read the verdict" in c]) == 1


async def test_a_note_that_was_planned_and_not_sent_is_finished_by_the_next_run(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The window was closed when the note was planned: nothing was sent, nothing newer exists,
    and the note must still be written (it used to wait for a newer report that never came)."""
    from argus.caseteam import store

    r = rig(migrated_engine, writer_engine)
    case, kid = await posted(r, app_engine, migrated_engine, people)
    r.kibana.person_comment(kid, "asha.k", "Verdict: true positive")
    await read(r, app_engine)
    r.clock.now = r.clock.now.replace(hour=18)  # outside the write window
    r.advance(0)
    held = await r.run(case)
    assert held.stopped is not None
    assert "outside_window" in held.stopped
    assert not [c for u, c in r.kibana.user_comments(kid) if "read the verdict" in c]
    async with writer_engine.connect() as conn:
        assert await store.candidates(conn, 40, 0.8) == [case]  # it is still waiting

    r.advance(15 * 3600)  # the next day, inside the window; no newer report
    done = await r.run(case)
    assert done.stopped is None, done.lines()
    assert len([c for u, c in r.kibana.user_comments(kid) if "read the verdict" in c]) == 1
    again = await r.run(case)
    assert again.sent == 0
    async with writer_engine.connect() as conn:
        assert await store.candidates(conn, 40, 0.8) == []
