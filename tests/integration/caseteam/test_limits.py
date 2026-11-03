"""AR8, D-195 points 1 to 3 on the real database: posting off sends nothing (asserted at the
transport), the confidence rule, a person's confirmation and rejection, the daily cap, the notified
rules, the canary's approval (signed, bound to the plan, expiring), the keys that fail closed, a
Kibana case that already carries the incident ID, and the preview that is exactly what is sent."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.signing import iso
from argus.caseteam import approvals
from argus.incident import model as m
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import (
    CONFIG,
    SIGNER,
    a_case,
    another_case,
    decide,
    posted_today,
    rig,
    save_version,
)

pytestmark = pytest.mark.integration
REAL_NOW = datetime.now(UTC)


# --------------------------------------------------------------------------- 1. off by default


async def test_posting_off_sends_nothing_and_still_shows_what_it_would_send(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, post=False))
    case = await a_case(migrated_engine, app_engine, people["asha"])

    async def never(*_: Any) -> Any:
        raise AssertionError("posting is off: nothing may reach the transport")

    r.kibana.send = never  # type: ignore[method-assign]
    report = await r.run(case)

    assert report.decision.action == "none"
    assert report.decision.dry_run
    assert report.decision.would == "open"
    assert report.sent == 0
    assert report.stopped is None
    assert r.kibana.requests == []
    assert r.kibana.writes == []
    assert await r.sql("SELECT 1 FROM case_team_posts") == []
    assert await r.sql("SELECT 1 FROM case_team_steps") == []

    prep = await r.prepared(case)  # the dry run: the whole rendering, per case
    assert prep.plan is not None
    assert len(prep.plan.steps) == 23  # AR10: the glance and the dashboard are two more
    assert prep.problems == []
    shown = r.poster.requests(prep)
    assert len(shown) == 23
    assert [s["author"] for s in shown][:1] == ["argus-lead"]
    assert shown[0]["path"].endswith("/api/cases")
    assert shown[-1]["author"] == "argus-lead"
    assert prep.decision.dry_run
    assert "dry run" in prep.decision.why


async def test_the_preview_is_exactly_what_is_then_sent(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    preview = r.poster.requests(prep)
    plan_hash = prep.plan.plan_hash

    report = await r.run(case)
    assert report.stopped is None, report.lines()

    [kibana_case] = r.kibana.team_cases()
    sent = [
        (u, w.method, w.path, w.body)
        for (u, _), w in zip(r.kibana.by_user, r.kibana.writes, strict=True)
    ]
    assert len(sent) == len(preview)
    for shown, (user, method, path, body) in zip(preview, sent, strict=True):
        assert (shown["author"], shown["method"]) == (user, method)
        assert shown["path"].replace("NEWCASE", kibana_case["id"]) == path
        if shown["key"].startswith("file:"):
            assert shown["body"].split(" (")[0].replace(".pdf", "") in (body or b"").decode(
                "latin-1"
            )
        else:
            assert shown["body"] == (body or b"").decode()
    again = await r.prepared(case)  # after the post the plan is the posted one's update (none)
    assert again.plan is not None
    assert again.plan.plan_hash != plan_hash
    assert again.plan.steps == ()


# --------------------------------------------------------------------------- 2. when it opens


async def test_a_true_positive_under_the_minimum_waits_for_a_person_who_then_confirms(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.79)

    waiting = await r.run(case)
    assert waiting.decision.action == "none"
    assert "waiting for a person to confirm" in waiting.decision.why
    assert r.kibana.requests == []

    await decide(migrated_engine, case, people["ravi"], "confirmed")
    done = await r.run(case)
    assert done.decision.action == "open"
    assert done.decision.route == "a person confirmed the report"
    assert done.stopped is None
    assert len(r.kibana.team_cases()) == 1


async def test_a_true_positive_at_the_minimum_opens_by_itself(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.8)
    report = await r.run(case)
    assert report.decision.route == "ARGUS's verdict is a true positive (0.80)"
    assert len(r.kibana.team_cases()) == 1


async def test_a_person_who_rejected_the_report_stops_both_routes(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.95)
    await decide(migrated_engine, case, people["ravi"], "rejected")
    report = await r.run(case)
    assert report.decision.action == "none"
    assert "rejected" in report.decision.why
    assert r.kibana.requests == []


@pytest.mark.parametrize(
    "state", ["contained"]
)  # a closure needs an approval: policy unit tests cover closed
async def test_only_a_suggested_or_open_case_is_opened(
    state: str,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "UPDATE cases SET state = :s, closed_at = CASE WHEN :s = 'closed' THEN now() END,"
                " closure_reason = CASE WHEN :s = 'closed' THEN 'attempt_no_impact' END"
                " WHERE id = :c"
            ),
            {"s": state, "c": case},
        )
        await conn.execute(text("ALTER TABLE cases ENABLE TRIGGER USER"))
    report = await r.run(case)
    assert report.decision.action == "none"
    assert state in report.decision.why
    assert r.kibana.requests == []


async def test_at_most_per_day_cases_are_opened_a_day(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from tests.unit.kibana_sync.fake import T0

    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, per_day=1))
    other = await another_case(migrated_engine, app_engine, people["asha"])
    await posted_today(migrated_engine, other, 7, T0 - timedelta(hours=1))  # the day's one
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True)

    report = await r.run(case)
    assert report.decision.action == "none"
    assert "today's limit of 1 cases" in report.decision.why
    assert r.kibana.requests == []

    r.advance(24 * 3600)  # the next IST day: the cap counts a day's openings only
    r.kibana.faults.clear()
    later = await r.run(case)
    assert later.decision.action == "open"
    assert later.stopped is None


# --------------------------------------------------------------------------- notified cases


def with_notice(changes: int) -> Any:
    def change(report: m.IncidentReport) -> m.IncidentReport:
        notice = m.ReportNotice(
            notified_at=REAL_NOW - timedelta(days=2),
            alerts_since=4,
            still_active=True,
            changes=changes,
            line="The owner was told two days ago.",
        )
        return report.model_copy(
            update={"summary": report.summary.model_copy(update={"notice": notice})}
        )

    return change


async def test_a_notified_case_unchanged_since_the_notice_is_never_posted_again(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    writes = len(r.kibana.writes)

    await save_version(app_engine, case, with_notice(0))
    r.advance(7 * 3600)
    report = await r.run(case)

    assert report.decision.action == "none"
    assert "unchanged since the notice" in report.decision.why
    assert len(r.kibana.writes) == writes
    assert len(r.kibana.team_cases()) == 1


async def test_a_change_since_the_notice_is_a_new_comment_on_the_existing_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    [kibana_case] = r.kibana.team_cases()
    before = r.kibana.user_comments(kibana_case["id"])

    def changed(report: m.IncidentReport) -> m.IncidentReport:
        report = with_notice(2)(report)
        line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A new destination"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, changed)
    r.advance(7 * 3600)
    report = await r.run(case)

    assert report.decision.action == "update"
    assert report.decision.why == "changed since the notice"
    assert len(r.kibana.team_cases()) == 1  # never a second case
    after = r.kibana.user_comments(kibana_case["id"])
    assert after[: len(before)] == before  # nothing earlier was touched
    assert after[len(before)][0] == "argus-evidence"
    assert after[len(before)][1].startswith("## Update: Evidence")


# --------------------------------------------------------------------------- 3. the canary


async def approve(
    api: AsyncEngine, case: uuid.UUID, plan_hash: str, version: int, person: Person
) -> int:
    async with api.begin() as conn:
        return await approvals.record(
            conn,
            SIGNER,
            case_id=case,
            gen=1,
            plan_hash=plan_hash,
            report_version=version,
            approver_user_id=person.user_id,
            now=REAL_NOW,
        )


async def test_the_first_case_needs_a_persons_approval_of_that_exact_plan(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, canary=1))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    assert prep.decision.needs_approval
    assert "approval" in prep.decision.why
    assert prep.approval == "no person has approved this plan yet"

    blocked = await r.run(case)  # nothing is sent before a person approves this case
    assert blocked.decision.action == "none"
    assert r.kibana.requests == []

    await approve(web_engine, case, "0" * 64, 1, people["meera"])  # another plan: no use
    assert (await r.run(case)).decision.action == "none"
    assert r.kibana.requests == []

    forged = {  # a row not made by the web: its signature is not the key's
        "c": case,
        "h": prep.plan.plan_hash,
        "u": people["meera"].user_id,
        "a": REAL_NOW,
        "e": REAL_NOW + timedelta(hours=30),
    }
    statement = approvals.statement_of(
        case_id=case,
        gen=1,
        plan_hash=prep.plan.plan_hash,
        report_version=1,
        approver_user_id=people["meera"].user_id,
        approved_at=REAL_NOW,
        expires_at=forged["e"],
    )
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
                " approver_user_id, statement, signature, approved_at, expires_at)"
                " VALUES (:c, 1, :h, 1, :u, CAST(:s AS jsonb), :sig, :a, :e)"
            ),
            {
                **forged,
                "s": __import__("json").dumps(statement),
                "sig": "hmac-sha256:" + "0" * 16 + ":" + "0" * 64,
            },
        )
    again = await r.prepared(case)
    assert (again.approval is not None and "no valid signature" in again.approval) or (
        again.approval is not None and "tampered" in again.approval
    )
    assert (await r.run(case)).decision.action == "none"
    assert r.kibana.requests == []

    await approve(web_engine, case, prep.plan.plan_hash, 1, people["meera"])
    approved = await r.prepared(case)
    assert approved.approval is None
    assert approved.decision.action == "open"
    assert approved.decision.needs_approval
    done = await r.run(case)
    assert done.stopped is None
    assert done.sent == 23
    assert len(r.kibana.team_cases()) == 1


async def test_a_changed_plan_needs_a_new_approval(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, canary=1))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    await approve(web_engine, case, prep.plan.plan_hash, 1, people["meera"])
    assert (await r.prepared(case)).approval is None

    def more(report: m.IncidentReport) -> m.IncidentReport:  # the report changed afterwards
        line = report.evidence[-1].model_copy(update={"id": "E99", "title": "Another check"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, more)
    after = await r.prepared(case)
    assert after.approval == "no person has approved this plan yet"
    assert (await r.run(case)).decision.action == "none"
    assert r.kibana.requests == []


async def test_an_approval_expires_and_a_revoked_approver_no_longer_counts(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, canary=1))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    await approve(web_engine, case, prep.plan.plan_hash, 1, people["meera"])
    [row] = await r.sql("SELECT expires_at FROM case_team_approvals")
    assert iso(row.expires_at) > iso(REAL_NOW)

    async with migrated_engine.begin() as conn:  # the approver's account is disabled afterwards
        await conn.execute(
            text("UPDATE users SET disabled = true WHERE id = :u"), {"u": people["meera"].user_id}
        )
    gone = await r.prepared(case)
    assert gone.approval == "the person who approved it is no longer an active account"
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET disabled = false WHERE id = :u"), {"u": people["meera"].user_id}
        )
    assert (await r.prepared(case)).approval is None

    r.clock.now = row.expires_at + timedelta(minutes=1)  # past the window it was given for
    late = await r.prepared(case)
    assert late.approval == "the approval expired: ask again"


# --------------------------------------------------------------------------- fail closed


async def test_a_missing_key_stops_the_whole_case_before_its_first_write(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    keys = CONFIG.keys - {"argus-intel"}
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, keys=frozenset(keys)))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    report = await r.run(case)
    assert report.sent == 0
    assert r.kibana.requests == []
    assert any("no key is installed for argus-intel" in h for h in report.held)
    assert await r.sql("SELECT 1 FROM case_team_steps") == []  # nothing even planned


async def test_the_lane_itself_refuses_a_user_whose_key_is_missing_at_send_time(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """Second layer: the poster thinks every key is there, the transport knows better."""
    from argus.gateway.errors import TemplateRejectedError

    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    real = r.kibana.refusal

    def refusal(wire: Any) -> Any:
        if wire.as_user == "argus-hunter":
            return TemplateRejectedError(
                "no_key", "no case team key is configured for argus-hunter"
            )
        return real(wire)

    r.kibana.refusal = refusal  # type: ignore[method-assign]
    report = await r.run(case)
    assert report.stopped is not None
    assert "no_key" in report.stopped
    [kibana_case] = r.kibana.team_cases()
    authors = [u for u, _ in r.kibana.user_comments(kibana_case["id"])]
    assert "argus-hunter" not in authors
    assert "argus-lead" not in authors
    assert await r.sql("SELECT 1 FROM case_team_steps WHERE state = 'sending'") == []


# --------------------------------------------------------------------------- the incident ID


async def test_a_case_that_already_carries_the_incident_id_is_never_made_again(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    # someone made a case by hand with this ID (the hand-made ACME-IR-2026-1027-01)
    r.kibana.create(by="elastic", title="By hand", tags=(prep.plan.incident_id, "incident"))
    posts_before = r.kibana.count("POST")

    report = await r.run(case)

    assert r.kibana.count("POST") == posts_before == 0  # not one write
    assert report.stopped is not None
    assert "already carries" in report.stopped
    [post] = await r.sql("SELECT state, held_reason FROM case_team_posts")
    assert post.state == "held"
    assert "elastic" in post.held_reason


async def test_the_leads_own_earlier_case_is_adopted_and_the_rest_goes_on(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    opening = prep.plan.steps[0]
    kid = r.kibana.create(
        by="argus-lead", title=opening.payload["title"], tags=tuple(opening.payload["tags"])
    )
    r.kibana.cases[kid]["description"] = opening.text
    r.kibana.cases[kid]["severity"] = opening.payload["severity"]

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert len(r.kibana.team_cases()) == 1  # no second one
    assert len(r.kibana.user_comments(kid)) == 8
    [row] = await r.sql(
        "SELECT state, state_reason, sent_count FROM case_team_steps WHERE key = 'open'"
    )
    assert row.state == "verified"
    assert row.sent_count == 0
    assert "already there" in row.state_reason
