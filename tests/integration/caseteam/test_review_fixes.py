"""AR8 after the adversarial review (D-201 to D-210) on the real database and the real Kibana lane
with the team's fake Kibana: the poster reaches the one case that qualifies among sixty, one run at
a time (a lock the terminal and housekeeping take too), a create in doubt counts against the
day's cap and the canary, nothing is ever sent to a placeholder case, a person's confirm opens a
case only for a true positive on the newest report, a run is bounded by the lane's cap whatever
cases it takes, tag answers that are partial (alerts the index dropped, version conflicts) never
hold a case or pause the class, and a 500-alert case goes 25 alerts a call at the budget's pace."""

from __future__ import annotations

import asyncio
import itertools
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import approvals, store
from argus.caseteam.sender import Poster
from argus.gateway.kibana.writes import WriteCaps
from tests.integration.cases import knownkit
from tests.integration.cases.conftest import SIGNER, VERIFIER, Person
from tests.integration.caseteam.fake import Fault, writes_by
from tests.integration.caseteam.kit import (
    CONFIG,
    Rig,
    a_case,
    another_case,
    decide,
    rig,
    save_version,
    write_again,
)
from tests.integration.incident import kit as incident_kit
from tests.integration.writer.kit import alerts_in_kibana_index
from tests.unit.kibana_sync.fake import T0

pytestmark = pytest.mark.integration


async def copy_report(owner: AsyncEngine, template: uuid.UUID, case: uuid.UUID) -> None:
    """The template case's newest report, stored for another case (a filler that needs a report
    for the poster to look at it; the copy is exactly what a real one holds)."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO incident_reports (case_id, version, schema_version, writer,"
                " content_hash, case_version, verdict_outcome, verdict_confidence, body, prose,"
                " as_at) SELECT :n, version, schema_version, writer, content_hash, case_version,"
                " verdict_outcome, verdict_confidence, body, prose, as_at FROM incident_reports"
                " WHERE case_id = :t ORDER BY version DESC LIMIT 1"
            ),
            {"n": case, "t": template},
        )


# --------------------------------------------------------------------------- 4. liveness


OLD_CANDIDATES = (
    "SELECT c.id FROM cases c LEFT JOIN case_team_posts p ON p.case_id = c.id"
    " WHERE (c.state IN ('suspected', 'open', 'assigned', 'contained')"
    "        AND EXISTS (SELECT 1 FROM incident_reports r WHERE r.case_id = c.id))"
    " ORDER BY p.last_round_at NULLS FIRST, c.number LIMIT 40"
)  # the first version's query: the active cases with a report, by number


async def test_the_one_qualifying_case_among_sixty_is_reached_in_one_pass(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    fillers = [await another_case(migrated_engine, app_engine, people["asha"]) for _ in range(54)]
    # a person confirmed it, so only that route (ARGUS's own confidence is 0.5)
    qualifying = await a_case(
        migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5
    )
    fillers += [await another_case(migrated_engine, app_engine, people["asha"]) for _ in range(5)]
    [number] = [
        x.number for x in await r.sql("SELECT number FROM cases WHERE id = :c", c=qualifying)
    ]
    assert number == 55
    for filler in fillers:  # sixty active cases with a report each, none of them qualifying
        await copy_report(migrated_engine, qualifying, filler)
    assert len(await r.sql("SELECT 1 FROM cases WHERE state = 'open'")) == 60

    old = [x.id for x in await r.sql(OLD_CANDIDATES)]  # the premise: the old query starved it
    assert len(old) == 40
    assert qualifying not in old

    async with writer_engine.connect() as conn:
        found = await store.candidates(conn, 40, 0.8)
    assert found == [qualifying]  # picked in SQL: only a case that could qualify

    reports = await r.poster.run_pass(limit=40)

    assert [x.case_id for x in reports] == [qualifying]
    assert reports[0].stopped is None, reports[0].lines()
    assert len(r.kibana.team_cases()) == 1
    [look] = await r.sql("SELECT case_id FROM case_team_looks")
    assert look.case_id == qualifying


async def test_cases_that_cannot_qualify_are_not_candidates_and_each_route_is(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.79)

    async def candidates(minimum: float | None = 0.8) -> list[uuid.UUID]:
        async with writer_engine.connect() as conn:
            return await store.candidates(conn, 40, minimum)

    assert await candidates() == []  # a true positive under the minimum, no person yet
    assert await candidates(0.79) == [case]  # the minimum is a setting
    assert await candidates(None) == []  # case_team.auto off: ARGUS's own verdict never qualifies
    await decide(migrated_engine, case, people["ravi"], "rejected")
    assert await candidates(0.5) == []  # a rejection stops both routes
    await decide(migrated_engine, case, people["ravi"], "confirmed")
    assert await candidates() == [case]  # the newest decision is a confirm of this version
    assert await candidates(None) == [case]  # a person's confirm qualifies with auto off too
    assert (await r.run(case)).stopped is None
    assert await candidates() == []  # posted, nothing newer, nothing waiting

    def more(report: Any) -> Any:
        line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, more)
    assert await candidates() == [case]  # a case already in Kibana with a newer report
    r.advance(7 * 3600)
    assert (await r.run(case)).stopped is None
    assert await candidates() == []


async def test_the_poster_rotates_through_the_cases_by_when_it_last_looked(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, per_day=0))
    template = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.9)
    others = [await another_case(migrated_engine, app_engine, people["asha"]) for _ in range(5)]
    for other in others:
        await copy_report(migrated_engine, template, other)  # six cases ARGUS would open
    seen: list[uuid.UUID] = []
    for _ in range(3):
        reports = await r.poster.run_pass(limit=2)
        assert len(reports) == 2
        assert all("limit of 0 cases" in x.decision.why for x in reports)  # looked at, not opened
        seen += [x.case_id for x in reports]
        r.advance(1)
    assert sorted(seen) == sorted([template, *others])  # six cases, two a pass: all reached
    assert len(await r.sql("SELECT 1 FROM case_team_looks")) == 6
    assert r.kibana.requests == []


# --------------------------------------------------------------------------- 8. locking


async def test_two_runs_at_once_post_the_case_once(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    second = Poster(
        writer_engine,
        r.gateway,
        r.config,
        verifier=VERIFIER,
        clock=r.clock,
        sleep=r.clock.sleep,
        wait_for_gaps=True,
    )
    r.healthy()

    first_report, second_report = await asyncio.gather(
        r.poster.run_case(case), second.run_case(case)
    )

    reports = sorted([first_report, second_report], key=lambda x: x.stopped is not None)
    done, busy = reports
    assert done.stopped is None, done.lines()
    assert busy.stopped is not None
    assert "another case team run is in progress" in busy.stopped
    assert busy.sent == 0
    [kibana_case] = r.kibana.team_cases()
    texts = [c for _, c in r.kibana.user_comments(kibana_case["id"])]
    assert len(texts) == len(set(texts)) == 8  # the glance is the eighth comment
    assert kibana_case["totalAlerts"] == 25
    assert set((await r.states(case)).keys()) == {"verified"}


async def test_the_terminals_run_for_one_case_and_housekeeping_wait_for_the_lock_too(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    r.kibana.faults.append(
        Fault(writes_by("argus-evidence", "/comments", 1), "timeout", land_after=0.0)
    )
    first = await r.run(case)
    assert first.ambiguous == 1
    r.advance(130)  # the first look is due

    async with writer_engine.connect() as other:  # another process holds the case team's lock
        got = (
            await other.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": store.LOCK_KEY})
        ).scalar_one()
        assert got
        before = len(r.kibana.requests)
        assert await r.poster.housekeeping() == 0  # not looked at: the other run may be
        busy = await r.poster.run_case(case)  # `argus case team run <n>` is a run_case
        assert busy.stopped is not None
        assert "in progress" in busy.stopped
        assert await r.poster.run_pass() == []
        assert len(r.kibana.requests) == before  # nothing was asked of Kibana, nothing sent
        states = await r.states(case)
        assert states.get("ambiguous") == 1
        await other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
        await other.commit()

    assert await r.poster.housekeeping() == 1  # the lock is free: the look is made
    for _ in range(70):  # a timeout puts the write lane in debt for about 75 minutes
        r.advance(130)
        done = await r.run(case)
        if done.stopped is None and not done.held:
            break
    assert done.stopped is None, done.lines()
    assert set((await r.states(case)).keys()) == {"verified"}


# ------------------------------------------------------------------ the day's cap, the canary


async def test_a_create_in_doubt_counts_against_the_days_cap(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, per_day=1))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    other = await another_case(migrated_engine, app_engine, people["asha"])
    await write_again(app_engine, other, incident_kit.NOW)
    await decide(migrated_engine, other, people["asha"])
    r.kibana.faults.append(Fault(writes_by("argus-lead", "/cases", 1), "timeout", land_after=None))

    first = await r.run(case)
    assert first.ambiguous == 1  # the create may have landed: its outcome is not known
    [post] = await r.sql("SELECT kibana_case_id, opened_at FROM case_team_posts")
    assert (post.kibana_case_id, post.opened_at) == (None, None)

    prep = await r.prepared(other)
    assert prep.decision.action == "none"
    assert "today's limit of 1 cases" in prep.decision.why
    async with writer_engine.connect() as conn:
        assert await store.opened_total(conn) == 1


async def test_a_create_in_doubt_counts_toward_the_canary_and_a_planned_one_does_not(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=replace(CONFIG, canary=1))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    other = await another_case(migrated_engine, app_engine, people["asha"])
    await write_again(app_engine, other, incident_kit.NOW)
    await decide(migrated_engine, other, people["asha"])

    await r.run(case)  # the canary: no approval yet, nothing was sent
    async with writer_engine.connect() as conn:
        assert await store.opened_total(conn) == 0  # a plan nothing was sent for is no opening
    assert (await r.prepared(other)).decision.needs_approval

    prep = await r.prepared(case)
    assert prep.plan is not None
    async with web_engine.begin() as conn:
        await approvals.record(
            conn,
            SIGNER,
            case_id=case,
            gen=1,
            plan_hash=prep.plan.plan_hash,
            report_version=1,
            approver_user_id=people["meera"].user_id,
            now=datetime.now(UTC),
        )
    r.kibana.faults.append(Fault(writes_by("argus-lead", "/cases", 1), "timeout", land_after=None))
    sent = await r.run(case)
    assert sent.ambiguous == 1  # the approved create left, and nobody knows whether it landed
    async with writer_engine.connect() as conn:
        assert await store.opened_total(conn) == 1

    later = await r.prepared(other)  # the canary's one case is out: no second approval is asked
    assert not later.decision.needs_approval
    assert later.approval is None


# ------------------------------------------------------------------ 7. a hand-made case


async def test_nothing_is_sent_to_a_placeholder_and_skip_is_refused_until_the_case_exists(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    hand = r.kibana.create(by="elastic", title="By hand", tags=(prep.plan.incident_id, "incident"))

    held = await r.run(case)
    assert held.stopped is not None
    assert "already carries" in held.stopped
    [open_step] = await r.sql("SELECT id, state FROM case_team_steps WHERE key = 'open'")
    assert open_step.state == "held"

    with pytest.raises(ValueError, match="does not exist yet"):
        await r.poster.skip(open_step.id, by="mina", reason="it was done by hand")
    [still] = await r.sql("SELECT state FROM case_team_steps WHERE id = :i", i=open_step.id)
    assert still.state == "held"  # the refusal changed nothing
    other = await r.sql("SELECT id FROM case_team_steps WHERE key = 'comment:evidence:1'")
    with pytest.raises(ValueError, match="does not exist yet"):
        await r.poster.skip(other[0].id, by="mina", reason="x")

    again = await r.run(case)  # waits for a person: still nothing sent
    assert again.stopped is not None
    assert r.kibana.writes == []
    assert not any("NEWCASE" in w.path for w in r.kibana.requests)
    assert hand in r.kibana.cases


async def test_a_step_that_is_not_the_create_is_never_sent_without_the_case_even_if_skipped_by_hand(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """A second layer: should the create ever be marked done without a Kibana case (the owner's
    SQL, a bug), the steps after it stop at the poster instead of going to a placeholder."""
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    r.kibana.create(by="elastic", title="By hand", tags=(prep.plan.incident_id, "incident"))
    await r.run(case)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE case_team_steps SET state = 'skipped' WHERE key = 'open'"))
    report = await r.run(case)
    assert report.stopped is not None
    assert "placeholder" in report.stopped
    assert r.kibana.writes == []
    assert not any("NEWCASE" in w.path for w in r.kibana.requests)
    assert any("placeholder" in h for h in report.held)


async def test_the_runbooks_path_for_a_hand_made_collision_ends_in_one_whole_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The team renames the hand-made case's incident tag in Kibana; ``resend`` on the held create;
    ARGUS looks for the incident ID again, finds none, and makes its own case."""
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    prep = await r.prepared(case)
    assert prep.plan is not None
    hand = r.kibana.create(by="elastic", title="By hand", tags=(prep.plan.incident_id, "incident"))
    await r.run(case)
    [open_step] = await r.sql("SELECT id FROM case_team_steps WHERE key = 'open'")

    assert await r.poster.resend(open_step.id, by="mina")  # a held create can be released
    still = await r.run(case)  # the hand-made case still carries the ID: held again
    assert still.stopped is not None
    assert "already carries" in still.stopped
    assert r.kibana.writes == []

    r.kibana.cases[hand]["tags"] = ["ACME-IR-2026-1027-01-by-hand", "incident"]  # a person renames
    assert await r.poster.resend(open_step.id, by="mina")
    done = await r.run(case)
    assert done.stopped is None, done.lines()
    assert len(r.kibana.team_cases()) == 2  # theirs and ARGUS's own, apart
    [mine] = [c for c in r.kibana.team_cases() if prep.plan.incident_id in c["tags"]]
    assert mine["id"] != hand
    assert set((await r.states(case)).keys()) == {"verified"}
    [post] = await r.sql("SELECT state, held_reason FROM case_team_posts")
    assert (post.state, post.held_reason) == ("active", None)


# --------------------------------------------------------------------------- 9. route (a)


async def with_verdict(app: AsyncEngine, case: uuid.UUID, outcome: str, kind: str) -> Any:
    def change(report: Any) -> Any:
        verdict = report.verdict.model_copy(
            update={"outcome": outcome, "kind": kind, "confidence": None}
        )
        return report.model_copy(update={"verdict": verdict})

    return await save_version(app, case, change)


async def test_a_confirm_of_a_benign_verdict_never_opens_a_kibana_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confidence=0.5)
    stored = await with_verdict(app_engine, case, "benign_expected", "person")
    async with migrated_engine.begin() as conn:  # the confirm stores the verdict it confirmed
        await conn.execute(
            text(
                "INSERT INTO incident_report_decisions (report_id, decision, outcome, by_user_id)"
                " VALUES (:r, 'confirmed', 'benign_expected', :u)"
            ),
            {"r": stored.id, "u": people["asha"].user_id},
        )
    async with writer_engine.connect() as conn:
        assert await store.candidates(conn, 40, 0.8) == []
    report = await r.run(case)
    assert report.decision.action == "none"
    assert "not a true positive" in report.decision.why
    assert r.kibana.requests == []
    for outcome in ("inconclusive", "rule_false_positive", "benign_policy"):
        newer = await with_verdict(app_engine, case, outcome, "person")
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO incident_report_decisions (report_id, decision, outcome,"
                    " by_user_id) VALUES (:r, 'confirmed', :o, :u)"
                ),
                {"r": newer.id, "o": outcome, "u": people["asha"].user_id},
            )
        assert (await r.run(case)).decision.action == "none", outcome
    assert r.kibana.requests == []


async def test_a_confirm_of_an_older_version_opens_the_newest(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """D-229: the report changed after the person read it (new evidence, their own verdict); it
    still says true positive, so the confirm opens the case."""
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5)

    def more(report: Any) -> Any:
        line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
        return report.model_copy(update={"evidence": (*report.evidence, line)})

    await save_version(app_engine, case, more)
    async with writer_engine.connect() as conn:
        assert await store.candidates(conn, 40, 0.8) == [case]
    opened = await r.run(case)
    assert opened.decision.route == "a person confirmed the report"
    assert opened.stopped is None


async def test_a_runs_cap_binds_the_whole_run_not_each_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(team_per_run=20))
    first = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True)
    second = await another_case(migrated_engine, app_engine, people["asha"])
    await write_again(app_engine, second, incident_kit.NOW)
    await decide(migrated_engine, second, people["asha"])

    reports = await r.poster.run_pass()

    counted = [w for w in r.kibana.writes if not w.path.endswith("/tags")]
    assert len(counted) == 20  # sixteen for the first case, four for the second: one run's cap
    assert [x.case_id for x in reports] == [first, second]
    assert reports[0].stopped is None
    assert reports[1].stopped is not None
    assert "run_cap" in reports[1].stopped
    assert len(r.kibana.team_cases()) == 2

    for _ in range(4):  # the next runs finish the second case
        r.advance(20)
        await r.poster.run_pass()
    assert set((await r.states(second)).keys()) == {"verified"}
    assert set((await r.states(first)).keys()) == {"verified"}


# --------------------------------------------------------------------------- tags that are partial


def tag_steps(rows: list[Any]) -> list[Any]:
    return [x for x in rows if x.key.startswith("tag:")]


async def posted_with_tag_trouble(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, person: Person
) -> tuple[Rig, uuid.UUID, list[str]]:
    """The Amadey case about to be posted; returns the first tag call's alert ids."""
    r = rig(owner, writer)
    case = await a_case(owner, app, person)
    prep = await r.prepared(case)
    assert prep.plan is not None
    first_tag = next(s for s in prep.plan.steps if s.key == "tag:1")
    return r, case, list(first_tag.payload["ids"])


async def test_alerts_the_index_dropped_are_left_out_with_a_note_and_never_hold_the_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, ids = await posted_with_tag_trouble(
        app_engine, migrated_engine, writer_engine, people["asha"]
    )
    fired = {"done": False}

    def lose_before_the_first_tag(wire: Any) -> bool:
        if wire.path.endswith("/signals/tags") and not fired["done"]:
            fired["done"] = True
            r.kibana.lose_alerts(*ids[:2])  # lifecycle removed two between the attach and the tag
        return False

    r.kibana.crashes.append((lose_before_the_first_tag, False))
    report = await r.run(case)

    assert report.stopped is None, report.lines()
    rows = await r.sql("SELECT key, state, kibana_ids FROM case_team_steps ORDER BY id")
    tag = tag_steps(rows)[0]
    assert tag.state == "verified"
    assert tag.kibana_ids["gone_count"] == 2
    assert sorted(tag.kibana_ids["gone"]) == sorted(ids[:2])
    assert {x.state for x in rows} == {"verified"}  # the whole case went through
    lane = await r.lane.kibana_lane()
    assert dict(lane.paused) == {}  # a smaller update report is no wrong answer: WC is not paused
    [kibana_case] = r.kibana.team_cases()
    untagged = [c for u, c in r.kibana.user_comments(kibana_case["id"]) if "no longer exists" in c]
    assert len(untagged) == 1
    assert untagged[0].startswith("2 alerts of the 5 one tag call")
    assert set(r.kibana.alert_tags) >= set(ids[2:])
    assert not set(ids[:2]) & set(r.kibana.alert_tags)

    again = await r.run(case)  # said once
    assert again.sent == 0

    # the next round leaves the two out of its plan
    def more(rep: Any) -> Any:
        line = rep.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
        return rep.model_copy(update={"evidence": (*rep.evidence, line)})

    await save_version(app_engine, case, more)
    async with writer_engine.connect() as conn:
        posted = await store.posted_state(conn, case)
    assert posted is not None
    assert posted.gone == frozenset(ids[:2])


async def test_a_version_conflict_is_tried_once_more_on_a_later_pass(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, ids = await posted_with_tag_trouble(
        app_engine, migrated_engine, writer_engine, people["asha"]
    )
    for alert in ids[:3]:
        r.kibana.conflicts[alert] = 1  # a rule rewrites three alerts once

    first = await r.run(case)

    assert first.stopped is not None
    assert "tag:1 is in doubt" in first.stopped
    [tag] = await r.sql(
        "SELECT state, sent_count, kibana_ids FROM case_team_steps WHERE key = 'tag:1'"
    )
    assert (tag.state, tag.sent_count) == ("ambiguous", 1)
    assert tag.kibana_ids["conflicts"] == 3
    assert (await r.lane.kibana_lane()).paused == {}

    soon = await r.run(case)  # not yet: the retry waits for a later pass
    assert soon.sent == 0
    r.advance(11 * 60)
    later = await r.run(case)
    assert later.stopped is None, later.lines()
    [tag] = await r.sql(
        "SELECT state, sent_count, kibana_ids FROM case_team_steps WHERE key = 'tag:1'"
    )
    assert (tag.state, tag.sent_count) == ("verified", 2)
    assert len(r.kibana.alert_tags) == 25  # every alert is tagged now
    assert set((await r.states(case)).keys()) == {"verified"}
    [kibana_case] = r.kibana.team_cases()
    assert not [
        c for _, c in r.kibana.user_comments(kibana_case["id"]) if "could not be tagged" in c
    ]


async def test_a_conflict_that_comes_back_is_left_and_said_and_the_case_goes_on(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, ids = await posted_with_tag_trouble(
        app_engine, migrated_engine, writer_engine, people["asha"]
    )
    r.kibana.conflicts[ids[0]] = 2  # it conflicts on both tries
    await r.run(case)
    r.advance(11 * 60)
    done = await r.run(case)

    assert done.stopped is None, done.lines()
    [tag] = await r.sql(
        "SELECT state, sent_count, kibana_ids FROM case_team_steps WHERE key = 'tag:1'"
    )
    assert (tag.state, tag.sent_count) == ("verified", 2)  # only once more, never a third time
    assert tag.kibana_ids["untagged"] == 1
    assert set((await r.states(case)).keys()) == {"verified"}  # nothing is held for ever
    [kibana_case] = r.kibana.team_cases()
    said = [c for _, c in r.kibana.user_comments(kibana_case["id"]) if "could not be tagged" in c]
    assert len(said) == 1
    assert said[0].startswith("1 alert of the 5 one tag call")
    assert ids[0] not in r.kibana.alert_tags


async def test_a_failure_report_is_still_a_wrong_answer_that_pauses_the_class(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case, _ = await posted_with_tag_trouble(
        app_engine, migrated_engine, writer_engine, people["asha"]
    )
    real = r.kibana._tags

    def failing(body: dict[str, Any]) -> dict[str, Any]:
        answer = real(body)
        answer["failures"] = [{"cause": {"type": "x"}}]
        return answer

    r.kibana._tags = failing  # type: ignore[method-assign]
    report = await r.run(case)
    assert report.stopped is not None
    assert "WC" in (await r.lane.kibana_lane()).paused
    [tag] = await r.sql("SELECT state FROM case_team_steps WHERE key = 'tag:1'")
    assert tag.state == "ambiguous"  # looked for, not sent again by itself... (a tag is a set)


# --------------------------------------------------------------------------- 500 alerts


async def big_case(owner: AsyncEngine, app: AsyncEngine, person: Person, alerts: int) -> uuid.UUID:
    """One investigation of ``alerts`` alerts in a case a person confirmed."""
    when = incident_kit.day(0)
    inv = await knownkit.make(owner, when=when, rule="beacon", alerts=alerts)
    await incident_kit.rich_alerts(owner, inv, when)
    await incident_kit.pair_evidence(owner, inv, knownkit.SERVERS[0], 40, when)
    await incident_kit.propose(owner, inv)
    case = await knownkit.open_case(app, person, [inv])
    await alerts_in_kibana_index(owner)
    await incident_kit.write(app, case, incident_kit.NOW)
    await decide(owner, case, person)
    return case


@pytest.mark.parametrize(
    ("per_call", "gap"), [(100, 3), (25, 45)], ids=["the defaults (D-235)", "the old pace (D-209)"]
)
async def test_a_500_alert_case_goes_in_calls_of_the_settings_size_at_the_settings_pace(
    per_call: int,
    gap: int,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    config = replace(
        CONFIG, max_alerts=500, alerts_per_call=per_call, alert_pause=timedelta(seconds=gap)
    )
    caps = WriteCaps(team_alerts_per_call=per_call, team_alert_gap=timedelta(seconds=gap))
    r = rig(migrated_engine, writer_engine, config=config, caps=caps)
    case = await big_case(migrated_engine, app_engine, people["asha"], 500)
    prep = await r.prepared(case)
    assert prep.plan is not None
    kinds = [s.kind for s in prep.plan.steps]
    calls = 500 // per_call
    assert (kinds.count("attach"), kinds.count("tag")) == (calls, calls)
    assert not prep.notes  # every alert has a concrete index of the space

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["totalAlerts"] == 500
    assert len(r.kibana.alert_tags) == 500
    alert_calls = [
        (t, w)
        for t, w in zip(r.kibana.written_at, r.kibana.writes, strict=True)
        if w.path.endswith("/signals/tags") or b'"alertId"' in (w.body or b"")
    ]
    assert len(alert_calls) == 2 * calls
    sizes = {
        len(body.get("alertId") or body.get("ids") or [])
        for body in (__import__("json").loads(w.body or b"{}") for _, w in alert_calls)
    }
    assert sizes == {per_call}
    gaps = [b[0] - a[0] for a, b in itertools.pairwise(alert_calls)]
    assert min(gaps).total_seconds() >= gap  # the pause the settings ask for
    counted = [w for w in r.kibana.writes if not w.path.endswith("/tags")]
    assert len(counted) <= 40  # one run's cap: the whole case fits in it
    assert (await r.lane.kibana_lane()).counters.alert_mutations == 1_000
    assert set((await r.states(case)).keys()) == {"verified"}
    assert (r.clock.now - T0).total_seconds() >= (2 * calls - 1) * gap
