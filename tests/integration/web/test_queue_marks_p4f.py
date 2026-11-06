"""UI v2's queue work through ``/api/v1`` (spec §2.3) on the web's own database login: "I'm
checking" (A1), "Mark as seen" (A2), the spot-check answer (A3), "I'm caught up" (A4), bulk "Not an
incident" (A9), the bulk review of one incident's alert groups, the undo of one's own dismissal
(A8), "sent to the CISO" (A14) and a next step ticked (A16).

What the routes are held to: each declares its capability and is refused before anything is read
(403), a change needs the CSRF token, names what the person looked at (409 when it moved, nothing
written), a bulk change is all or none, and every write leaves an audit row as the person's."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Link
from argus.cases.model import Actor, Member
from argus.cases.service import CaseService
from argus.web import auth
from argus.web.capabilities import Capability
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in
from tests.integration.web.conftest import PASSWORD

pytestmark = pytest.mark.integration
C = Capability


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    made = await make_world(seeded, web_engine, migrated_engine, tmp_path)
    async with seeded.begin() as conn:  # may manage cases, may not review
        await auth.add_user(conn, "max", "Max Manager", PASSWORD,
                            capabilities=[C.VIEW, C.MANAGE_CASES])  # fmt: skip
    return made


def later(**delta: float) -> str:
    return (datetime.now(UTC) + timedelta(**delta)).isoformat()


async def audits(w: World, action: str) -> list[Any]:
    return await w.rows(
        "SELECT actor, target_id, details FROM audit_events WHERE action = :a ORDER BY id",
        a=action,
    )


async def queue_ids(http: httpx.AsyncClient, view: str = "queue") -> tuple[set[str], int]:
    got = await http.get(f"{V1}/cases", params={"view": view})
    assert got.status_code == 200, got.text
    body = got.json()
    return {c["id"] for c in body["items"]}, int(body["counts"][view])


async def delete(http: httpx.AsyncClient, csrf: str, path: str) -> httpx.Response:
    return await http.delete(V1 + path, headers={"X-CSRF-Token": csrf})


# --------------------------------------------------------------------------- A1 hold


async def test_a_hold_takes_the_case_out_of_everyone_elses_needs_you_and_into_mine(
    world: World,
) -> None:
    held = await world.open_suspected(4, "Likely beaconing from lab-pc-17")
    other = await world.open_suspected(5)
    mina = await world.user_id("mina")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{held}/hold",
                          {"expected_version": 1, "reason": "Asked the lab admin",
                           "until": later(days=2)})  # fmt: skip
        assert done.status_code == 200, done.text
        row = done.json()["case"]
        assert row["version"] == 1  # a hold changes nothing about the case
        assert row["hold"]["by"] == {"username": "mina", "name": "Mina Manager"}
        assert row["hold"]["reason"] == "Asked the lab admin"
        assert row["hold"]["mine"] is True
        assert row["waiting_since"] is not None
        mine, mine_count = await queue_ids(http, "mine")
        assert str(held) in mine
        assert mine_count == len(mine)
        queue, count = await queue_ids(http)
        assert {str(held), str(other)} <= queue  # still in the holder's own Needs you
        assert count == len(queue)
        page = await http.get(f"{V1}/cases/{held}")
        assert page.json()["hold"]["mine"] is True
        assert page.json()["case"]["hold"]["reason"] == "Asked the lab admin"
    async with world.app() as http:
        await sign_in(http, "omar")
        queue, count = await queue_ids(http)
        assert str(held) not in queue
        assert str(other) in queue
        assert count == len(queue)
        page = await http.get(f"{V1}/cases/{held}")
        assert page.json()["hold"]["mine"] is False
        assert page.json()["hold"]["by"]["name"] == "Mina Manager"
    [entry] = await audits(world, "case.hold")
    assert (entry.actor, entry.target_id) == (f"user:{mina}", str(held))
    assert entry.details["replaced"] is False


async def test_stop_checking_brings_it_back_and_only_the_holder_stops(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        made = await post(http, csrf, f"/cases/{case}/hold",
                          {"expected_version": 1, "reason": "Checking the logs myself",
                           "until": later(hours=5)})  # fmt: skip
        assert made.status_code == 200, made.text
    async with world.app() as http:
        csrf = await sign_in(http, "omar")
        not_mine = await delete(http, csrf, f"/cases/{case}/hold")
        assert not_mine.status_code == 404
        taken = await post(
            http,
            csrf,
            f"/cases/{case}/hold",
            {"expected_version": 1, "reason": "me too", "until": later(hours=5)},
        )
        assert taken.status_code == 409
        assert "Mina Manager is checking this already" in taken.json()["detail"]
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        again = await post(http, csrf, f"/cases/{case}/hold",
                           {"expected_version": 1, "reason": "Waiting on the network team",
                            "until": later(days=1)})  # fmt: skip
        assert again.status_code == 200  # the holder's own hold is replaced
        stopped = await delete(http, csrf, f"/cases/{case}/hold")
        assert stopped.status_code == 200, stopped.text
        assert stopped.json()["case"]["hold"] is None
        twice = await delete(http, csrf, f"/cases/{case}/hold")
        assert twice.status_code == 404
    async with world.app() as http:
        await sign_in(http, "omar")
        assert str(case) in (await queue_ids(http))[0]
    rows = await world.rows(
        "SELECT ended_why FROM case_holds WHERE case_id = :c ORDER BY id", c=case
    )
    assert [r.ended_why for r in rows] == ["replaced", "released"]
    assert len(await audits(world, "case.hold_released")) == 1


async def test_a_hold_is_refused_when_it_cannot_be_a_hold(world: World) -> None:
    case = await world.open_suspected(4)
    confirmed = await world.open_case(1, start=6)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for until in (later(hours=-1), later(days=15)):
            got = await post(
                http,
                csrf,
                f"/cases/{case}/hold",
                {"expected_version": 1, "reason": "x", "until": until},
            )
            assert got.status_code == 422, got.text
        naive = await post(http, csrf, f"/cases/{case}/hold",
                           {"expected_version": 1, "reason": "x",
                            "until": "2030-01-01T09:00:00"})  # fmt: skip
        assert naive.status_code == 422
        blank = await post(
            http,
            csrf,
            f"/cases/{case}/hold",
            {"expected_version": 1, "reason": "   ", "until": later(days=1)},
        )
        assert blank.status_code == 422
        stale = await post(
            http,
            csrf,
            f"/cases/{case}/hold",
            {"expected_version": 2, "reason": "x", "until": later(days=1)},
        )
        assert stale.status_code == 409
        open_one = await post(
            http,
            csrf,
            f"/cases/{confirmed}/hold",
            {"expected_version": 1, "reason": "x", "until": later(days=1)},
        )
        assert open_one.status_code == 409
        assert "Only a possible incident" in open_one.json()["detail"]
        missing = await post(
            http,
            csrf,
            f"/cases/{uuid.uuid4()}/hold",
            {"expected_version": 1, "reason": "x", "until": later(days=1)},
        )
        assert missing.status_code == 404
        no_csrf = await http.post(f"{V1}/cases/{case}/hold",
                                  json={"expected_version": 1, "reason": "x",
                                        "until": later(days=1)})  # fmt: skip
        assert no_csrf.status_code == 403
    for user in ("vera", "rita"):  # view only; review without the case capability
        async with world.app() as http:
            csrf = await sign_in(http, user)
            got = await post(
                http,
                csrf,
                f"/cases/{case}/hold",
                {"expected_version": 1, "reason": "x", "until": later(days=1)},
            )
            assert got.status_code == 403, user
            assert (await delete(http, csrf, f"/cases/{case}/hold")).status_code == 403
    assert await world.rows("SELECT id FROM case_holds") == []


async def test_a_hold_ends_when_the_case_is_decided_and_does_not_come_back(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        made = await post(http, csrf, f"/cases/{case}/hold",
                          {"expected_version": 1, "reason": "Asked the owner",
                           "until": later(days=3)})  # fmt: skip
        assert made.status_code == 200
    async with world.app() as http:  # someone else decides anyway
        csrf = await sign_in(http, "omar")
        closed = await post(http, csrf, f"/cases/{case}/dismiss",
                            {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert closed.status_code == 200, closed.text
        assert closed.json()["case"]["state"] == "closed"
        back = await post(http, csrf, f"/cases/{case}/reopen",
                          {"expected_version": 2, "reason": "too quick"})  # fmt: skip
        assert back.status_code == 200, back.text
        assert back.json()["case"]["state"] == "suspected"
        queue, _ = await queue_ids(http)
        assert str(case) in queue  # the old hold does not hold the reopened case
        page = await http.get(f"{V1}/cases/{case}")
        assert page.json()["hold"] is None
    async with world.app() as http:  # and the case's one open hold can be a new one
        csrf = await sign_in(http, "omar")
        fresh = await post(
            http,
            csrf,
            f"/cases/{case}/hold",
            {"expected_version": 3, "reason": "now me", "until": later(days=1)},
        )
        assert fresh.status_code == 200, fresh.text
    rows = await world.rows("SELECT ended_why FROM case_holds WHERE case_id = :c ORDER BY id",
                            c=case)  # fmt: skip
    assert [r.ended_why for r in rows] == ["decided", None]


# --------------------------------------------------------------------------- A2 seen


async def test_mark_as_seen_is_the_persons_own_and_never_goes_back(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        csrf = await sign_in(http, "vera")  # view only may mark what they saw
        first = await post(http, csrf, f"/cases/{case}/seen", {"engine_version": 3})
        assert first.status_code == 200, first.text
        assert first.json()["seen"]["engine_version"] == 3
        older = await post(http, csrf, f"/cases/{case}/seen", {"engine_version": 2})
        assert older.json()["seen"]["engine_version"] == 3
        plain = await post(http, csrf, f"/cases/{case}/seen", {})
        assert plain.json()["seen"]["engine_version"] == 3
        assert plain.json()["seen"]["case_version"] == 1
        rows = await http.get(f"{V1}/cases", params={"view": "suspected"})
        mine = next(c for c in rows.json()["items"] if c["id"] == str(case))
        assert mine["seen"]["engine_version"] == 3
        for bad in ({"engine_version": 0}, {"engine_version": "x"}, {"other": 1}):
            assert (await post(http, csrf, f"/cases/{case}/seen", bad)).status_code == 422
        missing = await post(http, csrf, f"/cases/{uuid.uuid4()}/seen", {"engine_version": 1})
        assert missing.status_code == 404
        no_csrf = await http.post(f"{V1}/cases/{case}/seen", json={"engine_version": 4})
        assert no_csrf.status_code == 403
    async with world.app() as http:
        await sign_in(http, "mina")
        rows = await http.get(f"{V1}/cases", params={"view": "suspected"})
        theirs = next(c for c in rows.json()["items"] if c["id"] == str(case))
        assert theirs["seen"] is None  # another person's look is theirs
    vera = await world.user_id("vera")
    assert [a.actor for a in await audits(world, "case.seen")] == [f"user:{vera}"] * 3


# --------------------------------------------------------------------------- A3 / A4


async def argus_joins(world: World, case: uuid.UUID, investigation: uuid.UUID) -> None:
    """ARGUS links an alert group to an incident that exists already, on its own."""
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        joined = Link((Member(investigation, "actor"),))
        await service.apply(Actor.argus("linker"), case, joined, expected_version=None)


async def argus_closes(world: World, case: uuid.UUID) -> None:
    """ARGUS closes a possible incident on its own. The case machine has no such move yet (the
    incident engine's will be one), so its row and event are written as that move would."""
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE cases SET state = 'closed', closed_at = now(), attention = NULL,"
                " closure_reason = 'attempt_no_impact', version = version + 1 WHERE id = :c"
            ),
            {"c": case},
        )
        await conn.execute(
            text(
                "INSERT INTO case_events (case_id, case_version, kind, actor, from_state,"
                " to_state) SELECT id, version, 'dismissed', 'argus:engine', 'suspected',"
                " 'closed' FROM cases WHERE id = :c"
            ),
            {"c": case},
        )


async def test_a_spot_check_answer_is_recorded_once_per_person_with_the_teams_score(
    world: World,
) -> None:
    group = world.investigations[3]
    open_case = await world.open_case(1, start=6)
    await argus_joins(world, open_case, group)
    number = (await world.rows("SELECT number FROM cases WHERE id = :c", c=open_case))[0].number
    closed = await world.open_suspected(4)
    await argus_closes(world, closed)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        right = await post(http, csrf, f"/today/audit/{group}", {"answer": "right"})
        assert right.status_code == 200, right.text
        body = right.json()
        assert (body["kind"], body["answer"], body["closed_as"]) == (
            "alert_group", "right", f"Joined to incident #{number}")  # fmt: skip
        assert body["score"] == {"days": 30, "checked": 1, "wrong": 0}
        wrong = await post(http, csrf, f"/today/audit/{closed}", {"answer": "wrong"})
        assert wrong.status_code == 200, wrong.text
        assert wrong.json()["kind"] == "incident"
        assert wrong.json()["closed_as"]
        assert wrong.json()["score"] == {"days": 30, "checked": 2, "wrong": 1}
        changed = await post(http, csrf, f"/today/audit/{closed}", {"answer": "cant_tell"})
        assert changed.json()["score"] == {"days": 30, "checked": 2, "wrong": 0}
        not_closed = await post(http, csrf, f"/today/audit/{open_case}", {"answer": "right"})
        assert not_closed.status_code == 409
        missing = await post(http, csrf, f"/today/audit/{uuid.uuid4()}", {"answer": "right"})
        assert missing.status_code == 404
        wrong_kind = await post(http, csrf, f"/today/audit/{group}",
                                {"answer": "right", "kind": "incident"})  # fmt: skip
        assert wrong_kind.status_code == 404
        bad = await post(http, csrf, f"/today/audit/{group}", {"answer": "maybe"})
        assert bad.status_code == 422
    async with world.app() as http:
        csrf = await sign_in(http, "omar")
        other = await post(http, csrf, f"/today/audit/{group}", {"answer": "wrong"})
        assert other.json()["score"] == {"days": 30, "checked": 2, "wrong": 1}
    async with world.app() as http:
        csrf = await sign_in(http, "vera")
        refused = await post(http, csrf, f"/today/audit/{group}", {"answer": "right"})
        assert refused.status_code == 403
    rows = await world.rows("SELECT count(*) AS n FROM spot_checks")
    assert rows[0].n == 3
    assert len(await audits(world, "spot_check.answer")) == 4


async def test_a_spot_check_takes_only_what_argus_decided_without_a_person(world: World) -> None:
    """A stale tab or a crafted request cannot count a person's decision, or something nobody
    decided, as ARGUS's mistake: only what ARGUS closed or joined on its own is answered."""
    open_case = await world.open_case(1, start=6)  # a person put investigation 6 in it
    dismissed = await world.open_suspected(4)
    proposed, decided, undecided = (world.investigations[i] for i in (8, 9, 10))
    mina = await world.user_id("mina")
    async with world.owner.begin() as conn:  # 8: closed on ARGUS's proposal; 9: by a person
        assessment = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) SELECT id, version, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'benign_expected' FROM investigations WHERE id = :i RETURNING id"
                ),
                {"i": proposed},
            )
        ).scalar_one()
        for inv, from_proposal in ((proposed, assessment), (decided, None)):
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, assessment_id) SELECT id, version, alert_count, :u,"
                    " 'reviewed', 'benign_expected', :a FROM investigations WHERE id = :i"
                ),
                {"i": inv, "u": mina, "a": from_proposal},
            )
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        shut = await post(http, csrf, f"/cases/{dismissed}/dismiss",
                          {"expected_version": 1, "reason": "attempt_no_impact"})  # fmt: skip
        assert shut.status_code == 200, shut.text
    async with world.app() as http:
        csrf = await sign_in(http, "rita")  # review only: a stale tab answers "wrong"
        accepted = await post(http, csrf, f"/today/audit/{proposed}", {"answer": "right"})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["closed_as"] == "Benign: expected activity"
        for target in (world.investigations[6], decided, undecided, open_case, dismissed):
            refused = await post(http, csrf, f"/today/audit/{target}", {"answer": "wrong"})
            assert refused.status_code == 409, (target, refused.text)
        again = (await post(http, csrf, f"/today/audit/{proposed}", {"answer": "right"})).json()
    assert again["score"] == {"days": 30, "checked": 1, "wrong": 0}  # no refused "wrong" counted
    assert len(await world.rows("SELECT id FROM spot_checks")) == 1


async def test_caught_up_moves_the_persons_since(world: World) -> None:
    async with world.app() as http:
        csrf = await sign_in(http, "vera")
        first = await post(http, csrf, "/today/caught-up")
        assert first.status_code == 200, first.text
        again = await post(http, csrf, "/today/caught-up")
        assert again.json()["since"] >= first.json()["since"]
        no_csrf = await http.post(f"{V1}/today/caught-up")
        assert no_csrf.status_code == 403
    vera = await world.user_id("vera")
    rows = await world.rows("SELECT user_id FROM user_rounds")
    assert [r.user_id for r in rows] == [vera]
    assert len(await audits(world, "today.caught_up")) == 2


# --------------------------------------------------------------------------- A9 bulk dismiss


async def test_bulk_dismiss_closes_all_or_none(world: World) -> None:
    cases = [await world.open_suspected(i, f"Scan of site {i}") for i in (2, 3, 4)]
    items = [{"id": str(c), "expected_version": 1} for c in cases]
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        stale = await post(http, csrf, "/cases/bulk-dismiss",
                           {"items": [*items[:2], {**items[2], "expected_version": 5}],
                            "reason": "attempt_no_impact"})  # fmt: skip
        assert stale.status_code == 409, stale.text
        assert stale.json()["detail"].startswith("Nothing was closed.")
        states = await world.rows("SELECT state FROM cases WHERE id = ANY(CAST(:i AS uuid[]))",
                                  i=cases)  # fmt: skip
        assert {r.state for r in states} == {"suspected"}
        for bad in (
            {"items": [items[0], items[0]], "reason": "benign_expected"},
            {"items": items, "reason": "duplicate"},
            {"items": [], "reason": "benign_expected"},
            {"items": [items[0]] * 26, "reason": "benign_expected"},
            {"items": items, "reason": "risk_accepted"},
        ):
            assert (await post(http, csrf, "/cases/bulk-dismiss", bad)).status_code == 422
        missing = await post(http, csrf, "/cases/bulk-dismiss",
                             {"items": [*items, {"id": str(uuid.uuid4()), "expected_version": 1}],
                              "reason": "benign_expected"})  # fmt: skip
        assert missing.status_code == 404
        done = await post(
            http,
            csrf,
            "/cases/bulk-dismiss",
            {"items": items, "reason": "attempt_no_impact", "note": "one scanner"},
        )
        assert done.status_code == 200, done.text
        closed = done.json()["closed"]
        assert [c["id"] for c in closed] == [str(c) for c in cases]
        assert {c["state"] for c in closed} == {"closed"}
        assert {c["closure_reason"] for c in closed} == {"attempt_no_impact"}
    mina = await world.user_id("mina")
    events = await world.rows(
        "SELECT actor FROM case_events WHERE kind = 'dismissed' AND case_id ="
        " ANY(CAST(:i AS uuid[]))",
        i=cases,
    )
    assert [e.actor for e in events] == [f"user:{mina}"] * 3
    [entry] = await audits(world, "case.bulk_dismiss")
    assert entry.details["reason"] == "attempt_no_impact"


async def test_bulk_dismiss_needs_the_case_and_review_capabilities(world: World) -> None:
    case = await world.open_suspected(4)
    body = {"items": [{"id": str(case), "expected_version": 1}], "reason": "benign_expected"}
    for user in ("vera", "rita", "max"):
        async with world.app() as http:
            csrf = await sign_in(http, user)
            got = await post(http, csrf, "/cases/bulk-dismiss", body)
            assert got.status_code == 403, (user, got.text)
    assert (await world.rows("SELECT state FROM cases WHERE id = :c", c=case))[0].state == (
        "suspected"
    )


# --------------------------------------------------------------- bulk review of alert groups


async def member_versions(world: World, ids: list[uuid.UUID]) -> list[dict[str, Any]]:
    rows = await world.rows(
        "SELECT i.id, i.version, (SELECT max(r.id) FROM review_events r"
        " WHERE r.investigation_id = i.id) AS latest FROM investigations i"
        " WHERE i.id = ANY(CAST(:ids AS uuid[]))",
        ids=ids,
    )
    by_id = {r.id: r for r in rows}
    return [{"investigation_id": str(i), "seen_version": int(by_id[i].version),
             "seen_review": by_id[i].latest} for i in ids]  # fmt: skip


async def test_an_incidents_alert_groups_are_reviewed_together_all_or_none(world: World) -> None:
    case = await world.open_case(2, start=0)
    suspected = await world.open_suspected(4)
    members = world.investigations[:2]
    items = await member_versions(world, members)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")  # review is enough
        outsider = await post(
            http,
            csrf,
            f"/cases/{case}/members/reviews",
            {
                "action": "reviewed",
                "outcome": "benign_expected",
                "items": await member_versions(world, [world.investigations[5]]),
            },
        )
        assert outsider.status_code == 422
        stale = await post(
            http,
            csrf,
            f"/cases/{case}/members/reviews",
            {
                "action": "reviewed",
                "outcome": "benign_expected",
                "items": [items[0], {**items[1], "seen_version": 99}],
            },
        )
        assert stale.status_code == 409, stale.text
        assert await world.rows("SELECT id FROM review_events") == []
        no_outcome = await post(http, csrf, f"/cases/{case}/members/reviews",
                                {"action": "reviewed", "items": items})  # fmt: skip
        assert no_outcome.status_code == 422
        follow_outcome = await post(http, csrf, f"/cases/{case}/members/reviews",
                                    {"action": "follow_up", "outcome": "benign_policy",
                                     "items": items})  # fmt: skip
        assert follow_outcome.status_code == 422
        done = await post(
            http,
            csrf,
            f"/cases/{case}/members/reviews",
            {"action": "reviewed", "outcome": "true_positive", "items": items},
        )
        assert done.status_code == 201, done.text
        assert [r["investigation_id"] for r in done.json()["reviews"]] == [str(i) for i in members]
        real_on_possible = await post(
            http, csrf, f"/cases/{suspected}/members/reviews",
            {"action": "reviewed", "outcome": "true_positive",
             "items": await member_versions(world, [world.investigations[4]])},
        )  # fmt: skip
        assert real_on_possible.status_code == 409
        assert "confirmed incident" in real_on_possible.json()["detail"]
        harmless = await post(
            http, csrf, f"/cases/{suspected}/members/reviews",
            {"action": "follow_up",
             "items": await member_versions(world, [world.investigations[4]])},
        )  # fmt: skip
        assert harmless.status_code == 201, harmless.text
    async with world.app() as http:
        csrf = await sign_in(http, "vera")
        refused = await post(http, csrf, f"/cases/{case}/members/reviews",
                             {"action": "follow_up", "items": items})  # fmt: skip
        assert refused.status_code == 403
    rita = await world.user_id("rita")
    reviews = await world.rows("SELECT user_id, outcome FROM review_events ORDER BY id")
    assert [(r.user_id, r.outcome) for r in reviews] == [
        (rita, "true_positive"),
        (rita, "true_positive"),
        (rita, None),
    ]
    assert len(await audits(world, "case.members_reviewed")) == 2


# --------------------------------------------------------------------------- A8 undo


async def test_the_person_who_dismissed_may_undo_it_at_once_without_reopen(world: World) -> None:
    case = await world.open_suspected(4)
    other = await world.open_suspected(5)
    async with world.app() as http:
        csrf = await sign_in(http, "nora")  # no reopen capability
        closed = await post(http, csrf, f"/cases/{case}/dismiss",
                            {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert closed.status_code == 200
        page = await http.get(f"{V1}/cases/{case}")
        assert page.json()["undo_until"] is not None
        reopen = await post(http, csrf, f"/cases/{case}/reopen",
                            {"expected_version": 2, "reason": "oops"})  # fmt: skip
        assert reopen.status_code == 403
        undone = await post(http, csrf, f"/cases/{case}/undo-dismissal", {"expected_version": 2})
        assert undone.status_code == 200, undone.text
        assert undone.json()["case"]["state"] == "suspected"
        twice = await post(http, csrf, f"/cases/{case}/undo-dismissal", {"expected_version": 3})
        assert twice.status_code == 409
    async with world.app() as http:  # someone else's dismissal is not theirs to undo
        csrf = await sign_in(http, "mina")
        shut = await post(http, csrf, f"/cases/{other}/dismiss",
                          {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert shut.status_code == 200
    async with world.app() as http:
        csrf = await sign_in(http, "nora")
        page = await http.get(f"{V1}/cases/{other}")
        assert page.json()["undo_until"] is None
        theirs = await post(http, csrf, f"/cases/{other}/undo-dismissal", {"expected_version": 2})
        assert theirs.status_code == 409
        missing = await post(http, csrf, f"/cases/{uuid.uuid4()}/undo-dismissal",
                             {"expected_version": 2})  # fmt: skip
        assert missing.status_code == 404
    nora = await world.user_id("nora")
    events = await world.rows(
        "SELECT kind, actor, details ->> 'reason' AS reason FROM case_events WHERE case_id = :c"
        " ORDER BY case_version",
        c=case,
    )
    assert [(e.kind, e.actor) for e in events][-1] == ("reopened", f"user:{nora}")
    assert events[-1].reason == "Undone by Nora NoReopen right after closing it"


# ------------------------------------------------------------------- A14 sent, A16 a step


async def test_sent_to_the_ciso_needs_a_confirmed_incident_and_its_report(world: World) -> None:
    from tests.integration.web.test_incident_report_ar7 import a_case, write_report

    possible = await world.open_suspected(4)
    case = await a_case(world, 2)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        none_yet = await post(http, csrf, f"/cases/{case}/sent",
                              {"to": "ciso", "report_version": 1})  # fmt: skip
        assert none_yet.status_code == 404
        version = await write_report(world, case)
        too_soon = await post(http, csrf, f"/cases/{possible}/sent",
                              {"to": "ciso", "report_version": 1})  # fmt: skip
        assert too_soon.status_code == 409
        triage = await write_report(world, possible)  # a possible incident's triage report
        shut = await post(http, csrf, f"/cases/{possible}/dismiss",
                          {"expected_version": 1, "reason": "attempt_no_impact"})  # fmt: skip
        assert shut.status_code == 200, shut.text
        never = await post(http, csrf, f"/cases/{possible}/sent",
                           {"to": "ciso", "report_version": triage})  # fmt: skip
        assert never.status_code == 409, never.text  # dismissed, never confirmed
        bad = await post(http, csrf, f"/cases/{case}/sent", {"to": "press", "report_version": 1})
        assert bad.status_code == 422
        sent = await post(http, csrf, f"/cases/{case}/sent",
                          {"to": "ciso", "report_version": version})  # fmt: skip
        assert sent.status_code == 201, sent.text
        assert sent.json()["by"] == "Mina Manager"
        double = await post(http, csrf, f"/cases/{case}/sent",
                            {"to": "ciso", "report_version": version})  # fmt: skip
        assert double.json()["at"] == sent.json()["at"]  # a double click is one record
        report = await http.get(f"{V1}/cases/{case}/report")
        assert report.json()["sent"]["report_version"] == version
        assert report.json()["glance"]["alerts"] >= 1
        listed = await http.get(f"{V1}/incident-reports")
        row = next(r for r in listed.json()["items"] if r["case_id"] == str(case))
        assert row["sent"]["by"] == "Mina Manager"
        assert row["version"] == version
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        refused = await post(http, csrf, f"/cases/{case}/sent",
                             {"to": "ciso", "report_version": version})  # fmt: skip
        assert refused.status_code == 403
    assert len(await audits(world, "case.report_sent")) == 1


async def test_a_step_not_advised_is_refused_and_nothing_is_recorded(world: World) -> None:
    case = await world.open_case(1, start=6)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        unknown = await post(http, csrf, f"/cases/{case}/actions/nothing.here/done",
                             {"attestation": "done by the lab"})  # fmt: skip
        assert unknown.status_code == 422, unknown.text
        bad_id = await post(http, csrf, f"/cases/{case}/actions/NOT-AN-ID/done",
                            {"attestation": "done"})  # fmt: skip
        assert bad_id.status_code == 422
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        refused = await post(http, csrf, f"/cases/{case}/actions/nothing.here/done",
                             {"attestation": "done"})  # fmt: skip
        assert refused.status_code == 403
    assert await world.rows("SELECT id FROM case_actions") == []
