"""Q-B3 review findings that need the database or a browser: each test carries its finding number.

The reviewer's repros keep their names; where a decision of the lead changed what a test expects,
the test says so. The rest are the fixer's."""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals
from argus.web import casepages
from tests.integration.web.b2_support import Watch, open_context
from tests.integration.web.b3_support import (
    MANAGER,
    V1,
    Live,
    World,
    make_world,
    post,
    request_closure,
    sign_in,
    start_server,
    step_up,
    stepped,
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


HEX = "0" * 64


async def ask(world: World, case: object, reason: str = "benign_expected", *, by: str = "mina",
              note: str | None = None, version: int = 1) -> dict[str, Any]:  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, by)
        asked = await request_closure(http, csrf, case, reason, version=version, note=note)
        assert asked.status_code == 201, asked.text
        body: dict[str, Any] = asked.json()
        return body


async def benign_group(world: World, n: int, reason: str = "benign_expected") -> list[int]:
    ids = []
    for k in range(n):
        case = await world.open_case(1, title=f"Case {k}", start=k)
        ids.append(int((await ask(world, case, reason))["request_id"]))
    return ids


# R3-1 (major): the group a person approves is the one the server formed, not one the client chose
async def decide(
    http: httpx.AsyncClient, csrf: str, rid: int, digest: str, group: list[int] | None = None
) -> httpx.Response:
    body: dict[str, Any] = {"decision": "approved", "payload_hash": digest}
    if group is not None:
        body["group"] = group
    return await post(http, csrf, f"/approvals/{rid}/decision", body)


def a_set_whose_sample_leaves_out(target: int, ids: list[int]) -> list[int]:
    """A subset of ``ids`` holding ``target`` whose own sample does not hold it."""
    for size in range(4, len(ids)):
        for combo in itertools.combinations(ids, size):
            if target in combo:
                smaller = approvals.sample(combo, casepages.group_seed(combo))
                if target not in smaller:
                    return list(combo)
    raise AssertionError("no such set")


async def test_r3_1_a_group_is_the_one_the_server_formed(world: World) -> None:
    ids = await benign_group(world, 8)
    async with stepped(world, "oona") as (http, csrf):
        q = (await http.get(f"{V1}/approvals")).json()
        [group] = q["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        assert sorted(hashes) == sorted(ids)
        # a request the server would have made the person look at ...
        target = sorted(group["sample"])[0]
        # ... left out of the sample by choosing a different set around it
        chosen = a_set_whose_sample_leaves_out(target, ids)
        for rid in approvals.sample(chosen, casepages.group_seed(chosen)):
            one = await decide(http, csrf, rid, hashes[rid], chosen)
            assert one.status_code == 409, one.text  # not a group ARGUS formed
            assert "not a group ARGUS formed" in one.json()["detail"], one.text
        items = [{"request_id": i, "payload_hash": hashes[i]} for i in chosen]
        done = await post(http, csrf, "/approvals/group", {"items": items})
        assert done.status_code == 409, done.text
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_r3_1_a_group_one_request_short_of_the_servers_is_not_one_either(
    world: World,
) -> None:
    ids = await benign_group(world, 6)
    async with stepped(world, "oona") as (http, csrf):
        [group] = (await http.get(f"{V1}/approvals")).json()["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        short = sorted(ids)[:-1]
        sample = approvals.sample(short, casepages.group_seed(short))
        one = await decide(http, csrf, sample[0], hashes[sample[0]], short)
        assert one.status_code == 409, one.text
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_r3_1_the_servers_group_is_approved_sample_then_rest(world: World) -> None:
    ids = await benign_group(world, 8)
    async with stepped(world, "oona") as (http, csrf):
        [group] = (await http.get(f"{V1}/approvals")).json()["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        for rid in group["sample"]:
            one = await decide(http, csrf, rid, hashes[rid], ids)
            assert one.status_code == 200, one.text  # the group shrinks as it is worked through
        items = [{"request_id": i, "payload_hash": hashes[i]} for i in ids]
        done = await post(http, csrf, "/approvals/group", {"items": items})
        assert done.status_code == 200, done.text
    assert len(await world.rows("SELECT id FROM approval_decisions")) == 8


async def test_r3_1_a_second_sample_step_must_keep_to_the_batch_the_first_recorded(
    world: World,
) -> None:
    """The first decision of a group is the one the server checks; the next ones are held to the
    batch it recorded, so the set cannot be swapped for another halfway."""
    ids = await benign_group(world, 8)
    async with stepped(world, "oona") as (http, csrf):
        [group] = (await http.get(f"{V1}/approvals")).json()["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        first, second = sorted(group["sample"])[:2]
        assert (await decide(http, csrf, first, hashes[first], ids)).status_code == 200
        other = next(
            sorted(set(ids) - {drop})
            for drop in ids
            if drop not in (first, second)
            and first
            in approvals.sample(
                sorted(set(ids) - {drop}), casepages.group_seed(sorted(set(ids) - {drop}))
            )
        )  # a set that keeps the first step's request in its sample, but is not its batch
        swapped = await decide(http, csrf, second, hashes[second], other)
        assert swapped.status_code == 409, swapped.text
        assert "another group" in swapped.json()["detail"], swapped.text
        assert (await decide(http, csrf, second, hashes[second], ids)).status_code == 200
    assert len(await world.rows("SELECT id FROM approval_decisions")) == 2


# R3-3 (follows from R3-1): overlapping groups, and a decision against a group's rest, at once
async def concurrent_posts(
    world: World, monkeypatch: pytest.MonkeyPatch, slow: bool, first_set: list[int],
    second_set: list[int], hashes: dict[int, str], group_a: list[int], group_b: list[int],
) -> list[Any]:  # fmt: skip
    import asyncio

    from argus.cases.desk import ApprovalDesk

    async with world.app() as omar, world.app() as oona:
        co, ci = await sign_in(omar, "omar"), await sign_in(oona, "oona")
        await step_up(omar, co)
        await step_up(oona, ci)
        for http, csrf, group in ((omar, co, group_a), (oona, ci, group_b)):
            for rid in approvals.sample(group, casepages.group_seed(group)):
                r = await decide(http, csrf, rid, hashes[rid], group)
                assert r.status_code in (200, 409), r.text  # a set the server formed, or not
        if slow:
            original = ApprovalDesk.decide

            async def widened(self: ApprovalDesk, *args: Any, **kwargs: Any) -> Any:
                out = await original(self, *args, **kwargs)
                await asyncio.sleep(0.4)  # the window two people at once would rarely hit
                return out

            monkeypatch.setattr(ApprovalDesk, "decide", widened)
        items_a = [{"request_id": i, "payload_hash": hashes[i]} for i in first_set]
        items_b = [{"request_id": i, "payload_hash": hashes[i]} for i in second_set]
        first = asyncio.ensure_future(post(omar, co, "/approvals/group", {"items": items_a}))
        await asyncio.sleep(0.2)
        second = asyncio.ensure_future(post(oona, ci, "/approvals/group", {"items": items_b}))
        return list(await asyncio.gather(first, second, return_exceptions=True))


@pytest.mark.parametrize("slow", [True, False])
async def test_r3_3_overlapping_groups_approved_at_once_do_not_deadlock(
    world: World, monkeypatch: pytest.MonkeyPatch, slow: bool
) -> None:
    import random

    ids = await benign_group(world, 12)
    rng = random.Random(7)
    pick: tuple[list[int], list[int]] | None = None
    for _ in range(20000):
        a = sorted(rng.sample(ids, rng.randint(5, 7)))
        b = sorted(rng.sample(ids, rng.randint(5, 7)))
        sa = approvals.sample(a, casepages.group_seed(a))
        sb = approvals.sample(b, casepages.group_seed(b))
        ra = [i for i in a if i not in sa]
        rb = [i for i in b if i not in sb]
        if set(sa) & set(b) or set(sb) & set(a) or not ra or not rb:
            continue
        if ra[0] not in rb and rb[0] in ra[1:] and ra[0] < rb[0]:
            pick = (a, b)
            break
    assert pick is not None, "no pair of overlapping sets found"
    a, b = pick
    async with stepped(world, "omar") as (http, _csrf):
        q = (await http.get(f"{V1}/approvals")).json()
    hashes = {p["id"]: p["payload_hash"] for p in q["pending"]}
    got = await concurrent_posts(world, monkeypatch, slow, a, b, hashes, a, b)
    codes = [g.status_code if isinstance(g, httpx.Response) else repr(g)[:80] for g in got]
    assert all(isinstance(c, int) and c < 500 for c in codes), f"a database deadlock became {codes}"
    assert codes == [409, 409], codes  # neither is a group the server formed
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_r3_3_a_decision_against_a_groups_rest_at_once_is_a_retry_not_an_outage(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one deadlock the page can still reach: one person approves a group's rest (the cases
    in order, the chain lock kept) while another decides one of those requests alone (that case's
    lock first, then the chain). The database ends one; it is a 409 to ask again, not a 503."""
    import asyncio

    from argus.cases.desk import ApprovalDesk, SessionProof

    ids = await benign_group(world, 6)
    async with world.app() as omar, world.app() as oona:
        co, ci = await sign_in(omar, "omar"), await sign_in(oona, "oona")
        await step_up(omar, co)
        await step_up(oona, ci)
        [group] = (await omar.get(f"{V1}/approvals")).json()["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        for rid in group["sample"]:
            assert (await decide(omar, co, rid, hashes[rid], ids)).status_code == 200
        rest = sorted(i for i in ids if i not in group["sample"])
        mine = (await world.rows("SELECT id FROM users WHERE username = 'omar'"))[0].id
        original = ApprovalDesk.decide

        async def widened(
            self: ApprovalDesk, session: SessionProof, *args: Any, **kwargs: Any
        ) -> Any:
            out = await original(self, session, *args, **kwargs)
            if session.user_id == mine:
                await asyncio.sleep(0.5)  # omar holds the chain lock while he reads the next
            return out

        monkeypatch.setattr(ApprovalDesk, "decide", widened)
        items = [{"request_id": i, "payload_hash": hashes[i]} for i in ids]
        first = asyncio.ensure_future(post(omar, co, "/approvals/group", {"items": items}))
        await asyncio.sleep(0.25)
        second = asyncio.ensure_future(decide(oona, ci, rest[1], hashes[rest[1]]))
        got = await asyncio.gather(first, second, return_exceptions=True)
    codes = [g.status_code if isinstance(g, httpx.Response) else repr(g)[:80] for g in got]
    assert all(isinstance(c, int) and c < 500 for c in codes), f"a database deadlock became {codes}"
    retried = [g for g in got if isinstance(g, httpx.Response) and g.status_code == 409]
    for r in retried:
        assert "same moment" in r.json()["detail"], r.text


async def test_r3_3_a_deadlock_is_a_409_and_any_other_database_failure_a_503(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psycopg.errors
    from sqlalchemy.exc import OperationalError

    from argus.cases.desk import ApprovalDesk

    await benign_group(world, 3)
    raised: list[Exception] = []

    async def fails(*args: Any, **kwargs: Any) -> Any:
        raise raised[0]

    monkeypatch.setattr(ApprovalDesk, "decide", fails)
    async with stepped(world, "oona") as (http, csrf):
        pending = (await http.get(f"{V1}/approvals")).json()["pending"][0]
        for error, status in (
            (psycopg.errors.DeadlockDetected("deadlock detected"), 409),
            (psycopg.errors.SerializationFailure("could not serialize"), 409),
            (psycopg.errors.AdminShutdown("terminating connection"), 503),
        ):
            raised[:] = [OperationalError("stmt", {}, error)]
            got = await decide(http, csrf, pending["id"], pending["payload_hash"])
            assert got.status_code == status, (type(error).__name__, got.text)
            if status == 409:
                assert "same moment" in got.json()["detail"]


# R3-2 (major, design choice 1): the web's login writes the case record in the name it likes.
# Decision 22: argus-web is runtime-equivalent for the case record; the database ties what it can
# (a case event is the person's own, a member or indicator is added by a person, no W1 write) and
# the rest is the session's. The notes and whose person it is are the accepted limit.
async def test_r3_2a_a_note_in_another_active_persons_name_is_the_accepted_limit(
    world: World,
) -> None:
    """The database cannot know which person a web session is: a web process that is hijacked can
    write a note (or an event) under any existing user's id. This test pins that limit, which the
    gate report names; a stronger rule would change it."""
    case = await world.open_case(1)
    other = await world.user_id("omar")
    async with world.web.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_notes (case_id, author_user_id, body) VALUES (:c, :u, 'forged')"
            ),
            {"c": case, "u": other},
        )
    rows = await world.rows("SELECT author_user_id FROM case_notes WHERE case_id = :c", c=case)
    assert [r.author_user_id for r in rows] == [other]


async def forge(world: World, case: object, *, actor: str, actor_user_id: int | None) -> str:
    """The web's login moves a case one step and records the event as given (raw SQL: what a
    buggy or hijacked web process can do); returns the database's refusal."""
    other = await world.user_id("omar")

    async def move() -> None:
        async with world.web.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE cases SET state = 'assigned', owner_user_id = :o, version = 2"
                    " WHERE id = :c"
                ),
                {"c": case, "o": other},
            )
            await conn.execute(
                text(
                    "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                    " from_state, to_state, details, kibana_rows) VALUES (:c, 2, 'assigned',"
                    " :a, :u, 'open', 'assigned', '{}', 0)"
                ),
                {"c": case, "a": actor, "u": actor_user_id},
            )

    with pytest.raises(DBAPIError) as info:
        await move()
    return str(info.value.orig)


async def test_r3_2b_the_web_login_cannot_record_a_case_event_in_arguss_voice(
    world: World,
) -> None:
    case = await world.open_case(1)
    for actor in ("argus", "argus:opener", "cli", "system"):
        said = await forge(world, case, actor=actor, actor_user_id=None)
        assert "only as the person who acted" in said, said
    row = (await world.rows("SELECT state, version FROM cases WHERE id = :c", c=case))[0]
    assert (row.state, row.version) == ("open", 1)


async def test_r3_2b_the_web_login_cannot_attribute_a_case_event_to_someone_else(
    world: World,
) -> None:
    """An actor and the user id behind it must be the same person; a name with no id is refused."""
    case = await world.open_case(1)
    omar, mina = await world.user_id("omar"), await world.user_id("mina")
    for actor, uid in ((f"user:{omar}", mina), (f"user:{omar}", None), (f"user:{mina}", omar),
                       (f"user:{omar} ", omar), (f"user: {omar}", omar)):  # fmt: skip
        said = await forge(world, case, actor=actor, actor_user_id=uid)
        assert "only as the person who acted" in said, (actor, uid, said)


async def test_r3_2b_an_event_as_the_person_who_acted_is_what_the_web_may_write(
    world: World,
) -> None:
    """The control (and the accepted limit): the same step recorded as ``user:<id>`` with that id
    goes through, whose id it is being the session's to say."""
    case = await world.open_case(1)
    omar = await world.user_id("omar")
    async with world.web.begin() as conn:
        await conn.execute(
            text(
                "UPDATE cases SET state = 'assigned', owner_user_id = :o, version = 2 WHERE id = :c"
            ),
            {"c": case, "o": omar},
        )
        await conn.execute(
            text(
                "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                " from_state, to_state, details, kibana_rows) VALUES (:c, 2, 'assigned', :a, :o,"
                " 'open', 'assigned', '{}', 0)"
            ),
            {"c": case, "a": f"user:{omar}", "o": omar},
        )
    row = (await world.rows("SELECT state, owner_user_id FROM cases WHERE id = :c", c=case))[0]
    assert (row.state, row.owner_user_id) == ("assigned", omar)


async def test_r3_2c_the_web_login_adds_members_and_indicators_only_as_a_person(
    world: World,
) -> None:
    case = await world.open_case(1)
    mina = await world.user_id("mina")
    indicator = (
        "INSERT INTO case_indicators (case_id, kind, value, role, source, added_version,"
        " added_by) VALUES (:c, 'ip', '203.0.113.9', 'actor', 'investigation', 1, :by)"
    )
    member = (
        "INSERT INTO case_members (case_id, investigation_id, link, link_value, added_version,"
        " added_by) VALUES (:c, :i, 'person', NULL, 1, :by)"
    )
    for sql in (indicator, member):
        for by in ("argus:opener", "argus", "user:", "user:0", "cli", f"user:{mina}x", ""):
            with pytest.raises(DBAPIError) as info:
                async with world.web.begin() as conn:
                    await conn.execute(text(sql), {"c": case, "i": world.investigations[3],
                                                   "by": by})  # fmt: skip
            assert "only as a person" in str(info.value.orig), (by, str(info.value.orig))
    # a person's name goes through the trigger (the statement may still fail for another reason)
    async with world.web.begin() as conn:
        await conn.execute(text(indicator), {"c": case, "by": f"user:{mina}"})
    assert len(await world.rows("SELECT 1 FROM case_indicators WHERE value = '203.0.113.9'")) == 1


async def test_r3_2d_the_web_login_plans_no_w1_write_to_kibana(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A command from a page changes or closes a Kibana case (W2, W3); a W1 write opens or
    comments one, which only ARGUS does. The service is made to plan one from the web's login."""
    from argus.cases import kibana
    from argus.cases.machine import Take
    from argus.cases.model import Actor
    from argus.cases.service import CaseService

    case = await world.open_case(1, kibana=True)
    mina = await world.user_id("mina")
    monkeypatch.setattr(
        kibana,
        "update",
        lambda *a, **k: [kibana.PlannedWrite("W1", "comment", {"template": "x", "params": {}})],
    )
    who = Actor.person(mina, frozenset(c.value for c in MANAGER), via="test")
    with pytest.raises(DBAPIError) as info:
        async with world.web.begin() as conn:
            await (await CaseService.start(conn)).apply(who, case, Take(), expected_version=1)
    assert "opens or comments a Kibana case" in str(info.value.orig)
    monkeypatch.undo()
    async with world.web.begin() as conn:  # the same command with its own W2 writes goes through
        await (await CaseService.start(conn)).apply(who, case, Take(), expected_version=1)


async def test_r3_2e_the_web_login_cannot_plan_a_closing_write_without_its_approval(
    world: World,
) -> None:
    """Already true before the review (the table's CHECK and ``argus_outbox_guard``); kept so a
    change to either shows here."""
    case = await world.open_case(1, kibana=True)
    event = (await world.rows("SELECT id FROM case_events WHERE case_id = :c", c=case))[0].id
    with pytest.raises(DBAPIError):
        async with world.web.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
                    " write_class, op, payload, payload_hash) VALUES (:c, :e, 0, 'x', 'W3',"
                    " 'close', '{\"status\": \"closed\"}', repeat('a', 64))"
                ),
                {"c": case, "e": event},
            )


async def test_r3_2f_the_doctor_sees_a_missing_or_disabled_web_trigger(
    world: World, migrated_engine: AsyncEngine
) -> None:
    from argus.db import migrate

    assert await migrate.missing_guard_triggers(migrated_engine) == []
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE case_events DISABLE TRIGGER case_events_web_writes"))
        await conn.execute(text("DROP TRIGGER kibana_outbox_web_writes ON kibana_outbox"))
    assert await migrate.missing_guard_triggers(migrated_engine) == [
        "case_events.case_events_web_writes",
        "kibana_outbox.kibana_outbox_web_writes",
    ]


# R3-10 (minor): a view-only account is handed the list of everyone who can be assigned a case
async def test_r3_10_a_view_only_session_is_not_given_the_people_list(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "vera")  # view only: every action is disabled
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert not any(a["enabled"] for a in detail["actions"])
    assert detail["assignees"] == [], (
        f"{len(detail['assignees'])} usernames sent to a view-only account"
    )


async def test_r3_10_only_an_account_that_may_assign_is_given_the_people(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "rita")  # may review, may not manage cases
        assert (await http.get(f"{V1}/cases/{case}")).json()["assignees"] == []
    async with world.app() as http:
        await sign_in(http, "mina")
        people = (await http.get(f"{V1}/cases/{case}")).json()["assignees"]
    assert {"omar", "oona", "vera"} <= {p["username"] for p in people}


# R3-11 (minor): what the case page cuts off, it cuts off without a word
async def test_r3_11_a_case_with_more_notes_than_the_page_shows_says_so(world: World) -> None:
    case = await world.open_case(1)
    me = await world.user_id("mina")
    async with world.runtime.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_notes (case_id, author_user_id, body)"
                " SELECT :c, :u, 'note ' || g FROM generate_series(1, 230) g"
            ),
            {"c": case, "u": me},
        )
    async with world.app() as http:
        await sign_in(http, "mina")
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert len(detail["notes"]) == 200
    # the response says how many there are, and the page prints "N older notes are not shown"
    assert any(key.startswith("notes_") for key in detail), (
        "30 notes vanish with no sign that they exist"
    )
    assert detail["notes_total"] == 230


async def test_r3_11_every_list_the_case_page_cuts_says_how_many_there_are(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.cases.model import Indicator

    marks = tuple(Indicator("ip", f"10.1.0.{n}", "actor") for n in range(1, 4))
    case = await world.open_case(1, kibana=True, indicators=marks)
    me = await world.user_id("mina")
    async with world.runtime.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_notes (case_id, author_user_id, body) SELECT :c, :u, 'n' || g"
                 " FROM generate_series(1, 3) g"),
            {"c": case, "u": me},
        )  # fmt: skip
        await conn.execute(
            text("INSERT INTO kibana_findings (found_at, kind, severity, case_id, dedupe_key)"
                 " SELECT now(), 'person_commented', 'info', :c, 'k' || g"
                 " FROM generate_series(1, 3) g"),
            {"c": case},
        )  # fmt: skip
        for other in world.investigations[3:5]:
            await conn.execute(
                text("INSERT INTO case_suggestions (investigation_id, case_id, link, link_value,"
                     " kind, why) VALUES (:i, :c, 'c2', '1.2.3.4', 'shared', 'shared address')"),
                {"i": other, "c": case},
            )  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        assert (
            await post(http, csrf, f"/cases/{case}/take", {"expected_version": 1})
        ).status_code == 200
        asked = await request_closure(http, csrf, case, "benign_expected", version=2)
        assert asked.status_code == 201, asked.text
        for name in ("NOTES", "INDICATORS", "HISTORY", "TIMELINE", "FINDINGS", "WRITES",
                     "APPROVALS", "SUGGESTIONS"):  # fmt: skip
            monkeypatch.setattr(casepages, f"DETAIL_{name}", 1)
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert (len(detail["notes"]), detail["notes_total"]) == (1, 3)
    assert (len(detail["indicators"]), detail["indicators_total"]) == (1, 3)
    assert (len(detail["suggestions"]), detail["suggestions_total"]) == (1, 2)
    assert (len(detail["mirror"]["findings"]), detail["mirror"]["findings_total"]) == (1, 3)
    assert (len(detail["mirror"]["writes"]), detail["mirror"]["writes_total"]) == (1, 3)
    assert (len(detail["approvals"]), detail["approvals_total"]) == (1, 1)
    # opened, taken, the request's event, the request and the member's alerts
    assert len(detail["history"]) == 1
    assert detail["history_total"] >= 4
    assert len(detail["timeline"]) == 1
    assert detail["timeline_total"] >= 2
    assert detail["children_total"] == 0


async def test_r3_11_nothing_is_said_to_be_missing_when_nothing_is(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "mina")
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert detail["notes_total"] == len(detail["notes"]) == 0
    assert detail["indicators_total"] == len(detail["indicators"])
    assert detail["history_total"] == len(detail["history"]) == 1
    assert detail["timeline_total"] == len(detail["timeline"])
    assert detail["mirror"]["writes_total"] == len(detail["mirror"]["writes"])
    assert detail["approvals_total"] == len(detail["approvals"]) == 0


# R3-12 (minor): a request whose alerts changed since it was asked for goes in no batch
async def test_r3_12_a_request_whose_alerts_changed_is_not_approved_in_a_batch_unseen(
    world: World,
) -> None:
    from datetime import UTC, datetime

    from tests.integration.cases.conftest import _alert

    ids = await benign_group(world, 4)
    async with world.owner.begin() as conn:  # new alerts reach the first case after it was asked
        await _alert(conn, "late-alert-1", world.investigations[0], datetime.now(UTC))
    async with stepped(world, "oona") as (http, csrf):
        queue = (await http.get(f"{V1}/approvals")).json()
        changed = [p for p in queue["pending"] if p["alerts_same"] is False]
        assert [p["id"] for p in changed] == [ids[0]]
        in_a_group = {i["request_id"] for g in queue["groups"] for i in g["items"]}
        assert changed[0]["id"] not in in_a_group, (
            "bundled into a batch whose rest shows only a title"
        )
        # the other three are still a group, and a group that names the changed one is refused
        [group] = queue["groups"]
        assert sorted(i["request_id"] for i in group["items"]) == sorted(ids[1:])
        hashes = {p["id"]: p["payload_hash"] for p in queue["pending"]}
        named = await decide(http, csrf, ids[1], hashes[ids[1]], ids)
        assert named.status_code == 409, named.text
        assert "alerts changed since it was asked for" in named.json()["detail"], named.text
        assert "request" not in named.json()["detail"].lower().replace("asked", "")
        # the changed one is decided alone, with the warning the card shows
        assert (await decide(http, csrf, ids[0], hashes[ids[0]])).status_code == 200


# Note (c): a person adds at most 30 notes an hour
async def test_a_person_adds_at_most_thirty_notes_an_hour(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for n in range(30):
            made = await post(http, csrf, f"/cases/{case}/notes", {"body": f"note {n}"})
            assert made.status_code == 201, made.text
        over = await post(http, csrf, f"/cases/{case}/notes", {"body": "one too many"})
        assert over.status_code == 422, over.text
        assert over.json()["detail"].startswith("You have added 30 notes in the last hour"), (
            over.text
        )
        # entity notes count with them; a double submit is still answered as one
        entity = await post(http, csrf, "/entity-notes",
                            {"kind": "ip", "value": "10.0.0.1", "body": "also"})  # fmt: skip
        assert entity.status_code == 422, entity.text
        again = await post(http, csrf, f"/cases/{case}/notes", {"body": "note 29"})
        assert again.status_code == 201
        assert again.json()["duplicate"] is True
    async with world.app() as http:  # another person is not held by it
        other = await sign_in(http, "nora")
        assert (
            await post(http, other, f"/cases/{case}/notes", {"body": "mine"})
        ).status_code == 201
    assert len(await world.rows("SELECT id FROM case_notes WHERE body = 'one too many'")) == 0


async def test_notes_older_than_an_hour_do_not_count_against_the_limit(world: World) -> None:
    case = await world.open_case(1)
    omar = await world.user_id("omar")
    async with (
        world.owner.begin() as conn
    ):  # thirty notes from yesterday (the owner may set a time)
        await conn.execute(
            text("INSERT INTO case_notes (case_id, author_user_id, body, created_at)"
                 " SELECT :c, :u, 'old ' || g, now() - interval '2 hours'"
                 " FROM generate_series(1, 30) g"),
            {"c": case, "u": omar},
        )  # fmt: skip
    async with stepped(world, "omar") as (http, csrf):
        assert (await post(http, csrf, f"/cases/{case}/notes", {"body": "now"})).status_code == 201


# R3-4 (minor, accessibility): after a keyboard user approves a request the focus is nowhere
@pytest.fixture
async def live(
    seeded: AsyncEngine,
    web_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    test_database: str,
    make_api_login: Any,
    tmp_path: Path,
) -> AsyncIterator[Live]:
    made = await make_world(seeded, web_engine, migrated_engine, tmp_path)
    async for server in start_server(made, test_database, await make_api_login(), tmp_path):
        yield server


async def test_r3_4_focus_is_not_lost_when_a_decision_removes_the_card_that_had_it(
    live: Live,
) -> None:
    from playwright.async_api import async_playwright

    await benign_group(live.world, 5)
    async with async_playwright() as play:
        browser, context = await open_context(
            play, "chromium", viewport={"width": 1440, "height": 900}
        )
        page = await context.new_page()
        page.set_default_timeout(20_000)
        Watch().attach(page)
        await page.goto(f"{live.url}/signin?next=/app/approvals")
        await page.fill("#username", "omar")
        await page.fill("#password", "correct horse battery")
        await page.click("button[type=submit]")
        await page.wait_for_url("**/app/approvals")
        await page.get_by_role("link", name="Confirm it is you").click()
        await page.fill("#password", "correct horse battery")
        await page.click("button[type=submit]")
        await page.wait_for_url("**/app/approvals")
        await page.get_by_text("Confirmed").first.wait_for()
        await page.get_by_role("button", name="Approve (part of the sample)…").first.focus()
        await page.keyboard.press("Enter")
        await page.get_by_role("button", name="Review the request").first.focus()
        await page.keyboard.press("Enter")
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        await page.keyboard.press("Tab")  # Cancel -> Approve
        await page.keyboard.press("Enter")
        await dialog.wait_for(state="hidden")
        await page.wait_for_timeout(600)
        tag = await page.evaluate("document.activeElement ? document.activeElement.tagName : null")
        inside = await page.evaluate("document.activeElement?.closest('main') !== null")
        await browser.close()
    assert tag not in (None, "BODY"), f"the focus fell to {tag} after the approval"
    assert inside, "the focus left the page's content"
