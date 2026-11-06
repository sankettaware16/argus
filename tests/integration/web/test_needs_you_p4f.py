"""Needs you is one set (UI v2 spec §3.1 term 4, §6.3, Q-2): the Incidents tab
(``GET /cases?view=queue``), its count, and what a page that sends a part of it (Today's cards)
asks for (:func:`argus.web.needsyou.needs_you`) are the same cases for the same person, whatever
the holds on them: a possible incident nobody else is checking, a confirmed one nobody took.

Also here: the server's sentences on the decision bar (A6, A7), the Kibana-posting health (A5) and
the incident an alert group belongs to (A15)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Dismiss, Take
from argus.cases.model import LOCAL_CAPABILITIES, Actor
from argus.cases.service import CaseService
from argus.web import casepages, decisions, needsyou
from tests.integration.web.b3_support import V1, World, make_world, sign_in

pytestmark = pytest.mark.integration
PEOPLE = ("mina", "omar", "nora")


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


@dataclass
class Board:
    """A fixed set of cases in every state the set depends on."""

    open_free: uuid.UUID  # confirmed, nobody took it
    taken: uuid.UUID  # confirmed, taken by omar
    suspected: list[uuid.UUID]
    closed: uuid.UUID  # dismissed
    users: dict[str, int]


async def board(world: World) -> Board:
    users = {name: await world.user_id(name) for name in PEOPLE}
    open_free = await world.open_case(1, start=0, title="Open, nobody took it")
    taken = await world.open_case(1, start=1, title="Taken by omar")
    suspected = [await world.open_suspected(i, f"Possible {i}") for i in range(2, 7)]
    closed = await world.open_suspected(7, "Dismissed")
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        omar = Actor.person(users["omar"], LOCAL_CAPABILITIES | {"manage_cases"}, via="test")
        await service.apply(omar, taken, Take(), expected_version=1)
        mina = Actor.person(users["mina"], LOCAL_CAPABILITIES | {"manage_cases"}, via="test")
        await service.apply(mina, closed, Dismiss("benign_expected"), expected_version=1)
    return Board(open_free, taken, suspected, closed, users)


Hold = tuple[int, str, str]  # (which case, holder, "past" | "soon" | "later" | "ended")
HOLDS = st.lists(
    st.tuples(st.integers(0, 6), st.sampled_from(PEOPLE),
              st.sampled_from(["past", "soon", "later", "ended"])),
    max_size=8, unique_by=lambda h: h[0],
)  # fmt: skip


async def place(world: World, b: Board, holds: list[Hold]) -> dict[uuid.UUID, str]:
    """End every hold, then place these (as the owner: an expired hold is dated in the past).
    Returns the holds that hold: case -> holder."""
    targets = [*b.suspected, b.closed, b.open_free]  # 0-4 possible, 5 closed, 6 confirmed
    now = datetime.now(UTC)
    holding: dict[uuid.UUID, str] = {}
    async with world.owner.begin() as conn:
        await conn.execute(text("UPDATE case_holds SET ended_at = now(), ended_why = 'released'"
                                " WHERE ended_at IS NULL"))  # fmt: skip
        for index, who, when in holds:
            case = targets[index]
            made, until = {
                "past": (now - timedelta(days=2), now - timedelta(hours=1)),
                "soon": (now, now + timedelta(hours=1)),
                "later": (now, now + timedelta(days=3)),
                "ended": (now, now + timedelta(days=3)),
            }[when]
            version = await conn.scalar(text("SELECT version FROM cases WHERE id = :c"),
                                        {"c": case})  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO case_holds (case_id, user_id, reason, until, case_version,"
                    " created_at, ended_at, ended_why) VALUES (:c, :u, 'checking', :t, :v, :m,"
                    " :e, :w)"
                ),
                {"c": case, "u": b.users[who], "t": until, "v": version, "m": made,
                 "e": now if when == "ended" else None,
                 "w": "released" if when == "ended" else None},
            )  # fmt: skip
            if when in ("soon", "later") and index <= 4:
                holding[case] = who
    return holding


def expected(b: Board, holding: dict[uuid.UUID, str], viewer: str) -> set[uuid.UUID]:
    """The spec's definition, written out: possible incidents nobody else is checking, and the
    confirmed incident nobody took."""
    return {b.open_free} | {c for c in b.suspected if holding.get(c, viewer) == viewer}


@given(holds=HOLDS, viewer=st.sampled_from(PEOPLE), page=st.integers(1, 4))
@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])  # fmt: skip
async def test_the_queue_view_its_count_and_todays_needs_you_are_one_set(
    world: World, holds: list[Hold], viewer: str, page: int
) -> None:
    async with world.runtime.connect() as conn:
        built = await conn.scalar(text("SELECT count(*) FROM cases"))
    if not built:
        await board(world)
    b = await _board_of(world)
    holding = await place(world, b, holds)
    me = b.users[viewer]
    want = expected(b, holding, viewer)
    async with world.web.connect() as conn:
        listed: list[uuid.UUID] = []
        offset = 0
        while True:  # the tab, page by page
            got = await casepages.list_cases(conn, me, "queue", offset=offset, limit=page)
            listed += [c.id for c in got.items]
            if not got.has_more:
                break
            offset += page
        first = await casepages.list_cases(conn, me, "queue", offset=0, limit=100)
        cards, total = await needsyou.needs_you(conn, me, limit=page)
        mine = await casepages.list_cases(conn, me, "mine", offset=0, limit=100)
    assert len(listed) == len(set(listed))
    assert set(listed) == want
    assert first.counts.queue == len(want)
    assert total == len(want)
    assert cards == [c.id for c in first.items][:page]  # Today's cards are the tab's first rows
    assert len(cards) + max(0, total - page) == first.counts.queue  # + "more waiting"
    held_by_me = {c for c, who in holding.items() if who == viewer}
    assert held_by_me <= {c.id for c in mine.items}
    if viewer == "omar":
        assert b.taken in {c.id for c in mine.items}
    for row in first.items:
        assert (row.hold is not None) == (row.id in holding)
        if row.hold is not None:
            assert row.hold.mine == (holding[row.id] == viewer)
        assert row.waiting_since is not None


async def _board_of(world: World) -> Board:
    rows = {r.title: r.id for r in await world.rows("SELECT id, title FROM cases")}
    users = {name: await world.user_id(name) for name in PEOPLE}
    return Board(rows["Open, nobody took it"], rows["Taken by omar"],
                 [rows[f"Possible {i}"] for i in range(2, 7)], rows["Dismissed"],
                 users)  # fmt: skip


async def test_the_tab_over_http_says_the_same(world: World) -> None:
    b = await board(world)
    await place(world, b, [(0, "omar", "later"), (1, "mina", "past")])
    async with world.app() as http:
        await sign_in(http, "mina")
        got = await http.get(f"{V1}/cases", params={"view": "queue"})
        body = got.json()
        ids = {uuid.UUID(c["id"]) for c in body["items"]}
        assert ids == expected(b, {b.suspected[0]: "omar"}, "mina")
        assert body["counts"]["queue"] == len(ids)


# --------------------------------------------------------------------------- A6, A7, A5, A15


async def test_the_decision_bar_carries_the_servers_own_sentences(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(decisions, "ROOT", tmp_path)  # no case team switches file here
    case = await world.open_suspected(4)
    async with world.app() as http:
        await sign_in(http, "mina")
        bar = (await http.get(f"{V1}/cases/{case}")).json()["decision"]
    assert bar["dismiss_effect"] == decisions.dismiss_effect()
    assert "two weeks" in bar["dismiss_effect"]
    assert "Posting to Kibana is off" in bar["kibana_after_confirm"]
    assert "Kibana gets" not in bar["kibana_after_confirm"]


async def test_the_kibana_sentence_counts_todays_posts_and_never_promises_one(
    world: World, tmp_path: Path
) -> None:
    @dataclass
    class Team:
        post: bool = True
        per_day: int = 5

    async with world.web.connect() as conn:
        words = await decisions.kibana_after_confirm(conn, Team(), datetime.now(UTC), tmp_path)
        none_left = await decisions.kibana_after_confirm(conn, Team(per_day=0),
                                                         datetime.now(UTC), tmp_path)  # fmt: skip
    assert "5 of today's 5 posts are left" in words
    assert "once a person confirms its incident report" in words
    assert "used up" in none_left


async def test_health_says_whether_confirmed_incidents_reach_kibana(world: World) -> None:
    async with world.app() as http:
        await sign_in(http, "vera")
        before = (await http.get(f"{V1}/health")).json()["case_team"]
        assert before == {"state": "ok", "last_run_at": None, "failing_since": None, "held": 0}
    await world.open_case(1, start=6)  # confirmed, waiting for someone to open it in Kibana
    async with world.app() as http:
        await sign_in(http, "vera")
        after = (await http.get(f"{V1}/health")).json()["case_team"]
    assert (after["state"], after["held"]) == ("waiting", 1)


async def posted(world: World, case: uuid.UUID, number: int) -> None:
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"),
            {"c": case, "i": f"SOC-IR-2026-1107-{number:02d}"},
        )


async def step(world: World, case: uuid.UUID, seq: int, kind: str, state: str,
               sent: datetime, planned: datetime) -> None:  # fmt: skip
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part,"
                " report_version, text_body, request_hash, state, sent_count, sent_at,"
                " verified_at, created_at) VALUES (:c, 1, :n, :k, :kind, :a, 'evidence', 1, 'x',"
                " repeat(CAST(:n AS text), 64), :s, 1, :at,"
                " CASE WHEN :s = 'verified' THEN CAST(:at AS timestamptz) END, :planned)"
            ),
            {"c": case, "n": seq, "k": f"{kind}:{seq}", "kind": kind, "s": state, "at": sent,
             "a": "argus-lead" if kind == "open" else "argus-evidence", "planned": planned},
        )  # fmt: skip


async def health_of(world: World) -> dict[str, Any]:
    async with world.app() as http:
        await sign_in(http, "vera")
        found: dict[str, Any] = (await http.get(f"{V1}/health")).json()["case_team"]
        return found


async def test_health_is_failing_while_a_failed_request_waits_even_after_others_landed(
    world: World,
) -> None:
    """A post's create landed and its next comment failed: the failed step waits for a person,
    so the header says failing (since it was sent), as ``kibana=failing`` lists the case."""
    case = await world.open_case(1, start=6)
    await posted(world, case, 1)
    now = datetime.now(UTC)
    planned = now - timedelta(hours=1)  # a generation's steps are all written when planned
    await step(world, case, 1, "open", "verified", now - timedelta(minutes=49), planned)
    failed_at = now - timedelta(minutes=40)
    await step(world, case, 2, "comment", "failed", failed_at, planned)
    health = await health_of(world)
    assert health["state"] == "failing"
    assert datetime.fromisoformat(health["failing_since"]) == failed_at
    async with world.app() as http:
        await sign_in(http, "vera")
        listed = await http.get(f"{V1}/cases", params={"view": "all", "kibana": "failing"})
    assert [c["id"] for c in listed.json()["items"]] == [str(case)]
    other = await world.open_case(1, start=7)  # another case posts fine afterwards
    await posted(world, other, 2)
    await step(world, other, 1, "open", "verified", now, now)
    still = await health_of(world)
    assert (still["state"], still["failing_since"]) == ("failing", health["failing_since"])
    async with world.owner.begin() as conn:  # a person decides it: skipped, nothing waits
        await conn.execute(
            text("UPDATE case_team_steps SET state = 'skipped' WHERE state = 'failed'")
        )
    done = await health_of(world)
    assert (done["state"], done["failing_since"]) == ("waiting", None)


async def test_an_alert_group_names_the_incident_it_belongs_to(world: World) -> None:
    case = await world.open_suspected(4, "Possible beacon")
    async with world.app() as http:
        await sign_in(http, "vera")
        inside = (await http.get(f"{V1}/investigations/{world.investigations[4]}")).json()
        outside = (await http.get(f"{V1}/investigations/{world.investigations[5]}")).json()
    assert inside["case"] == {"id": str(case), "number": inside["case"]["number"],
                              "title": "Possible beacon", "state": "suspected"}  # fmt: skip
    assert outside["case"] is None


# --------------------------------------------------------------------------- A10 filters


async def test_the_list_filters_by_who_took_it_and_kibana_and_sorts_by_waiting(
    world: World,
) -> None:
    b = await board(world)
    async with world.app() as http:
        await sign_in(http, "omar")

        async def ids(**params: str) -> list[str]:
            got = await http.get(f"{V1}/cases", params={"view": "all", **params})
            assert got.status_code == 200, got.text
            return [c["id"] for c in got.json()["items"]]

        assert await ids(taken_by="me") == [str(b.taken)]
        assert await ids(taken_by="omar") == [str(b.taken)]
        assert str(b.taken) not in await ids(taken_by="nobody")
        assert await ids(taken_by="nosuchperson") == []
        # the confirmed ones, neither in Kibana yet
        assert set(await ids(kibana="waiting")) == {str(b.open_free), str(b.taken)}
        assert await ids(kibana="in") == []
        assert await ids(kibana="failing") == []
        waiting = await ids(sort="waiting")
        assert waiting[0] == str(b.open_free)  # the first case made waits longest
        assert len(await ids(sort="activity")) == len(waiting)
        for bad in ({"taken_by": "a b"}, {"kibana": "maybe"}, {"sort": "priority"}):
            got = await http.get(f"{V1}/cases", params={"view": "all", **bad})
            assert got.status_code == 422, bad
