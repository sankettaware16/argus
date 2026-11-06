"""AR4 after the adversarial review (D-186) on ``/api/v1``, on the web's own database login:

* the singles are ranked for the queue (changed since a notice, raised by ARGUS's evidence,
  follow-up, severity, newest), not by the rule's severity alone, and the Inbox's ``queue`` sort
  holds the same order;
* a case someone owns, or that is contained, with an unreviewed investigation in Needs attention is
  work (``kind`` "new", with how many), and the case list's ``work`` view holds the queue's cases
  (``queue`` is UI v2's Needs you since P4-F);
* every investigation in Needs attention is a single or a member of a case card, counted in the
  totals, on randomized data; the lists are compared, not only the numbers;
* the totals say what the capped lists leave out (``order_total``).
"""

from __future__ import annotations

import random
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import raised
from argus.cases.machine import Contain, Dismiss
from argus.cases.model import Actor, Indicator, QuietWindow
from argus.cases.service import CaseService
from tests.integration.web.b3_support import MANAGER, V1, World, make_world, post, sign_in
from tests.integration.web.conftest import NOW
from tests.integration.web.test_queue_ar4 import changed, queue

pytestmark = pytest.mark.integration

_BULK = """
INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key, bucket_start,
  bucket_end, previous_id, alert_count, first_event_at, last_event_at, severity, version)
SELECT md5(:tag || j)::uuid, '1', 'bulk-' || (j % 5), 'Bulk rule ' || (j % 5),
  '[["source.ip","10.9.' || (j / 250) || '.' || (j % 250) || '"]]',
  :now - interval '1 day', :now, md5('prev-' || :tag || j)::uuid, 3,
  :now - interval '1 day', :now - make_interval(mins => j), :sev, 1
FROM generate_series(1, :n) j
"""


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def _quiet(case: object) -> QuietWindow:
    return QuietWindow(True, "72 quiet hours")


async def end(world: World, case: Any, how: str) -> None:
    """The case machine's own move: contained (a verified quiet window) or dismissed (closed)."""
    who = Actor.person(await world.user_id("mina"), frozenset(c.value for c in MANAGER), via="test")
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn, _quiet)  # type: ignore[arg-type]
        move = Contain("cleaned", QuietWindow(True, "x")) if how == "contained" else Dismiss(
            "benign_expected")  # fmt: skip
        await service.apply(who, case, move, expected_version=None)


async def bulk(world: World, n: int, severity: str, tag: str) -> None:
    """``n`` unreviewed investigations of one severity, in no case."""
    async with world.owner.begin() as conn:
        await conn.execute(text(_BULK), {"tag": tag, "now": NOW, "sev": severity, "n": n})


async def raise_it(world: World, inv: uuid.UUID) -> None:
    """ARGUS's evidence flagged it: a threat-list hit and another flag (AR2b)."""
    flags = f'["{raised.THREAT_LIST}", "beacon"]'
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                 " flags) SELECT id, version, repeat('a', 64), CAST(:f AS jsonb)"
                 " FROM investigations WHERE id = :i"), {"i": inv, "f": flags})  # fmt: skip


async def lows(world: World) -> list[uuid.UUID]:
    """The seeded investigations the rule rates low (nothing but their own flags raises them)."""
    rows = await world.rows(
        "SELECT id FROM investigations WHERE id = ANY(:ids) AND severity IS DISTINCT FROM 'high'"
        " AND severity IS DISTINCT FROM 'critical' ORDER BY last_event_at DESC, id",
        ids=world.investigations,
    )  # fmt: skip
    return [r.id for r in rows]


async def attention_ids(http: Any, sort: str | None = None) -> list[str]:
    """The Inbox's Needs attention view, every page."""
    out: list[str] = []
    offset = 0
    while True:
        params: dict[str, Any] = {"view": "attention", "limit": 100, "offset": offset}
        if sort is not None:
            params["sort"] = sort
        got = (await http.get(f"{V1}/investigations", params=params)).json()
        out += [i["id"] for i in got["items"]]
        if not got["has_more"]:
            return out
        offset += 100


# --------------------------------------------------------------------------- the queue's order


async def test_the_singles_are_ranked_for_the_queue_not_by_the_rules_severity_alone(
    world: World,
) -> None:
    low = await lows(world)
    assert len(low) >= 5
    flagged, moved = low[0], low[1]
    await bulk(world, 30, "high", "h")  # more than the twenty the queue shows
    await bulk(world, 30, "critical", "c")
    await raise_it(world, flagged)
    case = await world.open_case(1, title="Notified", start=world.investigations.index(low[4]))
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
        await changed(world, case, moved, "a new flagged destination: 203.0.113.9")
        seen = await queue(http)
        by_queue = await attention_ids(http, "queue")
    shown = [s["investigation"]["id"] for s in seen["singles"]]
    assert len(shown) == 20
    # the investigation changed since a notice first, the one ARGUS raised second, though both
    # are rated low and more than 20 others are rated high or critical
    assert shown[:2] == [str(moved), str(flagged)]
    sevs = [s["investigation"]["severity"] for s in seen["singles"][2:]]
    assert sevs == sorted(sevs, key=["critical", "high"].index)  # severity next, then the newest
    assert seen["singles"][0]["investigation"]["known"]["outcome"] == "changed"
    # the Inbox in queue order holds the same order (its list also holds the case's members)
    members = {str(r.investigation_id) for r in await world.rows(
        "SELECT investigation_id FROM case_members WHERE removed_at IS NULL")}  # fmt: skip
    assert [i for i in by_queue if i not in members][:20] == shown
    # the totals say what the lists leave out: 62 or more singles, 20 shown and walked
    assert seen["singles_total"] >= 62
    assert len(seen["singles"]) == 20
    assert seen["order_total"] == seen["singles_total"] + sum(
        c["unreviewed"] for c in seen["cases"])  # fmt: skip
    assert len(seen["order"]) < seen["order_total"]


async def test_a_follow_up_ranks_after_what_changed_or_was_raised_and_before_severity(
    world: World,
) -> None:
    low = await lows(world)
    followed = low[0]
    await bulk(world, 25, "critical", "c")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        inv = (await http.get(f"{V1}/investigations/{followed}")).json()["investigation"]
        done = await post(http, csrf, f"/investigations/{followed}/reviews",
                          {"action": "follow_up", "outcome": None, "note": None,
                           "seen_review": None, "seen_version": inv["version"]})  # fmt: skip
        assert done.status_code == 201, done.text
        seen = await queue(http)
    assert seen["singles"][0]["investigation"]["id"] == str(followed)
    assert seen["singles"][0]["investigation"]["human_state"] == "follow_up"


# --------------------------------------------------------------------------- work in a worked case


async def test_a_case_someone_owns_with_an_unreviewed_investigation_is_work(world: World) -> None:
    ids = world.investigations
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        att = await attention_ids(http)
        inv = uuid.UUID(att[0])
        case = await world.open_case(1, title="Owned", start=ids.index(inv))
        taken = await post(http, csrf, f"/cases/{case}/take", {"expected_version": 1})
        assert taken.status_code == 200, taken.text
        seen = await queue(http)
        listed = (await http.get(f"{V1}/cases", params={"view": "work"})).json()
    (card,) = [c for c in seen["cases"] if c["id"] == str(case)]
    assert card["kind"] == "new"
    assert card["state"] == "assigned"
    assert card["new_members"] == 1
    assert card["why"] == "1 new investigation in a case someone owns."
    assert card["first_investigation_id"] == str(inv)
    assert str(inv) in seen["order"]
    assert seen["cases_total"] == 1
    # nothing about the case itself is flagged: only its member needs a person
    assert not card["waiting_for_approval"]
    # and it is no single any more
    assert str(inv) not in [s["investigation"]["id"] for s in seen["singles"]]
    # the list behind Home's link holds the queue's cases, and says how many
    assert [c["id"] for c in listed["items"]] == [str(case)]
    assert listed["counts"]["work"] == 1


async def test_a_contained_case_with_new_work_is_work_and_a_reviewed_one_is_not(
    world: World,
) -> None:
    ids = world.investigations
    case = await world.open_case(2, title="Contained, then new alerts", start=0)
    await end(world, case, "contained")
    async with world.owner.begin() as conn:
        await conn.execute(text("UPDATE investigations SET severity = 'low' WHERE id = ANY(:i)"),
                           {"i": ids[:2]})  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        quiet = await queue(http)
        assert str(case) not in [c["id"] for c in quiet["cases"]]  # nothing in it needs a person
        await raise_it(world, ids[0])
        loud = await queue(http)
        (card,) = [c for c in loud["cases"] if c["id"] == str(case)]
        assert card["kind"] == "new"
        assert card["why"] == "1 new investigation in a case that is contained."
        inv = (await http.get(f"{V1}/investigations/{ids[0]}")).json()["investigation"]
        done = await post(http, csrf, f"/investigations/{ids[0]}/reviews",
                          {"action": "reviewed", "outcome": "benign_expected", "note": None,
                           "seen_review": None, "seen_version": inv["version"]})  # fmt: skip
        assert done.status_code == 201, done.text
        after = await queue(http)
    assert str(case) not in [c["id"] for c in after["cases"]]


# --------------------------------------------------------------------------- the invariant


async def build_random_world(world: World, http: Any, csrf: str, rng: random.Random) -> None:
    """Cases in every state, with and without owners and notices, members reviewed or flagged or
    known, over the seeded investigations."""
    ids = world.investigations
    i = 0
    suspected = 0
    while i < len(ids) - 4:
        kind = rng.choice(["open", "assigned", "notified", "contained", "suspected", "closed"])
        size = rng.randint(1, 3)
        if kind in ("suspected", "closed"):
            case = await world.open_suspected(i, title=f"Suspected {i}")
            size = 1
            if kind == "closed":
                await end(world, case, "closed")
            suspected += 1
        else:
            device = (Indicator("ip", f"10.1.0.{i}", "actor"),)
            case = await world.open_case(size, title=f"{kind} {i}", start=i, indicators=device)
            if kind == "assigned":
                assert (await post(http, csrf, f"/cases/{case}/take",
                                   {"expected_version": 1})).status_code == 200  # fmt: skip
            elif kind == "notified":
                told = {"expected_version": 1, "told": "the warden", "how": "phone"}
                assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
                for member in ids[i : i + size]:
                    outcome = rng.choice(["known", "changed", None])
                    if outcome is not None:
                        await match(world, case, member, outcome)
            elif kind == "contained":
                await end(world, case, "contained")
        i += size + rng.randint(0, 1)  # now and then a single in between
    for inv in ids:  # what the rules and ARGUS said, and what people did
        roll = rng.random()
        async with world.owner.begin() as conn:
            await conn.execute(
                text("UPDATE investigations SET severity = :s WHERE id = :i"),
                {"s": rng.choice(["low", "low", "medium", "high", "critical"]), "i": inv},
            )
        if roll < 0.2:
            await raise_it(world, inv)
        elif roll < 0.5:
            seen = (await http.get(f"{V1}/investigations/{inv}")).json()["investigation"]
            action = rng.choice(["reviewed", "reviewed", "follow_up"])
            done = await post(
                http, csrf, f"/investigations/{inv}/reviews",
                {"action": action, "outcome": "benign_expected" if action == "reviewed" else None,
                 "note": None, "seen_review": seen["latest_review"],
                 "seen_version": seen["version"]})  # fmt: skip
            assert done.status_code == 201, done.text


async def match(world: World, case: Any, inv: uuid.UUID, outcome: str) -> None:
    async with world.runtime.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome,"
                 " why, changed_version) SELECT :i, :c, i.version, :o,"
                 " CASE WHEN :o = 'changed' THEN :w END,"
                 " CASE WHEN :o = 'changed' THEN i.version END FROM investigations i"
                 " WHERE i.id = :i ON CONFLICT DO NOTHING"),
            {"i": inv, "c": case, "o": outcome, "w": "a new flagged destination"})  # fmt: skip


@pytest.mark.parametrize("seed", range(8))
async def test_every_investigation_in_needs_attention_is_a_single_or_a_member_of_a_case_card(
    world: World, seed: int
) -> None:
    rng = random.Random(seed)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await build_random_world(world, http, csrf, rng)
        seen = await queue(http)
        attention = set(await attention_ids(http))
        counts = (await http.get(f"{V1}/counts")).json()
    singles = {s["investigation"]["id"] for s in seen["singles"]}
    cards = {c["id"] for c in seen["cases"]}
    # the world is small enough that nothing is cut: the lists are the whole of it
    assert seen["singles_total"] == len(singles)
    assert seen["cases_total"] == len(cards)
    assert counts["attention"] == len(attention)
    member_rows = await world.rows(
        "SELECT mm.investigation_id AS inv, mm.case_id AS case_id, c.state FROM case_members mm"
        " JOIN cases c ON c.id = mm.case_id WHERE mm.removed_at IS NULL")  # fmt: skip
    in_open_case = {str(r.inv): str(r.case_id) for r in member_rows if r.state != "closed"}
    in_a_card = {str(r.inv) for r in member_rows if str(r.case_id) in cards}
    # the set of Needs attention is the singles and the members of the cards, nothing else
    assert singles <= attention
    assert attention == singles | (attention & in_a_card), (
        f"in Needs attention but in neither: {attention - singles - in_a_card}")  # fmt: skip
    assert not singles & set(in_open_case)  # a single belongs to no case that is worked
    # every one of them in a case that is worked is on that case's card, and Next walks it
    for inv in attention - singles:
        assert in_open_case[inv] in cards
        assert inv in seen["order"]
    assert set(seen["order"]) >= attention
    # the list behind Home's link holds exactly the cards
    async with world.app() as http:
        await sign_in(http, "mina")
        listed = (await http.get(f"{V1}/cases", params={"view": "work", "limit": 100})).json()
    assert {c["id"] for c in listed["items"]} == cards
    assert listed["counts"]["work"] == len(cards)


async def test_the_random_worlds_are_not_empty(world: World) -> None:
    """The invariant above is not vacuous: its worlds put investigations on both sides."""
    rng = random.Random(3)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await build_random_world(world, http, csrf, rng)
        seen = await queue(http)
    assert seen["cases"], "cards"
    assert seen["singles"], "singles"
    assert any(c["kind"] == "new" for c in seen["cases"]) or any(
        c["unreviewed"] for c in seen["cases"])  # fmt: skip


async def test_a_follow_up_on_a_known_investigation_of_a_notified_case_is_still_work(
    world: World,
) -> None:
    """A person's request for a follow-up is in Needs attention even on an investigation ARGUS
    holds as known; its case must carry it, or it would be on no card at all."""
    ids = world.investigations
    case = await world.open_case(2, title="Notified laptop", start=0)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
        await match(world, case, ids[0], "known")
        await match(world, case, ids[1], "known")
        quiet = await queue(http)
        assert quiet["cases"] == []  # known: counted, not work
        inv = (await http.get(f"{V1}/investigations/{ids[0]}")).json()["investigation"]
        done = await post(http, csrf, f"/investigations/{ids[0]}/reviews",
                          {"action": "follow_up", "outcome": None, "note": None,
                           "seen_review": None, "seen_version": inv["version"]})  # fmt: skip
        assert done.status_code == 201, done.text
        loud = await queue(http)
        attention = set(await attention_ids(http))
    assert str(ids[0]) in attention
    (card,) = loud["cases"]
    assert card["id"] == str(case)
    assert loud["order"][0] == str(ids[0])
    assert str(ids[1]) not in loud["order"]  # the other one is still known
