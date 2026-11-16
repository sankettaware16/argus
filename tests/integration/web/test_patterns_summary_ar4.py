"""AR4 after the adversarial review (D-186): the patterns ARGUS recommends closing, for Home, are
counted in SQL from the investigator's runs and their patterns (real totals, no sample), with
known and reviewed members left out; the rule is ``stance.recommend``'s, held to it on generated
data; closing reads the covered members on demand; the Patterns page's sample is the newest and
says it is a sample; and "the agent's own assessment" is one rule everywhere."""

from __future__ import annotations

import random
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import patternsummary, queries, stance
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in
from tests.integration.web.test_gold import with_dossiers
from tests.integration.web.test_queue_ar4 import assess, reading_of
from tests.integration.web.test_queue_review_ar4 import bulk

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def bulk_ids(world: World, n: int, tag: str) -> list[uuid.UUID]:
    """``n`` more unreviewed investigations (the seeded world has twelve)."""
    await bulk(world, n, "low", tag)
    rows = await world.rows(
        "SELECT id FROM investigations WHERE rule_id LIKE 'bulk-%' AND id = ANY("
        "SELECT md5(:tag || j)::uuid FROM generate_series(1, :n) j) ORDER BY last_event_at, id",
        tag=tag, n=n)  # fmt: skip
    return [r.id for r in rows]


def hash_of(n: int) -> str:
    return f"{n:064x}"


async def share_to(world: World, assessment: int, invs: list[uuid.UUID], pattern: str) -> None:
    async with world.owner.begin() as conn:
        for inv in invs:
            await conn.execute(
                text("INSERT INTO assessment_shares (assessment_id, investigation_id, version,"
                     " pattern, day) SELECT :a, i.id, i.version, :p, current_date"
                     " FROM investigations i WHERE i.id = :i ON CONFLICT DO NOTHING"),
                {"a": assessment, "i": inv, "p": pattern})  # fmt: skip


async def pattern_of(
    world: World,
    n: int,
    members: list[uuid.UUID],
    *,
    outcome: str = "benign_expected",
    confidence: float | None = 0.8,
    assessor: str = "agent@1",
) -> int:
    """One run on the first member, standing for all of them."""
    run = await assess(world, members[0], outcome=outcome, confidence=confidence,
                       assessor=assessor)  # fmt: skip
    await share_to(world, run, members, hash_of(n))
    return run


async def summary(http: Any) -> dict[str, Any]:
    done = await http.get(f"{V1}/patterns/summary")
    assert done.status_code == 200, done.text
    found: dict[str, Any] = done.json()
    return found


async def review(http: Any, csrf: str, inv: uuid.UUID, action: str = "reviewed") -> None:
    seen = (await http.get(f"{V1}/investigations/{inv}")).json()["investigation"]
    done = await post(http, csrf, f"/investigations/{inv}/reviews",
                      {"action": action, "outcome": "benign_expected" if action == "reviewed"
                       else None, "note": None, "seen_review": seen["latest_review"],
                       "seen_version": seen["version"]})  # fmt: skip
    assert done.status_code == 201, done.text


# --------------------------------------------------------------------------- the summary


async def test_the_summary_counts_every_pattern_and_lists_the_largest(world: World) -> None:
    ids = await bulk_ids(world, 24, "p")
    sizes = [4, 3, 3, 2, 2, 2, 2, 2, 2, 2]  # ten patterns over 24 investigations
    at = 0
    for n, size in enumerate(sizes):
        await pattern_of(world, n, ids[at : at + size])
        at += size
    async with world.app() as http:
        await sign_in(http, "mina")
        found = await summary(http)
    assert found["total"] == 10  # all of them, though only eight are listed
    assert found["investigations"] == sum(sizes)
    assert len(found["items"]) == patternsummary.SHOWN
    assert [i["covered"] for i in found["items"]] == sorted(
        (i["covered"] for i in found["items"]), reverse=True)  # fmt: skip
    first = found["items"][0]
    assert (first["investigations"], first["covered"]) == (4, 4)
    assert (first["outcome"], first["confidence"], first["source"]) == (
        "benign_expected", 0.8, "the AI investigator")  # fmt: skip
    assert len(first["examples"]) == 3
    assert set(first["examples"]) <= {str(i) for i in ids[:4]}
    assert first["alerts"] > 0


async def test_known_and_reviewed_members_are_left_out_of_the_pattern(world: World) -> None:
    ids = world.investigations
    await pattern_of(world, 1, ids[:5])
    case = await world.open_case(1, title="A notified laptop", start=11)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
        before = (await summary(http))["items"][0]
        async with world.runtime.begin() as conn:  # the notice covered one of the five: known
            await conn.execute(
                text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                     " SELECT :i, :c, i.version, 'known' FROM investigations i WHERE i.id = :i"),
                {"i": ids[0], "c": case})  # fmt: skip
        known = (await summary(http))["items"][0]
        await review(http, csrf, ids[1])  # a person reviewed another
        reviewed = (await summary(http))["items"][0]
        await review(http, csrf, ids[2])
        await review(http, csrf, ids[3])  # one left: not a pattern any more
        gone = await summary(http)
    assert (before["investigations"], before["covered"]) == (5, 5)
    assert (known["investigations"], known["covered"]) == (4, 4)
    assert (reviewed["investigations"], reviewed["covered"]) == (3, 3)
    assert gone == {"total": 0, "investigations": 0, "items": []}


async def test_members_without_a_proposal_are_counted_but_not_covered(world: World) -> None:
    ids = world.investigations
    run = await assess(world, ids[0], outcome="benign_policy", confidence=0.9)
    await share_to(world, run, ids[:2], hash_of(1))
    reading = await assess(world, ids[5], status="no_decision", outcome=None, confidence=None,
                           reasons=reading_of("benign_expected", "floor"))  # fmt: skip
    await share_to(
        world, reading, [ids[2]], hash_of(1)
    )  # a reading of the investigator: no proposal
    async with world.app() as http:
        await sign_in(http, "mina")
        (item,) = (await summary(http))["items"]
    assert (item["investigations"], item["covered"], item["outcome"]) == (3, 2, "benign_policy")


async def test_nothing_is_recommended_for_mixed_outcomes_a_threat_or_a_non_closing_outcome(
    world: World,
) -> None:
    ids = world.investigations
    a = await assess(world, ids[0], outcome="benign_expected")
    b = await assess(world, ids[1], outcome="benign_policy")
    await share_to(world, a, ids[:1], hash_of(1))
    await share_to(world, b, ids[1:2], hash_of(1))  # two closing outcomes in one pattern
    tp = await pattern_of(world, 2, ids[2:5], outcome="true_positive")  # never closed
    blocked = await assess(world, ids[5], status="no_decision", outcome=None, confidence=None,
                           reasons=reading_of("true_positive", "floor"))  # fmt: skip
    ok = await assess(world, ids[6], outcome="benign_expected")
    await share_to(world, ok, ids[6:8], hash_of(3))
    await share_to(world, blocked, [ids[8]], hash_of(3))  # one member's answer was a threat
    assert tp
    async with world.app() as http:
        await sign_in(http, "mina")
        found = await summary(http)
    assert found == {"total": 0, "investigations": 0, "items": []}


async def test_an_engine_proposal_and_a_missing_confidence_say_so(world: World) -> None:
    ids = world.investigations
    await pattern_of(world, 1, ids[:3], assessor="engine@1", confidence=None)
    async with world.app() as http:
        await sign_in(http, "mina")
        (item,) = (await summary(http))["items"]
    assert (item["source"], item["confidence"]) == ("the decision engine", None)


# ---------------------------------------------------------------------- the same rule as the page's


def reference(
    groups: dict[tuple[str, Any], list[uuid.UUID]], leaned: dict[uuid.UUID, Any]
) -> dict[tuple[str, Any], tuple[Any, ...]]:
    """``stance.recommend`` over each pattern's members: what the SQL must say."""
    out = {}
    for key, members in groups.items():
        found = stance.recommend(members, leaned)
        if len(members) >= 2 and found is not None:
            out[key] = (found.outcome, len(found.members), found.confidence, found.source,
                        len(members))  # fmt: skip
    return out


CLOSING = ["benign_expected", "benign_policy", "rule_false_positive"]
EVERY = [*CLOSING, "true_positive", "inconclusive"]


@pytest.mark.parametrize("seed", range(20))
async def test_the_sql_recommends_exactly_what_stance_recommend_does(
    world: World, seed: int
) -> None:
    rng = random.Random(seed)
    ids = world.investigations
    for n in range(rng.randint(2, 5)):
        members = rng.sample(ids[:11], rng.randint(2, 6))
        style = rng.choice(["clean", "clean", "mixed", "blocked", "threat", "partial"])
        base = rng.choice(CLOSING if style != "threat" else ["true_positive"])
        for run_on in rng.sample(members, rng.randint(1, min(3, len(members)))):
            outcome = rng.choice(EVERY) if style == "mixed" else base
            run = await assess(world, run_on, outcome=outcome,
                               confidence=rng.choice([None, 0.5, 0.9]),
                               assessor=rng.choice(["agent@1", "engine@1", "agent@2"]))  # fmt: skip
            await share_to(world, run, rng.sample(members, rng.randint(1, len(members)))
                           if style == "partial" else members, hash_of(n))  # fmt: skip
        if rng.random() < 0.4:  # a member the investigator read itself, with nothing to propose
            await assess(world, rng.choice(members), status="no_decision", outcome=None,
                         confidence=None, assessor=rng.choice(["agent@1", "agent@2"]),
                         reasons=reading_of(rng.choice(CLOSING), "floor"))  # fmt: skip
        if rng.random() < 0.3:  # a member the decision engine proposed for on its own
            await assess(world, rng.choice(members), outcome=rng.choice(CLOSING),
                         confidence=rng.choice([None, 0.6]), assessor="engine@1")  # fmt: skip
        if style == "blocked":  # a member whose answer was a threat that it did not propose
            reading = await assess(world, rng.choice(members), status="no_decision", outcome=None,
                                   confidence=None, assessor="agent@1",
                                   reasons=reading_of("true_positive", "floor"))  # fmt: skip
            await share_to(world, reading, members, hash_of(n))
    case = await world.open_case(1, title="A notified laptop", start=11)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for inv in rng.sample(ids[:11], 2):  # people reviewed some
            await review(http, csrf, inv)
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
    async with world.runtime.begin() as conn:  # and ARGUS holds some as a known infection
        for inv in rng.sample(ids[:11], 2):
            await conn.execute(
                text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                     " SELECT :i, :c, i.version, 'known' FROM investigations i WHERE i.id = :i"
                     " ON CONFLICT DO NOTHING"), {"i": inv, "c": case})  # fmt: skip
    # what a pattern holds now: its unreviewed members at their current version
    held = await world.rows(
        "SELECT s.pattern, s.day, array_agg(DISTINCT s.investigation_id) AS members"
        " FROM assessment_shares s JOIN investigations i ON i.id = s.investigation_id"
        " AND i.version = s.version LEFT JOIN review_state last ON last.investigation_id = i.id"
        " LEFT JOIN case_known_matches km ON km.investigation_id = i.id"
        " WHERE last.decision_id IS NULL AND NOT coalesce(km.outcome = 'known'"
        " AND km.version = i.version, false) GROUP BY s.pattern, s.day")  # fmt: skip
    groups = {(r.pattern, r.day): list(r.members) for r in held}
    async with world.runtime.connect() as conn:
        leaned = await stance.lean(conn, [i for m in groups.values() for i in m])
        rows = (await conn.execute(text(patternsummary._SUMMARY), {"n": 1000})).all()
    want = reference(groups, leaned)
    got = {
        (r.pattern, r.day): (
            r.outcome,
            int(r.covered),
            None if r.unsure else r.sure,
            patternsummary._source(r),
            int(r.members),
        )
        for r in rows
    }
    assert got == want
    assert rows == [] or int(rows[0].total) == len(want)


# --------------------------------------------------------------------------- closing


async def test_closing_reads_the_covered_members_now_with_their_versions_and_reviews(
    world: World,
) -> None:
    ids = world.investigations
    run = await assess(world, ids[0], outcome="benign_expected")
    await share_to(world, run, ids[:4], hash_of(1))
    noted = await assess(world, ids[9], status="no_decision", outcome=None, confidence=None,
                         reasons=reading_of("benign_expected", "floor"))  # fmt: skip
    await share_to(world, noted, [ids[4]], hash_of(1))  # in the pattern, no proposal
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        (item,) = (await summary(http))["items"]
        assert (item["investigations"], item["covered"]) == (5, 4)
        got = await http.get(
            f"{V1}/patterns/closing", params={"pattern": item["pattern"], "day": item["day"]}
        )
        assert got.status_code == 200, got.text
        closing = got.json()
        assert closing["brief"]["covered"] == 4
        named = {m["investigation_id"] for m in closing["members"]}
        assert named == {str(i) for i in ids[:4]}  # the fifth has no proposal: not named
        assert all(m["version"] == 1 and m["latest_review"] is None for m in closing["members"])
        # the request it makes is the review route's, and closes them
        sent = await post(http, csrf, "/patterns/review",
                          {"outcome": closing["brief"]["outcome"],
                           "items": closing["members"]})  # fmt: skip
        assert sent.status_code == 200, sent.text
        assert sent.json() == {"reviewed": 4, "changed": 0}
        # nothing is left to recommend: the pattern is one investigation, then it is gone
        gone = await http.get(
            f"{V1}/patterns/closing", params={"pattern": item["pattern"], "day": item["day"]}
        )
        assert gone.status_code == 404
        assert gone.json()["code"] == "not_found"
        wrong = await http.get(
            f"{V1}/patterns/closing", params={"pattern": "zz", "day": "2026-10-29"}
        )
        assert wrong.status_code == 422


async def test_closing_is_refused_for_a_viewer_who_is_not_signed_in(world: World) -> None:
    async with world.app() as http:
        gone = await http.get(
            f"{V1}/patterns/closing", params={"pattern": hash_of(1), "day": "2026-10-29"}
        )
        assert gone.status_code == 401
        assert (await http.get(f"{V1}/patterns/summary")).status_code == 401
        await sign_in(http, "vera")  # view only: reads
        assert (await http.get(f"{V1}/patterns/summary")).status_code == 200


# --------------------------------------------------------------------------- the page's sample


async def test_the_patterns_page_groups_the_newest_and_says_it_is_a_sample(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, world: World
) -> None:
    await with_dossiers(seeded, migrated_engine, 24)
    async with seeded.connect() as conn:
        whole = await queries.patterns_page(conn)
        sample = await queries.patterns_page(conn, limit=9)
    assert (whole.read, whole.sampled) == (12, False)  # the seeded world has twelve
    assert (sample.read, sample.limit, sample.sampled) == (9, 9, True)
    newest = await world.rows(
        "SELECT id FROM investigations ORDER BY last_event_at DESC NULLS LAST, id LIMIT 9"
    )
    in_groups = {m["id"] for g in sample.groups for m in g["members"]}
    assert in_groups <= {str(r.id) for r in newest}  # the newest, not the lowest ids
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/patterns")).json()
    assert set(page) == {"groups", "read", "limit", "sampled"}
    assert (page["read"], page["limit"], page["sampled"]) == (12, queries.PATTERN_SAMPLE, False)


async def test_the_patterns_page_leaves_known_investigations_out(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, world: World
) -> None:
    await with_dossiers(seeded, migrated_engine, 24)
    case = await world.open_case(1, title="A notified laptop", start=11)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
        before = (await http.get(f"{V1}/patterns")).json()
        async with world.runtime.begin() as conn:
            for inv in world.investigations[:6]:
                await conn.execute(
                    text(
                        "INSERT INTO case_known_matches (investigation_id, case_id, version,"
                        " outcome) SELECT :i, :c, i.version, 'known' FROM investigations i"
                        " WHERE i.id = :i ON CONFLICT DO NOTHING"
                    ),
                    {"i": inv, "c": case},
                )
        after = (await http.get(f"{V1}/patterns")).json()
    assert after["read"] == before["read"] - 6


# --------------------------------------------------------------------------- the agent's own


async def test_an_assessment_by_any_version_of_the_investigator_is_its_own_everywhere(
    world: World,
) -> None:
    """The page, the stance and the lists read "the agent's own assessment" by one rule
    (``assessed.is_agent``): agent@2 is the investigator's as agent@1 is, so a shared run never
    replaces it and "same pattern as" is not shown beside it."""
    a, b = world.investigations[:2]
    mine = await assess(world, a, outcome="benign_policy", assessor="agent@2")
    other = await assess(world, b, outcome="true_positive")
    await share_to(world, other, [a, b], hash_of(1))
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/investigations/{a}")).json()
    assert page["stance"]["assessment_id"] == mine
    assert page["stance"]["from_investigation_id"] is None
    assert page["same_pattern"] is None
    assert page["ask_available"] is False
