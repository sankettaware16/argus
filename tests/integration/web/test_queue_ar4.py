"""AR4 (D-182) on ``/api/v1``, on the web's own database login: the case-first queue (suggested
cases and cases with a change since the notice first, each with ARGUS's verdict or reading; a
notified case with nothing changed is a count, not work; single investigations that belong to no
case; the order Next walks), the stance on an investigation's page (a recommendation, the
pattern's run, a reading, nothing) and the recommendation on a pattern."""

from __future__ import annotations

import itertools
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Indicator
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in
from tests.integration.web.test_gold import with_dossiers

pytestmark = pytest.mark.integration
HOST = "10.0.0.1"
_SEQ = itertools.count(1)


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def assess(
    world: World,
    inv: uuid.UUID,
    *,
    status: str = "proposed",
    outcome: str | None = "true_positive",
    confidence: float | None = 0.8,
    assessor: str = "agent@1",
    reasons: list[Any] | None = None,
) -> int:
    """An assessment of the investigation at its current version, as the owner writes it."""
    n = next(_SEQ)
    async with world.owner.begin() as conn:
        made = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome, confidence, decided_by,"
                    " reasons, finished_at) SELECT :i, i.version, 'p', repeat('a', 64),"
                    " lpad(CAST(:n AS text), 64, '0'), :a, now(), :s, :o, :c, :a || '#m',"
                    " CAST(:r AS jsonb), now() FROM investigations i WHERE i.id = :i RETURNING id"
                ),
                {
                    "i": inv,
                    "n": n,
                    "a": assessor,
                    "s": status,
                    "o": outcome,
                    "c": confidence,
                    "r": json.dumps(reasons or []),
                },
            )
        ).scalar_one()
    return int(made)


def reading_of(outcome: str = "true_positive", kind: str = "undecided") -> list[Any]:
    """The reasons a no-decision run of the AI investigator leaves (AR1): its answer and its
    reading, among the plain refusals."""
    return [
        {"answer": {"outcome": outcome, "confidence": 0.7, "explanation": "It beacons.",
                    "cites": ["every 300 s", "made up"]},
         "reading": {"kind": kind, "checked": [True, False], "blocked": []}},
        "the agent could not decide",
    ]  # fmt: skip


async def share(world: World, assessment: int, inv: uuid.UUID, pattern: str = "1" * 64) -> None:
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO assessment_shares (assessment_id, investigation_id, version, pattern,"
                 " day) SELECT :a, i.id, i.version, :p, current_date FROM investigations i"
                 " WHERE i.id = :i ON CONFLICT DO NOTHING"),
            {"a": assessment, "i": inv, "p": pattern},
        )  # fmt: skip


async def changed(world: World, case: Any, inv: uuid.UUID, why: str) -> None:
    async with world.runtime.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome,"
                 " why, changed_version) SELECT :i, :c, i.version, 'changed', :w, i.version"
                 " FROM investigations i WHERE i.id = :i"),
            {"i": inv, "c": case, "w": why},
        )  # fmt: skip


async def queue(http: Any) -> dict[str, Any]:
    done = await http.get(f"{V1}/queue")
    assert done.status_code == 200, done.text
    found: dict[str, Any] = done.json()
    return found


# --------------------------------------------------------------------------- the queue


async def test_the_queue_puts_suggested_and_changed_cases_first_and_counts_the_quiet_ones(
    world: World,
) -> None:
    ids = world.investigations
    suggested = await world.open_suspected(0, "Proposed beacon")  # low; the AI proposes TP
    unowned = await world.open_case(1, title="Nobody has this", start=2)
    quiet = await world.open_case(
        1, title="Quiet but notified", start=3, indicators=(Indicator("ip", HOST, "actor"),)
    )
    moved = await world.open_case(
        1, title="Notified, then something changed", start=4, severity="medium",
        indicators=(Indicator("ip", "10.0.0.2", "actor"), Indicator("ip", "10.0.0.3", "actor")),
    )  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{quiet}/notices", told)).status_code == 200
        assert (await post(http, csrf, f"/cases/{moved}/notices", told)).status_code == 200
        await changed(world, moved, ids[4], "a new flagged destination: 203.0.113.9")
        seen = await queue(http)
    by_id = {c["id"]: c for c in seen["cases"]}
    assert str(quiet) not in by_id  # notified, still active, nothing changed: not work
    assert seen["notified_cases"] == 2
    assert seen["cases_total"] == 3
    # suggested and changed first (the more severe of the two first), then the others
    assert [c["id"] for c in seen["cases"]] == [str(moved), str(suggested), str(unowned)]
    one = by_id[str(suggested)]
    assert (one["kind"], one["state"]) == ("suggested", "suspected")
    assert one["why"].startswith("Suspected from ARGUS's own proposal")
    assert one["stance"]["kind"] == "recommends"
    assert one["stance"]["outcome"] == "true_positive"
    assert one["stance"]["source"] == "the AI investigator"
    assert one["first_investigation_id"] == str(ids[0])
    two = by_id[str(moved)]
    assert two["kind"] == "changed"
    assert two["changes"] == ["a new flagged destination: 203.0.113.9"]
    assert two["notified_at"] is not None
    assert two["devices"] == ["10.0.0.2", "10.0.0.3"]
    assert two["devices_total"] == 2
    assert two["first_investigation_id"] == str(ids[4])
    three = by_id[str(unowned)]
    assert (three["kind"], three["stance"]["kind"]) == ("unowned", "none")
    assert three["why"] == "A person confirmed it and nobody owns it yet."
    # Next walks the work case by case; a quiet notified case's investigation is not in it
    assert seen["order"][:3] == [str(ids[4]), str(ids[0]), str(ids[2])]
    assert str(ids[3]) not in seen["order"]
    assert len(set(seen["order"])) == len(seen["order"])


async def test_a_known_investigation_of_a_notified_case_is_not_work_but_a_changed_one_is(
    world: World,
) -> None:
    ids = world.investigations
    case = await world.open_case(3, title="A notified laptop", severity="medium")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert (await post(http, csrf, f"/cases/{case}/notices", told)).status_code == 200
        async with world.runtime.begin() as conn:
            for i in ids[:2]:  # two investigations the notice covered: known
                await conn.execute(
                    text("INSERT INTO case_known_matches (investigation_id, case_id, version,"
                         " outcome) SELECT :i, :c, i.version, 'known' FROM investigations i"
                         " WHERE i.id = :i"), {"i": i, "c": case})  # fmt: skip
        quiet = await queue(http)
        assert quiet["cases"] == []  # nothing changed: a count, not work
        assert quiet["notified_cases"] == 1
        await changed(world, case, ids[2], "a flag the case never carried")
        loud = await queue(http)
    (found,) = loud["cases"]
    assert found["kind"] == "changed"
    assert found["unreviewed"] == 1  # the two known ones are not work
    assert found["first_investigation_id"] == str(ids[2])
    assert loud["order"][0] == str(ids[2])
    assert not {str(ids[0]), str(ids[1])} & set(loud["order"])


async def test_the_singles_are_the_investigations_in_needs_attention_without_a_case(
    world: World,
) -> None:
    async with world.app() as http:
        await sign_in(http, "mina")
        attention = (await http.get(f"{V1}/investigations", params={"view": "attention"})).json()
        listed = [i["id"] for i in attention["items"]]
        assert len(listed) >= 3
        counts = (await http.get(f"{V1}/counts")).json()
        before = await queue(http)
        assert before["singles_total"] == counts["attention"] == len(listed)
        assert [s["investigation"]["id"] for s in before["singles"]] == listed
        case = await world.open_case(1, title="One of them", start=world.investigations.index(
            uuid.UUID(listed[0])))  # fmt: skip
        after = await queue(http)
        assert after["singles_total"] == len(listed) - 1
        assert listed[0] not in [s["investigation"]["id"] for s in after["singles"]]
        assert listed[0] in after["order"]  # it is the case's work
    assert case


async def test_a_view_only_account_reads_the_queue_and_a_signed_out_one_is_refused(
    world: World,
) -> None:
    await world.open_suspected(0)
    async with world.app() as http:
        assert (await http.get(f"{V1}/queue")).status_code == 401
        await sign_in(http, "vera")
        seen = await queue(http)
    assert seen["cases_total"] == 1


# --------------------------------------------------------------------------- the stance


async def stance(http: Any, inv: uuid.UUID) -> dict[str, Any]:
    done = await http.get(f"{V1}/investigations/{inv}")
    assert done.status_code == 200, done.text
    found: dict[str, Any] = done.json()["stance"]
    return found


async def test_the_stance_is_its_own_proposal_then_the_patterns_then_a_reading_then_nothing(
    world: World,
) -> None:
    a, b, c, d, e = world.investigations[:5]
    own = await assess(world, a, outcome="benign_expected", confidence=0.9)
    shared = await assess(world, b, outcome="true_positive", confidence=0.6)
    await share(world, shared, b)
    await share(world, shared, c)
    await assess(world, d, status="no_decision", outcome=None, confidence=None,
                 reasons=reading_of("true_positive", "citation"))  # fmt: skip
    async with world.app() as http:
        await sign_in(http, "mina")
        mine = await stance(http, a)
        pattern = await stance(http, c)
        run_on = await stance(http, b)
        read = await stance(http, d)
        nothing = await stance(http, e)
        whole = (await http.get(f"{V1}/investigations/{a}")).json()
    assert (mine["kind"], mine["outcome"], mine["confidence"]) == ("recommends", "benign_expected",
                                                                   0.9)  # fmt: skip
    assert mine["assessment_id"] == own
    assert mine["acceptable"] is True
    assert whole["acceptable_assessment_id"] == own
    assert mine["from_investigation_id"] is None
    # the pattern's proposal on another investigation: shown, never acceptable for this one
    assert (pattern["kind"], pattern["outcome"]) == ("recommends", "true_positive")
    assert pattern["from_investigation_id"] == str(b)
    assert pattern["acceptable"] is False
    assert pattern["pattern_investigations"] == 2  # the run's own and this one
    # the investigation the run was made on has its own
    assert (run_on["kind"], run_on["from_investigation_id"], run_on["acceptable"]) == (
        "recommends", None, True)  # fmt: skip
    assert run_on["pattern_investigations"] == 2
    assert (read["kind"], read["outcome"], read["confidence"]) == ("reading", "true_positive", 0.7)
    assert read["why"] == "it quoted something that is not in the evidence"
    assert read["acceptable"] is False
    assert read["source"] == "the AI investigator"
    assert nothing == {
        "kind": "none", "outcome": None, "confidence": None, "source": None, "why": None,
        "assessment_id": None, "from_investigation_id": None, "acceptable": False,
        "pattern_investigations": None, "pattern_alerts": None,
    }  # fmt: skip


async def test_a_proposal_beats_a_reading_and_the_investigators_beats_the_engines(
    world: World,
) -> None:
    a, b = world.investigations[:2]
    await assess(world, a, status="no_decision", outcome=None, confidence=None,
                 reasons=reading_of("benign_expected", "floor"))  # fmt: skip
    engine = await assess(world, a, assessor="engine@1", outcome="benign_policy", confidence=1.0)
    agent = await assess(world, b, outcome="true_positive")
    await assess(world, b, assessor="engine@1", outcome="benign_policy", confidence=1.0)
    async with world.app() as http:
        await sign_in(http, "mina")
        first = await stance(http, a)
        second = await stance(http, b)
    # the engine's proposal beats the investigator's own reading
    assert (first["kind"], first["outcome"], first["assessment_id"]) == (
        "recommends", "benign_policy", engine)  # fmt: skip
    assert first["source"] == "the decision engine"
    assert (second["outcome"], second["assessment_id"]) == ("true_positive", agent)


async def test_a_reviewed_investigation_has_a_stance_but_nothing_to_accept(world: World) -> None:
    (a,) = world.investigations[:1]
    await assess(world, a, outcome="true_positive")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        before = (await http.get(f"{V1}/investigations/{a}")).json()
        done = await http.post(
            f"{V1}/investigations/{a}/reviews",
            headers={"X-CSRF-Token": csrf},
            json={"action": "reviewed", "outcome": "true_positive", "note": None,
                  "seen_review": None, "seen_version": before["investigation"]["version"]},
        )  # fmt: skip
        assert done.status_code == 201, done.text
        after = (await http.get(f"{V1}/investigations/{a}")).json()
    assert before["stance"]["acceptable"] is True
    assert after["stance"]["kind"] == "recommends"
    assert after["stance"]["acceptable"] is False
    assert after["acceptable_assessment_id"] is None


# --------------------------------------------------------------------------- patterns


async def test_a_pattern_carries_arguss_recommendation_to_close_it(
    world: World, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 24)
    async with world.app() as http:
        await sign_in(http, "mina")
        groups = (await http.get(f"{V1}/patterns")).json()["groups"]
    assert groups, "the seeded rules make patterns"
    assert all(g["recommendation"] is None for g in groups)  # nobody has proposed anything yet
    biggest = groups[0]
    members = [uuid.UUID(m["investigation_id"]) for m in biggest["members"]]
    for inv in members[:2]:
        await assess(world, inv, outcome="benign_expected", confidence=0.9)
    pattern = await assess(world, members[2], outcome="benign_expected", confidence=0.7)
    await share(world, pattern, members[2])
    await share(world, pattern, members[3])
    async with world.app() as http:
        await sign_in(http, "mina")
        groups = (await http.get(f"{V1}/patterns")).json()["groups"]
        wanted = next(g for g in groups if g["rule_id"] == biggest["rule_id"])
        others = [g for g in groups if g["rule_id"] != biggest["rule_id"]]
    rec = wanted["recommendation"]
    assert rec["outcome"] == "benign_expected"
    assert rec["confidence"] == 0.7  # the least sure
    assert rec["source"] == "the AI investigator"
    assert set(rec["members"]) == {str(m) for m in members[:4]}
    assert (rec["covered"], rec["total"]) == (4, len(members))
    assert all(g["recommendation"] is None for g in others)


async def test_arguss_recommendation_is_withheld_when_the_proposals_differ_or_one_says_threat(
    world: World, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 24)
    async with world.app() as http:
        await sign_in(http, "mina")
        biggest = (await http.get(f"{V1}/patterns")).json()["groups"][0]
    members = [uuid.UUID(m["investigation_id"]) for m in biggest["members"]]
    await assess(world, members[0], outcome="benign_expected")
    await assess(world, members[1], outcome="benign_policy")  # a different closing outcome
    async with world.app() as http:
        await sign_in(http, "mina")
        mixed = next(g for g in (await http.get(f"{V1}/patterns")).json()["groups"]
                     if g["rule_id"] == biggest["rule_id"])  # fmt: skip
    assert mixed["recommendation"] is None
    async with world.owner.begin() as conn:
        await conn.execute(text("DELETE FROM assessments WHERE investigation_id = :i"),
                           {"i": members[1]})  # fmt: skip
    await assess(world, members[2], status="no_decision", outcome=None, confidence=None,
                 reasons=reading_of("true_positive", "floor"))  # fmt: skip
    async with world.app() as http:
        await sign_in(http, "mina")
        blocked = next(g for g in (await http.get(f"{V1}/patterns")).json()["groups"]
                       if g["rule_id"] == biggest["rule_id"])  # fmt: skip
    assert blocked["recommendation"] is None  # one member's answer was a threat it did not propose
    async with world.owner.begin() as conn:
        await conn.execute(text("DELETE FROM assessments WHERE investigation_id = :i"),
                           {"i": members[2]})  # fmt: skip
        await conn.execute(text("UPDATE assessments SET outcome = 'true_positive'"
                                " WHERE investigation_id = :i"), {"i": members[0]})  # fmt: skip
    async with world.app() as http:
        await sign_in(http, "mina")
        threat = next(g for g in (await http.get(f"{V1}/patterns")).json()["groups"]
                      if g["rule_id"] == biggest["rule_id"])  # fmt: skip
    assert threat["recommendation"] is None  # a true positive is never recommended for closing
