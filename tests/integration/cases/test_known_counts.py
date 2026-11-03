"""New work and known work, counted apart (AR4b, D-169 point 8), against an independent
recomputation: over random mixes of severity, evidence, reviews and the decisions about notified
cases' devices, Needs attention, the "notified, still active" list and the counts agree with a
plain Python statement of the rules, and new + known is what Needs attention was before
notices."""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Notify, Open
from argus.cases.model import Member
from argus.cases.service import CaseService
from argus.web import casepages, queries
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.knownkit import BEACON, OUTSIDE

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
WHY = "changed since notice: a new flagged destination (x)"
REASON = "Changed since notice: a new flagged destination (x)."


@dataclass(frozen=True)
class Expected:
    old: bool  # in Needs attention before notices existed
    new: bool  # in Needs attention now
    known: bool  # a known infection's investigation (the "notified, still active" list)
    held: bool  # known, and kept out of Needs attention by it (the tile's number)
    frozen: bool  # decided known for a case that ended: kept out, counted nowhere (D-181)


def by_the_rules(
    human: str, severity: str, flags: list[str], outcome: str | None, notified: bool
) -> Expected:
    """The rules, written out again: an unreviewed investigation is in Needs attention when the
    rule rates it high or critical or its evidence raises it (a flagged destination and another
    flag); a follow-up and a change since a review always are, unless it is decided known (and a
    decision of a case that has ended stays: it is frozen); what changed since a notice is, until
    a person reviews it."""
    raised = OUTSIDE in flags and len(set(flags)) >= 2
    would = human == "changed_since_review" or (
        human == "unreviewed" and (severity in ("critical", "high") or raised)
    )
    old = human == "follow_up" or would
    decided_known = outcome == "known"
    live = decided_known and notified
    changed = outcome == "changed"
    new = human == "follow_up" or (not decided_known and would) or (changed and human != "reviewed")
    return Expected(old, new, live and would, live and would, decided_known and not live and would)


async def reviewed(owner: AsyncEngine, inv: uuid.UUID, user: int, action: str) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 1, :u, :a, :o)"
            ),
            {"i": inv, "u": user, "a": action,
             "o": "true_positive" if action == "reviewed" else None},
        )  # fmt: skip


@pytest.mark.parametrize("seed", range(6))
async def test_new_plus_known_is_what_needs_attention_was(
    seed: int, app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    rnd = random.Random(seed)
    asha = people["asha"]
    members = [await investigation(migrated_engine) for _ in range(2)]
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        cases = []
        for member in members:
            opened = await service.open(
                asha.actor(), Open("Beacon", "high", "person", (Member(member, "person"),))
            )
            cases.append(opened.case.id)
        notified, plain = cases
        await service.apply(asha.actor(), notified, Notify("the owner", "email"),
                            expected_version=None)  # fmt: skip
    expected: dict[uuid.UUID, Expected] = {}
    for n in range(30):
        severity = rnd.choice(["low", "medium", "high", "critical"])
        inv = await investigation(migrated_engine, actor=(("source.ip", f"10.9.{seed}.{n}"),),
                                  severity=severity, alerts=1)  # fmt: skip
        flags = rnd.choice([[], [BEACON], [BEACON, OUTSIDE], [OUTSIDE]])
        human = rnd.choice(["unreviewed", "unreviewed", "reviewed", "follow_up",
                            "changed_since_review"])  # fmt: skip
        if human != "unreviewed":
            await reviewed(migrated_engine, inv, asha.user_id,
                           "follow_up" if human == "follow_up" else "reviewed")  # fmt: skip
        version = 2 if human == "changed_since_review" else 1
        outcome = rnd.choice([None, None, "known", "changed"])
        case = rnd.choice([notified, plain])
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE investigations SET version = :v WHERE id = :i"),
                               {"v": version, "i": inv})  # fmt: skip
            await conn.execute(
                text("INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                     " flags) VALUES (:i, :v, repeat('a', 64), CAST(:f AS jsonb))"),
                {"i": inv, "v": version, "f": str(flags).replace("'", '"')},
            )  # fmt: skip
            if outcome is not None:
                await conn.execute(
                    text("INSERT INTO case_known_matches (investigation_id, case_id, version,"
                         " outcome, why, changed_version) VALUES (:i, :c, :v, :o, :w, :cv)"),
                    {"i": inv, "c": case, "v": version, "o": outcome,
                     "w": WHY if outcome == "changed" else None,
                     "cv": version if outcome == "changed" else None},
                )  # fmt: skip
        expected[inv] = by_the_rules(human, severity, flags, outcome, case == notified)
    async with app_engine.connect() as conn:
        counts = await queries.counts(conn, NOW)
        shown = {s.id for s in await queries.inbox(conn, "attention", limit=100)}
        known = {s.id for s in await queries.inbox(conn, "known", limit=100)}
        before = int(
            await conn.scalar(
                text(
                    f"SELECT count(*) FROM investigations i {queries._STATE}"  # noqa: S608
                    f" WHERE {queries.BEFORE_NOTICES}"
                )
            )
            or 0
        )
    held = {i for i, e in expected.items() if e.held}
    frozen = {i for i, e in expected.items() if e.frozen}
    old = {i for i, e in expected.items() if e.old}
    new = {i for i, e in expected.items() if e.new}
    # the two investigations that hold the cases are unreviewed and rated high: new work
    assert shown == new | set(members)
    assert counts["attention"] == len(new) + len(members)
    assert before == len(old) + len(members)
    assert counts["known"] == len(held)
    assert known == held  # the tile's number and its list are the same set (D-181)
    assert len(known) == counts["known"]
    # new + known is what Needs attention was: what a known infection keeps out is the part of
    # the old list that is not new, and what is new but was not on the old list is a change; what
    # a case that ended decided known stays out too (frozen), and is counted nowhere
    assert len(old - held - frozen) + len(held) + len(frozen) == len(old)
    assert new - old == {i for i in new if i not in old}
    assert (new & old) == old - held - frozen
    assert counts["attention"] + counts["known"] + len(frozen) - len(new - old) == before


async def test_a_known_investigation_of_a_case_no_longer_notified_stays_known_until_a_new_version(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The case ends (contained, closed, merged, or its notice withdrawn): what it decided known
    is frozen and never comes back as new work (D-181); a later version of the investigation is
    judged afresh by the normal pipeline."""
    asha = people["asha"]
    kept = await investigation(migrated_engine, severity="high")
    other = await investigation(migrated_engine, severity="high")
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        opened = await service.open(
            asha.actor(), Open("Beacon", "high", "person", (Member(other, "person"),))
        )
        case = opened.case.id
        await service.apply(asha.actor(), case, Notify("the owner", "email"), expected_version=None)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                 " VALUES (:i, :c, 1, 'known')"), {"i": kept, "c": case},
        )  # fmt: skip
    async with app_engine.connect() as conn:
        assert kept not in {s.id for s in await queries.inbox(conn, "attention", limit=50)}
        assert {s.id for s in await queries.inbox(conn, "known", limit=50)} == {kept}
    # the case stops being notified (contained, in life): what it held stays held
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER cases_guard"))
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE cases SET notified_at = NULL WHERE id = :c"), {"c": case})
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases ENABLE ALWAYS TRIGGER cases_guard"))
    async with app_engine.connect() as conn:
        assert kept not in {s.id for s in await queries.inbox(conn, "attention", limit=50)}
        assert await queries.inbox(conn, "known", limit=50) == []  # no longer "still active"
        assert (await queries.counts(conn, NOW))["known"] == 0
        found = await queries.investigation(conn, kept)
        assert found is not None
        assert (found.known_case, found.known_outcome) == (1, "known")  # the page still says so
        assert found.known_since is None
    # a later version of the investigation is a new decision: the normal pipeline
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": kept})
    async with app_engine.connect() as conn:
        assert kept in {s.id for s in await queries.inbox(conn, "attention", limit=50)}
        found = await queries.investigation(conn, kept)
        assert found is not None
        assert found.known_outcome is None


async def test_a_change_outlives_the_next_version_until_a_person_reviews_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """D-181: Needs attention, the investigation's reasons and the case's attention hold a change
    through the investigation's next versions; a review at or after the change ends it."""
    asha = people["asha"]
    inv = await investigation(migrated_engine, severity="low", alerts=1)
    anchor = await investigation(migrated_engine, severity="low", alerts=1)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        opened = await service.open(
            asha.actor(), Open("Beacon", "high", "person", (Member(anchor, "person"),))
        )
        case = opened.case.id
        await service.apply(asha.actor(), case, Notify("the owner", "email"), expected_version=None)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET version = 3 WHERE id = :i"), {"i": inv})
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome,"
                 " why, changed_version) VALUES (:i, :c, 3, 'changed', :w, 3)"),
            {"i": inv, "c": case, "w": WHY},
        )  # fmt: skip

    async def state() -> tuple[bool, list[str], bool]:
        """In Needs attention, its reasons, and whether the case page asks for attention."""
        async with app_engine.connect() as conn:
            listed = {s.id: s for s in await queries.inbox(conn, "attention", limit=50)}
            page = await casepages.row_of(conn, case)
            assert page is not None
            return inv in listed, listed[inv].reasons if inv in listed else [], page.needs_attention

    assert await state() == (True, [REASON], True)
    # the next alerts of the investigation: versions 4 and 5. The change is still there.
    for version in (4, 5):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE investigations SET version = :v WHERE id = :i"),
                               {"v": version, "i": inv})  # fmt: skip
        assert await state() == (True, [REASON], True)
    # a person reviews a version older than the change: it still waits
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, 2, 1, :u, 'reviewed', 'true_positive')"),
            {"i": inv, "u": asha.user_id},
        )  # fmt: skip
    assert (await state())[0]
    # a review of a version at or after the change (here the current one, 5) ends it
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, 5, 1, :u, 'reviewed', 'true_positive')"),
            {"i": inv, "u": asha.user_id},
        )  # fmt: skip
    listed_now, _, case_now = await state()
    assert not listed_now
    assert not case_now
