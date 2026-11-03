"""AR2 (D-150, D-160) against the database, as ARGUS's own login: the agent's queue takes one
investigation per pattern (per rule and IST day, split by the evidence's flags), raised ones first,
at most ``--agent-per-day`` patterns a day; the other members share the run and are never
assessed, scored or accepted through it."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import patterns, queue, runner
from argus.assess.runner import Verdict
from argus.llm.privacy import Privacy, load_policy
from argus.web import assessed
from tests.integration.cases.conftest import investigation, make_person, rows
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
ENGINE, AGENT = "engine@1", "agent@1"
BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.0}
LISTED = {"name": "ti.listed", "status": "known", "value": 1}
SEVERITY = ("low", "medium", "high", "critical")


@pytest.fixture(scope="module")
def layer() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


async def make(
    owner: AsyncEngine, *, rule: str = "r1", host: int = 1, day: int = 0, severity: str = "high",
    signals: tuple[dict[str, Any], ...] = (), minutes: int = 10, engine_said: bool = True,
) -> uuid.UUID:  # fmt: skip
    """An unreviewed investigation with its dossier and, as the pipeline leaves it, the decision
    engine's "no decision" on that dossier."""
    inv = await investigation(owner, rule=rule, actor=(("source.ip", f"10.1.1.{host}"),),
                              severity=severity, day=day)  # fmt: skip
    dossier = inv.hex.ljust(64, "0")
    body = {"local_signals": list(signals), "signals": [], "report": {"steps": []},
            "context": {"pack": {"fields": {}}}, "facts": {"rule_name": rule}}  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(minutes=minutes), "i": inv},
        )
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'generic@12', 1, 1, 'collect', 'generic', 'evidence_ready',"
                " :h, CAST(:b AS jsonb), 0, :t)"
            ),
            {"i": inv, "h": dossier, "b": json.dumps(body), "t": NOW - timedelta(minutes=minutes)},
        )
        if engine_said:
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, status, run_after, decided_by, reasons, finished_at)"
                    " VALUES (:i, 1, 'generic@12', :h, :h, :a, 'no_decision', now(), :a,"
                    " '[\"x\"]'::jsonb, now())"
                ),
                {"i": inv, "h": dossier, "a": ENGINE},
            )
    return inv


async def schedule(engine: AsyncEngine, layer: Privacy, **more: Any) -> patterns.Scheduled:
    args: dict[str, Any] = {"limit": 50, "after": ENGINE, "per_day": 100, **more}
    async with engine.begin() as conn:
        return await patterns.schedule(conn, layer, AGENT, NOW, **args)


async def agent_rows(engine: AsyncEngine) -> list[Any]:
    return await rows(
        engine,
        "SELECT id, investigation_id, status FROM assessments WHERE assessor = :a ORDER BY id",
        a=AGENT,
    )


async def shares(engine: AsyncEngine) -> set[tuple[int, uuid.UUID]]:
    found = await rows(engine, "SELECT assessment_id, investigation_id FROM assessment_shares")
    return {(s.assessment_id, s.investigation_id) for s in found}


async def test_a_pattern_gets_one_run_and_every_member_is_attached_to_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    members = [await make(migrated_engine, host=n, severity=SEVERITY[n % 4], minutes=10 + n)
               for n in range(1, 6)]  # fmt: skip
    got = await schedule(app_engine, layer)
    assert (got.queued, got.shared) == (1, 5)
    (run,) = await agent_rows(app_engine)
    assert run.investigation_id == members[2]  # the most severe of the five
    assert await shares(app_engine) == {(run.id, m) for m in members}
    for member in members:
        if member != run.investigation_id:  # no assessment of its own: never scored or accepted
            assert await rows(app_engine, "SELECT * FROM assessments WHERE investigation_id = :i"
                              " AND assessor = :a", i=member, a=AGENT) == []  # fmt: skip
    again = await schedule(app_engine, layer)
    assert (again.queued, again.shared) == (0, 0)  # nothing new, nothing twice
    assert len(await agent_rows(app_engine)) == 1


async def test_the_run_goes_to_the_most_severe_and_then_the_newest(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    await make(migrated_engine, host=1, severity="high", minutes=5)
    newest = await make(migrated_engine, host=2, severity="critical", minutes=20)
    older = await make(migrated_engine, host=3, severity="critical", minutes=60)
    await schedule(app_engine, layer)
    (run,) = await agent_rows(app_engine)
    assert run.investigation_id == newest
    assert older != newest


async def test_a_member_arriving_later_joins_the_run_and_costs_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    first = await make(migrated_engine, host=1)
    await schedule(app_engine, layer)
    (run,) = await agent_rows(app_engine)
    late = await make(migrated_engine, host=2, minutes=1)
    got = await schedule(app_engine, layer, per_day=1)  # the day's runs are used up
    assert (got.queued, got.shared) == (0, 1)
    assert await shares(app_engine) == {(run.id, first), (run.id, late)}
    assert len(await agent_rows(app_engine)) == 1


async def test_flagged_and_plain_members_of_a_rule_are_two_patterns_and_the_flagged_goes_first(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    plain = [await make(migrated_engine, host=n, severity="critical") for n in (1, 2)]
    flagged = [await make(migrated_engine, host=n, severity="low", signals=(BEACON,))
               for n in (3, 4)]  # fmt: skip
    one = await schedule(app_engine, layer, limit=1)  # the batch is one pattern a pass
    assert one.queued == 1
    (first,) = await agent_rows(app_engine)
    assert first.investigation_id in flagged  # raised first, whatever the severity
    two = await schedule(app_engine, layer, limit=1)
    assert two.queued == 1
    second = (await agent_rows(app_engine))[1]
    assert second.investigation_id in plain
    attached = await shares(app_engine)
    assert {inv for a, inv in attached if a == first.id} == set(flagged)
    assert {inv for a, inv in attached if a == second.id} == set(plain)


async def test_a_pattern_whose_destination_outside_intel_flags_goes_first_without_splitting(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    """AR3 (D-165): the outside flag puts a pattern's run first, but it is not part of the
    pattern's key (it arrives after the dossier, and would split the pattern in two)."""
    hot = await make(migrated_engine, rule="hot", host=1, severity="low")
    await make(migrated_engine, rule="cold", host=2, severity="critical")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigation_raises (investigation_id, version, dossier_hash, flags)"
                " VALUES (:i, 1, 'h', CAST(:f AS jsonb))"
            ),
            {"i": hot, "f": json.dumps(["flagged by outside threat intel"])},
        )
    one = await schedule(app_engine, layer, limit=1)
    assert one.queued == 1
    (first,) = await agent_rows(app_engine)
    assert first.investigation_id == hot  # first, whatever the severity of the other
    other = await make(migrated_engine, rule="hot", host=3, severity="low")
    got = await schedule(app_engine, layer, limit=1)
    assert (await shares(app_engine)) >= {(first.id, hot), (first.id, other)}
    assert got.queued == 1  # the cold pattern's run, not a second run for the hot one


async def test_the_daily_cap_counts_patterns_not_investigations(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    for rule in ("a", "b", "c"):
        for host in (1, 2, 3):  # nine investigations, three patterns
            await make(migrated_engine, rule=rule, host=host)
    got = await schedule(app_engine, layer, per_day=2)
    assert (got.queued, got.shared) == (2, 6)
    async with app_engine.connect() as conn:
        assert await patterns.runs_today(conn, AGENT, NOW) == 2
    again = await schedule(app_engine, layer, per_day=2)
    assert again.queued == 0  # two patterns a day
    more = await schedule(app_engine, layer, per_day=3)
    assert more.queued == 1  # raising the cap runs the last one
    assert len(await agent_rows(app_engine)) == 3
    assert len(await shares(app_engine)) == 9


async def test_another_day_is_another_pattern(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    await make(migrated_engine, host=1, day=0)
    await make(migrated_engine, host=2, day=1)
    assert (await schedule(app_engine, layer)).queued == 2


async def test_only_what_the_engine_could_not_decide_and_nobody_reviewed_is_taken(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    undecided = await make(migrated_engine, host=1)
    await make(migrated_engine, host=2, engine_said=False)  # the engine has not looked yet
    reviewed = await make(migrated_engine, host=3)
    owed = await make(migrated_engine, host=4)
    asha = await make_person(app_engine, "asha")
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 2, :u, 'reviewed', 'benign_expected')"
            ),
            {"i": reviewed, "u": asha.user_id},
        )
    got = await schedule(app_engine, layer, skip={owed})
    assert (got.queued, got.shared) == (1, 1)
    assert (await agent_rows(app_engine))[0].investigation_id == undecided
    assert {inv for _, inv in await shares(app_engine)} == {undecided}


async def test_a_failed_run_hands_the_pattern_to_another_member_and_three_end_the_day(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    for host in range(1, 7):
        await make(migrated_engine, host=host, minutes=host)
    seen_runs: list[uuid.UUID] = []
    for n in range(patterns.MAX_FAILED + 1):
        got = await schedule(app_engine, layer)
        runs = await agent_rows(app_engine)
        if n == patterns.MAX_FAILED:
            assert got.queued == 0  # three failures: the pattern waits for tomorrow
            assert len(runs) == patterns.MAX_FAILED
            break
        assert got.queued == 1
        latest = runs[-1]
        assert latest.investigation_id not in seen_runs  # another member each time
        seen_runs.append(latest.investigation_id)
        async with migrated_engine.begin() as conn:  # the worker gave up on it
            await conn.execute(
                text("UPDATE assessments SET status = 'failed', finished_at = now() WHERE id = :i"),
                {"i": latest.id},
            )


async def test_a_run_in_progress_covers_its_pattern(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    await make(migrated_engine, host=1)
    await schedule(app_engine, layer)
    (run,) = await agent_rows(app_engine)
    assert run.status == "queued"
    await make(migrated_engine, host=2)
    got = await schedule(app_engine, layer)
    assert got.queued == 0  # the queued run covers it
    assert len(await agent_rows(app_engine)) == 1


async def test_two_passes_at_once_do_not_pick_two_representatives_for_one_pattern(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    first = await make(migrated_engine, host=1, severity="medium")
    picked = asyncio.Event()
    commit = asyncio.Event()

    async def slow_pass() -> patterns.Scheduled:
        async with app_engine.begin() as conn:  # a pass that has picked and not yet committed
            got = await patterns.schedule(conn, layer, AGENT, NOW, limit=50, after=ENGINE,
                                          per_day=100)  # fmt: skip
            picked.set()
            await commit.wait()
        return got

    one = asyncio.create_task(slow_pass())
    try:
        await asyncio.wait_for(picked.wait(), 10)
        # a worse-looking member would be the other pass's choice if it could not see the first run
        better = await make(migrated_engine, host=2, severity="critical")
        two = asyncio.create_task(schedule(app_engine, layer))
        done, _ = await asyncio.wait({two}, timeout=1.0)
        assert not done  # it waits for the first pass to commit
    finally:
        commit.set()
    assert (await one).queued == 1
    got = await asyncio.wait_for(two, 10)
    assert (got.queued, got.shared) == (
        0,
        1,
    )  # the first run covers the pattern; the new member joins
    (run,) = await agent_rows(app_engine)
    assert run.investigation_id == first
    assert await shares(app_engine) == {(run.id, first), (run.id, better)}


class Fake:
    """The investigator, replaced by a model-free stand-in that proposes."""

    name = AGENT

    async def assess(self, conn: Any, investigation_id: uuid.UUID, body: Any) -> Verdict:
        return Verdict("true_positive", "agent@1#fake", ["It beacons."], 0.75)


async def test_a_shared_run_is_shown_on_the_others_and_is_never_theirs(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    members = [await make(migrated_engine, host=n, minutes=n) for n in (1, 2, 3)]
    await schedule(app_engine, layer)
    (run,) = await agent_rows(app_engine)
    other = next(m for m in members if m != run.investigation_id)
    async with app_engine.connect() as conn:
        assert await assessed.shared(conn, other) is None  # nothing to show before it finishes
    done = await runner.run_once(app_engine, Fake(), "w", lambda: datetime.now(UTC), 5)
    assert done["proposed"] == 1

    async with app_engine.connect() as conn:
        shown = await assessed.shared(conn, other)
        assert shown is not None
        assert (shown.source, shown.earlier) == (run.investigation_id, False)
        assert (shown.detail.status, shown.detail.outcome) == ("proposed", "true_positive")
        assert await assessed.shared(conn, run.investigation_id) is None  # its own is its own
        assert [d.assessor for d in await assessed.history(conn, other)] == [ENGINE]
        assert await queue.current(conn, other, AGENT) is None  # not its assessment
        assert (await assessed.verdicts(conn, [other])).get(other, {}).get("assessor") == ENGINE
        assert (await queue.current(conn, run.investigation_id, AGENT)) is not None
    # scores, closures and write-back read assessments and reviews: the others have none
    assert await rows(app_engine, "SELECT * FROM assessments WHERE investigation_id = :i"
                      " AND assessor = :a", i=other, a=AGENT) == []  # fmt: skip
    proposals = await rows(app_engine, "SELECT investigation_id FROM assessments"
                                       " WHERE status = 'proposed'")  # fmt: skip
    assert [p.investigation_id for p in proposals] == [run.investigation_id]


async def test_the_assessed_investigation_that_changed_shows_its_run_as_its_earlier_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    first = await make(migrated_engine, host=1)
    await schedule(app_engine, layer)
    await runner.run_once(app_engine, Fake(), "w", lambda: datetime.now(UTC), 5)
    async with migrated_engine.begin() as conn:  # new alerts: version 2 and its dossier
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"),
                           {"i": first})  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " SELECT investigation_id, 2, pack, 2, job_id, run_kind, family, status,"
                " repeat('9', 64), body, evidence_count, now() FROM dossiers WHERE"
                " investigation_id = :i"
            ),
            {"i": first},
        )
    async with app_engine.connect() as conn:
        assert await queue.current(conn, first, AGENT) is None  # the old run is stale
    got = await schedule(app_engine, layer, after=None)
    assert (got.queued, got.shared) == (0, 1)  # the day's pattern is covered: no new call
    async with app_engine.connect() as conn:
        shown = await assessed.shared(conn, first)
    assert shown is not None
    assert (shown.source, shown.earlier) == (first, True)


async def test_the_members_of_a_suggested_case_go_to_the_head_of_the_queue(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    """AR2b: a host seen by two rules, one of them flagged, becomes a suggested case; its
    investigations (the unflagged one too) are run before a plain critical pattern."""
    from argus.assess import raised
    from argus.assets.classify import IpClassifier
    from argus.cases import suggest
    from argus.cases.membership import Shared

    download = await make(migrated_engine, rule="download", host=1, severity="low", minutes=30)
    beacon = await make(
        migrated_engine, rule="beacon", host=1, severity="low", signals=(BEACON, LISTED), minutes=20
    )
    plain = await make(migrated_engine, rule="plain", host=9, severity="critical", minutes=1)
    async with app_engine.begin() as conn:
        await raised.evaluate(conn, NOW)
    done = await suggest.run(
        app_engine, classifier=IpClassifier(None), dry_run=False, shared=Shared(), now=NOW
    )
    assert done.applied == {"suggested": 1}

    order = []
    for _ in range(3):
        assert (await schedule(app_engine, layer, limit=1)).queued == 1
        order.append((await agent_rows(app_engine))[-1].investigation_id)
    assert order[2] == plain
    assert set(order[:2]) == {download, beacon}  # both of the story's rules before it
