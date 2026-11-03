"""P3 (D-084): the assessment queue: queued once per view, leased and fenced, deferred without
holding a lease, stale assessments never current, acceptance fenced."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue, runner
from argus.llm.privacy import Privacy, load_policy
from argus.web import auth, queries
from argus.web.reviews import add_review
from tests.integration.web.conftest import NOW, PASSWORD
from tests.unit.llm.conftest import ASSETS

pytestmark = pytest.mark.integration
H = "a" * 64


def body(note: str = "x") -> dict[str, Any]:
    return {"facts": {"rule_name": note, "first_event_at": "2026-10-14T20:30:00Z"}}


async def dossiers(seeded: AsyncEngine, owner: AsyncEngine, n: int) -> list[queries.Summary]:
    async with seeded.connect() as conn:
        found = (await queries.inbox(conn, "all"))[:n]
    async with owner.begin() as conn:
        for inv in found:
            await put_dossier(conn, inv.id, inv.version, H, body())
    return found


async def put_dossier(conn: Any, inv: uuid.UUID, version: int, h: str, b: dict[str, Any]) -> None:
    import json

    await conn.execute(
        text(
            "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
            " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
            " VALUES (:i, :v, :p, :v, 1, 'collect', 'generic', 'evidence_ready', :h,"
            " CAST(:b AS jsonb), 0, now())"
        ),
        {"i": inv, "v": version, "p": f"generic@{h[0]}", "h": h, "b": json.dumps(b)},
    )


async def test_enqueue_once_per_view_and_never_for_a_reviewed_one(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    a, b = await dossiers(seeded, migrated_engine, 2)
    async with seeded.begin() as conn:
        args = (a.version, "generic@a", H, "1" * 64, "engine@1", NOW)
        assert await queue.enqueue(conn, a.id, *args)
        assert not await queue.enqueue(conn, a.id, *args)  # same view: once
        assert await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "agent@1", NOW)
        assert not await queue.enqueue(conn, a.id, a.version + 1, "generic@a", H, "2" * 64,
                                       "engine@1", NOW)  # not its current version  # fmt: skip
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        await add_review(conn, made[1], b.id, action="reviewed", outcome="benign_expected",
                         note=None, seen_review=None, seen_version=b.version)  # fmt: skip
        assert not await queue.enqueue(conn, b.id, b.version, "generic@a", H, "3" * 64,
                                       "engine@1", NOW)  # fmt: skip


async def test_claims_are_leases_fenced_and_given_up_after_crashes(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    a, b = await dossiers(seeded, migrated_engine, 2)
    async with seeded.begin() as conn:
        for inv, vh in ((a, "1"), (b, "2")):
            await queue.enqueue(conn, inv.id, inv.version, "generic@a", H, vh * 64, "e", NOW)
    async with seeded.begin() as conn:
        first = await queue.claim(conn, "w1", NOW)
        second = await queue.claim(conn, "w2", NOW)
        none = await queue.claim(conn, "w3", NOW)
    assert len(first) == len(second) == 1
    assert first[0].assessment_id != second[0].assessment_id
    assert none == []
    later = NOW + queue.LEASE + timedelta(seconds=1)  # w1 died: its lease expired
    async with seeded.begin() as conn:
        again = await queue.claim(conn, "w4", later, limit=10)
    assert [c.assessment_id for c in again] == [first[0].assessment_id, second[0].assessment_id]
    async with seeded.begin() as conn:
        with pytest.raises(queue.LeaseLostError):
            await queue.propose(conn, first[0], later, "true_positive", "e", [])
    async with seeded.begin() as conn:
        await queue.propose(conn, again[0], later, "true_positive", "e", ["c2"], 0.9)
    t = later
    for _ in range(queue.MAX_LOST):  # the second row's workers keep dying
        t += queue.LEASE + timedelta(seconds=1)
        async with seeded.begin() as conn:
            await queue.claim(conn, "w", t)
    async with seeded.connect() as conn:
        rows: dict[int, str] = dict(
            (await conn.execute(text("SELECT id, status FROM assessments"))).all()
        )
    assert rows[first[0].assessment_id] == "proposed"
    assert rows[second[0].assessment_id] == "failed"


async def test_defer_holds_no_lease_and_failures_back_off(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "e", NOW)
        (job,) = await queue.claim(conn, "w", NOW)
        await queue.defer(conn, job, NOW, NOW + timedelta(minutes=7))
        assert await queue.claim(conn, "w", NOW + timedelta(minutes=6)) == []
        row = (await conn.execute(text(
            "SELECT status, lease_until, deferrals, failures FROM assessments"))).one()  # fmt: skip
    assert tuple(row) == ("queued", None, 1, 0)
    t = NOW + timedelta(minutes=7)
    statuses = []
    for _ in range(queue.MAX_FAILURES):
        async with seeded.begin() as conn:
            claimed = await queue.claim(conn, "w", t)
            assert len(claimed) == 1
            statuses.append(await queue.fail(conn, claimed[0], t, "boom" * 200))
            t += timedelta(days=1)
    assert statuses == ["queued"] * (queue.MAX_FAILURES - 1) + ["failed"]
    async with seeded.connect() as conn:
        error = await conn.scalar(text("SELECT error FROM assessments"))
    assert len(error) == 500


async def test_current_proposals_and_fenced_acceptance(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "e", NOW)
        (job,) = await queue.claim(conn, "w", NOW)
        with pytest.raises(ValueError, match="not an outcome"):
            await queue.propose(conn, job, NOW, "maybe", "e", [])
        await queue.propose(conn, job, NOW, "benign_expected", "engine@1: key", ["k"], 0.97)
        cur = await queue.current(conn, a.id)
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
    assert cur is not None
    assert (cur.outcome, cur.decided_by, cur.reasons, cur.confidence) == (
        "benign_expected", "engine@1: key", ["k"], 0.97)  # fmt: skip
    async with seeded.begin() as conn:
        await queue.accept(conn, cur.assessment_id, made[1].user_id, "ok")
        linked = await conn.scalar(
            text("SELECT assessment_id FROM review_events WHERE investigation_id = :i"),
            {"i": a.id},
        )
    assert linked == cur.assessment_id
    async with seeded.begin() as conn:
        with pytest.raises(queue.AssessmentConflict, match="already reviewed"):
            await queue.accept(conn, cur.assessment_id, made[1].user_id)
    async with migrated_engine.begin() as conn:  # new alerts: the investigation moves on
        await conn.execute(text("UPDATE investigations SET version = version + 1 WHERE id = :i"),
                           {"i": a.id})  # fmt: skip
    async with seeded.begin() as conn:
        assert await queue.current(conn, a.id) is None  # stale: never shown as current
        with pytest.raises(queue.AssessmentConflict, match="changed"):
            await queue.accept(conn, cur.assessment_id, made[1].user_id)


class Fake:
    name = "fake"

    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers

    async def assess(self, conn: Any, investigation_id: uuid.UUID, body: Any) -> runner.Verdict:
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        assert isinstance(answer, runner.Verdict)
        return answer


async def test_schedule_and_run(seeded: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    found = await dossiers(seeded, migrated_engine, 4)
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "fake", NOW) == 4
        assert await runner.schedule(conn, privacy, "fake", NOW) == 0
    async with migrated_engine.begin() as conn:  # a re-derivation with the same view: no new row
        await put_dossier(conn, found[0].id, found[0].version, "b" * 64, body())
        await put_dossier(conn, found[1].id, found[1].version, "c" * 64, body("changed"))
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "fake", NOW) == 1
    fake = Fake([
        runner.Verdict("true_positive", "fake", ["c2"], 0.9),
        runner.Verdict(None, "fake", ["unknown"]),
        runner.Defer(NOW + timedelta(hours=1), "budget"),
        RuntimeError("boom"),
        runner.Verdict("benign_expected", "fake", []),
    ])  # fmt: skip
    counts = await runner.run_once(seeded, fake, "w", lambda: NOW, limit=10)
    assert counts == {"proposed": 2, "no_decision": 1, "deferred": 1, "failed": 1, "lost": 0}
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT status, count(*) FROM assessments GROUP BY 1 ORDER BY 1"))).all()  # fmt: skip
    assert dict(rows) == {"no_decision": 1, "proposed": 2, "queued": 2}


async def test_only_the_newest_dossier_is_scheduled(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """An older pack's dossier of the same version is never assessed once the newest is."""
    privacy = Privacy.build(load_policy(), ASSETS)
    (a,) = await dossiers(seeded, migrated_engine, 1)  # pack generic@a
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE dossiers SET created_at = now() - interval '1 hour'"))
        await put_dossier(conn, a.id, a.version, "b" * 64, body("newer"))  # pack generic@b
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "fake", NOW) == 1
        assert await runner.schedule(conn, privacy, "fake", NOW) == 0  # not the older one
        rows = (await conn.execute(text("SELECT pack FROM assessments"))).all()
    assert [r.pack for r in rows] == ["generic@b"]


async def test_a_lease_is_five_minutes_and_ten_deaths_give_up(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "e", NOW)
        assert len(await queue.claim(conn, "w1", NOW)) == 1
        until = await conn.scalar(text("SELECT lease_until FROM assessments"))
        assert until == NOW + timedelta(minutes=5)
        assert await queue.claim(conn, "w2", NOW + timedelta(minutes=5)) == []  # still held
    t = NOW + timedelta(minutes=5, microseconds=1)
    for _ in range(9):  # nine more deaths: ten in all
        async with seeded.begin() as conn:
            assert len(await queue.claim(conn, "w", t)) == 1
        t += timedelta(minutes=5, microseconds=1)
    async with seeded.begin() as conn:
        assert await queue.claim(conn, "w", t) == []
        row = (await conn.execute(text("SELECT status, error, finished_at FROM assessments"))).one()
    assert tuple(row) == ("failed", "gave up: the worker died 10 times while running it", t)


async def test_claims_and_currents_carry_their_row(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from dataclasses import FrozenInstanceError, astuple

    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "engine@1", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "engine@1")
        await queue.no_decision(conn, job, NOW, "engine@1#x", ["no key"])
        cur = await queue.current(conn, a.id, "engine@1")
        row_id = await conn.scalar(text("SELECT id FROM assessments"))
    assert astuple(job) == (row_id, a.id, a.version, "generic@a", H, "1" * 64, "engine@1", 1, "w")
    assert cur is not None
    assert astuple(cur) == (row_id, a.version, "engine@1", "no_decision", None, None,
                            "engine@1#x", ["no key"], NOW)  # fmt: skip
    with pytest.raises(FrozenInstanceError):
        job.claim = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        cur.status = "proposed"  # type: ignore[misc]


async def test_every_finish_is_fenced_and_failures_back_off_doubling(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "e", NOW)
        (stale,) = await queue.claim(conn, "w1", NOW)
    later = NOW + timedelta(minutes=6)
    async with seeded.begin() as conn:
        (job,) = await queue.claim(conn, "w2", later)
    finishes = (
        lambda conn: queue.no_decision(conn, stale, later, "e", []),
        lambda conn: queue.fail(conn, stale, later, "boom"),
        lambda conn: queue.defer(conn, stale, later, later + timedelta(hours=1)),
    )
    for finish in finishes:
        async with seeded.begin() as conn:
            with pytest.raises(queue.LeaseLostError):
                await finish(conn)
    t = later
    for failures, wait in ((0, 2), (1, 4), (2, 8)):  # two minutes, doubled per failure
        async with seeded.begin() as conn:
            if failures:
                (job,) = await queue.claim(conn, "w", t)
            assert await queue.fail(conn, job, t, "boom") == "queued"
            row = (await conn.execute(text("SELECT run_after, failures FROM assessments"))).one()
        assert tuple(row) == (t + timedelta(minutes=wait), failures + 1)
        t += timedelta(minutes=wait)
    for _ in range(2):  # five failures in all: given up
        async with seeded.begin() as conn:
            (job,) = await queue.claim(conn, "w", t)
            status = await queue.fail(conn, job, t, "boom")
        t += timedelta(days=1)
    assert status == "failed"


async def test_a_newer_proposal_cannot_be_overtaken_and_conflicts_say_why(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        for assessor in ("first", "second"):
            await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, assessor, NOW)
            (job,) = await queue.claim(conn, "w", NOW, assessor)
            await queue.propose(conn, job, NOW, "benign_expected", assessor, [])
        older, newer = (await conn.execute(text("SELECT id FROM assessments ORDER BY id"))).all()
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
    async with seeded.begin() as conn:
        with pytest.raises(
            queue.AssessmentConflict, match=r"^a newer assessment exists or it is already reviewed$"
        ):
            await queue.accept(conn, older[0], made[1].user_id)
    async with seeded.begin() as conn:
        with pytest.raises(
            queue.AssessmentConflict,
            match=r"^the investigation changed or the proposal is not current$",
        ):
            await queue.accept(conn, newer[0] + 1, made[1].user_id)
        await queue.accept(conn, newer[0], made[1].user_id)


async def test_a_wildcard_in_a_stamp_never_shields_another_stamp(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        for vh, by in (("1", "e#a_b: k"), ("2", "e#aXb: k"), ("3", "e#aXXXXb: k")):
            await queue.enqueue(conn, a.id, a.version, "generic@a", H, vh * 64, "e", NOW)
            (job,) = await queue.claim(conn, "w", NOW, "e")
            await queue.no_decision(conn, job, NOW, by, [])
        assert await queue.requeue(conn, "e", "e#a%b", NOW) == 3
    async with seeded.begin() as conn:  # and it still shields its own keyed assessments
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "4" * 64, "f", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "f")
        await queue.no_decision(conn, job, NOW, "e#a_%b: k", [])
        assert await queue.requeue(conn, "f", "e#a_%b", NOW) == 0


def test_verdicts_are_values_and_a_defer_says_why() -> None:
    from dataclasses import FrozenInstanceError

    with pytest.raises(FrozenInstanceError):
        runner.Verdict(None, "x").outcome = "true_positive"  # type: ignore[misc]
    wait = runner.Defer(NOW, "budget")
    assert (str(wait), wait.until) == ("budget", NOW)
    assert str(runner.Defer(NOW)) == ""


async def test_a_pass_queues_at_most_500(seeded: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                " bucket_start, bucket_end, previous_id, alert_count, first_event_at,"
                " last_event_at, severity, version) SELECT gen_random_uuid(), '1', 'bulk',"
                " 'k' || g, :s, :e, gen_random_uuid(), 1, :s, :s, 'low', 1"
                " FROM generate_series(1, 501) g"
            ),
            {"s": NOW, "e": NOW + timedelta(hours=1)},
        )
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " SELECT id, version, 'generic@a', version, 1, 'collect', 'generic',"
                " 'evidence_ready', :h, '{}'::jsonb, 0, now() FROM investigations"
                " WHERE rule_id = 'bulk'"
            ),
            {"h": H},
        )
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "fake", NOW) == 500
        assert await runner.schedule(conn, privacy, "fake", NOW) == 1


class Clocked(Fake):
    """Its first assessment takes longer than a lease."""

    def __init__(self, answers: list[Any]) -> None:
        super().__init__(answers)
        self.now = NOW

    def clock(self) -> Any:
        return self.now

    async def assess(self, conn: Any, investigation_id: uuid.UUID, body: Any) -> runner.Verdict:
        self.now = NOW + timedelta(minutes=6)
        return await super().assess(conn, investigation_id, body)


async def test_run_once_counts_what_happened(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        for n in range(11):
            await queue.enqueue(conn, a.id, a.version, "generic@a", H, f"{n:064}", "fake", NOW)
    fake = Fake([runner.Verdict("true_positive", "fake", [])] * 11)
    counts = await runner.run_once(seeded, fake, "w", lambda: NOW)  # ten at a time
    assert counts == {"proposed": 10, "no_decision": 0, "deferred": 0, "failed": 0, "lost": 0}
    assert len(fake.answers) == 1
    async with seeded.begin() as conn:  # a dossier that is gone: no decision, not assessed
        await queue.enqueue(conn, a.id, a.version, "generic@a", "f" * 64, "e" * 64, "fake", NOW)
    counts = await runner.run_once(seeded, Fake(fake.answers), "w", lambda: NOW)
    assert counts == {"proposed": 1, "no_decision": 1, "deferred": 0, "failed": 0, "lost": 0}
    async with seeded.connect() as conn:
        row = (await conn.execute(text(
            "SELECT status, decided_by, reasons FROM assessments WHERE dossier_hash = :h"),
            {"h": "f" * 64})).one()  # fmt: skip
    assert tuple(row) == ("no_decision", "fake", ["the dossier is gone"])


async def test_run_once_counts_lost_leases(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        for vh in "123":
            await queue.enqueue(conn, a.id, a.version, "generic@a", H, vh * 64, "fake", NOW)
    slow = Clocked([
        runner.Verdict("true_positive", "fake", []),
        runner.Defer(NOW + timedelta(hours=1)),
        RuntimeError("boom"),
    ])  # fmt: skip
    counts = await runner.run_once(seeded, slow, "w", slow.clock)
    assert counts == {"proposed": 0, "no_decision": 0, "deferred": 0, "failed": 0, "lost": 3}
    async with seeded.connect() as conn:
        rows = (
            await conn.execute(text("SELECT status, failures, deferrals FROM assessments"))
        ).all()
    assert [tuple(r) for r in rows] == [("running", 0, 0)] * 3


async def test_after_another_assessor_and_a_daily_quota(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    a, b, c = await dossiers(seeded, migrated_engine, 3)
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "e", NOW) == 3
        jobs = {j.investigation_id: j for j in await queue.claim(conn, "w", NOW, "e", 3)}
        await queue.no_decision(conn, jobs[a.id], NOW, "e", [])
        await queue.no_decision(conn, jobs[b.id], NOW, "e", [])
        await queue.propose(conn, jobs[c.id], NOW, "true_positive", "e", [], None)
        assert await runner.schedule(conn, privacy, "g", NOW, after="e") == 2
        assert await runner.schedule(conn, privacy, "g", NOW, after="e") == 0
        queued = await conn.execute(text("SELECT investigation_id FROM assessments"
                                         " WHERE assessor = 'g'"))  # fmt: skip
        assert set(queued.scalars()) == {a.id, b.id}
        assert await runner.schedule(conn, privacy, "q", NOW, per_day=1) == 1
        assert await runner.schedule(conn, privacy, "q", NOW, per_day=1) == 0
        assert await runner.schedule(conn, privacy, "q", NOW, per_day=3) == 2
        assert await runner.schedule(conn, privacy, "r", NOW, per_day=1) == 1
    async with migrated_engine.begin() as conn:  # yesterday's do not count today
        await conn.execute(text("UPDATE assessments SET created_at = :t WHERE assessor = 'r'"),
                           {"t": NOW - timedelta(days=1)})  # fmt: skip
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "r", NOW, per_day=1) == 1
        assert await runner.schedule(conn, privacy, "r", NOW, per_day=1) == 0


async def test_the_newest_dossiers_are_queued_first(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    found = await dossiers(seeded, migrated_engine, 3)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE dossiers SET created_at = created_at + interval '1 hour' WHERE"
                 " investigation_id = :i"), {"i": found[1].id},
        )  # fmt: skip
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "n", NOW, limit=1) == 1
        (got,) = (await conn.execute(text("SELECT investigation_id FROM assessments"))).scalars()
    assert got == found[1].id


async def test_no_transaction_is_open_while_assessing_and_the_lease_is_the_assessors(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await runner.schedule(conn, privacy, "slow", NOW)
    seen: dict[str, Any] = {}

    class Slow:
        name = "slow"
        lease = timedelta(minutes=17)

        async def assess(self, conn: Any, inv: uuid.UUID, body: Any) -> runner.Verdict:
            seen["open"] = conn.in_transaction()
            async with seeded.connect() as other:  # the row is not locked by the run
                seen["lease"] = await other.scalar(
                    text("SELECT lease_until FROM assessments WHERE assessor = 'slow'")
                )
                await other.execute(
                    text("SELECT 1 FROM assessments WHERE assessor = 'slow' FOR UPDATE NOWAIT")
                )
            return runner.Verdict("true_positive", "slow#1", ["r"], 0.5)

    counts = await runner.run_once(seeded, Slow(), "w", lambda: NOW)
    assert counts["proposed"] == 1
    assert seen["open"] is False
    assert seen["lease"] == NOW + timedelta(minutes=17)


async def test_a_quota_already_overrun_queues_nothing(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    await dossiers(seeded, migrated_engine, 3)
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "z", NOW, per_day=3) == 3
        assert await runner.schedule(conn, privacy, "z2", NOW) == 3
    async with seeded.begin() as conn:  # z has 3 today: a quota of 1 is overrun by 2
        assert await runner.schedule(conn, privacy, "z", NOW, per_day=1) == 0


async def test_a_person_asks_for_an_assessment_even_after_a_review(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    privacy = Privacy.build(load_policy(), ASSETS)
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        reviewer = await auth.add_user(conn, "lead", "Lead", PASSWORD)
        await conn.execute(text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
            " outcome) VALUES (:i, :v, 1, :u, 'reviewed', 'true_positive')"),
            {"i": a.id, "v": a.version, "u": reviewer})  # fmt: skip
        assert (
            await queue.enqueue(conn, a.id, a.version, "generic@a", H, "e" * 64, "x", NOW) is False
        )
        assert await runner.request(conn, privacy, a.id, "agent@1", NOW) == "queued"
        assert await runner.request(conn, privacy, a.id, "agent@1", NOW) == "exists"
        assert await runner.request(conn, privacy, uuid.uuid4(), "agent@1", NOW) == "no dossier"
        row = (await conn.execute(text(
            "SELECT version, pack, dossier_hash, view_hash, status FROM assessments"
            " WHERE assessor = 'agent@1'"))).one()  # fmt: skip
    assert tuple(row) == (a.version, "generic@a", H, runner.view_hash(privacy, body()), "queued")
    async with seeded.begin() as conn:  # it is claimed before anything else waiting
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "f" * 64, "agent@1",
                            NOW - timedelta(days=30), even_reviewed=True)  # fmt: skip
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        asked = await conn.scalar(text("SELECT priority FROM assessments WHERE id = :i"),
                                  {"i": job.assessment_id})  # fmt: skip
        assert asked == 1
        await queue.defer(conn, job, NOW, NOW + timedelta(minutes=5))  # deferred: still first
        (again,) = await queue.claim(conn, "w", NOW + timedelta(minutes=6), "agent@1")
    assert again.assessment_id == job.assessment_id


async def test_a_deferral_waits_an_hour_at_most_and_says_why(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    """10-21: one refusal parked 11 items until 1 November (the paid provider's monthly cap),
    while a free provider could answer them within the hour (D-106)."""
    (a,) = await dossiers(seeded, migrated_engine, 1)
    async with seeded.begin() as conn:
        await queue.enqueue(conn, a.id, a.version, "generic@a", H, "1" * 64, "e", NOW)
        (job,) = await queue.claim(conn, "w", NOW)
        await queue.defer(conn, job, NOW, NOW + timedelta(days=10), "openai: monthly cost cap")
        row = (await conn.execute(text("SELECT run_after, error FROM assessments"))).one()
    assert tuple(row) == (NOW + queue.MAX_DEFER, "deferred: openai: monthly cost cap")
    assert timedelta(hours=1) == queue.MAX_DEFER
    async with seeded.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW + queue.MAX_DEFER)
        await queue.defer(conn, job, NOW + queue.MAX_DEFER, NOW + timedelta(minutes=70), "x" * 600)
        row = (await conn.execute(text("SELECT run_after, error FROM assessments"))).one()
    assert row[0] == NOW + timedelta(minutes=70)  # a shorter wait is kept as given
    assert row[1] == ("deferred: " + "x" * 600)[:500]
    async with seeded.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW + timedelta(minutes=70))
        await queue.defer(conn, job, NOW + timedelta(minutes=70), NOW)  # in the past, no reason
        row = (await conn.execute(text("SELECT run_after, error FROM assessments"))).one()
        assert tuple(row) == (NOW + timedelta(minutes=70), None)
        (job,) = await queue.claim(conn, "w", NOW + timedelta(minutes=70))
        await queue.no_decision(conn, job, NOW + timedelta(minutes=71), "e", ["r"])
        assert await conn.scalar(text("SELECT error FROM assessments")) is None  # cleared
