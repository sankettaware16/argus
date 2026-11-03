"""P4 (D-085): what the engine learns from, first-seen entities, volume spikes, requeueing."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import engine, queue
from argus.web import auth, queries
from tests.integration.assess.test_queue import H, body, put_dossier
from tests.integration.web.conftest import NOW, PASSWORD

pytestmark = pytest.mark.integration
STEPS = {"facts": {"rule_name": "R"}, "report": {"steps": [{"number": 1, "status": "answered"}]}}


async def test_learning_uses_people_and_gold_dev_only(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        a, b, c, d, e = (await queries.inbox(conn, "all"))[:5]
    async with migrated_engine.begin() as conn:
        for inv in (a, b, c, d, e):
            await put_dossier(conn, inv.id, inv.version, H, STEPS)
    async with seeded.begin() as conn:
        assistant = await auth.add_user(conn, "argus-assistant", "Assistant", PASSWORD)
        person = (await auth.login(conn, "asha", PASSWORD, NOW))[1].user_id  # type: ignore[index]
        await queue.enqueue(conn, e.id, e.version, "generic@a", H, "1" * 64, "x", NOW)
        (job,) = await queue.claim(conn, "w", NOW)
        await queue.propose(conn, job, NOW, "benign_expected", "x", [])
    async with migrated_engine.begin() as conn:
        for inv, split in ((c, "test"), (d, "dev")):
            await conn.execute(
                text(
                    "INSERT INTO gold_items (set_name, investigation_id, version, pack,"
                    " dossier_hash, rule_name, split, why, suggestion) VALUES ('v1', :i, :v,"
                    " 'generic@a', :h, 'R', :s, '{}', '{}'::jsonb)"
                ),
                {"i": inv.id, "v": inv.version, "h": H, "s": split},
            )
        for inv, user, outcome, link in (
            (a, person, "benign_expected", None), (b, assistant, "benign_expected", None),
            (c, person, "true_positive", None), (e, person, "benign_expected", job.assessment_id),
        ):  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, assessment_id) VALUES (:i, :v, 1, :u, 'reviewed', :o, :a)"
                ),
                {"i": inv.id, "v": inv.version, "u": user, "o": outcome, "a": link},
            )
        await conn.execute(
            text(
                "INSERT INTO gold_labels (set_name, investigation_id, user_id, outcome)"
                " VALUES ('v1', :i, :u, 'rule_false_positive')"
            ),
            {"i": d.id, "u": person},
        )
    async with seeded.connect() as conn:
        learned = await engine.learn(conn)
    outcomes = sorted(x.outcome for x in learned.by_key[("steps", "R", "1:answered")])
    assert outcomes == ["benign_expected", "rule_false_positive"]  # a (person) and d (gold dev)


async def test_first_seen_and_spikes(seeded: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        a = (await queries.inbox(conn, "all"))[0]
        assert not await engine.first_seen(conn, a.id)  # its address is in others too
        assert await engine.spike(conn, a.id) is None  # no earlier days of its rule and key
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                 " VALUES (:i, 'domain', 'only-here.example')"), {"i": a.id})  # fmt: skip
        row = (await conn.execute(text(
            "SELECT rule_id, group_key, bucket_start, alert_count FROM investigations"
            " WHERE id = :i"), {"i": a.id})).one()  # fmt: skip
        # days 1 to 5 back are the window; 5.5 and 6 are not
        for day, count in ((1, 2), (2, 2), (3, 3), (5, 2), (5.5, 100), (6, 100)):  # fmt: skip
            start = row.bucket_start - timedelta(days=day)
            await conn.execute(
                text(
                    "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                    " bucket_start, bucket_end, previous_id, alert_count, first_event_at,"
                    " last_event_at, severity, version) VALUES (gen_random_uuid(), '1', :r, :k,"
                    " :s, :e, gen_random_uuid(), :n, :s, :s, 'low', 1)"
                ),
                {"r": row.rule_id, "k": row.group_key, "s": start, "e": start + timedelta(days=1),
                 "n": count},
            )  # fmt: skip
        await conn.execute(text("UPDATE investigations SET alert_count = 7 WHERE id = :i"),
                           {"i": a.id})  # fmt: skip
    async with seeded.connect() as conn:
        assert await engine.first_seen(conn, a.id)
        assert await engine.spike(conn, a.id)  # 7 > 3 times the median 2 (of days 1 to 5)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET alert_count = 6 WHERE id = :i"),
                           {"i": a.id})  # fmt: skip
    async with seeded.connect() as conn:
        assert not await engine.spike(conn, a.id)  # 6 is not over 3 times 2


async def test_requeue_when_what_was_learned_changed(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        a, b, c, d = (await queries.inbox(conn, "all"))[:4]
    async with migrated_engine.begin() as conn:
        for inv in (a, b, c, d):
            await put_dossier(conn, inv.id, inv.version, H, body())
    async with seeded.begin() as conn:
        for inv, vh in ((a, "1"), (b, "2"), (c, "3"), (d, "4")):
            await queue.enqueue(conn, inv.id, inv.version, "generic@a", H, vh * 64, "engine@1", NOW)
        jobs = await queue.claim(conn, "w", NOW, limit=4)
        await queue.no_decision(conn, jobs[0], NOW, "engine@1#old", ["no key"])
        await queue.propose(conn, jobs[1], NOW, "true_positive", "engine@1#old: steps / R", [])
        await queue.no_decision(conn, jobs[2], NOW, "engine@1#new", ["no key"])
        await queue.propose(conn, jobs[3], NOW, "true_positive", "engine@1#new: steps / R", [])
        assert await queue.requeue(conn, "engine@1", "engine@1#new", NOW) == 2
        assert await queue.requeue(conn, "engine@1", "engine@1#new", NOW) == 0
        rows = dict((await conn.execute(text(
            "SELECT investigation_id, status FROM assessments"))).all())  # fmt: skip
    assert (rows[a.id], rows[b.id], rows[c.id], rows[d.id]) == (
        "queued", "queued", "no_decision", "proposed")  # fmt: skip
    assert json.dumps(STEPS)


async def test_a_person_wins_a_tie_with_the_gold_set(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        a = (await queries.inbox(conn, "all"))[0]
    async with seeded.begin() as conn:
        person = (await auth.login(conn, "asha", PASSWORD, NOW))[1].user_id  # type: ignore[index]
    async with migrated_engine.begin() as conn:
        await put_dossier(conn, a.id, a.version, H, STEPS)
        await conn.execute(
            text(
                "INSERT INTO gold_items (set_name, investigation_id, version, pack,"
                " dossier_hash, rule_name, split, why, suggestion) VALUES ('v1', :i, :v,"
                " 'generic@a', :h, 'R', 'dev', '{}', '{}'::jsonb)"
            ),
            {"i": a.id, "v": a.version, "h": H},
        )
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, created_at) VALUES (:i, :v, 1, :u, 'reviewed',"
                " 'benign_expected', :t)"
            ),
            {"i": a.id, "v": a.version, "u": person, "t": NOW},
        )
        await conn.execute(
            text(
                "INSERT INTO gold_labels (set_name, investigation_id, user_id, outcome, created_at)"
                " VALUES ('v1', :i, :u, 'rule_false_positive', :t)"
            ),
            {"i": a.id, "u": person, "t": NOW},
        )
    async with seeded.connect() as conn:
        learned = await engine.learn(conn)
    assert [x.outcome for x in learned.by_key[("steps", "R", "1:answered")]] == ["benign_expected"]


async def test_the_engine_as_an_assessor(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        a = (await queries.inbox(conn, "all"))[0]  # not first-seen; no volume baseline
    key = ("steps", "R", "1:answered")
    labels = [engine.Label("true_positive", NOW - timedelta(days=1)) for _ in range(5)]
    positive = engine.Learned()
    positive.by_key[key] = labels
    benign = engine.Learned()
    benign.by_key[key] = [engine.Label("benign_expected", x.at) for x in labels]
    async with seeded.connect() as conn:
        tp = await engine.Engine(positive, NOW).assess(conn, a.id, STEPS)
        blocked = await engine.Engine(benign, NOW).assess(conn, a.id, STEPS)
        nothing = await engine.Engine(engine.Learned(), NOW).assess(conn, a.id, STEPS)
        old = await engine.Engine(positive, NOW + timedelta(days=31)).assess(conn, a.id, STEPS)
    stamp = f"engine@1#{positive.fingerprint()}"
    assert (tp.outcome, tp.decided_by, tp.confidence) == (
        "true_positive", f"{stamp}: steps / R / 1:answered", 1.0)  # fmt: skip
    assert tp.reasons == ["key steps / R / 1:answered: 5 human labels, all or nearly all"
                          " true_positive"]  # fmt: skip
    assert (blocked.outcome, blocked.confidence) == (None, None)
    assert blocked.decided_by == f"engine@1#{benign.fingerprint()}: steps / R / 1:answered"
    assert blocked.reasons[1] == "floor: threat lists not checked; volume baseline not known"
    assert (nothing.outcome, nothing.confidence) == (None, None)
    assert nothing.decided_by == f"engine@1#{engine.Learned().fingerprint()}"
    assert old.outcome is None  # its clock is the one it was made with
