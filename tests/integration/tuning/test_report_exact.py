"""The weekly tuning report on a designed store (P7): every number checked against a value
worked out by hand: runs at the limit, days in and out of the week, a rule known by its id,
the people's newest verdict (not the assistant's, not a confirmed proposal, not older than
30 days), proposals at the current version only, grouping-key pairs counted once."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.tuning import report
from argus.tuning.report import RuleReport, ValueStat
from argus.web import auth

pytestmark = pytest.mark.integration
END = datetime(2026, 10, 16, 12, tzinfo=UTC)
D = timedelta(days=1)


def at(day: int, hour: int = 10) -> datetime:
    return datetime(2026, 10, day, hour, tzinfo=UTC)


async def alert(conn: Any, n: int, detected: datetime, normalized: dict[str, Any] | None,
                rule_id: str | None = "r") -> None:  # fmt: skip
    await conn.execute(text(
        "INSERT INTO alert_records (alert_id, index, status, quarantine_reason, normalizer_version,"
        " rule_id, detected_at, raw, normalized, content_hash, state_hash, recovered_by)"
        " VALUES (:a, 'i', :s, :q, '1', :r, :d, '{}', CAST(:n AS jsonb), 'h', 'h', 'live')"),
        {"a": f"a{n}", "s": "normalized" if normalized is not None else "quarantined",
         "q": None if normalized is not None else "bad", "r": rule_id, "d": detected,
         "n": None if normalized is None else json.dumps(normalized)})  # fmt: skip


async def investigation(conn: Any, rule_name: str | None, rule_id: str, key: str,
                        bucket: datetime, alerts: int, version: int = 1) -> uuid.UUID:  # fmt: skip
    inv = uuid.uuid4()
    await conn.execute(text(
        "INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key,"
        " bucket_start, bucket_end, previous_id, alert_count, first_event_at, last_event_at,"
        " severity, version) VALUES (:i, '1', :r, :n, :k, :b, :e, gen_random_uuid(), :c, :b,"
        " :b, 'low', :v)"),
        {"i": inv, "r": rule_id, "n": rule_name, "k": key, "b": bucket, "e": bucket + D,
         "c": alerts, "v": version})  # fmt: skip
    return inv


async def entity(conn: Any, inv: uuid.UUID, kind: str, value: str) -> None:
    await conn.execute(text(
        "INSERT INTO investigation_entities (investigation_id, kind, value) VALUES (:i, :k, :v)"),
        {"i": inv, "k": kind, "v": value})  # fmt: skip


async def review(conn: Any, inv: uuid.UUID, user: int, outcome: str, when: datetime,
                 version: int = 1, assessment: int | None = None) -> None:  # fmt: skip
    await conn.execute(text(
        "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
        " outcome, assessment_id, created_at) VALUES (:i, :v, 1, :u, 'reviewed', :o, :a, :t)"),
        {"i": inv, "v": version, "u": user, "o": outcome, "a": assessment, "t": when})  # fmt: skip


async def assessment(conn: Any, inv: uuid.UUID, version: int, assessor: str,
                     outcome: str, n: int) -> int:  # fmt: skip
    found: int = (await conn.execute(text(
        "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
        " assessor, status, run_after, outcome, decided_by) VALUES (:i, :v, 'p', :h, :w, :a,"
        " 'proposed', now(), :o, :a) RETURNING id"),
        {"i": inv, "v": version, "h": "a" * 64, "w": f"{n:064x}", "a": assessor,
         "o": outcome})).scalar_one()  # fmt: skip
    return found


@pytest.fixture
async def world(migrated_engine: AsyncEngine) -> dict[str, Any]:
    r = {"rule_name": "R", "max_signals": 3}
    async with migrated_engine.begin() as conn:
        asha = await auth.add_user(conn, "asha", "Asha", "correct horse battery")
        bot = await auth.add_user(conn, "argus-assistant", "A", "correct horse battery")
        n = 0
        for detected, run in [(at(14), "a")] * 3 + [(at(15), "b")]:
            n += 1
            await alert(conn, n, detected, {**r, "execution_uuid": run})
        for _ in range(2):  # run c, no limit recorded
            n += 1
            await alert(conn, n, at(16, 11), {"rule_name": "R", "execution_uuid": "c"})
        await alert(conn, 90, at(8), {**r, "execution_uuid": "old"})  # before the week
        await alert(conn, 91, END, {**r, "execution_uuid": "late"})  # at the end: not in
        await alert(conn, 92, at(15), None)  # quarantined: no normalized form
        await alert(conn, 93, at(15), {"execution_uuid": "s", "max_signals": 5}, "S-id")

        inv1 = await investigation(conn, "R", "r", '[["source.ip","10.0.0.1"],'
                                   '["source.ip","10.0.0.1"]]', at(15), 4, version=2)  # fmt: skip
        inv2 = await investigation(conn, "R", "r", '[["source.ip","10.0.0.1"]]', at(14), 2)
        inv3 = await investigation(conn, "R", "r", '[["source.ip","10.0.0.9"]]', at(1), 7)
        await investigation(conn, "R", "r", '[["source.ip","10.0.0.8"]]', at(2), 1)
        inv5 = await investigation(conn, "R", "r", "[]", datetime(2026, 9, 1, tzinfo=UTC), 1)
        await investigation(conn, None, "S-id", "not json", at(15), 1)
        inv7 = await investigation(conn, "T", "t", "[]", at(15), 3)
        inv8 = await investigation(conn, "U", "u", "[]", at(1), 1)
        await entity(conn, inv1, "ip", "8.8.8.8")
        await entity(conn, inv2, "ip", "8.8.8.8")
        await entity(conn, inv2, "domain", "e.example")
        await entity(conn, inv3, "ip", "8.8.8.8")
        for k in range(9):
            await entity(conn, inv7, "ip", f"1.1.1.{k}")

        await review(conn, inv1, asha, "true_positive", END - 3 * D, version=2)
        await review(conn, inv1, asha, "rule_false_positive", END - 2 * D, version=2)
        await review(conn, inv2, bot, "benign_expected", END - D)
        old = await assessment(conn, inv2, 1, "engine@1", "true_positive", 1)
        await review(conn, inv2, asha, "true_positive", END - D, assessment=old)
        await review(conn, inv3, asha, "true_positive", END - D)
        await review(conn, inv5, asha, "benign_expected", END - D)
        await review(conn, inv8, asha, "benign_expected", END - D)

        await assessment(conn, inv1, 1, "engine@1", "benign_expected", 2)  # an old version
        await assessment(conn, inv1, 2, "engine@1", "benign_policy", 3)
        await assessment(conn, inv1, 2, "engine@1", "true_positive", 4)  # newest of the two
        await assessment(conn, inv1, 2, "agent@1", "benign_expected", 5)
    return {"inv1": inv1}


async def test_the_report_exactly(world: dict[str, Any], migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.connect() as conn:
        got = {r.rule: r for r in await report.build(conn, END)}
    assert sorted(got) == ["R", "S-id", "T"]  # U: only an old labelled one, nothing this week
    assert got["R"] == RuleReport(
        rule="R", start=END - 7 * D, end=END, alerts=6,
        per_day=((date(2026, 10, 14), 3), (date(2026, 10, 15), 1), (date(2026, 10, 16), 2)),
        investigations=2, runs=3, runs_at_limit=1, max_signals=3,
        labels={"rule_false_positive": 1, "true_positive": 1},
        proposals={"true_positive": 2, "benign_expected": 1},
        values=(
            ValueStat("entity.ip", "8.8.8.8", 2, 6,
                      {"rule_false_positive": 1, "true_positive": 1}),
            ValueStat("source.ip", "10.0.0.1", 2, 6, {"rule_false_positive": 1}),
            ValueStat("entity.domain", "e.example", 1, 2, {}),
        ),
    )  # fmt: skip
    assert got["S-id"] == RuleReport("S-id", END - 7 * D, END, 1, ((date(2026, 10, 15), 1),),
                                     1, 1, 0, 5, {}, {}, ())  # fmt: skip
    t = got["T"]
    assert (t.alerts, t.investigations, t.runs, t.max_signals) == (0, 1, 0, None)
    assert [v.value for v in t.values] == [f"1.1.1.{k}" for k in range(8)]  # TOP is 8


async def test_the_dict_form(world: dict[str, Any], migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.connect() as conn:
        r = next(x for x in await report.build(conn, END) if x.rule == "R")
    assert r.as_dict() == {
        "rule": "R", "start": "2026-10-09T12:00:00+00:00", "end": "2026-10-16T12:00:00+00:00",
        "alerts": 6, "per_day": [["2026-10-14", 3], ["2026-10-15", 1], ["2026-10-16", 2]],
        "investigations": 2, "runs": 3, "runs_at_limit": 1, "max_signals": 3,
        "labels": {"rule_false_positive": 1, "true_positive": 1},
        "proposals": {"benign_expected": 1, "true_positive": 2},
        "values": [
            {"path": "entity.ip", "value": "8.8.8.8", "investigations": 2, "alerts": 6,
             "labels": {"rule_false_positive": 1, "true_positive": 1}},
            {"path": "source.ip", "value": "10.0.0.1", "investigations": 2, "alerts": 6,
             "labels": {"rule_false_positive": 1}},
            {"path": "entity.domain", "value": "e.example", "investigations": 1, "alerts": 2,
             "labels": {}},
        ],
    }  # fmt: skip


def test_constants_and_pairs() -> None:
    assert (report.WEEK, report.LABEL_DAYS, report.TOP) == (7 * D, 30 * D, 8)
    assert report.ASSISTANT == "argus-assistant"
    assert report._pairs('[["a", 1], ["b"], "c", ["d", "e"]]') == [("a", "1"), ("d", "e")]
    assert report._pairs("{") == []
    assert report.label_support({"labels": {"true_positive": 2, "benign_expected": 1}}) == (1, 2)


def test_records_are_frozen() -> None:
    import dataclasses

    stat = ValueStat("p", "v", 1, 1)
    rep = RuleReport("r", END, END, 0, (), 0, 0, 0, None, {}, {}, ())
    for record in (stat, rep):
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.rule = "x"  # type: ignore[misc, union-attr]


async def test_a_zero_limit_ties_and_empty_alert_counts(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await alert(conn, 1, at(15), {"rule_name": "Z", "execution_uuid": "z", "max_signals": 0})
        a = await investigation(conn, "Z", "z", '[["host.name","a"]]', at(15), 3)
        b = await investigation(conn, "Z", "z", '[["host.name","b"]]', at(15), 9)
        c = await investigation(conn, "Z", "z", '[["host.name","c"]]', at(15), 0)
        for inv in (a, b, c):
            await entity(conn, inv, "ip", "8.8.8.8")
    async with migrated_engine.connect() as conn:
        (z,) = await report.build(conn, END)
    assert (z.runs, z.runs_at_limit, z.max_signals) == (1, 0, 0)  # a limit of 0 is no limit
    assert [(v.path, v.value, v.investigations, v.alerts) for v in z.values] == [
        ("entity.ip", "8.8.8.8", 3, 12),
        ("host.name", "b", 1, 9),  # same count of investigations: more alerts first
        ("host.name", "a", 1, 3),
        ("host.name", "c", 1, 0),  # no alert, still one of this week's
    ]
