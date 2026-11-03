"""The weekly tuning report (P7): every number recomputed from the store; the people's
labels (not the assistant's) attach to the rule and to the values they carry; stored once."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.tuning import advise, report, store
from argus.web import auth, queries
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_reviewed import decide

pytestmark = pytest.mark.integration
END = NOW + timedelta(hours=1)


async def test_the_numbers_match_the_store(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        reports = {r.rule: r for r in await report.build(conn, END)}
        alerts = dict((await conn.execute(text(
            "SELECT coalesce(normalized->>'rule_name', rule_id), count(*) FROM alert_records"
            " GROUP BY 1"))).all())  # fmt: skip
        investigations = dict((await conn.execute(text(
            "SELECT coalesce(rule_name, rule_id), count(*) FROM investigations GROUP BY 1"
        ))).all())  # fmt: skip
        runs = dict((await conn.execute(text(
            "SELECT coalesce(normalized->>'rule_name', rule_id),"
            " count(DISTINCT normalized->>'execution_uuid') FROM alert_records GROUP BY 1"
        ))).all())  # fmt: skip
    assert {r: rep.alerts for r, rep in reports.items()} == alerts
    assert {r: rep.investigations for r, rep in reports.items()} == investigations
    assert {r: rep.runs for r, rep in reports.items()} == runs
    for rep in reports.values():
        assert sum(n for _, n in rep.per_day) == rep.alerts
        assert rep.start == END - report.WEEK
        assert rep.end == END
        assert rep.labels == {}
        assert len(rep.values) <= report.TOP
        assert [v.investigations for v in rep.values] == sorted(
            (v.investigations for v in rep.values), reverse=True
        )
    later = END + timedelta(days=8)
    async with seeded.connect() as conn:
        assert await report.build(conn, later) == []  # nothing in that week


async def test_people_label_the_rule_and_its_values(seeded: AsyncEngine) -> None:
    async with seeded.begin() as conn:
        await auth.add_user(conn, "argus-assistant", "Assistant", PASSWORD)
    async with seeded.connect() as conn:
        found = await queries.inbox(conn, "all")
    rule = found[0].rule_name or found[0].rule_id
    same = [s for s in found if (s.rule_name or s.rule_id) == rule]
    await decide(seeded, "asha", same[0], action="reviewed", outcome="rule_false_positive")
    await decide(seeded, "ravi", same[1], action="reviewed", outcome="true_positive")
    await decide(seeded, "argus-assistant", same[2], action="reviewed",
                 outcome="benign_expected")  # fmt: skip
    async with seeded.connect() as conn:
        rep = next(r for r in await report.build(conn, END) if r.rule == rule)
    assert rep.labels == {"rule_false_positive": 1, "true_positive": 1}
    total = sum(sum(v.labels.values()) for v in rep.values)
    assert total >= 2
    for v in rep.values:
        assert set(v.labels) <= {"rule_false_positive", "true_positive"}
    benign, positives = report.label_support(rep.values[0])
    assert benign + positives == sum(rep.values[0].labels.values())


async def test_a_report_is_stored_once_per_rule_and_week(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        (rep, *_) = await report.build(conn, END)
    got = advise.Advice(
        [advise.Suggestion("threshold", "", "", "raise it", "runs at the limit", ("x",), "r")],
        ["exception: 1 benign"], "openai/m", 0.002,
    )  # fmt: skip
    async with seeded.begin() as conn:
        assert await store.save(conn, rep, got) is True
        assert await store.save(conn, rep, advise.Advice()) is False
        assert await store.last_week_end(conn) == END
    async with seeded.connect() as conn:
        (row,) = [r for r in await store.latest(conn) if r["rule"] == rep.rule]
    assert row["report"] == rep.as_dict()
    assert row["suggestions"] == [got.suggestions[0].as_dict()]
    assert row["dropped"] == ["exception: 1 benign"]
    assert (row["model"], row["cost_usd"]) == ("openai/m", 0.002)
    async with seeded.connect() as conn:
        assert await store.last_week_end(conn) == END
