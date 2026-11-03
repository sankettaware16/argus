"""R9 on Postgres: the rules registry from the stored alerts, truncated executions in the
coverage ledger, the abuse-ioc mirror and the cached acme-threat-intel lookups."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Template
from argus.reference import store
from argus.reference.templates import LookupParams, TiLookup, TiMirrorPage, TiNewest
from tests.integration.grouping.test_grouping import NOW, doc, ingest
from tests.integration.reference.sources import ABUSE, ACME, lookup_source, mirror_source

pytestmark = pytest.mark.integration
ZERO = {"new_revisions": 0, "new_truncated": 0, "pending": 0}
HOLD0 = timedelta(0)  # count what was stored a moment ago (production holds 5 min back)


async def rows(engine: AsyncEngine, query: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(query), params)).all())


def ruled(n: int, rule: str, *, revision: int = 3, note: str = "check the host",
          execution: str = "exec-1", max_signals: int = 100, at: datetime | None = None,
          ) -> dict[str, Any]:  # fmt: skip
    d = doc(n, rule, f"10.0.0.{n % 250}", at or NOW - timedelta(hours=1))
    s = d["_source"]
    s.update({"kibana.alert.rule.revision": revision, "kibana.alert.rule.note": note,
              "kibana.alert.rule.execution.uuid": execution, "kibana.alert.rule.max_signals":
              max_signals, "kibana.alert.rule.name": f"Rule {rule}", "kibana.alert.rule.version":
              2, "kibana.alert.rule.interval": "5m", "kibana.alert.rule.from": "now-6m",
              "kibana.alert.rule.execution.timestamp": "2026-10-09T10:59:00.000Z"})  # fmt: skip
    return d


# ----------------------------------------------------------------------------- rules


async def test_the_registry_is_rebuilt_from_the_alerts(app_engine: AsyncEngine) -> None:
    older = NOW - timedelta(hours=3)
    await ingest(app_engine, [ruled(1, "r1", revision=2, note="old", at=older),
                              ruled(2, "r1"), ruled(3, "r2", execution="e2")])  # fmt: skip
    async with app_engine.begin() as conn:
        got = await store.refresh_rules(conn, NOW, hold=HOLD0)
    assert got == {"rules": 2, "new_revisions": 3, "new_truncated": 0, "pending": 0}
    (r1,) = await rows(app_engine, "SELECT * FROM rules WHERE rule_id = 'r1'")
    assert (r1.name, r1.revision, r1.version, r1.interval, r1.lookback, r1.max_signals) == (
        "Rule r1", 3, 2, "5m", "now-6m", 100)  # fmt: skip
    assert (r1.note, r1.note_hash) == ("check the host", store.note_hash("check the host"))
    assert (r1.alerts, r1.execution_status, r1.refreshed_at) == (2, "unknown", NOW)
    assert r1.first_alert_at < r1.last_alert_at
    assert r1.last_execution_at == datetime(2026, 10, 9, 10, 59, tzinfo=UTC)
    revisions = await rows(app_engine, "SELECT rule_id, revision, note_hash FROM rule_revisions"
                                       " ORDER BY 1, 2")  # fmt: skip
    assert [(r.rule_id, r.revision) for r in revisions] == [("r1", 2), ("r1", 3), ("r2", 3)]
    assert revisions[0].note_hash == store.note_hash("old")
    async with app_engine.begin() as conn:  # again: nothing new
        assert await store.refresh_rules(conn, NOW, hold=HOLD0) == ZERO | {"rules": 2}
    assert store.note_hash(None) == store.note_hash("")


async def test_an_execution_at_its_limit_opens_a_truncated_gap_once(
    app_engine: AsyncEngine,
) -> None:
    await ingest(
        app_engine,
        [ruled(n, "r1", execution="full", max_signals=3) for n in range(3)]
        + [ruled(10 + n, "r1", execution="short", max_signals=3) for n in range(2)],
    )
    async with app_engine.begin() as conn:
        assert (await store.refresh_rules(conn, NOW, hold=HOLD0))["new_truncated"] == 1
        assert (await store.refresh_rules(conn, NOW, hold=HOLD0))["new_truncated"] == 0
    (gap,) = await rows(app_engine, "SELECT kind, subject, start_at, end_at, detail"
                                    " FROM coverage_gaps")  # fmt: skip
    assert (gap.kind, gap.subject) == ("truncated_execution", "rule:r1:execution:full")
    assert gap.start_at == gap.end_at == datetime(2026, 10, 9, 10, 59, tzinfo=UTC)
    assert gap.detail == "3 alerts, the rule's limit is 3: more may exist"


async def test_malformed_rule_numbers_never_break_the_refresh(app_engine: AsyncEngine) -> None:
    bad = ruled(1, "r1")
    bad["_source"]["kibana.alert.rule.revision"] = "three"
    await ingest(app_engine, [bad, ruled(2, "r2")])
    async with app_engine.begin() as conn:
        got = await store.refresh_rules(conn, NOW, hold=HOLD0)
    assert got["rules"] == 2  # r1 counted already; its definition waits for a readable alert
    r1 = await rows(app_engine, "SELECT alerts, revision FROM rules WHERE rule_id = 'r1'")
    assert [(r.alerts, r.revision) for r in r1] == [(1, None)]


# ----------------------------------------------------------------------------- TI


class FakeTI:
    def __init__(self, abuse: list[dict[str, Any]], acme: list[dict[str, Any]]) -> None:
        self.abuse, self.acme = abuse, acme
        self.calls: list[tuple[str, Any]] = []
        self.total: int | None = None

    async def run(self, template: Template, params: Params) -> Result:
        self.calls.append((template.name, params))
        if isinstance(template, TiMirrorPage):
            hits = [{"_source": d} for d in self.abuse]
            total = len(hits) if self.total is None else self.total
            return Result({"hits": {"total": {"value": total, "relation": "eq"}, "hits": hits}},
                          5, (ABUSE,))  # fmt: skip
        if isinstance(template, TiNewest):
            newest = {"_source": {"@timestamp": "2026-09-02T10:00:00Z"}}
            return Result({"hits": {"hits": [newest]}}, 1, ())
        assert isinstance(template, TiLookup)
        assert isinstance(params, LookupParams)
        hits = [{"_source": d} for d in self.acme if d["ioc_value"] in params.values]
        return Result({"hits": {"total": {"value": len(hits)}, "hits": hits}}, 3, (ACME,))


ABUSE_DOCS = [
    {"@timestamp": "2026-10-12T00:00:00Z",
     "threat": {"indicator": {"type": "ipv4-addr", "ip": "77.221.155.150",
                              "description": "PS1Bot C2", "confidence": "High"}}},
    {"@timestamp": "2026-10-11T00:00:00Z",
     "threat": {"indicator": {"type": "domain-name", "domain": "Evil.example"}}},
]  # fmt: skip
ACME_ROWS = [
    {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo",
     "@timestamp": "2026-09-02T10:00:00Z"},
]  # fmt: skip


async def test_the_mirror_and_lookups_answer_with_freshness(app_engine: AsyncEngine) -> None:
    ti = FakeTI(ABUSE_DOCS, ACME_ROWS)
    async with app_engine.begin() as conn:
        synced = await store.sync_mirror(conn, ti.run, NOW, mirror_source())
        assert synced == {"documents": 2, "indicators": 2, "removed": 0, "unreadable": 0}
        assert await store.sync_newest(conn, ti.run, NOW, lookup_source()) == datetime(
            2026, 9, 2, 10, tzinfo=UTC
        )
        answers = await store.lookup(
            conn, ti.run, [("ip", "77.221.155.150"), ("ip", "45.9.9.9"), ("ip", "10.1.1.1"),
                           ("domain", "evil.example")], NOW)  # fmt: skip
    by = {(a["kind"], a["value"]): a["sources"] for a in answers}
    assert by[("ip", "77.221.155.150")][ABUSE]["match"][0]["description"] == "PS1Bot C2"
    assert by[("ip", "77.221.155.150")][ABUSE]["freshness"]["stale"] is False  # newest 1 d
    assert by[("ip", "45.9.9.9")][ACME]["match"][0]["description"] == "feodo"
    absent = by[("ip", "10.1.1.1")]
    expected = {"source": ACME, "newest": "2026-09-02T10:00:00+00:00",
                "checked_at": NOW.isoformat(), "stale": True}  # fmt: skip
    assert absent[ACME] == {"no_match": expected}
    assert set(absent[ABUSE]) == {"no_match"}
    assert by[("domain", "evil.example")][ABUSE]["match"][0]["kind"] == "domain"
    assert [name for name, _ in ti.calls].count("ti.lookup") == 1  # one batch of 4 values
    async with app_engine.begin() as conn:  # within 24 h: from the cache, misses too
        await store.lookup(conn, ti.run, [("ip", "10.1.1.1")], NOW + timedelta(hours=23))
        assert [name for name, _ in ti.calls].count("ti.lookup") == 1
        await store.lookup(conn, ti.run, [("ip", "10.1.1.1")], NOW + timedelta(hours=24))
        assert [name for name, _ in ti.calls].count("ti.lookup") == 2
        offline = await store.lookup(conn, None, [("ip", "10.9.9.9")], NOW)
    assert set(offline[0]["sources"][ACME]) == {"not_checked"}  # never asked: not a no-match


async def test_lookups_go_in_batches_of_100(app_engine: AsyncEngine) -> None:
    ti = FakeTI([], [])
    values = [("ip", f"10.2.{n // 250}.{n % 250}") for n in range(250)]
    async with app_engine.begin() as conn:
        await store.lookup(conn, ti.run, values, NOW)
    sizes = [len(p.values) for name, p in ti.calls if name == "ti.lookup"]
    assert sizes == [100] * 5  # 50 values a batch, each with its IPv4-mapped spelling


async def test_the_mirror_marks_vanished_indicators_and_refuses_partial_reads(
    app_engine: AsyncEngine,
) -> None:
    ti = FakeTI(ABUSE_DOCS, [])
    async with app_engine.begin() as conn:
        await store.sync_mirror(conn, ti.run, NOW, mirror_source())
    ti.abuse = ABUSE_DOCS[:1]
    later = NOW + timedelta(hours=6)
    async with app_engine.begin() as conn:
        assert (await store.sync_mirror(conn, ti.run, later, mirror_source()))["removed"] == 1
    gone = await rows(app_engine, "SELECT value, removed_at FROM ti_indicators"
                                  " WHERE removed_at IS NOT NULL")  # fmt: skip
    assert [(g.value, g.removed_at) for g in gone] == [("evil.example", later)]
    ti.total = 5000  # more than one read holds
    with pytest.raises(store.IncompleteAnswer, match="holds 5000 documents"):
        async with app_engine.begin() as conn:
            await store.sync_mirror(conn, ti.run, later + timedelta(hours=6), mirror_source())
    ti.total = 3  # the total says 3, the page has 1
    with pytest.raises(store.IncompleteAnswer, match="1 of 3 documents"):
        async with app_engine.begin() as conn:
            await store.sync_mirror(conn, ti.run, later + timedelta(hours=6), mirror_source())
    assert len(await rows(app_engine, "SELECT 1 FROM ti_indicators WHERE removed_at IS NULL")) == 1


async def test_the_refresh_is_incremental_and_exact(app_engine: AsyncEngine) -> None:
    """Each refresh reads only what was stored since the last one; counts add up, a newer
    alert brings its definition, a late one (old detection time) counts but changes nothing
    else, and an execution split over two refreshes is still found truncated."""
    async with app_engine.begin() as conn:
        assert await store.refresh_rules(conn, NOW, hold=HOLD0) == ZERO | {"rules": 0}
    await ingest(app_engine, [ruled(1, "r1", execution="x", max_signals=3),
                              ruled(2, "r1", execution="x", max_signals=3)])  # fmt: skip
    async with app_engine.begin() as conn:
        assert (await store.refresh_rules(conn, NOW, hold=HOLD0))["new_truncated"] == 0
    await ingest(app_engine, [ruled(3, "r1", execution="x", max_signals=3, revision=4,
                                    note="new steps")], NOW + timedelta(minutes=1))  # fmt: skip
    async with app_engine.begin() as conn:
        got = await store.refresh_rules(conn, NOW + timedelta(minutes=1), hold=HOLD0)
    assert got == {"rules": 1, "new_revisions": 1, "new_truncated": 1, "pending": 0}
    (r1,) = await rows(app_engine, "SELECT alerts, revision, note FROM rules")
    assert (r1.alerts, r1.revision, r1.note) == (3, 4, "new steps")
    late = ruled(4, "r1", revision=2, note="old", at=NOW - timedelta(days=2))
    await ingest(app_engine, [late], NOW + timedelta(minutes=2))
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW + timedelta(minutes=2), hold=HOLD0)
        nothing = await store.refresh_rules(conn, NOW + timedelta(minutes=3), hold=HOLD0)
    (r1,) = await rows(app_engine, "SELECT alerts, revision, note, first_alert_at FROM rules")
    assert (r1.alerts, r1.revision, r1.note) == (4, 4, "new steps")  # counted, not adopted
    assert r1.first_alert_at < NOW - timedelta(days=1)
    assert nothing == {"rules": 1, "new_revisions": 0, "new_truncated": 0, "pending": 0}


async def test_a_large_backlog_is_read_in_batches(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [ruled(n, "r1") for n in range(5)])
    await ingest(app_engine, [ruled(10 + n, "r1") for n in range(3)], NOW + timedelta(seconds=1))
    async with app_engine.begin() as conn:
        first = await store.refresh_rules(
            conn, NOW, batch=2, hold=HOLD0
        )  # all 5 of the first stamp
        second = await store.refresh_rules(conn, NOW, batch=2, hold=HOLD0)
    assert (first["pending"], second["pending"]) == (3, 0)
    (r1,) = await rows(app_engine, "SELECT alerts FROM rules")
    assert r1.alerts == 8


async def test_a_batch_past_the_row_cap_is_asked_again_in_halves(app_engine: AsyncEngine) -> None:
    """2026-10-14: the refreshed feed held hundreds of rows for one indicator; a batch hit the
    500-row cap and the whole lookup was refused. Now the batch is split until each answer is
    complete; a single value past the cap is a match all the same."""
    from argus.reference.templates import LOOKUP_SIZE

    noisy = [{"ioc_type": "ip", "ioc_value": "45.1.1.1", "intel_source": f"feed-{n % 3}",
              "@timestamp": "2026-10-14T10:00:00Z"} for n in range(LOOKUP_SIZE)]  # fmt: skip
    quiet = [{"ioc_type": "ip", "ioc_value": "45.2.2.2", "intel_source": "misp",
              "@timestamp": "2026-10-14T10:00:00Z"}]  # fmt: skip

    class Capped(FakeTI):
        async def run(self, template: Template, params: Params) -> Result:
            got = await super().run(template, params)
            hits = got.body.get("hits", {}).get("hits", [])[:LOOKUP_SIZE]
            return Result({"hits": {"hits": hits}}, 3, (ACME,))

    ti = Capped([], noisy + quiet)
    values = [("ip", "45.1.1.1"), ("ip", "45.2.2.2"), ("ip", "45.3.3.3"), ("ip", "45.4.4.4")]
    async with app_engine.begin() as conn:
        answers = await store.lookup(conn, ti.run, values, NOW)
    by = {a["value"]: a["sources"][ACME] for a in answers}
    assert len(by["45.1.1.1"]["match"]) == 3  # distinct rows kept (three feeds), not 500
    assert by["45.2.2.2"]["match"][0]["description"] == "misp"
    assert "no_match" in by["45.3.3.3"]
    asked = [p.values for name, p in ti.calls if name == "ti.lookup"]
    assert len(asked) == 5  # all 4, then halves of 2, then the noisy one's half again
    assert len(asked) < 2 * len(values) + 1  # bounded: a binary split
    assert store.KEPT_ROWS == 20
