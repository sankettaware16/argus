"""R9 adversarial review, round 1: each finding as a test, shown failing before its fix."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reference import store
from argus.reference.ti import canonical, guess_kind
from tests.integration.grouping.test_grouping import NOW, ingest
from tests.integration.reference.sources import ABUSE, ACME, mirror_source
from tests.integration.reference.test_reference import ABUSE_DOCS, FakeTI, rows, ruled

pytestmark = pytest.mark.integration


async def alerts_of(engine: AsyncEngine, rule: str) -> int:
    got = await rows(engine, "SELECT alerts FROM rules WHERE rule_id = :r", r=rule)
    return got[0].alerts if got else 0


# H1a: a rule whose new alerts had no readable definition lost their counts.
async def test_alerts_without_a_readable_definition_are_still_counted(
    app_engine: AsyncEngine,
) -> None:
    bad = ruled(1, "r1")
    bad["_source"]["kibana.alert.rule.revision"] = "three"
    await ingest(app_engine, [bad])
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(0))
    await ingest(app_engine, [ruled(2, "r1")], NOW + timedelta(minutes=1))
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(0))
    assert await alerts_of(app_engine, "r1") == 2
    (r1,) = await rows(app_engine, "SELECT revision FROM rules")
    assert r1.revision == 3  # the definition arrived with the readable alert


# H1b: an ingest that committed after a refresh, with an earlier first_seen_at, was skipped.
async def test_a_late_commit_is_counted_by_the_next_refresh(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await ingest(app_engine, [ruled(1, "r1")])
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(seconds=60))
        db_now = (await conn.execute(text("SELECT now()"))).scalar_one()
    await ingest(app_engine, [ruled(2, "r1")])
    async with migrated_engine.begin() as conn:  # its transaction began 30 s before the refresh
        await conn.execute(text("UPDATE alert_records SET first_seen_at = :t"
                                " WHERE alert_id = :a"),
                           {"t": db_now - timedelta(seconds=30), "a": f"{2:040x}"})  # fmt: skip
    async with migrated_engine.begin() as conn:  # and everything is old enough now
        await conn.execute(text("UPDATE alert_records SET first_seen_at = first_seen_at"
                                " - interval '2 minutes'"))  # fmt: skip
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(seconds=60))
    assert await alerts_of(app_engine, "r1") == 2


# H2: two refreshes at once counted everything twice.
async def test_concurrent_refreshes_count_once(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [ruled(n, "r1") for n in range(3)])

    async def refresh() -> None:
        async with app_engine.begin() as conn:
            await store.refresh_rules(conn, NOW, hold=timedelta(0))
            await asyncio.sleep(0.2)  # hold the transaction open

    await asyncio.gather(refresh(), refresh())
    assert await alerts_of(app_engine, "r1") == 3


# M2: a late older alert's definition replaced a newer one.
async def test_the_definition_comes_from_the_newest_readable_alert(
    app_engine: AsyncEngine,
) -> None:
    await ingest(app_engine, [ruled(1, "r1", revision=5, note="new")])
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(0))
    late = ruled(2, "r1", revision=2, note="old", at=NOW - timedelta(days=2))
    newer = ruled(3, "r1", at=NOW)
    newer["_source"]["kibana.alert.rule.revision"] = "unreadable"
    await ingest(app_engine, [late, newer], NOW + timedelta(minutes=1))
    async with app_engine.begin() as conn:
        await store.refresh_rules(conn, NOW, hold=timedelta(0))
    (r1,) = await rows(app_engine, "SELECT revision, note, alerts FROM rules")
    assert (r1.revision, r1.note, r1.alerts) == (5, "new", 3)


# H3: kinds filtered matches out, and case/spelling variants on the SIEM were never asked for.
async def test_lookups_match_by_value_and_ask_for_spelling_variants(
    app_engine: AsyncEngine,
) -> None:
    ti = FakeTI([], [
        {"ioc_type": "domain", "ioc_value": "10.0.0.7", "intel_source": "a"},
        {"ioc_type": "sha256", "ioc_value": "AB" * 32, "intel_source": "b"},
        {"ioc_type": "domain", "ioc_value": "Evil.Example", "intel_source": "c"},
        {"ioc_type": "ip", "ioc_value": "::ffff:10.0.0.8", "intel_source": "d"},
    ])  # fmt: skip
    async with app_engine.begin() as conn:
        answers = await store.lookup(conn, ti.run, [
            ("ip", "10.0.0.7"), ("hash", "ab" * 32), ("domain", "evil.example"),
            ("ip", "10.0.0.8")], NOW)  # fmt: skip
    by = {a["value"]: a["sources"][ACME] for a in answers}
    assert "match" in by["10.0.0.7"]  # filed as a domain, still the value asked for
    assert "match" in by["ab" * 32]  # stored upper-case on the SIEM
    # mixed case is a limit of exact keyword lookups (D-059): only these spellings are asked
    assert "no_match" in by["evil.example"]
    assert "match" in by["10.0.0.8"]  # stored IPv4-mapped
    asked = {v for name, p in ti.calls if name == "ti.lookup" for v in p.values}
    assert {"AB" * 32, "Evil.Example"} - asked == {"Evil.Example"}  # upper/lower, not mixed
    assert "::ffff:10.0.0.8" in asked


# M3 and M5: never asked or too old is not an answer.
async def test_old_cache_entries_and_unsynced_sources_are_not_checked(
    app_engine: AsyncEngine,
) -> None:
    ti = FakeTI([], [])
    async with app_engine.begin() as conn:
        await store.lookup(conn, ti.run, [("ip", "10.1.1.1")], NOW)
        later = await store.lookup(conn, None, [("ip", "10.1.1.1")], NOW + timedelta(days=30))
        fresh = await store.lookup(conn, None, [("ip", "10.1.1.1")], NOW + timedelta(hours=1))
    assert set(later[0]["sources"][ACME]) == {"not_checked"}
    assert set(fresh[0]["sources"][ACME]) == {"no_match"}
    assert set(later[0]["sources"][ABUSE]) == {"not_checked"}  # the mirror was never synced


# L1: an empty read was taken as "everything was removed".
async def test_an_empty_read_never_empties_the_mirror(app_engine: AsyncEngine) -> None:
    ti = FakeTI(ABUSE_DOCS, [])
    async with app_engine.begin() as conn:
        await store.sync_mirror(conn, ti.run, NOW, mirror_source())
    ti.abuse = []
    with pytest.raises(store.IncompleteAnswer, match="empty"):
        async with app_engine.begin() as conn:
            await store.sync_mirror(conn, ti.run, NOW + timedelta(hours=6), mirror_source())
    assert len(await rows(app_engine, "SELECT 1 FROM ti_indicators WHERE removed_at IS NULL")) == 2


# M4: rows that cannot be read are counted, and differently spelled types understood.
async def test_unreadable_rows_are_counted_and_type_spellings_understood(
    app_engine: AsyncEngine,
) -> None:
    docs: list[dict[str, Any]] = [
        *ABUSE_DOCS,
        {"@timestamp": "2026-10-12T00:00:00Z",
         "threat": {"indicator": {"type": "IPv4 Address", "ip": "1.2.3.4"}}},
        {"@timestamp": "2026-10-12T00:00:00Z",
         "threat": {"indicator": {"type": "ipv4-addr", "ip": "10.0.0.9:80"}}},
    ]  # fmt: skip
    ti = FakeTI(docs, [])
    async with app_engine.begin() as conn:
        got = await store.sync_mirror(conn, ti.run, NOW, mirror_source())
    assert (got["indicators"], got["unreadable"]) == (3, 1)
    kinds = await rows(app_engine, "SELECT kind FROM ti_indicators WHERE value = '1.2.3.4'")
    assert [k.kind for k in kinds] == ["ip"]


# M1, L2, L3: the kind of a typed value, URLs, naive times.
def test_kinds_urls_and_times() -> None:
    assert guess_kind("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert guess_kind("a" * 40) == "hash"
    assert guess_kind("B" * 64) == "hash"
    assert guess_kind("1.2.3.4") == "ip"
    assert guess_kind("::ffff:1.2.3.4") == "ip"
    assert guess_kind("evil.example") == "domain"
    assert guess_kind("http://evil.example/x") == "url"
    assert guess_kind("evil.example/x") == "url"
    assert guess_kind("1.2.3.4:80") is None
    assert guess_kind("12345") is None
    assert guess_kind("a@b.example") == "email"
    assert canonical("domain", "evil.com/x") is None
    assert canonical("domain", "1.2.3.4:80") is None
    assert canonical("url", "HTTP://Evil.EXAMPLE:80/a#frag") == "http://evil.example/a"
    assert canonical("url", "https://x.example:443/b?q=1") == "https://x.example/b?q=1"
    assert canonical("url", "https://x.example:8443/b") == "https://x.example:8443/b"
    naive = store.newest_of(_result({"@timestamp": "2026-10-01T00:00:00"}))
    assert naive is None
    assert store.newest_of(_result({"@timestamp": "2026-10-01T00:00:00Z"})) == datetime(
        2026, 10, 1, tzinfo=UTC)  # fmt: skip


def _result(source: dict[str, Any]) -> Any:
    from argus.gateway.gateway import Result

    return Result({"hits": {"hits": [{"_source": source}]}}, 1, ())
