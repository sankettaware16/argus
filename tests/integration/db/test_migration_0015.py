"""Migration 0015 (D-066): host entities that name the alert's observer or agent are removed
from stored alerts, investigations and the entity counts; other hosts stay."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.grouping.test_grouping import NOW, doc, ingest

pytestmark = pytest.mark.integration


async def plant(owner: AsyncEngine, alert_id: str, value: str) -> None:
    """What the 1.0 normalizer stored: the value as a host entity everywhere."""
    async with owner.begin() as conn:
        entity = {"kind": "host", "field": "host.name", "value": value}
        await conn.execute(
            text("UPDATE alert_records SET normalized = jsonb_set(normalized, '{entities}',"
                 " (normalized -> 'entities') || CAST(:e AS jsonb)) WHERE alert_id = :a"),
            {"e": json.dumps([entity]), "a": alert_id},
        )  # fmt: skip
        found = text("SELECT investigation_id FROM investigation_alerts WHERE alert_id = :a")
        inv = (await conn.execute(found, {"a": alert_id})).scalar_one()
        link = text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                    " VALUES (:i, 'host', :v) ON CONFLICT DO NOTHING")  # fmt: skip
        await conn.execute(link, {"i": inv, "v": value})
        await conn.execute(
            text("INSERT INTO entities (kind, value, investigations) VALUES ('host', :v, 1)"
                 " ON CONFLICT (kind, value) DO UPDATE SET investigations ="
                 " entities.investigations + 1"), {"v": value})  # fmt: skip


async def test_reporter_hosts_are_removed_and_others_kept(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    proxy = [doc(n, "r1", f"10.0.0.{n}", NOW - timedelta(minutes=n)) for n in range(3)]
    for d in proxy:
        d["_source"]["observer"] = {"hostname": "tp8"}
        d["_source"]["host"] = {"name": "tp8"}  # squid writes its own name here too
    nested = doc(7, "r2", "10.0.0.7", NOW)
    nested["_source"]["agent"] = {"name": "Shipper-1"}
    nested["_source"]["host"] = {"name": "shipper-1"}
    await ingest(app_engine, [*proxy, nested])
    for d in proxy:
        await plant(migrated_engine, d["_id"], "tp8")
    await plant(migrated_engine, nested["_id"], "shipper-1")
    await plant(migrated_engine, proxy[0]["_id"], "pc-12")  # a real host: stays
    await migrate.downgrade(migrated_engine, "0014")
    await migrate.upgrade(migrated_engine)
    async with migrated_engine.connect() as conn:
        query = "SELECT value FROM investigation_entities WHERE kind = 'host' ORDER BY 1"
        hosts = (await conn.execute(text(query))).scalars().all()
        counts = dict((await conn.execute(text(
            "SELECT value, investigations FROM entities WHERE kind = 'host'"))).all())  # fmt: skip
        stored = (await conn.execute(text(
            "SELECT alert_id, normalized FROM alert_records ORDER BY alert_id"))).all()  # fmt: skip
    assert hosts == ["pc-12"]
    assert counts == {"pc-12": 1}
    by_id = {r.alert_id: r.normalized for r in stored}
    first = by_id[proxy[0]["_id"]]
    assert [e["value"] for e in first["entities"] if e["kind"] == "host"] == ["pc-12"]
    assert first["normalizer_version"] == "1.1.0"
    assert [e for e in by_id[nested["_id"]]["entities"] if e["kind"] == "host"] == []
    assert all(e["kind"] != "host" or e["value"] == "pc-12"
               for n in by_id.values() for e in n["entities"])  # fmt: skip
    assert len(first["entities"]) > 1  # the other entities stay


async def test_the_downgrade_restores_the_old_entities(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    proxy = doc(1, "r1", "10.0.0.1", NOW)
    proxy["_source"]["observer"] = {"hostname": "tp8"}
    proxy["_source"]["host"] = {"name": "tp8"}
    await ingest(app_engine, [proxy])  # the 1.1 normalizer: no host entity
    await migrate.downgrade(migrated_engine, "0014")
    async with migrated_engine.connect() as conn:
        hosts_q = "SELECT value FROM investigation_entities WHERE kind = 'host'"
        hosts = (await conn.execute(text(hosts_q))).scalars().all()
        count_q = "SELECT investigations FROM entities WHERE kind = 'host' AND value = 'tp8'"
        count = (await conn.execute(text(count_q))).scalar_one()
        version_q = "SELECT normalized ->> 'normalizer_version' FROM alert_records"
        version = (await conn.execute(text(version_q))).scalar_one()
    assert (hosts, count, version) == (["tp8"], 1, "1.0.0")
    await migrate.upgrade(migrated_engine)
    async with migrated_engine.connect() as conn:
        left_q = "SELECT count(*) FROM investigation_entities WHERE kind = 'host'"
        left = (await conn.execute(text(left_q))).scalar_one()
    assert left == 0
