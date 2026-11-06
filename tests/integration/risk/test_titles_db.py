"""Incident titles read from the engine's own tables, as the runtime role: a real pass of the
linker over made-up alert groups, then the title of each incident from what it holds (its
devices, links, flags), another incident's case through a shared outside thing, the case it
follows, and a site whose file the checking lane verified served (ACME's made-up world)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import naming
from argus.risk import checking, run, titles
from tests.integration.risk import test_exposure as web_world
from tests.integration.risk.conftest import NOW, all_rows, group, rule, setup
from tests.integration.risk.test_incidents import C2_DOMAIN, OUTSIDE, linked

pytestmark = pytest.mark.integration
BEACON = {"proxy.regularity": 0.1}


async def _title(engine: AsyncEngine, incident: int, word: str = naming.SUSPECTED) -> str:
    async with engine.connect() as conn:
        facts = await titles.read_facts(conn, incident, titles.Context(setup().classifier))
    assert facts is not None
    return titles.title_for_incident(facts, word).text


async def _case(owner: AsyncEngine, incident: int) -> int:
    async with owner.begin() as conn:
        number = (await conn.execute(text(
            "INSERT INTO cases (id, title, state, severity, version, cause) VALUES"
            " (gen_random_uuid(), 't', 'suspected', 'low', 1, 'person') RETURNING id, number"
        ))).one()  # fmt: skip
        await conn.execute(text(
            "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
            " from_state, to_state) VALUES (:c, 1, 'suspected', 'argus:test', NULL, NULL,"
            " 'suspected')"
        ), {"c": number.id})  # fmt: skip
        await conn.execute(text("UPDATE risk_incidents SET case_id = :c WHERE id = :i"),
                           {"c": number.id, "i": incident})  # fmt: skip
    return int(number.number)


async def test_device_incidents_are_titled_from_their_objects_links_and_flags(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    for actor, hours in (("10.1.1.2", 2), ("10.1.1.3", 5)):
        await group(migrated_engine, "r-ioc", actor=actor, severity="critical", hours_ago=hours,
                    fields=C2_DOMAIN, flags=(OUTSIDE,))  # fmt: skip
    for _ in range(3):  # more alert groups of one device: still one device
        await group(
            migrated_engine,
            "r-ioc",
            actor="10.1.1.9",
            severity="critical",
            fields={"url.domain": ["beacon.unrelated-example.org"]},
            signals=BEACON,
        )
    await run.step(app_engine, linked(), NOW)
    rows = await all_rows(
        migrated_engine, "SELECT id, devices, groups FROM risk_incidents ORDER BY devices DESC"
    )
    assert [(r.devices, r.groups) for r in rows] == [(2, 2), (1, 3)]
    pair, alone = rows[0].id, rows[1].id
    assert await _title(app_engine, pair, naming.LIKELY) == (
        "Likely contact with c2-example.net from 2 campus devices"
    )
    assert await _title(app_engine, alone) == (
        "Suspected beaconing from 10.1.1.9 to unrelated-example.org"
    )
    # VirusTotal's cached answer for the flagged domain: its engines, and a family in its tags
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO outside_lookups (source, kind, indicator, status, answer) VALUES"
            " ('virustotal', 'domain', 'c2-example.net', 'found', CAST(:a AS jsonb))"
        ), {"a": '{"malicious": 7, "engines": 94, "tags": ["amadey"]}'})  # fmt: skip
    async with app_engine.connect() as conn:
        made = await titles.title_for(conn, pair, titles.Context(), naming.LIKELY)
    assert made is not None
    assert made.text == (
        "Likely Amadey contact with c2-example.net (VirusTotal: 7 engines) from 2 campus devices"
    )
    # an earlier incident's case whose links carry the same outside thing
    number = await _case(migrated_engine, pair)
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO risk_links (incident_id, a_object, b_object, via, value, priority,"
            " delta_seconds, reason, kept, created_at) SELECT :i, object_id, NULL, 'rare',"
            " 'domain:unrelated-example.org', 4, 0, 'test', true, :now"
            " FROM risk_incident_objects WHERE incident_id = :i LIMIT 1"
        ), {"i": pair, "now": NOW})  # fmt: skip
    assert await _title(app_engine, alone) == (
        f"Suspected beaconing from 10.1.1.9 to unrelated-example.org, the server of case {number}"
    )
    # or a link of its own the caps kept apart, whose far end that incident holds
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("DELETE FROM risk_links WHERE incident_id = :i AND reason = 'test'"), {"i": pair}
        )
        await conn.execute(text(
            "INSERT INTO risk_links (incident_id, a_object, b_object, via, value, priority,"
            " delta_seconds, reason, kept, created_at) SELECT :me, a.object_id, b.object_id,"
            " 'rare', 'domain:unrelated-example.org', 4, 0, 'not joined (test)', false, :now"
            " FROM risk_incident_objects a, risk_incident_objects b"
            " WHERE a.incident_id = :me AND b.incident_id = :i LIMIT 1"
        ), {"me": alone, "i": pair, "now": NOW})  # fmt: skip
    assert (await _title(app_engine, alone)).endswith(f", the server of case {number}")
    # a threat list's entry for the name the device beaconed to names its family
    answers = [{"value": "beacon.unrelated-example.org", "sources": {"feed": {"match": [
        {"description": "PS1Bot C2 (made-up feed)"}]}}}]  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE dossiers SET body = CAST(:b AS jsonb) WHERE investigation_id IN"
                " (SELECT investigation_id FROM risk_incident_groups WHERE incident_id = :i)"
            ),
            {
                "b": json.dumps(
                    {
                        "context": {
                            "pack": {
                                "ti": {
                                    "listed": ["beacon.unrelated-example.org"],
                                    "answers": answers,
                                }
                            }
                        }
                    }
                ),
                "i": alone,
            },
        )
    assert (await _title(app_engine, alone)).startswith("Suspected PS1Bot beaconing from 10.1.1.9")
    # the case it follows is said once, at the end
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE risk_incidents SET follows_id = :p WHERE id = :i"),
                           {"p": pair, "i": alone})  # fmt: skip
    assert await _title(app_engine, alone) == (
        f"Suspected PS1Bot beaconing from 10.1.1.9 to unrelated-example.org — follows case {number}"
    )
    async with app_engine.connect() as conn:
        assert await titles.read_facts(conn, 10**9, titles.Context()) is None


async def test_a_site_says_served_only_after_the_checking_lane_verified_it(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await web_world.world(migrated_engine)
    config = linked()
    await run.step(app_engine, config, web_world.WHEN)
    assert await all_rows(migrated_engine, "SELECT id FROM risk_incidents") == []  # no lane yet
    await checking.run_pass(app_engine, web_world.Fake(), web_world.normal, now=web_world.WHEN,
                            config=web_world.ON, clock=lambda: web_world.WHEN)  # fmt: skip
    await run.step(app_engine, config, web_world.WHEN + timedelta(minutes=2))
    rows = await all_rows(
        migrated_engine,
        "SELECT i.id, b.key FROM risk_incidents i JOIN risk_incident_objects m"
        " ON m.incident_id = i.id JOIN risk_objects b ON b.id = m.object_id",
    )
    by_site = {r.key: r.id for r in rows}
    assert set(by_site) == {f"domain:{web_world.SITE}"}  # the soft-404 site stays in the digest
    made = await _title(app_engine, by_site[f"domain:{web_world.SITE}"], naming.LIKELY)
    assert made == f"Likely web scan of {web_world.SITE} by {web_world.SCOUT} — a .env file served"
    async with app_engine.connect() as conn:
        facts = await titles.read_facts(conn, by_site[f"domain:{web_world.SITE}"],
                                        titles.Context())  # fmt: skip
    assert facts is not None
    assert {(p.source, p.site) for p in facts.exposure if p.served} == {
        (web_world.SCOUT, web_world.SITE)
    }


async def test_a_capped_object_read_reads_devices_first_and_counts_the_rest(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    for actor, hours in (("10.1.1.2", 2), ("10.1.1.3", 5)):
        await group(migrated_engine, "r-ioc", actor=actor, severity="critical", hours_ago=hours,
                    fields=C2_DOMAIN, flags=(OUTSIDE,))  # fmt: skip
    await run.step(app_engine, linked(), NOW)
    (pair,) = [r.id for r in await all_rows(migrated_engine, "SELECT id FROM risk_incidents")]
    # more of the incident's objects: a device on two days (one device), a host, two accounts
    extra = [("device", "ip:10.1.1.50@2026-10-19"), ("device", "ip:10.1.1.50@2026-10-20"),
             ("device", "host:lab-pc-9"), ("account", "alice"), ("account", "bob")]  # fmt: skip
    async with migrated_engine.begin() as conn:
        for kind, key in extra:
            await conn.execute(text(
                "WITH o AS (INSERT INTO risk_objects (kind, key, first_seen, last_seen)"
                " VALUES (:k, :key, :now, :now) RETURNING id) INSERT INTO risk_incident_objects"
                " (incident_id, object_id, role, joined_at) SELECT :i, id, 'actor', :now FROM o"
            ), {"k": kind, "key": key, "now": NOW, "i": pair})  # fmt: skip
    whole = await _title(app_engine, pair, naming.LIKELY)
    assert whole == "Likely contact with c2-example.net from 2 of 4 campus devices"
    monkeypatch.setattr(titles, "OBJECTS_READ", 3)  # the read stops inside the devices
    async with app_engine.connect() as conn:
        facts = await titles.read_facts(conn, pair, titles.Context(setup().classifier))
    assert facts is not None
    assert all(r.kind == "device" for r in facts.objects)  # devices before accounts
    assert len(facts.objects) == 3
    assert facts.more_devices == 1  # 10.1.1.50's two days, one device
    assert facts.more_accounts == 2
    assert await _title(app_engine, pair, naming.LIKELY) == whole  # the same M, and no less
