"""The engine's pass against the database, as the runtime role (P4-F E1, shadow): rule
metadata, observations, scores, lanes, crossings and digest categories; idempotence; a new dossier
read again; the keep periods; the retention purge's cascade; and today's tables untouched."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.risk import observe, rulemeta, run
from argus.risk.roles import RoleEntity
from tests.integration.risk.conftest import (
    ACCESS,
    C2,
    EXFIL,
    NOW,
    all_rows,
    dossier,
    group,
    rule,
    scalar,
    setup,
)

pytestmark = pytest.mark.integration
OUTSIDE = "flagged by outside threat intel"
BEACON = {"proxy.regularity": 0.1, "ports.risky": 2, "proxy.hosts_to_destination": 1}


async def world(owner: AsyncEngine) -> dict[str, object]:
    await rule(owner, "r-beacon", "Beacon rule", threat=(C2, EXFIL))
    await rule(owner, "r-download", "Download rule", severity="medium", threat=(C2, ACCESS))
    await rule(owner, "r-ioc", "IOC rule", severity="critical", indices=("acme-logs-*",))
    await rule(owner, "r-web", "Web rule", severity="high", indices=("acme-logs-nginx-*",))
    made = {
        # one device: a beacon and a download in 24 h with weak evidence -> the burst lane
        "burst_a": await group(owner, "r-beacon", actor="10.1.1.1", risk_score=35,
                               signals=BEACON, fields={"destination.ip": ["45.138.12.9"]}),
        "burst_b": await group(owner, "r-download", actor="10.1.1.1", hours_ago=3,
                               signals={"proxy.regularity": 0.2}),
        # a critical rule's match on another device -> decisive
        "decisive": await group(owner, "r-ioc", actor="10.1.1.2", severity="critical"),
        # an outside detection on a third device's beacon -> decisive with two sources
        "outside": await group(owner, "r-beacon", actor="10.1.1.3", flags=(OUTSIDE,),
                               signals={"proxy.regularity": 0.1}),
        # rule hits alone on a fourth -> no lane
        "quiet": await group(owner, "r-beacon", actor="10.1.1.4"),
        # an outside scanner with no campus target named -> the digest's inbound attempts
        "inbound": await group(owner, "r-web", actor="45.138.13.7", severity="high",
                               signals={"ti.listed": 2}),
        # blocked inbound
        "blocked": await group(owner, "r-web", actor="45.138.13.8", outcome="failure"),
    }  # fmt: skip
    return made  # type: ignore[return-value]


async def test_a_pass_observes_scores_and_records_lanes(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    report = await run.step(app_engine, setup(), NOW)
    assert report.observed == len(made)
    sources = await all_rows(migrated_engine, "SELECT source_key, objects_median FROM risk_sources")
    assert all(r.objects_median >= 1 for r in sources)
    assert report.rules == 4
    found = await all_rows(
        migrated_engine, "SELECT rule_id, lineage, tactics, stage_mask, family FROM rules"
    )
    meta = {r.rule_id: r for r in found}
    assert meta["r-beacon"].tactics == ["command and control", "exfiltration"]
    assert meta["r-beacon"].stage_mask == 0b1100
    assert meta["r-beacon"].family == "squid"
    assert meta["r-ioc"].family is None  # a rule over every index names no family
    assert meta["r-web"].family == "nginx"
    lanes = {r.key: (tuple(r.lanes), r.held) for r in await all_rows(
        migrated_engine, "SELECT key, lanes, held FROM risk_objects")}  # fmt: skip
    assert lanes["ip:10.1.1.1"] == (("burst",), "lane")
    assert lanes["ip:10.1.1.2"] == (("decisive",), "lane")
    assert lanes["ip:10.1.1.3"][0][0] == "decisive"
    assert lanes["ip:10.1.1.4"] == ((), "below")
    assert not any(k.startswith("ip:45.") for k in lanes)  # outside addresses are no objects
    crossings = await all_rows(
        migrated_engine,
        "SELECT b.key, c.lane, c.new_item FROM risk_crossings c JOIN risk_objects b"
        " ON b.id = c.object_id ORDER BY 1, 2",
    )
    assert {(r.key, r.lane) for r in crossings} >= {("ip:10.1.1.1", "burst"),
                                                     ("ip:10.1.1.2", "decisive")}  # fmt: skip
    assert all(r.new_item for r in crossings)
    category = {r.investigation_id: r.category for r in await all_rows(
        migrated_engine, "SELECT investigation_id, category FROM risk_groups")}  # fmt: skip
    assert category[made["burst_a"].id] == "presented"  # type: ignore[attr-defined]
    assert category[made["quiet"].id] == "outbound_low"  # type: ignore[attr-defined]
    assert category[made["inbound"].id] == "inbound_attempt"  # type: ignore[attr-defined]
    assert category[made["blocked"].id] == "inbound_blocked"  # type: ignore[attr-defined]
    roles = {(r.kind, r.value, r.role) for r in await all_rows(
        migrated_engine, "SELECT kind, value, role FROM risk_entities")}  # fmt: skip
    assert ("ip", "45.138.12.9", "threat") in roles
    assert ("ip", "45.138.13.7", "actor") in roles
    why = await scalar(
        migrated_engine,
        "SELECT s.breakdown FROM risk_object_scores s JOIN risk_objects b ON b.id = s.object_id"
        " WHERE b.key = 'ip:10.1.1.1' AND s.span = '24h'",
    )
    assert {w["source"] for w in why} >= {"ev:beacon", "ev:ports", "ev:rare_dest"}
    factors = await scalar(
        migrated_engine,
        "SELECT count(*) FROM risk_observations o JOIN risk_sources s ON s.source_key ="
        " o.source_key AND s.role = o.role WHERE o.prevalence = s.prevalence"
        " AND abs(o.score - o.base * o.outcome * s.prevalence * s.fidelity) < 1e-9",
    )
    assert factors == await scalar(migrated_engine, "SELECT count(*) FROM risk_observations")


async def test_a_second_pass_reads_nothing_again_and_records_no_new_crossing(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, setup(), NOW)
    counts = await all_rows(
        migrated_engine,
        "SELECT (SELECT count(*) FROM risk_observations), (SELECT count(*) FROM risk_crossings),"
        " (SELECT max(id) FROM risk_observations)",
    )
    again = await run.step(app_engine, setup(), NOW + timedelta(minutes=2))
    assert again.observed == 0
    assert again.crossings == 0
    assert again.new_items == 0
    assert counts == await all_rows(
        migrated_engine,
        "SELECT (SELECT count(*) FROM risk_observations), (SELECT count(*) FROM risk_crossings),"
        " (SELECT max(id) FROM risk_observations)",
    )


async def feed(owner: AsyncEngine, days_old: float) -> None:
    """The suite's mirror feed, its newest indicator ``days_old``."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ti_sources (source, newest, checked_at) VALUES ('abuse-ioc', :n, :n)"
                " ON CONFLICT (source) DO UPDATE SET newest = EXCLUDED.newest"
            ),
            {"n": NOW - timedelta(days=days_old)},
        )


async def test_a_new_dossier_is_read_again_and_replaces_the_observations(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await feed(migrated_engine, 1)
    quiet = await group(migrated_engine, "r-x", actor="10.2.2.2")
    await run.step(app_engine, setup(), NOW)
    sources = "SELECT array_agg(source_key ORDER BY source_key) FROM risk_observations"
    assert len(await scalar(migrated_engine, sources)) == 1
    await dossier(migrated_engine, quiet.id, 2, {"ti.listed": 4, "proxy.regularity": 0.1})
    report = await run.step(app_engine, setup(), NOW + timedelta(minutes=2))
    assert report.observed == 1
    found = await scalar(migrated_engine, sources)
    assert {s.split(":")[0] for s in found} == {"rule", "ev"}
    assert "ev:ti" in found
    assert await scalar(migrated_engine, "SELECT version FROM risk_groups") == 2
    lanes = await scalar(migrated_engine, "SELECT lanes FROM risk_objects")
    assert lanes == ["decisive", "burst"]  # a fresh threat-list hit with another source


async def test_a_hit_on_a_stale_feed_weighs_less_and_is_not_decisive(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await feed(migrated_engine, 29)
    await group(migrated_engine, "r-x", actor="10.2.2.2", signals={"ti.listed": 4})
    await run.step(app_engine, setup(), NOW)
    ti = await all_rows(migrated_engine, "SELECT base, strong FROM risk_observations"
                                         " WHERE source_key = 'ev:ti'")  # fmt: skip
    assert [(r.base, r.strong) for r in ti] == [(20.0, False)]
    assert await scalar(migrated_engine, "SELECT lanes FROM risk_objects") == []


async def test_an_object_leaves_its_lane_as_its_score_decays_and_returns_as_no_new_item(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    await group(migrated_engine, "r-ioc", actor="10.3.3.3", severity="critical")
    await run.step(app_engine, setup(), NOW)
    later = NOW + timedelta(days=2)
    await run.step(app_engine, setup(), later)
    assert await scalar(migrated_engine, "SELECT lanes FROM risk_objects") == []
    await group(migrated_engine, "r-ioc", actor="10.3.3.3", severity="critical",
                hours_ago=-47)  # fmt: skip
    report = await run.step(app_engine, setup(), later)
    assert report.crossings == 1
    assert report.new_items == 0


async def test_the_keep_periods_prune_and_the_purge_cascades(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    await run.step(app_engine, setup(), NOW)
    keep = setup().config.keep_days
    await run.prune(app_engine, setup().config, NOW + timedelta(days=keep + 1))
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_groups") == 0
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_observations") == 0
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_entities") == 0
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_crossings") > 0
    # an investigation the retention purge removes takes the engine's rows with it
    await run.step(app_engine, setup(), NOW)
    gid = made["burst_a"].id  # type: ignore[attr-defined]
    async with migrated_engine.begin() as conn:
        for table in ("signals", "dossiers", "investigation_alerts", "investigation_entities"):
            await conn.execute(text(f"DELETE FROM {table} WHERE investigation_id = :i"), {"i": gid})  # noqa: S608
        await conn.execute(text("DELETE FROM investigations WHERE id = :i"), {"i": gid})
    left = "SELECT count(*) FROM {} WHERE investigation_id = :i"
    for table in ("risk_groups", "risk_entities", "risk_observations"):
        assert await scalar(migrated_engine, left.format(table), i=gid) == 0


async def test_a_recreated_rule_keeps_its_lineage_in_the_registry(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-old", "Same rule", first=NOW - timedelta(days=40))
    async with app_engine.begin() as conn:
        await rulemeta.sync(conn, setup().families, NOW)
    await rule(migrated_engine, "r-new", "same  RULE", first=NOW - timedelta(days=1))
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE rules SET name = 'Renamed' WHERE rule_id = 'r-old'"))
    async with app_engine.begin() as conn:
        changed = await rulemeta.sync(conn, setup().families, NOW)
    assert changed == 1
    lineages = {r.rule_id: r.lineage for r in await all_rows(
        migrated_engine, "SELECT rule_id, lineage FROM rules")}  # fmt: skip
    # the old rule was renamed first: the new one still finds no rule of its name...
    assert lineages["r-old"] == rulemeta.new_lineage("r-old")
    assert lineages["r-new"] == rulemeta.new_lineage("r-new")
    await rule(migrated_engine, "r-newer", "Renamed", first=NOW)
    async with app_engine.begin() as conn:
        await rulemeta.sync(conn, setup().families, NOW)
    newer = await scalar(migrated_engine, "SELECT lineage FROM rules WHERE rule_id = 'r-newer'")
    assert newer == lineages["r-old"]  # ...and a rule made again under the new name takes it


async def test_the_pass_writes_nothing_of_todays_pipeline(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    tables = ("investigations", "investigation_raises", "investigation_entities", "cases",
              "case_members", "case_suggestions", "assessments", "review_events")  # fmt: skip
    query = " UNION ALL ".join(
        f"SELECT '{t}', md5(coalesce(string_agg(x::text, ',' ORDER BY x::text), '')) FROM {t} x"  # noqa: S608
        for t in tables
    )
    before = await all_rows(migrated_engine, query)
    await run.step(app_engine, setup(), NOW)
    assert await all_rows(migrated_engine, query) == before


async def test_a_regroup_empties_the_engines_tables_with_the_investigations(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Every engine row derives from the alert groups (risk_groups names them by foreign key):
    a regroup empties them all, and keeps the rules' engine columns."""
    from argus.grouping.regroup import regroup

    await world(migrated_engine)
    await run.step(app_engine, setup(), NOW)
    tables = ("risk_groups", "risk_entities", "risk_observations", "risk_objects",
              "risk_sources", "risk_object_scores", "risk_crossings", "risk_incidents",
              "risk_incident_objects", "risk_incident_groups", "risk_links")  # fmt: skip
    count = " + ".join(f"(SELECT count(*) FROM {t})" for t in tables)  # noqa: S608 - constants
    assert await scalar(migrated_engine, f"SELECT {count}") > 0
    async with migrated_engine.begin() as conn:  # the suite's alerts are no NormalizedAlert
        await conn.execute(text("UPDATE alert_records SET status = 'quarantined',"
                                " quarantine_reason = 'not a normalized alert'"))  # fmt: skip
    assert await regroup(migrated_engine, NOW) == (0, 0)
    for table in tables:
        assert await scalar(migrated_engine, f"SELECT count(*) FROM {table}") == 0  # noqa: S608
    assert await scalar(migrated_engine, "SELECT count(lineage) FROM rules") == 4


async def test_a_root_dns_name_and_a_group_the_database_refuses_never_hold_the_batch_back(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await rule(migrated_engine, "r-dns", "DNS rule", indices=("acme-logs-dns-*",))
    root = await group(migrated_engine, "r-dns", actor="10.5.5.1",
                       fields={"dns.question.name": ["."], "url.domain": ["..."]})  # fmt: skip
    bad = await group(migrated_engine, "r-dns", actor="10.5.5.2")
    healthy = await group(migrated_engine, "r-dns", actor="10.5.5.3",
                          fields={"dns.question.name": ["rare.example.net."]})  # fmt: skip
    real = run.observe

    def refused(g: observe.Group, meta: rulemeta.RuleMeta | None,
                ctx: observe.Context) -> observe.Observed:  # fmt: skip
        seen = real(g, meta, ctx)
        if g.id != bad.id:
            return seen
        return replace(seen, entities=(*seen.entities, RoleEntity("domain", "", "threat", "x")))

    monkeypatch.setattr(run, "observe", refused)
    report = await run.step(app_engine, setup(), NOW)
    assert (report.observed, report.unwritten) == (3, 1)
    assert "1 alert groups could not be written" in report.line()
    held = {
        r.investigation_id: r.n
        for r in await all_rows(
            migrated_engine,
            "SELECT g.investigation_id, count(o.id) AS n FROM risk_groups g"
            " LEFT JOIN risk_observations o ON o.investigation_id = g.investigation_id GROUP BY 1",
        )
    }
    assert held == {root.id: 1, bad.id: 0, healthy.id: 1}  # fmt: skip
    domains = {r.value for r in await all_rows(
        migrated_engine, "SELECT value FROM risk_entities WHERE kind = 'domain'")}  # fmt: skip
    assert domains == {"rare.example.net"}
    again = await run.step(app_engine, setup(), NOW + timedelta(minutes=2))
    assert (again.observed, again.unwritten) == (0, 0)  # held until its inputs change


async def test_a_rule_over_every_index_gives_each_group_its_own_alerts_family(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Its newest alert came from squid; a group made from DNS logs is a DNS observation, so a
    squid rule on the same device is a second family, and one on the other device is not."""
    await rule(migrated_engine, "r-ioc", "IOC rule", indices=("acme-logs-*",),
               ancestor="acme-logs-squid-2026.10.19")  # fmt: skip
    await rule(migrated_engine, "r-squid", "Squid rule")
    await group(migrated_engine, "r-ioc", actor="10.6.6.1", index="acme-logs-dns-2026.10.20")
    await group(migrated_engine, "r-ioc", actor="10.6.6.2", index="acme-logs-squid-2026.10.20")
    for actor in ("10.6.6.1", "10.6.6.2"):
        await group(migrated_engine, "r-squid", actor=actor, hours_ago=4,
                    index="acme-logs-squid-2026.10.20")  # fmt: skip
    await run.step(app_engine, setup(), NOW)
    assert await scalar(migrated_engine,
                        "SELECT family FROM rules WHERE rule_id = 'r-ioc'") is None  # fmt: skip
    families = {(r.key, r.source_key.startswith("rule:L") and r.family) for r in await all_rows(
        migrated_engine, "SELECT b.key, o.source_key, o.family FROM risk_observations o"
        " JOIN risk_objects b ON b.id = o.object_id")}  # fmt: skip
    assert families == {("ip:10.6.6.1", "dns"), ("ip:10.6.6.1", "squid"),
                        ("ip:10.6.6.2", "squid")}  # fmt: skip
    two = await all_rows(
        migrated_engine,
        "SELECT b.key, s.families FROM risk_object_scores s JOIN risk_objects b"
        " ON b.id = s.object_id WHERE s.span = '24h' ORDER BY 1",
    )
    assert [(r.key, r.families) for r in two] == [("ip:10.6.6.1", 2), ("ip:10.6.6.2", 1)]
