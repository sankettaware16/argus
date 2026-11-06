"""The linker and the incident lifecycle against the database, as the runtime role (P4-F E2 and
E4, shadow): one incident from two linked devices, every link with its reason, silent folding,
a material change, idempotence, the retro-hunt, host aliases, and today's cases untouched."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.risk import incident_config, incidents, run
from argus.risk.identity import Identity
from tests.integration.risk.conftest import C2, NOW, all_rows, group, rule, scalar, setup

pytestmark = pytest.mark.integration
OUTSIDE = "flagged by outside threat intel"
C2_DOMAIN = {"url.domain": ["cdn.c2-example.net"]}


def linked() -> run.Setup:
    base = setup()
    config = incident_config.load()
    who = Identity(base.classifier, config.identity, config.hubs.roles)
    return replace(base, linking=incidents.LinkSetup(config, who))


async def world(owner: AsyncEngine) -> dict[str, object]:
    await rule(owner, "r-ioc", "IOC rule", severity="critical", indices=("acme-logs-squid-*",))
    await rule(owner, "r-beacon", "Beacon rule", threat=(C2,))
    return {
        "one": await group(owner, "r-ioc", actor="10.1.1.2", severity="critical",
                           fields=C2_DOMAIN, flags=(OUTSIDE,)),
        "two": await group(owner, "r-ioc", actor="10.1.1.3", severity="critical",
                           fields=C2_DOMAIN, hours_ago=5),
        "alone": await group(owner, "r-ioc", actor="10.1.1.9", severity="critical",
                             fields={"url.domain": ["unrelated-example.org"]}),
    }  # fmt: skip


async def test_two_devices_on_one_flagged_domain_are_one_incident_with_reasons(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    report = await run.step(app_engine, linked(), NOW)
    assert "incidents (shadow): 2 live, 2 new" in report.incidents
    rows = await all_rows(
        migrated_engine,
        "SELECT id, state, devices, groups, version, changed, view, lanes FROM risk_incidents"
        " ORDER BY devices DESC",
    )
    assert [(r.devices, r.groups, r.version, r.state) for r in rows] == [
        (2, 2, 1, "active"), (1, 1, 1, "active"),
    ]  # fmt: skip
    top = rows[0]
    assert top.changed == ["new incident"]
    assert {o["label"] for o in top.view["objects"]} == {"10.1.1.2", "10.1.1.3"}
    assert top.view["lane"] == "decisive"
    assert {"decisive", "campaign"} <= set(top.lanes)
    links = await all_rows(
        migrated_engine,
        "SELECT via, reason, kept, b_object FROM risk_links WHERE incident_id = :i",
        i=top.id,
    )
    pair = [lk for lk in links if lk.b_object is not None]
    assert pair
    assert all(lk.reason and len(lk.reason) <= 200 and lk.kept for lk in links)
    assert any("c2-example.net" in lk.reason for lk in pair)
    members = {r.investigation_id for r in await all_rows(
        migrated_engine, "SELECT investigation_id FROM risk_incident_groups WHERE incident_id = :i",
        i=top.id)}  # fmt: skip
    assert members == {made["one"].id, made["two"].id}  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_threats") >= 1
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 0  # shadow

    again = await run.step(app_engine, linked(), NOW + timedelta(minutes=2))  # idempotent
    assert "0 new" in again.incidents
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_incidents") == 2
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_links WHERE incident_id = :i",
                        i=top.id) == len(links)  # fmt: skip


async def test_new_alert_groups_fold_in_and_a_new_rule_is_a_material_change(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, linked(), NOW - timedelta(minutes=50))
    later = await group(migrated_engine, "r-ioc", actor="10.1.1.2", severity="critical",
                        hours_ago=0.3, fields=C2_DOMAIN)  # fmt: skip
    await run.step(app_engine, linked(), NOW)
    top = (await all_rows(migrated_engine, "SELECT id, groups, version FROM risk_incidents"
                          " WHERE devices = 2"))[0]  # fmt: skip
    assert (top.groups, top.version) == (3, 1)  # folded in silently
    member = await scalar(
        migrated_engine,
        "SELECT count(*) FROM risk_incident_groups WHERE incident_id = :i"
        " AND investigation_id = :g",
        i=top.id, g=later.id,
    )  # fmt: skip
    assert member == 1
    await group(migrated_engine, "r-beacon", actor="10.1.1.3", hours_ago=0.1,
                signals={"dns.tunnel_suspected": True})  # fmt: skip
    await run.step(app_engine, linked(), NOW + timedelta(minutes=10))
    row = (await all_rows(migrated_engine, "SELECT version, changed FROM risk_incidents"
                          " WHERE id = :i", i=top.id))[0]  # fmt: skip
    assert row.version == 2
    assert any("new rule" in c for c in row.changed)


async def test_a_thing_flagged_later_reads_again_what_touched_it(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-beacon", "Beacon rule", threat=(C2,))
    early = await group(migrated_engine, "r-beacon", actor="10.1.1.4", hours_ago=20,
                        fields={"url.domain": ["late-example.net"]})  # fmt: skip
    await run.step(app_engine, linked(), NOW - timedelta(hours=1))
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_threats") == 0
    await group(migrated_engine, "r-beacon", actor="10.1.1.5", hours_ago=0.2, flags=(OUTSIDE,),
                fields={"url.domain": ["late-example.net"]})  # fmt: skip
    report = await run.step(app_engine, linked(), NOW)
    assert "(1 new: 2 alert groups to read again)" in report.incidents
    signature = await scalar(
        migrated_engine, "SELECT signature FROM risk_groups WHERE investigation_id = :g",
        g=early.id,
    )  # fmt: skip
    assert signature == incidents.RETRO_SIGNATURE
    hunted = await scalar(migrated_engine, "SELECT hunted_at FROM risk_threats")
    assert hunted == NOW
    next_pass = await run.step(app_engine, linked(), NOW + timedelta(minutes=2))
    assert next_pass.observed >= 1  # read again with its flag
    assert "0 new:" in next_pass.incidents


async def test_a_host_named_by_a_key_is_an_alias_of_its_address(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    from tests.integration.risk import conftest

    await rule(migrated_engine, "r-host", "Host rule", severity="critical")
    made = await conftest.group(migrated_engine, "r-host", actor="lab-pc-7", severity="critical",
                                fields={"host.ip": ["10.1.1.7"]})  # fmt: skip
    peer = await conftest.group(
        migrated_engine, "r-host", actor="web-srv-01", fields={"source.ip": ["10.1.4.20"]}
    )  # its client
    # the conftest keys groups by source.ip; rewrite these keys as host keys
    from sqlalchemy import text

    async with migrated_engine.begin() as conn:
        for host, gid in (("lab-pc-7", made.id), ("web-srv-01", peer.id)):
            await conn.execute(
                text("UPDATE investigations SET group_key = :k WHERE id = :i"),
                {"k": f'[["host.name","{host}"]]', "i": gid},
            )
    await run.step(app_engine, linked(), NOW)
    rows = await all_rows(migrated_engine, "SELECT device, kind, value, source FROM risk_aliases")
    assert [(r.device, r.kind, r.value, r.source) for r in rows] == [
        ("ip:10.1.1.7", "host", "lab-pc-7", "alert")
    ]  # the server's client (its source.ip) is never its alias


MAP = b"""
networks:
  - {name: dynamic pool, range: 10.1.5.0/24, fields: {site.addressing: dynamic}}
  - {name: border, range: 10.1.6.1, fields: {site.type: gateway}}
"""


def with_identity(unknown: str = "static") -> run.Setup:
    """The pass with the linker on, an asset map (a dynamic pool, a gateway) and a resolver."""
    import ipaddress

    from argus.assets.assetmap import parse_asset_map
    from argus.assets.classify import IpClassifier

    base = setup()
    classifier = IpClassifier(parse_asset_map(MAP), (ipaddress.ip_network("131.21.124.0/22"),))
    config = incident_config.load()
    identity = config.identity.model_copy(update={"unknown_addressing": unknown})
    who = Identity(classifier, identity, config.hubs.roles, (ipaddress.ip_network("10.1.9.53/32"),))
    return replace(base, classifier=classifier, linking=incidents.LinkSetup(config, who))


async def test_the_pass_keys_dynamic_addresses_per_day_and_leaves_resolvers_out(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    await group(migrated_engine, "r-ioc", actor="10.1.5.20", severity="critical",
                fields=C2_DOMAIN, flags=(OUTSIDE,))  # fmt: skip
    await group(migrated_engine, "r-ioc", actor=["10.1.9.53", "10.1.1.2"], severity="critical",
                fields={"url.domain": ["one-example.net"]})  # fmt: skip
    alone = await group(migrated_engine, "r-ioc", actor="10.1.9.53", severity="critical",
                        fields={"url.domain": ["two-example.net"]})  # fmt: skip
    gateway = await group(migrated_engine, "r-ioc", actor="10.1.6.1", severity="critical")
    first = await run.step(app_engine, with_identity(), NOW)
    assert first.observed == 4
    keys = {r.key for r in await all_rows(migrated_engine, "SELECT key FROM risk_objects")}
    assert any(k.startswith("ip:10.1.5.20@") for k in keys)  # a dynamic address: per day
    assert "ip:10.1.1.2" in keys
    assert not [k for k in keys if k.startswith(("ip:10.1.9.53", "ip:10.1.6.1"))]  # hubs
    categories = {r.investigation_id: r.category for r in await all_rows(
        migrated_engine, "SELECT investigation_id, category FROM risk_groups")}  # fmt: skip
    assert categories[alone.id] == categories[gateway.id] == "hub_activity"
    await run.step(app_engine, with_identity(), NOW + timedelta(minutes=1))  # the retro-hunt's
    again = await run.step(app_engine, with_identity(), NOW + timedelta(minutes=2))
    assert again.observed == 0
    changed = await run.step(app_engine, with_identity("dynamic"), NOW + timedelta(minutes=4))
    assert changed.observed == 4  # identity's settings changed: every group is read again
    keys = {r.key for r in await all_rows(
        migrated_engine, "SELECT b.key FROM risk_objects b"
        " JOIN risk_observations o ON o.object_id = b.id")}  # fmt: skip
    assert any(k.startswith("ip:10.1.1.2@") for k in keys)


async def test_a_merge_of_two_capped_incidents_moves_the_overflows_in_the_database(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    for n in range(12):
        for actor in ("10.1.1.2", "10.1.1.3"):
            await group(migrated_engine, "r-ioc", actor=actor, severity="critical",
                        hours_ago=3 + n / 10)  # fmt: skip
    base = linked()
    assert base.linking is not None
    config = base.linking.config
    small = config.model_copy(update={"caps": config.caps.model_copy(update={"groups": 10})})
    capped = replace(base, linking=replace(base.linking, config=small))
    await run.step(app_engine, capped, NOW - timedelta(hours=1))
    before = await all_rows(migrated_engine, "SELECT id, parent_id FROM risk_incidents ORDER BY id")
    assert len(before) == 4  # two incidents, each with an overflow
    for actor in ("10.1.1.2", "10.1.1.3"):  # a flagged domain now joins them
        await group(migrated_engine, "r-ioc", actor=actor, severity="critical", hours_ago=0.2,
                    fields=C2_DOMAIN, flags=(OUTSIDE,))  # fmt: skip
    await run.step(app_engine, capped, NOW)
    rows = await all_rows(migrated_engine, "SELECT id, state, parent_id, merged_into, groups"
                          " FROM risk_incidents ORDER BY id")  # fmt: skip
    gone = [r for r in rows if r.state == "merged"]
    assert len(gone) == 1
    kept = gone[0].merged_into
    live = [r for r in rows if r.state != "merged"]
    assert all(r.groups <= 10 for r in live)
    assert all(r.parent_id == kept for r in live if r.id != kept)  # no orphaned overflow
    members = await all_rows(migrated_engine, "SELECT m.incident_id, m.investigation_id"
                             " FROM risk_incident_groups m")  # fmt: skip
    assert len(members) == len({m.investigation_id for m in members}) == 26
    assert {m.incident_id for m in members} <= {r.id for r in live}
