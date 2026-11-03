"""AR2c (D-170, D-174) against the database: which campus devices an investigation involves. A DNS
rule groups by the rare domain and lists every source address in its key; a rule that groups by
destination holds every device that reached it among its entities, which do not say which side an
address was on. Devices are the source side of a key and the campus's own addresses among the
entities; the campus resolvers named in ``campaigns.resolvers`` are none, and neither is private
space that no network of the asset map covers. How many investigations hold an address says
nothing: a device infected with a domain-generation algorithm is in hundreds of them.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.campaigns import load
from argus.campaigns.load import actors_of
from tests.integration.cases.conftest import investigation
from tests.integration.outside.conftest import CAMPUS_NET

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
CLASSIFIER = IpClassifier(None, (CAMPUS_NET,))


def test_a_key_names_its_campus_addresses_and_host_names_only() -> None:
    key = json.dumps([["source.ip", "10.1.1.7"], ["host.name", "tp8"], ["user.name", "alice"]])
    assert actors_of(key, CLASSIFIER) == {("ip", "10.1.1.7"), ("host", "tp8")}
    outside = json.dumps([["source.ip", "45.33.32.9"]])
    assert actors_of(outside, CLASSIFIER) == frozenset()  # an outside actor is no campus device
    listed = json.dumps([["source.ip", ["10.1.1.7", "10.1.1.8", "45.33.32.9", "x", 5]]])
    assert actors_of(listed, CLASSIFIER) == {("ip", "10.1.1.7"), ("ip", "10.1.1.8")}
    # (a list is read under a source field only: a destination's list names no device)
    far = json.dumps([["destination.ip", ["10.1.1.7"]], ["url.domain", ["10.1.1.8"]]])
    assert actors_of(far, CLASSIFIER) == frozenset()
    assert actors_of("not json", CLASSIFIER) == actors_of("[1, 2]", CLASSIFIER) == frozenset()


async def make(
    owner: AsyncEngine, key: str, entities: list[tuple[str, str]]
) -> uuid.UUID:  # fmt: skip
    inv = await investigation(
        owner, rule="dns", actor=(("source.ip", "10.99.0.1"),), entities=entities
    )
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET group_key = :k, last_event_at = :t WHERE id = :i"),
            {"k": key, "t": NOW - timedelta(hours=1), "i": inv},
        )
        await conn.execute(
            text("DELETE FROM investigation_entities WHERE investigation_id = :i"
                 " AND value = '10.99.0.1'"),
            {"i": inv},
        )  # fmt: skip
    return inv


async def test_the_devices_are_the_source_side_of_the_key_and_the_campus_among_the_entities(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    listed = json.dumps([["source.ip", ["10.1.1.7", "10.1.1.8", "10.4.200.47"]]])
    held = [("ip", "10.1.1.7"), ("ip", "10.1.1.8"), ("ip", "45.33.32.9"),
            ("domain", "x.example.com")]  # fmt: skip
    a = await make(migrated_engine, listed, held)
    b = await make(migrated_engine, json.dumps([["host.name", "tp8"]]),
                   [("host", "tp8"), ("ip", "10.1.1.9"), ("ip", "198.51.100.31")])  # fmt: skip
    c = await make(migrated_engine, json.dumps([["source.ip", "45.33.32.9"]]),
                   [("ip", "198.51.100.30")])  # fmt: skip
    keys = {
        a: listed,
        b: json.dumps([["host.name", "tp8"]]),
        c: json.dumps([["source.ip", "45.33.32.9"]]),
    }
    async with app_engine.connect() as conn:
        got = await load.hosts_for(conn, keys, CLASSIFIER)
    # the key lists its sources; the outside address among the entities is no device
    assert got[a] == {("ip", "10.1.1.7"), ("ip", "10.1.1.8"), ("ip", "10.4.200.47")}
    # private space that no network of the map covers (10.1.1.9) is not a campus device among the
    # entities: it may be a resolver or a server as well (D-174)
    assert got[b] == {("host", "tp8"), ("ip", "198.51.100.31")}
    assert got[c] == {("ip", "198.51.100.30")}  # (a campus prefix address)


async def test_a_heavy_dga_device_is_kept(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The device that asks for a new random name every minute is in hundreds of investigations;
    the old rule (an address that 50 or more investigations hold is a resolver) dropped it."""
    keys = {}
    for n in range(60):
        inv = await make(
            migrated_engine, "[]", [("ip", "198.51.100.77"), ("ip", f"198.51.100.{n + 100}")]
        )
        keys[inv] = "[]"
    async with app_engine.connect() as conn:
        every = await load.hosts_for(conn, keys, CLASSIFIER)
    assert all(("ip", "198.51.100.77") in hosts for hosts in every.values())
    assert all(len(hosts) == 2 for hosts in every.values())


async def test_the_resolvers_named_in_the_settings_are_no_devices(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    listed = json.dumps([["source.ip", ["198.51.100.53", "198.51.100.54", "198.51.100.90"]]])
    held = [("ip", "198.51.100.53"), ("ip", "198.51.100.54"), ("ip", "198.51.100.55"),
            ("ip", "198.51.100.90")]  # fmt: skip
    inv = await make(migrated_engine, listed, held)
    only = await make(migrated_engine, "[]", [("ip", "198.51.100.53")])
    resolvers = [ipaddress.ip_network("198.51.100.53/32"), ipaddress.ip_network("198.51.100.54/32")]
    async with app_engine.connect() as conn:
        got = await load.hosts_for(conn, {inv: listed, only: "[]"}, CLASSIFIER, resolvers)
        none = await load.hosts_for(conn, {inv: listed, only: "[]"}, CLASSIFIER)
    assert got[inv] == {("ip", "198.51.100.90"), ("ip", "198.51.100.55")}
    assert only not in got  # an investigation with no device left has none
    assert ("ip", "198.51.100.53") in none[inv]  # (nothing is guessed when none is named)
    net = [ipaddress.ip_network("198.51.100.88/29")]  # a network: .88 to .95
    async with app_engine.connect() as conn:
        by_net = await load.hosts_for(conn, {inv: listed}, CLASSIFIER, net)
    assert by_net[inv] == {
        ("ip", "198.51.100.53"),
        ("ip", "198.51.100.54"),
        ("ip", "198.51.100.55"),
    }
