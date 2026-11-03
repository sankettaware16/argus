"""The sign-in store (AR6, D-216): what is saved and read back, which addresses an investigation's
devices are (the existing definition, not a second one), and the ranks of the pass."""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.signins import model as m
from argus.signins import store
from argus.signins.plan import Tier
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.knownkit import make, open_case
from tests.integration.signins import kit as k
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
D28, D27 = date(2026, 10, 28), date(2026, 10, 27)
LOOKED = datetime(2026, 10, 29, 6, 0, tzinfo=UTC)


async def test_a_saved_day_reads_back_with_its_lookup_and_its_sightings(
    app_engine: AsyncEngine,
) -> None:
    a = kit.sighting("user01", hours=(9, 10), events=5, failures=2)
    b = kit.sighting("user02", hours=(14,), events=3, agent=kit.SAFARI)
    lookup = m.Lookup(k.HOST_A, D28, LOOKED, True, 2, 0)
    async with app_engine.begin() as conn:
        await store.save(conn, [lookup], [a, b])
    async with app_engine.connect() as conn:
        found = await store.records(conn, [k.HOST_A, k.HOST_B], D27, D28)
    assert list(found) == [(k.HOST_A, D28)]  # a pair never asked about is not there
    record = found[(k.HOST_A, D28)]
    assert record.lookup == lookup
    assert record.sightings == (a, b)
    assert store.by_address(found)[k.HOST_A][D28] == record


async def test_a_complete_lookup_replaces_the_day_and_an_incomplete_one_keeps_the_sightings(
    app_engine: AsyncEngine,
) -> None:
    first = kit.sighting("user01", hours=(9,))
    async with app_engine.begin() as conn:
        await store.save(conn, [m.Lookup(k.HOST_A, D28, LOOKED, True, 1, 0)], [first])
    second = kit.sighting("user02", hours=(15,))
    async with app_engine.begin() as conn:
        await store.save(conn, [m.Lookup(k.HOST_A, D28, LOOKED, True, 1, 0)], [second])
    async with app_engine.connect() as conn:
        (record,) = (await store.records(conn, [k.HOST_A], D28, D28)).values()
    assert [s.user for s in record.sightings] == ["user02"]
    later = LOOKED + timedelta(hours=1)
    async with app_engine.begin() as conn:
        await store.save(conn, [m.Lookup(k.HOST_A, D28, later, False, 0, 0, m.FAILED)], [])
    async with app_engine.connect() as conn:
        (record,) = (await store.records(conn, [k.HOST_A], D28, D28)).values()
    assert [s.user for s in record.sightings] == ["user02"]
    assert record.lookup == m.Lookup(k.HOST_A, D28, later, False, 0, 0, m.FAILED)


async def test_an_address_looked_up_with_no_sign_in_is_a_lookup_and_no_sighting(
    app_engine: AsyncEngine,
) -> None:
    async with app_engine.begin() as conn:
        await store.save(conn, [m.Lookup(k.HOST_A, D28, LOOKED, True, 0, 0)], [])
    async with app_engine.connect() as conn:
        (record,) = (await store.records(conn, [k.HOST_A], D28, D28)).values()
    assert record.sightings == ()
    assert record.lookup is not None
    assert record.lookup.accounts == 0


async def test_prune_removes_what_is_older_than_keep_days_and_nothing_else(
    app_engine: AsyncEngine,
) -> None:
    old, new = date(2026, 4, 1), date(2026, 10, 1)
    async with app_engine.begin() as conn:
        for day in (old, new):
            await store.save(
                conn,
                [m.Lookup(k.HOST_A, day, LOOKED, True, 1, 0)],
                [kit.sighting("user01", day=day, address=k.HOST_A)],
            )
        removed = await store.prune(conn, date(2026, 10, 29), 180)
    assert removed == 1
    async with app_engine.connect() as conn:
        left = await store.records(conn, [k.HOST_A], date(2026, 1, 1), date(2026, 12, 31))
    assert list(left) == [(k.HOST_A, new)]


async def test_counts_say_how_much_is_stored_without_a_name(app_engine: AsyncEngine) -> None:
    async with app_engine.begin() as conn:
        await store.save(
            conn,
            [
                m.Lookup(k.HOST_A, D28, LOOKED, True, 1, 0),
                m.Lookup(k.HOST_B, D28, LOOKED, False, 0, 0, m.GONE),
            ],
            [kit.sighting("user01", address=k.HOST_A)],
        )
        got = await store.counts(conn)
    assert got == {"sightings": 1, "addresses": 2, "lookups": 2, "incomplete": 1}


def test_only_ipv4_addresses_are_kept_canonical_and_in_numeric_order() -> None:
    mixed = ["10.1.10.1", "10.1.2.9", "fe80::1", "not an address", "10.1.2.9", "::ffff:10.1.2.9"]
    got = store.ipv4(mixed)
    assert got[:2] == ["10.1.2.9", "10.1.10.1"]
    assert all(ipaddress.ip_address(a).version == 4 for a in got)
    assert len(got) == len(set(got))


async def test_the_wants_are_the_source_side_devices_of_the_investigations_keys(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """D-226: a campus server that was only the destination of outside traffic, an address that is
    only among the entities, a public address and a campus resolver are not devices."""
    device = await investigation(
        migrated_engine, rule="r", actor=(("source.ip", "10.1.2.3"), ("destination.ip", "8.8.8.8")),
        entities=(("ip", "10.9.9.9"), ("ip", "fd00::1")),
    )  # fmt: skip
    attacked = await investigation(
        migrated_engine, rule="r2", actor=(("source.ip", "203.0.113.9"),
                                           ("destination.ip", "10.1.2.7")),
        entities=(("ip", "10.1.2.7"),),
    )  # fmt: skip
    resolver = await investigation(
        migrated_engine, rule="r3", actor=(("source.ip", "10.53.0.2"),), entities=()
    )
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t"),
            {"t": datetime(2026, 10, 28, 13, 0, tzinfo=UTC)},
        )
    async with app_engine.connect() as conn:
        found = await store.wants(
            conn, k.CLASSIFIER, (ipaddress.ip_network("10.53.0.0/24"),),
            datetime(2000, 1, 1, tzinfo=UTC),
        )  # fmt: skip
    assert {w.address for w in found} == {"10.1.2.3"}
    assert {attacked, device, resolver}  # all three were read


async def test_the_ranks_are_case_member_then_raised_then_the_rest(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    invs = await k.world(migrated_engine)
    await open_case(app_engine, people["asha"], [invs["b"]], host=k.HOST_B, servers=())
    plain = await make(
        migrated_engine, when=datetime(2026, 10, 28, 8, 0, tzinfo=UTC), host="10.1.2.9",
        flags=(), severity="low",
    )  # fmt: skip
    high = await make(
        migrated_engine, when=datetime(2026, 10, 28, 8, 0, tzinfo=UTC), host="10.1.2.10",
        flags=(), severity="high",
    )  # fmt: skip
    async with app_engine.connect() as conn:
        found = await store.recent(conn, datetime(2026, 10, 25, tzinfo=UTC), 100)
        wants = await store.wants(conn, k.CLASSIFIER, (), datetime(2026, 10, 25, tzinfo=UTC))
    tier = {w.address: w.tier for w in wants}
    assert tier[k.HOST_B] is Tier.CASE
    assert tier[k.HOST_A] is Tier.RAISED  # flags from its evidence
    assert tier["10.1.2.10"] is Tier.RAISED  # rated high
    assert tier["10.1.2.9"] is Tier.REST
    assert tier[k.HOST_C] is Tier.REST
    assert {i.id for i in found} >= {invs["a"], invs["b"], plain, high}
    assert all(w.first_alert <= w.last_alert for w in wants)


async def test_an_investigation_outside_the_days_asked_is_not_read(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    async with app_engine.connect() as conn:
        assert await store.wants(conn, k.CLASSIFIER, (), datetime(2026, 10, 29, tzinfo=UTC)) == []
