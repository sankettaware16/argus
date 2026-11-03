"""Who a device is and over which alerts it is read (AR6 review, D-226), against the real database:
a case's devices are the sources of its members' alerts, never a server that was only probed, and
each device is attributed over its own investigations' alerts, never the whole case's span. The
page's card, ``argus signins show`` and the incident report read it one way."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.incident import run as incident_run
from argus.signins import model as m
from argus.signins import store, view
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.knownkit import make, open_case
from tests.integration.signins import kit as k
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
READING = view.Reading(m.Rules(), k.CLASSIFIER, (), True)
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
SERVER = "10.1.2.7"
SCANNER = "203.0.113.9"


async def stamp(owner: AsyncEngine, inv: uuid.UUID, first: datetime, last: datetime) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :f, last_event_at = :l WHERE id = :i"),
            {"f": first, "l": last, "i": inv},
        )


async def looked(
    engine: AsyncEngine, address: str, days: list[date], who: dict[date, str] | None = None
) -> None:
    """Complete lookups of ``address`` on ``days``; ``who``: the account that signed in that day."""
    lookups = [
        m.Lookup(address, d, m.day_end(d) + timedelta(hours=5), True, int(d in (who or {})), 0)
        for d in days
    ]
    seen = [
        kit.sighting(user, address=address, day=d, hours=tuple(range(24)), events=48)
        for d, user in (who or {}).items()
    ]
    async with engine.begin() as conn:
        await store.save(conn, lookups, seen)


async def test_a_device_is_attributed_over_its_own_alerts_not_the_whole_cases_span(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """X alerted on the 28th and nobody signed in from it then; an account signed in on the 30th,
    after Y alerted. Over the case's whole span X read "likely: that account"."""
    on28 = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
    on30 = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)
    x = await make(migrated_engine, when=on28, host=k.HOST_A, flags=())
    y = await make(migrated_engine, when=on30, host=k.HOST_B, flags=())
    case = await open_case(app_engine, people["asha"], [x, y], host=k.HOST_A, servers=())
    days = [date(2026, 10, 28), date(2026, 10, 29), date(2026, 10, 30)]
    await looked(app_engine, k.HOST_A, days, {date(2026, 10, 30): "user-late"})
    await looked(app_engine, k.HOST_B, days, {date(2026, 10, 30): "user-y"})
    async with app_engine.connect() as conn:
        users = await view.for_case(conn, READING, case, NOW)
    by = {a.address: a for a in users.attributions}
    assert by[k.HOST_A].state == "none_seen"  # its own window: 28 Oct 08:00 to 12:00
    assert [a.user for a in by[k.HOST_B].accounts] == ["user-y"]
    assert by[k.HOST_B].state == "likely"
    assert not any(e.user == "user-late" for e in users.entries)  # nor in the timeline


async def test_a_device_in_two_investigations_is_read_over_both_and_not_a_third(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    a = await make(migrated_engine, when=datetime(2026, 10, 27, 10, 0, tzinfo=UTC), host=k.HOST_A)
    b = await make(migrated_engine, when=datetime(2026, 10, 28, 10, 0, tzinfo=UTC), host=k.HOST_A)
    c = await make(migrated_engine, when=datetime(2026, 10, 30, 10, 0, tzinfo=UTC), host=k.HOST_B)
    case = await open_case(app_engine, people["asha"], [a, b, c], host=k.HOST_A, servers=())
    async with app_engine.connect() as conn:
        spans = await view.spans_of_case(conn, READING, case)
    assert spans[k.HOST_A] == (
        datetime(2026, 10, 27, 10, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC),
    )  # fmt: skip
    assert spans[k.HOST_B] == (
        datetime(2026, 10, 30, 10, 0, tzinfo=UTC), datetime(2026, 10, 30, 10, 0, tzinfo=UTC),
    )  # fmt: skip


async def test_a_server_that_was_only_probed_is_no_device_for_the_card_or_the_report(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The scanner is the source; the campus server is the destination (and the case's "actor"
    indicator, as the opener reads a key). Only the infected host's own key names a device."""
    when = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)
    probed = await investigation(
        migrated_engine, rule="scan",
        actor=(("source.ip", SCANNER), ("destination.ip", SERVER)), entities=(("ip", SERVER),),
    )  # fmt: skip
    infected = await make(migrated_engine, when=when, host=k.HOST_A, flags=())
    await stamp(migrated_engine, probed, when, when)
    case = await open_case(app_engine, people["asha"], [probed, infected], host=SERVER, servers=())
    async with app_engine.connect() as conn:
        users = await view.for_case(conn, READING, case, NOW)
        assert [a.address for a in users.attributions] == [k.HOST_A]
        assert users.devices_total == 1
        facts = SimpleNamespace(case=SimpleNamespace(id=case))
        ctx = SimpleNamespace(signins=READING, as_at=NOW)
        reported = await incident_run.users_of(conn, facts, ctx)  # type: ignore[arg-type]
    assert [a.address for a in reported.attributions] == [k.HOST_A]  # the report agrees


async def test_an_actor_a_person_added_is_a_device_over_the_whole_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    when = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)
    inv = await make(migrated_engine, when=when, host=k.HOST_A, flags=())
    case = await open_case(app_engine, people["asha"], [inv], host=k.HOST_A, servers=())
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_indicators (case_id, kind, value, role, source, added_version,"
                " added_by) VALUES (:c, 'ip', :v, 'actor', 'person', 1, 'test')"
            ),
            {"c": case, "v": k.HOST_C},
        )
    async with app_engine.connect() as conn:
        spans = await view.spans_of_case(conn, READING, case)
    assert sorted(spans) == [k.HOST_A, k.HOST_C]
    assert spans[k.HOST_C] == spans[k.HOST_A]


async def test_the_pass_asks_for_the_sources_and_not_for_the_probed_server(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """A scanner probing 100 campus servers would have been 100 address-days of SSO lookups each."""
    when = datetime(2026, 10, 28, 13, 0, tzinfo=UTC)
    for n in range(5):
        probed = await investigation(
            migrated_engine, rule=f"scan{n}",
            actor=(("source.ip", SCANNER), ("destination.ip", f"10.1.9.{n}")),
        )  # fmt: skip
        await stamp(migrated_engine, probed, when, when)
    infected = await make(migrated_engine, when=when, host=k.HOST_A, flags=())
    assert infected
    wire = k.Wire(k.reply())
    from tests.integration.signins.test_pass import go

    report = await go(app_engine, wire)
    (body,) = wire.asked()
    assert body["query"]["bool"]["filter"][0]["terms"]["source.ip"] == [k.HOST_A]
    assert report.addresses == 1
