"""Who used this device through ``/api/v1`` (AR6, D-216): an investigation's and a case's card with
the probable users for an account that may read the logs, and counts and no name for one that may
not (nowhere in the answer, not even in the timeline), the case timeline's sign-ins as context, and
a server with the feature off."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.signins import attribute, store, view
from argus.signins import model as m
from tests.integration.web.b3_support import V1, World, make_world, sign_in
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
NAME = "user-ar6-alpha"
OTHER = "user-ar6-beta"
READING = view.Reading(m.Rules(), IpClassifier(None, ()), (), True)


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Any
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def span(world: World, inv: uuid.UUID) -> tuple[list[str], datetime, datetime]:
    async with world.runtime.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT group_key, first_event_at, last_event_at FROM investigations"
                    " WHERE id = :i"
                ),
                {"i": inv},
            )
        ).one()
        found = store.devices_of({inv: row.group_key}, READING.classifier, ())
    return found[inv], row.first_event_at, row.last_event_at


async def sign_ins(
    world: World, inv: uuid.UUID, *, users: tuple[str, ...] = (NAME,), lookups: bool = True
) -> list[str]:
    """Sightings of ``users`` on the investigation's devices, in the hours of its alerts, with
    complete lookups for each day its window touches."""
    devices, first, last = await span(world, inv)
    start, end = attribute.window_of(first, last, READING.rules.pad)
    sightings: list[m.Sighting] = []
    looks: list[m.Lookup] = []
    for address in devices:
        for day in attribute.window_days(start, end):
            if lookups:
                looked = m.day_end(day) + timedelta(days=1)
                looks.append(m.Lookup(address, day, looked, True, len(users), 0))
            for user in users:
                hours = tuple(range(0, 24))
                sightings.append(kit.sighting(user, address=address, day=day, hours=hours))
    async with world.runtime.begin() as conn:
        await store.save(conn, looks, sightings)
    return devices


def everything(response: Any) -> str:
    return str(response.text)


async def test_an_account_with_log_access_sees_the_probable_user_of_a_device(world: World) -> None:
    inv = world.investigations[0]
    devices = await sign_ins(world, inv)
    async with world.app(signins=READING) as http:
        await sign_in(http, "mina")
        got = (await http.get(f"{V1}/investigations/{inv}")).json()
    card = got["signins"]
    assert card["enabled"] is True
    assert card["hidden"] is False
    assert card["lead"] == attribute.LEAD
    assert card["devices_total"] == len(devices)
    assert [s["state"] for s in card["states"]] == ["likely"]
    device = card["devices"][0]
    assert device["address"] in devices
    assert device["state"] == "likely"
    assert device["words"] == f"Probable user: {NAME}."
    (account,) = device["accounts"]
    assert account["user"] == NAME
    assert account["devices"] == ["Chrome on Windows"]
    assert account["events"] > 0
    assert account["successes"] > 0


async def test_an_account_without_log_access_gets_counts_and_no_name_anywhere(
    world: World,
) -> None:
    inv = world.investigations[0]
    await sign_ins(world, inv, users=(NAME, OTHER))
    async with world.app(signins=READING) as http:
        await sign_in(http, "sven")  # may review and manage cases, but not read the logs
        got = await http.get(f"{V1}/investigations/{inv}")
        vera = await sign_in(http, "vera")
        viewer = await http.get(f"{V1}/investigations/{inv}")
    assert vera
    for response in (got, viewer):
        assert response.status_code == 200
        assert NAME not in everything(response)
        assert OTHER not in everything(response)
        card = response.json()["signins"]
        assert card["hidden"] is True
        device = card["devices"][0]
        assert device["state"] == "possible"
        assert device["accounts"] == []
        assert device["hands"] == []
        assert device["failed_only"] == []
        assert device["account_count"] == 2
        assert (
            device["words"] == "2 accounts signed in from this address — hidden: needs log access."
        )


async def test_a_device_never_looked_up_is_unknown_and_says_why(world: World) -> None:
    inv = world.investigations[0]
    async with world.app(signins=READING) as http:
        await sign_in(http, "mina")
        card = (await http.get(f"{V1}/investigations/{inv}")).json()["signins"]
    device = card["devices"][0]
    assert device["state"] == "unknown"
    assert device["accounts"] == []
    assert device["gaps"][0]["why"] in {"not_looked", "logs_gone"}
    assert device["words"].startswith("Not known:")


async def test_a_server_without_the_feature_has_no_card(world: World) -> None:
    inv = world.investigations[0]
    async with world.app() as http:
        await sign_in(http, "mina")
        got = (await http.get(f"{V1}/investigations/{inv}")).json()
    assert got["signins"] is None


async def test_a_case_shows_the_card_and_the_sign_ins_on_its_timeline_as_context(
    world: World,
) -> None:
    case = await world.open_case(2)
    for inv in world.investigations[:2]:
        await sign_ins(world, inv)
    async with world.app(signins=READING) as http:
        await sign_in(http, "mina")
        got = (await http.get(f"{V1}/cases/{case}")).json()
    card = got["signins"]
    assert card["hidden"] is False
    assert card["devices"]
    assert all(d["accounts"][0]["user"] == NAME for d in card["devices"] if d["accounts"])
    entries = [i for i in got["timeline"] if i["kind"] == "signin"]
    assert entries
    assert all(
        NAME in i["text"] and "signed in" in i["text"] and " IST" in i["text"] for i in entries
    )
    assert [i["at"] for i in got["timeline"]] == sorted(i["at"] for i in got["timeline"])
    assert got["timeline_total"] >= len(entries)


async def test_the_case_of_an_account_without_log_access_has_no_name_and_no_sign_in_entry(
    world: World,
) -> None:
    case = await world.open_case(2)
    for inv in world.investigations[:2]:
        await sign_ins(world, inv, users=(NAME, OTHER))
    async with world.app(signins=READING) as http:
        await sign_in(http, "sven")
        response = await http.get(f"{V1}/cases/{case}")
    got = response.json()
    assert NAME not in everything(response)
    assert OTHER not in everything(response)
    assert got["signins"]["hidden"] is True
    assert got["logs_hidden"] is True
    assert [i for i in got["timeline"] if i["kind"] == "signin"] == []


def test_the_dates_of_the_window_are_utc_days() -> None:
    first = datetime.fromisoformat("2026-10-28T23:30:00+00:00")
    start, end = attribute.window_of(first, first, timedelta(hours=2))
    assert attribute.window_days(start, end) == (date(2026, 10, 28), date(2026, 10, 29))
