"""The accounts in the incident report through ``/api/v1`` (AR6, D-216): the report a pass writes
from the stored sightings names the accounts that signed in from the case's devices; an account that
may read the logs sees them and the accounts CSV, one that may not gets the state and the count and
a refusal for the file; a new account makes a new version of the report and more sign-ins of the
same account do not."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases.model import Indicator
from argus.config.settings import Settings, SigninsSettings
from argus.incident import gather, run
from argus.signins import attribute, store
from argus.signins import model as m
from tests.integration.incident import kit as ikit
from tests.integration.web.b3_support import V1, World, make_world, sign_in
from tests.integration.web.test_signins_ar6 import NAME, OTHER
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
HOST = "10.0.0.1"
CLASSIFIER = IpClassifier(None, ())


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Any
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


def settings() -> Settings:
    return Settings(signins=SigninsSettings(enabled=True))


async def a_case(world: World) -> uuid.UUID:
    """A case over the investigation whose grouping key names HOST as its source (the third of the
    seeded world): HOST is its one device (D-226)."""
    case = await world.open_case(
        1, title="Regular beaconing from 10.0.0.1", start=2,
        indicators=(Indicator("ip", HOST, "actor"),),
    )  # fmt: skip
    for inv in world.investigations[2:3]:
        await ikit.propose(world.owner, inv)
    return case


async def stored(world: World, users: tuple[str, ...], events: int = 6) -> None:
    """Sightings of ``users`` from HOST on every day the case's alerts touch, with their lookups."""
    first = last = None
    async with world.runtime.connect() as conn:
        from sqlalchemy import text

        row = (
            await conn.execute(
                text(
                    "SELECT min(i.first_event_at) AS f, max(i.last_event_at) AS l"
                    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
                )
            )
        ).one()
        first, last = row.f, row.l
    start, end = attribute.window_of(first, last, m.Rules().pad)
    looks, seen = [], []
    for day in attribute.window_days(start, end):
        looks.append(m.Lookup(HOST, day, m.day_end(day) + timedelta(days=1), True, len(users), 0))
        for user in users:
            seen.append(
                kit.sighting(user, address=HOST, day=day, hours=tuple(range(24)), events=events)
            )
    async with world.runtime.begin() as conn:
        await store.save(conn, looks, seen)


async def write(world: World, case: uuid.UUID) -> tuple[int, bool]:
    now = datetime.now(UTC)
    ctx = run.context_for(settings(), now, CLASSIFIER)
    async with world.runtime.connect() as conn:
        signal = (await gather.signals(conn, [case]))[case]
    made = await run.make(world.runtime, case, ctx)
    assert made is not None
    stored_, new = await run.write(world.runtime, made, run.key_of(signal, ctx), now)
    assert stored_ is not None
    return stored_.version, new


async def signal(world: World, case: uuid.UUID) -> str:
    async with world.runtime.connect() as conn:
        return (await gather.signals(conn, [case]))[case].text


async def report_of(http: Any, case: uuid.UUID) -> dict[str, Any]:
    return (await http.get(f"{V1}/cases/{case}/report")).json()  # type: ignore[no-any-return]


async def test_the_report_names_the_accounts_to_an_account_that_may_read_the_logs(
    world: World,
) -> None:
    case = await a_case(world)
    await stored(world, (NAME,))
    assert await write(world, case) == (1, True)
    async with world.app() as http:
        await sign_in(http, "mina")
        got = await report_of(http, case)
        csv = await http.get(f"{V1}/cases/{case}/report/files/affected-accounts.csv")
    (device,) = got["report"]["users"]["devices"]
    assert (device["device"], device["state"]) == (HOST, "likely")
    assert device["accounts"][0]["name"] == NAME
    assert got["report"]["users"]["lead"] == attribute.LEAD
    kinds = [f["kind"] for f in got["files"]]
    assert kinds == ["pdf", "indicators_csv", "affected_csv", "accounts_csv"]
    assert all(f["available"] for f in got["files"])
    assert csv.status_code == 200
    assert NAME in csv.text
    assert 'filename="ACME-IR-' in csv.headers["content-disposition"]
    assert csv.headers["content-disposition"].endswith('_affected_accounts.csv"')


async def test_an_account_without_log_access_gets_the_state_and_no_name_and_no_file(
    world: World,
) -> None:
    case = await a_case(world)
    await stored(world, (NAME, OTHER))
    await write(world, case)
    async with world.app() as http:
        await sign_in(http, "sven")  # may review and manage cases, not read the logs
        response = await http.get(f"{V1}/cases/{case}/report")
        refused = await http.get(f"{V1}/cases/{case}/report/files/affected-accounts.csv")
        pdf = await http.get(f"{V1}/cases/{case}/report/files/report.pdf")
        await sign_in(http, "vera")
        viewer = await http.get(f"{V1}/cases/{case}/report")
    for answer in (response, viewer):
        assert NAME not in answer.text
        assert OTHER not in answer.text
        body = answer.json()
        (device,) = body["report"]["users"]["devices"]
        assert device["state"] == "possible"
        assert device["account_count"] == 2
        assert device["accounts"] == []
        assert body["report"]["users"]["signins"] == []
        assert device["sentence"]["text"] == "Hidden: needs log access in ELK."
        accounts_file = next(f for f in body["files"] if f["kind"] == "accounts_csv")
        assert accounts_file["available"] is False
    assert refused.status_code == 403
    assert NAME not in refused.text
    assert pdf.status_code == 403


async def test_a_new_account_makes_a_new_version_and_more_sign_ins_of_the_same_do_not(
    world: World,
) -> None:
    case = await a_case(world)
    assert await write(world, case) == (1, True)  # nothing looked up yet
    before = await signal(world, case)
    await stored(world, (NAME,), events=6)
    first = await signal(world, case)
    assert first != before
    assert await write(world, case) == (2, True)
    await stored(world, (NAME,), events=30)  # the same account signed in more
    assert await signal(world, case) == first  # the report is not read again for that
    await stored(world, (NAME, OTHER), events=30)  # a second account
    assert await signal(world, case) != first
    assert await write(world, case) == (3, True)
    again = await write(world, case)
    assert again == (3, False)  # the same evidence is the same version


async def test_a_case_without_the_feature_is_the_report_it_always_was(world: World) -> None:
    case = await a_case(world)
    await stored(world, (NAME,))
    now = datetime.now(UTC)
    ctx = run.context_for(Settings(), now, CLASSIFIER)  # signins.enabled is off
    made = await run.make(world.runtime, case, ctx)
    assert made is not None
    assert made.report.users.devices == ()
    assert NAME not in made.report.model_dump_json()
    async with world.runtime.connect() as conn:
        before = (await gather.signals(conn, [case]))[case].text
    assert "user" not in before  # the signal holds a hash, never a name
    assert NAME not in before


async def test_an_actor_address_that_is_not_a_plain_ipv4_never_fails_the_signal(
    world: World,
) -> None:
    """The signal reads the case's actor addresses as inet: a value that is not one (IPv6, an
    out-of-range octet) is passed over, and the report of the case is still read."""
    case = await world.open_case(
        2,
        title="Odd actors",
        indicators=(
            Indicator("ip", "2001:db8::7", "actor"),
            Indicator("ip", "999.9.9.9", "actor"),
            Indicator("ip", "10.0.0.1", "actor"),
        ),
    )
    await stored(world, (NAME,))
    text_ = await signal(world, case)
    assert text_
    assert NAME not in text_
