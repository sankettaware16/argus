"""UI v2's finding routes through ``/api/v1`` (spec §2.3, §9, §10, §11): an entity's page (A11),
the one search box (A12) and the incident reports list (A13), on the web's own database login.

What they are held to: they read ARGUS's own records only, each list is cut and says how many there
are in all, an account's page needs ``see_logs`` (it names a person) and a device's page gives the
accounts behind its address as counts without it, and a value ARGUS has no record of answers with
empty lists, never an error."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.cases.model import Indicator
from argus.web import lookups
from tests.integration.grouping.test_grouping import doc, ingest
from tests.integration.web.b3_support import V1, World, make_world, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def an_address(world: World) -> str:
    rows = await world.rows(
        "SELECT value FROM investigation_entities WHERE kind = 'ip' AND investigation_id = :i",
        i=world.investigations[4],
    )
    assert rows
    return str(rows[0].value)


async def sightings(world: World, address: str, days: dict[int, list[str]]) -> None:
    """SSO sign-ins seen from the address (made-up names), ``days`` back from today."""
    today = datetime.now(UTC).date()
    async with world.owner.begin() as conn:
        for back, names in days.items():
            for name in names:
                await conn.execute(
                    text(
                        "INSERT INTO signin_sightings (address, day, user_name, first_at,"
                        " last_at, events, successes, failures, hours, user_agents, written_at)"
                        " VALUES (CAST(:a AS inet), :d, :u, now(), now(), 1, 1, 0, '{9}',"
                        " '[]'::jsonb, now())"
                    ),
                    {"a": address, "d": today - timedelta(days=back), "u": name},
                )


async def test_a_device_page_says_what_argus_knows_and_holds(world: World) -> None:
    address = await an_address(world)
    case = await world.open_suspected(4, f"Likely beaconing from {address}")
    await sightings(world, address, {0: ["asha.k"], 1: ["ravi.m"]})
    async with world.app() as http:
        await sign_in(http, "mina")
        got = await http.get(f"{V1}/entities/device/{address}")
        assert got.status_code == 200, got.text
        page = got.json()
        assert (page["noun"], page["stored_kind"]) == ("Device", "ip")
        assert page["history_days"] >= 1
        assert str(case) in {c["id"] for c in page["incidents"]}
        assert page["incidents_total"] >= 1
        assert page["open_incidents"] >= 1
        assert page["alert_groups_total"] >= 1
        assert len(page["alert_groups"]) <= lookups.PAGE_ROWS
        assert page["timeline"]
        assert page["timeline"][0]["alerts"] >= 1
        assert page["dynamic"] is None  # a different person each day alone cannot tell
        assert page["shared_by"] == 1
        assert all(d["hosts"] == [] for d in page["days"])  # no host name in its groups
        names = {n for d in page["days"] for n in (d["account_names"] or [])}
        assert names == {"asha.k", "ravi.m"}
    async with world.app() as http:  # without log access: counts, no names
        await sign_in(http, "sven")
        page = (await http.get(f"{V1}/entities/device/{address}")).json()
        assert all(d["account_names"] is None for d in page["days"])
        assert sum(d["accounts"] or 0 for d in page["days"]) == 2


async def test_shared_is_not_dynamic(world: World) -> None:
    address = await an_address(world)
    await sightings(world, address, {0: ["asha.k", "ravi.m"], 1: ["asha.k", "ravi.m"]})
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/entities/device/{address}")).json()
    assert (page["dynamic"], page["shared_by"]) == (False, 2)


NUMBERS = itertools.count(1000)  # alert ids of the groups a test adds (the seed's are below)


def group_day(back: int) -> str:
    """The site's day of an alert group made ``back`` days ago (its bucket's day)."""
    at = datetime.now(UTC) - timedelta(days=back, minutes=5)
    return str(at.astimezone(site.zone()).date())


async def groups_on(
    world: World, address: str, days: dict[int, list[tuple[str, ...]]], *, user: str | None = None
) -> None:
    """Alert groups of the address through the real store and grouper, ``days`` back from now:
    one group per tuple (its own rule), naming those host names (and ``user``)."""
    now = datetime.now(UTC)
    docs = []
    for back, groups in days.items():
        for hosts in groups:
            n = next(NUMBERS)
            d = doc(n, f"rule-host-{n}", address, now - timedelta(days=back, minutes=5))
            if hosts:
                d["_source"]["host"] = {"name": list(hosts) if len(hosts) > 1 else hosts[0]}
            if user is not None:
                d["_source"]["user"] = {"name": user}
            docs.append(d)
    await ingest(world.runtime, docs, now)


async def page_of(world: World, address: str, user: str = "mina") -> dict[str, Any]:
    async with world.app() as http:
        await sign_in(http, user)
        got = await http.get(f"{V1}/entities/device/{address}")
    assert got.status_code == 200, got.text
    page: dict[str, Any] = got.json()
    return page


async def test_a_lab_pc_with_rotating_students_is_not_called_dynamic(world: World) -> None:
    address = "10.0.9.17"
    await sightings(world, address, {0: ["s1", "s2"], 1: ["s1", "s3"]})
    page = await page_of(world, address)
    assert (page["dynamic"], page["shared_by"]) == (False, 2)  # s1 both days: the same PC
    await sightings(world, address, {2: ["s4"]})  # a day with nobody in common
    assert (await page_of(world, address))["dynamic"] is None  # sign-ins alone cannot tell
    await groups_on(world, address, {0: [("lab-pc-17",)], 2: [("lab-pc-17",)]})
    page = await page_of(world, address)
    assert page["dynamic"] is False  # one host name every day: one machine
    by_day = {d["day"]: d for d in page["days"]}
    assert by_day[group_day(0)]["hosts"] == ["lab-pc-17"]
    assert by_day[group_day(2)]["hosts"] == ["lab-pc-17"]
    assert all(d["hosts"] == [] for d in page["days"] if d["alert_groups"] == 0)


async def test_a_dynamic_address_is_told_by_its_host_names_day_by_day(world: World) -> None:
    address = "10.0.9.18"
    await groups_on(world, address, {0: [("hostel-laptop-a",), ("hostel-laptop-a",)],
                                     1: [("hostel-laptop-b",)], 3: [(), ("a", "b")]})  # fmt: skip
    await sightings(world, address, {0: ["asha.k"], 1: ["asha.k"]})  # a person, two devices
    page = await page_of(world, address, "sven")
    assert page["dynamic"] is True
    hosts = {d["day"]: d["hosts"] for d in page["days"]}
    assert hosts[group_day(0)] == ["hostel-laptop-a"]
    assert hosts[group_day(1)] == ["hostel-laptop-b"]
    assert hosts[group_day(3)] == []  # no host, or more than one: unknown
    groups = {d["day"]: d["alert_groups"] for d in page["days"]}
    assert (groups[group_day(0)], groups[group_day(3)]) == (2, 2)
    assert all(d["account_names"] is None for d in page["days"])  # no see_logs
    other = "10.0.9.19"  # one group naming two hosts tells nothing about the address's device
    await groups_on(world, other, {0: [("pc-a", "pc-b")], 1: [("pc-c", "pc-d")]})
    assert (await page_of(world, other))["dynamic"] is None


async def test_an_account_page_needs_log_access_and_unknown_values_are_empty(
    world: World,
) -> None:
    async with world.app() as http:
        await sign_in(http, "sven")  # no see_logs
        refused = await http.get(f"{V1}/entities/account/asha.k")
        assert refused.status_code == 403
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/entities/account/asha.k")).json()
        assert (page["noun"], page["stored_kind"], page["incidents"]) == ("Account", "user", [])
        assert page["dynamic"] is None
        assert page["reputation"] == []
        outside = (await http.get(f"{V1}/entities/outside/203.0.113.40")).json()
        assert (outside["noun"], outside["address_class"]) == ("Outside address", "special")
        site = (await http.get(f"{V1}/entities/site/www.dept.example.ac.in")).json()
        assert site["stored_kind"] == "domain"
        for bad in ("device/a%00b", "planet/x", "device/" + "a" * 513):
            assert (await http.get(f"{V1}/entities/{bad}")).status_code in (404, 422), bad


async def test_search_guesses_and_groups(world: World) -> None:
    address = await an_address(world)
    case = await world.open_case(
        1,
        start=6,
        title="Beaconing to an outside server",
        indicators=(Indicator("ip", "203.0.113.40", "actor"),),
    )
    number = (await world.rows("SELECT number FROM cases WHERE id = :c", c=case))[0].number
    async with world.app() as http:
        await sign_in(http, "vera")
        by_number = (await http.get(f"{V1}/search", params={"q": f"#{number}"})).json()
        assert by_number["guess"] == "number"
        assert [c["id"] for c in by_number["incidents"]] == [str(case)]
        outside = (await http.get(f"{V1}/search", params={"q": "203.0.113.40"})).json()
        assert (outside["guess"], outside["entity"]["noun"]) == (
            "outside_address", "Outside address")  # fmt: skip
        assert str(case) in {c["id"] for c in outside["incidents"]}
        device = (await http.get(f"{V1}/search", params={"q": address})).json()
        assert device["guess"] == "device_address"
        assert device["entity"]["noun"] == "Device"
        assert len(device["alert_groups"]) <= lookups.SEARCH_ROWS
        assert device["alert_groups_total"] >= len(device["alert_groups"])
        words = (await http.get(f"{V1}/search", params={"q": "outside server"})).json()
        assert words["guess"] == "words"
        assert str(case) in {c["id"] for c in words["incidents"]}
        rule = (await http.get(f"{V1}/search", params={"q": "Remote-Admin"})).json()
        assert (rule["guess"], rule["entity"]) == ("name", None)  # no such host: words
        assert rule["alert_groups_total"] >= 1
        assert rule["alert_groups"][0]["rule_name"]
        nothing = (await http.get(f"{V1}/search", params={"q": "nothing like this"})).json()
        assert (nothing["incidents"], nothing["alert_groups"]) == ([], [])
        ir = (await http.get(f"{V1}/search", params={"q": "IR-2026-1104-01"})).json()
        assert ir["guess"] == "ir"
        for bad in ("", "   ", "a\x00b", "x" * 201):
            assert (await http.get(f"{V1}/search", params={"q": bad})).status_code == 422


async def test_search_names_an_account_only_to_who_may_open_its_page(world: World) -> None:
    await groups_on(world, "10.0.9.20", {0: [()]}, user="asha.k")
    async with world.app() as http:
        await sign_in(http, "sven")  # no see_logs: an account's page answers 403
        hidden = (await http.get(f"{V1}/search", params={"q": "asha.k"})).json()
        assert (hidden["guess"], hidden["entity"]) == ("name", None)
        assert (hidden["alert_groups"], hidden["alert_groups_total"]) == ([], 0)
        assert (await http.get(f"{V1}/entities/account/asha.k")).status_code == 403
    async with world.app() as http:
        await sign_in(http, "mina")
        shown = (await http.get(f"{V1}/search", params={"q": "asha.k"})).json()
        assert shown["entity"] == {"kind": "account", "value": "asha.k", "noun": "Account"}
        assert shown["alert_groups_total"] == 1
        assert (await http.get(f"{V1}/entities/account/asha.k")).status_code == 200


def test_the_guess_follows_the_spec() -> None:
    assert lookups.guess("#31", None)[0] == "number"
    assert lookups.guess("31", None)[0] == "number"
    assert lookups.guess("SOC-IR-2026-1104-01", None)[0] == "ir"
    assert lookups.guess("IR-7", None)[0] == "ir"
    assert lookups.guess("10.0.12.17", None)[0] == "device_address"
    assert lookups.guess("www.dept.example.ac.in", None)[0] == "domain"
    assert lookups.guess("lab-pc-17", None)[0] == "name"
    assert lookups.guess(".env scan", None)[0] == "words"


async def test_incident_reports_list_confirmed_incidents_newest_first(world: World) -> None:
    from tests.integration.web.test_incident_report_ar7 import a_case, write_report

    async with world.app() as http:
        await sign_in(http, "vera")
        empty = (await http.get(f"{V1}/incident-reports")).json()
        assert empty == {"items": [], "offset": 0, "limit": 50, "has_more": False}
    case = await a_case(world, 2)
    version = await write_report(world, case)
    possible = await world.open_suspected(4)
    await write_report(world, possible)  # a possible incident's report is not listed
    async with world.app() as http:
        await sign_in(http, "vera")
        listed = (await http.get(f"{V1}/incident-reports")).json()
        assert [r["case_id"] for r in listed["items"]] == [str(case)]
        row = listed["items"][0]
        assert row["version"] == version
        assert row["sent"] is None
        assert {f["kind"]: f["available"] for f in row["files"]}["pdf"] is False  # no see_logs
        found = (await http.get(f"{V1}/incident-reports", params={"q": "beaconing"})).json()
        assert len(found["items"]) == 1
        none = (await http.get(f"{V1}/incident-reports", params={"q": "no such"})).json()
        assert none["items"] == []
        paged = (await http.get(f"{V1}/incident-reports", params={"limit": 1, "offset": 1})).json()
        assert paged["items"] == []
        for bad in ({"limit": 0}, {"limit": 51}, {"offset": -1}):
            assert (await http.get(f"{V1}/incident-reports", params=bad)).status_code == 422
