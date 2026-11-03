"""A case's ready block list (AR4b, D-169 point 5) against the database: the case's outside
addresses and names with the evidence ARGUS holds, the registered parent of its names, nothing in
shared infrastructure, and the exports (CSV, plain text)."""

from __future__ import annotations

import csv
import io
import ipaddress

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import blocklist
from argus.cases.machine import Link, RecordBlock
from argus.cases.membership import Shared
from argus.cases.model import Indicator
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import HOST, at, make, notify, open_case

pytestmark = pytest.mark.integration
SERVER = "185.1.1.1"
CDN = "104.16.0.5"
SHARED = Shared(networks=(ipaddress.ip_network("104.16.0.0/12"),))


async def put_answer(owner: AsyncEngine, kind: str, value: str, answer: dict[str, object]) -> None:
    import json

    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO outside_lookups (source, kind, indicator, status, answer,"
                " answer_bytes, fetched_at) VALUES ('virustotal', :k, :v, 'found',"
                " CAST(:a AS jsonb), 10, :t)"
            ),
            {"k": kind, "v": value, "a": json.dumps(answer), "t": at(2)},
        )


async def world(app: AsyncEngine, owner: AsyncEngine, people: dict[str, Person]) -> object:
    first = await make(
        owner, when=at(0, 10), servers=(SERVER, CDN),
        extra=(("domain", "a.bad-domain.com"), ("domain", "b.bad-domain.com")),
    )  # fmt: skip
    later = await make(owner, when=at(1, 10), servers=(SERVER,),
                       extra=(("domain", "a.bad-domain.com"),))  # fmt: skip
    case = await open_case(app, people["asha"], [first, later], servers=(SERVER,))
    async with app.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((), (Indicator("domain", "a.bad-domain.com", "c2"),
                      Indicator("domain", "b.bad-domain.com", "c2"),
                      Indicator("ip", CDN, "c2"))),
            expected_version=None,
        )  # fmt: skip
    await put_answer(owner, "domain", "bad-domain.com",
                     {"malicious": 5, "engines": 95, "created": "2026-09-21"})  # fmt: skip
    await put_answer(owner, "ip", SERVER, {"malicious": 7, "engines": 94, "owner": "Shady Hosting"})
    return case


async def test_the_list_holds_the_parent_the_names_and_the_servers_with_their_evidence(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await world(app_engine, migrated_engine, people)
    async with app_engine.connect() as conn:
        listing = await blocklist.build(conn, case, SHARED)  # type: ignore[arg-type]
    assert listing is not None
    got = [(e.type, e.value) for e in listing.entries]
    assert got == [
        ("family", "bad-domain.com"),
        ("domain", "a.bad-domain.com"),
        ("domain", "b.bad-domain.com"),
        ("address", SERVER),
    ]  # fmt: skip
    assert listing.skipped == 1  # the content-delivery address is left out, and said so
    assert HOST not in {e.value for e in listing.entries}  # a campus device is no block
    family, _, _, server = listing.entries
    assert (family.flagging, family.engines, family.registered) == (5, 95, "2026-09-21")
    assert family.evidence == "5 of 95 engines flag it"
    assert (server.flagging, server.engines, server.owner) == (7, 94, "Shady Hosting")
    assert family.first_seen == at(0, 10)  # first seen on campus, by the case's investigations
    assert server.first_seen == at(0, 10)
    assert family.devices == 1
    assert listing.entries[1].evidence == "no outside record yet"  # nothing is made up for a name


async def test_the_csv_is_one_row_for_each_thing_and_safe_for_a_spreadsheet(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await world(app_engine, migrated_engine, people)
    async with app_engine.connect() as conn:
        listing = await blocklist.build(conn, case, SHARED)  # type: ignore[arg-type]
    assert listing is not None
    made = blocklist.to_csv(listing, bom=True)
    assert made.startswith(blocklist.BOM)  # a spreadsheet reads UTF-8 only with it
    assert made.encode("utf-8").startswith(b"\xef\xbb\xbf")
    assert not blocklist.to_csv(listing).startswith(blocklist.BOM)  # the terminal's copy has none
    rows = list(csv.reader(io.StringIO(made.removeprefix(blocklist.BOM))))
    assert rows[0] == list(blocklist.COLUMNS)
    assert [r[0] for r in rows[1:]] == ["family", "domain", "domain", "address"]
    assert rows[1][1:4] == ["bad-domain.com", "registered domain (every name under it)", "5"]
    assert rows[4][5] == "Shady Hosting"
    # a name that would be read as a formula is quoted
    hostile = blocklist.Blocklist(
        1, "t", (blocklist.Entry("domain", "=cmd|' /C calc'!A0", owner="+x"),)
    )
    cells = list(
        csv.reader(io.StringIO(blocklist.to_csv(hostile, bom=True).removeprefix(blocklist.BOM)))
    )[1]
    assert cells[1].startswith("'=")
    assert cells[5].startswith("'+")


async def test_the_email_says_what_happened_and_what_to_block(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await world(app_engine, migrated_engine, people)
    await notify(app_engine, people["asha"], case, at(3, 9))
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["ravi"].actor(), case, RecordBlock("network team", "DNS", at(4, 9)),
            expected_version=None,
        )  # fmt: skip
    async with app_engine.connect() as conn:
        listing = await blocklist.build(conn, case, SHARED)  # type: ignore[arg-type]
    assert listing is not None
    body = blocklist.to_text(listing)
    assert body.startswith("Subject: Please block these at the network (ARGUS case ")
    assert "To the head of cybersecurity," in body
    assert "The owners were told on " in body
    assert "A block was recorded on " in body
    assert "Registered domains (block every name under them):" in body
    assert "  bad-domain.com  (5 of 95 engines flag it; registered 2026-09-21; first seen" in body
    assert "  185.1.1.1  (7 of 94 engines flag it; network: Shady Hosting; first seen" in body
    assert "Left out: 1 shared address(es) or name(s)" in body
    assert body.endswith("ARGUS (the first-line analyst of the ACME)\n")


async def test_a_case_with_nothing_to_block_has_an_empty_list_and_a_missing_case_none(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    import uuid

    only = await make(migrated_engine, when=at(0, 10), servers=())
    case = await open_case(app_engine, people["asha"], [only], servers=())
    async with app_engine.connect() as conn:
        listing = await blocklist.build(conn, case, SHARED)
        assert listing is not None
        assert listing.entries == ()
        assert "Registered domains" not in blocklist.to_text(listing)
        assert await blocklist.build(conn, uuid.uuid4(), SHARED) is None
