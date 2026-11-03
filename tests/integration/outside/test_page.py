"""AR3 (D-165) on the investigation page: "What ARGUS checked" says, in plain sentences, what
outside threat intel found about the investigation's external addresses (read from the cache by
the web's own login, which may read the answers and never the ledger, and cannot write either).
"""

from __future__ import annotations

import html
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.outside import store
from argus.outside.read import View
from argus.web import queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
DEST = "45.33.32.156"
BAD = {"malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 27, "engines": 94}
CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24, "engines": 94}


def flat(page: str) -> str:
    return " ".join(html.unescape(page).split())


async def seed_cache(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, ids: list[object]
) -> None:
    async with migrated_engine.begin() as conn:
        for inv in ids[:1]:
            await conn.execute(
                text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                     " VALUES (:i, 'ip', :v), (:i, 'ip', '45.33.32.157')"),
                {"i": inv, "v": DEST},
            )  # fmt: skip
    async with app_engine.begin() as conn:
        await store.put(conn, "virustotal", "ip", DEST, "found", BAD, 300, NOW)
        await store.put(conn, "virustotal", "ip", "45.33.32.157", "found", CLEAN, 300, NOW)
        await store.put(conn, "shodan", "ip", DEST, "found", {"ports": [22, 443]}, 200, NOW)
        await store.put(conn, "virustotal", "ip", "45.33.32.200", "found", BAD, 300, NOW)


async def test_the_investigation_page_says_what_outside_intel_found(
    client: httpx.AsyncClient,
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    async with seeded.connect() as conn:
        found = await queries.inbox(conn, "all", limit=5)
    mine, other = found[0].id, found[1].id
    await seed_cache(seeded, migrated_engine, [mine])
    await client.post("/login", data={"username": "asha", "password": PASSWORD})

    page = flat((await client.get(f"/investigations/{mine}")).text)
    assert "Outside threat intel" in page
    assert f'<span class="mono">{DEST}</span>: VirusTotal: 7 of 94 engines flag this IP' in page
    assert f'<span class="mono">{DEST}</span>: Shodan: open ports 22, 443' in page
    assert (
        '<span class="mono">45.33.32.157</span>: VirusTotal: no engine of 94 flags this IP' in page
    )
    assert page.index("7 of 94") < page.index("no engine of 94")  # detections first
    assert "45.33.32.200" not in page  # not an indicator of this investigation
    assert "never from this page" in page

    quiet = (await client.get(f"/investigations/{other}")).text
    assert "Outside threat intel" not in quiet


async def test_an_old_answer_is_not_shown(
    client: httpx.AsyncClient,
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    async with seeded.connect() as conn:
        mine = (await queries.inbox(conn, "all", limit=1))[0].id
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                 " VALUES (:i, 'ip', :v)"), {"i": mine, "v": DEST})  # fmt: skip
    async with seeded.begin() as conn:
        await store.put(conn, "virustotal", "ip", DEST, "found", BAD, 300,
                        NOW - timedelta(days=8))  # fmt: skip
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    assert "Outside threat intel" not in (await client.get(f"/investigations/{mine}")).text


async def test_the_page_reads_the_cache_as_configured_not_with_the_defaults(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """The window, the clean window and the threshold are settings (``outside.*``): the page
    must read the cache the way the services that wrote and flagged it do."""
    async with seeded.connect() as conn:
        mine = (await queries.inbox(conn, "all", limit=1))[0].id
    a, b, c, d, e = "45.33.32.10", "45.33.32.200", "45.33.32.11", "45.33.32.12", "45.33.32.13"
    async with migrated_engine.begin() as conn:
        for value in (a, b, c, d, e):
            await conn.execute(
                text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                     " VALUES (:i, 'ip', :v)"), {"i": mine, "v": value})  # fmt: skip
    base = {"suspicious": 0, "harmless": 60, "undetected": 20, "engines": 94}
    async with seeded.begin() as conn:  # (what, how many engines call it malicious, how old)
        for value, malicious, age in (
            (a, 4, timedelta(days=2, hours=12)), (b, 9, timedelta(days=2)),
            (e, 9, timedelta(days=10)),
            (c, 0, timedelta(hours=36)), (d, 0, timedelta(days=4)),
        ):  # fmt: skip
            await store.put(conn, "virustotal", "ip", value, "found",
                            {**base, "malicious": malicious}, 300, NOW - age)  # fmt: skip

    async def page(view: View | None) -> str:
        app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1), outside_view=view)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as c:
            await c.post("/login", data={"username": "asha", "password": PASSWORD})
            return flat((await c.get(f"/investigations/{mine}")).text)

    def shown(text: str) -> list[str]:
        return [v for v in (a, b, c, d, e) if f'<span class="mono">{v}</span>' in text]

    # the defaults: 7 days for a detection, a day for a clean answer, 3 engines to call it one
    assert shown(await page(None)) == [a, b]
    # configured: 20 days, a clean answer 3 days, and 6 engines to call it a detection (so the
    # 4 engines of the first are no detection: kept as long as a clean answer, 3 days)
    six = await page(View(timedelta(days=20), 6, timedelta(days=3)))
    assert shown(six) == [a, b, c, e]
    assert f'<span class="mono">{a}</span>: VirusTotal: 4 of 94 engines flag this IP' in six
    assert f'<span class="mono">{c}</span>: VirusTotal: no engine of 94' in six
    assert six.index(f">{b}<") < six.index(f">{a}<")  # only 9 engines is a detection: first
    three = await page(View(timedelta(days=20), 3, timedelta(days=3)))
    assert three.index(f">{a}<") < three.index(f">{b}<")  # both are: by address


async def test_the_web_login_reads_the_answers_but_not_the_ledger_and_writes_neither(
    web_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    async with web_engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM outside_lookups"))).scalar_one() == 0
    refused = (
        "SELECT * FROM outside_requests",
        "INSERT INTO outside_lookups (source, kind, indicator, status) VALUES"
        " ('shodan', 'ip', '1.2.3.4', 'found')",
        "DELETE FROM outside_lookups",
        "UPDATE outside_lookups SET status = 'found'",
    )
    for sql in refused:
        with pytest.raises(DBAPIError, match="permission denied"):
            async with web_engine.begin() as conn:
                await conn.execute(text(sql))
