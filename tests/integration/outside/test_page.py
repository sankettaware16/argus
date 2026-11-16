"""AR3 (D-165) on the investigation page: "What ARGUS checked" says, in plain sentences, what
outside threat intel found about the investigation's external addresses (read from the cache by
the web's own login, which may read the answers and never the ledger, and cannot write either).
"""

from __future__ import annotations

import html

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.outside import store
from tests.integration.web.conftest import NOW

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
