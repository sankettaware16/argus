"""What Q-B2's browser tests share: a server with a richer set of records than Q-B1's (people's
reviews, a group of engine proposals, a gold-set item, an investigation with a hostile name), the
same person's other session through the API (for "someone else got there first"), and the
page-watching helpers of Q-B1's suite."""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.evaluation import store as gold_store
from argus.web import queries
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_app_browser import TRIPWIRE, Watch, open_context, sign_in
from tests.integration.web.test_external import server

__all__ = ["TRIPWIRE", "Watch", "open_context", "review_as", "rich_server", "server", "sign_in"]

BROWSERS = ["chromium", "firefox"]
# the span the seeded records are in, whatever today is (the records are of 2026-10-09)
SPAN = "range=90d"
GROUP_KEY = "engine@1#fp: steps / rule-1 / 1:answered"  # what decided the engine's four proposals


async def seed_more(seeded: AsyncEngine) -> dict[str, Any]:
    """Reviews by people, a group of four engine proposals, and a gold-set item, on top of the
    records Q-B1's server fixture made (twelve investigations, their dossiers, one proposal by
    the AI investigator, one no-decision, one hostile one)."""
    async with seeded.connect() as conn:
        everything = await queries.inbox(conn, "all", limit=100, sort="oldest")
        taken = {r[0] for r in await conn.execute(text("SELECT investigation_id FROM assessments"))}
    free = [i for i in everything if i.id not in taken and "<script>" not in (i.rule_name or "")]
    group, reviewed, gold = free[:4], free[4:6], free[6]
    async with seeded.begin() as conn:
        ravi = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'ravi'"))
        ).scalar_one()
        for n, inv in enumerate(group):
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", "a" * 64,
                                f"{n + 40:064x}", "engine@1", NOW)  # fmt: skip
        for job in await queue.claim(conn, "w", NOW, "engine@1", 10):
            await queue.propose(conn, job, NOW, "benign_expected", GROUP_KEY, ["as before"], 1.0)
        for inv, action, outcome in ((reviewed[0], "reviewed", "benign_policy"),
                                     (reviewed[1], "follow_up", None)):  # fmt: skip
            await conn.execute(
                text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                     " action, outcome) SELECT id, version, alert_count, :u, :a, :o"
                     " FROM investigations WHERE id = :i"),
                {"u": ravi, "a": action, "o": outcome, "i": inv.id})  # fmt: skip
        dossier = (await conn.execute(
            text("SELECT pack, dossier_hash FROM dossiers WHERE investigation_id = :i"
                 " AND version = :v"), {"i": gold.id, "v": gold.version})).one()  # fmt: skip
        await gold_store.import_set(conn, [{
            "investigation_id": str(gold.id), "version": gold.version, "pack": dossier.pack,
            "dossier_hash": dossier.dossier_hash, "rule_name": gold.rule_name or "rule",
            "split": "dev", "why": ["a kind"],
            "suggestion": {"outcome": "benign_expected", "reasons": ["no hit"],
                           "source": "signals"}}])  # fmt: skip
    async with seeded.connect() as conn:
        hostile = [
            i
            for i in await queries.inbox(conn, "all", limit=100)
            if "<script>" in (i.rule_name or "")
        ]
        agent = (await conn.execute(text(
            "SELECT investigation_id, id FROM assessments WHERE assessor = 'agent@1'"
            " AND status = 'proposed'"))).one()  # fmt: skip
    return {"group": group, "reviewed": reviewed, "gold": gold, "hostile": hostile[0],
            "plain": free[7], "racy": free[8], "answered": free[9],
            "agent": {"investigation_id": str(agent[0]),
                      "assessment_id": int(agent[1])}}  # fmt: skip


@pytest.fixture
async def rich_server(server: str, seeded: AsyncEngine) -> tuple[str, dict[str, Any]]:
    return server, await seed_more(seeded)


def review_as(server_url: str, user: str, investigation: Any, outcome: str) -> httpx.Response:
    """Another person reviews an investigation through the API, as it stood when they looked."""
    with httpx.Client(base_url=server_url) as client:
        made = client.post("/api/login", json={"username": user, "password": PASSWORD},
                           headers={"Origin": server_url})  # fmt: skip
        assert made.status_code == 200, made.text
        return client.post(
            f"/api/v1/investigations/{investigation.id}/reviews",
            headers={"Origin": server_url, "X-CSRF-Token": made.json()["csrf_token"]},
            json={"action": "reviewed", "outcome": outcome, "seen_review": None,
                  "seen_version": investigation.version},
        )  # fmt: skip


def numbers(text_: str) -> str:
    """Digits only: the classic page groups thousands with commas, the app with lakhs."""
    return re.sub(r"\D", "", text_)
