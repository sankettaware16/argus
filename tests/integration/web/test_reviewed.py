"""The user's requests of 2026-10-14 (D-067): find reviewed investigations again (a Reviewed
view, newest decision first, with the decision, who and when), a summary and a search on the
home page; a decision needs an outcome; the labels criterion of the exit report."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import soak
from argus.web import auth, queries
from argus.web.reviews import add_review
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_r15 import empty, saver  # noqa: F401 - fixtures

pytestmark = pytest.mark.integration


async def decide(engine: AsyncEngine, user: str, inv: queries.Summary, **kw: Any) -> None:
    async with engine.begin() as conn:
        made = await auth.login(conn, user, PASSWORD, NOW)
        assert made is not None
        await add_review(conn, made[1], inv.id, note=kw.pop("note", None),
                         seen_review=inv.latest_review, seen_version=inv.version, **kw)  # fmt: skip


async def test_the_reviewed_view_newest_decision_first(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        a, b, c, d = (await queries.inbox(conn, "all"))[:4]
    await decide(seeded, "asha", a, action="reviewed", outcome="true_positive")
    await decide(seeded, "ravi", b, action="reviewed", outcome="benign_policy")
    await decide(seeded, "asha", c, action="follow_up", outcome=None)
    await decide(seeded, "asha", d, action="note", outcome=None, note="only a note")
    async with seeded.connect() as conn:
        got = await queries.inbox(conn, "reviewed")
        now = datetime.now(UTC)  # reviews carry the database's own time
        counts = await queries.counts(conn, now)
        late = await queries.counts(conn, now + timedelta(days=2))
    assert [s.id for s in got] == [c.id, b.id, a.id]  # newest decision first; a note is none
    assert [(s.last_outcome, s.last_reviewer) for s in got] == [
        (None, "Asha"), ("benign_policy", "Ravi"), ("true_positive", "Asha")]  # fmt: skip
    assert all(s.last_reviewed_at is not None for s in got)
    assert counts["reviewed"] == 3
    assert counts["reviewed_today"] == 3
    assert late["reviewed_today"] == 0
    assert counts["follow_up"] == 1
    assert counts["changed"] == 0
    assert counts["all"] == 3 + counts["open"] - 1  # the follow-up is still open
    assert counts["attention"] >= 1


async def test_pages_show_the_reviewed_view_summary_and_search(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    async with seeded.connect() as conn:
        first = (await queries.inbox(conn, "all"))[0]
    await decide(seeded, "asha", first, action="reviewed", outcome="rule_false_positive")
    home = (await client.get("/")).text
    nav = 'title="Investigations already decided, with who and when">Reviewed</a>'
    assert f'href="/?view=reviewed" {nav}' in home
    summary = re.sub(r"\s+", " ", home.split('<ul class="summary"', 1)[1].split("</ul>", 1)[0])
    assert "<strong>1</strong> reviewed</a> (1 in the last 24 h)" in summary
    assert '<form class="find" method="get" action="/">' in home
    reviewed = (await client.get("/?view=reviewed")).text
    assert "<h1>Reviewed</h1>" in reviewed
    assert "Rule false positive" in reviewed
    assert '<th scope="col">Decision</th>' in reviewed
    assert '<ul class="summary"' not in reviewed  # the summary is on the home page only
    filtered = (await client.get("/?view=attention&rule=rule-1")).text
    assert '<ul class="summary"' not in filtered
    (_, value) = first.key_fields[0]
    found = (await client.get("/", params={"view": "all", "kind": "ip", "value": value})).text
    assert str(first.id) in found
    api = await client.get("/api/investigations", params={"view": "reviewed"})
    assert [i["id"] for i in api.json()] == [str(first.id)]


async def test_the_labels_criterion(seeded: AsyncEngine) -> None:
    async with seeded.begin() as conn:
        await auth.add_user(conn, soak.ASSISTANT, "ARGUS assistant", PASSWORD)
        rules = dict((await conn.execute(text(  # a rule is its name (D-081)
            "SELECT coalesce(rule_name, rule_id), count(*) FROM investigations GROUP BY 1"
        ))).all())  # fmt: skip
    async with seeded.connect() as conn:
        before = await soak.labels(conn)
    assert before["result"] == "PENDING"
    assert before["why"].startswith(f"0 of {len(rules)} rules done; furthest behind: ")
    assert before["why"].endswith("; 0 by people, 0 by the assistant (D-071)")
    async with seeded.connect() as conn:
        everything = await queries.inbox(conn, "all", limit=1000)
    for inv in everything:  # every investigation decided by the assistant (D-071): labels
        await decide(seeded, soak.ASSISTANT, inv, action="reviewed", outcome="benign_expected")
    async with seeded.connect() as conn:
        assistant_only = await soak.labels(conn)
        refreshed = await queries.inbox(conn, "all", limit=1000)
    total = len(everything)
    assert assistant_only == {
        "criterion": "≥ 30 reviewer labels per rule (or all of a rule's investigations)",
        "result": "PASS",
        "why": f"all {len(rules)} rules have their labels; 0 by people, {total} by the"
        " assistant (D-071)",
    }
    for inv in refreshed[:2]:
        await decide(seeded, "asha", inv, action="reviewed", outcome="benign_expected")
    async with seeded.connect() as conn:
        mixed = await soak.labels(conn)
    assert mixed["why"].endswith(f"2 by people, {total - 2} by the assistant (D-071)")
    assert soak.LABELS == 30


async def test_no_investigations_no_labels(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as conn:
        assert (await soak.labels(conn))["why"] == "no investigations yet"


async def test_phase_2_measurements(empty: AsyncEngine, saver: Any) -> None:  # noqa: F811
    from tests.integration.web.test_r15 import investigate, three_hosts

    async with empty.connect() as conn:
        none = {"criterion": "Phase 2 measurements", "result": "INFO", "why": "no dossiers yet"}
        assert await soak.measurements(conn) == [none]
    await investigate(empty, saver, three_hosts())
    async with empty.connect() as conn:
        got = await soak.measurements(conn)
    assert [g["result"] for g in got] == ["INFO"] * 3
    assert got[0]["why"].startswith("Rule r1 ")  # every signal known or not, as a share
    assert got[0]["why"].endswith("%")
    assert got[1]["why"] == "at most 1 patterns on a day with up to 3 investigations (1 days)"
    tokens = int(got[2]["why"].split("p95 ")[1].split(" ")[0])
    assert 0 < tokens < 1200  # the digest is bounded (4,800 characters)
    assert got[2]["why"].endswith(
        f"at most 1 model requests and {tokens:,} input tokens a day (one per undecided"
        " pattern)")  # fmt: skip
