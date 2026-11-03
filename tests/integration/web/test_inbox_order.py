"""The lists' order and paging (Q-A1 review F2): with the indexes that keep every sort fast at
the exit's scale, and the urgent order read in two parts (follow-ups, then the rest), every
view in every sort, at every offset and page size, is exactly what its definition says:
written out here on its own, over generated investigations with ties, missing times and odd
severities, and reviews of every kind."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
VIEWS = ("attention", "open", "reviewed", "all")
SORTS = ("newest", "oldest", "urgent", "reviewed", None)
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
TIMES = [None, *(NOW - timedelta(hours=h) for h in (0, 0, 1, 2, 5))]  # ties and gaps


@dataclass
class Row:
    id: uuid.UUID
    severity: str | None
    last_event_at: datetime | None
    version: int
    decision: tuple[str, int, datetime] | None  # action, version, decided at


INVESTIGATION = st.tuples(
    st.uuids(),
    st.sampled_from([None, "low", "medium", "high", "critical", "unknown"]),
    st.sampled_from(TIMES),
    st.integers(1, 3),  # its version now
    st.lists(  # its reviews, oldest first: action, the version seen, minutes after NOW
        st.tuples(
            st.sampled_from(["reviewed", "follow_up", "note"]),
            st.integers(1, 3),
            st.sampled_from([0, 0, 1, 7]),
        ),
        max_size=3,
    ),
)


def human(row: Row) -> str:
    if row.decision is None:
        return "unreviewed"
    action, version, _ = row.decision
    if action == "follow_up":
        return "follow_up"
    return "changed_since_review" if version < row.version else "reviewed"


def shown(row: Row, view: str) -> bool:
    state = human(row)
    if view == "attention":
        return state in ("follow_up", "changed_since_review") or (
            state == "unreviewed" and row.severity in ("critical", "high")
        )
    if view == "open":
        return state != "reviewed"
    if view == "reviewed":
        return row.decision is not None
    return True


def key(row: Row, sort: str) -> tuple[Any, ...]:
    """The sort's definition (a smaller key comes first; ids in byte order, as Postgres)."""
    at = row.last_event_at.timestamp() if row.last_event_at else None
    newest = (at is None, -(at or 0.0))  # newest first, missing times last
    if sort == "newest":
        return (*newest, row.id.bytes)
    if sort == "oldest":
        return (at is None, at or 0.0, row.id.bytes)
    if sort == "urgent":
        return (human(row) != "follow_up", -RANK.get(row.severity or "", 0), *newest,
                row.id.bytes)  # fmt: skip
    decided = row.decision[2].timestamp() if row.decision else None
    return (decided is not None, -(decided or 0.0), row.id.bytes)  # never decided first


async def store(owner: AsyncEngine, made: list[tuple[Any, ...]]) -> list[Row]:
    rows: dict[uuid.UUID, Row] = {}
    async with owner.begin() as conn:
        await conn.execute(text("TRUNCATE investigations, review_events, review_state CASCADE"))
        user = await conn.scalar(text("SELECT id FROM users ORDER BY id LIMIT 1"))
        for n, (inv, severity, at, version, reviews) in enumerate(made):
            if inv in rows:
                continue
            await conn.execute(
                text(
                    "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                    " bucket_start, bucket_end, previous_id, alert_count, last_event_at,"
                    " severity, version) VALUES (:id, '1', 'rule', :key, :start, :end, :id, 1,"
                    " :at, :sev, :v)"
                ),
                {"id": inv, "key": f"k{n}", "start": NOW - timedelta(days=1), "end": NOW,
                 "at": at, "sev": severity, "v": version},
            )  # fmt: skip
            decision = None
            for action, seen, minutes in reviews:
                decided = NOW + timedelta(minutes=minutes)
                await conn.execute(
                    text(
                        "INSERT INTO review_events (investigation_id, version, alert_count,"
                        " user_id, action, outcome, note, created_at) VALUES (:i, :v, 1, :u,"
                        " :a, NULL, :note, :at)"
                    ),
                    {"i": inv, "v": seen, "u": user, "a": action, "at": decided,
                     "note": "a note" if action == "note" else None},
                )  # fmt: skip
                if action != "note":
                    decision = (action, seen, decided)
            rows[inv] = Row(inv, severity, at, version, decision)
    return list(rows.values())


@settings(
    max_examples=max(10, settings().max_examples // 4),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(made=st.lists(INVESTIGATION, min_size=0, max_size=14), pages=st.sampled_from(
    [(0, 100), (0, 1), (1, 2), (2, 3), (3, 1), (5, 4), (13, 100)]))  # fmt: skip
async def test_every_list_is_in_its_defined_order_on_every_page(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, made: list[tuple[Any, ...]],
    pages: tuple[int, int],
) -> None:  # fmt: skip
    rows = await store(migrated_engine, made)
    offset, limit = pages
    async with seeded.connect() as conn:
        for view in VIEWS:
            for sort in SORTS:
                order = sort or ("reviewed" if view == "reviewed" else "urgent")
                expected = sorted((r for r in rows if shown(r, view)), key=lambda r: key(r, order))
                got = await queries.inbox(conn, view, offset=offset, limit=limit, sort=sort)
                assert [s.id for s in got] == [r.id for r in expected][offset : offset + limit], (
                    view,
                    sort,
                )
                assert [s.human_state for s in got] == [
                    human(r) for r in expected[offset : offset + limit]
                ]


async def test_reading_a_list_leaves_the_planner_as_it_was(seeded: AsyncEngine) -> None:
    """Sorting is switched off for a walking part's one statement only: whatever the request
    reads next is planned as usual (and a rule's list may still be sorted)."""
    async with seeded.begin() as conn:
        for sort in SORTS:
            await queries.inbox(conn, "all", sort=sort)
            await queries.inbox(conn, "all", rule="rule-1", sort=sort)
            assert await conn.scalar(text("SELECT current_setting('enable_sort')")) == "on"


@pytest.mark.parametrize("path", ["/api/v1/investigations", "/api/investigations", "/"])
async def test_lists_page_ten_thousand_deep_at_most(
    seeded: AsyncEngine, path: str, web_engine: AsyncEngine
) -> None:
    """Every list answers within criterion 14's 300 ms that deep at the exit's scale
    (test_scale.py); deeper pages are refused, and the Inbox page offers none."""
    app = create_app(web_engine, clock=lambda: NOW)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=SAME_ORIGIN) as http:  # fmt: skip
        await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        deepest = await http.get(path, params={"view": "all", "offset": queries.DEEPEST})
        deeper = await http.get(path, params={"view": "all", "offset": queries.DEEPEST + 1})
    assert deepest.status_code == 200
    assert deeper.status_code == 422
    if path.startswith("/api/v1"):
        assert deeper.json() == {"detail": "query.offset: Input should be less than or equal"
                                 " to 10000", "code": "invalid"}  # fmt: skip
