"""The SOC dashboard on a real database (D-103): every number against an independent count, each
filter, the incidents, and the page and API behind a login."""

from __future__ import annotations

import re
import statistics
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import dashboard, queries
from argus.web.dashboard import Filters
from tests.integration.web.conftest import NOW
from tests.integration.web.test_reviewed import decide

pytestmark = pytest.mark.integration
LATER = NOW + timedelta(hours=1)  # the clients' clock


async def build(engine: AsyncEngine, f: Filters | None = None) -> dashboard.Dashboard:
    async with engine.connect() as conn:
        return await dashboard.build(conn, f or Filters(), LATER)


async def propose(owner: AsyncEngine, inv: queries.Summary, outcome: str, n: int) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
                " assessor, status, run_after, outcome, decided_by) VALUES (:i, :v, 'p', :h, :w,"
                " 'agent@1', 'proposed', now(), :o, 'agent@1')"
            ),
            {"i": inv.id, "v": inv.version, "h": "a" * 64, "w": f"{n:064x}", "o": outcome},
        )


async def oracle(engine: AsyncEngine) -> dict[str, Any]:
    """The same numbers, counted without the dashboard's SQL."""
    async with engine.connect() as conn:
        cases = await queries.inbox(conn, "all", limit=10_000)
        alerts = (await conn.execute(text(
            "SELECT ia.investigation_id, ar.event_time FROM alert_records ar"
            " JOIN investigation_alerts ia ON ia.alert_id = ar.alert_id"))).all()  # fmt: skip
        entities = (await conn.execute(text(
            "SELECT investigation_id, kind, value FROM investigation_entities"))).all()  # fmt: skip
    start = LATER - timedelta(days=7)
    active = [c for c in cases if c.last_event_at and c.last_event_at >= start
              and c.first_event_at and c.first_event_at < LATER]  # fmt: skip
    ids = {c.id for c in active}
    return {
        "cases": active,
        "alerts": sum(1 for i, t in alerts if i in ids and start <= t < LATER),
        "entities": [(k, v, i) for i, k, v in entities if i in ids],
    }


async def test_every_number_against_an_independent_count(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        a, b, c, d, e = (await queries.inbox(conn, "all"))[:5]
    await decide(seeded, "asha", a, action="reviewed", outcome="true_positive")
    await decide(seeded, "ravi", b, action="reviewed", outcome="benign_expected")
    await decide(seeded, "asha", c, action="follow_up", outcome=None)
    await propose(migrated_engine, d, "true_positive", 1)  # suspected: nobody has decided
    await propose(migrated_engine, a, "true_positive", 2)  # confirmed already: not suspected
    await propose(migrated_engine, e, "benign_expected", 3)
    want = await oracle(seeded)
    got = await build(seeded)
    states = [s.human_state for s in want["cases"]]
    assert got.kpis["cases"] == len(want["cases"]) > 5
    assert got.kpis["alerts"] == want["alerts"] > 0
    assert got.kpis["open"] == sum(s != "reviewed" for s in states)
    assert got.kpis["reviewed"] == 2
    assert got.kpis["follow_up"] == 1
    assert got.kpis["incidents"] == 1
    assert got.kpis["suspected"] == 1
    assert got.kpis["assessed"] == 3
    assert got.kpis["open_critical"] == 0
    assert got.kpis["attention"] == sum(
        s.human_state in ("follow_up", "changed_since_review")
        or (s.human_state == "unreviewed" and s.severity in ("critical", "high"))
        for s in want["cases"]
    )
    assert got.kpis["alerts_before"] == 0  # nothing in the week before
    assert sum(got.states.values()) == sum(got.severities.values()) == got.kpis["cases"]
    assert sum(got.verdicts.values()) == sum(got.ais.values()) == got.kpis["cases"]
    assert got.verdicts["true_positive"] == got.verdicts["benign_expected"] == 1
    assert got.ais == {"proposed_tp": 2, "proposed_other": 1, "none": got.kpis["cases"] - 3}
    assert sum(sum(v.values()) for _, v in got.series) == got.kpis["alerts"]
    assert got.bucket == "day"
    # the incidents: the confirmed one first, then the suspected; never the benign one
    assert [i.id for i in got.incidents] == [str(a.id), str(d.id)]
    assert (got.incidents[0].verdict, got.incidents[1].ai) == ("true_positive", "proposed_tp")
    assert all(x.state != "reviewed" for x in got.open_cases)
    assert got.open_cases[0].id == str(c.id)  # a follow-up comes first
    # the rules: their cases and alerts add up, the busiest first
    assert sum(r["cases"] for r in got.rules) == got.kpis["cases"]
    assert [r["alerts"] for r in got.rules] == sorted(
        (r["alerts"] for r in got.rules), reverse=True
    )
    assert {r["rule_id"] for r in got.rules} == {s.rule_id for s in want["cases"]}
    # the entities: counted per kind and value
    for kind, rows in got.entities.items():
        for row in rows:
            n = sum(1 for k, v, _ in want["entities"] if (k, v) == (kind, row["value"]))
            assert row["cases"] == n, (kind, row)
    assert got.kpis["median_review_s"] is not None
    first = {a.id: a, b.id: b, c.id: c}
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT investigation_id, min(created_at) FROM review_events"
            " WHERE action <> 'note' GROUP BY 1"))).all()  # fmt: skip
    waits = [(t - first[i].first_event_at).total_seconds() for i, t in rows
             if t >= first[i].first_event_at]  # fmt: skip
    assert got.kpis["median_review_s"] == pytest.approx(statistics.median(waits))


async def test_each_filter_narrows_every_widget(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.connect() as conn:
        everything = await queries.inbox(conn, "all", limit=10_000)
    a = everything[0]
    await decide(seeded, "asha", a, action="reviewed", outcome="true_positive")
    await propose(migrated_engine, everything[1], "true_positive", 1)
    whole = await build(seeded)

    high = await build(seeded, Filters(severity=("high",)))
    assert high.kpis["cases"] == sum(s.severity == "high" for s in everything) > 0
    assert set(high.severities) == {"high"}

    rule = await build(seeded, Filters(rule=a.rule_id))
    assert rule.kpis["cases"] == sum(s.rule_id == a.rule_id for s in everything)
    assert [r["rule_id"] for r in rule.rules] == [a.rule_id]
    assert (a.rule_id, a.rule_name or a.rule_id) in whole.rule_choices
    assert len(rule.rule_choices) == len(whole.rule_choices)  # the menu keeps every rule

    reviewed = await build(seeded, Filters(state=("reviewed",)))
    assert (reviewed.kpis["cases"], reviewed.states) == (1, {"reviewed": 1})
    open_ = await build(seeded, Filters(state=("unreviewed", "follow_up")))
    assert open_.kpis["cases"] == whole.kpis["cases"] - 1

    tp = await build(seeded, Filters(verdict=("true_positive",)))
    assert [i.id for i in tp.incidents] == [str(a.id)]
    none = await build(seeded, Filters(verdict=("none",)))
    assert none.kpis["cases"] == whole.kpis["cases"] - 1

    suspected = await build(seeded, Filters(ai=("proposed_tp",)))
    assert suspected.kpis["cases"] == suspected.kpis["suspected"] == 1
    assert (await build(seeded, Filters(ai=("none",)))).kpis["cases"] == whole.kpis["cases"] - 1

    (field, value) = a.key_fields[0]
    kind = "ip" if "ip" in field else "host"
    one = await build(seeded, Filters(kind=kind, value=str(value)))
    assert str(a.id) in [i.id for i in one.incidents]
    assert one.kpis["cases"] == sum(
        1 for s in everything if any(str(v) == str(value) for _, v in s.key_fields)
    )
    assert (await build(seeded, Filters(kind="ip", value="203.0.113.99"))).kpis["cases"] == 0

    day = await build(seeded, Filters(range="24h"))
    assert day.bucket == "hour"
    assert day.kpis["alerts"] == whole.kpis["alerts"]  # every seeded alert is within 24 h
    old = Filters(start=(NOW - timedelta(days=30)).date(), end=(NOW - timedelta(days=20)).date())
    assert (await build(seeded, old)).kpis["cases"] == 0


async def test_the_page_and_the_api(seeded: AsyncEngine, client: httpx.AsyncClient) -> None:
    assert (await client.get("/dashboard")).status_code in (303, 307)  # signed out
    assert (await client.get("/api/dashboard")).status_code == 401
    await client.post("/login", data={"username": "asha", "password": "correct horse battery"})
    page = (await client.get("/dashboard")).text
    assert "<h1>Dashboard</h1>" in page
    assert '<a aria-current="page" href="/dashboard"' in page
    assert re.findall(r"<script[^>]*>", page) == ['<script src="/static/cost.js" defer>']
    assert 'role="img" aria-label="Alerts per day by severity"' in page
    assert "style=" not in page  # the CSP allows no inline style
    filtered = (
        await client.get("/dashboard", params=[("severity", "high"), ("range", "24h")])
    ).text
    assert '<input type="checkbox" name="severity" value="high" checked>' in filtered
    assert "severity: high" in filtered  # the active filter's chip
    assert 'aria-label="Alerts per hour by severity"' in filtered
    for bad in ({"range": "1y"}, {"severity": "urgent"}, {"kind": "mac", "value": "x"},
                {"start": "yesterday"}, {"value": "x" * 301},
                {"start": "2019-12-31", "end": "x"}):  # fmt: skip
        assert (await client.get("/dashboard", params=bad)).status_code == 422, bad
        assert (await client.get("/api/dashboard", params=bad)).status_code == 422, bad
    for asked, used in (  # a custom span is clamped, never refused (schemathesis, 10-21)
        (("2000-01-01", "6281-04-29"), ("2098-12-31", "2100-01-01")),  # 2099-01-01 to 2100-01-01
        (("2026-10-09", "2019-01-01"), ("2025-10-08", "2026-10-09")),  # sorted, then 366 days
        (("2025-01-01", "2026-01-01"), ("2024-12-31", "2026-01-01")),  # 366 days: kept whole
    ):
        got = await client.get("/api/dashboard", params={"start": asked[0], "end": asked[1]})
        assert got.status_code == 200, asked
        span = (got.json()["start"], got.json()["end"])
        assert span == (f"{used[0]}T18:30:00+00:00", f"{used[1]}T18:30:00+00:00"), asked
    api = (await client.get("/api/dashboard", params={"severity": "high"})).json()
    keys = {"start", "end", "bucket", "kpis", "series", "states", "severities", "verdicts",
            "ai", "rules", "entities", "incidents", "open_cases", "notified"}  # fmt: skip
    assert set(api) == keys
    assert api["severities"] == {"high": api["kpis"]["cases"]}
    assert api["kpis"] == (await build(seeded, Filters(severity=("high",)))).kpis


async def test_top_lists_are_capped_and_ranked(seeded: AsyncEngine) -> None:
    from tests.integration.grouping.test_grouping import doc, ingest

    extra = [doc(1000 + k, f"rule-z{k:02d}", f"10.1.0.{k}", NOW - timedelta(minutes=k))
             for k in range(12)]  # fmt: skip
    for d, level in zip(extra[:3], ("critical", "low", "medium"), strict=False):
        d["_source"]["kibana.alert.severity"] = level
        d["_source"]["kibana.alert.rule.name"] = f"big {level}"
    await ingest(seeded, extra)
    want = await oracle(seeded)
    got = await build(seeded)
    assert len(got.rules) == dashboard.TOP == 10
    assert len(got.entities["ip"]) == 10
    ranked = sorted(want["cases"], key=lambda s: s.rule_id)
    alerts = {
        r: sum(s.alert_count for s in ranked if s.rule_id == r) for r in {s.rule_id for s in ranked}
    }
    best = sorted(alerts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    assert [(r["rule_id"], r["alerts"]) for r in got.rules] == best
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for r in got.rules:
        worst = max((s.severity for s in ranked if s.rule_id == r["rule_id"]),
                    key=lambda v: rank.get(v or "", 0))  # fmt: skip
        assert r["severity"] == worst, r
    assert {"critical", "high", "medium", "low"} <= {r["severity"] for r in got.rules}
    assert got.rule_choices[0][0] is not None  # no rule filter: no empty choice in the menu
    per_ip: dict[str, int] = {}
    for kind, value, _ in want["entities"]:
        if kind == "ip":
            per_ip[value] = per_ip.get(value, 0) + 1
    top = sorted(per_ip.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    assert [(e["value"], e["cases"]) for e in got.entities["ip"]] == top
    nothing = await build(seeded, Filters(kind="ip", value="203.0.113.1"))
    assert nothing.entities == {"ip": [], "host": [], "domain": [], "user": []}
    assert nothing.rules == []


async def test_the_span_before_the_hourly_switch_and_half_filters(seeded: AsyncEngine) -> None:
    async with seeded.connect() as conn:
        late = await dashboard.build(conn, Filters(range="24h"), NOW + timedelta(hours=18))
        everything = await dashboard.build(conn, Filters(kind="ip"), LATER)  # no value: no filter
        unknown = await dashboard.build(conn, Filters(rule="no-such-rule"), LATER)
        spans = [
            (
                await dashboard.build(conn, Filters(start=d, end=d + timedelta(days=extra)), LATER)
            ).bucket
            for d in [NOW.date()]
            for extra in (0, 1, 2)
        ]
    # the seeded alerts are 37 minutes apart, the newest at NOW: 10 in the last 6 hours of a
    # 24-hour span ending at NOW + 18 h, the other 14 in the 24 hours before it
    assert (late.kpis["alerts"], late.kpis["alerts_before"]) == (10, 14)
    assert everything.kpis["cases"] == (await build(seeded)).kpis["cases"]
    assert unknown.rule_choices[0] == ("no-such-rule", "no-such-rule")  # kept in the menu
    assert unknown.kpis["cases"] == 0
    assert spans == ["hour", "hour", "day"]  # 1 and 2 days hourly, 3 daily


async def test_the_page_names_every_choice(client: httpx.AsyncClient) -> None:
    await client.post("/login", data={"username": "asha", "password": "correct horse battery"})
    page = (await client.get("/dashboard", params={"range": "30d"})).text
    ranges = {"24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days",
              "90d": "Last 90 days"}  # fmt: skip
    for key, title in ranges.items():
        selected = " selected" if key == "30d" else ""
        assert f'<option value="{key}"{selected}>{title}</option>' in page
    states = {"unreviewed": "Not reviewed", "follow_up": "Follow-up",
              "changed_since_review": "Changed since review", "reviewed": "Reviewed"}  # fmt: skip
    for key, title in states.items():
        assert f'<input type="checkbox" name="state" value="{key}"> {title}</label>' in page
    ais = {"proposed_tp": "Proposes true positive", "proposed_other": "Proposes benign",
           "no_proposal": "No proposal", "working": "Working on it",
           "none": "Not assessed"}  # fmt: skip
    for key, title in ais.items():
        assert f'<input type="checkbox" name="ai" value="{key}"> {title}</label>' in page
    week = (await client.get("/dashboard")).text
    assert '<option value="7d" selected>Last 7 days</option>' in week
    assert "Last 7 days:" in week
    days = (await client.get("/dashboard", params={"range": "90d"})).text
    assert "Last 90 days:" in days
    for title in ("Top IP addresses", "Top hosts", "Top domains", "Top users"):
        assert f"<h2>{title}</h2>" in page
    assert "Last 30 days:" in page


async def test_the_form_as_a_browser_sends_it(
    seeded: AsyncEngine, client: httpx.AsyncClient
) -> None:
    """A form sends every field, empty ones as "" (the user's 422 on Apply, 10-21)."""
    await client.post("/login", data={"username": "asha", "password": "correct horse battery"})
    rule = (await build(seeded)).rules[0]["rule_id"]
    query = f"range=7d&rule={rule}&kind=&value=&start=&end="
    got = await client.get(f"/dashboard?{query}")
    assert got.status_code == 200
    assert f'<option value="{rule}" selected>' in got.text
    api = (await client.get(f"/api/dashboard?{query}")).json()
    assert [r["rule_id"] for r in api["rules"]] == [rule]
    half = await client.get("/api/dashboard?start=2026-10-01&end=&kind=ip&value=")
    assert half.status_code == 200  # one date, or a kind without a value: no filter
    assert half.json()["kpis"] == (await build(seeded)).kpis
