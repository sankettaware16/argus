"""D-174: what the adversarial review of AR2c found, as scenarios on a throwaway database as the
runtime login, with a scripted transport. Nothing reaches the network.

The real VirusTotal answers of 28 Oct (a pair of Cloudflare name servers and no address, DNS-volume
ranks only, registered in 2019 and 2022) end to end; a popular domain kept for a week; the family
step's failure not stopping AR3's part; a parent's answer inherited only when it says so; the cap
of names; a spent budget preparing nothing.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import raising
from argus.assess import raised
from argus.campaigns import load, lookups
from argus.cases.membership import NO_SHARED, load_shared
from argus.db import migrate
from argus.outside import prefetch, read, store
from tests.integration.assess.test_raised_db import dossier
from tests.integration.campaigns.test_campaigns import (
    BENIGN,
    CLASSIFIER,
    DGA,
    NOW,
    SISTER,
    WINDOW,
    Make,
    device,
    evaluate,
    flags_of,
    passes,
    the_campaign,
    transport,
)
from tests.integration.cases.conftest import investigation, rows
from tests.integration.outside.conftest import Clock, Transport, json_reply

pytestmark = pytest.mark.integration

PAIR = ("tani.ns.cloudflare.com", "todd.ns.cloudflare.com")


def stamp(days_ago: float = 1) -> int:
    return int((NOW - timedelta(days=days_ago)).timestamp())


def real_reply(
    malicious: int, created: int, ranks: dict[str, Any], *, servers: tuple[str, ...] = PAIR,
) -> dict[str, Any]:  # fmt: skip
    """A domain as VirusTotal answers for the real campaign: name servers and no A record."""
    records = [{"type": "NS", "ttl": 300, "value": s} for s in servers]
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 80,
                                "undetected": 12},
        "creation_date": created, "registrar": "Reg Inc", "last_dns_records": records,
        "popularity_ranks": ranks,
    }}}  # fmt: skip


# -- the real answers, end to end (R1) -----------------------------------------------------------


async def test_the_real_dns_campaign_is_found_and_the_popular_service_is_not(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    answers = {
        DGA: real_reply(  # created 2019, 5 engines; ranked by DNS-volume lists only
            5, 1_551_000_000, {"Cisco Umbrella": {"rank": 706_434, "timestamp": stamp(2)},
                               "Cloudflare Radar": {"rank": 50_000, "timestamp": stamp(3)}}),
        SISTER: real_reply(  # created 2022, 0 engines; a stale Alexa rank and DNS-volume lists
            0, 1_655_000_000, {"Alexa": {"rank": 268_720, "timestamp": 1_587_000_000},
                               "Cisco Umbrella": {"rank": 967_313, "timestamp": stamp(2)},
                               "Cloudflare Radar": {"rank": 100_000, "timestamp": stamp(3)}}),
        BENIGN: real_reply(  # a real-time media service: popular on the web
            0, 1_200_000_000, {"Majestic": {"rank": 28_474, "timestamp": stamp(5)},
                               "Statvoo": {"rank": 11_569, "timestamp": stamp(900)},
                               "Cisco Umbrella": {"rank": 9_014, "timestamp": stamp(2)},
                               "Cloudflare Radar": {"rank": 1_000, "timestamp": stamp(3)}},
            servers=("ns-1.example-dns.net", "ns-2.example-dns.net")),
    }  # fmt: skip
    outside = make_outside(
        Transport(lambda r: json_reply(200, answers[r.url.rsplit("/", 1)[1]])),
        virustotal_per_minute=4,
    )
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    shared = load_shared()  # cloudflare.com is on it: the name-server tie must stand all the same
    reports = await passes(app_engine, outside, clock, 4, shared)
    assert sum(r.asked for r in reports) == 3  # three parents; no address to look up for any
    assert reports[-1].campaigns == 1
    for inv in held[DGA]:
        assert {raised.OUTSIDE, raised.CAMPAIGN} <= set(await flags_of(app_engine, inv))
    only_sister = [inv for inv in held[SISTER] if inv not in held[DGA]]
    for inv in only_sister:  # rare, and the same operator as the detected one
        assert {raised.OPERATOR, raised.CAMPAIGN} <= set(await flags_of(app_engine, inv))
    only_benign = [i for i in held[BENIGN] if i not in held[DGA] and i not in held[SISTER]]
    assert await flags_of(app_engine, only_benign[0]) == []  # popular: nothing
    _, result = await lookups.run(app_engine, outside, shared, CLASSIFIER, clock.now, window=WINDOW)
    (found,) = result.campaigns
    assert set(found.parents) == {DGA, SISTER}
    assert found.benign == (BENIGN,)
    assert found.infrastructure == (f"name servers {PAIR[0]} and {PAIR[1]}",)
    ledger = await rows(app_engine, "SELECT kind FROM outside_requests")
    assert [r.kind for r in ledger] == ["domain"] * 3  # no A records, no address request


# -- a popular domain is kept for the week, and its address is never asked (review 3) -----------


async def test_a_popular_domain_is_not_asked_again_the_next_day(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4, virustotal_per_day=400)
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 6)
    first = [r.url.rsplit("/", 1)[1] for r in outside.transport.sent]  # type: ignore[attr-defined]
    assert BENIGN in first
    assert "45.33.33.5" not in first  # the popular family's address is not worth a request
    clock.advance(hours=25)
    await passes(app_engine, outside, clock, 8)
    second = [r.url.rsplit("/", 1)[1] for r in outside.transport.sent][len(first) :]  # type: ignore[attr-defined]
    assert BENIGN not in second  # kept for the cache window (7 days), not the clean day
    assert "45.33.33.5" not in second
    assert DGA not in second  # a detection is kept for the week too
    assert SISTER in second  # the rare, clean one is looked at again after a day


# -- a spent budget prepares nothing (review 11) -------------------------------------------------


async def test_a_spent_budget_does_no_work_for_the_next_candidate(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """The day's family requests are made. Before the fix every pass still prepared the campus
    view of the first candidate (a query for each investigation that holds a name under it, up to
    500) and only then found the budget spent."""
    await the_campaign(migrated_engine)
    async with migrated_engine.begin() as conn:  # two requests today, the whole budget
        for _ in range(2):
            await conn.execute(
                text("INSERT INTO outside_requests (at, source, kind, purpose, outcome)"
                     " VALUES (:t, 'virustotal', 'domain', 'families', 'ok')"),
                {"t": NOW},
            )  # fmt: skip
    prepared: list[uuid.UUID] = []
    real = prefetch.campus_of

    async def spy(conn: Any, holder: uuid.UUID, outside_: Any) -> Any:
        prepared.append(holder)
        return await real(conn, holder, outside_)

    monkeypatch.setattr(prefetch, "campus_of", spy)
    outside = make_outside(transport(), virustotal_per_minute=4, families_per_day=2)
    clock.now = NOW
    reports = await passes(app_engine, outside, clock, 3)
    assert prepared == []  # a spent budget prepares nothing at all
    assert outside.transport.sent == []  # type: ignore[attr-defined]
    assert all("budget" in r.stopped for r in reports)
    assert [r.asked for r in reports] == [0, 0, 0]
    roomy = make_outside(transport(), virustotal_per_minute=4, families_per_day=3)
    await passes(app_engine, roomy, clock, 1)
    assert prepared  # with one request of room the first candidate is prepared and asked


# -- the family step's failure never stops AR3's part (review 4) ---------------------------------


async def test_a_failure_of_the_family_step_does_not_stop_the_prefetch_and_the_upkeep(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """The new code on a schema that is not upgraded yet (0048: the ledger does not know the
    purpose "families"): the step fails, says so, and the beacon prefetch, the refresh of the
    flags and the cache's upkeep still run."""
    await the_campaign(migrated_engine)
    await migrate.downgrade(migrated_engine, "0048")
    calls: list[str] = []
    real_prefetch, real_refresh = prefetch.run, raised.refresh_outside

    async def spy_prefetch(*a: Any, **k: Any) -> Any:
        calls.append("prefetch")
        return await real_prefetch(*a, **k)

    async def spy_refresh(*a: Any, **k: Any) -> Any:
        calls.append("refresh")
        return await real_refresh(*a, **k)

    monkeypatch.setattr(prefetch, "run", spy_prefetch)
    monkeypatch.setattr(raised, "refresh_outside", spy_refresh)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    done = await raising.run(app_engine, CLASSIFIER, NOW, suggesting=False, last=None,
                             outside=outside, shared=NO_SHARED, window=WINDOW)  # fmt: skip
    assert calls == ["prefetch", "refresh"]
    assert any(w.startswith("warning: campaign look-ups failed (") for w in done.warned)
    assert not any("outside threat intel failed" in w for w in done.warned)
    assert done.campaigns == ()


# -- a parent's answer is a fact of its names only when it says so (review 5) --------------------

WEEK, DAY = timedelta(days=7), timedelta(days=1)
PARENT = "popular-site-example.com"


async def seed(
    owner: AsyncEngine, parent: str, answer: dict[str, Any], status: str = "found"
) -> Any:
    inv = await investigation(owner, rule="web", actor=(("source.ip", "10.1.1.5"),),
                              severity="low", entities=(("domain", f"cdn.{parent}"),))  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=1), "i": inv},
        )
        await store.put(conn, "virustotal", "domain", parent, status, answer, 0,
                        NOW - timedelta(hours=2))  # fmt: skip
    await dossier(owner, inv, 1, ())
    return inv


CURRENT = {"malicious": 4, "engines": 90, "shape": 3}


@pytest.mark.parametrize(
    ("label", "answer", "status", "inherited"),
    [
        ("current shape, unranked", {**CURRENT, "ranked": False}, "found", True),
        ("current shape, popular", {**CURRENT, "ranked": True, "best_rank": 300}, "found", False),
        ("current shape, popularity unknown", CURRENT, "found", False),
        ("older shape 2 says unranked", {**CURRENT, "shape": 2, "ranked": False}, "found", False),
        ("before AR2c", {"malicious": 4, "engines": 90}, "found", False),
        ("no record", {}, "not_found", False),
    ],
)  # fmt: skip
async def test_the_parent_answer_is_inherited_only_when_it_says_unranked_in_the_current_shape(
    migrated_engine: AsyncEngine, label: str, answer: dict[str, Any], status: str, inherited: bool
) -> None:
    inv = await seed(migrated_engine, PARENT, answer, status)
    async with migrated_engine.begin() as conn:
        found = await read.facts_for(conn, [inv], NOW, WEEK, 3, clean_window=DAY)
        await raised.evaluate(conn, NOW, view=read.View(WEEK, 3, DAY))
    assert bool(found.get(inv)) is inherited, label
    stored = await rows(migrated_engine, "SELECT flags FROM investigation_raises"
                                         " WHERE investigation_id = :i", i=inv)  # fmt: skip
    assert (raised.OUTSIDE in stored[0].flags) is inherited, label


async def test_a_parent_the_view_does_not_allow_is_not_inherited(
    migrated_engine: AsyncEngine,
) -> None:
    inv = await seed(migrated_engine, PARENT, {**CURRENT, "ranked": False})
    shared = load_shared()
    async with migrated_engine.begin() as conn:
        not_shared = lambda p: shared.reason("domain", p) is None  # noqa: E731
        allowed = await read.facts_for(conn, [inv], NOW, WEEK, 3, clean_window=DAY,
                                       parent_ok=not_shared)  # fmt: skip
        refused = await read.facts_for(conn, [inv], NOW, WEEK, 3, clean_window=DAY,
                                       parent_ok=lambda p: p != PARENT)  # fmt: skip
        view = read.View(WEEK, 3, DAY, lambda p: p != PARENT)
        await raised.evaluate(conn, NOW, view=view)
    assert allowed[inv][0]["value"] == PARENT
    assert refused == {}
    (flags,) = await rows(migrated_engine, "SELECT flags FROM investigation_raises"
                                           " WHERE investigation_id = :i", i=inv)  # fmt: skip
    assert raised.OUTSIDE not in flags.flags


async def test_the_lookup_service_applies_the_shared_list_and_eligibility_to_parents(
    make_outside: Make,
) -> None:
    outside = make_outside(transport())
    assert outside.parent_ok("rapid-dns-hosting.com")
    assert not outside.parent_ok("example.edu")  # a campus name is never read for
    assert not outside.parent_ok("x.local")
    assert outside.view.parent_ok is not None


# -- the cap of names is said (review 10) --------------------------------------------------------


async def test_a_window_with_more_names_than_the_cap_is_said_in_the_log(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    for n in range(1, 4):
        await device(migrated_engine, n, (DGA,), k=3)  # nine names
    async with app_engine.connect() as conn:
        with caplog.at_level(logging.WARNING, logger="argus.campaigns"):
            names, _, _ = await load.sightings(conn, NOW, WINDOW, limit=4)
    assert len(names) >= 1
    (record,) = [r for r in caplog.records if r.name == "argus.campaigns"]
    assert "cap of 4 domain names was reached" in record.getMessage()
    assert DGA not in record.getMessage()  # counts only: no name, no address
    caplog.clear()
    async with app_engine.connect() as conn:
        with caplog.at_level(logging.WARNING, logger="argus.campaigns"):
            await load.sightings(conn, NOW, WINDOW)
    assert caplog.records == []  # under the cap: silence


async def test_a_family_ranked_on_the_web_is_never_a_campaign_whatever_the_engines_say(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    """A family VirusTotal ranks on the web (here Tranco, at a poor rank) is popular: six engines
    flag it, four devices reach it with random names, and it still raises nothing."""
    held = [await device(migrated_engine, n, (BENIGN,), k=8) for n in range(1, 5)]
    answers = {
        BENIGN: real_reply(
            6, stamp(30), {"Tranco": {"rank": 3_000_000, "timestamp": stamp(1)}}, servers=PAIR
        )
    }
    outside = make_outside(
        Transport(lambda r: json_reply(200, answers[r.url.rsplit("/", 1)[1]])),
        virustotal_per_minute=4,
    )  # fmt: skip
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    reports = await passes(app_engine, outside, clock, 3)
    assert sum(r.asked for r in reports) == 1
    (stored,) = await rows(
        migrated_engine, "SELECT answer FROM outside_lookups WHERE indicator = :d", d=BENIGN
    )
    assert stored.answer["ranked"] is True
    assert stored.answer["best_rank"] == 3_000_000
    assert reports[-1].campaigns == 0
    for inv in held:
        assert await flags_of(app_engine, inv) == []
