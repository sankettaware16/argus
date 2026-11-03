"""AR2c (D-168, D-170) against the database, as the runtime login: the DNS campaign of D-168 in
miniature. Many campus devices each ask for a few random names under two domains of one operator;
no single investigation shows anything. The family step looks the two parents up once each (and
the first address of each), flags every investigation that holds a name under them, raises them
into Needs attention, and the suggester makes one case naming both domains with the benign family
split off. Nothing reaches the network: the transport is scripted, and the investigations, names
and addresses are made up.
"""

from __future__ import annotations

import json
import random
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import combinations
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import raised
from argus.assets.classify import IpClassifier
from argus.campaigns import lookups
from argus.cases import suggest
from argus.cases.machine import Confirm
from argus.cases.membership import NO_SHARED, Shared
from argus.cases.service import CaseService
from argus.outside import facts, read, store
from argus.outside.service import Outside
from argus.web import queries
from tests.integration.assess.test_raised_db import dossier
from tests.integration.cases.conftest import Person, investigation, rows
from tests.integration.outside.conftest import (
    CAMPUS_NET,
    Clock,
    Transport,
    json_reply,
)

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
WINDOW = timedelta(days=5)
CLASSIFIER = IpClassifier(None, (CAMPUS_NET,))
DGA = "rapid-dns-hosting.com"
SISTER = "win-service-portal.com"
BENIGN = "cdn-edge-bench.net"
OP_ADDRESS = "45.33.32.9"
SISTER_ADDRESS = "45.33.32.77"
Make = Callable[..., Outside]


def vt_domain(
    malicious: int, *, ranked: bool = False, created: int = 1_790_000_000,
    addresses: tuple[str, ...] = (), servers: tuple[str, ...] = (),
) -> dict[str, Any]:  # fmt: skip
    records = [{"type": "A", "ttl": 300, "value": a} for a in addresses]
    records += [{"type": "NS", "ttl": 300, "value": s} for s in servers]
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 80,
                                "undetected": 10},
        "creation_date": created, "registrar": "Reg Inc", "last_dns_records": records,
        "popularity_ranks": (
            {"Majestic": {"rank": 412, "timestamp": int(NOW.timestamp()) - 3600}} if ranked else {}
        ),
    }}}  # fmt: skip


VT_IP = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 0, "harmless": 80}, "asn": 64501,
    "as_owner": "Shady Hosting", "country": "CH"}}}  # fmt: skip

ANSWERS = {
    DGA: vt_domain(5, addresses=(OP_ADDRESS,), servers=("ns1.shady-dns-farm.net",)),
    SISTER: vt_domain(0, addresses=(SISTER_ADDRESS,), servers=("ns2.shady-dns-farm.net",)),
    BENIGN: vt_domain(0, ranked=True, created=1_300_000_000, addresses=("45.33.33.5",)),
    OP_ADDRESS: VT_IP,
    SISTER_ADDRESS: VT_IP,
    "45.33.33.5": VT_IP,
}


def transport() -> Transport:
    def answer(request: Any) -> Any:
        return json_reply(200, ANSWERS[request.url.rsplit("/", 1)[1]])

    return Transport(answer)


def names(parent: str, k: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    return [f"{rnd.randrange(16**10):010x}.{parent}" for _ in range(k)]


async def device(
    owner: AsyncEngine, n: int, parents: tuple[str, ...], *, k: int = 6, hours: float = 2.0,
    extra: tuple[tuple[str, str], ...] = (), rule: str = "dns",
) -> uuid.UUID:  # fmt: skip
    """The investigation of campus device ``10.1.1.n`` that asked for ``k`` names under each of
    ``parents`` (unreviewed, low severity, with a dossier that carries no flag)."""
    entities = tuple(("domain", name) for p in parents for name in names(p, k, n * 31 + len(p)))
    inv = await investigation(
        owner, rule=rule, actor=(("source.ip", f"10.1.1.{n}"),), severity="low",
        entities=(*entities, *extra),
    )  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=hours), "i": inv},
        )
    await dossier(owner, inv, 1, ())
    return inv


async def the_campaign(owner: AsyncEngine) -> dict[str, list[uuid.UUID]]:
    """Devices 1-4 reach the flagged domain, 3-6 its sister; 1-3 and 7 the popular benign one."""
    out: dict[str, list[uuid.UUID]] = {DGA: [], SISTER: [], BENIGN: []}
    for n in range(1, 8):
        who = ((DGA, (1, 2, 3, 4)), (SISTER, (3, 4, 5, 6)), (BENIGN, (1, 2, 3, 7)))
        parents = tuple(p for p, devices in who if n in devices)
        inv = await device(owner, n, parents, k=2 if n == 1 else 6)
        for p in parents:
            out[p].append(inv)
    return out


async def flags_of(engine: AsyncEngine, inv: uuid.UUID) -> list[str]:
    found = await rows(engine, "SELECT flags FROM investigation_raises WHERE investigation_id"
                               " = :i", i=inv)  # fmt: skip
    return list(found[0].flags) if found else []


async def evaluate(engine: AsyncEngine, view: read.View) -> None:
    async with engine.begin() as conn:
        await raised.evaluate(conn, NOW, view=view)


async def attention(engine: AsyncEngine) -> dict[uuid.UUID, queries.Summary]:
    async with engine.connect() as conn:
        return {s.id: s for s in await queries.inbox(conn, "attention", limit=500)}


async def passes(
    engine: AsyncEngine, outside: Outside, clock: Clock, n: int, shared: Shared = NO_SHARED
) -> list[lookups.Report]:
    """``n`` assessment passes a minute apart, as the service runs them."""
    out = []
    for _ in range(n):
        report, _ = await lookups.run(engine, outside, shared, CLASSIFIER, clock.now, window=WINDOW)
        out.append(report)
        clock.advance(minutes=1)
    return out


# -- the DNS campaign ---------------------------------------------------------------------------


async def test_the_dns_campaign_is_flagged_raised_and_one_case_names_both_domains(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    assert await attention(app_engine) == {}  # no single investigation shows anything

    reports = await passes(app_engine, outside, clock, 6)
    # three parents, and the first address of the two rare ones: a popular site's network is not
    # worth a request (D-174)
    assert sum(r.asked for r in reports) == 5
    assert reports[-1].campaigns == 1

    dga, sister, benign = held[DGA], held[SISTER], held[BENIGN]
    out, op, rare = raised.OUTSIDE, raised.OPERATOR, raised.CAMPAIGN
    for inv in dga:  # the flagged domain is a detection of every name under it
        assert {out, rare} <= set(await flags_of(app_engine, inv))
    for inv in sister:  # its sister is the same operator, and rare itself
        assert {op, rare} <= set(await flags_of(app_engine, inv))
    only_sister = [inv for inv in sister if inv not in dga]
    for inv in only_sister:
        assert out not in await flags_of(app_engine, inv)  # tied to a flagged domain, not flagged
    only_benign = [inv for inv in benign if inv not in dga and inv not in sister]
    assert len(only_benign) == 1  # device 7 reached only the popular family
    assert await flags_of(app_engine, only_benign[0]) == []  # which brings no flag of its own
    shown = await attention(app_engine)
    assert set(shown) == set(dga) | set(sister)  # the campaign is in Needs attention ...
    assert only_benign[0] not in shown  # ... the popular family alone is not
    assert all(s.reasons[0].startswith("ARGUS raised it: ") for s in shown.values())

    # what was asked: each parent once, its first address once, nothing of the campus
    ledger = await rows(app_engine, "SELECT source, kind, purpose, outcome FROM outside_requests")
    assert {(r.source, r.purpose, r.outcome) for r in ledger} == {("virustotal", "families", "ok")}
    assert sorted(r.kind for r in ledger) == ["domain"] * 3 + ["ip"] * 2
    sent = sorted(r.url.rsplit("/", 1)[1] for r in outside.transport.sent)  # type: ignore[attr-defined]
    assert sent == sorted([DGA, SISTER, BENIGN, OP_ADDRESS, SISTER_ADDRESS])
    assert not any("10.1.1" in str(r.url) for r in outside.transport.sent)  # type: ignore[attr-defined]

    # nothing more is asked once the cache holds it all
    again = await passes(app_engine, outside, clock, 2)
    assert [r.asked for r in again] == [0, 0]
    assert len(outside.transport.sent) == 5  # type: ignore[attr-defined]


async def test_the_suggester_makes_one_case_for_the_operator_and_lists_the_benign_family(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 6)
    _, result = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                  window=WINDOW)  # fmt: skip
    (found,) = result.campaigns
    assert set(found.parents) == {DGA, SISTER}
    assert found.flagged == (DGA,)
    assert found.benign == (BENIGN,)
    assert len(found.hosts) == 6
    assert found.infrastructure[0] == "AS64501 (Shady Hosting)"

    done = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED,
                             now=NOW, campaigns=result.campaigns)  # fmt: skip
    assert done.applied == {"suggested": 1}
    (case,) = await rows(app_engine, "SELECT * FROM cases")
    assert (case.state, case.cause, case.opened_at) == (
        "suspected",
        "raised",
        None,
    )  # a person confirms
    assert case.title == "Contact with flagged server rapid-dns-hosting.com from 6 campus devices"
    assert case.attention.startswith("ARGUS suggests this case: one operator, 6 campus devices: ")
    for word in (
        DGA,
        SISTER,
        "AS64501 (Shady Hosting)",
        "(benign, ARGUS recommends closing)",
        BENIGN,
    ):
        assert word in case.attention
    joined = await rows(app_engine, "SELECT investigation_id FROM case_members"
                                    " WHERE removed_at IS NULL")  # fmt: skip
    members = {m.investigation_id for m in joined}
    assert members == set(held[DGA]) | set(held[SISTER])
    marks = {(r.kind, r.value, r.role) for r in await rows(
        app_engine, "SELECT kind, value, role FROM case_indicators")}  # fmt: skip
    assert {("domain", DGA, "indicator"), ("domain", SISTER, "indicator")} <= marks
    assert "10.1.1" not in case.title + case.attention  # no campus address in what ARGUS says

    # the next pass makes nothing new; a new day of a known device is not a new suggestion, and a
    # new device reaching the same domains is offered to the case (D-170)
    again = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED,
                              now=NOW, campaigns=result.campaigns)  # fmt: skip
    assert again.applied == {}
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1


async def test_a_new_day_and_a_new_device_join_the_case_not_a_new_one(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    make_outside: Make,
    clock: Clock,
    people: dict[str, Person],
) -> None:
    await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 6)
    _, first = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                 window=WINDOW)  # fmt: skip
    await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED, now=NOW,
                      campaigns=first.campaigns)  # fmt: skip
    (case,) = await rows(app_engine, "SELECT * FROM cases")

    # a person confirmed it: the case is open, and the devices stay infected
    async with app_engine.begin() as conn:
        service_ = await CaseService.start(conn)
        await service_.apply(people["asha"].actor(), case.id, Confirm(), expected_version=1)
    again = await device(migrated_engine, 2, (DGA,), hours=0.3)  # device 2, a new day
    fresh = await device(migrated_engine, 9, (DGA,), hours=0.2)  # device 9, never seen
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 1)
    _, second = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                  window=WINDOW)  # fmt: skip
    done = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=True, shared=NO_SHARED,
                             now=NOW, campaigns=second.campaigns)  # fmt: skip
    assert [a for a in done.planned if isinstance(a, suggest.OpenCase)] == []
    (offer,) = done.planned
    assert isinstance(offer, suggest.SuggestMembers)
    assert offer.case_id == case.id
    assert offer.kind == "also"
    assert [m.investigation_id for m in offer.members] == [fresh]
    assert again not in {m.investigation_id for m in offer.members}  # a known device: nothing


async def test_a_suggested_case_nobody_confirmed_takes_the_new_device_and_the_new_day(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 6)
    _, first = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                 window=WINDOW)  # fmt: skip
    await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED, now=NOW,
                      campaigns=first.campaigns)  # fmt: skip

    again = await device(migrated_engine, 2, (DGA,), hours=0.3)  # a known device, a new day
    fresh = await device(migrated_engine, 9, (SISTER,), hours=0.2)  # a device never seen
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 1)
    _, second = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                  window=WINDOW)  # fmt: skip
    done = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED,
                             now=NOW, campaigns=second.campaigns)  # fmt: skip
    assert done.applied == {"linked": 1}  # one change to the one case, never a second case
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1
    joined = await rows(app_engine, "SELECT investigation_id FROM case_members"
                                    " WHERE removed_at IS NULL")  # fmt: skip
    assert {m.investigation_id for m in joined} == (
        set(held[DGA]) | set(held[SISTER]) | {again, fresh}
    )


# -- what is never asked ------------------------------------------------------------------------


async def test_a_campus_a_shared_and_a_name_with_a_users_name_are_never_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    for n in range(1, 5):
        await device(migrated_engine, n, ("example.edu",), k=6)  # a campus domain: 4 devices
        await device(migrated_engine, 10 + n, ("cdn.cloudfront.net",), k=6)  # shared
        await device(migrated_engine, 20 + n, ("jsmith-files.com",), k=6,
                     extra=(("user", "jsmith"),))  # fmt: skip
    for n in range(1, 4):
        await device(migrated_engine, 30 + n, ("printer.local",), k=8)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    shared = Shared(domains=frozenset({"cloudfront.net"}))
    await evaluate(app_engine, outside.view)
    reports = await passes(app_engine, outside, clock, 3, shared)
    assert [r.asked for r in reports] == [0, 0, 0]
    assert outside.transport.sent == []  # type: ignore[attr-defined]
    assert await rows(app_engine, "SELECT * FROM outside_requests") == []


async def test_without_a_key_nothing_is_asked_but_the_flags_follow_the_cache(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    keyed = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await evaluate(app_engine, keyed.view)
    await passes(app_engine, keyed, clock, 6)  # a key made the cache
    async with migrated_engine.begin() as conn:
        await conn.execute(text("DELETE FROM investigation_raises"))
    await evaluate(app_engine, keyed.view)  # a dossier is read again (with the parent's answer)
    nothing = make_outside(Transport(), "shodan", virustotal_per_minute=4)  # no VirusTotal key
    (report,) = await passes(app_engine, nothing, clock, 1)
    assert (report.asked, report.off) == (0, "no VirusTotal key")
    assert nothing.transport.sent == []  # type: ignore[attr-defined]
    assert raised.OUTSIDE in await flags_of(app_engine, held[DGA][0])
    assert raised.CAMPAIGN in await flags_of(app_engine, held[DGA][0])


async def test_the_families_budget_is_its_own_and_ends_the_pass(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4, families_per_day=3)
    clock.now = NOW
    reports = await passes(app_engine, outside, clock, 6)
    assert sum(r.asked for r in reports) == 3  # the day's three requests, then the budget is spent
    assert any("budget" in r.stopped for r in reports)
    assert len(outside.transport.sent) == 3  # type: ignore[attr-defined]
    off = make_outside(transport(), families_per_day=0)
    (report,) = await passes(app_engine, off, clock, 1)
    assert (report.asked, report.off) == (0, "switched off")


async def test_an_answer_in_an_older_shape_is_asked_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    """An answer cached before this version (counts only, no family fields) cannot say whether the
    parent is ranked, so the family step asks again; the new answer replaces it."""
    await the_campaign(migrated_engine)
    clock.now = NOW
    async with migrated_engine.begin() as conn:
        await store.put(conn, "virustotal", "domain", DGA, "found",
                        {"malicious": 5, "engines": 95}, 40, NOW)  # fmt: skip
    outside = make_outside(transport(), virustotal_per_minute=4)
    await passes(app_engine, outside, clock, 3)
    asked = [r.url.rsplit("/", 1)[1] for r in outside.transport.sent]  # type: ignore[attr-defined]
    assert asked.count(DGA) == 1  # the cached answer had no family fields: asked once, again
    (row,) = await rows(
        app_engine, "SELECT answer FROM outside_lookups WHERE indicator = :d", d=DGA
    )
    assert row.answer["shape"] == facts.DOMAIN_SHAPE
    assert row.answer["ranked"] is False


async def test_a_ranked_parents_flagging_is_not_a_detection_of_its_names(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = {n: await device(migrated_engine, n, (BENIGN,), k=8) for n in range(1, 5)}
    answers = {BENIGN: vt_domain(4, ranked=True, created=1_300_000_000), "ignored": VT_IP}
    outside = make_outside(
        Transport(lambda r: json_reply(200, answers[r.url.rsplit("/", 1)[1]])),
        virustotal_per_minute=4,
    )
    clock.now = NOW
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 3)
    for inv in held.values():
        assert not set(await flags_of(app_engine, inv)) & {
            raised.OUTSIDE,
            raised.OPERATOR,
            raised.CAMPAIGN,
        }
    assert await attention(app_engine) == {}
    async with app_engine.connect() as conn:  # and the page and the model read no such fact
        facts = await read.facts_for(conn, list(held.values()), NOW, WINDOW, 3)
    assert facts == {}


# -- reading the cache for a name's parent ------------------------------------------------------


async def test_a_name_has_the_fact_of_its_registered_parent(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    held = await the_campaign(migrated_engine)
    outside = make_outside(transport(), virustotal_per_minute=4)
    clock.now = NOW
    await passes(app_engine, outside, clock, 6)
    async with app_engine.connect() as conn:
        found = await read.facts_for(conn, held[DGA] + held[SISTER], NOW, WINDOW, 3)
    mine = found[held[DGA][0]]
    assert [(f["value"], f["flagged"]) for f in mine] == [(DGA, True)]
    sentence = facts.describe(mine[0])
    assert sentence == (
        "VirusTotal: 5 of 95 engines flag this domain; not among the popular sites;"
        " registered 2026-09-21"
    )
    only_sister = found[held[SISTER][-1]]
    assert [(f["value"], f["flagged"]) for f in only_sister] == [(SISTER, False)]


# -- the flags in the pages' SQL and in raises() agree on every combination ----------------------


async def test_the_pages_sql_and_raises_agree_on_every_set_of_flags(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    every = [raised.THREAT_LIST, raised.OUTSIDE, raised.OPERATOR, raised.CAMPAIGN,
             "regular traffic, like a beacon", "successful answers after the alert",
             "remote-admin, P2P or anonymizer ports"]  # fmt: skip
    inv = await device(migrated_engine, 1, (DGA,), k=1)
    sql = f"SELECT {queries.RAISED} AS raised FROM investigations i WHERE i.id = :i"  # noqa: S608
    checked = 0
    for size in range(len(every) + 1):
        for flags in combinations(every, size):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("INSERT INTO investigation_raises (investigation_id, version,"
                         " dossier_hash, flags) VALUES (:i, 1, 'h', CAST(:f AS jsonb))"
                         " ON CONFLICT (investigation_id) DO UPDATE SET flags = EXCLUDED.flags"),
                    {"i": inv, "f": json.dumps(list(flags))},
                )  # fmt: skip
            got = (await rows(app_engine, sql, i=inv))[0].raised
            assert got is raised.raises(flags), flags
            checked += 1
    assert checked == 2 ** len(every)
