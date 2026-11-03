"""D-174 against the database: what a dismissal and an offer cost and keep. A campaign of 25 domains
that a person dismissed stays dismissed after a device joins it (every domain is stored and read
back); offers to an open case have an hourly budget, and an offer made is not made again.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.campaigns import lookups
from argus.campaigns.analysis import Campaign
from argus.cases import suggest
from argus.cases.machine import Confirm, Dismiss
from argus.cases.membership import NO_SHARED
from argus.cases.service import CaseService
from tests.integration.campaigns.test_campaigns import (
    CLASSIFIER,
    DGA,
    NOW,
    WINDOW,
    Make,
    device,
    evaluate,
    passes,
    the_campaign,
    transport,
)
from tests.integration.cases.conftest import Person, rows
from tests.integration.outside.conftest import Clock

pytestmark = pytest.mark.integration


async def test_a_dismissed_campaign_of_25_domains_stays_dismissed_after_a_device_joins(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    parents = tuple(f"dga{n:02d}.bad-operator.net" for n in range(25))
    devices = {n: await device(migrated_engine, n, (), hours=2) for n in range(1, 7)}

    def campaign(count: int) -> Campaign:
        members = {i: frozenset({("ip", f"10.1.1.{n}")}) for n, i in list(devices.items())[:count]}
        return Campaign(
            frozenset(members), frozenset(h for hosts in members.values() for h in hosts),
            parents, (), parents[:1], (), (), 0.9, members,
        )  # fmt: skip

    first = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, shared=NO_SHARED,
                              now=NOW, campaigns=[campaign(5)])  # fmt: skip
    assert first.applied == {"suggested": 1}
    stored = await rows(app_engine, "SELECT value FROM case_indicators WHERE kind = 'domain'")
    assert {r.value for r in stored} == set(parents)  # all 25, not the first 20
    (case,) = await rows(app_engine, "SELECT * FROM cases")
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(people["ravi"].actor(), case.id, Dismiss("benign_expected"),
                            expected_version=1)  # fmt: skip
    async with app_engine.connect() as conn:
        (no,) = await suggest.load_dismissed(conn, NOW)
    assert {v for k, v in no.indicators if k == "domain"} == set(parents)
    same = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=True, shared=NO_SHARED,
                             now=NOW, campaigns=[campaign(5)])  # fmt: skip
    joined = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=True, shared=NO_SHARED,
                               now=NOW, campaigns=[campaign(6)])  # fmt: skip
    assert same.planned == []
    assert joined.planned == []  # the sixth device does not bring the dismissed case back


async def test_offers_stop_at_the_hourly_budget_and_an_offer_is_made_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock,
    people: dict[str, Person],
) -> None:  # fmt: skip
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
    async with app_engine.begin() as conn:  # a person confirmed it: the devices stay infected
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), case.id, Confirm(), expected_version=1)
    fresh = [await device(migrated_engine, n, (DGA,), hours=0.2) for n in range(20, 25)]
    await evaluate(app_engine, outside.view)
    await passes(app_engine, outside, clock, 1)
    _, second = await lookups.run(app_engine, outside, NO_SHARED, CLASSIFIER, clock.now,
                                  window=WINDOW)  # fmt: skip

    async def go(budget: int) -> suggest.Report:
        return await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False,
                                 shared=NO_SHARED, now=NOW, campaigns=second.campaigns,
                                 offers_per_hour=budget)  # fmt: skip

    three = await go(3)
    assert three.applied == {"offered": 3}  # five new devices, a budget of three
    async with app_engine.connect() as conn:
        assert await suggest.offered_last_hour(conn) == 3
    spent = await go(3)
    assert spent.planned == []  # the hour's offers are made
    more = await go(10)
    assert more.applied == {"offered": 2}  # only the two that were not offered yet
    offered = await rows(app_engine, "SELECT investigation_id FROM case_suggestions")
    assert {r.investigation_id for r in offered} == set(fresh)
    assert (await go(10)).planned == []  # and every one is offered once
    none = await go(0)
    assert none.planned == []
