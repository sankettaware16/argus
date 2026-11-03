"""The gap this component closes (plan §2, success rule 18), end to end on Postgres: PS1Bot's
hosts beaconed for 10 days after their verdicts and nobody was told. A person confirms a case, the
watch finds the host active again, and the next pass e-mails a link, a severity and a count, and
nothing else, within the hour; the watch's other answers and the case's own words stay in ARGUS."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.notices import run, triggers
from tests.fakesmtp import FakeSmtp
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, H1, H2, World, at, context
from tests.integration.notices.conftest import BASE, config_for

pytestmark = pytest.mark.integration

FACTS = [
    H1,
    H2,
    C2,
    "Rule c2",
    "Regular beaconing",
    "campus host",
    "asha",
    "squid",
    "example.org/x",
]


async def notices_pass(world: World, server: FakeSmtp, now) -> run.Report:  # type: ignore[no-untyped-def]
    found = await triggers.compute(
        world.runtime, now, classifier=IpClassifier(None), watch_mode="local"
    )
    return await run.run(world.runtime, config_for(server), found, now=now)


async def test_a_host_that_keeps_beaconing_after_its_verdict_reaches_a_person_at_once(
    world: World, people: dict[str, Person], smtp: FakeSmtp
) -> None:
    ctx = context(None)
    inv = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    await world.run(ctx, at(1, 3))
    quiet = await notices_pass(world, smtp, at(1, 4))
    assert (quiet.conditions, quiet.sent) == (0, 0)  # the verdict day's own alerts are no news
    await world.add_alert(inv, at(1, 5))  # the host beacons again the day after its verdict
    await world.run(ctx, at(2, 3))  # the daily watch notices (the "flag")
    told = await notices_pass(world, smtp, at(2, 3, 10))  # the next pass: ten minutes later
    assert (told.conditions, told.sent) == (1, 1)
    (got,) = smtp.received
    headers = dict(got.headers)
    assert headers["Subject"] == "[ARGUS High] A confirmed case is still active"
    payload = got.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    body = payload.decode()
    assert f"{BASE}/go/case/{case_id}" in body
    assert "Severity: High" in body
    assert "Activity seen on 1 day" in body
    wire = got.message.as_string()
    for fact in FACTS:
        assert fact not in wire, fact
    # nothing more until a day has passed; then a reminder; then it stops when the case is quiet
    assert (await notices_pass(world, smtp, at(2, 6))).sent == 0
    await world.add_alert(inv, at(2, 20))
    await world.run(ctx, at(3, 3))
    reminded = await notices_pass(world, smtp, at(3, 4))
    assert reminded.sent == 1
    assert dict(smtp.received[-1].headers)["Subject"].startswith("[ARGUS High] Still waiting: ")
    for day in (4, 5, 6, 7, 8):  # quiet days: nobody alerts; the last sign ages out in 3 days
        await world.run(ctx, at(day, 3))
    over = await notices_pass(world, smtp, at(8, 4))
    assert (over.conditions, over.resolved, over.sent) == (0, 1, 0)
    async with world.owner.connect() as conn:
        kinds = (await conn.execute(text("SELECT kind, notified FROM notices"))).all()
    assert [(k.kind, k.notified) for k in kinds] == [("case_active", 2)]


async def test_two_hosts_two_cases_two_notices_and_nothing_twice(
    world: World, people: dict[str, Person], smtp: FakeSmtp
) -> None:
    ctx = context(None)
    one = await world.investigation(H1, [at(0, 9)], entities=(("ip", "198.51.100.1"),))
    two = await world.investigation(H2, [at(0, 9)], entities=(("ip", "203.0.113.2"),))
    await world.open_case(people["asha"], [one], [H1], at(0, 10), c2="198.51.100.1")
    await world.open_case(people["asha"], [two], [H2], at(0, 10), c2="203.0.113.2")
    await world.add_alert(one, at(1, 5))
    await world.add_alert(two, at(1, 6))
    await world.run(ctx, at(2, 3))
    first = await notices_pass(world, smtp, at(2, 4))
    again = await notices_pass(world, smtp, at(2, 5))
    assert (first.sent, again.sent) == (2, 0)
    links = {
        line
        for m in smtp.received
        for line in (m.message.get_payload(decode=True) or b"").decode().split()  # type: ignore[union-attr]
        if "/go/case/" in line
    }
    assert len(links) == 2


async def test_the_pass_is_computed_from_arguss_own_database_alone(
    world: World, app_engine: AsyncEngine
) -> None:
    """No gateway, no key, no SIEM URL is involved: the pass needs a database engine and a
    classifier, nothing else (the worktree's the SIEM is unreachable by design)."""
    found = await triggers.compute(app_engine, at(2, 4), classifier=IpClassifier(None))
    assert found.conditions == []
    assert found.failed == set()
