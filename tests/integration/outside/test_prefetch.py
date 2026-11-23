"""AR3 (D-164, D-165) against the database: the replay of the Amadey shape, and the look-ups that
make it work. A beacon alone raises nothing; once VirusTotal flags the server the beacon talks
to, the investigation is raised into Needs attention with the reason in words. The beacon-
flagged investigations' external destinations are looked up in priority order within a daily
budget, the cache makes repeats free, and nothing of the campus, no shared infrastructure and
nothing a local list settles is ever asked.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import engine, raised
from argus.cases.membership import NO_SHARED, Shared
from argus.outside import facts, prefetch, read, service
from argus.outside.service import Outside
from argus.web import queries
from tests.integration.assess.test_raised_db import (
    BEACON,
    LISTED,
    dossier,
    in_attention,
)
from tests.integration.cases.conftest import investigation, make_person, rows
from tests.integration.outside.conftest import (
    VT_BAD,
    VT_CLEAN,
    Clock,
    Transport,
    json_reply,
)

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
DEST = "45.33.32.156"
VIEW = read.View(timedelta(days=7), 3)
Make = Callable[..., Outside]
FEW_ENGINES = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 2, "suspicious": 0, "harmless": 70, "undetected": 22}}}}  # fmt: skip
WORDS = "ARGUS raised it: regular traffic, like a beacon; flagged by outside threat intel."


@pytest.fixture(autouse=True)
def _now(clock: Clock) -> None:
    clock.now = NOW


async def make(
    owner: AsyncEngine, *, host: int = 1, dest: Sequence[tuple[str, str]] = (("ip", DEST),),
    severity: str = "low", signals: tuple[dict[str, Any], ...] = (BEACON,), hours: float = 1.0,
) -> uuid.UUID:  # fmt: skip
    """An unreviewed investigation of campus host 10.1.1.<host> that carries ``signals`` and
    reaches ``dest``, its last alert ``hours`` ago."""
    inv = await investigation(
        owner, rule=f"r{host}", actor=(("source.ip", f"10.1.1.{host}"),), severity=severity,
        entities=tuple(dest),
    )  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=hours), "i": inv},
        )
    await dossier(owner, inv, 1, signals)
    return inv


async def flags_of(engine_: AsyncEngine, inv: uuid.UUID) -> list[str]:
    found = await rows(engine_, "SELECT flags FROM investigation_raises WHERE investigation_id"
                                " = :i", i=inv)  # fmt: skip
    return list(found[0].flags) if found else []


async def evaluate(app_engine: AsyncEngine, view: read.View | None = VIEW) -> Any:
    async with app_engine.begin() as conn:
        return await raised.evaluate(conn, NOW, view=view)


async def refresh(app_engine: AsyncEngine) -> int:
    async with app_engine.begin() as conn:
        return await raised.refresh_outside(conn, NOW, VIEW)


# -- the Amadey shape ---------------------------------------------------------------------------


async def test_a_beacon_is_raised_once_virustotal_flags_its_server(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    amadey = await make(migrated_engine, host=1, dest=(("ip", DEST),))
    quiet = await make(migrated_engine, host=2, dest=(("ip", "45.33.32.157"),))
    few = await make(migrated_engine, host=3, dest=(("ip", "45.33.32.158"),))
    transport = Transport(
        lambda r: json_reply(200, {DEST: VT_BAD, "45.33.32.157": VT_CLEAN,
                                   "45.33.32.158": FEW_ENGINES}[r.url.rsplit("/", 1)[1]])
    )  # fmt: skip
    outside = make_outside(transport, virustotal_per_minute=4)

    assert await evaluate(app_engine) == {"read": 3, "raised": 3}  # a beacon is a flag ...
    assert await in_attention(app_engine) == {}  # ... and, alone, raises nothing (D-164)
    for inv in (amadey, quiet, few):
        assert await flags_of(app_engine, inv) == ["regular traffic, like a beacon"]

    report = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert (report.asked, report.found, report.failed, report.stopped) == (3, 3, 0, "")
    assert sorted(r.url.rsplit("/", 1)[1] for r in transport.sent) == [
        DEST, "45.33.32.157", "45.33.32.158",
    ]  # fmt: skip
    assert await refresh(app_engine) == 1  # only the server VirusTotal flags
    assert await flags_of(app_engine, amadey) == [
        "regular traffic, like a beacon", "flagged by outside threat intel",
    ]  # fmt: skip
    assert await flags_of(app_engine, quiet) == ["regular traffic, like a beacon"]
    assert await flags_of(app_engine, few) == ["regular traffic, like a beacon"]  # 2 < 3 engines
    shown = await in_attention(app_engine)
    assert set(shown) == {amadey}
    assert shown[amadey].reasons == [WORDS]
    async with app_engine.connect() as conn:
        assert (await queries.counts(conn, NOW))["attention"] == 1

    # the cache makes repeats free: nothing more is asked, nothing more changes
    again = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert again.asked == 0
    assert again.picked == []
    assert await refresh(app_engine) == 0
    assert len(transport.sent) == 3


async def test_a_detection_already_in_the_cache_flags_a_dossier_when_it_is_first_read(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", DEST)
    inv = await make(migrated_engine)
    assert await evaluate(app_engine) == {"read": 1, "raised": 1}
    assert await flags_of(app_engine, inv) == [
        "regular traffic, like a beacon", "flagged by outside threat intel",
    ]  # fmt: skip
    assert set(await in_attention(app_engine)) == {inv}
    assert await evaluate(app_engine, None) == {"read": 0, "raised": 0}


async def test_a_newer_dossier_is_read_again_and_keeps_the_detection_the_cache_holds(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inv = await make(migrated_engine)
    await evaluate(app_engine)
    await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", DEST)
    assert await refresh(app_engine) == 1
    async with migrated_engine.begin() as conn:  # more alerts: version 2, the beacon goes on
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": inv})
    assert set(await in_attention(app_engine)) == set()  # a stale read is not shown
    await dossier(migrated_engine, inv, 2, (BEACON,))
    assert await evaluate(app_engine) == {"read": 1, "raised": 1}
    assert "flagged by outside threat intel" in await flags_of(app_engine, inv)
    assert set(await in_attention(app_engine)) == {inv}


async def test_the_flag_is_not_added_to_a_reviewed_old_or_stale_investigation(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    done = await make(migrated_engine, host=1)
    old = await make(migrated_engine, host=2, hours=24 * 5)
    moved = await make(migrated_engine, host=3)
    fresh = await make(migrated_engine, host=4)
    await evaluate(app_engine, VIEW)  # (the one 5 days old is outside the 3-day horizon: unread)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": moved}
        )
    asha = await make_person(app_engine, "asha")
    async with app_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, 1, 2, :u, 'reviewed', 'benign_expected')"),
            {"i": done, "u": asha.user_id},
        )  # fmt: skip
    await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", DEST)
    assert await refresh(app_engine) == 1
    assert "flagged by outside threat intel" in await flags_of(app_engine, fresh)
    for other in (done, old, moved):
        assert "flagged by outside threat intel" not in await flags_of(app_engine, other)


async def test_a_threat_list_hit_and_a_detection_raise_it_without_a_beacon(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inv = await make(migrated_engine, signals=(LISTED,))
    await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", DEST)
    await evaluate(app_engine)
    assert await flags_of(app_engine, inv) == [
        "on a threat list",
        "flagged by outside threat intel",
    ]
    assert set(await in_attention(app_engine)) == {inv}


# -- who is looked up, and in which order -------------------------------------------------------


async def asked(transport: Transport) -> list[str]:
    return [r.url.rsplit("/", 1)[1] for r in transport.sent]


async def test_the_destinations_are_asked_in_priority_order_within_the_batch(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    high = await make(migrated_engine, host=1, severity="high", dest=(("ip", "45.33.32.1"),))
    medium = await make(migrated_engine, host=2, severity="medium", dest=(("ip", "45.33.32.2"),))
    low_old = await make(migrated_engine, host=3, severity="low", hours=5,
                         dest=(("ip", "45.33.32.3"),))  # fmt: skip
    low_new = await make(migrated_engine, host=4, severity="low", hours=1,
                         dest=(("ip", "45.33.32.4"),))  # fmt: skip
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, prefetch_batch=4, virustotal_per_minute=4)
    await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert await asked(transport) == ["45.33.32.2", "45.33.32.4", "45.33.32.3", "45.33.32.1"]
    assert {high, medium, low_old, low_new}  # (the high one is last: it is in Needs attention)


async def test_a_batch_is_small_and_the_rest_wait_for_the_next_pass(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    for n in range(1, 6):
        await make(migrated_engine, host=n, dest=(("ip", f"45.33.32.{n}"),), hours=n)
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4)  # the default batch is 3
    first = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert first.asked == 3
    assert await asked(transport) == ["45.33.32.1", "45.33.32.2", "45.33.32.3"]
    second = await prefetch.run(app_engine, outside, NO_SHARED, NOW)  # the minute is not over
    assert second.asked == 1
    assert second.stopped.startswith("VirusTotal is at its limit")
    assert len(transport.sent) == 4


async def test_the_daily_budget_is_the_prefetchs_own_and_ends_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    for n in range(1, 5):
        await make(migrated_engine, host=n, dest=(("ip", f"45.33.32.{n}"),), hours=n)
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, prefetch_per_day=2, virustotal_per_minute=4)
    assert (await prefetch.run(app_engine, outside, NO_SHARED, NOW)).asked == 2
    clock.advance(minutes=5)
    spent = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert (spent.asked, spent.off) == (0, "today's budget is spent")
    assert spent.line() == "outside: prefetch off (today's budget is spent)"
    assert len(transport.sent) == 2


async def test_a_prefetch_without_a_key_or_switched_off_asks_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    await make(migrated_engine)
    await evaluate(app_engine)
    transport = Transport()
    assert (
        await prefetch.run(app_engine, make_outside(transport, "shodan"), NO_SHARED, NOW)
    ).off == ("no VirusTotal key")
    assert (
        await prefetch.run(app_engine, make_outside(transport, prefetch=False), NO_SHARED, NOW)
    ).off == ("switched off")
    assert transport.sent == []


async def test_nothing_of_the_campus_shared_or_listed_is_ever_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inside = (
        ("ip", "10.20.3.4"), ("ip", "198.51.100.7"), ("ip", "192.168.1.1"),
        ("domain", "www.example.edu"), ("domain", "printer.local"), ("host", "tp8"),
        ("user", "alice"), ("ip", "104.16.1.1"), ("domain", "x.cloudfront.net"),
    )  # fmt: skip
    await make(migrated_engine, host=1, dest=inside)
    await make(migrated_engine, host=2, signals=(BEACON, LISTED), dest=(("ip", "45.33.32.9"),))
    await make(migrated_engine, host=3, signals=(), dest=(("ip", "45.33.32.8"),))  # no beacon
    await evaluate(app_engine)
    shared = Shared(networks=(ipaddress.ip_network("104.16.0.0/13"),),
                    domains=frozenset({"cloudfront.net"}))  # fmt: skip
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4)
    report = await prefetch.run(app_engine, outside, shared, NOW)
    assert report.asked == 0
    assert transport.sent == []
    assert await rows(app_engine, "SELECT * FROM outside_requests") == []


async def test_a_destination_two_investigations_share_is_asked_once_and_names_after_addresses(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    await make(migrated_engine, host=1, hours=1, dest=(
        ("domain", "c2.evil-site.com"), ("ip", "45.33.32.1"), ("ip", "45.33.32.2"),
        ("ip", "45.33.32.3"), ("ip", "45.33.32.4"),
    ))  # fmt: skip
    await make(migrated_engine, host=2, hours=2, dest=(("ip", "45.33.32.1"),))
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, prefetch_batch=4, virustotal_per_minute=4)
    await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    # at most three of the first investigation's indicators (addresses before names), and the
    # second investigation's shares the first's address
    assert await asked(transport) == ["45.33.32.1", "45.33.32.2", "45.33.32.3"]


async def test_a_limit_ends_the_pass_and_a_stop_is_said(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    for n in range(1, 4):
        await make(migrated_engine, host=n, dest=(("ip", f"45.33.32.{n}"),), hours=n)
    await evaluate(app_engine)
    transport = Transport(json_reply(429))
    outside = make_outside(transport, virustotal_per_minute=4)
    report = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert len(transport.sent) == 1  # the first answer stopped the pass
    assert "is stopped" in report.stopped
    assert report.asked == 0
    assert report.line().startswith("outside: looked up 0 (found 0, no record 0, failed 0); ")


# -- the campus names of an investigation ------------------------------------------------------


async def test_a_name_holding_the_investigations_host_or_user_is_never_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    """``jsmith.c2.com`` is a public name, and the user ``jsmith`` is a campus name: the model's
    view of this investigation scrubs it, so the prefetch must not send it to a provider. A
    refused name takes no place in the investigation's three."""
    await make(migrated_engine, host=1, dest=(
        ("host", "desktop-ab12cd"), ("user", "jsmith"),
        ("domain", "a-jsmith.c2.com"), ("domain", "b-desktop-ab12cd.c2.com"),
        ("domain", "c.c2.com"), ("domain", "d.c2.com"), ("domain", "e.c2.com"),
    ))  # fmt: skip
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, prefetch_batch=4, virustotal_per_minute=4)
    await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert await asked(transport) == ["c.c2.com", "d.c2.com", "e.c2.com"]


async def test_the_names_come_from_the_dossiers_fields_and_the_grouping_key_too(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inv = await make(migrated_engine, host=1, dest=(
        ("domain", "keyname.c2.com"), ("domain", "fieldname.c2.com"), ("domain", "plain.c2.com"),
    ))  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET group_key = :k WHERE id = :i"),
            {"i": inv, "k": '[["user.name","keyname"]]'},
        )
        await conn.execute(
            text("UPDATE dossiers SET body = body || CAST(:b AS jsonb)"
                 " WHERE investigation_id = :i"),
            {"i": inv, "b": '{"context": {"pack": {"fields": {"host.name":'
                            ' {"top": [["fieldname", 3]]}}}}}'},
        )  # fmt: skip
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4)
    await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert await asked(transport) == ["plain.c2.com"]


async def test_a_name_one_investigation_scrubs_is_not_asked_for_another_that_holds_it_too(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    """The same string is one indicator: if any investigation that holds it would have a campus
    name scrubbed from it, it is not sent."""
    await make(migrated_engine, host=1, hours=1, dest=(
        ("user", "bob"), ("domain", "shared.c2.com"), ("domain", "carol.c2.com"),
    ))  # fmt: skip
    await make(migrated_engine, host=2, hours=2, dest=(
        ("user", "carol"), ("domain", "carol.c2.com"),
    ))  # fmt: skip
    await evaluate(app_engine)
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4, prefetch_batch=4)
    await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    # carol.c2.com is fine for the first investigation, whose user is bob, and not for the
    # second, whose user is carol
    assert await asked(transport) == ["shared.c2.com"]


async def test_a_lookup_given_a_campus_checks_it_before_any_request(
    make_outside: Make, app_engine: AsyncEngine
) -> None:
    from argus.llm.detect import OwnSpace

    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    mine = OwnSpace(domains=("example.edu",), users=frozenset({"jsmith"}))
    refused = await outside.lookup("virustotal", "domain", "jsmith.c2.com", ours=mine)
    assert (refused.status, refused.reason) == (
        service.REFUSED, "never looked up outside: a campus name",
    )  # fmt: skip
    assert transport.sent == []
    assert await rows(app_engine, "SELECT * FROM outside_requests") == []
    assert (await outside.lookup("virustotal", "domain", "jsmith.c2.com")).status == service.FETCHED


# -- indicators that fail ----------------------------------------------------------------------


async def test_indicators_that_keep_failing_do_not_take_every_pass_and_the_day(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    for n in range(1, 6):
        await make(migrated_engine, host=n, dest=(("ip", f"45.33.32.{n}"),), hours=n)
    await evaluate(app_engine)
    bad = {"45.33.32.1", "45.33.32.2", "45.33.32.3"}
    transport = Transport(
        lambda r: json_reply(500) if r.url.rsplit("/", 1)[1] in bad else json_reply(200, VT_CLEAN)
    )
    outside = make_outside(transport, virustotal_per_minute=4)

    first = await prefetch.run(app_engine, outside, NO_SHARED, clock.now)
    assert (first.asked, first.failed) == (3, 3)  # the three most urgent fail ...
    clock.advance(minutes=2)
    second = await prefetch.run(app_engine, outside, NO_SHARED, clock.now)
    assert (second.asked, second.failed, second.not_found + second.found) == (2, 0, 2)
    assert await asked(transport) == [
        f"45.33.32.{n}" for n in (1, 2, 3, 4, 5)
    ]  # ... and it moves on
    clock.advance(minutes=2)
    idle = await prefetch.run(app_engine, outside, NO_SHARED, clock.now)
    assert (idle.asked, idle.picked) == (0, [])  # failed lately, or answered: nothing to ask
    assert len(transport.sent) == 5

    # an error is never "no record" and never clean: no answer, no fact, no flag
    stored = await rows(app_engine, "SELECT indicator FROM outside_lookups ORDER BY indicator")
    assert [r.indicator for r in stored] == ["45.33.32.4", "45.33.32.5"]
    failed_inv = await _one(app_engine, "45.33.32.1")
    async with app_engine.connect() as conn:
        assert (
            await read.facts_for(conn, [failed_inv], clock.now, VIEW.window, VIEW.threshold) == {}
        )

    clock.advance(hours=6)  # the backoff is over: the three are tried again, once each
    again = await prefetch.run(app_engine, outside, NO_SHARED, clock.now)
    assert (again.asked, again.failed) == (3, 3)
    assert len(transport.sent) == 8
    day = await rows(app_engine, "SELECT count(*) AS n FROM outside_requests"
                                 " WHERE purpose = 'prefetch'")  # fmt: skip
    assert day[0].n == 8  # not 300: a failing indicator costs a try every six hours


async def _one(engine: AsyncEngine, value: str) -> uuid.UUID:
    found = await rows(engine, "SELECT investigation_id FROM investigation_entities"
                               " WHERE kind = 'ip' AND value = :v", v=value)  # fmt: skip
    return uuid.UUID(str(found[0].investigation_id))


async def test_a_failing_indicator_does_not_stop_the_others_in_its_investigation(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    await make(migrated_engine, host=1, dest=(("ip", "45.33.32.1"), ("ip", "45.33.32.2")))
    await evaluate(app_engine)
    transport = Transport(
        lambda r: json_reply(500) if r.url.endswith(".1") else json_reply(200, VT_CLEAN)
    )
    outside = make_outside(transport, virustotal_per_minute=4)
    report = await prefetch.run(app_engine, outside, NO_SHARED, NOW)
    assert (report.asked, report.failed, report.not_found) == (2, 1, 0)
    assert report.found == 1


# -- how long an answer is kept ----------------------------------------------------------------


async def test_a_clean_answer_is_asked_again_after_a_day_and_a_detection_after_a_week(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    await make(migrated_engine, host=1, dest=(("ip", "45.33.32.1"),), hours=1)
    await make(migrated_engine, host=2, dest=(("ip", DEST),), hours=2)
    await evaluate(app_engine)
    transport = Transport(lambda r: json_reply(200, VT_BAD if r.url.endswith(DEST) else VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4, prefetch_batch=4)
    assert (await prefetch.run(app_engine, outside, NO_SHARED, clock.now)).asked == 2
    clock.advance(hours=23)
    assert (await prefetch.run(app_engine, outside, NO_SHARED, clock.now)).picked == []
    clock.advance(hours=2)  # a day and an hour: the clean one is looked at again, once
    again = await prefetch.run(app_engine, outside, NO_SHARED, clock.now)
    assert again.picked == [("ip", "45.33.32.1")]
    assert again.asked == 1
    assert await asked(transport) == ["45.33.32.1", DEST, "45.33.32.1"]  # the detection waits


# -- the decision engine ------------------------------------------------------------------------


async def test_a_detection_in_the_cache_blocks_a_benign_key_of_the_decision_engine(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inv = await make(migrated_engine, signals=())
    key = ("steps", "R", "1:answered")
    labels = [engine.Label("benign_expected", NOW - timedelta(days=1)) for _ in range(5)]
    learned = engine.Learned()
    learned.by_key[key] = labels
    steps = {
        "facts": {"rule_name": "R"},
        "report": {"steps": [{"number": 1, "status": "answered"}]},
        "signals": [{"name": "ti.listed", "status": "known", "value": 0}],
    }
    async with app_engine.connect() as conn:
        plain = await engine.Engine(learned, NOW, VIEW).assess(conn, inv, steps)
    await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", DEST)
    async with app_engine.connect() as conn:
        blocked = await engine.Engine(learned, NOW, VIEW).assess(conn, inv, steps)
        unaware = await engine.Engine(learned, NOW).assess(conn, inv, steps)
    assert "flagged by outside threat intel" not in plain.reasons[-1]
    assert blocked.outcome is None
    assert "flagged by outside threat intel" in blocked.reasons[-1]
    assert "flagged by outside threat intel" not in unaware.reasons[-1]


async def test_attach_gives_an_item_the_cached_facts_of_its_external_indicators_only(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make
) -> None:
    inv = await make(migrated_engine, dest=(("ip", DEST), ("ip", "45.33.32.1")))
    other = await make(migrated_engine, host=2, dest=(("ip", "45.33.32.2"),))
    outside = make_outside(Transport(json_reply(200, VT_BAD)), virustotal_per_minute=4)
    await outside.lookup("virustotal", "ip", DEST)
    await outside.lookup("virustotal", "ip", "45.33.32.2")
    async with app_engine.connect() as conn:
        item = await outside.attach(conn, inv, {"facts": {}})
        none = await outside.attach(conn, uuid.uuid4(), {"facts": {}})
        theirs = await outside.attach(conn, other, {"facts": {}})
    assert [(f["value"], f["flagged"]) for f in item["outside"]] == [(DEST, True)]
    assert [f["value"] for f in theirs["outside"]] == ["45.33.32.2"]
    assert none == {"facts": {}}
    assert (
        facts.describe(item["outside"][0])
        == "VirusTotal: 7 of 94 engines flag this IP, 1 more call it suspicious"
    )
    assert isinstance(service.Outside.attach, Callable)  # type: ignore[arg-type]
