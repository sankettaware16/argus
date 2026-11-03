"""AR3 (D-165) against the database, as the runtime login: an outside lookup is refused for
anything of the campus, answered from the 7-day cache, kept to each source's limits, stopped by
a 429, and ledgered without a key or an indicator. Nothing reaches the network: the transport is
scripted.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.outside import service, store
from argus.outside.providers import TransportError
from argus.outside.service import Outside
from tests.integration.cases.conftest import rows
from tests.integration.outside.conftest import (
    KEYS,
    SHODAN_HOST,
    VT_BAD,
    VT_CLEAN,
    Clock,
    Transport,
    json_reply,
)

pytestmark = pytest.mark.integration
IP = "45.33.32.156"
Make = Callable[..., Outside]


async def ledger(engine: AsyncEngine) -> list[tuple[str, str, str, str, int | None, int | None]]:
    got = await rows(engine, "SELECT source, kind, purpose, outcome, http_status, answer_bytes"
                             " FROM outside_requests ORDER BY id")  # fmt: skip
    return [tuple(r) for r in got]  # type: ignore[misc]


# -- the answer and the cache -------------------------------------------------------------------


async def test_a_lookup_asks_once_and_keeps_the_answer_for_the_window(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    transport = Transport(json_reply(200, VT_BAD))
    outside = make_outside(transport)
    first = await outside.lookup("virustotal", "ip", IP)
    assert (first.status, first.answer_status) == (service.FETCHED, "found")
    assert first.answer["malicious"] == 7
    assert first.answer["engines"] == 94
    assert [r.url for r in transport.sent] == [
        f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"
    ]
    clock.advance(days=6, hours=23)
    again = await outside.lookup("virustotal", "ip", IP)
    assert (again.status, again.answer) == (service.CACHED, first.answer)
    assert len(transport.sent) == 1  # never twice inside the window
    assert len(await ledger(app_engine)) == 1  # a cache hit is no request
    clock.advance(hours=2)  # past 7 days
    third = await outside.lookup("virustotal", "ip", IP)
    assert third.status == service.FETCHED
    assert len(transport.sent) == 2


async def test_no_record_is_kept_a_day_and_a_detection_the_whole_window(
    make_outside: Make, clock: Clock
) -> None:
    """So that a fresh server nobody flags yet is looked at again, and a known one is not."""
    quiet, bad = "45.33.32.1", "45.33.32.2"
    transport = Transport(
        lambda r: json_reply(404) if r.url.endswith(quiet) else json_reply(200, VT_BAD)
    )
    outside = make_outside(transport, virustotal_per_minute=4)
    await outside.lookup("virustotal", "ip", quiet)
    await outside.lookup("virustotal", "ip", bad)
    clock.advance(hours=23)
    assert (await outside.lookup("virustotal", "ip", quiet)).status == service.CACHED
    assert len(transport.sent) == 2
    clock.advance(hours=2)  # past a day
    again = await outside.lookup("virustotal", "ip", quiet)
    assert again.status == service.FETCHED
    assert (await outside.lookup("virustotal", "ip", bad)).status == service.CACHED
    clock.advance(days=5, hours=22)  # 6 days 23 hours after the detection
    assert (await outside.lookup("virustotal", "ip", bad)).status == service.CACHED
    clock.advance(hours=2)
    assert (await outside.lookup("virustotal", "ip", bad)).status == service.FETCHED


@pytest.mark.parametrize(
    ("reply", "kept"),
    [(json_reply(200, VT_CLEAN), "a day"), (json_reply(404), "a day"),
     (json_reply(200, {"data": {"attributes": {"last_analysis_stats": {
         "malicious": 2, "suspicious": 0, "harmless": 70, "undetected": 22}}}}), "a day"),
     (json_reply(200, {"data": {"attributes": {"last_analysis_stats": {}}}}), "a day"),
     (json_reply(200, VT_BAD), "the window")],
)  # fmt: skip
async def test_virustotal_answers_that_are_no_detection_are_kept_a_day(
    make_outside: Make, clock: Clock, reply: object, kept: str
) -> None:
    transport = Transport(reply)  # type: ignore[arg-type]
    outside = make_outside(transport)
    await outside.lookup("virustotal", "ip", IP)
    clock.advance(days=2)
    got = await outside.lookup("virustotal", "ip", IP)
    assert got.status == (service.FETCHED if kept == "a day" else service.CACHED)


async def test_a_servers_description_is_kept_the_whole_window_and_no_record_a_day(
    make_outside: Make, clock: Clock
) -> None:
    transport = Transport(json_reply(200, SHODAN_HOST), json_reply(404))
    outside = make_outside(transport, "shodan")
    await outside.lookup("shodan", "ip", "45.33.32.1")
    await outside.lookup("shodan", "ip", "45.33.32.2")
    clock.advance(days=2)
    assert (await outside.lookup("shodan", "ip", "45.33.32.1")).status == service.CACHED
    assert (await outside.lookup("shodan", "ip", "45.33.32.2")).status == service.FETCHED


async def test_the_clean_window_is_a_setting_and_never_longer_than_the_window(
    make_outside: Make, clock: Clock
) -> None:
    transport = Transport(json_reply(404))
    outside = make_outside(transport, clean_cache_window="2h")
    await outside.lookup("virustotal", "ip", IP)
    clock.advance(hours=1, minutes=59)
    assert (await outside.lookup("virustotal", "ip", IP)).status == service.CACHED
    clock.advance(minutes=2)
    assert (await outside.lookup("virustotal", "ip", IP)).status == service.FETCHED
    assert outside.view.clean_window == timedelta(hours=2)
    short = make_outside(transport, cache_window="6h", clean_cache_window="6h")
    assert short.view.clean_window == short.view.window == timedelta(hours=6)


async def test_the_spelling_does_not_matter_to_the_cache(make_outside: Make) -> None:
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    await outside.lookup("virustotal", "domain", "Evil-C2.COM.")
    got = await outside.lookup("virustotal", "domain", "evil-c2.com")
    assert got.status == service.CACHED
    assert len(transport.sent) == 1


async def test_no_record_is_cached_too(make_outside: Make) -> None:
    transport = Transport(json_reply(404, {"error": {"code": "NotFoundError"}}))
    outside = make_outside(transport)
    first = await outside.lookup("virustotal", "ip", IP)
    assert (first.status, first.answer_status) == (service.FETCHED, "not_found")
    again = await outside.lookup("virustotal", "ip", IP)
    assert (again.status, again.answer_status) == (service.CACHED, "not_found")
    assert len(transport.sent) == 1
    assert not first.fact(3)["flagged"]  # type: ignore[index]


async def test_the_same_indicator_asked_at_once_is_asked_of_the_source_once(
    make_outside: Make,
) -> None:
    transport = Transport(json_reply(200, VT_BAD))
    outside = make_outside(transport, virustotal_per_minute=4)
    got = await asyncio.gather(*(outside.lookup("virustotal", "ip", IP) for _ in range(6)))
    assert sorted(g.status for g in got) == [service.CACHED] * 5 + [service.FETCHED]
    assert len(transport.sent) == 1


async def test_the_cache_is_per_source_and_kind(make_outside: Make) -> None:
    transport = Transport(json_reply(200, VT_CLEAN), json_reply(200, SHODAN_HOST))
    outside = make_outside(transport, "virustotal", "shodan")
    await outside.lookup("virustotal", "ip", IP)
    got = await outside.lookup("shodan", "ip", IP)
    assert got.status == service.FETCHED
    assert got.answer["ports"] == [22, 80]
    assert [r.url.split("/")[2] for r in transport.sent] == ["www.virustotal.com", "api.shodan.io"]


# -- never the campus ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "value"),
    [("ip", "10.20.3.4"), ("ip", "192.168.1.1"), ("ip", "127.0.0.1"), ("ip", "198.51.100.7"),
     ("ip", "fe80::1"), ("domain", "www.example.edu"), ("domain", "printer.local"),
     ("domain", "localhost"), ("url", "http://10.1.2.3/x"), ("url", "http://mail.example.edu/"),
     ("ip", "not an address"), ("hash", "xyz"), ("mac", "aa:bb:cc:dd:ee:ff")],
)  # fmt: skip
async def test_a_campus_private_or_unreadable_indicator_is_never_looked_up(
    make_outside: Make, app_engine: AsyncEngine, kind: str, value: str
) -> None:
    transport = Transport()
    outside = make_outside(transport)
    got = await outside.lookup("virustotal", kind, value)
    assert got.status == service.REFUSED
    assert not got.has_answer
    assert transport.sent == []
    assert await ledger(app_engine) == []
    assert await rows(app_engine, "SELECT * FROM outside_lookups") == []


async def test_a_source_does_not_take_every_kind(make_outside: Make) -> None:
    transport = Transport()
    outside = make_outside(transport, "virustotal", "shodan", "censys")
    for source in ("shodan", "censys"):
        got = await outside.lookup(source, "domain", "evil-c2.com")
        assert got.status == service.REFUSED
    assert (await outside.lookup("bing", "ip", IP)).status == service.REFUSED
    assert transport.sent == []


async def test_a_source_without_a_key_is_off(make_outside: Make, app_engine: AsyncEngine) -> None:
    transport = Transport()
    outside = make_outside(transport, "virustotal", shodan_internetdb=False)
    got = await outside.lookup("shodan", "ip", IP)
    assert (got.status, got.reason) == (service.OFF, "Shodan is off (no key)")
    assert not outside.on("shodan")
    assert outside.on("virustotal")
    got = await outside.lookup("censys", "ip", IP)
    assert (got.status, got.reason) == (service.OFF, "Censys is off (no key)")
    assert transport.sent == []
    assert await ledger(app_engine) == []


INTERNETDB = {
    "cpes": ["cpe:/a:apache:http_server:2.4.41"], "hostnames": ["srv1.hosting.net"], "ip": IP,
    "ports": [80, 443], "tags": ["cloud"], "vulns": ["CVE-2021-23017"],
}  # fmt: skip


async def test_shodan_without_a_key_asks_its_free_internetdb(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    """D-168: the user's Shodan key is on the free plan (no host lookups); the source answers from
    InternetDB, which needs no key, under the same limits and the same ledger."""
    transport = Transport(json_reply(200, INTERNETDB))
    outside = make_outside(transport, "virustotal")  # no Shodan key; the database is on
    assert outside.on("shodan")
    got = await outside.lookup("shodan", "ip", IP)
    assert (got.status, got.answer_status) == (service.FETCHED, "found")
    assert got.answer["ports"] == [80, 443]
    assert got.answer["products"] == ["http server 2.4.41"]
    assert [r.url for r in transport.sent] == [f"https://internetdb.shodan.io/{IP}"]
    assert dict(transport.sent[0].headers) == {}
    assert dict(transport.sent[0].params) == {}
    again = await outside.lookup("shodan", "ip", IP)
    assert again.status == service.CACHED
    assert len(transport.sent) == 1
    assert (await ledger(app_engine))[0][:4] == ("shodan", "ip", "agent", "ok")
    clock.advance(seconds=2)
    missing = Transport(json_reply(404, {"detail": "No information available"}))
    outside = make_outside(missing, "virustotal")
    nothing = await outside.lookup("shodan", "ip", "45.33.32.157")
    assert (nothing.status, nothing.answer_status) == (service.FETCHED, "not_found")


async def test_a_shodan_key_keeps_the_keyed_host_lookup(make_outside: Make) -> None:
    transport = Transport(json_reply(200, SHODAN_HOST))
    outside = make_outside(transport, "virustotal", "shodan")
    got = await outside.lookup("shodan", "ip", IP)
    assert got.status == service.FETCHED
    (sent,) = transport.sent
    assert sent.url == f"https://api.shodan.io/shodan/host/{IP}"
    assert dict(sent.params) == {"key": KEYS["shodan"]}


async def test_internetdb_off_means_shodan_off_and_its_limits_are_shodans(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    transport = Transport(json_reply(200, INTERNETDB))
    outside = make_outside(transport, "virustotal", shodan_per_day=2)
    for n in range(2):
        got = await outside.lookup("shodan", "ip", f"45.33.32.{n + 1}")
        assert got.status == service.FETCHED
        clock.advance(seconds=2)
    third = await outside.lookup("shodan", "ip", "45.33.32.9")
    assert third.status == service.BLOCKED  # 200 a day is the setting, kept like the keyed path's
    assert len(transport.sent) == 2


async def test_an_out_of_date_cached_answer_is_asked_again_when_the_caller_says_so(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    transport = Transport(json_reply(200, VT_BAD))
    outside = make_outside(transport)
    await outside.lookup("virustotal", "domain", "evil-c2.com")
    assert len(transport.sent) == 1
    same = await outside.lookup("virustotal", "domain", "evil-c2.com", fresh=lambda st, a: True)
    assert same.status == service.CACHED
    assert len(transport.sent) == 1
    clock.advance(seconds=30)
    older = await outside.lookup("virustotal", "domain", "evil-c2.com",
                                 fresh=lambda st, a: a.get("shape") == 99)  # fmt: skip
    assert older.status == service.FETCHED
    assert len(transport.sent) == 2


# -- limits and stops ---------------------------------------------------------------------------


async def test_virustotal_is_kept_to_three_a_minute_below_the_plans_four(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine
) -> None:
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    for n in range(3):
        got = await outside.lookup("virustotal", "ip", f"45.33.32.{n + 1}")
        assert got.status == service.FETCHED
        clock.advance(seconds=10)
    fourth = await outside.lookup("virustotal", "ip", "45.33.32.9")
    assert fourth.status == service.BLOCKED
    assert fourth.until == clock.now + timedelta(seconds=30)
    assert "has room again" in fourth.reason
    assert len(transport.sent) == 3
    clock.advance(seconds=31)  # the oldest request has left the minute
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.FETCHED
    assert len(await ledger(app_engine)) == 4  # a blocked lookup is no request


async def test_virustotal_may_be_set_to_the_plans_four_a_minute(
    make_outside: Make, clock: Clock
) -> None:
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4)
    for n in range(4):
        assert (
            await outside.lookup("virustotal", "ip", f"45.33.32.{n + 1}")
        ).status == service.FETCHED
        clock.advance(seconds=10)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.BLOCKED


async def test_the_daily_limit_holds_until_midnight_utc(make_outside: Make, clock: Clock) -> None:
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_day=3)
    for n in range(3):
        assert (
            await outside.lookup("virustotal", "ip", f"45.33.32.{n + 1}")
        ).status == service.FETCHED
        clock.advance(minutes=2)
    blocked = await outside.lookup("virustotal", "ip", "45.33.32.9")
    assert blocked.status == service.BLOCKED
    assert blocked.until == clock.now.replace(
        hour=0, minute=0, second=0, microsecond=0
    ) + timedelta(days=1)
    clock.advance(days=1)
    clock.now = clock.now.replace(hour=0, minute=1)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.FETCHED


async def test_censys_keeps_to_its_monthly_budget(make_outside: Make, clock: Clock) -> None:
    transport = Transport(json_reply(200, {"result": {"resource": {"services": [{"port": 22}]}}}))
    outside = make_outside(transport, "censys", censys_per_month=2, censys_per_day=2)
    assert (await outside.lookup("censys", "ip", "45.33.32.1")).status == service.FETCHED
    assert (await outside.lookup("censys", "ip", "45.33.32.2")).status == service.FETCHED
    clock.advance(days=1, hours=1)  # a new day, the same month
    got = await outside.lookup("censys", "ip", "45.33.32.3")
    assert got.status == service.BLOCKED
    assert got.until.month == 11
    assert len(transport.sent) == 2


async def test_shodan_waits_a_second_between_requests(make_outside: Make, clock: Clock) -> None:
    transport = Transport(json_reply(200, SHODAN_HOST))
    outside = make_outside(transport, "shodan")
    await outside.lookup("shodan", "ip", "45.33.32.1")
    got = await outside.lookup("shodan", "ip", "45.33.32.2")  # the same instant: it waits
    assert got.status == service.FETCHED
    assert clock.slept == [store.SPACING]
    assert len(transport.sent) == 2


async def test_shodans_second_has_a_margin_for_the_gap_between_reserving_and_sending(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine
) -> None:
    """The ledger holds the time a request was reserved. Reserved a full second apart, two
    requests may still be sent less than a second apart: they wait the margin too."""
    transport = Transport(json_reply(200, SHODAN_HOST))
    outside = make_outside(transport, "shodan")
    await outside.lookup("shodan", "ip", "45.33.32.1")
    clock.advance(seconds=1)
    got = await outside.lookup("shodan", "ip", "45.33.32.2")
    assert got.status == service.FETCHED
    assert clock.slept == [pytest.approx(store.SPACING - 1)]
    times = [r.at for r in await rows(app_engine, "SELECT at FROM outside_requests ORDER BY id")]
    assert (times[1] - times[0]).total_seconds() >= store.SPACING


async def test_the_prefetch_has_a_daily_budget_of_its_own(make_outside: Make) -> None:
    transport = Transport(json_reply(200, VT_CLEAN))
    outside = make_outside(transport, virustotal_per_minute=4)
    for n in range(2):
        got = await outside.lookup("virustotal", "ip", f"45.33.32.{n + 1}", purpose="prefetch",
                                   day_cap=2)  # fmt: skip
        assert got.status == service.FETCHED
    capped = await outside.lookup("virustotal", "ip", "45.33.32.3", purpose="prefetch", day_cap=2)
    assert capped.status == service.BLOCKED
    assert "budget" in capped.reason
    free = await outside.lookup("virustotal", "ip", "45.33.32.3", purpose="agent")
    assert free.status == service.FETCHED  # the investigator's allowance is untouched


async def test_a_429_with_the_daily_limit_used_stops_virustotal_for_the_rest_of_the_day(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    transport = Transport(json_reply(429, {"error": {"code": "QuotaExceededError"}}),
                          json_reply(200, VT_CLEAN))  # fmt: skip
    outside = make_outside(transport, virustotal_per_day=1)  # this request is the day's last
    with caplog.at_level(logging.INFO, logger="argus.outside"):
        first = await outside.lookup("virustotal", "ip", IP)
    assert first.status == service.BLOCKED
    midnight = clock.now.replace(hour=0, minute=0) + timedelta(days=1)
    assert first.until == midnight  # the ledger shows the day's quota spent
    (row,) = await rows(
        app_engine, "SELECT outcome, http_status, stopped_until FROM outside_requests"
    )
    assert (row.outcome, row.http_status, row.stopped_until) == ("limited", 429, midnight)
    clock.advance(hours=2)
    again = await outside.lookup("virustotal", "ip", "45.33.32.9")
    assert again.status == service.BLOCKED
    assert "is stopped until 00:00 UTC" in again.reason
    assert len(transport.sent) == 1  # nothing was asked of a stopped source
    clock.now = midnight + timedelta(minutes=1)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.FETCHED
    assert "429" in caplog.text
    assert IP not in caplog.text
    assert KEYS["virustotal"] not in caplog.text


async def test_a_429_without_retry_after_stops_virustotal_for_an_hour_not_the_day(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine
) -> None:
    """A 429 is as likely the minute's limit (or a busy hour) as the day's: the ledger says the
    day's limit is far from used, so the stop is short."""
    transport = Transport(json_reply(429, {"error": {"code": "QuotaExceededError"}}),
                          json_reply(200, VT_CLEAN))  # fmt: skip
    outside = make_outside(transport)
    first = await outside.lookup("virustotal", "ip", IP)
    assert first.status == service.BLOCKED
    assert first.until == clock.now + service.VIRUSTOTAL_STOP == clock.now + timedelta(hours=1)
    (row,) = await rows(app_engine, "SELECT stopped_until FROM outside_requests")
    assert row.stopped_until == first.until
    clock.advance(minutes=59)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.BLOCKED
    assert len(transport.sent) == 1
    clock.advance(minutes=2)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.FETCHED


async def test_a_retry_after_of_zero_means_now_not_unset(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine
) -> None:
    transport = Transport(json_reply(429, {}, retry="0"), json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    first = await outside.lookup("virustotal", "ip", IP)
    assert (first.status, first.until) == (service.BLOCKED, clock.now)  # a stop that has ended
    (row,) = await rows(app_engine, "SELECT outcome, stopped_until FROM outside_requests")
    assert (row.outcome, row.stopped_until) == ("limited", clock.now)
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.FETCHED


@pytest.mark.parametrize("value", ["\u00b2", "9" * 5_000, "tomorrow", "-1"])
async def test_a_retry_after_that_is_not_a_number_is_still_a_stop(
    make_outside: Make, clock: Clock, value: str
) -> None:
    """Never a crash: a number past a day counts as a day, anything unreadable as none."""
    transport = Transport(json_reply(429, {}, retry=value), json_reply(200, VT_CLEAN))
    got = await make_outside(transport).lookup("virustotal", "ip", IP)
    assert got.status == service.BLOCKED
    assert got.until is not None
    expected = timedelta(days=1) if value[0] == "9" else service.VIRUSTOTAL_STOP
    assert got.until == clock.now + expected


async def test_a_retry_after_sets_the_stop(make_outside: Make, clock: Clock) -> None:
    transport = Transport(json_reply(429, {}, retry="90"), json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    first = await outside.lookup("virustotal", "ip", IP)
    assert first.until == clock.now + timedelta(seconds=90)
    clock.advance(seconds=91)
    assert (await outside.lookup("virustotal", "ip", IP)).status == service.FETCHED


async def test_shodans_429_clears_in_minutes_and_censys_stops_for_the_month(
    make_outside: Make, clock: Clock
) -> None:
    shodan = make_outside(Transport(json_reply(429)), "shodan")
    got = await shodan.lookup("shodan", "ip", IP)
    assert got.until == clock.now + service.SHODAN_STOP
    censys = make_outside(Transport(json_reply(429)), "censys")
    got = await censys.lookup("censys", "ip", IP)
    assert got.until is not None
    assert (got.until.month, got.until.day) == (11, 1)


async def test_a_key_the_source_refuses_stops_it_for_an_hour(
    make_outside: Make, clock: Clock, app_engine: AsyncEngine
) -> None:
    transport = Transport(json_reply(401), json_reply(200, VT_CLEAN))
    outside = make_outside(transport)
    got = await outside.lookup("virustotal", "ip", IP)
    assert (got.status, got.reason) == (service.BLOCKED, "VirusTotal did not accept its key")
    assert got.until == clock.now + service.REFUSED_STOP
    assert (await outside.lookup("virustotal", "ip", "45.33.32.9")).status == service.BLOCKED
    assert len(transport.sent) == 1
    assert (await ledger(app_engine))[0][3:5] == ("error", 401)


async def test_a_failure_is_not_cached_and_is_tried_again_after_the_backoff(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    transport = Transport(TransportError("deadline"), json_reply(500), json_reply(200, VT_BAD))
    outside = make_outside(transport, virustotal_per_minute=4)
    failed_at = clock.now
    with caplog.at_level(logging.INFO, logger="argus.outside"):
        one = await outside.lookup("virustotal", "ip", IP)
        assert outside.failed_lately("virustotal", "ip", IP)
        soon = await outside.lookup("virustotal", "ip", IP)  # not hammered: no request
        clock.advance(hours=6, seconds=1)
        assert not outside.failed_lately("virustotal", "ip", IP)
        two = await outside.lookup("virustotal", "ip", IP)
        clock.advance(hours=6, seconds=1)
        three = await outside.lookup("virustotal", "ip", IP)
    assert (one.status, two.status) == (service.FAILED, service.FAILED)
    assert soon.status == service.RETRY_LATER
    assert soon.until is not None
    assert soon.until == failed_at + timedelta(hours=6)
    assert "not asked again before" in soon.reason
    assert not soon.has_answer  # an error is never "no record" and never clean
    assert three.status == service.FETCHED
    assert await rows(app_engine, "SELECT indicator FROM outside_lookups") != []
    assert [r[3] for r in await ledger(app_engine)] == ["error", "error", "ok"]
    assert not outside.failed_lately("virustotal", "ip", IP)  # an answer clears it
    assert IP not in caplog.text
    assert KEYS["virustotal"] not in caplog.text


async def test_a_failure_leaves_no_cache_row_and_no_answer(
    make_outside: Make, app_engine: AsyncEngine
) -> None:
    outside = make_outside(Transport(json_reply(500)))
    got = await outside.lookup("virustotal", "ip", IP)
    assert (got.status, got.answer_status, got.fact(3)) == (service.FAILED, None, None)
    assert await rows(app_engine, "SELECT * FROM outside_lookups") == []
    again = await outside.lookup("virustotal", "ip", IP)
    assert (again.status, again.answer_status, again.fact(3)) == (service.RETRY_LATER, None, None)


async def test_the_remembered_failures_are_bounded_and_forgotten_when_over(
    make_outside: Make, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "MAX_FAILED", 3)
    outside = make_outside(Transport(json_reply(500)), virustotal_per_minute=4)
    for n in range(3):
        await outside.lookup("virustotal", "ip", f"45.33.32.{n + 1}")
        clock.advance(seconds=1)
    outside._failure("virustotal", "ip", "45.33.32.9", clock.now)
    assert len(outside._failed) == 3  # the oldest went
    assert not outside.failed_lately("virustotal", "ip", "45.33.32.1")
    assert outside.failed_lately("virustotal", "ip", "45.33.32.9")
    clock.advance(hours=7)
    outside._failure("virustotal", "ip", "45.33.32.8", clock.now)
    assert list(outside._failed) == [("virustotal", "ip", "45.33.32.8")]  # the ended ones went


async def test_a_reply_that_cannot_be_read_is_a_failure_not_an_answer(
    make_outside: Make, app_engine: AsyncEngine
) -> None:
    transport = Transport(json_reply(200, {"data": 5}))
    got = await make_outside(transport).lookup("virustotal", "ip", IP)
    assert got.status == service.FAILED
    assert "gave no usable answer" in got.reason
    assert await rows(app_engine, "SELECT * FROM outside_lookups") == []


async def test_any_exception_of_the_transport_is_a_failure_with_its_type_and_nothing_else(
    make_outside: Make, app_engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    secret_url = f"https://api.shodan.io/shodan/host/{IP}?key={KEYS['shodan']}"
    transport = Transport(RuntimeError(f"boom at {secret_url}"))
    outside = make_outside(transport, "shodan")
    with caplog.at_level(logging.INFO, logger="argus.outside"):
        got = await outside.lookup("shodan", "ip", IP)
    assert (got.status, got.reason) == (service.FAILED, "Shodan did not answer")
    assert "RuntimeError" in caplog.text
    assert KEYS["shodan"] not in caplog.text
    assert IP not in caplog.text
    assert [r[3] for r in await ledger(app_engine)] == ["error"]  # counted, not left reserved


async def test_a_parser_that_raises_is_a_failure_not_a_crash(
    make_outside: Make, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.outside import providers

    def boom(self: object, kind: str, reply: object) -> object:
        raise ValueError("unexpected shape")

    monkeypatch.setattr(providers.VirusTotal, "parse", boom)
    got = await make_outside(Transport(json_reply(200, VT_BAD))).lookup("virustotal", "ip", IP)
    assert got.status == service.FAILED


# -- the ledger ---------------------------------------------------------------------------------


async def test_the_ledger_has_time_source_kind_and_size_and_neither_key_nor_indicator(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    transport = Transport(json_reply(200, VT_BAD))
    outside = make_outside(transport)
    await outside.lookup("virustotal", "ip", IP)
    await outside.lookup("virustotal", "domain", "evil-c2.com", purpose="prefetch")
    got = await rows(app_engine, "SELECT * FROM outside_requests ORDER BY id")
    assert [(r.at, r.source, r.kind, r.purpose, r.outcome, r.http_status) for r in got] == [
        (clock.now, "virustotal", "ip", "agent", "ok", 200),
        (clock.now, "virustotal", "domain", "prefetch", "ok", 200),
    ]  # fmt: skip
    size = len(transport.replies[0].body)
    assert [r.answer_bytes for r in got] == [size, size]
    assert size > 0
    dump = " ".join(str(tuple(r)) for r in got)
    assert IP not in dump
    assert "evil-c2.com" not in dump
    assert KEYS["virustotal"] not in dump
    assert set(got[0]._fields) == {
        "id", "at", "source", "kind", "purpose", "outcome", "http_status", "answer_bytes",
        "stopped_until",
    }  # fmt: skip


async def test_a_crash_between_reserving_and_finishing_only_ever_over_counts(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    async with app_engine.begin() as conn:  # a request reserved, never finished
        for _ in range(4):
            await store.reserve(conn, "virustotal", "ip", "agent",
                                store.limits_of("virustotal", make_outside(Transport())
                                                .settings), clock.now)  # fmt: skip
    got = await make_outside(Transport()).lookup("virustotal", "ip", IP)
    assert got.status == service.BLOCKED
    assert {r[3] for r in await ledger(app_engine)} == {"reserved"}


async def test_limits_hold_across_processes_and_threads_of_the_same_source(
    app_engine: AsyncEngine, clock: Clock, make_outside: Make
) -> None:
    limits = store.limits_of(
        "virustotal", make_outside(Transport(), virustotal_per_minute=4).settings
    )

    async def take() -> object:
        async with app_engine.begin() as conn:
            return await store.reserve(conn, "virustotal", "ip", "agent", limits, clock.now)

    got = await asyncio.gather(*(take() for _ in range(12)))
    ids = [g for g in got if isinstance(g, int)]
    assert len(ids) == 4
    assert len(set(ids)) == 4
    assert all(isinstance(g, store.Blocked) for g in got if not isinstance(g, int))


# -- upkeep -------------------------------------------------------------------------------------


async def test_old_answers_are_pruned_and_a_fresh_one_is_kept(
    make_outside: Make, app_engine: AsyncEngine, clock: Clock
) -> None:
    outside = make_outside(Transport(json_reply(200, VT_CLEAN)))
    await outside.lookup("virustotal", "ip", "45.33.32.1")
    clock.advance(days=20)
    await outside.lookup("virustotal", "ip", "45.33.32.2")
    clock.advance(days=9)  # the first is 29 days old, four windows are 28
    assert await outside.prune() == 1
    left = await rows(app_engine, "SELECT indicator FROM outside_lookups")
    assert [r.indicator for r in left] == ["45.33.32.2"]


async def test_the_runtime_login_may_do_what_it_needs_and_no_more(
    app_engine: AsyncEngine,
) -> None:
    from sqlalchemy.exc import DBAPIError

    async def refused(sql: str) -> None:
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(sql))

    await refused("DELETE FROM outside_requests")
    await refused("UPDATE outside_requests SET source = 'shodan'")
    await refused("UPDATE outside_requests SET at = now()")
    await refused("UPDATE outside_lookups SET indicator = 'x'")
    await refused("TRUNCATE outside_requests")
