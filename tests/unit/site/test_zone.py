"""P4-D1 part 2, step 1 (D-284): the time zone is ``site.timezone``. On ACME's section (the suite's
own, tests/conftest.py) every time, day and investigation id is what it was; on the neutral
default it is UTC; on another zone it follows that zone."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus import site
from argus.assess.patterns import day_of
from argus.cases import knownview
from argus.grouping import assign as ga
from argus.incident import gather
from argus.incident.words import ist_date, ist_day, ist_moment
from argus.report.render import when as report_when
from argus.responder.machine import ist12
from argus.responder.machine import ist_day as responder_day
from argus.site import QuietHours, SiteSettings
from argus.web import render
from argus.web.cutover import ist as cutover_ist
from argus.writer.render import _when as writer_time

pytestmark = pytest.mark.unit

AT = datetime(2026, 10, 29, 13, 50, tzinfo=UTC)  # 7:20 PM in IST
NEW_YORK = SiteSettings(timezone="America/New_York")
BERLIN = SiteSettings(timezone="Europe/Berlin", timezone_label="CET")
NEUTRAL = SiteSettings()

# Investigation ids, made by the code before the zone was a setting (06e8ab7), for ACME's zone.
# Each: rule, group key, an event time, the bucket's start, its id, the previous id, the next id.
KEY = '[["source.ip","10.1.2.3"]]'
ACME_IDS = [
    (
        "rule-a",
        KEY,
        "2026-01-01T18:29:59+00:00",
        "2025-12-31T18:30:00+00:00",
        "0beca971-8942-55be-b506-993041bc1fd7",
        "582fa91c-2a65-539a-af05-9aeee2c9c0cc",
        "eb9d2182-8e99-50cf-9fb4-e35afc4b2909",
    ),
    (
        "rule-a",
        KEY,
        "2026-01-01T18:30:00+00:00",
        "2026-01-01T18:30:00+00:00",
        "eb9d2182-8e99-50cf-9fb4-e35afc4b2909",
        "0beca971-8942-55be-b506-993041bc1fd7",
        "56cc496d-55ff-5379-b881-785cc364a42a",
    ),
    (
        "rule-a",
        KEY,
        "2026-10-29T13:50:00+00:00",
        "2026-10-28T18:30:00+00:00",
        "6313f932-8a85-5c57-9bc2-d2112e8d04c0",
        "a06a2fcb-7f41-5114-b64c-d0292ba1d4c9",
        "d593ba09-6fcb-563d-9080-fa5805ecb0a8",
    ),
    (
        "rule-b",
        "alert:abc",
        "2026-10-29T18:29:59+00:00",
        "2026-10-28T18:30:00+00:00",
        "400d9b18-7ca7-5353-8f5f-48877b7a5961",
        "c3c84c4c-e832-5309-ba45-53aa7a3e7f78",
        "c51ab257-d54b-5574-a9ec-441fa1804261",
    ),
    (
        "rule-b",
        "alert:abc",
        "2026-10-29T18:30:00+00:00",
        "2026-10-29T18:30:00+00:00",
        "c51ab257-d54b-5574-a9ec-441fa1804261",
        "400d9b18-7ca7-5353-8f5f-48877b7a5961",
        "28d8fdd3-df2b-5503-bf7f-f7ebfdac37f2",
    ),
    (
        "9f1c0c2e-0000-4000-8000-000000000001",
        '[["host.name","h1"],["user.name","u"]]',
        "2025-12-31T20:00:00+00:00",
        "2025-12-31T18:30:00+00:00",
        "9a7b2a98-5951-55c2-9144-e2930848d357",
        "c4f099c9-00fc-5804-a3a8-c96bbebaf402",
        "fe6da70d-db38-54a0-8fb4-db38e6060041",
    ),
    (
        "rule-a",
        KEY,
        "2027-03-31T00:00:00+00:00",
        "2027-03-30T18:30:00+00:00",
        "af73c2f8-ca85-5ddc-8ce1-5f4c458c10de",
        "7cc4d2b3-2bfa-5631-b9b3-f02a3465d5d8",
        "ca8f1c38-33d0-5611-85e5-02fe0a920ba6",
    ),
]


# --------------------------------------------------------------------------- the id anchor


@pytest.mark.parametrize(("rule", "key", "when", "start", "ident", "before", "after"), ACME_IDS)
def test_acmes_investigation_ids_are_byte_for_byte_what_they_were(
    rule: str, key: str, when: str, start: str, ident: str, before: str, after: str
) -> None:
    begin = ga.bucket_start(datetime.fromisoformat(when))
    assert begin.isoformat() == start
    assert str(ga.investigation_id(rule, key, begin)) == ident
    assert str(ga.investigation_id(rule, key, begin - ga.WINDOW)) == before
    assert str(ga.investigation_id(rule, key, begin + ga.WINDOW)) == after


def test_acmes_anchor_is_midnight_ist() -> None:
    assert datetime(2026, 1, 1, 18, 30, tzinfo=UTC) == ga.anchor()


def test_the_anchor_is_midnight_of_the_sites_zone() -> None:
    with site.using(NEUTRAL):
        assert ga.anchor() == datetime(2026, 1, 2, tzinfo=UTC)
    with site.using(NEW_YORK):
        assert ga.anchor() == datetime(2026, 1, 2, 5, tzinfo=UTC)  # 00:00 EST
    with site.using(SiteSettings(timezone="Asia/Kolkata")):
        assert ga.anchor() == datetime(2026, 1, 1, 18, 30, tzinfo=UTC)


@given(
    st.datetimes(
        min_value=datetime(2026, 1, 1),  # noqa: DTZ001
        max_value=datetime(2030, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    )
)
def test_a_bucket_is_the_sites_day_for_a_zone_without_clock_changes(at: datetime) -> None:
    for name in ("Asia/Kolkata", "UTC", "Asia/Tokyo"):
        with site.using(SiteSettings(timezone=name)):
            start = ga.bucket_start(at)
            local = start.astimezone(ZoneInfo(name))
            assert (local.hour, local.minute, local.second) == (0, 0, 0)
            assert start <= at < start + ga.WINDOW


DST_ZONES = (
    "Australia/Sydney", "Australia/Lord_Howe", "Pacific/Chatham", "Pacific/Auckland",
    "America/New_York", "America/Sao_Paulo", "Europe/Berlin", "Europe/Dublin", "Africa/Casablanca",
    "America/St_Johns", "Asia/Tehran", "Asia/Kolkata", "UTC",
)  # fmt: skip


def test_a_dst_zone_names_the_investigation_day_by_the_calendar_day_in_both_seasons() -> None:
    # F2: the bucket was anchored at January's midnight, so in a zone that is ahead in January
    # the winter bucket started at 23:00 the evening before and named the previous day
    sydney = SiteSettings(timezone="Australia/Sydney")
    with site.using(sydney):
        zone = ZoneInfo("Australia/Sydney")
        winter = datetime(2026, 7, 10, 22, 0, tzinfo=zone)  # AEST
        summer = datetime(2026, 12, 10, 22, 0, tzinfo=zone)  # AEDT
        assert ga.anchor() == datetime(2026, 1, 1, 14, 0, tzinfo=UTC)  # 00:00 AEST
        for event in (winter, summer):
            start = ga.bucket_start(event)
            assert day_of(start) == event.date()
            assert start <= event < start + ga.WINDOW
        assert ga.bucket_start(winter).astimezone(zone).hour == 0
        assert ga.bucket_start(summer).astimezone(zone).hour == 1  # one hour past midnight
    with site.using(SiteSettings(timezone="America/New_York")):
        zone = ZoneInfo("America/New_York")
        event = datetime(2026, 7, 10, 8, 0, tzinfo=zone)
        assert day_of(ga.bucket_start(event)) == event.date()
        assert ga.bucket_start(event).astimezone(zone).hour == 1
    with site.using(SiteSettings(timezone="Pacific/Chatham")):
        zone = ZoneInfo("Pacific/Chatham")
        july = datetime(2026, 7, 11, 0, 45, tzinfo=zone)  # standard time: the day starts at 00:00
        assert day_of(ga.bucket_start(july)) == july.date()
        summer = datetime(2026, 12, 11, 0, 45, tzinfo=zone)  # daylight saving: it starts at 01:00
        assert day_of(ga.bucket_start(summer)) == summer.date() - timedelta(days=1)
        later = datetime(2026, 12, 11, 1, 30, tzinfo=zone)
        assert day_of(ga.bucket_start(later)) == later.date()


def test_a_zone_that_is_ahead_in_january_has_the_same_ids_in_winter_and_summer() -> None:
    # the standard offset is the smallest of the year: Sydney +10, New York -5, Dublin 0
    for name, hours in (("Australia/Sydney", 10), ("America/New_York", -5), ("Europe/Dublin", 0),
                        ("Australia/Lord_Howe", 10.5), ("Asia/Kolkata", 5.5)):  # fmt: skip
        assert ga.standard_offset(ZoneInfo(name)) == timedelta(hours=hours), name


@given(
    st.sampled_from(DST_ZONES),
    st.datetimes(
        min_value=datetime(2025, 6, 1),  # noqa: DTZ001
        max_value=datetime(2029, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    ),
)
def test_a_bucket_is_named_by_the_calendar_day_of_its_start_in_any_season(
    name: str, at: datetime
) -> None:
    with site.using(SiteSettings(timezone=name)):
        zone = ZoneInfo(name)
        start = ga.bucket_start(at)
        local = start.astimezone(zone)
        assert start <= at < start + ga.WINDOW
        assert day_of(start) == local.date() == (start + ga.WINDOW / 2).astimezone(zone).date()
        assert (
            timedelta(0)
            <= local.replace(tzinfo=None) - datetime.combine(local.date(), datetime.min.time())
            < timedelta(hours=2, minutes=1)
        )
        event = at.astimezone(zone)
        if event.hour >= 2:  # past the hour or two a daylight-saving bucket starts late
            assert day_of(start) == event.date()
        assert abs((event.date() - day_of(start)).days) <= 1


def test_a_neutral_site_buckets_by_utc_day() -> None:
    with site.using(NEUTRAL):
        assert ga.bucket_start(datetime(2026, 10, 29, 23, 59, tzinfo=UTC)) == datetime(
            2026, 10, 29, tzinfo=UTC
        )
        # the same alert is in another investigation than ACME's
        a = ga.investigation_id("r", "k", ga.bucket_start(AT))
    assert a != uuid.UUID(ACME_IDS[2][4])


# --------------------------------------------------------------------------- rendered times


def test_acmes_times_are_what_they_were() -> None:
    assert render.ist(AT) == "29 Oct 2026, 7:20 PM IST"
    assert cutover_ist(AT) == "2026-10-29 7:20 PM IST"
    assert ist12(AT) == "7:20 PM IST on 29 Oct 2026"
    assert responder_day(AT) == "29 Oct 2026"
    assert ist_moment(AT) == "29 Oct 2026, 7:20 PM IST"
    assert ist_date(AT) == "29 Oct 2026"
    assert ist_day(AT) == "2026-10-29"
    assert report_when(AT) == "29 Oct 19:20 IST"
    assert writer_time(AT.isoformat()) == "2026-10-29 19:20 IST"


def test_the_neutral_site_reads_utc() -> None:
    with site.using(NEUTRAL):
        assert render.ist(AT) == "29 Oct 2026, 1:50 PM UTC"
        assert cutover_ist(AT) == "2026-10-29 1:50 PM UTC"
        assert ist12(AT) == "1:50 PM UTC on 29 Oct 2026"
        assert ist_moment(AT) == "29 Oct 2026, 1:50 PM UTC"
        assert report_when(AT) == "29 Oct 13:50 UTC"
        assert writer_time(AT.isoformat()) == "2026-10-29 13:50 UTC"


def test_another_zone_is_shown_with_the_offset_in_force() -> None:
    winter = datetime(2026, 1, 15, 17, 0, tzinfo=UTC)
    summer = datetime(2026, 7, 15, 17, 0, tzinfo=UTC)
    with site.using(NEW_YORK):
        assert render.ist(winter) == "15 Jan 2026, 12:00 PM UTC-05:00"
        assert render.ist(summer) == "15 Jul 2026, 1:00 PM UTC-04:00"
        assert ist_moment(summer) == "15 Jul 2026, 1:00 PM UTC-04:00"
        assert site.zone_label(summer) == "UTC-04:00"
    with site.using(BERLIN):  # a fixed label wins over the zone's own
        assert render.ist(summer) == "15 Jul 2026, 7:00 PM CET"


def test_an_unlabelled_zone_is_labelled_by_its_offset_as_the_browser_does() -> None:
    # the tz database says CEST, JST, +06; the browser's locale data says GMT+2, GMT+9, GMT+6: the
    # label is the offset on both sides (frontend/src/lib/site.ts) so one instant reads one way
    for zone_name, label in (
        ("Asia/Kathmandu", "UTC+05:45"),
        ("America/Sao_Paulo", "UTC-03:00"),
        ("Europe/Berlin", "UTC+01:00"),
        ("Asia/Tokyo", "UTC+09:00"),
        ("Asia/Dhaka", "UTC+06:00"),
        ("UTC", "UTC"),
        ("Europe/London", "UTC"),
    ):
        with site.using(SiteSettings(timezone=zone_name)):
            assert site.zone_label(datetime(2026, 1, 15, 12, 0, tzinfo=UTC)) == label, zone_name
    with site.using(SiteSettings(timezone="Europe/Berlin")):
        assert site.zone_label(datetime(2026, 7, 15, 12, 0, tzinfo=UTC)) == "UTC+02:00"


@given(
    st.datetimes(
        min_value=datetime(1990, 1, 1),  # noqa: DTZ001
        max_value=datetime(2060, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    )
)
def test_acmes_label_never_changes(at: datetime) -> None:
    assert site.zone_label(at) == "IST"
    assert render.ist(at).endswith(" IST")


# --------------------------------------------------------------------------- SQL days


def test_the_sql_days_name_the_sites_zone() -> None:
    assert site.zone_sql() == "'Asia/Kolkata'"
    assert "AT TIME ZONE 'Asia/Kolkata')::date AS day" in str(knownview._alerts())
    assert str(gather.zoned(gather._ORDER)).count("'Asia/Kolkata'") == 2
    assert gather.ZONE_MARK not in str(gather.zoned(gather._SIGNALS))
    with site.using(NEW_YORK):
        assert "AT TIME ZONE 'America/New_York')::date AS day" in str(knownview._alerts())
        assert "'Asia/Kolkata'" not in str(gather.zoned(gather._DAYS))
        assert "'Asia/Kolkata'" not in str(gather.zoned(gather._INV_DAYS))
        assert "'Asia/Kolkata'" not in str(gather.zoned(gather._SIGNALS))


def test_acmes_sql_is_the_text_it_was() -> None:
    assert str(gather.zoned(gather._ORDER)) == (
        "SELECT count(*) FROM cases WHERE number <= :n"
        " AND (created_at AT TIME ZONE 'Asia/Kolkata')::date"
        " = (CAST(:made AS timestamptz) AT TIME ZONE 'Asia/Kolkata')::date"
    )


@pytest.mark.parametrize("name", ["Asia/Kolkata'; DROP TABLE x; --", "../etc/passwd", "UTC\n", ""])
def test_a_zone_that_could_carry_sql_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match="time zone"):
        SiteSettings(timezone=name)


# --------------------------------------------------------------------------- the settings


def test_the_label_is_text_without_spaces_or_quotes() -> None:
    for bad in ("", "I S T", "IST'", "x" * 13, "1ST"):
        with pytest.raises(ValueError, match="timezone_label"):
            SiteSettings(timezone_label=bad)
    assert SiteSettings(timezone_label="UTC+5:30").timezone_label == "UTC+5:30"


def test_the_defaults_name_no_organisation() -> None:
    s = SiteSettings()
    assert (s.timezone, s.timezone_label, s.own_network_noun) == ("UTC", None, "your network")
    assert (s.organisation.name, s.organisation.short_name) == ("your organisation", "SOC")
    assert s.quiet_hours == QuietHours(start="00:00", end="01:30")


def test_the_session_tells_the_pages_the_sites_words() -> None:
    from argus.web.v1.routes import site_out

    out = site_out()
    assert (out.timezone, out.timezone_label, out.own_network_noun) == (
        "Asia/Kolkata",
        "IST",
        "campus",
    )
    assert (out.organisation_name, out.organisation_short_name) == ("Example University", "ACME")
    with site.using(NEUTRAL):
        out = site_out()
        assert (out.timezone, out.timezone_label, out.own_network_noun) == (
            "UTC",
            None,
            "your network",
        )
        assert "IIT" not in out.model_dump_json()


def test_a_day_is_24_hours_whatever_the_zone() -> None:
    assert timedelta(hours=24) == ga.WINDOW


def _day_turns(at: datetime) -> tuple[object, object]:
    """The investigation day of the second before ``at`` and of ``at`` itself."""
    return (
        day_of(ga.bucket_start(at - timedelta(seconds=1))),
        day_of(ga.bucket_start(at)),
    )


def test_the_investigation_day_turns_at_local_midnight_and_in_dst_zones_at_standard_midnight() -> (
    None
):
    # ACME (no clock changes): the IST day turns at 18:30 UTC, all year (D-289: what the growth
    # signal's day and the report days count from)
    for month in (1, 7, 10):
        turn = datetime(2026, month, 28, 18, 30, tzinfo=UTC)
        before, after = _day_turns(turn)
        assert (before, after) == (turn.date(), turn.date() + timedelta(days=1))
    # Sydney, standard time +10: the turn is 14:00 UTC, which is 00:00 in July and 01:00 in
    # December; the day a bucket is named for is its start's calendar day in both seasons
    with site.using(SiteSettings(timezone="Australia/Sydney")):
        for month in (7, 12):
            turn = datetime(2026, month, 10, 14, 0, tzinfo=UTC)
            before, after = _day_turns(turn)
            assert after == turn.astimezone(ZoneInfo("Australia/Sydney")).date()
            assert before == after - timedelta(days=1)
    # New York, standard time -5: the turn is 05:00 UTC (00:00 in January, 01:00 in July)
    with site.using(SiteSettings(timezone="America/New_York")):
        for month in (1, 7):
            turn = datetime(2026, month, 10, 5, 0, tzinfo=UTC)
            before, after = _day_turns(turn)
            assert after == turn.astimezone(ZoneInfo("America/New_York")).date()
            assert before == after - timedelta(days=1)
