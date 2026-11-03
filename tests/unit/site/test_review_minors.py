"""P4-D1 part 2 review, the minor findings (D-285): F8 zone names, F10 nights without quiet hours,
F11 the noun, F12 the family's types and limit, F15 the first-family warning, F16 unquoted quiet
hours, F17 the write window's location."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from argus import site
from argus.config.settings import KibanaSettings, Settings, load_settings
from argus.doctor import site_check
from argus.freshness.model import OK, Reading
from argus.freshness.report import nights
from argus.site import LogFamily, QuietHours, Role, SiteSettings, zone_disagreements

pytestmark = pytest.mark.unit

# --------------------------------------------------------------------------- F8: zone names


@pytest.mark.parametrize("name", ["localtime", "posixrules", "Factory", "CET", "EET", "MET", "WET"])
def test_a_zone_that_python_and_postgres_read_differently_is_refused(name: str) -> None:
    with pytest.raises(ValidationError, match="name the region"):
        SiteSettings(timezone=name)


@pytest.mark.parametrize(
    "name", ["Europe/Berlin", "Asia/Kolkata", "UTC", "America/New_York", "Australia/Lord_Howe"]
)
def test_region_zones_are_accepted(name: str) -> None:
    assert SiteSettings(timezone=name).timezone == name


def test_the_database_and_python_are_compared_instant_by_instant() -> None:
    zone = timezone(timedelta(hours=1))
    berlin = site.ZoneInfo("Europe/Berlin")
    honest = [(at, at.astimezone(berlin).replace(tzinfo=None)) for at in site.ZONE_PROBES]
    assert zone_disagreements("Europe/Berlin", honest) == []
    # a database that read the name as a fixed +01:00 abbreviation drifts in summer
    fixed = [(at, at.astimezone(zone).replace(tzinfo=None)) for at in site.ZONE_PROBES]
    odd = zone_disagreements("Europe/Berlin", fixed)
    assert len(odd) == 5  # the five probes in daylight saving time
    assert odd[0].startswith("2026-04-15 (database 13:00, Python 14:00)")
    assert len(site.ZONE_PROBES) == 9
    assert {at.year for at in site.ZONE_PROBES} == {2026}


# --------------------------------------------------------------------------- F10


def test_no_quiet_hours_no_nights() -> None:
    day = datetime(2026, 10, 20, 2, 0, tzinfo=UTC)
    readings = [Reading("squid", day + timedelta(minutes=5 * n), OK,
                        day + timedelta(minutes=5 * n),
                        day + timedelta(minutes=5 * n - 1)) for n in range(2000)]  # fmt: skip
    margin, gap = timedelta(minutes=3), timedelta(minutes=10)
    assert nights(readings, margin, gap)[0] > 0
    with site.using(SiteSettings(quiet_hours=QuietHours(start="03:00", end="03:00"))):
        assert nights(readings, margin, gap) == (0, 0)


# --------------------------------------------------------------------------- F11


@pytest.mark.parametrize(
    "bad", ["campus\nINJECTED", "<b>x</b>", "  ", "{team}", "The Plant", "", "Campus", "a" * 41]
)
def test_the_noun_is_one_plain_phrase_that_starts_in_lower_case(bad: str) -> None:
    with pytest.raises(ValidationError, match="own_network_noun"):
        SiteSettings(own_network_noun=bad)


@pytest.mark.parametrize(
    "good", ["campus", "the plant", "your network", "office network", "university", "o", "lab-1"]
)
def test_ordinary_nouns_are_accepted(good: str) -> None:
    assert SiteSettings(own_network_noun=good).own_network_noun == good


def test_the_sentence_grammar_of_the_nouns() -> None:
    with site.using(SiteSettings(own_network_noun="university")):
        assert site.a_own("server") == "a university server"  # not "an university"
    with site.using(SiteSettings(own_network_noun="office")):
        assert site.a_own("server") == "an office server"
    with site.using(SiteSettings()):
        assert site.own("names") == "names of your network"  # "with names of your network hidden"


# --------------------------------------------------------------------------- F12


def test_types_must_name_fields_of_the_family() -> None:
    ok = LogFamily(role=Role.PROXY, pattern="p-*", types={"url.original": "keyword"})
    assert ok.types == {"url.original": "keyword"}
    for bad in (
        {"nonexistent.field": "keyword"},
        {"url.original.keyword": "keyword"},
        {"@timestamp": "keyword"},
    ):
        with pytest.raises(ValidationError, match="types names a field"):
            LogFamily(role=Role.PROXY, pattern="p-*", types=bad)
    # a field the family renamed is the one to type
    renamed = LogFamily(role=Role.PROXY, pattern="p-*", fields={"url": "http.url"},
                        types={"http.url": "keyword"})  # fmt: skip
    assert renamed.value_limit("http.url") == 256
    with pytest.raises(ValidationError, match="types names a field"):
        LogFamily(role=Role.PROXY, pattern="p-*", fields={"url": "http.url"},
                  types={"url.original": "keyword"})  # fmt: skip


@pytest.mark.parametrize(("limit", "ok"), [(1, False), (31, False), (32, True), (32766, True)])
def test_ignore_above_has_a_floor(limit: int, ok: bool) -> None:
    if ok:
        assert LogFamily(role=Role.PROXY, pattern="p-*", ignore_above=limit).ignore_above == limit
    else:
        with pytest.raises(ValidationError):
            LogFamily(role=Role.PROXY, pattern="p-*", ignore_above=limit)


# --------------------------------------------------------------------------- F15


async def test_a_role_with_two_families_is_warned_where_only_the_first_is_read() -> None:
    two_auth = SiteSettings(
        families=(
            LogFamily(name="sso", role=Role.AUTH, pattern="sso-*"),
            LogFamily(name="vpn", role=Role.AUTH, pattern="vpn-*"),
        )
    )
    quiet = Settings.model_validate({"site": two_auth.model_dump()})
    assert len(await site_check(quiet)) == 1  # sign-ins off: nothing is read from them
    loud = Settings.model_validate({"site": two_auth.model_dump(), "signins": {"enabled": True}})
    results = await site_check(loud)
    assert [r.name for r in results] == ["site", "site auth families"]
    assert results[1].label == "WARN"
    assert "the sign-ins read sso only" in results[1].detail
    watch = Settings.model_validate(
        {
            "site": SiteSettings(
                families=(
                    LogFamily(name="a", role=Role.PROXY, pattern="a-*"),
                    LogFamily(name="b", role=Role.PROXY, pattern="b-*"),
                )
            ).model_dump(),
            "cases": {"watch": "on"},
        }
    )
    assert (await site_check(watch))[1].name == "site proxy families"


# --------------------------------------------------------------------------- F16


@pytest.mark.parametrize("bad", [1320, 22.0, None, ["22:00"]])
def test_an_unquoted_time_says_to_quote_it(bad: object) -> None:
    with pytest.raises(ValidationError, match='write the time in quotes, as "22:00"'):
        QuietHours.model_validate({"start": bad, "end": "23:30"})


def test_the_yaml_error_says_so_with_its_line(tmp_path_factory: pytest.TempPathFactory) -> None:
    from argus.config.errors import ConfigError

    folder = tmp_path_factory.mktemp("quiet")
    config = folder / "argus.yaml"
    config.write_text("site:\n  quiet_hours: {start: 22:00, end: 23:30}\n")
    with pytest.raises(ConfigError, match="write the time in quotes"):
        load_settings(config, env_file=None)


# --------------------------------------------------------------------------- F17


def test_the_write_window_error_names_its_setting() -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(kibana=KibanaSettings(write_window=("00:30", "05:00")))
    [error] = caught.value.errors(include_url=False, include_input=False, include_context=False)
    assert error["loc"] == ("kibana", "write_window")
    assert error["msg"] == "must not reach into the quiet hours (00:00-01:30 UTC)"


def test_the_config_error_reads_with_the_setting_not_root(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    from argus.config.errors import ConfigError

    folder = tmp_path_factory.mktemp("window")
    config = folder / "argus.yaml"
    config.write_text("kibana:\n  write_window: ['00:30', '05:00']\n")
    with pytest.raises(ConfigError) as caught:
        load_settings(config, env_file=None)
    text = str(caught.value)
    assert "kibana.write_window: must not reach into the quiet hours" in text
    assert "<root>" not in text
