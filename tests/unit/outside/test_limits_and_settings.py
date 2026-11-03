"""AR3 (D-165): the limits are settings with defaults below the free plans and refused above them; a
source without a key is off; the keys are secrets (never shown, registered for redaction, read from
``.env`` as ``ARGUS_OUTSIDE__<SOURCE>_API_KEY``); a window says when it has room again."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus.config import ConfigError, load_settings
from argus.config.settings import CUSTODY_SECRETS, OutsideSettings, Settings, secret_settings
from argus.observability.redaction import clear_registered_secrets
from argus.outside.store import SPACING, Limit, limits_of

NOW = datetime(2026, 10, 28, 13, 45, 30, tzinfo=UTC)
SECRET = "Synthetic-Outside-Key-91"


# -- the defaults and their bounds --------------------------------------------------------------


def test_the_defaults_are_below_the_free_plans() -> None:
    s = OutsideSettings()
    assert (s.virustotal_per_minute, s.virustotal_per_day) == (3, 400)  # the plan: 4 and 500
    assert s.virustotal_per_minute < 4  # below the plan's rate, not equal to it
    assert s.shodan_per_minute == 30  # the plan: 1 a second; the second-by-second pacing is below
    assert (s.censys_per_day, s.censys_per_month) == (10, 50)
    assert s.cache_window == timedelta(days=7)
    assert s.clean_cache_window == timedelta(days=1)  # no record or too few engines: a day
    assert s.error_backoff == timedelta(hours=6)
    assert s.flag_threshold == 3
    assert (s.prefetch, s.prefetch_per_day, s.prefetch_batch) == (True, 260, 3)
    assert s.prefetch_per_day < s.virustotal_per_day  # the investigator keeps an allowance
    assert s.families_per_day == 40  # D-168: taken from the prefetch's 300
    # the prefetch's and the families' shares leave the investigator its 100 of the 400
    assert s.virustotal_per_day - s.prefetch_per_day - s.families_per_day >= 100
    assert s.shodan_internetdb is True


@pytest.mark.parametrize(
    ("name", "value"),
    [("virustotal_per_minute", 5), ("virustotal_per_day", 501), ("shodan_per_minute", 61),
     ("virustotal_per_minute", 0), ("flag_threshold", 0), ("prefetch_batch", 5),
     ("prefetch_per_day", 501), ("families_per_day", 201), ("families_per_day", -1),
     ("shodan_internetdb", "maybe"), ("cache_window", "30m"), ("cache_window", "31d"),
     ("clean_cache_window", "30m"), ("clean_cache_window", "31d"), ("error_backoff", "30s"),
     ("error_backoff", "2d"), ("timeout", "1s"), ("nonsense", 1)],
)  # fmt: skip
def test_a_limit_above_the_plan_or_an_unknown_setting_is_refused(name: str, value: object) -> None:
    with pytest.raises(ValidationError):
        OutsideSettings(**{name: value})


def test_a_clean_answer_is_never_kept_longer_than_a_detection() -> None:
    assert OutsideSettings(cache_window="2d", clean_cache_window="2d").clean_cache_window
    with pytest.raises(ValidationError, match="clean_cache_window"):
        OutsideSettings(cache_window="2d", clean_cache_window="3d")
    with pytest.raises(ValidationError, match="clean_cache_window"):
        OutsideSettings(cache_window="12h")  # the default clean window is a day


def test_a_source_without_a_key_is_off() -> None:
    s = OutsideSettings()
    assert [s.key_of(n) for n in ("virustotal", "shodan", "censys")] == [None, None, None]
    on = OutsideSettings(virustotal_api_key=SecretStr(SECRET), shodan_api_key=SecretStr("  "))
    assert on.key_of("virustotal") == SECRET
    assert on.key_of("shodan") is None  # blank is no key
    assert on.key_of("censys") is None
    assert on.key_of("bing") is None


def test_the_keys_are_secrets_that_show_nowhere() -> None:
    s = OutsideSettings(virustotal_api_key=SecretStr(SECRET))
    assert SECRET not in repr(s)
    assert SECRET not in str(s)
    assert SECRET not in s.model_dump_json()
    names = secret_settings()
    assert {"outside.virustotal_api_key", "outside.shodan_api_key", "outside.censys_api_key"} <= (
        set(names)
    )
    held = {k for k in CUSTODY_SECRETS["svc"] if k.startswith("outside.")}
    assert held == {
        "outside.virustotal_api_key",
        "outside.shodan_api_key",
        "outside.censys_api_key",
    }
    for account in ("web", "writer", "owner"):
        assert not {k for k in CUSTODY_SECRETS[account] if k.startswith("outside.")}


@pytest.fixture
def clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    clear_registered_secrets()
    config = tmp_path / "argus.yaml"
    config.write_text("outside:\n  virustotal_per_day: 100\n  flag_threshold: 5\n")
    return config


def test_the_keys_are_read_from_dotenv_and_registered_for_redaction(clean: Path) -> None:
    dotenv = clean.parent / ".env"
    dotenv.write_text(
        f"ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY={SECRET}\nARGUS_OUTSIDE__SHODAN_API_KEY=\n"
    )
    settings = load_settings(clean, env_file=dotenv)
    assert settings.outside.key_of("virustotal") == SECRET
    assert settings.outside.key_of("shodan") is None
    assert settings.outside.key_of("censys") is None
    assert (settings.outside.virustotal_per_day, settings.outside.flag_threshold) == (100, 5)
    assert SECRET in settings.secret_values()
    assert SECRET not in repr(settings)


def test_a_misspelt_key_variable_stops_the_service_rather_than_being_ignored(clean: Path) -> None:
    dotenv = clean.parent / ".env"
    dotenv.write_text(f"ARGUS_OUTSIDE__VIRUSTOTAL_KEY={SECRET}\n")
    with pytest.raises(ConfigError) as caught:
        load_settings(clean, env_file=dotenv)
    assert SECRET not in str(caught.value)


def test_the_example_env_file_names_each_key_and_loads(clean: Path) -> None:
    text = (Path(__file__).resolve().parents[3] / ".env.example").read_text()
    for name in ("VIRUSTOTAL", "SHODAN", "CENSYS"):
        assert f"ARGUS_OUTSIDE__{name}_API_KEY=" in text
    assert isinstance(Settings().outside, OutsideSettings)


# -- the windows --------------------------------------------------------------------------------


def test_each_source_has_its_own_limits() -> None:
    s = OutsideSettings()
    assert limits_of("virustotal", s) == (Limit("rolling", 3, 60), Limit("day", 400))
    assert limits_of("shodan", s) == (
        Limit("rolling", 1, SPACING), Limit("rolling", 30, 60), Limit("day", 200),
    )  # fmt: skip
    assert limits_of("censys", s) == (
        Limit("rolling", 1, SPACING), Limit("day", 10), Limit("month", 50),
    )  # fmt: skip


def test_a_request_a_second_is_kept_with_a_margin() -> None:
    """The ledger holds the reservation time, not the send time, which can differ by a
    transaction: two requests of Shodan or Censys are further apart than the second they
    are allowed."""
    assert SPACING > 1.0
    for source in ("shodan", "censys"):
        first = limits_of(source, OutsideSettings())[0]
        assert (first.maximum, first.seconds) == (1, SPACING)
        assert first.resets(NOW, NOW) == NOW + timedelta(seconds=SPACING)


def test_windows_start_and_reopen() -> None:
    minute, day, month = Limit("rolling", 4, 60), Limit("day", 400), Limit("month", 50)
    assert minute.since(NOW) == NOW - timedelta(seconds=60)
    assert day.since(NOW) == datetime(2026, 10, 28, tzinfo=UTC)
    assert month.since(NOW) == datetime(2026, 10, 1, tzinfo=UTC)
    oldest = NOW - timedelta(seconds=45)
    assert minute.resets(oldest, NOW) == NOW + timedelta(seconds=15)
    assert day.resets(None, NOW) == datetime(2026, 10, 29, tzinfo=UTC)
    assert month.resets(None, NOW) == datetime(2026, 11, 1, tzinfo=UTC)
    december = datetime(2026, 12, 31, 23, 59, tzinfo=UTC)
    assert month.resets(None, december) == datetime(2027, 1, 1, tzinfo=UTC)


@given(
    st.datetimes(
        min_value=datetime(2026, 1, 1),  # noqa: DTZ001 - hypothesis wants naive bounds
        max_value=datetime(2030, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    )
)
def test_a_window_never_reopens_in_the_past_and_a_day_reopens_within_a_day(now: datetime) -> None:
    for limit in (Limit("rolling", 4, 60), Limit("day", 1), Limit("month", 1)):
        assert limit.since(now) <= now
        assert limit.resets(None, now) >= now
    assert Limit("day", 1).resets(None, now) - now <= timedelta(days=1)
    assert Limit("month", 1).resets(None, now) - now <= timedelta(days=31)
    assert Limit("day", 1).since(now) == now.replace(hour=0, minute=0, second=0, microsecond=0)


def test_a_source_is_enabled_by_its_key_and_shodan_also_by_its_keyless_database() -> None:
    plain = OutsideSettings()
    assert [plain.enabled(x) for x in ("virustotal", "shodan", "censys")] == [False, True, False]
    off = OutsideSettings(shodan_internetdb=False)
    assert [off.enabled(x) for x in ("virustotal", "shodan", "censys")] == [False, False, False]
    keyed = OutsideSettings(shodan_internetdb=False, shodan_api_key=SecretStr("Synthetic-Key-1"),
                            virustotal_api_key=SecretStr("  "))  # fmt: skip
    assert [keyed.enabled(x) for x in ("virustotal", "shodan", "censys")] == [False, True, False]


def test_families_per_day_zero_switches_the_family_lookups_off() -> None:
    assert OutsideSettings(families_per_day=0).families_per_day == 0
