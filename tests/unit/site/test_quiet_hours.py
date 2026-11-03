"""P4-D1 part 2, step 4 (D-284): the quiet hours are ``site.quiet_hours`` (UTC; default and ACME's
00:00-01:30). Every place that kept the window as a constant reads the site; on ACME's section each
answers for every minute of the day exactly as the constants did."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus import site
from argus.config.settings import KibanaSettings
from argus.context import bounds, live_check
from argus.evaluation import agent_eval
from argus.freshness import model as freshness
from argus.gateway import gateway
from argus.gateway.kibana import writes
from argus.kibana_sync import classify
from argus.llm.providers import EvaluationConfig
from argus.site import QuietHours, SiteSettings

pytestmark = pytest.mark.unit
DAY = datetime(2026, 10, 29, tzinfo=UTC)
MINUTES = [DAY + timedelta(minutes=m) for m in range(24 * 60)]
NONE = SiteSettings(quiet_hours=QuietHours(start="00:00", end="00:00"))
NIGHT = SiteSettings(quiet_hours=QuietHours(start="23:00", end="01:00"))  # across midnight
EVENING = SiteSettings(quiet_hours=QuietHours(start="18:00", end="19:30"))


def old_rule(at: datetime) -> bool:
    return at.astimezone(UTC).time() < time(1, 30)  # the constant every module had


# --------------------------------------------------------------------------- the window


def test_the_default_is_the_window_the_constants_had() -> None:
    assert SiteSettings().quiet_hours == QuietHours(start="00:00", end="01:30")
    assert site.quiet_hours() == QuietHours(start="00:00", end="01:30")
    assert str(site.quiet_hours()) == "00:00-01:30 UTC"
    assert site.quiet_hours().length == timedelta(hours=1, minutes=30)


def test_every_minute_of_the_day_is_judged_as_the_old_constant_judged_it() -> None:
    for at in MINUTES:
        want = old_rule(at)
        assert gateway.in_quiet_hours(at) is want
        assert classify.quiet_hours(at) is want
        assert bounds.quiet(at) is want
        assert writes.in_quiet_hours(at) is want
        assert site.in_quiet_hours(at) is want


def test_a_moment_in_another_zone_is_judged_in_utc() -> None:
    kolkata = ZoneInfo("Asia/Kolkata")
    assert gateway.in_quiet_hours(datetime(2026, 10, 29, 5, 30, tzinfo=kolkata))  # 00:00 UTC
    assert not gateway.in_quiet_hours(datetime(2026, 10, 29, 7, 0, tzinfo=kolkata))  # 01:30 UTC


def test_a_window_across_midnight_and_none() -> None:
    with site.using(NIGHT):
        held = [at for at in MINUTES if gateway.in_quiet_hours(at)]
        assert len(held) == 120
        assert site.quiet_hours().length == timedelta(hours=2)
        assert gateway.in_quiet_hours(DAY.replace(hour=23, minute=30))
        assert gateway.in_quiet_hours(DAY.replace(hour=0, minute=59))
        assert not gateway.in_quiet_hours(DAY.replace(hour=1))
    with site.using(NONE):
        assert not any(gateway.in_quiet_hours(at) for at in MINUTES)
        assert site.quiet_hours().length == timedelta(0)
        assert str(site.quiet_hours()) == "no quiet hours"


@given(st.integers(0, 23), st.integers(0, 59), st.integers(0, 23), st.integers(0, 59))
def test_overlap_agrees_with_asking_every_minute(a: int, b: int, c: int, d: int) -> None:
    quiet = QuietHours(start=f"{a:02d}:{b:02d}", end=f"{c:02d}:{d:02d}")
    first, last = time(10, 0), time(11, 0)
    asked = any(
        quiet.holds_time((DAY.replace(hour=10) + timedelta(minutes=n)).time()) for n in range(60)
    )
    assert quiet.overlaps(first, last) is asked


@given(st.integers(0, 1439), st.integers(0, 1439), st.integers(0, 1439))
def test_the_end_of_the_window_is_the_first_moment_outside_it(
    start: int, end: int, now: int
) -> None:
    quiet = QuietHours(
        start=f"{start // 60:02d}:{start % 60:02d}", end=f"{end // 60:02d}:{end % 60:02d}"
    )
    at = DAY + timedelta(minutes=now)
    over = quiet.next_end(at)
    assert over >= at
    assert not quiet.holds(over)
    if quiet.holds(at):
        assert over > at
        assert all(
            quiet.holds(at + timedelta(minutes=n))
            for n in range(int((over - at).total_seconds() // 60))
        )
    else:
        assert over == at


@pytest.mark.parametrize("bad", ["24:00", "1:30", "01:60", "0130", "01:30:00", "", " 01:30"])
def test_a_time_is_hh_mm(bad: str) -> None:
    with pytest.raises(ValidationError):
        QuietHours(start=bad)
    with pytest.raises(ValidationError):
        QuietHours(end=bad)


# --------------------------------------------------------------------------- the readers


def test_the_write_window_follows_the_quiet_hours() -> None:
    caps = writes.WriteCaps()  # 02:30-17:30 UTC
    assert writes.in_window(DAY.replace(hour=3), caps)
    assert not writes.in_window(DAY.replace(hour=1), caps)
    with site.using(EVENING):
        assert writes.in_window(DAY.replace(hour=3), caps) is True
        assert not writes.in_window(DAY.replace(hour=18, minute=30), caps)
        with pytest.raises(ValueError, match="quiet hours"):
            writes.WriteCaps(window=(time(17, 0), time(20, 0)))
        writes.WriteCaps(window=(time(2, 30), time(17, 30)))
    with site.using(NIGHT), pytest.raises(ValueError, match="quiet hours"):
        writes.WriteCaps(window=(time(0, 30), time(17, 30)))
    with site.using(NONE):
        assert writes.in_window(
            DAY.replace(hour=1), writes.WriteCaps(window=(time(0, 30), time(5)))
        )


def test_the_settings_refuse_a_write_window_in_the_quiet_hours() -> None:
    from argus.config.settings import Settings

    Settings()  # 02:30-17:30 against 00:00-01:30
    with pytest.raises(ValidationError, match="quiet hours"):
        Settings(kibana=KibanaSettings(write_window=("01:00", "17:30")))
    with pytest.raises(ValidationError, match="quiet hours"):
        Settings(
            kibana=KibanaSettings(write_window=("17:00", "20:00")),
            site=EVENING,
        )
    Settings(kibana=KibanaSettings(write_window=("00:30", "17:30")), site=NONE)
    with pytest.raises(ValidationError, match="before it ends"):
        KibanaSettings(write_window=("17:30", "02:30"))


def test_the_live_check_says_the_sites_hours() -> None:
    said = live_check.window(DAY.replace(hour=0, minute=30))
    assert said == "00:00 to 01:30 UTC is the SIEM's busy time (index creation): try after 01:30"
    with site.using(EVENING):
        said = live_check.window(DAY.replace(hour=18, minute=45))
        assert (
            said == "18:00 to 19:30 UTC is the SIEM's busy time (index creation): try after 19:30"
        )


def test_the_gold_run_defers_inside_the_pause_and_names_when_it_ends() -> None:
    calls: list[int] = []

    async def fetch() -> str:
        calls.append(1)
        return "read"

    def run(at: datetime) -> str:
        guarded = agent_eval.outside_siem_pause(fetch, lambda: at)
        return asyncio.run(guarded())

    assert run(DAY.replace(hour=3)) == "read"
    with pytest.raises(agent_eval.Defer) as caught:
        run(DAY.replace(hour=1))
    assert caught.value.until == DAY.replace(hour=1, minute=30)
    assert "00:00-01:30 UTC" in str(caught.value)
    with site.using(NIGHT):
        with pytest.raises(agent_eval.Defer) as caught:
            run(DAY.replace(hour=23, minute=40))
        assert caught.value.until == DAY + timedelta(days=1, hours=1)
    assert calls == [1]


def test_the_freshness_nights_follow_the_quiet_hours() -> None:
    night = DAY
    assert freshness.quiet_nights(night - timedelta(minutes=1), night + timedelta(minutes=1)) == [
        (night, night + timedelta(hours=1, minutes=30))
    ]
    with site.using(NIGHT):  # 23:00-01:00: the pause that spans midnight is found from either side
        found = freshness.quiet_nights(DAY - timedelta(minutes=30), DAY + timedelta(minutes=30))
        assert found == [(DAY - timedelta(hours=1), DAY + timedelta(hours=1))]
        assert len(freshness.quiet_nights(DAY, DAY + timedelta(days=2, minutes=30))) == 3
    with site.using(NONE):
        assert freshness.quiet_nights(DAY, DAY + timedelta(days=5)) == []


def test_the_evaluation_window_stays_outside_the_quiet_hours() -> None:
    EvaluationConfig(window_utc=(time(2, 0), time(5, 0)))
    EvaluationConfig(window_utc=(time(17, 30), time(0, 0)))  # to midnight
    with pytest.raises(ValidationError, match="window_utc must lie between 01:30 and 24:00 UTC"):
        EvaluationConfig(window_utc=(time(1, 0), time(5, 0)))
    with pytest.raises(ValidationError, match="the SIEM pauses 00:00-01:30 UTC"):
        EvaluationConfig(window_utc=(time(0, 0), time(5, 0)))
    with site.using(EVENING):
        EvaluationConfig(window_utc=(time(0, 30), time(5, 0)))
        with pytest.raises(ValidationError, match="between 19:30 and 24:00 UTC"):
            EvaluationConfig(window_utc=(time(17, 0), time(20, 0)))


def test_the_messages_name_the_sites_hours() -> None:
    from argus.context import batch1

    assert batch1.Refusal("quiet_hours").sentence == (
        "this check does not run between 00:00 and 01:30 UTC, the SIEM's busy time"
    )
    with site.using(EVENING):
        assert "between 18:00 and 19:30 UTC" in batch1.Refusal("quiet_hours").sentence
    with site.using(NONE):
        assert "between no hour" in batch1.Refusal("quiet_hours").sentence
