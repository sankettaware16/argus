"""The Kibana lane's settings and the lane budgets' (Q-D2): off by default, no class on, the
write window outside the quiet hours, lanes that never exceed the ceiling."""

from __future__ import annotations

from datetime import timedelta

import pydantic
import pytest
from pydantic import SecretStr

from argus.config.errors import ConfigError
from argus.config.settings import KibanaSettings, Settings, SiemSettings
from argus.gateway.kibana.service import build_kibana_gateway, caps, keys, transport
from argus.gateway.lanes import Lane
from argus.gateway.service import collector_config, lane_plan

pytestmark = pytest.mark.unit


def test_kibana_is_off_with_no_class_and_no_key() -> None:
    k = KibanaSettings()
    assert (k.enabled, k.write_classes, k.accepted_residual) == (False, (), ())
    assert (k.reader_api_key, k.cases_writer_api_key, k.alert_writer_api_key) == (None, None, None)
    assert (k.timeout, k.write_window, k.service_user) == (
        timedelta(seconds=15), ("02:30", "17:30"), "argus",
    )  # fmt: skip
    assert k.url is None  # no default address: ARGUS sends nothing until one is set
    with pytest.raises(ConfigError, match=r"kibana\.url is not configured"):
        k.address()


def test_nothing_is_built_while_kibana_is_off() -> None:
    from argus.config.errors import ConfigError

    with pytest.raises(ConfigError, match="off"):
        transport(Settings())
    with pytest.raises(ConfigError, match="off"):
        build_kibana_gateway(Settings(), None)  # type: ignore[arg-type]
    on = Settings(kibana=KibanaSettings(enabled=True))
    with pytest.raises(ConfigError, match="reader_api_key"):
        transport(on)


@pytest.mark.parametrize(
    "window",
    [("17:30", "02:30"), ("2:30", "17:30"), ("24:00", "x")],
)
def test_the_write_window_is_two_utc_times_in_order(window: tuple[str, str]) -> None:
    with pytest.raises(pydantic.ValidationError):
        KibanaSettings(write_window=window)


@pytest.mark.parametrize("window", [("00:30", "05:00"), ("01:00", "17:30")])
def test_the_write_window_never_reaches_the_quiet_hours(window: tuple[str, str]) -> None:
    """The quiet hours are the site's (D-284), so the settings as a whole check it."""
    with pytest.raises(pydantic.ValidationError, match="quiet hours"):
        Settings(kibana=KibanaSettings(write_window=window))


def test_write_classes_are_typed_by_name() -> None:
    writer = SecretStr("w")
    assert KibanaSettings(write_classes="W1, W2", cases_writer_api_key=writer).write_classes == (  # type: ignore[arg-type]
        "W1", "W2",
    )  # fmt: skip
    for bad in ("WT", "w1", "W4", "all"):
        with pytest.raises(pydantic.ValidationError):
            KibanaSettings(write_classes=(bad,))  # type: ignore[arg-type]
    with pytest.raises(pydantic.ValidationError):
        KibanaSettings(url="http://10.20.60.11:5601")


def test_caps_and_keys_from_the_settings() -> None:
    k = KibanaSettings(write_window=("03:00", "12:00"), reader_api_key="r", cases_writer_api_key="")  # type: ignore[arg-type]
    settings = Settings(kibana=k)
    assert [t.isoformat() for t in caps(settings).window] == ["03:00:00", "12:00:00"]
    assert [role.value for role in keys(settings)] == ["reader"]  # an empty key is no key


def test_lanes_default_to_their_share_of_the_ceiling() -> None:
    plan = lane_plan(SiemSettings())
    # 400 of 1,800 to checking (E3), then 800 of the 1,400 left to enrichment (D-321)
    assert plan.spec(Lane.COLLECTOR).per_minute_ms == 600
    assert plan.spec(Lane.ENRICHMENT).per_minute_ms == 800
    assert collector_config(SiemSettings()).took_per_day_ms == 720_000
    assert collector_config(SiemSettings()).burst_ms == 10_000  # NORMAL: an hour's reconciling
    assert plan.spec(Lane.CHECKING).per_day_ms == 600_000
    small = SiemSettings(budget={"took_per_minute_ms": 1_000, "burst_ms": 1_000})  # type: ignore[arg-type]
    assert lane_plan(small).spec(Lane.COLLECTOR).per_minute_ms == 200
    assert lane_plan(small).spec(Lane.ENRICHMENT).per_minute_ms == 266


def test_an_explicit_lane_counts_against_the_ceiling() -> None:
    given = {"kibana_read": {"per_minute_ms": 200, "per_day_ms": 240_000}}
    assert lane_plan(SiemSettings(lanes=given)).spec(Lane.KIBANA_READ).per_minute_ms == 200  # type: ignore[arg-type]
    with pytest.raises(pydantic.ValidationError, match="exceeds the ceiling"):
        SiemSettings(lanes={"kibana_read": {"per_minute_ms": 1_000, "per_day_ms": 1}})  # type: ignore[arg-type]
    with pytest.raises(pydantic.ValidationError):
        SiemSettings(lanes={"kibana": {"per_minute_ms": 1, "per_day_ms": 1}})  # type: ignore[arg-type]
