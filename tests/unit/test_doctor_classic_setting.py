"""`argus doctor` on ``web.classic``: gone since the classic pages went; a file or unit that
still sets it loads, is ignored, and is warned about until it is removed."""

from __future__ import annotations

import pytest

from argus.config.settings import Settings, UnitsSettings, UnitWebSettings, WebSettings
from argus.doctor import classic_setting_check

pytestmark = pytest.mark.unit


async def test_a_file_that_does_not_set_it_gets_no_line() -> None:
    assert await classic_setting_check(Settings()) == []


@pytest.mark.parametrize("value", ["primary", "fallback"])
async def test_the_old_web_setting_loads_and_is_warned_about(value: str) -> None:
    settings = Settings.model_validate({"web": {"classic": value}})
    (result,) = await classic_setting_check(settings)
    assert (result.ok, result.warn, result.label) == (True, True, "WARN")
    assert "web.classic is no longer used: remove it" in result.detail


async def test_the_old_unit_setting_loads_and_is_warned_about() -> None:
    settings = Settings(units=UnitsSettings(web=UnitWebSettings(classic="fallback")))
    (result,) = await classic_setting_check(settings)
    assert "units.web.classic is no longer used: remove it" in result.detail
    assert UnitWebSettings(classic="fallback").environment() == {}


async def test_the_setting_changes_nothing_in_the_web_settings() -> None:
    assert WebSettings(classic="fallback").model_dump(
        exclude={"classic"}
    ) == WebSettings().model_dump(exclude={"classic"})
