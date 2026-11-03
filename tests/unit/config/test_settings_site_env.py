"""site.own_domains and site.own_networks from the environment: one string, comma-separated."""

from __future__ import annotations

import pytest

from argus.site import SiteSettings

pytestmark = pytest.mark.unit


def test_a_comma_separated_string_is_the_list() -> None:
    site = SiteSettings.model_validate(
        {"own_domains": "example.test, example.org", "own_networks": "192.0.2.0/24,198.51.100.0/24"}
    )
    assert site.own_domains == ("example.test", "example.org")
    assert [str(n) for n in site.own_networks] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert SiteSettings.model_validate({"own_domains": ["a.example"]}).own_domains == ("a.example",)
