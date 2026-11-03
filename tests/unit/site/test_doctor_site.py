"""`argus doctor` on the site profile (D-280, D-284): which log families it names and the zone,
the incident ID prefix and the own networks and domains it uses."""

from __future__ import annotations

import pytest

from argus.config.settings import Settings
from argus.doctor import site_check
from argus.site import SiteSettings

pytestmark = pytest.mark.unit


async def test_the_neutral_site_names_no_family() -> None:
    (result,) = await site_check(Settings(site=SiteSettings()))
    assert result.ok
    assert not result.warn
    assert result.name == "site"
    assert "0 log families (none yet: `argus discover` proposes them); space default" in (
        result.detail
    )
    assert "zone UTC; incident IDs IR-YYYY-MMDD-NN; 0 own networks, 0 own domains" in result.detail


async def test_acmes_section_says_its_zone_prefix_and_own_networks() -> None:
    (result,) = await site_check(Settings(site=acme()))
    assert "5 log families (squid, dns, nginx, postfix, sso); space acme-soc" in result.detail
    assert (
        "zone Asia/Kolkata; incident IDs ACME-IR-YYYY-MMDD-NN; 1 own networks, 2 own domains"
        in result.detail
    )


def acme() -> SiteSettings:
    from argus import site

    return site.active()  # the suite runs on ACME's own section
