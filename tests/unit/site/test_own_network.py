"""P4-D1 part 2, step 3 (D-284): the organisation's own networks, domains, noun and names are the
site's. ACME's section gives what ``assets.campus_prefixes``, the policy's campus domains and the
literals "campus" and "ACME" gave; the neutral default names no organisation."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from argus import site
from argus.config.settings import AssetsSettings, Settings, load_settings
from argus.site import SiteSettings
from tests.conftest import shipped_config_on_the_suites_site

pytestmark = pytest.mark.unit
NET = ipaddress.ip_network


def test_acmes_own_networks_are_the_campus_prefixes_it_had(tmp_path: Path) -> None:
    loaded = load_settings(shipped_config_on_the_suites_site(tmp_path), env_file=None)
    assert loaded.site.own_networks == (NET("131.21.124.0/22"),)
    assert loaded.assets.campus_prefixes == ()  # moved into the site section
    assert site.own_networks() == (NET("131.21.124.0/22"),)


def test_the_older_setting_still_fills_the_sites_networks() -> None:
    old = AssetsSettings(campus_prefixes=(NET("192.0.2.0/24"),))
    assert Settings(assets=old).site.own_networks == (NET("192.0.2.0/24"),)  # the site had none
    both = Settings(assets=old, site=SiteSettings(own_networks=(NET("198.51.100.0/24"),)))
    assert both.site.own_networks == (NET("198.51.100.0/24"), NET("192.0.2.0/24"))
    same = Settings(
        assets=AssetsSettings(campus_prefixes=(NET("198.51.100.0/24"),)),
        site=SiteSettings(own_networks=(NET("198.51.100.0/24"),)),
    )
    assert same.site.own_networks == (NET("198.51.100.0/24"),)  # once


def test_a_neutral_install_has_no_own_network_beyond_the_private_ranges() -> None:
    assert Settings().site.own_networks == ()
    assert SiteSettings().own_domains == ()


def test_the_older_name_alone_loads_through_a_file(tmp_path: Path) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("assets:\n  campus_prefixes: [192.0.2.0/24]\n", encoding="utf-8")
    assert load_settings(config, env_file=None).site.own_networks == (NET("192.0.2.0/24"),)


def test_the_classifier_treats_the_sites_networks_as_campus(tmp_path: Path) -> None:
    from argus.assets.classify import IpClass, IpClassifier

    config = shipped_config_on_the_suites_site(tmp_path)
    classifier = IpClassifier(None, load_settings(config, env_file=None).site.own_networks)
    assert classifier.classify("131.21.124.7").ip_class is IpClass.CAMPUS
    assert classifier.classify("8.8.8.8").ip_class is IpClass.PUBLIC


# --------------------------------------------------------------------------- domains and words


def test_own_domains_are_cleaned_and_listed_once_the_sites_first() -> None:
    assert site.own_domains() == ("example.edu", "example-univ.org")
    assert site.own_domains([".EXAMPLE.edu.", "extra.example", ""]) == (
        "example.edu",
        "example-univ.org",
        "extra.example",
    )
    with site.using(SiteSettings()):
        assert site.own_domains() == ()
        assert site.own_domains(["X.example"]) == ("x.example",)


def test_the_noun_has_the_three_forms() -> None:
    forms = {
        "campus": ("campus", "the campus", "a campus", "Campus"),
        "your network": ("your network", "your network", "your network", "Your network"),
        "office network": (
            "office network",
            "the office network",
            "an office network",
            "Office network",
        ),
        "the plant": ("plant", "the plant", "the plant", "Plant"),
        "our site": ("our site", "our site", "our site", "Our site"),
    }
    for word, expected in forms.items():
        with site.using(SiteSettings(own_network_noun=word)):
            assert (
                site.noun(),
                site.the_noun(),
                site.a_noun(),
                site.noun_capital(),
            ) == expected, word


def test_acmes_names_and_the_neutral_ones() -> None:
    assert (site.organisation().name, site.organisation().short_name) == (
        "Example University",
        "ACME",
    )
    with site.using(SiteSettings()):
        assert (site.organisation().name, site.organisation().short_name) == (
            "your organisation",
            "SOC",
        )


@pytest.mark.parametrize("bad", ["", "a\nb", "a\x00b", "x" * 81, "a" + chr(0x2028) + "b"])
def test_an_organisation_name_is_one_plain_line(bad: str) -> None:
    with pytest.raises(ValueError, match="name"):
        SiteSettings.model_validate({"organisation": {"name": bad}})
