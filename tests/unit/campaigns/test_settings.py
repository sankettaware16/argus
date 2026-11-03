"""D-174: the settings the review added. ``campaigns.resolvers`` names the campus resolvers (nothing
guesses them any more); ``cases.offers_per_hour`` is the hourly budget of offers to open cases."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from pydantic import ValidationError

from argus.config.settings import Settings, load_settings

CONFIG = Path(__file__).resolve().parents[3] / "config" / "argus.yaml"


def test_no_resolver_is_assumed_and_the_offer_budget_defaults_to_thirty() -> None:
    settings = Settings()
    assert settings.campaigns.resolvers == ()
    assert settings.cases.offers_per_hour == 30


def test_resolvers_are_addresses_or_networks() -> None:
    settings = Settings(campaigns={"resolvers": ["10.0.0.53", "10.0.1.0/30", "2001:db8::53"]})
    assert settings.campaigns.resolvers == (
        ipaddress.ip_network("10.0.0.53/32"),
        ipaddress.ip_network("10.0.1.0/30"),
        ipaddress.ip_network("2001:db8::53/128"),
    )
    with pytest.raises(ValidationError):
        Settings(campaigns={"resolvers": ["not an address"]})
    with pytest.raises(ValidationError):
        Settings(campaigns={"resolvers": ["10.0.0.0/8", "dns.example"]})


def test_an_unknown_campaign_key_is_an_error() -> None:
    with pytest.raises(ValidationError):
        Settings(campaigns={"resolver": ["10.0.0.53"]})


@pytest.mark.parametrize(("value", "valid"), [(0, True), (30, True), (500, True), (-1, False),
                                              (501, False)])  # fmt: skip
def test_the_offer_budget_is_bounded(value: int, valid: bool) -> None:
    if valid:
        assert Settings(cases={"offers_per_hour": value}).cases.offers_per_hour == value
    else:
        with pytest.raises(ValidationError):
            Settings(cases={"offers_per_hour": value})


def test_the_shipped_config_sets_the_budget_and_says_to_set_the_resolvers() -> None:
    settings = load_settings(CONFIG)
    assert settings.cases.offers_per_hour == 30
    assert settings.campaigns.resolvers == ()  # production sets its own
    text = CONFIG.read_text()
    assert "resolvers:" in text
    assert "SET THIS" in text  # the note: nothing guesses the resolvers any more
