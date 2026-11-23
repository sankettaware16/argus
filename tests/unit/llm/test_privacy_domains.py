"""P4-D1 part 2 review F4 (D-285): the privacy layer fails closed. The organisation's domains
(``site.own_domains`` and the policy's ``own_domains``, together) must name at least one, or no
text for a model is built: a layer that replaces no domain would send ``example.org`` to a cloud
provider with every other check green."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from argus import site
from argus.cases import titling
from argus.config.settings import Settings
from argus.doctor import privacy_domains_check
from argus.llm import providers
from argus.llm.privacy import Policy, Privacy, PrivacyConfigError, load_policy
from argus.site import SiteSettings
from tests.unit.llm.conftest import ASSETS

pytestmark = pytest.mark.unit

NEUTRAL = SiteSettings()


def test_acmes_configuration_names_its_domains() -> None:
    assert site.own_domains(load_policy().own_domains) == ("example.edu", "example-univ.org")
    assert Privacy.build(load_policy(), ASSETS).ours.domains == (
        "example.edu",
        "example-univ.org",
    )


def test_the_neutral_site_refuses_to_load_the_policy_or_build_the_layer() -> None:
    with site.using(NEUTRAL):
        with pytest.raises(PrivacyConfigError, match=r"site\.own_domains"):
            load_policy()
        policy = load_policy(require_domains=False)  # a reader that sends nothing
        with pytest.raises(PrivacyConfigError, match="no text is built for a model"):
            Privacy.build(policy, ASSETS)
    assert issubclass(PrivacyConfigError, ValueError)


def test_one_domain_in_either_list_is_enough() -> None:
    bare = load_policy(require_domains=False)
    assert bare.own_domains == ()  # the shipped policy lists none: the site's are the list
    with site.using(SiteSettings(own_domains=("example.org",))):
        assert Privacy.build(load_policy(), ASSETS).ours.domains == ("example.org",)
    listed = Policy.model_validate({**bare.model_dump(), "own_domains": ["example.edu"]})
    with site.using(NEUTRAL):
        assert Privacy.build(listed, ASSETS).ours.domains == ("example.edu",)
    # entries that clean to nothing are no domain
    blank = Policy.model_validate({**bare.model_dump(), "own_domains": ["..", " "]})
    with site.using(NEUTRAL), pytest.raises(PrivacyConfigError):
        Privacy.build(blank, ASSETS)


def test_the_case_titles_still_read_the_list_without_a_domain() -> None:
    titling._policy_domains.cache_clear()
    try:
        with site.using(NEUTRAL):
            assert titling.default_own_domains() == ()  # nothing is sent: no refusal
    finally:
        titling._policy_domains.cache_clear()


def _providers(*enabled: bool) -> Any:
    return SimpleNamespace(
        providers=[SimpleNamespace(name=f"p{n}", enabled=on) for n, on in enumerate(enabled)]
    )


async def test_doctor_passes_on_acme_and_fails_when_a_provider_could_be_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acme = Settings(site=site.active())
    [ok] = await privacy_domains_check(acme)
    assert (ok.label, ok.detail) == ("PASS", "2 own domains are replaced")
    neutral = Settings(site=NEUTRAL)
    monkeypatch.setattr(providers, "load_config", lambda: _providers(False, True))
    [failed] = await privacy_domains_check(neutral)
    assert failed.label == "FAIL"
    assert "site.own_domains" in failed.detail
    assert "enabled: p1" in failed.detail
    monkeypatch.setattr(providers, "load_config", lambda: _providers(False, False))
    [warned] = await privacy_domains_check(neutral)
    assert warned.label == "WARN"
    assert "no model is enabled" in warned.detail
    # naming one domain mends it
    mended = Settings(site=SiteSettings(own_domains=("example.org",)))
    assert (await privacy_domains_check(mended))[0].label == "PASS"
