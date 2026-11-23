"""AR3 (D-165): nothing about the campus leaves ARGUS through an outside lookup. A campus, private
or special address, an address of the asset map or of the campus prefixes, a campus name, an
asset's name or a name that cannot be public is refused before any request; an external
indicator passes.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.llm.privacy import Privacy, load_policy
from argus.outside import facts
from argus.outside.eligible import Eligibility
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

# the test asset map holds 10.20.0.0/16, 10.30.1.8, 203.0.113.0/24 and 192.168.12.0/24; the
# campus public prefix is 198.51.100.0/24; its entries are named Geology Lab Block, tp8,
# Mailgate and H12 Wing-C
PRIVACY = Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))
E = Eligibility(PRIVACY.classifier, PRIVACY.ours, PRIVACY.ours_for)


@pytest.mark.parametrize(
    "address",
    ["10.20.3.4", "10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "169.254.1.1", "0.0.0.0",  # noqa: S104
     "224.0.0.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "255.255.255.255", "192.0.2.1",
     "10.30.1.8", "203.0.113.9", "198.51.100.7"],
)  # fmt: skip
def test_a_private_special_asset_or_campus_address_is_never_looked_up(address: str) -> None:
    assert E.check("ip", address) is not None


@pytest.mark.parametrize(
    "address",
    ["fec0::1", "feff:ffff::1", "fec0:0:0:1::5", "FEC0::1"],
)
def test_a_site_local_address_is_never_looked_up(address: str) -> None:
    """fec0::/10 is deprecated but still routed inside some networks; the classifier calls it
    public."""
    assert E.check("ip", facts.canonical("ip", address) or "") is not None
    assert E.check("ip", "fbff:ffff::1") is not None  # unique-local neighbours stay refused ...
    assert E.check("ip", "2606:4700:4700::1111") is None  # ... and a global address passes


def test_an_external_address_passes() -> None:
    assert E.check("ip", "8.8.8.8") is None
    assert E.check("ip", "45.33.32.156") is None
    assert E.check("ip", "2606:4700:4700::1111") is None
    assert E.check("ip", "not an ip") == "not an address"


@given(st.integers(0, 2**32 - 1))
def test_every_address_is_refused_unless_it_is_global_and_not_the_campus(number: int) -> None:
    address = ipaddress.IPv4Address(number)
    got = E.check("ip", str(address))
    in_asset_map = any(
        address in ipaddress.ip_network(n)
        for n in ("10.20.0.0/16", "10.30.1.8/32", "203.0.113.0/24", "192.168.12.0/24")
    )
    special = (  # the classifier says no to these even where Python calls them global
        address.is_multicast
        or address.is_reserved
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    )
    if address in CAMPUS_PREFIX or in_asset_map or special or not address.is_global:
        assert got is not None
    else:
        assert got is None


@pytest.mark.parametrize(
    "name",
    ["www.example.edu", "mail.cse.example.edu", "example.edu", "printer.local", "nas.internal",
     "router.lan", "x.corp", "host.home.arpa", "x.in-addr.arpa", "hidden.onion", "a.localhost",
     "a.test", "a.invalid", "a.example"],
)  # fmt: skip
def test_a_campus_or_non_public_name_is_never_looked_up(name: str) -> None:
    assert E.check("domain", name) is not None


def test_a_public_name_passes_and_an_unreadable_one_does_not() -> None:
    assert E.check("domain", "evil-c2.com") is None
    assert E.check("domain", "Evil-C2.com") == "not a public domain name"  # not canonical
    assert E.check("domain", "a b.com") == "not a public domain name"
    assert E.check("domain", "localhost") == "not a public domain name"


def test_a_name_that_holds_an_asset_name_is_never_looked_up() -> None:
    assert E.check("domain", "geology-lab-block.evil.com") == "a campus name"
    assert E.check("domain", "mailgate.evil.com") == "a campus name"
    assert E.check("domain", "ordinary.evil.com") is None


def test_a_url_needs_an_eligible_host_and_no_campus_identifier() -> None:
    assert E.check("url", "http://evil.com/a?b=1") is None
    assert E.check("url", "https://8.8.8.8/x") is None
    assert E.check("url", "http://10.1.2.3/x") is not None
    assert E.check("url", "http://www.example.edu/x") is not None
    assert E.check("url", "http://evil.com/?next=http://www.example.edu/") is not None
    assert E.check("url", "http://evil.com/geology-lab-block") is not None
    assert E.check("url", "http://u:p@evil.com/") == "not a URL"
    assert E.check("url", "HTTP://evil.com/") == "not a URL"  # not canonical


def test_a_hash_names_nothing_on_the_campus() -> None:
    assert E.check("hash", "d41d8cd98f00b204e9800998ecf8427e") is None
    assert E.check("hash", "D41D8CD98F00B204E9800998ECF8427E") == "not a file hash"
    assert E.check("mac", "aa:bb:cc:dd:ee:ff") == "no lookups of mac"


@given(st.sampled_from(facts.KINDS), st.text(max_size=80))
def test_the_check_never_raises(kind: str, text: str) -> None:
    got = E.check(kind, text)
    assert got is None or isinstance(got, str)


# -- the campus view of one investigation -------------------------------------------------------


def item(hosts: list[str], users: list[str], **more: object) -> dict[str, object]:
    return {"facts": {"entities": {"host": hosts, "user": users}, **more}}


def test_a_name_holding_the_investigations_host_or_user_is_refused_for_that_item() -> None:
    """The privacy layer scrubs an investigation's own host and user names from the model's view;
    an outside name that holds one is refused with exactly that view."""
    body = item(["desktop-ab12cd"], ["jsmith"])
    mine = E.for_item(body)
    for name in ("jsmith.c2.com", "login.jsmith.c2.com", "desktop-ab12cd.c2.com",
                 "x-jsmith-y.c2.com", "desktop_ab12cd.evil.net"):  # fmt: skip
        assert E.check("domain", name) is None, name  # the base view does not know the names
        assert mine.check("domain", name) == "a campus name", name
    for name in ("c2.com", "update.c2.com", "jsmithson.c2.com"):  # no whole-word match
        assert mine.check("domain", name) is None, name
    assert mine.check("url", "http://evil.com/jsmith/gate.php") is not None
    assert E.check("url", "http://evil.com/jsmith/gate.php") is None
    assert mine.check("ip", "45.33.32.156") is None  # an address holds no name


def test_the_item_view_is_the_privacy_layers_own_view() -> None:
    body = item(["web7"], ["bob"], group_key='[["host.name","gk1"],["user.name","carol"]]')
    body["context"] = {"pack": {"fields": {"host.name": {"top": [["fld1", 1]]},
                                          "user.name": {"top": [["dave", 1]]}}}}  # fmt: skip
    assert E.for_item(body).ours == PRIVACY.ours_for([body])
    for name in ("web7", "bob", "gk1", "carol", "fld1", "dave"):
        assert E.for_item(body).check("domain", f"{name}.evil.com") == "a campus name"
        assert E.check("domain", f"{name}.evil.com") is None


def test_without_the_privacy_layers_view_the_base_check_is_kept() -> None:
    bare = Eligibility(PRIVACY.classifier, PRIVACY.ours)
    assert bare.for_item(item(["web7"], [])) is bare
    assert (
        bare.with_ours(PRIVACY.ours_for([item(["web7"], [])])).check("domain", "web7.evil.com")
        == "a campus name"
    )


@given(st.from_regex(r"[a-z][a-z0-9]{3,11}", fullmatch=True))
def test_any_host_or_user_name_makes_a_name_holding_it_a_campus_name(name: str) -> None:
    for body in (item([name], []), item([], [name])):
        mine = E.for_item(body)
        assert mine.check("domain", f"{name}.c2.com") == "a campus name"
        assert mine.check("domain", f"www.{name}.c2.com") == "a campus name"


def test_the_outside_service_the_assess_run_builds_checks_each_item_by_its_own_names() -> None:
    """``raising.outside_for`` is the one place a production Outside is made: its check must
    carry the privacy layer's per-item campus view (a base campus alone has no host or user)."""
    from argus.config.settings import Settings
    from argus.raising import outside_for

    outside, _, _ = outside_for(Settings(), PRIVACY, None)  # type: ignore[arg-type]
    assert outside.eligibility.ours_for == PRIVACY.ours_for
    body = item(["desktop-ab12cd"], ["jsmith"])
    assert outside.eligibility.check("domain", "jsmith.c2.com") is None
    assert outside.eligibility.for_item(body).check("domain", "jsmith.c2.com") == "a campus name"


# -- the campus domains the runtime uses (D-174) ------------------------------------------------


@pytest.mark.parametrize(
    "name", ["example-univ.org", "alumni.example-univ.org", "x.y.example-univ.org"]
)
def test_exampleuniv_org_is_a_campus_domain_and_never_looked_up(name: str) -> None:
    assert E.check("domain", name) == "a campus name"
    assert E.check("domain", "notexample-univ.org") is None  # a suffix match is on whole labels


def test_the_shipped_fixture_policy_names_no_domains_of_its_own() -> None:
    """``config/fixtures.yaml`` (sanitizing fixtures) ships neutral (D-294): the domains it
    sanitizes are its private overlay's (fixtures.local.yaml), which a site's pack checks against
    the site's own domains with the privacy policy's."""
    from argus.config.sources import read_yaml_file
    from argus.llm.privacy import POLICY

    fixtures = read_yaml_file(POLICY.parent / "fixtures.yaml")[0]
    assert fixtures["own_domains"] == []
