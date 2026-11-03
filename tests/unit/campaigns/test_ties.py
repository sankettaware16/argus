"""D-174: what ties two rare families to one operator, from the review and from the real answers.

An identical set of two or more name servers, the /24 of the first address outside the shared
networks, or the same autonomous system unless it is a big hoster. A pool of name servers under
one registered domain (Route53's ``awsdns-NN``) ties nothing; neither does a big hoster's AS.
"""

from __future__ import annotations

import ipaddress
import random
import uuid
from datetime import date

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assess import raised
from argus.assess.raised import CAMPAIGN, OPERATOR, OUTSIDE
from argus.campaigns import analysis
from argus.campaigns.analysis import Reading, World, analyse
from argus.campaigns.families import Sighting
from argus.cases.membership import Shared, load_shared
from tests.unit.campaigns.test_analysis import NOW, device, host, inv, names

FAST = "fast-dns-host.example"  # the real campaign's shape: 5 engines, registered in 2019
SERVICE = "service-windows.example"  # 0 engines, registered in 2022
CLOUDFLARE_PAIR = ("tani.ns.cloudflare.com", "todd.ns.cloudflare.com")


def two_vendors(bad: Reading, ok: Reading) -> tuple[World, frozenset[uuid.UUID]]:
    """The reviewer's world: a flagged C2 domain reached by 3 devices, and an unrelated SaaS
    vendor (unranked, 5 devices, 30 names of telemetry) that is ordinary."""
    items = []
    for d in range(1, 4):
        items.append(Sighting(inv(d), device(d), frozenset(names("evil-c2.example-bad.net", 3, d))))
    for d in range(10, 15):
        items.append(
            Sighting(inv(100 + d), device(d), frozenset(names("vendor-telemetry.io", 6, d)))
        )
    readings = {"example-bad.net": bad, "vendor-telemetry.io": ok}
    hosts = {s.investigation_id: s.hosts for s in items}
    vendor = frozenset(s.investigation_id for s in items if any("vendor" in n for n in s.names))
    return World(tuple(items), readings, {}, hosts), vendor


def vendor(**more: object) -> Reading:
    base = {"found": True, "malicious": 0, "engines": 90, "ranked": False,
            "created": date(2025, 3, 1), "owner": "Y"}  # fmt: skip
    return Reading(**{**base, **more})  # type: ignore[arg-type]


def bad(**more: object) -> Reading:
    base = {"found": True, "malicious": 6, "engines": 90, "ranked": False,
            "created": date(2026, 10, 1), "owner": "X"}  # fmt: skip
    return Reading(**{**base, **more})  # type: ignore[arg-type]


def tied(world: World, vendors: frozenset[uuid.UUID]) -> bool:
    out = analyse(world, shared=load_shared(), now=NOW)
    return bool(out.flags[OPERATOR] & vendors)


# -- the reviewer's scenarios (review 1) --------------------------------------------------------


def test_two_unrelated_customers_of_one_big_cloud_are_not_one_operator() -> None:
    world, v = two_vendors(
        bad(asn=16509, address="52.1.1.1", addresses=("52.1.1.1",),
            name_servers=("ns-1.awsdns-01.com",)),
        vendor(asn=16509, address="3.5.5.5", addresses=("3.5.5.5",),
               name_servers=("ns-9.awsdns-02.org",)),
    )  # fmt: skip
    assert not tied(world, v)  # AS16509 is Amazon's: it says nothing about who is behind it
    out = analyse(world, shared=load_shared(), now=NOW)
    assert not out.flags[OPERATOR]
    # the vendor is rare and large, but raised by nothing: the pair of flags needs a tie
    assert not raised.raises([f for f, ids in out.flags.items() if v & ids])


def test_route53_zones_that_share_a_pool_are_not_one_operator() -> None:
    """Two zones whose servers are in the same awsdns-NN pool but are not the same set."""
    world, v = two_vendors(
        bad(asn=64501, address="203.0.113.9", addresses=("203.0.113.9",),
            name_servers=("ns-1.awsdns-01.com", "ns-2.awsdns-02.org", "ns-3.awsdns-03.co.uk",
                          "ns-4.awsdns-04.net")),
        vendor(asn=64502, address="198.51.100.9", addresses=("198.51.100.9",),
               name_servers=("ns-77.awsdns-01.com", "ns-78.awsdns-02.org",
                             "ns-79.awsdns-03.co.uk", "ns-80.awsdns-04.net")),
    )  # fmt: skip
    assert not tied(world, v)


def test_the_same_hoster_digitalocean_ties_nothing() -> None:
    world, v = two_vendors(
        bad(asn=14061, address="159.65.1.1", addresses=("159.65.1.1",)),
        vendor(asn=14061, address="64.225.2.2", addresses=("64.225.2.2",)),
    )  # fmt: skip
    assert not tied(world, v)


def test_a_shared_dns_hosts_default_pair_ties_nothing() -> None:
    """Namecheap's default pair serves every customer alike: two rare domains on it are not one
    operator (the fixer's open risk 1, D-174)."""
    pair = ("dns1.registrar-servers.com", "dns2.registrar-servers.com")
    world, v = two_vendors(
        bad(asn=64501, address="203.0.113.9", addresses=("203.0.113.9",), name_servers=pair),
        vendor(asn=64502, address="198.51.100.9", addresses=("198.51.100.9",), name_servers=pair),
    )  # fmt: skip
    assert not tied(world, v)
    assert analysis.name_server_set(bad(name_servers=pair), load_shared()) == frozenset()


def test_a_pair_with_one_server_of_its_own_still_ties() -> None:
    pair = ("dns1.registrar-servers.com", "ns1.operator-own.example")
    world, v = two_vendors(
        bad(asn=64501, address="203.0.113.9", addresses=("203.0.113.9",), name_servers=pair),
        vendor(asn=64502, address="198.51.100.9", addresses=("198.51.100.9",), name_servers=pair),
    )  # fmt: skip
    assert tied(world, v)


def test_nothing_shared_nothing_tied() -> None:
    world, v = two_vendors(
        bad(asn=64501, address="203.0.113.9", addresses=("203.0.113.9",)),
        vendor(asn=64502, address="198.51.100.9", addresses=("198.51.100.9",)),
    )  # fmt: skip
    assert not tied(world, v)


def test_a_small_operators_autonomous_system_still_ties() -> None:
    world, v = two_vendors(
        bad(asn=51852, address="203.0.113.9", addresses=("203.0.113.9",)),
        vendor(asn=51852, address="198.51.100.9", addresses=("198.51.100.9",)),
    )  # fmt: skip
    assert tied(world, v)  # Private Layer is not on the list of big hosters


def test_the_listed_hosters_cover_the_big_clouds() -> None:
    systems = load_shared().autonomous_systems
    wanted = {16509, 14618, 15169, 396982, 8075, 14061, 16276, 24940, 63949, 20940, 13335, 54113,
              37963, 45102, 31898, 20473, 51167, 132203, 59019}  # fmt: skip
    assert wanted <= systems
    assert 51852 not in systems


# -- the real DNS campaign (R1): no address, a Cloudflare pair of name servers -------------------


def real_dns_world(**over: Reading) -> World:
    """Both domains point nowhere (no A record) and use the same pair of Cloudflare name servers;
    fast-dns-host was registered in 2019 (5 engines), service-windows in 2022 (none); both are
    rare (only DNS-volume lists rank them). Seven devices reach one or both."""
    items = []
    for d in range(1, 5):
        items.append(Sighting(inv(d), device(d), frozenset(names(FAST, 6, d))))
    for d in range(3, 8):
        items.append(Sighting(inv(100 + d), device(d), frozenset(names(SERVICE, 6, 50 + d))))
    readings = {
        FAST: Reading(True, 5, 0, 92, False, None, date(2019, 3, 4), "Reg", CLOUDFLARE_PAIR),
        SERVICE: Reading(True, 0, 0, 92, False, None, date(2022, 6, 9), "Reg", CLOUDFLARE_PAIR),
    }
    hosts = {s.investigation_id: s.hosts for s in items}
    return World(tuple(items), {**readings, **over}, {}, hosts)


def test_the_real_dns_pair_is_one_operator_by_its_name_server_set() -> None:
    world = real_dns_world()
    # cloudflare.com is on the shared list (Cloudflare serves everyone's names) ...
    shared = load_shared()
    assert shared.reason("domain", "cloudflare.com") is not None
    out = analyse(world, shared=shared, now=NOW)
    (campaign,) = out.campaigns
    assert set(campaign.parents) == {FAST, SERVICE}
    assert campaign.flagged == (FAST,)
    assert campaign.hosts == {host(d) for d in range(1, 8)}
    sister = frozenset(
        s.investigation_id for s in world.sightings if any(SERVICE in n for n in s.names)
    )
    assert out.flags[OPERATOR] == sister  # (service-windows is tied to the detected fast-dns-host)
    assert out.flags[OUTSIDE] == frozenset(
        s.investigation_id for s in world.sightings if any(FAST in n for n in s.names)
    )
    assert campaign.infrastructure == (f"name servers {' and '.join(sorted(CLOUDFLARE_PAIR))}",)
    # the age of FAST (2019) or the clean look of SERVICE (0 engines) excludes neither
    assert out.flags[CAMPAIGN] >= sister
    assert campaign.benign == ()


def test_a_different_pair_of_cloudflare_name_servers_is_another_account() -> None:
    other = Reading(True, 0, 0, 92, False, None, date(2022, 6, 9), "Reg",
                    ("bob.ns.cloudflare.com", "kim.ns.cloudflare.com"))  # fmt: skip
    out = analyse(real_dns_world(**{SERVICE: other}), shared=load_shared(), now=NOW)
    assert not out.flags[OPERATOR]
    (campaign,) = out.campaigns
    assert campaign.parents == (FAST,)  # the flagged domain alone is still a campaign of 4


def test_an_old_domain_is_not_benign_unless_it_is_popular() -> None:
    old = Reading(True, 0, 0, 92, False, None, date(2012, 1, 1))
    assert not old.benign()
    assert Reading(True, 0, 0, 92, True, 28_474, date(2012, 1, 1)).benign()


# -- the first address outside shared networks and special-purpose space ------------------------


SINKS = ["127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.0.9", "169.254.1.1"]  # noqa: S104


@pytest.mark.parametrize("sink", SINKS)
def test_domains_that_point_at_a_sinkhole_are_not_one_operator(sink: str) -> None:
    """A taken-down domain points at loopback or a private address: thousands of unrelated ones."""
    world, v = two_vendors(
        bad(addresses=(sink,), address=sink, asn=64501),
        vendor(addresses=(sink,), address=sink, asn=64501),
    )  # fmt: skip
    assert not tied(world, v)


def test_the_first_address_outside_the_shared_networks_is_the_one_that_counts() -> None:
    cloud = Shared(networks=(ipaddress.ip_network("104.16.0.0/13"),))
    world, v = two_vendors(
        bad(addresses=("104.16.1.1", "203.0.113.9"), address="203.0.113.9"),
        vendor(addresses=("104.17.5.5", "203.0.113.200"), address="203.0.113.200"),
    )  # fmt: skip
    out = analyse(world, shared=cloud, now=NOW)
    assert out.flags[OPERATOR] & v  # the CDN addresses are skipped; the /24 behind them ties
    far = vendor(addresses=("104.17.5.5", "198.51.100.200"), address="198.51.100.200")
    world, v = two_vendors(bad(addresses=("104.16.1.1", "203.0.113.9"), address="203.0.113.9"), far)
    assert not analyse(world, shared=cloud, now=NOW).flags[OPERATOR] & v


def test_a_family_that_points_at_a_flagged_address_is_tied_to_it_by_any_of_its_addresses() -> None:
    world, _ = two_vendors(
        bad(addresses=("203.0.113.9",), address="203.0.113.9"),
        vendor(addresses=("198.51.100.4", "192.0.2.77"), address="198.51.100.4"),
    )  # fmt: skip
    server = "192.0.2.77"  # the vendor's second address, in a /24 of its own
    hosts = {**world.hosts, inv(900): device(20), inv(901): device(21)}
    world = World(world.sightings, world.readings, {server: frozenset({inv(900), inv(901)})},
                  hosts)  # fmt: skip
    out = analyse(world, shared=load_shared(), now=NOW)
    assert any(server in c.servers and "vendor-telemetry.io" in c.parents for c in out.campaigns)


# -- an address of a popular family is no flagged server (review 3) -----------------------------


def test_a_flagged_address_a_popular_family_points_at_is_no_campaign() -> None:
    server = "203.0.113.50"
    reached = {server: frozenset({inv(1), inv(2)})}
    hosts = {inv(1): device(1), inv(2): device(2)}
    alone = World((), {}, reached, hosts)
    assert len(analyse(alone, now=NOW).campaigns) == 1  # the Amadey shape: control
    popular = Reading(True, 3, 0, 90, True, 500, date(2012, 1, 1), addresses=(server,))
    sightings = (Sighting(inv(1), device(1), frozenset({"www.popular-site.example"})),)
    world = World(sightings, {"popular-site.example": popular}, reached, hosts)
    assert analyse(world, now=NOW).campaigns == ()  # the address is a popular service's
    rare = Reading(True, 3, 0, 90, False, None, date(2012, 1, 1), addresses=(server,))
    world = World(sightings, {"popular-site.example": rare}, reached, hosts)
    assert len(analyse(world, now=NOW).campaigns) == 1  # an unranked family's address still is


# -- properties ---------------------------------------------------------------------------------

SERVERS = ["ns1.a.example", "ns2.a.example", "ns3.a.example", "ns1.b.example", "ns2.b.example",
           "dns1.registrar-servers.com", "dns2.registrar-servers.com", "tani.ns.cloudflare.com",
           "todd.ns.cloudflare.com"]  # fmt: skip
ADDRESSES = ["203.0.113.9", "203.0.113.200", "198.51.100.4", "192.0.2.77", "127.0.0.1", "10.0.0.5"]
SHARED = Shared(networks=(ipaddress.ip_network("192.0.2.0/24"),),
                domains=frozenset({"registrar-servers.com", "cloudflare.com"}),
                autonomous_systems=frozenset({16509}))  # fmt: skip


@st.composite
def readings(draw: st.DrawFn) -> Reading:
    where = draw(st.lists(st.sampled_from(ADDRESSES), max_size=3, unique=True))
    asn = draw(st.sampled_from([None, 16509, 64501, 64502]))
    looked = draw(st.sampled_from(where)) if where and draw(st.booleans()) else None
    return Reading(True, 0, 0, 90, False, None, None, None,
                   tuple(draw(st.lists(st.sampled_from(SERVERS), max_size=4, unique=True))),
                   tuple(where), looked, asn, "Owner")  # fmt: skip


@given(readings(), readings())
def test_two_readings_share_a_key_only_by_the_three_ties(a: Reading, b: Reading) -> None:
    keys_a, keys_b = analysis.operator_keys(a, SHARED), analysis.operator_keys(b, SHARED)
    for kind, value in keys_a & keys_b:
        if kind == "ns":
            assert set(a.name_servers) == set(b.name_servers)  # an identical set ...
            assert len(set(a.name_servers)) >= 2  # ... of two or more
            assert not all(  # ... not a shared DNS host's default
                SHARED.reason("domain", s) is not None
                and not s.endswith(analysis.ACCOUNT_NAME_SERVERS)
                for s in a.name_servers
            )
        elif kind == "net":
            fa, fb = analysis.first_tie_address(a, SHARED), analysis.first_tie_address(b, SHARED)
            assert fa is not None
            assert fb is not None
            assert analysis.net_of(fa) == analysis.net_of(fb) == value
            assert SHARED.reason("ip", fa) is None  # outside the shared networks
            assert ipaddress.ip_address(fa).is_global or fa.startswith(("203.", "198.", "192."))
        else:
            assert kind == "as"
            assert a.asn == b.asn == int(value)
            assert int(value) != 16509  # a big hoster's number ties nothing


@given(readings())
def test_a_reading_never_ties_by_what_it_cannot_say(r: Reading) -> None:
    keys = {kind for kind, _ in analysis.operator_keys(r, SHARED)}
    if len(set(r.name_servers)) < 2:
        assert "ns" not in keys
    if r.asn == 16509 or r.address is None:
        assert "as" not in keys
    assert not any(v.startswith(("127.", "10.")) for k, v in analysis.operator_keys(r, SHARED)
                   if k == "net")  # fmt: skip


@given(st.randoms(use_true_random=False))
def test_the_ties_are_the_same_in_any_order(rnd: random.Random) -> None:
    world = real_dns_world()
    items = list(world.sightings)
    rnd.shuffle(items)
    again = World(tuple(items), world.readings, world.servers, world.hosts, world.threshold)
    shared = load_shared()
    assert analyse(world, shared=shared, now=NOW) == analyse(again, shared=shared, now=NOW)
