"""AR2c (D-168, D-170): what the families and the outside answers say together. The synthetic world
is the DNS campaign of D-168 in miniature: two domains of one operator reached by many campus
devices, one of them flagged outside, with a popular benign family in the same alerts and a rare
lone family nobody flags. Names are made up (RFC 5737 addresses, invented domains).
"""

from __future__ import annotations

import ipaddress
import random
import uuid
from dataclasses import replace
from datetime import UTC, date, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assess.raised import CAMPAIGN, OPERATOR, OUTSIDE
from argus.campaigns import analysis
from argus.campaigns.analysis import Reading, World, analyse, reading_of
from argus.campaigns.families import Key, Sighting
from argus.cases.membership import Shared
from argus.outside import facts

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
DGA = "rapid-dns-hosting.com"  # flagged by 5 engines
SISTER = "win-service-portal.com"  # not flagged; the same operator
BENIGN = "cdn-edge-bench.net"  # old and popular
LONE = "qqq-lone-site.com"  # rare, large, tied to nothing
OP_NS = "ns1.shady-dns-farm.net"


def host(n: int) -> Key:
    return ("ip", f"10.1.0.{n}")


def device(n: int) -> frozenset[Key]:
    return frozenset({host(n)})


def inv(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


def names(parent: str, k: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    return [f"{rnd.randrange(16**8):08x}.{parent}" for _ in range(k)]


def reading(**more: object) -> Reading:
    base: dict[str, object] = {"found": True, "ranked": False, "created": date(2026, 10, 2)}
    return Reading(**{**base, **more})  # type: ignore[arg-type]


OP_NS_SET = (OP_NS, "ns2.shady-dns-farm.net")  # the operator's own pair of name servers
OPERATOR_NET = {"addresses": ("203.0.113.9",), "address": "203.0.113.9", "asn": 64501,
                "owner": "Shady Hosting", "name_servers": OP_NS_SET}  # fmt: skip


def campaign_world(**over: object) -> World:
    """Six devices: devices 1-4 reach the flagged domain, 3-6 its sister (1 to 3 also the popular
    benign domain); devices 7-9 a lone rare domain. Each investigation is one device."""
    items: list[Sighting] = []
    for d in range(1, 5):
        extra = [f"www.{BENIGN}"] if d <= 3 else []
        items.append(Sighting(inv(d), device(d), frozenset(names(DGA, 6, d) + extra)))
    for d in range(3, 7):
        items.append(Sighting(inv(100 + d), device(d), frozenset(names(SISTER, 6, 50 + d))))
    for d in range(7, 10):
        items.append(Sighting(inv(200 + d), device(d), frozenset(names(LONE, 8, 90 + d))))
    readings = {
        DGA: reading(malicious=5, engines=91, **OPERATOR_NET),
        SISTER: reading(malicious=0, engines=90, **OPERATOR_NET),
        BENIGN: reading(malicious=0, engines=90, ranked=True, best_rank=412,
                        created=date(2012, 1, 1)),
        LONE: reading(malicious=0, engines=90),
    }  # fmt: skip
    hosts = {s.investigation_id: s.hosts for s in items}
    base: dict[str, object] = {"sightings": tuple(items), "readings": readings, "hosts": hosts}
    return World(**{**base, **over})  # type: ignore[arg-type]


def ids(world: World, parent: str) -> frozenset[uuid.UUID]:
    return frozenset(s.investigation_id for s in world.sightings
                     if any(n.endswith("." + parent) or n == parent for n in s.names))  # fmt: skip


# -- the reading of a cached answer -------------------------------------------------------------


def test_a_reading_is_made_from_the_cached_answers() -> None:
    answer = {
        "malicious": 5, "suspicious": 1, "engines": 91, "shape": facts.DOMAIN_SHAPE,
        "ranked": False,
        "created": "2026-10-02", "registrar": "Reg Inc", "name_servers": [OP_NS],
        "addresses": ["203.0.113.9", "bad", "203.0.113.10"],
    }  # fmt: skip
    got = reading_of("found", answer, {"asn": 64501, "owner": "Shady Hosting"}, "203.0.113.9")
    assert (got.found, got.malicious, got.suspicious, got.engines) == (True, 5, 1, 91)
    assert (got.ranked, got.best_rank, got.created) == (False, None, date(2026, 10, 2))
    assert got.registrar == "Reg Inc"
    assert got.name_servers == (OP_NS,)  # as the answer lists them
    assert got.addresses == ("203.0.113.9", "203.0.113.10")  # what is not an address is dropped
    assert (got.address, got.asn, got.owner) == ("203.0.113.9", 64501, "Shady Hosting")
    assert got.detected(3)
    assert not got.detected(6)
    assert got.unranked
    assert not got.popular
    assert reading_of("found", answer).address is None  # no look-up of the address yet


def test_no_record_is_rare_and_says_nothing_else() -> None:
    got = reading_of("not_found", {})
    assert (got.found, got.unranked, got.popular, got.detected(1)) == (False, True, False, False)
    assert not got.benign()


def test_an_answer_that_does_not_say_whether_it_is_ranked_is_not_rare() -> None:
    got = reading_of("found", {"malicious": 0, "engines": 90, "shape": facts.DOMAIN_SHAPE})
    assert got.ranked is None
    assert not got.unranked
    assert not got.popular


def test_benign_is_popular_on_the_web_with_no_engine_against_it() -> None:
    assert reading(malicious=0, ranked=True, created=None).benign()
    assert reading(malicious=0, ranked=True, created=date(2026, 6, 1)).benign()  # young but popular
    assert not reading(malicious=1, ranked=True).benign()  # one engine is enough to doubt it
    # age alone is not enough: fast-dns-host.com was registered in 2019 and is a campaign (D-174)
    old = reading(malicious=0, ranked=False, created=date(2019, 1, 1))
    assert not old.benign()
    assert not reading(malicious=0, ranked=False, created=date(2020, 1, 1)).benign()
    assert not reading(malicious=0, ranked=None, created=date(2012, 1, 1)).benign()


@pytest.mark.parametrize(
    ("status", "answer", "expected"),
    [("found", {"shape": facts.DOMAIN_SHAPE}, True), ("found", {"malicious": 1}, False),
     ("found", {"shape": 2}, False), ("found", {"shape": 1}, False), ("not_found", {}, True)],
)  # fmt: skip
def test_only_the_current_shape_is_read(
    status: str, answer: dict[str, object], expected: bool
) -> None:
    assert analysis.current(status, answer) is expected


# -- detections, operators, the campaign shape --------------------------------------------------


def test_a_flagged_parent_flags_every_investigation_holding_a_name_under_it() -> None:
    world = campaign_world()
    out = analyse(world, now=NOW)
    assert out.flags[OUTSIDE] == ids(world, DGA)
    assert not out.flags[OUTSIDE] & ids(world, BENIGN) - ids(
        world, DGA
    )  # the benign one: not alone
    assert not out.flags[OUTSIDE] & ids(world, SISTER)  # a sister is tied, not flagged


def test_a_family_tied_to_a_flagged_one_carries_the_operator_flag() -> None:
    world = campaign_world()
    out = analyse(world, now=NOW)
    assert out.flags[OPERATOR] == ids(world, SISTER)
    assert not out.flags[OPERATOR] & ids(world, LONE)


def test_the_campaign_shape_needs_three_hosts_twenty_names_and_no_rank() -> None:
    world = campaign_world()
    out = analyse(world, now=NOW)
    # DGA: 4 hosts, 24 names; SISTER: 4 hosts, 24 names; LONE: 3 hosts, 24 names; the benign
    # family is ranked; every one is looked at
    assert out.flags[CAMPAIGN] == ids(world, DGA) | ids(world, SISTER) | ids(world, LONE)
    thin = campaign_world(sightings=tuple(
        s for s in world.sightings if not (s.investigation_id.int >= 200 and s.hosts == device(9))
    ))  # fmt: skip
    assert ids(thin, LONE)
    assert not analyse(thin, now=NOW).flags[CAMPAIGN] & ids(thin, LONE)
    few_names = campaign_world(sightings=tuple(
        Sighting(s.investigation_id, s.hosts, frozenset(list(s.names)[:2]))
        if any(n.endswith(LONE) for n in s.names) else s
        for s in world.sightings
    ))  # fmt: skip
    assert not analyse(few_names, now=NOW).flags[CAMPAIGN] & ids(few_names, LONE)  # 6 names only


def test_a_ranked_family_never_carries_a_campaign_or_operator_flag_or_a_detection() -> None:
    world = campaign_world()
    popular = {**world.readings,
               DGA: reading(malicious=5, engines=91, ranked=True, **OPERATOR_NET)}  # fmt: skip
    out = analyse(campaign_world(readings=popular), now=NOW)
    assert not out.flags[OUTSIDE]  # a popular site flagged by a few engines: not a campaign
    assert not out.flags[OPERATOR]  # nothing flagged, so nothing to be tied to
    assert not out.flags[CAMPAIGN] & ids(world, DGA)
    assert out.campaigns == ()


def test_a_family_nobody_looked_up_has_no_flag() -> None:
    world = campaign_world(readings={})
    out = analyse(world, now=NOW)
    assert all(not ids_ for ids_ in out.flags.values())
    assert out.campaigns == ()


def test_unknown_popularity_is_not_rarity() -> None:
    quiet = reading(malicious=0, ranked=None)
    out = analyse(campaign_world(readings={**campaign_world().readings, LONE: quiet}), now=NOW)
    assert not out.flags[CAMPAIGN] & ids(campaign_world(), LONE)


def test_the_thresholds_are_those_of_the_decision() -> None:
    assert (analysis.MIN_FLAG_HOSTS, analysis.MIN_FLAG_NAMES, analysis.MIN_SERVER_HOSTS) == (
        3,
        20,
        2,
    )
    below = analyse(campaign_world(threshold=6), now=NOW)  # five engines are below six
    assert not below.flags[OUTSIDE]
    assert below.campaigns == ()


# -- what ties a family to another --------------------------------------------------------------


def tie_world(sister: Reading) -> World:
    world = campaign_world()
    return campaign_world(readings={**world.readings, SISTER: sister})


@pytest.mark.parametrize(
    "sister",
    [
        # the same AS, another network
        reading(
            asn=64501, owner="Shady Hosting", address="198.51.100.4", addresses=("198.51.100.4",)
        ),
        reading(addresses=("203.0.113.200",)),  # the same /24
        reading(addresses=("203.0.113.9",)),  # the very same address
        reading(name_servers=OP_NS_SET),  # the very same pair of name servers
        reading(name_servers=tuple(reversed(OP_NS_SET))),  # (in any order)
    ],
    ids=["same AS", "same /24", "same address", "same name-server set", "same set, other order"],
)
def test_each_tie_makes_the_sister_the_same_operator(sister: Reading) -> None:
    world = tie_world(sister)
    out = analyse(world, now=NOW)
    assert out.flags[OPERATOR] == ids(world, SISTER)


@pytest.mark.parametrize(
    "sister",
    [
        reading(),  # nothing to tie by
        reading(asn=64999, address="198.51.100.4", addresses=("198.51.100.4",)),
        reading(addresses=("203.0.114.9",), name_servers=("ns1.other-dns.net",)),
        # name servers of one registered domain are a pool, not an account's pair (D-174)
        reading(name_servers=("ns2.shady-dns-farm.net", "ns3.shady-dns-farm.net")),
        reading(name_servers=(OP_NS,)),  # one server alone is no set
        reading(name_servers=(OP_NS, "ns9.shady-dns-farm.net", "ns8.other-dns.net")),  # a superset
    ],
    ids=[
        "no infrastructure",
        "another AS and network",
        "near but different",
        "same pool",
        "one server",
        "another set",
    ],
)
def test_no_shared_infrastructure_no_operator(sister: Reading) -> None:
    world = tie_world(sister)
    out = analyse(world, now=NOW)
    assert not out.flags[OPERATOR]
    (campaign,) = out.campaigns
    assert campaign.parents == (DGA,)  # the flagged domain alone is still a campaign of 4 devices


def test_shared_infrastructure_ties_nothing() -> None:
    cloud = Shared(networks=(ipaddress.ip_network("203.0.113.0/24"),))
    plain = {**OPERATOR_NET, "name_servers": ()}  # (the name servers are tested apart)
    world = campaign_world(readings={
        **campaign_world().readings, DGA: reading(malicious=5, engines=91, **plain),
        SISTER: reading(malicious=0, engines=90, **plain),
    })  # fmt: skip
    assert analyse(world, now=NOW).flags[OPERATOR]  # tied by the AS and the /24 ...
    out = analyse(world, shared=cloud, now=NOW)
    assert not out.flags[OPERATOR]  # ... unless the network is everyone's
    shared_address = reading(asn=64501, address="203.0.113.50", addresses=("203.0.113.50",))
    other_as = analyse(tie_world(shared_address), shared=cloud, now=NOW)
    assert not other_as.flags[OPERATOR]  # an AS seen only through a shared address ties nothing


def test_a_big_hoster_ties_nothing_but_an_identical_set_of_name_servers_always_does() -> None:
    hoster = Shared(autonomous_systems=frozenset({64501}))
    plain = {**OPERATOR_NET, "address": "198.51.100.7", "addresses": ("198.51.100.7",)}
    world = campaign_world(readings={
        **campaign_world().readings,
        DGA: reading(malicious=5, engines=91, **{**plain, "name_servers": ()}),
        SISTER: reading(malicious=0, engines=90, **{**plain, "address": "192.0.2.9",
                                                    "addresses": ("192.0.2.9",),
                                                    "name_servers": ()}),
    })  # fmt: skip
    assert analyse(world, now=NOW).flags[OPERATOR]  # one AS, two networks: tied by the AS
    assert not analyse(world, shared=hoster, now=NOW).flags[OPERATOR]  # a hoster's customers
    # an account's own pair of name servers ties even when their provider's domain is shared
    # (Cloudflare gives each account a fixed pair; cloudflare.com is on the shared list)
    both = {**campaign_world().readings,
            DGA: reading(malicious=5, engines=91, asn=64501, address="198.51.100.7",
                         addresses=("198.51.100.7",), name_servers=OP_NS_SET),
            SISTER: reading(malicious=0, engines=90, asn=64501, address="192.0.2.9",
                            addresses=("192.0.2.9",), name_servers=OP_NS_SET)}  # fmt: skip
    account = ("tani.ns.cloudflare.com", "todd.ns.cloudflare.com")
    both = {k: (replace(r, name_servers=account) if k in (DGA, SISTER) else r)
            for k, r in both.items()}  # fmt: skip
    cloud = Shared(domains=frozenset({"cloudflare.com"}), autonomous_systems=frozenset({64501}))
    tied = analyse(campaign_world(readings=both), shared=cloud, now=NOW)
    assert tied.flags[OPERATOR] == ids(campaign_world(), SISTER)
    # a shared DNS host's default set serves all its customers alike: it ties nothing (D-174)
    farm = {k: (replace(r, name_servers=OP_NS_SET) if k in (DGA, SISTER) else r)
            for k, r in both.items()}  # fmt: skip
    pooled = Shared(domains=frozenset({"shady-dns-farm.net"}),
                    autonomous_systems=frozenset({64501}))  # fmt: skip
    assert not analyse(campaign_world(readings=farm), shared=pooled, now=NOW).flags[OPERATOR]


def test_the_operator_needs_a_flagged_member() -> None:
    world = campaign_world()
    readings = {**world.readings, DGA: reading(malicious=0, engines=91, **OPERATOR_NET)}
    out = analyse(campaign_world(readings=readings), now=NOW)
    assert not out.flags[OUTSIDE]
    assert not out.flags[OPERATOR]
    assert out.campaigns == ()
    # rare, alike, and 24 names from 4 devices each: the campaign shape, but no proof of harm
    assert out.flags[CAMPAIGN] >= ids(world, DGA) | ids(world, SISTER)


# -- campaigns ----------------------------------------------------------------------------------


def test_the_dns_campaign_is_one_operator_with_its_devices_and_the_benign_split_off() -> None:
    world = campaign_world()
    out = analyse(world, now=NOW)
    (campaign,) = out.campaigns
    assert set(campaign.parents) == {DGA, SISTER}
    assert campaign.flagged == (DGA,)
    assert campaign.hosts == {host(d) for d in range(1, 7)}  # six devices; 7-9 are another story
    assert campaign.members == ids(world, DGA) | ids(world, SISTER)
    assert campaign.benign == (BENIGN,)
    assert campaign.infrastructure == (
        "AS64501 (Shady Hosting)",
        "network 203.0.113.0/24",
        "name servers ns1.shady-dns-farm.net and ns2.shady-dns-farm.net",
    )
    assert campaign.keys() == {("domain", DGA), ("domain", SISTER)}
    reason = campaign.reason()
    assert reason.startswith("one operator, 6 campus devices: ")
    assert DGA in reason
    assert SISTER in reason
    assert f"(flagged outside: {DGA})" in reason
    assert "; infrastructure: AS64501 (Shady Hosting), network 203.0.113.0/24" in reason
    assert "(benign, ARGUS recommends closing): " + BENIGN in reason
    assert LONE not in reason


def test_the_domains_widest_first_and_the_random_share_in_the_words() -> None:
    out = analyse(campaign_world(), now=NOW)
    (campaign,) = out.campaigns
    assert campaign.parents[0] in (DGA, SISTER)
    assert 0.0 <= campaign.random_share <= 1.0
    assert campaign.random_share >= 0.8  # eight hex digits mostly look random
    assert "% of the names look random" in campaign.reason()


def test_a_benign_family_of_the_same_alerts_is_listed_even_in_other_investigations() -> None:
    """The DNS rule makes one investigation for each rare domain: the popular domains it fired on
    beside the campaign's are in investigations of their own, raised by the same rule."""
    base = campaign_world()
    rule = "DNS rare domain"

    def rare_rule(s: Sighting) -> Sighting:  # (without the popular names it held itself)
        return Sighting(
            s.investigation_id, s.hosts, frozenset(n for n in s.names if BENIGN not in n), rule
        )

    own = tuple(rare_rule(s) for s in base.sightings if s.investigation_id.int < 200)
    others = (
        Sighting(inv(300), device(1) | device(2), frozenset(names(BENIGN, 5, 7)), rule),
        Sighting(inv(301), device(3) | device(4), frozenset(names(BENIGN, 5, 8)), rule),
        Sighting(inv(302), device(5) | device(6), frozenset(names(BENIGN, 5, 9)), rule),
    )
    world = campaign_world(sightings=(*own, *others))
    benign = analyse(world, now=NOW).campaigns[0].benign
    assert benign == (BENIGN,)  # not in the campaign's investigations, but the same alerts
    # another rule's investigations of the same devices are not "in the same alerts" ...
    elsewhere = tuple(Sighting(s.investigation_id, s.hosts, s.names, "proxy rule") for s in others)
    world = campaign_world(sightings=(*own, *elsewhere))
    assert analyse(world, now=NOW).campaigns[0].benign == ()
    # ... while the same rule's investigations of other devices are (the DNS rule's popular
    # domains were asked for by other devices than the campaign's)
    strangers = (
        Sighting(inv(300), device(20) | device(21), frozenset(names(BENIGN, 5, 7)), rule),
        Sighting(inv(301), device(22) | device(23), frozenset(names(BENIGN, 5, 8)), rule),
        Sighting(inv(302), device(24) | device(25), frozenset(names(BENIGN, 5, 9)), rule),
    )
    world = campaign_world(sightings=(*own, *strangers))
    assert analyse(world, now=NOW).campaigns[0].benign == (BENIGN,)


def test_one_device_is_not_a_campaign() -> None:
    world = campaign_world()
    one = campaign_world(sightings=tuple(s for s in world.sightings if s.hosts == device(1)),
                         readings={DGA: world.readings[DGA]})  # fmt: skip
    assert analyse(one, now=NOW).campaigns == ()
    two = campaign_world(
        sightings=tuple(s for s in world.sightings if s.hosts <= {host(1), host(2)}),
        readings={DGA: world.readings[DGA]},
    )  # fmt: skip
    (campaign,) = analyse(two, now=NOW).campaigns
    assert len(campaign.hosts) == 2  # the Amadey shape: two devices reaching one flagged server


def test_a_flagged_address_reached_by_two_devices_is_a_campaign() -> None:
    reached = {"203.0.113.50": frozenset({inv(1), inv(2), inv(3)})}
    world = World((), {}, reached, {inv(1): device(1), inv(2): device(2), inv(3): device(1)})
    (campaign,) = analyse(world, now=NOW).campaigns
    assert campaign.servers == ("203.0.113.50",)
    assert campaign.flagged == ("203.0.113.50",)
    assert campaign.hosts == {host(1), host(2)}
    assert len(campaign.members) == 3
    assert (
        campaign.reason()
        == "one operator, 2 campus devices: 203.0.113.50 (flagged outside: 203.0.113.50)"
    )
    alone = World((), {}, {"203.0.113.50": frozenset({inv(1), inv(3)})}, world.hosts)
    assert analyse(alone, now=NOW).campaigns == ()  # one device twice


def test_servers_of_one_network_are_one_campaign() -> None:
    servers = {f"203.0.113.{n}": frozenset({inv(n), inv(10 + n)}) for n in (50, 51, 52)}
    hosts = {i: device(i.int % 10 + 1) for ids_ in servers.values() for i in ids_}
    out = analyse(World((), {}, servers, hosts), now=NOW)
    (campaign,) = out.campaigns
    assert campaign.servers == ("203.0.113.50", "203.0.113.51", "203.0.113.52")
    far = {**servers, "198.51.100.7": frozenset({inv(70), inv(71)})}
    hosts = {**hosts, inv(70): device(8), inv(71): device(9)}
    assert len(analyse(World((), {}, far, hosts), now=NOW).campaigns) == 2


def test_a_server_in_shared_infrastructure_is_no_campaign() -> None:
    reached = {"203.0.113.50": frozenset({inv(1), inv(2)})}
    world = World((), {}, reached, {inv(1): device(1), inv(2): device(2)})
    cloud = Shared(networks=(ipaddress.ip_network("203.0.113.0/24"),))
    assert analyse(world, shared=cloud, now=NOW).campaigns == ()


def test_a_flagged_address_that_a_family_points_at_ties_the_family_to_it() -> None:
    world = campaign_world()
    reached = {"203.0.113.9": frozenset({inv(40), inv(41)})}
    hosts = {**world.hosts, inv(40): device(20), inv(41): device(21)}
    out = analyse(campaign_world(servers=reached, hosts=hosts), now=NOW)
    (campaign,) = out.campaigns
    assert campaign.servers == ("203.0.113.9",)
    assert {host(20), host(21)} <= campaign.hosts
    assert set(campaign.parents) == {DGA, SISTER}


def test_an_unusable_parent_is_never_read() -> None:
    out = analyse(campaign_world(), now=NOW, usable=lambda parent: parent != DGA)
    assert not out.flags[OUTSIDE]
    assert out.campaigns == ()
    shared = Shared(domains=frozenset({DGA}))
    assert not analyse(campaign_world(), shared=shared, now=NOW).flags[OUTSIDE]


# -- properties ---------------------------------------------------------------------------------


@st.composite
def worlds(draw: st.DrawFn) -> World:
    parents = ["a-rare.com", "b-rare.com", "c-rare.com", "d-pop.net"]
    items = []
    hosts: dict[uuid.UUID, Key] = {}
    for n in range(draw(st.integers(0, 14))):
        h = host(draw(st.integers(1, 6)))
        picked = draw(st.lists(st.sampled_from(parents), min_size=1, max_size=3))
        count = draw(st.integers(1, 12))
        found_names = frozenset(f"x{k}{n}.{p}" for p in picked for k in range(count))
        items.append(Sighting(inv(n + 1), frozenset({h}), found_names))
        hosts[inv(n + 1)] = h
    readings = {}
    for p in parents:
        if draw(st.booleans()):
            readings[p] = reading(
                malicious=draw(st.sampled_from([0, 0, 3, 8])),
                engines=90,
                ranked=draw(st.sampled_from([False, False, True, None])),
                asn=draw(st.sampled_from([None, 64501, 64502])),
                address=draw(st.sampled_from([None, "203.0.113.9"])),
                addresses=draw(st.sampled_from([(), ("203.0.113.9",), ("198.51.100.4",)])),
            )
    reached = {}
    if draw(st.booleans()) and items:
        reached["203.0.113.77"] = frozenset(
            s.investigation_id for s in items[: draw(st.integers(1, 4))]
        )
    return World(tuple(items), readings, reached, hosts, 3)


@given(worlds(), st.randoms(use_true_random=False))
def test_the_analysis_is_the_same_in_any_order(world: World, rnd: random.Random) -> None:
    items = list(world.sightings)
    rnd.shuffle(items)
    again = World(tuple(items), world.readings, world.servers, world.hosts, world.threshold)
    assert analyse(world, now=NOW) == analyse(again, now=NOW)


@given(worlds())
def test_what_the_analysis_says_is_consistent(world: World) -> None:
    out = analyse(world, now=NOW)
    everyone = {s.investigation_id for s in world.sightings}
    for flag_ids in out.flags.values():
        assert flag_ids <= everyone
    for c in out.campaigns:
        assert len(c.hosts) >= analysis.MIN_SERVER_HOSTS
        assert c.flagged
        assert set(c.flagged) <= {*c.parents, *c.servers}
        assert c.members
        assert c.hosts == {h for i in c.members for h in world.hosts.get(i, ())}
        assert set(c.member_hosts) <= c.members  # the suggester treats these as its actors
        assert 0.0 <= c.random_share <= 1.0
        assert c.reason().startswith("one operator, ")
        for p in c.parents:
            assert out.families[p].investigations <= c.members
    # a detection is a reading that says so, of a family that is not ranked
    detected = [p for p, r in world.readings.items() if r.detected(3) and not r.popular]
    named = set().union(*(out.families[p].investigations for p in detected if p in out.families))
    assert out.flags[OUTSIDE] == frozenset(named)
    # an investigation whose names are all under ranked families is flagged by nothing
    for s in world.sightings:
        parents = {p for p, f in out.families.items() if s.investigation_id in f.investigations}
        if parents and all(world.readings.get(p) and world.readings[p].popular for p in parents):
            assert all(s.investigation_id not in ids_ for ids_ in out.flags.values())
