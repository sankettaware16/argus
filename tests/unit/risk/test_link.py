"""The linker (E2): which campus objects become one incident, and what never links them. The
adversarial fixtures (a NAT with 300 users, a resolver in a DNS key, a scanner hitting 500 sites)
are here; DHCP reuse is in test_identity. Every value is made up (the suite's ACME site)."""

from __future__ import annotations

import ipaddress
import random
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest

from argus.assets.classify import IpClassifier
from argus.risk import incident_config, link
from argus.risk.identity import Identity, SignIn
from argus.risk.incidents import group_flags
from argus.risk.link import Flag, World
from argus.risk.observe import ObjectRef, Observation, observe
from argus.risk.score import Factors, Stats

from .conftest import CONFIG, NOW, context, group, meta, obs

pytestmark = pytest.mark.unit
LINKING = incident_config.load()
NEUTRAL = Stats()
EMPTY = World()


def dev(n: int) -> ObjectRef:
    return ObjectRef("device", f"ip:10.1.{n // 250}.{n % 250 + 1}")


def seen(
    n: int, threats: tuple[str, ...], *, hours_ago: float = 1.0, source: str = "rule:L1",
    role: str = "actor", kind: str = "device", key: str | None = None,
) -> Observation:  # fmt: skip
    ref = dev(n)
    return obs(source, key=key or ref.key, kind=kind, role=role, hours_ago=hours_ago,
               threats=threats)  # fmt: skip


def lanes(*refs: ObjectRef) -> dict[ObjectRef, tuple[str, ...]]:
    return dict.fromkeys(refs, ("decisive",))


def run(
    observations: list[Observation], candidates: dict[ObjectRef, tuple[str, ...]],
    world: World = EMPTY, stats: Stats = NEUTRAL,
) -> list[link.Component]:  # fmt: skip
    return link.link_all(observations, NOW, candidates, LINKING, stats, world)


def sizes(components: list[link.Component]) -> list[int]:
    return sorted((len(c.objects) for c in components), reverse=True)


# --------------------------------------------------------------------------- links by kind


def test_a_flagged_domain_within_seven_days_links_two_devices_with_a_reason() -> None:
    t = "domain:c2-example.net"
    found = run([seen(1, (t,), hours_ago=100), seen(2, (t,))], lanes(dev(1), dev(2)),
                World({t: Flag("outside")}))  # fmt: skip
    assert sizes(found) == [2]
    reasons = [lk.reason for lk in found[0].links if lk.b is not None]
    assert any("c2-example.net" in r and "flagged by outside threat intel" in r for r in reasons)
    assert all(len(lk.reason) <= 200 for lk in found[0].links)


def test_a_flagged_domain_too_far_apart_does_not_link() -> None:
    t = "domain:c2-example.net"
    found = run([seen(1, (t,), hours_ago=24 * 8 + 5), seen(2, (t,))], lanes(dev(1), dev(2)),
                World({t: Flag("outside")}))  # fmt: skip
    assert sizes(found) == [1, 1]


def test_a_rare_domain_links_within_48_hours_only() -> None:
    t = "domain:rare-example.org"
    near = run([seen(1, (t,), hours_ago=40), seen(2, (t,))], lanes(dev(1), dev(2)))
    far = run([seen(1, (t,), hours_ago=60), seen(2, (t,))], lanes(dev(1), dev(2)))
    assert sizes(near) == [2]
    assert sizes(far) == [1, 1]
    assert "rare" in next(lk.via for lk in near[0].links if lk.b is not None)


def test_a_domain_seven_objects_reached_is_not_rare_and_a_popular_one_never_is() -> None:
    t = "domain:common-example.org"
    wide = [seen(n, (t,)) for n in range(7)]
    assert max(sizes(run(wide, lanes(*(dev(n) for n in range(7)))))) == 1
    two = [seen(1, (t,)), seen(2, (t,))]
    assert sizes(run(two, lanes(dev(1), dev(2)), World(popular={t}))) == [1, 1]


def test_a_bare_outside_address_links_within_8_hours_and_three_objects() -> None:
    t = "ip:45.33.12.7"
    assert sizes(run([seen(1, (t,), hours_ago=7), seen(2, (t,))], lanes(dev(1), dev(2)))) == [2]
    assert sizes(run([seen(1, (t,), hours_ago=10), seen(2, (t,))], lanes(dev(1), dev(2)))) == [1, 1]
    four = [seen(n, (t,)) for n in range(4)]
    assert max(sizes(run(four, lanes(*(dev(n) for n in range(4)))))) == 1


def test_a_noisy_source_never_bridges() -> None:
    t = "domain:rare-example.org"
    noisy = Stats({("rule:NOISY", "actor"): Factors(prevalence=0.41)})
    found = run([seen(1, (t,), source="rule:NOISY"), seen(2, (t,), source="rule:NOISY")],
                lanes(dev(1), dev(2)), stats=noisy)  # fmt: skip
    assert sizes(found) == [1, 1]


def test_a_popular_site_never_links_even_when_a_list_flags_it() -> None:
    t = "domain:popular-cdn-example.com"
    world = World({t: Flag("ti")}, popular={t})
    found = run([seen(n, (t,)) for n in range(5)], lanes(*(dev(n) for n in range(5))), world)
    assert max(sizes(found)) == 1
    assert not link.campaign_lane([seen(n, (t,)) for n in range(5)], NOW, LINKING, NEUTRAL,
                                  world, set())  # fmt: skip


def test_each_pair_keeps_its_best_link() -> None:
    flagged, rare = "domain:c2-example.net", "domain:rare-example.org"
    found = run([seen(1, (flagged, rare)), seen(2, (flagged, rare))], lanes(dev(1), dev(2)),
                World({flagged: Flag("ti")}))  # fmt: skip
    pairs = [lk for lk in found[0].links if lk.b is not None]
    assert len(pairs) == 1
    assert pairs[0].via == "flagged"


# --------------------------------------------------------------------------- pull-in and depth


def test_an_object_outside_every_lane_joins_only_through_a_strong_link() -> None:
    flagged, rare = "domain:c2-example.net", "domain:rare-example.org"
    world = World({flagged: Flag("outside")})
    pulled = run([seen(1, (flagged,)), seen(2, (flagged,))], lanes(dev(1)), world)
    kept_out = run([seen(1, (rare,)), seen(2, (rare,))], lanes(dev(1)), world)
    assert sizes(pulled) == [2]
    assert sizes(kept_out) == [1]


def test_pull_in_stops_at_the_depth() -> None:
    # dev1 (in a lane) - account u1 - dev2 - account u2 - dev3 - account u3 - dev4
    at = NOW - timedelta(hours=2)
    signs = [SignIn(dev(n), f"user{u}", at, at + timedelta(hours=1))
             for u, n in ((1, 1), (1, 2), (2, 2), (2, 3), (3, 3), (3, 4))]  # fmt: skip
    found = run([seen(n, ()) for n in (1, 2, 3, 4)], lanes(dev(1)), World(sign_ins=signs))
    assert sizes(found) == [3]  # dev4 is three steps away


def test_a_flagged_destination_two_devices_reached_is_a_campaign() -> None:
    t = "domain:c2-example.net"
    found = run([seen(1, (t,)), seen(2, (t,))], {}, World({t: Flag("outside")}))
    assert sizes(found) == [2]
    assert found[0].campaign
    assert all(lanes_ == ("campaign",) for lanes_ in found[0].lanes.values())


# --------------------------------------------------------------------------- the caps


def test_a_chain_past_the_device_cap_is_split_and_the_rest_recommended() -> None:
    chain = []
    for n in range(60):  # dev n and dev n+1 share a rare domain of their own
        t = f"domain:rare-{n}-example.org"
        chain += [seen(n, (t,)), seen(n + 1, (t,))]
    found = run(chain, lanes(*(dev(n) for n in range(61))))
    assert max(c.devices for c in found) == LINKING.caps.objects
    assert sum(c.devices for c in found) == 61
    assert any(not lk.kept and "50 risk objects" in lk.reason
               for c in found for lk in c.recommended)  # fmt: skip


def test_a_flagged_campaign_may_hold_more_devices_than_the_cap() -> None:
    t = "domain:campaign-example.net"
    many = [seen(n, (t,)) for n in range(80)]
    found = run(many, lanes(*(dev(n) for n in range(80))), World({t: Flag("outside")}))
    assert sizes(found) == [80]
    assert found[0].campaign


# --------------------------------------------------------------------------- adversarial


def test_a_nat_with_300_users_never_joins_them() -> None:
    nat = 999
    world: list[Observation] = []
    for n in range(300):  # each user's own rare destination, also seen through the NAT
        t = f"domain:user-{n}-example.org"
        world += [seen(n, (t,)), seen(nat, (t,))]
    found = run(world, lanes(*(dev(n) for n in range(300)), dev(nat)))
    assert max(sizes(found)) == 1
    assert all(dev(nat) not in c.objects or len(c.objects) == 1 for c in found)


def test_a_resolver_in_a_dns_key_gets_no_observation_and_links_nothing() -> None:
    classifier = IpClassifier(None, (ipaddress.ip_network("131.21.124.0/22"),))
    who = Identity(classifier, LINKING.identity, LINKING.hubs.roles,
                   (ipaddress.ip_network("10.9.9.53/32"),))  # fmt: skip
    ctx = context(devices=lambda a, d: (who.device(a, d).ref, who.device(a, d).hub))
    found: list[Observation] = []
    for n, name in enumerate(("one-example.net", "two-example.net")):
        g = group(actor=["10.9.9.53", f"10.1.1.{n + 1}"], fields={"dns.question.name": [name]},
                  rule="dns-rule")  # fmt: skip
        out = observe(g, meta("dns-rule", family="dns"), ctx)
        assert "a resolver" in out.hubs
        assert all("10.9.9.53" not in o.object.key for o in out.observations)
        found.extend(out.observations)
    flags = {t: Flag("outside") for o in found for t in o.threats}
    comps = run(found, lanes(*{o.object for o in found}), World(flags))
    assert sizes(comps) == [1, 1]


def test_a_scanner_hitting_500_sites_links_none_of_them() -> None:
    scanner = "ip:45.33.12.7"
    sites = [obs("rule:L9", key=f"domain:site{n}.example.edu", kind="site", role="target",
                 threats=(scanner,)) for n in range(500)]  # fmt: skip
    refs = {o.object for o in sites}
    found = run(sites, lanes(*refs), World({scanner: Flag("ti")}))
    assert max(sizes(found)) == 1
    assert not link.campaign_lane(sites, NOW, LINKING, NEUTRAL, World({scanner: Flag("ti")}),
                                  set())  # fmt: skip


def test_one_campus_device_naming_a_listed_scanner_never_joins_the_sites_it_probed() -> None:
    scanner = "ip:45.33.12.7"
    sites = [obs("rule:L9", key=f"domain:site{n}.example.edu", kind="site", role="target",
                 threats=(scanner,)) for n in range(300)]  # fmt: skip
    replies = [seen(1, (scanner,)), seen(2, (scanner,))]  # campus devices that answered it
    world = World({scanner: Flag("ti")})
    found = run([*sites, *replies], lanes(*{o.object for o in sites}, dev(1), dev(2)), world)
    assert sizes(found)[:2] == [2, 1]  # the two devices, and every site alone
    assert all(o.kind == "device" for c in found if len(c.objects) > 1 for o in c.objects)


def test_a_bare_outside_address_never_links_campus_targets() -> None:
    t = "ip:45.33.12.7"
    sites = [obs("rule:L9", key=f"domain:site{n}.example.edu", kind="site", role="target",
                 threats=(t,)) for n in range(3)]  # fmt: skip
    assert sizes(run(sites, lanes(*{o.object for o in sites}))) == [1, 1, 1]


def test_the_cap_counts_every_risk_object_not_only_devices() -> None:
    chain = []
    for n in range(60):  # site n and site n+1 share a rare path pattern of their own
        t = f"url_pattern:/p{n}/x"
        chain += [obs("rule:L9", key=f"domain:site{m}.example.edu", kind="site", role="target",
                      threats=(t,)) for m in (n, n + 1)]  # fmt: skip
    found = run(chain, lanes(*{o.object for o in chain}))
    assert max(c.size for c in found) == LINKING.caps.objects
    assert sum(c.size for c in found) == 61


def test_a_campus_wide_flagged_destination_past_500_objects_never_links() -> None:
    t = "domain:everyone-example.net"
    many = [seen(n, (t,)) for n in range(LINKING.links.flagged.max_reach + 1)]
    found = run(many, lanes(*{o.object for o in many}), World({t: Flag("outside")}))
    assert max(sizes(found)) == 1


# --------------------------------------------------------------------------- identity links


def test_one_likely_account_on_two_devices_within_a_day_links_them() -> None:
    a, b = (
        ObjectRef("device", "ip:10.1.1.1@2026-10-19"),
        ObjectRef("device", "ip:10.1.1.9@2026-10-20"),
    )
    signs = [SignIn(a, "alice", NOW - timedelta(hours=20), NOW - timedelta(hours=19)),
             SignIn(b, "alice", NOW - timedelta(hours=2), NOW - timedelta(hours=1))]  # fmt: skip
    observations = [obs("rule:L1", key=a.key, hours_ago=20), obs("rule:L2", key=b.key)]
    found = run(observations, lanes(a, b), World(sign_ins=signs))
    assert sizes(found) == [2]
    assert any(lk.via == "account" for lk in found[0].links)
    apart = [signs[0], SignIn(b, "alice", NOW + timedelta(hours=10), NOW + timedelta(hours=11))]
    assert sizes(run(observations, lanes(a, b), World(sign_ins=apart))) == [1, 1]


def test_the_same_host_name_links_its_address() -> None:
    ip, host = ObjectRef("device", "ip:10.1.1.1"), ObjectRef("device", "host:lab-pc-7")
    world = World(hosts=[(ip, host, NOW - timedelta(hours=3), NOW - timedelta(hours=2))])
    found = run([obs("rule:L1", key=ip.key), obs("rule:L2", key=host.key)], lanes(ip), world)
    assert sizes(found) == [2]


def test_the_host_link_says_how_far_apart_the_address_and_the_host_were() -> None:
    ip, host = ObjectRef("device", "ip:10.1.1.1"), ObjectRef("device", "host:lab-pc-7")
    rows = [obs("rule:L1", key=ip.key), obs("rule:L2", key=host.key)]
    then = NOW - timedelta(hours=100)
    old = run(rows, lanes(ip), World(hosts=[(ip, host, then, then + timedelta(hours=1))]))
    assert [lk.reason for lk in old[0].links if lk.via == "host"] == [
        "the same host lab-pc-7, 4 days apart"
    ]
    now = run(rows, lanes(ip), World(hosts=[(ip, host, NOW - timedelta(hours=2), NOW)]))
    assert [lk.reason for lk in now[0].links if lk.via == "host"] == [
        "the same host lab-pc-7, within the hour"
    ]


def test_an_address_two_hosts_held_links_neither_unless_it_is_one_device() -> None:
    server = ObjectRef("device", "ip:10.4.0.10")
    a, b = ObjectRef("device", "host:srv-old"), ObjectRef("device", "host:srv-new")
    day1, day3 = NOW - timedelta(days=3), NOW - timedelta(days=1)
    hosts = [(server, a, day1, day1 + timedelta(hours=1)),
             (server, b, day3, day3 + timedelta(hours=1))]  # fmt: skip
    assert link.linkable_hosts(hosts, NOW, LINKING) == []  # nobody says: a reused address
    renamed = link.linkable_hosts(hosts, NOW, LINKING, lambda ref: ref == server)
    assert {h[1] for h in renamed} == {a, b}  # one device: renamed between days
    one_day = [(server, a, day3, day3 + timedelta(hours=1)),
               (server, b, day3 + timedelta(hours=2), day3 + timedelta(hours=3))]  # fmt: skip
    assert link.linkable_hosts(one_day, NOW, LINKING, lambda ref: ref == server) == []
    future = [(server, a, NOW + timedelta(hours=1), NOW + timedelta(hours=2))]
    assert link.linkable_hosts(future, NOW, LINKING) == []  # not known yet


def test_a_host_seen_on_many_addresses_links_through_none() -> None:
    host = ObjectRef("device", "host:web-srv-01")
    at = NOW - timedelta(hours=5)
    hosts = [(ObjectRef("device", f"ip:10.1.4.{n}"), host, at, at + timedelta(minutes=5))
             for n in range(1, 41)]  # fmt: skip
    assert link.linkable_hosts(hosts, NOW, LINKING) == []
    rows = [obs("rule:L1", key=h[0].key) for h in hosts] + [obs("rule:L2", key=host.key)]
    found = run(rows, lanes(hosts[0][0]), World(hosts=hosts))
    assert sizes(found) == [1]
    few = hosts[: LINKING.links.host.max_addresses]
    assert len(link.linkable_hosts(few, NOW, LINKING)) == len(few)


# --------------------------------------------------------------------------- flags of groups


def test_strong_evidence_names_its_outside_thing_only_when_it_holds_one() -> None:
    gid, wide = uuid.uuid4(), uuid.uuid4()
    rows = [
        obs("rule:L1", gid=gid, threats=("domain:c2-example.net",)),
        obs("ev:outside", gid=gid, strong=True),
        obs("rule:L1", gid=wide, threats=("domain:a-example.net", "domain:b-example.net")),
        obs("ev:outside", gid=wide, strong=True),
    ]
    flags = group_flags(rows, LINKING)
    assert set(flags) == {"domain:c2-example.net"}
    assert flags["domain:c2-example.net"].source == "outside"


# --------------------------------------------------------------------------- generic


def test_order_and_rule_names_never_change_the_components() -> None:
    t, r = "domain:c2-example.net", "domain:rare-example.org"
    base = [seen(n, (t,) if n % 2 else (r,), hours_ago=n, source=f"rule:L{n % 3}")
            for n in range(12)]  # fmt: skip
    world = World({t: Flag("outside")})
    cands = lanes(*(dev(n) for n in range(0, 12, 3)))
    want = [c.objects for c in run(base, cands, world)]
    shuffled = list(base)
    random.Random(7).shuffle(shuffled)
    assert [c.objects for c in run(shuffled, cands, world)] == want
    renamed = [replace(o, source_key=o.source_key.replace("rule:L", "rule:X")) for o in base]
    assert [c.objects for c in run(renamed, cands, world)] == want


def test_config_is_complete_and_the_flag_sources_are_known() -> None:
    assert LINKING.caps.objects == 50
    assert LINKING.caps.groups == 200
    assert CONFIG.max_threats >= LINKING.flag_threats
