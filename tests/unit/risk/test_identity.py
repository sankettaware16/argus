"""Identity (E4): which device an address is, hubs, criticality, the account behind a device,
and what never links (DHCP reuse, a shared lab, generic and service accounts). Made-up values."""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime, timedelta

import pytest

from argus.assets.assetmap import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.risk import incident_config, link
from argus.risk.identity import (
    Identity,
    address_of,
    device_of,
    likely_user,
    service_account,
    sign_ins,
)
from argus.risk.observe import ObjectRef, observe
from argus.risk.score import Stats, evaluate
from argus.signins import model as m

from .conftest import CONFIG, NOW, context, group, meta

pytestmark = pytest.mark.unit
LINKING = incident_config.load()
MAP = b"""
networks:
  - {name: hostel wifi, range: 10.3.0.0/16, fields: {site.role: wifi}}
  - {name: server, range: 10.4.0.10, fields: {site.criticality: critical}}
  - {name: servers, range: 10.4.0.0/24, fields: {site.addressing: static, site.criticality: high}}
  - {name: dynamic pool, range: 10.5.0.0/24, fields: {site.addressing: dynamic}}
  - {name: nat, range: 10.6.0.1, fields: {site.type: gateway}}
  - {name: lab, range: 10.7.0.0/24, fields: {site.type: lab}}
  - {name: plain, range: 10.8.0.0/24, fields: {site.zone: north}}
"""
DAY = date(2026, 10, 20)


def who(*, unknown: str = "static") -> Identity:
    classifier = IpClassifier(parse_asset_map(MAP), (ipaddress.ip_network("131.21.124.0/22"),))
    config = LINKING.identity.model_copy(update={"unknown_addressing": unknown})
    return Identity(classifier, config, LINKING.hubs.roles, (ipaddress.ip_network("10.9.9.0/30"),))


def test_device_keys_follow_the_asset_map() -> None:
    i = who()
    assert i.device("10.4.0.10", DAY).ref.key == "ip:10.4.0.10"  # a /32 is the device
    assert i.device("10.4.0.20", DAY).ref.key == "ip:10.4.0.20"  # stated static
    assert i.device("10.5.0.20", DAY).ref.key == "ip:10.5.0.20@2026-10-20"  # stated dynamic
    assert i.device("10.3.1.2", DAY).ref.key == "ip:10.3.1.2@2026-10-20"  # a Wi-Fi pool
    assert i.device("10.8.0.2", DAY).ref.key == "ip:10.8.0.2"  # nobody says: unknown_addressing
    assert who(unknown="dynamic").device("10.8.0.2", DAY).ref.key == "ip:10.8.0.2@2026-10-20"
    assert who(unknown="dynamic").device("10.4.0.10", DAY).ref.key == "ip:10.4.0.10"


def test_hubs_criticality_and_shared_roles() -> None:
    i = who()
    assert i.device("10.6.0.1", DAY).hub == "asset role gateway"
    assert i.device("10.9.9.1", DAY).hub == "a resolver"
    assert i.device("10.8.0.2", DAY).hub is None
    assert i.device("10.4.0.10", DAY).criticality == 2.0
    assert i.device("10.4.0.20", DAY).criticality == 1.5
    assert i.device("10.8.0.2", DAY).criticality == 1.0
    assert i.shared(ObjectRef("device", "ip:10.7.0.4"))
    assert not i.shared(ObjectRef("device", "ip:10.8.0.2"))


def test_keys_name_their_address_and_device() -> None:
    ref = ObjectRef("device", "ip:10.5.0.20@2026-10-20")
    assert address_of(ref) == "10.5.0.20"
    assert device_of(ref) == "ip:10.5.0.20"
    assert address_of(ObjectRef("device", "host:lab-pc-7")) is None


def test_dhcp_reuse_never_accumulates_for_the_next_person() -> None:
    i = who()
    ctx = context(devices=lambda a, d: (i.device(a, d).ref, i.device(a, d).hub))
    monday = group(actor="10.5.0.20", rule="rule-a", severity="high", hours_ago=30)
    tuesday = group(actor="10.5.0.20", rule="rule-b", severity="high", hours_ago=2)
    rows = [o for g in (monday, tuesday) for o in observe(g, meta(g.rule_id), ctx).observations]
    keys = {o.object.key for o in rows}
    assert len(keys) == 2  # one device a day: two people, two keys
    one = [o for o in rows if o.group == tuesday.id]
    alone = evaluate(one, NOW, CONFIG, Stats(), ref=one[0].object).window("7d").score
    merged = evaluate([o for o in rows if o.object == one[0].object], NOW, CONFIG, Stats(),
                      ref=one[0].object).window("7d").score  # fmt: skip
    assert alone == merged  # Monday's alerts are not on Tuesday's person
    assert len(link.link_all(rows, NOW, {r.object: ("burst",) for r in rows}, LINKING, Stats(),
                             link.World())) == 2  # fmt: skip


# The field set of a real asset map: a site type only (switch, gateway, lab, computer-room,
# none), no addressing field, no Wi-Fi or VPN role. Values are made up.
SITE_TYPES_ONLY = b"""
networks:
  - {name: hostel block, range: 10.5.1.0/24, fields: {site.type: none, site.zone: south}}
  - {name: core switch, range: 10.5.2.1, fields: {site.type: switch}}
  - {name: border, range: 10.5.2.254, fields: {site.type: gateway}}
  - {name: teaching lab, range: 10.5.3.0/24, fields: {site.type: lab}}
  - {name: terminals, range: 10.5.4.0/24, fields: {site.type: computer-room}}
"""


def site_types_only() -> Identity:
    classifier = IpClassifier(parse_asset_map(SITE_TYPES_ONLY),
                              (ipaddress.ip_network("131.21.124.0/22"),))  # fmt: skip
    return Identity(classifier, LINKING.identity, LINKING.hubs.roles)


def test_dhcp_reuse_where_nobody_states_addressing_never_joins_two_peoples_hosts() -> None:
    i = site_types_only()
    ctx = context(devices=i.devices())
    alice = group(actor="pc-alice", field="host.name", fields={"host.ip": ["10.5.1.9"]},
                  rule="rule-a", severity="high", hours_ago=72)  # fmt: skip
    bob = group(actor="pc-bob", field="host.name", fields={"host.ip": ["10.5.1.9"]},
                rule="rule-b", hours_ago=24)  # fmt: skip
    plain = group(actor="10.5.1.9", rule="rule-c", hours_ago=2)  # the address alone
    made = [(g, observe(g, meta(g.rule_id), ctx)) for g in (alice, bob, plain)]
    rows = [o for _, seen in made for o in seen.observations]
    hosts = [(ip, host, g.first_at, g.last_at) for g, seen in made for ip, host in seen.aliases]
    assert {ip.key for ip, *_ in hosts} == {"ip:10.5.1.9"}  # keyed whole: nobody says dynamic
    pc_alice = ObjectRef("device", "host:pc-alice")
    world = link.World(hosts=hosts, one_device=i.one_device)
    found = link.link_all(rows, NOW, {pc_alice: ("burst",)}, LINKING, Stats(), world)
    assert [c.objects for c in found] == [(pc_alice,)]  # neither the address nor pc-bob
    only = link.World(hosts=hosts[:1], one_device=i.one_device)  # one host ever had it
    found = link.link_all(rows, NOW, {pc_alice: ("burst",)}, LINKING, Stats(), only)
    assert [c.objects for c in found] == [(pc_alice, ObjectRef("device", "ip:10.5.1.9"))]


def test_site_types_alone_make_gateways_hubs_and_labs_shared() -> None:
    i = site_types_only()
    assert i.device("10.5.2.254", DAY).hub == "asset role gateway"
    assert i.device("10.5.2.1", DAY).hub is None
    assert i.shared(ObjectRef("device", "ip:10.5.3.7"))
    assert i.shared(ObjectRef("device", "ip:10.5.4.7"))
    assert not i.one_device(ObjectRef("device", "ip:10.5.1.9"))
    assert i.one_device(ObjectRef("device", "ip:10.5.2.1"))  # a /32


def test_one_device_only_when_the_asset_map_says_so() -> None:
    i = who()
    assert i.one_device(ObjectRef("device", "ip:10.4.0.10"))  # a /32
    assert i.one_device(ObjectRef("device", "ip:10.4.0.20"))  # stated static
    assert not i.one_device(ObjectRef("device", "ip:10.8.0.2"))  # nobody says
    assert not i.one_device(ObjectRef("device", "ip:10.5.0.20@2026-10-20"))
    assert not i.one_device(ObjectRef("device", "host:lab-pc-7"))
    assert i.hub(ObjectRef("device", "ip:10.6.0.1")) == "asset role gateway"
    assert i.hub(ObjectRef("device", "host:lab-pc-7")) is None


def test_the_fingerprint_follows_identitys_settings_and_the_asset_map() -> None:
    base = who().fingerprint()
    assert base == who().fingerprint()
    assert who(unknown="dynamic").fingerprint() != base
    more = MAP + b"  - {name: extra, range: 10.10.0.0/24, fields: {site.role: wifi}}\n"
    classifier = IpClassifier(parse_asset_map(more), (ipaddress.ip_network("131.21.124.0/22"),))
    other = Identity(classifier, LINKING.identity, LINKING.hubs.roles,
                     (ipaddress.ip_network("10.9.9.0/30"),))  # fmt: skip
    assert other.fingerprint() != base


def test_a_hub_address_gets_no_observation() -> None:
    i = who()
    ctx = context(devices=lambda a, d: (i.device(a, d).ref, i.device(a, d).hub))
    out = observe(group(actor="10.6.0.1", severity="critical"), meta(), ctx)
    assert out.observations == ()
    assert out.hubs == ("asset role gateway",)


def test_a_host_named_by_the_key_with_one_campus_address_of_its_own_is_an_alias() -> None:
    g = group(actor="lab-pc-7", field="host.name", fields={"host.ip": ["10.8.0.2", "fe80::1"]})
    out = observe(g, meta(), context())
    assert out.aliases == (
        (ObjectRef("device", "ip:10.8.0.2"), ObjectRef("device", "host:lab-pc-7")),
    )
    two = group(actor="lab-pc-7", field="host.name", fields={"host.ip": ["10.8.0.2", "10.8.0.3"]})
    assert observe(two, meta(), context()).aliases == ()


def test_a_servers_client_is_never_its_alias() -> None:
    # a login to web-srv-01 from a campus client: source.ip is the client, not the server
    g = group(actor="web-srv-01", field="host.name", fields={"source.ip": ["10.1.4.20"]})
    assert observe(g, meta(), context()).aliases == ()
    peer = group(actor="web-srv-01", field="host.name",
                 fields={"client.ip": ["10.1.4.21"], "host.ip": ["10.1.4.5"]})  # fmt: skip
    assert observe(peer, meta(), context()).aliases == (
        (ObjectRef("device", "ip:10.1.4.5"), ObjectRef("device", "host:web-srv-01")),
    )


@pytest.mark.parametrize(
    ("name", "service"),
    [("root", True), ("svc-backup", True), ("backup_svc", True), ("ws-12$", True),
     ("noreply@example.edu", True), ("jenkins", True), ("alice", False),
     ("asha.k@example.edu", False), ("gita", False), ("mail.daemon", True)],
)  # fmt: skip
def test_generic_and_service_accounts(name: str, service: bool) -> None:
    assert service_account(name) is service


# --------------------------------------------------------------------------- sign-ins


def _day(address: str, users: dict[str, tuple[int, int]], hours: tuple[int, ...] = (10,),
         more: int = 0) -> m.DayRecord:  # fmt: skip
    start = datetime(2026, 10, 20, tzinfo=UTC)
    lookup = m.Lookup(address, DAY, start + timedelta(days=2), True, len(users), more)
    sightings = tuple(
        m.Sighting(address, DAY, u, start + timedelta(hours=hours[0]),
                   start + timedelta(hours=hours[-1], minutes=30), ok + bad, ok, bad, hours)
        for u, (ok, bad) in users.items()
    )  # fmt: skip
    return m.DayRecord(address, DAY, lookup, sightings)


AT = datetime(2026, 10, 20, 10, 20, tzinfo=UTC)
LATER = datetime(2026, 10, 25, tzinfo=UTC)
RULES = m.Rules()


def test_one_successful_account_in_the_hour_is_the_likely_user() -> None:
    record = _day("10.8.0.2", {"Asha": (3, 0), "bob": (0, 4)})
    assert likely_user("10.8.0.2", {DAY: record}, AT, RULES, LATER) == "asha"
    assert likely_user("10.8.0.2", {DAY: record}, AT + timedelta(hours=3), RULES, LATER) is None
    crowd = _day("10.8.0.2", {"a1": (1, 0), "a2": (1, 0)})
    assert likely_user("10.8.0.2", {DAY: crowd}, AT, RULES, LATER) is None
    assert likely_user("10.8.0.2", {}, AT, RULES, LATER) is None  # never looked up: unknown


def test_sign_ins_skip_shared_roles_service_accounts_and_busy_accounts() -> None:
    i = who()
    plain, lab = ObjectRef("device", "ip:10.8.0.2"), ObjectRef("device", "ip:10.7.0.4")
    records = {("10.8.0.2", DAY): _day("10.8.0.2", {"asha": (2, 0)}),
               ("10.7.0.4", DAY): _day("10.7.0.4", {"ravi": (2, 0)})}  # fmt: skip
    found = sign_ins([(plain, AT), (lab, AT)], i, records, RULES, LATER, {}, 3)
    assert [(s.device, s.user) for s in found] == [(plain, "asha")]
    assert sign_ins([(plain, AT)], i, records, RULES, LATER, {("asha", DAY): 4}, 3) == []
    service = {("10.8.0.2", DAY): _day("10.8.0.2", {"svc-sync": (9, 0)})}
    assert sign_ins([(plain, AT)], i, service, RULES, LATER, {}, 3) == []
