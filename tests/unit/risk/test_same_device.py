"""One device under several addresses (D-334): a dynamic address changes with the network a laptop
joins, so one account's addresses that were never active at the same time are one device to the
engine's counts, its campaign lane, its priority and its titles. Two addresses at once, two
accounts on an address, a shared role, a stated static address and a service account join
nothing."""

from __future__ import annotations

import ipaddress
import itertools
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assets import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.risk import incident_config, lifecycle, link, present, titles
from argus.risk import priority as prio
from argus.risk.identity import (
    SAME,
    Identity,
    Used,
    device_of,
    same_devices,
    spans_of,
    used_by,
)  # fmt: skip
from argus.risk.lifecycle import Incident
from argus.risk.link import Flag, World
from argus.risk.observe import ObjectRef
from argus.signins import model as sm
from tests.unit.risk import titles_kit as tk
from tests.unit.risk.conftest import CONFIG, NOW, obs
from tests.unit.risk.test_present_pure import verdicts
from tests.unit.signins import kit as sk

pytestmark = pytest.mark.unit
LINKING = incident_config.load()
T0 = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)
A, B, C, D = (ObjectRef("device", f"ip:10.211.0.{n}") for n in (11, 12, 13, 14))


def used(ref: ObjectRef, user: str, day: int, hours: int = 3, start: int = 0) -> Used:
    at = T0 + timedelta(days=day, hours=start)
    return Used(ref, user, at, at + timedelta(hours=hours))


# --------------------------------------------------------------------------- the rule (pure)


def test_one_accounts_addresses_never_active_together_are_one_device() -> None:
    found = same_devices([used(A, "asha", 0), used(B, "asha", 1), used(C, "asha", 3)])
    assert found == dict.fromkeys((A, B, C), SAME + "asha")
    assert {device_of(r, found) for r in (A, B, C)} == {"same:asha"}
    assert device_of(D, found) == "ip:10.211.0.14"  # nobody's: its own device


def test_two_addresses_at_once_are_two_devices_and_then_none_is_joined() -> None:
    # the phone and the laptop of one person, both on the network in the same hours
    together = [used(A, "asha", 0), used(B, "asha", 0, start=1), used(C, "asha", 4)]
    assert same_devices(together) == {}


def test_an_address_two_accounts_used_is_nobodys_own_device() -> None:
    found = same_devices([used(A, "asha", 0), used(B, "asha", 1), used(B, "ravi", 1),
                          used(C, "asha", 2)])  # fmt: skip
    assert found == dict.fromkeys((A, C), SAME + "asha")


def test_one_address_alone_and_its_own_days_join_nothing() -> None:
    assert same_devices([used(A, "asha", 0)]) == {}
    day1, day2 = (ObjectRef("device", f"ip:10.211.0.11@2026-11-0{n}") for n in (1, 2))
    assert same_devices([used(day1, "asha", 0, 20), used(day2, "asha", 0, 30, start=10)]) == {}
    # its days are one device already; with another address they are one device together
    found = same_devices([used(day1, "asha", 0), used(day2, "asha", 1), used(B, "asha", 3)])
    assert set(found) == {day1, day2, B}


def test_different_accounts_are_different_devices() -> None:
    found = same_devices([used(A, "asha", 0), used(B, "asha", 1), used(C, "ravi", 0),
                          used(D, "ravi", 1)])  # fmt: skip
    assert found == {A: "same:asha", B: "same:asha", C: "same:ravi", D: "same:ravi"}


@given(st.lists(st.tuples(st.integers(0, 5), st.sampled_from(["asha", "ravi"]),
                          st.integers(0, 20), st.integers(1, 30)), max_size=12))  # fmt: skip
def test_no_two_joined_addresses_were_ever_active_at_the_same_time(
    rows: list[tuple[int, str, int, int]],
) -> None:
    items = [Used(ObjectRef("device", f"ip:10.211.1.{n}"), who, T0 + timedelta(hours=start),
                  T0 + timedelta(hours=start + length)) for n, who, start, length in rows]  # fmt: skip  # noqa: E501
    found = same_devices(items)
    spans: dict[ObjectRef, tuple[datetime, datetime]] = {}
    users: dict[ObjectRef, set[str]] = {}
    for u in items:
        low, high = spans.get(u.device, (u.start, u.end))
        spans[u.device] = (min(low, u.start), max(high, u.end))
        users.setdefault(u.device, set()).add(u.user)
    groups: dict[str, list[ObjectRef]] = {}
    for ref, key in found.items():
        groups.setdefault(key, []).append(ref)
    for key, refs in groups.items():
        assert len(refs) >= 2
        assert all(users[r] == {key.removeprefix(SAME)} for r in refs)
        ordered = sorted(spans[r] for r in refs)
        assert all(b[0] >= a[1] for a, b in itertools.pairwise(ordered))


# --------------------------------------------------------------------------- who was behind it

ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - name: Hostel Nine
    range: 10.211.0.0/16
    fields: {site.type: hostel}
  - name: Teaching Lab
    range: 10.212.0.0/24
    fields: {site.type: lab}
  - name: Mail Server
    range: 10.213.0.5
    fields: {site.type: server}
"""
)
IDENTITY = Identity(
    IpClassifier(ASSETS, (ipaddress.ip_network("10.0.0.0/8"),)),
    LINKING.identity,
    LINKING.hubs.roles,
)
RULES = sm.Rules()


def records(
    by_address: dict[str, list[str]], days: int = 3
) -> dict[tuple[str, date], sm.DayRecord]:
    out: dict[tuple[str, date], sm.DayRecord] = {}
    for address, names in by_address.items():
        for n in range(-1, days + 1):
            day = (T0 + timedelta(days=n)).date()
            seen = tuple(sk.sighting(name, address=address, day=day, hours=tuple(range(24)),
                                     events=24) for name in names)  # fmt: skip
            looked = sm.day_end(day) + timedelta(days=1)
            out[(address, day)] = sm.DayRecord(
                address, day, sm.Lookup(address, day, looked, True, len(names), 0), seen
            )
    return out


def test_a_lab_machine_a_single_static_address_and_a_hub_never_move() -> None:
    hostel, lab, server = (ObjectRef("device", f"ip:{a}") for a in
                           ("10.211.0.11", "10.212.0.7", "10.213.0.5"))  # fmt: skip
    account = ObjectRef("account", "asha")
    spans = spans_of([(r, T0) for r in (hostel, lab, server, account)], IDENTITY)
    assert set(spans) == {hostel}  # a lab has many users, a /32 is that device, an account is none
    later = spans_of([(hostel, T0), (hostel, T0 + timedelta(hours=5))], IDENTITY)
    assert later[hostel] == (T0, T0 + timedelta(hours=5))


def test_the_one_account_behind_an_address_over_its_activity() -> None:
    now = T0 + timedelta(days=10)
    spans = {A: (T0, T0 + timedelta(hours=4)), B: (T0, T0 + timedelta(hours=4)),
             C: (T0, T0 + timedelta(hours=4)), D: (T0, T0 + timedelta(hours=4))}  # fmt: skip
    held = records({"10.211.0.11": ["asha"], "10.211.0.12": ["asha", "ravi"],
                    "10.211.0.13": ["svc-backup"], "10.211.0.14": []})  # fmt: skip
    found = used_by(spans, held, RULES, now)
    assert found == [Used(A, "asha", T0, T0 + timedelta(hours=4))]
    # another account on the same address later that day, outside the hours of the activity:
    # the address is still the first account's while it was active
    day = T0.date()
    late = sk.sighting("ravi", address="10.211.0.11", day=day, hours=(22,), events=3)
    record = held[("10.211.0.11", day)]
    early = sk.sighting("asha", address="10.211.0.11", day=day, hours=(5, 6, 7, 8, 9), events=9)
    held[("10.211.0.11", day)] = sm.DayRecord(
        record.address, record.day, sm.Lookup("10.211.0.11", day, record.lookup.looked_at,
                                              True, 2, 0), (early, late)
    )  # fmt: skip
    again = used_by({A: spans[A]}, held, RULES, now)
    assert [u.user for u in again] == ["asha"]


# --------------------------------------------------------------------------- the linker


def test_one_device_under_two_addresses_is_not_a_campaign_and_still_one_incident() -> None:
    t = "ip:203.0.113.40"
    a, b = (ObjectRef("device", f"ip:10.1.0.{n}") for n in (2, 3))
    seen = [obs("rule:L1", key=a.key, hours_ago=400, threats=(t,)),
            obs("rule:L1", key=b.key, hours_ago=1, threats=(t,))]  # fmt: skip
    lanes = dict.fromkeys((a, b), ("decisive",))
    flags = {t: Flag("outside")}
    apart = link.link_all(seen, NOW, lanes, LINKING, link.Stats(), World(flags))
    assert sorted(len(c.objects) for c in apart) == [1, 1]  # 400 hours apart: no link joins them
    same = dict.fromkeys((a, b), SAME + "asha")
    found = link.link_all(seen, NOW, lanes, LINKING, link.Stats(), World(flags, same=same))
    (one,) = found
    assert (len(one.objects), one.devices, one.campaign) == (2, 1, False)
    (joined,) = [lk for lk in one.links if lk.via == "account"]
    assert "most likely one device that moved" in joined.reason
    # two real devices reaching it within the window are a campaign, as before
    near = [obs("rule:L1", key=a.key, hours_ago=3, threats=(t,)), seen[1]]
    (camp,) = link.link_all(near, NOW, {}, LINKING, link.Stats(), World(flags))
    assert camp.campaign
    assert camp.devices == 2
    assert link.link_all(near, NOW, {}, LINKING, link.Stats(), World(flags, same=same)) == []


def test_the_incident_counts_its_devices_as_the_pass_read_them() -> None:
    inc = Incident(None, NOW, NOW, NOW, dict.fromkeys((A, B, C, D), "actor"))
    assert inc.devices == 4
    facts = lifecycle.facts_of([], NOW, lambda t: False, None, {A: "same:asha", B: "same:asha"})
    material = lifecycle.material_of(inc, facts, lambda i: "P3")
    assert inc.devices == 3
    assert material.devices == lifecycle.bucket(3)
    assert inc.size == 4  # the cap still counts every address


# --------------------------------------------------------------------------- the priority


def scored(same: dict[ObjectRef, str]) -> tuple[present.Value, list[present.Obj]]:
    refs = [ObjectRef("device", f"ip:10.1.0.{n}") for n in (2, 3, 4)]
    items = [obs("ev:outside", key=r.key, base=30.0, strong=True, hours_ago=2 + n,
                 threats=("ip:203.0.113.40",)) for n, r in enumerate(refs)]  # fmt: skip
    found = verdicts(items)
    objs = [present.obj_of(r, found[r], same=same.get(r)) for r in refs]  # type: ignore[arg-type]
    value = present.value(objs, NOW, present.Context(CONFIG), confirmed=False, reach={},
                          signals=(), rule_names={}, lanes=("decisive",), last_seen=NOW)  # fmt: skip  # noqa: E501
    return value, objs


def test_addresses_of_one_device_are_one_object_to_the_priority() -> None:
    apart, objs = scored({})
    refs = [o.ref for o in objs]
    one, joined = scored(dict.fromkeys(refs, "same:asha"))
    assert apart.evidence.objects == 3
    assert one.evidence.objects == 1
    assert apart.evidence.spread > 1
    assert apart.evidence.others > 0
    assert (one.evidence.spread, one.evidence.others) == (1.0, 0.0)
    assert one.evidence.x < apart.evidence.x
    assert not any("other" in i.text or "spread" in i.text for i in one.why)
    said = [c.text for c in one.checks if "one" in c.text and "moved" in c.text]
    assert said == ["3 of its addresses are most likely one campus device that moved: the same"
                    " account signed in from each, never from two at the same time"]  # fmt: skip
    assert not any("moved" in c.text for c in apart.checks)
    # two of three: the third is another device beside it
    two, _ = scored(dict.fromkeys(refs[:2], "same:asha"))
    assert two.evidence.objects == 2
    assert present.joined(joined) == 3
    kept = present.as_devices(joined)
    assert len(kept) == 1
    assert kept[0].last_at == max(o.last_at for o in joined if o.last_at)


def test_the_ranker_reads_the_passs_one_device_map_when_it_ranks() -> None:
    refs = [ObjectRef("device", f"ip:10.1.0.{n}") for n in (2, 3, 4)]
    items = [obs("ev:outside", key=r.key, base=30.0, strong=True, threats=("ip:203.0.113.40",))
             for r in refs]  # fmt: skip
    found = verdicts(items)
    same: dict[ObjectRef, str] = {}
    band_of = present.ranker(found, NOW, CONFIG, same=same)  # type: ignore[arg-type]
    inc = Incident(None, NOW, NOW, NOW, dict.fromkeys(refs, "actor"))
    band_of(inc)
    before = inc.priority
    same.update(dict.fromkeys(refs, "same:asha"))  # the linking pass fills it before it ranks
    band_of(inc)
    assert inc.priority < before
    assert prio.band_of(inc.priority)


# --------------------------------------------------------------------------- the title


def test_the_title_counts_one_device_for_one_accounts_addresses() -> None:
    a, b, c = tk.dev("10.211.0.11"), tk.dev("10.211.0.12"), tk.dev("10.212.0.9")
    facts = tk.incident([tk.grp([a]), tk.grp([b]), tk.grp([c])])
    names = titles._device_names(facts)
    assert len({names[r] for r in (a, b, c)}) == 3
    moved = titles.IncidentFacts(objects=facts.objects, groups=facts.groups,
                                 same={a: "same:asha", b: "same:asha"})  # fmt: skip
    names = titles._device_names(moved)
    assert names[a] == names[b] != names[c]
    assert len({d.value for d in titles.naming_facts(moved).devices}) == 2
