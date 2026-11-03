"""Adversarial attack on R2's IP pseudonymizer, ``argus.fixtures.ipmap.IPMapper`` (D-030).

Lens FXC: break the map's stated guarantees: prefix preservation inside a class region or site
prefix, bijectivity, region preservation, public addresses moved to a different public address,
``x in P <=> map(x) in map_network(P)`` for networks inside one class or site region, and
determinism for a given key and site-prefix list.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every address, prefix and key here is
synthetic (documentation, benchmarking and private ranges, and the key ``b"k" * 32`` or a variant
of it); nothing touches the network. The colliding pairs below were found offline by inverting the
keyed permutation; they are written out so the tests do not depend on the mapper's internals.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import random
import subprocess
import sys
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.fixtures.ipmap import (
    CLASS_REGIONS,
    KEEP_REGIONS,
    SITE_SPACE_V4,
    SITE_SPACE_V6,
    IPAddress,
    IPMapError,
    IPMapper,
    IPNetwork,
    format_ip,
)

KEY = b"k" * 32
SITE = "203.0.112.0/22"  # one public /22, as on the real campus (synthetic here)
SITES = (SITE,)
MAPPER = IPMapper(KEY, SITES)
MULTI_SITES = ("203.0.112.0/22", "192.0.2.0/24", "198.51.96.0/20", "2001:db8::/56")
MULTI = IPMapper(KEY, MULTI_SITES)

V4_CLASSES = [n for n in CLASS_REGIONS if n.version == 4]
ALL_CLASSES = list(CLASS_REGIONS)


def _addr(value: int, version: int) -> IPAddress:
    return ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value)


def common_prefix(a: IPAddress, b: IPAddress) -> int:
    return a.max_prefixlen - (int(a) ^ int(b)).bit_length()


def inside(net: IPNetwork) -> st.SearchStrategy[IPAddress]:
    lo, hi = int(net.network_address), int(net.broadcast_address)
    return st.integers(lo, hi).map(lambda v: _addr(v, net.version))


ANY_V4 = st.integers(0, 2**32 - 1).map(ipaddress.IPv4Address)
# Revised with FXC-01: a real address in the site space is refused (tested on its own). Drawing
# one is rare, but Hypothesis keeps a failing example and replays it on every later run.
MAPPABLE_V4 = ANY_V4.filter(lambda a: a not in SITE_SPACE_V4)
ANY_V6 = st.integers(0, 2**128 - 1).map(ipaddress.IPv6Address)
GLOBAL_V6 = st.integers(0, 2**125 - 1).map(lambda v: ipaddress.IPv6Address((1 << 125) | v))


def _relation(a: IPNetwork, b: IPNetwork) -> str:
    if not a.overlaps(b):
        return "disjoint"
    if a == b:
        return "equal"
    return "inside" if a.subnet_of(b) else "contains"  # type: ignore[arg-type]


# ================================================================== DEFECTS

# (non-global "public" input, global input, the one pseudonym both get) under KEY and SITES.
_COLLISIONS = [
    ("198.18.0.1", "25.190.213.109", "94.253.95.164"),  # benchmarking 198.18.0.0/15
    ("198.19.255.254", "25.191.158.206", "94.252.55.157"),
    ("192.0.2.1", "31.110.46.174", "88.214.149.1"),  # TEST-NET-1
    ("198.51.100.7", "25.150.207.208", "94.214.55.2"),  # TEST-NET-2
    ("192.0.0.1", "31.110.44.159", "88.214.150.52"),  # IETF protocol assignments
    (  # Teredo 2001::/32 (a Windows client address)
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2258:59d9:fe5c:bcf7:82c3:4177:7c06:ba33",
        "2312:d897:79db:950b:78d0:1733:2e08:8d10",
    ),
    (  # IPv6 documentation 2001:db8::/32
        "2001:db8::1",
        "2258:553a:3be:cdcf:9858:9df7:176b:53a6",
        "2312:d125:1eca:f219:d2a1:f4bf:a692:8679",
    ),
    (  # IPv6 benchmarking = the site space 2001:2::/48 itself
        "2001:2::5",
        "2258:59db:ab78:aaeb:a066:fbc9:5fb9:e7a8",
        "2312:d895:857a:d0d7:d6cd:a0d4:9f3a:e64b",
    ),
]


@pytest.mark.parametrize(("special", "global_peer", "pseudonym"), _COLLISIONS)
def test_fxc01_non_global_public_inputs_collide_with_a_global_address(
    special: str, global_peer: str, pseudonym: str
) -> None:
    """DEFECT FXC-01: two different public originals get one pseudonym (not a bijection).

    ``_map_public`` takes every address whose region is ``public``, including non-global ones
    (TEST-NETs, 198.18.0.0/15, 192.0.0.0/24, Teredo, 2001:db8::/32, 2001:2::/48), but the walk
    only stops on ``is_global`` addresses. Cycle-walking is a bijection only when the set it walks
    from equals the set it stops on: a non-global ``y`` walks on to the image of the global
    address just before it on its cycle. Every such input collides with exactly one global one
    (here: the whole of 198.18.0.0/15 with 25.190.0.0/15)."""
    a, b = ipaddress.ip_address(special), ipaddress.ip_address(global_peer)
    # Revised with the fix: the regions now come from a fixed table (documentation, Teredo and
    # 6to4 blocks are class-like), and an input inside the site space is refused, because a
    # one-to-one map has no image left for it (the site prefixes take them all).
    if MAPPER.region(a).startswith("sitespace:"):
        with pytest.raises(IPMapError, match="site space"):
            MAPPER.map_address(a)
        return
    fa, fb = MAPPER.map_address(a), MAPPER.map_address(b)
    assert fa != fb, f"{special} and {global_peer} both map to {fa}"


def test_fxc02_ipv6_outside_2000_3_collides_with_a_global_unicast_address() -> None:
    """DEFECT FXC-02: IPv6 public inputs use two different permutations with one output set.

    Inputs in 2000::/3 are permuted with the top 3 bits kept; every other public IPv6 input is
    permuted over the whole space and may land in 2000::/3, where it hits the image of some
    global unicast address. ``c0de::1`` (an unallocated but ``is_global`` address) and
    ``3f8a:518f:7d8f:90c0:d91e:a277:cbea:a05b`` both become ``394d:3c7d:a5f6:...``."""
    outside = ipaddress.ip_address("c0de::1")
    unicast = ipaddress.ip_address("3f8a:518f:7d8f:90c0:d91e:a277:cbea:a05b")
    assert MAPPER.region(outside) == MAPPER.region(unicast) == "public"
    assert MAPPER.map_address(outside) != MAPPER.map_address(unicast)


def test_fxc03_fixed_point_of_the_public_permutation_cannot_be_mapped() -> None:
    """DEFECT FXC-03: a public address that the keyed permutation fixes raises IPMapError.

    The walk refuses ``current == value``, so for a fixed point (a 1-cycle) it spins
    ``_MAX_WALK`` times and gives up; the sanitizer does not catch IPMapError from
    ``map_address``, so one such address in a corpus aborts the whole run. Whether a key has
    public fixed points is luck: this synthetic key (``b"k" * 31 + b"\\x09"``) fixes 9.40.53.181,
    9.40.53.180, 9.40.53.177, 9.40.53.176 and 9.40.50.167."""
    mapper = IPMapper(b"k" * 31 + b"\x09", SITES)
    addr = ipaddress.IPv4Address("9.40.53.181")
    assert mapper.region(addr) == "public"
    try:
        out = mapper.map_address(addr)
    except IPMapError as exc:
        pytest.fail(f"a valid public address cannot be pseudonymized: {exc}")
    assert out != addr
    assert out.is_global


_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_V6_IS_GLOBAL = ipaddress.IPv6Address.is_global  # the property object itself


def _six_to_four_global(flag: bool) -> property:
    def fget(self: ipaddress.IPv6Address) -> bool:
        if self in _SIX_TO_FOUR:
            return flag
        return bool(_V6_IS_GLOBAL.fget(self))  # type: ignore[attr-defined]

    return property(fget)


def test_fxc04_pseudonyms_depend_on_the_interpreters_is_global_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT FXC-04: the map is not fixed by key and site list; it follows CPython's
    ``is_global`` table, which CVE-2024-4032 changed in 3.12.4 (2002::/16, 64:ff9b:1::/48,
    192.0.0.0/24, exceptions inside 2001::/23) and which distributions backport into older
    patch versions (this venv's Ubuntu 3.12.3 has it; python.org/uv 3.12.3 does not).
    ``requires-python`` allows any 3.12.x. This global address's first permuted candidate is
    2002:c633:6401::1, so its pseudonym flips with the 2002::/16 entry."""
    addr = ipaddress.IPv6Address("225a:8bd6:4031:9a48:dbea:95ee:4495:7319")
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", _six_to_four_global(True))
    old_table = IPMapper(KEY, SITES).map_address(addr)
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", _six_to_four_global(False))
    new_table = IPMapper(KEY, SITES).map_address(addr)
    assert old_table == new_table, f"{old_table} on one 3.12.x, {new_table} on another"


@pytest.mark.parametrize(
    ("net", "member"),
    [("0.0.0.0/1", "8.8.8.8"), ("::ffff:0.0.0.0/97", "::ffff:8.8.8.8")],
)
def test_fxc05_map_network_treats_two_keep_regions_as_one(net: str, member: str) -> None:
    """DEFECT FXC-05: ``map_network`` compares only the region *labels* of the two ends, and
    every keep region has the label ``keep``. 0.0.0.0/1 starts in 0.0.0.0/8 and ends in
    127.0.0.0/8, so it is returned unchanged although it holds 2**31 public addresses that are
    permuted out of it: 8.8.8.8 is in it, its image 210.225.189.146 is not. (0.0.0.0/1 and
    128.0.0.0/1 are the OpenVPN ``def1`` split-default routes.)"""
    network = ipaddress.ip_network(net)
    addr = ipaddress.ip_address(member)
    assert addr in network
    try:
        image = MAPPER.map_network(network)
    except IPMapError:
        return  # refusing the network is a correct answer too
    assert MAPPER.map_address(addr) in image, f"{addr} in {network} but not its image in {image}"


def test_fxc06_prf_cache_grows_by_about_a_hundred_entries_per_ipv6_address() -> None:
    """DEFECT FXC-06: ``_prf_bit`` caches every prefix up to ``bits - 8``: for IPv6 that is 120
    of 128 levels, so each distinct global IPv6 address adds ~106 cache entries (~15 KB;
    measured 76 MB for 5,000 addresses). The comment beside it says deep bits are *not* cached
    so the cache cannot grow without bound; that holds for IPv4 only. A long-lived mapper (the
    Phase 2 pseudonymizer before cloud calls) would grow without limit."""
    rng = random.Random(6)
    mapper = IPMapper(KEY, SITES)
    count = 1000
    for _ in range(count):
        mapper.map_address(ipaddress.IPv6Address((1 << 125) | rng.getrandbits(125)))
    per_address = len(mapper._prf_cache) / count
    assert per_address <= 32, f"{per_address:.0f} cached PRF bits per distinct IPv6 address"


_PROBES = ["10.1.2.3", "8.8.8.8", "203.0.113.5", "fd00::1", "2a00:1450::1", "100.64.1.1"]


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (KEY, KEY + b"\x00"),  # HMAC pads short keys with zero bytes
        (b"L" * 100, hashlib.sha256(b"L" * 100).digest()),  # and hashes keys over 64 bytes
    ],
    ids=["trailing-nul", "long-key-vs-its-sha256"],
)
def test_fxc07_distinct_keys_give_the_same_map(first: bytes, second: bytes) -> None:
    """DEFECT FXC-07: the raw fixture key is used as the HMAC key, and HMAC treats ``K`` and
    ``K + b"\\0"`` (and a key over 64 bytes and its SHA-256) as the same key. Two different keys
    with different fingerprints (``key_fingerprint`` hashes the raw key) produce one map."""
    a, b = IPMapper(first, SITES), IPMapper(second, SITES)
    outputs_a = [a.map_text(p) for p in _PROBES]
    outputs_b = [b.map_text(p) for p in _PROBES]
    assert outputs_a != outputs_b


@pytest.mark.parametrize("prefix", ["203.0.112.1/22", "not-a-prefix", "203.0.112.0/33"])
def test_fxc08a_bad_site_prefix_raises_ipmaperror(prefix: str) -> None:
    """DEFECT FXC-08a: a site prefix with host bits set (a typo for the campus range) or one that
    is not a prefix at all escapes as a bare ValueError from ``ipaddress.ip_network``, not as the
    module's documented IPMapError naming the policy entry."""
    with pytest.raises(IPMapError):
        IPMapper(KEY, [prefix])


@pytest.mark.parametrize(
    "sites",
    [("192.0.2.0/24", "198.18.0.0/24"), ("198.19.0.0/16",), ("2001:db8::/56", "2001:2::/64")],
)
def test_fxc08b_site_prefix_inside_the_site_space_is_refused(sites: tuple[str, ...]) -> None:
    """DEFECT FXC-08b: a site prefix inside the site space is accepted. With 192.0.2.0/24 and
    198.18.0.0/24, 192.0.2.0/24 is allocated 198.18.0.0/24: every pseudonym of the first site is
    a real address of the second (and the sanitizer then drops it from the leak denylist as
    "ambiguous")."""
    with pytest.raises(IPMapError):
        IPMapper(KEY, sites)


@pytest.mark.parametrize(
    ("text", "secret"),
    [("fe80::1%10.1.2.3", "10.1.2.3"), ("ff02::1%lab-host-17", "lab-host-17")],
)
def test_fxc09_keep_region_ipv6_keeps_its_scope_id_verbatim(text: str, secret: str) -> None:
    """DEFECT FXC-09: keep-region addresses are returned as the same object, scope id included,
    so whatever text the zone carries survives (a public IPv6's scope id is dropped, so the two
    paths disagree). Keep regions "identify nothing"; their zone text can."""
    out = MAPPER.map_text(text)
    assert secret not in out, out


# ================================================================== LOCK-INS


@pytest.mark.parametrize("region", ALL_CLASSES, ids=str)
@given(data=st.data())
def test_class_region_and_common_prefix_survive(region: IPNetwork, data: st.DataObject) -> None:
    """LOCK-IN: inside every class region (RFC 1918, CGNAT 100.64/10, ULA) the image stays in the
    same region and the common-prefix length of any two addresses is preserved exactly."""
    a, b = data.draw(inside(region)), data.draw(inside(region))
    fa, fb = MULTI.map_address(a), MULTI.map_address(b)
    assert fa in region
    assert fb in region
    assert common_prefix(fa, fb) == common_prefix(a, b)


@pytest.mark.parametrize("site", MULTI_SITES)
@given(data=st.data())
def test_multi_site_prefix_preservation(site: str, data: st.DataObject) -> None:
    """LOCK-IN: with four site prefixes of different lengths (/22, /24, /20, IPv6 /56) every
    site's addresses land in its own block inside the site space with prefixes preserved."""
    net = ipaddress.ip_network(site)
    target = dict(MULTI.sites)[net]
    a, b = data.draw(inside(net)), data.draw(inside(net))
    fa, fb = MULTI.map_address(a), MULTI.map_address(b)
    assert fa in target
    assert fb in target
    assert common_prefix(fa, fb) == common_prefix(a, b)


def test_site_allocation_is_aligned_disjoint_and_order_free() -> None:
    """LOCK-IN: allocated blocks are aligned, pairwise disjoint, inside the right site space, of
    the source's length, and independent of the order (and duplicates) of the policy list."""
    targets = [t for _, t in MULTI.sites]
    for source, target in MULTI.sites:
        space = SITE_SPACE_V4 if target.version == 4 else SITE_SPACE_V6
        assert target.subnet_of(space)  # type: ignore[arg-type]
        assert target.prefixlen == source.prefixlen
        assert int(target.network_address) % target.num_addresses == 0
    for i, a in enumerate(targets):
        for b in targets[i + 1 :]:
            assert a.version != b.version or not a.overlaps(b)
    shuffled = IPMapper(KEY, [*reversed(MULTI_SITES), MULTI_SITES[0]])
    assert sorted(map(str, shuffled.sites)) == sorted(map(str, MULTI.sites))


@pytest.mark.parametrize(
    ("sites", "message"),
    [
        (["203.0.0.0/16", "203.1.0.0/16", "192.0.2.0/24"], "too small"),
        (["203.0.0.0/14"], "too small"),
        (["2001:db8::/48", "2001:db9::/48"], "too small"),
        (["2001:db8::/32"], "too small"),
        (["203.0.112.0/22", "203.0.113.0/24"], "overlap"),
        (["2001:db8::/48", "2001:db8::/56"], "overlap"),
        (["100.64.0.0/24"], "reserved/class"),
        (["fd00::/48"], "reserved/class"),
    ],
)
def test_site_space_exhaustion_and_nesting_fail_closed(sites: list[str], message: str) -> None:
    """LOCK-IN: an exhausted site space (two /16s plus a /24; an IPv6 /32 or two /48s), nested
    site prefixes and site prefixes inside class regions all raise IPMapError at construction."""
    with pytest.raises(IPMapError, match=message):
        IPMapper(KEY, sites)


def test_every_address_of_a_slash_22_site_is_a_prefix_preserving_bijection() -> None:
    """LOCK-IN (exhaustive): all 1,024 addresses of the /22 site map one-to-one into its block,
    and every one of the 523,776 pairs keeps its exact common-prefix length."""
    net = ipaddress.ip_network(SITE)
    target = MAPPER.sites[0][1]
    src = [int(a) for a in net]
    out = [int(MAPPER.map_address(a)) for a in net]
    assert len(set(out)) == len(src)
    assert all(int(target.network_address) <= o <= int(target.broadcast_address) for o in out)
    for i in range(len(src)):
        si, oi = src[i], out[i]
        for j in range(i + 1, len(src)):
            assert (si ^ src[j]).bit_length() == (oi ^ out[j]).bit_length()


@pytest.mark.parametrize(
    "block", ["10.250.0.0/20", "172.31.240.0/20", "192.168.240.0/20", "100.127.240.0/20"]
)
def test_dense_class_blocks_are_bijective(block: str) -> None:
    """LOCK-IN (exhaustive): 4,096 addresses at the top end of each IPv4 class region map to
    4,096 distinct addresses of one /20 in the same region."""
    net = ipaddress.ip_network(block)
    outs = {MAPPER.map_address(a) for a in net}
    assert len(outs) == net.num_addresses
    images = {ipaddress.ip_network(f"{o}/20", strict=False) for o in outs}
    assert len(images) == 1


def test_site_space_inputs_never_collide_with_site_outputs() -> None:
    """LOCK-IN (exhaustive), revised with FXC-01: a real address in the allocated site block
    (198.18.0.0/22) is refused instead of being mapped. It used to go to the public walk, where it
    took the image of some global address (two originals, one pseudonym)."""
    site_out = {MAPPER.map_address(a) for a in ipaddress.ip_network(SITE)}
    target = MAPPER.sites[0][1]
    assert site_out == set(target)
    for addr in target:
        with pytest.raises(IPMapError, match="site space"):
            MAPPER.map_address(addr)


@given(MAPPABLE_V4)
def test_every_ipv4_input_keeps_its_region_kind(addr: ipaddress.IPv4Address) -> None:
    """LOCK-IN: keep stays identical, class stays in its class, site goes to its block, public
    goes to a different global address outside class, keep, site prefixes and the site space; so
    no two of these four kinds can ever share a pseudonym. 100.64/10 counts as class, not public.
    """
    region = MULTI.region(addr)
    out = MULTI.map_address(addr)
    if region == "keep":
        assert out == addr
    elif region.startswith("class:"):
        assert out in ipaddress.ip_network(region.removeprefix("class:"))
    elif region.startswith("site:"):
        assert out in dict(MULTI.sites)[ipaddress.ip_network(region.removeprefix("site:"))]
    else:
        assert out != addr
        assert out.is_global
        assert out not in SITE_SPACE_V4
        assert MULTI.region(out) == "public"


@given(GLOBAL_V6)
def test_global_ipv6_goes_to_a_different_global_unicast_address(
    addr: ipaddress.IPv6Address,
) -> None:
    """LOCK-IN: a public 2000::/3 address maps to a different global 2000::/3 address outside the
    IPv6 site space and the site prefixes."""
    if MULTI.region(addr) != "public":
        return
    out = MULTI.map_address(addr)
    assert out != addr
    assert out in ipaddress.ip_network("2000::/3")
    assert out.is_global
    assert out not in SITE_SPACE_V6
    assert MULTI.region(out) == "public"


@given(MAPPABLE_V4)
def test_ipv4_mapped_form_is_consistent_with_plain_ipv4(addr: ipaddress.IPv4Address) -> None:
    """LOCK-IN: ``::ffff:a.b.c.d`` maps to ``::ffff:`` + the IPv4 pseudonym, whatever the region,
    in both the compressed-hex and the dotted spelling."""
    mapped = ipaddress.IPv6Address(f"::ffff:{addr}")
    expected = f"::ffff:{MULTI.map_address(addr)}"
    assert format_ip(MULTI.map_address(mapped)) == expected
    assert MULTI.map_text(str(mapped)) == expected


@pytest.mark.parametrize(
    "text",
    [
        "2002:a01:203::1",  # 6to4 embedding 10.1.2.3
        "64:ff9b::a01:203",  # NAT64 embedding 10.1.2.3
        "::a01:203",  # IPv4-compatible 10.1.2.3
        "2001:0:4136:e378:8000:63bf:f5fe:fdfc",  # Teredo, obfuscated client 10.1.2.3
        "192.88.99.1",
        "192.0.0.170",
        "100.64.0.1",
    ],
)
def test_special_ranges_map_without_leaking_an_embedded_ipv4(text: str) -> None:
    """LOCK-IN: special and embedding forms map without error, change, and do not carry the
    embedded private IPv4 (in hex or dotted form) into the pseudonym."""
    out = MULTI.map_text(text)
    assert out != text
    for needle in ("a01:203", "10.1.2.3", "f5fe:fdfc"):
        assert needle not in out


def _net_in(region: IPNetwork) -> st.SearchStrategy[IPNetwork]:
    def build(base: int, extra: int) -> IPNetwork:
        prefixlen = min(region.prefixlen + extra, region.max_prefixlen)
        return ipaddress.ip_network((base, prefixlen), strict=False)

    lo, hi = int(region.network_address), int(region.broadcast_address)
    return st.builds(build, st.integers(lo, hi), st.integers(0, region.max_prefixlen))


_REGIONS: list[IPNetwork] = [*ALL_CLASSES, *(s for s, _ in MULTI.sites)]


@pytest.mark.parametrize("region", _REGIONS, ids=str)
@given(data=st.data())
def test_membership_preserved_for_members_neighbours_and_strangers(
    region: IPNetwork, data: st.DataObject
) -> None:
    """LOCK-IN: for any network P inside a class or site region, ``x in P <=> f(x) in f(P)`` for
    members, the two addresses just outside P, and arbitrary addresses of the same family
    (other regions, keep, public)."""
    net = data.draw(_net_in(region))
    image = MULTI.map_network(net)
    assert image.prefixlen == net.prefixlen
    top = 2**net.max_prefixlen - 1
    first, last = int(net.network_address), int(net.broadcast_address)
    probes = [first, last, data.draw(st.integers(first, last)), data.draw(st.integers(0, top))]
    probes += [v for v in (first - 1, last + 1) if 0 <= v <= top]
    for value in probes:
        x = _addr(value, net.version)
        if MULTI.region(x).startswith("sitespace:"):
            continue  # revised with FXC-01: a real address in the site space is refused
        assert (x in net) == (MULTI.map_address(x) in image), (x, net, image)


@pytest.mark.parametrize("region", _REGIONS, ids=str)
@given(data=st.data())
def test_nesting_and_disjointness_survive(region: IPNetwork, data: st.DataObject) -> None:
    """LOCK-IN: two networks in one region keep their relation: P inside Q stays inside, disjoint
    stays disjoint, equal stays equal."""
    a, b = data.draw(_net_in(region)), data.draw(_net_in(region))
    assert _relation(MULTI.map_network(a), MULTI.map_network(b)) == _relation(a, b)


@pytest.mark.parametrize(
    ("net", "same"),
    [
        ("0.0.0.0/0", True),
        ("::/0", True),
        ("10.0.0.0/8", True),
        ("172.16.0.0/12", True),
        ("fc00::/7", True),
        ("::ffff:192.168.0.0/112", True),
        ("::ffff:0.0.0.0/96", True),
        ("10.9.8.7/32", False),
        ("fd12::7/128", False),
    ],
)
def test_edge_networks(net: str, same: bool) -> None:
    """LOCK-IN: /0, whole class regions (also IPv4-mapped) map to themselves; a /32 or /128 maps
    to the single pseudonym of its address."""
    network = ipaddress.ip_network(net)
    image = MAPPER.map_network(network)
    if same:
        assert image == network
    else:
        assert image.num_addresses == 1
        assert image.network_address == MAPPER.map_address(network.network_address)


@pytest.mark.parametrize(
    "net", ["10.0.0.0/7", "203.0.112.0/21", "203.0.0.0/16", "8.8.8.0/24", "fc00::/6"]
)
def test_unmappable_networks_are_refused(net: str) -> None:
    """LOCK-IN: a network spanning two regions, containing the site prefix, or public raises."""
    with pytest.raises(IPMapError):
        MAPPER.map_network(ipaddress.ip_network(net))


@given(data=st.data())
def test_ipv4_mapped_networks_keep_membership(data: st.DataObject) -> None:
    """LOCK-IN: ``::ffff:10.x/1xx`` networks behave like their IPv4 counterparts."""
    v4 = data.draw(_net_in(ipaddress.ip_network("10.0.0.0/8")))
    net = ipaddress.ip_network(f"::ffff:{v4.network_address}/{96 + v4.prefixlen}")
    image = MAPPER.map_network(net)
    x4 = data.draw(MAPPABLE_V4)
    x = ipaddress.IPv6Address(f"::ffff:{x4}")
    assert (x in net) == (MAPPER.map_address(x) in image)
    assert (x in net) == (MAPPER.map_address(x4) in MAPPER.map_network(v4))


_MIXED = st.one_of(
    MAPPABLE_V4,
    GLOBAL_V6,
    inside(ipaddress.ip_network("10.0.0.0/8")),
    inside(ipaddress.ip_network("fc00::/7")),
    inside(ipaddress.ip_network(SITE)),
    inside(ipaddress.ip_network("2001:db8::/56")),
    MAPPABLE_V4.map(lambda a: ipaddress.IPv6Address(f"::ffff:{a}")),
)


@given(data=st.data())
def test_output_does_not_depend_on_mapping_order(data: st.DataObject) -> None:
    """LOCK-IN: the PRF cache key omits ``bits`` and the class domain is shared by IPv4 and IPv6,
    but no cached bit is ever reused across families: fresh mappers fed the same mixed set in two
    different orders agree on every pseudonym."""
    addrs = data.draw(st.lists(_MIXED, min_size=1, max_size=12, unique=True))
    order = data.draw(st.permutations(addrs))
    first, second = IPMapper(KEY, MULTI_SITES), IPMapper(KEY, MULTI_SITES)
    a = {x: first.map_address(x) for x in addrs}
    b = {x: second.map_address(x) for x in order}
    assert a == b


_DETERMINISM_PROBES = [
    "10.1.2.3",
    "172.20.1.9",
    "100.100.1.1",
    "203.0.113.200",
    "192.0.2.77",
    "8.8.8.8",
    "198.20.0.1",  # was 198.18.0.1: the site space is refused since FXC-01
    "::ffff:10.1.2.3",
    "fd00:1::5",
    "2001:db8::77",
    "2a00:1450:4001:80b::200e",
    "64:ff9b::808:808",
]
_CHILD = """
import json, sys
from argus.fixtures.ipmap import IPMapper
sites, probes = json.loads(sys.argv[1]), json.loads(sys.argv[2])
mapper = IPMapper(b"k" * 32, sites)
print(json.dumps([mapper.map_text(p) for p in probes]))
"""


def test_outputs_do_not_depend_on_the_hash_seed() -> None:
    """LOCK-IN: three interpreters with different PYTHONHASHSEED values (site prefixes passed in
    a different order each time) produce the in-process pseudonyms."""
    expected = [MULTI.map_text(p) for p in _DETERMINISM_PROBES]
    for seed, sites in (("0", MULTI_SITES), ("1", MULTI_SITES[::-1]), ("4242", MULTI_SITES)):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed inline script
            [sys.executable, "-c", _CHILD, json.dumps(sites), json.dumps(_DETERMINISM_PROBES)],
            capture_output=True,
            text=True,
            env=env,
            check=True,
            timeout=60,
        )
        assert json.loads(completed.stdout) == expected, seed


# Revised with FXG-01: every fresh mapper now chooses its re-keyed domains once (about 0.1 s),
# so this test, which builds two mappers per example, has no per-example deadline and a fixed
# number of key pairs at every profile.
@settings(deadline=None, max_examples=200)
@given(st.binary(min_size=32, max_size=200), st.binary(min_size=32, max_size=200))
def test_unrelated_keys_give_unrelated_maps(k1: bytes, k2: bytes) -> None:
    """LOCK-IN: keys of any length >= 32 are accepted, and two keys that are not HMAC-equivalent
    give different pseudonyms (FXC-07 covers the equivalent ones)."""

    def norm(k: bytes) -> bytes:
        return (hashlib.sha256(k).digest() if len(k) > 64 else k).rstrip(b"\x00")

    if norm(k1) == norm(k2):
        return
    a, b = IPMapper(k1, SITES), IPMapper(k2, SITES)
    assert [a.map_text(p) for p in _PROBES] != [b.map_text(p) for p in _PROBES]


def test_keep_regions_are_identity() -> None:
    """LOCK-IN: every keep region maps to itself, as a network and at both of its edges."""
    for region in KEEP_REGIONS:
        assert MAPPER.map_network(region) == region
        for edge in (region.network_address, region.broadcast_address):
            assert MAPPER.map_address(edge) == edge


@pytest.mark.parametrize(
    "factory",
    [
        lambda: IPMapper(KEY, SITES).map_text("not-an-ip"),
        lambda: IPMapper(b"k" * 31),
    ],
)
def test_bad_inputs_raise_ipmaperror(factory: Callable[[], object]) -> None:
    """LOCK-IN: a non-address text and a short key raise IPMapError."""
    with pytest.raises(IPMapError):
        factory()
