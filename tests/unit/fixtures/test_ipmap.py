"""R2 gate properties of the IP pseudonymizer (all addresses here are synthetic)."""

from __future__ import annotations

import ipaddress
import random
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from argus.fixtures import ipmap as ipmap_module
from argus.fixtures.ipmap import (
    CLASS_REGIONS,
    KEEP_REGIONS,
    SITE_SPACE_V4,
    SPECIAL_REGIONS,
    IPAddress,
    IPMapError,
    IPMapper,
)
from argus.fixtures.policy import load_policy
from tests.conftest import REPO_ROOT, local_asset_map

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
SITE = "192.0.2.0/24"  # a synthetic "campus public" prefix for these tests
MAPPER = IPMapper(KEY, [SITE])
ASSETS = local_asset_map()


def common_prefix(a: IPAddress, b: IPAddress) -> int:
    x = int(a) ^ int(b)
    return a.max_prefixlen - x.bit_length()


def in_net(net: str) -> st.SearchStrategy[ipaddress.IPv4Address]:
    n = ipaddress.ip_network(net)
    return st.integers(int(n.network_address), int(n.broadcast_address)).map(ipaddress.IPv4Address)


V4_CLASSES = [str(n) for n in CLASS_REGIONS if n.version == 4]


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 — an address under test, not a bind
        "169.254.10.20",
        "224.0.0.251",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "ff02::1",
    ],
)
def test_keep_regions_are_unchanged(addr: str) -> None:
    assert MAPPER.map_text(addr) == addr


def test_deterministic_and_keyed() -> None:
    assert MAPPER.map_text("10.1.2.3") == IPMapper(KEY, [SITE]).map_text("10.1.2.3")
    assert MAPPER.map_text("10.1.2.3") != IPMapper(OTHER_KEY, [SITE]).map_text("10.1.2.3")


def test_short_key_rejected() -> None:
    with pytest.raises(IPMapError, match=r"^the fixture key must be at least 32 bytes$"):
        IPMapper(b"k" * 31)


@pytest.mark.parametrize(
    ("addr", "region"),
    [
        ("192.0.0.168", "class:192.0.0.168/31"),  # a two-address IANA piece is a class of its own
        ("192.0.0.169", "class:192.0.0.168/31"),
        ("::ffff:10.1.2.3", "class:10.0.0.0/8"),  # an IPv4-mapped address is its IPv4 address
        ("::ffff:192.0.2.5", f"site:{SITE}"),
        ("::ffff:192.0.0.9", "keep"),
        ("fe80::1%eth0", "keep"),
        ("8.8.8.8", "public"),
    ],
)
def test_regions(addr: str, region: str) -> None:
    assert MAPPER.region(ipaddress.ip_address(addr)) == region


@pytest.mark.parametrize("region", V4_CLASSES)
@given(data=st.data())
def test_class_and_common_prefix_preserved(region: str, data: st.DataObject) -> None:
    a = data.draw(in_net(region))
    b = data.draw(in_net(region))
    fa, fb = MAPPER.map_address(a), MAPPER.map_address(b)
    net = ipaddress.ip_network(region)
    assert fa in net
    assert fb in net
    assert common_prefix(fa, fb) == common_prefix(a, b)
    assert (fa == fb) == (a == b)


@given(data=st.data())
def test_site_prefix_moves_into_site_space(data: st.DataObject) -> None:
    a = data.draw(in_net(SITE))
    b = data.draw(in_net(SITE))
    fa, fb = MAPPER.map_address(a), MAPPER.map_address(b)
    target = MAPPER.sites[0][1]
    assert fa in target
    assert target.subnet_of(SITE_SPACE_V4)  # type: ignore[arg-type]
    assert common_prefix(fa, fb) == common_prefix(a, b)


@given(st.integers(0, 2**32 - 1).map(ipaddress.IPv4Address))
def test_public_stays_public_and_changes(addr: ipaddress.IPv4Address) -> None:
    if MAPPER.region(addr) != "public":
        return
    out = MAPPER.map_address(addr)
    assert out != addr
    assert out.is_global
    assert MAPPER.region(out) == "public"
    assert out not in SITE_SPACE_V4


def test_bijection_on_a_dense_block() -> None:
    block = ipaddress.ip_network("10.20.0.0/20")
    outputs = {MAPPER.map_address(a) for a in block}
    assert len(outputs) == block.num_addresses


@given(
    st.integers(8, 32),
    st.integers(0, 2**24 - 1),
    st.integers(0, 2**24 - 1),
)
def test_membership_preserved_in_class_space(prefixlen: int, base: int, probe: int) -> None:
    net = ipaddress.ip_network(
        (int(ipaddress.IPv4Address("10.0.0.0")) | base, prefixlen), strict=False
    )
    mapped_net = MAPPER.map_network(net)
    assert mapped_net.prefixlen == net.prefixlen
    candidate = ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.0.0.0")) | probe)
    assert (candidate in net) == (MAPPER.map_address(candidate) in mapped_net)


def _span(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int]:
    return int(net.network_address), int(net.broadcast_address)


def _relation(a: tuple[int, int], b: tuple[int, int]) -> str:
    if a[1] < b[0] or b[1] < a[0]:
        return "disjoint"
    if a == b:
        return "equal"
    return "inside" if b[0] <= a[0] and a[1] <= b[1] else "contains"


@pytest.mark.skipif(
    not ASSETS.is_file(), reason="local asset map not present (data/ is gitignored)"
)
def test_membership_preserved_for_every_real_asset_network() -> None:
    """R2 gate criterion 2 under the real policy's site prefixes (and a synthetic key; the real
    key is checked by ``scripts/sanitize_fixtures.py check-assets``)."""
    config = REPO_ROOT / "config"
    policy, _ = load_policy(config / "fixtures.yaml", config / "fixtures.local.yaml")
    mapper = IPMapper(KEY, policy.site_prefixes)
    data = yaml.safe_load(ASSETS.read_text())
    rng = random.Random(7)
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in data["networks"]:
        ranges = [entry["range"]] if "range" in entry else entry.get("ranges", [])
        nets.extend(ipaddress.ip_network(str(value), strict=False) for value in ranges)
    images = [mapper.map_network(net) for net in nets]
    for net, mapped in zip(nets, images, strict=True):
        first, last = _span(net)
        members = {first, last} | {rng.randint(first, last) for _ in range(3)}
        for m in members:
            assert mapper.map_address(ipaddress.IPv4Address(m)) in mapped
        for o in (first - 1, last + 1):
            assert mapper.map_address(ipaddress.IPv4Address(o)) not in mapped
    spans = [_span(n) for n in nets]
    image_spans = [_span(n) for n in images]
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            assert _relation(spans[i], spans[j]) == _relation(image_spans[i], image_spans[j])
    assert len(nets) >= 900


@pytest.mark.parametrize(
    ("net", "message"),
    [
        ("8.8.8.0/24", "is public: membership cannot be preserved after cycle-walking"),
        ("10.0.0.0/7", "spans more than one region"),
        # contains 172.16/12 but both ends are public
        ("172.0.0.0/8", "is public: membership cannot be preserved after cycle-walking"),
        ("192.0.2.0/23", "spans more than one region"),
        # both ends are kept, but in two reserved regions (multicast and 240/4)
        ("224.0.0.0/3", "spans more than one reserved region"),
        ("198.18.0.0/24", "is inside the fixture site space"),
    ],
)
def test_unmappable_networks_are_refused(net: str, message: str) -> None:
    with pytest.raises(IPMapError, match=f"^{re.escape(net)} {re.escape(message)}$"):
        MAPPER.map_network(ipaddress.ip_network(net))


def test_an_address_in_the_site_space_is_refused() -> None:
    message = (
        "an address inside the fixture site space 198.18.0.0/15 cannot be pseudonymized: "
        "its images belong to the site prefixes"
    )
    with pytest.raises(IPMapError, match=f"^{re.escape(message)}$"):
        MAPPER.map_text("198.18.0.5")


@pytest.mark.parametrize(
    "net", ["127.0.0.0/8", "224.0.0.0/4", "192.0.0.9/32", "fe80::%eth0/64", "::ffff:127.0.0.0/104"]
)
def test_a_kept_network_comes_back_as_given(net: str) -> None:
    given = ipaddress.ip_network(net)
    assert str(MAPPER.map_network(given)) == str(given)


def test_class_level_networks_map_to_themselves() -> None:
    for region in V4_CLASSES:
        assert str(MAPPER.map_network(ipaddress.ip_network(region))) == region


def test_ipv6_regions() -> None:
    ula = ipaddress.ip_address("fd12:3456:789a::1")
    glob = ipaddress.ip_address("2a00:1450:4001:80b::200e")
    assert MAPPER.map_address(ula) in ipaddress.ip_network("fc00::/7")
    out = MAPPER.map_address(glob)
    assert out.is_global
    assert out != glob
    mapped = MAPPER.map_text("::ffff:10.1.2.3")
    assert mapped == f"::ffff:{MAPPER.map_text('10.1.2.3')}"


@pytest.mark.parametrize(
    ("sites", "message"),
    [
        (["192.0.2.0/24", "192.0.2.128/25"], "overlap"),
        (["10.1.0.0/16"], "overlaps reserved/class"),
        (["127.0.0.0/8"], "overlaps reserved/class"),
    ],
)
def test_bad_site_prefixes_rejected(sites: list[str], message: str) -> None:
    with pytest.raises(IPMapError, match=message):
        IPMapper(KEY, sites)


def test_sites_get_distinct_aligned_blocks() -> None:
    mapper = IPMapper(KEY, ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/25"])
    targets = [t for _, t in mapper.sites]
    for i, a in enumerate(targets):
        assert a.subnet_of(SITE_SPACE_V4)  # type: ignore[arg-type]
        assert int(a.network_address) % a.num_addresses == 0
        for b in targets[i + 1 :]:
            assert not a.overlaps(b)
    _ = Path  # keep import used in type-only contexts


@pytest.mark.parametrize("site", ["192.0.2.0/25", "198.51.100.0/23", "203.0.112.0/22"])
@given(data=st.data())
def test_sites_whose_host_bits_are_not_a_whole_byte(site: str, data: st.DataObject) -> None:
    """Regression: a /22 site has 10 host bits; addresses in its upper half used to overflow the
    PRF's prefix encoding (found on the real corpus, not the 8 samples)."""
    mapper = IPMapper(KEY, [site])
    a = data.draw(in_net(site))
    b = data.draw(in_net(site))
    fa, fb = mapper.map_address(a), mapper.map_address(b)
    target = mapper.sites[0][1]
    assert fa in target
    assert fb in target
    assert common_prefix(fa, fb) == common_prefix(a, b)


def test_every_address_of_a_slash_22_site_maps_into_its_block() -> None:
    mapper = IPMapper(KEY, ["203.0.112.0/22"])
    site = ipaddress.ip_network("203.0.112.0/22")
    outputs = {mapper.map_address(a) for a in site}
    assert len(outputs) == site.num_addresses
    assert all(o in mapper.sites[0][1] for o in outputs)


def test_a_walk_never_returns_to_its_input() -> None:
    """FXG-01: under this key a public 2-cycle pairs 19.38.97.220 with a reserved address; the
    chosen permutation must not have it, so the address maps."""
    mapper = IPMapper(b"k" * 31 + b"\x1e", [SITE])
    out = mapper.map_address(ipaddress.IPv4Address("19.38.97.220"))
    assert out != ipaddress.IPv4Address("19.38.97.220")
    assert mapper.region(out) == "public"


def test_the_public_walks_refuse_exactly_what_they_do_not_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The spans a public walk hands to the domain search are the exact complement of what the
    walk accepts (public, IPv4-mapped never, and the right side of 2000::/3): a span too few
    lets the search pass a permutation whose walk can come back to its input."""
    calls: list[tuple[bytes, int, int, int, tuple[tuple[int, int], ...]]] = []
    original = IPMapper._domain

    def recording(
        self: IPMapper, base: bytes, bits: int, keep: int, start: int, refused: Any
    ) -> bytes:
        calls.append((base, bits, keep, start, refused))
        return original(self, base, bits, keep, start, refused)

    monkeypatch.setattr(IPMapper, "_domain", recording)
    mapper = IPMapper(KEY, [SITE, "2001:db8:1::/48"])
    for text in ("8.8.8.8", "2a00:1450::1", "c0de::1"):
        mapper.map_text(text)
    walks = {
        base: (bits, keep, start, refused)
        for base, bits, keep, start, refused in calls
        if base.startswith(b"public")
    }
    assert set(walks) == {b"public4", b"public6", b"public6x"}
    v6_global = ipaddress.ip_network("2000::/3")
    rng = random.Random(7)
    for base, (bits, keep, start, refused) in walks.items():
        inside = base == b"public6"
        lo, hi = (
            (int(v6_global.network_address), int(v6_global.broadcast_address))
            if inside
            else (0, (1 << bits) - 1)
        )
        # the edges of the spans handed over and of every block the map knows, so that a block
        # missing from the spans is probed too
        known = (*KEEP_REGIONS, *CLASS_REGIONS, *SPECIAL_REGIONS, SITE_SPACE_V4)
        known += (ipaddress.ip_network("2001:2::/48"), ipaddress.ip_network("::ffff:0:0/96"))
        known += (v6_global, *(source for source, _ in mapper.sites))
        edges = [(a, b) for a, b in refused] + [
            (int(n.network_address), int(n.broadcast_address))
            for n in known
            if n.max_prefixlen == bits
        ]
        probes = {v for a, b in edges for v in (a - 1, a, b, b + 1)}
        probes |= {rng.randint(lo, hi) for _ in range(2000)}
        for value in sorted(v for v in probes if lo <= v <= hi):
            addr: IPAddress = (
                ipaddress.IPv4Address(value) if bits == 32 else ipaddress.IPv6Address(value)
            )
            mapped_v4 = isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None
            in_global = addr.version == 6 and addr in v6_global
            accepted = mapper.region(addr) == "public" and not mapped_v4 and in_global == inside
            assert any(a <= value <= b for a, b in refused) is not accepted, (base, addr)
            if accepted:  # the search covers the block the walk runs in
                assert value >> (bits - keep) == start, (base, addr)


@pytest.mark.parametrize(
    ("site", "address", "pseudonym"),
    [
        # the bit just above the host bits is 1: the host part must not take it in
        ("198.51.100.0/22", "198.51.101.7", "198.18.2.91"),
        ("203.0.113.0/24", "203.0.113.200", "198.18.0.220"),
    ],
)
def test_site_known_answers(site: str, address: str, pseudonym: str) -> None:
    assert IPMapper(KEY, [site]).map_text(address) == pseudonym


def test_a_walk_that_comes_back_to_its_input_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(IPMapper, "_domain", lambda self, *args: b"any")
    monkeypatch.setattr(IPMapper, "_permute", lambda self, value, bits, keep, domain: value)
    message = "an address would be its own pseudonym: create a new fixture key"
    with pytest.raises(IPMapError, match=f"^{re.escape(message)}$"):
        IPMapper(KEY).map_text("8.8.8.8")


def test_a_walk_that_finds_no_image_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A permutation that keeps landing on refused addresses gives up after _MAX_WALK steps."""
    monkeypatch.setattr(ipmap_module, "_MAX_WALK", 5)
    monkeypatch.setattr(IPMapper, "_domain", lambda self, *args: b"any")
    refused = int(ipaddress.IPv4Address("10.0.0.1"))
    monkeypatch.setattr(IPMapper, "_permute", lambda self, value, bits, keep, domain: refused)
    message = "cycle-walking found no image; create a new fixture key"
    with pytest.raises(IPMapError, match=f"^{re.escape(message)}$"):
        IPMapper(KEY).map_text("8.8.8.8")


def test_a_domain_without_a_safe_permutation_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every re-keyed permutation has an orbit a walk would come back through: refuse."""
    monkeypatch.setattr(IPMapper, "_lone_orbits", lambda self, *args: [[1]])
    message = "no fixed-point-free permutation found; create a new fixture key"
    with pytest.raises(IPMapError, match=f"^{re.escape(message)}$"):
        IPMapper(b"q" * 32).map_text("8.8.8.8")
