"""The asset map: strict loading, messages without values, longest-prefix match = brute force
(R3 gate: 100k addresses at the gate profile, every network boundary ± 1)."""

from __future__ import annotations

import ipaddress
import random
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.assets import AssetMap, AssetMapError, parse_asset_map
from argus.assets.assetmap import MAX_MAP_BYTES, AssetEntry, IPNetwork
from argus.assets.store import load_asset_map
from tests.conftest import local_asset_map

pytestmark = pytest.mark.unit

SECRET = "Secretname7"  # stands for a real network name: must never appear in a message


def amap(text: str) -> AssetMap:
    return parse_asset_map(text.encode())


GOOD = """
defaults: {site.organization: Example Univ}
networks:
  - name: Big
    range: 10.0.0.0/16
    fields: {site.zone: north}
  - name: Lab
    ranges: [10.0.1.0/24, "10.0.2.0/24", 10.0.1.0/24]
    fields: {site.zone: south, site.floor: 2, site.organization: Lab Org}
  - name: Printer
    range: 10.0.1.7
  - name: Six
    range: 2001:db8::/32
  - name: Dup
    range: 10.0.2.0/24
"""


def test_good_map() -> None:
    m = amap(GOOD)
    assert [e.name for e in m.entries] == ["Big", "Lab", "Printer", "Six", "Dup"]
    lab = m.entries[1]
    assert lab.networks == (
        ipaddress.ip_network("10.0.1.0/24"),
        ipaddress.ip_network("10.0.2.0/24"),
    )
    assert dict(lab.fields) == {
        "site.organization": "Lab Org",
        "site.zone": "south",
        "site.floor": "2",
    }
    assert dict(m.entries[2].fields) == {"site.organization": "Example Univ"}
    assert (m.network_count, m.duplicate_networks) == (5, 1)
    assert len(m.sha256) == 64


@pytest.mark.parametrize(
    ("address", "network", "names"),
    [
        ("10.0.1.7", "10.0.1.7/32", ["Printer"]),
        ("10.0.1.8", "10.0.1.0/24", ["Lab"]),
        ("10.0.2.1", "10.0.2.0/24", ["Lab", "Dup"]),
        ("10.0.200.1", "10.0.0.0/16", ["Big"]),
        ("::ffff:10.0.1.7", "10.0.1.7/32", ["Printer"]),
        ("2001:db8::5", "2001:db8::/32", ["Six"]),
        ("2001:db8::5%eth0", "2001:db8::/32", ["Six"]),
    ],
)
def test_match(address: str, network: str, names: list[str]) -> None:
    found = amap(GOOD).match(address)
    assert found is not None
    assert str(found.network) == network
    assert [e.name for e in found.entries] == names
    assert found.ambiguous is (len(names) > 1)
    assert amap(GOOD).match(ipaddress.ip_address(address.split("%")[0])) == found


@pytest.mark.parametrize(
    "address", ["10.1.0.0", "9.255.255.255", "2001:db9::", "x", "", "1" * 100, 5]
)
def test_no_match(address: Any) -> None:
    assert amap(GOOD).match(address) is None


BAD = [
    (b"\xff\xfe", "not UTF-8"),
    (b"[1, 2]", "mapping with 'defaults' and 'networks'"),
    (b"networks: []\nextra: 1", "mapping with 'defaults' and 'networks'"),
    (b"networks: []", "non-empty list"),
    (b"networks: {a: 1}", "non-empty list"),
    (b"networks:\n  - 5", "entry #1 must be a mapping"),
    (b"networks:\n  - {name: x, range: 10.0.0.0/8, owner: Secretname7}", "entry #1: unknown keys"),
    (b"networks:\n  - {name: Secretname7}", "entry #1 has no range"),
    (b"networks:\n  - {name: x, ranges: 10.0.0.0/8}", "'ranges' must be a list"),
    (b"networks:\n  - {name: x, range: 167772160}", "a range must be text"),
    (b"networks:\n  - {name: x, range: Secretname7}", "not an IP network"),
    (b"networks:\n  - {name: x, range: 10.0.0.1/8}", "host bits"),
    (b"networks:\n  - {name: x, range: '::ffff:10.0.0.0/120'}", "IPv4-mapped"),
    (b"networks:\n  - {range: 10.0.0.0/8}", "entry #1 name must be text"),
    (b"networks:\n  - {name: yes, range: 10.0.0.0/8}", "entry #1 name must be text"),
    (b"networks:\n  - {name: '', range: 10.0.0.0/8}", "printable"),
    (b'networks:\n  - {name: "a\\tb", range: 10.0.0.0/8}', "printable"),
    (
        b"networks:\n  - {name: x, range: 10.0.0.0/8, fields: [Secretname7]}",
        "mapping of site.* fields",
    ),
    (b"networks:\n  - {name: x, range: 10.0.0.0/8, fields: {owner: Secretname7}}", "site.<name>"),
    (
        b"networks:\n  - {name: x, range: 10.0.0.0/8, fields: {site.zone: [Secretname7]}}",
        "site.zone must be text",
    ),
    (b"defaults: 5\nnetworks:\n  - {name: x, range: 10.0.0.0/8}", "defaults must be a mapping"),
    (b"networks:\n  - &a {name: Secretname7, range: 10.0.0.0/8}\n  - *a", "anchors and aliases"),
    (b"base: &b {site.zone: z}\nnetworks: []", "anchors and aliases"),
    (b"networks:\n  - {<<: {name: x}, range: 10.0.0.0/8}", "merge keys"),
    (b"networks:\n  - {name: x, name: Secretname7, range: 10.0.0.0/8}", "duplicate key (line 2)"),
    (b"networks: [[[[[[[[[[1]]]]]]]]]]", "nesting is too deep"),
    (b"networks: [Secretname7: : :", "not valid YAML"),
    (b"networks:\n  - {name: x, range: 10.0.0.0/8}\n\x07", "not valid YAML"),
]


@pytest.mark.parametrize(("raw", "message"), BAD)
def test_invalid_maps_are_refused_without_values(raw: bytes, message: str) -> None:
    with pytest.raises(AssetMapError) as caught:
        parse_asset_map(raw)
    assert message in str(caught.value)
    assert SECRET not in str(caught.value)
    assert "10.0.0" not in str(caught.value)


def test_limits() -> None:
    with pytest.raises(AssetMapError, match="larger than"):
        parse_asset_map(b" " * (MAX_MAP_BYTES + 1))
    many = "networks:\n" + "".join(f"  - {{name: n, range: 10.0.0.{i % 256}}}\n" for i in range(5))
    assert len(amap(many).entries) == 5
    ranges = ", ".join(f"10.0.{i // 256}.{i % 256}" for i in range(257))
    with pytest.raises(AssetMapError, match="more than 256 ranges"):
        amap(f"networks:\n  - {{name: n, ranges: [{ranges}]}}\n")
    with pytest.raises(AssetMapError, match="1-256 printable"):
        amap(f"networks:\n  - {{name: {'n' * 257}, range: 10.0.0.0/8}}\n")


def _message(raw: str) -> str:
    try:
        parse_asset_map(raw.encode())
    except AssetMapError as exc:
        return str(exc)
    return ""


@given(
    st.text(
        st.characters(blacklist_categories=("Cs",), blacklist_characters="'"),
        min_size=4,
        max_size=30,
    )
)
def test_no_value_ever_appears_in_a_message(secret: str) -> None:
    """A message never contains a value: it is the message for the same file with a neutral
    placeholder (unless the value is a word of that message, such as 'entry')."""
    for template in (
        "networks:\n  - {{name: x, range: '{}'}}\n",
        "networks:\n  - {{name: x, range: 10.0.0.0/8, fields: {{'{}': v}}}}\n",
        "networks:\n  - {{name: x, range: 10.0.0.0/8, '{}': 1}}\n",
        "networks:\n  - {{name: '{}', range: 10.0.0.0/8, oops: [}}\n",
        "networks:\n  - {{name: '{}', range: 10.0.0.0/33}}\n",
    ):
        message = _message(template.format(secret))
        neutral = _message(template.format("Q" * len(secret)))
        assert secret not in message or secret in neutral


# --------------------------------------------------------------------------- brute force


def brute_force(entries: list[AssetEntry], address: Any) -> tuple[IPNetwork, list[str]] | None:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    best: IPNetwork | None = None
    for entry in entries:
        for network in entry.networks:
            if (
                network.version == ip.version
                and ip in network
                and (best is None or network.prefixlen > best.prefixlen)
            ):
                best = network
    if best is None:
        return None
    return best, [e.name for e in entries if best in e.networks]


def mismatches(m: AssetMap, addresses: list[Any]) -> int:
    entries = list(m.entries)
    count = 0
    for address in addresses:
        found = m.match(address)
        got = None if found is None else (found.network, [e.name for e in found.entries])
        count += got != brute_force(entries, address)
    return count


def assert_same(m: AssetMap, addresses: list[Any]) -> None:
    """For synthetic maps only: the failure shows the address and the networks."""
    entries = list(m.entries)
    for address in addresses:
        found = m.match(address)
        got = None if found is None else (found.network, [e.name for e in found.entries])
        assert got == brute_force(entries, address), address


def boundaries(networks: list[IPNetwork]) -> list[Any]:
    out: list[Any] = []
    for n in networks:
        top = (1 << n.max_prefixlen) - 1
        for value in (
            int(n.network_address) - 1, int(n.network_address),
            int(n.broadcast_address), int(n.broadcast_address) + 1,
        ):  # fmt: skip
            if 0 <= value <= top:
                out.append(
                    ipaddress.ip_address(value) if n.version == 4 else ipaddress.IPv6Address(value)
                )
    return out


def realistic_map(rnd: random.Random, size: int) -> str:
    """Nested like the real map: /16s holding /19s, /20s, /24s and single hosts, a few listed
    twice, some entries with several ranges."""
    lines = ["networks:"]
    supers = [
        ipaddress.ip_network(f"10.{rnd.randrange(256)}.0.0/16") for _ in range(size // 50 + 1)
    ]
    for i in range(size):
        outer = rnd.choice(supers)
        length = rnd.choice([16, 19, 20, 24, 24, 24, 32, 32, 32, 32])
        offset = rnd.randrange(outer.num_addresses) >> (32 - length) << (32 - length)
        net = ipaddress.ip_network((int(outer.network_address) + offset, length))
        extra = (
            f", {ipaddress.ip_network((int(net.network_address), length))}" if i % 37 == 0 else ""
        )
        lines.append(f"  - {{name: n{i}, ranges: [{net}{extra}]}}")
    lines.append("  - {name: v6, range: 'fd00:1::/48'}")
    lines.append("  - {name: v6host, range: 'fd00:1::1'}")
    return "\n".join(lines) + "\n"


def sample_addresses(rnd: random.Random, m: AssetMap, count: int) -> list[Any]:
    networks = [n for e in m.entries for n in e.networks]
    out: list[Any] = []
    for _ in range(count):
        roll = rnd.random()
        if roll < 0.6:  # near a network: inside, or just outside
            n = rnd.choice(networks)
            value = int(n.network_address) + rnd.randrange(-300, n.num_addresses + 300)
            value = min(max(value, 0), (1 << n.max_prefixlen) - 1)
            out.append(
                ipaddress.ip_address(value) if n.version == 4 else ipaddress.IPv6Address(value)
            )
        elif roll < 0.95:
            out.append(ipaddress.IPv4Address(rnd.getrandbits(32)))
        else:
            out.append(f"::ffff:{ipaddress.IPv4Address(rnd.getrandbits(32))}")
    return out


def _count() -> int:
    return settings().max_examples * 10  # 100,000 at the gate profile


def test_realistic_synthetic_map_matches_brute_force() -> None:
    rnd = random.Random(20261012)
    m = amap(realistic_map(rnd, 1000))
    assert m.duplicate_networks > 0
    networks = [n for e in m.entries for n in e.networks]
    assert_same(m, boundaries(networks))
    assert_same(m, sample_addresses(rnd, m, _count()))


@settings(max_examples=max(20, settings().max_examples // 10))
@given(st.integers(0, 2**32 - 1), st.integers(1, 60))
def test_random_maps_match_brute_force(seed: int, size: int) -> None:
    rnd = random.Random(seed)
    m = amap(realistic_map(rnd, size))
    networks = [n for e in m.entries for n in e.networks]
    assert_same(m, boundaries(networks) + sample_addresses(rnd, m, 200))


REAL_MAP = local_asset_map()


@pytest.mark.skipif(not REAL_MAP.is_file(), reason="no local asset map (data/ is never committed)")
def test_real_map_matches_brute_force() -> None:
    m = load_asset_map(REAL_MAP)
    assert m is not None
    networks = [n for e in m.entries for n in e.networks]
    rnd = random.Random(7)
    # Counts only: a failure must not print the real map's networks or names.
    assert mismatches(m, boundaries(networks)) == 0
    assert mismatches(m, sample_addresses(rnd, m, _count())) == 0
