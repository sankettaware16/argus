"""Keyed, prefix- and class-preserving IP pseudonymization for test fixtures.

The map is a Crypto-PAn style permutation: output bit *i* is input bit *i* XOR a keyed PRF of the
input's first *i* bits, so addresses sharing a *k*-bit prefix map to addresses sharing exactly a
*k*-bit prefix. Keep regions (loopback, multicast ...) are unchanged; site prefixes move into the
benchmarking space 198.18.0.0/15; class regions (RFC 1918, CGNAT, ULA) and special-purpose blocks
keep their leading bits; other public addresses are cycle-walked until public again. No address is
its own pseudonym.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Callable, Iterable, Iterator

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _nets(*texts: str) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(text) for text in texts)


CLASS_REGIONS = _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
_BASE_KEEP = _nets(
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
)
# Single anycast service addresses (PCP, TURN, 2001:1::1-3): they identify nothing, and a block of
# one address has no permutation that moves it.
_SERVICE_ADDRESSES = _nets(
    "192.0.0.9/32", "192.0.0.10/32", "2001:1::1/128", "2001:1::2/128", "2001:1::3/128"
)
SITE_SPACE_V4: IPNetwork = ipaddress.ip_network("198.18.0.0/15")
_SITE_SPACE_V6 = ipaddress.IPv6Network("2001:2::/48")
SITE_SPACE_V6: IPNetwork = _SITE_SPACE_V6
_MAPPED_V4 = ipaddress.IPv6Network("::ffff:0:0/96")


def _remainder(block: IPNetwork, holes: tuple[IPNetwork, ...]) -> tuple[IPNetwork, ...]:
    """``block`` without ``holes`` (disjoint subnets of it), as CIDR pieces."""
    pieces = [block]
    for hole in holes:
        pieces = [
            piece
            for whole in pieces
            for piece in (
                whole.address_exclude(hole)  # type: ignore[arg-type]
                if hole.version == whole.version and hole.subnet_of(whole)  # type: ignore[arg-type]
                else (whole,)
            )
        ]
    return tuple(sorted(pieces, key=lambda n: (n.version, int(n.network_address))))


# Blocks that keep their own leading bits inside a larger IETF block: Teredo, AS112-v6, ORCHID,
# ORCHIDv2, DRIP inside 2001::/23; DS-Lite and NAT64 discovery inside 192.0.0.0/24. The rest of
# each block is split around them (and around the site space and the service addresses).
_IETF_PIECES: tuple[IPNetwork, ...] = _nets(
    "192.0.0.0/29",
    "192.0.0.170/31",
    "2001::/32",
    "2001:4:112::/48",
    "2001:10::/28",
    "2001:20::/28",
    "2001:30::/28",
)
_IETF_REST = _remainder(
    ipaddress.ip_network("192.0.0.0/24"), (*_IETF_PIECES, *_SERVICE_ADDRESSES)
) + _remainder(
    ipaddress.ip_network("2001::/23"), (*_IETF_PIECES, _SITE_SPACE_V6, *_SERVICE_ADDRESSES)
)
KEEP_REGIONS: tuple[IPNetwork, ...] = (
    _BASE_KEEP + _SERVICE_ADDRESSES + tuple(n for n in _IETF_REST if n.num_addresses == 1)
)
# Not-globally-reachable blocks of the IANA special-purpose registries (2024-10), plus the newer
# documentation and SRv6 blocks; a site prefix may overlap them (the site wins). Hard-coded, not
# taken from ``ipaddress``, so the map is the same on every Python 3.12.x.
SPECIAL_REGIONS: tuple[IPNetwork, ...] = (
    _nets(
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
    )
    + _IETF_PIECES
    + tuple(n for n in _IETF_REST if n.num_addresses > 1)
)
_V6_GLOBAL = ipaddress.ip_network("2000::/3")
_MAX_WALK = 10_000
_MAX_REKEY = 64
_FIXED_POINT_SEARCH = 2_000_000  # orbit nodes; the expected search is a few thousand
# Chosen domains, shared by mappers alike in everything the choice depends on: the derived key,
# the site prefixes, the domain and the search budget.
_DOMAIN_CACHE: dict[tuple[bytes, tuple[str, ...], bytes, int], bytes] = {}
_CACHED_LEVELS = 24  # PRF bits of prefixes shorter than this are cached (shared by many addresses)


class IPMapError(ValueError):
    """The address or network cannot be mapped under the policy."""


class IPMapper:
    """Deterministic for a given key and site-prefix list."""

    def __init__(self, key: bytes, site_prefixes: Iterable[str] = ()) -> None:
        if len(key) < 32:
            raise IPMapError("the fixture key must be at least 32 bytes")
        # Length-prefixed, so K and K + b"\0" (one key to HMAC) are different keys here.
        self._key = hashlib.sha256(
            b"argus-fixtures/ipmap|" + len(key).to_bytes(4, "big") + key
        ).digest()
        self._prf_cache: dict[tuple[bytes, int, int], int] = {}
        self._addr_cache: dict[IPAddress, IPAddress] = {}
        self._domains: dict[bytes, bytes] = {}
        self.sites: tuple[tuple[IPNetwork, IPNetwork], ...] = allocate_sites(site_prefixes)

    # ------------------------------------------------------------------ public API

    def region(self, addr: IPAddress) -> str:
        """``keep``, ``site:<net>``, ``sitespace:<net>``, ``class:<net>`` or ``public``."""
        addr = _unwrap(addr)
        for net in KEEP_REGIONS:
            if addr.version == net.version and addr in net:
                return "keep"
        for source, _target in self.sites:
            if addr.version == source.version and addr in source:
                return f"site:{source}"
        for space in (SITE_SPACE_V4, SITE_SPACE_V6):
            if addr.version == space.version and addr in space:
                return f"sitespace:{space}"
        for net in (*CLASS_REGIONS, *SPECIAL_REGIONS):
            if addr.version == net.version and addr in net:
                return f"class:{net}"
        return "public"

    def map_address(self, addr: IPAddress) -> IPAddress:
        addr = _unscoped(addr)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            inner = self.map_address(addr.ipv4_mapped)
            return ipaddress.IPv6Address(f"::ffff:{inner}")
        cached = self._addr_cache.get(addr)
        if cached is None:
            cached = self._map_uncached(addr)
            self._addr_cache[addr] = cached
        return cached

    def map_text(self, text: str) -> str:
        """Map an address written as text; raises IPMapError if it is not an address."""
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            raise IPMapError(f"not an IP address: {text!r}") from None
        return format_ip(self.map_address(addr))

    def map_network(self, net: IPNetwork) -> IPNetwork:
        """Map a network whose members all share one region; membership is preserved."""
        if net.prefixlen == 0 or net == _MAPPED_V4:
            return net  # a whole address family: every address is a member, before and after
        first = _unwrap(net.network_address)
        last = _unwrap(net.broadcast_address)
        region = self.region(first)
        if region != self.region(last):
            raise IPMapError(f"{net} spans more than one region")
        if region == "keep":
            if not any(
                first in k and last in k for k in KEEP_REGIONS if k.version == first.version
            ):
                raise IPMapError(f"{net} spans more than one reserved region")
            return net
        if region == "public":
            raise IPMapError(f"{net} is public: membership cannot be preserved after cycle-walking")
        if region.startswith("sitespace:"):
            raise IPMapError(f"{net} is inside the fixture site space")
        if region.startswith("class:") and self._sites_inside(_network(region)):
            raise IPMapError(f"{net}: its block holds a site prefix, so membership is not kept")
        mapped = self.map_address(net.network_address)
        return ipaddress.ip_network(f"{mapped}/{net.prefixlen}", strict=False)

    # ------------------------------------------------------------------ internals

    def _map_uncached(self, addr: IPAddress) -> IPAddress:
        region = self.region(addr)
        bits = addr.max_prefixlen
        value = int(addr)
        if region == "keep":
            return addr
        if region.startswith("sitespace:"):
            space = region.removeprefix("sitespace:")
            raise IPMapError(
                f"an address inside the fixture site space {space} cannot be pseudonymized: "
                "its images belong to the site prefixes"
            )
        if region.startswith("site:"):
            source, target = next(s for s in self.sites if str(s[0]) == region[5:])
            host_bits = bits - source.prefixlen
            host = value & ((1 << host_bits) - 1)
            domain = b"site|" + source.network_address.packed + bytes([source.prefixlen])
            permuted = self._permute(host, host_bits, 0, domain)
            return _make(int(target.network_address) | permuted, bits)
        if region.startswith("class:"):
            net = _network(region)
            # A special block may hold a site prefix: its walk steps over the site's addresses.
            rejected = _spans(
                s for s, _ in self.sites if s.version == net.version and s.overlaps(net)
            )
            domain = self._domain(
                b"class|" + net.network_address.packed + bytes([net.prefixlen]),
                bits,
                net.prefixlen,
                int(net.network_address) >> (bits - net.prefixlen),
                rejected,
            )
            return self._walk(value, bits, net.prefixlen, domain, lambda c: not self._in_site(c))
        return self._map_public(addr)

    def _map_public(self, addr: IPAddress) -> IPAddress:
        bits = addr.max_prefixlen
        inside = bits == 128 and addr in _V6_GLOBAL
        if bits == 32:
            keep, base = 0, b"public4"
        elif inside:
            keep, base = 3, b"public6"
        else:
            keep, base = 0, b"public6x"

        def accept(candidate: IPAddress) -> bool:
            if isinstance(candidate, ipaddress.IPv6Address) and candidate.ipv4_mapped is not None:
                return False  # ::ffff:x belongs to the IPv4 map, never to an IPv6 walk
            in_global = candidate.version == 6 and candidate in _V6_GLOBAL
            return self.region(candidate) == "public" and in_global == inside

        # Everything the walk refuses, as blocks: exactly the complement of ``accept``.
        refused = [
            n
            for n in (*KEEP_REGIONS, *CLASS_REGIONS, *SPECIAL_REGIONS, SITE_SPACE_V4, SITE_SPACE_V6)
            if n.version == addr.version
        ] + [s for s, _ in self.sites if s.version == addr.version]
        if bits == 128:
            refused.append(_MAPPED_V4)
            if not inside:
                refused.append(_V6_GLOBAL)
        start = 1 if keep else 0  # 2000::/3 starts with the bits 001
        domain = self._domain(base, bits, keep, start, _spans(refused))
        return self._walk(int(addr), bits, keep, domain, accept)

    def _walk(
        self, value: int, bits: int, keep: int, domain: bytes, accept: Callable[[IPAddress], bool]
    ) -> IPAddress:
        """Cycle-walk: apply the permutation until the result is in the set the input came from."""
        current = value
        for _ in range(_MAX_WALK):
            current = self._permute(current, bits, keep, domain)
            if current == value:
                raise IPMapError("an address would be its own pseudonym: create a new fixture key")
            candidate = _make(current, bits)
            if accept(candidate):
                return candidate
        raise IPMapError("cycle-walking found no image; create a new fixture key")

    def _domain(
        self, base: bytes, bits: int, keep: int, start: int, refused: tuple[tuple[int, int], ...]
    ) -> bytes:
        """The first re-keyed domain whose permutation has no orbit, of any size, with exactly
        one member the walk accepts (``refused`` lists what it does not, as spans): a walk from
        that member would come back to it (an orbit of one is a fixed point). Deterministic: a
        pure function of the key, the site prefixes and the domain."""
        found = self._domains.get(base)
        if found is not None:
            return found
        sites = tuple(str(source) for source, _ in self.sites)
        cache_key = (self._key, sites, base, _FIXED_POINT_SEARCH)
        found = _DOMAIN_CACHE.get(cache_key)
        if found is not None:
            self._domains[base] = found
            return found
        for counter in range(_MAX_REKEY):
            domain = base + b"|" + str(counter).encode()
            if self._lone_orbits(domain, bits, keep, start, refused) == []:
                self._domains[base] = _DOMAIN_CACHE[cache_key] = domain
                return domain
        raise IPMapError("no fixed-point-free permutation found; create a new fixture key")

    def _lone_orbits(
        self, domain: bytes, bits: int, keep: int, start: int, refused: tuple[tuple[int, int], ...]
    ) -> list[list[int]] | None:
        """Every orbit with exactly one accepted member, or None if the search grows too large.

        Exact for any orbit size: an orbit of prefixes with two members wholly accepted (or with
        no member that holds an accepted address) cannot have such a descendant, since every
        descendant orbit holds a descendant of each member. So only orbits along the borders of
        the refused blocks are followed."""
        found: list[list[int]] = []
        stack: list[tuple[int, list[int]]] = [(keep, [start])]
        for _ in range(_FIXED_POINT_SEARCH):
            if not stack:
                return found
            level, orbit = stack.pop()
            cover = [_cover(prefix, level, bits, refused) for prefix in orbit]
            if cover.count(1) >= 2 or all(c == 0 for c in cover):
                continue
            if level == bits:
                if cover.count(1) == 1:
                    found.append(orbit)
                continue
            flips = [self._prf_bit(domain, level, prefix, bits) for prefix in orbit]
            laps = 1 if sum(flips) % 2 == 0 else 2
            for first in (0, 1) if laps == 1 else (0,):
                child: list[int] = []
                bit = first
                for _lap in range(laps):
                    for prefix, flip in zip(orbit, flips, strict=True):
                        child.append((prefix << 1) | bit)
                        bit ^= flip
                stack.append((level + 1, child))
        return None

    def _fixed_points(self, domain: bytes, bits: int, keep: int, start: int) -> list[int] | None:
        """Every value the permutation leaves unchanged, or None if the search grows too large."""
        orbits = self._short_orbits(domain, bits, keep, start, 1)
        return None if orbits is None else [value for orbit in orbits for value in orbit]

    def _short_orbits(
        self, domain: bytes, bits: int, keep: int, start: int, max_size: int
    ) -> list[list[int]] | None:
        """Every orbit of the permutation with at most ``max_size`` members (as values), or None
        if the search grows too large.

        The permutation acts on prefixes level by level: ``P(p·b) = P(p)·(b XOR f(p))``. An orbit
        of prefixes ``o`` either splits into two orbits of the same size at the next level (the
        XOR of ``f`` over ``o`` is 0) or doubles (it is 1), so only orbits that stay small are
        followed. With ``max_size`` 1 this finds exactly the fixed points."""
        found: list[list[int]] = []
        stack: list[tuple[int, list[int]]] = [(keep, [start])]
        for _ in range(_FIXED_POINT_SEARCH):
            if not stack:
                return found
            level, orbit = stack.pop()
            if level == bits:
                found.append(orbit)
                continue
            flips = [self._prf_bit(domain, level, prefix, bits) for prefix in orbit]
            laps = 1 if sum(flips) % 2 == 0 else 2
            if laps == 2 and 2 * len(orbit) > max_size:
                continue
            for first in (0, 1) if laps == 1 else (0,):
                child: list[int] = []
                bit = first
                for _lap in range(laps):
                    for prefix, flip in zip(orbit, flips, strict=True):
                        child.append((prefix << 1) | bit)
                        bit ^= flip
                stack.append((level + 1, child))
        return None

    def _permute(self, value: int, bits: int, keep: int, domain: bytes) -> int:
        out = value
        for i in range(keep, bits):
            prefix = value >> (bits - i)
            if self._prf_bit(domain, i, prefix, bits):
                out ^= 1 << (bits - 1 - i)
        return out

    def _prf_bit(self, domain: bytes, i: int, prefix: int, bits: int) -> int:
        # Only short prefixes are shared by many addresses; caching deep bits would grow without
        # bound on large corpora, so they are recomputed (an HMAC is ~1-2 µs).
        cacheable = i < _CACHED_LEVELS
        cache_key = (domain, i, prefix)
        if cacheable:
            hit = self._prf_cache.get(cache_key)
            if hit is not None:
                return hit
        # (bits + 7) // 8: host-bit permutations inside a site prefix work on widths such as 10
        # bits (/22), which a whole number of bytes must still hold.
        message = domain + b"|" + i.to_bytes(1, "big") + prefix.to_bytes((bits + 7) // 8, "big")
        bit = hmac.new(self._key, message, hashlib.sha256).digest()[0] & 1
        if cacheable:
            self._prf_cache[cache_key] = bit
        return bit

    def _in_site(self, addr: IPAddress) -> bool:
        return any(addr.version == s.version and addr in s for s, _ in self.sites)

    def _sites_inside(self, block: IPNetwork) -> bool:
        return any(s.version == block.version and s.overlaps(block) for s, _ in self.sites)


def _spans(networks: Iterable[IPNetwork]) -> tuple[tuple[int, int], ...]:
    return tuple(sorted((int(n.network_address), int(n.broadcast_address)) for n in networks))


def _cover(prefix: int, level: int, bits: int, refused: tuple[tuple[int, int], ...]) -> int:
    """0 if every address of the prefix's block is refused, 1 if none is, 2 if some are."""
    lo = prefix << (bits - level)
    hi = lo + (1 << (bits - level)) - 1
    if any(a <= lo and hi <= b for a, b in refused):
        return 0
    return 2 if any(not (b < lo or a > hi) for a, b in refused) else 1


def format_ip(addr: IPAddress) -> str:
    """Text form; IPv4-mapped IPv6 keeps the dotted ``::ffff:a.b.c.d`` form logs use."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return f"::ffff:{addr.ipv4_mapped}"
    return str(addr)


def _make(value: int, bits: int) -> IPAddress:
    return ipaddress.IPv4Address(value) if bits == 32 else ipaddress.IPv6Address(value)


def _network(region: str) -> IPNetwork:
    return ipaddress.ip_network(region.partition(":")[2])


def _unscoped(addr: IPAddress) -> IPAddress:
    """Drop an IPv6 zone (``fe80::1%eth0``): it is free text and never part of the pseudonym."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id is not None:
        return ipaddress.IPv6Address(int(addr))
    return addr


def _unwrap(addr: IPAddress) -> IPAddress:
    addr = _unscoped(addr)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _iter_networks(prefixes: Iterable[str]) -> Iterator[IPNetwork]:
    for prefix in prefixes:
        try:
            yield ipaddress.ip_network(prefix)
        except ValueError as exc:
            raise IPMapError(f"site prefix {prefix!r} is not a network: {exc}") from None


def allocate_sites(prefixes: Iterable[str]) -> tuple[tuple[IPNetwork, IPNetwork], ...]:
    """Give every site prefix its own aligned, same-length block inside the site space."""
    networks = sorted(
        set(_iter_networks(prefixes)),
        key=lambda n: (n.version, n.prefixlen, int(n.network_address)),
    )
    for a in networks:
        if isinstance(a, ipaddress.IPv6Network) and a.overlaps(_MAPPED_V4):
            raise IPMapError(f"site prefix {a} covers IPv4-mapped addresses: use IPv4 prefixes")
        for b in networks:
            if a != b and a.version == b.version and a.overlaps(b):
                raise IPMapError(f"site prefixes overlap: {a} and {b}")
        for region in (*CLASS_REGIONS, *KEEP_REGIONS):
            if a.version == region.version and a.overlaps(region):
                raise IPMapError(f"site prefix {a} overlaps reserved/class region {region}")
        space = SITE_SPACE_V4 if a.version == 4 else SITE_SPACE_V6
        if a.overlaps(space):
            raise IPMapError(f"site prefix {a} overlaps the site space {space}")
    allocated: list[tuple[IPNetwork, IPNetwork]] = []
    cursor = {4: int(SITE_SPACE_V4.network_address), 6: int(SITE_SPACE_V6.network_address)}
    # Largest blocks first keeps every allocation aligned.
    for net in sorted(networks, key=lambda n: (n.version, n.prefixlen)):
        space = SITE_SPACE_V4 if net.version == 4 else SITE_SPACE_V6
        size = net.num_addresses
        start = -(-cursor[net.version] // size) * size  # align up
        target = ipaddress.ip_network(f"{_make(start, net.max_prefixlen)}/{net.prefixlen}")
        if not target.subnet_of(space):  # type: ignore[arg-type]
            raise IPMapError(f"site space {space} is too small for the configured site prefixes")
        allocated.append((net, target))
        cursor[net.version] = start + size
    return tuple(allocated)
