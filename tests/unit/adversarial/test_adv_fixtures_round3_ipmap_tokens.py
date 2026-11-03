"""Adversarial round 3 on R2's IP map, tokens and policy after fix round 2 (D-042).

Lens FXI: break what fix round 2 changed:

* ``argus.fixtures.ipmap``: orbit-based re-keying (``_short_orbits``, ``_domain`` with
  ``max_orbit``), class walks of special blocks that hold site prefixes, the ``_IETF_PIECES`` /
  ``_remainder`` table, and the IPv4-mapped refusal in the IPv6 walk;
* ``argus.fixtures.tokens``: the id permutation ``D = F⁻¹ ∘ (+1) ∘ F`` walked within the id's
  class, ``normalize_domain`` (NFC, punycode, the dots table), ``_unpuny``/``_squash``, sensitive
  last labels and campus aliases;
* ``argus.fixtures.policy``: the load-time checks of the keep lists, field patterns,
  ``campus_replacement`` and ``site_prefixes``.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every address, prefix, name and key is
synthetic (documentation, benchmarking, NAT64 and private ranges, ``*.example``-style names, the
key ``b"k" * 32`` or a one-byte variant of it); nothing touches the network. Crafted inputs (the
colliding id, the returning address) were found offline by inverting the keyed permutations;
they are written out so the DEFECT tests use the public API only. Several LOCK-INs compare private
helpers with brute force or an exact search on purpose.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.fixtures.ipmap import (
    CLASS_REGIONS,
    KEEP_REGIONS,
    SITE_SPACE_V4,
    SITE_SPACE_V6,
    SPECIAL_REGIONS,
    IPAddress,
    IPMapError,
    IPMapper,
    IPNetwork,
)
from argus.fixtures.policy import FixturePolicy, load_policy
from argus.fixtures.tokens import (
    _B64URL_DIGITS,
    MULTI_LABEL_SUFFIXES,
    DomainMapper,
    Tokenizer,
    _id_class,
    _unpuny,
    normalize_domain,
)

KEY = b"k" * 32
SITES = ("203.0.112.0/22",)  # one public /22, as on the real campus (synthetic here)
MAPPER = IPMapper(KEY, SITES)
TOKENS = Tokenizer(KEY)
REPO = Path(__file__).resolve().parents[3]
HEX_LOWER = string.digits + "abcdef"
HEX_UPPER = string.digits + "ABCDEF"
DEVANAGARI = "आईआईटी"  # a Unicode campus name (synthetic)
_DOMAINS = DomainMapper(TOKENS, ["campus.ac.in"], ["amazonaws.com", "github.com"])
_V6_GLOBAL = ipaddress.IPv6Network("2000::/3")
_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")
_LDH = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")


def _decoded(name: str) -> str:
    """A name as a reader sees it: punycode labels decoded, NFKC, case-folded."""
    return unicodedata.normalize("NFKC", _unpuny(name)).casefold()


def _ip(text: str) -> IPAddress:
    return ipaddress.ip_address(text)


def _rejected(mapper: IPMapper, version: int) -> list[IPNetwork]:
    """Every block outside the public set of one address family (keep, class, special, site
    space and the mapper's own site prefixes)."""
    table = [*KEEP_REGIONS, *CLASS_REGIONS, *SPECIAL_REGIONS, SITE_SPACE_V4, SITE_SPACE_V6]
    table += [source for source, _ in mapper.sites]
    return [net for net in table if net.version == version]


def _cover(prefix: int, level: int, bits: int, spans: list[tuple[int, int]]) -> int:
    """0 if the prefix block is wholly rejected, 1 if wholly accepted, 2 if mixed."""
    lo = prefix << (bits - level)
    hi = lo + (1 << (bits - level)) - 1
    if any(a <= lo and hi <= b for a, b in spans):
        return 0
    return 2 if any(not (b < lo or a > hi) for a, b in spans) else 1


def _lone_orbits(
    mapper: IPMapper, domain: bytes, bits: int, keep: int, start: int, rejected: list[IPNetwork]
) -> list[list[int]]:
    """Exact search, any orbit size: every orbit of the keyed permutation with exactly one
    accepted member. An orbit of prefixes with two wholly accepted members (or none that is
    accepted at all) cannot have such a descendant, because every descendant orbit holds a
    descendant of each member; so only the few orbits along region boundaries are followed."""
    spans = [(int(n.network_address), int(n.broadcast_address)) for n in rejected]
    found: list[list[int]] = []
    stack: list[tuple[int, list[int]]] = [(keep, [start])]
    while stack:
        level, orbit = stack.pop()
        cover = [_cover(p, level, bits, spans) for p in orbit]
        if cover.count(1) >= 2 or all(c == 0 for c in cover):
            continue
        if level == bits:
            if cover.count(1) == 1:
                found.append(orbit)
            continue
        flips = [mapper._prf_bit(domain, level, p, bits) for p in orbit]
        laps = 1 if sum(flips) % 2 == 0 else 2
        for first in (0, 1) if laps == 1 else (0,):
            child, bit = [], first
            for _ in range(laps):
                for prefix, flip in zip(orbit, flips, strict=True):
                    child.append((prefix << 1) | bit)
                    bit ^= flip
            stack.append((level + 1, child))
    return found


def _preimage(mapper: IPMapper, domain: bytes, bits: int, target: int) -> int:
    """The input the keyed (keep = 0) permutation sends to ``target``: bit by bit, since output
    bit i is input bit i XOR a PRF of the input's first i bits."""
    value = 0
    for i in range(bits):
        out_bit = (target >> (bits - 1 - i)) & 1
        value = (value << 1) | (out_bit ^ mapper._prf_bit(domain, i, value, bits))
    return value


# ================================================================== DEFECTS: IP map

NAT64_SITES = ("64:ff9b::/98", "64:ff9b::4000:0/98", "64:ff9b::8000:0/98")


def test_fxi01_ipv6_special_block_with_several_sites_walk_returns_to_its_input() -> None:
    """DEFECT FXI-01 (LOW): the re-keying check is complete for an IPv4 special /24 holding a
    site (orbits up to 256), but for an IPv6 special block holding sites it only looks at orbits
    of 1 and 2 (``_SHORT_ORBIT_V6``). With three site prefixes covering three quarters of
    64:ff9b::/96, every orbit that doubles at bits 96 and 97 and then stays at 4 members has
    exactly one non-site member. Under the key ``b"k" * 31 + b"<"`` the chosen domain (counter 0)
    has the 4-orbit 64:ff9b::fee4:6393 -> ::4529:a9fc -> ::a9ee:e7c5 -> ::2398:b9e3 (the last
    three are site members), so the walk from 64:ff9b::fee4:6393 comes back and raises "an
    address would be its own pseudonym". 11 of 600 keys tried fail this way for this policy. Only
    policies with several sites inside one small IPv6 special block are affected (one site in a
    block is safe: its lone orbits have 2 members), hence LOW; D-042's "a walk therefore never
    returns to its input" is not true for them."""
    mapper = IPMapper(b"k" * 31 + b"<", NAT64_SITES)
    block = ipaddress.ip_network("64:ff9b::/96")
    addr = _ip("64:ff9b::fee4:6393")
    assert mapper.region(addr) == f"class:{block}"
    try:
        out = mapper.map_address(addr)
    except IPMapError as exc:
        pytest.fail(f"{addr} (in {block}, outside every site) cannot be mapped: {exc}")
    assert out in block
    assert not any(out in ipaddress.ip_network(s) for s in NAT64_SITES)
    assert out != addr


@pytest.mark.parametrize(
    ("text", "block"),
    [("192.0.0.2", "192.0.0.0/29"), ("192.0.0.170", "192.0.0.170/31")],
    ids=["ds-lite-b4", "nat64-discovery"],
)
def test_fxi07_ietf_sub_blocks_of_192_0_0_0_24_leave_their_block(text: str, block: str) -> None:
    """DEFECT FXI-07 (LOW, fidelity only): FXG-03 gave Teredo, AS112-v6 and ORCHID their own
    pieces of 2001::/23, but the IPv4 counterpart 192.0.0.0/24 (IETF Protocol Assignments) is
    still one block, so its registered sub-blocks are permuted inside the /24 and leave
    themselves: the DS-Lite B4 address 192.0.0.2 (192.0.0.0/29) maps to 192.0.0.101, the NAT64
    discovery address 192.0.0.170 (192.0.0.170/31, ipv4only.arpa) to 192.0.0.140. The same holds
    for the anycast addresses 2001:1::1, ::2, ::3 inside the piece 2001:1::/32. Fix: pieces for
    192.0.0.0/29 and 192.0.0.170/31 (and the remainder), and treat single-address service blocks
    (192.0.0.8-10/32, 2001:1::1-3/128) as keep regions: a one-address class region has no
    fixed-point-free permutation."""
    out = MAPPER.map_address(_ip(text))
    assert out in ipaddress.ip_network(block), f"{text} -> {out}"


def test_fxi08_a_site_prefix_holding_the_ipv4_mapped_block_is_accepted() -> None:
    """DEFECT FXI-08 (LOW): FXG-12 (b) refuses a site prefix *inside* ::ffff:0:0/96, but a
    supernet of it (``::fffe:0:0/95``) passes ``allocate_sites`` and the policy. Its upper half
    is the IPv4-mapped block, which ``region()`` always unwraps to IPv4 first, so half of the
    configured site silently never matches (``::ffff:198.51.100.7`` is ``class:198.51.100.0/24``,
    not ``site:``). Fix: refuse any site prefix that *overlaps* ::ffff:0:0/96."""
    with pytest.raises(ValueError):  # noqa: PT011 - IPMapError or pydantic's ValidationError
        FixturePolicy(site_prefixes=("::fffe:0:0/95",))
    with pytest.raises(IPMapError):
        IPMapper(KEY, ["::fffe:0:0/95"])


# ================================================================== DEFECTS: tokens


@pytest.mark.parametrize(
    ("fallback", "permuted"),
    [("evt.4711", "KyXGKE-e--FkPK8Eig5"), ("ruleset:42", "aFH-jLP39jbVvqW7bvN")],
)
def test_fxi02_fallback_ids_collide_with_permuted_base64url_ids(
    fallback: str, permuted: str
) -> None:
    """DEFECT FXI-02 (LOW): two different ids, one pseudonym, no error. An id outside the
    alphabets (a ``.``, ``:``, space, or more than 128 characters) becomes ``"id-"`` + 16
    base32 characters: a 19-character base64url string of the "other" class. 19-character
    base64url ids go through the class permutation, which is *onto* that class, so every
    fallback pseudonym is also the image of exactly one base64url id. Inverting the permutation
    gives ``opaque_id("evt.4711") == opaque_id("KyXGKE-e--FkPK8Eig5") == "id-swmsv76gr6zontfh"``.
    ``TokenCollisionError`` only tracks the fallback tokens among themselves. By chance this needs
    2**-114 per pair; FXG-02 was the same kind of finding. Fix: give fallback pseudonyms a shape
    no permuted id can have (a character outside base64url, e.g. ``id.``), or a length > 21."""
    a, b = TOKENS.opaque_id(fallback), TOKENS.opaque_id(permuted)
    assert a != b, f"{fallback!r} and {permuted!r} both become {a!r}"


@pytest.mark.parametrize(
    "domain",
    [f"{DEVANAGARI}-backups.s3.amazonaws.com", f"printer.{DEVANAGARI}"],
    ids=["kept-head", "last-label"],
)
def test_fxi03_an_idn_campus_name_survives(domain: str) -> None:
    """DEFECT FXI-03 (LOW): for a campus domain with a Unicode first label (``आईआईटी.भारत``),
    the sensitive terms are built from the *normalised* name, i.e. punycode
    (``xnm1bafb9ioi``), while ``_is_sensitive`` compares them with the *decoded* head
    (``_unpuny``, the FXG-08 fix). The two forms never meet: ``आईआईटी-backups.s3.amazonaws.com``
    is kept verbatim as ``xn---backups-dbqavb31a1p.s3.amazonaws.com`` and ``printer.आईआईटी``
    becomes ``x6lcan64.xn--m1bafb9ioi``; both decode straight back to the campus name. IIT
    Bombay's domains are ASCII, hence LOW. Fix: add ``_squash(_unpuny(label))`` of each campus
    label (and of the whole campus domain) to the terms."""
    mapper = DomainMapper(TOKENS, [f"{DEVANAGARI}.भारत"], ["amazonaws.com"])
    out = mapper.map(domain)
    assert DEVANAGARI not in _decoded(out), f"{domain} -> {out}"


@pytest.mark.parametrize(
    "domain",
    [
        "ｃａｍｐｕｓ-backups.s3.amazonaws.com",  # fullwidth  # noqa: RUF001
        "\U0001d41c\U0001d41a\U0001d426\U0001d429\U0001d42e\U0001d42c-backups.s3.amazonaws.com",
        "printer.ｃａｍｐｕｓ",  # noqa: RUF001
    ],
    ids=["fullwidth-kept-head", "math-bold-kept-head", "fullwidth-last-label"],
)
def test_fxi04_compatibility_forms_of_a_campus_name_survive(domain: str) -> None:
    """DEFECT FXI-04 (LOW): ``normalize_domain`` applies NFC, not the NFKC case folding that
    IDNA (UTS 46) and every browser apply, and ``_squash`` only case-folds. A campus name in
    fullwidth or mathematical letters therefore never matches the ASCII term: fullwidth
    ``campus-backups.s3.amazonaws.com`` is kept verbatim (``xn---backups-df39bta5iob1b1a…``),
    ``printer.`` + fullwidth ``campus`` keeps its last label; NFKC-decoded, both read
    ``campus``. The same mismatch makes ``www.`` + fullwidth ``campus`` + ``.ac.in`` (one domain
    for a browser) miss the campus replacement. Such forms reach logs only through crafted
    text, hence LOW. Fix: NFKC + casefold per label in ``normalize_domain``, and NFKC in
    ``_squash`` (both modules)."""
    mapper = DomainMapper(TOKENS, ["campus.ac.in"], ["amazonaws.com"])
    out = mapper.map(domain)
    assert "campus" not in _decoded(out), f"{domain} -> {out}"


@pytest.mark.parametrize("domain", ["www.campus.ac.in .", "www.campus.ac.in\t.", "a 。"])
def test_fxi05_normalize_domain_is_not_idempotent(domain: str) -> None:
    """DEFECT FXI-05 (LOW): ``normalize_domain`` strips whitespace from the whole name *before*
    it drops the trailing dots, so whitespace in front of the trailing dot survives the first
    pass and is stripped by the second: ``"www.campus.ac.in ."`` -> ``"www.campus.ac.in "`` ->
    ``"www.campus.ac.in"``. The first form is no longer recognised as campus: it maps to
    ``nj4xtrco.62o6vdys.hvg43mlm.in `` instead of ``nj4xtrco.univ.example`` (no leak, one name
    with two pseudonyms). Found by Hypothesis (``"a\\t."``). Fix: strip each label (or refuse
    whitespace inside a name) and drop labels that are empty after stripping."""
    once = normalize_domain(domain)
    assert normalize_domain(once) == once, (domain, once, normalize_domain(once))


def test_fxi06_a_long_unicode_label_takes_quadratic_time() -> None:
    """DEFECT FXI-06 (LOW): ``normalize_domain`` punycode-encodes a label of any length, and
    Python's punycode encoder is quadratic in the number of distinct code points (the reason
    CPython's ``idna`` codec caps labels, CVE-2022-45061). Measured: 2,000 distinct CJK
    characters 0.9 s, 8,000 16 s, 32,000 119 s, for *one* domain value, which an attacker writes
    into a Host header or a URL. A DNS label is at most 63 octets. Fix: a label (or name) over
    63 (253) characters is not a domain: give it the ``.invalid`` token without encoding it."""
    label = "".join(chr(0x4E00 + i) for i in range(3000))
    start = time.perf_counter()
    _DOMAINS.map(f"{label}.example-shop.de")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.25, f"one 3,000-character label took {elapsed:.2f} s"


# ================================================================== DEFECTS: policy


@pytest.mark.parametrize(
    "data",
    [
        {
            "literals": {"Campus University": "Example University"},
            "keep_names": ("root", "Campus-University"),
        },
        {"campus_domains": ("campusu.ac.in",), "keep_names": ("root", "campusu-admin")},
        {"campus_domains": (f"{DEVANAGARI}.भारत",), "keep_names": ("root", DEVANAGARI)},
        {"literals": {DEVANAGARI: "Univ"}, "keep_domains": (f"{DEVANAGARI}-cdn.com",)},
        {"campus_domains": (f"{DEVANAGARI}.भारत",), "keep_domains": (f"{DEVANAGARI}-cdn.com",)},
        {"campus_domains": ("iit.ac.in",), "keep_domains": ("iit-cdn.com",)},
    ],
    ids=[
        "keep-name-is-a-literal-with-a-dash",
        "keep-name-holds-campus-label",
        "keep-name-is-unicode-campus-label",
        "keep-domain-holds-unicode-literal",
        "keep-domain-holds-unicode-campus-label",
        "keep-domain-holds-3-letter-campus-label",
    ],
)
def test_fxi09_contradictory_keep_lists_still_pass(data: dict[str, object]) -> None:
    """DEFECT FXI-09 (LOW): ``_check_keep_lists`` (the FXG-10 fix) compares in forms the
    sanitizer does not use:
    * keep names are compared by equality, but literals match case-insensitively across ``-``,
      ``_``, ``.``, ``+`` and ``%20`` (``Campus-University`` stays raw in ``user.name`` while
      the free text replaces it), and a keep name that *holds* a campus label passes
      (``campusu-admin``), although a keep domain that holds one is refused;
    * campus labels and keep domains are compared in punycode, so a Unicode literal or campus
      label never matches (``आईआईटी-cdn.com`` is kept verbatim: FXG-08's hole, at load time);
    * terms shorter than 4 are skipped, but ``DomainMapper`` treats 3-letter campus labels as
      sensitive (``iit``), so ``iit-cdn.com`` is kept verbatim while ``iit-x.s3.amazonaws.com``
      is tokenized.
    The scanner usually flags the result, so the run fails late instead of at load. Fix: compare
    ``_squash(_unpuny(x))`` forms by containment for keep names and keep domains, with the same
    length threshold as ``DomainMapper`` (3)."""
    with pytest.raises(ValueError):  # noqa: PT011 - any load-time refusal is the fix
        FixturePolicy.model_validate(data)


@pytest.mark.parametrize(
    "fields",
    [
        {"host": ("*[!.]*",)},
        {"host": ("[!.]*",)},
        {"host": ("*.name",), "user": ("**.name",)},
    ],
    ids=["bracket-match-all", "bracket-match-all-2", "one-pattern-two-spellings-two-kinds"],
)
def test_fxi10_field_pattern_checks_are_syntactic(fields: dict[str, tuple[str, ...]]) -> None:
    """DEFECT FXI-10 (LOW): the FXG-11 fix refuses a pattern whose dot-separated segments are all
    wildcard characters, and one *string* under two kinds. ``*[!.]*`` has the segments ``*[!``
    and ``]*``, whose stripped form ``!`` is not empty, so it passes, yet it matches every field
    (``message``, ``@timestamp``): every value becomes a host name. ``*.name`` and ``**.name``
    are one pattern for fnmatch, so a policy with them under two kinds passes and policy order
    silently decides. Fix: probe each pattern against fixed canary paths (``message``,
    ``@timestamp``, ``event.original``) and compare normalised patterns (``*`` runs collapsed)."""
    with pytest.raises(ValueError):  # noqa: PT011 - any load-time refusal is the fix
        FixturePolicy(fields=fields)


@pytest.mark.parametrize("replacement", ["univ。example", " univ.example", "univ..example"])
def test_fxi11_campus_replacement_is_checked_normalised_but_used_raw(replacement: str) -> None:
    """DEFECT FXI-11 (LOW): ``_check_domains`` validates ``normalize_domain(replacement)``
    (``univ.example``), but ``DomainMapper`` writes the raw string into every campus pseudonym:
    ``www.campus.ac.in`` becomes ``nj4xtrco.univ。example``, ``nj4xtrco. univ.example`` or
    ``nj4xtrco.univ..example``: not domain-shaped, and (the first) not ASCII. Fix: refuse a
    replacement that is not already a lower-case LDH name, or store the normalised form."""
    try:
        policy = FixturePolicy(campus_domains=("campus.ac.in",), campus_replacement=replacement)
    except ValueError:
        return
    mapper = DomainMapper(TOKENS, policy.campus_domains, (), policy.campus_replacement)
    out = mapper.map("www.campus.ac.in")
    assert _LDH.fullmatch(out), f"campus pseudonym {out!r}"


# ================================================================== LOCK-INS: IP map


def test_lockin_short_orbit_search_matches_brute_force_for_every_size() -> None:
    """LOCK-IN (exhaustive): ``_short_orbits`` returns exactly the brute-force orbits of at most
    1, 2, 4, 8 and 16 members, on 24 synthetic domains at three widths (9 to 12 bits, with and
    without kept leading bits), so orbit-based re-keying sees what it claims to see."""
    mapper = IPMapper(KEY, ())

    def brute(domain: bytes, bits: int, keep: int, start: int) -> list[list[int]]:
        lo = start << (bits - keep)
        seen: set[int] = set()
        orbits = []
        for v in range(lo, lo + (1 << (bits - keep))):
            if v in seen:
                continue
            orbit, cur = [v], mapper._permute(v, bits, keep, domain)
            while cur != v:
                orbit.append(cur)
                cur = mapper._permute(cur, bits, keep, domain)
            seen.update(orbit)
            orbits.append(sorted(orbit))
        return orbits

    for n in range(24):
        domain = b"probe|" + str(n).encode()
        for bits, keep, start in ((10, 0, 0), (12, 2, 1), (9, 1, 1)):
            orbits = brute(domain, bits, keep, start)
            for size in (1, 2, 4, 8, 16):
                found = mapper._short_orbits(domain, bits, keep, start, size)
                assert found is not None
                want = sorted(o for o in orbits if len(o) <= size)
                assert sorted(sorted(o) for o in found) == want, (n, bits, size)


def test_lockin_public_walks_have_no_lone_orbit_of_any_size() -> None:
    """LOCK-IN (exact): for 24 keys, the re-keyed public IPv4 permutation (with a /22 site) has
    no orbit, of *any* size, with exactly one public member; for 6 keys the same holds for the
    two IPv6 walks (2000::/3 and the rest). So no public walk returns to its input: the
    orbit-size cut (4 for IPv4, 2 for IPv6) is safe for the public sets, whose non-public parts
    are a few large blocks. The search is not vacuous: about 1 in 6 un-re-keyed domains has a
    lone orbit (of 1, 2 or, rarely, 4 members; none larger in 40,000 domains tried offline)."""
    raw_hits = 0
    for n in range(24):
        mapper = IPMapper(bytes([n + 1]) * 32, SITES)
        mapper.map_address(_ip("8.8.8.8"))
        rejected4 = _rejected(mapper, 4)
        assert _lone_orbits(mapper, mapper._domains[b"public4"], 32, 0, 0, rejected4) == []
        for counter in range(4):
            raw = b"public4|raw" + str(4 * n + counter).encode()
            raw_hits += bool(_lone_orbits(mapper, raw, 32, 0, 0, rejected4))
        if n < 6:
            mapper.map_address(_ip("2a00:1450::1"))
            mapper.map_address(_ip("4000::1"))
            rejected6 = _rejected(mapper, 6)
            outside = [*rejected6, _V6_GLOBAL, _MAPPED]
            assert _lone_orbits(mapper, mapper._domains[b"public6"], 128, 3, 1, rejected6) == []
            assert _lone_orbits(mapper, mapper._domains[b"public6x"], 128, 0, 0, outside) == []
    assert raw_hits >= 6


_V4_LAYOUTS = {
    "half": ["{b}.0/25"],
    "middle-quarter": ["{b}.64/26"],
    "three-quarters": ["{b}.0/26", "{b}.64/26", "{b}.128/26"],
    "one-host": ["{b}.77/32"],
    "two-left": [
        "{b}.0/25", "{b}.128/26", "{b}.192/27", "{b}.224/28", "{b}.240/29", "{b}.248/30",
        "{b}.252/31",
    ],
    "both-ends-left": [
        "{b}.1/32", "{b}.2/31", "{b}.4/30", "{b}.8/29", "{b}.16/28", "{b}.32/27", "{b}.64/26",
        "{b}.128/26", "{b}.192/27", "{b}.224/28", "{b}.240/29", "{b}.248/30", "{b}.252/31",
        "{b}.254/32",
    ],
}  # fmt: skip


@pytest.mark.parametrize("layout", sorted(_V4_LAYOUTS))
def test_lockin_special_v4_blocks_holding_sites_map_exactly(layout: str) -> None:
    """LOCK-IN (exhaustive): an IPv4 special /24 holding site prefixes, in six layouts from one
    host to all but two addresses (both ends of the block), under 6 keys and 2 blocks: the
    non-site addresses map one-to-one onto themselves, none to itself, none into a site, and
    nothing raises. (The whole-block orbit check, 256 members, is exact.)"""
    for base in ("192.0.2", "198.51.100"):
        block = ipaddress.ip_network(f"{base}.0/24")
        sites = [s.format(b=base) for s in _V4_LAYOUTS[layout]]
        for k in range(6):
            mapper = IPMapper(bytes([k + 7]) * 32, sites)
            free = [a for a in block if not mapper._in_site(a)]
            out = [mapper.map_address(a) for a in free]
            assert sorted(out) == free, (layout, base, k)
            assert all(a != b for a, b in zip(free, out, strict=True)), (layout, base, k)


def test_lockin_ietf_pieces_tile_2001_23_and_keep_their_blocks() -> None:
    """LOCK-IN: the IETF pieces, the remainder pieces and the IPv6 site space tile 2001::/23
    exactly (no gap, no overlap); under 8 keys Teredo, AS112-v6, ORCHID, ORCHIDv2 and DRIP
    addresses stay in their own block and a remainder-piece address stays in its piece; a site
    prefix inside a remainder piece maps into the site space and the rest of the piece stays
    in the piece; the benchmarking block 2001:2::/48 is refused."""
    whole = ipaddress.IPv6Network("2001::/23")
    # Revised with FXI-07: the single service addresses 2001:1::1-3 (and the one-address pieces
    # beside them) are keep regions now, so they take part in the tiling too.
    pieces = sorted(
        [
            n
            for n in (*SPECIAL_REGIONS, *KEEP_REGIONS)
            if n.version == 6 and n.subnet_of(whole)  # type: ignore[arg-type]
        ]
        + [SITE_SPACE_V6]
    )
    assert sum(p.num_addresses for p in pieces) == whole.num_addresses
    for a, b in itertools.pairwise(pieces):
        assert int(a.broadcast_address) + 1 == int(b.network_address), (a, b)
    probes = {
        "2001:0:4136:e378:8000:63bf:3fff:fdd2": "2001::/32",
        "2001:4:112::1": "2001:4:112::/48",
        "2001:10::1": "2001:10::/28",
        "2001:20::abcd": "2001:20::/28",
        "2001:30::7": "2001:30::/28",
        "2001:4:113::9": "2001:4:113::/48",
        "2001:2:1::5": "2001:2:1::/48",
    }
    for k in range(8):
        mapper = IPMapper(bytes([k + 40]) * 32, ("2001:5:1::/56",))
        for text, block in probes.items():
            assert mapper.map_address(_ip(text)) in ipaddress.ip_network(block), (k, text)
        assert mapper.map_address(_ip("2001:5:1::9")) in SITE_SPACE_V6
        out = mapper.map_address(_ip("2001:5:2::9"))
        assert out in ipaddress.ip_network("2001:5::/32")
        assert out not in ipaddress.ip_network("2001:5:1::/56")
        with pytest.raises(IPMapError):
            mapper.map_address(_ip("2001:2::1"))


def test_lockin_crafted_preimages_of_ipv4_mapped_addresses_stay_out_of_the_mapped_block() -> None:
    """LOCK-IN (FXG-02 fix): for 6 keys, an IPv6 input that the chosen non-2000::/3 permutation
    sends *into* ::ffff:0:0/96 (built by inverting it) maps to a native IPv6 address, distinct
    from the pseudonym of the IPv4-mapped address it was aimed at. The refusal holds for
    deliberately aimed inputs, not just for random ones."""
    checked = 0
    for k in range(6):
        mapper = IPMapper(bytes([k + 90]) * 32, SITES)
        mapper.map_address(_ip("4000::1"))
        domain = mapper._domains[b"public6x"]
        for target_text in ("::ffff:9.9.9.9", "::ffff:8.8.4.4", "::ffff:203.0.112.5"):
            target = _ip(target_text)
            source = ipaddress.IPv6Address(_preimage(mapper, domain, 128, int(target)))
            if mapper.region(source) != "public" or source in _V6_GLOBAL or source in _MAPPED:
                continue
            assert mapper._permute(int(source), 128, 0, domain) == int(target)
            out = mapper.map_address(source)
            assert out not in _MAPPED, (k, source, out)
            assert out != mapper.map_address(target)
            checked += 1
    assert checked >= 12


# Revised at the R2 gate: CPU time of this process, not wall time on a shared machine.
def test_lockin_first_use_cost_is_bounded_under_many_keys() -> None:
    """LOCK-IN: building a mapper and the first mapping in each walk (public IPv4, both public
    IPv6 walks, ULA, a special block, a special /24 holding a site) stays under 5 s per key for
    16 keys (measured: median well under 0.1 s; the IPv6 domain choice has a heavy tail, p99
    about 0.6 s and up to 2 s in 4,000 domains, far above D-042's "about 30 ms" but far below the
    2,000,000-node search budget)."""
    probes = [
        _ip(t)
        for t in ("8.8.8.8", "2a00:1450::1", "4000::1", "fd00::1", "2001:db8::1", "192.0.2.200")
    ]
    worst = 0.0
    for k in range(16):
        start = time.process_time()
        mapper = IPMapper((k + 1000).to_bytes(4, "big") * 8, (*SITES, "192.0.2.0/26"))
        for probe in probes:
            mapper.map_address(probe)
        worst = max(worst, time.process_time() - start)
    assert worst < 5, f"worst first use {worst:.2f} s"


_CHILD = """
import json, sys
from argus.fixtures.ipmap import IPMapper
from argus.fixtures.tokens import DomainMapper, Tokenizer
ips, ids, names = json.loads(sys.argv[1])
key = b"k" * 32
mapper = IPMapper(key, ["192.0.2.0/26", "2001:db8:1::/48", "203.0.112.0/22"])
tokens = Tokenizer(key)
domains = DomainMapper(tokens, ["campus.ac.in", "\\u0906\\u0908.example"], ["amazonaws.com"])
print(json.dumps([[mapper.map_text(i) for i in ips], [tokens.opaque_id(i) for i in ids],
                  [domains.map(n) for n in names]]))
"""


def test_lockin_round2_paths_do_not_depend_on_order_seed_or_instance() -> None:
    """LOCK-IN: the round-2 paths (a special /24 and an IPv6 special block holding sites, the
    IETF pieces, ids of every class, IDN and campus domains) give the same pseudonyms in a fresh
    mapper fed in shuffled order and in two interpreters with different PYTHONHASHSEED values."""
    ips = [
        "192.0.2.77", "192.0.2.200", "2001:db8:2::5", "2001:db8:1::5", "2001:0:4136::1",
        "2001:4:112::1", "8.8.8.8", "10.1.2.3", "203.0.112.9", "4000::1",
    ]  # fmt: skip
    ids = ["7", "0f", "1D", "aZ-_", "SyntheticAlertId0001", "a" * 40, "evt.4711"]
    names = ["www.campus.ac.in", "x.आई.example", "bücher.example-shop.de", "a.b.c.de"]
    first = IPMapper(KEY, ["192.0.2.0/26", "2001:db8:1::/48", "203.0.112.0/22"])
    expected_ips = [first.map_text(i) for i in ips]
    expected = [expected_ips, [TOKENS.opaque_id(i) for i in ids]]
    domains = DomainMapper(TOKENS, ["campus.ac.in", "आई.example"], ["amazonaws.com"])
    expected.append([domains.map(n) for n in names])
    shuffled = ips[:]
    random.Random(3).shuffle(shuffled)
    second = IPMapper(KEY, ["203.0.112.0/22", "2001:db8:1::/48", "192.0.2.0/26"])
    again = {i: second.map_text(i) for i in shuffled}
    assert [again[i] for i in ips] == expected_ips
    for seed in ("0", "977"):
        completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed inline script
            [sys.executable, "-c", _CHILD, json.dumps([ips, ids, names])],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
            timeout=60,
        )
        assert json.loads(completed.stdout) == expected, seed


# ================================================================== LOCK-INS: tokens


@pytest.mark.parametrize(
    ("alphabet", "length"),
    [
        (string.digits, 1),
        (string.digits, 2),
        (string.digits, 3),
        (HEX_LOWER, 1),
        (HEX_LOWER, 3),
        (HEX_UPPER, 3),
        (_B64URL_DIGITS, 1),
        (_B64URL_DIGITS, 2),
    ],
    ids=["dec-1", "dec-2", "dec-3", "hex-1", "hex-3", "HEX-3", "b64-1", "b64-2"],
)
def test_lockin_ids_are_a_fixed_point_free_bijection_per_class(alphabet: str, length: int) -> None:
    """LOCK-IN (exhaustive): over every string of one alphabet and length (so every class that
    occurs in it: decimal, hex, HEX, other base64url), ``opaque_id`` maps each class onto itself
    one to one and moves every id: the class walk on the single cycle ``D`` is correct, whatever
    alphabet an id was routed to."""
    values = ["".join(p) for p in itertools.product(alphabet, repeat=length)]
    by_class: dict[int, list[tuple[str, str]]] = {}
    for value in values:
        by_class.setdefault(_id_class(value), []).append((value, TOKENS.opaque_id(value)))
    for cls, pairs in by_class.items():
        assert sorted(v for v, _ in pairs) == sorted(o for _, o in pairs), cls
        assert all(v != o for v, o in pairs), cls


def test_lockin_feistel_inverse_and_single_cycle() -> None:
    """LOCK-IN: the inverse Feistel network undoes the forward one at every even width used
    (4 to 128 bits); the inverse cycle walk undoes the forward one on [0, N); and
    ``D = F⁻¹ ∘ (+1) ∘ F`` is one cycle through all N strings for decimal ids of 1 to 3 digits
    and hex ids of 2 characters (so every class walk ends)."""
    rng = random.Random(5)
    tweak = b"probe"
    for bits in (4, 6, 8, 20, 64, 120, 126, 128):
        for _ in range(50):
            v = rng.getrandbits(bits)
            fwd = TOKENS._feistel(v, bits, tweak)
            assert fwd < 1 << bits
            assert TOKENS._feistel(fwd, bits, tweak, inverse=True) == v
    for size, bits in ((10, 4), (100, 8), (1000, 10), (256, 8)):
        for v in range(size):
            fwd = TOKENS._cycle_walk(v, size, bits, tweak, inverse=False)
            assert fwd < size
            assert TOKENS._cycle_walk(fwd, size, bits, tweak, inverse=True) == v
        start, cur, steps = 0, 0, 0
        while True:
            fwd = TOKENS._cycle_walk(cur, size, bits, tweak, inverse=False)
            cur = TOKENS._cycle_walk((fwd + 1) % size, size, bits, tweak, inverse=True)
            steps += 1
            if cur == start:
                break
        assert steps == size


def test_lockin_class_walks_are_short_and_fast() -> None:
    """LOCK-IN: over every 1- and 2-character base64url id the class walk takes at most 12
    cycle-walk calls (6 steps of ``D``; the sparse classes are 2-character hex and HEX); for
    300 random 20-character base64url, 38-digit decimal and 32-hex ids it takes exactly one step;
    the image keeps length and class; 2,000 Elasticsearch-shaped ids take well under a second
    (measured about 50 µs each)."""
    calls = 0
    tokenizer = Tokenizer(KEY)
    original = tokenizer._cycle_walk

    def counting(*args: object, **kwargs: object) -> int:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)  # type: ignore[arg-type]

    tokenizer._cycle_walk = counting  # type: ignore[method-assign]

    def walk_cost(value: str) -> int:
        nonlocal calls
        calls = 0
        out = tokenizer.opaque_id(value)
        assert len(out) == len(value)
        assert _id_class(out) == _id_class(value)
        return calls

    short = ["".join(p) for n in (1, 2) for p in itertools.product(_B64URL_DIGITS, repeat=n)]
    assert max(walk_cost(v) for v in short) <= 12
    rng = random.Random(9)
    for alphabet, length in ((_B64URL_DIGITS, 20), (string.digits, 38), (HEX_LOWER, 32)):
        values = ["".join(rng.choice(alphabet) for _ in range(length)) for _ in range(300)]
        assert max(walk_cost(v) for v in values) == 2, (alphabet[:5], length)
    start = time.perf_counter()
    for _ in range(2000):
        TOKENS.opaque_id("".join(rng.choice(_B64URL_DIGITS) for _ in range(20)))
    assert time.perf_counter() - start < 2


_LABEL_CHARS = st.sampled_from(
    [
        *"aZ09-_\u00e9\u00c9\u0301\u00df\u0130\u212a\u03a3\u03c3\u3002\uff0e\uff61",
        "xn--",
        "b\u00fccher",
    ]
)


@settings(deadline=None)
@given(st.lists(_LABEL_CHARS, max_size=10).map("".join))
def test_lockin_normalize_domain_is_idempotent_without_whitespace(domain: str) -> None:
    """LOCK-IN: without whitespace, ``normalize_domain`` is idempotent and agrees for NFC and NFD
    spellings and for the three Unicode full stops (FXI-05 is about whitespace only)."""
    once = normalize_domain(domain)
    assert normalize_domain(once) == once
    assert normalize_domain(unicodedata.normalize("NFD", domain)) == once
    assert normalize_domain(re.sub("[。．｡]", ".", domain)) == once  # noqa: RUF001


@settings(deadline=None)
@given(st.text(alphabet=string.ascii_letters + string.digits + "-", max_size=40))
def test_lockin_unpuny_and_is_sensitive_never_raise(tail: str) -> None:
    """LOCK-IN: ``_unpuny`` and ``_is_sensitive`` accept any ``xn--`` label (invalid punycode,
    huge code points, decoded lone surrogates) without raising."""
    _unpuny(f"xn--{tail}.xn--{tail[::-1]}")
    _DOMAINS._is_sensitive(f"xn--{tail}.s3")
    _DOMAINS.map(f"xn--{tail}.s3.amazonaws.com")


def test_lockin_shipped_policy_keeps_real_suffixes_and_hides_campus_variants() -> None:
    """LOCK-IN: under the shipped ``config/fixtures.yaml``, with an organisation's domain and name
    laid over it as its private overlay would (D-294; the adversarial tests' ``campus.ac.in``), no
    real public suffix counts as sensitive (every multi-label suffix and 28 common TLDs are
    kept), while the campus name in a kept head, in dashes, dots, upper case or punycode, or as
    the last label, is tokenized."""
    shipped, _ = load_policy(REPO / "config" / "fixtures.yaml")
    overlay = {"campus_domains": ["campus.ac.in"], "literals": {"Campus University": "UNIV"}}
    policy = FixturePolicy.model_validate({**shipped.model_dump(), **overlay})
    mapper = DomainMapper(
        TOKENS,
        policy.campus_domains,
        policy.keep_domains,
        policy.campus_replacement,
        sensitive_terms=policy.literals,
    )
    tlds = [
        "com", "net", "org", "edu", "gov", "in", "uk", "de", "fr", "jp", "cn", "ru", "br", "au",
        "io", "co", "ai", "app", "dev", "xyz", "info", "biz", "me", "tv", "us", "ca", "nl", "se",
    ]  # fmt: skip
    for suffix in [*sorted(MULTI_LABEL_SUFFIXES), *tlds]:
        assert mapper.map(f"shop.{suffix}").endswith(f".{suffix}"), suffix
    campus_label = policy.campus_domains[0].split(".")[0]
    for name in (
        f"{campus_label}-backups.s3.amazonaws.com",
        f"{campus_label.upper()}.backups.s3.amazonaws.com",
        f"{'.'.join(campus_label)}.s3.amazonaws.com",
        f"printer.{campus_label}",
        f"x.{policy.campus_domains[0]}.cdn.github.com",
    ):
        out = mapper.map(name)
        assert campus_label not in _decoded(out).replace(".", "").replace("-", ""), (name, out)


def test_lockin_campus_aliases_follow_policy_order() -> None:
    """LOCK-IN: three campus domains map to ``univ.example``, ``c2.`` and ``c3.`` in policy
    order whatever their length, and a repeat in another case or with trailing dots does not
    take a number."""
    campus = ["zz.example.org", "EXAMPLE.EDU.", "a-much-longer-campus.example.net", "example.edu"]
    mapper = DomainMapper(TOKENS, campus, [])
    assert mapper.map("x.zz.example.org").endswith(".univ.example")
    assert mapper.map("x.example.edu").endswith(".c2.univ.example")
    assert mapper.map("x.a-much-longer-campus.example.net").endswith(".c3.univ.example")
    assert mapper.map("example.edu") == "c2.univ.example"


@pytest.mark.parametrize(
    "data",
    [
        {"campus_domains": ("Campus.AC.IN.",), "keep_domains": ("WWW.CAMPUS.AC.IN",)},
        {"campus_domains": ("campus.ac.in",), "keep_domains": ("campus。ac。in",)},
        {"campus_domains": ("campus.ac.in",), "campus_replacement": "u.CAMPUS.AC.IN."},
        {"keep_domains": ("github.com",), "literals": {"GitHub.COM.": "vendor"}},
        {"campus_domains": ("campusu.ac.in",), "keep_domains": ("cdn-Campus_U.example.com",)},
        {"literals": {"Campus University": "U"}, "keep_domains": ("campus-university.net",)},
        {"campus_domains": ("bücher.de",), "keep_domains": ("xn--bcher-kva.de",)},
    ],
)
def test_lockin_policy_refusals_hold_across_spellings(data: dict[str, object]) -> None:
    """LOCK-IN: the round-2 load-time refusals (keep domain over a campus domain, replacement
    inside a campus domain, a literal that is a kept domain, a keep domain holding a campus or
    literal term) hold for upper case, trailing and Unicode dots, ``-``/``_`` separators and
    Unicode-versus-punycode spellings."""
    with pytest.raises(ValueError):  # noqa: PT011 - pydantic wraps the ValueError
        FixturePolicy.model_validate(data)


@pytest.mark.parametrize(
    "prefixes",
    [
        ("203.0.112.1/22",),
        ("10.20.0.0/16",),
        ("169.254.1.0/24",),
        ("198.19.0.0/24",),
        ("::ffff:203.0.112.0/118",),
        ("203.0.112.0/22", "203.0.113.0/24"),
        ("100.0.0.0/16", "101.0.0.0/16", "102.0.0.0/24"),
        ("2001:db8::/40",),
        ("fd00:1::/48",),
        ("not-a-prefix",),
    ],
)
def test_lockin_site_prefixes_are_validated_at_load(prefixes: tuple[str, ...]) -> None:
    """LOCK-IN (FXG-12 fix): host bits, class/keep overlaps, the site space, IPv4-mapped
    prefixes, overlapping sites, an exhausted IPv4 site space, an IPv6 prefix larger than the
    /48 site space and garbage are refused when the policy is loaded; the shipped prefix is
    accepted. (An IPv6 campus allocation shorter than /48 can therefore never be a site: it
    fails closed at load.)"""
    with pytest.raises(ValueError):  # noqa: PT011 - IPMapError or pydantic's ValidationError
        FixturePolicy(site_prefixes=prefixes)
    assert FixturePolicy(site_prefixes=SITES).site_prefixes == SITES
