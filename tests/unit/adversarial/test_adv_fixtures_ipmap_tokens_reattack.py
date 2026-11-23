"""Adversarial re-attack on R2's IP map, tokens and policy after fix round 1 (D-041).

Lens FXG: break the rewritten ``argus.fixtures.ipmap`` (one set per walk, re-keying until no
fixed point, a fixed region table, site-space refusal), ``argus.fixtures.tokens`` (collision
errors, the keyed format-preserving permutation for ids, campus aliases, sensitive kept-domain
heads) and the load-time validation of ``argus.fixtures.policy``.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every address, prefix, name and key here is
synthetic (documentation, benchmarking and private ranges, ``*.example`` style names and the key
``b"k" * 32`` or a one-byte variant of it); nothing touches the network. The colliding and
crashing inputs below were found offline (by enumerating short cycles of the keyed permutation or
inverting it); they are written out so the DEFECT tests do not depend on the mapper's internals.
A few LOCK-INs compare private helpers with brute force on purpose.
"""

from __future__ import annotations

import ipaddress
import itertools
import random
import re
import string
import time
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.fixtures import ipmap
from argus.fixtures.ipmap import (
    CLASS_REGIONS,
    KEEP_REGIONS,
    SITE_SPACE_V4,
    SITE_SPACE_V6,
    SPECIAL_REGIONS,
    IPAddress,
    IPMapError,
    IPMapper,
    format_ip,
)
from argus.fixtures.policy import FixturePolicy, load_policy
from argus.fixtures.tokens import (
    _B64URL_DIGITS,
    MULTI_LABEL_SUFFIXES,
    DomainMapper,
    TokenCollisionError,
    Tokenizer,
)
from tests.conftest import cpu_limit

KEY = b"k" * 32
SITES = ("203.0.112.0/22",)  # one public /22, as on the real campus (synthetic here)
MAPPER = IPMapper(KEY, SITES)
TOKENS = Tokenizer(KEY)
V4_SPECIAL_24 = [n for n in SPECIAL_REGIONS if n.version == 4 and n.prefixlen == 24]
HEX_LOWER = string.digits + "abcdef"
HEX_UPPER = string.digits + "ABCDEF"
DEVANAGARI_LITERAL = "आईआईटी"  # a Unicode campus literal


def _common_prefix(a: int, b: int, bits: int) -> int:
    return bits - (a ^ b).bit_length()


# ================================================================== DEFECTS: IP map


def test_fxg01a_public_walk_returns_to_its_input_and_raises() -> None:
    """DEFECT FXG-01 (a): a valid public IPv4 address cannot be pseudonymized.

    ``_domain`` re-keys until the permutation P has no *fixed point* in the accepted set, but the
    map is the *cycle-walked* permutation W, and W also fixes x when x's P-cycle has exactly one
    accepted member. Under the synthetic key ``b"k" * 31 + b"\\x1e"`` P has the 2-cycle
    19.38.97.220 <-> 255.120.93.155: the partner is in 240.0.0.0/4 (keep), so the walk rejects it,
    comes back to 19.38.97.220 and raises "an address would be its own pseudonym". Such P-cycles
    (a fixed /k node, one flip, no growth below) exist for about one key in 20 (3 of 65 keys
    tried); the sanitizer does not catch IPMapError, so one such address aborts a run."""
    mapper = IPMapper(b"k" * 31 + b"\x1e", SITES)
    addr = ipaddress.IPv4Address("19.38.97.220")
    assert mapper.region(addr) == "public"
    try:
        out = mapper.map_address(addr)
    except IPMapError as exc:
        pytest.fail(f"a valid public address cannot be pseudonymized: {exc}")
    assert out != addr
    assert mapper.region(out) == "public"


@pytest.mark.parametrize(
    "text", ["192.88.99.124", "192.88.99.125", "192.88.99.126", "192.88.99.127"]
)
def test_fxg01b_site_inside_a_special_block_makes_the_class_walk_raise(text: str) -> None:
    """DEFECT FXG-01 (b): the same hole in a class walk. A site prefix may overlap a special block
    ("the site wins"); the block's walk then skips site members. Under ``b"k" * 32`` with the
    synthetic site 192.88.99.0/26, P on 192.88.99.0/24 has the 2-cycle 192.88.99.124 <->
    192.88.99.10 (a site member), so these four addresses raise instead of mapping. For the
    class domain ``_domain`` passes ``member=lambda _: True``, i.e. it only ever looks at P."""
    mapper = IPMapper(KEY, ["192.88.99.0/26"])
    addr = ipaddress.IPv4Address(text)
    block, site = ipaddress.ip_network("192.88.99.0/24"), ipaddress.ip_network("192.88.99.0/26")
    try:
        out = mapper.map_address(addr)
    except IPMapError as exc:
        pytest.fail(f"{addr} (in {block}, outside the site {site}) cannot be mapped: {exc}")
    assert out in block
    assert out not in site
    assert out != addr


def test_fxg02_ipv6_outside_2000_3_can_take_an_ipv4_mapped_pseudonym() -> None:
    """DEFECT FXG-02: two originals, one pseudonym. The walk for public IPv6 outside 2000::/3
    accepts any candidate whose ``region()`` is ``public``, and ``region()`` unwraps
    ``::ffff:a.b.c.d`` to its IPv4 address. So a candidate inside ::ffff:0:0/96 holding a public
    IPv4 is accepted, although IPv4-mapped inputs never enter this walk (``map_address`` sends
    them to the IPv4 map): the walk stops on a larger set than it starts from. Inverting the keyed
    permutation gives ``c71d:3fff:c287:fd65:1256:7019:1fec:a6fb`` -> ``::ffff:9.9.9.0``, and
    ``::ffff:53.44.93.247`` -> ``::ffff:`` + map(53.44.93.247) = ``::ffff:9.9.9.0`` too. A
    random input lands there with probability 2**-96, but the one-to-one claim is false."""
    a = ipaddress.IPv6Address("c71d:3fff:c287:fd65:1256:7019:1fec:a6fb")
    b = ipaddress.IPv6Address("::ffff:53.44.93.247")
    fa, fb = MAPPER.map_address(a), MAPPER.map_address(b)
    assert fa != fb, f"{a} and {format_ip(b)} both map to {format_ip(fa)}"
    mapped_space = ipaddress.ip_network("::ffff:0:0/96")
    assert fa not in mapped_space, "a native IPv6 input became an IPv4-mapped address"


def test_fxg03_teredo_does_not_keep_its_leading_bits() -> None:
    """DEFECT FXG-03: the module docstring promises that special-purpose blocks "(documentation,
    6to4, NAT64, Teredo, ...) keep their leading bits", but Teredo 2001::/32 is not in the table
    on its own: it is part of the piece 2001::/31 cut from 2001::/23, so bit 31 is permuted and,
    for about half of all keys, every Teredo address leaves Teredo. Under ``b"k" * 31 + b"\\x00"``
    the Windows Teredo address below maps to 2001:1:84d:59:... (not Teredo). The same holds for
    the other IANA sub-blocks merged into the pieces (ORCHIDv2 2001:20::/28 maps into
    2001:30::/28 under ``b"k" * 32``; AS112-v6 2001:4:112::/48)."""
    mapper = IPMapper(b"k" * 31 + b"\x00", SITES)
    addr = ipaddress.IPv6Address("2001:0:4136:e378:8000:63bf:3fff:fdd2")
    out = mapper.map_address(addr)
    assert out in ipaddress.ip_network("2001::/32"), f"Teredo {addr} -> {out}"


def test_fxg12b_an_ipv4_mapped_site_prefix_is_accepted_and_silently_ignored() -> None:
    """DEFECT FXG-12 (b): a site prefix written in IPv4-mapped form (``::ffff:203.0.112.0/118``,
    as some exporters print it) passes every check and is allocated 2001:2::/118, but
    ``region()`` unwraps every address to IPv4 first, so no address ever matches it: the campus
    address 203.0.112.5 (and ``::ffff:203.0.112.5``) goes through the public walk to an
    arbitrary public address instead of the site space. Refusing the prefix, or normalizing it to
    its IPv4 form, are both correct."""
    try:
        mapper = IPMapper(KEY, ["::ffff:203.0.112.0/118"])
    except IPMapError:
        return
    for text in ("203.0.112.5", "::ffff:203.0.112.5"):
        addr = ipaddress.ip_address(text)
        assert mapper.region(addr).startswith("site:"), (text, mapper.region(addr))


# ================================================================== DEFECTS: tokens


@pytest.mark.parametrize(("first", "second"), [("0f", "11"), ("00a", "328"), ("1D", "21")])
def test_fxg04_opaque_ids_of_different_alphabets_collide(first: str, second: str) -> None:
    """DEFECT FXG-04: ``opaque_id`` routes an id to the first alphabet that matches it (decimal,
    lower hex, upper hex, base64url) and permutes *all* strings of that alphabet and length. The
    hex permutation is only fed ids with a letter, but its image covers the all-digit strings
    too, which are exactly the decimal permutation's image: ``0f`` (hex) and ``11`` (decimal) both
    become ``99``; ``00a`` and ``328`` both become ``820``; ``1D`` and ``21`` both become ``51``.
    Nothing tracks ids, so no TokenCollisionError is raised: the merge is silent. (20-character
    Elasticsearch ``_id``s and UUIDs are practically safe; short event ids are not.)"""
    a, b = TOKENS.opaque_id(first), TOKENS.opaque_id(second)
    assert a != b, f"{first!r} and {second!r} both become {a!r}"


def test_fxg04_every_two_character_id_gets_its_own_pseudonym() -> None:
    """DEFECT FXG-04 (exhaustive): the 4,096 two-character base64url strings (which include every
    two-character decimal and hex id) get only 3,714 distinct pseudonyms: 382 collisions."""
    values = ["".join(p) for p in itertools.product(_B64URL_DIGITS, repeat=2)]
    outs = {TOKENS.opaque_id(v) for v in values}
    assert len(outs) == len(values), f"{len(values) - len(outs)} collisions"


@pytest.mark.parametrize("value", ["3", "38", "74", "870"])
def test_fxg05_an_id_can_be_its_own_pseudonym(value: str) -> None:
    """DEFECT FXG-05: the id permutation is not re-keyed against fixed points (the IP map is), so
    the original id survives verbatim. A keyed permutation has one fixed point per (alphabet,
    length) on average, so short ids hit this for almost every key: under ``b"k" * 32`` the
    decimal ids ``3``, ``38``, ``74`` and ``870`` map to themselves. The scanner then reports an
    "ambiguous" identifier whose only remedy is a new key."""
    assert TOKENS.opaque_id(value) != value


_DOMAINS = DomainMapper(TOKENS, ["campus.ac.in"], ["amazonaws.com", "github.com"])


@pytest.mark.parametrize(
    ("first", "second", "same"),
    [
        ("straße.de", "xn--strae-oqa.de", True),  # one domain: its Unicode and DNS forms
        ("straße.de", "strasse.de", False),  # two different registrable domains
        ("www.campus.ac.in。", "www.campus.ac.in", True),  # ideographic full stop
    ],
    ids=["unicode-vs-its-punycode", "eszett-vs-ss", "trailing-ideographic-dot"],
)
def test_fxg06_idn_normalisation_splits_and_merges_domains(
    first: str, second: str, same: bool
) -> None:
    """DEFECT FXG-06: ``DomainMapper.map`` uses Python's ``idna`` codec, which is IDNA 2003: it
    maps ``ß`` to ``ss``. So ``straße.de`` (the URL a user typed) gets the pseudonym of
    the different domain ``strasse.de``, while its real DNS form ``xn--strae-oqa.de`` (in
    ``dns.question.name``) gets another one. ``_norm`` also strips only ASCII trailing dots before
    encoding, so ``www.campus.ac.in。`` is not recognised as campus at all: every label is
    tokenized, the trailing dot is kept, and the pseudonym differs from ``www.campus.ac.in``'s."""
    a, b = _DOMAINS.map(first), _DOMAINS.map(second)
    assert (a == b) is same, (first, a, second, b)


@pytest.mark.parametrize("domain", ["printer.campus", "srv.campusuniversity", "gw.campus-alt"])
def test_fxg07_a_campus_term_as_the_last_label_survives(domain: str) -> None:
    """DEFECT FXG-07: a domain that is neither campus nor kept keeps its last label verbatim as the
    "public suffix", whatever it is. Internal names with a campus pseudo-TLD therefore keep the
    campus term: ``printer.campus`` -> ``x6lcan64.campus``, ``srv.campusuniversity`` ->
    ``gk6fzp2d.campusuniversity``. ``_is_sensitive`` is applied to kept-domain heads only. (With
    the real policy the scanner flags the literal afterwards, so the run fails closed.)"""
    mapper = DomainMapper(
        TOKENS, ["campus.ac.in", "campus-alt.org"], [], sensitive_terms=["Campus University"]
    )
    out = mapper.map(domain)
    assert "campus" not in out, f"{domain} -> {out}"


def test_fxg08a_a_unicode_literal_survives_in_punycode_in_a_kept_domain() -> None:
    """DEFECT FXG-08 (a): ``_squash`` keeps only ``[0-9a-z]``, so a Unicode literal squashes to
    nothing and is dropped from the sensitive terms; and the head is checked in its punycode form
    anyway. ``<literal>-backups.s3.amazonaws.com`` is kept verbatim as
    ``xn---backups-dbqavb31a1p.s3.amazonaws.com``, which decodes straight back to the literal.
    The scanner compares the Unicode literal and does not decode punycode: a silent leak."""
    mapper = DomainMapper(
        TOKENS, ["campus.ac.in"], ["amazonaws.com"], sensitive_terms=[DEVANAGARI_LITERAL]
    )
    out = mapper.map(f"{DEVANAGARI_LITERAL}-backups.s3.amazonaws.com")
    decoded = out.encode("ascii").decode("idna")
    assert DEVANAGARI_LITERAL not in decoded, f"{out} decodes to {decoded}"


def test_fxg08b_a_short_campus_label_with_dashes_survives_in_a_kept_domain() -> None:
    """DEFECT FXG-08 (b): sensitive terms are the squashed literals and the campus *first labels*
    of 3+ characters. For a campus domain with a 2-letter first label (``cu.ac.in``) there is no
    term, so ``cu-ac-in.s3.amazonaws.com`` (the campus domain with dashes, a common bucket name)
    is kept verbatim; only the dotted form ``cu.ac.in.`` is caught. The squashed whole campus
    domain (``cuacin``) would be a safe term."""
    mapper = DomainMapper(TOKENS, ["cu.ac.in"], ["amazonaws.com"])
    domain = "cu-ac-in.s3.amazonaws.com"
    assert mapper.map(domain) != domain


# ================================================================== DEFECTS: policy


@pytest.mark.parametrize("replacement", ["ac.in", "co.uk", ""])
def test_fxg09_campus_replacement_is_not_validated(replacement: str) -> None:
    """DEFECT FXG-09: only "inside a campus domain" is refused. A replacement that is a public
    suffix makes campus pseudonyms collide with the pseudonyms of real non-campus domains: with
    ``own_replacement: ac.in``, ``foo.a.ac.in`` (campus) and ``foo.ac.in`` (another
    university) both become ``vicsqzx5.ac.in``. An empty replacement maps the campus domain
    itself to the empty string. The replacement should be a non-empty name under a reserved TLD
    (``.example``, ``.invalid``, ``.test``)."""
    with pytest.raises(ValueError, match="own_replacement"):
        FixturePolicy(own_domains=("a.ac.in",), own_replacement=replacement)


@pytest.mark.parametrize(
    "data",
    [
        {"own_domains": ("campus.ac.in",), "keep_names": ("root", "campus")},
        {"literals": {"CampusU": "Univ"}, "keep_names": ("root", "campusu")},
        {"own_domains": ("campus.ac.in",), "keep_domains": ("campus-cdn.com",)},
        {"literals": {"CampusU": "Univ"}, "keep_domains": ("campusu-cdn.net",)},
        {"keep_domains": ("github.com",), "literals": {"github.com": "vendor"}},
    ],
    ids=[
        "keep-name-is-campus-label",
        "keep-name-is-literal",
        "keep-domain-holds-campus-term",
        "keep-domain-holds-literal",
        "literal-is-keep-domain",
    ],
)
def test_fxg10_contradictory_keep_lists_are_accepted(data: dict[str, object]) -> None:
    """DEFECT FXG-10: the keep lists are not checked against the campus names and literals. With
    ``keep_names: [campus]`` the sanitizer writes ``host.name: campus`` verbatim; with
    ``keep_domains: [campus-cdn.com]`` it keeps ``img.campus-cdn.com`` verbatim (a kept domain
    is only checked for sensitive terms in its *head*); with a literal ``github.com`` the free
    text says ``vendor`` while ``url.domain`` keeps ``github.com``. The scanner then flags every
    run, or (for terms that are not literals) nothing does."""
    with pytest.raises(ValueError):  # noqa: PT011 - any load-time refusal is the fix
        FixturePolicy.model_validate(data)


@pytest.mark.parametrize(
    "fields",
    [{"host": ("*.name",), "user": ("*.name",)}, {"host": ("*",)}],
    ids=["one-pattern-two-kinds", "match-everything"],
)
def test_fxg11_field_patterns_are_not_validated(fields: dict[str, tuple[str, ...]]) -> None:
    """DEFECT FXG-11: an exact path under two kinds is refused (FXD-13), but the same *pattern*
    under two kinds is accepted and silently resolved by policy order (``x.name`` is a host).
    A bare ``*`` is accepted too: every field, ``@timestamp`` and ``message`` included, becomes a
    host name."""
    with pytest.raises(ValueError):  # noqa: PT011 - any load-time refusal is the fix
        FixturePolicy(fields=fields)


@pytest.mark.parametrize(
    "prefix", ["not-a-network", "203.0.112.1/22", "10.1.0.0/16", "198.18.0.0/24"]
)
def test_fxg12a_site_prefixes_are_not_validated_at_load(prefix: str) -> None:
    """DEFECT FXG-12 (a): ``load_policy`` promises load-time validation, but ``site_prefixes`` are
    plain strings there: garbage, a prefix with host bits, one inside a class region and one
    inside the site space are all accepted, and fail only later, when ``IPMapper`` is built."""
    with pytest.raises(IPMapError):
        IPMapper(KEY, [prefix])  # the mapper refuses it ...
    with pytest.raises(ValueError):  # noqa: PT011 - ... the policy should refuse it at load
        FixturePolicy(site_prefixes=(prefix,))


# ================================================================== LOCK-INS: IP map


def test_lockin_fixed_point_search_matches_brute_force() -> None:
    """LOCK-IN (exhaustive): ``_fixed_points`` returns exactly the brute-force fixed points, for
    the class domains of every IPv4 special /24 (eight re-key counters each) and for 32 synthetic
    12-bit domains with nothing kept. At least some of the domains do have fixed points, so the
    comparison is not vacuous."""
    mapper = IPMapper(KEY, SITES)
    nonempty = 0
    for block in V4_SPECIAL_24:
        lo = int(block.network_address)
        base = b"class|" + block.network_address.packed + bytes([block.prefixlen])
        for counter in range(8):
            domain = base + b"|" + str(counter).encode()
            found = mapper._fixed_points(domain, 32, 24, lo >> 8)
            brute = [v for v in range(lo, lo + 256) if mapper._permute(v, 32, 24, domain) == v]
            assert found is not None
            assert sorted(found) == brute, (block, counter)
            nonempty += bool(brute)
    for n in range(32):
        domain = b"probe|" + str(n).encode()
        found = mapper._fixed_points(domain, 12, 0, 0)
        brute = [v for v in range(4096) if mapper._permute(v, 12, 0, domain) == v]
        assert found is not None
        assert sorted(found) == brute, n
        nonempty += bool(brute)
    assert nonempty >= 5


@pytest.mark.parametrize("block", V4_SPECIAL_24, ids=str)
def test_lockin_special_blocks_are_exhaustively_one_to_one(block: ipaddress.IPv4Network) -> None:
    """LOCK-IN (exhaustive): every IPv4 special /24 without a site in it maps onto itself one to
    one, fixes no address, and keeps the exact common-prefix length of all 32,640 pairs."""
    mapper = IPMapper(KEY, ())
    src = [int(a) for a in block]
    out = [int(mapper.map_address(a)) for a in block]
    assert sorted(out) == src
    assert all(s != o for s, o in zip(src, out, strict=True))
    for i in range(len(src)):
        for j in range(i + 1, len(src)):
            assert _common_prefix(src[i], src[j], 32) == _common_prefix(out[i], out[j], 32)


def test_lockin_site_inside_a_special_block_never_collides_and_refuses_networks() -> None:
    """LOCK-IN (exhaustive): with the site 192.88.99.0/26 inside 192.88.99.0/24, every address of
    the rest of the block that maps (all but FXG-01's four) lands in the block, outside the site,
    on a distinct image different from itself; and ``map_network`` refuses the block and its
    sub-networks (membership could not be kept)."""
    mapper = IPMapper(KEY, ["192.88.99.0/26"])
    block, site = ipaddress.ip_network("192.88.99.0/24"), ipaddress.ip_network("192.88.99.0/26")
    site_images = {mapper.map_address(a) for a in site}
    images: dict[IPAddress, IPAddress] = {}
    for addr in block:
        if addr in site:
            continue
        try:
            images[addr] = mapper.map_address(addr)
        except IPMapError:
            continue  # FXG-01 (b): a returning walk; a fix may map these too
    assert len(images) >= 192 - 4
    assert len(set(images.values())) == len(images)
    for addr, out in images.items():
        assert out in block
        assert out not in site
        assert out != addr
        assert out not in site_images
    for net in ("192.88.99.0/24", "192.88.99.128/25", "192.88.99.200/29"):
        with pytest.raises(IPMapError):
            mapper.map_network(ipaddress.ip_network(net))


def test_lockin_an_exhausted_fixed_point_search_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: when the fixed-point search runs out of budget it reports "unknown" (None), never
    "no fixed points"; with a budget of one node every re-key is rejected and the mapper raises
    instead of using a permutation it could not check."""
    monkeypatch.setattr(ipmap, "_FIXED_POINT_SEARCH", 1)
    mapper = IPMapper(KEY, SITES)
    for text in ("8.8.8.8", "10.1.2.3", "2a00:1450::1"):
        with pytest.raises(IPMapError, match="fixed-point-free"):
            mapper.map_address(ipaddress.ip_address(text))


def test_lockin_domain_choice_does_not_depend_on_order() -> None:
    """LOCK-IN: the re-keyed domain of every walk is a function of the key and the walk only:
    two fresh mappers fed the same addresses in opposite orders pick identical domains and give
    identical pseudonyms."""
    probes = [
        ipaddress.ip_address(t)
        for t in (
            "8.8.8.8",
            "10.1.2.3",
            "192.0.2.9",
            "2a00:1450::1",
            "4000::1",
            "fd00::1",
            "2001:db8::1",
            "2002:a01:203::1",
            "203.0.112.7",
            "::ffff:172.16.0.1",
        )
    ]
    a, b = IPMapper(KEY, SITES), IPMapper(KEY, SITES)
    out_a = {p: a.map_address(p) for p in probes}
    out_b = {p: b.map_address(p) for p in reversed(probes)}
    assert out_a == out_b
    assert a._domains == b._domains


def test_lockin_region_table_is_disjoint() -> None:
    """LOCK-IN: keep, class and special blocks and the two site spaces never overlap one another,
    so ``region()``'s answer does not depend on the order in which it tries them."""
    table = [*KEEP_REGIONS, *CLASS_REGIONS, *SPECIAL_REGIONS, SITE_SPACE_V4, SITE_SPACE_V6]
    for i, a in enumerate(table):
        for b in table[i + 1 :]:
            assert a.version != b.version or not a.overlaps(b), (a, b)


@pytest.mark.parametrize(
    "text", ["fd00::1%eth0", "2a00:1450::1%3", "::ffff:10.1.2.3%eth0", "2001:db8::5%lab-17"]
)
def test_lockin_scoped_forms_map_like_their_unscoped_address(text: str) -> None:
    """LOCK-IN: a zone id never changes or survives into the pseudonym, in any region."""
    out = MAPPER.map_text(text)
    assert out == MAPPER.map_text(text.split("%")[0])
    assert "%" not in out


# Revised at the R2 gate: CPU time of this process, not wall time on a shared machine, and a
# limit that allows for coverage tracing.
def test_lockin_mapping_many_addresses_is_fast() -> None:
    """LOCK-IN: building a mapper and mapping 50,000 random IPv4 and 10,000 random global IPv6
    addresses takes seconds, not minutes (measured 9 s of CPU on the dev machine)."""
    rng = random.Random(0)
    addrs: list[IPAddress] = [ipaddress.IPv4Address(rng.getrandbits(32)) for _ in range(50_000)]
    addrs += [ipaddress.IPv6Address((1 << 125) | rng.getrandbits(125)) for _ in range(10_000)]
    start = time.process_time()
    mapper = IPMapper(KEY, SITES)
    for addr in addrs:
        if mapper.region(addr).startswith("sitespace:"):
            continue
        mapper.map_address(addr)
    assert time.process_time() - start < cpu_limit(30)


# ================================================================== LOCK-INS: tokens


@pytest.mark.parametrize(
    ("alphabet", "length"),
    [(string.digits, 3), (HEX_LOWER, 2), (HEX_UPPER, 2), (_B64URL_DIGITS, 2), (string.digits, 1)],
    ids=["decimal-3", "hex-2", "HEX-2", "b64url-2", "decimal-1"],
)
def test_lockin_the_id_permutation_is_a_permutation_of_its_alphabet(
    alphabet: str, length: int
) -> None:
    """LOCK-IN (exhaustive): the keyed Feistel permutation maps the set of all strings of one
    alphabet and length onto itself one to one, leading zeros included."""
    values = ["".join(p) for p in itertools.product(alphabet, repeat=length)]
    outs = [TOKENS._permute_id(v, alphabet) for v in values]
    assert sorted(outs) == sorted(values)


_SHAPES = st.one_of(
    st.text(alphabet=string.digits, min_size=1, max_size=45),
    st.text(alphabet=HEX_LOWER, min_size=1, max_size=45),
    st.text(alphabet=HEX_UPPER, min_size=1, max_size=45),
    st.text(alphabet=_B64URL_DIGITS, min_size=1, max_size=30),
)


@given(_SHAPES)
def test_lockin_ids_keep_length_and_alphabet_across_the_128_bit_boundary(value: str) -> None:
    """LOCK-IN: below and above 128 bits (38/39 decimal digits, 32/33 hex, 21/22 base64url
    characters, where ``_stretch`` takes over), every id keeps its length and stays inside the
    alphabet it was routed to; the result is deterministic."""
    out = TOKENS.opaque_id(value)
    assert len(out) == len(value)
    if value.isdigit():
        assert out.isdigit()
    elif re.fullmatch(r"[0-9a-f]+", value):
        assert re.fullmatch(r"[0-9a-f]+", out)
    elif re.fullmatch(r"[0-9A-F]+", value):
        assert re.fullmatch(r"[0-9A-F]+", out)
    else:
        assert re.fullmatch(r"[A-Za-z0-9_-]+", out)
    assert out == Tokenizer(KEY).opaque_id(value)


def test_lockin_uuid_case_variants_and_braces_agree() -> None:
    """LOCK-IN: lower, upper, mixed-case and braced forms of one UUID share one pseudonym (upper
    case kept for an upper-case input, braces kept)."""
    lower = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
    base = TOKENS.opaque_id(lower)
    assert TOKENS.opaque_id(lower.upper()) == base.upper()
    assert TOKENS.opaque_id("0F8e7d6c-5b4A-4392-8170-6f5e4d3c2b1a") == base
    assert TOKENS.opaque_id("{" + lower.upper() + "}") == "{" + base.upper() + "}"
    assert TOKENS.opaque_id("{" + lower + "}") == "{" + base + "}"


def test_lockin_token_collisions_are_detected_and_never_false() -> None:
    """LOCK-IN: a real collision (forced with a 2-character token) raises TokenCollisionError;
    the same value twice, the same value under two kinds, label case variants and every label of
    a few thousand domain names never do."""
    tokenizer = Tokenizer(KEY)

    def issue_two_character_tokens() -> None:
        for n in range(2000):  # 1,024 possible tokens: a collision is certain
            tokenizer.token("probe", f"value-{n}", "", 2)

    with pytest.raises(TokenCollisionError):
        issue_two_character_tokens()
    fresh = Tokenizer(KEY)
    assert fresh.token("user", "alice", "u-") == fresh.token("user", "alice", "u-")
    fresh.token("org", "alice", "org-")
    mapper = DomainMapper(fresh, ["campus.ac.in"], ["amazonaws.com"])
    assert mapper.label("WWW") == mapper.label("www")
    for n in range(3000):
        mapper.map(f"Host-{n}.Lab{n % 7}.campus.ac.in")
        mapper.map(f"host-{n}.lab{n % 7}.campus.ac.in.")


def test_lockin_token_keys_are_length_prefixed() -> None:
    """LOCK-IN: ``K`` and ``K + b"\\0"`` (one key to HMAC) give different tokens and ids."""
    a, b = Tokenizer(KEY), Tokenizer(KEY + b"\x00")
    assert a.token("user", "alice", "u-") != b.token("user", "alice", "u-")
    assert a.opaque_id("SyntheticAlertId0001") != b.opaque_id("SyntheticAlertId0001")


def test_lockin_domain_forms_that_held_up() -> None:
    """LOCK-IN: Unicode and punycode spellings of a non-eszett IDN agree; case and ASCII trailing
    dots are ignored; campus aliases follow policy order, not length; a kept domain whose head
    carries a campus domain in another case, or a literal split across labels, is tokenized;
    multi-label public suffixes are kept."""
    mapper = DomainMapper(
        TOKENS,
        ["zz-a-very-long-campus-name.ac.in", "b.org"],
        ["amazonaws.com"],
        sensitive_terms=["Campus University"],
    )
    assert mapper.map("bücher.example-shop.de") == mapper.map("xn--bcher-kva.example-shop.de")
    assert mapper.map("WWW.B.ORG..") == mapper.map("www.b.org")
    assert mapper.map("x.b.org").endswith(".c2.univ.example")
    assert mapper.map("x.zz-a-very-long-campus-name.ac.in").endswith(".univ.example")
    assert not mapper.map("x.zz-a-very-long-campus-name.ac.in").endswith(".c2.univ.example")
    for kept in ("www.B.ORG.s3.amazonaws.com", "campus.university.s3.amazonaws.com"):
        out = mapper.map(kept)
        assert out.endswith(".amazonaws.com")
        assert out != kept.lower()
    assert mapper.map("cdn.s3.amazonaws.com") == "cdn.s3.amazonaws.com"
    for suffix in sorted(MULTI_LABEL_SUFFIXES):
        assert mapper.map(f"shop.{suffix}").endswith(f".{suffix}")


# ================================================================== LOCK-INS: policy


@pytest.mark.parametrize(
    "text",
    [
        "literals: {1: 2}\n",
        "fields: {host: host.name}\n",
        "fields: {host: [1]}\n",
        "site_prefixes: 10.0.0.0/8\n",
        "keep_names: root\n",
        "own_domains: campus.ac.in\n",
        "literals: {CampusU: null}\n",
        "keep_domains: [1.5]\n",
        "literals: {yes: no}\n",
        "own_replacement: 12\n",
    ],
)
def test_lockin_non_string_yaml_values_are_refused(text: str, tmp_path: Path) -> None:
    """LOCK-IN: YAML that is not the declared shape (numbers or booleans where strings are
    expected, a bare string where a list is expected, ``null``) is refused at load: pydantic v2
    does not coerce numbers to strings or strings to sequences."""
    path = tmp_path / "fixtures.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):  # noqa: PT011 - pydantic's ValidationError
        load_policy(path)
