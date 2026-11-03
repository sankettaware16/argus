"""The search behind the IP map's re-keying, checked exactly on small widths (fast: these run
first in mutation testing, before any full-width search; all values synthetic)."""

from __future__ import annotations

import random

import pytest

from argus.fixtures import ipmap as ipmap_module
from argus.fixtures.ipmap import IPMapper, _cover

KEY = b"k" * 32


def test_permutation_known_answers() -> None:
    """``_permute`` flips bit i of the input when the keyed PRF of its first i bits says so."""
    mapper = IPMapper(KEY)
    assert [mapper._permute(v, 8, 0, b"perm-check") for v in (0, 1, 5, 200, 255)] == [
        63,
        62,
        57,
        199,
        241,
    ]
    # the first 4 bits (1010) are kept
    assert [mapper._permute(v, 8, 4, b"perm-check") for v in (0xA0, 0xA7, 0xAF)] == [170, 172, 164]
    prf = [mapper._prf_bit(b"perm-check", i, p, 8) for i, p in ((0, 0), (1, 1), (3, 5), (7, 100))]
    assert prf == [0, 0, 0, 1]
    assert mapper._permute(0x0A010203, 32, 0, b"public4|0") == 884335215


@pytest.mark.parametrize(
    ("prefix", "level", "refused", "cover"),
    [
        (0, 4, (), 1),  # nothing refused
        (0, 4, ((0, 255),), 0),  # everything refused
        (0, 4, ((0, 15),), 0),  # exactly the block 0-15
        (0, 3, ((0, 15),), 2),  # half of the block 0-31
        (0, 4, ((10, 10),), 2),  # one address inside
        (1, 4, ((10, 10),), 1),  # the block 16-31: none
        (0, 4, ((16, 16),), 1),  # the address just after the block
        (1, 4, ((16, 16),), 2),  # the block's first address
        (1, 4, ((15, 15),), 1),  # the address just before the block
        (1, 4, ((31, 31),), 2),  # the block's last address
        (1, 4, ((15, 16),), 2),  # a span over the block's start
        (1, 4, ((31, 32),), 2),  # a span over its end
        (1, 4, ((16, 31), (40, 50)), 0),  # one of several spans covers it
        (15, 4, ((0, 239),), 1),  # the last block, just after the span
    ],
)
def test_cover(prefix: int, level: int, refused: tuple[tuple[int, int], ...], cover: int) -> None:
    """0: every address of the block is refused; 1: none is; 2: some are (8-bit addresses)."""
    assert _cover(prefix, level, 8, refused) == cover


def _cycles(mapper: IPMapper, domain: bytes, bits: int, keep: int, start: int) -> list[list[int]]:
    lo = start << (bits - keep)
    perm = {v: mapper._permute(v, bits, keep, domain) for v in range(lo, lo + (1 << (bits - keep)))}
    seen: set[int] = set()
    cycles = []
    for value in perm:
        cycle = []
        while value not in seen:
            seen.add(value)
            cycle.append(value)
            value = perm[value]
        if cycle:
            cycles.append(sorted(cycle))
    return cycles


@pytest.mark.parametrize(("keep", "start"), [(0, 0), (4, 0b1010)])
def test_short_orbit_search_equals_brute_force(keep: int, start: int) -> None:
    """The orbit search behind re-keying (a walk must never come back to its input) finds
    exactly the short cycles of the permutation: checked against a full cycle decomposition of
    12-bit permutations."""
    mapper = IPMapper(KEY)
    for n in range(20):
        domain = b"orbit-check|" + str(n).encode()
        cycles = _cycles(mapper, domain, 12, keep, start)
        for size in (1, 2, 4, 8):
            found = mapper._short_orbits(domain, 12, keep, start, size)
            assert found is not None
            assert sorted(sorted(o) for o in found) == sorted(c for c in cycles if len(c) <= size)


@pytest.mark.parametrize(("keep", "start"), [(0, 0), (4, 0b1010)])
def test_lone_orbit_search_equals_brute_force(keep: int, start: int) -> None:
    """The exact search behind re-keying finds every orbit with exactly one accepted member and
    nothing else: checked against a full cycle decomposition of 12-bit permutations under random
    refused spans (small ones, large ones, ones that touch block borders by one address)."""
    mapper = IPMapper(KEY)
    rng = random.Random(12)
    lo = start << (12 - keep)
    hi = lo + (1 << (12 - keep)) - 1
    for n in range(40):
        domain = b"lone-check|" + str(n).encode()
        cycles = _cycles(mapper, domain, 12, keep, start)
        spans: list[tuple[int, int]] = []
        for _ in range(rng.randint(1, 6)):
            a = rng.randint(lo, hi)
            width = rng.choice([0, 1, 2, rng.randint(0, 64), rng.randint(0, hi - lo)])
            spans.append((a, min(hi, a + width)))
        refused = tuple(sorted(spans))

        def accepted(value: int, refused: tuple[tuple[int, int], ...] = refused) -> bool:
            return not any(a <= value <= b for a, b in refused)

        expected = sorted(c for c in cycles if sum(map(accepted, c)) == 1)
        found = mapper._lone_orbits(domain, 12, keep, start, refused)
        assert found is not None
        assert sorted(sorted(o) for o in found) == expected, (n, refused)


def test_pruning_keeps_the_lone_orbit_search_small(monkeypatch: pytest.MonkeyPatch) -> None:
    """Orbits with two wholly accepted members, or none, are not followed: a 16-bit space shaped
    like IPv4 (reserved blocks at the start, middle and end) needs 160 nodes (390 with a weaker
    pruning that waits for three accepted members). Without the
    pruning, orbits double level by level and a 32-bit search runs for minutes."""
    monkeypatch.setattr(ipmap_module, "_FIXED_POINT_SEARCH", 300)
    refused = ((0, 255), (0x7F00, 0x7FFF), (0xA000, 0xA0FF), (0xC000, 0xC00F), (0xE000, 0xFFFF))
    assert IPMapper(KEY)._lone_orbits(b"search-size|0", 16, 0, 0, refused) is not None
