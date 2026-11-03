"""Tests written for the mutants the R3 asset-map suite missed: exact limits as literals, exact
messages (they are the operator's only clue, and must never carry a value from the file),
immutability, and address parsing edges."""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest

from argus.assets import AssetMapError, parse_asset_map
from argus.assets.assetmap import parse_address

pytestmark = pytest.mark.unit

ONE = "networks:\n  - name: A\n    range: 10.0.0.0/8\n"


def refused(raw: bytes) -> str:
    with pytest.raises(AssetMapError) as info:
        parse_asset_map(raw)
    return str(info.value)


def test_size_limit_is_16_mib() -> None:
    # Bytes that are not UTF-8: the size check comes first, so the message tells which ran.
    assert refused(b"\xff" * (16 * 1024 * 1024)) == "the asset map is not UTF-8 text"
    assert refused(b"\xff" * (16 * 1024 * 1024 + 1)) == (
        "the asset map is larger than 16777216 bytes"
    )


def test_entry_limit_is_100_000() -> None:
    def zeros(count: int) -> bytes:
        return ("networks: [" + ",".join(["0"] * count) + "]\n").encode()

    assert refused(zeros(100_000)) == "entry #1 must be a mapping"
    assert refused(zeros(100_001)) == "more than 100000 entries"


@pytest.mark.parametrize(("lists", "deep"), [(6, False), (7, True)])
def test_yaml_depth_limit_is_8(lists: int, deep: bool) -> None:
    # root mapping, key, then the lists, then the scalar: lists + 2 levels.
    message = refused(("a: " + "[" * lists + "1" + "]" * lists + "\n").encode())
    assert (message == "the asset map is not valid YAML: nesting is too deep (line 1)") is deep


def test_depth_is_counted_per_branch() -> None:
    # Many shallow siblings before a branch at the limit: depth must come back down each time.
    siblings = "".join(f"  - [[[[[{i}]]]]]\n" for i in range(20))
    message = refused(f"a:\n{siblings}  - [[[[[1]]]]]\n".encode())
    assert message == "the asset map must be a mapping with 'defaults' and 'networks' only"


def test_messages() -> None:
    assert refused(b"a: 1\n") == (
        "the asset map must be a mapping with 'defaults' and 'networks' only"
    )
    assert refused(b"networks: []\n") == "'networks' must be a non-empty list"
    assert refused(b"networks:\n  - name: A\n    range: 10.0.0.0/8\n    other: 1\n") == (
        "entry #1: unknown keys (allowed: fields, name, range, ranges)"
    )
    assert refused(b"networks:\n  - &x {name: A}\n") == (
        "the asset map is not valid YAML: anchors and aliases are not allowed (line 2)"
    )
    assert refused(b"networks:\n  - name: A\n  - name: [unclosed\n") == (
        "the asset map is not valid YAML: invalid YAML (line 4)"
    )


def test_text_limit_is_256() -> None:
    name = "N" * 256
    assert parse_asset_map(ONE.replace("name: A", f"name: {name}").encode()).entries[0].name == (
        name
    )
    assert refused(ONE.replace("name: A", f"name: {name}N").encode()) == (
        "entry #1 name must be 1-256 printable characters"
    )


def test_range_limit_is_256_per_entry() -> None:
    def ranges(count: int) -> bytes:
        listed = ", ".join(f"10.0.{i // 256}.{i % 256}/32" for i in range(count))
        return f"networks:\n  - name: A\n    ranges: [{listed}]\n".encode()

    assert len(parse_asset_map(ranges(256)).entries[0].networks) == 256
    assert refused(ranges(257)) == "entry #1 has more than 256 ranges"


def test_entries_and_matches_are_frozen_with_slots() -> None:
    amap = parse_asset_map(ONE.encode())
    entry = amap.entries[0]
    match = amap.match("10.1.2.3")
    assert match is not None
    assert not hasattr(entry, "__dict__")
    assert not hasattr(match, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.name = "B"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        match.entries = ()  # type: ignore[misc]


def test_address_text_limit_is_64() -> None:
    scoped = "fe80::1%" + "x" * 56  # 64 characters
    assert parse_address(scoped) == ipaddress.IPv6Address("fe80::1")
    assert parse_address(scoped + "x") is None


def test_the_zone_is_dropped() -> None:
    parsed = parse_address("fe80::1%eth0")
    assert parsed == ipaddress.IPv6Address("fe80::1")
    assert str(parsed) == "fe80::1"
    assert str(parse_address("2001:db8::1")) == "2001:db8::1"
    assert parse_address("::ffff:10.0.0.1") == ipaddress.IPv4Address("10.0.0.1")


# --------------------------------------------------------------------------- classify


def test_classification_wire_values_and_immutability() -> None:
    from argus.assets.classify import AssetLookup, IpClass, IpClassifier

    assert [c.value for c in IpClass] == [
        "asset", "campus", "internal", "public", "special", "invalid",
    ]  # fmt: skip
    assert [c.value for c in AssetLookup] == ["matched", "not_found", "no_map", "not_applicable"]
    result = IpClassifier(None).classify("10.0.0.1")
    assert not hasattr(result, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.address = "x"  # type: ignore[misc]
