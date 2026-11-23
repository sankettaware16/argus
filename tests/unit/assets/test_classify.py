"""IP classification: asset map first, then campus, private, special and public."""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assets import AssetLookup, IpClass, IpClassifier, parse_asset_map

pytestmark = pytest.mark.unit

MAP = parse_asset_map(
    b"networks:\n"
    b"  - {name: Hostel, range: 10.20.0.0/16}\n"
    b"  - {name: Egress, range: 198.51.100.8/29}\n"
    b"  - {name: Odd, range: 127.0.0.0/8}\n"
)
CAMPUS = (ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("2001:db8:5::/48"))
CLASSIFIER = IpClassifier(MAP, CAMPUS)


@pytest.mark.parametrize(
    ("address", "ip_class", "lookup"),
    [
        ("10.20.3.4", IpClass.ASSET, AssetLookup.MATCHED),
        ("198.51.100.9", IpClass.ASSET, AssetLookup.MATCHED),
        ("127.0.0.1", IpClass.ASSET, AssetLookup.MATCHED),  # the map wins over everything
        ("198.51.100.1", IpClass.OWN, AssetLookup.NOT_FOUND),
        ("2001:db8:5::1", IpClass.OWN, AssetLookup.NOT_FOUND),
        ("10.21.0.1", IpClass.INTERNAL, AssetLookup.NOT_FOUND),
        ("172.31.255.255", IpClass.INTERNAL, AssetLookup.NOT_FOUND),
        ("192.168.0.1", IpClass.INTERNAL, AssetLookup.NOT_FOUND),
        ("fd12::1", IpClass.INTERNAL, AssetLookup.NOT_FOUND),
        ("172.32.0.1", IpClass.PUBLIC, AssetLookup.NOT_FOUND),
        ("8.8.8.8", IpClass.PUBLIC, AssetLookup.NOT_FOUND),
        ("2606:4700::1", IpClass.PUBLIC, AssetLookup.NOT_FOUND),
        ("::ffff:8.8.8.8", IpClass.PUBLIC, AssetLookup.NOT_FOUND),
        ("100.64.0.1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("169.254.1.1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("224.0.0.251", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("240.0.0.1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("255.255.255.255", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("0.0.0.0", IpClass.SPECIAL, AssetLookup.NOT_FOUND),  # noqa: S104
        ("192.0.2.1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("198.18.0.1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("::1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("fe80::1%eth0", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("ff02::1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
        ("2001:db8::1", IpClass.SPECIAL, AssetLookup.NOT_FOUND),
    ],
)
def test_classes(address: str, ip_class: IpClass, lookup: AssetLookup) -> None:
    result = CLASSIFIER.classify(address)
    assert (result.ip_class, result.lookup) == (ip_class, lookup)
    assert (result.asset is not None) is (lookup is AssetLookup.MATCHED)


@pytest.mark.parametrize("value", ["", "10.0.0.256", "host", None, 5, b"10.0.0.1", "1" * 80])
def test_invalid(value: Any) -> None:
    result = CLASSIFIER.classify(value)
    assert (result.address, result.ip_class, result.lookup) == (
        None, IpClass.INVALID, AssetLookup.NOT_APPLICABLE,
    )  # fmt: skip


def test_without_a_map_the_lookup_is_unknown() -> None:
    result = IpClassifier(None).classify("10.20.3.4")
    assert (result.ip_class, result.lookup, result.asset) == (
        IpClass.INTERNAL, AssetLookup.NO_MAP, None,
    )  # fmt: skip


@given(st.ip_addresses())
def test_every_address_gets_one_consistent_class(address: Any) -> None:
    result = CLASSIFIER.classify(str(address))
    assert result.ip_class is not IpClass.INVALID
    assert result.address == str(getattr(address, "ipv4_mapped", None) or address)
    if result.ip_class is IpClass.PUBLIC:
        assert ipaddress.ip_address(result.address).is_global
    if result.lookup is AssetLookup.MATCHED:
        assert result.ip_class is IpClass.ASSET
