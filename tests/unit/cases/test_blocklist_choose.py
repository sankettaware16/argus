"""What a block list may hold (AR4b, D-169, D-181): only public, non-shared addresses and valid
names. The database side (the case's indicators, the evidence) is
tests/integration/cases/test_blocklist.py."""

from __future__ import annotations

import ipaddress

import pytest

from argus.assets.classify import IpClassifier
from argus.cases import blocklist
from argus.cases.membership import Shared


def kept(marks: list[tuple[str, str]], **more: object) -> blocklist.Chosen:
    return blocklist.choose(marks, Shared(**more))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "address",
    [
        "10.1.1.1",  # private
        "172.16.4.4",
        "192.168.0.7",
        "127.0.0.1",  # loopback
        "169.254.3.3",  # link-local
        "0.0.0.0",  # noqa: S104 - unspecified, as a value to refuse
        "224.0.0.1",  # multicast
        "100.64.1.1",  # carrier-grade NAT
        "::1",
        "fc00::1",  # ULA
        "fe80::1",
    ],
)
def test_a_campus_private_or_loopback_address_is_never_a_block(address: str) -> None:
    out = kept([("ip", address), ("ip", "77.221.155.150")])
    assert out.ips == ("77.221.155.150",)


def test_an_address_of_the_campus_prefixes_is_never_a_block() -> None:
    ours = IpClassifier(None, [ipaddress.ip_network("131.21.124.0/22")])
    out = blocklist.choose([("ip", "131.21.125.9"), ("ip", "185.9.9.9")], Shared(), ours)
    assert out.ips == ("185.9.9.9",)


def test_a_shared_address_or_name_is_left_out_and_counted() -> None:
    shared = Shared(
        networks=(ipaddress.ip_network("104.16.0.0/12"),), domains=frozenset({"cdn.example"})
    )
    out = blocklist.choose(
        [
            ("ip", "104.16.1.1"),
            ("ip", "185.9.9.9"),
            ("domain", "a.cdn.example"),
            ("domain", "evil.example.net"),
        ],
        shared,
    )
    assert out.ips == ("185.9.9.9",)
    assert out.domains == ("evil.example.net",)
    assert out.skipped == 2


@pytest.mark.parametrize(
    "value",
    [
        "d41d8cd98f00b204e9800998ecf8427e",  # a file hash is no name
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "=cmd|' /C calc'!A0.example.com",  # nothing a spreadsheet would run
        "@SUM(1+1).example.com",
        "evil.example.com/path",
        "not a name",
        "localhost",
        "1.2.3.4",  # a dotted number is an address, not a name
        "",
    ],
)
def test_a_value_that_is_no_domain_name_is_never_a_block(value: str) -> None:
    out = kept([("domain", value)])
    assert (out.parents, out.domains, out.ips) == ((), (), ())


def test_a_name_is_listed_with_its_registered_parent_once_and_the_count_agrees() -> None:
    out = kept(
        [
            ("domain", "a.evil.example.net"),
            ("domain", "b.evil.example.net"),
            ("domain", "other.org"),
            ("ip", "185.9.9.9"),
            ("url", "http://x.example.net/a"),  # a URL is not a destination of the list
        ]
    )
    assert out.parents == ("example.net", "other.org")
    assert out.domains == ("a.evil.example.net", "b.evil.example.net", "other.org")
    # parents + the names under no parent + the addresses: what the list holds
    assert out.total == 2 + 2 + 1
