"""P1: the detector's helpers, value by value (spans, bounds and limits), so a changed
boundary or limit shows (mutation testing, D-040)."""

from __future__ import annotations

import base64
import ipaddress
from typing import Any

import pytest

from argus.llm import detect
from argus.llm.detect import Campus, Found, find

pytestmark = pytest.mark.unit
V4 = ipaddress.IPv4Address


def spans(text: str, campus: Campus | None = None) -> list[tuple[int, int, str, str]]:
    return [(f.start, f.end, f.kind, f.value) for f in find(text, campus or Campus())]


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        (["10", "1", "2", "3"], [V4("10.1.2.3"), V4("10.1.2.3")]),
        (["010", "1", "2", "3"], [V4("10.1.2.3"), V4("8.1.2.3")]),
        (["0x0a", "1", "2", "3"], [V4("10.1.2.3"), V4("10.1.2.3")]),
        (["0X0A", "1", "2", "3"], [V4("10.1.2.3"), V4("10.1.2.3")]),
        (["09", "1", "2", "3"], [V4("9.1.2.3")]),  # 09 is no octal number
        (["256", "1", "2", "3"], []),
        (["10", "1", "2", "255"], [V4("10.1.2.255"), V4("10.1.2.255")]),
        (["10", "1", "2", "256"], []),
        (["10", "65535"], [V4("10.0.255.255"), V4("10.0.255.255")]),
        (["10", "16777215"], [V4("10.255.255.255"), V4("10.255.255.255")]),
        (["10", "16777216"], []),
        (["10", "1", "65535"], [V4("10.1.255.255"), V4("10.1.255.255")]),
        (["10", "1", "65536"], []),
        (["167838211"], [V4("10.1.2.3"), V4("10.1.2.3")]),
        (["1", "2", "3", "4", "5"], []),
        ([], []),
        (["0"], [V4(0), V4(0)]),
    ],
)
def test_aton(parts: list[str], expected: list[V4]) -> None:
    assert detect._aton(parts) == expected


@pytest.mark.parametrize(
    ("text", "octal", "value"),
    [("0x1f", False, 31), ("0X1F", True, 31), ("017", False, 17), ("017", True, 15),
     ("0", True, 0), ("08", True, None), ("7", True, 7)],
)  # fmt: skip
def test_part(text: str, octal: bool, value: int | None) -> None:
    assert detect._part(text, octal) == value


@pytest.mark.parametrize(
    ("address", "embedded"),
    [
        ("::ffff:10.1.2.3", ["10.1.2.3"]),
        ("2002:a01:203::1", ["10.1.2.3"]),
        ("::10.1.2.3", ["10.1.2.3"]),
        ("::1:0", ["0.1.0.0"]),  # just above 0xFFFF: compatible
        ("::ffff", []),  # 0xFFFF itself: not
        ("::1", []),
        ("64:ff9b::a01:203", ["10.1.2.3"]),
        ("64:ff9b:1::a01:203", ["10.1.2.3"]),
        ("2001:0:4136:e378:8000:63bf:f5fe:fdfc", ["10.1.2.3"]),
        ("2001:db8::1", []),
        ("1::a01:203", []),  # high bits set: no IPv4 inside
    ],
)
def test_embedded(address: str, embedded: list[str]) -> None:
    got = detect._embedded(ipaddress.IPv6Address(address))
    assert [str(a) for a in got] == embedded


def test_campus_defaults_and_equality() -> None:
    campus = Campus()
    assert campus.domains == ("example.edu", "example-univ.org")  # the site's own_domains
    assert campus.campus_domain("A.EXAMPLE.EDU.")
    assert not campus.campus_domain("example.edu.x")
    assert Campus(is_internal=lambda ip: True) == Campus(is_internal=lambda ip: False)
    assert hash(Campus()) == hash(Campus(is_internal=lambda ip: True))
    shown = repr(Campus(assets=frozenset({"aa1"}), hosts=frozenset({"bb2"}),
                        users=frozenset({"cc3"}), ordinary=frozenset({"dd4"})))  # fmt: skip
    for name in ("aa1", "bb2", "cc3", "dd4"):
        assert name not in shown


def test_found_defaults() -> None:
    assert Found(0, 1, "ip", "x").encoded is False


def test_name_index_shape() -> None:
    campus = Campus(assets=frozenset({"Geology Lab", "geology", "ab"}), hosts=frozenset({"h1"}))
    assert campus.name_index == {"geology": (("geology", "lab"), ("geology",)), "h1": (("h1",),)}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a 10.1.2.3 b", [(2, 10, "ip", "10.1.2.3")]),
        ("10.1.2.3.4", [(0, 10, "ip", "10.1.2.3")]),  # the first window decides
        ("1.10.1.2.3", [(0, 10, "ip", "10.1.2.3")]),  # the second window
        ("1.2.10.1.2.3", [(0, 12, "ip", "10.1.2.3")]),
        ("192.168.12.990", [(0, 14, "ip", "192.168.12.990")]),
        ("10.1.2.x y", [(0, 8, "ip", "10.1.2")]),
        ("10.1.2... y", [(0, 9, "ip", "10.1.2")]),
        ("10.1.2", []),
        ("198.51.100", [(0, 10, "ip", "198.51.100")]),
        ("10.65538", [(0, 8, "ip", "10.1.0.2")]),
        ("10.255", []),  # a short form with a small last part reads as a version
        ("a-10-1-2-3-b", [(2, 10, "ip", "10.1.2.3")]),
        ("1-10-1-2-3", [(0, 10, "ip", "10.1.2.3")]),
        ("10-1-2", []),
    ],
)
def test_dotted_and_dashed(text: str, expected: list[Any]) -> None:
    campus = Campus(networks=(ipaddress.ip_network("198.51.100.0/24"),))
    assert [s for s in spans(text, campus) if s[2] == "ip"] == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("fd00::1", [(0, 7, "ip", "fd00::1")]),
        ("x:fd00::1:", [(2, 9, "ip", "fd00::1")]),
        ("a.fd00::1.0", [(2, 9, "ip", "fd00::1")]),
        ("fd00::1 fd00::2", [(0, 7, "ip", "fd00::1"), (8, 15, "ip", "fd00::2")]),
        ("fd00:0:0:0:0:0:0:1:fd00::2", [(0, 18, "ip", "fd00::1"), (19, 26, "ip", "fd00::2")]),
        ("fd00:::1", [(0, 6, "ip", "fd00::")]),  # the valid address inside
        ("fd00::1::2", [(0, 7, "ip", "fd00::1")]),
        ("2001:db8::1", []),
    ],
)
def test_ipv6_spans(text: str, expected: list[Any]) -> None:
    assert [s for s in spans(text) if s[2] == "ip"] == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("00:1A:2b:3c:4d:5e", [(0, 17, "mac", "00:1a:2b:3c:4d:5e")]),
        ("x 00-1a-2b-3c-4d-5e y", [(2, 19, "mac", "00-1a-2b-3c-4d-5e")]),
        ("0:00:1a:2b:3c:4d:5e", [(0, 19, "mac", "00:1a:2b:3c:4d:5e")]),
        ("001a.2b3c.4d5e", [(0, 14, "mac", "001a.2b3c.4d5e")]),
        ("00:1a:2b-3c:4d:5e", []),  # mixed separators
        ("00:1a:2b:3c:4d", []),
        ("001a.2b3c", []),
        ("00.1a.2b.3c.4d.5e", []),  # dots join 4-digit groups only
        ("001a:2b3c:4d5e", []),
    ],
)
def test_macs(text: str, expected: list[Any]) -> None:
    assert [s for s in spans(text) if s[2] == "mac"] == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.edu", [(0, 11, "domain", "example.edu")]),
        ("x Moodle.EXAMPLE.edu", [(2, 20, "domain", "moodle.example.edu")]),
        ("-.a.example.edu", [(2, 15, "domain", "a.example.edu")]),
        ("a..example.edu", [(0, 14, "domain", "a..example.edu")]),
        ("http://a-b.example.edu/", [(7, 22, "domain", "a-b.example.edu")]),
        (
            "example.edu example.edu",
            [(0, 11, "domain", "example.edu"), (12, 23, "domain", "example.edu")],
        ),
        ("xexample.edu", []),
        ("-example.edu", []),
        ("example.edux", []),
        ("example.edu9", []),
    ],
)
def test_domain_spans(text: str, expected: list[Any]) -> None:
    assert [s for s in spans(text) if s[2] == "domain"] == expected


def test_a_subdomain_is_read_back_at_most_253_characters() -> None:
    label = "a" * 300
    found = [s for s in spans(f"{label}.example.edu") if s[2] == "domain"]
    assert found == [(48, 312, "domain", "a" * 252 + ".example.edu")]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail a.b@x.org now", [(5, 14, "email", "a.b@x.org")]),
        ("a@b.org.0", [(0, 7, "email", "a@b.org")]),
        ("a@b.c", []),
        ("@b.org", []),
        ("a@org", []),
        ("a@b..org", []),
        ("x" * 70 + "@b.org", [(6, 76, "email", "x" * 64 + "@b.org")]),
        ("a@b.org@c.net", [(0, 7, "email", "a@b.org"), (2, 13, "email", "b.org@c.net")]),
    ],
)
def test_email_spans(text: str, expected: list[Any]) -> None:
    assert [s for s in spans(text) if s[2] == "email"] == expected


def test_an_email_domain_is_read_at_most_253_characters() -> None:
    found = [s for s in spans("a@" + "b" * 300 + ".org") if s[2] == "email"]
    assert found == []  # the domain is cut before its top-level label


def test_encodings_are_undone_three_deep_not_four() -> None:
    def b64(text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    three = b64(b64(b64("10.1.2.3")))
    four = b64(three)
    assert any(f.kind == "ip" for f in find(three, Campus()))
    assert not any(f.kind == "ip" for f in find(four, Campus()))
    assert detect.DEPTH == 3


def test_url_token_keys_are_matched_as_listed() -> None:
    for key in ("access_token", "refresh_token", "x-amz-credential", "client_secret", "sid"):
        assert [s[2] for s in spans(f"/a?{key}=abcd1234")] == ["url_token"], key
    assert spans("/a?page=abcd1234") == []


def test_hex_strings_and_punycode_are_decoded() -> None:
    assert [s[2] for s in spans("31302e312e322e33")] == ["ip"]
    assert spans("31302e312e322e") == []  # seven bytes, but no address in them
    puny = "xn--10-1-2-3-xyz.example"
    assert detect.LABELS.fullmatch(puny)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10.1.2.3.10.4.5.6", [(0, 17, "ip", "10.1.2.3")]),  # the first address names the run
        ("192.168.12.990.10.1.2.3", [(0, 23, "ip", "192.168.12.990.10.1.2.3")]),
        ("10.256", [(0, 6, "ip", "10.0.1.0")]),
        ("10.0256", [(0, 7, "ip", "10.0.1.0")]),  # decimal first; octal would be 10.0.0.174
        ("010.1.2.x", [(0, 9, "ip", "010.1.2")]),  # decimal 10.1.2 is private
        ("010.1.2", []),  # unmarked, and its decimal reading is private
        ("8.8.8.x", []),
        ("10-1-2-3-4", [(0, 10, "ip", "10.1.2.3")]),
        ("1-2-3-10-1-2", []),  # no window of four reads as internal
        ("012-1-2-3", []),  # dashed forms are decimal only
        ("10-1-2-3-10-4-5-6", [(0, 17, "ip", "10.1.2.3")]),
        ("4.4.8.8.in-addr.arpa", []),
        ("9999999999", []),  # above 2**32: no address
        ("4294967295", []),
    ],
)
def test_more_address_spans(text: str, expected: list[Any]) -> None:
    assert [s for s in spans(text) if s[2] == "ip"] == expected


def test_arpa_and_hex_spans() -> None:
    assert [s[:2] for s in spans("x 3.2.1.10.in-addr.arpa y") if s[2] == "ip"] == [(2, 23)]
    assert [s for s in spans("0x0a010203") if s[2] == "ip"] == [(0, 10, "ip", "10.1.2.3")]


def test_ipv6_runs_are_not_read_twice() -> None:
    assert [s for s in spans("x fd00::1:2 y") if s[2] == "ip"] == [(2, 11, "ip", "fd00::1:2")]
    assert [s for s in spans("fd00::fd00::1") if s[2] == "ip"] == [(0, 10, "ip", "fd00::fd00")]


def test_embedded_compatible_addresses_stay_within_32_bits() -> None:
    assert detect._embedded(ipaddress.IPv6Address("::1:0:0")) == []


def test_mac_windows() -> None:
    assert [s[3] for s in spans("00:1a:2b:3c:4d:5e-ff") if s[2] == "mac"] == ["00:1a:2b:3c:4d:5e"]
    assert [s for s in spans("00:1a:2b:3c:4d-5e") if s[2] == "mac"] == []
    assert len([s for s in spans("00:1a:2b:3c:4d:5e:6f") if s[2] == "mac"]) == 1


def test_domain_edges() -> None:
    assert [s for s in spans("example.edua-x") if s[2] == "domain"] == []
    assert [s[3] for s in spans("X.example.edu") if s[2] == "domain"] == ["x.example.edu"]
    assert [s[3] for s in spans("-a.example.edu") if s[2] == "domain"] == ["a.example.edu"]


def test_email_edges() -> None:
    assert [s for s in spans("a@ b.org") if s[2] == "email"] == []
    domain = "b" * 249 + ".org"  # 253 characters: the most a domain has
    assert [s[3] for s in spans("a@" + domain + "x") if s[2] == "email"] == ["a@" + domain]


def test_name_edges() -> None:
    campus = Campus(assets=frozenset({"Geology Lab", "geology"}), hosts=frozenset({"tp8"}))
    assert [s[3] for s in spans("geology xyz", campus) if s[2] == "name"] == ["geology"]
    assert [s[3] for s in spans("geology.lab", campus) if s[2] == "name"] == ["geology.lab"]
    dotted = Campus(users=frozenset({"asha.k"}))  # an account is often first.last
    assert [s[3] for s in spans("user asha.k signed in", dotted) if s[2] == "name"] == ["asha.k"]
    assert [s[3] for s in spans("asha_k and asha k", dotted) if s[2] == "name"] == [
        "asha_k", "asha k",
    ]  # fmt: skip
    assert [s for s in spans("asha/k", dotted) if s[2] == "name"] == []
    assert [s[3] for s in spans("geology lab", campus) if s[2] == "name"] == ["geology lab"]
    assert [s[3] for s in spans("tp8 and I1.IP_1", campus) if s[2] == "name"] == ["tp8"]
    only = Campus(assets=frozenset({"Geology Lab"}))
    assert [s for s in spans("geology xyz", only) if s[2] == "name"] == []


def test_unescape_limits() -> None:
    assert detect.unescape("\\u{10FFFF}") == chr(0x10FFFF)
    assert detect.unescape("\\u{110000}") == "\\u{110000}"
    assert detect.canonical("a[@]b and c[at]d") == "a@b and c@d"


def test_base64_between_long_path_parts() -> None:
    hidden = base64.b64encode(b"10.1.2.3").decode()
    assert "ip" in {s[2] for s in spans(f"/abcdefgh/{hidden}/ijklmnop")}


def test_punycode_is_decoded() -> None:
    campus = Campus(hosts=frozenset({"tp8"}))
    puny = "tp8ü.example".encode("idna").decode()
    assert puny.startswith("xn--")
    found = [f for f in find(puny, campus) if f.kind == "name"]
    assert (0, len(puny), True) in {(f.start, f.end, f.encoded) for f in found}


def test_a_segment_of_a_decoded_text_spans_the_whole_text() -> None:
    hidden = base64.b64encode(b"10.1.2.3").decode()
    text = "a%20" + hidden
    whole = [f for f in find(text, Campus()) if f.encoded and f.kind == "ip"]
    assert (0, len(text)) in {(f.start, f.end) for f in whole}


def test_outermost_prefers_the_longest_at_one_start() -> None:
    short = Found(0, 4, "name", "y")
    long = Found(0, 10, "ip", "x")
    assert detect.outermost([short, long]) == [long]


def test_aton_refuses_five_parts() -> None:
    assert detect._aton(["1", "2", "3", "4", "0"]) == []


def test_a_broken_quad_shows_its_network_in_the_decimal_reading() -> None:
    assert [s for s in spans("010.1.2.990") if s[2] == "ip"] == [(0, 11, "ip", "010.1.2.990")]


@pytest.mark.parametrize("number", ["4294967296", "5000000000"])
def test_numbers_from_two_to_the_32_are_no_addresses(number: str) -> None:
    assert spans(number) == []


def test_an_ipv6_address_after_a_found_one_ending_in_colons() -> None:
    found = [s for s in spans("fd00::::a14:304") if s[2] == "ip"]
    assert found == [(0, 6, "ip", "fd00::"), (6, 15, "ip", "::a14:304")]


def test_base64_with_one_character_glued_after_it() -> None:
    hidden = base64.b64encode(b"10.1.2.30").decode()  # 12 characters, no padding
    assert "ip" in {s[2] for s in spans("q=" + hidden + "x")}


def test_a_pseudonym_before_an_at_is_no_email() -> None:
    assert [s for s in spans("http://I1.CRED_1@evil.example/") if s[2] == "email"] == []
