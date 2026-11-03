"""P1: every form of an internal identifier is found; ordinary text is left alone; every
pattern stays fast on adversarial input (review 1, D1-D11)."""

from __future__ import annotations

import base64
import ipaddress
import time
from urllib.parse import quote

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.llm.detect import Campus, Found, canonical, find, outermost, unescape

pytestmark = pytest.mark.unit


def kinds(text: str, campus: Campus) -> set[str]:
    return {f.kind for f in find(text, campus)}


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    "text",
    [
        "src 10.1.2.3 dst",
        "010.001.002.003",  # leading zeros
        "012.1.2.3",  # octal part: 012 = 10
        "0x0a.0x01.0x02.0x03",  # hex parts
        "167838211",  # one decimal integer
        "it was 167774983.",  # ... before a full stop
        "0x0a010203",  # one hex integer
        "0X0A010203",
        "it was 0x0a141e07.",
        "01200000001",  # one octal integer
        "10.65538",  # inet_aton short forms
        "10.20.772",
        "198.51.25636",
        "::ffff:10.1.2.3",
        "::ffff:a01:203",
        "::10.20.3.4",  # IPv4-compatible
        "::a14:105",
        "64:ff9b::a14:105",  # NAT64
        "2002:a01:203::1",  # 6to4
        "2001:0:4136:e378:8000:63bf:f5fe:fdfc",  # Teredo, client 10.1.2.3
        "3.2.1.10.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
        "10.1.2…",
        "10.1.2...",
        "10.1.2.x",
        "10.1.2.*",
        "198.51.100",  # a bare campus prefix (outside private space)
        "192.168.12.990",  # not an address, but its network shows
        "host.10.20.3.4",  # bounded by dots
        "Scanning...10.20.3.4 done",
        "IP 10.20.1.5.51234 > 8.8.8.8.53",  # tcpdump: an address with a port
        "1.3.6.1.4.1.10.20.1.5",  # inside an OID
        "x10.1.2.3y",  # glued to letters
        "ip-10-20-1-5.ec2.internal",  # dashed
        "host-192-168-12-5",
        "src:fd00::7",  # IPv6 after a label
        "Source fd00::7: scanning",
        "fd00::7:",
        "ip:fe80::1",
        "sfd00::1",
        "x.fd00::1",
        "\u00f4fd00::7",
        "fe80::1%eth0",
        "fd00::1",
        "100.64.1.1",
        "172.16.5.4:8080",
        "http://192.168.12.4/x",
        "198.51.100.7",  # a campus prefix
        "203.0.113.9",  # a public network in the asset map
        "10%2e1%2e2%2e3",
        "10%252e1%252e2%252e3",  # percent twice
        "10&#46;1&#46;2&#46;3",
        "10&#x2e;1&#x2e;2&#x2e;3",
        "10\\u002e1\\u002e2\\u002e3",
        "10\\x2e1\\x2e2\\x2e3",
        "\\\\x31\\\\x30.20.1.5",  # doubled backslashes
        "%u0031%u0030.1.2.3",  # IIS
        "\\061\\060.1.2.3",  # octal escapes
        "\uff11\uff10.\uff11.\uff12.\uff13",  # fullwidth digits
        "10\u30021\u30022\u30023",  # ideographic full stops
        "10\u200b.1.2.3",  # a zero-width blank inside
        "10[.]20[.]1[.]5",  # defanged
        "10(.)1(.)2(.)3",
        "10[dot]1[dot]2[dot]3",
        "q=" + b64("host 10.1.2.3 here"),
        "q=" + b64(quote("10.1.2.3", safe="")),  # percent inside base64
        "/a/" + b64("10.1.2.3") + "/b",  # between slashes
        "x" + b64("10.1.2.3"),  # glued to a letter
        b64("10.20.7.7") + "=L",
        "q=" + base64.urlsafe_b64encode(b"\xfb\xff 10.1.2.3").decode().rstrip("="),
        "-enc " + base64.b64encode("iwr http://10.20.1.5/a".encode("utf-16-le")).decode(),
        "31302e312e322e33",  # a hex string
    ],
)
def test_internal_addresses_in_every_form(text: str, campus: Campus) -> None:
    assert "ip" in kinds(text, campus), text


@pytest.mark.parametrize(
    "text",
    [
        "8.8.8.8",
        "8.8.8.8:53",
        "Chrome/120.0.0.0 Safari",
        "Version/10.0.1 Mobile",  # private space, three parts, no mark: a version
        "Version/10.0.19041.1",
        "PAN-OS 10.2.x and 10.1.x",  # a two-part version with a mark
        "Windows NT 10.0.x",
        "10.0 and 172.16",
        "size 4096 bytes",
        "1700000000",  # a time stamp, not internal
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "I1.IP_3 and I2.IP_14",
        "1.2.3.4.5",
        "2026-10-14",
        "20:40:00",
        "::",
    ],
)
def test_no_false_addresses(text: str, campus: Campus) -> None:
    assert "ip" not in kinds(text, campus), text


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("see www.example.edu now", "domain"),
        ("MOODLE.EXAMPLE.EDU.", "domain"),
        ("example.edu", "domain"),
        ("a.example.edu:443", "domain"),
        ("www.example.edu.evil.example", "domain"),  # a look-alike: its campus part
        ("host.example.edu.0", "domain"),
        ("example[.]edu", "domain"),
        ("cse.example[.]edu", "domain"),
        ("cse\u3002example\u3002edu", "domain"),
        ("xn--80ak6aa92e.example.edu", "domain"),
        ("mail me at a.b@x.org", "email"),
        ("alic\u00e9@example.com", "email"),
        ("00:1a:2b:3c:4d:5e", "mac"),
        ("00-1A-2B-3C-4D-5E", "mac"),
        ("001a.2b3c.4d5e", "mac"),
        ("/~alice/index.html", "user_path"),
        ("/~USER_1-zed/", "user_path"),  # a pseudonym look-alike is not a pseudonym
        ("https://bob:" + "hunter2@example.org/", "credentials"),
        ("/cb?token=abcd1234efgh", "url_token"),
        ("/x;jsessionid=1;sid=ABCDEF12", "url_token"),
        ("/x?access_key=AKIA1234&jwt=eyJabc.def", "url_token"),
        ("/x?X-Amz-Signature=abcd1234", "url_token"),
        ("/x?PHPSESSID=abcd1234", "url_token"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hex_id"),
        ("123e4567-e89b-12d3-a456-426614174000", "hex_id"),
        ("roll 21D070012 here", "roll_number"),
        ("\u00f421D070012.", "roll_number"),
        ("key sk-proj-abcdefghijklmnopqrstuv", "secret"),
        ("gsk" + "_abcdefghijklmnopqrstuvwx", "secret"),
        ("AI" + "zaSyA-abcdefghijklmnopqrstuvwxyz", "secret"),
        ("Authorization: Bearer abcdefghijklmnopqrstu", "secret"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", "secret"),
        ("AKIAABCDEFGHIJKLMNOP", "secret"),
        ("-----BEGIN RSA " + "PRIVATE KEY-----", "secret"),
        ("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----", "secret"),
        ("password=correcthorse1", "secret"),
        ('{"pass' + 'word":"hunter2hunter2"}', "secret"),
        ("aws_secret_access_key = " + "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "secret"),
        ("pwd=hunter2hunter2", "secret"),
        ("pass: hunter2hunter2", "secret"),
        ("Cookie: sessionid=abcdefghijklmnop", "secret"),
        ("gl" + "pat-abcdefghijklmnopqrstu", "secret"),
        ("hooks.slack.com/services/T000/B000/XXXX", "secret"),
        ("ghp_abcdefghijklmnopqrstuvwxyz", "secret"),
        ("the tp8 box", "name"),
        ("in geology   lab\nblock today", "name"),  # several words, any blanks, any case
        ("Geology-Lab-Block", "name"),
        ("Geology_Lab_Block", "name"),
        ("h12 wing-c", "name"),
        ("H12-Wing-C", "name"),
        ("MAILGATE relays", "name"),
    ],
)
def test_other_identifiers(text: str, kind: str, campus: Campus) -> None:
    assert kind in kinds(text, campus), text


@pytest.mark.parametrize(
    "text",
    [
        "example.edudia",
        "a.example.edu443",
        "notexample.edu",
        "example.org",
        "jquery@3.5.1",  # not an e-mail address
        "order 21A1234567",  # not a roll number
        "tp80 and atp8 and tp8x",  # a name only as a whole word
        "I1.HOST_2 and HOST_7",
        "/~I1.USER_2/",
        "geology lab",  # part of a name is not the name
        "token: answered",  # no digit and short: not a secret
        "the gate is open",
    ],
)
def test_no_false_identifiers(text: str, campus: Campus) -> None:
    assert not kinds(text, campus), (text, kinds(text, campus))


def test_names_by_length_and_ordinary_words() -> None:
    campus = Campus(
        assets=frozenset({"ab", "gateway", "x9z"}),
        hosts=frozenset({"h1"}),
        users=frozenset({"Alice.Smith"}),
        ordinary=frozenset({"gateway"}),
    )
    found = [f.value for f in find("ab gateway x9z h1 alice smith", campus)]
    assert found == ["x9z", "h1", "alice smith"]  # an asset name needs 3, a request name 2
    assert Campus().name_index == {}


def test_names_say_whether_they_are_users() -> None:
    campus = Campus(hosts=frozenset({"tp8"}), users=frozenset({"Alice.Smith"}))
    assert campus.name_kind("ALICE SMITH") == "user"
    assert campus.name_kind("alice.smith") == "user"
    assert campus.name_kind("tp8") == "host"


def test_a_name_inside_a_pseudonym_is_not_a_name() -> None:
    campus = Campus(assets=frozenset({"host"}))
    assert kinds("I1.HOST_3", campus) == set()
    assert kinds("the host", campus) == {"name"}


def test_embedded_addresses_are_unwrapped(campus: Campus) -> None:
    assert campus.internal(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert campus.internal(ipaddress.ip_address("64:ff9b:1::a00:1"))
    assert not campus.internal(ipaddress.ip_address("::1"))
    assert not campus.internal(ipaddress.ip_address("64:ff9b::808:808"))


def test_encoded_findings_span_the_encoded_stretch(campus: Campus) -> None:
    text = "a " + b64("10.1.2.3 inside") + " b"
    found = [f for f in find(text, campus) if f.encoded]
    assert found[0].start == 2
    assert found[0].end == len(text) - 2
    assert found[0].value == "10.1.2.3"
    whole = [f for f in find("x 10%2e1%2e2%2e3 y", campus) if f.encoded]
    assert (whole[0].start, whole[0].end) == (0, 18)


def test_values_are_canonical(campus: Campus) -> None:
    assert [f.value for f in find("010.001.002.003", campus)] == ["10.1.2.3"]
    assert [f.value for f in find("167838211", campus)] == ["10.1.2.3"]
    assert {f.value for f in find("3.2.1.10.in-addr.arpa", campus)} == {"10.1.2.3"}
    assert [f.value for f in find("FD00::0001", campus)] == ["fd00::1"]
    assert [f.value for f in find("00:1A:2B:3C:4D:5E", campus)] == ["00:1a:2b:3c:4d:5e"]


def test_spans(campus: Campus) -> None:
    assert [(f.start, f.end) for f in find("at 10.1.2.x now", campus)] == [(3, 11)]
    assert [(f.start, f.end) for f in find("src:fd00::7 x", campus)] == [(4, 11)]
    assert [(f.start, f.end) for f in find("a cse.example.edu b", campus)] == [(2, 17)]


def test_canonical_and_unescape() -> None:
    assert canonical("a%2541") == "aA"
    assert canonical("10[.]1(.)2[dot]3 x[at]y") == "10.1.2.3 x@y"
    assert canonical("plain") == "plain"
    assert unescape("\\x41\\u0042\\u{43}\\104%u0045") == "ABCDE"
    assert unescape("\\\\x41") == "A"


def test_outermost_keeps_the_longest_span_at_each_position() -> None:
    a = Found(0, 10, "ip", "x")
    b = Found(2, 4, "name", "y")
    c = Found(10, 12, "name", "z")
    assert outermost([b, c, a]) == [a, c]


@pytest.mark.parametrize(
    "text",
    ["a." * 25_000, "1." * 25_000, "xn--a." * 8_000, "_-" * 25_000, "a" * 50_000 + "@b.org",
     ":" * 50_000, "1:" * 25_000, "ab" * 25_000, "QUJD" * 12_000, "10.1.2.3 " * 5_000],
)  # fmt: skip
def test_adversarial_input_stays_fast(text: str, campus: Campus) -> None:
    start = time.perf_counter()
    find(text, campus)
    assert time.perf_counter() - start < 5  # 50 KB; quadratic patterns took minutes


@given(st.ip_addresses(network="10.0.0.0/8"), st.sampled_from(["", " ", "x=", "/", "(", ".", ":"]))
def test_any_private_address_is_found_in_its_forms(ip: ipaddress.IPv4Address, pre: str) -> None:
    campus = Campus()
    forms = [
        str(ip),
        str(int(ip)),
        f"0x{int(ip):08x}",
        f"::ffff:{ip}",
        f"64:ff9b::{ip}",
        ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa",
        str(ip).replace(".", "-"),
        str(ip).replace(".", "[.]"),
        quote(str(ip), safe="").replace(".", "%2E"),
        b64(f"ip={ip}"),
        f"{ip}.443",
    ]
    for form in forms:
        assert "ip" in kinds(pre + form + " ", campus), form


@given(st.ip_addresses(v=4))
def test_public_addresses_are_never_found(ip: ipaddress.IPv4Address) -> None:
    campus = Campus()
    if campus.internal(ip):
        return
    assert "ip" not in kinds(f"from {ip} to", campus)


@given(st.text(max_size=200))
def test_find_never_raises(text: str) -> None:
    for f in find(text, Campus(hosts=frozenset({"tp8"}))):
        assert 0 <= f.start <= f.end <= len(text)
