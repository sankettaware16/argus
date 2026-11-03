"""Addresses ARGUS will put on a message (Q-H4): one plain address, ASCII, nothing a header, an
envelope or an SMTP command could be smuggled in by. Hostile inputs and a property over any text."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.notices.address import (
    MAX_ADDRESS,
    MAX_HOST,
    MAX_LOCAL,
    NOT_A_HOST,
    NOT_AN_ADDRESS,
    domain_of,
    parse_address,
    parse_host,
)

pytestmark = pytest.mark.unit

GOOD = [
    "ta@example.org",
    "a.b+c_d%e-f@mail.example.edu",
    "x@a.b.example.co",
    "A1@Example.ORG",
    "r2-d2@sub-domain.example.org",
]
HOSTILE = [
    "",
    " ta@example.org",
    "ta@example.org ",
    "ta@example.org\n",
    "ta@example.org\r\nBcc: evil@example.org",
    "ta@example.org\nBcc: evil@example.org",
    "ta@example.org\x00",
    "ta@exa\x00mple.org",
    "ta@example.org, evil@example.org",
    "ta@example.org;evil@example.org",
    "ta@example.org evil@example.org",
    "Name <ta@example.org>",
    "<ta@example.org>",
    '"ta"@example.org',
    '"ta bob"@example.org',
    "ta(comment)@example.org",
    "ta@[127.0.0.1]",
    "ta@localhost",
    "ta@example",
    "ta@",
    "@example.org",
    "ta@@example.org",
    "ta@exam ple.org",
    ".ta@example.org",
    "ta.@example.org",
    "t..a@example.org",
    "ta@-example.org",
    "ta@example-.org",
    "ta@example..org",
    "ta@example.org.",
    "ta@example.o",
    "ta@example.123",
    "tá@example.org",
    "ta@exämple.org",
    "ta@example.org\u2028Bcc: x@example.org",
    "ta@example.org\u202e",
    "ta\\@example.org",
    "ta@example.org>\r\nRCPT TO:<evil@example.org",
    "ta@example.org>",
    "ta'--@example.org\r\nDATA",
    "a" * 65 + "@example.org",
    "ta@" + "a" * 64 + ".org",
    "ta@" + ".".join(["abcdefghij"] * 26) + ".org",
    "x" * MAX_ADDRESS + "@example.org",
]


@pytest.mark.parametrize("address", GOOD)
def test_one_plain_address_passes_unchanged(address: str) -> None:
    assert parse_address(address) == address


@pytest.mark.parametrize("address", HOSTILE)
def test_everything_else_is_refused_and_never_echoed(address: str) -> None:
    with pytest.raises(ValueError, match="plain e-mail address") as refused:
        parse_address(address)
    with pytest.raises(ValueError, match="plain e-mail address") as fixed:
        parse_address("not an address")
    assert str(refused.value) == str(fixed.value)  # the same words whatever was given


def test_non_text_is_refused() -> None:
    for value in (None, 5, b"ta@example.org", ["ta@example.org"]):
        with pytest.raises(ValueError, match="plain e-mail address"):
            parse_address(value)  # type: ignore[arg-type]


@given(st.text(max_size=300))
def test_property_an_accepted_address_has_no_character_that_can_split_a_header(value: str) -> None:
    try:
        got = parse_address(value)
    except ValueError:
        return
    assert got == value
    assert value.isascii()
    assert not any(c in value for c in "\r\n\x00 \t,;<>\"'()[]\\:")
    assert value.count("@") == 1
    assert len(value) <= MAX_ADDRESS


@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    st.sampled_from(["\r", "\n", "\r\n", "\x00", " ", ",", ";", "<", ">", '"']),
    st.sampled_from(["example.org", "mail.example.edu"]),
)
def test_property_any_one_hostile_character_in_a_good_address_refuses_it(
    local: str, bad: str, domain: str
) -> None:
    assert parse_address(f"{local}@{domain}") == f"{local}@{domain}"
    for broken in (f"{local}{bad}@{domain}", f"{local}@{domain}{bad}", f"{bad}{local}@{domain}"):
        with pytest.raises(ValueError, match="plain e-mail address"):
            parse_address(broken)


def test_the_domain_of_an_address() -> None:
    assert domain_of("ta@mail.example.org") == "mail.example.org"
    with pytest.raises(ValueError, match="plain e-mail address"):
        domain_of("not an address")


@pytest.mark.parametrize("host", ["mail.example.org", "localhost", "127.0.0.1", "relay-1"])
def test_a_host_name_is_letters_digits_hyphens_and_dots(host: str) -> None:
    assert parse_host(host) == host


@pytest.mark.parametrize(
    "host",
    ["", "mail example.org", "mail.example.org\r\n", "a" * 64, "-x", "x-", "x..y", "ma\x00il",
     "mail.example.org:25", "http://mail", "x" * 254, "ünï.example"],
)  # fmt: skip
def test_anything_else_is_not_a_host_name(host: str) -> None:
    with pytest.raises(ValueError, match="not a host name"):
        parse_host(host)


def domain_with(length: int) -> str:
    """A valid host name of exactly ``length`` characters (labels of at most 63)."""
    labels = []
    left = length - 4  # the last label ("org" plus its dot) is added below
    while left > 0:
        take = min(63, left - (1 if left > 64 else 0))
        labels.append("a" * take)
        left -= take + 1
    return ".".join([*labels, "org"])


def test_the_limits_are_exact() -> None:
    assert (MAX_ADDRESS, MAX_LOCAL, MAX_HOST) == (254, 64, 253)  # RFC 5321's, written out
    assert len(domain_with(100)) == 100
    # a local part of 64 is the most; the whole address 254
    assert parse_address("a" * MAX_LOCAL + "@example.org")
    with pytest.raises(ValueError, match="plain e-mail address"):
        parse_address("a" * (MAX_LOCAL + 1) + "@example.org")
    longest = "a" * MAX_LOCAL + "@" + domain_with(MAX_ADDRESS - MAX_LOCAL - 1)
    assert len(longest) == MAX_ADDRESS
    assert parse_address(longest) == longest
    too_long = "a" * MAX_LOCAL + "@" + domain_with(MAX_ADDRESS - MAX_LOCAL)
    assert len(too_long) == MAX_ADDRESS + 1
    with pytest.raises(ValueError, match="plain e-mail address"):
        parse_address(too_long)
    assert parse_host(domain_with(MAX_HOST)) == domain_with(MAX_HOST)
    with pytest.raises(ValueError, match="not a host name"):
        parse_host(domain_with(MAX_HOST + 1))


def test_the_refusals_use_these_exact_words() -> None:
    with pytest.raises(ValueError, match="plain e-mail address") as bad_address:
        parse_address("nope")
    assert str(bad_address.value) == NOT_AN_ADDRESS
    with pytest.raises(ValueError, match="not a host name") as bad_host:
        parse_host("no pe")
    assert str(bad_host.value) == NOT_A_HOST
    assert (
        NOT_AN_ADDRESS == "not a plain e-mail address (one address, ASCII, like name@example.org)"
    )
    assert NOT_A_HOST == "not a host name (letters, digits, hyphens and dots only)"


def test_a_non_ascii_letter_is_refused_by_the_pattern_itself() -> None:
    for bad in ("ta@exämple.org", "tä@example.org", "ta@example.örg", "ta@example.org\u0661"):
        with pytest.raises(ValueError, match="plain e-mail address"):
            parse_address(bad)
    for bad in ("exämple.org", "example.\u0661"):
        with pytest.raises(ValueError, match="not a host name"):
            parse_host(bad)
