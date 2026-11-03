"""Known answers and boundaries of the R2 pseudonym functions (found missing by mutation testing).

The known answers pin the derivation itself: tokens, ids, domains and addresses under a fixed
synthetic key. Every committed fixture depends on it, so a change here must be deliberate and come
with a new SANITIZER_VERSION and regenerated fixtures (``scripts/sanitize_fixtures.py samples``).
"""

from __future__ import annotations

import re

import pytest

from argus.fixtures import tokens as tokens_module
from argus.fixtures.ipmap import IPMapper
from argus.fixtures.tokens import DomainMapper, Tokenizer, normalize_domain

KEY = b"k" * 32
TOKENS = Tokenizer(KEY)


def test_token_known_answers() -> None:
    assert TOKENS.token("user", "alice", "u-") == "u-x4qh5bqa"
    assert TOKENS.token("label", "lab-pc-07", "", 8) == "7k75la5f"
    # a lone surrogate (from a bad \ud800 escape in a log) is hashed, not refused
    assert TOKENS.token("user", "a\ud800b", "u-") == "u-f5i3cdyg"


@pytest.mark.parametrize(
    ("value", "pseudonym"),
    [
        ("1234", "4112"),
        ("42", "46"),  # 100 values: 7 bits, widened to 8 for a balanced Feistel network
        ("12345", "85607"),  # 17 bits, widened to 18
        ("0f", "a6"),
        ("0F", "D4"),
        ("SyntheticAlertId0001", "4CtSuXXut2l-0MU8X04M"),
        ("0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a", "958289c4-3616-3b06-2402-b79b3b7049dd"),
        ("0F8E7D6C-5B4A-4392-8170-6F5E4D3C2B1A", "958289C4-3616-3B06-2402-B79B3B7049DD"),
        ("{0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a}", "{958289c4-3616-3b06-2402-b79b3b7049dd}"),
        ("ab" * 32, "d3eeab8d0c7b05bd6d015a110a1630d46c9024789ed9459209411d59fba4d932"),
        (
            "cd" * 64,
            "4407558b96c4fe984e3fa4b87f1d2dd2e2672267b918ff58589ebafc262dce76"
            "34387c5737eb61c1bedf3a68fb9745f81d44c6aa72671c7fef37682f4e8a4dd8",
        ),
        ("ef" * 65, "id-i7g32ovvsgawprevlust"),
        ("e" * 129, "id-7mbex36wclyz52mvxkz3"),
        ("weird id/with spaces", "id-hgi5b2tzk5qnjwsh2iel"),
        ("{not-a-uuid}", "id-gjlmm32ed44fqa7epcws"),
        ("{0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a", "id-ob2g7pupjfjqqwpx2mxt"),
        ("", ""),
    ],
    ids=[
        "decimal",
        "decimal-odd-width",
        "decimal-odd-width-17",
        "hex",
        "HEX",
        "es-id",
        "uuid",
        "UUID",
        "braced-uuid",
        "hex-256-bits",
        "hex-128-chars",
        "hex-130-chars-fallback",
        "hex-129-chars-fallback",
        "fallback",
        "braces-without-uuid",
        "half-braced-uuid",
        "empty",
    ],
)
def test_opaque_id_known_answers(value: str, pseudonym: str) -> None:
    assert TOKENS.opaque_id(value) == pseudonym


def test_a_short_key_is_refused_by_name() -> None:
    with pytest.raises(ValueError, match=r"^the fixture key must be at least 32 bytes$"):
        Tokenizer(b"k" * 31)


def test_the_id_class_walk_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A walk that never reaches the id's class fails loudly instead of spinning."""
    monkeypatch.setattr(tokens_module, "_MAX_ID_STEPS", 50)
    monkeypatch.setattr(tokens_module, "_id_class", lambda value: hash(value))
    with pytest.raises(ValueError, match=r"^the id permutation did not reach the id's class$"):
        Tokenizer(KEY).opaque_id("1234")


def test_the_cycle_walk_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tokens_module, "_MAX_ID_STEPS", 50)
    monkeypatch.setattr(Tokenizer, "_feistel", lambda self, value, bits, tweak, inverse: 1 << bits)
    with pytest.raises(ValueError, match=r"^the id permutation's cycle walk did not return$"):
        Tokenizer(KEY).opaque_id("1234")


DOMAINS = DomainMapper(
    TOKENS, ["campus.ac.in", "campus-alt.org"], ["vendor.example"], "univ.example", ["CU"]
)


@pytest.mark.parametrize(
    ("domain", "pseudonym"),
    [
        ("www.campus.ac.in", "nj4xtrco.univ.example"),
        ("www.campus-alt.org", "nj4xtrco.c2.univ.example"),
        ("x.y.example.com", "xilzmfum.6zae6i33.sauzwvfx.com"),
        ("a.vendor.example", "a.vendor.example"),
        ("campus-backups.s3.vendor.example", "msnsslw7.6yipb24g.vendor.example"),
        # a 2-letter literal (CU) is not looked for inside labels: "cuisine" is not a campus name
        ("cuisine.vendor.example", "cuisine.vendor.example"),
        ("x.y.example.co.in", "xilzmfum.6zae6i33.sauzwvfx.co.in"),  # a two-label public suffix
        ("printer.campus", "x6lcan64.62o6vdys"),  # a campus name in last place is no suffix
        ("a" * 64 + ".example", "d-x2ipscq7nq6k.invalid"),  # not a domain name
        (".", "."),  # nothing to map
        ("  ", "  "),
    ],
)
def test_domain_known_answers(domain: str, pseudonym: str) -> None:
    assert DOMAINS.map(domain) == pseudonym


def test_the_longest_campus_domain_wins() -> None:
    mapper = DomainMapper(TOKENS, ["campus.ac.in", "cs.campus.ac.in"], [])
    assert mapper.map("www.cs.campus.ac.in") == "nj4xtrco.c2.univ.example"


def test_the_longest_kept_domain_wins() -> None:
    """Only the labels in front of the longest kept domain are looked at and tokenized."""
    mapper = DomainMapper(TOKENS, ["campus.ac.in"], ["vendor.example", "s3.vendor.example"])
    assert mapper.map("campus-backups.s3.vendor.example") == "msnsslw7.s3.vendor.example"
    assert mapper.map("plain.s3.vendor.example") == "plain.s3.vendor.example"


def test_a_three_letter_campus_name_is_sensitive() -> None:
    mapper = DomainMapper(TOKENS, ["abc.ac.in"], ["vendor.example"])
    assert mapper.map("abc-backups.vendor.example") == "23v6oh4s.vendor.example"


def test_an_idn_campus_name_is_sensitive_in_its_punycode_spelling_too() -> None:
    """``mirror-xn--bcher-kva`` is no punycode label (it does not start with ``xn--``), but it
    spells the campus name ``bücher`` as punycode."""
    mapper = DomainMapper(TOKENS, ["xn--bcher-kva.example"], ["vendor.example"])
    assert mapper.map("mirror-xn--bcher-kva.vendor.example") == "giecrng5.vendor.example"
    assert mapper.map("mirror.vendor.example") == "mirror.vendor.example"


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("a" * 64 + ".example", "a domain label longer than 63 characters"),
        (".".join(["a" * 63] * 4) + ".b", "a domain name longer than 253 characters"),
    ],
)
def test_domain_length_errors(name: str, message: str) -> None:
    with pytest.raises(UnicodeError, match=f"^{re.escape(message)}$"):
        normalize_domain(name)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("a" * 63 + ".example", True),
        ("a" * 64 + ".example", False),
        (".".join(["a" * 61] * 4) + ".b", True),  # 249 + 2 = 251 characters
        (".".join(["a" * 63] * 4) + ".b", False),  # 255 + 2 = 257 characters
        ("a" * 49 + "." + ".".join(["b" * 50] * 4), True),  # 253 characters exactly
        ("a" * 50 + "." + ".".join(["b" * 50] * 4), False),  # 254 characters
    ],
    ids=["label-63", "label-64", "name-251", "name-257", "name-253", "name-254"],
)
def test_domain_length_limits(name: str, valid: bool) -> None:
    out = DOMAINS.map(name)
    assert out.endswith(".invalid") is not valid


@pytest.mark.parametrize(
    ("address", "pseudonym"),
    [
        ("10.1.2.3", "10.55.161.254"),
        ("8.8.8.8", "55.105.245.173"),
        ("192.0.2.7", "198.18.0.199"),
        ("100.64.1.1", "100.73.136.41"),
        ("2a00:1450::1", "2538:48c5:8252:24b8:cf7f:b0ae:a14d:863f"),
        ("fd00::1", "fc1d:2563:7a14:5e86:ef41:7c4:3cc1:a6e0"),
        ("c0de::1", "52b:a8fd:6c84:e97a:890:bc92:526c:110f"),
        ("::ffff:10.1.2.3", "::ffff:10.55.161.254"),
    ],
)
def test_address_known_answers(address: str, pseudonym: str) -> None:
    assert IPMapper(KEY, ["192.0.2.0/24"]).map_text(address) == pseudonym
