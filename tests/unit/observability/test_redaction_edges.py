"""Edge cases of argus.observability.redaction the other tests leave open (R1 mutation testing).

The exact marker each rule leaves (so a reader can still tell what was there), the escaped forms
of a registered secret, values that have a text form, and how dataclasses and pydantic models
are shown. Every key-shaped value here is synthetic.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import urllib.parse
from collections.abc import Iterator, Mapping
from datetime import UTC, date, datetime, time
from decimal import Decimal
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel

from argus.observability.redaction import (
    _first_letter_of,
    clear_registered_secrets,
    is_sensitive_key,
    redact,
    redact_text,
    register_secret,
)

PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END " + "RSA PRIVATE KEY-----"
WHEN = datetime(2026, 10, 10, 1, 2, 3, tzinfo=UTC)


# --------------------------------------------------------------------------- words and markers


@pytest.mark.parametrize("key", ["clientsecret", "setcookie"])
def test_compound_words_without_a_separator_are_secret(key: str) -> None:
    assert is_sensitive_key(key)
    assert redact_text(f"{key}=abc123") == f"{key}=***"


def test_every_word_list_must_start_with_letters() -> None:
    with pytest.raises(ValueError, match=r"^every word must start with a letter$"):
        _first_letter_of(("password", "_token"))


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ('{\\"password\\": \\"hunter22\\"}', '{\\"password\\": \\"***\\"}'),
        (
            '[[\\"Authorization\\", \\"Basic c3ludGhldGljOmZha2U=\\"]]',
            '[[\\"Authorization\\", \\"***\\"]]',
        ),
    ],
    ids=["value", "pair"],
)
def test_json_inside_a_json_string_keeps_its_escaped_quotes(text: str, masked: str) -> None:
    assert redact_text(text) == masked


@pytest.mark.parametrize(
    ("secret", "marker"),
    [
        (PEM, "-----PRIVATE KEY ***-----"),
        ("SCRAM-SHA-256$4096:" + "c2FsdA==$c3RvcmVk:c2VydmVy", "SCRAM-SHA-256$***"),
        ("gsk_" + "Ab1" * 8, "gsk_***"),
        ("sk-or-v1-" + "0f" * 16, "sk-or-v1-***"),
        ("sk-proj-" + "Zz9_" * 8, "sk-***"),
        ("AIza" + "Sy" * 18, "AIza***"),
        ("AQ." + "Qw" * 12, "AQ.***"),
        ("ghp_" + "a1" * 18, "gh_***"),
        ("xoxb-" + "1234567890-abcdef", "xox-***"),
    ],
    ids=["pem", "scram", "groq", "openrouter", "openai", "google", "ai-studio", "github", "slack"],
)
def test_each_shape_leaves_a_marker_of_what_it_was(secret: str, marker: str) -> None:
    assert redact_text(f"before {secret} after") == f"before {marker} after"


def test_text_over_one_mebibyte_is_cut_and_says_how_much() -> None:
    limit = 1 << 20
    assert redact_text("a" * limit) == "a" * limit
    assert redact_text("a" * (limit + 5)) == "a" * limit + "...<5 chars truncated>"


# --------------------------------------------------------------------------- registered secrets


def test_only_whole_registered_secrets_are_masked() -> None:
    secret = "Synthetic-Secret-9x"
    register_secret(secret)
    pieces = f"{secret[1:]} {secret[:-1]}"
    assert redact_text(pieces) == pieces
    assert redact_text(f"[{secret}]") == "[***]"


def test_a_secret_is_masked_in_json_written_without_ascii_escapes() -> None:
    secret = 'Synth\N{LATIN SMALL LETTER E WITH ACUTE}tique"Secret-7'
    register_secret(secret)
    assert redact_text(json.dumps({"note": secret}, ensure_ascii=False)) == '{"note": "***"}'


@pytest.mark.parametrize("quote", [urllib.parse.quote, urllib.parse.quote_plus])
def test_a_secret_is_masked_in_a_url(quote: Any) -> None:
    secret = "Synthetic/Secret 7&x"
    register_secret(secret)
    url = f"https://example.test/?q={quote(secret, safe='')}"
    assert redact_text(url) == "https://example.test/?q=***"


def test_cleared_secrets_are_no_longer_masked() -> None:
    register_secret("Synthetic-Secret-5")
    clear_registered_secrets()
    assert redact_text("Synthetic-Secret-5") == "Synthetic-Secret-5"


# --------------------------------------------------------------------------- values and objects


class _Colour(enum.Enum):
    PLAIN = "token=abc123"


class _BrokenMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("cannot be read")

    def __len__(self) -> int:
        return 1


def test_values_with_a_text_form_are_redacted_as_that_text() -> None:
    assert redact(WHEN) == "2026-10-10T01:02:03+00:00"
    assert redact(date(2026, 10, 10)) == "2026-10-10"
    assert redact(time(1, 2, 3)) == "01:02:03"
    assert redact(_Colour.PLAIN) == "token=***"
    uuid = "12345678-1234-5678-1234-567812345678"
    assert redact(UUID(uuid)) == uuid
    assert redact(Decimal("1.50")) == "1.50"
    assert redact(PurePosixPath("/srv/password=hunter22")) == "/srv/password=***"


def test_a_part_that_cannot_be_read_is_replaced_on_its_own() -> None:
    assert redact({"ok": "fine", "bad": _BrokenMapping()}) == {
        "ok": "fine",
        "bad": "<redaction-failed>",
    }


def test_each_mapping_level_counts_towards_the_depth_limit() -> None:
    deep: Any = "leaf"
    for _ in range(20):
        deep = {"a": deep}
    out = redact(deep)
    for _ in range(12):
        out = out["a"]
    assert out == "<max-depth>"


class _Login(BaseModel):
    user: str
    password: str
    since: datetime


@dataclasses.dataclass
class _Event:
    token: str
    at: datetime


def test_models_and_dataclasses_are_shown_through_their_fields() -> None:
    """Field by field: the key-name rule applies, and a value shows in its redacted form."""
    login = _Login(user="bob", password="hunter22", since=WHEN)
    assert redact(login) == (
        "_Login(user='bob', password='***', since='2026-10-10T01:02:03+00:00')"
    )
    assert redact(_Event("abc123", WHEN)) == "_Event(token='***', at='2026-10-10T01:02:03+00:00')"


@dataclasses.dataclass(repr=False)
class _Private:
    token: str


def _private_repr(self: object) -> str:
    return "_Private(<kept private>)"


_recursive_repr = getattr(dataclasses, "_recursive_repr", None)
if _recursive_repr is not None:
    _Private.__repr__ = _recursive_repr(_private_repr)  # type: ignore[method-assign]


def test_a_hand_written_repr_behind_the_recursion_wrapper_is_kept() -> None:
    """dataclasses wraps its generated __repr__ in a recursion guard; wrapped the same way, a
    hand-written one is still the class's own, and what it hides stays hidden."""
    if _recursive_repr is None:
        pytest.skip("this Python's dataclasses has no _recursive_repr")
    assert redact(_Private("abc123")) == "_Private(<kept private>)"


@dataclasses.dataclass
class _Generated:
    token: str = "abc123"


class _Borrowed:
    """Not a dataclass, but shown by a dataclass's generated __repr__."""

    __repr__ = _Generated.__repr__
    token = "abc123"


@dataclasses.dataclass(repr=False)
class _Child(_Borrowed):
    secret: str = "s3cret-value"


def test_a_generated_repr_shows_the_fields_of_the_class_it_was_made_for() -> None:
    """_Child's repr is _Generated's (inherited through _Borrowed), which shows token only."""
    assert redact(_Child()) == "_Child(token='***')"
