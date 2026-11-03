"""Mapping keys: which key names are secret, and keys made text by the consumers of redact().

redact() keeps a mapping's keys as they are (an int key stays an int). Its consumers turn them
into text: log records (argus.observability.logs) and audit details (argus.db.audit), where
JSON makes ``1`` and ``"1"`` the same key. Every entry must survive that (R1 verification
round 2: record_audit kept only the last of such keys). All values here are synthetic.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy.ext.asyncio import AsyncSession

from argus.db.audit import AuditError, record_audit
from argus.db.models import AuditEvent
from argus.observability import redaction
from argus.observability.redaction import MASK, distinct_keys, is_sensitive_key, redact, redact_text

UNREG = "fake-unreg-Kq3w8Z1x"  # never registered: only the shape and key-name rules catch it


class _Session:
    """Stands in for an AsyncSession: record_audit only adds the event and flushes."""

    def add(self, event: AuditEvent) -> None:
        self.event = event

    async def flush(self) -> None:
        return None


async def _stored(details: Mapping[Any, Any]) -> Any:
    """The details record_audit gives the database: redacted, encoded as JSON and decoded."""
    session = cast(AsyncSession, _Session())
    event = await record_audit(session, actor="test", action="unit.test", details=details)
    return event.details


def _entries(value: Any) -> int:
    """The number of mapping entries in ``value``, at every depth."""
    if isinstance(value, dict):
        return len(value) + sum(_entries(item) for item in value.values())
    if isinstance(value, list | tuple):
        return sum(_entries(item) for item in value)
    return 0


# --------------------------------------------------------------------------- audit details


async def test_audit_detail_keys_stored_as_the_same_json_text_are_all_kept() -> None:
    assert await _stored({1: "int", "1": "str"}) == {"1 (int)": "int", "1": "str"}
    assert await _stored({None: "none", "null": "str"}) == {
        "null (NoneType)": "none",
        "null": "str",
    }
    assert await _stored({True: "bool", "true": "str"}) == {"true (bool)": "bool", "true": "str"}
    assert await _stored({"a\x00": "nul", "a\ufffd": "fffd"}) == {
        "a\ufffd": "nul",
        "a\ufffd (str)": "fffd",
    }


async def test_a_str_detail_key_keeps_its_text_wherever_it_is() -> None:
    assert await _stored({"1": "str", 1: "int"}) == {"1": "str", "1 (int)": "int"}
    assert await _stored({1: "int", "1": "str", "1 (int)": "taken"}) == {
        "1 (int 2)": "int",
        "1": "str",
        "1 (int)": "taken",
    }


async def test_audit_detail_keys_that_do_not_collide_are_stored_the_json_way() -> None:
    assert await _stored({7: "int", 2.5: "float", False: "bool", None: "none", "s": "str"}) == {
        "7": "int",
        "2.5": "float",
        "false": "bool",
        "null": "none",
        "s": "str",
    }


@pytest.mark.parametrize(
    "key",
    [("tuple", "key"), frozenset({1}), math.nan, math.inf],
    ids=["tuple", "frozenset", "nan", "inf"],
)
async def test_audit_detail_keys_that_json_refuses_are_still_an_audit_error(key: object) -> None:
    with pytest.raises(AuditError, match="JSON"):
        await _stored({key: 1})


# Keys whose stored text can coincide: JSON text of scalars, NUL and lone surrogates (stored as
# U+FFFD), names a renamed key would take, and bytes (redact() decodes them).
_COLLIDING_KEYS: list[object] = [
    *("1", "null", "true", "false", "2.5", "a", "a\x00", "a\ufffd", "1 (int)", "null (NoneType)"),
    *(1, 0, True, False, None, 2.5, -0.0, 1e100, b"1", b"a", "a\ud800"),
]
_detail_keys = st.one_of(st.sampled_from(_COLLIDING_KEYS), st.text(max_size=3))
# One level of nesting, in a mapping and in a list, reaches every branch of the key handling.
_flat_details = st.dictionaries(_detail_keys, st.integers(), max_size=6)
_detail_values = st.one_of(
    st.integers() | st.text(max_size=3) | st.none(),
    _flat_details,
    st.lists(_flat_details, max_size=2),
)


@given(st.dictionaries(_detail_keys, _detail_values, max_size=8))
async def test_record_audit_keeps_every_entry_of_the_redacted_details(
    details: dict[Any, Any],
) -> None:
    stored = await _stored(details)
    assert _entries(stored) == _entries(redact(details))


# --------------------------------------------------------------------------- distinct_keys


def test_distinct_keys_follow_their_documented_rule() -> None:
    """Of the keys shown the same way, the first str key keeps the text (the first key, if none
    is a str); each of the others gets its type appended, numbered if that name is taken."""
    assert distinct_keys([(1, "1"), ("1", "1")]) == ["1 (int)", "1"]
    assert distinct_keys([(b"1", "1"), (1, "1")]) == ["1", "1 (int)"]
    assert distinct_keys([("token=A", f"token={MASK}"), ("token=B", f"token={MASK}")]) == [
        f"token={MASK}",
        f"token={MASK} (str)",
    ]
    assert distinct_keys([(1, "1"), ("1", "1"), ("1 (int)", "1 (int)")]) == [
        "1 (int 2)",
        "1",
        "1 (int)",
    ]


# --------------------------------------------------------------------------- spaced key words

_SPACED_WORDS = (
    "session id",
    "api key",
    "access key",
    "secret key",
    "private key",
    "client secret",
)


def test_the_key_name_pattern_has_no_spaced_words() -> None:
    """is_sensitive_key turns whitespace into "_" before matching, so an alternative with a space
    could never match a key (R1 verification round 2 found these six in the key pattern)."""
    pattern = redaction._SENSITIVE_KEY.pattern
    assert [word for word in _SPACED_WORDS if word in pattern] == []


@pytest.mark.parametrize("word", _SPACED_WORDS)
def test_spaced_secret_words_are_key_names_through_their_underscore_form(word: str) -> None:
    for key in (word, word.title(), word.upper(), word.replace(" ", " \t "), f"x {word}"):
        assert is_sensitive_key(key), key
        assert redact({key: UNREG}) == {key: MASK}


@pytest.mark.parametrize("word", _SPACED_WORDS)
def test_spaced_secret_words_mask_assigned_or_quoted_values_in_text(word: str) -> None:
    assert redact_text(f"{word}={UNREG}") == f"{word}={MASK}"
    assert redact_text(f'{word}: "{UNREG}"') == f'{word}: "{MASK}"'
