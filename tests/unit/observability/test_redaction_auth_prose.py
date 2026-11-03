"""Regression (R1 verification round 2): a prose key word, ":" and a known auth scheme.

Round 2 made "auth:" / "credentials:" prose words (so "auth: failed for user bob" stays
readable), which left letters-only credentials after a known scheme unmasked. All values here
are synthetic.
"""

from __future__ import annotations

import pytest

from argus.observability.redaction import MASK, redact_text

LETTERS_ONLY = "QwErTyUiOpAsDfGh"  # a credential with no digit or symbol
BASE64_LETTERS = "dXNlcjpwYXNz"


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        (f"auth: Basic {BASE64_LETTERS}", "auth: Basic "),
        (f"Auth: Bearer {LETTERS_ONLY}", "Auth: Bearer "),
        (f"X-Auth: Bearer {LETTERS_ONLY}", "X-Auth: Bearer "),
        (f"credentials: Basic {BASE64_LETTERS}", "credentials: Basic "),
        (f"proxy_auth: Basic {BASE64_LETTERS}", "proxy_auth: Basic "),
        (f"upstream auth: Basic {BASE64_LETTERS}", "upstream auth: Basic "),
        (f"Auth:Bearer {LETTERS_ONLY}", "Auth:Bearer "),
        (f"auth: token {LETTERS_ONLY}", "auth: token "),
        (f"AUTH: APIKEY {LETTERS_ONLY}", "AUTH: APIKEY "),
    ],
)
def test_prose_key_then_known_scheme_is_masked(text: str, kept: str) -> None:
    out = redact_text(text)
    assert LETTERS_ONLY not in out
    assert BASE64_LETTERS not in out
    assert out == kept + MASK


@pytest.mark.parametrize(
    "text",
    [
        "auth: failed for user bob",
        "ldap auth: user not found",
        "credentials: none configured",
        "auth: basically fine",  # "basic" must be a whole word to count as a scheme
    ],
)
def test_prose_without_a_scheme_stays_readable(text: str) -> None:
    assert redact_text(text) == text
