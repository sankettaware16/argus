"""Accepted residual gaps of redaction (DECISIONS.md D-038), pinned on purpose.

Each ``test_accepted_residual_d038_*`` test states what redaction does today in a case it is
known to get wrong: a leak, or a mask it should not apply. They are not goals. A change that
closes or widens a gap makes its test fail, and whoever makes that change updates the test and
D-038 together, so no gap changes by accident. Every credential-looking value is synthetic.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.observability.redaction import MASK, redact_text

UNREG = "fake-unreg-Rd3x7K2v"  # never registered: only the shape rules could catch it
LETTERS = "QwErTyUiOpAsDf"  # a letters-only credential: no digit or symbol gives it away

# A '"' followed by one of these closes a quoted string, so it ends a URL (redaction._URL_QUOTE).
_CLOSERS = ",:;)]}>"


# --------------------------------------------------------------------------- URL passwords


@pytest.mark.parametrize("closer", list(_CLOSERS))
def test_accepted_residual_d038_url_password_with_a_quote_before_a_closer_is_printed(
    closer: str,
) -> None:
    """The URL ends at that quote, before the "@", so nothing marks the password as one."""
    url = f'https://elastic:a"{closer}{UNREG}@10.0.0.9:9200/_search'
    for text in (
        f'postgresql://argus:x"{closer}y{UNREG}@db/argus',
        f'redis://user:sV3Hi{{5"{closer}E{UNREG}@cache:6379',
        json.dumps({"url": url}),
        repr(url),
    ):
        assert redact_text(text) == text


@pytest.mark.parametrize("closer", list(_CLOSERS))
def test_accepted_residual_d038_url_password_is_masked_only_up_to_an_at_before_such_a_quote(
    closer: str,
) -> None:
    text = f'postgresql://argus:p@x"{closer}y{UNREG}@db/argus'
    assert redact_text(text) == f'postgresql://argus:{MASK}@x"{closer}y{UNREG}@db/argus'


@pytest.mark.parametrize(
    "text",
    [
        '["http://h:9200","bob@example.org"]',
        '{"http://h:9200":"bob@example.org"}',
        'a="http://h:9200";b="bob@example.org"',
        'f("http://h:9200"),g("bob@example.org")',
        'hosts=["http://h:9200"]&notify=bob@example.org',
        'q={"url":"http://h:9200"}&notify=bob@example.org',
        '<a href="http://h:9200">bob@example.org</a>',
    ],
    ids=list(_CLOSERS),
)
def test_a_quote_before_a_closer_ends_the_url_so_the_text_after_it_is_kept(text: str) -> None:
    """Why the residual above exists: without it, the host and an address after the URL would be
    masked as if they were a password (compact JSON, markup, code)."""
    assert redact_text(text) == text


# Every visible ASCII character that may follow a '"' inside a URL password, plus a few others
# (whitespace ends a URL anyway, as the rule's comment says).
_NOT_CLOSERS = [
    char
    for char in (chr(code) for code in range(33, 127))
    if char not in _CLOSERS and char not in "@/?#"
] + ["\u00e4", "\u20ac"]


@pytest.mark.parametrize("after", _NOT_CLOSERS)
def test_a_quote_before_anything_but_a_closer_stays_inside_the_masked_password(after: str) -> None:
    """The residual is exactly the seven closers: a '"' followed by any other character is part
    of the password and masked with it (round-3 verification: adding "'" to the closers passed
    every test except a lucky property run)."""
    for text in (
        f'postgresql://argus:x"{after}y{UNREG}@db/argus',
        f'https://elastic:a"{after}{UNREG}@10.0.0.9:9200/_search',
    ):
        out = redact_text(text)
        assert UNREG not in out, (after, out)
        assert MASK in out


_QUOTE_BEFORE_A_CLOSER = re.compile(rf'"[{re.escape(_CLOSERS)}]')
_URL_PASSWORD_ALPHABET = (
    "".join(chr(code) for code in range(33, 127) if chr(code) not in "@/") + "äé€"
)
_URL_FORMS: dict[str, Callable[[str], str]] = {
    "plain": str,
    "repr": repr,
    "json": lambda url: json.dumps({"url": url}),
    "compact-json": lambda url: json.dumps({"url": url, "@t": 1}, separators=(",", ":")),
}


@given(
    password=st.text(alphabet=_URL_PASSWORD_ALPHABET, min_size=1, max_size=24).filter(
        lambda password: _QUOTE_BEFORE_A_CLOSER.search(password) is None
    ),
    template=st.sampled_from(
        [
            "postgresql://argus:{pw}@db.internal:5432/argus",
            "redis://user:{pw}@cache:6379",
            "https://elastic:{pw}@10.0.0.9:9200/_search?q=a",
        ]
    ),
    form=st.sampled_from(list(_URL_FORMS)),
)
def test_the_quote_residual_is_only_a_quote_before_a_closer(
    password: str, template: str, form: str
) -> None:
    """Any other '"' in a URL password is masked with the rest of it."""
    url = template.format(pw=f"{password}{UNREG}")
    assert UNREG not in redact_text(_URL_FORMS[form](url))


# --------------------------------------------------------------------------- list values


@pytest.mark.parametrize(
    ("text", "redacted"),
    [
        (
            f"{{'credentials': [('user', '{UNREG}')]}}",
            f"{{'credentials': [('{MASK}', '{UNREG}')]}}",
        ),
        (f'{{"token": [["a", "{UNREG}"]]}}', f'{{"token": [["{MASK}", "{UNREG}"]]}}'),
        (f'secret: ["a", "b {UNREG}"].', f'secret: ["{MASK}", "b {UNREG}"].'),
        (f"password=['a b', '{UNREG}']:", f"password=['{MASK} b', '{UNREG}']:"),
        (f'{{"secret": {{"value": "{UNREG}"}}}}', f'{{"secret": {MASK}"value": "{UNREG}"}}}}'),
    ],
    ids=["nested-tuple", "nested-list", "list-then-full-stop", "list-then-colon", "object-value"],
)
def test_accepted_residual_d038_an_unparseable_list_value_has_only_its_first_token_masked(
    text: str, redacted: str
) -> None:
    """A value that opens with "[", "(" or "{" but is not a flat list that ends the value is
    masked as an unquoted value, which stops at the first whitespace, quote, comma, semicolon,
    "&" or "}"."""
    assert redact_text(text) == redacted


# --------------------------------------------------------------------------- pairs


@pytest.mark.parametrize(
    ("text", "redacted"),
    [
        ('fields=["password", "user.name"]', f'fields=["password", "{MASK}"]'),
        ("cfg.get('password', 'default')", f"cfg.get('password', '{MASK}')"),
        ("redact_fields=('password', 'token')", f"redact_fields=('password', '{MASK}')"),
        ("args=('password', 'confirm_password')", f"args=('password', '{MASK}')"),
        ("WHERE k IN ('token', 'bob')", f"WHERE k IN ('token', '{MASK}')"),
    ],
)
def test_accepted_residual_d038_a_two_item_list_after_a_secret_name_loses_its_second_item(
    text: str, redacted: str
) -> None:
    """The pair rule reads any two-item list or call whose first string is a sensitive key name
    as ('name', 'value'), as in raw header lists; a list of three or more names is kept."""
    assert redact_text(text) == redacted


# --------------------------------------------------------------------------- scheme words


@pytest.mark.parametrize(
    ("scheme", "text"),
    [
        ("Basic", f"sending Basic {LETTERS} upstream"),
        ("Bearer", f"retry with Bearer {LETTERS} now"),
        ("Token", f"Token {LETTERS} was rejected"),
    ],
)
def test_accepted_residual_d038_a_letters_only_credential_after_a_scheme_word_in_prose_is_kept(
    scheme: str, text: str
) -> None:
    """In prose a word after Basic/Bearer/Token/ApiKey is masked only if it looks like a
    credential, so "Basic licence." stays readable; in a header the same word is masked."""
    assert redact_text(text) == text
    assert redact_text(f"Authorization: {scheme} {LETTERS}") == f"Authorization: {scheme} {MASK}"
