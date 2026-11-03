"""Redaction tests. All key-shaped values here are synthetic — never real credentials."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.observability.redaction import (
    MASK,
    is_sensitive_key,
    redact,
    redact_text,
    register_secret,
)

FAKE_GROQ = "gsk_" + "Ab1" * 18
FAKE_OPENROUTER = "sk-or-v1-" + "0f" * 32
FAKE_OPENAI = "sk-proj-" + "Zz9_" * 8
FAKE_GOOGLE = "AIza" + "Sy" * 18
FAKE_AISTUDIO = "AQ.Ab8" + "Qw" * 20
FAKE_GITHUB = "ghp_" + "a1" * 18
FAKE_ES_APIKEY = "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWORD",
        "db_password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh-token",
        "api_key",
        "apikey",
        "apiKey",
        "x-api-key",
        "API-KEY",
        "authorization",
        "Authorization",
        "auth",
        "cookie",
        "set-cookie",
        "credential",
        "credentials",
        "private_key",
        "session_id",
        "access_key",
        "elastic.api_key",
    ],
)
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)
    assert redact({key: "value"}) == {key: MASK}


@pytest.mark.parametrize(
    "key",
    [
        "token_count",
        "max_tokens",
        "tokens",
        "author",
        "authority",
        "password_policy",
        "keyword",
        "monkey",
        "secretary",
        "user",
        "event",
        "url",
        "host",
        "api_version",
    ],
)
def test_ordinary_keys_are_kept(key: str) -> None:
    assert not is_sensitive_key(key)
    assert redact({key: "value"}) == {key: "value"}


def test_non_string_keys() -> None:
    assert not is_sensitive_key(42)
    assert redact({42: "x", None: "y"}) == {42: "x", None: "y"}


def test_none_under_sensitive_key_is_kept() -> None:
    assert redact({"password": None}) == {"password": None}


def test_nested_structures() -> None:
    value = {"a": {"b": [{"password": "x"}, ("api_key", {"token": "y"})]}, "n": 3, "f": 1.5}
    assert redact(value) == {
        "a": {"b": [{"password": MASK}, ("api_key", {"token": MASK})]},
        "n": 3,
        "f": 1.5,
    }


def test_registered_secret_masked_everywhere() -> None:
    secret = "hunter2-hunter2"
    register_secret(secret)
    value = {
        "msg": f"connecting with {secret}!",
        "list": [secret, b"bytes:" + secret.encode()],
        "error": ValueError(f"bad {secret}"),
        f"key-{secret}": "v",
    }
    rendered = str(redact(value))
    assert secret not in rendered
    assert MASK in rendered


def test_short_values_are_not_registered() -> None:
    register_secret("abc")
    register_secret("")
    register_secret(None)
    assert redact_text("abc abc") == "abc abc"


def test_overlapping_secrets_longest_first() -> None:
    register_secret("secret-long-value")
    register_secret("long-value")
    assert redact_text("x secret-long-value y long-value") == f"x {MASK} y {MASK}"


def test_secret_containing_the_mask_cannot_reappear() -> None:
    # One pass turns "qq***r1r1" into "q***r1" — the secret again. It must still end up masked.
    register_secret("q***r1")
    assert "q***r1".replace("q***r1", MASK) == MASK
    assert "qq***r1r1".replace("q***r1", MASK) == "q***r1"
    out = redact_text("qq***r1r1")
    assert "q***r1" not in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "postgresql+psycopg://argus:s3cr3t@127.0.0.1:55432/argus",  # fake-secret
            f"postgresql+psycopg://argus:{MASK}@127.0.0.1:55432/argus",
        ),
        (
            "https://elastic:pa55w0rd@10.0.0.1:9200/_search",  # fake-secret
            f"https://elastic:{MASK}@10.0.0.1:9200/_search",
        ),
        ("https://user@host/path", "https://user@host/path"),
        ("plain text without credentials", "plain text without credentials"),
    ],
)
def test_url_userinfo(text: str, expected: str) -> None:
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: ApiKey {FAKE_ES_APIKEY}",
        "authorization: Bearer abc.def-ghi_jkl",
        "Authorization: Basic ZWxhc3RpYzpzZWNyZXQ=",
        "Token 1234567890abcdef",
    ],
)
def test_authorization_schemes(text: str) -> None:
    out = redact_text(text)
    assert MASK in out
    assert FAKE_ES_APIKEY not in out
    assert "ZWxhc3RpYzpzZWNyZXQ=" not in out


@pytest.mark.parametrize(
    "text",
    [
        "password=hunter2&user=bob",
        "?api_key=abcd1234&x=1",
        '{"token": "abcd1234", "user": "bob"}',
        "secret: abcd1234",
        "PWD=abcd1234",
        "client_secret='abcd1234'",
    ],
)
def test_key_value_pairs_in_text(text: str) -> None:
    out = redact_text(text)
    assert "abcd1234" not in out
    assert "hunter2" not in out
    assert MASK in out


@pytest.mark.parametrize(
    "fake", [FAKE_GROQ, FAKE_OPENROUTER, FAKE_OPENAI, FAKE_GOOGLE, FAKE_AISTUDIO, FAKE_GITHUB]
)
def test_provider_key_formats(fake: str) -> None:
    out = redact_text(f"calling provider with {fake} now")
    assert fake not in out
    assert MASK in out
    assert out.startswith("calling provider with ")


def test_private_key_block() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----"  # fake-secret
        "\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----"
    )
    out = redact_text(f"key:\n{pem}\nafter")
    assert "MIIEow" not in out
    assert out.endswith("after")


def test_unterminated_private_key_block_is_masked_to_end() -> None:
    out = redact_text("-----BEGIN PRIVATE KEY-----\nMIIEow-truncated")  # fake-secret
    assert "MIIEow" not in out


def test_exceptions_and_objects() -> None:
    register_secret("object-secret-1")

    class Thing:
        def __repr__(self) -> str:
            return "Thing(object-secret-1)"

    assert redact(ValueError("password=abc123")) == f"ValueError: password={MASK}"
    assert "object-secret-1" not in redact(Thing())
    assert redact(SecretStr("zzz-secret")) == "SecretStr('**********')"


def test_broken_repr_only_affects_that_value() -> None:
    class Broken:
        def __repr__(self) -> str:
            raise RuntimeError("boom")

    assert redact({"ok": "fine", "bad": Broken()}) == {"ok": "fine", "bad": "<unrepresentable>"}


def test_cycles_and_depth() -> None:
    cyclic: dict[str, Any] = {"a": 1}
    cyclic["self"] = cyclic
    assert redact(cyclic) == {"a": 1, "self": "<cycle>"}

    deep: Any = "leaf"
    for _ in range(50):
        deep = [deep]
    out = redact(deep)
    for _ in range(12):
        out = out[0]
    assert out == "<max-depth>"


def test_shared_references_are_not_cycles() -> None:
    shared = {"password": "x"}
    assert redact({"a": shared, "b": shared}) == {"a": {"password": MASK}, "b": {"password": MASK}}


def test_sets_and_bytes() -> None:
    assert sorted(redact({"password=abc12345", "plain"})) == [f"password={MASK}", "plain"]
    assert redact(bytearray(b"token=abc12345")) == f"token={MASK}"
    assert redact(b"\xff\xfe") == "��"


# --------------------------------------------------------------------------- properties

_safe_text = st.text(alphabet=st.characters(blacklist_categories=["Cs"]), max_size=40)


@given(
    secret=st.text(min_size=6, max_size=30).filter(lambda s: s.strip() == s and s),
    prefix=_safe_text,
    suffix=_safe_text,
)
def test_registered_secret_never_survives(secret: str, prefix: str, suffix: str) -> None:
    from argus.observability.redaction import clear_registered_secrets

    clear_registered_secrets()
    register_secret(secret)
    assert secret not in redact_text(prefix + secret + suffix)
    assert secret not in str(redact({"x": [prefix, {"y": prefix + secret + suffix}]}))
    clear_registered_secrets()


_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | _safe_text,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(_safe_text, children, max_size=4)
    ),
    max_leaves=25,
)


@given(_json)
def test_redact_never_raises_and_keeps_shape(value: Any) -> None:
    out = redact(value)
    if isinstance(value, dict):
        assert isinstance(out, dict)
        assert len(out) <= len(value)
    if isinstance(value, list):
        assert isinstance(out, list)
        assert len(out) == len(value)
