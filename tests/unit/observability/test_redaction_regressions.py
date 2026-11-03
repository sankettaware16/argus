"""Regression tests for redaction fix round 2 (docs/reviews/2026-10-10-r1-fix-round-1.md).

Every credential-looking value here is synthetic.
"""

from __future__ import annotations

import collections
import dataclasses
import io
import json
import logging
import signal
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, NamedTuple

import pytest
import structlog
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, Field

from argus.observability.logs import configure_logging, get_logger
from argus.observability.redaction import (
    MASK,
    distinct_keys,
    is_sensitive_key,
    redact,
    redact_text,
    register_secret,
)

UNREG = "fake-unreg-Rd2x9Q4w"  # never registered: only shape / key-name rules can catch it
UNREG2 = "fake-unreg-Lk7m3Z8p"
LETTERS = "QwErTyUiOpAsDfGh"  # a letters-only credential: no digit or symbol to give it away
SECRET = "fake-secret-Rd2Reg77"


@pytest.fixture
def json_stream() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging("DEBUG", "json", stream=stream)
    yield stream
    structlog.contextvars.clear_contextvars()
    configure_logging("WARNING", "console", stream=io.StringIO())


def _records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


class _TookTooLongError(BaseException):
    """BaseException on purpose: redact()'s ``except Exception`` must not swallow the deadline."""


@contextmanager
def _hard_deadline(seconds: float) -> Iterator[None]:
    def _expire(_signum: int, _frame: object) -> None:
        raise _TookTooLongError

    previous = signal.signal(signal.SIGALRM, _expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _seconds(fn: Callable[[], object], hard_limit: float = 3.0) -> float:
    """Wall time of ``fn()``; ``inf`` if it had to be interrupted at ``hard_limit``."""
    start = time.perf_counter()
    try:
        with _hard_deadline(hard_limit):
            fn()
    except _TookTooLongError:
        return float("inf")
    return time.perf_counter() - start


# --------------------------------------------------------------------------- URL userinfo

# Characters that are never unencoded in a well-formed URL, but are in generated passwords.
_URL_SPECIALS = ['"', "<", ">", "{", "}", "|", "\\", "^", "`"]
_URL_CONTEXTS = {
    "dsn-with-path": "connecting to postgresql://argus:{pw}@db.internal:5432/argus failed",
    "no-path": "redis://user:{pw}@cache:6379",
    "in-json-value": '{{"dsn": "postgresql://argus:{pw}@db/argus"}}',
    "at-sign-in-password": "https://elastic:p@{pw}@10.0.0.9:9200/_search",
}


@pytest.mark.parametrize("char", _URL_SPECIALS)
@pytest.mark.parametrize("template", list(_URL_CONTEXTS.values()), ids=list(_URL_CONTEXTS))
def test_url_password_with_any_special_character_is_masked(template: str, char: str) -> None:
    """Round 1 ended the password at " < > { } | \\ ^ ` and printed such passwords in full."""
    for password in (f"pa{char}ss{UNREG}", f"{char}{UNREG}", f"{UNREG}{char}"):
        out = redact_text(template.format(pw=password))
        assert UNREG not in out, (char, out)
        assert f":{MASK}@" in out


@pytest.mark.parametrize("char", _URL_SPECIALS)
def test_url_password_is_masked_in_repr_and_json_escaped_forms(char: str) -> None:
    url = f"https://elastic:a{char}{UNREG}@10.0.0.9:9200/_search"  # fake-secret
    for text in (repr(url), repr({"url": url}), json.dumps({"url": url}), str([url])):
        out = redact_text(text)
        assert UNREG not in out, (char, out)
        assert "@10.0.0.9:9200/_search" in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://u:pw@host?email=a@b.org", f"https://u:{MASK}@host?email=a@b.org"),
        ("https://u:pw@host#to=a@b.org", f"https://u:{MASK}@host#to=a@b.org"),
        ("https://u:p@w@host?email=a@b.org", f"https://u:{MASK}@host?email=a@b.org"),
        (
            '{"url":"http://u:pw@h:9200","@timestamp":"2026-10-10T00:00:00Z"}',
            f'{{"url":"http://u:{MASK}@h:9200","@timestamp":"2026-10-10T00:00:00Z"}}',
        ),
    ],
    ids=["query-with-email", "fragment-with-at", "at-in-password", "compact-json-ecs"],
)
def test_url_host_is_kept_when_an_at_sign_follows_the_host(text: str, expected: str) -> None:
    """The password ends at the last "@" before "/", "?" or "#", as urllib splits a URL."""
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    "password",
    [f"47?{UNREG}", f"#{UNREG}{{?]", f"?{UNREG}", f"7?|N61od`{UNREG}", f"/{UNREG}"],
    ids=["digits-query", "leading-hash", "leading-query", "digits-query-symbols", "leading-slash"],
)
@pytest.mark.parametrize(
    "template",
    [
        "redis://user:{pw}@cache:6379",
        "postgresql://argus:{pw}@db.internal:5432/argus",
        "'https://elastic:{pw}@10.0.0.9:9200/_search'",
    ],
)
def test_url_password_starting_like_a_port_or_query_is_masked(template: str, password: str) -> None:
    out = redact_text(template.format(pw=password))
    assert UNREG not in out, out


@pytest.mark.parametrize(
    "text",
    [
        '{"url":"http://h:9200","to":"a@b"}',
        '["http://h:9200","bob@example.org"]',
        '<a href="http://h:9200">mail bob@example.org</a>',
        "http://kibana:5601?next=/app&user=a@b.org",
        "http://kibana.internal:5601/app/discover#/?_a=(query:'user@example.org')",
        "GET https://10.0.0.9:9200/_search?q=user:bob@example.org",
        "cloning ssh://git@github.com:22/org/repo.git",
    ],
)
def test_url_without_credentials_is_kept(text: str) -> None:
    assert redact_text(text) == text


_URL_PASSWORD_ALPHABET = (
    "".join(chr(code) for code in range(33, 127) if chr(code) not in '@/"') + "äé€"
)


@given(
    password=st.text(alphabet=_URL_PASSWORD_ALPHABET, min_size=1, max_size=24),
    template=st.sampled_from(
        [
            "postgresql://argus:{pw}@db.internal:5432/argus",
            "redis://user:{pw}@cache:6379",
            "x {{'dsn': 'postgresql://:{pw}@db/argus'}} y",
            "https://elastic:{pw}@10.0.0.9:9200/_search?q=a",
        ]
    ),
)
def test_url_password_never_survives(password: str, template: str) -> None:
    marked = f"{password}{UNREG}"  # a fixed tail to look for, after random special characters
    assert UNREG not in redact_text(template.format(pw=marked))


# --------------------------------------------------------------------------- generated reprs


@dataclasses.dataclass(repr=False)
class _ApiKeyAuth:
    key_id: str
    key: str

    def __repr__(self) -> str:
        return f"_ApiKeyAuth(key_id={self.key_id!r}, key='<hidden>')"


@dataclasses.dataclass
class _HandWritten:
    """repr=True (the default), but a __repr__ in the class body wins over the generated one."""

    name: str
    material: str

    def __repr__(self) -> str:
        return f"_HandWritten(name={self.name!r})"


@dataclasses.dataclass
class _Endpoint:
    host: str


@dataclasses.dataclass(repr=False)
class _EndpointWithMaterial(_Endpoint):
    """Inherits _Endpoint's generated repr, which shows only ``host``."""

    material: str


class _MaskingModel(BaseModel):
    name: str
    material: str

    def __repr__(self) -> str:
        return f"_MaskingModel(name={self.name!r}, material=<hidden>)"


class _MaskingReprStrModel(BaseModel):
    name: str
    material: str

    def __repr_str__(self, join_str: str) -> str:
        return f"name={self.name!r}"


class _MaskingTuple(NamedTuple):
    name: str
    material: str

    def __repr__(self) -> str:
        return f"_MaskingTuple(name={self.name!r}, material=<hidden>)"


@pytest.mark.parametrize(
    "value",
    [
        _ApiKeyAuth("kid-1", UNREG),
        _HandWritten("n", UNREG),
        _EndpointWithMaterial("db.internal", UNREG),
        _MaskingModel(name="n", material=UNREG),
        _MaskingReprStrModel(name="n", material=UNREG),
        _MaskingTuple("n", UNREG),
    ],
    ids=lambda value: type(value).__name__,
)
def test_a_class_with_its_own_repr_is_redacted_through_it(value: object) -> None:
    """Round 1 rendered these field by field and printed the values their repr hides."""
    out = redact({"v": value})
    assert UNREG not in str(out)
    assert out == {"v": redact_text(repr(value))}


def test_generated_reprs_still_mask_fields_by_name() -> None:
    @dataclasses.dataclass
    class Creds:
        user: str
        newPassWord: str  # noqa: N815 - JSON-style field name on purpose

    class Model(BaseModel):
        user: str
        api_token: str
        hidden: str = Field(repr=False)

    assert redact(Creds("bob", UNREG)) == f"Creds(user='bob', newPassWord='{MASK}')"
    assert redact(Model(user="bob", api_token=UNREG, hidden=UNREG2)) == (
        f"Model(user='bob', api_token='{MASK}')"
    )


# --------------------------------------------------------------------------- named tuples


class _Point(NamedTuple):
    x: int
    y: int


class _Login(NamedTuple):
    user: str
    password: str


def test_named_tuples_stay_structures_with_sensitive_fields_masked() -> None:
    """Round 1 turned named tuples into strings ('Point(x=1, y=2)'), a schema change."""
    point_class = collections.namedtuple("point_class", "x y")
    assert redact({"p": _Point(1, 2)}) == {"p": (1, 2)}
    assert redact({"p": point_class(1, 2)}) == {"p": (1, 2)}
    assert redact([_Login("bob", UNREG)]) == [("bob", MASK)]
    assert redact(_Login("bob", None)) == ("bob", None)  # type: ignore[arg-type]


def test_named_tuples_render_as_json_arrays_in_logs(json_stream: io.StringIO) -> None:
    get_logger("argus.test").info("moved", to=_Point(1, 2), login=_Login("bob", UNREG))
    (record,) = _records(json_stream)
    assert record["to"] == [1, 2]
    assert record["login"] == ["bob", MASK]
    assert UNREG not in json_stream.getvalue()


# --------------------------------------------------------------------------- key names


@pytest.mark.parametrize(
    "key",
    [
        "passWord",
        "PassWord",
        "PassWd",
        "PassPhrase",
        "userPassWord",
        "newPassWord",
        "KeyPassPhrase",
    ],
)
def test_key_names_with_capitals_inside_the_word_are_sensitive(key: str) -> None:
    """Round 1 matched only the camelCase-split key ("pass_Word"), so these were kept."""
    assert is_sensitive_key(key)
    assert is_sensitive_key(key.encode())
    assert redact({key: UNREG}) == {key: MASK}


@pytest.mark.parametrize(
    "key", ["TokenCount", "isPasswordSet", "OAuth", "csrftoken", "PassWordPolicy"]
)
def test_capitalised_lookalike_key_names_are_not_sensitive(key: str) -> None:
    assert not is_sensitive_key(key)


def test_login_body_with_camel_case_password_is_masked_in_logs(json_stream: io.StringIO) -> None:
    get_logger("argus.test").info("user update", body={"userName": "bob", "passWord": UNREG})
    (record,) = _records(json_stream)
    assert record["body"] == {"userName": "bob", "passWord": MASK}


# --------------------------------------------------------------------------- list values, pairs


@pytest.mark.parametrize(
    "text",
    [
        f'{{"Authorization": ["Basic {LETTERS}"]}}',
        f"{{'Authorization': ['Basic {LETTERS}', 'Bearer {UNREG}']}}",
        f"authorization: ['{LETTERS}']",
        f'http.request.headers={{"Authorization":["Bearer {LETTERS}"]}}',
        f'{{\\"authorization\\": [\\"{LETTERS}\\"]}}',
        f'{{"access_token": ["{UNREG}"]}}',
        f"{{'password': ('{UNREG}',)}}",
        f'{{"api_key": [\n  "{UNREG}",\n  "{LETTERS}"\n]}}',
        f'{{"credentials": ["{UNREG}"]}}',
    ],
    ids=[
        "json-header-list",
        "repr-multi-value-header",
        "repr-header-list",
        "ecs-header-array",
        "json-in-json-list",
        "json-token-list",
        "repr-password-tuple",
        "pretty-printed-json-list",
        "prose-word-with-list",
    ],
)
def test_list_valued_credentials_are_fully_masked(text: str) -> None:
    """Round 1 masked only the "[" and printed the credential right after the mask."""
    out = redact_text(text)
    assert LETTERS not in out
    assert UNREG not in out
    assert f"[{MASK}]" in out or f"({MASK})" in out


@pytest.mark.parametrize(
    "text",
    [
        f"[('Authorization', 'Bearer {LETTERS}')]",
        f"[(b'host', b'example.org'), (b'authorization', b'Basic {LETTERS}')]",
        f'[["Authorization","Basic {LETTERS}"]]',
        f"('Proxy-Authorization', 'Basic {LETTERS}')",
        f"[('access_token', '{UNREG}'), ('page', '2')]",
        f"('Cookie', 'sid={UNREG}')",
        f"('auth', '{UNREG}')",
    ],
    ids=[
        "header-tuple",
        "asgi-raw-headers",
        "json-pair",
        "proxy-authorization",
        "query-param-pairs",
        "cookie-pair",
        "prose-word-pair",
    ],
)
def test_credentials_in_name_value_pairs_are_masked(text: str) -> None:
    """Round 1 printed letters-only credentials in header tuples (and any value in pairs)."""
    out = redact_text(text)
    assert LETTERS not in out
    assert UNREG not in out
    assert MASK in out


def test_header_pairs_keep_their_shape() -> None:
    assert redact_text(f"[('Authorization', 'Bearer {LETTERS}')]") == (
        f"[('Authorization', '{MASK}')]"
    )
    assert redact_text(f"[(b'authorization', b'{LETTERS}'), (b'host', b'h')]") == (
        f"[(b'authorization', b'{MASK}'), (b'host', b'h')]"
    )


@pytest.mark.parametrize(
    "text",
    [
        "redact_headers=('authorization', 'cookie', 'x-api-key')",
        "fields: ['password', 'email', 'name']",
        '{"token": [], "password": ()}',
    ],
)
def test_lists_of_names_and_empty_lists_are_kept(text: str) -> None:
    """Lists of three or more names. A two-item list is read as a ('name', 'value') pair: an
    accepted residual (D-038), pinned in test_redaction_residuals.py."""
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "[(b'host', b'example.org'), (b'user-agent', b'curl/8.5')]",
        "params=[('page', '2'), ('q', 'author:bob')]",
        '[["Content-Type","application/json"],["X-Request-Id","r-1"]]',
        "('token_count', '42')",
    ],
)
def test_pairs_with_ordinary_names_are_kept(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        f"https://h/x?secret=(29G%i0N<{UNREG}]pMwdD&page=2",
        f"api_key=(#zL*uRa!){UNREG}",
        f"retry with token=[9HU7mmx{{.q#){UNREG}]%7H now",
        f"password=[{UNREG}",
        f"password=[]{UNREG}",
        f'{{"token": ["{UNREG}',
        f"token=[[{UNREG}]]",
    ],
)
def test_bracketed_unquoted_values_are_masked_to_their_end(text: str) -> None:
    """A value that only starts like a list is masked as one unquoted value."""
    out = redact_text(text)
    assert UNREG not in out
    assert MASK in out


def test_list_valued_headers_are_masked_in_logs(json_stream: io.StringIO) -> None:
    logging.getLogger("thirdparty").warning("headers %s", [("Authorization", f"Basic {LETTERS}")])
    logging.getLogger("thirdparty").warning("headers %s", {"Authorization": [f"Basic {LETTERS}"]})
    assert LETTERS not in json_stream.getvalue()
    assert [r["event"] for r in _records(json_stream)] == [
        f"headers [('Authorization', '{MASK}')]",
        f"headers {{'Authorization': [{MASK}]}}",
    ]


# --------------------------------------------------------------------------- scheme words in prose


@pytest.mark.parametrize(
    "text",
    [
        "Elastic cluster runs on the Basic licence.",
        "Token refreshed.",
        "expected a Bearer token.",
        "Basic read-only access is enabled",
        "Token auto-refresh enabled",
        "Basic e.g. password login",
        "Bearer token-based auth.",
    ],
)
def test_auth_scheme_words_before_punctuated_prose_are_kept(text: str) -> None:
    """A trailing full stop or a single hyphen does not make a word a credential."""
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "credential",
    [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        "abcdef.ghijkl.mnopqr",
        "abc-def-ghi",
        "dXNlcjpwYXNzd29yZA==",
        "1234567890abcdef",
        "fake_token_value",
        "QwErTyUiOpAsDfGhJkLzXcVbNmQwErTyU",
    ],
)
def test_credentials_after_a_scheme_word_are_still_masked(credential: str) -> None:
    out = redact_text(f"retrying with Bearer {credential} now")
    assert credential not in out
    assert out == f"retrying with Bearer {MASK} now"


# --------------------------------------------------------------------------- prose key words


@pytest.mark.parametrize(
    "text",
    [
        "auth: failed for user bob",
        "ldap auth: user not found",
        "Kerberos auth: ticket expired for host",
        "session id: 12345 closed",
        "credentials: none configured",
        "api key: missing, set ARGUS_ELASTIC__API_KEY",
        "secret key: not set",
    ],
)
def test_prose_with_auth_and_spaced_key_words_is_kept(text: str) -> None:
    """Round 1 masked one or two words after these, e.g. 'auth: *** user bob'."""
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        f"auth={UNREG}",
        f"GET /login?user=bob&auth={UNREG}",
        f'auth: "{UNREG}"',
        f'{{"auth": "{UNREG}"}}',
        f"{{'auth': {UNREG}}}",
        f'credentials="{UNREG}"',
        f"credentials: '{UNREG}'",
        f'api key="{UNREG}"',
        f"session id = {UNREG}",
        f'{{"session id": "{UNREG}"}}',
        f"Authorization: {UNREG}",
        f"Authorization: SSWS {UNREG}",
        f"session_id: {UNREG}",
        f"api_key: {UNREG}",
    ],
)
def test_assigned_or_quoted_prose_key_words_are_masked(text: str) -> None:
    out = redact_text(text)
    assert UNREG not in out
    assert MASK in out


# --------------------------------------------------------------------------- registered secrets


def test_registered_secret_is_masked_in_ascii_and_bytes_repr_forms(
    json_stream: io.StringIO,
) -> None:
    """Round 1 missed ascii()/%a output and bytes reprs of non-ASCII secrets."""
    password = "Pä\"ss\\wörd 1'x-€-adv"
    register_secret(password)
    forms = {
        "ascii": (ascii(password), f"'{MASK}'"),
        "percent-a": ("%a" % password, f"'{MASK}'"),  # noqa: UP031 - the %a form is tested
        "bytes-repr": (repr(password.encode()), f"b'{MASK}'"),
        "bytes-str": (str(password.encode()), f"b'{MASK}'"),
    }
    for name, (form, masked) in forms.items():
        assert redact_text(f"connect with {form} failed") == f"connect with {masked} failed", name
    logging.getLogger("thirdparty").warning("auth %a then %s", password, password.encode())
    logging.getLogger("thirdparty").warning("auth %r", {"pw": password.encode()})
    events = [record["event"] for record in _records(json_stream)]
    assert events == [f"auth '{MASK}' then b'{MASK}'", f"auth {{'pw': b'{MASK}'}}"]


def test_registering_a_secret_with_a_lone_surrogate_does_not_raise() -> None:
    secret = "abc\udcffdef-adv"
    register_secret(secret)
    assert secret not in redact_text(f"x {secret} y")
    assert ascii(secret)[1:-1] not in redact_text(f"x {secret!a} y")


# --------------------------------------------------------------------------- key collisions


def test_keys_that_become_equal_as_text_are_all_kept() -> None:
    """Round 1 silently dropped an entry when two keys had the same text."""
    assert redact({b"a": 1, "a": 2}) == {"a (bytes)": 1, "a": 2}
    assert redact({"a": 2, b"a": 1}) == {"a": 2, "a (bytes)": 1}
    register_secret(SECRET)
    assert redact({f"user_{SECRET}": 1, f"user_{MASK}": 2}) == {
        f"user_{MASK}": 1,
        f"user_{MASK} (str)": 2,
    }
    masked = redact({f"token={UNREG}": 1, f"token={UNREG2}": 2})
    assert masked == {f"token={MASK}": 1, f"token={MASK} (str)": 2}


def test_distinct_keys_never_reuse_a_name() -> None:
    keys = distinct_keys(
        [(1, "1"), ("1", "1"), ("1 (int)", "1 (int)"), (2.0, "1"), (b"1", "1"), (True, "x")]
    )
    assert len(set(keys)) == len(keys)
    assert keys[1] == "1"  # a str key keeps its text
    assert keys[2] == "1 (int)"  # ...even when a renamed key would have wanted it


def test_mixed_key_types_that_collide_are_all_logged(json_stream: io.StringIO) -> None:
    get_logger("argus.test").info("counts", c={1: "int", "1": "str"}, b={b"x": 1, "x": 2})
    (record,) = _records(json_stream)
    assert record["c"] == {"1 (int)": "int", "1": "str"}
    assert record["b"] == {"x (bytes)": 1, "x": 2}


def test_many_colliding_keys_are_renamed_in_linear_time() -> None:
    mapping = {f"token={i}": i for i in range(50_000)}
    result: dict[str, Any] = {}

    def _run() -> None:
        result["out"] = redact(mapping)

    assert _seconds(_run, hard_limit=6.0) < 3.0
    assert len(result["out"]) == len(mapping)


@given(
    st.dictionaries(
        st.one_of(st.text(max_size=8), st.binary(max_size=8), st.integers(-3, 3)),
        st.integers(),
        max_size=12,
    )
)
def test_redact_and_log_rendering_keep_every_entry(mapping: dict[Any, int]) -> None:
    from argus.observability.logs import redact_event

    out = redact(mapping)
    assert isinstance(out, dict)
    assert len(out) == len(mapping)
    rendered = redact_event(None, "info", {"event": "e", "m": mapping})
    assert len(rendered["m"]) == len(mapping)
    assert all(isinstance(key, str) for key in rendered["m"])


# --------------------------------------------------------------------------- ReDoS on new branches

_KB200 = 200_000
_ADVERSARIAL_INPUTS = {
    "list-items-unclosed": 'password=["a",' + '"a",' * (_KB200 // 4),
    "list-many-starts": 'password=["a ' * (_KB200 // 13),
    "list-bare-items": "secret=(" + "a," * (_KB200 // 2),
    "list-openers": "token=" + "[ " * (_KB200 // 2),
    "list-closers-after": "token=[a]" + "]" * _KB200,
    "list-escapes": 'token=["' + "\\a" * (_KB200 // 2),
    "pair-repeated": "('authorization', " * (_KB200 // 18),
    "pair-unclosed-value": "('Authorization', 'x" + "y" * _KB200,
    "pair-no-closer": "('Authorization', 'x' " * (_KB200 // 22),
    "prose-colon-run": "auth: " * (_KB200 // 6),
    "prose-quote-run": 'auth: "' * (_KB200 // 7),
    "url-port-query": "a://b:1?" + "x" * _KB200,
    "url-quote-runs": "a://b:" + '"x' * (_KB200 // 2),
    "url-qmark-run": "a://b:" + "?" * _KB200,
    "url-json-many": '"http://u:p@h:9200","@t":1,' * (_KB200 // 27),
    "scheme-hyphen-run": "Bearer " + "a-" * (_KB200 // 2),
    "scheme-hyphen-words": "Basic read-only " * (_KB200 // 16),
}


@pytest.mark.parametrize(
    "payload", list(_ADVERSARIAL_INPUTS.values()), ids=list(_ADVERSARIAL_INPUTS)
)
def test_redaction_of_200kb_input_aimed_at_new_branches_is_fast(payload: str) -> None:
    assert _seconds(lambda: redact_text(payload)) < 1.0
