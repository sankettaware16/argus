"""Q-A1: the request rules (argus.web.security): where a change may come from, which requests
are background ones, where sign-in may send the browser, the login-CSRF token."""

from __future__ import annotations

import re
import tracemalloc
from urllib.parse import urljoin, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.web import security
from argus.web.security import is_background, refusal, safe_next, signin_token_ok

pytestmark = pytest.mark.unit
OWN = "http://127.0.0.1:8765"
_TOKEN_CHARS = st.sampled_from(["a", "?", "é", "\ud800", "\udfff"])  # "?" and lone surrogates


def test_safe_methods_pass_unless_they_are_another_sites_api_request() -> None:
    for method in ("GET", "HEAD", "OPTIONS", "get"):
        assert refusal(method, "/rules", {}, OWN) is None
        assert refusal(method, "/rules", {"sec-fetch-site": "cross-site"}, OWN) is None
        assert refusal(method, "/api/rules", {"sec-fetch-site": "cross-site"}, OWN) is not None
        assert refusal(method, "/api", {"sec-fetch-site": "same-site"}, OWN) is not None
        assert refusal(method, "/api/v1/x", {"sec-fetch-site": "same-origin"}, OWN) is None
        assert refusal(method, "/api/v1/x", {"sec-fetch-site": "none"}, OWN) is None
        assert refusal(method, "/apiary", {"sec-fetch-site": "cross-site"}, OWN) is None


@pytest.mark.parametrize(
    ("headers", "refused"),
    [
        ({}, True),
        ({"origin": OWN}, False),
        ({"origin": OWN.upper()}, False),
        ({"origin": OWN + "/"}, True),
        ({"origin": "http://127.0.0.1"}, True),
        ({"origin": "https://127.0.0.1:8765"}, True),
        ({"origin": "null"}, True),
        ({"origin": ""}, True),
        ({"sec-fetch-site": "same-origin"}, False),
        ({"sec-fetch-site": "same-site"}, True),
        ({"sec-fetch-site": "cross-site"}, True),
        ({"sec-fetch-site": "none"}, True),
        ({"sec-fetch-site": "SAME-ORIGIN"}, True),
        ({"origin": OWN, "sec-fetch-site": "cross-site"}, True),
        ({"origin": "http://evil.example", "sec-fetch-site": "same-origin"}, True),
    ],
)  # fmt: skip
def test_changes_need_proof_of_this_origin(headers: dict[str, str], refused: bool) -> None:
    for method in ("POST", "PUT", "PATCH", "DELETE", "post"):
        assert (refusal(method, "/x", headers, OWN) is not None) is refused, (method, headers)


def test_the_reasons() -> None:
    assert refusal("POST", "/x", {}, OWN) == (
        "a change needs a request from this site's own page (no Origin header)"
    )
    assert refusal("POST", "/x", {"origin": "http://e"}, OWN) == "cross-origin request refused"
    for site in ("cross-site", "same-site", "none"):
        assert refusal("POST", "/x", {"sec-fetch-site": site}, OWN) == (
            "cross-origin request refused"
        )
    assert refusal("GET", "/api/x", {"sec-fetch-site": "cross-site"}, OWN) == (
        "the API answers this site's own pages only"
    )
    assert security.own_origin("HTTPS", "Argus.Example") == "https://argus.example"


def test_background_requests() -> None:
    assert is_background({"x-argus-background": "1"})
    for value in ("0", "true", "yes", "", " 1"):
        assert not is_background({"x-argus-background": value})
    assert not is_background({})


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("/", True), ("/rules", True), ("/?view=open", True), ("/investigations/x#alerts", True),
        ("/go/case/2b6f0cc9-4f1a-4f1e-9b0e-2f1f3c1d9e11", True), ("/apiary", True),
        ("/%2F%2Fevil.example", True),  # a path, still on this site
        ("/!", True), ("/~", True), ("/" + "a" * 2047, True),  # printable ASCII, 2048 at most
        ("/\x7f", False), ("/!\x7f", False), ("/~\x80", False),
        (None, False), ("", False), ("rules", False), ("//evil.example", False),
        ("///evil.example", False), ("/\\evil.example", False), ("\\\\evil.example", False),
        ("/\t/evil.example", False), ("/\n/evil.example", False), ("/ /evil", False),
        ("https://evil.example", False), ("http:/evil.example", False),
        ("javascript:alert(1)", False), ("/résumé", False), ("/‮", False),
        ("/api", False), ("/api/v1/session", False), ("/static/style.css", False),
        ("/signin", False), ("/signin?next=/x", False), ("/stepup", False), ("/login", False),
        ("/logout", False), ("/" + "a" * 2048, False),
    ],
)  # fmt: skip
def test_where_sign_in_may_go_back_to(value: str | None, kept: bool) -> None:
    assert safe_next(value) == (value if kept else "/")


@given(st.text(max_size=80))
def test_safe_next_never_leaves_this_site(value: str) -> None:
    got = safe_next(value)
    assert got == "/" or got == value
    assert got.startswith("/")
    assert not got.startswith("//")
    assert re.fullmatch(r"[!-~]*", got)  # printable ASCII only: nothing a browser strips
    assert "\\" not in got
    # resolved as a browser would, it stays on this origin
    assert urljoin("https://argus.example/somewhere/", got).startswith("https://argus.example/")


@given(st.text(alphabet=st.characters(codec="ascii"), max_size=40))
def test_safe_next_on_ascii_never_leaves_this_site(tail: str) -> None:
    got = safe_next("/" + tail)
    assert urljoin("https://argus.example/", got).startswith("https://argus.example/")


@given(st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), max_size=40))
def test_urlsplit_finds_no_host_in_what_safe_next_parses(tail: str) -> None:
    # What safe_next has checked before it parses: printable ASCII, no backslash, one leading
    # "/". On such text urlsplit finds no scheme and no host, so its own check of them is a
    # second line that never decides today (its mutants are listed as equivalent, D-040).
    value = "/" + tail
    if value.startswith("//") or "\\" in value:
        return
    parts = urlsplit(value)
    assert (parts.scheme, parts.netloc) == ("", "")
    assert parts.path.split("/", 2)[1] == parts.path.split("/")[1]  # any maxsplit from 1 on


def test_the_login_csrf_token() -> None:
    token = security.new_signin_token()
    assert len(token) == 43
    assert token != security.new_signin_token()
    assert signin_token_ok(token, token)
    for cookie, field in ((token, token + "x"), (None, token), (token, None), ("", ""),
                          ("x" * 101, "x" * 101), ("é", "é"), (token, "é")):  # fmt: skip
        assert signin_token_ok(cookie, field) is (cookie == field and cookie == "é"), (cookie,)


def test_the_login_csrf_token_is_compared_exactly() -> None:
    assert signin_token_ok("x" * 100, "x" * 100)  # up to 100 characters each
    assert not signin_token_ok("x" * 101, "x" * 101)
    # equal means the same text: a lone surrogate is neither a "?" nor another surrogate (the
    # "replace" error handler made it a "?" before the comparison)
    assert signin_token_ok("\ud800", "\ud800")
    for cookie, field in (("?", "\ud800"), ("\ud800", "?"), ("\ud800", "\udfff")):
        assert not signin_token_ok(cookie, field), (cookie, field)


def test_an_oversized_token_is_refused_without_reading_it() -> None:
    """'Of a sane size': a cookie or field over 100 characters is refused before any work
    proportional to its length (no encoding of it), whatever the other side is."""
    big = "a" * 1_000_000
    for cookie, field in ((big, "a"), ("a", big), (big, big), (big, "a" * 100)):
        tracing = tracemalloc.is_tracing()
        if not tracing:
            tracemalloc.start()
        try:
            before, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            assert not signin_token_ok(cookie, field)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            if not tracing:
                tracemalloc.stop()
        assert peak - before < 64_000, f"{peak - before} bytes allocated for a refused token"


@given(st.text(_TOKEN_CHARS, max_size=6), st.text(max_size=6))
def test_the_login_csrf_token_matches_only_itself(cookie: str, other: str) -> None:
    for field in (cookie, other, cookie.replace("\ud800", "?")):
        assert signin_token_ok(cookie, field) is (field == cookie != ""), (cookie, field)


def test_a_sign_in_form_reuses_the_browsers_token() -> None:
    token = security.new_signin_token()
    assert security.reused_signin_token(token) == token  # the browser's own, while it lasts
    assert security.reused_signin_token("A" * 43) == "A" * 43
    for cookie in (None, "", token[:-1], token + "x", token[:-1] + "=", token[:-1] + "é",
                   " " + token[1:], token[:-1] + "\n"):  # fmt: skip
        got = security.reused_signin_token(cookie)
        assert got != cookie, cookie  # anything not of our shape: a new token
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", got)


def test_the_cookie_names_and_policies() -> None:
    assert (security.session_cookie(True), security.session_cookie(False)) == (
        "__Host-argus_session",
        "argus_session",
    )
    assert (security.signin_cookie(True), security.signin_cookie(False)) == (
        "__Host-argus_signin",
        "argus_signin",
    )
    assert "script-src 'self'" in security.CSP
    assert "script-src 'none'" in security.CSP_NO_SCRIPT
    assert "connect-src 'none'" in security.CSP_NO_SCRIPT
    assert security.CSP_NO_SCRIPT.replace("script-src 'none'; connect-src 'none'",
                                          "script-src 'self'") == security.CSP  # fmt: skip


def _directives(policy: str) -> list[tuple[str, str]]:
    """A policy as a browser reads it: ``name sources`` directives between semicolons."""
    return [
        (name, sources)
        for name, _, sources in (d.strip().partition(" ") for d in policy.split(";"))
    ]


def test_the_content_security_policies_word_for_word() -> None:
    page = [
        ("default-src", "'self'"), ("script-src", "'self'"), ("style-src", "'self'"),
        ("img-src", "'self'"), ("object-src", "'none'"), ("base-uri", "'none'"),
        ("frame-ancestors", "'none'"), ("form-action", "'self'"),
    ]  # fmt: skip
    assert _directives(security.CSP) == page
    # the sign-in pages: no script, no connections, the rest the same
    assert _directives(security.CSP_NO_SCRIPT) == [
        page[0], ("script-src", "'none'"), ("connect-src", "'none'"), *page[2:]
    ]  # fmt: skip
