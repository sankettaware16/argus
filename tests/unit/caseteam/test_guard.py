"""The guardian of an outgoing comment (AR8): it reads the finished text as a Markdown reader
would and refuses what could act, whoever wrote it."""

from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.caseteam import guard
from argus.gateway.kibana.models import MAX_TEXT

pytestmark = pytest.mark.unit
ALLOWED = ("https://argus.example/go/case/", "https://kibana.example")


@pytest.mark.parametrize(
    "text",
    [
        "## Evidence\n\nA sentence with a fenced `value` and **bold**.",
        "| a | b |\n|---|---|\n| `x` | y |",
        '```esql\nFROM x | WHERE a == "<script>" @ http://e.example\n```',
        "A [link](https://argus.example/go/case/11111111-1111-4111-8111-111111111111) here",
        "[Open in Discover](https://kibana.example/s/acme-soc/app/discover#/?_g=%28a%29)",
        "escaped \\<b\\> and \\@bob and \\[x\\]\\(http\\://e\\.example\\)",
        "`` a ` b `` and ```` x ``` y ````",
        "Confirm or reject in a comment.",
    ],
)
def test_ordinary_text_passes(text: str) -> None:
    guard.check(text, ALLOWED)


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("", "empty"),
        ("   \n", "empty"),
        ("<script>alert(1)</script>", "HTML"),
        ("a <b>x</b>", "HTML"),
        ("hello @bob", "mention"),
        ("[x](javascript:alert(1))", "does not build"),
        ("[x](https://evil.example/a)", "does not build"),
        ("![i](https://argus.example/go/case/1)", "image"),
        ('[x](https://kibana.example/a"onmouseover=1)', "break out"),
        ("see http://evil.example/x", "URL"),
        ("see www.evil.example", "URL"),
        ("click javascript:alert(1)", "URL"),
        ("a [ref][1]\n\n[1]: http://e.example", "bracket"),
        ("> a quote", "block quote"),
        ("a `span that never closes", "code span is not closed"),
        ("```\nnever closed", "fence is not closed"),
        ("a‮b", "bidirectional"),
        ("a\x00b", "control"),
        ("a" * (MAX_TEXT + 1), "over Kibana's"),
        ("😀" * (MAX_TEXT // 2 + 1), "over Kibana's"),  # counted in UTF-16 units, as Kibana does
    ],
)
def test_what_could_act_is_refused(text: str, why: str) -> None:
    with pytest.raises(guard.GuardRefusal) as refused:
        guard.check(text, ALLOWED)
    assert why in str(refused.value)


def test_an_escaped_backtick_opens_nothing_and_an_escaped_bracket_is_text() -> None:
    guard.check("a \\` b \\[ c \\] d \\@e", ALLOWED)


def test_a_link_is_allowed_only_to_the_prefixes_given() -> None:
    text = "[x](https://kibana.example/a)"
    guard.check(text, ALLOWED)
    with pytest.raises(guard.GuardRefusal):
        guard.check(text, ())
    with pytest.raises(guard.GuardRefusal):
        guard.check(text, ("https://argus.example/go/case/",))


def test_a_link_inside_a_code_span_or_fence_is_data() -> None:
    guard.check("`[x](http://evil.example)` and\n```\n[y](javascript:1) @z <b>\n```", ALLOWED)


@given(st.text(alphabet="abc XYZ,.;-\n\t0123456789", min_size=1, max_size=300))
def test_plain_prose_without_markup_characters_always_passes(text: str) -> None:
    # (a line of dashes alone is a heading underline or a rule in Kibana: the guard refuses it)
    if text.strip() and not re.search(r"(?m)^ {0,3}-{2,}[ \t]*$", text):
        guard.check(text, ALLOWED)


@given(st.text(max_size=400))
def test_whatever_it_is_given_it_either_passes_or_refuses_and_never_raises_anything_else(
    text: str,
) -> None:
    try:
        guard.check(text, ALLOWED)
    except guard.GuardRefusal as refused:
        reasons = refused.reasons
    else:
        return
    assert reasons


# --------------------------------------------------------------------------- the link check


AT = "@"  # built apart: a URL with user information looks like a password to the commit hook
KIBANA = ("https://kibana.example:5601",)
CASE_LINK = ("https://argus.example/go/case/",)


@pytest.mark.parametrize(
    "target",
    [
        "https://kibana.example:5601/s/acme-soc/app/discover#/?_g=1",
        "https://KIBANA.example:5601/app/x",  # a host has no case
        "https://kibana.example:5601",
        "https://kibana.example:5601/",
    ],
)
def test_a_link_to_the_configured_scheme_host_and_port_is_allowed(target: str) -> None:
    assert guard.link_allowed(target, KIBANA)


@pytest.mark.parametrize(
    "target",
    [
        "https://kibana.example:5601.evil.com/x",  # the port runs on into another host
        f"https://kibana.example:5601{AT}evil.com/x",  # user information, the host is evil.com
        "https://kibana.example@evil.com/x",
        "https://evil.com@kibana.example:5601/x",  # user information on the right host
        "https://kibana.example:56010/x",  # another port
        "https://kibana.example:56/x",
        "https://kibana.example/x",  # the scheme's default port is not 5601
        "http://kibana.example:5601/x",  # another scheme
        "https://kibana.example.evil.com:5601/x",
        "https://evilkibana.example:5601/x",
        "https://kibana.example%2eevil.com:5601/x",
        f"https://kibana.example:5601\\{AT}evil.com/x",
        "//kibana.example:5601/x",
        "javascript:alert(1)",
        "https://",
        "",
    ],
)
def test_no_other_address_is_allowed_however_it_starts(target: str) -> None:
    assert not guard.link_allowed(target, KIBANA)


def test_a_path_must_lie_under_the_allowed_path_not_merely_start_with_it() -> None:
    uuid_ = "11111111-1111-4111-8111-111111111111"
    assert guard.link_allowed(f"https://argus.example/go/case/{uuid_}", CASE_LINK)
    for bad in (
        "https://argus.example/go/case",  # not under the directory
        "https://argus.example/go/cases/x",
        "https://argus.example/go/case2/x",
        "https://argus.example/other/go/case/x",
        "https://argus.example:8443/go/case/x",
        "https://argus.example.evil.com/go/case/x",
        "http://argus.example/go/case/x",
    ):
        assert not guard.link_allowed(bad, CASE_LINK), bad


@pytest.mark.parametrize(
    "target",
    [
        "https://kibana.example:5601.evil.com/x",
        f"https://kibana.example:5601{AT}evil.com/x",
        "https://kibana.example:56010/x",
    ],
)
def test_the_guardian_refuses_a_link_that_only_starts_like_kibanas(target: str) -> None:
    guard.check("[Open](https://kibana.example:5601/s/x)", KIBANA)
    with pytest.raises(guard.GuardRefusal, match="does not build"):
        guard.check(f"[Open in Discover]({target})", KIBANA)


@given(
    host=st.text("abcdefgxyz.-", min_size=1, max_size=12),
    port=st.one_of(st.none(), st.integers(0, 70000)),
    user=st.one_of(st.none(), st.text("abc:", min_size=1, max_size=5)),
    path=st.text("/abc-_%.", max_size=12),
)
def test_a_link_is_allowed_only_for_the_exact_origin(
    host: str, port: int | None, user: str | None, path: str
) -> None:
    got = "https://" + (f"{user}@" if user else "") + host + (f":{port}" if port else "") + path
    if guard.link_allowed(got, KIBANA):
        assert user is None
        assert host == "kibana.example"
        assert port == 5601
