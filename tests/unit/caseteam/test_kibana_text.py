"""Text for Kibana's Markdown (D-237): only what Kibana honours a backslash before is escaped, so no
backslash shows ("26 Oct 2026\\, 3\\:10 AM" was the bug), and nothing a value contains becomes
Markdown, a link or HTML. Property tests over arbitrary text; the checks are written from the
rule and not from the code: a scan of the finished text outside its code spans, and an independent
CommonMark parser (markdown-it)."""

from __future__ import annotations

import re
from typing import Any

import markdown_it
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.caseteam import guard
from argus.caseteam.render import cell, say, val
from argus.writer.render import clean, escape, fence, plain

pytestmark = pytest.mark.unit

KIBANA = frozenset("\\`*_{}[]()#+-.!>~|")  # what Kibana 8.19 honours a backslash before
HOSTILE = (
    "26 Oct 2026, 3:10 AM IST",
    'people\'s "on a threat list"',
    "Rules: Sensitive, Backup or Config File Served Successfully (4 alerts)",
    "[click](javascript:alert(1)) ![x](http://evil.example/p.png)",
    "<script>alert(1)</script> <img src=x onerror=alert(1)> <http://evil.example>",
    "@everyone @here a@b.example",
    "# heading\n- item\n> quote\n1. one\n2) two\n=== ---",
    "**bold** __bold__ ~~gone~~ `code` ``a ` b``",
    "| a | b |\n|---|---|",
    "http://evil.example/a?b=c&d=e www.evil.example mailto:x@y.example",
    "javascript:alert(1) vbscript:x data:text/html,<b>",
    "&lt;b&gt; &amp; &#64; &#x3C;",
    "\\\\ \\` \\[ \\] \\, \\: \\'",
    "$(rm -rf /) ${IFS} :smile: !{tooltip[a](b)}",
    "‮reversed⁦ and a\x00nul",
)
_RUN = re.compile(r"`+")


def outside_code(text: str) -> str:
    """The text as a Markdown reader sees it outside code: a backslash and the character it
    escapes become a space, a code span (a run of backticks to the next run of its length) is
    dropped, and a run of backticks with no closing run is a failure."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            assert i + 1 < n, "a backslash at the end shows"
            assert text[i + 1] in KIBANA, f"a backslash that shows: {text[i : i + 3]!r}"
            out.append("  ")
            i += 2
        elif c == "`":
            run = _RUN.match(text, i)
            assert run is not None
            ticks = run.group(0)
            at = run.end()
            while True:
                found = _RUN.search(text, at)
                assert found is not None, f"a code span is not closed: {text[i : i + 20]!r}"
                at = found.end()
                if found.group(0) == ticks:
                    break
            out.append(" ")
            i = at
        else:
            out.append(c)
            i += 1
    return "".join(out)


def assert_inert(text: str) -> None:
    """Nothing outside a code span can act in Kibana's Markdown."""
    plain_text = outside_code(text)
    assert not set(plain_text) & KIBANA, f"an unescaped Markdown character in {plain_text!r}"
    assert "<" not in plain_text, "a raw '<'"
    for found in re.finditer("&", plain_text):
        assert re.match(r"&(amp|lt);", plain_text[found.start() :]), "a raw '&'"
    assert not re.search(r"://|\bwww\.|@|\b(?:mailto|javascript|vbscript|data):", plain_text, re.I)
    assert "\n" not in text
    guard.check(f"x {text}", ())  # the sender's own guardian agrees


def kinds(text: str) -> set[str]:
    """The token types a CommonMark reader (markdown-it, HTML allowed, tables and strikethrough
    on) makes of the text: a paragraph of text and code spans, nothing else."""
    reader = markdown_it.MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])
    found: set[str] = set()
    for token in reader.parse(text):
        found.add(token.type)
        for child in token.children or []:
            found.add(f"inline:{child.type}")
    return found


ALLOWED = {"paragraph_open", "inline", "paragraph_close", "inline:text", "inline:code_inline"}


@pytest.mark.parametrize("value", HOSTILE)
def test_a_hostile_text_is_inert_and_shows_no_backslash(value: str) -> None:
    text = escape(value, 1_000)
    assert_inert(text)
    assert kinds(text) <= ALLOWED | {"inline:softbreak"}


@given(st.text(max_size=300))
@settings(deadline=None)
def test_any_text_is_inert_in_kibana(value: str) -> None:
    text = escape(value, 1_000)
    assert_inert(text)
    assert kinds(text) <= ALLOWED | {"inline:softbreak"}


@given(st.text(max_size=300))
@settings(deadline=None)
def test_what_a_reader_sees_is_the_text(value: str) -> None:
    """The visible text equals the cleaned input, entities and code spans decoded (spaces apart)."""
    reader = markdown_it.MarkdownIt("commonmark", {"html": True})
    shown = "".join(
        child.content
        for token in reader.parse(escape(value, 1_000))
        for child in token.children or []
        if child.type in ("text", "code_inline")
    )
    assert shown.replace(" ", "") == clean(value, 1_000).replace(" ", "")


def test_the_cases_that_showed_backslashes() -> None:
    assert escape("26 Oct 2026, 3:10 AM IST") == "26 Oct 2026, 3:10 AM IST"
    assert escape('people\'s "on a threat list"') == 'people\'s "on a threat list"'
    assert escape("Rules: Sensitive") == "Rules: Sensitive"
    # what Kibana does honour is still escaped
    assert escape("a_b *c* (d) [e] 1. -x #y | z") == r"a\_b \*c\* \(d\) \[e\] 1\. \-x \#y \| z"


def test_only_the_kibana_set_gets_a_backslash() -> None:
    for char in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
        out = escape(f"a{char}b")
        if char in KIBANA:
            assert f"\\{char}" in out, char
        else:
            assert "\\" not in out, char


@pytest.mark.parametrize(
    "sentence",
    [
        "45.148.10.238 probed evil.example.com and http://x.example/a?b=c, then 209.126.4.192.",
        "The first alert was at 26 Oct 2026, 3:10 AM IST; web.config and .env were asked for.",
        "Seen at 10.1.2.3:8080 (and www.example.org).",
    ],
)
def test_an_address_in_a_sentence_is_plain_in_a_code_span(sentence: str) -> None:
    text = say(sentence)
    assert "[.]" not in text
    assert "hxxp" not in text
    assert "\\," not in text
    assert "\\:" not in text
    assert_inert(text)
    spans = re.findall(r"` ([^`]+) `", text)
    for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", sentence):
        assert address in spans


@given(st.text(max_size=200), st.ip_addresses(v=4), st.text(max_size=100))
@settings(deadline=None)
def test_a_sentence_with_an_address_is_inert(before: str, ip: Any, after: str) -> None:
    text = say(f"{before} {ip} {after}", 1_000)
    assert_inert(text)
    assert kinds(text) <= ALLOWED | {"inline:softbreak"}
    assert f"` {ip} `" in text or str(ip) in before or str(ip) in after


@given(st.text(max_size=300))
@settings(deadline=None)
def test_a_value_is_one_code_span_written_plain(value: str) -> None:
    text = val(value)
    shown = clean(value)
    assert text == fence(value)
    if shown:
        assert_inert(text)
        assert shown in text
    else:
        assert text == "(empty)"


def test_a_pipe_is_escaped_once_in_a_cell() -> None:
    assert cell(escape("a | b")) == r"a \| b"
    assert cell("a | b") == r"a \| b"
    assert cell(r"a \| b") == r"a \| b"


def test_plain_leaves_markup_in_a_code_span_alone() -> None:
    assert plain("see http://x.example now") == "see ` http://x.example ` now"
    assert plain("mail a@b.example") == "mail ` a@b.example `"
