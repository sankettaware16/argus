"""The finished texts, read by Kibana's own Markdown reader (D-248): remark-parse 8.0.3 under
unified 9.2.2 with remark-emoji 2.2.0, through the node harness in tests/kibana_markdown/.

The other text tests model Kibana with markdown-it (CommonMark) and a hand-written scan, and that
was not enough: the reader differs from CommonMark exactly where the review of AR9 found the two
holes that got past them (a ``**`` inside a code span ends bold early; a pipe inside a code span
still ends a table cell). These tests fail on any link, image, reference, definition, html,
heading, list, quote, bold, emphasis or strike-through that a text has and its baseline (the same
text with a plain value) does not, on any link that is not one ARGUS builds, and on any table
whose rows differ in the number of their cells. They skip, saying why, where the packages or node
are not installed (tests/kibana_markdown/README.md)."""

from __future__ import annotations

import functools
import itertools
import re
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.caseteam import guard, visual
from argus.caseteam.render import bold, row, say, val
from argus.incident import build
from argus.incident import model as m
from argus.responder import catalogue as cat
from argus.writer.render import escape, fence
from tests.unit.caseteam import kibana_reader as reader
from tests.unit.caseteam import kit as team
from tests.unit.incident import kit

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not reader.available(), reason=reader.SKIP_REASON),
]
CATALOGUE = cat.load()
ALLOWED = team.CTX.allowed

# what the F1, F2 and F3 repros of the review put in a value, and other values that bite
REPROS = (
    "http://198.51.100.7/x**![beacon](http://evil.example/p.png)**",
    "x**[click here](http://evil.example/phish)**",
    "x__[c](http://evil.example/p)__",
    "x~~[c](http://evil.example/p)~~",
    "http://198.51.100.7/a\\\\|[Open the report](http://evil.example/login)",
    "/x\\\\|[click](http://evil.example/p)",
    "a|b|[c](http://evil.example/p)",
    "alice@example.edu",
    "a@http://x/a`[click](http://evil.example) tail",
    "a` b@c.com `d",
    "===",
    "/wp-content/plugins/x/readme.txt",
    "/admin/login.php?id=1",
    "**bold** __bold__ ~~gone~~ `code` ``a ` b``",
    "[click](javascript:alert(1)) ![x](http://evil.example/p.png)",
    "| a | b |\n|---|---|",
    "# heading\n- item\n> quote\n1. one\n2) two\n=== ---",
    "[ref]: http://evil.example\n[ref]",
    "<script>alert(1)</script> <img src=x onerror=alert(1)> <http://evil.example>",
    "@everyone @here a@b.example :smile: !{tooltip[a](b)}",
)


def fixtures() -> dict[str, m.IncidentReport]:
    return {
        "amadey": team.amadey(),
        "git": team.git(),
        "scanners": build.build(
            kit.scanners(), kit.ctx(catalogue=CATALOGUE, campus_domains=("example.edu",))
        ),
    }


def unfenced(text: str) -> str:
    """The text without its fenced code blocks (what is inside them is code)."""
    out: list[str] = []
    inside = False
    for line in text.split("\n"):
        if re.match(r"^ {0,3}`{3,}", line):
            inside = not inside
        elif not inside:
            out.append(line)
    return "\n".join(out)


def code_spans(text: str) -> list[tuple[int, int]]:
    """Where the inline code spans of a one-line text start and end."""
    found: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
        elif text[i] == "`":
            end = guard._code_end(text, i)
            if end > 0:
                found.append((i, end))
                i = end
            else:
                while i < len(text) and text[i] == "`":
                    i += 1
        else:
            i += 1
    return found


def check(label: str, text: str, got: reader.Read) -> None:
    """What holds of every text, whatever its baseline."""
    for kind in reader.NEVER:
        assert got.count(kind) == 0, f"{label}: {kind} in {text[:200]!r}"
    foreign = [u for u in got.urls if not u.startswith(ALLOWED)]
    assert not foreign, f"{label}: a link to {foreign} in {text[:200]!r}"
    assert got.ragged() == [], f"{label}: a table whose rows differ in cells {got.tables}"
    body = unfenced(text)
    assert got.count("heading") == len(re.findall(r"(?m)^#{1,6} ", body)), f"{label}: a heading"
    assert got.count("listItem") == len(re.findall(r"(?m)^- ", body)), f"{label}: a list item"


def test_the_reader_is_kibanas_not_commonmarks() -> None:
    """The harness is the right reader: it finds the end of bold in a code span and a pipe in a
    code span that ends a cell, as the review showed; without this the rest would prove nothing."""
    cut = "**E1 · ` http://198.51.100.7/x**![beacon](http://evil.example/p.png)** `**"
    split = "| a | b |\n|---|---|\n| ` x|[c](http://evil.example/p) ` | y |"
    fine = "**E1 · title** — ` http://198.51.100.7/x**![beacon](http://evil.example/p.png)** `"
    got = reader.read([cut, split, fine, "| a | b |\n|---|---|\n| 1 | 2 |"])
    assert got[0].count("image") == 1
    assert got[0].count("link") >= 1
    assert got[1].ragged() or got[1].count("link") >= 1
    assert got[2].count("image") == 0
    assert got[2].count("link") == 0
    assert got[3].tables == [[2, 2]]


@pytest.mark.parametrize("name", ["amadey", "git", "scanners"])
def test_every_comment_of_a_fixture_is_plain_in_kibana(name: str) -> None:
    every = team.texts(fixtures()[name])
    assert len(every) >= 8
    texts = list(every.values())
    for (key, text), got in zip(every.items(), reader.read(texts), strict=True):
        check(f"{name}/{key}", text, got)
        assert got.count("table") == len(re.findall(r"(?m)^\|---", unfenced(text))), key


@pytest.mark.parametrize("name", ["amadey", "git", "scanners"])
def test_the_living_glance_is_plain_in_kibana_in_every_form(name: str) -> None:
    """P4-F V3/V4: the glance with its charts, its lists, the line that says what is new, and the
    note for a field the alerts lack reads as two tables, its lists and nothing that acts."""
    report = fixtures()[name]
    before = visual.Seen(1, 3, 9, 0, 2, 0, "quiet")
    thin = report.model_copy(
        update={"meta": report.meta.model_copy(update={"carried": ("source.ip",)})}
    )
    texts = [
        visual.comment(report, "acme-soc", tagged=20)[0],
        visual.comment(report, "acme-soc", tagged=20, since=before)[0],
        visual.comment(report, "acme-soc", tagged=0, since=before)[0],
        visual.comment(thin, "acme-soc", tagged=5, since=before)[0],
    ]
    for n, (text, got) in enumerate(zip(texts, reader.read(texts), strict=True)):
        check(f"{name}/glance/{n}", text, got)
        assert got.count("table") == 2
        assert got.tables[0] == [4, 4]  # the head and the one row
        assert got.tables[1] == [7, 7]
        assert got.count("heading") == 1


@pytest.mark.parametrize("name", ["amadey", "git", "scanners"])
def test_a_hostile_value_in_every_field_adds_nothing_to_what_kibana_reads(name: str) -> None:
    """Each repro replaces every free-text string of a fixture (the F1, F2 and F3 repros among
    them); the comments that result read as the baseline ones do, with no more of any watched
    kind, and no table splits."""
    report = fixtures()[name]
    base_texts = team.texts(team.hostile_report(report, lambda _path, _old: "ok"))
    base_read = dict(zip(base_texts, reader.read(list(base_texts.values())), strict=True))
    for repro in REPROS:
        with team.no_check():
            hostile = team.texts(team.hostile_report(report, lambda _path, _old, v=repro: v))
        for (key, text), got in zip(
            hostile.items(), reader.read(list(hostile.values())), strict=True
        ):
            label = f"{name}/{key}/{repro[:30]!r}"
            check(label, text, got)
            if key in base_read:
                assert got.beyond(base_read[key]) == {}, f"{label}: {got.beyond(base_read[key])}"
            guard.check(text, ALLOWED)


def test_the_review_repro_f1_a_fence_is_never_inside_bold() -> None:
    report = team.amadey()
    asked = "http://198.51.100.7/x**![beacon](http://evil.example/p.png)**"
    line = report.evidence[0].model_copy(update={"asked": (asked,)})
    swapped = report.model_copy(update={"evidence": (line, *report.evidence[1:])})
    with team.no_check():
        text = team.texts(swapped)["comment:evidence:1"]
    got = reader.read([text])[0]
    check("F1", text, got)
    heading = next(ln for ln in text.split("\n") if ln.startswith("**E1 · "))
    assert re.match(r"^\*\*E1 · [^`*]+\*\* — ", heading), heading  # the bold ends before the value
    base = reader.read([text.replace(asked, "x")])[0]
    assert got.beyond(base) == {}


def test_the_review_repro_f2_a_pipe_in_a_value_cannot_split_a_cell() -> None:
    report = team.amadey()
    value = "http://198.51.100.7/a\\\\|[Open the report](http://evil.example/login)"
    mark = report.indicators[0].model_copy(update={"value": value})
    swapped = report.model_copy(update={"indicators": (mark, *report.indicators[1:])})
    with team.no_check():
        text = team.texts(swapped)["open"]
    got = reader.read([text])[0]
    check("F2 indicators", text, got)
    assert "\N{DIVIDES}" in text
    scan = fixtures()["scanners"]
    target = scan.targets[0].model_copy(
        update={"served": ("/x\\\\|[click](http://evil.example/p)",)}
    )
    bad = scan.model_copy(update={"targets": (target, *scan.targets[1:])})
    with team.no_check():
        text = team.texts(bad)["comment:devices:1"]
    check("F2 served", text, reader.read([text])[0])


def test_the_review_repro_f3_adjacent_fences_are_one_span() -> None:
    texts = [
        f"x {say('alice@example.edu signed in from 10.1.2.3')} y",
        f"x {say('bob@example.com')} y",
        f"x {say('a@http://x/a`[click](http://evil.example) tail')} y",
    ]
    got = reader.read(texts)
    for text, one in zip(texts, got, strict=True):
        check("F3", text, one)
        guard.check(text, ())
    assert texts[0] == "x ` alice@example.edu ` signed in from ` 10.1.2.3 ` y"
    assert got[0].count("inlineCode") == 2
    assert got[1].count("inlineCode") == 1


# --------------------------------------------------------------------------- property


ALPHABET = (
    list("`|*_~\\[]()<>#!@:/.-=&; \t") + list("abz019") + ["é", "\N{DIVIDES}", "\N{NO-BREAK SPACE}"]
)
TOKENS = [
    "http://",
    "www.",
    "a@b.com",
    "10.1.2.3",
    "/path/x.php",
    "**",
    "__",
    "~~",
    "![x](y)",
    "[a](b)",
    ":smile:",
    "mailto:",
    "javascript:",
]
VALUES = st.lists(
    st.one_of(st.sampled_from(TOKENS), st.text(alphabet=ALPHABET, min_size=1, max_size=6)),
    max_size=8,
).map("".join)
TEMPLATES: dict[str, Callable[[str], str]] = {
    "paragraph": lambda v: f"x {say(v, 400)} y",
    "after_a_line": lambda v: f"{bold('E1 · title')}\n{say(v, 400)}\nSource: z",
    "heading": lambda v: (
        f"{bold('E1 · ' + escape(v, 100))} — {val(v)}, {val(v + 'z')}\n{say(v)}\n"
        f"Source: {fence(v)} · check {fence('t')}"
    ),
    "cells": lambda v: (
        f"| H1 | H2 | H3 |\n|---|---|---|\n{row(say(v, 300), val(v), escape(v, 100))}\n"
        f"{row('**Kept**', say(v + v, 300), val(v))}"
    ),
    "bullet": lambda v: f"- {escape('device')}: {val(v)} ({say(v, 100)})",
    "fact": lambda v: f"| | |\n|---|---|\n{row('Detected by', say(v, 500))}",
}


@functools.cache
def baselines() -> dict[str, reader.Read]:
    """What each template reads as with a plain value (one run of node for all)."""
    names = sorted(TEMPLATES)
    return dict(zip(names, reader.read([TEMPLATES[n]("benign") for n in names]), strict=True))


@functools.cache
def plain_sentence() -> reader.Read:
    return reader.read(["x ok y"])[0]


CASES = st.lists(
    st.tuples(st.sampled_from(sorted(TEMPLATES)), VALUES),
    min_size=50,
    max_size=50,
)


@given(CASES)
@settings(max_examples=6, deadline=None)  # six runs of fifty: 300 texts, one node run each
def test_arbitrary_values_in_a_sentence_a_cell_or_a_heading_read_as_the_baseline(
    cases: list[tuple[str, str]],
) -> None:
    baseline = baselines()
    texts = [TEMPLATES[name](value) for name, value in cases]
    for (name, value), text, got in zip(cases, texts, reader.read(texts), strict=True):
        label = f"{name}/{value!r}"
        assert got.ragged() == [], f"{label}: {got.tables} in {text!r}"
        assert got.beyond(baseline[name]) == {}, f"{label}: {got.beyond(baseline[name])} {text!r}"
        for kind in reader.NEVER:
            assert got.count(kind) == 0, f"{label}: {kind} in {text!r}"
        assert not got.urls, f"{label}: a link to {got.urls} in {text!r}"
        guard.check(text, ())


@given(
    st.text(alphabet=ALPHABET, max_size=12),
    st.sampled_from(["alice@example.edu", "bob@example.com", "10.1.2.3", "a.b.example", "/x/y.z"]),
    st.text(alphabet=ALPHABET, max_size=12),
)
@settings(max_examples=40, deadline=None)
def test_a_sentence_around_an_address_never_puts_two_code_spans_side_by_side(
    prefix: str, address: str, suffix: str
) -> None:
    text = f"x {say(prefix + address + suffix, 400)} y"
    got = reader.read([text])[0]
    assert got.beyond(plain_sentence()) == {}
    assert not got.urls
    guard.check(text, ())
    spans = code_spans(text)
    for (_, ends), (starts, _) in itertools.pairwise(spans):
        assert ends != starts, f"two code spans side by side in {text!r}"
