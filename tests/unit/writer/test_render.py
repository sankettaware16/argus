"""Q-D4's renderer: deterministic text only, hostile values inert (plan §3 rule 13, DQ10 (a)).

A real CommonMark parser (markdown-it, HTML off, as Kibana's renderer treats a comment) reads
every text the renderer writes from hostile values: it must find no link but ARGUS's own, no
image, no HTML, no heading, list or quote that a value could have made, and each value in one
code span that holds the value whole."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.writer import render

markdown_it = pytest.importorskip("markdown_it")

pytestmark = pytest.mark.unit

BASE = "https://argus.example"
CASE = uuid.UUID("3f2a9c1e-5b7d-4e86-9a10-c4d2e8f61b73")
OWN_LINK = f"{BASE}/go/case/{CASE}"
HOSTILE = [
    "[click](http://evil.example/steal)",
    "![x](http://evil.example/p.png)",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "# a heading\n- a list\n> a quote\n```\ncode\n```",
    "`` ` `` ``` `` \\` `",
    "http://evil.example/a.b?c=d#e",
    "https://user:pw@evil.example/",
    "javascript:alert(1)",
    "@everyone @here",
    "| a | b |\n|---|---|",
    "‮gnp.exe",
    "line one\nline two\r\nline three",
    "[ref]: http://evil.example\n\n[ref]",
    "<http://evil.example>",
    "evil[.]example & &amp; &#x3C;",
    "x" * 5000,
    "",
    "\x00\x1b[31mred\x1b[0m",
    "a​b﻿c",
]


def parse(text: str) -> list[Any]:
    return markdown_it.MarkdownIt("commonmark", {"html": False}).parse(text)


def inline(tokens: list[Any]) -> list[Any]:
    return [child for t in tokens if t.type == "inline" for child in (t.children or [])]


def description(**over: Any) -> str:
    params: dict[str, Any] = {
        "case": str(CASE), "link": f"/go/case/{CASE}", "what": "C2 beacon from 3 campus hosts",
        "hosts": ["10.0.0.1"], "more_hosts": 0, "indicators": ["evil.example"],
        "more_indicators": 0, "investigations": 2,
        "first_alert": "2026-10-20T03:00:00+00:00", "latest_alert": "2026-10-21T04:30:00+00:00",
    }  # fmt: skip
    params.update(over)
    return render.description(params, render.Context(BASE))


def only_safe(text: str, *, links: int = 1) -> None:
    tokens = parse(text)
    types = {t.type for t in tokens}
    assert not types & {"heading_open", "bullet_list_open", "ordered_list_open", "blockquote_open",
                        "fence", "code_block", "html_block", "table_open", "hr"}  # fmt: skip
    kids = inline(tokens)
    assert not {c.type for c in kids} & {"html_inline", "image"}
    hrefs = [c.attrs.get("href") for c in kids if c.type == "link_open"]
    assert hrefs == [OWN_LINK] * links


@pytest.mark.parametrize("value", HOSTILE)
def test_a_hostile_host_or_indicator_is_one_inert_code_span(value: str) -> None:
    text = description(hosts=[value], indicators=[value])
    only_safe(text)
    spans = [c.content for c in inline(parse(text)) if c.type == "code_inline"]
    shown = render.clean(value)  # an address, a domain or a URL is written plain in the span
    assert spans == ([shown] * 2 if shown else [])  # a value that is nothing is "(empty)"
    assert "(empty)" in text or shown


@pytest.mark.parametrize("value", HOSTILE)
def test_a_hostile_what_stays_plain_text(value: str) -> None:
    text = description(what=value)
    only_safe(text)
    assert "<" not in text.replace("` <", "").replace("&lt;", "")  # a bracket: entity or code


@pytest.mark.parametrize("value", HOSTILE)
def test_a_hostile_name_in_a_comment_is_escaped_text(value: str) -> None:
    ctx = render.Context(BASE, people={"user:7": value}, reference="c:v2:0")
    text = render.comment("taken", {"by": "user:7"}, ctx)
    only_safe(text, links=0)
    closing = render.Context(
        BASE,
        approvers=(render.Approver(value, value),),
        approved_at=datetime(2026, 10, 26, 8, 35, tzinfo=UTC),
    )
    only_safe(render.comment("closed", {"reason": "benign_policy"}, closing), links=0)


@given(st.text(max_size=300))
def test_any_value_is_an_inert_code_span(value: str) -> None:
    text = description(hosts=[value])
    only_safe(text)


@given(st.text(max_size=300))
def test_any_name_is_inert(value: str) -> None:
    ctx = render.Context(BASE, people={"user:1": value})
    only_safe(render.comment("assigned", {"to": "user:1", "by": "user:1"}, ctx), links=0)


def test_titles_are_still_defanged_but_text_is_not() -> None:
    """A title is plain text, not Markdown: ``defang`` stays for it (the writer's title). A value in
    a case's text is written plain in a code span (D-237)."""
    assert render.defang("https://evil.example.com/a.b") == "hxxps://evil[.]example[.]com/a[.]b"
    assert render.defang("http://1.2.3.4") == "hxxp://1[.]2[.]3[.]4"
    assert render.defang("ftp://x.y") == "fxp://x[.]y"
    assert render.defang("gopher://x") == "gopher[://]x"
    text = description(hosts=["https://evil.example.com"])
    assert "` https://evil.example.com `" in text
    assert "[.]" not in text
    assert "hxxp" not in text


def test_the_only_link_is_the_configured_address_with_the_case_uuid() -> None:
    assert OWN_LINK in description()
    with pytest.raises(render.RenderError):
        description(link="/go/case/another")
    with pytest.raises(render.RenderError):
        render.link("http://evil.example/x", CASE)  # a path is not an address
    with pytest.raises(render.RenderError):
        render.link("javascript:alert(1)", CASE)
    with pytest.raises(render.RenderError):
        render.link(BASE, "../../etc")


def test_the_description_says_what_the_plan_says() -> None:
    text = description()
    assert "decisions" in text.lower()
    assert "ARGUS" in text
    assert "C2 beacon from 3 campus hosts" not in text or "C2 beacon from 3 campus hosts" in text
    assert "`" in text
    assert "` 10.0.0.1 `" in text
    assert "2026-10-20 08:30 IST" in text  # 03:00 UTC is 08:30 IST


def test_more_than_twenty_hosts_are_counted_not_listed() -> None:
    hosts = [f"pc{n}.lab.example" for n in range(25)]
    text = description(hosts=hosts, more_hosts=4)
    assert text.count("`") == 2 * (20 + 1)  # 20 hosts and the one indicator
    assert "Hosts (29)" in text
    assert "and 9 more" in text


def test_the_same_input_gives_the_same_text() -> None:
    assert description() == description()
    ctx = render.Context(BASE, reference="k")
    assert render.comment("reopened", {"by": "user:3"}, ctx) == render.comment(
        "reopened", {"by": "user:3"}, ctx
    )


def test_a_closing_comment_names_the_approver_and_the_time_in_ist() -> None:
    ctx = render.Context(
        BASE,
        approvers=(render.Approver("Asha Rao", "a.rao"),),
        approved_at=datetime(2026, 10, 26, 8, 35, tzinfo=UTC),
        reference="x:v3:1",
    )
    text = render.comment("closed", {"reason": "remediated_verified"}, ctx)
    assert text.startswith(
        "Closed by ARGUS on the approval of Asha Rao (` a.rao `), 2026-10-26 14:05 IST."
    )
    assert "ARGUS reference: ` x:v3:1 `" in text
    with pytest.raises(render.RenderError):
        render.comment("closed", {"reason": "remediated_verified"}, render.Context(BASE))
    with pytest.raises(render.RenderError):
        render.comment("closed", {"reason": "because I said so"}, ctx)


def test_an_unknown_template_or_parameter_is_an_error_not_text() -> None:
    ctx = render.Context(BASE)
    with pytest.raises(render.RenderError):
        render.comment("model_summary", {}, ctx)
    with pytest.raises(render.RenderError):
        render.comment("taken", {"by": "user:1", "extra": "<b>"}, ctx)
    with pytest.raises(render.RenderError):
        render.comment("taken", {}, ctx)
    with pytest.raises(render.RenderError):
        render.comment("severity", {"severity": "apocalyptic"}, ctx)
    with pytest.raises(render.RenderError):
        description(hosts="not a list")


def test_every_comment_template_renders_with_its_params() -> None:
    ctx = render.Context(BASE, people={"user:1": "Asha"}, reference="r")
    cases: dict[str, dict[str, Any]] = {
        "taken": {"by": "user:1"}, "assigned": {"to": "user:1", "by": "user:2"},
        "released": {"by": "user:1"}, "contained": {"by": "user:1"},
        "reopened": {"by": "user:1"}, "new_activity": {}, "severity": {"severity": "high"},
        "merged_in": {"source": str(CASE)}, "corrected": {"what": "update", "of": "k:v2:0"},
        "opened": {"case": str(CASE), "link": f"/go/case/{CASE}", "alerts": 4, "investigations": 2},
    }  # fmt: skip
    assert set(cases) | {"closed"} == set(render.COMMENTS)
    for name, params in cases.items():
        text = render.comment(name, params, ctx)
        assert text.endswith("ARGUS reference: ` r `"), name
        assert "http" not in text.replace(OWN_LINK, ""), name
