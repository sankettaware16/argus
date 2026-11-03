"""The case team's unit test kit: the Amadey and Git reports as the pure writer makes them
(tests/unit/incident/kit.py), a rendering context, and a way to put hostile text into a report."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from unittest import mock

from markdown_it import MarkdownIt
from pydantic import ValidationError

from argus.caseteam import render
from argus.caseteam.render import Context
from argus.incident import build
from argus.incident import model as m
from tests.unit.incident import kit

LINK_BASE = "https://argus.example"
KIBANA = "https://kibana.example"
CTX = Context(LINK_BASE, (KIBANA,))
CASE_ID = str(kit.CASE_ID)

# strings that must never act as markup, a link, a mention or a command, in any field
HOSTILE = (
    "[click](javascript:alert(1))",
    "![pixel](https://evil.example/p.png)",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "@everyone @here @argus-lead",
    "```\n# pwned\n```",
    "`` ` ``` ` ``",
    "‮⁦reversed⁩",
    "http://evil.example/a?b=c&d=e",
    "evil.example/login",
    "10.0.0.1 and 77.221.155.150",
    "| a | b |\n|---|---|\n| 1 | 2 |",
    "# Heading\n\n> quote\n\n- item",
    "\x00nul\x07bell\x1b[31m",
    "$(rm -rf /) ; `id` ; ${IFS}",
    "&#64;admin; &lt;b&gt;",
    "[ref]: http://evil.example\n[ref]",
    "www.evil.example",
    "javascript:alert(1)",
    "\\\\ \\` \\[ \\]",
)


def amadey() -> m.IncidentReport:
    return build.build(kit.amadey(), kit.ctx())


def git() -> m.IncidentReport:
    return build.build(kit.git(), kit.ctx())


def texts(report: m.IncidentReport, ctx: Context = CTX) -> dict[str, str]:
    """Every outgoing text of a case by its step key (the description is ``open``)."""
    from argus.caseteam import plan

    p = plan.first_plan(report, 1, [], ctx)
    return {s.key: s.text for s in p.steps if s.text is not None}


def map_strings(
    node: Any, change: Callable[[str, str], str], path: str = "", skip: tuple[str, ...] = ()
) -> Any:
    """A copy of a dumped report with ``change(path, value)`` applied to every string whose path
    does not end in one of ``skip`` (identifiers and enumerations the model pins)."""
    if isinstance(node, str):
        return node if path.endswith(skip) else change(path, node)
    if isinstance(node, dict):
        return {k: map_strings(v, change, f"{path}.{k}", skip) for k, v in node.items()}
    if isinstance(node, list):
        return [map_strings(v, change, f"{path}[]", skip) for v in node]
    return node


# fields the model pins (patterns, enumerations, times); hostile text goes in every other string
PINNED = (
    ".id",
    ".fact",
    ".kind",
    ".status",
    ".by",
    ".language",
    ".standing",
    ".day",
    ".incident_id",
    ".case_id",
    ".case_state",
    ".schema_version",
    ".severity",
    ".writer",
    ".time_from",
    ".time_to",
    ".at",
    ".start",
    ".end",
    ".first_seen",
    ".last_seen",
    ".first_alert_at",
    ".last_alert_at",
    ".as_at",
    ".notified_at",
    ".blocked_at",
    ".outcome",
    ".state",
    ".role",
    ".index",
    ".template",
    ".cites",
    ".confidence_words",
)


def hostile_report(report: m.IncidentReport, pick: Callable[[str, str], str]) -> m.IncidentReport:
    """The report with ``pick(path, old)`` in every free-text string (cut to what the field
    holds). The citation check (which compares digits) is lifted: it guards the writer, and this
    feeds the renderer."""
    body = map_strings(report.model_dump(mode="json"), pick, skip=PINNED)
    for _ in range(8):
        try:
            with mock.patch("argus.incident.model.check", return_value=[]):
                return m.IncidentReport.model_validate(body)
        except ValidationError as exc:
            for err in exc.errors():
                if err["type"] != "string_too_long":
                    raise
                node: Any = body
                for key in err["loc"][:-1]:
                    node = node[key]
                last = err["loc"][-1]
                node[last] = node[last][: err["ctx"]["max_length"]]
    raise AssertionError("a hostile report could not be cut to the model")


@contextmanager
def no_check() -> Iterator[None]:
    with mock.patch("argus.incident.model.check", return_value=[]):
        yield


_MD = MarkdownIt("commonmark").enable("table")
_TAGS = {
    "p",
    "h1",
    "h2",
    "h3",
    "strong",
    "em",
    "code",
    "pre",
    "ul",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "a",
    "br",
    "hr",
}


def html_of(markdown: str) -> str:
    return str(_MD.render(markdown))


def dangerous_html(markdown: str, allowed: tuple[str, ...]) -> list[str]:
    """What a Markdown reader would make of ``markdown`` that is not plain text: a tag outside
    the ones the renderers use, an image, a link to anywhere but ``allowed``, a script target,
    an HTML comment or entity-built tag. Empty means nothing acts."""
    html = html_of(markdown)
    problems: list[str] = []
    for tag in re.findall(r"<\s*/?\s*([A-Za-z][A-Za-z0-9-]*)", html):
        if tag.lower() not in _TAGS:
            problems.append(f"tag <{tag}>")
    problems += [
        f"link to {u[:40]}"
        for u in re.findall(r'<a href="([^"]*)"', html)
        if not any(u.startswith(a) for a in allowed)
    ]
    if "<!--" in html:
        problems.append("html comment")
    for tag, attrs in re.findall(r"<([A-Za-z][A-Za-z0-9-]*)((?:\s[^>]*)?)>", html):
        if re.search(r"(?i)\bon[a-z]+\s*=", attrs):
            problems.append(f"event handler on <{tag}>")
    return problems


__all__ = ["CASE_ID", "CTX", "HOSTILE", "KIBANA", "LINK_BASE", "render"]
