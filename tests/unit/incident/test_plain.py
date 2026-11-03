"""The terminal view of the report (AR7): every value is shown with unprintable characters
escaped, so a user agent or a path from a log can never write to the operator's terminal."""

from __future__ import annotations

from dataclasses import replace

import pytest

from argus.incident import plain
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def test_a_value_with_a_terminal_escape_is_shown_escaped() -> None:
    facts = kit.git()
    hostile = tuple(
        replace(d, fields={**d.fields, "user_agent.original": ("evil\x1b]0;owned\x07 agent",)})
        for d in facts.docs
    )
    report = build(replace(facts, docs=hostile), kit.ctx())
    shown = "\n".join(plain.lines(report))
    assert "\x1b" not in shown
    assert "\x07" not in shown
    assert plain.printable("a\x1b[2Jb") == "a\\x1b[2Jb"


def test_every_part_is_there_in_order() -> None:
    out = plain.lines(build(kit.amadey(), kit.ctx()))
    heads = [line for line in out if line.isupper() and line.strip() == line]
    assert heads[:8] == [
        "SUMMARY",
        "VERDICT",
        "TIMELINE (IST)",
        "ACTORS",
        "AFFECTED ASSETS (1)",
        "INDICATORS (5)",
        "EVIDENCE",
        "HYPOTHESES",
    ]
    assert out[0].startswith("ACME-IR-2026-1026-01 · ")
