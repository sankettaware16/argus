"""The evidence sentences read the answer as ARGUS stores it (``{"rows", "total", ...}``): an
empty threat-list lookup said "could not be read" in every report until 2026-10-30."""

from __future__ import annotations

from typing import Any

import pytest

from argus.incident import evidence

pytestmark = pytest.mark.unit

SPAN = {
    "ip": "45.138.12.51",
    "start": "2026-10-27T01:40:00+00:00",
    "end": "2026-10-27T05:00:00+00:00",
}


def stored(total: int, rows: list[Any] | None = None) -> dict[str, Any]:
    return {"rows": rows or [], "total": total, "aggregations": None, "rows_complete": True}


def test_an_empty_threat_list_lookup_says_the_values_are_not_listed() -> None:
    params = {"values": ["34.185.253.9", "::ffff:34.185.253.9"]}
    said = evidence.say("ti.lookup", params, stored(0), "empty")
    assert said.text == "None of 2 values is on the local threat lists."
    assert said.empty
    assert said.count == 0


def test_a_threat_list_match_counts_its_records() -> None:
    said = evidence.say("ti.lookup", {"values": ["77.1.2.3"]}, stored(1, [{}]), "ok")
    assert said.text == "1 record on the local threat lists names the 1 value asked about."
    assert said.count == 1


@pytest.mark.parametrize(
    ("template", "total", "words"),
    [
        ("web.followups", 0, "no successful answer"),
        ("web.followups", 20, "20 successful (2xx) answers"),
        ("logs.source_events", 0, "hold no event"),
        ("logs.source_events", 3, "hold 3 events"),
    ],
)
def test_the_hit_counted_checks_read_the_stored_total(
    template: str, total: int, words: str
) -> None:
    said = evidence.say(template, SPAN, stored(total), "ok" if total else "empty")
    assert words in said.text
    assert "could not be read" not in said.text
    assert said.count == total


def test_a_raw_answer_still_reads_its_hits_total() -> None:
    raw = {"hits": {"total": {"value": 4, "relation": "eq"}, "hits": []}}
    assert evidence.say("web.followups", SPAN, raw, "ok").count == 4


def test_an_answer_without_a_count_still_says_only_that_it_ran() -> None:
    said = evidence.say("ti.lookup", {"values": ["x"]}, {"rows": []}, "ok")
    assert said.text == "ARGUS's ti.lookup check ran and could not be read."
