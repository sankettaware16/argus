"""Naming v2 in the incident report: the header names the certainty word that leads ARGUS's own
title (so Kibana's title can leave it out), and none for a person's title; the summary's verdict
line is not this change's (it stays as it was). Made-up values."""

from __future__ import annotations

from dataclasses import replace

from argus.caseteam import render
from argus.incident.build import build
from tests.unit.incident import kit
from tests.unit.incident.test_build import catalogue_ctx


def _with_title(title: str, by_person: bool):  # type: ignore[no-untyped-def]
    facts = kit.amadey()
    return replace(facts, case=replace(facts.case, title=title, title_by_person=by_person))


def test_argus_title_names_its_certainty_and_kibana_leaves_it_out() -> None:
    report = build(_with_title("Likely beaconing from 10.0.4.7 to 198.51.100.20", False),
                   catalogue_ctx())  # fmt: skip
    assert report.header.certainty == "Likely"
    assert report.header.title.endswith("· Likely beaconing from 10.0.4.7 to 198.51.100.20")
    assert render.title_of(report).endswith("· Beaconing from 10.0.4.7 to 198.51.100.20")


def test_a_persons_title_has_no_certainty_word_even_when_it_starts_like_one() -> None:
    report = build(_with_title("Likely phishing of the lab office", True), catalogue_ctx())
    assert report.header.certainty is None
    assert render.title_of(report).endswith("· Likely phishing of the lab office")


def test_an_old_title_has_none() -> None:
    report = build(_with_title("Regular beaconing from a campus host", False), catalogue_ctx())
    assert report.header.certainty is None
