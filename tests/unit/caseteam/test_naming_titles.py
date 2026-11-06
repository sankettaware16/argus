"""Naming v2 in Kibana: the title the case team writes leaves out ARGUS's certainty word (only
confirmed cases are posted) and keeps a person's title as written; ARGUS's retitle reaches a posted
case only on a material change (words, or a count that shrank or grew by half) or once a small
count bump has waited six hours, never for a certainty word alone. A new address, case or place is
words, not a count. Made-up values only."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from argus.caseteam import plan, render
from argus.incident import model as m
from tests.unit.caseteam.test_edit_plan import CTX, first, posted_from

pytestmark = pytest.mark.unit
IDENT = "ACME-IR-2026-1026-01"


def named(report: m.IncidentReport, title: str, certainty: str | None) -> m.IncidentReport:
    header = report.header.model_copy(
        update={"title": f"{IDENT} · {title}", "certainty": certainty}
    )
    return report.model_copy(update={"header": header})


def test_kibana_title_leaves_out_argus_certainty_word() -> None:
    report, _ = first()
    likely = named(report, "Likely beaconing from 10.0.4.7 to 198.51.100.20", "Likely")
    assert render.title_of(likely) == f"{IDENT} · Beaconing from 10.0.4.7 to 198.51.100.20"
    unclear = named(report, "Unclear: beaconing from 10.0.4.7", "Unclear")
    assert render.title_of(unclear) == f"{IDENT} · Beaconing from 10.0.4.7"
    scan = named(report, "Confirmed .env scan of www.example.edu by 6 outside IPs", "Confirmed")
    assert render.title_of(scan) == f"{IDENT} · .env scan of www.example.edu by 6 outside IPs"


def test_a_persons_title_reaches_kibana_as_they_wrote_it() -> None:
    report, _ = first()
    person = named(report, "Likely phishing of the hostel office", None)
    assert render.title_of(person) == f"{IDENT} · Likely phishing of the hostel office"


def _posted(old: str):  # type: ignore[no-untyped-def]
    report, p = first()
    return replace(posted_from(p), title=f"{IDENT} · {old}"), report


def test_a_certainty_change_alone_plans_no_kibana_retitle() -> None:
    posted, report = _posted("Beaconing to 198.51.100.20 from 12 of 22 campus devices")
    confirmed = named(report, "Confirmed beaconing to 198.51.100.20 from 12 of 22 campus devices",
                      "Confirmed")  # fmt: skip
    assert plan.retitle_step(confirmed, posted) is None


def test_a_small_count_bump_waits_and_a_large_one_or_a_shrink_is_sent() -> None:
    posted, report = _posted("Beaconing to 198.51.100.20 from 12 of 22 campus devices")
    bump = named(report, "Likely beaconing to 198.51.100.20 from 13 of 23 campus devices", "Likely")
    assert plan.retitle_step(bump, posted) is None
    grown = named(
        report, "Likely beaconing to 198.51.100.20 from 18 of 30 campus devices", "Likely"
    )
    step = plan.retitle_step(grown, posted)
    assert step is not None
    assert step.payload["title"].endswith("from 18 of 30 campus devices")
    shrunk = named(
        report, "Likely beaconing to 198.51.100.20 from 11 of 22 campus devices", "Likely"
    )
    assert plan.retitle_step(shrunk, posted) is not None


def test_new_words_are_sent_at_once() -> None:
    posted, report = _posted("Beaconing to 198.51.100.20 from 12 of 22 campus devices")
    family = named(report, "Likely Amadey beaconing to 198.51.100.20 from 12 of 22 campus devices",
                   "Likely")  # fmt: skip
    step = plan.retitle_step(family, posted)
    assert step is not None
    assert (
        step.payload["title"]
        == f"{IDENT} · Amadey beaconing to 198.51.100.20 from 12 of 22 campus devices"
    )


NOW = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)


def test_a_small_count_bump_is_sent_once_the_posted_title_has_waited() -> None:
    posted, report = _posted("Beaconing to 198.51.100.20 from 12 of 22 campus devices")
    bump = named(report, "Likely beaconing to 198.51.100.20 from 13 of 23 campus devices", "Likely")
    fresh = replace(posted, title_at=NOW - timedelta(hours=5))
    assert plan.retitle_step(bump, fresh, now=NOW) is None
    old = replace(posted, title_at=NOW - timedelta(hours=6))
    step = plan.retitle_step(bump, old, now=NOW)
    assert step is not None
    assert step.payload["title"].endswith("from 13 of 23 campus devices")
    assert plan.retitle_step(bump, replace(posted, title_at=None), now=NOW) is not None
    assert plan.retitle_step(bump, old) is None  # no time: it waits
    update = plan.update_plan(bump, 2, [], CTX, old, max_alerts=25, now=NOW)
    assert [s.kind for s in update.steps if s.kind == "retitle"] == ["retitle"]


def test_a_persons_refresh_sets_a_small_count_bump_at_once() -> None:
    posted, report = _posted("Beaconing to 198.51.100.20 from 12 of 22 campus devices")
    bump = named(report, "Likely beaconing to 198.51.100.20 from 13 of 23 campus devices", "Likely")
    refresh = plan.refresh_plan(bump, 2, CTX, replace(posted, title_at=NOW))
    assert [s.payload["title"] for s in refresh.steps if s.kind == "retitle"] == [
        render.title_of(bump)
    ]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("Beaconing from 10.0.4.12 to 203.0.113.5 (VirusTotal: 4 engines)",
         "Likely beaconing from 10.0.4.13 to 203.0.113.6 (VirusTotal: 4 engines)"),
        ("Beaconing from 10.0.4.12 to 203.0.113.5",
         "Likely beaconing from 10.0.4.13 to 203.0.113.5"),
        ("Beaconing from 10.0.4.1 to 203.0.113.5, the server of case 3",
         "Likely beaconing from 10.0.4.1 to 203.0.113.5, the server of case 4"),
        ("Beaconing from 10.0.4.1 (Hostel 12) to 203.0.113.5",
         "Likely beaconing from 10.0.4.1 (Hostel 13) to 203.0.113.5"),
    ],
    ids=["addresses", "a device", "a case", "a place"],
)  # fmt: skip
def test_a_new_address_case_or_place_is_sent_at_once(old: str, new: str) -> None:
    posted, report = _posted(old)
    fresh = replace(posted, title_at=NOW - timedelta(minutes=15))
    step = plan.retitle_step(named(report, new, "Likely"), fresh, now=NOW)
    assert step is not None
    assert step.payload["title"] == f"{IDENT} · B{new.removeprefix('Likely b')}"
