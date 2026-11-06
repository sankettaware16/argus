"""No ``{token}`` reaches a reader (P4-F V0). The site's words are written into sentences as
``site.say`` tokens (``{noun}``, ``{Own:sites}``, ...); one that is not put through ``say``
reaches the page as it is, as the dashboard's foot printed "contains {noun} addresses" from P4-D1
on. Every PDF page, every CSV and every comment the case team can post is read here, for the
three fixture cases, a case with accounts, and the neutral site as well as the suite's."""

from __future__ import annotations

import io
import re
from collections.abc import Iterator

import pytest
from pypdf import PdfReader

from argus import site
from argus.caseteam import plan, render, visual
from argus.incident import dashboard, files
from argus.incident import model as m
from argus.incident.build import build
from argus.site import SiteSettings
from tests.unit.caseteam import kit
from tests.unit.caseteam.test_edit_plan import newer, posted_from
from tests.unit.caseteam.test_plan import alerts, posted_after
from tests.unit.incident import kit as facts
from tests.unit.incident.test_accounts import NAME, OTHER
from tests.unit.incident.test_accounts import report as with_accounts

pytestmark = pytest.mark.unit
TOKEN = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*(?::[^{}\s]*)?\}")
CTX = kit.CTX


def reports() -> dict[str, m.IncidentReport]:
    return {
        "amadey": kit.amadey(),
        "git": kit.git(),
        "scanners": build(facts.scanners(), facts.ctx()),
        "accounts": with_accounts(NAME, OTHER),
    }


def pdf_text(data: bytes) -> str:
    reader = PdfReader(io.BytesIO(data))
    meta = reader.metadata
    said = [p.extract_text() for p in reader.pages]
    if meta is not None:
        said += [str(meta.title or ""), str(meta.author or "")]
    return "\n".join(said)


def every_comment(report: m.IncidentReport) -> Iterator[tuple[str, str]]:
    """Each text of a first post, an update round, a refresh and the lead's notes."""
    first = plan.first_plan(report, 1, alerts(4), CTX)
    for s in first.steps:
        if s.text is not None:
            yield f"first/{s.key}", s.text
    later = newer(report).model_copy(
        update={
            "meta": report.meta.model_copy(update={"alerts_total": report.meta.alerts_total + 7})
        }
    )
    update = plan.update_plan(later, 2, alerts(6), CTX, posted_after(first, report), max_alerts=500)
    for s in update.steps:
        if s.text is not None:
            yield f"update/{s.key}", s.text
    posted = posted_from(
        first, comments={**posted_from(first).comments, **posted_after(first, report).comments}
    )
    for s in plan.refresh_plan(later, 2, CTX, posted).steps:
        if s.text is not None:
            yield f"refresh/{s.key}", s.text
    case = report.header.case_id
    yield (
        "closing",
        render.closing_comment(
            CTX, case, who="A Person", outcome="true_positive", effect=render.Effect("confirmed", 3)
        ),
    )
    yield "conflict", render.conflict_comment(CTX, case, [("A", "true_positive"), ("B", "x")])
    yield "untagged", render.untagged_comment(CTX, case, named=5, gone=1, untagged=1)
    yield "glance/new", visual.comment(report, "acme-soc", since=visual.Seen(1, 0, 0, 0, 0, 0))[0]


@pytest.fixture(params=["suite", "neutral"])
def a_site(request: pytest.FixtureRequest) -> Iterator[str]:
    """The suite's made-up site, and the neutral defaults a fresh install starts with."""
    if request.param == "suite":
        yield "suite"
        return
    with site.using(SiteSettings()):
        yield "neutral"


@pytest.mark.parametrize("name", ["amadey", "git", "scanners", "accounts"])
def test_no_token_reaches_a_page_of_either_pdf_or_a_csv(name: str, a_site: str) -> None:
    report = reports()[name]
    for label, data in files.bundle(report).items():
        text = pdf_text(data) if label.endswith(".pdf") else data.decode("utf-8")
        found = TOKEN.findall(text)
        assert not found, f"{a_site}/{name}/{label}: {found}"
    assert site.say(files.FOOTER) in files.footer_text(report)
    assert site.organisation().name in pdf_text(dashboard.pdf(report))


@pytest.mark.parametrize("name", ["amadey", "git", "scanners", "accounts"])
def test_no_token_reaches_a_comment(name: str, a_site: str) -> None:
    said = list(every_comment(reports()[name]))
    assert any(key.startswith("update/edit:comment:glance") for key, _ in said)
    for key, text in said:
        found = TOKEN.findall(text)
        assert not found, f"{a_site}/{name}/{key}: {found}"


def test_the_check_finds_a_token_left_in_a_text() -> None:
    """The test above would catch the bug it is for."""
    assert TOKEN.findall(files.FOOTER) == ["{noun}"]
    assert TOKEN.findall("{Own:sites} reached") == ["{Own:sites}"]
    assert not TOKEN.findall('!{lens{"timeRange":{"from":"x"}}}')  # a chart's JSON is no token
    assert not TOKEN.findall("\\{noun\\}")  # a value written escaped is no token either
